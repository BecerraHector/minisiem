//! Follows the systemd journal through `journalctl --follow --output=json`.

use std::env;
use std::ffi::OsString;
use std::io::{self, BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use super::Outlet;
use crate::ingestion::{JournalParser, LogParser, SSHD_PROCESSES};

/// Name used in messages about this source.
const SOURCE: &str = "journald";

/// Overrides the `journalctl` binary, which is otherwise looked up in `PATH`
/// (used by tests; documented in the README).
pub const JOURNALCTL_ENV: &str = "MINISIEM_JOURNALCTL";

/// A running `journalctl`; dropping it stops the process.
pub struct JournalFollow {
    child: Arc<Mutex<Child>>,
}

impl JournalFollow {
    /// Starts `journalctl` and the threads reading it.
    pub fn start(outlet: Outlet) -> Result<Self, String> {
        let program = env::var_os(JOURNALCTL_ENV).unwrap_or_else(|| "journalctl".into());
        let mut child = journalctl_command(program)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{SOURCE}: cannot run journalctl: {e}"))?;
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr = child.stderr.take().expect("stderr is piped");
        let child = Arc::new(Mutex::new(child));

        // Relay journalctl's own messages; a permission warning is fatal.
        let warnings = outlet.clone();
        let relay = thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if is_permission_warning(&line) {
                    warnings.fail(
                        SOURCE,
                        format!(
                            "cannot read the system journal ({}); run as root or as a member of the \
                             'systemd-journal' group",
                            line.trim()
                        ),
                    );
                    return;
                }
                eprintln!("minisiem: journalctl: {line}");
            }
        });

        let exited = Arc::clone(&child);
        thread::spawn(move || {
            let result = forward_events(BufReader::new(stdout), &outlet);
            outlet.fail(SOURCE, stop_and_explain(result, &exited, relay));
        });

        Ok(Self { child })
    }
}

/// Stops `journalctl` once reading its output ended: kills it if it still
/// runs, waits for its stderr relay, reaps it, and explains why it stopped.
fn stop_and_explain(result: io::Result<Ended>, child: &Mutex<Child>, relay: JoinHandle<()>) -> String {
    // Usually journalctl is already gone (stdout closed). After a read error,
    // or once the pipeline is gone, it may still run, and the relay would
    // wait for its stderr forever: stop it first. Killing an exited process
    // is harmless and keeps its exit status.
    if let Ok(mut child) = child.lock() {
        let _ = child.kill();
    }
    // Let journalctl's last words reach stderr before reporting, or the
    // process may exit first.
    let _ = relay.join();
    let status = child.lock().ok().and_then(|mut child| child.wait().ok());
    match (result, status) {
        (Err(e), _) => format!("reading journalctl output failed: {e}"),
        // Killed above: its status would read as if it had crashed.
        (Ok(Ended::PipelineGone), _) => "journalctl stopped by minisiem: detection no longer reads events".into(),
        (Ok(_), Some(status)) => format!("journalctl exited ({status})"),
        (Ok(_), None) => "journalctl exited".into(),
    }
}

/// `journalctl` following new entries of OpenSSH processes only. The match
/// is on `_COMM`, which journald sets itself: `--identifier=sshd` would
/// match `SYSLOG_IDENTIFIER`, which any process can claim.
///
/// It runs in its own process group: Ctrl+C in a terminal signals the whole
/// foreground group, and journalctl exiting on it could be reported as a
/// failed source before minisiem handles the interrupt. minisiem stops it
/// instead (see `Drop`).
fn journalctl_command(program: OsString) -> Command {
    let mut command = Command::new(program);
    command.args(["--follow", "--output=json", "--lines=0", "--no-pager"]);
    command.args(SSHD_PROCESSES.iter().map(|process| format!("_COMM={process}")));
    command.process_group(0);
    command
}

/// Why reading journalctl's output ended without an error.
#[derive(Debug, PartialEq, Eq)]
enum Ended {
    /// journalctl closed its output: it exited, or is exiting.
    Output,
    /// Nobody takes events any more; journalctl is still running.
    PipelineGone,
}

/// Sends every sshd event found in `reader` until it ends. Waits when the
/// queue is full: journalctl then waits too, and journald keeps the entries.
fn forward_events(mut reader: impl BufRead, outlet: &Outlet) -> io::Result<Ended> {
    let mut buf = Vec::new();
    while reader.read_until(b'\n', &mut buf)? > 0 {
        let line = String::from_utf8_lossy(&buf);
        if let Some(event) = JournalParser.parse(line.trim_end())
            && !outlet.wait_and_send(event)
        {
            return Ok(Ended::PipelineGone);
        }
        buf.clear();
    }
    Ok(Ended::Output)
}

/// `journalctl` does not fail without permission to read the system journal:
/// it warns and shows the user's own entries only, which would leave sshd
/// invisible.
fn is_permission_warning(line: &str) -> bool {
    line.contains("not seeing messages from other users")
}

impl Drop for JournalFollow {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_only_new_entries_of_sshd_processes_by_trusted_field() {
        let command = journalctl_command("journalctl".into());
        let args: Vec<_> = command.get_args().map(|a| a.to_string_lossy().into_owned()).collect();

        assert_eq!(command.get_program(), "journalctl");
        for expected in [
            "--follow",
            "--output=json",
            "--lines=0",
            "_COMM=sshd",
            "_COMM=sshd-session",
            "_COMM=sshd-auth",
        ] {
            assert!(args.contains(&expected.to_string()), "missing {expected} in {args:?}");
        }
        assert!(
            !args.iter().any(|a| a.starts_with("--identifier") || a == "-t"),
            "{args:?}"
        );
    }

    #[test]
    fn forwards_parsed_sshd_events_and_skips_the_rest() {
        let journal = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/journal.json")).unwrap();
        let (outlet, inlet) = super::super::channel(100);

        assert_eq!(forward_events(journal.as_slice(), &outlet).unwrap(), Ended::Output);
        drop(outlet);

        assert_eq!(
            inlet.events.iter().count(),
            11,
            "10 failures and 1 login; spoofed and unrelated entries skipped"
        );
    }

    #[test]
    fn waits_for_room_instead_of_dropping_when_the_queue_is_full() {
        // journald keeps its entries, so slowing journalctl down loses nothing.
        let journal = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/journal.json")).unwrap();
        let (outlet, inlet) = super::super::channel(2);
        let dropped = inlet.dropped_counter();
        let reader = thread::spawn(move || {
            thread::sleep(std::time::Duration::from_millis(100));
            std::iter::from_fn(|| inlet.next(std::time::Duration::from_secs(5)).ok()).count()
        });

        forward_events(journal.as_slice(), &outlet).unwrap();
        drop(outlet);

        assert_eq!(reader.join().unwrap(), 11);
        assert_eq!(dropped.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn reports_a_read_error_while_journalctl_is_still_running() {
        // The relay ends only when stderr closes, which a live journalctl
        // never does on its own.
        let mut sleep = Command::new("sleep");
        sleep.arg("600");

        assert_eq!(
            explain_stop(sleep, Err(io::Error::other("boom"))),
            "reading journalctl output failed: boom"
        );
    }

    /// Runs `stop_and_explain` on a stand-in for journalctl, with a stderr
    /// relay like the real one, and never leaves the stand-in running.
    fn explain_stop(mut command: Command, result: io::Result<Ended>) -> String {
        let mut child = command.stderr(Stdio::piped()).spawn().unwrap();
        let stderr = child.stderr.take().unwrap();
        let relay = thread::spawn(move || for _ in BufReader::new(stderr).lines() {});
        let child = Arc::new(Mutex::new(child));

        let (done, reported) = std::sync::mpsc::channel();
        let running = Arc::clone(&child);
        thread::spawn(move || {
            let _ = done.send(stop_and_explain(result, &running, relay));
        });
        let reason = reported.recv_timeout(std::time::Duration::from_secs(5));
        let _ = child.lock().map(|mut child| child.kill());
        reason.expect("stop_and_explain must not wait for journalctl forever")
    }

    #[test]
    fn stops_reading_once_the_pipeline_is_gone() {
        let journal = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/journal.json")).unwrap();
        let (outlet, inlet) = super::super::channel(100);
        drop(inlet);

        assert_eq!(
            forward_events(journal.as_slice(), &outlet).unwrap(),
            Ended::PipelineGone
        );
    }

    #[test]
    fn says_minisiem_stopped_journalctl_once_the_pipeline_is_gone() {
        let mut sleep = Command::new("sleep");
        sleep.arg("600");

        assert_eq!(
            explain_stop(sleep, Ok(Ended::PipelineGone)),
            "journalctl stopped by minisiem: detection no longer reads events"
        );
    }

    #[test]
    fn recognizes_the_missing_permission_warning() {
        assert!(is_permission_warning(
            "Hint: You are currently not seeing messages from other users and the system."
        ));
        assert!(!is_permission_warning("-- No entries --"));
    }
}
