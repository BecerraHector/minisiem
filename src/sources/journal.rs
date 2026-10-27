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

/// Overrides the `journalctl` binary (used by tests).
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
fn stop_and_explain(result: io::Result<()>, child: &Mutex<Child>, relay: JoinHandle<()>) -> String {
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
        (Ok(()), Some(status)) => format!("journalctl exited ({status})"),
        (Ok(()), None) => "journalctl exited".into(),
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

/// Sends every sshd event found in `reader` until it ends.
fn forward_events(mut reader: impl BufRead, outlet: &Outlet) -> io::Result<()> {
    let mut buf = Vec::new();
    while reader.read_until(b'\n', &mut buf)? > 0 {
        let line = String::from_utf8_lossy(&buf);
        if let Some(event) = JournalParser.parse(line.trim_end())
            && !outlet.event(event)
        {
            return Ok(());
        }
        buf.clear();
    }
    Ok(())
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

        forward_events(journal.as_slice(), &outlet).unwrap();
        drop(outlet);

        assert_eq!(
            inlet.events.iter().count(),
            11,
            "10 failures and 1 login; spoofed and unrelated entries skipped"
        );
    }

    #[test]
    fn reports_a_read_error_while_journalctl_is_still_running() {
        // The relay ends only when stderr closes, which a live journalctl
        // never does on its own.
        let mut child = Command::new("sleep").arg("600").stderr(Stdio::piped()).spawn().unwrap();
        let stderr = child.stderr.take().unwrap();
        let relay = thread::spawn(move || for _ in BufReader::new(stderr).lines() {});
        let child = Arc::new(Mutex::new(child));

        let (done, reported) = std::sync::mpsc::channel();
        let running = Arc::clone(&child);
        thread::spawn(move || {
            let reason = stop_and_explain(Err(io::Error::other("boom")), &running, relay);
            let _ = done.send(reason);
        });
        let reason = reported.recv_timeout(std::time::Duration::from_secs(5));

        // Never leave the stand-in running, whatever the outcome.
        let _ = child.lock().map(|mut child| child.kill());
        assert_eq!(
            reason.as_deref(),
            Ok("reading journalctl output failed: boom"),
            "the failure must be reported, not wait for journalctl forever"
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
