use std::io::{BufRead, BufReader, Read, Write};
use std::net::UdpSocket;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

/// Forwards each line of a child's output to a channel, so tests can wait
/// for a line with a timeout instead of hanging forever.
fn lines_of(output: impl Read + Send + 'static) -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(output).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    rx
}

fn next_line(lines: &Receiver<String>) -> String {
    lines
        .recv_timeout(Duration::from_secs(10))
        .expect("expected a line within 10 seconds")
}

fn interrupt(child: &Child) {
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn watch_alerts_on_udp_syslog_and_stops_cleanly_on_interrupt() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_minisiem"))
        .args(["watch", "--syslog-udp", "127.0.0.1:0", "--threshold", "10"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = lines_of(child.stdout.take().unwrap());
    let stderr = lines_of(child.stderr.take().unwrap());

    let listening = next_line(&stderr);
    let addr = listening
        .strip_prefix("minisiem: listening for syslog on udp://")
        .unwrap_or_else(|| panic!("unexpected startup line: {listening}"));
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    for i in 0..10 {
        let frame = if i % 2 == 0 {
            format!("<38>Oct 22 10:15:{i:02} srv01 sshd[1]: Failed password for root from 203.0.113.7 port {i} ssh2")
        } else {
            format!(
                "<38>1 2026-10-22T10:15:{i:02}Z srv01 sshd-session 1 - - Failed password for admin from 203.0.113.7 port {i} ssh2"
            )
        };
        sender.send_to(frame.as_bytes(), addr).unwrap();
    }

    let alert = next_line(&stdout);
    assert!(
        alert.starts_with(
            "[HIGH] SSH brute force (T1110.001 Password Guessing) src=203.0.113.7 host=srv01 failures=10 users=admin,root"
        ),
        "alert: {alert}"
    );

    interrupt(&child);
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0));
    assert_eq!(next_line(&stderr), "minisiem: watch: events=10 alerts=1");
}

/// Waits for the child to exit, killing it if it takes longer than `limit`.
fn wait_at_most(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    for _ in 0..limit.as_millis() / 50 {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

#[cfg(target_os = "linux")]
/// True when one of the child's threads waits for room in a full pipe. The
/// kernel names that wait `pipe_write`, `pipe_wait_writable` or
/// `anon_pipe_write`, depending on its version; read-side waits
/// (`pipe_wait_readable`, and `pipe_wait` before Linux 5.5) do not count.
/// Other names, or a `wchan` reading `0`, give `false`.
fn blocked_writing_to_a_pipe(child: &Child) -> bool {
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{}/task", child.id())) else {
        return false;
    };
    tasks.filter_map(Result::ok).any(|task| {
        std::fs::read_to_string(task.path().join("wchan"))
            .is_ok_and(|wchan| ["pipe_write", "pipe_wait_writable", "anon_pipe_write"].contains(&wchan.trim()))
    })
}

#[cfg(target_os = "linux")]
#[test]
fn watch_stops_on_interrupt_even_when_nobody_reads_its_alerts() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_minisiem"))
        .args(["watch", "--syslog-udp", "127.0.0.1:0", "--threshold", "1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Kept open but never read: once the pipe fills, writing an alert blocks.
    let _unread_stdout = child.stdout.take().unwrap();
    let stderr = lines_of(child.stderr.take().unwrap());

    let listening = next_line(&stderr);
    let addr = listening
        .strip_prefix("minisiem: listening for syslog on udp://")
        .unwrap_or_else(|| panic!("unexpected startup line: {listening}"));
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    // One alert per source IP, in batches, until writing an alert blocks.
    // A kernel with another name for that wait only makes it slower: 10,000
    // alerts are far more than a pipe holds. Either way, the grace-period
    // message asserted below proves detection was stuck writing.
    let mut ip = 0u32;
    while ip < 10_000 && !blocked_writing_to_a_pipe(&child) {
        for _ in 0..100 {
            let frame = format!(
                "<38>Oct 22 10:15:00 srv01 sshd[1]: Failed password for root from 10.{}.{}.{} port 1 ssh2",
                ip / 62_500,
                ip / 250 % 250,
                ip % 250 + 1
            );
            sender.send_to(frame.as_bytes(), addr).unwrap();
            ip += 1;
        }
        thread::sleep(Duration::from_millis(20));
    }

    interrupt(&child);
    let status = wait_at_most(&mut child, Duration::from_secs(10));

    assert_eq!(
        status.map(|s| s.code()),
        Some(Some(0)),
        "watch must stop on Ctrl+C while blocked writing to stdout"
    );
    // The burst may also overflow the socket buffer, which is warned about.
    let stopping = std::iter::repeat_with(|| next_line(&stderr))
        .find(|line| !line.starts_with("minisiem: warning: the kernel is dropping datagrams"))
        .unwrap();
    assert_eq!(
        stopping,
        "minisiem: watch: detection did not stop within 2s (stdout blocked?), stopping without writing pending \
         alerts"
    );
    let summary = next_line(&stderr);
    assert!(summary.starts_with("minisiem: watch: events="), "{summary}");
}

/// Starts `watch --syslog-udp --threshold 1` with `MINISIEM_TEST_PANIC` set
/// to `panic`, sends it one sshd failure and returns it with its stdout and
/// stderr lines.
fn watch_one_event_with_test_panic(panic: &str) -> (Child, Receiver<String>, Receiver<String>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_minisiem"))
        .args(["watch", "--syslog-udp", "127.0.0.1:0", "--threshold", "1"])
        .env("MINISIEM_TEST_PANIC", panic)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = lines_of(child.stdout.take().unwrap());
    let stderr = lines_of(child.stderr.take().unwrap());
    let listening = next_line(&stderr);
    let addr = listening
        .strip_prefix("minisiem: listening for syslog on udp://")
        .unwrap_or_else(|| panic!("unexpected startup line: {listening}"))
        .to_string();

    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .send_to(
            b"<38>Oct 22 10:15:00 srv01 sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2",
            &addr,
        )
        .unwrap();
    (child, stdout, stderr)
}

#[test]
fn watch_exits_with_101_when_detection_panics() {
    let (mut child, _stdout, stderr) = watch_one_event_with_test_panic("1");
    let status = wait_at_most(&mut child, Duration::from_secs(10));

    assert_eq!(status.map(|s| s.code()), Some(Some(101)), "a panic must not hang watch");
    let reported = std::iter::from_fn(|| stderr.recv_timeout(Duration::from_secs(1)).ok())
        .any(|line| line.contains("panicked") || line.contains("MINISIEM_TEST_PANIC is set"));
    assert!(reported, "the panic message reaches stderr");
}

#[test]
fn watch_ignores_a_test_panic_variable_not_set_to_1() {
    for value in ["", "0"] {
        let (mut child, stdout, stderr) = watch_one_event_with_test_panic(value);
        // The alert shows the event went through detection without a panic.
        let alert = next_line(&stdout);
        assert!(alert.contains("src=203.0.113.7"), "{alert}");

        interrupt(&child);
        assert_eq!(
            wait_at_most(&mut child, Duration::from_secs(10)).map(|s| s.code()),
            Some(Some(0)),
            "MINISIEM_TEST_PANIC={value:?}"
        );
        assert_eq!(next_line(&stderr), "minisiem: watch: events=1 alerts=1");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn watch_reports_the_datagrams_the_kernel_drops_under_a_flood() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_minisiem"))
        .args(["watch", "--syslog-udp", "127.0.0.1:0"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = lines_of(child.stderr.take().unwrap());

    let listening = next_line(&stderr);
    let addr = listening
        .strip_prefix("minisiem: listening for syslog on udp://")
        .unwrap_or_else(|| panic!("unexpected startup line: {listening}"))
        .to_string();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    // Far faster than one thread can read and parse: the socket buffer fills,
    // however big it is, and the reader warns within a second.
    let frame = "<38>Oct 22 10:15:00 srv01 sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2";
    let warning = format!(
        "minisiem: warning: the kernel is dropping datagrams sent to udp://{addr}: they arrive faster than \
         minisiem reads them, possibly because of a flood"
    );
    let mut sent = 0u64;
    // The queue may fill too, and its warning may come first.
    while !stderr.try_iter().any(|line| line == warning) {
        assert!(sent < 20_000_000, "the kernel never dropped a datagram");
        for _ in 0..50_000 {
            sender.send_to(frame.as_bytes(), &addr).unwrap();
        }
        sent += 50_000;
    }
    interrupt(&child);
    assert_eq!(child.wait().unwrap().code(), Some(0));
    let summary = std::iter::repeat_with(|| next_line(&stderr))
        .find(|line| line.starts_with("minisiem: watch: "))
        .unwrap();
    let kernel_dropped: u64 = summary
        .split_once(" kernel_dropped=")
        .and_then(|(_, n)| n.split(' ').next()?.parse().ok())
        .unwrap_or_else(|| panic!("no kernel_dropped in {summary}"));
    let events: u64 = summary
        .strip_prefix("minisiem: watch: events=")
        .and_then(|rest| rest.split(' ').next()?.parse().ok())
        .unwrap_or_else(|| panic!("unexpected summary {summary}"));
    assert!(kernel_dropped > 0, "{summary}");
    assert!(events + kernel_dropped <= sent, "{summary}");
}

#[test]
fn watch_needs_at_least_one_source() {
    let output = minisiem(&["watch"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("required"), "stderr: {}", stderr(&output));
}

#[test]
fn watch_refuses_to_listen_beyond_loopback_without_opt_in() {
    let output = minisiem(&["watch", "--syslog-udp", "0.0.0.0:0"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).starts_with("minisiem: refusing to listen on 0.0.0.0:0"),
        "stderr: {}",
        stderr(&output)
    );
}

/// Starts `minisiem watch --journal` with a fake `journalctl` script.
fn watch_journal(fake: &str) -> Child {
    let script = format!("{}/tests/fixtures/fake-journalctl/{fake}", env!("CARGO_MANIFEST_DIR"));
    Command::new(env!("CARGO_BIN_EXE_minisiem"))
        .args(["watch", "--journal"])
        .env("MINISIEM_JOURNALCTL", script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Kills minisiem's and the fake journalctl's process groups if the test
/// fails before minisiem exits, so a failing run leaves nothing running.
/// Only on failure: after a clean exit the group IDs may already be reused.
struct KillGroupsOnFailure {
    minisiem: u32,
    dir: std::path::PathBuf,
}

impl Drop for KillGroupsOnFailure {
    fn drop(&mut self) {
        if thread::panicking() {
            let journalctl = std::fs::read_to_string(self.dir.join("group")).ok();
            let groups = std::iter::once(self.minisiem.to_string()).chain(journalctl.map(|g| g.trim().to_string()));
            for group in groups {
                let _ = Command::new("kill")
                    .args(["-KILL", "--", &format!("-{group}")])
                    .status();
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// True while any process of the group runs.
fn group_exists(group: &str) -> bool {
    Command::new("kill")
        .args(["-0", "--", &format!("-{group}")])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[test]
fn ctrl_c_in_a_terminal_does_not_reach_journalctl() {
    // A terminal sends Ctrl+C to the whole foreground process group. If it
    // reached journalctl too, its exit could be reported as a failure.
    //
    // The group the cleanup kills is read back from a file, so it lives in a
    // directory only this test can write: creating it fails if it exists.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("minisiem-ctrl-c-{}-{nanos}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let marker = dir.join("group");
    let script = format!(
        "{}/tests/fixtures/fake-journalctl/records-group.sh",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_minisiem"))
        .args(["watch", "--journal"])
        .env("MINISIEM_JOURNALCTL", script)
        .env("FAKE_JOURNALCTL_MARKER", &marker)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        // Its own group, standing in for the terminal's foreground group.
        .process_group(0)
        .spawn()
        .unwrap();
    let _cleanup = KillGroupsOnFailure {
        minisiem: child.id(),
        dir: dir.clone(),
    };
    let stderr = lines_of(child.stderr.take().unwrap());
    assert_eq!(
        next_line(&stderr),
        "minisiem: following journald (sshd, sshd-session, sshd-auth, sudo)"
    );
    let journalctl_group = (0..200)
        .find_map(|_| {
            let group = std::fs::read_to_string(&marker).ok();
            if group.is_none() {
                thread::sleep(Duration::from_millis(50));
            }
            group
        })
        .expect("the fake journalctl records its process group");
    let journalctl_group = journalctl_group.trim();
    assert_ne!(
        journalctl_group,
        child.id().to_string(),
        "journalctl is in minisiem's process group, so a terminal's Ctrl+C reaches it"
    );

    let status = Command::new("kill")
        .args(["-INT", "--", &format!("-{}", child.id())])
        .status()
        .unwrap();
    assert!(status.success());

    assert_eq!(child.wait().unwrap().code(), Some(0));
    // Out of reach of Ctrl+C, journalctl is stopped by minisiem itself. The
    // fake's last `sleep` may outlive it briefly, so give the group a moment.
    let stopped = (0..40).any(|_| {
        let gone = !group_exists(journalctl_group);
        if !gone {
            thread::sleep(Duration::from_millis(50));
        }
        gone
    });
    assert!(stopped, "journalctl is still running after minisiem exited");
}

#[test]
fn watch_follows_journald_and_stops_cleanly_on_interrupt() {
    let mut child = watch_journal("follow.sh");
    let stdout = lines_of(child.stdout.take().unwrap());
    let stderr = lines_of(child.stderr.take().unwrap());

    assert_eq!(
        next_line(&stderr),
        "minisiem: following journald (sshd, sshd-session, sshd-auth, sudo)"
    );
    let alert = next_line(&stdout);
    assert!(
        alert
            .starts_with("[HIGH] SSH brute force (T1110.001 Password Guessing) src=203.0.113.7 host=srv01 failures=10"),
        "alert: {alert}"
    );

    interrupt(&child);
    assert_eq!(child.wait().unwrap().code(), Some(0));
    assert_eq!(next_line(&stderr), "minisiem: watch: events=11 alerts=1");
}

#[test]
fn watch_exits_with_an_error_when_journalctl_stops() {
    let mut child = watch_journal("exits.sh");
    let stderr = lines_of(child.stderr.take().unwrap());

    assert_eq!(child.wait().unwrap().code(), Some(1));
    let lines: Vec<String> = stderr.iter().collect();
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("minisiem: journald: journalctl exited")),
        "stderr: {lines:#?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("Failed to iterate through journal: Bad message")),
        "journalctl's own error is relayed: {lines:#?}"
    );
}

#[test]
fn watch_exits_with_an_error_without_permission_to_read_the_journal() {
    let mut child = watch_journal("no-permission.sh");
    let stderr = lines_of(child.stderr.take().unwrap());

    assert_eq!(child.wait().unwrap().code(), Some(1));
    let lines: Vec<String> = stderr.iter().collect();
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("minisiem: journald: cannot read the system journal")),
        "stderr: {lines:#?}"
    );
}

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/auth.log");
const BRUTE_FORCE_ALERT: &str = "[HIGH] SSH brute force (T1110.001 Password Guessing) src=203.0.113.7 host=srv01 \
                                 failures=10 users=admin,oracle,root,test,ubuntu";

fn minisiem(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_minisiem"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn reads_journald_json_and_ignores_spoofed_sshd_entries() {
    let journal = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/journal.json");

    let output = minisiem(&[journal]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let alerts: Vec<_> = stdout(&output).lines().map(str::to_owned).collect();
    assert_eq!(alerts.len(), 1, "alerts: {alerts:?}");
    assert!(
        alerts[0].starts_with(
            "[HIGH] SSH brute force (T1110.001 Password Guessing) src=203.0.113.7 host=srv01 failures=10 users=root"
        ),
        "alert: {}",
        alerts[0]
    );
    // 12 "failures" from 198.51.100.99 written with `logger -t sshd`, and 12
    // from 198.51.100.77 written by a binary copied to ~/sshd, are not sshd's.
    assert!(
        stderr(&output).contains("lines=36 events=11 alerts=1"),
        "stderr: {}",
        stderr(&output)
    );
}

#[test]
fn detects_brute_force_in_a_log_file() {
    let output = minisiem(&[FIXTURE]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let alerts: Vec<_> = stdout(&output).lines().map(str::to_owned).collect();
    assert_eq!(alerts.len(), 1, "alerts: {alerts:?}");
    assert!(alerts[0].starts_with(BRUTE_FORCE_ALERT), "alert: {}", alerts[0]);
    assert!(
        stderr(&output).contains("lines=23 events=20 alerts=1"),
        "stderr: {}",
        stderr(&output)
    );
}

#[test]
fn reads_from_stdin_when_no_file_is_given() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_minisiem"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&std::fs::read(FIXTURE).unwrap())
        .unwrap();

    let output = child.wait_with_output().unwrap();

    assert!(output.status.success());
    assert!(stdout(&output).starts_with(BRUTE_FORCE_ALERT));
}

#[test]
fn threshold_and_window_flags_change_detection() {
    let output = minisiem(&["--threshold", "3", "--window", "3600", FIXTURE]);

    assert!(output.status.success());
    // 12 failures from 203.0.113.7 => four bursts of three. The slow attacker
    // (one failure per hour) still never reaches three inside the window.
    assert_eq!(stdout(&output).lines().count(), 4);
    assert!(!stdout(&output).contains("198.51.100.23"));
    assert!(stderr(&output).contains("alerts=4"));
}

#[test]
fn fails_with_clear_message_when_file_is_missing() {
    let output = minisiem(&["/nonexistent/auth.log"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).is_empty());
    assert!(
        stderr(&output).starts_with("minisiem: /nonexistent/auth.log:"),
        "stderr: {}",
        stderr(&output)
    );
}

#[test]
fn shipped_sigma_rules_add_alerts_in_event_order() {
    let rules = concat!(env!("CARGO_MANIFEST_DIR"), "/rules");

    let output = minisiem(&["--rules", rules, FIXTURE]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let alerts: Vec<_> = stdout(&output).lines().map(str::to_owned).collect();
    let expected_prefixes = [
        "[LOW] SSH probe for default account (T1110.001) src=203.0.113.7 host=srv01 user=oracle event_kind=invalid_user",
        "[LOW] SSH probe for default account (T1110.001) src=203.0.113.7 host=srv01 user=test event_kind=invalid_user",
        "[LOW] SSH probe for default account (T1110.001) src=203.0.113.7 host=srv01 user=ubuntu event_kind=invalid_user",
        "[MEDIUM] SSH user enumeration (T1110.001) src=203.0.113.7 host=srv01 group.src_ip=203.0.113.7 events=3",
        BRUTE_FORCE_ALERT,
        "[MEDIUM] SSH login from public IP (T1078, T1021.004) src=203.0.113.7 host=srv01 user=root \
         event_kind=successful_login",
        "[HIGH] SSH login as root (T1078.003) src=203.0.113.7 host=srv01 user=root event_kind=successful_login",
        "[CRITICAL] SSH login after brute force (T1110.001, T1078) src=203.0.113.7 host=srv01 \
         group.src_ip=203.0.113.7 events=11",
    ];
    assert_eq!(alerts.len(), expected_prefixes.len(), "alerts: {alerts:#?}");
    for (alert, prefix) in alerts.iter().zip(expected_prefixes) {
        assert!(alert.starts_with(prefix), "\nalert:  {alert}\nprefix: {prefix}");
    }
    assert!(alerts[3].ends_with("values=oracle,test,ubuntu"));
    assert!(alerts[6].ends_with("message=\"Accepted password for root from 203.0.113.7 port 52100 ssh2\""));
    // The chained alert spans the whole incident: it starts with the burst.
    let first_seen = |alert: &str| {
        alert
            .split(' ')
            .find(|f| f.starts_with("first_seen="))
            .map(str::to_owned)
    };
    assert_eq!(first_seen(&alerts[7]), first_seen(&alerts[4]));
    // 9 sshd rules and 4 sudo rules, which never fire on sshd events.
    assert!(stderr(&output).contains(&format!("minisiem: loaded 13 sigma rules from {rules}")));
    assert!(stderr(&output).contains("alerts=8"));
}

#[test]
fn refuses_to_start_with_a_correlation_referencing_an_unknown_rule() {
    let rules = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rules_bad_reference");

    let output = minisiem(&["--rules", rules, FIXTURE]);

    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).is_empty());
    let message = stderr(&output);
    assert!(
        message.starts_with(&format!(
            "minisiem: {rules}: correlation 'Orphan burst': unknown rule 'missing'"
        )),
        "stderr: {message}"
    );
}

#[test]
fn names_the_invalid_document_of_a_multi_document_file() {
    let rules = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rules_bad_document");

    let output = minisiem(&["--rules", rules, FIXTURE]);

    assert_eq!(output.status.code(), Some(1));
    let message = stderr(&output);
    assert!(
        message.contains("rules_bad_document/pair.yml: document 2: "),
        "stderr: {message}"
    );
    assert!(message.contains("'lt' is not supported"), "stderr: {message}");
}

#[test]
fn loads_rules_recursively_and_ignores_other_files() {
    let rules = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rules_nested");

    let output = minisiem(&["--rules", rules, FIXTURE]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("loaded 1 sigma rules"),
        "stderr: {}",
        stderr(&output)
    );
}

#[test]
fn refuses_to_start_with_an_invalid_rule() {
    let rules = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rules_invalid");

    let output = minisiem(&["--rules", rules, FIXTURE]);

    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).is_empty());
    let message = stderr(&output);
    assert!(message.contains("rules_invalid/bad.yml"), "stderr: {message}");
    assert!(message.contains("unknown field 'CommandLine'"), "stderr: {message}");
}

#[test]
fn fails_with_clear_message_when_rules_dir_is_missing() {
    let output = minisiem(&["--rules", "/nonexistent/rules", FIXTURE]);

    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).is_empty());
    assert!(
        stderr(&output).starts_with("minisiem: /nonexistent/rules:"),
        "stderr: {}",
        stderr(&output)
    );
}

#[test]
fn rejects_zero_threshold() {
    let output = minisiem(&["--threshold", "0", FIXTURE]);

    assert_eq!(output.status.code(), Some(2));
    assert!(stdout(&output).is_empty());
}

/// A fresh directory for one test's database, removed when the test ends.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("minisiem-{name}-{}-{nanos}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        Self(dir)
    }

    fn db(&self) -> String {
        self.0.join("minisiem.db").to_str().unwrap().to_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn count_rows(db: &str, table: &str) -> i64 {
    rusqlite::Connection::open(db)
        .unwrap()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))
        .unwrap()
}

/// Makes every later event write to `db` fail, as a full disk would.
fn break_event_writes(db: &str) {
    rusqlite::Connection::open(db)
        .unwrap()
        .execute_batch("CREATE TRIGGER broken BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'disk is full'); END;")
        .unwrap();
}

#[test]
fn batch_keeps_events_and_alerts_in_the_database_given_with_db_and_prints_the_same() {
    let dir = TempDir::new("batch-db");
    let without = minisiem(&[FIXTURE]);

    let with = minisiem(&["--db", &dir.db(), FIXTURE]);

    assert!(with.status.success(), "stderr: {}", stderr(&with));
    assert_eq!(stdout(&with), stdout(&without));
    assert_eq!(stderr(&with), stderr(&without));
    assert_eq!(count_rows(&dir.db(), "events"), 20);
    let title: String = rusqlite::Connection::open(dir.db())
        .unwrap()
        .query_row("SELECT title FROM alerts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(title, "SSH brute force");
}

#[test]
fn batch_fails_when_the_database_cannot_be_opened() {
    let output = minisiem(&["--db", "/nonexistent/dir/minisiem.db", FIXTURE]);

    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).is_empty());
    assert!(
        stderr(&output).starts_with("minisiem: cannot open database /nonexistent/dir/minisiem.db: "),
        "stderr: {}",
        stderr(&output)
    );
}

#[test]
fn batch_fails_when_writing_to_the_database_fails() {
    let dir = TempDir::new("batch-db-broken");
    assert!(minisiem(&["--db", &dir.db(), FIXTURE]).status.success());
    break_event_writes(&dir.db());

    let output = minisiem(&["--db", &dir.db(), FIXTURE]);

    assert_eq!(output.status.code(), Some(1));
    let expected = format!("cannot write to database {}: disk is full", dir.db());
    assert!(stderr(&output).contains(&expected), "stderr: {}", stderr(&output));
}

/// Starts watch on a free UDP port and returns where to send datagrams.
fn watch_udp(args: &[&str]) -> (Child, Receiver<String>, Receiver<String>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_minisiem"))
        .args(["watch", "--syslog-udp", "127.0.0.1:0"])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = lines_of(child.stdout.take().unwrap());
    let stderr = lines_of(child.stderr.take().unwrap());
    let listening = next_line(&stderr);
    let addr = listening
        .strip_prefix("minisiem: listening for syslog on udp://")
        .unwrap_or_else(|| panic!("unexpected startup line: {listening}"))
        .to_owned();
    (child, stdout, stderr, addr)
}

fn send_failures(addr: &str, count: usize) {
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    for i in 0..count {
        let frame =
            format!("<38>Oct 22 10:15:{i:02} srv01 sshd[1]: Failed password for root from 203.0.113.7 port {i} ssh2");
        sender.send_to(frame.as_bytes(), addr).unwrap();
    }
}

#[test]
fn watch_keeps_events_in_the_database_while_it_runs() {
    let dir = TempDir::new("watch-db");
    let (mut child, stdout, stderr, addr) = watch_udp(&["--threshold", "3", "--db", &dir.db()]);
    let _cleanup = KillOnDrop(child.id());

    send_failures(&addr, 3);
    next_line(&stdout);

    // Readable while watch still runs: a quiet moment commits what was written.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while count_rows(&dir.db(), "events") < 3 || count_rows(&dir.db(), "alerts") < 1 {
        assert!(
            std::time::Instant::now() < deadline,
            "events never reached the database"
        );
        thread::sleep(Duration::from_millis(50));
    }
    interrupt(&child);
    assert_eq!(child.wait().unwrap().code(), Some(0));
    assert_eq!(next_line(&stderr), "minisiem: watch: events=3 alerts=1");
    assert_eq!(count_rows(&dir.db(), "events"), 3);
}

#[test]
fn watch_exits_with_an_error_when_writing_to_the_database_fails() {
    let dir = TempDir::new("watch-db-broken");
    assert!(minisiem(&["--db", &dir.db(), FIXTURE]).status.success());
    break_event_writes(&dir.db());
    let (mut child, _stdout, stderr, addr) = watch_udp(&["--db", &dir.db()]);
    let _cleanup = KillOnDrop(child.id());

    send_failures(&addr, 1);

    let status = wait_at_most(&mut child, Duration::from_secs(10)).expect("watch kept running");
    assert_eq!(status.code(), Some(1));
    let lines: Vec<String> = stderr.iter().collect();
    let expected = format!("minisiem: cannot write to database {}: disk is full", dir.db());
    assert!(lines.contains(&expected), "stderr: {lines:?}");
}

/// Kills a watch the test left running because an assertion failed.
struct KillOnDrop(u32);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if thread::panicking() {
            let _ = Command::new("kill").args(["-KILL", &self.0.to_string()]).status();
        }
    }
}

/// A database holding what batch mode kept of `lines`, with `--threshold 2`.
fn search_db(dir: &TempDir, lines: &[String]) {
    let log = dir.0.join("input.log");
    std::fs::write(&log, lines.join("\n") + "\n").unwrap();
    let output = minisiem(&["--threshold", "2", "--db", &dir.db(), log.to_str().unwrap()]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
}

fn frame(time: &str, host: &str, message: &str) -> String {
    format!("<38>1 {time} {host} sshd 1 - - {message}")
}

fn search_fixture() -> Vec<String> {
    vec![
        frame(
            "2026-10-20T08:00:00Z",
            "srv01",
            "Failed password for root from 203.0.113.7 port 1 ssh2",
        ),
        frame(
            "2026-10-21T09:00:00Z",
            "srv02",
            "Failed password for admin from 198.51.100.2 port 2 ssh2",
        ),
        frame(
            "2026-10-22T10:00:00Z",
            "srv01",
            "Accepted password for root from 198.51.100.2 port 3 ssh2",
        ),
    ]
}

const E1: &str = "2026-10-20T08:00:00+00:00 host=srv01 process=sshd src=203.0.113.7 user=root event_kind=failed_login \
                  message=\"Failed password for root from 203.0.113.7 port 1 ssh2\"";
const E2: &str = "2026-10-21T09:00:00+00:00 host=srv02 process=sshd src=198.51.100.2 user=admin event_kind=failed_login \
                  message=\"Failed password for admin from 198.51.100.2 port 2 ssh2\"";
const E3: &str = "2026-10-22T10:00:00+00:00 host=srv01 process=sshd src=198.51.100.2 user=root \
                  event_kind=successful_login message=\"Accepted password for root from 198.51.100.2 port 3 ssh2\"";

fn search(db: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_minisiem"))
        .args(["search", "--db", db])
        .args(args)
        .env("TZ", "UTC")
        .output()
        .unwrap()
}

fn search_lines(db: &str, args: &[&str]) -> Vec<String> {
    let output = search(db, args);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    stdout(&output).lines().map(str::to_owned).collect()
}

#[test]
fn search_lists_events_oldest_first() {
    let dir = TempDir::new("search-all");
    search_db(&dir, &search_fixture());

    assert_eq!(search_lines(&dir.db(), &["events"]), [E1, E2, E3]);
}

#[test]
fn search_filters_events_by_ip_user_host_and_kind() {
    let dir = TempDir::new("search-filters");
    search_db(&dir, &search_fixture());

    assert_eq!(search_lines(&dir.db(), &["events", "--ip", "198.51.100.2"]), [E2, E3]);
    assert_eq!(search_lines(&dir.db(), &["events", "--user", "root"]), [E1, E3]);
    assert_eq!(search_lines(&dir.db(), &["events", "--host", "srv02"]), [E2]);
    assert_eq!(search_lines(&dir.db(), &["events", "--kind", "successful_login"]), [E3]);
    assert_eq!(
        search_lines(&dir.db(), &["events", "--ip", "198.51.100.2", "--user", "root"]),
        [E3]
    );
}

#[test]
fn search_since_and_until_take_a_time_or_a_date() {
    let dir = TempDir::new("search-times");
    search_db(&dir, &search_fixture());

    assert_eq!(
        search_lines(&dir.db(), &["events", "--since", "2026-10-21T09:00:00Z"]),
        [E2, E3]
    );
    assert_eq!(
        search_lines(&dir.db(), &["events", "--until", "2026-10-21T09:00:00Z"]),
        [E1, E2]
    );
    // A date is midnight, local time (UTC here).
    assert_eq!(
        search_lines(&dir.db(), &["events", "--since", "2026-10-21", "--until", "2026-10-22"]),
        [E2]
    );
}

#[test]
fn search_since_takes_an_age() {
    let dir = TempDir::new("search-age");
    let recent = (chrono::Utc::now() - chrono::Duration::hours(2))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let old = (chrono::Utc::now() - chrono::Duration::days(3))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    search_db(
        &dir,
        &[
            frame(&old, "srv01", "Failed password for root from 203.0.113.7 port 1 ssh2"),
            frame(
                &recent,
                "srv01",
                "Failed password for root from 203.0.113.8 port 2 ssh2",
            ),
        ],
    );

    let lines = search_lines(&dir.db(), &["events", "--since", "1d"]);
    assert_eq!(lines.len(), 1, "lines: {lines:?}");
    assert!(lines[0].contains("src=203.0.113.8"), "lines: {lines:?}");
    assert_eq!(search_lines(&dir.db(), &["events", "--since", "4d"]).len(), 2);
    assert_eq!(search_lines(&dir.db(), &["events", "--until", "1d"]).len(), 1);
}

#[test]
fn search_lists_alerts_as_the_console_prints_them() {
    let dir = TempDir::new("search-alerts");
    let mut lines = search_fixture();
    lines.push(frame(
        "2026-10-22T10:05:00Z",
        "srv01",
        "Failed password for root from 203.0.113.7 port 4 ssh2",
    ));
    let log = dir.0.join("input.log");
    std::fs::write(&log, lines.join("\n") + "\n").unwrap();
    let batch = minisiem(&[
        "--threshold",
        "2",
        "--window",
        "604800",
        "--db",
        &dir.db(),
        log.to_str().unwrap(),
    ]);
    let printed: Vec<String> = stdout(&batch).lines().map(str::to_owned).collect();
    assert_eq!(printed.len(), 1, "alerts: {printed:?}");

    assert_eq!(search_lines(&dir.db(), &["alerts"]), printed);
    assert_eq!(
        search_lines(&dir.db(), &["alerts", "--ip", "203.0.113.7", "--host", "srv01"]),
        printed
    );
    assert!(search_lines(&dir.db(), &["alerts", "--ip", "198.51.100.2"]).is_empty());
    assert!(search_lines(&dir.db(), &["alerts", "--until", "2026-10-22T10:04:59Z"]).is_empty());
}

#[test]
fn search_refuses_event_only_filters_for_alerts() {
    let dir = TempDir::new("search-alert-filters");
    search_db(&dir, &search_fixture());

    for filter in [["--user", "root"], ["--kind", "failed_login"]] {
        let output = search(&dir.db(), &["alerts", filter[0], filter[1]]);
        assert_eq!(output.status.code(), Some(2), "filter: {filter:?}");
        assert!(
            stderr(&output).contains(&format!("{} only filters events", filter[0])),
            "stderr: {}",
            stderr(&output)
        );
    }
}

#[test]
fn search_rejects_invalid_filters() {
    let dir = TempDir::new("search-invalid");
    search_db(&dir, &search_fixture());

    for args in [
        ["events", "--since", "yesterday"],
        ["events", "--kind", "logout"],
        ["events", "--ip", "not-an-ip"],
    ] {
        let output = search(&dir.db(), &args);
        assert_eq!(output.status.code(), Some(2), "args: {args:?}");
        assert!(stdout(&output).is_empty());
        assert!(
            stderr(&output).contains(&format!("invalid value '{}' for '{}", args[2], args[1])),
            "stderr: {}",
            stderr(&output)
        );
    }
}

#[test]
fn search_fails_without_creating_a_missing_database() {
    let dir = TempDir::new("search-missing");

    let output = search(&dir.db(), &["events"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).starts_with(&format!("minisiem: cannot open database {}: ", dir.db())),
        "stderr: {}",
        stderr(&output)
    );
    assert!(!std::path::Path::new(&dir.db()).exists());
}

/// A database with one event 40 days old and one a day old.
fn retention_db(dir: &TempDir) {
    let at = |days| {
        (chrono::Utc::now() - chrono::Duration::days(days))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    };
    search_db(
        dir,
        &[
            frame(
                &at(40),
                "srv01",
                "Failed password for root from 203.0.113.7 port 1 ssh2",
            ),
            frame(&at(1), "srv01", "Failed password for root from 203.0.113.8 port 2 ssh2"),
        ],
    );
}

#[test]
fn watch_retain_days_deletes_older_events_when_it_starts() {
    let dir = TempDir::new("retain");
    retention_db(&dir);

    let (mut child, _stdout, _stderr, _addr) = watch_udp(&["--db", &dir.db(), "--retain-days", "30"]);
    let _cleanup = KillOnDrop(child.id());

    // Deleted before watch starts listening.
    let kept = search_lines(&dir.db(), &["events"]);
    assert_eq!(kept.len(), 1, "events: {kept:?}");
    assert!(kept[0].contains("src=203.0.113.8"), "events: {kept:?}");
    interrupt(&child);
    assert_eq!(child.wait().unwrap().code(), Some(0));
}

#[test]
fn watch_without_retain_days_deletes_nothing() {
    let dir = TempDir::new("retain-none");
    retention_db(&dir);

    let (mut child, _stdout, _stderr, _addr) = watch_udp(&["--db", &dir.db()]);
    let _cleanup = KillOnDrop(child.id());
    interrupt(&child);
    assert_eq!(child.wait().unwrap().code(), Some(0));

    assert_eq!(search_lines(&dir.db(), &["events"]).len(), 2);
}

#[test]
fn retain_days_needs_a_database_and_at_least_one_day() {
    let dir = TempDir::new("retain-invalid");
    let db = dir.db();
    let cases = [
        (
            vec!["--retain-days", "30"],
            "required arguments were not provided:\n  --db <PATH>",
        ),
        (
            vec!["--db", &db, "--retain-days", "0"],
            "invalid value '0' for '--retain-days <DAYS>'",
        ),
    ];
    for (args, expected) in cases {
        let output = minisiem(&[&["watch", "--syslog-udp", "127.0.0.1:0"], &args[..]].concat());
        assert_eq!(output.status.code(), Some(2), "args: {args:?}");
        assert!(stderr(&output).contains(expected), "stderr: {}", stderr(&output));
    }
    assert!(!std::path::Path::new(&db).exists());
}

const SUDO_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sudo.log");

#[test]
fn keeps_sudo_commands_refusals_and_password_failures() {
    let dir = TempDir::new("sudo");

    let output = minisiem(&["--db", &dir.db(), SUDO_FIXTURE]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).is_empty(), "stdout: {}", stdout(&output));
    assert!(
        stderr(&output).contains("lines=5 events=3 alerts=0"),
        "stderr: {}",
        stderr(&output)
    );
    let lines = search_lines(&dir.db(), &["events"]);
    let kinds: Vec<&str> = lines
        .iter()
        .map(|line| line.split(" event_kind=").nth(1).unwrap().split(' ').next().unwrap())
        .collect();
    assert_eq!(kinds, ["sudo_command", "sudo_denied", "sudo_failed_password"]);
    assert!(
        lines[1].contains(" host=srv01 process=sudo src=- user=bob "),
        "{}",
        lines[1]
    );
    assert_eq!(
        search_lines(&dir.db(), &["events", "--kind", "sudo_denied", "--user", "bob"]).len(),
        1
    );
    let stored: (String, String) = rusqlite::Connection::open(dir.db())
        .unwrap()
        .query_row(
            "SELECT target_user, command FROM events WHERE kind = 'sudo_command'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(stored, ("root".into(), "/usr/bin/systemctl restart nginx".into()));
}

#[test]
fn shipped_sudo_rules_detect_privilege_escalation_attempts() {
    let rules = concat!(env!("CARGO_MANIFEST_DIR"), "/rules");
    let attack = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sudo_attack.log");

    let output = minisiem(&["--rules", rules, attack]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let alerts: Vec<_> = stdout(&output).lines().map(str::to_owned).collect();
    let expected_prefixes = [
        // The third summary of failures by one user within 10 minutes;
        // hector's single failure does not count towards it.
        "[MEDIUM] sudo password guessing (T1548.003, T1110.001) host=srv01 group.user=mallory events=3",
        // "command not allowed" is a refusal too, but not this rule's.
        "[HIGH] sudo by a user not in sudoers (T1548.003) host=srv01 user=mallory event_kind=sudo_denied",
        "[MEDIUM] Shell as root through sudo (T1548.003) host=srv01 user=hector event_kind=sudo_command",
        // A shell as postgres is not a root shell.
        "[MEDIUM] Shell as root through sudo (T1548.003) host=srv01 user=hector event_kind=sudo_command",
    ];
    assert_eq!(alerts.len(), expected_prefixes.len(), "alerts: {alerts:#?}");
    for (alert, prefix) in alerts.iter().zip(expected_prefixes) {
        assert!(alert.starts_with(prefix), "\nalert:  {alert}\nprefix: {prefix}");
    }
    assert!(alerts[2].contains("COMMAND=/bin/bash"), "{}", alerts[2]);
    assert!(alerts[3].contains("COMMAND=/usr/bin/su -"), "{}", alerts[3]);
    assert!(
        stderr(&output).contains("lines=10 events=10 alerts=4"),
        "stderr: {}",
        stderr(&output)
    );
}
