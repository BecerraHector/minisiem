use std::io::{BufRead, BufReader, Read, Write};
use std::net::UdpSocket;
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

#[test]
fn ctrl_c_in_a_terminal_does_not_reach_journalctl() {
    // A terminal sends Ctrl+C to the whole foreground process group. If it
    // reached journalctl too, its exit could be reported as a failure.
    let marker = std::env::temp_dir().join(format!("minisiem-ctrl-c-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
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
    let stderr = lines_of(child.stderr.take().unwrap());
    assert_eq!(
        next_line(&stderr),
        "minisiem: following journald (sshd, sshd-session, sshd-auth)"
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
    let _ = std::fs::remove_file(&marker);

    let status = Command::new("kill")
        .args(["-INT", "--", &format!("-{}", child.id())])
        .status()
        .unwrap();
    assert!(status.success());

    assert_eq!(child.wait().unwrap().code(), Some(0));
    assert_ne!(
        journalctl_group.trim(),
        child.id().to_string(),
        "journalctl is in minisiem's process group, so a terminal's Ctrl+C reaches it"
    );
}

#[test]
fn watch_follows_journald_and_stops_cleanly_on_interrupt() {
    let mut child = watch_journal("follow.sh");
    let stdout = lines_of(child.stdout.take().unwrap());
    let stderr = lines_of(child.stderr.take().unwrap());

    assert_eq!(
        next_line(&stderr),
        "minisiem: following journald (sshd, sshd-session, sshd-auth)"
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
    assert!(stderr(&output).contains(&format!("minisiem: loaded 9 sigma rules from {rules}")));
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
