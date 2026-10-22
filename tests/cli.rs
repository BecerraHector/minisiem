use std::io::Write;
use std::process::{Command, Output, Stdio};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/auth.log");
const BRUTE_FORCE_ALERT: &str = "[HIGH] SSH brute force (T1110.001 Password Guessing) src=203.0.113.7 host=srv01 \
                                 failures=10 users=admin,oracle,root,test,ubuntu";

fn minisiem(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_minisiem")).args(args).output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn detects_brute_force_in_a_log_file() {
    let output = minisiem(&[FIXTURE]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let alerts: Vec<_> = stdout(&output).lines().map(str::to_owned).collect();
    assert_eq!(alerts.len(), 1, "alerts: {alerts:?}");
    assert!(alerts[0].starts_with(BRUTE_FORCE_ALERT), "alert: {}", alerts[0]);
    assert!(stderr(&output).contains("lines=23 events=20 alerts=1"), "stderr: {}", stderr(&output));
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
    assert!(stderr(&output).starts_with("minisiem: /nonexistent/auth.log:"), "stderr: {}", stderr(&output));
}

#[test]
fn rejects_zero_threshold() {
    let output = minisiem(&["--threshold", "0", FIXTURE]);

    assert_eq!(output.status.code(), Some(2));
    assert!(stdout(&output).is_empty());
}
