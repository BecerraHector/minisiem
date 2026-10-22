use std::io::Write;
use std::process::{Command, Output, Stdio};

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
