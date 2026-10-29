//! journald entries as printed by `journalctl -o json` (one JSON object per line).

use std::path::{Component, Path, PathBuf};

use chrono::DateTime;
use serde_json::{Map, Value};

use super::LogParser;
use super::sshd::{SSHD_PROCESSES, sshd_event};
use crate::event::Event;

/// Parses journald JSON entries written by OpenSSH.
///
/// Only fields starting with `_` are set by journald itself; the others
/// (`SYSLOG_IDENTIFIER`, `MESSAGE`, ...) are chosen by whoever logged the
/// entry, e.g. `logger -t sshd "Failed password ..."`. Even the trusted
/// `_COMM` is just the executable's name, which a user controls by copying
/// any binary to `~/sshd`. So the entry must also come from an sshd binary
/// under `/usr/` (`_EXE`), where unprivileged users cannot write, running as
/// root (`_UID`): a user can still start an installed sshd binary with
/// `LD_PRELOAD`, but only as themselves. sshd logs the messages we detect
/// from its privileged monitor, which runs as root; the unprivileged child
/// forwards its logs to the monitor.
pub struct JournalParser;

impl LogParser for JournalParser {
    fn parse(&self, line: &str) -> Option<Event> {
        let entry: Map<String, Value> = serde_json::from_str(line).ok()?;

        let process = entry.get("_COMM")?.as_str()?;
        let executable = entry.get("_EXE")?.as_str()?;
        let uid = entry.get("_UID")?.as_str()?;
        if !SSHD_PROCESSES.contains(&process) || !is_installed_sshd(executable) || uid != "0" {
            return None;
        }
        // Microseconds since the epoch, set by journald on reception.
        let micros: i64 = entry.get("__REALTIME_TIMESTAMP")?.as_str()?.parse().ok()?;
        let timestamp = DateTime::from_timestamp_micros(micros)?;
        let host = entry.get("_HOSTNAME").and_then(Value::as_str).unwrap_or_default();
        let message = message_text(entry.get("MESSAGE")?)?;

        sshd_event(timestamp, host, process, &message)
    }
}

/// True for an sshd binary under `/usr/`, e.g. `/usr/sbin/sshd` or
/// `/usr/lib/openssh/sshd-session`. `..` is refused so a path cannot climb
/// out of `/usr/`, and so are spellings journald never records (`/./`, `//`,
/// a trailing `/`).
fn is_installed_sshd(executable: &str) -> bool {
    let path = Path::new(executable);
    path.starts_with("/usr")
        && path.components().collect::<PathBuf>().as_os_str() == executable
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| SSHD_PROCESSES.contains(&name))
}

/// `MESSAGE` is a string, or an array of byte values when it is not valid
/// UTF-8.
fn message_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Array(items) => {
            let bytes: Option<Vec<u8>> = items
                .iter()
                .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            Some(String::from_utf8_lossy(&bytes?).into_owned())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventKind, LogSource};
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    /// A journal entry from the real `/usr/lib/ssh/<comm>` binary.
    fn entry(comm: &str, message: serde_json::Value) -> String {
        entry_with_exe(comm, &format!("/usr/lib/ssh/{comm}"), message)
    }

    /// A journal entry logged by root.
    fn entry_with_exe(comm: &str, exe: &str, message: serde_json::Value) -> String {
        entry_with_uid(comm, exe, "0", message)
    }

    /// A journal entry as `journalctl -o json` prints it (all values strings).
    fn entry_with_uid(comm: &str, exe: &str, uid: &str, message: serde_json::Value) -> String {
        json!({
            "__REALTIME_TIMESTAMP": "1792667732123456",
            "_HOSTNAME": "srv01",
            "_COMM": comm,
            "_EXE": exe,
            "_PID": "4321",
            "_UID": uid,
            "SYSLOG_IDENTIFIER": "sshd-session",
            "MESSAGE": message,
        })
        .to_string()
    }

    #[test]
    fn parses_an_sshd_entry() {
        let line = entry(
            "sshd-session",
            json!("Failed password for root from 203.0.113.7 port 52211 ssh2"),
        );

        assert_eq!(
            JournalParser.parse(&line),
            Some(Event {
                timestamp: Utc.timestamp_micros(1_792_667_732_123_456).unwrap(),
                host: "srv01".into(),
                process: "sshd-session".into(),
                kind: EventKind::FailedLogin,
                user: "root".into(),
                src_ip: Some("203.0.113.7".parse().unwrap()),
                message: "Failed password for root from 203.0.113.7 port 52211 ssh2".into(),
                logsource: LogSource::new("linux", "sshd"),
            })
        );
    }

    #[test]
    fn decodes_messages_journald_stored_as_bytes() {
        // journald exports non-UTF-8 messages as an array of byte values.
        let mut bytes: Vec<u8> = b"Invalid user ".to_vec();
        bytes.extend([0xff, 0xfe]);
        bytes.extend(b" from 203.0.113.7 port 1");
        let line = entry("sshd", json!(bytes));

        let event = JournalParser
            .parse(&line)
            .expect("byte messages are still sshd messages");

        assert_eq!(event.kind, EventKind::InvalidUser);
        assert_eq!(event.user, "\u{fffd}\u{fffd}");
    }

    #[test]
    fn takes_the_real_source_ip_when_the_username_injects_another() {
        let line = entry(
            "sshd-session",
            json!("Failed password for invalid user x from 198.51.100.9 port 1 from 203.0.113.7 port 40000 ssh2"),
        );

        let event = JournalParser.parse(&line).expect("still an sshd event");

        assert_eq!(event.src_ip, Some("203.0.113.7".parse::<std::net::IpAddr>().unwrap()));
        assert_eq!(event.user, "x from 198.51.100.9 port 1");
    }

    #[test]
    fn identifies_sshd_by_the_trusted_comm_field() {
        let message = json!("Failed password for root from 203.0.113.7 port 1 ssh2");

        // `logger -t sshd ...`: the identifier says sshd, the process does not.
        assert_eq!(JournalParser.parse(&entry("logger", message.clone())), None);
        assert!(JournalParser.parse(&entry("sshd-auth", message)).is_some());
    }

    #[test]
    fn rejects_sshd_named_binaries_outside_root_owned_paths() {
        let message = json!("Failed password for root from 203.0.113.7 port 1 ssh2");
        // `cp /usr/bin/logger ~/sshd && ~/sshd "Failed password ..."` makes
        // journald record _COMM=sshd; only _EXE tells where it came from.
        let spoofed = [
            entry_with_exe("sshd", "/home/mallory/sshd", message.clone()),
            entry_with_exe("sshd", "/tmp/sshd", message.clone()),
            entry_with_exe("sshd", "/usr/../home/mallory/sshd", message.clone()),
            entry_with_exe("sshd", "/usr/bin/logger", message.clone()),
            json!({"__REALTIME_TIMESTAMP": "1792667732123456", "_COMM": "sshd", "MESSAGE": message.clone()})
                .to_string(),
        ];

        for line in spoofed {
            assert_eq!(JournalParser.parse(&line), None, "should be rejected: {line}");
        }
    }

    #[test]
    fn accepts_only_the_plain_spelling_of_an_sshd_path() {
        // journald records the resolved path: other spellings never come
        // from it.
        for exe in [
            "/usr/./sbin/sshd",
            "/usr//sbin/sshd",
            "/usr/sbin/sshd/",
            "/usr/sbin/./sshd",
        ] {
            assert!(!is_installed_sshd(exe), "should be rejected: {exe}");
        }
        assert!(is_installed_sshd("/usr/sbin/sshd"));
    }

    #[test]
    fn rejects_installed_sshd_binaries_not_running_as_root() {
        let message = json!("Failed password for root from 203.0.113.7 port 1 ssh2");
        // `LD_PRELOAD=~/fake.so /usr/lib/ssh/sshd-auth` logs with a genuine
        // _EXE and _COMM, but as the user who ran it.
        let spoofed = [
            entry_with_uid("sshd-auth", "/usr/lib/ssh/sshd-auth", "1000", message.clone()),
            entry_with_uid("sshd-session", "/usr/lib/ssh/sshd-session", "1000", message.clone()),
            entry_with_uid("sshd", "/usr/sbin/sshd", "00", message.clone()),
            json!({"__REALTIME_TIMESTAMP": "1792667732123456", "_COMM": "sshd",
                   "_EXE": "/usr/sbin/sshd", "MESSAGE": message.clone()})
            .to_string(),
        ];

        for line in spoofed {
            assert_eq!(JournalParser.parse(&line), None, "should be rejected: {line}");
        }
    }

    #[test]
    fn accepts_sshd_binaries_where_distributions_install_them() {
        let message = json!("Failed password for root from 203.0.113.7 port 1 ssh2");
        let installs = [
            ("sshd", "/usr/sbin/sshd"),
            ("sshd", "/usr/bin/sshd"),
            ("sshd-session", "/usr/lib/openssh/sshd-session"),
            ("sshd-session", "/usr/libexec/openssh/sshd-session"),
            ("sshd-auth", "/usr/lib/ssh/sshd-auth"),
            // Built from source (default prefix); still has to run as root.
            ("sshd-session", "/usr/local/libexec/sshd-session"),
        ];

        for (comm, exe) in installs {
            assert!(
                JournalParser
                    .parse(&entry_with_exe(comm, exe, message.clone()))
                    .is_some(),
                "should accept {exe}"
            );
        }
    }

    #[test]
    fn ignores_irrelevant_or_malformed_entries() {
        let lines = [
            entry("sshd", json!("Server listening on 0.0.0.0 port 22.")),
            entry("sshd", json!(42)),
            json!({"_COMM": "sshd", "MESSAGE": "Failed password for root from 203.0.113.7 port 1 ssh2"}).to_string(),
            json!({"__REALTIME_TIMESTAMP": "soon", "_COMM": "sshd",
                   "MESSAGE": "Failed password for root from 203.0.113.7 port 1 ssh2"})
            .to_string(),
            "{not json".to_string(),
            "[1, 2, 3]".to_string(),
        ];

        for line in lines {
            assert_eq!(JournalParser.parse(&line), None, "should be ignored: {line}");
        }
    }
}
