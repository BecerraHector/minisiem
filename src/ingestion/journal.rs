//! journald entries as printed by `journalctl -o json` (one JSON object per line).

use chrono::DateTime;
use serde_json::{Map, Value};

use super::LogParser;
use super::sshd::{SSHD_PROCESSES, sshd_event};
use crate::event::Event;

/// Parses journald JSON entries written by OpenSSH.
///
/// Only fields starting with `_` are set by journald itself; the others
/// (`SYSLOG_IDENTIFIER`, `MESSAGE`, ...) are chosen by whoever logged the
/// entry. The process is therefore identified by the trusted `_COMM`: any
/// local user can run `logger -t sshd "Failed password ..."`, but cannot fake
/// the name of the process that wrote it.
pub struct JournalParser;

impl LogParser for JournalParser {
    fn parse(&self, line: &str) -> Option<Event> {
        let entry: Map<String, Value> = serde_json::from_str(line).ok()?;

        let process = entry.get("_COMM")?.as_str()?;
        if !SSHD_PROCESSES.contains(&process) {
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

    /// A journal entry as `journalctl -o json` prints it (all values strings).
    fn entry(comm: &str, message: serde_json::Value) -> String {
        json!({
            "__REALTIME_TIMESTAMP": "1792667732123456",
            "_HOSTNAME": "srv01",
            "_COMM": comm,
            "_PID": "4321",
            "_UID": "0",
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
                src_ip: "203.0.113.7".parse().unwrap(),
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
    fn identifies_sshd_by_the_trusted_comm_field() {
        let message = json!("Failed password for root from 203.0.113.7 port 1 ssh2");

        // `logger -t sshd ...`: the identifier says sshd, the process does not.
        assert_eq!(JournalParser.parse(&entry("logger", message.clone())), None);
        assert!(JournalParser.parse(&entry("sshd-auth", message)).is_some());
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
