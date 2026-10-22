use std::io::{self, Write};

use super::AlertSink;
use crate::alert::Alert;

/// Writes one human-readable line per alert.
pub struct ConsoleSink<W: Write> {
    out: W,
}

impl<W: Write> ConsoleSink<W> {
    pub fn new(out: W) -> Self {
        Self { out }
    }
}

impl<W: Write> AlertSink for ConsoleSink<W> {
    fn emit(&mut self, alert: &Alert) -> io::Result<()> {
        writeln!(
            self.out,
            "[{}] {} ({} {}) src={} host={} failures={} users={} first_seen={} last_seen={}",
            alert.severity,
            alert.title,
            alert.technique.id,
            alert.technique.name,
            alert.src_ip,
            alert.host,
            alert.event_count,
            alert.users.join(","),
            alert.first_seen.to_rfc3339(),
            alert.last_seen.to_rfc3339(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{MitreTechnique, Severity};
    use chrono::{TimeZone, Utc};

    #[test]
    fn writes_one_line_per_alert() {
        let alert = Alert {
            rule_id: "ssh-brute-force",
            title: "SSH brute force",
            severity: Severity::High,
            technique: MitreTechnique { id: "T1110.001", name: "Password Guessing", tactic: "Credential Access" },
            src_ip: "203.0.113.7".parse().unwrap(),
            host: "srv01".into(),
            event_count: 3,
            first_seen: Utc.with_ymd_and_hms(2026, 10, 22, 10, 0, 0).unwrap(),
            last_seen: Utc.with_ymd_and_hms(2026, 10, 22, 10, 1, 0).unwrap(),
            users: vec!["admin".into(), "root".into()],
        };
        let mut sink = ConsoleSink::new(Vec::new());

        sink.emit(&alert).unwrap();

        assert_eq!(
            String::from_utf8(sink.out).unwrap(),
            "[HIGH] SSH brute force (T1110.001 Password Guessing) src=203.0.113.7 host=srv01 failures=3 \
             users=admin,root first_seen=2026-10-22T10:00:00+00:00 last_seen=2026-10-22T10:01:00+00:00\n"
        );
    }
}
