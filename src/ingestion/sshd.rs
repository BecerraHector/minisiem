use std::net::IpAddr;
use std::sync::LazyLock;

use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};
use regex::Regex;

use super::LogParser;
use crate::event::{Event, EventKind};

/// `<timestamp> <host> <sshd|sshd-session>[pid]: <message>`
static HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\S+)|(?P<bsd>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2})) (?P<host>\S+) (?P<process>sshd(?:-session)?)\[\d+\]: (?P<message>.+)$",
    )
    .unwrap()
});

static FAILED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Failed \S+ for (?:invalid user )?(?P<user>\S*) from (?P<ip>\S+) port \d+").unwrap()
});

static INVALID_USER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+) port \d+").unwrap());

static ACCEPTED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port \d+").unwrap());

/// Parses OpenSSH server lines from syslog files (`/var/log/auth.log`,
/// `/var/log/secure`) or `journalctl -o short-iso` output.
///
/// Classic syslog timestamps (`Oct 22 10:15:32`) carry neither year nor
/// timezone, so both are supplied by the caller.
pub struct SshdParser {
    year: i32,
    offset: FixedOffset,
}

impl SshdParser {
    pub fn new(year: i32, offset: FixedOffset) -> Self {
        Self { year, offset }
    }

    fn parse_timestamp(&self, iso: Option<&str>, bsd: Option<&str>) -> Option<DateTime<Utc>> {
        if let Some(iso) = iso {
            return DateTime::parse_from_str(iso, "%Y-%m-%dT%H:%M:%S%.f%z")
                .ok()
                .map(|ts| ts.with_timezone(&Utc));
        }

        // Collapse the space padding of single-digit days ("Oct  2").
        let bsd = bsd?.split_whitespace().collect::<Vec<_>>().join(" ");
        let naive = NaiveDateTime::parse_from_str(&format!("{} {bsd}", self.year), "%Y %b %d %H:%M:%S").ok()?;
        self.offset
            .from_local_datetime(&naive)
            .single()
            .map(|ts| ts.with_timezone(&Utc))
    }
}

/// Classifies an sshd message into an event kind, user and source IP.
fn classify(message: &str) -> Option<(EventKind, &str, IpAddr)> {
    let rules = [
        (&*FAILED, EventKind::FailedLogin),
        (&*INVALID_USER, EventKind::InvalidUser),
        (&*ACCEPTED, EventKind::SuccessfulLogin),
    ];

    rules.into_iter().find_map(|(regex, kind)| {
        let caps = regex.captures(message)?;
        let ip = caps.name("ip")?.as_str().parse().ok()?;
        Some((kind, caps.name("user")?.as_str(), ip))
    })
}

impl LogParser for SshdParser {
    fn parse(&self, line: &str) -> Option<Event> {
        let header = HEADER.captures(line)?;
        let (kind, user, src_ip) = classify(header.name("message")?.as_str())?;
        let timestamp = self.parse_timestamp(
            header.name("iso").map(|m| m.as_str()),
            header.name("bsd").map(|m| m.as_str()),
        )?;

        Some(Event {
            timestamp,
            host: header["host"].to_string(),
            process: header["process"].to_string(),
            kind,
            user: user.to_string(),
            src_ip,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventKind;
    use chrono::{TimeZone, Utc};

    fn parser() -> SshdParser {
        SshdParser::new(2026, FixedOffset::west_opt(5 * 3600).unwrap())
    }

    #[test]
    fn parses_failed_password_in_syslog_format() {
        let line = "Oct 22 10:15:32 srv01 sshd[1234]: Failed password for root from 203.0.113.7 port 52211 ssh2";

        let event = parser().parse(line).expect("line should parse");

        assert_eq!(
            event,
            Event {
                // 10:15:32 at UTC-5 is 15:15:32 UTC.
                timestamp: Utc.with_ymd_and_hms(2026, 10, 22, 15, 15, 32).unwrap(),
                host: "srv01".into(),
                process: "sshd".into(),
                kind: EventKind::FailedLogin,
                user: "root".into(),
                src_ip: "203.0.113.7".parse().unwrap(),
            }
        );
    }

    #[test]
    fn parses_failed_password_for_invalid_user() {
        let line = "Oct 22 10:15:33 srv01 sshd[1235]: Failed password for invalid user oracle from 203.0.113.7 port 52212 ssh2";

        let event = parser().parse(line).unwrap();

        assert_eq!(event.kind, EventKind::FailedLogin);
        assert_eq!(event.user, "oracle");
    }

    #[test]
    fn parses_invalid_user() {
        let line = "Oct 22 10:15:33 srv01 sshd[1235]: Invalid user oracle from 203.0.113.7 port 52212";

        let event = parser().parse(line).unwrap();

        assert_eq!(event.kind, EventKind::InvalidUser);
        assert_eq!(event.user, "oracle");
    }

    #[test]
    fn parses_accepted_publickey() {
        let line = "Oct 22 09:00:01 srv01 sshd[999]: Accepted publickey for hector from 192.168.1.10 port 40022 ssh2: ED25519 SHA256:abc";

        let event = parser().parse(line).unwrap();

        assert_eq!(event.kind, EventKind::SuccessfulLogin);
        assert_eq!(event.user, "hector");
        assert_eq!(event.src_ip, "192.168.1.10".parse::<std::net::IpAddr>().unwrap());
    }

    #[test]
    fn parses_single_digit_day_padded_with_space() {
        let line = "Oct  2 10:15:32 srv01 sshd[1234]: Failed password for root from 203.0.113.7 port 52211 ssh2";

        let event = parser().parse(line).unwrap();

        assert_eq!(event.timestamp, Utc.with_ymd_and_hms(2026, 10, 2, 15, 15, 32).unwrap());
    }

    #[test]
    fn parses_iso_timestamp_and_sshd_session_process() {
        // OpenSSH >= 9.8 logs per-connection messages as `sshd-session`.
        let line = "2026-10-22T10:15:32-05:00 srv01 sshd-session[4321]: Failed password for root from 203.0.113.7 port 52211 ssh2";

        let event = parser().parse(line).unwrap();

        assert_eq!(event.timestamp, Utc.with_ymd_and_hms(2026, 10, 22, 15, 15, 32).unwrap());
        assert_eq!(event.process, "sshd-session");
    }

    #[test]
    fn parses_iso_timestamp_with_fraction_and_compact_offset() {
        let line = "2026-10-22T10:15:32.123456+0000 srv01 sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2";

        let event = parser().parse(line).unwrap();

        assert_eq!(event.timestamp.timestamp(), Utc.with_ymd_and_hms(2026, 10, 22, 10, 15, 32).unwrap().timestamp());
    }

    #[test]
    fn parses_ipv6_source() {
        let line = "Oct 22 10:15:32 srv01 sshd[1]: Failed password for root from 2001:db8::7 port 1 ssh2";

        let event = parser().parse(line).unwrap();

        assert_eq!(event.src_ip, "2001:db8::7".parse::<std::net::IpAddr>().unwrap());
    }

    #[test]
    fn ignores_irrelevant_or_malformed_lines() {
        let lines = [
            "",
            "garbage",
            "Oct 22 10:17:01 srv01 CRON[2001]: pam_unix(cron:session): session opened for user root(uid=0)",
            "Oct 22 10:15:40 srv01 sshd[1236]: Connection closed by authenticating user root 203.0.113.7 port 52213 [preauth]",
            "Oct 22 10:15:32 srv01 sshd[1234]: Failed password for root from not-an-ip port 52211 ssh2",
            "Foo 22 10:15:32 srv01 sshd[1234]: Failed password for root from 203.0.113.7 port 52211 ssh2",
            // A forged message from another process must not be trusted as sshd.
            "Oct 22 10:15:32 srv01 evil[1]: Failed password for root from 203.0.113.7 port 1 ssh2",
        ];

        for line in lines {
            assert_eq!(parser().parse(line), None, "line should be ignored: {line:?}");
        }
    }
}
