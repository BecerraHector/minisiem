use std::net::IpAddr;
use std::sync::LazyLock;

use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};
use regex::Regex;

use super::LogParser;
use crate::event::{Event, EventKind, LogSource};

/// OpenSSH server processes. Since OpenSSH 9.8 per-connection messages come
/// from `sshd-session`; 10.0 split authentication into `sshd-auth`.
pub const SSHD_PROCESSES: [&str; 3] = ["sshd", "sshd-session", "sshd-auth"];

/// `<timestamp> <host> <sshd|sshd-session|sshd-auth>[pid]: <message>`
static HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\S+)|(?P<bsd>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2})) (?P<host>\S+) (?P<process>sshd(?:-session|-auth)?)\[\d+\]: (?P<message>.+)$",
    )
    .unwrap()
});

// sshd logs text the client chose on either side of the source IP, unescaped,
// so it can contain a fake ` from <ip> port <n>`. Before the IP only for
// invalid users: the client picks the name, but cannot pick an existing
// account's. After the IP only for valid users: OpenSSH appends key or
// hostbased details (a certificate ID, a client host name) once the user is
// valid. So invalid-user patterns take the last `from`, and valid-user
// patterns, whose name is a single word, take the first.
static FAILED_INVALID_USER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^Failed \S+ for invalid user (?P<user>.*) from (?P<ip>\S+) port \d+").unwrap());

static FAILED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^Failed \S+ for (?P<user>\S+) from (?P<ip>\S+) port \d+").unwrap());

static INVALID_USER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^Invalid user (?P<user>.*) from (?P<ip>\S+) port \d+").unwrap());

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
        (&*FAILED_INVALID_USER, EventKind::FailedLogin),
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

/// Builds an event from an sshd message, whatever format carried it.
/// Returns `None` for messages that are not about authentication.
pub(super) fn sshd_event(timestamp: DateTime<Utc>, host: &str, process: &str, message: &str) -> Option<Event> {
    let (kind, user, src_ip) = classify(message)?;
    Some(Event {
        timestamp,
        host: host.to_string(),
        process: process.to_string(),
        kind,
        user: user.to_string(),
        src_ip: Some(src_ip),
        message: message.to_string(),
        logsource: LogSource::new("linux", "sshd"),
    })
}

impl LogParser for SshdParser {
    fn parse(&self, line: &str) -> Option<Event> {
        let header = HEADER.captures(line)?;
        let timestamp = self.parse_timestamp(
            header.name("iso").map(|m| m.as_str()),
            header.name("bsd").map(|m| m.as_str()),
        )?;
        sshd_event(timestamp, &header["host"], &header["process"], &header["message"])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
                src_ip: Some("203.0.113.7".parse().unwrap()),
                message: "Failed password for root from 203.0.113.7 port 52211 ssh2".into(),
                logsource: LogSource::new("linux", "sshd"),
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
        assert_eq!(event.src_ip, Some("192.168.1.10".parse::<std::net::IpAddr>().unwrap()));
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
        let line =
            "2026-10-22T10:15:32.123456+0000 srv01 sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2";

        let event = parser().parse(line).unwrap();

        assert_eq!(
            event.timestamp.timestamp(),
            Utc.with_ymd_and_hms(2026, 10, 22, 10, 15, 32).unwrap().timestamp()
        );
    }

    #[test]
    fn parses_ipv6_source() {
        let line = "Oct 22 10:15:32 srv01 sshd[1]: Failed password for root from 2001:db8::7 port 1 ssh2";

        let event = parser().parse(line).unwrap();

        assert_eq!(event.src_ip, Some("2001:db8::7".parse::<std::net::IpAddr>().unwrap()));
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

    /// Kind, user and source IP parsed from an sshd message.
    fn classified(message: &str) -> (EventKind, String, IpAddr) {
        let event = parser()
            .parse(&format!("Oct 22 10:15:32 srv01 sshd[1]: {message}"))
            .expect("should be an sshd event");
        (
            event.kind,
            event.user,
            event.src_ip.expect("sshd events have a source IP"),
        )
    }

    #[test]
    fn takes_the_source_ip_after_an_invalid_username_that_injects_another() {
        // sshd logs the username unescaped. Names with spaces never match a
        // real account, so the injection only reaches invalid-user messages.
        let real: IpAddr = "203.0.113.7".parse().unwrap();
        let injected = "x from 198.51.100.9 port 1 ssh2";

        assert_eq!(
            classified(&format!(
                "Failed password for invalid user {injected} from 203.0.113.7 port 40000 ssh2"
            )),
            (EventKind::FailedLogin, injected.to_string(), real)
        );
        assert_eq!(
            classified(&format!("Invalid user {injected} from 203.0.113.7 port 40000")),
            (EventKind::InvalidUser, injected.to_string(), real)
        );
        // Lines without the trailing protocol were already parsed before.
        assert_eq!(
            classified("Failed password for invalid user oracle from 203.0.113.7 port 40000"),
            (EventKind::FailedLogin, "oracle".to_string(), real)
        );
        // So were empty usernames.
        assert_eq!(
            classified("Failed none for invalid user  from 203.0.113.7 port 40000 ssh2"),
            (EventKind::FailedLogin, String::new(), real)
        );
        assert_eq!(
            classified("Invalid user  from 203.0.113.7 port 40000"),
            (EventKind::InvalidUser, String::new(), real)
        );
    }

    #[test]
    fn takes_the_source_ip_before_a_certificate_id_that_injects_another() {
        // A certificate's key ID (chosen by whoever signed it) is logged after
        // the source IP, but only for valid users, whose names have no spaces.
        let real: IpAddr = "203.0.113.7".parse().unwrap();
        let suffix = ": ED25519-CERT SHA256:abc ID x from 198.51.100.9 port 1 ssh2 (serial 1) CA ED25519 SHA256:def";

        assert_eq!(
            classified(&format!(
                "Failed publickey for root from 203.0.113.7 port 40000 ssh2{suffix}"
            )),
            (EventKind::FailedLogin, "root".to_string(), real)
        );
        assert_eq!(
            classified(&format!(
                "Accepted publickey for hector from 203.0.113.7 port 40000 ssh2{suffix}"
            )),
            (EventKind::SuccessfulLogin, "hector".to_string(), real)
        );
    }
}
