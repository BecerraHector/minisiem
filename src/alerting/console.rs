use std::fmt;
use std::io::{self, Write};

use super::AlertSink;
use crate::alert::{Alert, Evidence};
use crate::event::Event;

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
        self.write_line(alert)?;
        // A piped stdout is block-buffered: without a flush, a live alert can
        // sit in a buffer where nobody sees it.
        self.out.flush()
    }
}

impl<W: Write> ConsoleSink<W> {
    fn write_line(&mut self, alert: &Alert) -> io::Result<()> {
        write!(self.out, "[{}] {}{}", alert.severity, alert.title, techniques(alert),)?;
        // Left out for sources without one (e.g. sudo).
        if let Some(src_ip) = alert.src_ip {
            write!(self.out, " src={src_ip}")?;
        }
        write!(self.out, " host={}", alert.host)?;

        match &alert.evidence {
            Evidence::Burst {
                event_count,
                first_seen,
                last_seen,
                users,
            } => writeln!(
                self.out,
                " failures={event_count} users={} first_seen={} last_seen={}",
                field_list(users),
                first_seen.to_rfc3339(),
                last_seen.to_rfc3339(),
            ),
            Evidence::Event(event) => writeln!(
                self.out,
                " user={} event_kind={} time={} message={:?}",
                field_value(&event.user),
                event.kind.as_str(),
                event.timestamp.to_rfc3339(),
                // Debug formatting quotes the message and escapes control characters.
                event.message,
            ),
            Evidence::Correlation {
                group,
                event_count,
                first_seen,
                last_seen,
                values,
            } => {
                for (field, value) in group {
                    write!(self.out, " group.{field}={}", field_value(value))?;
                }
                write!(
                    self.out,
                    " events={event_count} first_seen={} last_seen={}",
                    first_seen.to_rfc3339(),
                    last_seen.to_rfc3339()
                )?;
                if !values.is_empty() {
                    write!(self.out, " values={}", field_list(values))?;
                }
                writeln!(self.out)
            }
        }
    }
}

/// One event as a console line, with its fields quoted as in alerts:
/// `<time> host=.. process=.. src=.. user=.. event_kind=.. message=".."`.
pub struct EventLine<'a>(pub &'a Event);

impl fmt::Display for EventLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let event = self.0;
        write!(
            f,
            "{} host={} process={} src={} user={} event_kind={} message={:?}",
            event.timestamp.to_rfc3339(),
            field_value(&event.host),
            field_value(&event.process),
            event.src_ip.map_or("-".to_owned(), |ip| ip.to_string()),
            field_value(&event.user),
            event.kind.as_str(),
            event.message,
        )
    }
}

/// ` (T1110.001 Password Guessing, T1078)`, or empty when there are none.
fn techniques(alert: &Alert) -> String {
    if alert.techniques.is_empty() {
        return String::new();
    }
    let list: Vec<String> = alert
        .techniques
        .iter()
        .map(|t| match &t.name {
            Some(name) => format!("{} {name}", t.id),
            None => t.id.clone(),
        })
        .collect();
    format!(" ({})", list.join(", "))
}

/// An attacker-controlled field value. Values with spaces, `=`, `,` or `"`
/// (e.g. an invalid username such as `x src=9.9.9.9`) are quoted so they
/// cannot pass for other fields or list items; the rest is printed as is.
fn field_value(value: &str) -> String {
    if value.contains(|c: char| c.is_whitespace() || matches!(c, '=' | ',' | '"')) {
        // Debug formatting quotes and escapes quotes and control characters.
        format!("{value:?}")
    } else {
        escape_control(value)
    }
}

/// A comma-separated list of attacker-controlled values.
fn field_list<S: AsRef<str>>(values: &[S]) -> String {
    values
        .iter()
        .map(|value| field_value(value.as_ref()))
        .collect::<Vec<_>>()
        .join(",")
}

/// Log fields can be attacker-controlled: escape control characters so they
/// cannot inject terminal escape sequences or fake extra lines.
fn escape_control(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_control() {
                c.escape_unicode().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{MitreTechnique, Severity};
    use crate::event::{Event, EventKind, LogSource};
    use chrono::{TimeZone, Utc};

    fn render(alert: &Alert) -> String {
        let mut sink = ConsoleSink::new(Vec::new());
        sink.emit(alert).unwrap();
        String::from_utf8(sink.out).unwrap()
    }

    fn burst_alert(users: Vec<String>) -> Alert {
        Alert {
            rule_id: "ssh-brute-force".into(),
            title: "SSH brute force".into(),
            severity: Severity::High,
            techniques: vec![MitreTechnique {
                id: "T1110.001".into(),
                name: Some("Password Guessing".into()),
            }],
            src_ip: Some("203.0.113.7".parse().unwrap()),
            host: "srv01".into(),
            evidence: Evidence::Burst {
                event_count: 3,
                first_seen: Utc.with_ymd_and_hms(2026, 10, 22, 10, 0, 0).unwrap(),
                last_seen: Utc.with_ymd_and_hms(2026, 10, 22, 10, 1, 0).unwrap(),
                users,
            },
        }
    }

    fn event_alert(techniques: Vec<MitreTechnique>, user: &str, message: &str) -> Alert {
        let event = Event {
            timestamp: Utc.with_ymd_and_hms(2026, 10, 22, 10, 17, 5).unwrap(),
            host: "srv01".into(),
            process: "sshd".into(),
            kind: EventKind::SuccessfulLogin,
            user: user.into(),
            src_ip: Some("203.0.113.7".parse().unwrap()),
            message: message.into(),
            logsource: LogSource::new("linux", "sshd"),
        };
        Alert {
            rule_id: "6c1b8f7e".into(),
            title: "SSH login as root".into(),
            severity: Severity::Medium,
            techniques,
            src_ip: event.src_ip,
            host: event.host.clone(),
            evidence: Evidence::Event(event),
        }
    }

    #[test]
    fn writes_one_line_per_burst_alert() {
        assert_eq!(
            render(&burst_alert(vec!["admin".into(), "root".into()])),
            "[HIGH] SSH brute force (T1110.001 Password Guessing) src=203.0.113.7 host=srv01 failures=3 \
             users=admin,root first_seen=2026-10-22T10:00:00+00:00 last_seen=2026-10-22T10:01:00+00:00\n"
        );
    }

    #[test]
    fn leaves_the_source_ip_out_when_there_is_none() {
        let mut alert = event_alert(vec![], "root", "msg");
        alert.src_ip = None;
        let Evidence::Event(event) = &mut alert.evidence else {
            unreachable!()
        };
        event.src_ip = None;
        let line = EventLine(event).to_string();

        assert!(line.contains(" src=- "), "{line}");
        let rendered = render(&alert);
        assert!(
            rendered.starts_with("[MEDIUM] SSH login as root host=srv01 user=root "),
            "{rendered}"
        );
    }

    #[test]
    fn writes_single_event_alert_with_unnamed_technique() {
        let alert = event_alert(
            vec![MitreTechnique {
                id: "T1078.003".into(),
                name: None,
            }],
            "root",
            "Accepted password for root from 203.0.113.7 port 52100 ssh2",
        );

        assert_eq!(
            render(&alert),
            "[MEDIUM] SSH login as root (T1078.003) src=203.0.113.7 host=srv01 user=root \
             event_kind=successful_login time=2026-10-22T10:17:05+00:00 \
             message=\"Accepted password for root from 203.0.113.7 port 52100 ssh2\"\n"
        );
    }

    #[test]
    fn lists_several_techniques_and_omits_parentheses_when_there_are_none() {
        let several = event_alert(
            vec![
                MitreTechnique {
                    id: "T1078".into(),
                    name: None,
                },
                MitreTechnique {
                    id: "T1021.004".into(),
                    name: Some("SSH".into()),
                },
            ],
            "root",
            "x",
        );
        let none = event_alert(vec![], "root", "x");

        assert!(render(&several).starts_with("[MEDIUM] SSH login as root (T1078, T1021.004 SSH) src="));
        assert!(render(&none).starts_with("[MEDIUM] SSH login as root src="));
    }

    fn correlation_alert(group: Vec<(&str, &str)>, values: Vec<&str>) -> Alert {
        Alert {
            rule_id: "ssh-user-enumeration".into(),
            title: "SSH user enumeration".into(),
            severity: Severity::Medium,
            techniques: vec![MitreTechnique {
                id: "T1087".into(),
                name: None,
            }],
            src_ip: Some("203.0.113.7".parse().unwrap()),
            host: "srv01".into(),
            evidence: Evidence::Correlation {
                group: group.into_iter().map(|(k, v)| (k.into(), v.into())).collect(),
                event_count: 3,
                first_seen: Utc.with_ymd_and_hms(2026, 10, 22, 10, 0, 0).unwrap(),
                last_seen: Utc.with_ymd_and_hms(2026, 10, 22, 10, 1, 0).unwrap(),
                values: values.into_iter().map(String::from).collect(),
            },
        }
    }

    /// Records how often it was flushed.
    #[derive(Default)]
    struct FlushCounter {
        flushes: usize,
    }

    impl Write for FlushCounter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn flushes_every_alert_so_pipes_see_it_immediately() {
        let mut sink = ConsoleSink::new(FlushCounter::default());

        sink.emit(&burst_alert(vec!["root".into()])).unwrap();
        sink.emit(&burst_alert(vec!["root".into()])).unwrap();

        assert_eq!(sink.out.flushes, 2);
    }

    #[test]
    fn writes_correlation_alert_with_group_and_values() {
        let alert = correlation_alert(
            vec![("src_ip", "203.0.113.7"), ("host", "srv01")],
            vec!["admin", "oracle", "test"],
        );

        assert_eq!(
            render(&alert),
            "[MEDIUM] SSH user enumeration (T1087) src=203.0.113.7 host=srv01 group.src_ip=203.0.113.7 \
             group.host=srv01 events=3 first_seen=2026-10-22T10:00:00+00:00 \
             last_seen=2026-10-22T10:01:00+00:00 values=admin,oracle,test\n"
        );
    }

    #[test]
    fn omits_values_when_the_correlation_counted_none() {
        let alert = correlation_alert(vec![("src_ip", "203.0.113.7")], vec![]);

        assert!(render(&alert).ends_with("last_seen=2026-10-22T10:01:00+00:00\n"));
    }

    #[test]
    fn escapes_control_characters_from_attacker_controlled_fields() {
        // An attacker picks the username: an ESC sequence must never reach the
        // analyst's terminal raw.
        let burst = render(&burst_alert(vec!["\x1b[2J".into()]));
        let event = render(&event_alert(vec![], "\x1b[2J", "Invalid user \x1b[2J from"));
        let correlation = render(&correlation_alert(vec![("user", "\x1b[2J")], vec!["\x1b[2J"]));

        assert!(!burst.contains('\x1b') && !event.contains('\x1b') && !correlation.contains('\x1b'));
        assert!(burst.contains("users=\\u{1b}[2J "), "{burst}");
        assert!(event.contains("user=\\u{1b}[2J "), "{event}");
        assert!(event.contains("message=\"Invalid user \\u{1b}[2J from\""), "{event}");
        assert!(correlation.contains("group.user=\\u{1b}[2J "), "{correlation}");
        assert!(correlation.contains("values=\\u{1b}[2J\n"), "{correlation}");
    }

    #[test]
    fn quotes_attacker_controlled_values_that_could_fake_other_fields() {
        // sshd logs invalid usernames verbatim, spaces included: unquoted, this
        // one would add a second `src=` to the line.
        let fake = "x src=9.9.9.9 host=evil";
        let burst = render(&burst_alert(vec!["admin".into(), fake.into()]));
        let event = render(&event_alert(vec![], fake, "Invalid user"));
        let correlation = render(&correlation_alert(vec![("user", fake)], vec!["root", "a,b"]));

        assert!(burst.contains(r#" users=admin,"x src=9.9.9.9 host=evil" "#), "{burst}");
        assert!(event.contains(r#" user="x src=9.9.9.9 host=evil" "#), "{event}");
        assert!(
            correlation.contains(r#" group.user="x src=9.9.9.9 host=evil" "#),
            "{correlation}"
        );
        assert!(correlation.contains(r#" values=root,"a,b""#), "{correlation}");
    }

    #[test]
    fn quotes_values_with_an_equals_sign_or_a_quote_even_without_spaces() {
        let equals = render(&event_alert(vec![], "x=src=9.9.9.9", "Invalid user"));
        let quote = render(&event_alert(vec![], r#"a"b"#, "Invalid user"));

        assert!(equals.contains(r#" user="x=src=9.9.9.9" "#), "{equals}");
        assert!(quote.contains(r#" user="a\"b" "#), "{quote}");
    }

    #[test]
    fn quoted_values_still_escape_control_characters() {
        let event = render(&event_alert(vec![], "x \x1b[2J\nfake", "Invalid user"));

        assert!(!event.contains('\x1b'), "{event}");
        assert_eq!(event.lines().count(), 1, "{event}");
        assert!(event.contains(r#" user="x \u{1b}[2J\nfake" "#), "{event}");
    }
}
