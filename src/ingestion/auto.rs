//! Picks the right parser for each line, so one input can mix formats.

use chrono::FixedOffset;

use super::LogParser;
use super::journal::JournalParser;
use super::sshd::SshdParser;
use crate::event::Event;

/// Dispatches on the first character: `{` is a journald JSON entry,
/// anything else a syslog line.
pub struct AutoParser {
    syslog: SshdParser,
}

impl AutoParser {
    /// `year` and `offset` complete syslog timestamps that lack them.
    pub fn new(year: i32, offset: FixedOffset) -> Self {
        Self {
            syslog: SshdParser::new(year, offset),
        }
    }
}

impl LogParser for AutoParser {
    fn parse(&self, line: &str) -> Option<Event> {
        if line.starts_with('{') {
            JournalParser.parse(line)
        } else {
            self.syslog.parse(line)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventKind;

    fn parser() -> AutoParser {
        AutoParser::new(2026, FixedOffset::east_opt(0).unwrap())
    }

    #[test]
    fn parses_syslog_and_journal_lines() {
        let syslog = "Oct 22 10:15:32 srv01 sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2";
        let journal = r#"{"__REALTIME_TIMESTAMP":"1792667732000000","_HOSTNAME":"srv02","_COMM":"sshd",
                          "MESSAGE":"Accepted publickey for hector from 192.168.1.10 port 2 ssh2"}"#;

        let from_syslog = parser().parse(syslog).unwrap();
        let from_journal = parser().parse(&journal.replace('\n', "")).unwrap();

        assert_eq!(
            (from_syslog.kind, from_syslog.host.as_str()),
            (EventKind::FailedLogin, "srv01")
        );
        assert_eq!(
            (from_journal.kind, from_journal.host.as_str()),
            (EventKind::SuccessfulLogin, "srv02")
        );
    }

    #[test]
    fn ignores_lines_no_parser_understands() {
        assert_eq!(parser().parse("{}"), None);
        assert_eq!(parser().parse("hello"), None);
        assert_eq!(parser().parse(""), None);
    }
}
