//! Log ingestion (adapters). Each parser translates one raw log format into
//! normalized [`Event`]s.

mod auto;
mod journal;
mod sshd;
mod syslog_net;

pub use auto::AutoParser;
pub use journal::JournalParser;
pub use sshd::SshdParser;

use crate::event::Event;

/// Port: turns one raw log line into an event, or `None` when the line is
/// not relevant (or not understood).
pub trait LogParser {
    fn parse(&self, line: &str) -> Option<Event>;
}
