//! Log ingestion (adapters). Each parser translates one raw log format into
//! normalized [`Event`]s.

mod auto;
mod journal;
mod sshd;
mod sudo;
mod syslog_net;

pub use auto::AutoParser;
pub use journal::JournalParser;
pub use sshd::{SSHD_PROCESSES, SyslogParser};
pub use sudo::SUDO_PROCESS;

use crate::event::Event;

/// The processes whose journald entries minisiem reads (`_COMM`).
pub const FOLLOWED_PROCESSES: [&str; 4] = [SSHD_PROCESSES[0], SSHD_PROCESSES[1], SSHD_PROCESSES[2], SUDO_PROCESS];

/// Port: turns one raw log line into an event, or `None` when the line is
/// not relevant (or not understood).
pub trait LogParser {
    fn parse(&self, line: &str) -> Option<Event>;
}
