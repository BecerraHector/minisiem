use std::net::IpAddr;

use chrono::{DateTime, Utc};

/// What happened, independent of the log format it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// An authentication attempt was rejected (wrong password, key, etc.).
    FailedLogin,
    /// A connection asked for a user that does not exist on the host.
    InvalidUser,
    /// An authentication attempt succeeded.
    SuccessfulLogin,
}

/// A normalized security event. Every log source is translated into this
/// shape so detection rules never depend on a specific log format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub process: String,
    pub kind: EventKind,
    pub user: String,
    pub src_ip: IpAddr,
}
