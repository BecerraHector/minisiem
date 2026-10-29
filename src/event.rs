use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// What happened, independent of the log format it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// An authentication attempt was rejected (wrong password, key, etc.).
    FailedLogin,
    /// A connection asked for a user that does not exist on the host.
    InvalidUser,
    /// An authentication attempt succeeded.
    SuccessfulLogin,
}

impl EventKind {
    /// Stable name used by detection rules (the `event_kind` field).
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::FailedLogin => "failed_login",
            EventKind::InvalidUser => "invalid_user",
            EventKind::SuccessfulLogin => "successful_login",
        }
    }
}

/// Where an event comes from, using Sigma's `logsource` vocabulary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogSource {
    pub product: Option<String>,
    pub service: Option<String>,
    pub category: Option<String>,
}

impl LogSource {
    pub fn new(product: &str, service: &str) -> Self {
        Self {
            product: Some(product.into()),
            service: Some(service.into()),
            category: None,
        }
    }
}

/// A normalized security event. Every log source is translated into this
/// shape so detection rules never depend on a specific log format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub process: String,
    pub kind: EventKind,
    pub user: String,
    pub src_ip: IpAddr,
    /// The original log message, without the syslog header.
    pub message: String,
    pub logsource: LogSource,
}

impl Event {
    /// Field names detection rules can match on.
    pub const FIELDS: [&'static str; 5] = ["host", "process", "user", "src_ip", "event_kind"];

    /// Value of one of [`Event::FIELDS`], or `None` for unknown names.
    pub fn field(&self, name: &str) -> Option<String> {
        match name {
            "host" => Some(self.host.clone()),
            "process" => Some(self.process.clone()),
            "user" => Some(self.user.clone()),
            "src_ip" => Some(self.src_ip.to_string()),
            "event_kind" => Some(self.kind.as_str().to_string()),
            _ => None,
        }
    }
}
