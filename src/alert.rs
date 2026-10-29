use std::fmt;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::event::Event;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Severity::Informational => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        };
        f.write_str(label)
    }
}

/// A MITRE ATT&CK technique, used to tell analysts *what* an alert means.
/// Sigma tags only carry the ID, so the name is optional.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,
    pub name: Option<String>,
}

/// Why a rule fired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Evidence {
    /// Several related events aggregated by a stateful rule.
    Burst {
        event_count: usize,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
        /// Distinct target users, sorted.
        users: Vec<String>,
    },
    /// The single event that matched a stateless rule.
    Event(Event),
    /// A correlation rule fired for one group of events.
    Correlation {
        /// `group-by` field names and their shared values, in rule order.
        group: Vec<(String, String)>,
        event_count: usize,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
        /// Distinct values counted by a `value_count` correlation, sorted.
        values: Vec<String>,
    },
}

/// The result of a detection rule firing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub techniques: Vec<MitreTechnique>,
    /// The source IP of the event behind the alert, when it had one.
    pub src_ip: Option<IpAddr>,
    pub host: String,
    pub evidence: Evidence,
}
