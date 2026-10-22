use std::fmt;
use std::net::IpAddr;

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        };
        f.write_str(label)
    }
}

/// A MITRE ATT&CK technique, used to tell analysts *what* an alert means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MitreTechnique {
    pub id: &'static str,
    pub name: &'static str,
    pub tactic: &'static str,
}

/// The result of a detection rule firing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub technique: MitreTechnique,
    pub src_ip: IpAddr,
    pub host: String,
    pub event_count: usize,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Distinct target users, sorted.
    pub users: Vec<String>,
}
