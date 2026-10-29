//! Spans of time written as `<number><s|m|h|d>`, as in Sigma timespans.

use std::sync::LazyLock;

use chrono::Duration;
use regex::Regex;

static TIMESPAN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d{1,9})([smhd])$").unwrap());

/// `<number><s|m|h|d>`, e.g. `90m`, strictly positive.
pub fn parse(text: &str) -> Option<Duration> {
    let caps = TIMESPAN.captures(text)?;
    let amount: i64 = caps[1].parse().expect("at most 9 digits");
    if amount == 0 {
        return None;
    }
    Some(match &caps[2] {
        "s" => Duration::seconds(amount),
        "m" => Duration::minutes(amount),
        "h" => Duration::hours(amount),
        _ => Duration::days(amount),
    })
}
