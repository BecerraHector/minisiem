use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use chrono::Duration;

use super::Detector;
use crate::alert::{Alert, Evidence, MitreTechnique, Severity};
use crate::event::{Event, EventKind};

fn password_guessing() -> MitreTechnique {
    MitreTechnique {
        id: "T1110.001".into(),
        name: Some("Password Guessing".into()),
    }
}

/// Fires when one source IP accumulates `threshold` failed logins within a
/// sliding time `window`. After firing, the counter for that IP resets, so a
/// sustained attack produces one alert per `threshold` failures instead of
/// one alert per line.
///
/// Events are expected in chronological order.
pub struct SshBruteForce {
    threshold: usize,
    window: Duration,
    failures: HashMap<IpAddr, VecDeque<Event>>,
}

impl SshBruteForce {
    pub fn new(threshold: usize, window: Duration) -> Self {
        Self {
            threshold,
            window,
            failures: HashMap::new(),
        }
    }
}

impl Detector for SshBruteForce {
    fn evaluate(&mut self, event: &Event) -> Option<Alert> {
        if event.kind != EventKind::FailedLogin {
            return None;
        }

        let recent = self.failures.entry(event.src_ip).or_default();
        recent.push_back(event.clone());

        // Slide the window: drop failures older than `window` before `event`.
        let cutoff = event.timestamp - self.window;
        while recent.front().is_some_and(|old| old.timestamp < cutoff) {
            recent.pop_front();
        }

        if recent.len() < self.threshold {
            return None;
        }

        let burst: Vec<Event> = recent.drain(..).collect();
        let mut users: Vec<String> = burst.iter().map(|e| e.user.clone()).collect();
        users.sort();
        users.dedup();

        Some(Alert {
            rule_id: "ssh-brute-force".into(),
            title: "SSH brute force".into(),
            severity: Severity::High,
            techniques: vec![password_guessing()],
            src_ip: event.src_ip,
            host: event.host.clone(),
            evidence: Evidence::Burst {
                event_count: burst.len(),
                first_seen: burst[0].timestamp,
                last_seen: event.timestamp,
                users,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::LogSource;
    use chrono::{DateTime, TimeZone, Utc};

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 22, 10, 0, 0).unwrap() + Duration::seconds(secs)
    }

    fn event(kind: EventKind, ip: &str, user: &str, secs: i64) -> Event {
        Event {
            timestamp: at(secs),
            host: "srv01".into(),
            process: "sshd".into(),
            kind,
            user: user.into(),
            src_ip: ip.parse().unwrap(),
            message: String::new(),
            logsource: LogSource::new("linux", "sshd"),
        }
    }

    fn failed(ip: &str, user: &str, secs: i64) -> Event {
        event(EventKind::FailedLogin, ip, user, secs)
    }

    fn rule() -> SshBruteForce {
        SshBruteForce::new(3, Duration::seconds(60))
    }

    #[test]
    fn fires_when_threshold_is_reached_within_window() {
        let mut rule = rule();
        assert_eq!(rule.evaluate(&failed("203.0.113.7", "root", 0)), None);
        assert_eq!(rule.evaluate(&failed("203.0.113.7", "admin", 30)), None);

        let alert = rule
            .evaluate(&failed("203.0.113.7", "root", 60))
            .expect("third failure inside the window must fire");

        assert_eq!(alert.rule_id, "ssh-brute-force");
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.techniques, vec![password_guessing()]);
        assert_eq!(alert.src_ip, "203.0.113.7".parse::<IpAddr>().unwrap());
        assert_eq!(alert.host, "srv01");
        assert_eq!(
            alert.evidence,
            Evidence::Burst {
                event_count: 3,
                first_seen: at(0),
                last_seen: at(60),
                users: vec!["admin".to_string(), "root".to_string()],
            }
        );
    }

    #[test]
    fn does_not_fire_below_threshold() {
        let mut rule = rule();
        assert_eq!(rule.evaluate(&failed("203.0.113.7", "root", 0)), None);
        assert_eq!(rule.evaluate(&failed("203.0.113.7", "root", 10)), None);
    }

    #[test]
    fn failures_older_than_window_are_forgotten() {
        let mut rule = rule();
        assert_eq!(rule.evaluate(&failed("203.0.113.7", "root", 0)), None);
        assert_eq!(rule.evaluate(&failed("203.0.113.7", "root", 61)), None);
        assert_eq!(rule.evaluate(&failed("203.0.113.7", "root", 62)), None);
    }

    #[test]
    fn counts_each_source_ip_separately() {
        let mut rule = rule();
        assert_eq!(rule.evaluate(&failed("203.0.113.7", "root", 0)), None);
        assert_eq!(rule.evaluate(&failed("198.51.100.23", "root", 1)), None);
        assert_eq!(rule.evaluate(&failed("203.0.113.7", "root", 2)), None);
        assert_eq!(rule.evaluate(&failed("198.51.100.23", "root", 3)), None);
    }

    #[test]
    fn ignores_events_that_are_not_failed_logins() {
        let mut rule = rule();
        for secs in 0..5 {
            assert_eq!(
                rule.evaluate(&event(EventKind::InvalidUser, "203.0.113.7", "x", secs)),
                None
            );
            assert_eq!(
                rule.evaluate(&event(EventKind::SuccessfulLogin, "203.0.113.7", "x", secs)),
                None
            );
        }
    }

    #[test]
    fn resets_after_firing_so_next_alert_needs_a_new_burst() {
        let mut rule = rule();
        for secs in 0..2 {
            rule.evaluate(&failed("203.0.113.7", "root", secs));
        }
        assert!(rule.evaluate(&failed("203.0.113.7", "root", 2)).is_some());

        assert_eq!(rule.evaluate(&failed("203.0.113.7", "root", 3)), None);
        assert_eq!(rule.evaluate(&failed("203.0.113.7", "root", 4)), None);
        let second = rule
            .evaluate(&failed("203.0.113.7", "root", 5))
            .expect("second burst fires");
        assert!(matches!(second.evidence, Evidence::Burst { first_seen, .. } if first_seen == at(3)));
    }
}
