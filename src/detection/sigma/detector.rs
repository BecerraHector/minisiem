use super::rule::SigmaRule;
use crate::alert::{Alert, Evidence};
use crate::detection::Detector;
use crate::event::Event;

/// Adapts one Sigma rule to the `Detector` port: one alert per matching event.
pub struct SigmaDetector {
    rule: SigmaRule,
}

impl SigmaDetector {
    pub fn new(rule: SigmaRule) -> Self {
        Self { rule }
    }
}

impl Detector for SigmaDetector {
    fn evaluate(&mut self, event: &Event) -> Option<Alert> {
        if !self.rule.matches(event) {
            return None;
        }

        Some(Alert {
            rule_id: self.rule.id.clone().unwrap_or_else(|| self.rule.title.clone()),
            title: self.rule.title.clone(),
            severity: self.rule.severity,
            techniques: self.rule.techniques.clone(),
            src_ip: event.src_ip,
            host: event.host.clone(),
            evidence: Evidence::Event(event.clone()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{MitreTechnique, Severity};
    use crate::event::{EventKind, LogSource};
    use chrono::{TimeZone, Utc};

    fn login(user: &str) -> Event {
        Event {
            timestamp: Utc.with_ymd_and_hms(2026, 10, 22, 10, 0, 0).unwrap(),
            host: "srv01".into(),
            process: "sshd".into(),
            kind: EventKind::SuccessfulLogin,
            user: user.into(),
            src_ip: "203.0.113.7".parse().unwrap(),
            message: format!("Accepted password for {user}"),
            logsource: LogSource::new("linux", "sshd"),
        }
    }

    fn detector(extra: &str) -> SigmaDetector {
        let yaml = format!(
            "title: SSH login as root\n{extra}level: high\ntags:\n  - attack.t1078.003\n\
             detection:\n  s:\n    user: root\n  condition: s\n"
        );
        SigmaDetector::new(SigmaRule::from_yaml(&yaml).unwrap())
    }

    #[test]
    fn emits_an_alert_carrying_rule_metadata_and_the_event() {
        let event = login("root");

        let alert = detector("id: rule-1\n").evaluate(&event).expect("rule should fire");

        assert_eq!(
            alert,
            Alert {
                rule_id: "rule-1".into(),
                title: "SSH login as root".into(),
                severity: Severity::High,
                techniques: vec![MitreTechnique {
                    id: "T1078.003".into(),
                    name: None
                }],
                src_ip: event.src_ip,
                host: "srv01".into(),
                evidence: Evidence::Event(event),
            }
        );
    }

    #[test]
    fn rule_id_falls_back_to_title() {
        let alert = detector("").evaluate(&login("root")).unwrap();

        assert_eq!(alert.rule_id, "SSH login as root");
    }

    #[test]
    fn stays_silent_when_the_rule_does_not_match() {
        assert_eq!(detector("").evaluate(&login("hector")), None);
    }
}
