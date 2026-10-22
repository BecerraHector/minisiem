//! Runs a whole [`RuleSet`]: detection rules first, then correlations in
//! dependency order, so chained correlations see this event's results.

use super::correlation::CorrelationKind;
use super::correlation_state::{CorrelationState, Fired, Hit};
use super::ruleset::{RuleRef, RuleSet};
use crate::alert::{Alert, Evidence};
use crate::detection::Detector;
use crate::event::Event;

pub struct SigmaEngine {
    rules: RuleSet,
    /// One state per correlation, aligned with `rules.correlations`.
    states: Vec<CorrelationState>,
}

impl SigmaEngine {
    pub fn new(rules: RuleSet) -> Self {
        let states = rules
            .correlations
            .iter()
            .map(|c| CorrelationState::new(c.rule.kind.clone(), c.rule.threshold, c.rule.timespan, c.inputs.len()))
            .collect();
        Self { rules, states }
    }
}

/// `group-by` fields with their values, in rule order.
type Group = Vec<(String, String)>;

impl Detector for SigmaEngine {
    fn evaluate(&mut self, event: &Event) -> Vec<Alert> {
        let mut alerts = Vec::new();

        let matched: Vec<bool> = self.rules.detections.iter().map(|d| d.rule.matches(event)).collect();
        for (detection, _) in self.rules.detections.iter().zip(&matched).filter(|(_, hit)| **hit) {
            if detection.standalone {
                let rule = &detection.rule;
                alerts.push(Alert {
                    rule_id: rule_id(&rule.id, &rule.name, &rule.title),
                    title: rule.title.clone(),
                    severity: rule.severity,
                    techniques: rule.techniques.clone(),
                    src_ip: event.src_ip,
                    host: event.host.clone(),
                    evidence: Evidence::Event(event.clone()),
                });
            }
        }

        // What each correlation reported for this event. Correlations are in
        // dependency order, so `fired[i]` is final before anything reads it.
        let mut fired: Vec<Option<(Fired, Group)>> = Vec::with_capacity(self.states.len());
        for (correlation, state) in self.rules.correlations.iter().zip(self.states.iter_mut()) {
            let rule = &correlation.rule;
            let counted = match &rule.kind {
                CorrelationKind::ValueCount { field } => Some(field.as_str()),
                _ => None,
            };

            let mut result = None;
            for (input, reference) in correlation.inputs.iter().enumerate() {
                let (group, hit) = match *reference {
                    RuleRef::Detection(i) if matched[i] => {
                        let group = rule
                            .group_by
                            .iter()
                            .map(|f| (f.clone(), event.field(f).unwrap_or_default()));
                        let hit = Hit {
                            input,
                            timestamp: event.timestamp,
                            first_seen: event.timestamp,
                            value: counted.and_then(|f| event.field(f)),
                            event_count: 1,
                        };
                        (group.collect::<Group>(), hit)
                    }
                    RuleRef::Correlation(i) => {
                        let Some((inner, inner_group)) = &fired[i] else {
                            continue;
                        };
                        // An inner correlation only knows its own group fields
                        // (load-time validation guarantees they cover ours).
                        let lookup = |field: &str| {
                            inner_group
                                .iter()
                                .find(|(name, _)| name == field)
                                .map(|(_, value)| value.clone())
                        };
                        let group = rule.group_by.iter().map(|f| (f.clone(), lookup(f).unwrap_or_default()));
                        let hit = Hit {
                            input,
                            timestamp: inner.last_seen,
                            first_seen: inner.first_seen,
                            value: counted.and_then(lookup),
                            event_count: inner.event_count,
                        };
                        (group.collect::<Group>(), hit)
                    }
                    RuleRef::Detection(_) => continue,
                };

                let key = group.iter().map(|(_, value)| value.clone()).collect();
                if let Some(outcome) = state.observe(key, hit) {
                    result.get_or_insert((outcome, group));
                }
            }

            if let (Some((outcome, group)), true) = (&result, correlation.standalone) {
                alerts.push(Alert {
                    rule_id: rule_id(&rule.id, &rule.name, &rule.title),
                    title: rule.title.clone(),
                    severity: rule.severity,
                    techniques: rule.techniques.clone(),
                    src_ip: event.src_ip,
                    host: event.host.clone(),
                    evidence: Evidence::Correlation {
                        group: group.clone(),
                        event_count: outcome.event_count,
                        first_seen: outcome.first_seen,
                        last_seen: outcome.last_seen,
                        values: outcome.values.clone(),
                    },
                });
            }
            fired.push(result);
        }

        alerts
    }
}

/// Prefer the stable `id`, then the `name`, then the title.
fn rule_id(id: &Option<String>, name: &Option<String>, title: &str) -> String {
    id.clone().or_else(|| name.clone()).unwrap_or_else(|| title.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{MitreTechnique, Severity};
    use crate::detection::sigma::parse_documents;
    use crate::event::{EventKind, LogSource};
    use chrono::{DateTime, Duration, TimeZone, Utc};

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 22, 10, 0, 0).unwrap() + Duration::seconds(secs)
    }

    fn event(kind: EventKind, user: &str, src_ip: &str, secs: i64) -> Event {
        Event {
            timestamp: at(secs),
            host: "srv01".into(),
            process: "sshd".into(),
            kind,
            user: user.into(),
            src_ip: src_ip.parse().unwrap(),
            message: format!("{} for {user}", kind.as_str()),
            logsource: LogSource::new("linux", "sshd"),
        }
    }

    fn failed(user: &str, src_ip: &str, secs: i64) -> Event {
        event(EventKind::FailedLogin, user, src_ip, secs)
    }

    fn success(user: &str, src_ip: &str, secs: i64) -> Event {
        event(EventKind::SuccessfulLogin, user, src_ip, secs)
    }

    fn engine(documents: &[&str]) -> SigmaEngine {
        let yaml = documents.join("---\n");
        SigmaEngine::new(RuleSet::new(parse_documents(&yaml).unwrap()).unwrap())
    }

    fn titles(alerts: &[Alert]) -> Vec<&str> {
        alerts.iter().map(|a| a.title.as_str()).collect()
    }

    const FAILED: &str = "title: Failed login\nname: failed\n\
                          detection:\n  s:\n    event_kind: failed_login\n  condition: s\n";
    const SUCCESS: &str = "title: Successful login\nname: success\n\
                           detection:\n  s:\n    event_kind: successful_login\n  condition: s\n";
    const BURST: &str = "title: SSH brute force\nname: burst\nlevel: high\ntags: [attack.t1110.001]\n\
                         correlation:\n  type: event_count\n  rules: [failed]\n  group-by: [src_ip]\n  \
                         timespan: 5m\n  condition:\n    gte: 3\n";

    #[test]
    fn standalone_detections_alert_with_rule_metadata() {
        let mut engine = engine(&["title: Root login\nid: r-1\nlevel: high\ntags: [attack.t1078.003]\n\
                                   detection:\n  s:\n    user: root\n  condition: s\n"]);
        let root = success("root", "203.0.113.7", 0);

        assert_eq!(
            engine.evaluate(&root),
            vec![Alert {
                rule_id: "r-1".into(),
                title: "Root login".into(),
                severity: Severity::High,
                techniques: vec![MitreTechnique {
                    id: "T1078.003".into(),
                    name: None
                }],
                src_ip: root.src_ip,
                host: "srv01".into(),
                evidence: Evidence::Event(root.clone()),
            }]
        );
        assert!(engine.evaluate(&success("hector", "203.0.113.7", 1)).is_empty());
    }

    #[test]
    fn rule_id_falls_back_to_name_then_title() {
        let mut named = engine(&[SUCCESS]);
        let mut untitled = engine(&["title: Any login\ndetection:\n  s:\n    user: root\n  condition: s\n"]);

        assert_eq!(named.evaluate(&success("root", "10.0.0.1", 0))[0].rule_id, "success");
        assert_eq!(
            untitled.evaluate(&success("root", "10.0.0.1", 0))[0].rule_id,
            "Any login"
        );
    }

    #[test]
    fn event_count_correlation_alerts_once_per_burst_and_hides_its_input() {
        let mut engine = engine(&[FAILED, BURST]);

        assert!(engine.evaluate(&failed("root", "203.0.113.7", 0)).is_empty());
        assert!(engine.evaluate(&failed("admin", "203.0.113.7", 10)).is_empty());
        let alerts = engine.evaluate(&failed("root", "203.0.113.7", 20));

        assert_eq!(
            alerts,
            vec![Alert {
                rule_id: "burst".into(),
                title: "SSH brute force".into(),
                severity: Severity::High,
                techniques: vec![MitreTechnique {
                    id: "T1110.001".into(),
                    name: None
                }],
                src_ip: "203.0.113.7".parse().unwrap(),
                host: "srv01".into(),
                evidence: Evidence::Correlation {
                    group: vec![("src_ip".into(), "203.0.113.7".into())],
                    event_count: 3,
                    first_seen: at(0),
                    last_seen: at(20),
                    values: vec![],
                },
            }]
        );
        assert!(
            engine.evaluate(&failed("root", "203.0.113.7", 30)).is_empty(),
            "the group starts over"
        );
    }

    #[test]
    fn generate_true_keeps_the_input_rule_alerting() {
        let burst = BURST.replace("  timespan: 5m\n", "  timespan: 5m\n  generate: true\n");
        let mut engine = engine(&[FAILED, &burst]);

        assert_eq!(
            titles(&engine.evaluate(&failed("root", "203.0.113.7", 0))),
            ["Failed login"]
        );
    }

    #[test]
    fn value_count_correlation_reports_distinct_values() {
        let mut engine = engine(&[
            FAILED,
            "title: User spraying\ncorrelation:\n  type: value_count\n  rules: [failed]\n  group-by: [src_ip]\n  \
             timespan: 5m\n  condition:\n    field: user\n    gte: 3\n",
        ]);

        for (secs, user) in [(0, "root"), (1, "root"), (2, "admin")] {
            assert!(engine.evaluate(&failed(user, "203.0.113.7", secs)).is_empty());
        }
        let alerts = engine.evaluate(&failed("oracle", "203.0.113.7", 3));

        assert!(matches!(
            &alerts[0].evidence,
            Evidence::Correlation { values, event_count: 4, .. } if *values == ["admin", "oracle", "root"]
        ));
    }

    #[test]
    fn chained_correlation_detects_brute_force_followed_by_success() {
        let outer = "title: Brute force then success\nlevel: critical\ncorrelation:\n  type: temporal_ordered\n  \
                     rules: [burst, success]\n  group-by: [src_ip]\n  timespan: 10m\n";
        let mut engine = engine(&[FAILED, SUCCESS, BURST, outer]);

        assert!(
            engine.evaluate(&success("root", "203.0.113.7", 0)).is_empty(),
            "success alone means nothing"
        );
        for secs in 1..4 {
            assert!(
                engine.evaluate(&failed("root", "203.0.113.7", secs)).is_empty(),
                "inner burst is silent"
            );
        }
        assert!(
            engine.evaluate(&success("root", "198.51.100.23", 5)).is_empty(),
            "other IP, other group"
        );
        let alerts = engine.evaluate(&success("root", "203.0.113.7", 60));

        assert_eq!(titles(&alerts), ["Brute force then success"]);
        assert!(matches!(
            &alerts[0].evidence,
            Evidence::Correlation { event_count: 4, first_seen, last_seen, group, .. }
                if *first_seen == at(1) && *last_seen == at(60)
                    && *group == [("src_ip".to_string(), "203.0.113.7".to_string())]
        ));
    }

    #[test]
    fn one_event_can_raise_detection_and_correlation_alerts_in_that_order() {
        let root = "title: Root login\ndetection:\n  s:\n    user: root\n  condition: s\n";
        let mut engine = engine(&[root, FAILED, BURST]);
        engine.evaluate(&failed("root", "203.0.113.7", 0));
        engine.evaluate(&failed("root", "203.0.113.7", 1));

        let alerts = engine.evaluate(&failed("root", "203.0.113.7", 2));

        assert_eq!(titles(&alerts), ["Root login", "SSH brute force"]);
    }

    #[test]
    fn correlations_without_group_by_count_all_events_together() {
        let global = BURST.replace("  group-by: [src_ip]\n", "");
        let mut engine = engine(&[FAILED, &global]);
        engine.evaluate(&failed("root", "203.0.113.7", 0));
        engine.evaluate(&failed("root", "198.51.100.23", 1));

        let alerts = engine.evaluate(&failed("root", "192.0.2.1", 2));

        assert!(matches!(&alerts[0].evidence, Evidence::Correlation { group, .. } if group.is_empty()));
    }
}
