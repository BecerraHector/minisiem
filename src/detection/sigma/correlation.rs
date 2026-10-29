//! Sigma correlation rules (Sigma specification v2.1.0) and multi-document
//! rule files.

use chrono::Duration;

use super::rule::{RawRule, RuleError, SigmaRule, error, parse_level, techniques_from_tags};
use super::value::Value;
use crate::alert::{MitreTechnique, Severity};
use crate::event::Event;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrelationKind {
    /// Counts matching events.
    EventCount,
    /// Counts distinct values of `field`.
    ValueCount { field: String },
    /// Every referenced rule matched, in any order.
    Temporal,
    /// Every referenced rule matched, in the listed order.
    TemporalOrdered,
}

/// Lower bound a count must reach. Only bounds that can be decided as events
/// arrive are supported (no `lt`, `lte`, `neq`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Threshold {
    Gt(u64),
    Gte(u64),
    Eq(u64),
}

impl Threshold {
    pub fn is_met(self, count: usize) -> bool {
        let count = count as u64;
        match self {
            Threshold::Gt(n) => count > n,
            Threshold::Gte(n) => count >= n,
            Threshold::Eq(n) => count == n,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CorrelationRule {
    pub id: Option<String>,
    pub name: Option<String>,
    pub title: String,
    pub severity: Severity,
    pub techniques: Vec<MitreTechnique>,
    pub kind: CorrelationKind,
    /// Names or ids of the referenced rules.
    pub rules: Vec<String>,
    pub group_by: Vec<String>,
    pub timespan: Duration,
    /// Required for `event_count` and `value_count`; unused otherwise.
    pub threshold: Option<Threshold>,
    /// Whether the referenced rules also alert on their own.
    pub generate: bool,
}

/// One document of a rule file.
#[derive(Debug)]
pub enum RuleDocument {
    Detection(SigmaRule),
    Correlation(CorrelationRule),
}

/// Parses a rule file, which may hold several YAML documents separated by `---`.
pub fn parse_documents(yaml: &str) -> Result<Vec<RuleDocument>, RuleError> {
    let raws: Vec<RawRule> = serde_saphyr::from_multiple(yaml).map_err(|e| RuleError(format!("invalid YAML: {e}")))?;
    let several = raws.len() > 1;

    raws.into_iter()
        .enumerate()
        .map(|(index, raw)| {
            let document = if raw.correlation.is_some() {
                CorrelationRule::from_raw(raw).map(RuleDocument::Correlation)
            } else {
                SigmaRule::from_raw(raw).map(RuleDocument::Detection)
            };
            document.map_err(|e| match several {
                true => RuleError(format!("document {}: {e}", index + 1)),
                false => e,
            })
        })
        .collect()
}

impl CorrelationRule {
    fn from_raw(raw: RawRule) -> Result<Self, RuleError> {
        if raw.detection.is_some() {
            return error("a rule cannot have both 'detection' and 'correlation'");
        }
        let Some(title) = raw.title else {
            return error("missing 'title'");
        };
        let Some(Value::Map(entries)) = raw.correlation else {
            return error("'correlation' must be a map");
        };

        let (mut kind, mut rules, mut group_by) = (None, None, Vec::new());
        let (mut timespan, mut condition, mut generate) = (None, None, false);
        for (key, value) in entries {
            match key.as_str() {
                "type" => kind = Some(scalar(value, "type")?),
                "rules" => rules = Some(strings(value, "rules")?),
                "group-by" => group_by = strings(value, "group-by")?,
                "timespan" => timespan = Some(parse_timespan(&scalar(value, "timespan")?)?),
                "condition" => condition = Some(value),
                "generate" => generate = parse_bool(value)?,
                "aliases" => return error("correlation 'aliases' are not supported"),
                other => return error(format!("unknown correlation key '{other}'")),
            }
        }

        let Some(kind) = kind else {
            return error("missing 'type' in 'correlation'");
        };
        let Some(rules) = rules else {
            return error("missing 'rules' in 'correlation'");
        };
        if rules.is_empty() {
            return error("'rules' must list at least one rule");
        }
        let Some(timespan) = timespan else {
            return error("missing 'timespan' in 'correlation'");
        };
        for field in &group_by {
            check_field(field, "group-by")?;
        }

        let (kind, threshold) = match kind.as_str() {
            "event_count" => (CorrelationKind::EventCount, Some(parse_condition(&kind, condition)?.0)),
            "value_count" => {
                let (threshold, field) = parse_condition(&kind, condition)?;
                let Some(field) = field else {
                    return error("value_count condition needs 'field'");
                };
                check_field(&field, "condition")?;
                (CorrelationKind::ValueCount { field }, Some(threshold))
            }
            "temporal" => (CorrelationKind::Temporal, None),
            "temporal_ordered" => (CorrelationKind::TemporalOrdered, None),
            "value_sum" | "value_avg" | "value_percentile" => {
                return error(format!("correlation type '{kind}' is not supported"));
            }
            other => return error(format!("unknown correlation type '{other}'")),
        };

        Ok(CorrelationRule {
            id: raw.id,
            name: raw.name,
            title,
            severity: parse_level(raw.level.as_deref())?,
            techniques: techniques_from_tags(&raw.tags),
            kind,
            rules,
            group_by,
            timespan,
            threshold,
            generate,
        })
    }
}

fn scalar(value: Value, key: &str) -> Result<String, RuleError> {
    match value {
        Value::Scalar(text) => Ok(text),
        _ => error(format!("'{key}' must be a string")),
    }
}

fn strings(value: Value, key: &str) -> Result<Vec<String>, RuleError> {
    match value {
        Value::List(items) => items.into_iter().map(|item| scalar(item, key)).collect(),
        _ => error(format!("'{key}' must be a list of strings")),
    }
}

fn parse_bool(value: Value) -> Result<bool, RuleError> {
    match value {
        Value::Scalar(text) if text == "true" => Ok(true),
        Value::Scalar(text) if text == "false" => Ok(false),
        _ => error("'generate' must be true or false"),
    }
}

fn check_field(field: &str, key: &str) -> Result<(), RuleError> {
    if Event::FIELDS.contains(&field) {
        return Ok(());
    }
    error(format!(
        "unknown field '{field}' in '{key}' (available: {})",
        Event::FIELDS.join(", ")
    ))
}

/// `<number><s|m|h|d>`, strictly positive.
fn parse_timespan(text: &str) -> Result<Duration, RuleError> {
    match crate::timespan::parse(text) {
        Some(span) => Ok(span),
        None => error(format!(
            "invalid timespan '{text}' (expected <number><s|m|h|d>, e.g. 5m)"
        )),
    }
}

/// Returns the threshold and the optional `field` of a count condition.
fn parse_condition(kind: &str, condition: Option<Value>) -> Result<(Threshold, Option<String>), RuleError> {
    let Some(Value::Map(entries)) = condition else {
        return error(format!("'{kind}' needs a 'condition' map, e.g. 'gte: 10'"));
    };

    let mut field = None;
    let mut thresholds = Vec::new();
    for (key, value) in entries {
        let number = |value: Value| match value {
            Value::Scalar(text) => text.parse::<u64>().ok(),
            _ => None,
        };
        match key.as_str() {
            "field" => field = Some(scalar(value, "field")?),
            op @ ("gt" | "gte" | "eq") => {
                let Some(n) = number(value) else {
                    return error(format!("condition '{op}' must be a non-negative integer"));
                };
                thresholds.push(match op {
                    "gt" => Threshold::Gt(n),
                    "gte" => Threshold::Gte(n),
                    _ => Threshold::Eq(n),
                });
            }
            op @ ("lt" | "lte" | "neq") => {
                return error(format!(
                    "condition operator '{op}' is not supported: streaming evaluation needs a lower bound \
                     ('gt', 'gte' or 'eq')"
                ));
            }
            other => return error(format!("unknown condition key '{other}'")),
        }
    }

    match thresholds.as_slice() {
        [threshold] => Ok((*threshold, field)),
        _ => error("condition must have exactly one of 'gt', 'gte', 'eq'"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A correlation document with the given `correlation` body (no indentation).
    fn yaml(body: &str) -> String {
        let body: String = body.lines().map(|line| format!("  {line}\n")).collect();
        format!("title: Correlation\ncorrelation:\n{body}")
    }

    fn correlation(body: &str) -> CorrelationRule {
        let yaml = yaml(body);
        match parse_documents(&yaml) {
            Ok(mut docs) if docs.len() == 1 => match docs.remove(0) {
                RuleDocument::Correlation(rule) => rule,
                other => panic!("expected a correlation, got {other:?}"),
            },
            other => panic!("expected one correlation, got {other:?}\n{yaml}"),
        }
    }

    fn error(body: &str) -> String {
        match parse_documents(&yaml(body)) {
            Ok(docs) => panic!("should be rejected, got {docs:?}"),
            Err(e) => e.to_string(),
        }
    }

    const EVENT_COUNT: &str = "type: event_count\nrules:\n  - failed_login\ngroup-by:\n  - src_ip\n\
                               timespan: 5m\ncondition:\n  gte: 10";

    #[test]
    fn parses_an_event_count_correlation() {
        let yaml = format!(
            "title: SSH brute force\nid: c-1\nname: ssh_brute_force\nlevel: high\n\
             tags:\n  - attack.t1110.001\n{}",
            yaml(EVENT_COUNT).trim_start_matches("title: Correlation\n")
        );

        let docs = parse_documents(&yaml).unwrap();

        let RuleDocument::Correlation(rule) = &docs[0] else {
            panic!("expected a correlation")
        };
        assert_eq!(
            *rule,
            CorrelationRule {
                id: Some("c-1".into()),
                name: Some("ssh_brute_force".into()),
                title: "SSH brute force".into(),
                severity: Severity::High,
                techniques: vec![MitreTechnique {
                    id: "T1110.001".into(),
                    name: None
                }],
                kind: CorrelationKind::EventCount,
                rules: vec!["failed_login".into()],
                group_by: vec!["src_ip".into()],
                timespan: Duration::minutes(5),
                threshold: Some(Threshold::Gte(10)),
                generate: false,
            }
        );
    }

    #[test]
    fn parses_value_count_field() {
        let rule =
            correlation("type: value_count\nrules: [invalid_user]\ntimespan: 10m\ncondition:\n  field: user\n  gt: 4");

        assert_eq!(rule.kind, CorrelationKind::ValueCount { field: "user".into() });
        assert_eq!(rule.threshold, Some(Threshold::Gt(4)));
        assert!(rule.group_by.is_empty());
    }

    #[test]
    fn temporal_correlations_need_no_condition() {
        let temporal = correlation("type: temporal\nrules: [a, b]\ngroup-by: [src_ip]\ntimespan: 1h");
        let ordered = correlation("type: temporal_ordered\nrules: [a, b]\ntimespan: 30s\ngenerate: true");

        assert_eq!(temporal.kind, CorrelationKind::Temporal);
        assert_eq!(temporal.threshold, None);
        assert_eq!(ordered.kind, CorrelationKind::TemporalOrdered);
        assert_eq!(ordered.timespan, Duration::seconds(30));
        assert!(ordered.generate);
    }

    #[test]
    fn parses_timespan_units() {
        let span = |text: &str| correlation(&format!("type: temporal\nrules: [a]\ntimespan: {text}")).timespan;

        assert_eq!(span("45s"), Duration::seconds(45));
        assert_eq!(span("90m"), Duration::minutes(90));
        assert_eq!(span("2h"), Duration::hours(2));
        assert_eq!(span("1d"), Duration::days(1));
    }

    #[test]
    fn rejects_invalid_timespans() {
        for text in ["5", "5w", "0m", "-5m", "m", "5 m", "99999999999999999999d"] {
            let message = error(&format!("type: temporal\nrules: [a]\ntimespan: '{text}'"));
            assert!(message.contains("invalid timespan"), "{text}: {message}");
        }
        assert!(error("type: temporal\nrules: [a]").contains("missing 'timespan'"));
    }

    #[test]
    fn checks_condition_operators() {
        let with = |condition: &str| format!("type: event_count\nrules: [a]\ntimespan: 5m\ncondition:\n{condition}");

        assert_eq!(correlation(&with("  eq: 3")).threshold, Some(Threshold::Eq(3)));
        for op in ["lt", "lte", "neq"] {
            let message = error(&with(&format!("  {op}: 3")));
            assert!(
                message.contains(&format!("'{op}'")) && message.contains("streaming"),
                "{message}"
            );
        }
        assert!(error(&with("  gt: 3\n  gte: 4")).contains("exactly one of"));
        assert!(error(&with("  gte: many")).contains("non-negative integer"));
        assert!(error(&with("  above: 3")).contains("unknown condition key 'above'"));
        assert!(error("type: event_count\nrules: [a]\ntimespan: 5m").contains("needs a 'condition'"));
    }

    #[test]
    fn value_count_needs_a_known_field() {
        let base = "type: value_count\nrules: [a]\ntimespan: 5m\ncondition:\n";

        assert!(error(&format!("{base}  gte: 3")).contains("needs 'field'"));
        assert!(error(&format!("{base}  field: TargetUser\n  gte: 3")).contains("unknown field 'TargetUser'"));
    }

    #[test]
    fn rejects_unsupported_or_malformed_correlations() {
        assert!(error("type: value_sum\nrules: [a]\ntimespan: 5m").contains("'value_sum' is not supported"));
        assert!(error("type: sometimes\nrules: [a]\ntimespan: 5m").contains("unknown correlation type 'sometimes'"));
        assert!(error("rules: [a]\ntimespan: 5m").contains("missing 'type'"));
        assert!(error("type: temporal\ntimespan: 5m").contains("missing 'rules'"));
        assert!(error("type: temporal\nrules: []\ntimespan: 5m").contains("'rules'"));
        assert!(error("type: temporal\nrules: [a]\ngroup-by: [CommandLine]\ntimespan: 5m").contains("unknown field"));
        assert!(error("type: temporal\nrules: [a]\ntimespan: 5m\naliases:\n  ip: {}").contains("aliases"));
        assert!(error("type: temporal\nrules: [a]\ntimespan: 5m\ngenerate: maybe").contains("'generate'"));
    }

    #[test]
    fn reads_every_document_of_a_file() {
        let yaml = "title: Failed login\nname: failed_login\n\
                    detection:\n  s:\n    event_kind: failed_login\n  condition: s\n\
                    ---\n\
                    title: Burst\ncorrelation:\n  type: event_count\n  rules: [failed_login]\n  timespan: 5m\n  \
                    condition:\n    gte: 3\n";

        let docs = parse_documents(yaml).unwrap();

        assert_eq!(docs.len(), 2);
        assert!(matches!(&docs[0], RuleDocument::Detection(rule) if rule.name.as_deref() == Some("failed_login")));
        assert!(matches!(&docs[1], RuleDocument::Correlation(rule) if rule.title == "Burst"));
    }

    #[test]
    fn names_the_failing_document_in_multi_document_files() {
        let yaml = "title: ok\ndetection:\n  s:\n    user: x\n  condition: s\n---\nlevel: high\n";

        let message = parse_documents(yaml).unwrap_err().to_string();

        assert!(message.starts_with("document 2: "), "{message}");
        assert!(message.contains("missing 'title'"), "{message}");
    }

    #[test]
    fn rejects_documents_with_detection_and_correlation() {
        let yaml = "title: both\ndetection:\n  s:\n    user: x\n  condition: s\ncorrelation:\n  type: temporal\n";

        assert!(parse_documents(yaml).unwrap_err().to_string().contains("both"));
    }

    #[test]
    fn thresholds_compare_counts() {
        assert!(Threshold::Gt(3).is_met(4) && !Threshold::Gt(3).is_met(3));
        assert!(Threshold::Gte(3).is_met(3) && !Threshold::Gte(3).is_met(2));
        assert!(Threshold::Eq(3).is_met(3) && !Threshold::Eq(3).is_met(4));
    }
}
