//! Sigma rule model, built from YAML and validated up front so evaluation
//! never fails at runtime.

use std::fmt;
use std::sync::LazyLock;

use ipnet::IpNet;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;

use super::condition::{Condition, Reference, Selector};
use super::value::Value;
use crate::alert::{MitreTechnique, Severity};
use crate::event::{Event, LogSource};

#[derive(Debug)]
pub struct SigmaRule {
    pub id: Option<String>,
    pub title: String,
    pub severity: Severity,
    pub techniques: Vec<MitreTechnique>,
    pub logsource: LogSource,
    /// Search identifiers in document order.
    pub searches: Vec<(String, Search)>,
    pub condition: Condition,
}

#[derive(Debug, PartialEq)]
pub enum Search {
    /// Matches when any keyword appears in the raw message.
    Keywords(Vec<ValueMatcher>),
    /// Matches when any map matches; a map matches when all its fields do.
    Maps(Vec<Vec<FieldMatcher>>),
}

#[derive(Debug, PartialEq)]
pub struct FieldMatcher {
    pub field: String,
    pub values: Vec<ValueMatcher>,
    /// `|all` modifier: every value must match instead of any.
    pub all: bool,
}

#[derive(Debug)]
pub enum ValueMatcher {
    /// Absent or empty field.
    Null,
    /// Case-insensitive glob (`contains`/`startswith`/`endswith` are folded in).
    Wildcard(String),
    Regex(Regex),
    Cidr(IpNet),
}

impl PartialEq for ValueMatcher {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::Wildcard(a), Self::Wildcard(b)) => a == b,
            (Self::Regex(a), Self::Regex(b)) => a.as_str() == b.as_str(),
            (Self::Cidr(a), Self::Cidr(b)) => a == b,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError(pub String);

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RuleError {}

/// The YAML document as written; validated and converted by `from_yaml`.
#[derive(Deserialize)]
struct RawRule {
    title: Option<String>,
    id: Option<String>,
    level: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    logsource: RawLogSource,
    detection: Option<Value>,
}

#[derive(Deserialize, Default)]
struct RawLogSource {
    product: Option<String>,
    service: Option<String>,
    category: Option<String>,
}

static TECHNIQUE_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^attack\.(t\d{4}(?:\.\d{3})?)$").unwrap());

/// Upper bound for compiled `|re` patterns, so a rule cannot exhaust memory.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

fn error<T>(message: impl Into<String>) -> Result<T, RuleError> {
    Err(RuleError(message.into()))
}

impl SigmaRule {
    pub fn from_yaml(yaml: &str) -> Result<Self, RuleError> {
        let raw: RawRule = serde_saphyr::from_str(yaml).map_err(|e| RuleError(format!("invalid YAML: {e}")))?;

        let Some(title) = raw.title else { return error("missing 'title'") };
        let Some(detection) = raw.detection else { return error("missing 'detection'") };
        let Value::Map(entries) = detection else { return error("'detection' must be a map") };

        let mut condition = None;
        let mut searches: Vec<(String, Search)> = Vec::new();
        for (name, value) in entries {
            if name == "condition" {
                condition = Some(parse_condition(value)?);
            } else if searches.iter().any(|(existing, _)| *existing == name) {
                return error(format!("duplicate search identifier '{name}'"));
            } else {
                let search = parse_search(&name, value)?;
                searches.push((name, search));
            }
        }

        let Some(condition) = condition else { return error("missing 'condition' in 'detection'") };
        if searches.is_empty() {
            return error("'detection' has no search identifiers");
        }
        validate_references(&condition, &searches)?;

        Ok(SigmaRule {
            id: raw.id,
            title,
            severity: parse_level(raw.level.as_deref())?,
            techniques: raw
                .tags
                .iter()
                .filter_map(|tag| TECHNIQUE_TAG.captures(tag))
                .map(|caps| MitreTechnique { id: caps[1].to_uppercase(), name: None })
                .collect(),
            logsource: LogSource {
                product: raw.logsource.product,
                service: raw.logsource.service,
                category: raw.logsource.category,
            },
            searches,
            condition,
        })
    }
}

fn parse_level(level: Option<&str>) -> Result<Severity, RuleError> {
    match level {
        None | Some("medium") => Ok(Severity::Medium),
        Some("informational") => Ok(Severity::Informational),
        Some("low") => Ok(Severity::Low),
        Some("high") => Ok(Severity::High),
        Some("critical") => Ok(Severity::Critical),
        Some(other) => error(format!("unknown level '{other}'")),
    }
}

/// A condition is a string, or a list of strings meaning "any of them".
fn parse_condition(value: Value) -> Result<Condition, RuleError> {
    let texts = match value {
        Value::Scalar(text) => vec![text],
        Value::List(items) if !items.is_empty() => items
            .into_iter()
            .map(|item| match item {
                Value::Scalar(text) => Ok(text),
                _ => error("'condition' list must only contain strings"),
            })
            .collect::<Result<_, _>>()?,
        _ => return error("'condition' must be a string or a list of strings"),
    };

    texts
        .iter()
        .map(|text| Condition::parse(text).map_err(|e| RuleError(format!("invalid condition '{text}': {e}"))))
        .reduce(|a, b| Ok(Condition::Or(Box::new(a?), Box::new(b?))))
        .expect("at least one condition")
}

fn validate_references(condition: &Condition, searches: &[(String, Search)]) -> Result<(), RuleError> {
    let identifiers: Vec<&str> = searches.iter().map(|(name, _)| name.as_str()).collect();

    for reference in condition.references() {
        match reference {
            Reference::Identifier(id) if !identifiers.contains(&id) => {
                return error(format!("condition uses undefined search identifier '{id}'"));
            }
            Reference::Pattern(pattern) if Selector::Pattern(pattern.into()).select(&identifiers).is_empty() => {
                return error(format!("condition pattern '{pattern}' matches no search identifier"));
            }
            _ => {}
        }
    }
    Ok(())
}

fn parse_search(name: &str, value: Value) -> Result<Search, RuleError> {
    let invalid = || error(format!("search '{name}' must be a map, a list of maps or a list of keywords"));

    match value {
        Value::Map(entries) => Ok(Search::Maps(vec![parse_map(name, entries)?])),
        Value::List(items) if items.is_empty() => invalid(),
        Value::List(items) if items.iter().all(|item| matches!(item, Value::Map(_))) => items
            .into_iter()
            .map(|item| match item {
                Value::Map(entries) => parse_map(name, entries),
                _ => unreachable!("checked above"),
            })
            .collect::<Result<_, _>>()
            .map(Search::Maps),
        Value::List(items) if items.iter().all(|item| matches!(item, Value::Scalar(_))) => Ok(Search::Keywords(
            items
                .into_iter()
                .map(|item| match item {
                    Value::Scalar(keyword) => ValueMatcher::Wildcard(format!("*{keyword}*")),
                    _ => unreachable!("checked above"),
                })
                .collect(),
        )),
        _ => invalid(),
    }
}

fn parse_map(name: &str, entries: Vec<(String, Value)>) -> Result<Vec<FieldMatcher>, RuleError> {
    if entries.is_empty() {
        return error(format!("search '{name}' has an empty map"));
    }
    entries.into_iter().map(|(key, value)| parse_field(&key, value)).collect()
}

/// Parses `field|modifier|...: value(s)`.
fn parse_field(key: &str, value: Value) -> Result<FieldMatcher, RuleError> {
    let mut parts = key.split('|');
    let field = parts.next().unwrap_or_default();
    if !Event::FIELDS.contains(&field) {
        return error(format!("unknown field '{field}' (available: {})", Event::FIELDS.join(", ")));
    }

    let mut all = false;
    // Modifiers that decide how a value is interpreted; at most one applies.
    let mut transforms = Vec::new();
    for modifier in parts {
        match modifier {
            "all" => all = true,
            "contains" | "startswith" | "endswith" | "re" | "cidr" => transforms.push(modifier),
            other => return error(format!("field '{field}': unknown modifier '{other}'")),
        }
    }
    if let [first, second, ..] = transforms.as_slice() {
        return error(format!("field '{field}': modifiers '{first}' and '{second}' cannot be combined"));
    }
    let transform = transforms.first().copied();

    let items = match value {
        Value::List(items) => items,
        single => vec![single],
    };
    if items.is_empty() {
        return error(format!("field '{field}' has no values"));
    }

    let values = items
        .into_iter()
        .map(|item| match (item, transform) {
            (Value::Null, None) => Ok(ValueMatcher::Null),
            (Value::Null, Some(modifier)) => {
                error(format!("field '{field}': null cannot be combined with modifier '{modifier}'"))
            }
            (Value::Scalar(text), transform) => build_matcher(field, &text, transform),
            _ => error(format!("field '{field}' values must be scalars or null")),
        })
        .collect::<Result<_, _>>()?;

    Ok(FieldMatcher { field: field.to_string(), values, all })
}

fn build_matcher(field: &str, text: &str, transform: Option<&str>) -> Result<ValueMatcher, RuleError> {
    Ok(match transform {
        None => ValueMatcher::Wildcard(text.to_string()),
        Some("contains") => ValueMatcher::Wildcard(format!("*{text}*")),
        Some("startswith") => ValueMatcher::Wildcard(format!("{text}*")),
        Some("endswith") => ValueMatcher::Wildcard(format!("*{text}")),
        Some("re") => RegexBuilder::new(text)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map(ValueMatcher::Regex)
            .map_err(|e| RuleError(format!("field '{field}': invalid regex '{text}': {e}")))?,
        Some("cidr") => text
            .parse()
            .map(ValueMatcher::Cidr)
            .map_err(|_| RuleError(format!("field '{field}': invalid CIDR '{text}'")))?,
        Some(other) => unreachable!("unexpected modifier {other}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a rule around a `detection` body written without indentation.
    fn yaml_with_detection(detection: &str) -> String {
        let body: String = detection.lines().map(|line| format!("  {line}\n")).collect();
        format!("title: Test rule\nlogsource:\n  product: linux\n  service: sshd\ndetection:\n{body}")
    }

    fn rule(yaml: &str) -> SigmaRule {
        SigmaRule::from_yaml(yaml).unwrap_or_else(|e| panic!("rule should load: {e}\n{yaml}"))
    }

    fn error(yaml: &str) -> String {
        match SigmaRule::from_yaml(yaml) {
            Ok(_) => panic!("rule should be rejected:\n{yaml}"),
            Err(e) => e.to_string(),
        }
    }

    fn search(detection: &str) -> Search {
        let mut rule = rule(&yaml_with_detection(detection));
        rule.searches.remove(0).1
    }

    fn single_field(detection: &str) -> FieldMatcher {
        match search(detection) {
            Search::Maps(mut maps) => maps.remove(0).remove(0),
            other => panic!("expected a map search, got {other:?}"),
        }
    }

    fn wildcard(pattern: &str) -> ValueMatcher {
        ValueMatcher::Wildcard(pattern.into())
    }

    #[test]
    fn parses_metadata() {
        let rule = rule(
            "title: SSH login as root\n\
             id: 6c1b8f7e-0000-4000-8000-000000000001\n\
             level: high\n\
             tags:\n  - attack.privilege_escalation\n  - attack.t1078.003\n  - attack.T1021\n  - cve.2024.6387\n\
             logsource:\n  product: linux\n  service: sshd\n\
             detection:\n  selection:\n    user: root\n  condition: selection\n",
        );

        assert_eq!(rule.id.as_deref(), Some("6c1b8f7e-0000-4000-8000-000000000001"));
        assert_eq!(rule.title, "SSH login as root");
        assert_eq!(rule.severity, Severity::High);
        assert_eq!(
            rule.techniques,
            vec![
                MitreTechnique { id: "T1078.003".into(), name: None },
                MitreTechnique { id: "T1021".into(), name: None },
            ]
        );
        assert_eq!(rule.logsource, LogSource::new("linux", "sshd"));
        assert_eq!(rule.condition, Condition::Search("selection".into()));
        assert_eq!(rule.searches.len(), 1);
    }

    #[test]
    fn maps_levels_and_defaults_to_medium() {
        let with_level = |level: &str| {
            format!("title: t\nlevel: {level}\ndetection:\n  s:\n    user: x\n  condition: s\n")
        };

        assert_eq!(rule("title: t\ndetection:\n  s:\n    user: x\n  condition: s\n").severity, Severity::Medium);
        assert_eq!(rule(&with_level("informational")).severity, Severity::Informational);
        assert_eq!(rule(&with_level("low")).severity, Severity::Low);
        assert_eq!(rule(&with_level("critical")).severity, Severity::Critical);
        assert!(error(&with_level("urgent")).contains("unknown level 'urgent'"));
    }

    #[test]
    fn rejects_rules_missing_required_parts() {
        assert!(error("detection:\n  s:\n    user: x\n  condition: s\n").contains("title"));
        assert!(error("title: t\n").contains("detection"));
        assert!(error(&yaml_with_detection("s:\n  user: x")).contains("missing 'condition'"));
        assert!(error(&yaml_with_detection("condition: s")).contains("no search identifiers"));
    }

    #[test]
    fn rejects_invalid_yaml_without_panicking() {
        assert!(!error("title: [unclosed\n").is_empty());
    }

    #[test]
    fn parses_a_map_search_as_and_of_fields() {
        let search = search("selection:\n  user: root\n  event_kind: successful_login\ncondition: selection");

        assert_eq!(
            search,
            Search::Maps(vec![vec![
                FieldMatcher { field: "user".into(), values: vec![wildcard("root")], all: false },
                FieldMatcher { field: "event_kind".into(), values: vec![wildcard("successful_login")], all: false },
            ]])
        );
    }

    #[test]
    fn parses_a_list_of_maps_and_value_lists() {
        let search = search("selection:\n  - user:\n      - root\n      - admin\n  - host: srv*\ncondition: selection");

        assert_eq!(
            search,
            Search::Maps(vec![
                vec![FieldMatcher { field: "user".into(), values: vec![wildcard("root"), wildcard("admin")], all: false }],
                vec![FieldMatcher { field: "host".into(), values: vec![wildcard("srv*")], all: false }],
            ])
        );
    }

    #[test]
    fn parses_keywords_as_contains() {
        let search = search("keywords:\n  - 'Did not receive identification'\n  - 5\ncondition: keywords");

        assert_eq!(search, Search::Keywords(vec![wildcard("*Did not receive identification*"), wildcard("*5*")]));
    }

    #[test]
    fn parses_null_values() {
        assert_eq!(single_field("s:\n  user: null\ncondition: s").values, vec![ValueMatcher::Null]);
        assert_eq!(single_field("s:\n  user: ~\ncondition: s").values, vec![ValueMatcher::Null]);
    }

    #[test]
    fn rejects_malformed_searches() {
        assert!(error(&yaml_with_detection("s: root\ncondition: s")).contains("search 's'"));
        assert!(error(&yaml_with_detection("s:\n  - root\n  - user: x\ncondition: s")).contains("search 's'"));
        assert!(error(&yaml_with_detection("s: []\ncondition: s")).contains("search 's'"));
        assert!(error(&yaml_with_detection("s:\n  user: []\ncondition: s")).contains("no values"));
        assert!(error(&yaml_with_detection("s:\n  user:\n    nested: x\ncondition: s")).contains("field 'user'"));
        assert!(error(&yaml_with_detection("s: {}\ncondition: s")).contains("empty map"));
        assert!(error(&yaml_with_detection("s:\n  user: x\ns:\n  user: y\ncondition: s")).contains("uplicate"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let message = error(&yaml_with_detection("s:\n  CommandLine: whoami\ncondition: s"));

        assert!(message.contains("unknown field 'CommandLine'"), "{message}");
        assert!(message.contains("src_ip"), "should list available fields: {message}");
    }

    #[test]
    fn folds_string_modifiers_into_wildcards() {
        assert_eq!(single_field("s:\n  user|contains: adm\ncondition: s").values, vec![wildcard("*adm*")]);
        assert_eq!(single_field("s:\n  user|startswith: adm\ncondition: s").values, vec![wildcard("adm*")]);
        assert_eq!(single_field("s:\n  user|endswith: adm\ncondition: s").values, vec![wildcard("*adm")]);
    }

    #[test]
    fn parses_all_modifier() {
        let field = single_field("s:\n  user|contains|all:\n    - a\n    - b\ncondition: s");

        assert!(field.all);
        assert_eq!(field.values, vec![wildcard("*a*"), wildcard("*b*")]);
    }

    #[test]
    fn compiles_regex_and_cidr_values() {
        assert_eq!(
            single_field("s:\n  user|re: '^r..t$'\ncondition: s").values,
            vec![ValueMatcher::Regex(Regex::new("^r..t$").unwrap())]
        );
        assert_eq!(
            single_field("s:\n  src_ip|cidr: 10.0.0.0/8\ncondition: s").values,
            vec![ValueMatcher::Cidr("10.0.0.0/8".parse().unwrap())]
        );
    }

    #[test]
    fn rejects_invalid_modifiers_and_values() {
        assert!(error(&yaml_with_detection("s:\n  user|base64: x\ncondition: s")).contains("unknown modifier 'base64'"));
        assert!(error(&yaml_with_detection("s:\n  user|re: '('\ncondition: s")).contains("invalid regex"));
        assert!(error(&yaml_with_detection("s:\n  src_ip|cidr: nope\ncondition: s")).contains("invalid CIDR"));
        assert!(error(&yaml_with_detection("s:\n  user|re|contains: x\ncondition: s")).contains("cannot be combined"));
        assert!(error(&yaml_with_detection("s:\n  user|contains: null\ncondition: s")).contains("null"));
    }

    #[test]
    fn validates_condition_against_search_identifiers() {
        assert!(
            error(&yaml_with_detection("s:\n  user: x\ncondition: s and missing"))
                .contains("undefined search identifier 'missing'")
        );
        assert!(
            error(&yaml_with_detection("s:\n  user: x\ncondition: 1 of filter*"))
                .contains("'filter*' matches no search identifier")
        );
        assert!(error(&yaml_with_detection("s:\n  user: x\ncondition: s | count() > 5")).contains("aggregation"));
    }

    #[test]
    fn a_list_of_conditions_means_any_of_them() {
        let rule = rule(&yaml_with_detection("a:\n  user: x\nb:\n  user: y\ncondition:\n  - a\n  - all of them"));

        assert_eq!(
            rule.condition,
            Condition::Or(
                Box::new(Condition::Search("a".into())),
                Box::new(Condition::AllOf(Selector::Them))
            )
        );
    }
}
