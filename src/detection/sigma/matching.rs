//! Evaluation of validated Sigma rules against normalized events.

use std::net::IpAddr;

use super::rule::{FieldMatcher, Search, SigmaRule, ValueMatcher};
use super::wildcard;
use crate::event::{Event, LogSource};

impl SigmaRule {
    pub fn matches(&self, event: &Event) -> bool {
        if !self.logsource.applies_to(&event.logsource) {
            return false;
        }

        let identifiers: Vec<&str> = self.searches.iter().map(|(name, _)| name.as_str()).collect();
        let is_match = |id: &str| {
            self.searches
                .iter()
                .find(|(name, _)| name == id)
                .is_some_and(|(_, search)| search.matches(event))
        };
        self.condition.evaluate(&identifiers, &is_match)
    }
}

impl LogSource {
    /// True when every key `self` declares equals the one in `event`.
    pub fn applies_to(&self, event: &LogSource) -> bool {
        let same = |wanted: &Option<String>, actual: &Option<String>| match (wanted, actual) {
            (None, _) => true,
            (Some(wanted), Some(actual)) => wanted.eq_ignore_ascii_case(actual),
            (Some(_), None) => false,
        };
        same(&self.product, &event.product)
            && same(&self.service, &event.service)
            && same(&self.category, &event.category)
    }
}

impl Search {
    fn matches(&self, event: &Event) -> bool {
        match self {
            Search::Keywords(keywords) => keywords.iter().any(|k| k.matches(Some(&event.message))),
            Search::Maps(maps) => maps.iter().any(|fields| fields.iter().all(|f| f.matches(event))),
        }
    }
}

impl FieldMatcher {
    fn matches(&self, event: &Event) -> bool {
        let value = event.field(&self.field);
        let value = value.as_deref();
        if self.all {
            self.values.iter().all(|matcher| matcher.matches(value))
        } else {
            self.values.iter().any(|matcher| matcher.matches(value))
        }
    }
}

impl ValueMatcher {
    fn matches(&self, value: Option<&str>) -> bool {
        match self {
            ValueMatcher::Null => value.is_none_or(str::is_empty),
            ValueMatcher::Wildcard(pattern) => value.is_some_and(|v| wildcard::matches(pattern, v)),
            ValueMatcher::Regex(regex) => value.is_some_and(|v| regex.is_match(v)),
            ValueMatcher::Cidr(net) => value
                .and_then(|v| v.parse::<IpAddr>().ok())
                .is_some_and(|ip| net.contains(&ip)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventKind;
    use chrono::{TimeZone, Utc};

    fn event(kind: EventKind, user: &str, src_ip: &str, message: &str) -> Event {
        Event {
            timestamp: Utc.with_ymd_and_hms(2026, 10, 22, 10, 0, 0).unwrap(),
            host: "srv01".into(),
            process: "sshd".into(),
            kind,
            user: user.into(),
            src_ip: src_ip.parse().unwrap(),
            message: message.into(),
            logsource: LogSource::new("linux", "sshd"),
        }
    }

    fn login(user: &str, src_ip: &str) -> Event {
        event(EventKind::SuccessfulLogin, user, src_ip, "Accepted password")
    }

    /// Rule for linux/sshd with the given detection body (no indentation).
    fn rule(detection: &str) -> SigmaRule {
        rule_with_logsource("  product: linux\n  service: sshd\n", detection)
    }

    fn rule_with_logsource(logsource: &str, detection: &str) -> SigmaRule {
        let body: String = detection.lines().map(|line| format!("  {line}\n")).collect();
        let yaml = format!("title: t\nlogsource:\n{logsource}detection:\n{body}");
        SigmaRule::from_yaml(&yaml).unwrap_or_else(|e| panic!("{e}\n{yaml}"))
    }

    #[test]
    fn plain_values_match_case_insensitively_with_wildcards() {
        let rule = rule("s:\n  user: ROO*\ncondition: s");

        assert!(rule.matches(&login("root", "203.0.113.7")));
        assert!(!rule.matches(&login("admin", "203.0.113.7")));
    }

    #[test]
    fn fields_in_a_map_must_all_match() {
        let rule = rule("s:\n  user: root\n  event_kind: successful_login\ncondition: s");

        assert!(rule.matches(&login("root", "203.0.113.7")));
        assert!(!rule.matches(&event(EventKind::FailedLogin, "root", "203.0.113.7", "")));
        assert!(!rule.matches(&login("admin", "203.0.113.7")));
    }

    #[test]
    fn a_value_list_matches_any_unless_all_modifier() {
        let any = rule("s:\n  user:\n    - root\n    - admin\ncondition: s");
        let all = rule("s:\n  user|contains|all:\n    - ro\n    - ot\ncondition: s");

        assert!(any.matches(&login("admin", "203.0.113.7")));
        assert!(!any.matches(&login("guest", "203.0.113.7")));
        assert!(all.matches(&login("root", "203.0.113.7")));
        assert!(!all.matches(&login("rook", "203.0.113.7")));
    }

    #[test]
    fn a_list_of_maps_matches_any_map() {
        let rule = rule("s:\n  - user: root\n  - host: srv02\ncondition: s");

        assert!(rule.matches(&login("root", "203.0.113.7")));
        assert!(!rule.matches(&login("admin", "203.0.113.7")));
    }

    #[test]
    fn keywords_search_the_raw_message() {
        let rule = rule("keywords:\n  - 'did not receive IDENTIFICATION'\n  - 'bad protocol'\ncondition: keywords");
        let probe = event(
            EventKind::InvalidUser,
            "x",
            "203.0.113.7",
            "Did not receive identification string from 203.0.113.7",
        );

        assert!(rule.matches(&probe));
        assert!(!rule.matches(&login("root", "203.0.113.7")));
    }

    #[test]
    fn null_matches_only_empty_fields() {
        let rule = rule("s:\n  user: null\ncondition: s");

        assert!(rule.matches(&event(EventKind::FailedLogin, "", "203.0.113.7", "")));
        assert!(!rule.matches(&login("root", "203.0.113.7")));
    }

    #[test]
    fn regex_values_match_case_sensitively() {
        let rule = rule("s:\n  user|re: '^r[o0]{2}t$'\ncondition: s");

        assert!(rule.matches(&login("r00t", "203.0.113.7")));
        assert!(!rule.matches(&login("ROOT", "203.0.113.7")));
    }

    #[test]
    fn cidr_values_match_ip_ranges() {
        let rule = rule("s:\n  src_ip|cidr:\n    - 10.0.0.0/8\n    - fd00::/8\ncondition: s");

        assert!(rule.matches(&login("root", "10.1.2.3")));
        assert!(rule.matches(&login("root", "fd12::1")));
        assert!(!rule.matches(&login("root", "203.0.113.7")));
    }

    #[test]
    fn condition_combines_searches() {
        let rule = rule(
            "selection:\n  event_kind: successful_login\n\
             filter_internal:\n  src_ip|cidr: 192.168.0.0/16\n\
             condition: selection and not filter_internal",
        );

        assert!(rule.matches(&login("root", "203.0.113.7")));
        assert!(!rule.matches(&login("root", "192.168.1.10")));
    }

    #[test]
    fn rules_only_apply_to_their_logsource() {
        let detection = "s:\n  user: root\ncondition: s";
        let root = login("root", "203.0.113.7");

        assert!(rule_with_logsource("  product: linux\n", detection).matches(&root));
        assert!(rule_with_logsource("  product: LINUX\n", detection).matches(&root));
        assert!(!rule_with_logsource("  product: windows\n", detection).matches(&root));
        assert!(!rule_with_logsource("  product: linux\n  category: process_creation\n", detection).matches(&root));
    }

    #[test]
    fn rules_without_logsource_apply_everywhere() {
        let yaml = "title: t\ndetection:\n  s:\n    user: root\n  condition: s\n";

        assert!(SigmaRule::from_yaml(yaml).unwrap().matches(&login("root", "203.0.113.7")));
    }
}
