//! Cross-rule validation: resolves the references between correlations and
//! the rules they use, orders correlations so inputs come first, and decides
//! which rules alert on their own.

use std::collections::HashMap;

use super::correlation::{CorrelationRule, RuleDocument};
use super::rule::{RuleError, SigmaRule};

/// A rule a correlation reads from, as an index into [`RuleSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleRef {
    Detection(usize),
    Correlation(usize),
}

#[derive(Debug)]
pub struct Detection {
    pub rule: SigmaRule,
    /// False when only correlations consume this rule (`generate: false`).
    pub standalone: bool,
}

#[derive(Debug)]
pub struct Correlation {
    pub rule: CorrelationRule,
    pub inputs: Vec<RuleRef>,
    pub standalone: bool,
}

#[derive(Debug, Default)]
pub struct RuleSet {
    pub detections: Vec<Detection>,
    /// Ordered so every correlation comes after the correlations it reads.
    pub correlations: Vec<Correlation>,
}

impl RuleSet {
    pub fn new(documents: Vec<RuleDocument>) -> Result<Self, RuleError> {
        let mut detections = Vec::new();
        let mut correlations = Vec::new();
        for document in documents {
            match document {
                RuleDocument::Detection(rule) => detections.push(rule),
                RuleDocument::Correlation(rule) => correlations.push(rule),
            }
        }

        let index = name_index(&detections, &correlations)?;
        let inputs: Vec<Vec<RuleRef>> = correlations
            .iter()
            .map(|correlation| {
                correlation
                    .rules
                    .iter()
                    .map(|reference| match index.get(reference) {
                        Some(found) => Ok(*found),
                        None => error_for(correlation, format!("unknown rule '{reference}'")),
                    })
                    .collect()
            })
            .collect::<Result<_, _>>()?;

        check_group_by(&correlations, &inputs)?;
        let order = topological_order(&correlations, &inputs)?;

        // Which rules are consumed by a correlation, and whether one of those
        // correlations asked for them to keep alerting (`generate: true`).
        let mut detection_use = vec![Usage::default(); detections.len()];
        let mut correlation_use = vec![Usage::default(); correlations.len()];
        for (correlation, refs) in correlations.iter().zip(&inputs) {
            for reference in refs {
                let usage = match *reference {
                    RuleRef::Detection(i) => &mut detection_use[i],
                    RuleRef::Correlation(i) => &mut correlation_use[i],
                };
                usage.referenced = true;
                usage.generate |= correlation.generate;
            }
        }

        let mut position = vec![0; correlations.len()];
        for (new, &old) in order.iter().enumerate() {
            position[old] = new;
        }
        let mut slots: Vec<Option<CorrelationRule>> = correlations.into_iter().map(Some).collect();

        Ok(RuleSet {
            detections: detections
                .into_iter()
                .zip(detection_use)
                .map(|(rule, usage)| Detection {
                    rule,
                    standalone: usage.standalone(),
                })
                .collect(),
            correlations: order
                .iter()
                .map(|&old| Correlation {
                    rule: slots[old].take().expect("each correlation is placed once"),
                    inputs: inputs[old]
                        .iter()
                        .map(|reference| match *reference {
                            RuleRef::Correlation(i) => RuleRef::Correlation(position[i]),
                            detection => detection,
                        })
                        .collect(),
                    standalone: correlation_use[old].standalone(),
                })
                .collect(),
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Usage {
    referenced: bool,
    generate: bool,
}

impl Usage {
    fn standalone(self) -> bool {
        !self.referenced || self.generate
    }
}

fn error_for<T>(correlation: &CorrelationRule, message: String) -> Result<T, RuleError> {
    Err(RuleError(format!("correlation '{}': {message}", correlation.title)))
}

/// Maps every rule `name` and `id` to the rule it identifies.
fn name_index(
    detections: &[SigmaRule],
    correlations: &[CorrelationRule],
) -> Result<HashMap<String, RuleRef>, RuleError> {
    let detection_keys = detections
        .iter()
        .enumerate()
        .map(|(i, rule)| (RuleRef::Detection(i), [&rule.name, &rule.id]));
    let correlation_keys = correlations
        .iter()
        .enumerate()
        .map(|(i, rule)| (RuleRef::Correlation(i), [&rule.name, &rule.id]));

    let mut index = HashMap::new();
    for (reference, keys) in detection_keys.chain(correlation_keys) {
        for key in keys.into_iter().flatten() {
            match index.insert(key.clone(), reference) {
                Some(previous) if previous != reference => {
                    return Err(RuleError(format!("duplicate rule name or id '{key}'")));
                }
                _ => {}
            }
        }
    }
    Ok(index)
}

/// An outer correlation can only group by fields its inner correlations
/// grouped by: other fields are no longer known once events are aggregated.
fn check_group_by(correlations: &[CorrelationRule], inputs: &[Vec<RuleRef>]) -> Result<(), RuleError> {
    for (outer, refs) in correlations.iter().zip(inputs) {
        for reference in refs {
            let RuleRef::Correlation(i) = *reference else { continue };
            let inner = &correlations[i];
            if let Some(field) = outer.group_by.iter().find(|f| !inner.group_by.contains(f)) {
                return error_for(
                    outer,
                    format!(
                        "groups by '{field}', which correlation '{}' does not group by",
                        inner.title
                    ),
                );
            }
        }
    }
    Ok(())
}

/// Depth-first search: a correlation is emitted after everything it reads.
/// Meeting a correlation that is still being visited means a cycle.
fn topological_order(correlations: &[CorrelationRule], inputs: &[Vec<RuleRef>]) -> Result<Vec<usize>, RuleError> {
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        New,
        Visiting,
        Done,
    }

    fn visit(
        i: usize,
        correlations: &[CorrelationRule],
        inputs: &[Vec<RuleRef>],
        marks: &mut [Mark],
        order: &mut Vec<usize>,
    ) -> Result<(), RuleError> {
        match marks[i] {
            Mark::Done => return Ok(()),
            Mark::Visiting => return error_for(&correlations[i], "is part of a reference cycle".into()),
            Mark::New => {}
        }
        marks[i] = Mark::Visiting;
        for reference in &inputs[i] {
            if let RuleRef::Correlation(j) = *reference {
                visit(j, correlations, inputs, marks, order)?;
            }
        }
        marks[i] = Mark::Done;
        order.push(i);
        Ok(())
    }

    let mut marks = vec![Mark::New; correlations.len()];
    let mut order = Vec::with_capacity(correlations.len());
    for i in 0..correlations.len() {
        visit(i, correlations, inputs, &mut marks, &mut order)?;
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::sigma::correlation::parse_documents;

    fn detection(name: &str) -> String {
        format!("title: {name}\nname: {name}\ndetection:\n  s:\n    user: x\n  condition: s\n")
    }

    fn correlation(name: &str, rules: &[&str], group_by: &[&str], extra: &str) -> String {
        format!(
            "title: {name}\nname: {name}\ncorrelation:\n  type: temporal\n  rules: [{}]\n  group-by: [{}]\n  \
             timespan: 5m\n{extra}",
            rules.join(", "),
            group_by.join(", ")
        )
    }

    fn rule_set(documents: &[String]) -> Result<RuleSet, RuleError> {
        RuleSet::new(parse_documents(&documents.join("---\n")).unwrap())
    }

    fn titles(set: &RuleSet) -> Vec<&str> {
        set.correlations.iter().map(|c| c.rule.title.as_str()).collect()
    }

    #[test]
    fn detections_without_correlations_alert_on_their_own() {
        let set = rule_set(&[detection("a"), detection("b")]).unwrap();

        assert_eq!(set.detections.len(), 2);
        assert!(set.detections.iter().all(|d| d.standalone));
        assert!(set.correlations.is_empty());
    }

    #[test]
    fn resolves_references_by_name_or_id() {
        let by_id = "title: Login\nid: 11111111-2222\ndetection:\n  s:\n    user: x\n  condition: s\n".to_string();
        let set = rule_set(&[
            detection("failed"),
            by_id,
            correlation("pair", &["failed", "11111111-2222"], &["src_ip"], ""),
        ])
        .unwrap();

        let pair = &set.correlations[0];
        assert_eq!(pair.inputs, vec![RuleRef::Detection(0), RuleRef::Detection(1)]);
        assert!(pair.standalone);
        assert!(
            set.detections.iter().all(|d| !d.standalone),
            "consumed rules stay silent by default"
        );
    }

    #[test]
    fn generate_keeps_referenced_rules_alerting() {
        let set = rule_set(&[
            detection("a"),
            detection("b"),
            correlation("pair", &["a"], &[], "  generate: true\n"),
        ])
        .unwrap();

        assert!(set.detections[0].standalone);
        assert!(set.detections[1].standalone, "unreferenced rules always alert");
    }

    #[test]
    fn orders_chained_correlations_inputs_first() {
        let set = rule_set(&[
            correlation("outer", &["inner", "success"], &["src_ip"], ""),
            detection("failed"),
            detection("success"),
            correlation("inner", &["failed"], &["src_ip", "user"], ""),
        ])
        .unwrap();

        assert_eq!(titles(&set), ["inner", "outer"]);
        assert_eq!(set.correlations[0].inputs, vec![RuleRef::Detection(0)]);
        assert_eq!(
            set.correlations[1].inputs,
            vec![RuleRef::Correlation(0), RuleRef::Detection(1)]
        );
        assert!(!set.correlations[0].standalone, "inner correlation only feeds outer");
        assert!(set.correlations[1].standalone);
    }

    #[test]
    fn rejects_unknown_references() {
        let message = rule_set(&[correlation("pair", &["missing"], &[], "")])
            .unwrap_err()
            .to_string();

        assert!(
            message.contains("'pair'") && message.contains("unknown rule 'missing'"),
            "{message}"
        );
    }

    #[test]
    fn rejects_reference_cycles() {
        let cycle = rule_set(&[correlation("a", &["b"], &[], ""), correlation("b", &["a"], &[], "")]);
        let itself = rule_set(&[correlation("a", &["a"], &[], "")]);

        assert!(cycle.unwrap_err().to_string().contains("cycle"));
        assert!(itself.unwrap_err().to_string().contains("cycle"));
    }

    #[test]
    fn rejects_duplicate_names() {
        let message = rule_set(&[detection("a"), detection("a")]).unwrap_err().to_string();

        assert!(message.contains("duplicate rule name or id 'a'"), "{message}");
    }

    #[test]
    fn outer_group_by_must_be_provided_by_inner_correlations() {
        let set = |outer_group: &[&str]| {
            rule_set(&[
                detection("failed"),
                correlation("inner", &["failed"], &["src_ip"], ""),
                correlation("outer", &["inner"], outer_group, ""),
            ])
        };

        assert!(set(&["src_ip"]).is_ok());
        let message = set(&["src_ip", "user"]).unwrap_err().to_string();
        assert!(
            message.contains("'outer'") && message.contains("'inner'") && message.contains("'user'"),
            "{message}"
        );
    }
}
