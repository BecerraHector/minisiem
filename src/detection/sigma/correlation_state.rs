//! Sliding-window state for one correlation rule, kept per group.

use std::collections::{BTreeSet, HashMap, VecDeque};

use chrono::{DateTime, Duration, Utc};

use super::correlation::{CorrelationKind, Threshold};

/// One match of a rule the correlation reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// Position of the matching rule in the correlation's `rules`.
    pub input: usize,
    pub timestamp: DateTime<Utc>,
    /// Value of the counted field, for `value_count`.
    pub value: Option<String>,
    /// Underlying events this hit stands for (more than one for a chained
    /// correlation).
    pub event_count: usize,
}

/// What a correlation reports when it fires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fired {
    pub event_count: usize,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Distinct counted values (`value_count` only), sorted.
    pub values: Vec<String>,
}

pub struct CorrelationState {
    kind: CorrelationKind,
    threshold: Option<Threshold>,
    timespan: Duration,
    inputs: usize,
    groups: HashMap<Vec<String>, VecDeque<Hit>>,
    last_sweep: Option<DateTime<Utc>>,
}

impl CorrelationState {
    pub fn new(kind: CorrelationKind, threshold: Option<Threshold>, timespan: Duration, inputs: usize) -> Self {
        Self {
            kind,
            threshold,
            timespan,
            inputs,
            groups: HashMap::new(),
            last_sweep: None,
        }
    }

    /// Records a hit for `group`; returns what fired, if anything. Hits are
    /// expected in chronological order.
    pub fn observe(&mut self, group: Vec<String>, hit: Hit) -> Option<Fired> {
        let cutoff = hit.timestamp - self.timespan;
        self.sweep(hit.timestamp, cutoff);

        if matches!(self.kind, CorrelationKind::ValueCount { .. }) && hit.value.is_none() {
            return None;
        }

        let hits = self.groups.entry(group.clone()).or_default();
        hits.push_back(hit);
        while hits.front().is_some_and(|old| old.timestamp < cutoff) {
            hits.pop_front();
        }

        // Borrow only the fields `evaluate` needs: `hits` already borrows
        // `self.groups` mutably, so borrowing all of `self` would not compile.
        let fired = Self::evaluate(&self.kind, self.threshold, self.inputs, hits)?;
        // One alert per burst: the group starts over after firing.
        self.groups.remove(&group);
        Some(fired)
    }

    /// Groups currently holding state (for tests and observability).
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Drops groups whose newest hit left the window. Runs at most once per
    /// `timespan`, so its cost is amortized over the hits in between.
    fn sweep(&mut self, now: DateTime<Utc>, cutoff: DateTime<Utc>) {
        if self.last_sweep.is_some_and(|last| now - last < self.timespan) {
            return;
        }
        self.groups
            .retain(|_, hits| hits.back().is_some_and(|newest| newest.timestamp >= cutoff));
        self.last_sweep = Some(now);
    }

    fn evaluate(
        kind: &CorrelationKind,
        threshold: Option<Threshold>,
        inputs: usize,
        hits: &VecDeque<Hit>,
    ) -> Option<Fired> {
        match kind {
            CorrelationKind::EventCount => {
                let met = threshold?.is_met(hits.len());
                met.then(|| summarize(hits, Vec::new()))?
            }
            CorrelationKind::ValueCount { .. } => {
                let values: BTreeSet<&str> = hits.iter().filter_map(|hit| hit.value.as_deref()).collect();
                let met = threshold?.is_met(values.len());
                met.then(|| summarize(hits, values.into_iter().map(String::from).collect()))?
            }
            CorrelationKind::Temporal => {
                let seen: BTreeSet<usize> = hits.iter().map(|hit| hit.input).collect();
                (seen.len() == inputs).then(|| summarize(hits, Vec::new()))?
            }
            CorrelationKind::TemporalOrdered => {
                // Greedy: the earliest hit of each rule, in rule order. If any
                // ordered sequence exists in the window, this one does.
                let mut sequence = Vec::with_capacity(inputs);
                for hit in hits {
                    if hit.input == sequence.len() {
                        sequence.push(hit);
                        if sequence.len() == inputs {
                            return summarize(sequence, Vec::new());
                        }
                    }
                }
                None
            }
        }
    }
}

fn summarize<'a>(hits: impl IntoIterator<Item = &'a Hit>, values: Vec<String>) -> Option<Fired> {
    let mut hits = hits.into_iter();
    let first = hits.next()?;
    let (mut event_count, mut last_seen) = (first.event_count, first.timestamp);
    for hit in hits {
        event_count += hit.event_count;
        last_seen = hit.timestamp;
    }
    Some(Fired {
        event_count,
        first_seen: first.timestamp,
        last_seen,
        values,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 22, 10, 0, 0).unwrap() + Duration::seconds(secs)
    }

    fn hit(input: usize, secs: i64) -> Hit {
        Hit {
            input,
            timestamp: at(secs),
            value: None,
            event_count: 1,
        }
    }

    fn valued(secs: i64, value: &str) -> Hit {
        Hit {
            value: Some(value.into()),
            ..hit(0, secs)
        }
    }

    fn group(ip: &str) -> Vec<String> {
        vec![ip.to_string()]
    }

    fn event_count(threshold: u64) -> CorrelationState {
        CorrelationState::new(
            CorrelationKind::EventCount,
            Some(Threshold::Gte(threshold)),
            Duration::seconds(60),
            1,
        )
    }

    fn temporal(kind: CorrelationKind) -> CorrelationState {
        CorrelationState::new(kind, None, Duration::seconds(60), 2)
    }

    #[test]
    fn event_count_fires_when_threshold_is_reached_in_window() {
        let mut state = event_count(3);

        assert_eq!(state.observe(group("a"), hit(0, 0)), None);
        assert_eq!(state.observe(group("a"), hit(0, 30)), None);
        assert_eq!(
            state.observe(group("a"), hit(0, 60)),
            Some(Fired {
                event_count: 3,
                first_seen: at(0),
                last_seen: at(60),
                values: vec![],
            })
        );
    }

    #[test]
    fn event_count_forgets_hits_outside_the_window() {
        let mut state = event_count(3);

        state.observe(group("a"), hit(0, 0));
        state.observe(group("a"), hit(0, 61));

        assert_eq!(state.observe(group("a"), hit(0, 62)), None);
    }

    #[test]
    fn groups_are_counted_separately() {
        let mut state = event_count(2);

        assert_eq!(state.observe(group("a"), hit(0, 0)), None);
        assert_eq!(state.observe(group("b"), hit(0, 1)), None);
        assert!(state.observe(group("a"), hit(0, 2)).is_some());
    }

    #[test]
    fn a_group_resets_after_firing() {
        let mut state = event_count(2);
        state.observe(group("a"), hit(0, 0));
        assert!(state.observe(group("a"), hit(0, 1)).is_some());

        assert_eq!(state.observe(group("a"), hit(0, 2)), None);
        assert_eq!(state.observe(group("a"), hit(0, 3)).map(|f| f.first_seen), Some(at(2)));
    }

    #[test]
    fn chained_hits_count_their_underlying_events() {
        let mut state = event_count(2);
        state.observe(
            group("a"),
            Hit {
                event_count: 10,
                ..hit(0, 0)
            },
        );

        assert_eq!(state.observe(group("a"), hit(0, 1)).map(|f| f.event_count), Some(11));
    }

    #[test]
    fn value_count_counts_distinct_values() {
        let mut state = CorrelationState::new(
            CorrelationKind::ValueCount { field: "user".into() },
            Some(Threshold::Gte(3)),
            Duration::seconds(60),
            1,
        );

        assert_eq!(state.observe(group("a"), valued(0, "root")), None);
        assert_eq!(state.observe(group("a"), valued(1, "root")), None);
        assert_eq!(state.observe(group("a"), valued(2, "admin")), None);
        assert_eq!(
            state.observe(group("a"), hit(0, 3)),
            None,
            "hits without a value are not counted"
        );

        let fired = state
            .observe(group("a"), valued(4, "oracle"))
            .expect("third distinct user");
        assert_eq!(fired.values, ["admin", "oracle", "root"]);
        assert_eq!(fired.event_count, 4, "only hits carrying a value count as events");
    }

    #[test]
    fn temporal_needs_every_rule_in_any_order() {
        let mut state = temporal(CorrelationKind::Temporal);

        assert_eq!(state.observe(group("a"), hit(1, 0)), None);
        assert_eq!(state.observe(group("a"), hit(1, 10)), None);
        assert!(state.observe(group("a"), hit(0, 20)).is_some());
    }

    #[test]
    fn temporal_ignores_rules_seen_outside_the_window() {
        let mut state = temporal(CorrelationKind::Temporal);
        state.observe(group("a"), hit(0, 0));

        assert_eq!(state.observe(group("a"), hit(1, 61)), None);
    }

    #[test]
    fn temporal_ordered_needs_the_listed_order() {
        let mut state = temporal(CorrelationKind::TemporalOrdered);

        assert_eq!(
            state.observe(group("a"), hit(1, 0)),
            None,
            "second rule first does not count"
        );
        assert_eq!(state.observe(group("a"), hit(0, 10)), None);
        let fired = state.observe(group("a"), hit(1, 20)).expect("first then second");

        assert_eq!(fired.first_seen, at(10), "the range covers the matching sequence");
        assert_eq!(fired.event_count, 2);
    }

    #[test]
    fn temporal_ordered_uses_arrival_order_for_equal_timestamps() {
        let mut state = temporal(CorrelationKind::TemporalOrdered);
        state.observe(group("a"), hit(0, 5));

        assert!(state.observe(group("a"), hit(1, 5)).is_some());
    }

    #[test]
    fn idle_groups_are_evicted() {
        let mut state = event_count(100);
        for i in 0..1000 {
            state.observe(group(&format!("10.0.{}.{}", i / 256, i % 256)), hit(0, 0));
        }
        assert_eq!(state.group_count(), 1000);

        state.observe(group("late"), hit(0, 3600));

        assert_eq!(state.group_count(), 1, "only the group seen within the window survives");
    }
}
