//! Use case: run every detector on normalized events and deliver the
//! resulting alerts, either from a line-oriented reader (batch) or one event
//! at a time (live sources).

use std::io::{self, BufRead};

use crate::alert::Alert;
use crate::alerting::AlertSink;
use crate::detection::Detector;
use crate::event::Event;
use crate::ingestion::LogParser;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub lines: usize,
    pub events: usize,
    pub alerts: usize,
}

/// Port: somewhere events and alerts are kept for later search. Writes may
/// be buffered until [`Archive::flush`].
pub trait Archive: Send {
    fn record_event(&mut self, event: &Event) -> io::Result<()>;
    fn record_alert(&mut self, alert: &Alert) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
}

pub struct Pipeline<S> {
    detectors: Vec<Box<dyn Detector>>,
    sink: S,
    archive: Option<Box<dyn Archive>>,
    stats: Stats,
}

impl<S: AlertSink> Pipeline<S> {
    pub fn new(detectors: Vec<Box<dyn Detector>>, sink: S) -> Self {
        Self {
            detectors,
            sink,
            archive: None,
            stats: Stats::default(),
        }
    }

    /// Also keeps every event and alert in `archive`, if there is one.
    pub fn with_archive(mut self, archive: Option<Box<dyn Archive>>) -> Self {
        self.archive = archive;
        self
    }

    /// Runs every detector on one event and emits what they raise, in order.
    /// With an archive, the event and its alerts are archived too.
    pub fn process(&mut self, event: &Event) -> io::Result<()> {
        self.stats.events += 1;
        if let Some(archive) = &mut self.archive {
            archive.record_event(event)?;
        }
        for detector in self.detectors.iter_mut() {
            for alert in detector.evaluate(event) {
                self.stats.alerts += 1;
                self.sink.emit(&alert)?;
                if let Some(archive) = &mut self.archive {
                    archive.record_alert(&alert)?;
                }
            }
        }
        Ok(())
    }

    /// Makes what the archive buffered durable. Without an archive, does
    /// nothing.
    pub fn flush_archive(&mut self) -> io::Result<()> {
        match &mut self.archive {
            Some(archive) => archive.flush(),
            None => Ok(()),
        }
    }

    /// Reads `input` to the end, parsing and processing each line.
    pub fn run<R: BufRead>(&mut self, mut input: R, parser: &dyn LogParser) -> io::Result<()> {
        let mut buf = Vec::new();

        // Read raw bytes instead of `lines()`: attacker-controlled fields can
        // carry invalid UTF-8, and one bad line must not stop the whole pipeline.
        while input.read_until(b'\n', &mut buf)? > 0 {
            self.stats.lines += 1;
            let line = String::from_utf8_lossy(&buf);
            if let Some(event) = parser.parse(line.trim_end_matches(['\n', '\r'])) {
                self.process(&event)?;
            }
            buf.clear();
        }
        Ok(())
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    pub fn into_sink(self) -> S {
        self.sink
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{Alert, Evidence};
    use crate::detection::SshBruteForce;
    use crate::ingestion::SshdParser;
    use chrono::{Duration, FixedOffset};

    #[derive(Default)]
    struct CollectSink(Vec<Alert>);

    impl AlertSink for CollectSink {
        fn emit(&mut self, alert: &Alert) -> io::Result<()> {
            self.0.push(alert.clone());
            Ok(())
        }
    }

    #[test]
    fn counts_lines_events_and_alerts_and_survives_invalid_utf8() {
        let mut input = Vec::new();
        input.extend_from_slice(b"Oct 22 10:00:00 srv01 CRON[1]: noise\n");
        input.extend_from_slice(b"Oct 22 10:00:01 srv01 sshd[2]: Invalid user \xff\xfe from 203.0.113.7 port 1\n");
        for sec in 2..4 {
            input.extend_from_slice(
                format!("Oct 22 10:00:0{sec} srv01 sshd[2]: Failed password for root from 203.0.113.7 port 1 ssh2\n")
                    .as_bytes(),
            );
        }
        let parser = SshdParser::new(2026, FixedOffset::east_opt(0).unwrap());
        let mut pipeline = Pipeline::new(
            vec![Box::new(SshBruteForce::new(2, Duration::seconds(60)))],
            CollectSink::default(),
        );

        pipeline.run(input.as_slice(), &parser).unwrap();

        assert_eq!(
            pipeline.stats(),
            Stats {
                lines: 4,
                events: 3,
                alerts: 1
            }
        );
        let alerts = pipeline.into_sink().0;
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0].evidence, Evidence::Burst { event_count: 2, .. }));
    }

    #[test]
    fn processes_events_one_at_a_time_without_counting_lines() {
        let parser = SshdParser::new(2026, FixedOffset::east_opt(0).unwrap());
        let event = parser
            .parse("Oct 22 10:00:00 srv01 sshd[2]: Failed password for root from 203.0.113.7 port 1 ssh2")
            .unwrap();
        let mut pipeline = Pipeline::new(vec![Box::new(TwoAlerts)], CollectSink::default());

        pipeline.process(&event).unwrap();
        pipeline.process(&event).unwrap();

        assert_eq!(
            pipeline.stats(),
            Stats {
                lines: 0,
                events: 2,
                alerts: 4
            }
        );
    }

    /// Fires twice for every event, like a rule plus a correlation over it.
    struct TwoAlerts;

    impl Detector for TwoAlerts {
        fn evaluate(&mut self, event: &crate::event::Event) -> Vec<Alert> {
            let alert = |title: &str| Alert {
                rule_id: title.into(),
                title: title.into(),
                severity: crate::alert::Severity::Low,
                techniques: vec![],
                src_ip: event.src_ip,
                host: event.host.clone(),
                evidence: Evidence::Event(event.clone()),
            };
            vec![alert("first"), alert("second")]
        }
    }

    #[test]
    fn emits_every_alert_a_detector_returns_in_order() {
        let input = b"Oct 22 10:00:00 srv01 sshd[2]: Failed password for root from 203.0.113.7 port 1 ssh2\n";
        let parser = SshdParser::new(2026, FixedOffset::east_opt(0).unwrap());
        let mut pipeline = Pipeline::new(vec![Box::new(TwoAlerts)], CollectSink::default());

        pipeline.run(input.as_slice(), &parser).unwrap();

        assert_eq!(pipeline.stats().alerts, 2);
        let alerts = pipeline.into_sink().0;
        let titles: Vec<_> = alerts.iter().map(|a| a.title.as_str()).collect();
        assert_eq!(titles, ["first", "second"]);
    }
}
