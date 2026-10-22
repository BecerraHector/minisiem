//! Use case: read raw lines, normalize them, run every detector and deliver
//! the resulting alerts.

use std::io::{self, BufRead};

use crate::alerting::AlertSink;
use crate::detection::Detector;
use crate::ingestion::LogParser;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub lines: usize,
    pub events: usize,
    pub alerts: usize,
}

pub fn run<R: BufRead>(
    mut input: R,
    parser: &dyn LogParser,
    detectors: &mut [Box<dyn Detector>],
    sink: &mut dyn AlertSink,
) -> io::Result<Stats> {
    let mut stats = Stats::default();
    let mut buf = Vec::new();

    // Read raw bytes instead of `lines()`: attacker-controlled fields can
    // carry invalid UTF-8, and one bad line must not stop the whole pipeline.
    while input.read_until(b'\n', &mut buf)? > 0 {
        stats.lines += 1;
        let line = String::from_utf8_lossy(&buf);

        if let Some(event) = parser.parse(line.trim_end_matches(['\n', '\r'])) {
            stats.events += 1;
            for detector in detectors.iter_mut() {
                if let Some(alert) = detector.evaluate(&event) {
                    stats.alerts += 1;
                    sink.emit(&alert)?;
                }
            }
        }
        buf.clear();
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::Alert;
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
        let mut detectors: Vec<Box<dyn Detector>> = vec![Box::new(SshBruteForce::new(2, Duration::seconds(60)))];
        let mut sink = CollectSink::default();

        let stats = run(input.as_slice(), &parser, &mut detectors, &mut sink).unwrap();

        assert_eq!(stats, Stats { lines: 4, events: 3, alerts: 1 });
        assert_eq!(sink.0.len(), 1);
        assert_eq!(sink.0[0].event_count, 2);
    }
}
