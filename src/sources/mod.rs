//! Live event sources (adapters) for watch mode. Each source runs on its own
//! thread and sends what it reads through a channel; the pipeline consumes
//! the channel on a single thread, so detectors never need locks.

mod syslog_udp;

pub use syslog_udp::{SyslogUdp, event_from_datagram};

use std::io;
use std::sync::mpsc::Receiver;

use crate::alerting::AlertSink;
use crate::event::Event;
use crate::pipeline::Pipeline;

/// What sources send to the pipeline thread.
#[derive(Debug)]
pub enum Message {
    Event(Event),
    /// A source stopped and will send nothing more.
    Failed {
        source: String,
        error: String,
    },
    /// The user asked to stop (Ctrl+C or SIGTERM).
    Shutdown,
}

/// Why watching ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Stop {
    Interrupted,
    SourceFailed { source: String, error: String },
}

/// Feeds every received event to the pipeline until the user stops or a
/// source fails. A failed source ends the watch: a source that silently
/// stopped would be a blind spot.
pub fn drain<S: AlertSink>(messages: &Receiver<Message>, pipeline: &mut Pipeline<S>) -> io::Result<Stop> {
    loop {
        match messages.recv() {
            Ok(Message::Event(event)) => pipeline.process(&event)?,
            Ok(Message::Shutdown) => return Ok(Stop::Interrupted),
            Ok(Message::Failed { source, error }) => return Ok(Stop::SourceFailed { source, error }),
            Err(_) => {
                return Ok(Stop::SourceFailed {
                    source: "sources".into(),
                    error: "every source disconnected".into(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::Alert;
    use crate::detection::SshBruteForce;
    use crate::event::{EventKind, LogSource};
    use chrono::{Duration, TimeZone, Utc};
    use std::sync::mpsc;

    #[derive(Default)]
    struct CollectSink(Vec<Alert>);

    impl AlertSink for CollectSink {
        fn emit(&mut self, alert: &Alert) -> io::Result<()> {
            self.0.push(alert.clone());
            Ok(())
        }
    }

    fn failed(secs: i64) -> Message {
        Message::Event(Event {
            timestamp: Utc.with_ymd_and_hms(2026, 10, 22, 10, 0, 0).unwrap() + Duration::seconds(secs),
            host: "srv01".into(),
            process: "sshd".into(),
            kind: EventKind::FailedLogin,
            user: "root".into(),
            src_ip: "203.0.113.7".parse().unwrap(),
            message: String::new(),
            logsource: LogSource::new("linux", "sshd"),
        })
    }

    fn pipeline() -> Pipeline<CollectSink> {
        Pipeline::new(
            vec![Box::new(SshBruteForce::new(2, Duration::seconds(60)))],
            CollectSink::default(),
        )
    }

    #[test]
    fn processes_events_until_shutdown() {
        let (tx, rx) = mpsc::channel();
        for message in [failed(0), failed(1), Message::Shutdown, failed(2)] {
            tx.send(message).unwrap();
        }
        let mut pipeline = pipeline();

        let stop = drain(&rx, &mut pipeline).unwrap();

        assert_eq!(stop, Stop::Interrupted);
        assert_eq!((pipeline.stats().events, pipeline.stats().alerts), (2, 1));
    }

    #[test]
    fn stops_when_a_source_fails() {
        let (tx, rx) = mpsc::channel();
        tx.send(failed(0)).unwrap();
        tx.send(Message::Failed {
            source: "journald".into(),
            error: "journalctl exited".into(),
        })
        .unwrap();
        let mut pipeline = pipeline();

        let stop = drain(&rx, &mut pipeline).unwrap();

        assert_eq!(
            stop,
            Stop::SourceFailed {
                source: "journald".into(),
                error: "journalctl exited".into()
            }
        );
        assert_eq!(pipeline.stats().events, 1);
    }

    #[test]
    fn treats_every_source_disconnecting_as_a_failure() {
        let (tx, rx) = mpsc::channel();
        tx.send(failed(0)).unwrap();
        drop(tx);

        let stop = drain(&rx, &mut pipeline()).unwrap();

        assert!(matches!(stop, Stop::SourceFailed { .. }));
    }
}
