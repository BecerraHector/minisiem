//! Live event sources (adapters) for watch mode. Each source runs on its own
//! thread and hands what it reads to an [`Outlet`]; the pipeline consumes the
//! [`Inlet`] on a single thread, so detectors never need locks.
//!
//! Events travel through a bounded queue: a flood cannot exhaust memory, it
//! can only make events drop, and drops are counted and reported. Control
//! messages (shutdown, failed sources) use a separate channel the pipeline
//! checks first, so they never wait behind a backlog of events.

mod journal;
mod syslog_udp;

pub use journal::{JOURNALCTL_ENV, JournalFollow};
pub use syslog_udp::{SyslogUdp, event_from_datagram};

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError, TrySendError};
use std::time::Duration;

use crate::alerting::AlertSink;
use crate::event::Event;
use crate::pipeline::Pipeline;

/// Events waiting for the pipeline before new ones are dropped.
pub const QUEUE_CAPACITY: usize = 10_000;

/// How long the pipeline waits for an event before checking control again.
const POLL: Duration = Duration::from_millis(100);

#[derive(Debug)]
enum Control {
    /// A source stopped and will send nothing more.
    Failed { source: String, error: String },
    /// The user asked to stop (Ctrl+C or SIGTERM).
    Shutdown,
}

/// The sending side, cloned into every source.
#[derive(Clone)]
pub struct Outlet {
    events: SyncSender<Event>,
    control: Sender<Control>,
    dropped: Arc<AtomicU64>,
}

/// The receiving side, owned by the pipeline thread.
pub struct Inlet {
    events: Receiver<Event>,
    control: Receiver<Control>,
    dropped: Arc<AtomicU64>,
}

pub fn channel(capacity: usize) -> (Outlet, Inlet) {
    let (event_tx, event_rx) = mpsc::sync_channel(capacity);
    let (control_tx, control_rx) = mpsc::channel();
    let dropped = Arc::new(AtomicU64::new(0));
    (
        Outlet {
            events: event_tx,
            control: control_tx,
            dropped: Arc::clone(&dropped),
        },
        Inlet {
            events: event_rx,
            control: control_rx,
            dropped,
        },
    )
}

impl Outlet {
    /// Queues an event, or drops and counts it when the queue is full.
    /// Returns `false` once the pipeline is gone, so the source can stop.
    pub fn event(&self, event: Event) -> bool {
        match self.events.try_send(event) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                // Dropping events is a blind spot an attacker can cause on
                // purpose, so the first one is announced, not hidden.
                if self.dropped.fetch_add(1, Ordering::Relaxed) == 0 {
                    eprintln!(
                        "minisiem: warning: event queue full ({QUEUE_CAPACITY}), dropping events: the pipeline \
                         cannot keep up, possibly because of a flood"
                    );
                }
                true
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    pub fn fail(&self, source: &str, error: String) {
        let _ = self.control.send(Control::Failed {
            source: source.to_string(),
            error,
        });
    }

    pub fn shutdown(&self) {
        let _ = self.control.send(Control::Shutdown);
    }
}

impl Inlet {
    /// Events dropped because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Why watching ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Stop {
    Interrupted,
    SourceFailed { source: String, error: String },
}

/// Feeds received events to the pipeline until the user stops or a source
/// fails. A failed source ends the watch: a source that silently stopped
/// would be a blind spot.
pub fn drain<S: AlertSink>(inlet: &Inlet, pipeline: &mut Pipeline<S>) -> io::Result<Stop> {
    loop {
        // Control first, before every event: stopping never waits for a
        // backlog to be processed.
        match inlet.control.try_recv() {
            Ok(Control::Shutdown) => return Ok(Stop::Interrupted),
            Ok(Control::Failed { source, error }) => return Ok(Stop::SourceFailed { source, error }),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => {}
        }

        match inlet.events.recv_timeout(POLL) {
            Ok(event) => pipeline.process(&event)?,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
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
    use chrono::{TimeZone, Utc};

    /// Collects alerts and asks to stop after the first one, like an analyst
    /// pressing Ctrl+C, so tests need no timing.
    struct StopOnAlert {
        alerts: Vec<Alert>,
        outlet: Outlet,
    }

    impl AlertSink for StopOnAlert {
        fn emit(&mut self, alert: &Alert) -> io::Result<()> {
            self.alerts.push(alert.clone());
            self.outlet.shutdown();
            Ok(())
        }
    }

    fn failed(secs: i64) -> Event {
        Event {
            timestamp: Utc.with_ymd_and_hms(2026, 10, 22, 10, 0, 0).unwrap() + chrono::Duration::seconds(secs),
            host: "srv01".into(),
            process: "sshd".into(),
            kind: EventKind::FailedLogin,
            user: "root".into(),
            src_ip: "203.0.113.7".parse().unwrap(),
            message: String::new(),
            logsource: LogSource::new("linux", "sshd"),
        }
    }

    fn pipeline(outlet: &Outlet) -> Pipeline<StopOnAlert> {
        Pipeline::new(
            vec![Box::new(SshBruteForce::new(2, chrono::Duration::seconds(60)))],
            StopOnAlert {
                alerts: vec![],
                outlet: outlet.clone(),
            },
        )
    }

    #[test]
    fn processes_events_until_shutdown() {
        let (outlet, inlet) = channel(10);
        let mut pipeline = pipeline(&outlet);
        for secs in 0..3 {
            assert!(outlet.event(failed(secs)));
        }

        let stop = drain(&inlet, &mut pipeline).unwrap();

        assert_eq!(stop, Stop::Interrupted);
        assert_eq!(
            (pipeline.stats().events, pipeline.stats().alerts),
            (2, 1),
            "the third event stays queued: shutdown wins"
        );
    }

    #[test]
    fn shutdown_does_not_wait_behind_queued_events() {
        let (outlet, inlet) = channel(1000);
        let mut pipeline = pipeline(&outlet);
        for secs in 0..1000 {
            outlet.event(failed(secs));
        }
        outlet.shutdown();

        assert_eq!(drain(&inlet, &mut pipeline).unwrap(), Stop::Interrupted);
        assert_eq!(pipeline.stats().events, 0);
    }

    #[test]
    fn stops_when_a_source_fails() {
        let (outlet, inlet) = channel(10);
        outlet.fail("journald", "journalctl exited".into());

        assert_eq!(
            drain(&inlet, &mut pipeline(&outlet)).unwrap(),
            Stop::SourceFailed {
                source: "journald".into(),
                error: "journalctl exited".into()
            }
        );
    }

    #[test]
    fn drains_what_is_queued_then_fails_when_every_source_is_gone() {
        let (outlet, inlet) = channel(10);
        outlet.event(failed(0));
        let mut pipeline = Pipeline::new(vec![], crate::alerting::ConsoleSink::new(io::sink()));
        drop(outlet);

        let stop = drain(&inlet, &mut pipeline).unwrap();

        assert!(matches!(stop, Stop::SourceFailed { .. }));
        assert_eq!(pipeline.stats().events, 1);
    }

    #[test]
    fn a_full_queue_drops_and_counts_new_events() {
        let (outlet, inlet) = channel(2);

        for secs in 0..5 {
            assert!(
                outlet.event(failed(secs)),
                "dropping is not a reason to stop the source"
            );
        }

        assert_eq!(inlet.dropped(), 3);
        assert_eq!(inlet.events.try_iter().count(), 2);
    }

    #[test]
    fn sources_learn_when_the_pipeline_is_gone() {
        let (outlet, inlet) = channel(2);
        drop(inlet);

        assert!(!outlet.event(failed(0)));
    }
}
