//! Live event sources (adapters) for watch mode. Each source runs on its own
//! thread and hands what it reads to an [`Outlet`]; the pipeline consumes the
//! [`Inlet`] on a single thread, so detectors never need locks.
//!
//! Events travel through a bounded queue: a flood cannot exhaust memory, it
//! can only make events drop, and drops are counted and reported. Sources
//! that wait instead of dropping hold at most half of it, so a backlog they
//! wait out never leaves the dropping sources without room. Control
//! messages (shutdown, failed sources) use a separate channel the pipeline
//! checks first, so they never wait behind a backlog of events.

mod journal;
mod syslog_udp;

pub use journal::{JOURNALCTL_ENV, JournalFollow};
pub use syslog_udp::{KernelDrops, SyslogUdp, event_from_datagram};

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError, TrySendError};
use std::time::Duration;

use crate::alerting::AlertSink;
use crate::event::Event;
use crate::pipeline::{Pipeline, Stats};

/// Events waiting for the pipeline before new ones are dropped.
pub const QUEUE_CAPACITY: usize = 10_000;

/// The part of a queue sources that wait may hold: the rest stays for the
/// sources that drop.
fn waiting_share(capacity: usize) -> usize {
    (capacity / 2).max(1)
}

/// An event in the queue, marked with whether its source waited for room.
struct Queued {
    event: Event,
    waited: bool,
}

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
    events: SyncSender<Queued>,
    /// One slot per waiting event in the queue: full means the waiting
    /// sources hold their whole share.
    waiting: SyncSender<()>,
    control: Sender<Control>,
    dropped: Arc<AtomicU64>,
    capacity: usize,
}

/// The receiving side, owned by the pipeline thread.
pub struct Inlet {
    events: Receiver<Queued>,
    waiting: Receiver<()>,
    control: Receiver<Control>,
    dropped: Arc<AtomicU64>,
    capacity: usize,
}

pub fn channel(capacity: usize) -> (Outlet, Inlet) {
    let (event_tx, event_rx) = mpsc::sync_channel(capacity);
    let (waiting_tx, waiting_rx) = mpsc::sync_channel(waiting_share(capacity));
    let (control_tx, control_rx) = mpsc::channel();
    let dropped = Arc::new(AtomicU64::new(0));
    (
        Outlet {
            events: event_tx,
            waiting: waiting_tx,
            control: control_tx,
            dropped: Arc::clone(&dropped),
            capacity,
        },
        Inlet {
            events: event_rx,
            waiting: waiting_rx,
            control: control_rx,
            dropped,
            capacity,
        },
    )
}

/// Announces the first event dropped from a queue of `capacity`.
fn queue_full_warning(capacity: usize) -> String {
    format!(
        "minisiem: warning: event queue full ({capacity}), dropping events: the pipeline cannot keep up, \
         possibly because of a flood"
    )
}

impl Outlet {
    /// Queues an event, or drops and counts it when the queue is full.
    /// Returns `false` once the pipeline is gone, so the source can stop.
    pub fn event(&self, event: Event) -> bool {
        match self.events.try_send(Queued { event, waited: false }) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                // Dropping events is a blind spot an attacker can cause on
                // purpose, so the first one is announced, not hidden.
                if self.dropped.fetch_add(1, Ordering::Relaxed) == 0 {
                    eprintln!("{}", queue_full_warning(self.capacity));
                }
                true
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Queues an event, waiting while the queue is full instead of dropping
    /// it. For sources that can be slowed down without losing anything
    /// (journald keeps its entries). Also waits while these sources hold
    /// their share of the queue. Returns `false` once the pipeline is gone,
    /// so the source can stop.
    pub fn wait_and_send(&self, event: Event) -> bool {
        self.waiting.send(()).is_ok() && self.events.send(Queued { event, waited: true }).is_ok()
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

    /// The live count behind [`Inlet::dropped`], readable from another thread.
    pub fn dropped_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.dropped)
    }

    /// The next queued event, waiting up to `timeout` for one.
    fn next(&self, timeout: Duration) -> Result<Event, RecvTimeoutError> {
        self.events.recv_timeout(timeout).map(|queued| self.taken(queued))
    }

    /// The next queued event, if there is one already.
    fn try_next(&self) -> Option<Event> {
        self.events.try_recv().ok().map(|queued| self.taken(queued))
    }

    /// Gives a waiting source its slot back once its event left the queue.
    fn taken(&self, queued: Queued) -> Event {
        if queued.waited {
            let _ = self.waiting.try_recv();
        }
        queued.event
    }

    /// Empties the queue and returns how many events it held, so stopping
    /// can report them instead of losing them silently. Takes at most one
    /// queue's worth, as sources may still be adding events. Only for when
    /// watching ends: waiting sources do not get their slots back.
    pub fn discard_queued(&self) -> usize {
        self.events.try_iter().take(self.capacity).count()
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
    drain_reporting(inlet, pipeline, |_| {})
}

/// Like [`drain`], and hands the pipeline's stats to `progress` after every
/// event, so another thread can report them if this one gets stuck.
pub fn drain_reporting<S: AlertSink>(
    inlet: &Inlet,
    pipeline: &mut Pipeline<S>,
    mut progress: impl FnMut(Stats),
) -> io::Result<Stop> {
    loop {
        // Control first, before every event: stopping never waits for a
        // backlog to be processed.
        match inlet.control.try_recv() {
            Ok(Control::Shutdown) => return Ok(Stop::Interrupted),
            Ok(Control::Failed { source, error }) => {
                process_backlog(inlet, pipeline, &mut progress)?;
                return Ok(Stop::SourceFailed { source, error });
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => {}
        }

        match inlet.next(POLL) {
            Ok(event) => {
                pipeline.process(&event)?;
                progress(pipeline.stats());
            }
            // A quiet moment: make what was archived durable and visible.
            Err(RecvTimeoutError::Timeout) => pipeline.flush_archive()?,
            Err(RecvTimeoutError::Disconnected) => {
                // The last source may have reported why it stopped after
                // the control check above.
                if let Ok(Control::Failed { source, error }) = inlet.control.try_recv() {
                    return Ok(Stop::SourceFailed { source, error });
                }
                return Ok(Stop::SourceFailed {
                    source: "sources".into(),
                    error: "every source disconnected".into(),
                });
            }
        }
    }
}

/// Processes the events already queued when a source failed: the last ones
/// before it died may be the most relevant. Ctrl+C still stops at once, and
/// at most one queue's worth is processed, as other sources keep adding.
fn process_backlog<S: AlertSink>(
    inlet: &Inlet,
    pipeline: &mut Pipeline<S>,
    progress: &mut impl FnMut(Stats),
) -> io::Result<()> {
    for _ in 0..inlet.capacity {
        // Another source failing too changes nothing: watching ends anyway.
        if let Ok(Control::Shutdown) = inlet.control.try_recv() {
            return Ok(());
        }
        let Some(event) = inlet.try_next() else {
            return Ok(());
        };
        pipeline.process(&event)?;
        progress(pipeline.stats());
    }
    Ok(())
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
    fn reports_progress_after_every_event() {
        let (outlet, inlet) = channel(10);
        let mut pipeline = pipeline(&outlet);
        for secs in 0..3 {
            outlet.event(failed(secs));
        }
        let mut seen = Vec::new();

        drain_reporting(&inlet, &mut pipeline, |stats| seen.push((stats.events, stats.alerts))).unwrap();

        assert_eq!(
            seen,
            [(1, 0), (2, 1)],
            "the shutdown raised by the alert stops the third"
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
    fn the_queue_full_warning_names_the_queue_size() {
        assert_eq!(
            queue_full_warning(2),
            "minisiem: warning: event queue full (2), dropping events: the pipeline cannot keep up, possibly \
             because of a flood"
        );
    }

    #[test]
    fn keeps_the_error_of_a_source_that_fails_and_disconnects_while_waiting() {
        let (outlet, inlet) = channel(10);
        // Fails once drain is already waiting for events, past its control check.
        std::thread::spawn(move || {
            std::thread::sleep(POLL / 2);
            outlet.fail("journald", "journalctl exited".into());
        });

        assert_eq!(
            drain(&inlet, &mut quiet_pipeline()).unwrap(),
            Stop::SourceFailed {
                source: "journald".into(),
                error: "journalctl exited".into()
            }
        );
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

    fn quiet_pipeline() -> Pipeline<crate::alerting::ConsoleSink<io::Sink>> {
        Pipeline::new(vec![], crate::alerting::ConsoleSink::new(io::sink()))
    }

    #[test]
    fn processes_queued_events_before_reporting_a_failed_source() {
        // The last events before a source dies may be the most relevant.
        let (outlet, inlet) = channel(10);
        for secs in 0..3 {
            outlet.event(failed(secs));
        }
        outlet.fail("journald", "journalctl exited".into());
        let mut pipeline = quiet_pipeline();

        let stop = drain(&inlet, &mut pipeline).unwrap();

        assert!(matches!(stop, Stop::SourceFailed { .. }));
        assert_eq!(pipeline.stats().events, 3);
    }

    #[test]
    fn ctrl_c_still_cuts_the_backlog_of_a_failed_source_short() {
        let (outlet, inlet) = channel(10);
        for secs in 0..5 {
            outlet.event(failed(secs));
        }
        outlet.fail("journald", "journalctl exited".into());
        // Asks to stop after the first alert, raised by the second event.
        let mut pipeline = pipeline(&outlet);

        let stop = drain(&inlet, &mut pipeline).unwrap();

        assert!(matches!(stop, Stop::SourceFailed { .. }), "the source did fail");
        assert_eq!(pipeline.stats().events, 2);
    }

    #[test]
    fn counts_and_discards_the_events_left_in_the_queue() {
        let (outlet, inlet) = channel(10);
        for secs in 0..4 {
            outlet.event(failed(secs));
        }

        assert_eq!(inlet.discard_queued(), 4);
        assert_eq!(inlet.discard_queued(), 0);
    }

    #[test]
    fn a_source_that_can_wait_loses_nothing_when_the_queue_is_full() {
        let (outlet, inlet) = channel(1);
        assert!(outlet.event(failed(0)));
        let dropped = inlet.dropped_counter();
        let reader = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            inlet.events.iter().take(2).count()
        });

        assert!(outlet.wait_and_send(failed(1)), "waits for space instead of dropping");

        assert_eq!(reader.join().unwrap(), 2);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
    }

    fn udp(secs: i64) -> Event {
        Event {
            host: "udp".into(),
            ..failed(secs)
        }
    }

    /// Waits until a sender blocked on a full queue has had time to block.
    fn settle() {
        std::thread::sleep(Duration::from_millis(100));
    }

    #[test]
    fn a_waiting_source_leaves_room_for_the_sources_that_drop() {
        let (outlet, inlet) = channel(4);
        let journald = outlet.clone();
        std::thread::spawn(move || (0..10).all(|secs| journald.wait_and_send(failed(secs))));
        settle();

        assert!(outlet.event(udp(0)));
        assert!(outlet.event(udp(1)));

        assert_eq!(inlet.dropped(), 0, "half the queue stays free for UDP");
    }

    #[test]
    fn both_sources_get_through_while_both_flood() {
        let (outlet, inlet) = channel(4);
        let journald = outlet.clone();
        let backlog = std::thread::spawn(move || (0..20).all(|secs| journald.wait_and_send(failed(secs))));
        let mut hosts: Vec<String> = Vec::new();

        // While journald still has a backlog, UDP sends bursts of its half of
        // the queue, and the pipeline takes events until it has the burst.
        for burst in 0..5 {
            settle();
            outlet.event(udp(2 * burst));
            outlet.event(udp(2 * burst + 1));
            while hosts.iter().filter(|host| *host == "udp").count() < 2 * (burst as usize + 1) {
                hosts.push(inlet.next(POLL).unwrap().host);
            }
        }
        drop(outlet);
        // Ends once journald has sent its whole backlog and let go.
        loop {
            match inlet.next(POLL) {
                Ok(event) => hosts.push(event.host),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        assert!(backlog.join().unwrap());
        assert_eq!(inlet.dropped(), 0);
        assert_eq!(hosts.iter().filter(|host| *host == "udp").count(), 10);
        assert_eq!(hosts.iter().filter(|host| *host == "srv01").count(), 20);
    }

    #[test]
    fn a_waiting_source_learns_when_the_pipeline_is_gone() {
        let (outlet, inlet) = channel(1);
        outlet.event(failed(0));
        drop(inlet);

        assert!(!outlet.wait_and_send(failed(1)));
    }
}
