use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration as StdDuration, Instant};

use chrono::{Datelike, Duration, Local, Offset};
use clap::{ArgGroup, Args, Parser, Subcommand};

use minisiem::alerting::ConsoleSink;
use minisiem::detection::sigma::SigmaEngine;
use minisiem::detection::{Detector, SshBruteForce};
use minisiem::ingestion::{AutoParser, SSHD_PROCESSES};
use minisiem::pipeline::{Pipeline, Stats};
use minisiem::rule_loading;
use minisiem::sources::{self, JournalFollow, QUEUE_CAPACITY, Stop, SyslogUdp, drain_reporting};

/// Detect attacks in sshd logs.
///
/// Reads sshd logs line by line, in any mix of these formats: syslog files
/// (/var/log/auth.log, /var/log/secure), `journalctl -o short-iso`,
/// `journalctl -o json` and network syslog (RFC 3164 / RFC 5424). Prints one
/// line per alert.
#[derive(Parser)]
#[command(version, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Log file to analyze. Reads standard input when omitted or "-".
    file: Option<PathBuf>,

    #[command(flatten)]
    detection: DetectionArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Watch live sources and print alerts as events arrive, until Ctrl+C.
    Watch(WatchArgs),
}

#[derive(Args)]
#[command(group(ArgGroup::new("sources").required(true).multiple(true).args(["journal", "syslog_udp"])))]
struct WatchArgs {
    /// Follow sshd entries in the systemd journal (runs `journalctl`; needs
    /// permission to read the system journal).
    #[arg(long)]
    journal: bool,

    /// Receive syslog messages (RFC 3164 or RFC 5424) on this UDP address,
    /// e.g. 127.0.0.1:5514. Events are timestamped on arrival.
    #[arg(long, value_name = "ADDR")]
    syslog_udp: Option<SocketAddr>,

    /// Allow --syslog-udp on a non-loopback address. UDP syslog is
    /// unauthenticated: anyone who can reach the port can inject events.
    #[arg(long, requires = "syslog_udp")]
    allow_remote_syslog: bool,

    #[command(flatten)]
    detection: DetectionArgs,
}

/// Options shared by every mode that runs detections.
#[derive(Args)]
struct DetectionArgs {
    /// Failed logins from one IP needed to raise an alert.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..))]
    threshold: u64,

    /// Sliding window, in seconds, in which failures are counted.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..))]
    window: u64,

    /// Directory of Sigma detection and correlation rules (*.yml, *.yaml,
    /// searched recursively) to run in addition to the built-in brute force
    /// detection. Any invalid rule aborts startup.
    #[arg(long, value_name = "DIR")]
    rules: Option<PathBuf>,
}

impl DetectionArgs {
    /// The built-in brute force detection plus, if requested, the Sigma rules.
    fn detectors(&self) -> Result<Vec<Box<dyn Detector>>, String> {
        let mut detectors: Vec<Box<dyn Detector>> = vec![Box::new(SshBruteForce::new(
            self.threshold as usize,
            Duration::seconds(self.window as i64),
        ))];
        if let Some(dir) = &self.rules {
            let rules = rule_loading::load_dir(dir).map_err(|e| e.to_string())?;
            eprintln!(
                "minisiem: loaded {} sigma rules from {}",
                rules.detections.len() + rules.correlations.len(),
                dir.display()
            );
            detectors.push(Box::new(SigmaEngine::new(rules)));
        }
        Ok(detectors)
    }
}

/// Parser for every supported format. Syslog timestamps lack year and
/// timezone: the current local ones are assumed.
fn parser() -> AutoParser {
    let now = Local::now();
    AutoParser::new(now.year(), now.offset().fix())
}

fn open_input(file: Option<&PathBuf>) -> io::Result<Box<dyn BufRead>> {
    match file {
        Some(path) if path.as_os_str() != "-" => Ok(Box::new(BufReader::new(File::open(path)?))),
        _ => Ok(Box::new(io::stdin().lock())),
    }
}

/// Batch mode: analyze a file or standard input until it ends.
fn analyze(file: Option<&PathBuf>, detection: &DetectionArgs) -> Result<(), String> {
    let detectors = detection.detectors()?;
    let source = file.map_or("<stdin>".into(), |p| p.display().to_string());
    let input = open_input(file).map_err(|e| format!("{source}: {e}"))?;

    let mut pipeline = Pipeline::new(detectors, ConsoleSink::new(io::stdout().lock()));
    pipeline.run(input, &parser()).map_err(|e| format!("{source}: {e}"))?;

    let stats = pipeline.stats();
    eprintln!(
        "minisiem: {source}: lines={} events={} alerts={}",
        stats.lines, stats.events, stats.alerts
    );
    Ok(())
}

/// Watch mode: run until interrupted or until a source fails.
fn watch(args: &WatchArgs) -> Result<(), String> {
    let mut detectors = args.detection.detectors()?;
    if std::env::var_os(TEST_PANIC_ENV).is_some() {
        detectors.push(Box::new(PanicOnEvent));
    }
    let (outlet, inlet) = sources::channel(QUEUE_CAPACITY);

    let mut kernel_drops = None;
    if let Some(addr) = args.syslog_udp {
        let udp = SyslogUdp::bind(addr, args.allow_remote_syslog)?;
        eprintln!("minisiem: listening for syslog on udp://{}", udp.local_addr());
        kernel_drops = udp.kernel_drops();
        udp.spawn(outlet.clone());
    }
    // Kept alive until watching ends: dropping it stops journalctl.
    let _journal = match args.journal {
        true => {
            let journal = JournalFollow::start(outlet.clone())?;
            eprintln!("minisiem: following journald ({})", SSHD_PROCESSES.join(", "));
            Some(journal)
        }
        false => None,
    };

    // Detection runs on its own thread, so this one can still stop watching
    // when writing an alert blocks (e.g. stdout is a pipe nobody reads).
    let (ended, end) = mpsc::channel();
    let interrupted = ended.clone();
    let shutdown = outlet.clone();
    ctrlc::set_handler(move || {
        shutdown.shutdown();
        let _ = interrupted.send(End::Interrupted);
    })
    .map_err(|e| format!("cannot handle Ctrl+C: {e}"))?;
    drop(outlet);

    let progress = Arc::new(Mutex::new(Stats::default()));
    let dropped = inlet.dropped_counter();
    {
        let progress = Arc::clone(&progress);
        thread::spawn(move || {
            let _report = ReportPanic(ended.clone());
            let mut pipeline = Pipeline::new(detectors, ConsoleSink::new(io::stdout().lock()));
            let stop = drain_reporting(&inlet, &mut pipeline, |stats| {
                if let Ok(mut progress) = progress.lock() {
                    *progress = stats;
                }
            });
            let stats = pipeline.stats();
            // Release stdout before the main thread reports and exits.
            drop(pipeline);
            let unprocessed = inlet.discard_queued();
            let _ = ended.send(End::Drained(stop, stats, unprocessed));
        });
    }

    // Ctrl+C has already queued a shutdown for the pipeline: give it a
    // moment, counted from the first Ctrl+C.
    let mut deadline: Option<Instant> = None;
    let (stop, stats, unprocessed) = loop {
        let message = match deadline {
            None => end.recv().ok(),
            Some(deadline) => end
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .ok(),
        };
        match message {
            Some(End::Drained(stop, stats, unprocessed)) => break (stop, stats, unprocessed),
            Some(End::Panicked) => {
                // Exit as the panic would have on the main thread (code 101,
                // message already printed), but stop journalctl first.
                drop(_journal);
                std::process::exit(101);
            }
            Some(End::Interrupted) => {
                deadline.get_or_insert_with(|| Instant::now() + STOP_GRACE);
            }
            None => {
                // Usually stuck writing an alert nobody reads. Leave it:
                // exiting ends the thread.
                eprintln!(
                    "minisiem: watch: detection did not stop within {}s (stdout blocked?), stopping without \
                     writing pending alerts",
                    STOP_GRACE.as_secs()
                );
                let stats = progress.lock().map(|stats| *stats).unwrap_or_default();
                // The queue is the stuck thread's: it cannot be counted.
                break (Ok(Stop::Interrupted), stats, 0);
            }
        }
    };

    let dropped = match dropped.load(Ordering::Relaxed) {
        0 => String::new(),
        n => format!(" dropped={n}"),
    };
    let unprocessed = match unprocessed {
        0 => String::new(),
        n => format!(" unprocessed={n}"),
    };
    // Datagrams lost before minisiem could read them, where the kernel tells.
    let kernel_dropped = match kernel_drops.and_then(|drops| drops.count()) {
        None | Some(0) => String::new(),
        Some(n) => format!(" kernel_dropped={n}"),
    };
    eprintln!(
        "minisiem: watch: events={} alerts={}{dropped}{unprocessed}{kernel_dropped}",
        stats.events, stats.alerts
    );
    match stop.map_err(|e| e.to_string())? {
        Stop::Interrupted => Ok(()),
        Stop::SourceFailed { source, error } => Err(format!("{source}: {error}")),
    }
}

/// How watching ended, as seen from the main thread.
enum End {
    /// The detection thread returned, with the pipeline's final stats and
    /// the events it left in the queue.
    Drained(io::Result<Stop>, Stats, usize),
    /// The detection thread panicked (the panic message is already printed).
    Panicked,
    /// Ctrl+C or SIGTERM.
    Interrupted,
}

/// Tells the main thread when the detection thread panics. The Ctrl+C
/// handler keeps its own sender, so the channel never disconnects and the
/// main thread would otherwise wait forever.
struct ReportPanic(mpsc::Sender<End>);

impl Drop for ReportPanic {
    fn drop(&mut self) {
        if thread::panicking() {
            let _ = self.0.send(End::Panicked);
        }
    }
}

/// How long Ctrl+C waits for detection to stop before giving up on it.
const STOP_GRACE: StdDuration = StdDuration::from_secs(2);

/// Makes watch's detection panic on its first event, so tests can check
/// how watch ends when a detector panics. Not for use outside tests.
const TEST_PANIC_ENV: &str = "MINISIEM_TEST_PANIC";

/// A detector that panics, enabled by [`TEST_PANIC_ENV`].
struct PanicOnEvent;

impl Detector for PanicOnEvent {
    fn evaluate(&mut self, _event: &minisiem::event::Event) -> Vec<minisiem::alert::Alert> {
        panic!("{TEST_PANIC_ENV} is set");
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match &cli.command {
        Some(Command::Watch(args)) => watch(args),
        None => analyze(cli.file.as_ref(), &cli.detection),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("minisiem: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panicking_detection_thread_still_reports_how_it_ended() {
        let (ended, end) = mpsc::channel();
        // Another sender stays alive, like the Ctrl+C handler's: without the
        // report, the main thread would wait forever.
        let _handler = ended.clone();

        let _ = thread::spawn(move || {
            let _report = ReportPanic(ended);
            panic!("detector bug");
        })
        .join();

        assert!(matches!(end.recv_timeout(StdDuration::from_secs(5)), Ok(End::Panicked)));
    }
}
