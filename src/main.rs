use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;
use std::process::ExitCode;

use chrono::{Datelike, Duration, Local, Offset};
use clap::{Args, Parser};

use minisiem::alerting::ConsoleSink;
use minisiem::detection::sigma::SigmaEngine;
use minisiem::detection::{Detector, SshBruteForce};
use minisiem::ingestion::AutoParser;
use minisiem::pipeline::Pipeline;
use minisiem::rule_loading;

/// Detect attacks in sshd logs.
///
/// Reads sshd logs line by line, in any mix of these formats: syslog files
/// (/var/log/auth.log, /var/log/secure), `journalctl -o short-iso`,
/// `journalctl -o json` and network syslog (RFC 3164 / RFC 5424). Prints one
/// line per alert.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Log file to analyze. Reads standard input when omitted or "-".
    file: Option<PathBuf>,

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

fn main() -> ExitCode {
    let cli = Cli::parse();

    match analyze(cli.file.as_ref(), &cli.detection) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("minisiem: {message}");
            ExitCode::FAILURE
        }
    }
}
