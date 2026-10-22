use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;
use std::process::ExitCode;

use chrono::{Datelike, Duration, Local, Offset};
use clap::Parser;

use minisiem::alerting::ConsoleSink;
use minisiem::detection::sigma::SigmaEngine;
use minisiem::detection::{Detector, SshBruteForce};
use minisiem::ingestion::SshdParser;
use minisiem::pipeline::Pipeline;
use minisiem::rule_loading;

/// Detect SSH brute force attacks in sshd logs.
///
/// Reads syslog-style lines (/var/log/auth.log, /var/log/secure or
/// `journalctl -u sshd -o short-iso`) and prints one line per alert.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Log file to analyze. Reads standard input when omitted or "-".
    file: Option<PathBuf>,

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

fn open_input(file: Option<&PathBuf>) -> io::Result<Box<dyn BufRead>> {
    match file {
        Some(path) if path.as_os_str() != "-" => Ok(Box::new(BufReader::new(File::open(path)?))),
        _ => Ok(Box::new(io::stdin().lock())),
    }
}

fn main() -> ExitCode {
    let args = Args::parse();

    let mut detectors: Vec<Box<dyn Detector>> = vec![Box::new(SshBruteForce::new(
        args.threshold as usize,
        Duration::seconds(args.window as i64),
    ))];
    if let Some(dir) = &args.rules {
        match rule_loading::load_dir(dir) {
            Ok(rules) => {
                eprintln!(
                    "minisiem: loaded {} sigma rules from {}",
                    rules.detections.len() + rules.correlations.len(),
                    dir.display()
                );
                detectors.push(Box::new(SigmaEngine::new(rules)));
            }
            Err(err) => {
                eprintln!("minisiem: {err}");
                return ExitCode::FAILURE;
            }
        }
    }

    let source = args.file.as_ref().map_or("<stdin>".into(), |p| p.display().to_string());

    let input = match open_input(args.file.as_ref()) {
        Ok(input) => input,
        Err(err) => {
            eprintln!("minisiem: {source}: {err}");
            return ExitCode::FAILURE;
        }
    };

    // Syslog timestamps lack year and timezone: assume the current local ones.
    let now = Local::now();
    let parser = SshdParser::new(now.year(), now.offset().fix());
    let mut pipeline = Pipeline::new(detectors, ConsoleSink::new(io::stdout().lock()));

    match pipeline.run(input, &parser) {
        Ok(()) => {
            let stats = pipeline.stats();
            eprintln!(
                "minisiem: {source}: lines={} events={} alerts={}",
                stats.lines, stats.events, stats.alerts
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("minisiem: {source}: {err}");
            ExitCode::FAILURE
        }
    }
}
