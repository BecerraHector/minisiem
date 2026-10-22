# minisiem

A small SIEM written in Rust, built phase by phase to learn detection engineering.

## Phase 1: SSH brute force detection

Reads sshd logs, normalizes each line into an `Event` and raises an alert when one
source IP accumulates `--threshold` failed logins within `--window` seconds
(MITRE ATT&CK [T1110.001](https://attack.mitre.org/techniques/T1110/001/)).

```sh
cargo run -- tests/fixtures/auth.log
cargo run -- --threshold 5 --window 60 /var/log/auth.log
journalctl -u sshd -o short-iso --no-pager | cargo run --
```

Alerts go to stdout, one per line; a summary goes to stderr.

## Architecture

```
raw line -> LogParser -> Event -> Detector -> Alert -> AlertSink
            (adapter)   (domain)  (domain)   (domain)  (adapter)
```

| Module       | Role                                         |
|--------------|----------------------------------------------|
| `event`      | Normalized event model                       |
| `alert`      | Alert, severity and MITRE technique          |
| `ingestion`  | `LogParser` port and the sshd adapter        |
| `detection`  | `Detector` port and detection rules          |
| `alerting`   | `AlertSink` port and the console adapter     |
| `pipeline`   | Use case wiring parser, detectors and sink   |

## Known limitations

- Syslog timestamps have no year or timezone: the current local ones are assumed
  (logs crossing New Year or a DST change get shifted).
- Events must arrive in chronological order.
- Per-IP state is never evicted; long-running use needs pruning.
