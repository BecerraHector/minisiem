# Feature: live sources and watch mode (minisiem phase 4a)

Objective: ingest sshd events from journald (JSON) and syslog over UDP, and run continuously with `minisiem watch`.
Branch: `feat/live-sources` · Delivery: single PR, work-unit commits (forecast ~1300 authored lines) · Test runner: `cargo test` (+ `cargo clippy --all-targets`, `cargo fmt --check`).

## Specs

- **S1** Scope agreed with the user: "4a: fuentes y modo continuo. JSON de `journald`, syslog UDP en `localhost` y el subcomando `watch`." Storage and search are phase 4b.
- **S2** Batch mode keeps its current invocation and output (`minisiem [FILE] [--threshold] [--window] [--rules]`). It now also accepts `journalctl -o json` lines and network syslog lines (`<PRI>` RFC 3164 or RFC 5424), detected per line.
- **S3** journald JSON: timestamp from `__REALTIME_TIMESTAMP` (microseconds), host from `_HOSTNAME`, message from `MESSAGE` (string or byte array). The process is identified by the trusted `_COMM` field (`sshd`, `sshd-session`, `sshd-auth`), never by `SYSLOG_IDENTIFIER`, which any local process can set.
- **S4** `minisiem watch` runs until interrupted, with sources `--journal` (follows `journalctl` for sshd processes) and/or `--syslog-udp <ADDR>`; at least one is required. Detection options (`--threshold`, `--window`, `--rules`) are the same as batch mode.
- **S5** UDP syslog binds only loopback addresses unless `--allow-remote-syslog` is given. Each datagram is one message, truncated to 8 KiB. Events received over UDP are timestamped on arrival, since the sender controls the claimed time.
- **S6** Fail closed: if a source stops (bind error, `journalctl` missing or exiting), `watch` reports it and exits with code 1. Ctrl+C stops cleanly with exit code 0 and prints the summary.
- **S7** Alerts are flushed as they are emitted, so they appear immediately when stdout is a pipe.
- **S8** Document `watch`, the formats, the trust model of each source and the `tail -F` recipe for following files in the README.

## Tasks

| ID | Specs | Route | Status | Evidence |
|----|-------|-------|--------|----------|
| T1 | S7 | inline | done | RED: `Pipeline` missing; GREEN: 106 unit + 11 CLI |
| T2 | S2, S3 | inline | done | RED: 6 unit + journald CLI (0 alerts); GREEN: 112 unit + 12 CLI |
| T3 | S2, S5 | inline | done | RED: 5 failing; GREEN: 118 unit + 12 CLI |
| T4 | S4 | inline | done | refactor only (shared `DetectionArgs`, `analyze`); the `watch` subcommand lands with T5 so no commit ships a stub. GREEN: 118 unit + 12 CLI unchanged |
| T5 | S4, S5, S6 | inline | pending | |
| T6 | S3, S4, S6, S8 | inline | pending | |

- T1: `Pipeline` struct usable event by event; console sink flushes per alert.
- T2: shared sshd message classification; journald JSON parser; per-line format detection in batch mode.
- T3: network syslog framing (`<PRI>`, RFC 5424) in the same detection.
- T4: CLI: `watch` subcommand next to the unchanged batch mode.
- T5: UDP source, event channel, Ctrl+C handling, summary, loopback guard; integration test.
- T6: journald follow source; README.

Routes: all inline (sequential tasks, no writer trigger).

## Log

- **L1** (2026-10-22) User: "arranquemos con la 4a"
- **L2** Environment: OpenSSH 10.6 (per-connection logs come from `sshd-session`; `sshd-auth` exists since 10.0 and is accepted defensively), systemd 262. A real journal entry showed `SYSLOG_IDENTIFIER` differing from `_COMM`: only underscore fields are set by journald. Crates: `serde_json` 1.0, `ctrlc` 3.5.
- **L4** T2: the syslog header regex now also accepts `sshd-auth`, matching the journald process list. The journald fixture includes 12 failures spoofed with `logger -t sshd` from another IP; they produce no events.
- **L3** Decisions: threads and `std::sync::mpsc` instead of an async runtime (two sources, one consumer, detectors stay single-threaded); file following is left to `tail -F` (rotation-safe) instead of reimplementing it.
