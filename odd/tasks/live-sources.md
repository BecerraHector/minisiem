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
- **S9** (review follow-up R1-comm-spoofable) `_COMM` alone is spoofable: a local user can copy any binary to `~/sshd` and run it. journald entries count only when the trusted `_EXE` is an sshd binary (file name in the sshd process list) under `/usr/`, which unprivileged users cannot write. The README trust model is corrected.
- **S10** (review follow-ups R1-unbounded-channel, R4-unbounded-event-channel, R4-shutdown-queued-behind-backlog) The event queue between sources and the pipeline is bounded (10,000 events). When it is full, new events are dropped and counted; the first drop prints a warning and the summary reports `dropped=N` when N > 0. Ctrl+C and source failures are handled ahead of queued events.

## Tasks

| ID | Specs | Route | Status | Evidence |
|----|-------|-------|--------|----------|
| T1 | S7 | inline | done | RED: `Pipeline` missing; GREEN: 106 unit + 11 CLI |
| T2 | S2, S3 | inline | done | RED: 6 unit + journald CLI (0 alerts); GREEN: 112 unit + 12 CLI |
| T3 | S2, S5 | inline | done | RED: 5 failing; GREEN: 118 unit + 12 CLI |
| T4 | S4 | inline | done | refactor only (shared `DetectionArgs`, `analyze`); the `watch` subcommand lands with T5 so no commit ships a stub. GREEN: 118 unit + 12 CLI unchanged |
| T5 | S4, S5, S6 | inline | done | RED: 9 unit + 3 CLI; GREEN: 127 unit + 15 CLI; UDP watch test stable 10/10 |
| T8 | S9 | inline | done | RED: `/home/mallory/sshd` entry produced an event; GREEN: 132 unit + 18 CLI (fixture: 12 copied-binary spoofs ignored) |
| T9 | S10 | inline | pending | |
| T6 | S3, S4, S6, S8 | inline | done | RED: 3 unit; GREEN: 130 unit + 18 CLI; watch tests 10/10, no orphan journalctl |

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
- **L7** (2026-10-22) User: "dale corrigamos estas 2 ahora" (fix R1-comm-spoofable and the unbounded channel before the PR; the other advisories become issues).
- **L6** Verification: native assess `high` (executable fixtures + escalated item 4). Independent verifier: S1-S8 PASS, no blockers, 6 advisories; parent spot check: batch output with `--rules` hashes identically at `6d86864` and HEAD. User granted native review (lenses risk, resilience, reliability): approved and acknowledged (lineage `review-25f0dd1fb9620326`), 8 non-blocking advisories: R1-comm-spoofable, R1-journalctl-env-override, R1-unbounded-channel, R3-ctrlc-journal-race, R3-read-error-hang, R3-stale-parser-year, R4-shutdown-queued-behind-backlog, R4-unbounded-event-channel. Pending user decision on follow-ups. Not pushed.
- **L5** T6: `MINISIEM_JOURNALCTL` overrides the `journalctl` binary so CLI tests run fake scripts (follow, exit, no permission). The reader thread joins the stderr relay before reporting a stopped source, so journalctl's last error is always printed. Orphan check: `pgrep -f "sleep 600"` matched the checking shell itself; `pgrep -x sleep` showed no leftover processes.
- **L4** T2: the syslog header regex now also accepts `sshd-auth`, matching the journald process list. The journald fixture includes 12 failures spoofed with `logger -t sshd` from another IP; they produce no events.
- **L3** Decisions: threads and `std::sync::mpsc` instead of an async runtime (two sources, one consumer, detectors stay single-threaded); file following is left to `tail -F` (rotation-safe) instead of reimplementing it.
