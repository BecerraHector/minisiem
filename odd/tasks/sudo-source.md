# Feature: sudo as a log source

Objective: normalize sudo log entries into events, make the source IP optional so events without one fit the model, and ship Sigma rules for sudo.
Branch: one per task (see Tasks) · Delivery: stacked PRs to main, one per task (forecast ~950 authored lines) · Test runner: `cargo test` (+ `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`; CI runs the same).

## Specs

- **S1** User: "ya mergeé, arranquemos con sumar fuentes". Source chosen: "sudo (Recommended)" — "Ya llega por los mismos canales (auth.log, journald, syslog). Detecta escalada de privilegios: sudo fallido, usuarios fuera de sudoers, comandos sensibles como root. Exige generalizar el modelo de evento, que hoy es solo logins SSH."
- **S2** Scope chosen: "Eventos + reglas Sigma (Recommended)" — "Normaliza 3 tipos de evento (sudo_command, sudo_denied, sudo_failed_password) con campos user, target_user y command, y suma reglas en rules/sudo/: usuario fuera de sudoers, shell como root y fallos repetidos (correlación). Las reglas se pueden editar sin recompilar."
- **S3** (assumption) `src_ip` becomes optional in events and alerts. sshd events always carry one, and their console output, batch output and stored rows do not change. An alert without a source IP leaves `src=` out of its console line, and an event line shows `src=-`. The brute force detector ignores events without a source IP. A correlation event that lacks a `group-by` field joins no group, so that correlation does not count it (no shared empty group).
- **S4** (assumption) Storage schema version 2 makes `src_ip` nullable (NULL when absent). Opening a version 1 database migrates it in one transaction: tables are rebuilt with every row kept, and a crash leaves version 1 intact. Version 2 databases are refused by older minisiem (S10 of storage-and-search).
- **S5** (assumption) sudo lines are read from syslog files, network syslog and journald. Message forms:
  - `<user> : TTY=.. ; PWD=.. ; USER=<target> ; COMMAND=<cmd>` → `sudo_command`;
  - `<user> : user NOT in sudoers ; ...` and `<user> : command not allowed ; ...` → `sudo_denied`;
  - `<user> : <n> incorrect password attempt(s) ; ...` → `sudo_failed_password`.
  pam_unix lines are ignored: the "incorrect password attempts" summary would count the same failure twice. Events carry `product: linux`, `service: sudo`, and the new fields `target_user` and `command` (empty for sshd).
- **S5b** (assumption) `target_user` and `command` are stored: schema version 3 adds both columns to `events` (version 2 upgrades with `ALTER TABLE ADD COLUMN`, version 1 is rebuilt straight into version 3). They are also Sigma fields, and they are left out of the stored alert JSON when empty, so sshd alert JSON is unchanged.
- **S6** (assumption, verified 2026-10-29 with `journalctl -o json _COMM=sudo` on the user's machine: `_UID=1000`, `_COMM=sudo`, `_EXE=/usr/bin/sudo`, even for a successful command) journald trust for sudo: require `_COMM=sudo` and `_EXE` to be a `sudo` binary under `/usr/`. `_UID` is the invoking user, so it is not checked. `logger -t sudo` (`_COMM=logger`) and copies outside `/usr` are ignored. `watch --journal` also follows `_COMM=sudo`.
- **S7** (assumption) `PWD` and the `COMMAND` arguments are chosen by the user running sudo, so a crafted directory name can misreport `target_user` and `command`. The event kind and the invoking user cannot be forged this way. Document this in the trust model.
- **S8** Rules in `rules/sudo/`: user not in sudoers, shell as root, and repeated sudo password failures (correlation), with fixtures and CLI tests; README documents the source, fields and rules.

## Tasks

| ID | Specs | Route | Status | Evidence |
|----|-------|-------|--------|----------|
| T1 | S3, S4 | inline | done (PR1, `feat/optional-src-ip`) | Type change first: all 172 + 1 + 39 tests still green (sshd output and JSON unchanged). RED: 3 new tests failed (NOT NULL insert, no v1 upgrade, empty-IP group formed a burst); GREEN after nullable schema v2 + `upgrade_from_1` + group skip. Console and brute force behaviour is forced by the type, so their tests have no RED |
| T2 | S5, S5b, S6, S7 | inline | done (PR2, `feat/sudo-parser`) | RED: 5 of 6 `sudo_event` tests failed against a stub; 3 parser tests (syslog lines, network syslog, journald) and the journalctl args and startup line tests failed before the change. The "ignores" tests passed before and after (behavior kept). Storage v3 was written before its tests: mutations (no `2 =>` upgrade, no stored target_user/command) each fail a test. 192 unit + 1 + 40 CLI |
| T3 | S8 | inline | pending | |

Routes are inline: one parent context, sequential units (each builds on the previous). No Writer trigger.

## Log

- **L1** (2026-10-29) User: "ya mergeé, arranquemos con sumar fuentes"
- **L2** (2026-10-29) Choices: "sudo (Recommended)", then "Eventos + reglas Sigma (Recommended)". Base: `main` at `54bee3f`.
- **L3** Explorer map: `src_ip` is `IpAddr` in `Event` (src/event.rs:67) and `Alert` (src/alert.rs:71), `TEXT NOT NULL` in storage (src/storage/mod.rs:44,61); brute force keys on it (ssh_brute_force.rs:67); correlation group-by uses `unwrap_or_default` (engine.rs:68); the syslog `HEADER` regex hard-codes sshd and needs `[pid]` (sshd.rs:17), but sudo file lines are `sudo:` with no pid; `JournalParser` requires `_UID == "0"` (journal.rs:33).
- **L4** (2026-10-29) User chose delivery: "PRs encadenados a main (Recommended)". PR1 = T1, PR2 = T2, PR3 = T3.
- **L5** (2026-10-29) T1 independent verifier (2 min): S3 PASS (batch output byte-identical to baseline for auth.log and journal.json, with and without rules); S4 FAIL, one blocker: `search --db` on a version 1 database exited 1 with "unknown database schema version 1" because `Store::open_existing` did not upgrade. The upgrade itself kept every row and index; a failed upgrade left version 1 intact; baseline refuses version 2 without changing the file. Fix: `open` and `open_existing` share `prepare`, which upgrades; `open_existing` still refuses a database minisiem did not create (version 0) before touching it. RED `search_upgrades_a_version_1_database_too`; recheck: baseline-written v1 db -> HEAD `search` lists 20 events, exit 0, version 2. Pre-existing flake (1/10 on main too): `sources::syslog_udp::tests::keeps_counting_after_the_reader_closed_its_socket`.
- **L6** (2026-10-29) User: "ya mergeé, sigamos con el PR2". PR #28 merged (`5b8517a`). T2 on `feat/sudo-parser`. `SshdParser` renamed `SyslogParser` (it now reads sudo lines too). The command is taken from the first ` ; COMMAND=` to the end of the line, so a crafted PWD cannot hide the command that ran; `target_user` is the last ` ; USER=` before it (fakeable, S7).
- **L7** (2026-10-29) T2 independent verifier (3.5 min): S5, S5b, S6, S7 PASS, no blockers. Batch output byte-identical to baseline; a baseline-written v2 db upgraded to 3 with identical rows and alert JSON; baseline refuses v3 unchanged; journald forgeries rejected, sshd still needs `_UID=0`; a crafted PWD changes only target_user. Advisories: a command with a raw newline produced no event (fixed: `(?s)` in the sudo regex, RED `keeps_a_command_with_a_newline_in_its_arguments`); `--help` still said "sshd logs" (fixed); `/usr/local/bin/sudo` is accepted, like sshd under `/usr/` (kept, consistent with the documented rule).
