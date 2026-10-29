# Feature: storage and search (minisiem phase 4b)

Objective: keep normalized events and alerts in SQLite and search them later from the CLI, with retention for long watches.
Branch: `feat/storage-and-search` · Delivery: stacked PRs to main, one per task (forecast ~1000 authored lines) · Test runner: `cargo test` (+ `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`; CI runs the same).

## Specs

- **S1** Phase scope, as recorded when 4a started: "Storage and search are phase 4b." User: "arranquemos con la fase 4b".
- **S2** Storage engine, user's choice: "SQLite (Recommended)" — "Una base en un archivo (rusqlite). Las búsquedas por IP, usuario o fechas van por índice, la retención es un DELETE y podés consultarla con sqlite3." (`rusqlite` 0.41 with the `bundled` feature.)
- **S3** What is stored, user's choice: "Eventos y alertas (Recommended)" — "Cada evento normalizado (login fallido, aceptado, etc.) y cada alerta. Permite investigar: '¿qué más hizo esta IP?'."
- **S4** Activation, user's choice: "Opt-in con --db PATH (Recommended)" — "Batch y watch guardan solo si les pasás --db minisiem.db. Sin el flag, todo funciona exactamente como hoy (la salida y los tests actuales no cambian)."
- **S5** Search, user's choice: "Subcomando con filtros (Recommended)" — "minisiem search --db PATH [events|alerts] con --ip, --user, --host, --kind, --since y --until, y una salida con el mismo formato que la consola. Lo que no cubran los filtros sale con sqlite3, con el esquema documentado en el README."
- **S6** Retention, user's choice: "--retain-days en watch (Recommended)" — "watch --db PATH --retain-days 30 borra lo que tenga más de 30 días al arrancar y después una vez por hora. Es automático mientras watch corre; sin el flag no se borra nada."
- **S7** (assumption) Writes are grouped in transactions (WAL journal), so a flood does not sync to disk once per event.
- **S8** (assumption) `--since`/`--until` accept an RFC 3339 time, a `YYYY-MM-DD` date, or a relative age `<number><s|m|h|d>` (as in Sigma timespans); results are listed oldest first.
- **S9** (assumption) Fail closed: if writing to the database fails, batch and watch report it and exit with code 1, as a stopped source does; storage failing silently would be a blind spot.
- **S10** (assumption) The schema carries a version (`PRAGMA user_version`); minisiem refuses a database with a version it does not know.

## Tasks

| ID | Specs | Route | Status | Evidence |
|----|-------|-------|--------|----------|
| T1 | S2, S3, S7, S10 | inline | done (PR1) | `8ece4d6`. New module, no prior RED; 7 tests, mutation-checked (no batch auto-commit, no commit on drop, any schema accepted: each fails a test). 169 unit + 1 + 23 CLI. 484 changed lines without Cargo.lock: over the 400 budget, no cohesive split (serde derives exist for this module; tests stay with code) |
| T2 | S4, S9 | inline | pending | |
| T3 | S5, S8 | inline | pending | |
| T4 | S6 | inline | pending | |
| T5 | S1-S6 | inline | pending | README: usage, schema, limitations; each PR documents its own part |

Routes are inline: one parent context, units are sequential (each builds on the storage module). No Writer trigger.

## Log

- **L1** (2026-10-29) User: "ya mergeé, arranquemos con la fase 4b"
- **L2** (2026-10-29) Decisions asked one at a time: storage "SQLite (Recommended)", content "Eventos y alertas (Recommended)", activation "Opt-in con --db PATH (Recommended)", search "Subcomando con filtros (Recommended)", retention "--retain-days en watch (Recommended)". Base: `main` at `df5ccc5`.
- **L3** Code map: `Pipeline::process` (src/pipeline.rs) runs detectors and emits through the `AlertSink` port (src/alerting/mod.rs); `Event` (src/event.rs) and `Alert`/`Evidence` (src/alert.rs) have no serde derives yet; `parse_timespan` exists privately in src/detection/sigma/correlation.rs.
- **L4** (2026-10-29) User chose delivery: "PRs encadenados a main (Recommended)". Slices: PR1 = T1 (`feat/storage`), PR2 = T2, PR3 = T3, PR4 = T4; each branches from main after the previous merges; README docs go with each slice.
- **L5** (2026-10-29) T1 committed `8ece4d6` on `feat/storage`; independent verifier launched with a 10-minute budget (the previous one hung for 30+ minutes).
- **L6** (2026-10-29) Verifier (T1, 3 min): PASS, batch output byte-identical over 22 fixture runs. Advisories A1 (schema creation not atomic; a half-created schema makes the file unopenable) and A2 (failed COMMIT wedged the store) fixed in a second commit. RED: 4 threads opening one new file -> "database is locked" at `PRAGMA journal_mode = WAL` (SQLite returns BUSY at once on that lock collision); fixed with a retry loop plus BEGIN IMMEDIATE around version check and schema; mutation `BEGIN` instead of `BEGIN IMMEDIATE` fails the test. A2 has no runnable RED (WAL commits do not fail on readers). A3 (Drop ignores flush errors) goes to T2, which flushes explicitly.
