# Feature: Sigma rules (minisiem phase 2)

Objective: load a basic subset of Sigma rules from YAML and evaluate them against normalized events.
Branch: `feat/minisiem-sigma-rules` · Delivery: single PR, work-unit commits (forecast ~1100 authored lines) · Test runner: `cargo test` (+ `cargo clippy --all-targets`).

## Specs

- **S1** Phase scope, as agreed in the roadmap: "Parser de Sigma propio (el subconjunto básico: `selection`, `condition`, modificadores)". Stateful/aggregation rules are out of scope (phase 3: correlation).
- **S2** `--rules <DIR>` loads every `*.yml` / `*.yaml` file under DIR, recursively. Any invalid rule aborts startup with exit code 1 and a message naming the file (decision: fail closed; a silently skipped rule is a blind spot). Without `--rules`, behavior and output are exactly as in phase 1.
- **S3** Supported rule fields: `title` (required), `id`, `level` (`informational|low|medium|high|critical`, default `medium`), `tags` (`attack.tNNNN[.NNN]` become techniques), `logsource` (`product`, `service`, `category`), `detection` (required). Other top-level fields are ignored.
- **S4** Search identifiers: a map (AND across fields, OR across a field's list of values), a list of maps (OR), or a list of keywords (case-insensitive match against the raw log message). Plain string values are case-insensitive and support `*` and `?` wildcards. `null` matches an absent or empty field.
- **S5** Value modifiers: `contains`, `startswith`, `endswith`, `all`, `re`, `cidr`. An unknown modifier is a load error.
- **S6** Condition: identifiers, `and`, `or`, `not`, parentheses, `1 of <pattern>`, `all of <pattern>`, `1 of them`, `all of them`; precedence `not` > `and` > `or`. A condition using an aggregation (`|`) or an undefined identifier is a load error.
- **S7** Event fields available to rules: `host`, `process`, `user`, `src_ip`, `event_kind` (`failed_login`, `invalid_user`, `successful_login`); keywords match the raw sshd message. A rule only applies when every `logsource` key it declares equals the event's (sshd events: `product: linux`, `service: sshd`).
- **S8** Each matching rule emits one alert per event, printed by the existing console sink. The phase 1 brute force alert line stays byte-identical.
- **S9** Ship example rules in `rules/` and document supported fields and syntax in the README.

## Tasks

| ID | Specs | Route | Status | Evidence |
|----|-------|-------|--------|----------|
| T1 | S7, S8 | inline | done | RED: compile errors; GREEN: 20 unit + 5 CLI |
| T2 | S6 | inline | pending | |
| T3 | S3, S4, S5 | inline | pending | |
| T4 | S4, S5, S7, S8 | inline | pending | |
| T5 | S2, S8, S9 | inline | pending | |

- T1: generalize domain (`Event` gets raw message and logsource, `Alert` owns strings, `Severity::Informational`) without changing phase 1 output.
- T2: condition expression parser (recursive descent).
- T3: rule model and YAML loading with validation.
- T4: matcher and `SigmaDetector`.
- T5: CLI `--rules`, example rules, README, CLI tests.

Routes: all inline (no writer trigger: tasks are sequential and the user is learning from the walkthrough).

## Log

- **L1** (2026-10-22) User: "commitea y seguimos con la fase 2"
- **L2** Phase 1 committed as `ff4b0fd` on `main`. YAML crate: `serde-saphyr` (panic-free, maintained); `serde_yaml` is deprecated and `serde_yml` unmaintained. Detection values are read through a custom serde `Visitor` because Sigma's detection shape is dynamic.
- **L3** T1: `Alert` now carries `Evidence::{Burst, Event}`. Security fix found on the way: attacker-controlled usernames could inject terminal escape sequences into console output; control characters are now escaped (normal output unchanged).
