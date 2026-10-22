# Feature: Sigma correlation rules (minisiem phase 3)

Objective: evaluate Sigma correlation rules (Sigma spec v2.1.0) over the event stream, including chained correlations, with bounded state.
Branch: `feat/sigma-correlation` · Delivery: single PR, work-unit commits (forecast ~1500 authored lines) · Test runner: `cargo test` (+ `cargo clippy --all-targets`, `cargo fmt --check`).

## Specs

- **S1** Phase scope, as agreed in the roadmap: "Correlación con ventanas de tiempo y estado", including "N fallos y después un éxito desde la misma IP en 5 minutos".
- **S2** Correlation types `event_count`, `value_count`, `temporal`, `temporal_ordered`. `value_sum`, `value_avg`, `value_percentile` and `aliases` are rejected at load time with a clear error.
- **S3** `correlation` keys: `type` and `rules` (required), `group-by` (optional list of event fields; no grouping when absent), `timespan` (required, `<number><s|m|h|d>`), `condition` (required for `event_count`/`value_count`), `generate` (optional, default `false`). Correlation rules carry the usual metadata (`title`, `id`, `name`, `level`, `tags`).
- **S4** `condition` is a map of `gt`, `gte` or `eq` (plus `field` for `value_count`). Decision (streaming evaluation): `lt`, `lte` and `neq` are rejected, since they can only be decided when a window closes.
- **S5** `rules` reference other rules by `name` or `id`; a correlation may reference another correlation (chaining). Unknown references, reference cycles, and a `group-by` field the referenced correlation does not group by are load errors.
- **S6** Rule files may contain several YAML documents separated by `---`.
- **S7** A rule referenced by a correlation does not alert on its own unless a correlation referencing it sets `generate: true`.
- **S8** Semantics per group (events sharing all `group-by` values), within a sliding `timespan`: `event_count` counts matching events; `value_count` counts distinct values of `field`; `temporal` needs every referenced rule to match at least once; `temporal_ordered` needs them to match in the listed order. After firing, the group's state resets (one alert per burst, as in phase 1).
- **S9** State is bounded: entries older than `timespan` are evicted and idle groups are dropped. The built-in brute force detection gets the same eviction.
- **S10** Correlation alerts print the group, the number of contributing events, the time range and, for `value_count`, the distinct values; attacker-controlled values are escaped.
- **S11** Decision: the built-in brute force detection and `--threshold`/`--window` stay unchanged (no breaking CLI change). Ship correlation rules in `rules/` (brute force followed by a successful login, user enumeration) and document the syntax in the README.

## Tasks

| ID | Specs | Route | Status | Evidence |
|----|-------|-------|--------|----------|
| T1 | S7, S10 | inline | done | RED: trait mismatch; GREEN: 67 unit + 9 CLI |
| T2 | S2, S3, S4, S5, S6 | inline | done | RED: 20 failing; GREEN: 87 unit + 9 CLI |
| T3 | S8, S9 | inline | done | RED: 11 failing; GREEN: 98 unit (dead_code warnings until T4) |
| T4 | S5, S7, S8 | inline | done | RED: 8 failing; GREEN: 103 unit + 9 CLI; `SigmaDetector` replaced by `SigmaEngine`, loader returns `RuleSet` |
| T5 | S9 | inline | done | RED: 1001 tracked IPs instead of 1; GREEN: 104 unit + 9 CLI |
| T6 | S11 | inline | done | RED: shipped-rules CLI test (6 vs 8 alerts); GREEN: 104 unit + 11 CLI |
| T7 | S10 | inline | done | `60abd54` fix: chained alerts span the whole incident (RED: first_seen at(3) instead of at(1)) |

- T1: `Detector` returns all alerts for an event; `Evidence::Correlation` and its console format.
- T2: rule model: `name`, multi-document files, correlation parsing and load-time validation.
- T3: correlation state machines (pure domain) with eviction.
- T4: `SigmaEngine`: base matches feed correlations in dependency order, chaining, `generate`.
- T5: eviction for the built-in brute force detector.
- T6: CLI wiring, shipped rules, README, CLI tests.

Routes: all inline (sequential tasks, no writer trigger).

## Log

- **L1** (2026-10-22) User: "sigamos con la fase 3"
- **L2** Spec read from SigmaHQ `sigma-correlation-rules-specification.md` (v2.1.0): types, `rules` by name or id, chaining, `generate` default false, multi-document YAML, timespan units `s|m|h|d`, condition operators `gt|gte|lt|lte|eq|neq`.
- **L5** Native assessment of `main..HEAD`: risk `medium` (shipped rule files), `review_due: false` (`under_budget`); verification by the tier = own checks (104 unit + 11 CLI, clippy, fmt). Not pushed: push and PR are the user's call.
- **L4** Defect found while writing T6 rules: chained hits carried only the inner correlation's `last_seen`, so the outer alert started at the end of the burst. Fixed by giving `Hit` its own `first_seen` (T7). Fixture with shipped rules: 8 alerts, including `[CRITICAL] SSH login after brute force ... events=11` starting at the first failure.
- **L3** Repo is now `BecerraHector/minisiem` (phase 2 merged as PR #1, `0632afc`). Merged local branch `feat/minisiem-sigma-rules` deleted.
