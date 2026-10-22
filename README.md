# minisiem

A small SIEM written in Rust, built phase by phase to learn detection engineering.

```sh
cargo run -- tests/fixtures/auth.log
cargo run -- --rules rules tests/fixtures/auth.log
cargo run -- --threshold 5 --window 60 /var/log/auth.log
journalctl -u sshd -o short-iso --no-pager | cargo run -- --rules rules
```

Alerts go to stdout, one per line; startup messages and a summary go to stderr.
Exit codes: `0` success, `1` unreadable input or invalid rules, `2` invalid arguments.

## Phase 1: SSH brute force detection

Reads sshd logs, normalizes each line into an `Event` and raises an alert when one
source IP accumulates `--threshold` failed logins within `--window` seconds
(MITRE ATT&CK [T1110.001](https://attack.mitre.org/techniques/T1110/001/)).

## Phase 2: Sigma rules

`--rules <DIR>` loads every `*.yml` / `*.yaml` file under `DIR` (recursively) as a
[Sigma](https://sigmahq.io) rule. Rules run in addition to the brute force detection
and fire one alert per matching event. **Any invalid rule aborts startup**: a rule
that silently fails to load is a blind spot.

Example rules live in [`rules/`](rules/) and are exercised by the CLI tests.

### Supported subset

| Feature | Supported |
|---------|-----------|
| Metadata | `title` (required), `id`, `name`, `level`, `tags` (`attack.tNNNN[.NNN]` become techniques); other keys are ignored |
| `logsource` | `product`, `service`, `category`; sshd events are `product: linux`, `service: sshd` |
| Searches | map (all fields must match), list of maps (any), list of keywords (substring of the raw message) |
| Values | case-insensitive, `*` and `?` wildcards (`\*`, `\?`, `\\` escape them), lists (any), `null` (empty field) |
| Modifiers | `contains`, `startswith`, `endswith`, `all`, `re` (case-sensitive, linear-time), `cidr` |
| Condition | identifiers, `and`, `or`, `not`, parentheses, `1 of`/`all of` a pattern or `them`, or a list of conditions (any) |
| Not supported | aggregations (`\| count() ...`, use correlation rules instead), other modifiers (rejected at load time) |

### Fields

| Field | Example |
|-------|---------|
| `host` | `srv01` |
| `process` | `sshd`, `sshd-session` |
| `user` | `root` |
| `src_ip` | `203.0.113.7`, `2001:db8::7` |
| `event_kind` | `failed_login`, `invalid_user`, `successful_login` |

Keyword searches match the raw sshd message (e.g. `Accepted password for root from ...`).

## Phase 3: Sigma correlation rules

[Correlation rules](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md)
(Sigma specification v2.1.0) combine the matches of other rules over time. A rule file may hold
several YAML documents separated by `---`, so a correlation can ship with the rules it uses:

```yaml
title: SSH failed login
name: ssh_failed_login
detection:
  selection:
    event_kind: failed_login
  condition: selection
---
title: SSH password guessing
name: ssh_password_guessing
correlation:
  type: event_count
  rules: [ssh_failed_login]
  group-by: [src_ip]
  timespan: 5m
  condition:
    gte: 10
---
title: SSH login after brute force
level: critical
correlation:
  type: temporal_ordered
  rules: [ssh_password_guessing, ssh_successful_login]
  group-by: [src_ip]
  timespan: 15m
```

| Type | Fires when, within `timespan` and for one `group-by` group |
|------|-------------------------------------------------------------|
| `event_count` | the referenced rules matched `condition` times |
| `value_count` | the matches carry `condition` distinct values of `condition.field` |
| `temporal` | every referenced rule matched, in any order |
| `temporal_ordered` | every referenced rule matched, in the listed order |

- `rules` reference other rules by `name` or `id`, in any file of the rules directory. A correlation
  can reference another correlation (chaining): an outer correlation may only `group-by` fields
  the inner one groups by.
- `group-by` is optional; without it all matches form one group.
- `timespan` is `<number><s|m|h|d>`, e.g. `90m`.
- `condition` takes exactly one of `gt`, `gte`, `eq` (plus `field` for `value_count`). `lt`, `lte`
  and `neq` are rejected: they can only be decided once a window closes, and minisiem evaluates
  each event as it arrives.
- Rules referenced by a correlation do not alert on their own unless a correlation referencing
  them sets `generate: true`.
- After firing, a group starts over, so a sustained attack raises one alert per burst. Groups
  whose newest match left the window are dropped, which keeps memory bounded.
- Not supported (rejected at load time): `value_sum`, `value_avg`, `value_percentile`, `aliases`.

Correlation alerts show the group, the number of underlying events, the time range of the whole
incident and, for `value_count`, the distinct values:

```
[CRITICAL] SSH login after brute force (T1110.001, T1078) src=203.0.113.7 host=srv01 group.src_ip=203.0.113.7 events=11 first_seen=... last_seen=...
[MEDIUM] SSH user enumeration (T1110.001) src=203.0.113.7 host=srv01 group.src_ip=203.0.113.7 events=3 first_seen=... last_seen=... values=oracle,test,ubuntu
```

## Architecture

```
raw line -> LogParser -> Event -> Detector -> Alert -> AlertSink
            (adapter)   (domain)  (domain)   (domain)  (adapter)
```

| Module | Role |
|--------|------|
| `event` | Normalized event model and the fields rules can use |
| `alert` | Alert, severity, MITRE technique and evidence |
| `ingestion` | `LogParser` port and the sshd adapter |
| `detection` | `Detector` port, the brute force rule and the Sigma engine (rules, correlations, per-group state) |
| `rule_loading` | Adapter that loads Sigma rule files from a directory into a validated rule set |
| `alerting` | `AlertSink` port and the console adapter |
| `pipeline` | Use case wiring parser, detectors and sink |

## Known limitations

- Syslog timestamps have no year or timezone: the current local ones are assumed
  (logs crossing New Year or a DST change get shifted).
- Events must arrive in chronological order.
- A single group can still hold many entries if one source floods matches within one window.
