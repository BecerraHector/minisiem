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
| Metadata | `title` (required), `id`, `level`, `tags` (`attack.tNNNN[.NNN]` become techniques); other keys are ignored |
| `logsource` | `product`, `service`, `category`; sshd events are `product: linux`, `service: sshd` |
| Searches | map (all fields must match), list of maps (any), list of keywords (substring of the raw message) |
| Values | case-insensitive, `*` and `?` wildcards (`\*`, `\?`, `\\` escape them), lists (any), `null` (empty field) |
| Modifiers | `contains`, `startswith`, `endswith`, `all`, `re` (case-sensitive, linear-time), `cidr` |
| Condition | identifiers, `and`, `or`, `not`, parentheses, `1 of`/`all of` a pattern or `them`, or a list of conditions (any) |
| Not supported | aggregations (`\| count() ...`), correlation rules, other modifiers (rejected at load time) |

### Fields

| Field | Example |
|-------|---------|
| `host` | `srv01` |
| `process` | `sshd`, `sshd-session` |
| `user` | `root` |
| `src_ip` | `203.0.113.7`, `2001:db8::7` |
| `event_kind` | `failed_login`, `invalid_user`, `successful_login` |

Keyword searches match the raw sshd message (e.g. `Accepted password for root from ...`).

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
| `detection` | `Detector` port, the brute force rule and the Sigma engine |
| `rule_loading` | Adapter that loads Sigma rules from a directory |
| `alerting` | `AlertSink` port and the console adapter |
| `pipeline` | Use case wiring parser, detectors and sink |

## Known limitations

- Syslog timestamps have no year or timezone: the current local ones are assumed
  (logs crossing New Year or a DST change get shifted).
- Events must arrive in chronological order.
- Per-IP state is never evicted; long-running use needs pruning.
