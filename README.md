# minisiem

A small SIEM written in Rust, built phase by phase to learn detection engineering.

```sh
cargo run -- tests/fixtures/auth.log
cargo run -- --rules rules tests/fixtures/auth.log
cargo run -- --threshold 5 --window 60 /var/log/auth.log
journalctl -o json --no-pager _COMM=sshd-session | cargo run -- --rules rules
cargo run -- watch --journal --syslog-udp 127.0.0.1:5514 --rules rules
cargo run -- watch --journal --rules rules --db minisiem.db
cargo run -- search --db minisiem.db events --ip 203.0.113.7 --since 1d
```

Alerts go to stdout, one per line, flushed as they happen; startup messages and a summary go
to stderr. Exit codes: `0` success (or watch stopped with Ctrl+C), `1` unreadable input,
invalid rules, a failed source or a database that cannot be written, `2` invalid arguments.

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

## Phase 4a: input formats and watch mode

### Formats

Every input is read line by line and each line's format is detected on its own, so one stream
can mix them:

| Line starts with | Format |
|------------------|--------|
| `{` | journald entry from `journalctl -o json` |
| `<` | network syslog: `<PRI>` + RFC 3164 (`Oct 22 10:15:32 host sshd[1]: ...`) or RFC 5424 (`1 2026-10-22T10:15:32Z host sshd 1 - - ...`) |
| anything else | syslog file line (`/var/log/auth.log`, `/var/log/secure`, `journalctl -o short-iso`) |

### Watch mode

`minisiem watch` runs until Ctrl+C (or SIGTERM) and prints alerts as events arrive. It takes
the same detection options as batch mode and at least one source:

| Source | What it does |
|--------|--------------|
| `--journal` | Runs `journalctl --follow --output=json --lines=0` for the `sshd`, `sshd-session` and `sshd-auth` processes. Needs permission to read the system journal (root or the `systemd-journal` group). |
| `--syslog-udp <ADDR>` | Receives syslog datagrams on `ADDR`, e.g. `127.0.0.1:5514`. One datagram is one message, up to 8 KiB. |

`--journal` runs the `journalctl` found in `PATH`, or the program named by the
`MINISIEM_JOURNALCTL` environment variable, which the tests use to stand in for it. Like `PATH`,
it decides which program minisiem trusts for journald events, so keep it out of reach of other
users. `MINISIEM_TEST_PANIC=1`, for tests only, makes detection panic on the first event (watch then
exits with code 101).

`watch` and `search` are always subcommands: to analyze a file named `watch`, give it a path, as in
`minisiem ./watch`.

To follow a log file, let `tail` handle rotation and pipe it into batch mode:

```sh
tail -F /var/log/auth.log | cargo run -- --rules rules
```

To feed it from rsyslog on the same host:

```
# /etc/rsyslog.d/minisiem.conf
if $programname startswith 'sshd' then @127.0.0.1:5514;RSYSLOG_SyslogProtocol23Format
```

If a source stops (`journalctl` exits, the socket fails), watch reports it and exits with code 1:
a source that silently stopped would be a blind spot. The events it had already sent are processed
first, as the last ones before it died may be the most relevant.

Events wait for the detectors in a queue of 10,000. When a flood fills it, new UDP events are
dropped instead of exhausting memory: the first drop prints a warning and the summary adds
`dropped=N`. Dropping is itself a blind spot an attacker can cause on purpose, which is why it is
never silent. A UDP flood can also outrun the reader before the queue: the kernel then drops
datagrams once the socket buffer is full. On Linux minisiem reads the socket's drop counter from
`/proc/net/udp`, warns once when the kernel starts dropping and adds `kernel_dropped=N` to the
summary; elsewhere those drops stay uncounted. journald events are not dropped: the journald source waits for room, `journalctl`
waits with it, and journald keeps the entries meanwhile. journald holds at most half the queue, so a
journald backlog never takes the room UDP events need: with both sources flooding, each gets through,
and UDP only drops once its own half is full. Ctrl+C skips the queue, so stopping never
waits for a backlog; the events left in it are counted as `unprocessed=N` in the summary. Alerts are
written as they are raised; if stdout stops draining (a pipe nobody reads), detection waits for it
without losing alerts, and Ctrl+C still stops within 2 seconds: watch prints
`detection did not stop within 2s (stdout blocked?), stopping without writing pending alerts` and
the summary, and exits with `0`. That summary counts the events fully processed, so it leaves out
the one whose alert was stuck, and it cannot report `unprocessed` events.

### Trust model

Detection is only as good as the events it is fed, and each source can be lied to differently:

| Source | Who can forge an sshd event | What minisiem does |
|--------|-----------------------------|--------------------|
| journald | Forging a whole entry takes code running as root. The content of genuine entries is still partly remote input: sshd logs the username a client sends unescaped, so a crafted name can add a second `from <ip>` to the message. For invalid users minisiem reads the source IP after the username; for valid users, whose names a client cannot choose, it reads it before the key or hostbased details sshd may append (which can hold a certificate ID or host name the client chose). A crafted name cannot move it, and alerts quote values that contain spaces, `=`, `,` or `"`. Parsing is the same for every source | Requires `_COMM` to be an sshd process, `_EXE` to be an sshd binary under `/usr/` **and** `_UID` to be `0`. This stops `logger -t sshd` (`SYSLOG_IDENTIFIER`), binaries copied to `~/sshd` (`_COMM` alone) and installed sshd binaries started by a user with a preloaded library (`LD_PRELOAD`), which journald records with that user's `_UID`. sshd logs failed, invalid and accepted logins from its privileged monitor, which runs as root; an sshd run by another user (e.g. rootless containers) is ignored |
| syslog files | Any local user, with `logger -t sshd "Failed password ..."` | Nothing can tell them apart in plain text; prefer journald |
| syslog over UDP | Anyone who can reach the port, with any host name and timestamp | Binds loopback only unless `--allow-remote-syslog`; timestamps events on arrival so a forged date cannot reset detection windows |

`journalctl` without permission does not fail: it warns and shows only your own entries. Watch
treats that warning as a failed source instead of running blind.

## Phase 4b: storage

`--db <PATH>`, in batch and watch mode, also keeps every normalized event and every alert in a
SQLite database, created if missing; an existing one is added to. Without it nothing is stored and
the output is the same either way.

```sh
cargo run -- --rules rules --db minisiem.db /var/log/auth.log
sqlite3 minisiem.db "SELECT time, src_ip, user, kind FROM events WHERE src_ip = '203.0.113.7'"
```

Writes are grouped in transactions (WAL journal), so a flood does not sync to disk once per event.
They are committed every 1,000 rows, when watch has no event waiting, and at the end. If the
database cannot be opened or written, minisiem reports it and exits with code `1`
(`cannot write to database minisiem.db: ...`): storage failing silently would be a blind spot.

| Table | Columns |
|-------|---------|
| `events` | `time`, `host`, `process`, `kind` (as `event_kind`), `user`, `src_ip`, `message`, `product`, `service`, `category` |
| `alerts` | `time` (the last event behind the alert), `rule_id`, `title`, `severity`, `src_ip`, `host`, `alert` (the whole alert as JSON) |

`watch --db <PATH> --retain-days <N>` deletes the events and alerts more than `N` days old (by
their time, `1` to `36500`) when it starts, before listening, and then once an hour while it runs,
in chunks of 10,000 rows so other readers (`search`, `sqlite3`) are never locked out for long.
Detection waits while a prune runs, so the first one on a large database delays startup. Without
`--retain-days` nothing is deleted.

Times are UTC text such as `2026-10-22T10:15:32.000000Z`, so they sort in time order. `PRAGMA
user_version` holds the schema version; minisiem refuses a database with a version it does not know.

### Search

`minisiem search --db <PATH> <events|alerts>` lists what a database kept, oldest first. Alerts are
printed exactly as the console printed them; events as one line each:

```
2026-10-22T10:15:32+00:00 host=srv01 process=sshd src=203.0.113.7 user=root event_kind=failed_login message="Failed password for root from 203.0.113.7 port 22 ssh2"
```

| Filter | Matches |
|--------|---------|
| `--ip <IP>` | source IP |
| `--user <USER>` | user (events only) |
| `--host <HOST>` | host |
| `--kind <KIND>` | `failed_login`, `invalid_user` or `successful_login` (events only) |
| `--since <TIME>` / `--until <TIME>` | from / up to a time, both included: RFC 3339 (`2026-10-22T10:15:32Z`), a date (`2026-10-22`, local midnight) or an age (`<number><s\|m\|h\|d>`, e.g. `--since 30m`) |

Filters combine (all must match). `--user` and `--kind` with `alerts` are refused (exit code `2`),
and a missing database is an error, not a new empty one. Anything else is a `sqlite3` query away,
with the schema above.

```sh
minisiem search --db minisiem.db events --ip 203.0.113.7 --since 1d
minisiem search --db minisiem.db alerts --since 2026-10-22 --until 2026-10-23
```

## Architecture

```
raw line -> LogParser -> Event -> Detector -> Alert -> AlertSink
            (adapter)   (domain)  (domain)   (domain)  (adapter)
```

In watch mode each source runs on its own thread and sends events through a channel to a single
pipeline thread, so detectors keep their state without locks:

```
journald thread ──┐
                  ├──> channel ──> Pipeline (detectors) ──> console
UDP thread ───────┘       ^
Ctrl+C / SIGTERM ─────────┘ (shutdown)
```

| Module | Role |
|--------|------|
| `event` | Normalized event model and the fields rules can use |
| `alert` | Alert, severity, MITRE technique and evidence |
| `ingestion` | `LogParser` port and the parsers: syslog lines, journald JSON, network syslog, per-line detection |
| `detection` | `Detector` port, the brute force rule and the Sigma engine (rules, correlations, per-group state) |
| `rule_loading` | Adapter that loads Sigma rule files from a directory into a validated rule set |
| `alerting` | `AlertSink` port and the console adapter |
| `pipeline` | Use case running detectors on events and delivering alerts |
| `storage` | Adapter keeping events and alerts in SQLite, behind the pipeline's `Archive` port, and searching them |
| `timespan` | `<number><s\|m\|h\|d>` spans, shared by correlation rules and search |
| `sources` | Live source adapters for watch mode (journald, syslog UDP) and the channel they feed |

## Known limitations

- Syslog timestamps have no year or timezone: the current local ones are assumed
  (logs crossing New Year or a DST change get shifted).
- Events must arrive in chronological order; in watch mode, sources are interleaved as events
  arrive, so slightly late events are tolerated but not reordered.
- Lines are not length-limited in batch mode or from journald.
- A UDP flood loses datagrams in the kernel before minisiem reads them (a 300,000-datagram flood on
  a debug build delivered about 25,000): they are counted as `kernel_dropped=N` on Linux, but not
  recovered, and not counted elsewhere.
- When watch gives up on a blocked stdout, events and alerts not yet committed to the database are
  lost (at most the ones since watch last had no event waiting).
- A single group can still hold many entries if one source floods matches within one window.
