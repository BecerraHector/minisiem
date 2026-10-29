# Feature: small follow-ups from the live sources reviews (issue #8)

Objective: close the small follow-ups collected in issue #8.
Branch: `fix/review-follow-ups` · Delivery: single PR, work-unit commits (forecast ~350 authored lines) · Test runner: `cargo test` (+ `cargo clippy --all-targets`, `cargo fmt --check`).

## Specs

Items quoted from issue #8.

- **S1** "**Stale year.** The syslog parser's year and offset are computed once when `watch` starts. A watch running across New Year (or a DST change) parses classic syslog timestamps with the old values. UDP events use arrival time, so this only affects timestamps parsed before stamping."
- **S2** "**Warning text.** The queue-full warning always names `QUEUE_CAPACITY`, even for a queue created with another size."
- **S3** "**Library-only race in `drain`.** Without the Ctrl+C handler's outlet, a source can report a failure and disconnect between the control check and the queue wait; the specific error is then replaced by \"every source disconnected\". Checking the control channel once more on disconnect fixes it. It cannot happen from the CLI."
- **S4** "**`MINISIEM_JOURNALCTL`.** The variable that swaps the `journalctl` binary for tests is undocumented; document it or restrict it to test builds." Decision (L4): document it.
- **S5** "**`watch` shadows a file named `watch`.** `minisiem watch` now runs the subcommand; `./watch` still reads the file. Document it."
- **S6** "**Unusual `_EXE` spellings** such as `/usr/./sbin/sshd`, `/usr//sbin/sshd` or a trailing `/` are accepted. journald does not emit them, so this is cosmetic."
- **S7** "**Status wording after minisiem kills journalctl.** `stop_and_explain` (`src/sources/journal.rs`) always kills journalctl before reaping it. When reading ended with `Ok` while journalctl was still running (the pipeline is gone), the message reads `journalctl exited (signal: 9 ...)`, as if it crashed on its own. Nobody reads it in that case today, but the wording should say minisiem stopped it."
- **S8** "**Test for that `Ok` path.** The unit test covers only the read error path of `stop_and_explain`; nothing checks the `Ok` path with journalctl still running."
- **S9** "**Comment the `/proc` field in the fake.** `tests/fixtures/fake-journalctl/records-group.sh` reads field index 4 of `/proc/$$/stat` (pgrp, the 5th field) and relies on the process name having no spaces. Say so in a comment."
- **S10** "**Quote triggers without a test** (from the review of #12): `field_value` in `src/alerting/console.rs` quotes values containing `=` or `\"`, but only values with spaces and `,` are tested. Add cases such as `x=src=9.9.9.9` and a value with `\"`."
- **S11** "**End-to-end test for a detector panic in watch.** `watch` exits with 101 when the detection thread panics (`ReportPanic` in `src/main.rs`), but only the guard has a unit test; the exit code was checked by hand with an injected panic. A test-only way to trigger a panic would let a CLI test pin it." Decision (L5): an environment variable.
- **S12** "**CLI test robustness.** `watch_stops_on_interrupt_even_when_nobody_reads_its_alerts` assumes ~2000 UDP datagrams arrive and fill the stdout pipe within 500 ms. Consider waiting until the pipe is actually full, or sending more alerts, so small UDP buffers or large pipe buffers cannot make it flaky."

## Tasks

| ID | Specs | Route | Status | Evidence |
|----|-------|-------|--------|----------|
| T1 | S2, S3 | inline | done | `94a5263`. RED: warning named 10000 for a queue of 2; error replaced by "every source disconnected". GREEN: 156 unit |
| T2 | S7, S8, S9 | inline | done | `9dcf03e`. RED: `journalctl exited (signal: 9 (SIGKILL))`. `forward_events` returns why it ended (`Ended`), as `try_wait` races with journalctl closing stdout before exit. GREEN: 158 unit + 21 CLI |
| T3 | S10 | inline | done | `6bb9d93`. Test-only (behavior existed, no RED); mutation check: removing `=`/`"` from the quote triggers fails the test |
| T4 | S1 | inline | done | `7e563a6`. In watch only UDP parses syslog dates and stamps arrival time, so the stale year only lost dates absent from that year (leap day). RED: `None` for Feb 29 2028 with a 2027 parser. Each datagram now parsed with its arrival year/offset; `SyslogUdp::spawn` and `event_from_datagram` lose the parser parameter. Throughput unchanged within noise (base 118-139k, candidate 182-224k events of 300k in one session) |
| T5 | S6 | inline | done | `cb73cd5`. RED: `/usr/./sbin/sshd` accepted. Spelling must equal its own components |
| T6 | S5 | inline | done | `534bed6`. Checked: `minisiem watch` runs the subcommand, `minisiem ./watch` reads the file |
| T7 | S4 | inline | done | documented in the README (watch mode) and the constant's comment |
| T8 | S11 | inline | done | `MINISIEM_TEST_PANIC` adds a detector that panics. RED: watch kept running (killed after 10 s). GREEN: exit 101 and the panic message on stderr, 3/3; 161 unit + 22 CLI |
| T9 | S12 | inline | done | `d41073e`. Sends batches until a thread's wchan contains `pipe_w` (this kernel: `anon_pipe_write`); 0/10 failures; Linux-only |

Routes are inline: no Writer trigger (units are small and sequential, one parent context).

## Log

- **L1** (2026-10-28) User: "ya mergeé, sigamos con el #8"
- **L2** Base: `main` at `48379f7` (PR #18 merged). Not in scope unless the user asks: the two advisories from the #4 reviews offered for #8 (kernel_dropped over-count after the reader stops; tests depending on `net.core.rmem_default`), which got no answer.
- **L3** (2026-10-28) T1-T6 and T9 done inline (commits above). Next: decisions for T7 (S4) and T8 (S11).
- **L4** (2026-10-28) User chose for S4: "Documentarla (Recommended)" (no new attack surface: `journalctl` is already looked up in `PATH`).
- **L5** (2026-10-28) User chose for S11: "Variable de entorno (Recommended)".
- **L6** (2026-10-28) Independent verifier (whole feature, base `48379f7`): PASS on S1-S12, no blockers; batch output byte-identical over 33 fixture runs; 0/10 failures on the three timing-sensitive tests. Advisories kept: a non-leap-year "Feb 29" datagram is now rejected (out of domain); a Shutdown racing a full disconnect still reads "every source disconnected" (as on main); an empty `MINISIEM_TEST_PANIC=` also enables it. Native review `review-35e3abba5b353115` (reliability) approved and acknowledged; its R3-001 (wchan substring `pipe_w` also matches read-side waits, a false pass) fixed by matching exact write-side names, 0/10 failures; R3-002 (no non-Linux CLI test for blocked stdout) left as is.
