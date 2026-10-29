# Implementation log

Append-only: one entry per piece of work, newest last.

## 2026-10-29: v0.3, job report, log file, cgroup limits (issue #5)

Plan: [plans/v0.3-report.md](plans/v0.3-report.md).

- `--report FILE` / `SBX_REPORT_FILE`: `sbx run` writes its outcome as JSON once the sandbox is torn down (`src/report.rs`): sbx's exit code, the program's exit status or signal, `timed_out`, the failed setup stage and its messages, `supervisor_error`, denied syscalls per name, `killed_after_exit`, `wall_ms`, rusage of the reaped tree, and the cgroup counters. Every failure after the report's directory is opened produces a report; a stale file at the path is removed when sbx starts.
- `--log FILE` / `SBX_LOG_FILE`: sbx's own lines go to an append-only 0600 file instead of stderr. Text from the sandbox (process and DNS names) is escaped. A failed write tears the sandbox down.
- Both destinations (`src/destination.rs`): absolute path, canonical directory, every directory from `/` owned by root or sbx's uid and writable by nobody else (sticky directories only above the last); opened at start, written through the directory fd with `O_NOFOLLOW`; the report is replaced atomically. A non-root sbx also needs the directory outside every fs rule.
- `[cgroup]` is a new required policy table: `mode = "off"`, or `"delegated"` with `memory_mb` and `pids` (`src/cgroup.rs`). Delegated: sbx moves itself to `C/sbx-supervisor`, enables memory and pids, runs the program in `C/sbx-sandbox` (memory.max, memory.swap.max = 0, memory.oom.group = 1, pids.max), kills leftovers with `cgroup.kill`, reads the counters and restores C. `sbx probe` runs a reversible trial. Breaking change: v0.2 policies need `[cgroup] mode = "off"`.
- Setup errors carry a `Stage`; the child's stages replace its string literals. Signals are blocked at the start of `sbx run`; a termination signal pending before fork aborts the run.
- `wait4` replaces `waitpid` everywhere the supervisor reaps; the dispatcher thread is joined before the denial counts are read.
- `sbx version` prints `SBX_VERSION` (`git describe`), which the Makefile passes to cargo and the image build; CI checks out full history and, on `v*` tags, that it equals the tag. Cargo version 0.3.0.
- Tests: property tests (proptest, dev-only) for the pure parts (usage accumulation, exit codes, wait statuses, stage round trip, the directory-chain rule, leftover counting, cgroup value formatting and parsing, log escaping, cgroup policy round trip); smoke sections "report and log" and "cgroup limits" (gated by `TEST_REQUIRE_CGROUP`; `make smoke` runs podman with `--systemd=always`, `SMOKE_CGROUP=false` otherwise); image checks for the version, the report and log as PID 1, and the refusal on a read-only cgroupfs.
- Deviations from the plan: the destination code is its own module rather than part of `report.rs`; the cgroup trial runs only in `sbx probe` (in `sbx run` the real setup reports the same errors, at stage `cgroup`).
- Not verified here: GitHub's ubuntu-24.04 runner with `--systemd=always` (rootless podman may get no delegated controllers), and Cloud Run (`make live`).
