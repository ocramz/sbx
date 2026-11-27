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

## 2026-10-29: multi-arch images, linux/amd64 and linux/arm64

Plan: [plans/multiarch-images.md](plans/multiarch-images.md).

- CI: `check` and `image` run on a matrix of `ubuntu-24.04` (amd64) and `ubuntu-24.04-arm` (arm64), so lint, unit tests and `make smoke` run natively on both. On `main` and `v*` tags, each `image` job pushes its tested image as `:<sha>-<arch>`. A new `manifest` job (needs both) joins them into the index `:<sha>` plus `:main`, or `:<tag>` and `:latest`.
- Makefile:
  - `push` now pushes only `$(IMAGE):$(VERSION)-$(ARCH)`. It refuses an image whose architecture is not PLATFORM's.
  - new `manifest` target (podman): an empty list plus one `manifest add docker://…` per `ARCHS`, a check that the list holds exactly `ARCHS`, `manifest push --all` to `:$(VERSION)` and each of `PUSH_TAGS`, then the local list is removed
  - `PLATFORM` must be `linux/amd64` or `linux/arm64`
- README (Build and test, CI paragraph) and CHANGELOG (Unreleased) updated. No Rust or Dockerfile changes.
- Verified locally (arm64 Mac, podman 5.3, kernel 6.12):
  - `make smoke`: 135 + 13 passed
  - `push` and `manifest` against a local plain-HTTP registry, through a wrapper that adds `--tls-verify=false`: the per-arch tags and the index under `scratch1`, `main` and `latest`; `--platform linux/arm64` pulls the arm64 image from the index
  - `push` refuses an amd64 image when PLATFORM is arm64
  - a list left by a failed run makes `manifest` fail
- Deviation from the plan: `manifest create LIST IMAGE…` ignored `--tls-verify` for its images in podman 5.3, so the target creates an empty list and adds images one at a time.
- Found while testing: on an arm64 host, `make image PLATFORM=linux/amd64` gives an image whose config says amd64 but whose base layers are arm64. podman reuses the locally stored `debian:bookworm-slim`, as `tests/cloud-run.sh` already notes. The config then carries `variant: v8`, so an amd64 pull from an index containing it fails. `push`'s architecture check cannot see this. CI builds each architecture natively, so it does not happen there; a comment above `push` says to push natively built images only.
- Not verified here: the arm64 runner's kernel (Landlock ABI 6, `TEST_REQUIRE_LANDLOCK=true`) and cgroup delegation under podman `--systemd=always`; `rustup` on that runner; podman 4.9 `manifest add`/`push` against ghcr.io with docker's auth file. These are checked by the first branch push and the first push to `main`.

## 2026-10-29: delegated cgroup, retry EBUSY in setup and teardown (issue #8)

Plan: [plans/cgroup-ebusy.md](plans/cgroup-ebusy.md).

- Cause: since kernel commit d245698d727a a reaped or joined task still counts in its cgroup until its last context switch. So enabling `+memory +pids` in C just after the capability checks' children exit can fail with EBUSY. So can removing `sbx-supervisor` while an sbx thread is still exiting, because moving sbx back to C does not move such a thread.
- `src/cgroup.rs`:
  - `retry_busy` retries an operation that fails with EBUSY every 10 ms for up to 2 s. After that the error ends in ", still after 2s". Any other errno fails at once.
  - It is used for both `cgroup.subtree_control` writes (new `subtree_control` helper) and both `rmdir`s.
  - `rmdir` now uses `std::fs::remove_dir` instead of `unsafe libc::rmdir`.
  - `write` is split into `write_io` (the I/O) and `write` (the message).
- Tests (smoke, "cgroup limits"):
  - 50 rounds of `sbx probe` and `sbx run -- /bin/true` in one cgroup, each required to succeed and to leave C restored
  - a deterministic teardown test: a harness thread keeps `C/sbx-supervisor` busy with a `sleep` until 0.2 s after teardown removed `sbx-sandbox`. sbx must exit 0 and restore C. No unit test, since `retry_busy` could only be driven by a fake operation.
- Verified locally (arm64 Mac, podman, kernel 6.12.7, which does not have d245698d727a):
  - `make smoke`: 137 + 13 passed
  - clippy and unit tests in `rust:1.97.0`
  - the new suite against the pre-fix image `sbx-test:8d20afbcf5db` fails the teardown test with the issue's `rmdir …/sbx-supervisor: Resource busy`
- Not verified here: the setup race itself (the stress rounds), which needs a kernel with d245698d727a, such as GitHub's ubuntu-24.04 runners in CI.
- Not done: waiting for the check children to finish exiting before enabling controllers. waitpid and pidfds report the exit before the last context switch, so userspace has nothing to wait on.

## 2026-11-21: v0.4, memory by kind (issue #10)

Plan: [plans/v0.4-memory-by-kind.md](plans/v0.4-memory-by-kind.md).

- `[measure]` is a new required policy table: `memory_sample_ms` (0 = off, at most 60000) and `tmpfs` (mount points, only with sampling on). `RawMeasure` goes through `try_from`/`into` to `MeasureCfg { Off, Sampled { interval_ms: NonZeroU64, tmpfs } }`. Validation requires each tmpfs path to be absolute, canonical, listed once, a mount point (its `st_dev` differs from its parent's) and a tmpfs (`statfs` magic), with no filesystem listed twice. A missing table names the fix. Breaking change: v0.3 policies need `[measure] memory_sample_ms = 0, tmpfs = []`; the shipped policies say that. Cargo version 0.4.0.
- `src/memory.rs` (new):
  - pure: the parsers of `/proc/<pid>/status` (`RssAnon`, `RssFile`, `RssShmem`), `memory.stat` (`anon`, `shmem`, through `cgroup::keyed`) and `/proc/sysvipc/shm` (columns by header name); `sysv_bytes` (segments owned or created by the sandbox uid, or created by a live sandbox pid: `cuid` survives `IPC_SET`); `memfd_bytes` (deduplicated by device and inode); `Peaks::of`/`join`/`fold` (pointwise maxima; `tree_anon_kib` is the per-sample sum of `RssAnon`); `Tracker` (`unsampled_processes`: a reaped pid counts unless a sample read it and it stayed in /proc since); `MemoryReport`.
  - IO: `Sampler` reads each live sandbox pid's status and the `/memfd:` links in its fd table (`stat` through the link for device, inode and `st_blocks`), then `/proc/sysvipc/shm`, the tmpfs mounts (`statvfs`, minus the baseline read before fork) and, when delegated, the sandbox cgroup's `memory.stat`. A process or descriptor that went away meanwhile is skipped; any other failed read is logged the first time per kind, and counted.
- `src/supervisor.rs`: `supervise` wakes for the next sample with the deadline and the grace period, samples, and samples once more right after the program's process is reaped, before `kill_tree`. `wait()` feeds an `Accounts` struct (rusage plus the sampler's tracker). `live_descendants` returns the set of pids.
- `src/capabilities.rs`: with sampling on, the `CAP_SYS_PTRACE` check (one check whose message names egress and/or sampling) and `sandbox /proc access`: a child running as the sandbox uid creates a memfd and makes itself non-dumpable, and sbx must read its status and find the memfd in its fd table, and read `/proc/sysvipc/shm`.
- `src/cgroup.rs`: `Delegation::memory_stat`; `memory.stat` joins the files the sandbox cgroup must have.
- Report: a 12th key, `memory`. `Outcome::Ran` now boxes `Ran` (clippy `large_enum_variant`).
- Tests:
  - property tests: parse ∘ render = id for the three parsers; `Peaks::fold` monotone, idempotent and independent of sample order; a sample's figures; `memfd_bytes` under duplication and reordering; `sysv_bytes` against segments built to match or not; `Tracker` against a brute-force model; `MeasureCfg` through `sbx policy`; `live_descendants` as sets.
  - unit tests: the missing-table hint, `tmpfs` with sampling off, the path checks, the bound.
  - smoke, new section "memory by kind" (`/dev/shm` must now be a tmpfs mount with mode 1777): probe; a program holding a 64 MiB heap, a mapped 16 MiB memfd, an unmapped 32 MiB memfd, an 8 MiB `/dev/shm` file and a detached 4 MiB SysV segment; sampling off; a program that exits before the first sample; a tmpfs file left behind; refusals (not a tmpfs, tmpfs with sampling off, no CAP_SYS_PTRACE); the overhead at 10, 20 and 50 ms (printed, bound 1.5× + 100 ms); in the delegated cgroup, `memory.stat`. The report check counts 12 keys.
  - `tests/live.py` prints `/dev/shm`'s type and whether `/proc/sysvipc/shm` exists, and runs a smaller memory program with the no-Landlock example and sampling on.
- Verified locally (arm64 Mac, podman machine with 4 CPUs, kernel 6.12):
  - `cargo fmt --check`; clippy with `-D warnings` for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-musl` on macOS, and natively in `rust:1.97.0-slim-bookworm` (arm64); 75 unit tests pass there.
  - `make smoke` (delegated cgroup): 148 + 13 passed. The memory program at 20 ms: 30 samples, `memfd_peak_kib` 49152, `sysv_shm_peak_kib` 4096, `tmpfs_peak_kib` 8192, `max_anon_kib` 70328, `max_shmem_kib` 16384, `max_file_kib` 5256, against `rusage.max_rss_kib` 95936. Overhead, wall time of a 0.33 s CPU-bound program: off 344 ms, 10 ms 354 ms, 20 ms 326 ms, 50 ms 328 ms (within noise).
- Deviations from the plan: none in behaviour. `fs_used` uses `statvfs` (its field types are the same in glibc and musl, so no casts), and the magic check is generic over `f_type`'s type.
- Not verified here: Cloud Run (`make live`), including whether its `/dev/shm` is a tmpfs; the amd64 runner; a kernel without `RssAnon` (pre-4.5, below what sbx supports anyway).

## 2026-11-22: v0.4.1, /proc read as bytes; no stale report

Plan: [plans/v0.4.1-proc-bytes.md](plans/v0.4.1-proc-bytes.md). The series work that builds on it is planned in [plans/v0.5-series.md](plans/v0.5-series.md), [plans/v0.5-series-processes.md](plans/v0.5-series-processes.md) and [plans/v0.5-series-compression.md](plans/v0.5-series-compression.md).

- **Cause:** a process name can hold any byte but NUL, and the sandbox picks its own with `prctl(PR_SET_NAME)`. `/proc/<pid>/stat` prints the name as is, and `status` escapes only `\n` and `\\`. Every reader that used `read_to_string` failed on a name that is not UTF-8:
  - `supervisor::proc_table` dropped the process, so `own_children`, `live_descendants` and `leftovers` never saw it. A renamed `setsid` escapee survived sbx when sbx was not PID 1 and had no cgroup.
  - `memory::proc_mem` skipped it.
  - `capabilities::uid_unused` passed it.
  - `notify::tgid_of` failed, which with `on_violation = "kill"` was fatal (exit 125).
- **`src/procfs.rs` (new, pure):**
  - `Stat::parse(&[u8])` (ppid, zombie), with the fields after the last `)`
  - `status_field`/`status_text`: the first line starting with a key, trimmed
  - a `render` test module with the kernel's escaping of the `Name:` line
- **Callers now read bytes:**
  - `proc_table` logs, once per run, a read error other than ENOENT/ESRCH or an unparsable stat, instead of dropping the process silently.
  - `ProcMem::parse_status` takes bytes. `proc_mem`'s zombie check goes through `status_text`.
  - `uid_unused` and `tgid_of` parse with `status_text`. `uid_unused`'s message and `comm_of` escape the name with the new `log::untrusted_bytes`: valid UTF-8 as `untrusted` does, and other bytes as `\xNN` (`utf8_chunks`). The message used to print the `Name:` value unescaped.
- **`src/main.rs`:** `Outputs::open` opens the report and, for `run`, removes a stale one before it opens the log. `run_and_report` no longer removes it. One consequence: an invalid `--report` path is now reported on stderr even with `--log`.
- **Tests:**
  - property tests:
    - `stat_parsing_finds_the_fields_whatever_the_name`
    - `status_fields_are_found_whatever_the_name`
    - `status_parsing_survives_any_process_name`, which replaces `status_parsing_inverts_rendering`
    - three for `untrusted_bytes`: no controls, the same as `untrusted` on UTF-8, an invalid byte between ASCII spelled `\xNN`
  - unit test: a name cannot forge a `Uid:` line
  - smoke tests:
    - a `setsid` escapee renamed to `\xff\xfe` is killed (supervision) and counted in `killed_after_exit` (report)
    - kill mode kills a renamed process (exit 137, log `killed \xff[pid`)
    - `abi = "off"` refuses while a renamed process runs as the sandbox uid
    - a renamed 32 MiB heap is sampled
    - a refused `--log` leaves no stale report
- **Verified locally** (arm64 Mac, podman machine, kernel 6.12.7):
  - `cargo fmt --check`
  - clippy with `-D warnings`, natively and for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-musl`, in `rust:1.97.0-slim-bookworm`
  - 81 unit tests pass
  - `make smoke` with the v0.4 code and the new tests: 149 passed, the 7 new ones failed
  - `make smoke` with the fix: 156 + 13 passed
  - `make probe`: OK
- **Deviations from the plan:**
  - The parsers live in a new `src/procfs.rs` rather than in `supervisor.rs`, since memory, capabilities and notify use them too.
  - `ProcMem::parse_status` takes the bytes itself, so the property test covers the decoding.
- **Not verified here:** the amd64 runner, and Cloud Run (`make live`).

## 2026-11-22: v0.5 part 1, the memory time series

Plan: [plans/v0.5-series.md](plans/v0.5-series.md), part 1 of 3. v0.5 is released after [part 3](plans/v0.5-series-compression.md).

- **Policy (`src/policy.rs`):**
  - `[measure.series]` is a new required table: `SeriesCfg { Off, On { max_samples: NonZeroU32 } }` through `RawSeries`, like `CgroupCfg`. `max_samples` is refused with `"off"`, required with `"on"`, and must be 1..=1000000.
  - `MeasureCfg::Sampled` gains `series`, and `RawMeasure` has it as its last field (a table follows plain values in TOML). Series `On` with sampling off is a `TryFrom` error. `MeasureCfg::series()` gives `Off` for `MeasureCfg::Off`.
  - `validate_measure` refuses a series whose `series::bound` exceeds `SERIES_CEILING_BYTES` (256 MiB), naming the bound in MiB.
  - Hints: a missing `series` field names the v0.5 fix, and the v0.4 hint names `[measure.series]` too.
  - `SBX_SERIES_FILE` / `--series FILE`, in `Overrides`.
- **`src/series.rs` (new, pure):**
  - `SeriesSpec` (interval, `max_samples`, the tmpfs mounts sorted as the report keys them, `CgroupColumns { Absent, Present }`), built from the policy only when `--series` is given.
  - `Row::of` takes the maxima and tree sum from `Peaks::of`, so they agree with the report by construction, and converts to KiB with the report's `memory::kib`.
  - `MemorySeries::push(t_us, &Sample, When { Running, Final })` keeps running samples while there are fewer than `max_samples` rows, and always keeps the final one. The row vector grows by doubling, capped with `reserve_exact` at `max_samples + 1`.
  - `bound()` and `footprint()` share one cost model: `size_of::<Row>()` (112 bytes) per row plus, with any tmpfs mount, 16 bytes per mount and 16 for the allocator.
  - The `Serialize` impl streams each column from the rows with `collect_seq`/`collect_map`. The cgroup columns are `null` under `Absent`.
- **`src/memory.rs`:**
  - `Sample.sysv_bytes` and each `tmpfs_bytes` value are `Option` (`None` = failed read), and every measured mount has an entry. `Peaks::of` skips `None`, so the report is unchanged.
  - The pure state of sampling (peaks, tracker, count, series) moved from `Sampler` into a new `Tally`. `Sampler::sample(at, When, …)` reads, then calls `Tally::record`. `finish()` returns `(MemoryReport, Option<MemorySeries>)` and logs `memory series: N rows, D samples dropped, K KiB in memory`.
- **`src/supervisor.rs`:** running samples get `started.elapsed()` and `When::Running`, and the post-reap sample gets `When::Final`. `Ran.series`. The sampler now finishes before the `exit N after` line, so its lines come first.
- **`src/report.rs`:**
  - `Stage::Series` after `Log` (25 stages).
  - `Ran.series`, which is not part of the report (still 12 keys).
  - `series_json` writes one line of compact JSON.
- **`src/destination.rs`:** `write_atomic_with(FnOnce(&mut dyn Write))` over a 64 KiB `BufWriter`, and `write_atomic` delegates to it.
- **`src/main.rs`:**
  - `Outputs.series` is opened after the report's stale file is removed and before the log. It is refused when its path equals `--report`'s or `--log`'s, and that check comes before its own `remove_stale`, so it cannot delete the log.
  - At stage `series`: the mode must be on, and the directory out of the sandbox's reach.
  - `run_and_report` writes the series before the report. On failure it logs, sets exit 125 and sets `supervisor_error` unless one is set.
  - `probe` has a `series file` check.
- **Policies:** the three shipped policies, MINIMAL and smoke's `policy()` have `[measure.series] mode = "off"`. `tests/image-checks.sh` turned every `mode = "off"` line into the delegated cgroup; its sed is now limited to `[cgroup]`.
- **Tests:**
  - property tests:
    - `kept_rows_are_the_first_samples_and_the_final_one` (with `samples = rows + dropped`)
    - `the_series_agrees_with_the_report`, through `Tally`
    - `every_column_has_one_entry_per_row_and_null_exactly_where_reads_failed`, on the parsed JSON
    - `the_bound_covers_every_series_the_spec_allows` (capacity ≤ `max_samples + 1`, footprint ≤ bound)
    - `series_settings_survive_sbx_policy`
    - `measure_settings_survive_sbx_policy` now with series
    - memory's sample strategy now has failed reads
  - unit tests: the refusals (fields with "off", no `max_samples`, 0, 1000001, sampling off, an unknown field), the ceiling (1000000 samples with 32 listed mounts), both hints, 25 distinct stages with `series` fourth.
  - smoke, new section "time series":
    - a MEMPROG run whose columns' maxima equal the report's figures, with `t_us` increasing, the last row within 1 s of `wall_ms` with no live process, mode 0600 and one line
    - `max_samples = 3` keeps the first 3 and the post-exit row
    - `SBX_SERIES_FILE`
    - refusals: mode off at stage `series` (the stale file is removed), on with sampling off, a missing table, the ceiling, the same path as `--report` or `--log` (the log is left alone)
    - no file after a setup failure
    - a failed write (the directory is removed while the program runs) exits 125 with `supervisor_error`
    - probe ok and MISSING
    - in the delegated cgroup, the memory.stat columns
- **Verified locally** (arm64 Mac, podman machine, kernel 6.12.7):
  - `cargo fmt --check`
  - clippy with `-D warnings`, natively and for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-musl`, in `rust:1.97.0-slim-bookworm`
  - 90 unit tests pass
  - `make smoke` (delegated cgroup): 176 + 13 passed, including the 20 new checks. The image build validates the three shipped policies. The MEMPROG run at 20 ms kept 26 rows: 1515 bytes on disk, 8 KiB in memory (the first 64-row reservation).
  - The first smoke run caught the `image-checks.sh` sed.
  - `make probe`: OK
  - A manual run at 50 ms with `max_samples = 5`: 11 samples, 6 rows, 5 dropped, the last `t_us` 539510 against `wall_ms` 539.
- **Deviations from the plan:**
  - `series::bound(max_samples, n_tmpfs)` takes no cgroup flag, because the cgroup figures are stored inline and cost the same either way. Part 3's encoded columns may need it.
  - `live_processes` is `procs.len()`, not a new `Sample` field that would duplicate it.
  - The new `Tally` lets the agreement property run the real code without IO.
  - Smoke tests added beyond the plan: `SBX_SERIES_FILE`, the missing-table hint, the failed write, and the cgroup columns.
- **Not modelled by the bound:** a reallocation's transient copy of the row vector. glibc and musl move large allocations with `mremap`, so this should not double the peak, but it was not measured.
- **Not verified here:** the amd64 runner, and Cloud Run (`make live`). `tests/live.py` rewrites only `[measure]`, so its policy stays valid.

## 2026-11-22: v0.5 part 2, per-process entries in the memory series

Plan: [plans/v0.5-series-processes.md](plans/v0.5-series-processes.md), part 2 of 3.

- **Process identity (`src/procfs.rs`, `src/memory.rs`, `src/supervisor.rs`):**
  - `procfs::Stat` gains `start_ticks: StartTicks` (field 22) and `comm: Comm` (the raw name between the first `(` and the last `)`, cut to 16 bytes). A stat line with fewer fields is not parsed.
  - `ProcKey { pid, start }` names a process, and `Sample.procs` is `Vec<ProcRead { key, name, mem }>`. `Peaks::of` maps `mem`, so the report is unchanged.
  - The supervisor's `ProcEntry` is a struct with the start ticks, and `live_descendants` returns `BTreeMap<Pid, StartTicks>`.
  - `ProcDir` replaces `proc_mem(pid)` and `memfds(pid)`. It opens `/proc/<pid>` with `O_DIRECTORY` and reads `stat` and `status` through it with `openat`, and the `fd` directory with `openat`, `fdopendir`, `readdir`, `readlinkat` and `fstatat`. `ProcDir::of(key)` gives `Gone` when the start ticks differ, so the sampler reads only the processes `proc_table` found, and `Tracker` sees only those pids. Failed stat reads are a new failure kind, `/proc/<pid>/stat`.
  - `sysv_bytes` takes `is_live: impl Fn(Pid) -> bool`.
  - `capabilities::proc_access` reads its non-dumpable child through `ProcDir`, so `sbx probe` exercises the sampler's exact path.
- **Policy (`src/policy.rs`):** `SeriesCfg::On` gains `max_processes: u32` (0 lists none), required with `"on"` and refused with `"off"`. `validate_measure` refuses more than `MAX_SERIES_PROCESSES` (4096), and the ceiling message names `max_processes`.
- **`src/series.rs`:**
  - `SeriesSpec.processes: ProcessColumns { Absent, Top(NonZeroU32) }`.
  - `rank` orders a sample's processes by `(Reverse(rss_kib), key)` with `select_nth_unstable_by`, then sorts the first n. `Row::of` returns the row and its listed processes, and `Row.others` sums the rest.
  - The process table is `BTreeMap<ProcKey, Slot>` plus `Vec<(ProcKey, Comm)>`. A process listed again keeps its slot, and its name becomes the latest.
  - Listed processes go into one flat `entries: Vec<ProcessRow { row, process, mem }>`, by row and then rank.
  - Every vector grows through `room_for_one`, which doubles but is capped: `max_samples + 1` rows, and `(max_samples + 1) × max_processes` entries and table slots.
  - `bound(max_samples, n_tmpfs, max_processes)` and `footprint()` share one cost model. Each vector costs its capacity plus 16 bytes of allocator overhead (part 1 left that 16 out). The slot map costs `(1 + n/5) × 352` bytes, which follows std's B-tree layout (at most 11 entries per node, at least 5 in every node but the root while nothing is removed).
  - JSON:
    - the header gains `max_processes`
    - `rows` gains `others_processes`, `others_anon_kib`, `others_file_kib` and `others_shmem_kib`
    - new `processes` (`pid`, `start_ticks`, `name` through `log::untrusted_bytes`) and `process_rows` (`row`, `process`, `anon_kib`, `file_kib`, `shmem_kib`)
    - all `null` under `Absent`
  - `Sampler::finish` logs `memory series: N rows, D samples dropped, P processes listed, K KiB in memory (at most B KiB)`.
- **Sizes**, from a throwaway test in the dev container (aarch64): `Row` 144 bytes, `ProcessRow` 32, `(ProcKey, Comm)` 40, a modelled map node 352.
  - So a listed process costs at most 32 + 40 + 70.4 bytes.
  - 50000 samples × 32 processes with one tmpfs mount is bounded at 225.7 MiB, and the ceiling allows up to 56717 samples there.
  - 1000000 samples with no processes is 137.3 MiB, or 167.8 MiB with one mount.
- **Found by the first smoke run:** a process caught between losing its address space and becoming a zombie has a status with no `Rss*` lines and a state of `R`. It was logged as "needs Linux 4.5+". `ProcMem::exited` now treats a status without `VmRSS` as exited too, and so `Gone`. The race predates this part.
- **Tests:**
  - property tests in `series.rs`:
    - `listed_processes_are_the_largest_of_their_sample`, against a full sort
    - `listed_and_others_add_up_to_the_sample`
    - `the_process_table_holds_exactly_the_listed_processes_with_their_latest_name`
    - `a_recycled_pid_is_a_new_process`
    - `process_rows_point_at_existing_rows_and_processes`, on the JSON
    - the part 1 properties, now with processes that come and go and pids reused with other start ticks (memory's `procs()` strategy, with tiny sizes so that ranks tie)
    - the bound test, with samples full of new processes, the table's worst case
    - procfs's stat property, with start ticks and the name
  - **Measured heap use.** A counting `#[global_allocator]` (System, counted per thread) checks the cost model against real allocations:
    - `the_footprint_covers_the_series_real_memory`: the whole series held ≤ `footprint()`
    - `the_btree_model_covers_its_real_memory`: a slot map of up to 5000 keys, in order, reversed or shuffled, held ≤ `map_cost`
    - `the_btree_model_and_the_measured_figure_per_entry`: 100000 keys hold 43.6 bytes per entry in order and 35.0 shuffled, against 70.4 modelled
    - Two mutations of the model were each caught: dropping the 16-byte overhead per vector, and assuming 11 entries per node instead of 5.
  - `ProcDir` on the real kernel:
    - `a_proc_dir_reads_its_own_process`: a 1 MiB memfd is found, and a wrong start tick reads `Gone`
    - `a_proc_dir_is_pinned_to_its_process`: once a forked child is reaped, its open directory reads `Gone`
  - unit tests:
    - policy refusals: `max_processes` with "off", missing, negative, above 4096
    - the ceiling: 1000000 × 0, 1 × 4096 and 50000 × 32 with one mount pass; 1000000 × 32 is refused and names `max_processes`
    - a stat line without the start time is not parsed
    - an exiting status counts as exited, a pre-4.5 one does not
  - smoke, in "time series":
    - children named `sbx-kid-16/32/64` appear with the pids and names they print, the largest first, and the sums hold
    - `max_processes = 1` and `= 0`
    - a fork loop of short-lived children: each (pid, start) once, valid indices, the sums hold, and the logged footprint is within the logged bound
    - more than 4096 is refused
    - the ceiling check is now plain `max_samples = 1000000`
- **Verified locally** (arm64 Mac, podman machine, kernel 6.12.7):
  - `cargo fmt --check`
  - clippy with `-D warnings`, natively and for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-musl`, in `rust:1.97.0-slim-bookworm`
  - 100 unit tests pass
  - `make smoke` (delegated cgroup): 181 + 13 passed
    - The KIDS run listed 4 processes in 105 entries over 29 rows.
    - The fork loop listed 220 processes over 47 rows, in 52 KiB against a bound of 64221 KiB.
    - The sampling overhead check passed: off 327 ms, 10 ms 363 ms, 20 ms 331 ms.
    - The first run failed two new checks, both test mistakes: once the smallest child exits, a row lists only two children, and a series file was left before the probe's "writes nothing" check. It also showed the exit race fixed above.
  - `make probe`: OK
  - A manual run with two children and a parent that `exec`s `sleep`: the parent keeps its slot and its name becomes `sleep`, and each row's entries add up to `tree_anon_kib`.
- **Deviations from the plan:**
  - Listed processes are one flat `entries` vector, not a `Vec` in each row: the same layout as `process_rows`, and no allocation per row.
  - The B-tree's memory is a model at run time, checked by the heap tests above.
  - Pid reuse is not forced in smoke: pid_max is global before Linux 6.14, so it cannot be lowered for the test alone. The property test and the reaped-child `ProcDir` test cover it.
  - The log line gains the bound, so smoke can check the footprint against it.
  - `max_processes` above 4096 is a validation error, as `max_samples` above 1000000 is.
- **Not modelled by the bound:** a reallocation's transient copy, as in part 1. The heap counter sees `realloc` as one block that changes size.
- **Not verified here:** the amd64 runner, and Cloud Run (`make live`).

## 2026-11-22: v0.5 part 3, compressed series in memory and on disk

Plan: [plans/v0.5-series-compression.md](plans/v0.5-series-compression.md), part 3 of 3. v0.5 is complete with this part.

- **`src/series/codec.rs` (new, pure):**
  - `zigzag`/`unzigzag`, and LEB128 over values up to 2^64, so a varint is at most 10 bytes. An optional value needs the 65th bit: `null` is 0 and a value is zigzag(delta) + 1. The decoder is total: it stops at the end of the buffer and drops bits past the tenth byte.
  - `Word` (u64: at most 10 bytes; u32: at most 5, since the zigzag of a delta between two u32 is below 2^33) widens values to u64 for the wrapping delta.
  - `Column<T>`, `OptColumn` (a `null` leaves the last value as it was) and `RankColumn<T>`. A `RankColumn` stores rows in rank order, each value a delta from the last one at the same rank. Its state, one u64 per rank reached so far, grows only as rows need it.
  - Every buffer has a byte cap (values × the type's most bytes). `room_for(v, extra, cap)` grows it by doubling but never past the cap; it replaces part 2's `room_for_one`.
- **`src/series.rs`:**
  - `MemorySeries` holds `RowColumns` (one column per figure, plus one per tmpfs mount, in a boxed slice) and, under `Top(n)`, a boxed `Listed`: four `RankColumn`s (slot, anon, file, shmem) and the unchanged process table.
  - **The cgroup columns:** `CgroupStore::Present { anon: OptColumn, shmem: Column }`. `shmem` holds a value only for the rows whose `memory.stat` read succeeded, so a row cannot have one cgroup figure without the other.
  - **No entry counts:** a row lists `min(max_processes, live_processes)` processes, so no per-entry `row` and no count is stored. `process_rows.row` is rebuilt from `live_processes`.
  - **`others`** is kept under `Absent` too, so that `Row`s decode whole.
  - **Serialization:** a `Seq(|| iter)` wrapper decodes each column while serde writes it. The JSON is unchanged.
  - **API:**
    - `kept()` replaces `rows().len()`, and `compression()` is new.
    - `rows()`, `entries()`, `procs()` are test-only; they decode with the iterators the writer uses.
    - `SeriesSpec` gains `compression`.
  - **Cost model:** `blocks()` lists every heap block with what it takes now and the most it can take.
    - `footprint()` sums the first and `bound()` the second.
    - The most includes the decoding state of one rank column while the file is written.
    - The free `bound(max_samples, n_tmpfs, max_processes)` builds an empty series with the cgroup columns and sums its blocks. An empty series allocates only its tmpfs slice, so a policy with absurd limits costs nothing to check.
- **Policy (`src/policy.rs`):** `SeriesCompression { None, Gzip }`. `SeriesCfg::On` gains `compression`, required with "on" and refused with "off". `TryFrom<RawSeries>` is now one arm per mode.
- **Gzip:**
  - `flate2 = "1"` (1.1.11, miniz_oxide backend; `Cargo.lock` gains crc32fast, miniz_oxide, adler2, simd-adler32 and the unused optional zlib-rs).
  - `report::series_file` writes the JSON, or the JSON through a 64 KiB `BufWriter` into a `GzEncoder`, then `into_inner` (no sync flush) and `finish()`. Its errors are write errors, so a failure exits 125 with "writing the series".
  - `main.rs` calls it inside `write_atomic_with`. The usage text mentions it.
- **Policies:** the three shipped policies' comments list `compression`.
- **Worst-case figures** (aarch64 dev container, a throwaway test):
  - A row takes 130 bytes plus 10 per tmpfs mount: 12 u64 columns and the mounts at 10 bytes, 2 u32 columns at 5. The cgroup columns are counted at policy time.
  - A listed process takes 35 bytes plus the process table's 40 and the map's 70.4.
  - Totals:
    - 1000000 × 0: 133.5 MiB with one mount (167.8 before), 124.0 with none
    - 50000 × 32 with one mount: 228.5 MiB (225.7 before)
    - 50000 × 35 still fits (249.3); 50000 × 36 does not (256.3)
- **Tests:**
  - codec property tests:
    - `varints_round_trip`, up to 2^64
    - `zigzag_round_trips_and_keeps_small_magnitudes_small`
    - `encoded_columns_decode_to_the_values`: all three kinds of column, with extremes so that deltas wrap, nulls anywhere and rows longer than the ranks; the bytes stay within the type's worst case and the capacities within their caps
    - `a_steady_rank_takes_a_byte`
  - codec unit test: `the_largest_varint_is_ten_bytes`
  - series:
    - every part 1 and 2 property, unchanged but for the accessors
    - the JSON tests now go through `series_file`
    - `the_bound_covers_every_series_the_spec_allows` uses worst-case samples: every figure half the range or 2^56 KiB from the last, a failed read every third sample, times alternating 0 and 2^63. It checks every block against its most, and that the bound counts the cgroup columns.
    - `the_footprint_covers_the_series_real_memory` runs with up to 71 processes per sample, new ones or the same ones in every sample. With the same ones, the slot map's slack is too small to hide a missing block.
    - Four mutations of the model were each caught: leaving out the boxed `Listed`, the rank state, the tmpfs slice, or one row column. A fifth, a u32 worst case of 4 bytes, fails the codec tests.
    - new `gzip_output_inflates_to_the_plain_json`: "none" writes the JSON as is, and "gzip" starts with `1f 8b` and inflates to it byte for byte.
  - policy:
    - the round-trip strategy covers `compression`
    - refusals: with "off", missing with "on", `"zstd"`
    - the ceiling test is unchanged and passes
  - smoke, in "time series":
    - every "on" policy has `compression`
    - `load_series` inflates when the file starts with the gzip magic
    - new check: MEMPROG with "gzip", to the same `series.json` name, writes one gzipped line with the same structure as the "none" run, and it agrees with the report as that run does
    - the info lines give bytes per row on disk and in memory, and gzip against plain
- **Verified locally** (arm64 Mac, podman machine, kernel 6.12.7):
  - `cargo fmt --check`
  - clippy with `-D warnings`, natively and for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-musl`, in `rust:1.97.0-slim-bookworm`
  - 106 unit tests pass
  - `make smoke` (delegated cgroup): 182 + 13 passed, including the new gzip check.
    - The MEMPROG run kept 27 rows in 6 KiB (228 bytes per row), almost all of it the first 64-byte reservation of each buffer. It wrote 2552 bytes, or 574 gzipped.
    - The fork loop listed 207 processes over 46 rows, in 29 KiB against a bound of 62659 KiB; part 2 took 52 KiB for a similar run.
  - `make probe PLATFORM=linux/arm64`: OK
  - **A manual run in the test image:** three children growing their heaps for 4 s, sampled every 10 ms, with `max_processes = 32`.
    - It kept 362 rows and 1416 entries in 23 KiB, about 65 bytes per row with its four processes. Part 2's vectors would have held about 140 KiB.
    - The plain file was 41827 bytes and starts with `{"`. The gzip one was 7594 bytes, starts with `1f 8b`, and `gzip -dc` gives one line with the same 8 keys.
- **Deviations from the plan:**
  - Listed processes are deltas from the same rank in the row before, not from the same slot: the user's choice when per-slot state turned out to put 50000 × 32 over the ceiling (recorded in the plan).
  - No per-entry `row` column and no counts (derived from `live_processes`).
  - The cgroup shmem column holds only the rows whose read succeeded.
  - The worst case depends on the width: 5 bytes for u32 values, not 10 for every varint.
  - The bound also counts the decoding state while the file is written.
  - `rows()` is test-only; `kept()` serves the log line.
- **Not modelled by the bound:** a reallocation's transient copy, as before.
- **Cloud Run:** `make live` passed (run by the user).
- **Not verified here:** the amd64 runner.

## 2026-11-26: v0.6, a policy filter without the listener, for gVisor (issue #18)

Plan: [plans/v0.6-gvisor.md](plans/v0.6-gvisor.md).

- **Policy (`src/policy.rs`):**
  - `Notify { Listener, Off }` is the first field of `SeccompCfg`, required. A missing key gets the hint "seccomp.notify is new in sbx v0.6; add notify = "listener"".
  - `validate_network` refuses egress with `Off`.
  - `validate_seccomp` asks `seccomp_layer::reserved(name, notify)` why a syscall cannot be denied, and warns once for `Off`, with a text for `errno` and one for `kill`.
  - The `Violation::Kill` doc names both signals.
- **Filter (`src/seccomp_layer.rs`):**
  - `OnMatch { Notify, Verdict(Violation) }`, from `OnMatch::of(&SeccompCfg)`. `compile(table, on_match)` uses the existing marker and its rewrite into `USER_NOTIF` (now `into_user_notif`), or the plain seccompiler actions `Errno(EPERM)` and `KillProcess`.
  - `Programs.on_match`; the summary line names `notify`.
  - `RESERVED` became `reserved()`: `execve` always, `sendmsg` with the listener only. `sendmsg` moved into `EXTRA_NAMES`, so `seccomp.deny` accepts it.
  - `install_without_listener` installs with flags 0.
- **Supervisor (`src/supervisor.rs`):**
  - The socketpair, `recv_fd` (`Stage::Listener`) and the dispatcher exist only with `OnMatch::Notify`. The child matches `(on_match, socket)`; a mismatch is a `BUG:` error, as for Landlock.
  - `start_services` returns `Option<JoinHandle>` and refuses an egress filter without a listener.
  - `supervise` returns `denials: Some(..)` exactly when a dispatcher ran. Under `Verdict(Kill)`, a program killed by SIGSYS gets a hint in its log line (beyond the issue).
- **Probe (`src/capabilities.rs`):**
  - `notify` chooses the check. The new "seccomp filter" check compiles a one-rule table (`getppid`) through `compile`, and in a forked child sets `RLIMIT_CORE` to 0 and `NO_NEW_PRIVS` and installs the prelude and that filter.
  - It wants `EPERM` (exit 0) or death by SIGSYS.
  - `fork_check` now returns the wait status; `subreaper` checks it.
- **Report:** `Ran.denials: Option<Vec<..>>`, `null` in the JSON. A setup failure keeps `[]`. Still 12 keys.
- **Policies and image:**
  - the three shipped policies have `notify = "listener"`
  - `policy/gvisor.example.toml` is new: Landlock off, notify off, kill, cgroup off, network none, sampling off. The Dockerfile ships it and validates it with `sbx policy`.
  - version 0.6.0.
- **Tests:**
  - property `the_policy_filter_returns_its_verdict_exactly_when_a_rule_matches` replaces `bpf_matches_evaluator`.
    - Inputs: random policies (network mode, socket families, subprocesses, Landlock, `deny` from every lookup-able name, `allow` from the default denials, `notify`, `on_violation`) and calls from `samples()`, the table's numbers with random arguments, and any `i32`.
    - The expected verdict is written as literals in the test, so `OnMatch::of` is checked too.
    - Two mutations were caught: `KillThread` for `KillProcess`, and `Off` always mapped to `errno`.
  - property `the_prelude_verdicts_depend_only_on_the_architecture_and_number` replaces `prelude_verdicts`.
  - policy:
    - `the_notify_key_is_required_with_an_upgrade_hint`
    - `sendmsg_is_reserved_only_with_the_listener` (and `execve` always)
    - `egress_needs_the_listener`
    - `without_the_listener_sbx_warns_that_denials_are_not_seen`
  - report: `denials: None` is `null`, with 12 keys.
  - smoke: a section "seccomp without the listener" with 14 checks:
    - the probe
    - SIGSYS: exit 159, `{"signaled": 31}`, `denials` null, unlogged, the hint and the warning; for `unshare` too, and in a forked child
    - AF_UNIX
    - the two filters
    - `EPERM` with `denials` null
    - `--seccomp-action kill`
    - `clone3`
    - `sendmsg` with off and with the listener
    - egress refused
    - the missing-key hint
  - `tests/image-checks.sh`: the gVisor example's probe passes on runc.
  - new: `tests/gvisor.py` (stdlib), the in-sandbox suite. It prints the platform facts and both probes, and makes 13 or 14 checks: the listener refusal applies only where there is no listener.
  - new: `tests/modal_gvisor.py`, a uv script.
    - It pins `modal==1.6.4`, with `tests/modal_gvisor.py.lock` from `uv lock --script`.
    - It checks that sbx is a static x86-64 ELF, builds a `debian_slim(python 3.13)` image with sbx, the four policies and the suite, and runs the suite as the sandbox's own command.
    - The runtime is `"gvisor"` by default; `--runtime vm` is the control.
  - `make gvisor` builds the amd64 runtime image as `localhost/sbx-modal:<sha>` (so `$(IMAGE)` keeps its tag), copies sbx out and runs the script.
- **Verified** (arm64 Mac, podman machine, kernel 6.12.7):
  - `cargo fmt --check`
  - clippy `-D warnings` natively and for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, in `rust:1.97.0-slim-bookworm`
  - 110 unit tests pass
  - `make smoke` (delegated cgroup): 196 + 14 passed
  - `tests/gvisor.py` in the test image on runc: 13 passed
  - **Modal, gVisor** (`4.19.0-gvisor`, x86_64), with `make gvisor`: 14 passed.
    - The listener variant's probe shows `MISSING seccomp user notification: seccomp(SECCOMP_GET_NOTIF_SIZES): Invalid argument`, and `sbx run` with it exits 125 at stage `capabilities`.
    - The sandbox's own command has `CapBnd a80405fb`, without `CAP_SYS_PTRACE`, as #18 measured.
    - `/proc/self/status` there has no `Seccomp_filters` line.
  - **Modal, VM** (Linux 7.3.4) with `--runtime vm`: 13 passed. The listener probe passes there too.
- **Deviations from the plan:**
  - `OnMatch::ret()` was dropped: `compile` maps to seccompiler's actions, and the tests use literals.
  - `make gvisor` creates the container without `--platform`. podman records the image as `linux/amd64/v8` (the arm64 build machine's variant), which a `--platform linux/amd64` lookup misses. The script's ELF check covers the architecture.
- **Not verified here:** the amd64 CI runner; `docker run --runtime=runsc`, which `tests/gvisor.py` supports but no make target runs.

## 2026-11-27: v0.6.1, SysV IPC and POSIX message queues in `seccomp.deny` (issue #20)

Plan: [plans/v0.6.1-sysv-ipc.md](plans/v0.6.1-sysv-ipc.md).

- **Filter (`src/seccomp_layer.rs`):** `SYS_shmget`, `SYS_semget`, `SYS_msgget` and `SYS_mq_open` joined `EXTRA_NAMES`, the list for both architectures. `lookup`, `syscall_name` and `build_table` read it already, so nothing else changed: a denial under the listener is logged and counted as `shmget` etc. They are not defaults.
- **Policies:** `policy/gvisor.example.toml` has a commented `deny = ["msgget", "mq_open", "semget", "shmget"]`, with the reason.
- **Version:** 0.6.1 (`Cargo.toml`, `Cargo.lock`).
- **Tests:**
  - property `denying_the_ipc_calls_changes_only_their_verdict`: for random policies (as in `any_policy()`), the filter compiled with the four added to `seccomp.deny` returns the policy's match verdict for each of their numbers with random arguments, under either `notify` and `on_violation`, and the same verdict as the filter without them on every other call from `any_calls()`.
  - the four joined `samples()`, so the existing property runs them too.
  - `names`: `lookup`, `is_default_denied` and `syscall_name` for each.
  - policy: `seccomp_deny_accepts_the_ipc_calls`, with the listener (no warnings) and with `notify = "off"` (only its warning).
  - smoke: a section "SysV IPC and POSIX message queues in seccomp.deny" with 3 checks. `shmget(IPC_PRIVATE, 4096, 0600)` through ctypes works under the base policy. With the four denied, it fails with `EPERM` and is counted in `denials` under the listener, and it kills with SIGSYS (159, `{"signaled": 31}`, `denials: null`) under off and kill.
  - `tests/gvisor.py`: the same call works under the example and kills with SIGSYS with the four denied (2 checks), and the platform facts say whether `/proc/sysvipc` exists and whether `/dev/mqueue` is mounted.
- **Verified** (arm64 Mac, podman machine, kernel 6.12.7):
  - `cargo fmt --check`
  - clippy `-D warnings` natively and for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, in `rust:1.97.0-slim-bookworm`
  - 112 unit tests pass
  - `make smoke` (delegated cgroup): 199 + 14 passed
  - `tests/gvisor.py` in the test image on runc: 15 passed (`/proc/sysvipc` present, `/dev/mqueue` mounted)
  - **Modal, gVisor** (`4.19.0-gvisor`, x86_64), with `make gvisor`: 16 passed. `/proc/sysvipc` is absent and `/dev/mqueue` is not mounted, so under gVisor on Modal `mq_open` belongs in the denial too, as #20 anticipated.
- **Deviations from the plan:**
  - The example's commented line and the README name `mq_open` as well, after the Modal run showed `/dev/mqueue` unmounted there; #20 proposed `["msgget", "semget", "shmget"]` pending that fact.
  - `tests/gvisor.py` is not in the test image; on runc it ran from stdin (`python3 -`).
- **Not verified here:** the amd64 CI runner.
