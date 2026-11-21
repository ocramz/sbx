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
