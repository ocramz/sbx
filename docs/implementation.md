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
