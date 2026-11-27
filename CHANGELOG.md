# Changelog

## v0.6.1

### Added

- **`seccomp.deny` may name `shmget`, `semget`, `msgget` and `mq_open`** (#20). These calls create SysV IPC objects and POSIX message queues, which outlive the program. Deny them where the runtime can neither list nor remove those objects between runs: gVisor has no `/proc/sysvipc`. They are not denied by default. A denial counts in the report under the call's name with the listener, and kills with SIGSYS under `notify = "off"`, `on_violation = "kill"`. `policy/gvisor.example.toml` shows the line, commented out. See [Without the listener](docs/platforms.md#without-the-listener).
NB this is a backward-compatible change.

### Changed

- **The README is an introduction:** what sbx is, an example, and setup recipes for typical scenarios. The reference moved to `docs/`, one file per topic: [how sbx works](docs/how-it-works.md), [configuration](docs/configuration.md), [egress](docs/egress.md), [the report](docs/report.md), [cgroup limits](docs/cgroup.md), [platforms](docs/platforms.md) and [development](docs/development.md). The text is unchanged.

## v0.6

**Breaking:** every policy now needs `seccomp.notify`. To keep v0.5's behaviour, add:

```toml
[seccomp]
notify = "listener"
```

sbx refuses a policy without it and says what to add. The shipped policies already have it.

### Added

- **A policy filter without the listener, for gVisor** (#18). gVisor has no seccomp user notification (`SECCOMP_FILTER_FLAG_NEW_LISTENER` fails with `EINVAL`), so sbx v0.5 could not start there. With `seccomp.notify = "off"`:
  - **The kernel applies the verdict:** a policy match fails with `EPERM` (`on_violation = "errno"`) or kills the process with SIGSYS (`"kill"`: exit 159, `"program": {"signaled": 31}`), without the supervisor. The prelude, the deny-list, the argument checks and every other layer are unchanged.
  - **What is lost:** sbx neither logs nor counts denials, so the report's `denials` is `null` (unknown, not none), and sbx warns at setup. `network.mode = "egress"`, whose `connect()` decisions go through the listener, is refused.
  - **`seccomp.deny` may include `sendmsg`,** which is reserved only to hand the listener over. `execve` stays reserved.
  - **`sbx probe`** runs the check `seccomp filter` instead of `seccomp user notification`: the prelude and a one-rule filter in a forked child, and the kernel's verdict on a match.
  - **`policy/gvisor.example.toml`:** Landlock off, `notify = "off"`, `on_violation = "kill"`, cgroup off, no network, sampling off. The image ships it as `/etc/sbx/gvisor.example.toml` and validates it during the build.
  - **`make gvisor`** builds a static linux/amd64 sbx and runs `tests/gvisor.py` in a Modal sandbox under gVisor, through the uv script `tests/modal_gvisor.py` (`--runtime vm` for a control).

  See [Without the listener](docs/platforms.md#without-the-listener).

### Changed

- **The report's `denials` can be `null`,** with `seccomp.notify = "off"`. It is still a list with the listener, and `[]` when the program never started.
- **sbx's seccomp summary line** names `notify`.

## v0.5

**Breaking:** every policy now needs a `[measure.series]` table. To keep v0.4's behaviour, add:

```toml
[measure.series]
mode = "off"
```

sbx refuses a policy without it and says what to add. The shipped policies already have it.

### Added

- **The memory time series.** With `[measure.series] mode = "on"`, `max_samples`, `max_processes`, `compression` and memory sampling on, `--series FILE` (or `SBX_SERIES_FILE`) writes every memory sample, with its time, to a root-owned JSON file next to the report. Each sample holds the largest process per kind, the tree's anonymous total, memfds, SysV segments, each tmpfs mount and, with a delegated cgroup, its `memory.stat` figures. `null` marks a failed read.
  - **Processes:** each sample also lists its `max_processes` largest processes (0 to 4096), by resident set, with their figures, and sums the rest into `others_*` columns, so that the two add up to the sample. A table `processes` gives each listed process's pid, start time and latest name. A process is its pid and start time, so a recycled pid is a new process.
  - **Compression:** `compression = "none"` or `"gzip"` is required with mode "on". With `"gzip"` the file is the gzip of the same JSON; tell the two apart by the first bytes (`1f 8b`), as sbx does not look at the file's name.
  - **Memory:** sbx holds each number as a varint of its difference from the sample before (zigzag, LEB128), so most take a byte or two. A listed process's figures are differences from the process at the same rank in the row before.
  - **Limits:** sbx keeps the first `max_samples` samples and the one taken right after the program exits, and counts the rest. A policy whose series could take more than 256 MiB of sbx's memory is refused; the worst case counts every listed process as new and every number as far from the one before. The log gives the series' size and that bound when sbx finishes.
  - **Setup and probe:** `--series` with the mode off is refused at the new setup stage `series`. `sbx probe --series FILE` checks the destination.
  - **The report:** it keeps its 12 keys. If the series cannot be written, sbx exits 125 and the report's `supervisor_error` says why.

  See [Time series](docs/report.md#time-series).

### Changed

- **Memory sampling reads each process through its `/proc/<pid>` directory,** held open and checked against the start time the sample found, so a pid the kernel recycles mid-sample is not measured as the process it replaced. `sbx probe`'s `sandbox /proc access` check reads its child the same way.

## v0.4.1

### Fixed

- **A sandboxed process could hide from sbx by giving itself a name that is not UTF-8** (`prctl(PR_SET_NAME)`, which the policy allows). sbx read `/proc/<pid>/stat` and `/proc/<pid>/status` as text and skipped any process whose file did not decode. The effects:
  - **It could outlive sbx.** When sbx was not PID 1 and had no delegated cgroup, a renamed process that had also left the sandbox's process group (`setsid`) was never killed when the program exited.
  - **It was missed elsewhere:** left out of memory sampling and of `killed_after_exit`, and not caught by the check under `landlock.abi = "off"` that no other process runs as the sandbox uid.
  - **Kill mode failed:** with `seccomp.on_violation = "kill"`, a call it made that the policy denies made sbx exit 125 instead of killing it.

  sbx now reads these files as bytes. A process whose files it cannot read is logged instead of being skipped silently. In log lines, the bytes of a name that are not UTF-8 appear as `\xNN`.
- **A stale report could survive a failed run.** The stale report is now removed before the log file is opened, so a bad `--log` path no longer leaves the previous run's report in place. As a result, an invalid `--report` path is now reported on stderr even with `--log`.

## v0.4

**Breaking:** every policy now needs a `[measure]` table. To keep v0.3's behaviour, add:

```toml
[measure]
memory_sample_ms = 0
tmpfs = []
```

sbx refuses a policy without it and says what to add. The shipped policies already have it.

### Added

- Memory by kind (#10). With `[measure] memory_sample_ms` above 0, sbx samples the sandbox's memory while the program runs and the report gets a `memory` key (`null` with sampling off): the largest process's anonymous, file-backed and shared resident memory, the tree's anonymous total, memfds (mapped or not), SysV segments (attached or not), the use of the tmpfs mounts listed in `[measure] tmpfs`, and, with a delegated cgroup, its `memory.stat` `anon` and `shmem`, plus how many processes exited before any sample saw them. Sampled peaks are lower bounds; `rusage.max_rss_kib` stays the exact single-process peak. Sampling needs `CAP_SYS_PTRACE`, which `sbx probe` and `sbx run` check. See [Memory by kind](docs/report.md#memory-by-kind).

## v0.3.1

### Added

- Images for `linux/arm64` as well as `linux/amd64`. `ghcr.io/ocramz/sbx:<tag>`, `:latest`, `:main` and `:<sha>` are multi-arch, and each architecture's image passed the integration suite on a native runner. The per-architecture images are `:<sha>-amd64` and `:<sha>-arm64`.

### Fixed

- `[cgroup] mode = "delegated"` no longer fails at stage `cgroup` with EBUSY, and no longer leaves `C/sbx-supervisor` behind, on kernels where an exiting task stays in its cgroup until its last context switch. sbx now retries enabling and disabling the controllers and removing its cgroups for up to 2 s while they are busy (#8).

## v0.3

**Breaking:** every policy now needs a `[cgroup]` table. To keep v0.2's behaviour, add:

```toml
[cgroup]
mode = "off"
```

sbx refuses a policy without it and says what to add. The shipped policies already have it.

### Added

- `--report FILE` / `SBX_REPORT_FILE`: `sbx run` writes how the run ended to a root-owned JSON file. The report holds the exit code or signal, whether it timed out, the setup stage that failed, denied syscalls, processes left behind, wall and CPU time, and peak memory. The file is written once the sandbox is gone, and only to a directory the sandbox cannot write. `sbx probe --report FILE` checks the destination. See [Job report and log file](docs/report.md#job-report-and-log-file).
- `--log FILE` / `SBX_LOG_FILE`: sbx's own log lines go to a file instead of the program's stderr.
- `[cgroup] mode = "delegated"` with `memory_mb` and `pids`: the sandbox runs in a cgroup of its own with `memory.max` and `pids.max`. An OOM kill then hits the program, not sbx, and the report records it. This needs a delegated cgroup v2, e.g. podman `--systemd=always`. See [cgroup limits](docs/cgroup.md).
- `sbx version` prints the release tag.

### Changed

- The signals sbx handles are blocked from the start of `sbx run`. A SIGTERM during setup no longer stops sbx half-way: sbx exits before starting the program.
- Control characters in process and DNS names are escaped in sbx's log lines, so the sandbox cannot forge a line.
