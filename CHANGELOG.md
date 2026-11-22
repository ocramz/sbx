# Changelog

## Unreleased

**Breaking:** every policy now needs a `[measure.series]` table. To keep v0.4's behaviour, add:

```toml
[measure.series]
mode = "off"
```

sbx refuses a policy without it and says what to add. The shipped policies already have it.

### Added

- **The memory time series.** With `[measure.series] mode = "on"`, `max_samples`, `max_processes` and memory sampling on, `--series FILE` (or `SBX_SERIES_FILE`) writes every memory sample, with its time, to a root-owned JSON file next to the report. Each sample holds the largest process per kind, the tree's anonymous total, memfds, SysV segments, each tmpfs mount and, with a delegated cgroup, its `memory.stat` figures. `null` marks a failed read.
  - **Processes:** each sample also lists its `max_processes` largest processes (0 to 4096), by resident set, with their figures, and sums the rest into `others_*` columns, so that the two add up to the sample. A table `processes` gives each listed process's pid, start time and latest name. A process is its pid and start time, so a recycled pid is a new process.
  - **Limits:** sbx keeps the first `max_samples` samples and the one taken right after the program exits, and counts the rest. A policy whose series could take more than 256 MiB of sbx's memory is refused; the worst case counts every listed process as new. The log gives the series' size and that bound when sbx finishes.
  - **Setup and probe:** `--series` with the mode off is refused at the new setup stage `series`. `sbx probe --series FILE` checks the destination.
  - **The report:** it keeps its 12 keys. If the series cannot be written, sbx exits 125 and the report's `supervisor_error` says why.

  See the README, [Time series](README.md#time-series).

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

- Memory by kind (#10). With `[measure] memory_sample_ms` above 0, sbx samples the sandbox's memory while the program runs and the report gets a `memory` key (`null` with sampling off): the largest process's anonymous, file-backed and shared resident memory, the tree's anonymous total, memfds (mapped or not), SysV segments (attached or not), the use of the tmpfs mounts listed in `[measure] tmpfs`, and, with a delegated cgroup, its `memory.stat` `anon` and `shmem`, plus how many processes exited before any sample saw them. Sampled peaks are lower bounds; `rusage.max_rss_kib` stays the exact single-process peak. Sampling needs `CAP_SYS_PTRACE`, which `sbx probe` and `sbx run` check. See the README, [Memory by kind](README.md#memory-by-kind).

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

- `--report FILE` / `SBX_REPORT_FILE`: `sbx run` writes how the run ended to a root-owned JSON file. The report holds the exit code or signal, whether it timed out, the setup stage that failed, denied syscalls, processes left behind, wall and CPU time, and peak memory. The file is written once the sandbox is gone, and only to a directory the sandbox cannot write. `sbx probe --report FILE` checks the destination. See the README, [Job report and log file](README.md#job-report-and-log-file).
- `--log FILE` / `SBX_LOG_FILE`: sbx's own log lines go to a file instead of the program's stderr.
- `[cgroup] mode = "delegated"` with `memory_mb` and `pids`: the sandbox runs in a cgroup of its own with `memory.max` and `pids.max`. An OOM kill then hits the program, not sbx, and the report records it. This needs a delegated cgroup v2, e.g. podman `--systemd=always`. See the README, [cgroup limits](README.md#cgroup-limits).
- `sbx version` prints the release tag.

### Changed

- The signals sbx handles are blocked from the start of `sbx run`. A SIGTERM during setup no longer stops sbx half-way: sbx exits before starting the program.
- Control characters in process and DNS names are escaped in sbx's log lines, so the sandbox cannot forge a line.
