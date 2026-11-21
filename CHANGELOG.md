# Changelog

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
