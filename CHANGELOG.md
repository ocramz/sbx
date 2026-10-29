# Changelog

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
