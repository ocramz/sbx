# Report, log and memory measurements

## Job report and log file

`--report FILE` (or `SBX_REPORT_FILE`) makes `sbx run` write how the run ended as JSON. The file is written once, after the sandbox is gone and the cgroup and `/etc/resolv.conf` are restored, by atomically replacing the path, so it is either complete or absent. Every outcome after sbx has opened the report's directory produces a report: policy errors, missing capabilities, setup failures in the child, and runs of the program. Errors before that, in the flags, the `SBX_*` variables or the report path itself, go to stderr only. When sbx starts, it removes any file at the path, so a missing report means sbx failed early or was killed with SIGKILL. Every key is always present:

```json
{
  "sbx_version": "v0.4",
  "exit_code": 137,
  "program": {"signaled": 9},
  "timed_out": false,
  "setup_error": null,
  "supervisor_error": null,
  "denials": [{"syscall": "ptrace", "count": 2}],
  "killed_after_exit": 1,
  "wall_ms": 1520,
  "rusage": {"user_ms": 310, "sys_ms": 42, "max_rss_kib": 51200},
  "cgroup": {"memory_mb": 512, "pids": 256, "memory_peak_kib": 60112, "oom_kills": 1,
             "pids_max_hits": 0, "user_ms": 318, "sys_ms": 45},
  "memory": {"interval_ms": 20, "samples": 74, "max_anon_kib": 40960, "max_file_kib": 9216,
             "max_shmem_kib": 16384, "tree_peak_anon_kib": 45056, "memfd_peak_kib": 49152,
             "sysv_shm_peak_kib": 4096, "tmpfs_peak_kib": {"/dev/shm": 8192},
             "cgroup": {"peak_anon_kib": 44100, "peak_shmem_kib": 61440}, "unsampled_processes": 0}
}
```

| Key | Meaning |
|---|---|
| `exit_code` | sbx's own exit code, as documented under [Exit codes](configuration.md#exit-codes) |
| `program` | `{"exited": N}` or `{"signaled": N}` for the program's own process; `null` if it never started |
| `timed_out` | the wall-clock limit killed the sandbox (exit 124) |
| `setup_error` | `{"stage", "messages"}` when the program never started. Stages, in order: `policy`, `report`, `log`, `series`, `env`, `program`, `capabilities`, `slot`, `stdio`, `dns`, `cgroup`, `landlock`, `seccomp`, `launch`; then in the child `cgroup`, `setsid`, `chdir`, `setrlimit`, `identity`, `pdeathsig`, `no_new_privs`, `landlock`, `seccomp`, `close_range`, `signals`, `execve` (exit 127); then `listener` and `services` back in the supervisor |
| `supervisor_error` | why sbx tore a running sandbox down (exit 125), e.g. a failed notification thread or log file |
| `denials` | syscalls sbx's policy filter denied, per name (egress denials count as `connect`). Not counted: the prelude's `ENOSYS` (`clone3`, x32), Landlock's refusals, calls the container runtime's own seccomp profile refuses, and DNS names the proxy refuses. `null` with `seccomp.notify = "off"`, where nothing sees the denials: unknown, not none ([Without the listener](platforms.md#without-the-listener)) |
| `killed_after_exit` | processes still running when the program exited, which sbx then killed; `null` when sbx had already killed the tree (timeout, a second SIGTERM or the grace period, a fatal error) |
| `wall_ms` | from `execve` until the program's process was reaped |
| `rusage` | CPU time of every process sbx reaped, each including the descendants it waited for itself, and the largest resident set of any single process. Children of a process that ignores SIGCHLD are reaped by the kernel and not counted |
| `cgroup` | with `mode = "delegated"`: the limits, the peak memory of the whole sandbox (page cache and tmpfs files included), OOM kills, forks refused by `pids.max`, and the cgroup's CPU time; otherwise `null` |
| `memory` | with `[measure]` sampling on: the sandbox's memory by kind, sampled ([Memory by kind](#memory-by-kind)); otherwise, and when the program never started, `null` |

The report is trusted because the program cannot have touched it. Every directory from `/` down to the report's own must belong to root (or sbx's uid) and be writable by nobody else. A sticky directory such as `/tmp` is allowed above it, but not as the report's own directory. The directory must be canonical. sbx opens it when it starts, creates the file through that descriptor with `O_NOFOLLOW`, and gives it mode 0600. A symlink left at the path is replaced, not followed. If sbx is not root, the program runs as sbx's own uid, so the directory must also lie outside every fs rule (and Landlock must be on). `sbx probe --report FILE` checks the destination without touching the file there.

`--log FILE` (or `SBX_LOG_FILE`) sends sbx's own lines to FILE instead of stderr, so the program's stderr holds only what the program wrote. The same path rules apply. The file is appended to and created 0600 if missing; an existing one must be a regular file of sbx's uid that nobody else can access. Lines are written as they happen. Process names and DNS names in them have control characters escaped (and the bytes of a process name that are not UTF-8 written as `\xNN`), so the sandbox cannot forge a line. If a write fails, sbx prints the line and the error on stderr and tears the sandbox down (exit 125). Errors before the file is open still go to stderr.

## Memory by kind

`rusage.max_rss_kib` (`ru_maxrss`) is the exact peak resident set of the largest process, but as a measure of what a program costs it is off both ways: it counts the file pages of the binary and its libraries, and misses memory that no process maps, such as an unmapped memfd, a tmpfs or `/dev/shm` file, or a detached SysV segment. `[measure]`, required in every policy, makes sbx sample the sandbox's memory by kind while the program runs:

```toml
[measure]
memory_sample_ms = 20      # 0 = off (the shipped policies); at most 60000
tmpfs = ["/dev/shm"]       # tmpfs mount points to measure; only with sampling on
```

Every `memory_sample_ms`, and once more right after the program's process exits (so what it leaves behind counts), the supervisor reads:

* for each live sandbox process (the descendants of sbx, or every other process when sbx is PID 1): `RssAnon`, `RssFile` and `RssShmem` from `/proc/<pid>/status`, and the memfds among its descriptors in `/proc/<pid>/fd`, sized by their allocated blocks, each counted once however many descriptors and processes hold it;
* the SysV shared memory segments of the sandbox (owned or created by its uid, or created by one of its processes) from `/proc/sysvipc/shm`, by their resident size, attached or not;
* for each `tmpfs` mount, its use (`statvfs`) above the level it had when sbx started;
* with `[cgroup] mode = "delegated"`, the sandbox cgroup's `memory.stat` `anon` and `shmem` (which counts memfd, tmpfs and SysV pages by itself).

The report's `memory` holds `interval_ms`, `samples` and the peaks over all samples, in KiB:

| Key | Peak of |
|---|---|
| `max_anon_kib`, `max_file_kib`, `max_shmem_kib` | the largest single process, per kind, as `max_rss_kib` is |
| `tree_peak_anon_kib` | the sum of `RssAnon` over the sandbox's processes in one sample; copy-on-write pages shared after `fork` count once in each process |
| `memfd_peak_kib` | the memfds open in the sandbox |
| `sysv_shm_peak_kib` | the sandbox's SysV segments |
| `tmpfs_peak_kib` | per listed mount, its use above the level at start |
| `cgroup` | `{"peak_anon_kib", "peak_shmem_kib"}` from `memory.stat` with a delegated cgroup; otherwise `null` |
| `unsampled_processes` | processes sbx reaped (the program and orphans reparented to sbx) that no sample saw. A process reaped by its own parent is never seen by sbx and not counted here; its peak is still in `rusage.max_rss_kib` |

Sampled peaks are lower bounds: what rises and falls between two samples is missed, so a shorter interval catches more at the cost of supervisor time. `rusage.max_rss_kib` stays the exact single-process total. A failed read (other than of a process that exited meanwhile) is logged once per kind and sampling goes on.

Each process is read through its `/proc/<pid>` directory, held open while its `stat`, `status` and `fd` are read, and only if its start time is still the one the sample found when it listed `/proc`. An open `/proc/<pid>` directory belongs to one process, so if that process exits and the kernel gives its pid to another, the reads fail instead of measuring the newcomer.

Sampling needs `CAP_SYS_PTRACE`: listing the descriptors of a process of another uid needs it, and without it the sandbox could hide its memfds with `prctl(PR_SET_DUMPABLE, 0)`. sbx refuses to start without it, and `sbx probe` checks that it can read the status and descriptors of a non-dumpable child running as the sandbox uid. On Cloud Run, where no cgroup is delegated, the `/proc` figures are the whole measurement.

## Time series

The report keeps only the peaks. To get every sample, with its time, turn the series on and name a file with `--series FILE` (or `SBX_SERIES_FILE`). `[measure.series]` is required in every policy:

```toml
[measure.series]
mode = "off"              # the shipped policies; "off" takes no other field
# or
mode = "on"               # needs [measure] memory_sample_ms above 0
max_samples = 50000       # 1 to 1000000
max_processes = 32        # 0 to 4096: the largest processes each sample lists; 0 lists none
compression = "none"      # or "gzip": the file is then the gzip of the same JSON
```

The policy says how a series is made, and the flag says where it goes. sbx refuses `--series` when the mode is `"off"` (setup stage `series`), and with `"on"` but no `--series` it keeps nothing. sbx keeps the first `max_samples` samples taken while the program runs, then only counts the others. It always keeps the sample taken right after the program's process was reaped. Every number is held in memory until the program ends, as a varint of its difference from the one in the sample before; for a listed process, from the process at the same rank in the row before. Memory figures change slowly, so most numbers take a byte or two. sbx refuses a policy whose series could take more than 256 MiB of its memory in the worst case, and the error names the figure. In that worst case every number is far from the one before: a kept sample takes 130 bytes, plus 10 per measured tmpfs mount. Each process a sample lists takes 35 bytes more, and one listed for the first time about 110 more for the process table. sbx counts the worst case, in which every listed process is new. So with `/dev/shm` measured, 1000000 samples take at most about 134 MiB with `max_processes = 0`, and 50000 samples with `max_processes = 32` about 229 MiB. When sbx finishes, it logs the series' size and this bound, as `memory series: N rows, D samples dropped, P processes listed, K KiB in memory (at most B KiB)`.

The file is written only when the program ran, after the sandbox is gone and before the report. The same path rules as for the report apply, and it may not be the report's or the log's path. When sbx starts, it removes any file at the path, so after a setup failure there is no series file and the report has the error. If writing it fails, sbx exits 125, and the report's `supervisor_error` says why. `sbx probe --series FILE` checks the destination.

The file is one line of JSON, mode 0600, replaced atomically. With `compression = "gzip"` it is the gzip of that line instead (`gzip -dc FILE` gives the line back). sbx does not look at the file's name; a gzip file starts with the bytes `1f 8b`, and the JSON with `{`:

```json
{"sbx_version": "v0.5",
 "memory": {"interval_ms": 20, "max_samples": 50000, "max_processes": 1, "samples": 3, "dropped": 0,
   "rows": {"t_us": [20113, 40391, 52007], "live_processes": [1, 2, 0],
            "max_anon_kib": [32768, 65872, 0], "max_file_kib": [9216, 9216, 0],
            "max_shmem_kib": [0, 16384, 0], "tree_anon_kib": [32768, 98640, 0],
            "memfd_kib": [0, 49152, 0], "sysv_shm_kib": [0, null, 0],
            "tmpfs_kib": {"/dev/shm": [0, 8192, 8192]},
            "cgroup_anon_kib": null, "cgroup_shmem_kib": null,
            "others_processes": [0, 1, 0], "others_anon_kib": [0, 32768, 0],
            "others_file_kib": [0, 9216, 0], "others_shmem_kib": [0, 0, 0]},
   "processes": {"pid": [7, 9], "start_ticks": [415310, 415312], "name": ["python3", "worker"]},
   "process_rows": {"row": [0, 1], "process": [0, 1], "anon_kib": [32768, 65872],
                    "file_kib": [9216, 9216], "shmem_kib": [0, 16384]}}}
```

| Key | Meaning |
|---|---|
| `samples`, `dropped` | how many samples were taken, and how many were not kept (taken after the `max_samples`th, before the final one); `samples` equals the report's `memory.samples` |
| `rows` | one array per column, with entry i of each from sample i, in the order taken. The last is the sample taken right after the program's process was reaped |
| `t_us` | microseconds since the program started, the origin of the report's `wall_ms` |
| `live_processes` | the sandbox processes the sample read |
| `max_anon_kib`, `max_file_kib`, `max_shmem_kib` | the largest single process in the sample, per kind |
| `tree_anon_kib`, `memfd_kib`, `sysv_shm_kib`, `tmpfs_kib`, `cgroup_anon_kib`, `cgroup_shmem_kib` | the sample's figures behind the report's peaks of the same names ([Memory by kind](#memory-by-kind)) |
| `others_processes`, `others_anon_kib`, `others_file_kib`, `others_shmem_kib` | the sample's processes that its row does not list: how many, and their `RssAnon`, `RssFile` and `RssShmem` summed |
| `processes` | each listed process once, in the order first listed: its `pid`, its `start_ticks` (clock ticks since boot, field 22 of `/proc/<pid>/stat`) and its `name` |
| `process_rows` | one entry per listed process per row: `row` indexes `rows` and `process` indexes `processes`; `anon_kib`, `file_kib`, `shmem_kib` are its figures in that sample |

Each row lists the sample's `max_processes` largest processes by `RssAnon + RssFile + RssShmem`, ties broken by the smaller pid, then start time. `process_rows` is ordered by row, then by that rank, so a row's first entry is its largest process. The listed figures and the `others_*` add up exactly to the sample: the listed `anon_kib` plus `others_anon_kib` is `tree_anon_kib`, and the listed processes plus `others_processes` is `live_processes`. A process is its pid and start time, so a pid the kernel gives to a new process is a new entry in `processes`. Its `name` is the one it had when last listed (`exec` changes it), at most 16 bytes, escaped as log lines are (control characters and bytes that are not UTF-8 spelled out as `\n`, `\xff`). With `max_processes = 0`, `processes`, `process_rows` and the `others_*` columns are `null`.

`null` in a column marks a failed read in that sample: of `/proc/sysvipc/shm`, of one tmpfs mount, or of `memory.stat`. Without a delegated cgroup, the cgroup columns are `null` as a whole. Whenever `dropped` is 0, each column's maximum equals the report's figure. Otherwise it is no higher. Time series of other measurements will get their own keys next to `memory`.
