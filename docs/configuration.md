# Configuration

## Policy file

The policy file is required (`--policy` or `SBX_POLICY_FILE`; the image sets `SBX_POLICY_FILE=/etc/sbx/policy.toml`). Every field must be present and unknown fields are rejected. [`policy/default.toml`](../policy/default.toml) is the shipped policy (no network). [`policy/egress.example.toml`](../policy/egress.example.toml) shows egress rules and the DNS proxy, [`policy/no-landlock.example.toml`](../policy/no-landlock.example.toml) is the same for kernels without Landlock, and [`policy/gvisor.example.toml`](../policy/gvisor.example.toml) is for gVisor ([Without the listener](platforms.md#without-the-listener)). All four are validated against the image during the build.

## Upgrading

**Upgrading from v0.5:** add `notify = "listener"` to `[seccomp]` to keep v0.5's behaviour; sbx v0.6 refuses a policy without it and says so. **From v0.4,** also add `[measure.series]` with `mode = "off"`. **From v0.3,** also add `[measure]` with `memory_sample_ms = 0` and `tmpfs = []`. **From v0.2,** also add `[cgroup]` with `mode = "off"`.

## Flags and environment variables

Environment variables and flags extend the policy (path grants and egress rules are added) or replace a few scalars (flags win over the environment):

| Flag | Env var | Meaning |
|---|---|---|
| `--policy FILE` | `SBX_POLICY_FILE` | policy file (mount it from Secret Manager to change it without rebuilding) |
| `--ro / --rw / --rx PATHS` | `SBX_FS_RO / _RW / _RX` | grant paths, `:`-separated, repeatable |
| `--net MODE` | `SBX_NET` | `none`, `egress` or `unrestricted` |
| `--egress RULE` | `SBX_EGRESS` | add an egress rule: `api.github.com:443`, `*.example.com:443`, `10.0.0.0/8:5432+6432`, `[2001:db8::/32]:443` (env: comma-separated) |
| `--timeout SECS\|none` | `SBX_TIMEOUT` | wall-clock limit for the whole tree, exit 124 |
| `--workdir DIR` | `SBX_WORKDIR` | working directory (must be readable in the sandbox) |
| `--no-subprocesses` | `SBX_SUBPROCESSES=false` | threads only |
| `--env-pass NAMES` | `SBX_ENV_PASS` | pass these variables through (each must be set) |
| `--seccomp-action A` | `SBX_SECCOMP_ACTION` | `errno` or `kill` |
| `--quiet` | `SBX_QUIET=true` | hide info lines (warnings and errors are always printed) |
| `--report FILE` | `SBX_REPORT_FILE` | write the outcome as JSON ([Job report and log file](report.md#job-report-and-log-file)) |
| `--log FILE` | `SBX_LOG_FILE` | append sbx's own lines to FILE instead of stderr |
| `--series FILE` | `SBX_SERIES_FILE` | write every memory sample as JSON, gzipped with `compression = "gzip"`; needs `[measure.series] mode = "on"` ([Time series](report.md#time-series)) |

Booleans are `true`/`false`. An empty `SBX_*` value, a flag given twice, a missing `--` before the program, and **any `SBX_*` variable sbx does not know** are errors, so a typo cannot silently leave a setting at its file value. Keep other software's variables out of the `SBX_` prefix in sbx's environment.

## Commands

`sbx policy [flags]` validates and prints the effective policy. `sbx probe [flags]` checks every requirement of that policy on this kernel and container, and exits 1 if one is missing. These are operator inputs: never build sbx flags from the untrusted payload; pass payload data only as arguments after `--`.

`sbx version` prints the `git describe` of the commit sbx was built from: the tag, such as `v0.4`, for a release.

## Exit codes

Exit codes: the program's own, 124 on timeout, 125 for sbx errors (bad policy, missing capability, internal failure), 127 if the program cannot be executed, 128+N if it was killed by signal N.

## Kernel and container requirements

* Landlock ABI ≥ `landlock.abi` (the default policy pins 6: Linux 6.12). `none` and `egress` modes need ABI 4+ (Linux 6.7). With `landlock.abi = "off"`, no Landlock at all ([Without Landlock](platforms.md#without-landlock)).
* With `seccomp.notify = "listener"`: seccomp user notification with `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (Linux 5.19), and no other seccomp listener already installed in the container (`sbx probe` runs a full round trip). With `"off"`: seccomp filters with `SECCOMP_RET_KILL_PROCESS` (Linux 4.14), which gVisor has ([Without the listener](platforms.md#without-the-listener)).
* `close_range` (5.9) and `pidfd_open`/`pidfd_getfd` (5.6).
* Root with `CAP_SETPCAP` (for the bounding set) and `CAP_SETUID`/`CAP_SETGID`, which Docker grants by default. A non-root sbx runs the program at its own uid, which must equal the policy's, with no supplementary groups; the sandbox is then separated from the supervisor by Landlock scoping only, so use ABI 6+. With `landlock.abi = "off"`, non-root is refused ([Without Landlock](platforms.md#without-landlock)).
* Egress: Linux 6.9+ (`PIDFD_THREAD`), `CAP_SYS_PTRACE`, Yama `ptrace_scope` < 3, and port 53 on the loopback listen address.
* `cgroup.mode = "delegated"`: Linux 5.19+ (`memory.peak`, `cgroup.kill`), root, and a delegated cgroup v2 ([cgroup limits](cgroup.md)).
* `[measure]` sampling: Linux 4.5+ (`RssAnon` in `/proc/<pid>/status`), `CAP_SYS_PTRACE`, and `/proc/sysvipc/shm` ([Memory by kind](report.md#memory-by-kind)).
