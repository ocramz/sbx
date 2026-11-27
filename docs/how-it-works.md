# How sbx works

`sbx` is a small (about 1.2 MB, static) Rust launcher that becomes the container's PID 1, builds a sandbox from an operator-supplied policy, and runs the untrusted program inside it. It uses unprivileged kernel APIs only (Landlock, seccomp-BPF with user notification where the kernel has it, `no_new_privs`, rlimits): no `--privileged`, no `CAP_SYS_ADMIN`, no user namespaces.

sbx is strict by design. Every protection the policy asks for must be enforceable on the running kernel and container, or sbx refuses to start and says why. It has no built-in defaults, no best-effort mode and no fallbacks, and every failure is logged with the operation, the object, the OS error and, where possible, a hint. Landlock can only be turned off explicitly, in the policy file ([Without Landlock](platforms.md#without-landlock)).

sbx runs one sandbox at a time, one per container.

## Requirements → mechanism

| Requirement | How it is met |
|---|---|
| Runs on serverless platforms | Unprivileged syscalls only; static binary drops into any base image; PID 1 duties (signal forwarding, zombie reaping, SIGTERM grace period) |
| seccomp | A prelude filter (architecture, x32, `clone3`) plus a policy filter whose matches are sent to the supervisor through a seccomp user-notification listener, so every denial is logged; or, where there is no listener (gVisor), a policy filter whose verdict the kernel applies itself ([Without the listener](platforms.md#without-the-listener)) |
| Landlock | Path rules (read/write/execute), TCP bind/connect handling (ABI v4+), signal and abstract-socket scoping (ABI v6+), for exactly the ABI the policy pins; or explicitly off, with the compensations in [Without Landlock](platforms.md#without-landlock) |
| Fine-grained egress | `network.mode = "egress"`: every `connect()` is decided by the supervisor against CIDR and domain rules and carried out by the supervisor itself (TOCTOU-safe); a DNS proxy enforces domain rules |
| Subprocesses inherit | Landlock domains, seccomp filters, `no_new_privs`, rlimits and the identity switch are inherited across `fork`/`execve` and cannot be removed |
| Volumes | Platform mounts happen before the entrypoint, so sbx opens the mount points and binds rules to them |
| Configurable at start | A complete policy file, plus `SBX_*` variables and flags for per-run additions |
| Fail loudly | Requirements are probed before anything starts; unknown or empty settings, symlinked or missing paths, and unsupported ABIs are errors |
| Trustworthy outcome | `--report FILE`: a root-owned JSON report of how the run ended (exit code or signal, timeout, the setup stage that failed, denied syscalls, leftover processes, wall and CPU time, memory); `--log FILE` keeps sbx's own lines off the program's stderr ([Job report and log file](report.md#job-report-and-log-file)); `--series FILE` keeps every memory sample, with the largest processes of each, as JSON or gzipped JSON ([Time series](report.md#time-series)) |
| Memory by kind | `[measure] memory_sample_ms`: sbx samples the sandbox's anonymous, file-backed and shared memory per process, its memfds, SysV segments and tmpfs files, and reports the peaks, since `ru_maxrss` counts library pages and misses memory no process maps ([Memory by kind](report.md#memory-by-kind)) |
| Memory and process limits | `[cgroup] mode = "delegated"`: the sandbox runs in a cgroup of its own with `memory.max` and `pids.max`, so an OOM kill hits the program, not sbx, and is reported ([cgroup limits](cgroup.md)) |

## Architecture

```
container start
  sbx run [flags] -- PROGRAM ARGS        (PID 1, root, unsandboxed, never runs payload code)
   │ 0. open the log file and the report's directory; block the signals sbx handles
   │ 1. resolve policy: file + SBX_* env + flags; validate everything, report every error
   │ 2. check requirements (Landlock ABI, seccomp listener round trip or, without the
   │    listener, a filter's verdict; close_range, identity, no other sandbox; egress:
   │    CAP_SYS_PTRACE, pidfd_getfd, DNS listener,
   │    resolv.conf; memory sampling: CAP_SYS_PTRACE, /proc access), then claim the
   │    container's sandbox slot
   │ 3. delegated cgroup: create the sandbox cgroup; open allowed paths, build the
   │    Landlock ruleset, compile the BPF filters
   │ 4. fork
   ├─ child ─ [join the sandbox cgroup] → setsid → chdir → rlimits → empty capability bounding set
   │          → setgroups/setresgid/setresuid(65534) → clear all capabilities (verified)
   │          → PDEATHSIG → NO_NEW_PRIVS → landlock_restrict_self
   │          → seccomp(prelude) → seccomp(policy, NEW_LISTENER | WAIT_KILLABLE_RECV)
   │          → hand the listener to the parent (SCM_RIGHTS)
   │            [seccomp.notify = "off": seccomp(policy), no listener]
   │          → close inherited fds
   │          → reset every signal disposition and the mask → execve(PROGRAM, scrubbed env)
   └─ parent ─ notification thread (with the listener): log/deny policy matches,
               decide connect() (egress)
               DNS proxy threads (egress with domain rules)
               main loop: forward SIGTERM/INT/HUP/QUIT/USR1/USR2, enforce the timeout
               (exit 124), sample memory by kind, reap, kill everything left on exit,
               propagate the exit code
               teardown: restore the cgroup and resolv.conf, write the report
```

The sandbox slot is an abstract UNIX socket (`@sbx/sandbox`) that `sbx run` binds and holds until it exits. A second `sbx run` while one is running exits 125 ("another sbx sandbox is running"), and `sbx probe` reports it. Abstract sockets are per network namespace, so the slot covers the container on Cloud Run, the whole pod on Kubernetes, and the whole host with `docker run --network host`.

Fallible work happens before `fork`, so a bad policy produces a clear error instead of a half-built sandbox. The signals sbx handles are blocked before it changes anything, so a SIGTERM during setup cannot leave resolv.conf or the cgroup half-changed: sbx notices it before `fork` and stops. Setup failures in the child, including `execve` being denied by Landlock, are reported back over a close-on-exec pipe. If the notification thread or the DNS proxy fails, the supervisor tears the sandbox down and exits 125. If the supervisor itself dies, the listener closes and every pending or future notified syscall fails with `ENOSYS`, so the sandbox fails closed. Without the listener, the kernel applies every verdict itself, so none of them depends on the supervisor.

## The layers

**Landlock (filesystem, TCP, IPC scoping).** `landlock.abi` pins the ABI whose access rights are handled: the kernel must support at least that version (sbx stops otherwise), and when the kernel is newer sbx warns that rights added after the pinned ABI are not restricted. `landlock.abi = "off"` runs without Landlock ([Without Landlock](platforms.md#without-landlock)). Policy letters map to rights: `r` = read file + read dir; `w` = write, truncate, create (files, dirs, symlinks, fifos, sockets), remove, rename/link (`refer`), device ioctl, pathname-socket connect; `x` = execute. Creating device nodes is never granted. Rule paths must exist and be canonical (a symlink is an error that names its target). In `none` and `egress` modes TCP bind and connect are handled with no connect rules at all, so any connect made from inside the sandbox fails. `scope_signals` / `scope_abstract_unix` (ABI v6+) stop the sandbox from signalling, or connecting to abstract UNIX sockets of, anything outside its domain; Landlock's ptrace check also blocks reading `/proc/<supervisor>/environ` at the same uid.

**seccomp (kernel attack surface).** The payload is an arbitrary program, so the filter is a deny-list of syscalls that let code escape or attack the kernel: ptrace and cross-process memory/fd access, mount and namespace syscalls, `bpf`, `perf_event_open`, `userfaultfd`, io_uring, keyrings, handle-based opens, module loading, kexec, clock setting and similar. Argument checks deny `clone` with any `CLONE_NEW*` flag, restrict `socket`/`socketpair` to `seccomp.socket_families`, block `TIOCSTI`/`TIOCLINUX` and limit `personality`. `seccomp.deny` adds syscalls from a fixed list of names (`seccomp.allow` lifts a built-in denial). Among them are `shmget`, `semget`, `msgget` and `mq_open`, the only calls on x86-64 and aarch64 that create SysV IPC objects or POSIX message queues (neither has i386's `ipc(2)` multiplexer). Those objects outlive the program, so deny them where the runtime can neither list nor remove them between runs: gVisor has no `/proc/sysvipc` ([Without the listener](platforms.md#without-the-listener)). The prelude kills on a foreign architecture, returns `ENOSYS` for the x32 ABI and for `clone3` (whose flags BPF cannot see; libc falls back to `clone`). With `seccomp.notify = "listener"`, every policy match is delivered to the supervisor, which logs it once per program, syscall and reason (repeats are summarised at exit) and then fails the call with `EPERM` (`on_violation = "errno"`) or kills the process with SIGKILL before the call runs (`"kill"`). With `"off"`, the kernel applies the verdict itself, `EPERM` or SIGSYS, and nothing is logged ([Without the listener](platforms.md#without-the-listener)). A call that the container runtime's own seccomp profile already refuses never reaches sbx's filter (the kernel applies the most restrictive verdict), so it is denied but not logged by sbx.

**Process hygiene.** Started as root (the image default), sbx empties the capability bounding set, drops supplementary groups, switches to `65534:65534` and verifies that every capability set is empty. The environment is rebuilt from the policy (`env.pass` names must be set). Inherited file descriptors are closed with `close_range`. Every signal starts at its default disposition with an empty mask (sbx itself is a Rust program, which ignores SIGPIPE). Core dumps are disabled and rlimits cap open files, processes, file size, address space and CPU time (`"unlimited"` must be written explicitly).

## Threat model and limitations

The sandbox assumes a hostile payload and a correct kernel. It narrows what the payload can reach (files, sockets, destinations, other processes, dangerous syscalls). The payload still shares the kernel with the supervisor, so a kernel exploit through an allowed syscall defeats it. On Cloud Run the gen2 microVM is the outer boundary.

* **Metadata server.** `169.254.169.254` hands out the service account's token to anything that can make an HTTP request. `unrestricted` mode and any CIDR rule covering it expose it (sbx warns), DNS answers can never add it, and the job should run with a service account that has no roles beyond what its volumes need.
* **Egress is IP-level.** A domain rule allows the addresses that name resolved to, for that rule's ports, until sbx exits. Other sites on the same addresses (CDNs, shared load balancers) are reachable too. Wildcard rules let the payload send arbitrary query names to that domain's authoritative servers (a DNS exfiltration channel).
* **TCP only.** UDP (and QUIC) cannot leave the sandbox in egress mode. Programs whose resolver cannot use TCP (musl) need IP rules.
* **One sandbox per container.** A second `sbx run` in the same network namespace exits 125 ([Architecture](#architecture)). The DNS proxy also binds `network.dns.listen` exclusively, and `/etc/resolv.conf` is shared by the container: while an egress sandbox runs, the rest of the container also resolves names through the sbx proxy. sbx restores the file when it exits, unless someone else changed it meanwhile (sbx then warns and leaves it), or sbx is killed with SIGKILL.
* **UNIX sockets.** Below Landlock ABI 9, connecting to pathname UNIX sockets is restricted only by file permissions. A service outside the sandbox that listens on one could hand the sandbox an unfiltered socket, so do not expose such sockets to the sandbox's uid.
* **`x` is hygiene.** Landlock's `x` controls `execve`, not code loading: the payload can still run code through an allowed interpreter or by invoking `ld.so` on a file it wrote. To stop fileless execution, add `seccomp.deny = ["memfd_create", "execveat"]`.
* **Memory** is bounded only by the container limit unless the platform delegates a cgroup ([cgroup limits](cgroup.md)); without one, a payload that exhausts it takes down the instance, supervisor included, and no report is written. Keep service concurrency at 1 for untrusted work. `limits.as_mb` is available but breaks Go, the JVM and V8. Memory sampling ([Memory by kind](report.md#memory-by-kind)) measures; it does not limit.

Cloud Run also has a native **sandboxes** feature (public preview since July 2026) that runs code in a separate isolated environment inside a service instance, without access to the service's environment variables or the metadata server. If you only target Cloud Run, consider it as the outer layer with sbx inside, or instead of sbx.
