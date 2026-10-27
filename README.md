# sbx: a seccomp + Landlock sandbox image for serverless containers

`sbx` is a small (about 1.2 MB, static) Rust launcher that becomes the container's PID 1, builds a sandbox from an operator-supplied policy, and runs the untrusted program inside it. It uses unprivileged kernel APIs only (Landlock, seccomp-BPF with user notification, `no_new_privs`, rlimits): no `--privileged`, no `CAP_SYS_ADMIN`, no user namespaces.

sbx is strict by design. Every protection the policy asks for must be enforceable on the running kernel and container, or sbx refuses to start and says why. It has no built-in defaults, no best-effort mode and no fallbacks, and every failure is logged with the operation, the object, the OS error and, where possible, a hint.

## Requirements → mechanism

| Requirement | How it is met |
|---|---|
| Runs on serverless platforms | Unprivileged syscalls only; static binary drops into any base image; PID 1 duties (signal forwarding, zombie reaping, SIGTERM grace period) |
| seccomp | A prelude filter (architecture, x32, `clone3`) plus a policy filter whose matches are sent to the supervisor through a seccomp user-notification listener, so every denial is logged |
| Landlock | Path rules (read/write/execute), TCP bind/connect handling (ABI v4+), signal and abstract-socket scoping (ABI v6+), for exactly the ABI the policy pins |
| Fine-grained egress | `network.mode = "egress"`: every `connect()` is decided by the supervisor against CIDR and domain rules and carried out by the supervisor itself (TOCTOU-safe); a DNS proxy enforces domain rules |
| Subprocesses inherit | Landlock domains, seccomp filters, `no_new_privs`, rlimits and the identity switch are inherited across `fork`/`execve` and cannot be removed |
| Volumes | Platform mounts happen before the entrypoint, so sbx opens the mount points and binds rules to them |
| Configurable at start | A complete policy file, plus `SBX_*` variables and flags for per-run additions |
| Fail loudly | Requirements are probed before anything starts; unknown or empty settings, symlinked or missing paths, and unsupported ABIs are errors |

## Architecture

```
container start
  sbx run [flags] -- PROGRAM ARGS        (PID 1, root, unsandboxed, never runs payload code)
   │ 1. resolve policy: file + SBX_* env + flags; validate everything, report every error
   │ 2. check requirements (Landlock ABI, seccomp listener round trip, close_range,
   │    identity; egress: CAP_SYS_PTRACE, pidfd_getfd, DNS listener, resolv.conf)
   │ 3. open allowed paths, build the Landlock ruleset, compile the BPF filters
   │ 4. fork
   ├─ child ─ setsid → chdir → rlimits → empty capability bounding set
   │          → setgroups/setresgid/setresuid(65534) → clear all capabilities (verified)
   │          → PDEATHSIG → NO_NEW_PRIVS → landlock_restrict_self
   │          → seccomp(prelude) → seccomp(policy, NEW_LISTENER | WAIT_KILLABLE_RECV)
   │          → hand the listener to the parent (SCM_RIGHTS) → close inherited fds
   │          → reset every signal disposition and the mask → execve(PROGRAM, scrubbed env)
   └─ parent ─ notification thread: log/deny policy matches, decide connect() (egress)
               DNS proxy threads (egress with domain rules)
               main loop: forward SIGTERM/INT/HUP/QUIT/USR1/USR2, enforce the timeout
               (exit 124), reap, kill everything left on exit, propagate the exit code
```

Fallible work happens before `fork`, so a bad policy produces a clear error instead of a half-built sandbox. Setup failures in the child, including `execve` being denied by Landlock, are reported back over a close-on-exec pipe. If the notification thread or the DNS proxy fails, the supervisor tears the sandbox down and exits 125. If the supervisor itself dies, the listener closes and every pending or future notified syscall fails with `ENOSYS`, so the sandbox fails closed.

## The layers

**Landlock (filesystem, TCP, IPC scoping).** `landlock.abi` pins the ABI whose access rights are handled: the kernel must support at least that version (sbx stops otherwise), and when the kernel is newer sbx warns that rights added after the pinned ABI are not restricted. Policy letters map to rights: `r` = read file + read dir; `w` = write, truncate, create (files, dirs, symlinks, fifos, sockets), remove, rename/link (`refer`), device ioctl, pathname-socket connect; `x` = execute. Creating device nodes is never granted. Rule paths must exist and be canonical (a symlink is an error that names its target). In `none` and `egress` modes TCP bind and connect are handled with no connect rules at all, so any connect made from inside the sandbox fails. `scope_signals` / `scope_abstract_unix` (ABI v6+) stop the sandbox from signalling, or connecting to abstract UNIX sockets of, anything outside its domain; Landlock's ptrace check also blocks reading `/proc/<supervisor>/environ` at the same uid.

**seccomp (kernel attack surface).** The payload is an arbitrary program, so the filter is a deny-list of syscalls that let code escape or attack the kernel: ptrace and cross-process memory/fd access, mount and namespace syscalls, `bpf`, `perf_event_open`, `userfaultfd`, io_uring, keyrings, handle-based opens, module loading, kexec, clock setting and similar. Argument checks deny `clone` with any `CLONE_NEW*` flag, restrict `socket`/`socketpair` to `seccomp.socket_families`, block `TIOCSTI`/`TIOCLINUX` and limit `personality`. The prelude kills on a foreign architecture, returns `ENOSYS` for the x32 ABI and for `clone3` (whose flags BPF cannot see; libc falls back to `clone`). Every policy match is delivered to the supervisor, which logs it once per program, syscall and reason (repeats are summarised at exit) and then fails the call with `EPERM` (`on_violation = "errno"`) or kills the process with SIGKILL before the call runs (`"kill"`). A call that the container runtime's own seccomp profile already refuses never reaches sbx's filter (the kernel applies the most restrictive verdict), so it is denied but not logged by sbx.

**Process hygiene.** Started as root (the image default), sbx empties the capability bounding set, drops supplementary groups, switches to `65534:65534` and verifies that every capability set is empty. The environment is rebuilt from the policy (`env.pass` names must be set). Inherited file descriptors are closed with `close_range`. Every signal starts at its default disposition with an empty mask (sbx itself is a Rust program, which ignores SIGPIPE). Core dumps are disabled and rlimits cap open files, processes, file size, address space and CPU time (`"unlimited"` must be written explicitly).

## Egress filtering

With `network.mode = "egress"` the sandbox may create TCP sockets only (no UDP, raw, ICMP, SCTP or MPTCP), and every `connect()` goes to the supervisor:

1. The supervisor pins the calling thread (a `PIDFD_THREAD` pidfd, then `SECCOMP_IOCTL_NOTIF_ID_VALID` so a recycled id can never be mistaken for it) and takes its own reference to the socket from that thread's fd table with `pidfd_getfd`.
2. For non-IP sockets (UNIX, netlink) it lets the kernel run the call. This is safe even if another thread swaps an IP socket into that fd number in the meantime: the only IP sockets the sandbox can hold are TCP, and Landlock denies TCP connects made from inside the sandbox.
3. For IP sockets it copies the destination out of the caller's memory (`process_vm_readv`), checks the copy against the rules, and **performs the connect itself** on its reference to the caller's socket, then returns the result. The kernel never re-reads the caller's memory, so a racing thread cannot change the address after the check. Blocking and non-blocking sockets behave as usual (`EINPROGRESS`, `ECONNREFUSED` and so on are passed through), and `WAIT_KILLABLE_RECV` keeps signals from interrupting a call half-way.
4. Allowed destinations: `cidr` rules, addresses returned by the DNS proxy for names matching `domain` rules, and the DNS proxy itself. Anything else fails with `EACCES` and is logged. Connecting to `0.0.0.0` or `::` is refused explicitly; IPv4-mapped IPv6 addresses are matched as IPv4.

seccomp also refuses `MSG_FASTOPEN` (TCP Fast Open connects from inside `sendto`/`sendmsg`, which Landlock does not check on most kernels) and the socket options that change where packets go (`IP_OPTIONS` source routing, `IPV6_RTHDR`, `IPV6_2292RTHDR`, `IPV6_2292PKTOPTIONS`). An IP socket inherited on stdio would bypass the filter, so sbx refuses to start if fd 0-2 is one.

**DNS.** With domain rules, sbx serves DNS over TCP on a loopback address (`network.dns.listen`, port 53) and `/etc/resolv.conf` must name it with `options use-vc` (`resolv_conf = "write"` makes sbx write the file; `"verify"` only checks it). The proxy answers NXDOMAIN for names no rule matches (and logs them), NODATA for record types other than A/AAAA, and forwards everything else to the single `upstream` (no failover; a failed or truncated reply becomes SERVFAIL and is logged). A/AAAA records in an allowed answer are added to the allow-set, with that rule's ports, for the rest of the run, if their address class is listed in `answer_scopes` (`global`, `private`, `loopback`). Link-local (including the metadata server 169.254.169.254), multicast and reserved addresses are never learned. glibc and Go honour `use-vc`. musl (Alpine) resolvers do not and cannot resolve names in egress mode; give such programs IP rules.

Egress mode needs `CAP_SYS_PTRACE` in the container (`docker run --cap-add=SYS_PTRACE`; Kubernetes `securityContext.capabilities.add: [SYS_PTRACE]`). Docker and containerd's default seccomp profiles allow `pidfd_getfd` only with it, and reading another uid's memory needs it. The payload never has it.

## Configuration

The policy file is required (`--policy` or `SBX_POLICY_FILE`; the image sets `SBX_POLICY_FILE=/etc/sbx/policy.toml`). Every field must be present and unknown fields are rejected. [`policy/default.toml`](policy/default.toml) is the shipped policy (no network). [`policy/egress.example.toml`](policy/egress.example.toml) shows egress rules and the DNS proxy. Both are validated against the image during the build. Environment variables and flags then extend the policy (path grants and egress rules are added) or replace a few scalars (flags win over the environment):

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

Booleans are `true`/`false`. An empty `SBX_*` value, a flag given twice, a missing `--` before the program, and **any `SBX_*` variable sbx does not know** are errors, so a typo cannot silently leave a setting at its file value. Keep other software's variables out of the `SBX_` prefix in sbx's environment.

`sbx policy [flags]` validates and prints the effective policy. `sbx probe [flags]` checks every requirement of that policy on this kernel and container, and exits 1 if one is missing. These are operator inputs: never build sbx flags from the untrusted payload; pass payload data only as arguments after `--`.

Exit codes: the program's own, 124 on timeout, 125 for sbx errors (bad policy, missing capability, internal failure), 127 if the program cannot be executed, 128+N if it was killed by signal N.

### Kernel and container requirements

* Landlock ABI ≥ `landlock.abi` (the default policy pins 6: Linux 6.12). `none` and `egress` modes need ABI 4+ (Linux 6.7).
* seccomp user notification with `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (Linux 5.19), and no other seccomp listener already installed in the container (`sbx probe` runs a full round trip), plus `close_range` (5.9) and `pidfd_open`/`pidfd_getfd` (5.6).
* Root with `CAP_SETPCAP` (for the bounding set) and `CAP_SETUID`/`CAP_SETGID`, which Docker grants by default. A non-root sbx runs the program at its own uid, which must equal the policy's, with no supplementary groups; the sandbox is then separated from the supervisor by Landlock scoping only, so use ABI 6+.
* Egress: Linux 6.9+ (`PIDFD_THREAD`), `CAP_SYS_PTRACE`, Yama `ptrace_scope` < 3, and port 53 on the loopback listen address.

## Build and test

```sh
make lint test        # rustfmt, clippy (warnings are errors), unit tests
make image            # ghcr.io/ocramz/sbx:<git sha> on BASE_IMAGE (debian:bookworm-slim)
make smoke            # build images; integration suite in Docker; checks of the runtime image
make smoke-local      # integration suite on this host (root, private mount namespace)
make probe            # sbx probe in the runtime image
make push PUSH_TAGS="main"
make help             # everything else
```

The Rust version comes from `rust-toolchain.toml`. Images are built for the host's architecture (`linux/amd64` or `linux/arm64`); pass `PLATFORM=` to override, though the integration suite cannot run under emulation. Docker builds a static musl binary on `rust:<version>-slim-bookworm` and fails if it is not static. The integration suite ([`tests/smoke.py`](tests/smoke.py)) runs in a test image (the runtime stage on `python:3.13-slim-bookworm`) with `--cap-add SYS_PTRACE`. It covers escape attempts that only Landlock or seccomp can stop, strictness errors, egress allow/deny decisions, DNS learning and refusals, and two race tests: one flips the sockaddr from another thread during `connect`, the other swaps an AF_UNIX and a TCP socket under the same fd number. Both assert that the denied server never sees a connection. [`tests/image-checks.sh`](tests/image-checks.sh) then exercises the runtime image as shipped (PID 1, signal forwarding, cleanup of leftover processes).

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs `make lint`, `make test` and `make smoke` on every push and pull request. Pushes to `main` publish `ghcr.io/ocramz/sbx:<sha>` and `:main`; tags `v*` publish `:<tag>` and `:latest`.

## Deploying on Cloud Run

Use Cloud Run **jobs** (or a service pinned to `--execution-environment=gen2`). The first-generation environment is gVisor, which returns `ENOSYS` for Landlock, and sbx refuses to run there. First check what the platform provides, because Google does not document the Landlock ABI or the capabilities of its gen2 guests:

```sh
gcloud run jobs create sbx-probe --image=$IMAGE --region=$REGION \
  --command=/usr/local/bin/sbx --args=probe
gcloud run jobs execute sbx-probe --region=$REGION --wait    # then read the logs
# the same for the egress example (CAP_SYS_PTRACE, DNS listener, resolv.conf):
gcloud run jobs create sbx-probe-egress --image=$IMAGE --region=$REGION \
  --command=/usr/local/bin/sbx --args=probe --set-env-vars=SBX_POLICY_FILE=/etc/sbx/egress.example.toml
```

If the platform's kernel has an older Landlock ABI, lower `landlock.abi` (and the features that need it) explicitly in your policy. A job that runs untrusted code from a bucket, with a writable scratch volume and no network:

```sh
gcloud iam service-accounts create sbx-untrusted     # grant it NOTHING except what the volumes need

gcloud run jobs create sandbox --image=$IMAGE --region=$REGION \
  --service-account=sbx-untrusted@$PROJECT.iam.gserviceaccount.com \
  --memory=1Gi --task-timeout=15m --max-retries=0 \
  --add-volume=name=work,type=in-memory,size-limit=512Mi \
  --add-volume-mount=volume=work,mount-path=/workspace \
  --add-volume=name=code,type=cloud-storage,bucket=$CODE_BUCKET,readonly=true \
  --add-volume-mount=volume=code,mount-path=/mnt/code \
  --set-env-vars=SBX_TIMEOUT=600,SBX_FS_RO=/mnt/code

# per-execution overrides: arguments and env can change for each run
gcloud run jobs execute sandbox --region=$REGION \
  --args="--timeout=120,--,python3,/mnt/code/job-42/main.py"
```

gcloud splits `--set-env-vars` on commas, so use `:` between paths, and gcloud's alternate delimiter syntax (`--set-env-vars='^;^SBX_EGRESS=a.example.com:443,b.example.com:443'`) for lists of egress rules. For writable Cloud Storage volumes, make the files belong to the sandbox user with `mount-options="uid=65534;gid=65534"`.

**Services** have to serve HTTP on `$PORT`, so the server is the entrypoint and spawns one sandbox per request, for example `subprocess.run(["sbx", "run", "--quiet", "--timeout", "30", "--rw", job_dir, "--workdir", job_dir, "--", "python3", "main.py"], capture_output=True)` with `SBX_POLICY_FILE` set. Give each request its own directory, because concurrent requests on one instance share `/tmp`.

## Threat model and limitations

The sandbox assumes a hostile payload and a correct kernel. It narrows what the payload can reach (files, sockets, destinations, other processes, dangerous syscalls). The payload still shares the kernel with the supervisor, so a kernel exploit through an allowed syscall defeats it. On Cloud Run the gen2 microVM is the outer boundary.

* **Metadata server.** `169.254.169.254` hands out the service account's token to anything that can make an HTTP request. `unrestricted` mode and any CIDR rule covering it expose it (sbx warns), DNS answers can never add it, and the job should run with a service account that has no roles beyond what its volumes need.
* **Egress is IP-level.** A domain rule allows the addresses that name resolved to, for that rule's ports, until sbx exits. Other sites on the same addresses (CDNs, shared load balancers) are reachable too. Wildcard rules let the payload send arbitrary query names to that domain's authoritative servers (a DNS exfiltration channel).
* **TCP only.** UDP (and QUIC) cannot leave the sandbox in egress mode. Programs whose resolver cannot use TCP (musl) need IP rules.
* **One DNS proxy per address.** The proxy binds `network.dns.listen` exclusively and `/etc/resolv.conf` is shared by the container, so with domain rules only one sbx runs at a time per container (the Cloud Run job model). A second one fails to start with an error.
* **UNIX sockets.** Below Landlock ABI 9, connecting to pathname UNIX sockets is restricted only by file permissions. A service outside the sandbox that listens on one could hand the sandbox an unfiltered socket, so do not expose such sockets to the sandbox's uid.
* **`x` is hygiene.** Landlock's `x` controls `execve`, not code loading: the payload can still run code through an allowed interpreter or by invoking `ld.so` on a file it wrote. To stop fileless execution, add `seccomp.deny = ["memfd_create", "execveat"]`.
* **Memory** is bounded only by the container limit; a payload that exhausts it takes down the instance, supervisor included. Keep service concurrency at 1 for untrusted work. `limits.as_mb` is available but breaks Go, the JVM and V8.

Cloud Run also has a native **sandboxes** feature (public preview since July 2026) that runs code in a separate isolated environment inside a service instance, without access to the service's environment variables or the metadata server. If you only target Cloud Run, consider it as the outer layer with sbx inside, or instead of sbx.

## Files

```
Dockerfile                  build (static musl binary), runtime and test stages
Makefile                    build, lint, test, image, smoke, push targets
rust-toolchain.toml         the Rust version, for cargo, CI and the image build
policy/default.toml         shipped policy (no network)
policy/egress.example.toml  egress rules + DNS proxy example
src/main.rs                 CLI: run / probe / policy, environment, program lookup
src/policy.rs               policy model, overrides, validation
src/landlock_layer.rs       Landlock probe, ruleset, enforcement
src/seccomp_layer.rs        rule table, BPF prelude and policy filter, evaluator
src/notify.rs               seccomp user notification: listener, dispatcher, denials
src/egress.rs               connect() decisions and emulation
src/dns.rs                  DNS proxy, wire format, resolv.conf
src/net.rs                  CIDR, domain patterns, address classes, sockaddr parsing
src/capabilities.rs         requirement checks (probe, run)
src/supervisor.rs           fork/exec, identity and capability drop, signals, timeout, cleanup
src/log.rs                  stderr logging
tests/smoke.py              integration suite (run as root in a disposable environment)
tests/run-local.sh          runs the suite on a host inside a private mount namespace
tests/image-checks.sh       checks of the runtime image as shipped
```
