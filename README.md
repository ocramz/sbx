# sbx: a seccomp + Landlock sandbox image for serverless containers

`sbx` is a small (about 1.2 MB, static) Rust launcher that becomes the container's PID 1, builds a sandbox from an operator-supplied policy, and runs the untrusted program inside it. It uses unprivileged kernel APIs only (Landlock, seccomp-BPF with user notification, `no_new_privs`, rlimits): no `--privileged`, no `CAP_SYS_ADMIN`, no user namespaces.

sbx is strict by design. Every protection the policy asks for must be enforceable on the running kernel and container, or sbx refuses to start and says why. It has no built-in defaults, no best-effort mode and no fallbacks, and every failure is logged with the operation, the object, the OS error and, where possible, a hint. Even Landlock can only be turned off explicitly, in the policy file ([Without Landlock](#without-landlock)).

sbx runs one sandbox at a time, one per container.

## Requirements → mechanism

| Requirement | How it is met |
|---|---|
| Runs on serverless platforms | Unprivileged syscalls only; static binary drops into any base image; PID 1 duties (signal forwarding, zombie reaping, SIGTERM grace period) |
| seccomp | A prelude filter (architecture, x32, `clone3`) plus a policy filter whose matches are sent to the supervisor through a seccomp user-notification listener, so every denial is logged |
| Landlock | Path rules (read/write/execute), TCP bind/connect handling (ABI v4+), signal and abstract-socket scoping (ABI v6+), for exactly the ABI the policy pins; or explicitly off, with the compensations in [Without Landlock](#without-landlock) |
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
   │    identity, no other sandbox; egress: CAP_SYS_PTRACE, pidfd_getfd, DNS listener,
   │    resolv.conf), then claim the container's sandbox slot
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

The sandbox slot is an abstract UNIX socket (`@sbx/sandbox`) that `sbx run` binds and holds until it exits. A second `sbx run` while one is running exits 125 ("another sbx sandbox is running"), and `sbx probe` reports it. Abstract sockets are per network namespace, so the slot covers the container on Cloud Run, the whole pod on Kubernetes, and the whole host with `docker run --network host`.

Fallible work happens before `fork`, so a bad policy produces a clear error instead of a half-built sandbox. Setup failures in the child, including `execve` being denied by Landlock, are reported back over a close-on-exec pipe. If the notification thread or the DNS proxy fails, the supervisor tears the sandbox down and exits 125. If the supervisor itself dies, the listener closes and every pending or future notified syscall fails with `ENOSYS`, so the sandbox fails closed.

## The layers

**Landlock (filesystem, TCP, IPC scoping).** `landlock.abi` pins the ABI whose access rights are handled: the kernel must support at least that version (sbx stops otherwise), and when the kernel is newer sbx warns that rights added after the pinned ABI are not restricted. `landlock.abi = "off"` runs without Landlock ([Without Landlock](#without-landlock)). Policy letters map to rights: `r` = read file + read dir; `w` = write, truncate, create (files, dirs, symlinks, fifos, sockets), remove, rename/link (`refer`), device ioctl, pathname-socket connect; `x` = execute. Creating device nodes is never granted. Rule paths must exist and be canonical (a symlink is an error that names its target). In `none` and `egress` modes TCP bind and connect are handled with no connect rules at all, so any connect made from inside the sandbox fails. `scope_signals` / `scope_abstract_unix` (ABI v6+) stop the sandbox from signalling, or connecting to abstract UNIX sockets of, anything outside its domain; Landlock's ptrace check also blocks reading `/proc/<supervisor>/environ` at the same uid.

**seccomp (kernel attack surface).** The payload is an arbitrary program, so the filter is a deny-list of syscalls that let code escape or attack the kernel: ptrace and cross-process memory/fd access, mount and namespace syscalls, `bpf`, `perf_event_open`, `userfaultfd`, io_uring, keyrings, handle-based opens, module loading, kexec, clock setting and similar. Argument checks deny `clone` with any `CLONE_NEW*` flag, restrict `socket`/`socketpair` to `seccomp.socket_families`, block `TIOCSTI`/`TIOCLINUX` and limit `personality`. The prelude kills on a foreign architecture, returns `ENOSYS` for the x32 ABI and for `clone3` (whose flags BPF cannot see; libc falls back to `clone`). Every policy match is delivered to the supervisor, which logs it once per program, syscall and reason (repeats are summarised at exit) and then fails the call with `EPERM` (`on_violation = "errno"`) or kills the process with SIGKILL before the call runs (`"kill"`). A call that the container runtime's own seccomp profile already refuses never reaches sbx's filter (the kernel applies the most restrictive verdict), so it is denied but not logged by sbx.

**Process hygiene.** Started as root (the image default), sbx empties the capability bounding set, drops supplementary groups, switches to `65534:65534` and verifies that every capability set is empty. The environment is rebuilt from the policy (`env.pass` names must be set). Inherited file descriptors are closed with `close_range`. Every signal starts at its default disposition with an empty mask (sbx itself is a Rust program, which ignores SIGPIPE). Core dumps are disabled and rlimits cap open files, processes, file size, address space and CPU time (`"unlimited"` must be written explicitly).

## Without Landlock

Some kernels are built without Landlock, including Cloud Run's ([Deploying on Cloud Run](#deploying-on-cloud-run)). sbx never falls back on its own: the policy has to say `landlock.abi = "off"`. [`policy/no-landlock.example.toml`](policy/no-landlock.example.toml) is the egress example in that form. sbx then refuses whatever only Landlock could enforce, and compensates where it can:

| Without Landlock | What sbx does |
|---|---|
| **Files are protected by their permissions only.** The program (uid 65534, no capabilities) can read everything world-readable in the image and volumes, write everything world-writable or owned by its uid, and run any world-executable binary. | Nothing can replace this. `[[fs]]` rules, `--ro/--rw/--rx` and `SBX_FS_*` are refused, so the policy never promises more than sbx enforces. |
| Signal and abstract-socket scoping, and Landlock's check on `/proc/<pid>/mem` | Not needed with one sandbox per container: the supervisor runs as root, so the program (another uid, no capabilities) cannot signal it or open its `/proc` files. sbx refuses to start if another process already runs as the sandbox uid. |
| Egress: Landlock denies TCP connects made inside the sandbox, which makes it safe to let the kernel run `connect()` on non-IP sockets ([Egress filtering](#egress-filtering), step 2) | `connect()` on non-IP sockets (AF_UNIX) is denied in egress mode. Otherwise a thread could swap a TCP socket onto the fd and connect anywhere, metadata server included. |
| Egress: TCP binds limited to `network.bind_tcp` | `bind` and `listen` are denied in egress mode, and `bind_tcp` must be empty. |
| Mode `none`: Landlock denies TCP connects | seccomp already forbids IP sockets in mode `none`. An IP socket on stdio is refused, as in egress mode. |

Everything else is unchanged: the seccomp filters, the switch to uid 65534 with empty capability and bounding sets, `no_new_privs`, rlimits, the scrubbed environment, closed file descriptors, the timeout, and egress decisions for IP connects (DNS proxy and metadata-server block included).

Use it only if all of these hold:

* sbx starts as root and runs the program as a uid nothing else in the container uses. sbx checks both.
* One sandbox runs per container. sbx enforces it.
* Nothing the program must not read is world-readable: application code, configuration, mounted secrets (`chmod o-rwx`). Check how your platform mounts secret volumes.
* Volumes with code to run are mounted read-only.

**sbx must start as root.** A non-root sbx cannot switch uid, so the program runs as the same user as the supervisor. With Landlock, ABI 6 scoping keeps the two apart. Without it, nothing does: seccomp blocks `ptrace` and `process_vm_readv`, but not opening files under `/proc`. For example, if the container runs with `docker run --user 1000:1000` (or `runAsUser: 1000`) and the policy has `process.uid = 1000`, the program could do this:

```python
import os, signal
sbx = os.getppid()                                # the supervisor
open(f"/proc/{sbx}/environ", "rb").read()         # its environment, secrets included
open(f"/proc/{sbx}/mem", "r+b")                   # read and write its memory, e.g. the egress allow-list
os.kill(sbx, signal.SIGKILL)                      # or kill it: no timeout, no cleanup
```

The environment scrubbing, the egress filter and the timeout all live in the supervisor. So with `landlock.abi = "off"`, sbx refuses to start unless it runs as root, and exits 125 (`sbx probe` shows `MISSING identity`):

```
sbx: error: required capability missing: identity: landlock.abi = "off" needs sbx to start as root: as uid 1000 the program would share the supervisor's uid and could read or rewrite its memory through /proc/<pid>/mem
```

The image's default (`USER 0`) is fine. sbx starts as root and runs the program as 65534. A different uid with no capabilities cannot open root's `/proc/<pid>/environ` or `mem`, or signal it.

## Egress filtering

With `network.mode = "egress"` the sandbox may create TCP sockets only (no UDP, raw, ICMP, SCTP or MPTCP), and every `connect()` goes to the supervisor:

1. The supervisor pins the calling thread (a `PIDFD_THREAD` pidfd, then `SECCOMP_IOCTL_NOTIF_ID_VALID` so a recycled id can never be mistaken for it) and takes its own reference to the socket from that thread's fd table with `pidfd_getfd`.
2. For non-IP sockets (UNIX, netlink) it lets the kernel run the call. This is safe even if another thread swaps an IP socket into that fd number in the meantime: the only IP sockets the sandbox can hold are TCP, and Landlock denies TCP connects made from inside the sandbox. Without Landlock, these connects are denied instead.
3. For IP sockets it copies the destination out of the caller's memory (`process_vm_readv`), checks the copy against the rules, and **performs the connect itself** on its reference to the caller's socket, then returns the result. The kernel never re-reads the caller's memory, so a racing thread cannot change the address after the check. Blocking and non-blocking sockets behave as usual (`EINPROGRESS`, `ECONNREFUSED` and so on are passed through), and `WAIT_KILLABLE_RECV` keeps signals from interrupting a call half-way.
4. Allowed destinations: `cidr` rules, addresses returned by the DNS proxy for names matching `domain` rules, and the DNS proxy itself. Anything else fails with `EACCES` and is logged. Connecting to `0.0.0.0` or `::` is refused explicitly; IPv4-mapped IPv6 addresses are matched as IPv4.

seccomp also refuses `MSG_FASTOPEN` (TCP Fast Open connects from inside `sendto`/`sendmsg`, which Landlock does not check on most kernels) and the socket options that change where packets go (`IP_OPTIONS` source routing, `IPV6_RTHDR`, `IPV6_2292RTHDR`, `IPV6_2292PKTOPTIONS`). An IP socket inherited on stdio would bypass the filter, so sbx refuses to start if fd 0-2 is one.

**DNS.** With domain rules, sbx serves DNS over TCP on a loopback address (`network.dns.listen`, port 53) and `/etc/resolv.conf` must name it with `options use-vc` (`resolv_conf = "write"` makes sbx write the file and put the original back when it exits; `"verify"` only checks it). The proxy answers NXDOMAIN for names no rule matches (and logs them), NODATA for record types other than A/AAAA, and forwards everything else to the single `upstream` (no failover; a failed or truncated reply becomes SERVFAIL and is logged). A/AAAA records in an allowed answer are added to the allow-set, with that rule's ports, for the rest of the run, if their address class is listed in `answer_scopes` (`global`, `private`, `loopback`). Link-local (including the metadata server 169.254.169.254), multicast and reserved addresses are never learned. glibc and Go honour `use-vc`. musl (Alpine) resolvers do not and cannot resolve names in egress mode; give such programs IP rules.

Egress mode needs `CAP_SYS_PTRACE` in the container (`docker run --cap-add=SYS_PTRACE`; Kubernetes `securityContext.capabilities.add: [SYS_PTRACE]`). Docker and containerd's default seccomp profiles allow `pidfd_getfd` only with it, and reading another uid's memory needs it. The payload never has it.

## Configuration

The policy file is required (`--policy` or `SBX_POLICY_FILE`; the image sets `SBX_POLICY_FILE=/etc/sbx/policy.toml`). Every field must be present and unknown fields are rejected. [`policy/default.toml`](policy/default.toml) is the shipped policy (no network). [`policy/egress.example.toml`](policy/egress.example.toml) shows egress rules and the DNS proxy, and [`policy/no-landlock.example.toml`](policy/no-landlock.example.toml) is the same for kernels without Landlock. All three are validated against the image during the build. Environment variables and flags then extend the policy (path grants and egress rules are added) or replace a few scalars (flags win over the environment):

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

* Landlock ABI ≥ `landlock.abi` (the default policy pins 6: Linux 6.12). `none` and `egress` modes need ABI 4+ (Linux 6.7). With `landlock.abi = "off"`, no Landlock at all ([Without Landlock](#without-landlock)).
* seccomp user notification with `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (Linux 5.19), and no other seccomp listener already installed in the container (`sbx probe` runs a full round trip), plus `close_range` (5.9) and `pidfd_open`/`pidfd_getfd` (5.6).
* Root with `CAP_SETPCAP` (for the bounding set) and `CAP_SETUID`/`CAP_SETGID`, which Docker grants by default. A non-root sbx runs the program at its own uid, which must equal the policy's, with no supplementary groups; the sandbox is then separated from the supervisor by Landlock scoping only, so use ABI 6+. With `landlock.abi = "off"`, non-root is refused ([Without Landlock](#without-landlock)).
* Egress: Linux 6.9+ (`PIDFD_THREAD`), `CAP_SYS_PTRACE`, Yama `ptrace_scope` < 3, and port 53 on the loopback listen address.

## Build and test

```sh
make lint test        # rustfmt, clippy (warnings are errors), unit tests
make image            # ghcr.io/ocramz/sbx:<git sha> on BASE_IMAGE (debian:bookworm-slim)
make smoke            # build images; integration suite in Docker; checks of the runtime image
make smoke-local      # integration suite on this host (root, private mount namespace)
make probe            # sbx probe in the runtime image
make push PUSH_TAGS="main"
make live             # live tests on a Cloud Run service (see below)
make help             # everything else
```

The Rust version comes from `rust-toolchain.toml`. Images are built for the host's architecture (`linux/amd64` or `linux/arm64`); pass `PLATFORM=` to override, though the integration suite cannot run under emulation. The build stage runs on the build machine's own architecture and cross-compiles a static musl binary on `rust:<version>-slim-bookworm`, linked with `rust-lld`, so an amd64 image can be built on an arm64 Mac (x86_64 rustc crashes under QEMU); the build fails if the binary is not static. The integration suite ([`tests/smoke.py`](tests/smoke.py)) runs in a test image (the runtime stage on `python:3.13-slim-bookworm`) with `--cap-add SYS_PTRACE`. It covers escape attempts that only Landlock or seccomp can stop, strictness errors, egress allow/deny decisions, DNS learning and refusals, one sandbox per container, the Landlock-off mode, and two race tests: one flips the sockaddr from another thread during `connect`, the other swaps an AF_UNIX and a TCP socket under the same fd number. Both assert that the denied server never sees a connection. [`tests/image-checks.sh`](tests/image-checks.sh) then exercises the runtime image as shipped (PID 1, signal forwarding, cleanup of leftover processes).

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs `make lint`, `make test` and `make smoke` on every push and pull request. Pushes to `main` publish `ghcr.io/ocramz/sbx:<sha>` and `:main`; tags `v*` publish `:<tag>` and `:latest`.

## Deploying on Cloud Run

**Cloud Run does not support Landlock.** `make live` has shown this ([Live tests on Cloud Run](#live-tests-on-cloud-run), October 2026, europe-north1):

* The first-generation environment is gVisor, which returns `ENOSYS` for Landlock.
* The second-generation guest kernel is Linux 6.9.12 built without Landlock. `landlock_create_ruleset` returns `ENOSYS`. The kernel's active LSMs are capability, lockdown, loadpin, selinux and bpf. `/proc/kallsyms` has no Landlock symbols. The container's seccomp profile is not the cause: newer syscalls such as `fchmodat2`, `statmount` and `listmount` reach the kernel. Even if Google enabled Landlock, 6.9 provides at most ABI 4, below the default policy's 6.

Everything else sbx needs is there: seccomp user notification, `pidfd_getfd`, all capabilities except `CAP_SYS_MODULE`, `CAP_SYS_RAWIO` and `CAP_MKNOD`, no Yama, and a writable `/etc/resolv.conf`. The shipped Landlock policies therefore cannot run on Cloud Run. Use [`policy/no-landlock.example.toml`](policy/no-landlock.example.toml) under the conditions in [Without Landlock](#without-landlock). Google does not document its gen2 kernel, so run `make live` again to see whether this has changed.

Use Cloud Run **jobs** (or a service pinned to `--execution-environment=gen2`) with a policy the platform supports, and check it there first. On a platform whose kernel has an older Landlock ABI, lower `landlock.abi` (and the features that need it) explicitly instead of turning Landlock off.

```sh
gcloud run jobs create sbx-probe --image=$IMAGE --region=$REGION \
  --command=/usr/local/bin/sbx --args=probe --set-env-vars=SBX_POLICY_FILE=/etc/sbx/no-landlock.example.toml
gcloud run jobs execute sbx-probe --region=$REGION --wait    # then read the logs
```

A job that runs untrusted code from a bucket, with a writable scratch volume and no network. Its policy is a copy of the no-Landlock example with `mode = "none"` (no egress rules, no `[network.dns]`, `socket_families = ["unix"]`), built into your image as `/etc/sbx/job.toml`. The code volume is read-only, as running without Landlock requires; with Landlock, also grant it with `SBX_FS_RO=/mnt/code`.

```sh
gcloud iam service-accounts create sbx-untrusted     # grant it NOTHING except what the volumes need

gcloud run jobs create sandbox --image=$IMAGE --region=$REGION \
  --service-account=sbx-untrusted@$PROJECT.iam.gserviceaccount.com \
  --memory=1Gi --task-timeout=15m --max-retries=0 \
  --add-volume=name=work,type=in-memory,size-limit=512Mi \
  --add-volume-mount=volume=work,mount-path=/workspace \
  --add-volume=name=code,type=cloud-storage,bucket=$CODE_BUCKET,readonly=true \
  --add-volume-mount=volume=code,mount-path=/mnt/code \
  --set-env-vars=SBX_POLICY_FILE=/etc/sbx/job.toml,SBX_TIMEOUT=600

# per-execution overrides: arguments and env can change for each run
gcloud run jobs execute sandbox --region=$REGION \
  --args="--timeout=120,--,python3,/mnt/code/job-42/main.py"
```

gcloud splits `--set-env-vars` on commas, so use `:` between paths, and gcloud's alternate delimiter syntax (`--set-env-vars='^;^SBX_EGRESS=a.example.com:443,b.example.com:443'`) for lists of egress rules. For writable Cloud Storage volumes, make the files belong to the sandbox user with `mount-options="uid=65534;gid=65534"`.

**Services** have to serve HTTP on `$PORT`, so the server is the entrypoint and spawns one sandbox per request, for example `subprocess.run(["sbx", "run", "--quiet", "--timeout", "30", "--workdir", job_dir, "--", "python3", "main.py"], capture_output=True)` with `SBX_POLICY_FILE` set. sbx runs one sandbox per container, so deploy with `--concurrency=1`: a request that arrives while a sandbox runs would get exit 125. Create each job directory owned by the sandbox uid with mode 0700 (with Landlock, also pass `--rw job_dir`). Sandboxes run one after another as the same uid, so remove what the previous one left, its job directory and its files in `/tmp`, before starting the next.

## Live tests on Cloud Run

[`tests/cloud-run.sh`](tests/cloud-run.sh) finds out what Cloud Run's gen2 Linux provides by running sbx there. It builds the test image on this machine for `linux/amd64` (the only architecture Cloud Run runs), pushes it to Artifact Registry, creates or updates the private service `sbx-live` (gen2, one instance, one request at a time), runs two suites on it and prints the service's logs:

* [`tests/live.py`](tests/live.py) prints the platform facts (kernel, Landlock ABI, the container's capabilities and seccomp state, Yama, `/etc/resolv.conf`, the active LSMs, Landlock symbols in `/proc/kallsyms`, whether newer syscalls reach the kernel, and `sbx probe` for the three shipped policies). It then checks the sandbox and egress filtering on the real network: an allowed name resolves through the metadata server's DNS and connects; another address, the metadata server and an unlisted name are refused. It runs these checks with the Landlock policies if the kernel has Landlock ABI 6, and always with the no-Landlock example, which adds the checks that AF_UNIX connects and binds are refused.
* [`tests/smoke.py`](tests/smoke.py), the integration suite.

The service sets `TEST_REQUIRE_LANDLOCK=false` (`make smoke` sets it to `true`, the default). On a kernel without Landlock ABI 6, both suites then check that sbx refuses the Landlock policies, report the Landlock-only tests as n/a, and run everything else with `landlock.abi = "off"`. So `make live` passes on Cloud Run when everything that can run there works.

A service has to serve HTTP, so the service runs [`tests/live_server.py`](tests/live_server.py), which runs one suite per request (`GET /suite/live`, `GET /suite/smoke`) and streams its output back. A failure there can be a finding about the platform rather than a bug in sbx: for example, without `CAP_SYS_PTRACE` the egress mode cannot run at all.

```sh
make live                               # tests/cloud-run.sh all: up, deploy, test, logs
make live-down                          # delete the service and the repository
tests/cloud-run.sh up|deploy|test|logs|down    # one step at a time
```

The script authenticates only with a service account JSON key, activated in a throwaway gcloud configuration, so your own gcloud login is never used or changed. The registry login uses a one-hour access token derived from the key and is written to a temporary file, never to the engine's configuration. Settings come from the environment or from `.env` at the repository root (ignored by git; the environment wins):

```sh
GCP_KEY_FILE=/path/outside/the/repo/key.json   # required
GCP_REGION=europe-west1                        # required
GCP_PROJECT=...                                # default: the key's project_id
GCP_RUNTIME_SA=...                             # default: <key's account>-runtime@PROJECT.iam.gserviceaccount.com
DOCKER=podman                                  # as in the Makefile
```

The service scales to zero between runs. Each `make live` deploys a new revision, even when nothing changed, so the suites always start on a fresh instance; `make live-down` removes the service and the repository. Run one at a time per project, since the names are fixed.

One-time setup, with your own login (a dedicated project is best):

```sh
P=my-project
SA=sbx-testing@$P.iam.gserviceaccount.com
gcloud services enable run.googleapis.com artifactregistry.googleapis.com logging.googleapis.com --project=$P
gcloud iam service-accounts create sbx-testing --project=$P            # the key's identity
gcloud iam service-accounts create sbx-testing-runtime --project=$P    # the service's identity: no roles
for role in run.developer run.invoker artifactregistry.admin logging.viewer; do
  gcloud projects add-iam-policy-binding $P --role=roles/$role --member=serviceAccount:$SA --condition=None
done
gcloud iam service-accounts add-iam-policy-binding sbx-testing-runtime@$P.iam.gserviceaccount.com \
  --role=roles/iam.serviceAccountUser --member=serviceAccount:$SA --project=$P
gcloud iam service-accounts keys create /path/outside/the/repo/key.json --iam-account=$SA
```

The key can deploy and call Cloud Run services, create, push to and delete Artifact Registry repositories, and read logs in that project; it can act as `sbx-testing-runtime` and no other service account. Organisations that enforce `iam.disableServiceAccountKeyCreation` refuse the last command. To remove everything, run `make live-down`, then delete both service accounts (which also revokes the key).

## Threat model and limitations

The sandbox assumes a hostile payload and a correct kernel. It narrows what the payload can reach (files, sockets, destinations, other processes, dangerous syscalls). The payload still shares the kernel with the supervisor, so a kernel exploit through an allowed syscall defeats it. On Cloud Run the gen2 microVM is the outer boundary.

* **Metadata server.** `169.254.169.254` hands out the service account's token to anything that can make an HTTP request. `unrestricted` mode and any CIDR rule covering it expose it (sbx warns), DNS answers can never add it, and the job should run with a service account that has no roles beyond what its volumes need.
* **Egress is IP-level.** A domain rule allows the addresses that name resolved to, for that rule's ports, until sbx exits. Other sites on the same addresses (CDNs, shared load balancers) are reachable too. Wildcard rules let the payload send arbitrary query names to that domain's authoritative servers (a DNS exfiltration channel).
* **TCP only.** UDP (and QUIC) cannot leave the sandbox in egress mode. Programs whose resolver cannot use TCP (musl) need IP rules.
* **One sandbox per container.** A second `sbx run` in the same network namespace exits 125 ([Architecture](#architecture)). The DNS proxy also binds `network.dns.listen` exclusively, and `/etc/resolv.conf` is shared by the container: while an egress sandbox runs, the rest of the container also resolves names through the sbx proxy. sbx restores the file when it exits, unless someone else changed it meanwhile (sbx then warns and leaves it), or sbx is killed with SIGKILL.
* **UNIX sockets.** Below Landlock ABI 9, connecting to pathname UNIX sockets is restricted only by file permissions. A service outside the sandbox that listens on one could hand the sandbox an unfiltered socket, so do not expose such sockets to the sandbox's uid.
* **`x` is hygiene.** Landlock's `x` controls `execve`, not code loading: the payload can still run code through an allowed interpreter or by invoking `ld.so` on a file it wrote. To stop fileless execution, add `seccomp.deny = ["memfd_create", "execveat"]`.
* **Memory** is bounded only by the container limit; a payload that exhausts it takes down the instance, supervisor included. Keep service concurrency at 1 for untrusted work. `limits.as_mb` is available but breaks Go, the JVM and V8.

Cloud Run also has a native **sandboxes** feature (public preview since July 2026) that runs code in a separate isolated environment inside a service instance, without access to the service's environment variables or the metadata server. If you only target Cloud Run, consider it as the outer layer with sbx inside, or instead of sbx.

## Files

```
Dockerfile                       build (static musl binary), runtime and test stages
Makefile                         build, lint, test, image, smoke, push, live targets
rust-toolchain.toml              the Rust version, for cargo, CI and the image build
policy/default.toml              shipped policy (no network)
policy/egress.example.toml       egress rules + DNS proxy example
policy/no-landlock.example.toml  the egress example with landlock.abi = "off"
src/main.rs                      CLI: run / probe / policy, environment, program lookup
src/policy.rs                    policy model, overrides, validation
src/landlock_layer.rs            Landlock probe, ruleset, enforcement
src/seccomp_layer.rs             rule table, BPF prelude and policy filter, evaluator
src/notify.rs                    seccomp user notification: listener, dispatcher, denials
src/egress.rs                    connect() decisions and emulation
src/dns.rs                       DNS proxy, wire format, resolv.conf
src/net.rs                       CIDR, domain patterns, address classes, sockaddr parsing
src/capabilities.rs              requirement checks (probe, run)
src/supervisor.rs                fork/exec, identity and capability drop, signals, timeout, cleanup
src/log.rs                       stderr logging
tests/smoke.py                   integration suite (run as root in a disposable environment)
tests/run-local.sh               runs the suite on a host inside a private mount namespace
tests/image-checks.sh            checks of the runtime image as shipped
tests/cloud-run.sh               live tests: build, push, deploy a Cloud Run service, run the suites, logs
tests/live.py                    Cloud Run platform facts and checks (run on the service)
tests/live_server.py             HTTP front that runs the suites on the service
```
