# sbx: a seccomp + Landlock sandbox image for serverless containers

`sbx` is a small (about 1 MB, static) Rust launcher that becomes the container's PID 1, builds a sandbox from an operator-supplied policy, and runs the untrusted program inside it. Everything it uses is unprivileged kernel API (Landlock, seccomp-BPF, `no_new_privs`, rlimits), so it needs no `--privileged`, no `CAP_SYS_ADMIN` and no user namespaces, which is exactly what serverless platforms like Cloud Run don't give you.

## Requirements → mechanism

| Requirement | How it is met |
|---|---|
| Runs on serverless platforms | Only unprivileged syscalls; static binary drops into any base image; sbx acts as PID 1 (signal forwarding, zombie reaping, SIGTERM grace period) |
| seccomp | Two stacked BPF filters: an arch/x32/`clone3` prelude and a deny-list with argument checks on `clone`, `socket`, `ioctl`, `personality` |
| Landlock | Path rules (read/write/execute), TCP port rules (ABI v4+), signal and abstract-socket scoping (ABI v6+) |
| Subprocesses inherit | Landlock domains, seccomp filters, `no_new_privs`, rlimits and the UID drop are all inherited across `fork`/`execve` and cannot be removed; optional `subprocesses = false` allows threads but no new processes |
| Volumes | Platform mounts happen before the entrypoint, so sbx opens the mount points and binds rules to them; works with tmpfs, Cloud Storage FUSE and NFS |
| Configurable at start | Policy file + env vars + CLI flags, resolved at container start (file < env < flags) |

## Architecture

```
container start
  sbx run [flags] -- PROGRAM ARGS           (PID 1, root, unsandboxed, never runs payload code)
   │ 1. resolve policy: file → SBX_* env → flags; validate; warn on risky settings
   │ 2. probe Landlock ABI; fail closed if required and missing
   │ 3. open every allowed path, build Landlock ruleset, compile BPF   ← all errors surface here
   │ 4. fork
   ├─ child ─ setsid → chdir → rlimits → setgroups/setresgid/setresuid(65534)
   │          → clear ambient caps → PDEATHSIG → NO_NEW_PRIVS
   │          → landlock_restrict_self → seccomp(prelude) → seccomp(policy)
   │          → close inherited fds → execve(PROGRAM, scrubbed env)
   │              └─ PROGRAM and every descendant: all layers inherited, irrevocable
   └─ parent ─ sigtimedwait loop: forward SIGTERM/INT/HUP/QUIT/USR1/USR2 to the group,
               enforce timeout (exit 124), reap zombies, on exit SIGKILL everything left
               (kill(-1) as PID 1; subreaper + /proc scan otherwise), propagate exit code
```

Doing all fallible work before `fork` means a bad policy produces a clear error instead of a half-built sandbox, and the child only issues the few syscalls that actually apply restrictions. Failures in the child (including `execve` being denied by Landlock) are reported back over a `CLOEXEC` pipe, so you get `execve: /var/tmp/t: Permission denied` plus a hint rather than a bare exit code.

The order inside the child matters. The UID drop happens before `PR_SET_PDEATHSIG` because changing credentials clears it. Landlock is applied before seccomp so that seccomp never needs to permit the Landlock setup calls. File descriptors are closed after Landlock has consumed its ruleset fd.

## The layers

**Landlock (filesystem, TCP, IPC scoping).** The ruleset handles every access right the running kernel knows about (computed from the probed ABI, up to v9), so anything not granted is denied, including rights added in newer kernels. Policy letters map to rights as follows: `r` grants read file and read dir; `w` grants write, truncate, create (files, dirs, symlinks, fifos, sockets), remove, rename/link (`refer`), device ioctl and pathname-socket connect; `x` grants execute. Creating device nodes is never granted. Rules on regular files are masked to file-applicable rights automatically. In `network.mode = "none"` TCP is handled with no port rules, so every bind/connect is denied even if seccomp were bypassed; in `"restricted"` only listed ports are allowed. With ABI v6+ the sandbox cannot send signals to, or connect to abstract UNIX sockets of, anything outside its domain, and Landlock's cross-domain ptrace check blocks reading `/proc/<supervisor>/environ` and similar even at the same UID.

**seccomp (kernel attack surface).** The payload is an arbitrary program, so a strict allow-list would break interpreters and compilers. Instead the filter is default-allow with a deny-list of syscalls that let code escape or attack the kernel: ptrace and cross-process memory access, all mount and namespace syscalls, `bpf`, `perf_event_open`, `userfaultfd`, io_uring (whose operations bypass seccomp), keyrings, handle-based opens, module loading, kexec, clock setting and similar. Argument checks deny `clone` with any `CLONE_NEW*` flag, restrict `socket`/`socketpair` to the allowed address families, block `TIOCSTI`/`TIOCLINUX` terminal injection and limit `personality` to harmless values. The hand-written prelude kills on an unexpected architecture, returns `ENOSYS` for the x32 ABI (whose syscall numbers would otherwise slip past a deny-list) and returns `ENOSYS` for `clone3`, whose flags live in memory where BPF cannot see them; libc then falls back to `clone`, whose flags it can check. Violations return `EPERM` by default, or kill with `SIGSYS` (`kill`), or are allowed and logged (`log`, for profiling a workload).

Landlock only governs TCP, so in `restricted` mode seccomp also blocks every other IP socket kind (UDP, raw, SCTP, MPTCP via the protocol check) unless `allow_udp` is set.

**Process hygiene.** When sbx starts as root (the image default) the payload runs as `65534:65534` with no supplementary groups and no capabilities, which adds ordinary DAC protection on top of Landlock and means the payload cannot signal or inspect the root supervisor even on kernels without Landlock scoping. The environment is rebuilt from an allow-list, so platform-injected variables and secrets never reach the payload. Inherited file descriptors are closed. Core dumps are disabled and rlimits cap open files, processes (a fork-bomb brake) and file size.

## Configuration

The base policy is a TOML file: `--policy` / `SBX_POLICY_FILE`, else `/etc/sbx/policy.toml` (shipped in the image), else the same defaults compiled into the binary. [`policy/default.toml`](policy/default.toml) documents every field. On top of it, environment variables and flags apply; path grants are additive, everything else overrides.

| Flag | Env var | Meaning |
|---|---|---|
| `--policy FILE` | `SBX_POLICY_FILE` | base policy (mount it from Secret Manager to change it without rebuilding) |
| `--ro / --rw / --rx PATHS` | `SBX_FS_RO / _RW / _RX` | grant paths, `:` or `,` separated |
| `--net SPEC` | `SBX_NET` | `none`, `unrestricted`, `tcp:443,8443`, `tcp:443+udp` |
| `--timeout SECS` | `SBX_TIMEOUT` | wall-clock limit for the whole tree, exit 124 |
| `--workdir DIR` | `SBX_WORKDIR` | working directory |
| `--no-subprocesses` | `SBX_SUBPROCESSES=0` | threads only |
| `--env-pass NAMES` | `SBX_ENV_PASS` | let these variables through |
| `--seccomp-action A` | `SBX_SECCOMP_ACTION` | `errno`, `kill`, `log` |
| `--best-effort` | `SBX_BEST_EFFORT=1` | run without Landlock if the kernel lacks it (not recommended) |

`sbx policy [flags]` prints the fully resolved policy, and `sbx probe` reports what the kernel can enforce. All of these are operator inputs. Never build sbx flags from the untrusted payload; pass payload data only as arguments after `--`.

## Deploying on Cloud Run

Use Cloud Run **jobs** (or a service pinned to `--execution-environment=gen2`). The first-generation environment is gVisor, which returns `ENOSYS` for Landlock, and sbx fails closed there by design. Jobs and worker pools always run on gen2.

First verify the platform, because Google documents gen2 as a full-Linux microVM but does not document which Landlock ABI its guest kernel exposes:

```sh
gcloud run jobs create sbx-probe --image=$IMAGE --region=$REGION \
  --command=/usr/local/bin/sbx --args=probe
gcloud run jobs execute sbx-probe --region=$REGION --wait   # then read the logs
# full escape suite (needs a base image with python3 for the network/seccomp half):
gcloud run jobs create sbx-smoke --image=$IMAGE --region=$REGION \
  --command=/bin/sh --args=/opt/sbx/smoke.sh --set-env-vars=SBX=/usr/local/bin/sbx
```

A job that runs untrusted code from a bucket, with a writable scratch volume and no network:

```sh
gcloud iam service-accounts create sbx-untrusted     # grant it NOTHING except what the volumes need

gcloud run jobs create sandbox --image=$IMAGE --region=$REGION \
  --service-account=sbx-untrusted@$PROJECT.iam.gserviceaccount.com \
  --memory=1Gi --task-timeout=15m --max-retries=0 \
  --add-volume=name=work,type=in-memory,size-limit=512Mi \
  --add-volume-mount=volume=work,mount-path=/workspace \
  --add-volume=name=code,type=cloud-storage,bucket=$CODE_BUCKET,readonly=true \
  --add-volume-mount=volume=code,mount-path=/mnt/code \
  --set-env-vars=SBX_NET=none,SBX_TIMEOUT=600,SBX_FS_RO=/mnt/code

# per-execution overrides: arguments and env can change for each run
gcloud run jobs execute sandbox --region=$REGION \
  --args="--timeout=120,--,python3,/mnt/code/job-42/main.py" \
  --update-env-vars=SBX_NET=tcp:443
```

Use `:` rather than `,` between paths inside `--set-env-vars`, since gcloud splits on commas. For writable Cloud Storage volumes, make the files belong to the sandbox user with `mount-options="uid=65534;gid=65534"`, because FUSE volumes are owned by root by default and the payload runs as 65534.

**Services** have to serve HTTP on `$PORT`, so the server is the entrypoint and it spawns one sandbox per request, for example `subprocess.run(["sbx", "run", "--quiet", "--timeout", "30", "--rw", job_dir, "--workdir", job_dir, "--", "python3", "main.py"], capture_output=True)`. Give each request its own directory, because concurrent requests on one instance share `/tmp`. Landlock domains stack, so if the server process is itself sandboxed, every per-request sandbox can only be narrower. If the server runs as non-root, sbx runs the payload at the server's UID; `sbx probe` must then show ABI v6+, since signal scoping and Landlock's ptrace check are what separate the payload from the server.

## Threat model and limitations

The sandbox assumes a hostile payload and a correct kernel. It narrows what the payload can reach (files, sockets, other processes, dangerous syscalls); it does not change that the payload shares the guest kernel with the supervisor, so a kernel exploit through an allowed syscall defeats it. On Cloud Run the gen2 microVM is the outer boundary, and the platform's own isolation is what protects other tenants.

The **metadata server** at `169.254.169.254:80` hands out the service account's access token to anything that can make an HTTP request. Landlock filters by port, not address, so allowing port 80, or `unrestricted` mode, exposes it (sbx warns when you do). Run the job with a dedicated service account that has no IAM roles beyond what its volumes need.

`allow_udp` allows UDP to any destination, which is also a DNS-tunnelling exfiltration path. Glibc's resolver needs UDP unless `/etc/resolv.conf` has `options use-vc`.

Landlock's `x` controls `execve`, not code loading: the payload can still run code through an allowed interpreter or by invoking `ld.so` on a file it wrote. Treat `x` as hygiene, not a boundary. If you need to stop fileless execution, add `seccomp.deny = ["memfd_create", "execveat"]`.

Memory is bounded only by the container limit, so a payload that exhausts it takes down the whole instance, supervisor included. That is fine for one-task jobs, and is the reason to keep service concurrency at 1 for untrusted work. `RLIMIT_AS` is available but breaks Go, the JVM and V8.

Cloud Run also has a native **sandboxes** feature (public preview since July 2026) that runs code in a separate isolated environment inside a service instance, with no access to the service's environment variables or the metadata server and egress blocked by default. If you are only targeting Cloud Run, consider using it as the outer layer and sbx inside it, or instead of sbx. sbx remains useful for portability across platforms and for policy you control per execution.

## Files

```
Dockerfile            multi-stage build, static musl binary, BASE_IMAGE build arg for the payload runtime
Cargo.toml            deps: landlock 0.4.7, seccompiler 0.5, libc, serde, toml
policy/default.toml   default policy (also embedded in the binary)
src/main.rs           CLI: run / probe / policy, env scrubbing, program resolution
src/policy.rs         policy model, layering of file/env/flags, validation and warnings
src/landlock_layer.rs probe, ruleset construction, enforcement
src/seccomp_layer.rs  BPF prelude and deny-list filter
src/supervisor.rs     fork/exec, privilege drop, signal forwarding, timeout, tree cleanup
tests/smoke.sh        33 checks: escape attempts (each aimed at something DAC alone would allow) plus positive controls
```
