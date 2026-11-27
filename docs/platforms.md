# Platforms

Kernels and sandboxes without Landlock or without seccomp user notification, and what sbx has found on Cloud Run.

## Without Landlock

Some kernels are built without Landlock, including Cloud Run's ([Deploying on Cloud Run](#deploying-on-cloud-run)). sbx never falls back on its own: the policy has to say `landlock.abi = "off"`. [`policy/no-landlock.example.toml`](../policy/no-landlock.example.toml) is the egress example in that form. sbx then refuses whatever only Landlock could enforce, and compensates where it can:

| Without Landlock | What sbx does |
|---|---|
| **Files are protected by their permissions only.** The program (uid 65534, no capabilities) can read everything world-readable in the image and volumes, write everything world-writable or owned by its uid, and run any world-executable binary. | Nothing can replace this. `[[fs]]` rules, `--ro/--rw/--rx` and `SBX_FS_*` are refused, so the policy never promises more than sbx enforces. |
| Signal and abstract-socket scoping, and Landlock's check on `/proc/<pid>/mem` | Not needed with one sandbox per container: the supervisor runs as root, so the program (another uid, no capabilities) cannot signal it or open its `/proc` files. sbx refuses to start if another process already runs as the sandbox uid. |
| Egress: Landlock denies TCP connects made inside the sandbox, which makes it safe to let the kernel run `connect()` on non-IP sockets ([Egress filtering](egress.md), step 2) | `connect()` on non-IP sockets (AF_UNIX) is denied in egress mode. Otherwise a thread could swap a TCP socket onto the fd and connect anywhere, metadata server included. |
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

## Without the listener

Some sandboxes have no seccomp user notification: gVisor refuses `SECCOMP_FILTER_FLAG_NEW_LISTENER` with `EINVAL` (measured on Modal's gVisor, `4.19.0-gvisor`, in November 2026), while plain seccomp filters work there, their verdicts, stacking and inheritance across `fork` and `execve` included. sbx never falls back on its own: the policy has to say `seccomp.notify = "off"` (`"listener"` is what v0.5 did). [`policy/gvisor.example.toml`](../policy/gvisor.example.toml) is a policy for gVisor. The policy filter then returns `on_violation`'s verdict itself, and the kernel applies it:

| Without the listener | What sbx does |
|---|---|
| **Denials are not seen.** With the listener, every match reaches the supervisor, which logs the syscall and its reason and counts it in the report. | Nothing can replace this. The report's `denials` is `null` (unknown, not none), and sbx warns at setup. With `on_violation = "errno"` the call fails with `EPERM` and the program may go on, so a denial is invisible. With `"kill"` the kernel kills the whole process with SIGSYS before the call runs: a denial by the program's own process shows as `"program": {"signaled": 31}` and exit code 159 (sbx's log says so), without the syscall's name; a descendant's shows only to its parent. So take `"kill"`. |
| Egress mode: the supervisor decides each `connect()` through the listener | `network.mode = "egress"` is refused. |
| `on_violation = "kill"` | SIGSYS from the kernel instead of SIGKILL from the supervisor: exit 159, not 137. |
| `sendmsg` is reserved, to hand the listener over | `seccomp.deny` may include `sendmsg`. `execve` stays reserved. |

Everything else is unchanged: the deny-list and argument checks, `socket_families`, the prelude, `no_new_privs`, the empty capability sets, the uid switch, rlimits, the scrubbed environment, closed file descriptors and the timeout. `sbx probe` runs the check `seccomp filter` instead of `seccomp user notification`: in a forked child, the prelude and a one-rule filter, and the kernel's verdict on a match.

Under gVisor, also:

* `landlock.abi = "off"`, since gVisor has no Landlock, with the conditions in [Without Landlock](#without-landlock); and `cgroup.mode = "off"`, since its `/sys/fs/cgroup` is a read-only tmpfs of v1 hierarchies.
* Memory sampling (`[measure]`) needs `CAP_SYS_PTRACE`, which a Modal sandbox's own command lacks under gVisor (its bounding set is `a80405fb`, an `exec`'d process's `a80c05fb`), so a job run that way cannot sample memory.
* Within the sandbox, gVisor is the kernel the program attacks, which narrows what a syscall that sbx's filter misses could reach.
* gVisor has SysV IPC but no `/proc/sysvipc`, and its `shmctl`/`msgctl` cannot walk the objects (`SHM_STAT` is taken as `IPC_STAT`, by id, and there is no `SHM_STAT_ANY`). So nothing outside the program can find a segment, semaphore set or message queue that it leaves behind for the next run. Where that matters, add `seccomp.deny = ["msgget", "semget", "shmget"]`, and `"mq_open"` where `/dev/mqueue` is not mounted (or not emptied between runs), as in a Modal sandbox. A program that calls one is killed with SIGSYS. POSIX shared memory in `/dev/shm` and file descriptors stay allowed, which covers PyTorch's DataLoader, NCCL, Python's `multiprocessing` and glibc's POSIX semaphores. As with any denial without the listener, a forked child's denial shows only to its parent, but what the child would have made is never made.

`make gvisor` checks this on Modal ([Checks under gVisor](development.md#checks-under-gvisor)).

## Deploying on Cloud Run

**Cloud Run does not support Landlock.** `make live` has shown this ([Live tests on Cloud Run](development.md#live-tests-on-cloud-run), October 2026, europe-north1):

* The first-generation environment is gVisor, which returns `ENOSYS` for Landlock.
* The second-generation guest kernel is Linux 6.9.12 built without Landlock. `landlock_create_ruleset` returns `ENOSYS`. The kernel's active LSMs are capability, lockdown, loadpin, selinux and bpf. `/proc/kallsyms` has no Landlock symbols. The container's seccomp profile is not the cause: newer syscalls such as `fchmodat2`, `statmount` and `listmount` reach the kernel. Even if Google enabled Landlock, 6.9 provides at most ABI 4, below the default policy's 6.

Everything else sbx needs is there: seccomp user notification, `pidfd_getfd`, all capabilities except `CAP_SYS_MODULE`, `CAP_SYS_RAWIO` and `CAP_MKNOD`, no Yama, and a writable `/etc/resolv.conf`. Services and jobs run the same kernel with the same capabilities. On both, the no-Landlock example's egress filtering works on the real network, and in a job sbx runs as PID 1, an in-memory volume is writable by the sandbox uid, and sbx's exit code reaches the task (124 on timeout fails it). Outbound IPv6 works too, so AAAA answers are learned and used. The shipped Landlock policies therefore cannot run on Cloud Run. Use [`policy/no-landlock.example.toml`](../policy/no-landlock.example.toml) under the conditions in [Without Landlock](#without-landlock). Google does not document its gen2 kernel, so run `make live` again to see whether this has changed.

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
