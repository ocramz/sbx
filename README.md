# sbx

**Run untrusted code in a container under Landlock, seccomp and an egress allow-list, with no privileges.**

sbx is a small (about 1.2 MB, static) Rust launcher that becomes the container's PID 1, builds a sandbox from a policy you supply, and runs the untrusted program inside it. It uses unprivileged kernel APIs only: no `--privileged`, no `CAP_SYS_ADMIN`, no user namespaces. If the kernel or the container cannot enforce every protection the policy asks for, sbx refuses to start and says why.

## Example

The image's entrypoint is `sbx run` with the shipped policy, [`policy/default.toml`](policy/default.toml):

```console
$ docker run --rm ghcr.io/ocramz/sbx:latest -- /bin/bash -c '
  id
  cat /etc/hostname              # world-readable, but not in the policy
  echo > /dev/tcp/1.1.1.1/443    # the policy allows no network
  echo hello > /workspace/out && cat /workspace/out'
sbx: info: landlock: ABI v6 (kernel v6), 16 path rules, tcp bind+connect denied, scopes [signal, abstract-unix]
sbx: info: seccomp: 61 rules on 54 syscalls (335 BPF instructions), notify=listener, on_violation=errno, socket families [unix]
sbx: info: started pid 3
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
cat: /etc/hostname: Permission denied
sbx: error: seccomp: denied socket for bash[pid 3]: address family not in seccomp.socket_families
/bin/bash: socket: Operation not permitted
/bin/bash: line 4: /dev/tcp/1.1.1.1/443: Operation not permitted
hello
sbx: info: exit 0 after 0.0s
```

The program runs as uid 65534 with no capabilities. It may read and execute `/usr`, read a few files in `/etc` and `/proc`, and write `/tmp` and `/workspace`. Landlock refuses every other path, and seccomp refuses every socket but AF_UNIX. sbx logs each syscall it denies and exits with the program's exit code.

The default policy needs Linux 6.12 or later (Landlock ABI 6) on the host. On an older kernel, sbx refuses to start and names what is missing.

## What sbx enforces

* **Files**: Landlock rules grant read, write or execute per path, and nothing else is reachable. Landlock also handles TCP bind and connect, and scopes signals and abstract UNIX sockets to the sandbox ([the layers](docs/how-it-works.md#the-layers)).
* **Syscalls**: a seccomp deny-list of the calls that let code escape or attack the kernel (ptrace, mount and namespaces, `bpf`, io_uring, keyrings and more), and a fixed set of socket families. sbx logs and counts each denial.
* **Network**: none, or an allow-list of CIDR blocks and domain names. The supervisor decides each `connect()` and makes it itself, and a DNS proxy enforces the domain rules ([egress](docs/egress.md)).
* **Process**: uid 65534, empty capability sets, `no_new_privs`, rlimits, a scrubbed environment and closed file descriptors. Child processes inherit all of it and cannot remove it.
* **PID 1**: signal forwarding, zombie reaping, a wall-clock timeout (exit 124), and every leftover process killed when the program exits ([architecture](docs/how-it-works.md#architecture)).
* **Outcome**: a root-owned JSON report of how the run ended, the sandbox's memory by kind, and a time series of every memory sample ([report](docs/report.md)).
* **Limits**: `memory.max` and `pids.max` in a cgroup of its own, where the platform delegates one ([cgroup limits](docs/cgroup.md)).
* **Strictness**: no built-in defaults, no best-effort mode, no fallbacks. Every field of the policy must be present, and Landlock or the seccomp listener can be turned off only in the policy file ([platforms](docs/platforms.md)).

## Setup

### Your own image

The shipped image is Debian slim, without language runtimes. Copy sbx and its policies into an image that has yours:

```dockerfile
FROM python:3.13-slim-bookworm
COPY --from=ghcr.io/ocramz/sbx:latest /usr/local/bin/sbx /usr/local/bin/sbx
COPY --from=ghcr.io/ocramz/sbx:latest /etc/sbx/ /etc/sbx/
ENV SBX_POLICY_FILE=/etc/sbx/policy.toml
# `sbx policy` fails the build if a path in the policy does not exist in this image
RUN mkdir -p /workspace && chmod 1777 /workspace && sbx policy --quiet
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/sbx", "run"]
```

```sh
docker build -t my-sandbox .
docker run --rm -v "$PWD/app:/code:ro" my-sandbox --ro /code -- python3 /code/main.py
```

* Leave the container's user as root (the image default). sbx needs root only to switch the program to uid 65534 and empty its capability sets, and it never runs the program's code itself.
* Grant paths per run with `--ro`, `--rw` and `--rx`, or `SBX_FS_RO`, `SBX_FS_RW` and `SBX_FS_RX`. For anything else, copy a policy, edit it, and point `SBX_POLICY_FILE` at it. Flags and variables: [configuration](docs/configuration.md).
* Pin a release tag or a digest instead of `:latest`. `make image BASE_IMAGE=python:3.13-slim-bookworm` builds the image from source on any base.

### Network egress

To let the program reach some hosts and nothing else, start from [`policy/egress.example.toml`](policy/egress.example.toml). Copy it, put your rules in `egress` and your platform's resolver in `[network.dns] upstream` (the example has Cloud Run's metadata resolver), and add it to your image:

```dockerfile
COPY egress.toml /etc/sbx/policy.toml
```

The container needs `CAP_SYS_PTRACE` (on Kubernetes, `securityContext.capabilities.add: [SYS_PTRACE]`). The program never gets it. Add rules per run with `--egress` or `SBX_EGRESS`:

```sh
docker run --rm --cap-add=SYS_PTRACE my-sandbox --egress pypi.org:443 -- python3 -c \
  'import urllib.request; print(urllib.request.urlopen("https://pypi.org/simple/").status)'
```

Names that no rule matches get NXDOMAIN, and connects anywhere else fail with `EACCES`. sbx logs both. Only TCP leaves the sandbox, and names are resolved over TCP: glibc and Go resolvers do this, musl (Alpine) resolvers do not and need IP rules. Details: [egress filtering](docs/egress.md).

### Batch jobs: how the run ended

```sh
docker run --rm -v sbx-out:/out my-sandbox \
  --timeout 600 --report /out/report.json --log /out/sbx.log -- python3 /code/main.py
```

* `--report` writes JSON once the sandbox is gone: the exit code or signal, the timeout, the setup stage that failed, denied syscalls, leftover processes, wall and CPU time, and peak memory. Its directory must be owned by root and writable by nobody else, so the program cannot touch it.
* `--log` keeps sbx's own lines out of the program's stderr.
* `[measure] memory_sample_ms` adds the sandbox's memory by kind to the report (anonymous, file-backed, shared, memfd, SysV, tmpfs), and `--series` writes every sample. Sampling needs `CAP_SYS_PTRACE`.
* `[cgroup] mode = "delegated"` puts the sandbox in a cgroup with `memory.max` and `pids.max`, so an OOM kill hits the program, not sbx. This needs a delegated cgroup v2 (podman `--systemd=always`). Plain Docker and Kubernetes do not give one.

Details: [report, log and memory](docs/report.md), [cgroup limits](docs/cgroup.md).

### A server that runs one sandbox per request

When the container's entrypoint is your own server (a Cloud Run service, or a worker that takes jobs from a queue), the server starts sbx for each job, with `SBX_POLICY_FILE` set:

```python
subprocess.run(["sbx", "run", "--quiet", "--timeout", "30", "--workdir", job_dir, "--rw", job_dir,
                "--", "python3", "main.py"], capture_output=True)
```

* sbx runs one sandbox per container (per pod on Kubernetes): a second `sbx run` while one is running exits 125. Handle one job at a time. On Cloud Run, deploy with `--concurrency=1`.
* Create each job directory owned by uid 65534 with mode 0700. Sandboxes run one after another as the same uid, so before the next one starts, remove what the previous one left: its job directory and its files in `/tmp`.
* sbx's flags are operator input. Never build them from the payload. Pass payload data only as arguments after `--`.
* For cgroup limits, give each sbx a cgroup of its own ([A server that spawns sbx](docs/cgroup.md)).

### Cloud Run

Cloud Run's kernels have no Landlock: the first generation is gVisor, and the second runs Linux 6.9 built without it. So the shipped Landlock policies cannot run there. [`policy/no-landlock.example.toml`](policy/no-landlock.example.toml) turns Landlock off explicitly. Files are then protected by their permissions only, so use it only if:

* sbx starts as root (the image default) and runs the program as a uid nothing else in the container uses. sbx checks both.
* Nothing the program must not read is world-readable: application code, configuration, mounted secrets.
* Volumes with code to run are mounted read-only.

Use jobs, or a service pinned to `--execution-environment=gen2`, and check the platform first:

```sh
gcloud run jobs create sbx-probe --image=$IMAGE --region=$REGION \
  --command=/usr/local/bin/sbx --args=probe --set-env-vars=SBX_POLICY_FILE=/etc/sbx/no-landlock.example.toml
gcloud run jobs execute sbx-probe --region=$REGION --wait    # then read the logs
```

A job that runs untrusted code from a bucket, with a writable scratch volume and no network. `/etc/sbx/job.toml` is a copy of the no-Landlock example with `mode = "none"` (no egress rules, no `[network.dns]`, `socket_families = ["unix"]`), built into your image:

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

gcloud run jobs execute sandbox --region=$REGION \
  --args="--timeout=120,--,python3,/mnt/code/job-42/main.py"
```

The service account matters: the metadata server hands its token to anything that can make an HTTP request to it. For a service, see [A server that runs one sandbox per request](#a-server-that-runs-one-sandbox-per-request). Details, including what was measured on Cloud Run and gcloud's quirks: [Deploying on Cloud Run](docs/platforms.md#deploying-on-cloud-run).

### gVisor (Modal sandboxes)

gVisor has neither Landlock nor seccomp user notification. [`policy/gvisor.example.toml`](policy/gvisor.example.toml) turns both off explicitly, along with the cgroup and the network:

```sh
sbx probe --policy /etc/sbx/gvisor.example.toml                    # check the platform first
sbx run --policy /etc/sbx/gvisor.example.toml -- python3 main.py
```

The conditions for running without Landlock above apply. Without the listener, the kernel applies seccomp's verdicts itself and sbx cannot see them: a denied call kills the process with SIGSYS (exit 159), and the report's `denials` is `null`. There is no egress mode. Where SysV IPC objects left behind by one run matter to the next, uncomment the example's `seccomp.deny` line. Details: [without the listener](docs/platforms.md#without-the-listener).

### Check a setup before deploying

```sh
docker run --rm --entrypoint /usr/local/bin/sbx my-sandbox probe     # every requirement of the policy, here
docker run --rm --entrypoint /usr/local/bin/sbx my-sandbox policy    # the effective policy
```

Both take the same flags and `SBX_*` variables as `sbx run`. `sbx probe` exits 1 if a requirement is missing. Exit codes of `sbx run`: the program's own, 124 on timeout, 125 for sbx errors, 127 if the program cannot be executed, 128+N if it was killed by signal N. Every field of a policy is required, so after an upgrade sbx refuses an older policy until the new fields are added ([Upgrading](docs/configuration.md#upgrading)).

## Limits

sbx assumes a hostile program and a correct kernel. The program shares the kernel with the supervisor, so a kernel exploit through an allowed syscall defeats it. On Cloud Run the gen2 microVM is the outer boundary. Egress rules are IP-level: other sites on an allowed address are reachable too. Memory is bounded only by the container's limit unless a cgroup is delegated. See [Threat model and limitations](docs/how-it-works.md#threat-model-and-limitations).

## Documentation

* [How sbx works](docs/how-it-works.md): requirements and mechanisms, the architecture, the layers, the threat model.
* [Configuration](docs/configuration.md): the policy file, upgrading, flags and `SBX_*` variables, commands, exit codes, kernel and container requirements.
* [Egress filtering](docs/egress.md): how each `connect()` is decided, and the DNS proxy.
* [Report, log and memory](docs/report.md): the JSON report, the log file, memory by kind, the time series.
* [cgroup limits](docs/cgroup.md): memory and process limits in a delegated cgroup, and where one comes from.
* [Platforms](docs/platforms.md): without Landlock, without the seccomp listener (gVisor), Cloud Run.
* [Development](docs/development.md): build and test, CI, live tests on Cloud Run and under gVisor, the source files.
* [CHANGELOG.md](CHANGELOG.md).

## Build from source

```sh
make lint test    # rustfmt, clippy (warnings are errors), unit tests
make image        # ghcr.io/ocramz/sbx:<git sha> on BASE_IMAGE (debian:bookworm-slim)
make smoke        # build images; integration suite in a container
make help         # everything else
```

The Makefile uses podman; pass `DOCKER=docker` for Docker. See [Development](docs/development.md).
