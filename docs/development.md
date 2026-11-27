# Development

## Build and test

```sh
make lint test        # rustfmt, clippy (warnings are errors), unit tests
make image            # ghcr.io/ocramz/sbx:<git sha> on BASE_IMAGE (debian:bookworm-slim)
make smoke            # build images; integration suite in a container; checks of the runtime image
make smoke-local      # integration suite on this host (root, private mount namespace)
make probe            # sbx probe in the runtime image
make push             # push the runtime image as ghcr.io/ocramz/sbx:<git sha>-<arch>
make manifest PUSH_TAGS="main"   # podman: join ARCHS' pushed images into :<git sha> and :main
make live             # live tests on a Cloud Run service and jobs (see below)
make gvisor           # checks under gVisor in a Modal sandbox (uv, Modal credentials)
make help             # everything else
```

The Rust version comes from `rust-toolchain.toml`. `sbx version` comes from `SBX_VERSION`, which the Makefile sets to `git describe --tags --always --dirty` and passes to cargo and to the image build (a build without it reports `unknown`). Images are built for the host's architecture (`linux/amd64` or `linux/arm64`); pass `PLATFORM=` to override, though the integration suite cannot run under emulation, so CI builds and tests each architecture on a runner of its own. The build stage runs on the build machine's own architecture and cross-compiles a static musl binary on `rust:<version>-slim-bookworm`, linked with `rust-lld`, so an amd64 image can be built on an arm64 Mac (x86_64 rustc crashes under QEMU); the build fails if the binary is not static. The integration suite ([`tests/smoke.py`](../tests/smoke.py)) runs in a test image (the runtime stage on `python:3.13-slim-bookworm`) with `--cap-add SYS_PTRACE`. It covers escape attempts that only Landlock or seccomp can stop, strictness errors, egress allow/deny decisions, DNS learning and refusals, one sandbox per container, the Landlock-off mode, the policy filter without the listener (SIGSYS, `EPERM`, `denials: null`, the refusals), `shmget` denied by `seccomp.deny` with and without the listener, and two race tests: one flips the sockaddr from another thread during `connect`, the other swaps an AF_UNIX and a TCP socket under the same fd number. Both assert that the denied server never sees a connection. The suite also checks the report and the log file, and, in a container with a writable cgroup2 (`--systemd=always`, `TEST_REQUIRE_CGROUP=true`), the delegated cgroup: OOM kills, `pids.max`, refusals, and that sbx leaves its cgroup as it found it. With Docker, run `make smoke DOCKER=docker SMOKE_CGROUP=false`; the suite then checks that sbx refuses the delegated mode, as it does under `make smoke-local`. [`tests/image-checks.sh`](../tests/image-checks.sh) then exercises the runtime image as shipped (PID 1, signal forwarding, cleanup of leftover processes, the version, the report and log as PID 1, the refusal of the delegated mode on a read-only cgroupfs, and the gVisor example's probe).

## CI

CI ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) runs `make lint`, `make test` and `make smoke` on every push and pull request, on an amd64 and an arm64 runner. For pushes to `main` and tags `v*`, each runner pushes its tested image as `ghcr.io/ocramz/sbx:<sha>-amd64` or `:<sha>-arm64`, and `make manifest` joins the two into the multi-arch `:<sha>` and `:main`, or `:<tag>` and `:latest`. `:v0.3` and earlier are amd64 only.

## Checks under gVisor

`make gvisor` checks sbx under gVisor on Modal ([Without the listener](platforms.md#without-the-listener)). It builds a static linux/amd64 sbx, and [`tests/modal_gvisor.py`](../tests/modal_gvisor.py), a [uv](https://docs.astral.sh/uv/) script, uploads it with the shipped policies and runs [`tests/gvisor.py`](../tests/gvisor.py) as a sandbox's own command under gVisor, streaming its output. The suite prints the platform's facts (kernel, capabilities, both probes) and checks that the gVisor example's probe passes, that a denied call kills with SIGSYS or fails with `EPERM`, in a forked child too, that AF_UNIX sockets and `clone3`'s `ENOSYS` are as before, that `shmget` works until `seccomp.deny` names the SysV IPC calls and `mq_open` and then kills with SIGSYS, and that the report's `denials` is `null`. The facts include whether `/proc/sysvipc` exists and whether `/dev/mqueue` is mounted. It needs uv and Modal's credentials: `~/.modal.toml` (`modal token new`), or `MODAL_TOKEN_ID` and `MODAL_TOKEN_SECRET`. `uv run tests/modal_gvisor.py --runtime vm target/modal/sbx` runs the same suite in a Modal VM, as a control.

## Live tests on Cloud Run

[`tests/cloud-run.sh`](../tests/cloud-run.sh) finds out what Cloud Run's gen2 Linux provides by running sbx there. It builds the test image on this machine for `linux/amd64` (the only architecture Cloud Run runs), pushes it to Artifact Registry, creates or updates the targets (both by default), runs the tests on them and prints their logs. Every target is gen2 and runs as the runtime service account:

* **service**: the private service `sbx-live` (one instance, one request at a time) runs both suites. A service has to serve HTTP, so it runs [`tests/live_server.py`](../tests/live_server.py), which runs one suite per request (`GET /suite/live`, `GET /suite/smoke`) and streams its output back.
* **job**: the job `sbx-live-suites` runs each suite as its task, one execution per suite. The job `sbx-live-pid1` is the job from [Deploying on Cloud Run](platforms.md#deploying-on-cloud-run): the image's entrypoint `sbx run` is PID 1, configured with `SBX_POLICY_FILE` (the no-Landlock example) and `SBX_EGRESS`, with an in-memory volume as `/workspace`. It runs every case of [`tests/live_net.py`](../tests/live_net.py) in one sandbox and checks that sbx is the program's parent (PID 1), the program runs as uid 65534 and the volume is writable. A second execution overrides the arguments (`--timeout=2 -- /bin/sleep 30`), and sbx's exit code 124 must fail the task. A job's output reaches the script only through Cloud Logging, so the script waits for each execution to finish and for its last line to be logged, then prints and checks the log.

The suites:

* [`tests/live.py`](../tests/live.py) prints the platform facts (kernel, Landlock ABI, the container's capabilities and seccomp state, Yama, `/etc/resolv.conf`, `/etc/hosts`, the active LSMs, Landlock symbols in `/proc/kallsyms`, whether newer syscalls reach the kernel, and `sbx probe` for the three shipped policies). It then checks the sandbox, and egress filtering on the real network with names resolved through the metadata server's DNS. The egress cases are those of [`tests/live_net.py`](../tests/live_net.py), each in its own sbx run, with the example policy's rules (`api.github.com:443`, `*.githubusercontent.com:443`) plus `1.1.1.1/32:443`, `www.github.com:443` and `metadata.google.internal:80` in `SBX_EGRESS`. Allowed: a name, a verified TLS session with an HTTP reply, a name below the wildcard, a name answered with a CNAME, the CIDR address, and a non-blocking connect to it. Denied, each with the line sbx logs: an allowed name and the CIDR address on another port, the address next to the CIDR block, a public resolver over TCP, the metadata server by address and by an allowed name (which on Cloud Run comes from `/etc/hosts`), a link-local DNS answer for that name asked of the proxy directly (never learned), and, with NXDOMAIN, the wildcard's bare domain and an unlisted name. The cases need github.com, Cloudflare (1.1.1.1, 1.0.0.1), Google DNS (8.8.8.8) and the metadata DNS to answer from Cloud Run. live.py runs these checks with the Landlock policies if the kernel has Landlock ABI 6, and always with the no-Landlock example, which adds the checks that AF_UNIX connects and binds are refused.
* [`tests/smoke.py`](../tests/smoke.py), the integration suite.

The service and the suites job set `TEST_REQUIRE_LANDLOCK=false` and `TEST_REQUIRE_CGROUP=false` (`make smoke` sets both to `true`, the default). live.py also prints the platform's cgroup setup and what `sbx probe` says about a delegated cgroup there. On a kernel without Landlock ABI 6, both suites then check that sbx refuses the Landlock policies, report the Landlock-only tests as n/a, and run everything else with `landlock.abi = "off"`. So `make live` passes on Cloud Run when everything that can run there works. A failure can be a finding about the platform rather than a bug in sbx: for example, without `CAP_SYS_PTRACE` the egress mode cannot run at all.

```sh
make live                               # tests/cloud-run.sh all: up, deploy, test, logs
make live-down                          # delete the service, the jobs and the repository
tests/cloud-run.sh up|deploy|test|logs|down    # one step at a time
TARGETS=job make live                   # only the jobs
```

The script authenticates only with a service account JSON key, activated in a throwaway gcloud configuration, so your own gcloud login is never used or changed. The registry login uses a one-hour access token derived from the key and is written to a temporary file, never to the engine's configuration. Settings come from the environment or from `.env` at the repository root (ignored by git; the environment wins):

```sh
GCP_KEY_FILE=/path/outside/the/repo/key.json   # required
GCP_REGION=europe-west1                        # required
GCP_PROJECT=...                                # default: the key's project_id
GCP_RUNTIME_SA=...                             # default: <key's account>-runtime@PROJECT.iam.gserviceaccount.com
DOCKER=podman                                  # as in the Makefile
TARGETS="service job"                          # default; or only service, or only job
```

The service scales to zero between runs. Each `make live` deploys a new revision, even when nothing changed, so the suites always start on a fresh instance; every job execution starts on one anyway. `make live-down` removes the service, the jobs with their executions, and the repository. Run one at a time per project, since the names are fixed.

One-time setup, with your own login (a dedicated project is best):

```sh
P=my-project
SA=sbx-testing@$P.iam.gserviceaccount.com
gcloud services enable run.googleapis.com artifactregistry.googleapis.com logging.googleapis.com --project=$P
gcloud iam service-accounts create sbx-testing --project=$P            # the key's identity
gcloud iam service-accounts create sbx-testing-runtime --project=$P    # the targets' identity: no roles
for role in run.developer run.invoker artifactregistry.admin logging.viewer; do
  gcloud projects add-iam-policy-binding $P --role=roles/$role --member=serviceAccount:$SA --condition=None
done
gcloud iam service-accounts add-iam-policy-binding sbx-testing-runtime@$P.iam.gserviceaccount.com \
  --role=roles/iam.serviceAccountUser --member=serviceAccount:$SA --project=$P
gcloud iam service-accounts keys create /path/outside/the/repo/key.json --iam-account=$SA
```

The key can deploy and call Cloud Run services, create and run jobs, create, push to and delete Artifact Registry repositories, and read logs in that project; it can act as `sbx-testing-runtime` and no other service account. Organisations that enforce `iam.disableServiceAccountKeyCreation` refuse the last command. To remove everything, run `make live-down`, then delete both service accounts (which also revokes the key).

## Files

```
Dockerfile                       build (static musl binary), runtime and test stages
Makefile                         build, lint, test, image, smoke, push, live targets
rust-toolchain.toml              the Rust version, for cargo, CI and the image build
README.md                        introduction and setup
docs/*.md                        user documentation, linked from the README
docs/implementation.md           log of what has been implemented
docs/plans/                      implementation plans
policy/default.toml              shipped policy (no network)
policy/egress.example.toml       egress rules + DNS proxy example
policy/no-landlock.example.toml  the egress example with landlock.abi = "off"
policy/gvisor.example.toml       for gVisor: no Landlock, no seccomp listener, no network
src/main.rs                      CLI: run / probe / policy / version, environment, program lookup, report
src/policy.rs                    policy model, overrides, validation
src/report.rs                    setup stages, the run's outcome, the JSON report
src/memory.rs                    memory by kind: /proc (through pinned /proc/<pid> directories), SysV, tmpfs and memory.stat sampling, peaks
src/series.rs                    the memory time series: kept samples, ranked processes, the process table, the memory bound, the columns
src/series/codec.rs              the series' columns in memory: deltas, zigzag and LEB128 varints
src/destination.rs               safe paths for the report, the series and the log file, atomic writes
src/cgroup.rs                    delegated cgroup: setup, limits, counters, teardown
src/landlock_layer.rs            Landlock probe, ruleset, enforcement
src/seccomp_layer.rs             rule table, BPF prelude and policy filter (with or without the listener), evaluator
src/notify.rs                    seccomp user notification: listener, dispatcher, denials
src/egress.rs                    connect() decisions and emulation
src/dns.rs                       DNS proxy, wire format, resolv.conf
src/net.rs                       CIDR, domain patterns, address classes, sockaddr parsing
src/capabilities.rs              requirement checks (probe, run)
src/supervisor.rs                fork/exec, identity and capability drop, signals, timeout, cleanup
src/log.rs                       logging to stderr or the log file, escaping, fatal errors
tests/smoke.py                   integration suite (run as root in a disposable environment)
tests/run-local.sh               runs the suite on a host inside a private mount namespace
tests/image-checks.sh            checks of the runtime image as shipped
tests/cloud-run.sh               live tests: build, push, deploy a Cloud Run service and jobs, run the tests, logs
tests/live.py                    Cloud Run platform facts and checks (run on the service and a job)
tests/live_net.py                egress cases on the real network (run by live.py, and by a job with sbx as PID 1)
tests/live_server.py             HTTP front that runs the suites on the service
tests/gvisor.py                  checks under gVisor, as a Modal sandbox's own command (seccomp.notify = "off")
tests/modal_gvisor.py            uv script: runs tests/gvisor.py in a Modal sandbox (make gvisor)
```
