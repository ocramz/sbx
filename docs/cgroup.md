# cgroup limits

`[cgroup]` is required in every policy. `mode = "off"` (the shipped policies) leaves the sandbox in sbx's own cgroup, bounded only by the container's limits. `mode = "delegated"` runs it in a cgroup of its own:

```toml
[cgroup]
mode = "delegated"
memory_mb = 512        # memory.max, with memory.swap.max = 0 and memory.oom.group = 1
pids = 256             # pids.max: processes and threads
```

Both limits are required with `"delegated"` (a number or `"unlimited"`) and refused with `"off"`. sbx's cgroup C (from `/proc/self/cgroup`) must be delegated to it: cgroup v2 at `/sys/fs/cgroup`, writable, with the `memory` and `pids` controllers available, and no other process in C. cgroup v2 keeps processes out of cgroups whose controllers are enabled for their children, so sbx moves itself into `C/sbx-supervisor`, enables the controllers for C's children, and creates `C/sbx-sandbox` with the limits. The child joins `C/sbx-sandbox` before it drops its privileges, so the program and everything it starts are charged there. An OOM kill then hits the whole sandbox (`memory.oom.group`), never the supervisor, and the report records it. On exit, sbx kills what is left with `cgroup.kill`, reads the counters and puts C back as it was. `memory_mb` must be below C's own `memory.max`, or the container's OOM killer would act first and might pick sbx. sbx refuses `"delegated"` unless it starts as root, and refuses to start if any of this is not the case, naming the reason. `sbx probe` creates and removes a trial sandbox cgroup.

`memory_mb` counts everything the sandbox charges, including the page cache and files it writes to tmpfs, such as a Cloud Run in-memory volume. Such files stay charged after the processes exit, until they are removed. While sbx runs, no process can join C (`docker exec` and `kubectl exec` may fail or land in `C/sbx-supervisor`, depending on the runtime).

Where a delegated cgroup comes from:

* **podman**: `podman run --systemd=always` mounts a writable cgroup2 in the container's own cgroup namespace. `make smoke` runs the suite that way.
* **Docker and Kubernetes** mount `/sys/fs/cgroup` read-only unless the container is privileged, which the sandbox does not need otherwise. sbx then says `/sys/fs/cgroup is mounted read-only`.
* **A server that spawns sbx** (the Cloud Run service pattern) shares the container's cgroup with it, so C is never sbx's alone. The server must give each sbx a cgroup of its own, e.g. `mkdir /sys/fs/cgroup/job-42` and start sbx with a `preexec_fn` that writes `0` to its `cgroup.procs`, with the controllers enabled in the parent and the server itself moved out of the root cgroup. On recent kernels the reaped sbx can still count in its cgroup for a moment, so retry `rmdir` of that cgroup while it fails with EBUSY.
* **Cloud Run**: `make live` prints what the platform provides ([Live tests on Cloud Run](development.md#live-tests-on-cloud-run)).
