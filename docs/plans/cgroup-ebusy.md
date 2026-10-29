# Delegated cgroup: retry EBUSY in setup and teardown (issue #8)

## Context

Kernel commit d245698d727a ("cgroup: Defer task cgroup unlink until after the task is done switching out") unlinks an exiting task from its cgroup only after its final context switch. That can come after its parent has reaped it, or another thread has joined it. Until then `cgroup.procs` no longer lists the task, but `cgroup_has_tasks()` and `cgroup_is_populated()` still count it.

sbx makes writes that need an empty cgroup right after its own tasks exit:

1. **Setup.** `capabilities::require` (`sbx run`) and `capabilities::check` (`sbx probe`) fork check children while sbx is still in C. `Delegation::setup` then finds only itself in `cgroup.procs`, moves into `sbx-supervisor`, and writes `+memory +pids` to `C/cgroup.subtree_control`. A reaped check child that is still exiting makes that write fail with EBUSY: stage `cgroup`, exit 125. This happened in 2 of about 100 delegated runs on GitHub's ubuntu-24.04 runner.
2. **Teardown.** `Changes::undo` writes sbx's pid to `C/cgroup.procs`. A thread with PF_EXITING set is not migrated. That covers the joined dispatcher and a finished `sbx-connect` or `sbx-dns-conn` thread, which stays in `sbx-supervisor`. The `rmdir` of `sbx-supervisor` then fails with EBUSY. sbx only logs this, and the leftover cgroup makes the next sbx in C refuse to start.

## Design

All changes are in `src/cgroup.rs`.

- `retry_busy(what, op)`: runs `op` (an `io::Result<()>`). On EBUSY it sleeps 10 ms (the step `Delegation::finish` polls at) and tries again for up to 2 s. It then fails with `"{what}: {e}, still after 2s"`. Any other error fails at once as `"{what}: {e}"`. At the call sites only sbx's own exiting tasks can keep the cgroup busy: setup has checked that C holds only sbx, and `finish` has waited for `sbx-sandbox` to depopulate.
- `write` is split into `write_io` (the I/O, `io::Result`) and `write` (unchanged message and signature).
- `subtree_control(base, value)` writes `C/cgroup.subtree_control` through `retry_busy`. It is used for `+memory +pids` in setup and `-memory -pids` in undo. The kernel does not return EBUSY for tasks when controllers are disabled. Both writes share the helper anyway, which costs nothing.
- `rmdir` becomes `retry_busy` around `std::fs::remove_dir`, which keeps the errno and drops the `unsafe libc::rmdir`. It is only called for `sbx-sandbox` and `sbx-supervisor` in `Changes::undo`.

Not done: waiting until the check children have fully exited. Userspace has nothing to wait on, because waitpid and pidfds report the exit before the final context switch. The retry is the only signal.

## Tests

- No unit test for `retry_busy`: it would need a scripted fake `op`.
- Smoke (`tests/smoke.py`, delegated branch of "cgroup limits"): 50 rounds of `sbx probe` and `sbx run -- /bin/true`, all in one cgroup, so a leftover `sbx-supervisor` also fails the next round. After each run the check requires exit 0, no `setup_error`, and C restored (empty `cgroup.subtree_control`, no child cgroups).
- Smoke, same section: a test that works on any kernel. A harness thread moves a `sleep` into `C/sbx-supervisor` while the program runs. It kills that `sleep` 0.2 s after teardown has removed `sbx-sandbox`. sbx must still exit 0, log no "restoring sbx's cgroup" error and leave C restored.

## Docs

- CHANGELOG (Unreleased, Fixed).
- README, "cgroup limits", "A server that spawns sbx": retry `rmdir` of C on EBUSY briefly after sbx exits.
- `docs/implementation.md` entry.

## Verification

- `make lint`, `make test`.
- `make smoke` locally. The podman VM runs kernel 6.12, which does not have the change, so this only checks for regressions.
- CI `make smoke` on the ubuntu-24.04 runners, whose kernel failed.
