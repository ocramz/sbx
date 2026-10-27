#!/usr/bin/env python3
"""Cloud Run checks for sbx: what the platform provides, and egress on the real network.

Runs in the test image on the Cloud Run service that tests/cloud-run.sh deploys
(through tests/live_server.py), as root, with the policies shipped in the image.
It prints the platform facts first, then checks sbx on this platform. The egress
policy rewrites /etc/resolv.conf, so never run it on a host you care about.

Required environment:
  SBX  path to the sbx binary
"""

import ctypes
import os
import subprocess
import sys

PASS, FAIL = [], []


def ok(name):
    PASS.append(name)
    print(f"  ok   {name}", flush=True)


def bad(name, detail):
    FAIL.append(name)
    print(f"  FAIL {name}\n       {detail}", flush=True)


def check(name, cond, detail=""):
    (ok(name) if cond else bad(name, detail))


def die(msg):
    print(f"live: {msg}", file=sys.stderr)
    sys.exit(2)


SBX = os.environ.get("SBX") or die("set SBX to the sbx binary")
if os.geteuid() != 0:
    die("run as root (sbx is tested the way the container entrypoint runs it)")
if not os.access(SBX, os.X_OK):
    die(f"{SBX} is not executable")
DEFAULT = "/etc/sbx/policy.toml"
EGRESS = "/etc/sbx/egress.example.toml"
for path in (DEFAULT, EGRESS):
    if not os.path.isfile(path):
        die(f"{path} is missing (run in the test image)")
PY = os.path.realpath(sys.executable)
BASE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}


def sbx(args, pol, cmd="run", timeout=60):
    p = subprocess.run([SBX, cmd, *args], env=dict(BASE_ENV, SBX_POLICY_FILE=pol), capture_output=True, text=True,
                       timeout=timeout, stdin=subprocess.DEVNULL)
    return p.returncode, p.stdout, p.stderr


def expect(name, want, args, pol=DEFAULT, log=None, out=None, **kw):
    """want: an exit code. log/out: substrings expected in stderr/stdout."""
    rc, so, se = sbx(args, pol, **kw)
    good = rc == want and (not log or log in se) and (not out or out in so)
    check(name, good, f"rc={rc} (want {want}) stdout={so[-300:]!r} stderr={se[-600:]!r}")


# ---------------------------------------------------------------- platform


def landlock_abi():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    nr = {"x86_64": 444, "aarch64": 444}[os.uname().machine]
    abi = libc.syscall(ctypes.c_long(nr), None, ctypes.c_size_t(0), ctypes.c_uint(1))
    return f"v{abi}" if abi >= 0 else f"unavailable ({os.strerror(ctypes.get_errno())})"


def read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError as e:
        return f"unreadable ({e.strerror})"


print("== platform")
u = os.uname()
with open("/proc/self/status") as f:
    status = dict(l.split(":\t", 1) for l in f.read().splitlines() if ":\t" in l)
cap_eff = int(status["CapEff"], 16)
CAP_SYS_PTRACE = 19
RESOLV = "/etc/resolv.conf"
print(f"  kernel          {u.release} {u.version} ({u.machine})")
print(f"  Landlock ABI    {landlock_abi()}")
print(f"  CapEff          {status['CapEff'].strip()} (CAP_SYS_PTRACE {'present' if cap_eff >> CAP_SYS_PTRACE & 1 else 'absent'})")
print(f"  CapBnd          {status['CapBnd'].strip()}")
print(f"  seccomp         mode {status.get('Seccomp', '?').strip()}, {status.get('Seccomp_filters', '?').strip()} filters")
print(f"  NoNewPrivs      {status.get('NoNewPrivs', '?').strip()}")
print(f"  ptrace_scope    {read('/proc/sys/kernel/yama/ptrace_scope')}")
kind = f"symlink to {os.readlink(RESOLV)}" if os.path.islink(RESOLV) else "regular file" if os.path.isfile(RESOLV) else "missing"
print(f"  resolv.conf     {kind}: {' | '.join(read(RESOLV).splitlines())}")

print("== probe")
for name, pol in (("default policy", DEFAULT), ("egress example", EGRESS)):
    rc, so, se = sbx([], pol, cmd="probe")
    for line in (so + se).splitlines():
        print(f"       {line}")
    check(f"probe: {name}", rc == 0, f"rc={rc}")

# ---------------------------------------------------------------- sandbox

print("== sandbox (default policy)")
expect("runs a program", 0, ["--", "/bin/echo", "hello"], out="hello")
expect("drops to uid 65534", 0, ["--", "/bin/sh", "-c", 'test "$(id -u):$(id -g)" = 65534:65534'])
expect("Landlock denies files outside the policy", 1, ["--", "/bin/cat", "/etc/debian_version"],
       log="Permission denied")
expect("timeout kills the tree (exit 124)", 124, ["--timeout", "2", "--", "/bin/sleep", "30"], log="timeout after 2s")

# ---------------------------------------------------------------- egress

print("== egress (egress example policy, real network)")
CONNECT = """
import socket, sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=10).close()
except PermissionError:
    sys.exit(13)
except socket.gaierror as e:
    print("gaierror", e, file=sys.stderr)
    sys.exit(3)
"""


def connect(name, want, host, port, **kw):
    expect(name, want, ["--", PY, "-c", CONNECT, host, str(port)], pol=EGRESS, **kw)


connect("allowed name resolves and connects", 0, "api.github.com", 443, log="dns: api.github.com ->")
connect("unlisted address is denied (EACCES)", 13, "1.1.1.1", 443, log="denied connect to 1.1.1.1:443")
connect("metadata server is denied", 13, "169.254.169.254", 80, log="denied connect to 169.254.169.254:80")
connect("unlisted name gets NXDOMAIN", 3, "example.com", 443, log="dns: denied A example.com")

print(f"== {len(PASS)} passed, {len(FAIL)} failed")
for name in FAIL:
    print(f"  failed: {name}")
sys.exit(1 if FAIL else 0)
