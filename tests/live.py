#!/usr/bin/env python3
"""Cloud Run checks for sbx: what the platform provides, and egress on the real network.

Runs in the test image on the Cloud Run service that tests/cloud-run.sh deploys
(through tests/live_server.py), as root, with the policies shipped in the image.
It prints the platform facts first, then checks sbx on this platform: with the
shipped Landlock policies if the kernel has Landlock, and with the no-Landlock
example in any case. The egress policies rewrite /etc/resolv.conf, so never
run it on a host you care about.

Required environment:
  SBX  path to the sbx binary

Optional:
  TEST_REQUIRE_LANDLOCK  true (default): fail when the kernel lacks Landlock ABI 6,
                         which the shipped Landlock policies pin. false (Cloud Run):
                         then check that sbx refuses them and report their checks as n/a
"""

import ctypes
import errno
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
NO_LANDLOCK = "/etc/sbx/no-landlock.example.toml"
for path in (DEFAULT, EGRESS, NO_LANDLOCK):
    if not os.path.isfile(path):
        die(f"{path} is missing (run in the test image)")
REQUIRE_LANDLOCK = os.environ.get("TEST_REQUIRE_LANDLOCK", "true")
if REQUIRE_LANDLOCK not in ("true", "false"):
    die("TEST_REQUIRE_LANDLOCK must be true or false")
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


LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long
# Syscall numbers from 424 on are the same on x86_64 and aarch64.
NR_LANDLOCK_CREATE_RULESET = 444
NR_LSM_LIST_MODULES = 461
# Syscalls every Linux 6.9 build has, called with arguments the kernel rejects.
# ENOSYS from one of them comes from the container's seccomp filter, not the kernel.
NEWER_SYSCALLS = {439: "faccessat2", 441: "epoll_pwait2", 442: "mount_setattr", 448: "process_mrelease",
                  449: "futex_waitv", 452: "fchmodat2", 454: "futex_wake", 457: "statmount", 458: "listmount"}
# include/uapi/linux/lsm.h
LSM_IDS = {100: "capability", 101: "selinux", 102: "smack", 103: "tomoyo", 104: "apparmor", 105: "yama",
           106: "loadpin", 107: "safesetid", 108: "lockdown", 109: "bpf", 110: "landlock", 111: "ima", 112: "evm",
           113: "ipe"}


def errname(e):
    return errno.errorcode.get(e, str(e))


KABI = LIBC.syscall(ctypes.c_long(NR_LANDLOCK_CREATE_RULESET), None, ctypes.c_size_t(0), ctypes.c_uint(1))
KABI_ERRNO = ctypes.get_errno()
# The shipped Landlock policies pin ABI 6.
LANDLOCK = KABI >= 6


def landlock_abi():
    return f"v{KABI}" if KABI >= 0 else f"unavailable ({os.strerror(KABI_ERRNO)})"


def active_lsms():
    ids = (ctypes.c_uint64 * 32)()
    size = ctypes.c_uint32(ctypes.sizeof(ids))
    n = LIBC.syscall(ctypes.c_long(NR_LSM_LIST_MODULES), ids, ctypes.byref(size), ctypes.c_uint32(0))
    if n < 0:
        return f"unavailable ({errname(ctypes.get_errno())})"
    return ", ".join(LSM_IDS.get(ids[i], str(ids[i])) for i in range(n))


def landlock_symbols():
    """Landlock's own kernel symbols. A kernel built without Landlock has only the syscall stubs."""
    try:
        with open("/proc/kallsyms") as f:
            names = [line.split()[2] for line in f if "landlock" in line]
    except OSError as e:
        return f"unreadable ({e.strerror})"
    own = [n for n in names if "sys_landlock" not in n]
    return f"{len(own)} (built in), e.g. {', '.join(own[:3])}" if own else f"none besides {len(names)} syscall stubs"


def newer_syscalls():
    out = []
    for nr, name in NEWER_SYSCALLS.items():
        r = LIBC.syscall(ctypes.c_long(nr), *[ctypes.c_long(0)] * 6)
        out.append(f"{name} {'ok' if r >= 0 else errname(ctypes.get_errno())}")
    return ", ".join(out)


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
print(f"  active LSMs     {active_lsms()} (lsm_list_modules)")
print(f"  securityfs lsm  {read('/sys/kernel/security/lsm')}")
print(f"  kallsyms        Landlock symbols: {landlock_symbols()}")
print(f"  newer syscalls  {newer_syscalls()}")
print(f"  CapEff          {status['CapEff'].strip()} (CAP_SYS_PTRACE {'present' if cap_eff >> CAP_SYS_PTRACE & 1 else 'absent'})")
print(f"  CapBnd          {status['CapBnd'].strip()}")
print(f"  seccomp         mode {status.get('Seccomp', '?').strip()}, {status.get('Seccomp_filters', '?').strip()} filters")
print(f"  NoNewPrivs      {status.get('NoNewPrivs', '?').strip()}")
print(f"  ptrace_scope    {read('/proc/sys/kernel/yama/ptrace_scope')}")
RESOLV_BEFORE = read(RESOLV)
kind = f"symlink to {os.readlink(RESOLV)}" if os.path.islink(RESOLV) else "regular file" if os.path.isfile(RESOLV) else "missing"
print(f"  resolv.conf     {kind}: {' | '.join(read(RESOLV).splitlines())}")

print("== probe")
for name, pol in (("default policy", DEFAULT), ("egress example", EGRESS), ("no-Landlock example", NO_LANDLOCK)):
    rc, so, se = sbx([], pol, cmd="probe")
    for line in (so + se).splitlines():
        print(f"       {line}")
    if pol == NO_LANDLOCK or LANDLOCK or REQUIRE_LANDLOCK == "true":
        check(f"probe: {name}", rc == 0, f"rc={rc}")
    else:
        check(f"probe: {name} is refused for lack of Landlock ABI 6", rc == 1 and "MISSING  landlock" in so,
              f"rc={rc}")

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


def egress_checks(pol, prefix=""):
    """Egress on the real network: an allowed name resolves through the metadata server's DNS and connects."""
    def connect(name, want, host, port, **kw):
        expect(prefix + name, want, ["--", PY, "-c", CONNECT, host, str(port)], pol=pol, **kw)

    connect("allowed name resolves and connects", 0, "api.github.com", 443, log="dns: api.github.com ->")
    connect("unlisted address is denied (EACCES)", 13, "1.1.1.1", 443, log="denied connect to 1.1.1.1:443")
    connect("metadata server is denied", 13, "169.254.169.254", 80, log="denied connect to 169.254.169.254:80")
    connect("unlisted name gets NXDOMAIN", 3, "example.com", 443, log="dns: denied A example.com")


# ---------------------------------------------------------------- with Landlock

if LANDLOCK:
    print("== sandbox (default policy)")
    expect("runs a program", 0, ["--", "/bin/echo", "hello"], out="hello")
    expect("drops to uid 65534", 0, ["--", "/bin/sh", "-c", 'test "$(id -u):$(id -g)" = 65534:65534'])
    expect("Landlock denies files outside the policy", 1, ["--", "/bin/cat", "/etc/debian_version"],
           log="Permission denied")
    expect("timeout kills the tree (exit 124)", 124, ["--timeout", "2", "--", "/bin/sleep", "30"],
           log="timeout after 2s")
    print("== egress (egress example policy, real network)")
    egress_checks(EGRESS)
elif REQUIRE_LANDLOCK == "true":
    print("== sandbox and egress with Landlock")
    bad("sandbox and egress with Landlock", f"skipped: the kernel lacks Landlock ABI 6 ({landlock_abi()})")
else:
    print("== sandbox and egress with Landlock")
    print(f"  n/a  the kernel lacks Landlock ABI 6 ({landlock_abi()})")

# ---------------------------------------------------------------- without Landlock

print('== without Landlock (no-Landlock example policy, landlock.abi = "off")')
N = "off: "
expect(N + "runs a program", 0, ["--", "/bin/echo", "hello"], pol=NO_LANDLOCK, out="hello", log="landlock: off")
expect(N + "drops to uid 65534", 0, ["--", "/bin/sh", "-c", 'test "$(id -u):$(id -g)" = 65534:65534'],
       pol=NO_LANDLOCK)
expect(N + "world-readable files are readable (the documented loss)", 0, ["--", "/bin/cat", "/etc/debian_version"],
       pol=NO_LANDLOCK)
expect(N + "file permissions still apply", 1, ["--", "/bin/cat", "/etc/shadow"], pol=NO_LANDLOCK,
       log="Permission denied")
expect(N + "timeout kills the tree (exit 124)", 124, ["--timeout", "2", "--", "/bin/sleep", "30"], pol=NO_LANDLOCK,
       log="timeout after 2s")
egress_checks(NO_LANDLOCK, N)
UNIX_CONNECT = """
import socket, sys
try:
    socket.socket(socket.AF_UNIX).connect(sys.argv[1])
except PermissionError:
    sys.exit(13)
"""
expect(N + "AF_UNIX connect is denied", 13, ["--", PY, "-c", UNIX_CONNECT, "/nonexistent-sbx.sock"], pol=NO_LANDLOCK,
       log="non-IP sockets is denied")
expect(N + "bind is denied", 1, ["--", PY, "-c", "import socket; socket.socket().bind(('127.0.0.1', 0))"],
       pol=NO_LANDLOCK, log="denied bind")

check("resolv.conf is restored after the egress runs", read(RESOLV) == RESOLV_BEFORE,
      f"{read(RESOLV)!r} vs {RESOLV_BEFORE!r}")

print(f"== {len(PASS)} passed, {len(FAIL)} failed")
for name in FAIL:
    print(f"  failed: {name}")
sys.exit(1 if FAIL else 0)
