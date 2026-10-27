#!/usr/bin/env python3
"""Integration suite for sbx: escape attempts, egress filtering, strictness.

Run as root in a disposable environment:
  * test image:  make smoke        (docker run --cap-add SYS_PTRACE --tmpfs ...)
  * Linux host:  make smoke-local  (private mount namespace, see the Makefile)

Required environment:
  SBX                path to the sbx binary
  TEST_VOLUME        an empty mount point of its own (e.g. a tmpfs), outside /tmp
  TEST_REQUIRE_IPV6  true: fail instead of reporting IPv6 tests as n/a when the
                     kernel has no IPv6 (ipv6.disable=1)

Optional:
  TEST_REQUIRE_LANDLOCK  true (default): fail when the kernel lacks Landlock
                     ABI 6. false (Cloud Run): then check that sbx refuses
                     Landlock policies, report the Landlock-only tests as n/a
                     and run everything else with landlock.abi = "off"

The suite rewrites /etc/resolv.conf for the DNS tests and starts local TCP
servers on 127.0.0.1-3, so never run it directly on a host you care about.
Every prerequisite is checked up front; nothing is skipped silently.
"""

import ctypes
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

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
    print(f"smoke: {msg}", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------- environment

SBX = os.environ.get("SBX") or die("set SBX to the sbx binary")
VOLUME = os.environ.get("TEST_VOLUME") or die("set TEST_VOLUME to a dedicated writable mount point")
if os.geteuid() != 0:
    die("run as root (sbx is tested the way the container entrypoint runs it)")
if not os.access(SBX, os.X_OK):
    die(f"{SBX} is not executable")
if not os.path.ismount(VOLUME):
    die(f"TEST_VOLUME {VOLUME} is not a mount point")
if os.listdir(VOLUME):
    die(f"TEST_VOLUME {VOLUME} is not empty")
if not os.path.isfile("/etc/resolv.conf") or os.path.islink("/etc/resolv.conf"):
    die("/etc/resolv.conf must be a regular file (the DNS tests rewrite it)")
SETPRIV = shutil.which("setpriv") or die("setpriv (util-linux) is required")
REQUIRE_IPV6 = os.environ.get("TEST_REQUIRE_IPV6", "false")
if REQUIRE_IPV6 not in ("true", "false"):
    die("TEST_REQUIRE_IPV6 must be true or false")
try:
    socket.socket(socket.AF_INET6).close()
    HAVE_IPV6 = True
except OSError:
    HAVE_IPV6 = False
if REQUIRE_IPV6 == "true" and not HAVE_IPV6:
    die("TEST_REQUIRE_IPV6=true but this kernel has no IPv6")
REQUIRE_LANDLOCK = os.environ.get("TEST_REQUIRE_LANDLOCK", "true")
if REQUIRE_LANDLOCK not in ("true", "false"):
    die("TEST_REQUIRE_LANDLOCK must be true or false")
PY = os.path.realpath(sys.executable)
VOLUME = os.path.realpath(VOLUME)

LIBC = ctypes.CDLL(None, use_errno=True)


def kernel_landlock_abi():
    LIBC.syscall.restype = ctypes.c_long
    nr = {"x86_64": 444, "aarch64": 444}[os.uname().machine]
    return LIBC.syscall(ctypes.c_long(nr), None, ctypes.c_size_t(0), ctypes.c_uint(1))


KABI = kernel_landlock_abi()
LANDLOCK = KABI >= 6
if not LANDLOCK:
    have = f"v{KABI}" if KABI > 0 else f"unavailable ({os.strerror(ctypes.get_errno())})"
    why = f"the kernel's Landlock ABI is {have}; the Landlock tests need v6 (Linux 6.12+)"
    if REQUIRE_LANDLOCK == "true":
        die(f"{why} (set TEST_REQUIRE_LANDLOCK=false to run the rest without Landlock)")
    print(f'smoke: {why}: they are n/a, and the rest runs with landlock.abi = "off"', flush=True)
# The landlock.abi of the test policies.
ABI = 6 if LANDLOCK else "off"

# A clean environment for sbx: nothing from the caller leaks into the tests.
BASE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}

W = tempfile.mkdtemp(prefix="sbxtest.", dir="/tmp")
os.chmod(W, 0o755)

# ---------------------------------------------------------------- policies


def canonical_existing(paths):
    return [p for p in paths if os.path.exists(p) and os.path.realpath(p) == p]


RESOLV = os.path.realpath("/etc/resolv.conf")


def fs_rules(extra=()):
    rules = [("/usr", "rx")]
    rules += [(p, "r") for p in canonical_existing(
        ["/etc/ld.so.cache", "/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/hosts", "/proc", "/sys/fs/cgroup",
         "/dev/zero", "/dev/urandom", "/dev/random"])]
    rules += [(RESOLV, "r")]
    rules += [(p, "rw") for p in canonical_existing(["/dev/null", "/dev/full"])]
    rules += [("/tmp", "rw")]
    pyprefix = os.path.realpath(sys.base_prefix)
    if not pyprefix.startswith("/usr"):
        rules.append((pyprefix, "rx"))
    rules += list(extra)
    return rules


def toml_value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(toml_value(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{k} = {toml_value(x)}" for k, x in v.items()) + " }"
    raise TypeError(v)


def policy(mode="none", families=("unix",), egress=(), bind_tcp=(), dns=None, subprocesses=True,
           on_violation="errno", deny=(), allow=(), extra_fs=(), workdir="/tmp", timeout="none",
           env_pass=(), drop=None, uid=65534, gid=65534, abi=ABI, fs=None):
    """abi="off": no scopes and, unless fs is given, no fs rules."""
    landlock = abi != "off"
    if fs is None:
        fs = fs_rules(extra_fs) if landlock else []
    sections = {
        "landlock": {"abi": abi, "scope_signals": landlock, "scope_abstract_unix": landlock},
        "process": {"uid": uid, "gid": gid, "workdir": workdir, "timeout_secs": timeout, "kill_grace_secs": 2,
                    "subprocesses": subprocesses},
        "limits": {"nofile": 1024, "nproc": 512, "fsize_mb": 1024, "as_mb": "unlimited", "cpu_secs": "unlimited"},
        "env": {"pass": list(env_pass)},
        "env.set": {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8"},
        "network": {"mode": mode, "bind_tcp": list(bind_tcp), "egress": list(egress)},
        "seccomp": {"on_violation": on_violation, "deny": list(deny), "allow": list(allow),
                    "socket_families": list(families)},
    }
    if dns:
        sections["network.dns"] = dns
    # Plain keys come before the first table in TOML.
    out = [] if fs else ["fs = []", ""]
    for name, body in sections.items():
        out.append(f"[{name}]")
        for k, v in body.items():
            if drop == f"{name}.{k}":
                continue
            out.append(f"{k} = {toml_value(v)}")
        out.append("")
    for path, access in fs:
        out += ["[[fs]]", f"path = {toml_value(path)}", f"access = {toml_value(access)}", ""]
    fd, path = tempfile.mkstemp(prefix="policy.", suffix=".toml", dir=W)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(out))
    os.chmod(path, 0o644)
    return path


BASE = policy()
for path, _ in fs_rules():
    if VOLUME == path or VOLUME.startswith(path.rstrip("/") + "/"):
        die(f"TEST_VOLUME {VOLUME} lies under {path}, which the test policies grant; mount it elsewhere (e.g. /mnt)")


def sbx(args, pol=BASE, env=None, cmd="run", timeout=60, wrap=()):
    e = dict(BASE_ENV)
    if pol is not None:
        e["SBX_POLICY_FILE"] = pol
    e.update(env or {})
    p = subprocess.run([*wrap, SBX, cmd, *args], env=e, capture_output=True, text=True, timeout=timeout,
                       stdin=subprocess.DEVNULL)
    return p.returncode, p.stdout, p.stderr


def expect(name, want, args, pol=BASE, log=None, out=None, **kw):
    """want: an exit code, or 'nonzero'. log/out: substrings expected in stderr/stdout."""
    rc, so, se = sbx(args, pol=pol, **kw)
    good = (rc != 0) if want == "nonzero" else (rc == want)
    if log and log not in se:
        good = False
    if out and out not in so:
        good = False
    check(name, good, f"rc={rc} (want {want}) stdout={so[-300:]!r} stderr={se[-600:]!r}")
    return rc, so, se


def py(code, *argv):
    return ["--", PY, "-c", code, *[str(a) for a in argv]]


# ---------------------------------------------------------------- probe

print("== probe")
rc, so, se = sbx([], cmd="probe")
check("probe: base policy is enforceable", rc == 0, so + se)

# ---------------------------------------------------------------- strictness

print("== strictness (sbx refuses, exit 125)")
expect("no policy file", 125, ["--", "/bin/true"], pol=None, log="no policy file")
expect("unknown SBX_ variable", 125, ["--", "/bin/true"], env={"SBX_TIMOUT": "5"}, log="unknown environment variable SBX_TIMOUT")
expect("empty SBX_ variable", 125, ["--", "/bin/true"], env={"SBX_NET": ""}, log="set but empty")
expect("missing policy field", 125, ["--", "/bin/true"], pol=policy(drop="process.kill_grace_secs"), log="missing field")
os.symlink("/tmp", os.path.join(VOLUME, "link"))
expect("symlinked fs path", 125, ["--ro", os.path.join(VOLUME, "link"), "--", "/bin/true"], log="not canonical")
os.unlink(os.path.join(VOLUME, "link"))
expect("missing fs path", 125, ["--ro", "/nonexistent-sbx", "--", "/bin/true"], log="No such file")
expect("program without --", 125, ["/bin/true"], log="put -- before the program")
expect("flag given twice", 125, ["--timeout", "1", "--timeout", "2", "--", "/bin/true"], log="more than once")
expect("env.pass of an unset variable", 125, ["--", "/bin/true"], pol=policy(env_pass=["SBX_SMOKE_UNSET"]), log="not set")
expect("egress rule outside egress mode", 125, ["--egress", "example.com:443", "--", "/bin/true"], log="only used with mode")
expect("bad boolean", 125, ["--", "/bin/true"], env={"SBX_SUBPROCESSES": "0"}, log="expected true or false")
if not LANDLOCK:
    expect("a Landlock policy is refused (the kernel lacks ABI 6)", 125, ["--", "/bin/true"], pol=policy(abi=6),
           log="required capability missing: landlock")
elif KABI < 9:
    expect("Landlock ABI above the kernel's", 125, ["--", "/bin/true"], pol=policy(abi=KABI + 1), log=f"provides ABI v{KABI}")
else:
    print("  n/a  Landlock ABI above the kernel's (kernel already has the newest ABI this build knows)")
expect("non-root sbx cannot switch identity", 125, ["--", "/bin/true"],
       pol=policy(uid=12345, gid=12345, abi=6), wrap=(SETPRIV, "--reuid", "65534", "--regid", "65534", "--clear-groups"),
       log="cannot switch")

# ---------------------------------------------------------------- baseline

print("== baseline")
expect("runs a program", 0, ["--", "/bin/echo", "hi"], out="hi")
expect("drops to uid 65534", 0, ["--", "/bin/sh", "-c", 'test "$(id -u):$(id -g)" = 65534:65534'])
expect("environment is scrubbed", 0, ["--", "/bin/sh", "-c", 'test -z "${SECRET_TOKEN:-}"'], env={"SECRET_TOKEN": "leak"})
rc, so, se = sbx(["--quiet", "--", "/bin/cat", "/proc/self/status"])
fields = dict(l.split(":\t", 1) for l in so.splitlines() if ":\t" in l)
check("no capabilities (incl. bounding set)",
      all(fields.get(k, "?").strip() == "0000000000000000" for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")), so)
with open("/proc/self/status") as f:
    OUTER_FILTERS = int(dict(l.split(":\t", 1) for l in f.read().splitlines() if ":\t" in l)["Seccomp_filters"])
check("no_new_privs and sbx's two seccomp filters", fields.get("NoNewPrivs") == "1"
      and fields.get("Seccomp_filters", "").strip() == str(OUTER_FILTERS + 2), f"outside: {OUTER_FILTERS} filters; {so}")
check("signals: none ignored, none blocked", fields.get("SigIgn") == "0000000000000000" and fields.get("SigBlk") == "0000000000000000", so)

# ---------------------------------------------------------------- filesystem

print("== filesystem (Landlock)")
SECRET = "/var/tmp/sbx-secret"
with open(SECRET, "w") as f:
    f.write("topsecret\n")
os.chmod(SECRET, 0o644)
if LANDLOCK:
    expect("cannot read outside the allow-list", "nonzero", ["--", "/bin/cat", SECRET])
    expect("cannot list /etc", "nonzero", ["--", "/bin/ls", "/etc"])
    expect("can read an allowed file", 0, ["--", "/bin/cat", "/etc/passwd"])
    expect("cannot write to world-writable /var/tmp", "nonzero", ["--", "/bin/sh", "-c", "echo x > /var/tmp/sbx-pwn"])
    expect("can write to /tmp", 0, ["--", "/bin/sh", "-c", "echo x > /tmp/sbx-ok-$$ && rm /tmp/sbx-ok-$$"])
    shutil.copy("/bin/true", f"{W}/t")
    os.chmod(f"{W}/t", 0o755)
    expect("cannot exec from rw-only /tmp", 127, [f"--", f"{W}/t"], log="need 'x' in an fs rule")
    expect("subprocess inherits fs rules", "nonzero", ["--", "/bin/sh", "-c", f"/bin/sh -c '/bin/cat {SECRET}'"])
    os.chmod(VOLUME, 0o777)
    expect("volume granted rw is writable", 0, ["--rw", VOLUME, "--", "/bin/sh", "-c", f"echo x > {VOLUME}/f"])
    expect("volume granted ro is read-only", "nonzero", ["--ro", VOLUME, "--", "/bin/sh", "-c", f"echo y > {VOLUME}/g"])
    expect("volume granted ro is readable", 0, ["--ro", VOLUME, "--", "/bin/cat", f"{VOLUME}/f"])
    expect("ungranted volume is invisible", "nonzero", ["--", "/bin/cat", f"{VOLUME}/f"])
else:
    print("  n/a  filesystem rules (no Landlock)")

# ---------------------------------------------------------------- supervision

print("== process supervision")
expect("timeout kills the tree (exit 124)", 124, ["--timeout", "1", "--", "/bin/sleep", "5"], log="timeout after 1s")
sbx(["--", "/bin/sh", "-c", "setsid /bin/sleep 300 >/dev/null 2>&1 & echo started"])
time.sleep(0.3)
left = []
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            if f.read().split(b"\0")[:2] == [b"/bin/sleep", b"300"]:
                left.append(pid)
    except OSError:
        pass
check("orphans are killed on exit", not left, f"left over: {left}")
expect("--no-subprocesses blocks fork", "nonzero", ["--no-subprocesses", "--", "/bin/sh", "-c", "/bin/true; /bin/true"],
       log="process.subprocesses = false")

NR = (SETPRIV, "--reuid", "65534", "--regid", "65534", "--clear-groups")
if LANDLOCK:
    expect("same-uid: runs", 0, ["--", "/bin/true"], wrap=NR)
    expect("same-uid: fs rules still enforced", "nonzero", ["--", "/bin/cat", SECRET], wrap=NR)
    expect("same-uid: cannot signal the supervisor", "nonzero", ["--", "/bin/sh", "-c", "kill -0 $PPID"], wrap=NR)
    expect("same-uid: cannot read the supervisor's environ", "nonzero",
           ["--", "/bin/sh", "-c", "grep -q SBX_POLICY_FILE /proc/$PPID/environ"], wrap=NR)
else:
    print("  n/a  same-uid sbx (needs Landlock scoping; refused without Landlock, see below)")

print("== one sandbox per container")
first = subprocess.Popen([SBX, "run", "--", "/bin/sleep", "60"], env=dict(BASE_ENV, SBX_POLICY_FILE=BASE),
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
for line in first.stderr:
    if "started pid" in line:
        break
expect("a second sbx is refused while one runs", 125, ["--", "/bin/true"], log="another sbx sandbox is running")
rc, so, se = sbx([], cmd="probe")
check("probe reports the slot as taken", rc == 1 and "MISSING  one sandbox per container" in so, so + se)
first.terminate()
first.communicate(timeout=30)
expect("the slot is free again once it exits", 0, ["--", "/bin/true"])

# ---------------------------------------------------------------- seccomp

print("== seccomp")
expect("no AF_INET sockets in mode none", 1, py("import socket; socket.socket()"), log="denied socket")
expect("AF_UNIX sockets work", 0, py("import socket; socket.socketpair()"))


def allowed_outside(code):
    """Whether the snippet succeeds without sbx. Container runtimes install
    their own seccomp filters; a call they already refuse never reaches sbx's
    filter (ERRNO outranks USER_NOTIF), so sbx cannot log it."""
    return subprocess.run([PY, "-c", code], capture_output=True, stdin=subprocess.DEVNULL).returncode == 0


def expect_denied(name, code, syscall):
    if allowed_outside(code):
        expect(name, 1, py(code), log=f"denied {syscall}")
    else:
        expect(f"{name} (already refused by the container runtime)", 1, py(code))


UNSHARE = "import os; os.unshare(os.CLONE_NEWUSER)"
PTRACE = "import ctypes; l=ctypes.CDLL(None,use_errno=True); assert l.ptrace(0,0,0,0)==0"
IO_URING = "import ctypes; l=ctypes.CDLL(None,use_errno=True); assert l.syscall(425,1,ctypes.create_string_buffer(120))>=0"
expect_denied("no user namespaces", UNSHARE, "unshare")
expect_denied("no ptrace", PTRACE, "ptrace")
expect_denied("no io_uring", IO_URING, "io_uring_setup")
expect("clone3 -> ENOSYS", 0, py("import ctypes,errno; l=ctypes.CDLL(None,use_errno=True); l.syscall(435,0,0); assert ctypes.get_errno()==errno.ENOSYS"))
expect("threads work without subprocesses", 0,
       ["--no-subprocesses", *py("import threading; t=threading.Thread(target=print); t.start(); t.join()")])
if allowed_outside(PTRACE):
    expect("kill mode kills the process (SIGKILL)", 137, ["--seccomp-action", "kill", *py(PTRACE)], log="killed python3")
else:
    print("  n/a  kill mode (the container runtime already refuses ptrace, so sbx never sees it)")

# ---------------------------------------------------------------- egress


class Server:
    """A TCP server outside the sandbox that counts accepted connections."""

    def __init__(self, host):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.accepted = 0
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            c, _ = self.sock.accept()
            self.accepted += 1
            try:
                c.sendall(b"hello\n")
            except OSError:
                pass
            c.close()


def dns_name(m, pos):
    labels = []
    while m[pos]:
        labels.append(m[pos + 1:pos + 1 + m[pos]].decode().lower())
        pos += 1 + m[pos]
    return ".".join(labels), pos + 1


class FakeUpstream:
    """A TCP DNS server answering A queries from a table."""

    def __init__(self, answers):
        self.answers = answers
        self.seen = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            c, _ = self.sock.accept()
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c):
        with c:
            while True:
                hdr = c.recv(2, socket.MSG_WAITALL)
                if len(hdr) < 2:
                    return
                q = c.recv(struct.unpack("!H", hdr)[0], socket.MSG_WAITALL)
                name, pos = dns_name(q, 12)
                qtype = struct.unpack("!H", q[pos:pos + 2])[0]
                self.seen.append((name, qtype))
                ip = self.answers.get(name)
                flags = 0x8180 if ip else 0x8183
                an = 1 if ip and qtype == 1 else 0
                r = q[:2] + struct.pack("!HHHHH", flags, 1, an, 0, 0) + q[12:pos + 4]
                if an:
                    r += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
                c.sendall(struct.pack("!H", len(r)) + r)


print("== egress")
A = Server("127.0.0.1")       # allowed by CIDR rule
B = Server("127.0.0.1")       # not allowed
C = Server("127.0.0.2")       # allowed through DNS (allowed.test)
closed = socket.socket()
closed.bind(("127.0.0.1", 0))
CLOSED_PORT = closed.getsockname()[1]
closed.close()
UP = FakeUpstream({"allowed.test": "127.0.0.2", "meta.allowed.test": "169.254.169.254"})
DNS = {"listen": "127.0.0.53:53", "upstream": f"127.0.0.1:{UP.port}", "upstream_transport": "tcp",
       "resolv_conf": "write", "timeout_ms": 2000, "answer_scopes": ["global", "loopback"]}
EGRESS = policy(
    mode="egress", families=("unix", "inet", "inet6"), dns=DNS,
    egress=[{"cidr": "127.0.0.1/32", "ports": [A.port, CLOSED_PORT]},
            {"domain": "allowed.test", "ports": [C.port]},
            {"domain": "*.allowed.test", "ports": [C.port]}])

rc, so, se = sbx([], pol=EGRESS, cmd="probe")
check("probe: egress policy is enforceable", rc == 0, so + se)

CONNECT = """
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
fam = socket.AF_INET6 if ":" in host else socket.AF_INET
s = socket.socket(fam)
s.settimeout(5)
try:
    s.connect((host, port))
except PermissionError:
    sys.exit(13)
except ConnectionRefusedError:
    sys.exit(111)
assert s.recv(6) == b"hello\\n"
"""
e = lambda name, want, *argv, **kw: expect(name, want, py(CONNECT, *argv), pol=EGRESS, **kw)
e("allowed CIDR port connects", 0, "127.0.0.1", A.port)
e("other port is denied (EACCES)", 13, "127.0.0.1", B.port, log=f"denied connect to 127.0.0.1:{B.port}")
if HAVE_IPV6:
    e("IPv4-mapped IPv6 address is matched as IPv4", 0, "::ffff:127.0.0.1", A.port)
    e("IPv4-mapped IPv6 to another port is denied", 13, "::ffff:127.0.0.1", B.port)
else:
    print("  n/a  IPv4-mapped IPv6 tests (this kernel has no IPv6)")
e("refused connection is reported faithfully", 111, "127.0.0.1", CLOSED_PORT)
e("unspecified address is denied", 13, "0.0.0.0", A.port, log="unspecified address")
e("unresolved address is denied", 13, "127.0.0.2", C.port, log="no egress rule matches")
expect("non-blocking connect completes", 0, py("""
import socket, select, sys, errno
s = socket.socket(); s.setblocking(False)
assert s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == errno.EINPROGRESS
select.select([], [s], [], 5)
assert s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0
""", A.port), pol=EGRESS)
expect("connect from a thread after the main thread exited", 0, ["--timeout", "20", *py("""
import ctypes, os, socket, sys, threading, time
def worker():
    time.sleep(0.5)
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
    os._exit(0 if s.recv(6) == b"hello\\n" else 1)
threading.Thread(target=worker).start()
ctypes.CDLL(None).pthread_exit(None)
""", A.port)], pol=EGRESS)
expect("UDP sockets are refused", 1, py("import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM)"),
       pol=EGRESS, log="allows TCP sockets only")
expect("raw sockets are refused", 1, py("import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)"), pol=EGRESS)
expect("MPTCP is refused", 1, py("import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262)"), pol=EGRESS)
expect("TCP Fast Open is refused", 1, py("""
import socket, sys
s = socket.socket()
s.sendto(b"x", socket.MSG_FASTOPEN, ("127.0.0.1", int(sys.argv[1])))
""", B.port), pol=EGRESS, log="MSG_FASTOPEN")
expect("IP source routing options are refused", 1,
       py("import socket; socket.socket().setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, bytes(8))"),
       pol=EGRESS, log="source routing")
if LANDLOCK:
    expect("AF_UNIX connect still works", 0, py("""
import socket, os
p = "/tmp/sbx-unix-%d" % os.getpid()
srv = socket.socket(socket.AF_UNIX); srv.bind(p); srv.listen(1)
c = socket.socket(socket.AF_UNIX); c.connect(p)
os.unlink(p)
"""), pol=EGRESS)
else:
    print("  n/a  AF_UNIX connect still works (denied without Landlock, see below)")

RESOLVE = """
import socket, sys
try:
    ips = sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[1], 0, socket.AF_INET, socket.SOCK_STREAM)})
except socket.gaierror as e:
    print("gaierror", e); sys.exit(3)
print(" ".join(ips))
if len(sys.argv) > 2:
    s = socket.create_connection((ips[0], int(sys.argv[2])), timeout=5)
    assert s.recv(6) == b"hello\\n"
"""
expect("allowed name resolves and connects", 0, py(RESOLVE, "allowed.test", C.port), pol=EGRESS,
       out="127.0.0.2", log="dns: allowed.test -> 127.0.0.2")
check("upstream was asked over TCP", ("allowed.test", 1) in UP.seen, UP.seen)
expect("other names get NXDOMAIN", 3, py(RESOLVE, "other.test"), pol=EGRESS, log="dns: denied A other.test")
check("denied names never reach the upstream", all(n != "other.test" for n, _ in UP.seen), UP.seen)
expect("link-local answers are not learned", 1, py(RESOLVE, "meta.allowed.test", C.port), pol=EGRESS,
       log="not added to the egress allow-set")
with open("/etc/resolv.conf") as f:
    check("resolv.conf points at the proxy over TCP", "nameserver 127.0.0.53" in f.read(), "")

RACE_MEMORY = """
import ctypes, socket, struct, sys, threading
libc = ctypes.CDLL(None, use_errno=True)
def sin(port):
    return struct.pack("=H", socket.AF_INET) + struct.pack("!H", port) + socket.inet_aton("127.0.0.1") + bytes(8)
good, bad = sin(int(sys.argv[1])), sin(int(sys.argv[2]))
buf = ctypes.create_string_buffer(good, 16)
stop = False
def flip():
    while not stop:
        ctypes.memmove(buf, bad, 16); ctypes.memmove(buf, good, 16)
t = threading.Thread(target=flip); t.start()
for _ in range(1500):
    s = socket.socket(); libc.connect(s.fileno(), buf, 16); s.close()
stop = True; t.join()
"""
before = B.accepted
expect("TOCTOU: flipping the sockaddr during connect", 0, ["--quiet", *py(RACE_MEMORY, A.port, B.port)], pol=EGRESS, timeout=300)
time.sleep(0.2)
check("TOCTOU: the denied server saw no connection", B.accepted == before, f"accepted {B.accepted - before}")

RACE_FDS = """
import ctypes, os, socket, struct, sys, threading
libc = ctypes.CDLL(None, use_errno=True)
bad = struct.pack("=H", socket.AF_INET) + struct.pack("!H", int(sys.argv[1])) + socket.inet_aton("127.0.0.1") + bytes(8)
u = socket.socket(socket.AF_UNIX)
target = 200
stop = False
def flip():
    while not stop:
        t = socket.socket()
        os.dup2(u.fileno(), target); os.dup2(t.fileno(), target)
        t.close()
th = threading.Thread(target=flip); th.start()
buf = ctypes.create_string_buffer(bad, 16)
for _ in range(1500):
    libc.connect(target, buf, 16)
stop = True; th.join()
"""
before = B.accepted
expect("fd swap: AF_UNIX <-> TCP during connect", 0, ["--quiet", *py(RACE_FDS, B.port)], pol=EGRESS, timeout=300)
time.sleep(0.2)
check("fd swap: the denied server saw no connection", B.accepted == before, f"accepted {B.accepted - before}")

expect("egress needs CAP_SYS_PTRACE", 125, py(CONNECT, "127.0.0.1", A.port), pol=EGRESS,
       wrap=(SETPRIV, "--bounding-set=-sys_ptrace", "--inh-caps=-sys_ptrace"), log="CAP_SYS_PTRACE")
VERIFY = policy(mode="egress", families=("unix", "inet"), dns=dict(DNS, resolv_conf="verify"),
                egress=[{"domain": "allowed.test", "ports": [C.port]}])
with open("/etc/resolv.conf", "w") as f:
    f.write("nameserver 8.8.8.8\n")
expect("resolv.conf mismatch is refused", 125, ["--", "/bin/true"], pol=VERIFY, log="does not point the sandbox")

# ---------------------------------------------------------------- without Landlock

print('== without Landlock (landlock.abi = "off")')
OFF = policy(abi="off")
rc, so, se = sbx([], pol=OFF, cmd="probe")
check("off: probe: the policy is enforceable", rc == 0, so + se)
expect("off: runs a program", 0, ["--", "/bin/echo", "hi"], pol=OFF, out="hi", log="landlock: off")
rc, so, se = sbx(["--quiet", "--", "/bin/cat", "/proc/self/status"], pol=OFF)
fields = dict(l.split(":\t", 1) for l in so.splitlines() if ":\t" in l)
check("off: uid 65534, no capabilities, no_new_privs, sbx's two seccomp filters",
      fields.get("Uid", "").split() == ["65534"] * 4
      and all(fields.get(k, "?").strip() == "0000000000000000" for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
      and fields.get("NoNewPrivs") == "1" and fields.get("Seccomp_filters", "").strip() == str(OUTER_FILTERS + 2), so)
expect("off: world-readable files outside any rule are readable (the documented loss)", 0,
       ["--", "/bin/cat", SECRET], pol=OFF, out="topsecret")
PRIVATE = f"{W}/private"
with open(PRIVATE, "w") as f:
    f.write("private\n")
os.chmod(PRIVATE, 0o600)
expect("off: file permissions still apply", 1, ["--", "/bin/cat", PRIVATE], pol=OFF, log="Permission denied")
expect("off: fs rules are refused", 125, ["--ro", "/usr", "--", "/bin/true"], pol=OFF, log="fs rules need Landlock")
expect("off: non-root sbx is refused", 125, ["--", "/bin/true"], pol=OFF, wrap=NR, log="needs sbx to start as root")
with socket.socket() as s:
    p = subprocess.run([SBX, "run", "--", "/bin/true"], env=dict(BASE_ENV, SBX_POLICY_FILE=OFF), stdin=s.fileno(),
                       capture_output=True, text=True, timeout=60)
check("off: an IP socket on stdio is refused in mode none", p.returncode == 125 and "is an IP socket" in p.stderr,
      f"rc={p.returncode} stderr={p.stderr[-600:]!r}")
squatter = subprocess.Popen([*NR, "/bin/sleep", "60"], stdin=subprocess.DEVNULL)
for _ in range(50):
    with open(f"/proc/{squatter.pid}/status") as f:
        if "\nUid:\t65534\t" in f.read():
            break
    time.sleep(0.1)
expect("off: refused while another process runs as the sandbox uid", 125, ["--", "/bin/true"], pol=OFF,
       log="already run as uid 65534")
squatter.kill()
squatter.wait()

EGRESS_OFF = policy(
    abi="off", mode="egress", families=("unix", "inet", "inet6"), dns=DNS,
    egress=[{"cidr": "127.0.0.1/32", "ports": [A.port]}, {"domain": "allowed.test", "ports": [C.port]}])
rc, so, se = sbx([], pol=EGRESS_OFF, cmd="probe")
check("off: probe: the egress policy is enforceable", rc == 0, so + se)
eo = lambda name, want, *argv, **kw: expect(name, want, py(CONNECT, *argv), pol=EGRESS_OFF, **kw)
eo("off: allowed CIDR port connects", 0, "127.0.0.1", A.port)
eo("off: other port is denied (EACCES)", 13, "127.0.0.1", B.port, log=f"denied connect to 127.0.0.1:{B.port}")
expect("off: allowed name resolves and connects", 0, py(RESOLVE, "allowed.test", C.port), pol=EGRESS_OFF,
       out="127.0.0.2")
expect("off: other names get NXDOMAIN", 3, py(RESOLVE, "other.test"), pol=EGRESS_OFF, log="dns: denied A other.test")
UNIX_CONNECT = """
import socket, sys
try:
    socket.socket(socket.AF_UNIX).connect(sys.argv[1])
except PermissionError:
    sys.exit(13)
"""
expect("off: AF_UNIX connect is denied", 13, py(UNIX_CONNECT, "/nonexistent-sbx.sock"), pol=EGRESS_OFF,
       log="non-IP sockets is denied")
expect("off: bind is denied", 1, py("import socket; socket.socket().bind(('127.0.0.1', 0))"), pol=EGRESS_OFF,
       log="denied bind")
expect("off: listen is denied", 1, py("import socket; socket.socket().listen(1)"), pol=EGRESS_OFF, log="denied listen")
before = B.accepted
expect("off: fd swap: AF_UNIX <-> TCP during connect", 0, ["--quiet", *py(RACE_FDS, B.port)], pol=EGRESS_OFF,
       timeout=300)
time.sleep(0.2)
check("off: fd swap: the denied server saw no connection", B.accepted == before, f"accepted {B.accepted - before}")

# ---------------------------------------------------------------- cleanup

shutil.rmtree(W, ignore_errors=True)
for p in (SECRET, "/var/tmp/sbx-pwn"):
    if os.path.exists(p):
        os.unlink(p)
print(f"== {len(PASS)} passed, {len(FAIL)} failed")
for name in FAIL:
    print(f"  failed: {name}")
sys.exit(1 if FAIL else 0)
