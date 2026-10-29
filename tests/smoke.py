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
  TEST_REQUIRE_CGROUP  true (default): fail unless /sys/fs/cgroup is a
                     writable cgroup v2 with the memory and pids controllers
                     (podman run --systemd=always), and test
                     cgroup.mode = "delegated" in it. false: check that sbx
                     refuses that mode instead

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
with open("/etc/resolv.conf") as f:
    ORIGINAL_RESOLV_CONF = f.read()
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
REQUIRE_CGROUP = os.environ.get("TEST_REQUIRE_CGROUP", "true")
if REQUIRE_CGROUP not in ("true", "false"):
    die("TEST_REQUIRE_CGROUP must be true or false")
CG = "/sys/fs/cgroup"
if REQUIRE_CGROUP == "true":
    # The delegated tests move every process of CG into a child cgroup:
    # only ever do that at the root of a container's own cgroup namespace.
    INITIAL_CGROUP_NS = "cgroup:[4026531835]"
    with open("/proc/self/cgroup") as f:
        if f.read().strip() != "0::/" or os.readlink("/proc/self/ns/cgroup") == INITIAL_CGROUP_NS:
            die("TEST_REQUIRE_CGROUP=true needs the suite at the root of a cgroup namespace of its own "
                "(a container); set TEST_REQUIRE_CGROUP=false on a host")
    try:
        with open(f"{CG}/cgroup.controllers") as f:
            if not {"memory", "pids"} <= set(f.read().split()):
                raise OSError("the memory and pids controllers are not available")
        os.mkdir(f"{CG}/sbx-smoke-probe")
        os.rmdir(f"{CG}/sbx-smoke-probe")
    except OSError as e:
        die(f"TEST_REQUIRE_CGROUP=true but {CG} cannot be delegated ({e}); run the container with "
            "--systemd=always (podman) or set TEST_REQUIRE_CGROUP=false")
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
           env_pass=(), drop=None, uid=65534, gid=65534, abi=ABI, fs=None, cgroup=None):
    """abi="off": no scopes and, unless fs is given, no fs rules."""
    landlock = abi != "off"
    if fs is None:
        fs = fs_rules(extra_fs) if landlock else []
    sections = {
        "landlock": {"abi": abi, "scope_signals": landlock, "scope_abstract_unix": landlock},
        "process": {"uid": uid, "gid": gid, "workdir": workdir, "timeout_secs": timeout, "kill_grace_secs": 2,
                    "subprocesses": subprocesses},
        "limits": {"nofile": 1024, "nproc": 512, "fsize_mb": 1024, "as_mb": "unlimited", "cpu_secs": "unlimited"},
        "cgroup": cgroup or {"mode": "off"},
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


# Reports and logs go to a directory only root can write, as sbx requires.
RDIR = "/var/lib/sbx-smoke"
os.makedirs(RDIR, mode=0o700, exist_ok=True)
AUTO_REPORT = f"{RDIR}/auto.json"
REPORT_MISMATCHES = []


def sbx(args, pol=BASE, env=None, cmd="run", timeout=60, wrap=(), auto_report=True):
    """Unless auto_report is off or sbx runs wrapped (e.g. as another uid),
    every `sbx run` also writes a report, which must agree with the exit code."""
    e = dict(BASE_ENV)
    if pol is not None:
        e["SBX_POLICY_FILE"] = pol
    e.update(env or {})
    auto = auto_report and cmd == "run" and not wrap
    if auto:
        args = ["--report", AUTO_REPORT, *args]
    p = subprocess.run([*wrap, SBX, cmd, *args], env=e, capture_output=True, text=True, timeout=timeout,
                       stdin=subprocess.DEVNULL)
    if auto:
        try:
            with open(AUTO_REPORT) as f:
                got = json.load(f)["exit_code"]
            os.unlink(AUTO_REPORT)
        except FileNotFoundError:
            # Only errors in the flags and SBX_* variables come before the report.
            got = None if p.returncode == 125 else "missing"
        if got not in (None, p.returncode):
            REPORT_MISMATCHES.append((args, p.returncode, got))
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


def resolv_conf():
    with open("/etc/resolv.conf") as f:
        return f.read()


before = resolv_conf()
check("resolv.conf is back to what it was before the egress tests", before == ORIGINAL_RESOLV_CONF,
      f"{before!r} vs {ORIGINAL_RESOLV_CONF!r}")
expect("resolv.conf points at the proxy over TCP while sbx runs", 0, ["--", "/bin/cat", "/etc/resolv.conf"],
       pol=EGRESS, out="nameserver 127.0.0.53\noptions use-vc")
check("resolv.conf is restored when sbx exits", resolv_conf() == before, resolv_conf())
first = subprocess.Popen([SBX, "run", "--", "/bin/sleep", "2"], env=dict(BASE_ENV, SBX_POLICY_FILE=EGRESS),
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
for line in first.stderr:
    if "started pid" in line:
        break
with open("/etc/resolv.conf", "w") as f:
    f.write("nameserver 10.9.9.9\n")
_, se = first.communicate(timeout=30)
check("resolv.conf changed by someone else meanwhile is left alone",
      resolv_conf() == "nameserver 10.9.9.9\n" and "not restoring it" in se, f"{resolv_conf()!r} {se[-300:]!r}")
with open("/etc/resolv.conf", "w") as f:
    f.write(before)

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

# ---------------------------------------------------------------- report and log

print("== report and log")
VERSION = subprocess.run([SBX, "version"], capture_output=True, text=True).stdout.strip().removeprefix("sbx ")
check("version: sbx version names the build", VERSION and not VERSION.startswith("unknown"), VERSION)
REPORT = f"{RDIR}/report.json"


def reported(args, pol=BASE, **kw):
    """Run with --report REPORT; return rc, stdout, stderr and the report (None if there is none)."""
    if os.path.lexists(REPORT):
        os.unlink(REPORT)
    rc, so, se = sbx(["--report", REPORT, *args], pol=pol, auto_report=False, **kw)
    try:
        with open(REPORT) as f:
            return rc, so, se, json.load(f)
    except FileNotFoundError:
        return rc, so, se, None


def check_report(name, args, cond, pol=BASE, **kw):
    rc, so, se, r = reported(args, pol=pol, **kw)
    check(name, r is not None and r["exit_code"] == rc and cond(r), f"rc={rc} report={r} stderr={se[-600:]!r}")
    return r


r = check_report("report: a normal exit", ["--", "/bin/sh", "-c", "exit 3"], lambda r: r["program"] == {"exited": 3}
                 and not r["timed_out"] and r["setup_error"] is None and r["supervisor_error"] is None
                 and r["killed_after_exit"] == 0 and isinstance(r["wall_ms"], int) and r["cgroup"] is None
                 and set(r["rusage"]) == {"user_ms", "sys_ms", "max_rss_kib"} and r["rusage"]["max_rss_kib"] > 0
                 and r["sbx_version"] == VERSION)
check("report: every key is present", r is not None and len(r) == 11, r)
st = os.lstat(REPORT)
check("report: owned by root, mode 0600", st.st_uid == 0 and st.st_mode & 0o7777 == 0o600, oct(st.st_mode))
check_report("report: killed by a signal", ["--", "/bin/sh", "-c", "kill -9 $$"],
             lambda r: r["program"] == {"signaled": 9} and r["exit_code"] == 137)
check_report("report: timeout", ["--timeout", "1", "--", "/bin/sleep", "5"],
             lambda r: r["exit_code"] == 124 and r["timed_out"] and r["killed_after_exit"] is None)
check_report("report: denials per syscall", py("import socket\nfor _ in range(3):\n try: socket.socket()\n except OSError: pass"),
             lambda r: {"syscall": "socket", "count": 3} in r["denials"])
check_report("report: processes left behind are counted",
             ["--", "/bin/sh", "-c", "setsid /bin/sleep 300 >/dev/null 2>&1 & echo started"],
             lambda r: r["killed_after_exit"] == 1)
check_report("report: CPU time of the whole tree", py("import subprocess, sys; subprocess.run([sys.executable, '-c', "
                                                       "'import time\\nt=time.process_time()\\nwhile time.process_time()-t<0.3: pass'])"),
             lambda r: r["rusage"]["user_ms"] + r["rusage"]["sys_ms"] >= 250)
check_report("report: setup error in the policy", ["--", "/bin/true"],
             lambda r: r["setup_error"]["stage"] == "policy" and "missing field" in " ".join(r["setup_error"]["messages"])
             and r["program"] is None and r["wall_ms"] is None, pol=policy(drop="process.kill_grace_secs"))
check_report("report: setup error in the child (execve, exit 127)", ["--", "/nonexistent-sbx"],
             lambda r: r["exit_code"] == 127 and r["setup_error"]["stage"] == "execve")
check_report("report: missing capability", py(CONNECT, "127.0.0.1", A.port),
             lambda r: r["setup_error"]["stage"] == "capabilities", pol=EGRESS,
             wrap=(SETPRIV, "--bounding-set=-sys_ptrace", "--inh-caps=-sys_ptrace"))
if LANDLOCK:
    NRDIR = f"{W}/nr-reports"
    os.mkdir(NRDIR, 0o700)
    os.chown(NRDIR, 65534, 65534)
    rc, so, se = sbx(["--report", f"{NRDIR}/r.json", "--", "/bin/true"], wrap=NR)
    with open(f"{NRDIR}/r.json") as f:
        r = json.load(f)
    check("report: non-root sbx refuses a report directory inside an fs rule", rc == 125
          and r["setup_error"]["stage"] == "report" and "only Landlock" in se, f"rc={rc} {r} {se[-400:]!r}")
else:
    print("  n/a  report: non-root sbx and fs rules (needs Landlock)")
expect("report: a directory others can write is refused", 125, ["--report", "/tmp/sbx-report.json", "--", "/bin/true"],
       auto_report=False, log="writable by others")
check("report: nothing is written there", not os.path.lexists("/tmp/sbx-report.json"))
os.symlink(RDIR, f"{RDIR}-link")
expect("report: a symlinked directory is refused", 125, ["--report", f"{RDIR}-link/r.json", "--", "/bin/true"],
       auto_report=False, log="not canonical")
os.unlink(f"{RDIR}-link")
os.unlink(REPORT)
os.symlink("/etc/sbx-smoke-target", REPORT)
rc, so, se = sbx(["--report", REPORT, "--", "/bin/true"], auto_report=False)
check("report: a symlink at the path is replaced, not followed",
      rc == 0 and not os.path.islink(REPORT) and not os.path.exists("/etc/sbx-smoke-target"), se[-400:])
with open(REPORT, "w") as f:
    f.write("stale")
rc, so, se = sbx(["--report", REPORT], cmd="probe")
check("report: probe checks the destination and leaves the file alone",
      rc == 0 and "ok       report file" in so and open(REPORT).read() == "stale", so + se)
run = subprocess.Popen([SBX, "run", "--report", REPORT, "--", "/bin/sleep", "60"], env=dict(BASE_ENV, SBX_POLICY_FILE=BASE),
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
for line in run.stderr:
    if "started pid" in line:
        break
check("report: a stale report is removed when sbx starts", not os.path.lexists(REPORT))
run.terminate()
run.communicate(timeout=30)
with open(REPORT) as f:
    r = json.load(f)
check("report: SIGTERM is forwarded and reported", run.returncode == 143 and r["program"] == {"signaled": 15}, r)

LOG = f"{RDIR}/sbx.log"
rc, so, se = sbx(["--log", LOG, "--", "/bin/sh", "-c", "echo out; echo err >&2"])
with open(LOG) as f:
    logged = f.read()
check("log: the program's stderr has no sbx lines", rc == 0 and so == "out\n" and se == "err\n", repr(se))
check("log: sbx's lines are in the log file", "sbx: info: started pid" in logged and "sbx: info: exit 0" in logged,
      logged[-400:])
st = os.lstat(LOG)
check("log: owned by root, mode 0600", st.st_uid == 0 and st.st_mode & 0o7777 == 0o600, oct(st.st_mode))
expect("log: the program cannot read it", 1, ["--log", LOG, "--", "/bin/cat", LOG])
size = os.path.getsize(LOG)
FORGE = ("import ctypes, socket; ctypes.CDLL(None).prctl(15, b'x\\nsbx: info: fake', 0, 0, 0)\n"
         "try: socket.socket()\nexcept OSError: pass")
expect("log: a denial is logged", 0, ["--log", LOG, *py(FORGE)])
with open(LOG) as f:
    f.seek(size)
    added = f.read()
check("log: appended, with the program's name escaped",
      "denied socket for x\\nsbx: info: fa" in added and not any(l.startswith("sbx: info: fa") for l in added.splitlines()),
      added[-600:])
os.chmod(LOG, 0o644)
expect("log: a log file others can read is refused", 125, ["--log", LOG, "--", "/bin/true"], log="mode 0600")
os.unlink(LOG)

# ---------------------------------------------------------------- cgroup

print("== cgroup limits")


def delegated(memory_mb="unlimited", pids="unlimited"):
    return policy(cgroup={"mode": "delegated", "memory_mb": memory_mb, "pids": pids})


if REQUIRE_CGROUP == "false":
    rc, so, se = sbx([], pol=delegated(), cmd="probe")
    check("cgroup: probe reports delegation as missing", rc == 1 and "MISSING  cgroup delegation" in so, so + se)
    check_report("cgroup: delegated mode is refused here", ["--", "/bin/true"],
                 lambda r: r["exit_code"] == 125 and r["setup_error"]["stage"] == "cgroup", pol=delegated())
else:
    # sbx needs a cgroup of its own: move this suite out of the namespace's
    # root cgroup and run each delegated sbx in a fresh child of it.
    os.mkdir(f"{CG}/harness")
    with open(f"{CG}/cgroup.procs") as f:
        for pid in f.read().split():
            try:
                with open(f"{CG}/harness/cgroup.procs", "w") as g:
                    g.write(pid)
            except OSError:
                pass  # exited meanwhile
    with open(f"{CG}/cgroup.subtree_control", "w") as f:
        f.write("+memory +pids")
    N = [0]

    def cgroup_run(prepare=None):
        """A fresh cgroup for one sbx, and the wrapper that starts sbx in it."""
        N[0] += 1
        d = f"{CG}/run-{N[0]}"
        os.mkdir(d)
        if prepare:
            prepare(d)
        return d, ("/bin/sh", "-c", 'echo 0 > "$0/cgroup.procs" && exec "$@"', d)

    def restored(d):
        """sbx put its cgroup back as it found it."""
        with open(f"{d}/cgroup.subtree_control") as f:
            control = f.read().strip()
        subdirs = [e for e in os.listdir(d) if os.path.isdir(f"{d}/{e}")]
        return control == "" and subdirs == []

    def cgroup_report(name, args, cond, pol, prepare=None, **kw):
        d, wrap = cgroup_run(prepare)
        if os.path.lexists(REPORT):
            os.unlink(REPORT)
        rc, so, se = sbx(["--report", REPORT, *args], pol=pol, wrap=wrap, **kw)
        try:
            with open(REPORT) as f:
                r = json.load(f)
        except FileNotFoundError:
            r = None
        good = r is not None and r["exit_code"] == rc and cond(r)
        check(name, good and restored(d), f"rc={rc} report={r} restored={restored(d)} stderr={se[-600:]!r}")
        return d, r

    d, wrap = cgroup_run()
    rc, so, se = sbx([], pol=delegated(64, 32), cmd="probe", wrap=wrap)
    check("cgroup: probe tries delegation and leaves no trace", rc == 0 and "ok       cgroup delegation" in so
          and restored(d), so + se)
    cgroup_report("cgroup: a normal run is accounted", ["--", "/bin/sh", "-c", "/bin/true; /bin/true"],
                  lambda r: r["exit_code"] == 0 and r["cgroup"]["memory_mb"] == 64 and r["cgroup"]["pids"] == 32
                  and r["cgroup"]["oom_kills"] == 0 and r["cgroup"]["memory_peak_kib"] > 0, pol=delegated(64, 32))
    # Since kernel commit d245698d727a a task that was reaped or joined still
    # counts in its cgroup until its last context switch, so sbx's own check
    # children and threads can briefly keep C or sbx-supervisor busy (issue
    # #8). One cgroup for every round: a leftover also fails the next round.
    d, wrap = cgroup_run()
    flaky = []
    for i in range(50):
        rc, so, se = sbx([], pol=delegated(64, 32), cmd="probe", wrap=wrap)
        if rc != 0 or not restored(d):
            flaky.append(("probe", i, rc, se[-300:]))
        rc, so, se, r = reported(["--", "/bin/true"], pol=delegated(64, 32), wrap=wrap)
        if rc != 0 or r is None or r["setup_error"] is not None or not restored(d):
            flaky.append(("run", i, rc, se[-300:]))
    check("cgroup: 50 probes and runs in a row each leave sbx's cgroup as it was", not flaky, flaky[:3])

    def hold_supervisor(d, held):
        """Keep C/sbx-supervisor busy from setup until shortly after sbx's
        teardown has removed sbx-sandbox: sbx must wait for it, on any kernel."""
        def wait(cond):
            for _ in range(500):
                if cond():
                    return True
                time.sleep(0.01)
            return False
        if not wait(lambda: os.path.isdir(f"{d}/sbx-sandbox")):
            return
        p = subprocess.Popen(["/bin/sleep", "60"])
        try:
            with open(f"{d}/sbx-supervisor/cgroup.procs", "w") as f:
                f.write(str(p.pid))
            held.append(p.pid)
            wait(lambda: not os.path.exists(f"{d}/sbx-sandbox"))
            time.sleep(0.2)
        finally:
            p.kill()
            p.wait()

    d, wrap = cgroup_run()
    held = []
    t = threading.Thread(target=hold_supervisor, args=(d, held))
    t.start()
    rc, so, se, r = reported(["--", "/bin/sleep", "1"], pol=delegated(), wrap=wrap)
    t.join()
    check("cgroup: teardown waits for a busy sbx-supervisor", held and rc == 0 and r is not None
          and "restoring sbx's cgroup" not in se and restored(d), f"held={held} rc={rc} stderr={se[-600:]!r}")
    HOG ="x = b'x' * (256 << 20)"
    cgroup_report("cgroup: the OOM killer kills the program, not sbx", py(HOG),
                  lambda r: r["exit_code"] == 137 and r["program"] == {"signaled": 9} and r["cgroup"]["oom_kills"] >= 1,
                  pol=delegated(memory_mb=64))
    FORKS = """
import os, sys, time
kids = []
try:
    for _ in range(50):
        pid = os.fork()
        if pid == 0:
            time.sleep(60)
            os._exit(0)
        kids.append(pid)
except BlockingIOError:
    sys.exit(0)
sys.exit(1)
"""
    cgroup_report("cgroup: pids.max stops a fork bomb; the rest is killed", py(FORKS),
                  lambda r: r["exit_code"] == 0 and r["cgroup"]["pids_max_hits"] >= 1 and r["killed_after_exit"] == 7,
                  pol=delegated(pids=8))
    ESCAPE = """
import os, sys
cg = "/sys/fs/cgroup" + open("/proc/self/cgroup").read().strip()[3:]
fails = 0
for path, value in [(cg + "/memory.max", "max"), (os.path.dirname(cg) + "/sbx-supervisor/cgroup.procs", str(os.getpid()))]:
    try:
        with open(path, "w") as f:
            f.write(value)
    except OSError:
        fails += 1
sys.exit(0 if fails == 2 else 1)
"""
    cgroup_report("cgroup: the program cannot raise its limits or leave", py(ESCAPE),
                  lambda r: r["exit_code"] == 0, pol=delegated(memory_mb=64))

    def squat(d):
        p = subprocess.Popen(["/bin/sh", "-c", 'echo 0 > "$0/cgroup.procs" && exec /bin/sleep 60', d])
        for _ in range(50):
            with open(f"{d}/cgroup.procs") as f:
                if f.read().strip():
                    break
            time.sleep(0.1)
        SQUATTERS.append(p)

    SQUATTERS = []
    cgroup_report("cgroup: refused when other processes share sbx's cgroup", ["--", "/bin/true"],
                  lambda r: r["setup_error"]["stage"] == "cgroup"
                  and "also contains sleep" in " ".join(r["setup_error"]["messages"]),
                  pol=delegated(), prepare=squat)
    for p in SQUATTERS:
        p.kill()
        p.wait()

    def limit(d):
        with open(f"{d}/memory.max", "w") as f:
            f.write(str(32 << 20))

    cgroup_report("cgroup: refused when the limit is not below the container's", ["--", "/bin/true"],
                  lambda r: r["setup_error"]["stage"] == "cgroup"
                  and "not below the container's own limit" in " ".join(r["setup_error"]["messages"]),
                  pol=delegated(memory_mb=64), prepare=limit)
    expect("cgroup: refused for a non-root sbx", 125, ["--", "/bin/true"], pol=delegated(), wrap=NR,
           log="needs sbx to start as root")
    time.sleep(0.2)
    for e in os.listdir(CG):
        if e.startswith("run-"):
            try:
                os.rmdir(f"{CG}/{e}")
            except OSError:
                pass

check("every run's report agrees with its exit code", not REPORT_MISMATCHES, REPORT_MISMATCHES[:5])

# ---------------------------------------------------------------- cleanup

shutil.rmtree(W, ignore_errors=True)
with open("/etc/resolv.conf", "w") as f:
    f.write(ORIGINAL_RESOLV_CONF)
for p in (SECRET, "/var/tmp/sbx-pwn"):
    if os.path.exists(p):
        os.unlink(p)
shutil.rmtree(RDIR, ignore_errors=True)
print(f"== {len(PASS)} passed, {len(FAIL)} failed")
for name in FAIL:
    print(f"  failed: {name}")
sys.exit(1 if FAIL else 0)
