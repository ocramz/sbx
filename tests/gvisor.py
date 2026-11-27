#!/usr/bin/env python3
"""sbx under gVisor: the policy filter without a listener (seccomp.notify = "off").

Runs as root in a disposable gVisor sandbox, next to a static sbx and the
shipped policies: as a Modal sandbox's own command (tests/modal_gvisor.py, the
way a wrapper runs sbx there), or e.g. under docker run --runtime=runsc.

  SBX     the sbx binary (default /usr/local/bin/sbx)
  POLICY  the gVisor example policy (default /etc/sbx/gvisor.example.toml)

It prints the platform facts, then checks that sbx enforces the policy
filter without a listener: a denied call kills the process with SIGSYS (or
fails with EPERM), and the report's denials is null. That includes shmget,
once seccomp.deny names the SysV IPC calls and mq_open. It creates /workspace
(the policy's workdir) if missing and writes reports under /var/lib. Exit
code 1 if a check fails, 2 if the environment is wrong.
"""

import json
import os
import subprocess
import sys
import tempfile

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
    print(f"gvisor: {msg}", file=sys.stderr, flush=True)
    sys.exit(2)


SBX = os.environ.get("SBX", "/usr/local/bin/sbx")
POLICY = os.environ.get("POLICY", "/etc/sbx/gvisor.example.toml")
if os.geteuid() != 0:
    die("run as root (sbx is tested the way a container entrypoint runs it)")
if not os.access(SBX, os.X_OK):
    die(f"{SBX} is not executable")
if not os.path.isfile(POLICY):
    die(f"{POLICY} is missing")
PY = os.path.realpath(sys.executable)
if not os.path.isdir("/workspace"):
    os.mkdir("/workspace")
    os.chmod("/workspace", 0o1777)
# Reports go to a directory only root can write, as sbx requires.
RDIR = "/var/lib/sbx-gvisor"
os.makedirs(RDIR, mode=0o700, exist_ok=True)
REPORT = f"{RDIR}/report.json"
# A clean environment for sbx: nothing from the sandbox platform leaks in.
BASE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}

with open(POLICY) as f:
    EXAMPLE = f.read()
W = tempfile.mkdtemp(prefix="sbx-gvisor.")
os.chmod(W, 0o755)


def variant(name, *replacements):
    """The example with each (old, new) substring replaced exactly once."""
    text = EXAMPLE
    for old, new in replacements:
        if text.count(old) != 1:
            die(f"{POLICY}: expected {old!r} exactly once")
        text = text.replace(old, new)
    path = f"{W}/{name}.toml"
    with open(path, "w") as f:
        f.write(text)
    return path


LISTENER = variant("listener", ('notify = "off"', 'notify = "listener"'))
ERRNO = variant("errno", ('on_violation = "kill"', 'on_violation = "errno"'))
NO_SENDMSG = variant("no-sendmsg", ('on_violation = "kill"', 'on_violation = "errno"'),
                     ("deny = []", 'deny = ["sendmsg"]'))
NO_IPC = variant("no-ipc", ("deny = []", 'deny = ["msgget", "mq_open", "semget", "shmget"]'))


def sbx(args, pol=POLICY, cmd="run"):
    """Run sbx; for `run`, also return its report (None if there is none)."""
    if cmd == "run":
        if os.path.lexists(REPORT):
            os.unlink(REPORT)
        args = ["--report", REPORT, *args]
    p = subprocess.run([SBX, cmd, *args], env={**BASE_ENV, "SBX_POLICY_FILE": pol}, capture_output=True,
                       text=True, timeout=120, stdin=subprocess.DEVNULL)
    report = None
    if cmd == "run" and os.path.exists(REPORT):
        with open(REPORT) as f:
            report = json.load(f)
    return p.returncode, p.stdout, p.stderr, report


def py(code):
    return ["--", PY, "-c", code]


def status_fields(text):
    return {k: v.strip() for k, v in (l.split(":", 1) for l in text.splitlines() if ":" in l)}


def mounted(path):
    try:
        with open("/proc/mounts") as f:
            return "yes" if any(l.split()[1:2] == [path] for l in f) else "no"
    except OSError as e:
        return f"? ({e.strerror})"


def show(text):
    for line in text.splitlines():
        print(f"       {line}")


# ---------------------------------------------------------------- facts

print("== platform")
u = os.uname()
print(f"  kernel          {u.release} {u.version} ({u.machine})")
with open("/proc/self/status") as f:
    me = status_fields(f.read())
print(f"  this process    uid {os.getuid()}, Seccomp {me.get('Seccomp', '?')}, "
      f"{me.get('Seccomp_filters', '?')} filters, NoNewPrivs {me.get('NoNewPrivs', '?')}")
print(f"  capabilities    CapBnd {me.get('CapBnd', '?')}, CapEff {me.get('CapEff', '?')}")
print(f"  sbx             {subprocess.run([SBX, 'version'], capture_output=True, text=True).stdout.strip()}")
print(f"  SysV IPC        /proc/sysvipc {'present' if os.path.isdir('/proc/sysvipc') else 'absent'}; "
      f"/dev/mqueue mounted: {mounted('/dev/mqueue')}")

print("== probe")
rc, so, se, _ = sbx([], cmd="probe")
show(so + se)
check("probe: the gVisor example is enforceable, with the 'seccomp filter' check",
      rc == 0 and any(l.startswith("ok") and "seccomp filter" in l for l in so.splitlines()), f"rc={rc}")
rc, so_l, se_l, _ = sbx([], pol=LISTENER, cmd="probe")
NO_LISTENER = any(l.startswith("MISSING") and "seccomp user notification" in l for l in so_l.splitlines())
print(f"  fact: the same policy with notify = \"listener\": probe exit {rc}; "
      f"{'no seccomp user notification here' if NO_LISTENER else 'this platform has seccomp user notification'}")
show(so_l + se_l)
if NO_LISTENER:
    rc, so, se, r = sbx(["--", "/bin/true"], pol=LISTENER)
    check("listener: sbx run refuses to start (exit 125, stage capabilities)",
          rc == 125 and r is not None and (r["setup_error"] or {}).get("stage") == "capabilities"
          and "seccomp user notification" in " ".join(r["setup_error"]["messages"]),
          f"rc={rc} report={r} stderr={se[-600:]!r}")

# ---------------------------------------------------------------- the sandbox

print("== sandbox")
rc, so, se, r = sbx(py("print('hello')"))
check("runs a program; the report's denials is null",
      rc == 0 and so == "hello\n" and r is not None and r["program"] == {"exited": 0} and r["denials"] is None
      and len(r) == 12, f"rc={rc} stdout={so!r} report={r} stderr={se[-600:]!r}")
check("warns at setup that denials are not seen", 'warning: seccomp.notify = "off"' in se, se[-600:])
rc, so, se, _ = sbx(["--quiet", "--", "/bin/cat", "/proc/self/status"])
inner = status_fields(so)
print(f"  fact: in the sandbox, Seccomp {inner.get('Seccomp', '?')}, {inner.get('Seccomp_filters', '?')} filters, "
      f"CapBnd {inner.get('CapBnd', '?')}")
check("the program runs as 65534 with no_new_privs and no capabilities",
      rc == 0 and inner.get("Uid", "").split()[:1] == ["65534"] and inner.get("NoNewPrivs") == "1"
      and inner.get("CapEff") == "0000000000000000" and inner.get("CapBnd") == "0000000000000000", so + se)

print("== denials, on_violation = \"kill\"")
INET = "import socket\nsocket.socket()"  # AF_INET: the policy allows unix sockets only
rc, so, se, r = sbx(py(INET))
check("socket(AF_INET) kills the program with SIGSYS (exit 159); denials is null",
      rc == 159 and r is not None and r["program"] == {"signaled": 31} and r["denials"] is None,
      f"rc={rc} report={r} stderr={se[-600:]!r}")
check("... unlogged, with the SIGSYS hint", "seccomp: denied" not in se and "(SIGSYS" in se, se[-600:])
rc, so, se, r = sbx(py("import os; os.unshare(os.CLONE_NEWUSER)"))
check("unshare (the built-in deny-list) kills with SIGSYS", rc == 159 and r is not None
      and r["program"] == {"signaled": 31}, f"rc={rc} report={r} stderr={se[-600:]!r}")
rc, so, se, r = sbx(py("import subprocess, sys\n"
                       "r = subprocess.run([sys.executable, '-c', 'import socket; socket.socket()'])\n"
                       "sys.exit(0 if r.returncode == -31 else 1)"))
check("a forked child inherits the filter and is killed with SIGSYS", rc == 0, f"rc={rc} stderr={se[-600:]!r}")
rc, so, se, r = sbx(py("import socket; socket.socketpair()"))
check("AF_UNIX sockets work (the argument check lets them through)", rc == 0, f"rc={rc} stderr={se[-600:]!r}")
# shmget(IPC_PRIVATE, 4096, 0600): exit 0 if it works (and remove the segment), 1 on EPERM.
SHMGET = ("import ctypes, errno\nl = ctypes.CDLL(None, use_errno=True)\nid = l.shmget(0, 4096, 0o600)\n"
          "if id >= 0: l.shmctl(id, 0, None); raise SystemExit(0)\n"
          "raise SystemExit(1 if ctypes.get_errno() == errno.EPERM else 2)")
rc, so, se, r = sbx(py(SHMGET))
check("shmget works when it is not denied", rc == 0, f"rc={rc} stderr={se[-600:]!r}")
rc, so, se, r = sbx(py(SHMGET), pol=NO_IPC)
check("with the SysV calls and mq_open in seccomp.deny, shmget kills with SIGSYS; denials is null",
      rc == 159 and r is not None and r["program"] == {"signaled": 31} and r["denials"] is None,
      f"rc={rc} report={r} stderr={se[-600:]!r}")

print("== denials, on_violation = \"errno\"")
EPERM = ("import errno, socket\ntry: socket.socket()\n"
         "except OSError as e: raise SystemExit(0 if e.errno == errno.EPERM else 2)\nraise SystemExit(3)")
rc, so, se, r = sbx(["--seccomp-action", "errno", *py(EPERM)])
check("--seccomp-action errno: socket(AF_INET) fails with EPERM; denials is null",
      rc == 0 and r is not None and r["program"] == {"exited": 0} and r["denials"] is None,
      f"rc={rc} report={r} stderr={se[-600:]!r}")
rc, so, se, r = sbx(py(EPERM), pol=ERRNO)
check("on_violation = \"errno\" in the policy: the same", rc == 0, f"rc={rc} stderr={se[-600:]!r}")
rc, so, se, r = sbx(py("import ctypes, errno; l = ctypes.CDLL(None, use_errno=True); l.syscall(435, 0, 0)\n"
                       "raise SystemExit(0 if ctypes.get_errno() == errno.ENOSYS else 1)"), pol=ERRNO)
check("clone3 -> ENOSYS (the prelude)", rc == 0, f"rc={rc} stderr={se[-600:]!r}")
rc, so, se, r = sbx(py("import errno, socket\na, b = socket.socketpair()\ntry: a.sendmsg([b'x'])\n"
                       "except OSError as e: raise SystemExit(0 if e.errno == errno.EPERM else 2)\n"
                       "raise SystemExit(3)"), pol=NO_SENDMSG)
check("seccomp.deny may include sendmsg: it fails with EPERM", rc == 0, f"rc={rc} stderr={se[-600:]!r}")

print(f"gvisor: {len(PASS)} passed, {len(FAIL)} failed")
for name in FAIL:
    print(f"  FAIL {name}")
sys.exit(1 if FAIL else 0)
