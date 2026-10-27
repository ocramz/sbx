#!/bin/sh
# Escape-attempt test suite. Run as root (like the container entrypoint):
#   SBX=/usr/local/bin/sbx sh tests/smoke.sh
# On Cloud Run: execute a job with args ["sh","/opt/sbx/smoke.sh"] and an entrypoint override.
set -u
SBX=${SBX:-sbx}
PASS=0 FAIL=0
export SBX_QUIET=1
W=$(mktemp -d /tmp/sbxtest.XXXXXX); chmod 755 "$W"
BASE="--workdir /tmp --rx $W"

ok()   { PASS=$((PASS+1)); echo "  ok   $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL $1"; }
# expect <0|nonzero> <name> <sbx args...>
expect() {
  want=$1 name=$2; shift 2
  out=$("$SBX" run $BASE "$@" 2>&1 </dev/null); rc=$?
  if { [ "$want" = 0 ] && [ $rc -eq 0 ]; } || { [ "$want" != 0 ] && [ $rc -ne 0 ]; }
  then ok "$name"; else bad "$name (rc=$rc) :: $(echo "$out" | tail -2)"; fi
}
# expect_rc <exit code> <name> <sbx args...>
expect_rc() {
  want=$1 name=$2; shift 2
  out=$("$SBX" run $BASE "$@" 2>&1 </dev/null); rc=$?
  if [ $rc -eq "$want" ]; then ok "$name"; else bad "$name (rc=$rc, want $want) :: $(echo "$out" | tail -2)"; fi
}
has() { command -v "$1" >/dev/null 2>&1; }
# Every "cannot" test below targets something DAC alone would allow for uid 65534
# (world-readable file / world-writable dir), so only Landlock/seccomp can block it.

echo "== probe"; "$SBX" probe || { echo "kernel cannot enforce sandbox"; exit 1; }

echo "== baseline"
expect 0 "runs a program"                   -- /bin/echo hi
expect 0 "drops to uid 65534"               -- /bin/sh -c 'test "$(id -u)" = 65534'
SECRET_TOKEN=leak expect 0 "env is scrubbed" -- /bin/sh -c 'test -z "${SECRET_TOKEN:-}"'

echo "== filesystem (Landlock)"
SECRET_FILE=/var/tmp/sbx-secret; echo topsecret > $SECRET_FILE; chmod 644 $SECRET_FILE
expect 1 "cannot read outside allow-list"   -- /bin/cat "$SECRET_FILE"
expect 1 "cannot list /etc"                 -- /bin/ls /etc
expect 0 "can read allowed file"            -- /bin/cat /etc/passwd
expect 1 "cannot write to world-writable /var/tmp" -- /bin/sh -c 'echo x > /var/tmp/sbx-pwn'
expect 0 "can write to /tmp"                -- /bin/sh -c 'echo x > /tmp/sbx-ok && rm /tmp/sbx-ok'
cp /bin/true /tmp/sbx-true; chmod 755 /tmp/sbx-true
expect 1 "cannot exec from rw-only /tmp"    -- /tmp/sbx-true
expect 1 "subprocess inherits fs rules"     -- /bin/sh -c "/bin/sh -c '/bin/cat $SECRET_FILE'"
mkdir -p /mnt/sbxvol && (mountpoint -q /mnt/sbxvol || mount -t tmpfs tmpfs /mnt/sbxvol) 2>/dev/null
if mountpoint -q /mnt/sbxvol 2>/dev/null; then
  chmod 777 /mnt/sbxvol
  expect 0 "volume granted rw is writable"  --rw /mnt/sbxvol -- /bin/sh -c 'echo x > /mnt/sbxvol/f'
  expect 1 "volume granted ro is read-only" --ro /mnt/sbxvol -- /bin/sh -c 'echo y > /mnt/sbxvol/g'
  expect 0 "volume granted ro is readable"  --ro /mnt/sbxvol -- /bin/cat /mnt/sbxvol/f
  expect 1 "ungranted volume is invisible"  -- /bin/cat /mnt/sbxvol/f
  umount /mnt/sbxvol 2>/dev/null
fi

echo "== process supervision"
expect_rc 124 "timeout kills (exit 124)"         --timeout 1 -- /bin/sleep 5
"$SBX" run $BASE -- /bin/sh -c 'setsid /bin/sleep 300 >/dev/null 2>&1 & echo started' >/dev/null 2>&1
sleep 0.3
if grep -qs "sleep.300" /proc/[0-9]*/cmdline; then bad "orphans killed on exit"; else ok "orphans killed on exit"; fi
expect 1 "--no-subprocesses blocks fork"    --no-subprocesses -- /bin/sh -c '/bin/true; /bin/true'
if has setpriv; then
  # sbx started as non-root: sandbox shares its uid, so only Landlock scoping (ABI v6+) protects it.
  NR="setpriv --reuid 65534 --regid 65534 --clear-groups"
  r() { $NR "$SBX" run --workdir /tmp "$@" </dev/null >/dev/null 2>&1; }
  r -- /bin/sh -c 'kill -0 $PPID'; [ $? -ne 0 ] && ok "same-uid: cannot signal supervisor" || bad "same-uid: cannot signal supervisor"
  r -- /bin/cat $SECRET_FILE;       [ $? -ne 0 ] && ok "same-uid: fs rules still enforced" || bad "same-uid: fs rules still enforced"
  r -- /bin/true;                   [ $? -eq 0 ] && ok "same-uid: runs" || bad "same-uid: runs"
  SBX_TEST_SECRET=x r -- /bin/sh -c 'grep -q SBX_TEST_SECRET /proc/$PPID/environ'
  [ $? -ne 0 ] && ok "same-uid: cannot read supervisor /proc/PID/environ" || bad "same-uid: cannot read supervisor /proc/PID/environ"
fi

echo "== seccomp + network"
if has python3; then
  PY=$(command -v python3); PYDIR=$(dirname "$(readlink -f "$PY")")
  P="--rx $PYDIR"
  expect 1 "no AF_INET sockets (mode none)"  $P -- "$PY" -c 'import socket; socket.socket()'
  expect 0 "AF_UNIX sockets still work"      $P -- "$PY" -c 'import socket; socket.socketpair()'
  expect 1 "no user namespaces (unshare)"    $P -- "$PY" -c 'import os; os.unshare(os.CLONE_NEWUSER)'
  expect 1 "no ptrace"                       $P -- "$PY" -c 'import ctypes; l=ctypes.CDLL(None,use_errno=True); assert l.ptrace(0,0,0,0)==0'
  expect 1 "no io_uring"                     $P -- "$PY" -c 'import ctypes; l=ctypes.CDLL(None,use_errno=True); assert l.syscall(425,1,ctypes.create_string_buffer(120))>=0'
  expect 1 "clone3 -> ENOSYS"                $P -- "$PY" -c 'import ctypes,errno; l=ctypes.CDLL(None,use_errno=True); l.syscall(435,0,0); assert ctypes.get_errno()!=errno.ENOSYS'
  expect 0 "threads still work"              $P --no-subprocesses -- "$PY" -c 'import threading; t=threading.Thread(target=print); t.start(); t.join()'
  CONNECT='import socket,sys,errno
s=socket.socket(); s.settimeout(1)
try: s.connect(("127.0.0.1", int(sys.argv[1])))
except PermissionError: sys.exit(1)
except OSError: sys.exit(0)'
  expect 0 "restricted: allowed port reachable"  $P --net tcp:4443 -- "$PY" -c "$CONNECT" 4443
  expect 1 "restricted: other port denied"       $P --net tcp:4443 -- "$PY" -c "$CONNECT" 80
  expect 1 "restricted: UDP denied"              $P --net tcp:4443 -- "$PY" -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM)'
  expect 0 "restricted+udp: UDP allowed"         $P --net tcp:4443+udp -- "$PY" -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM)'
  expect_rc 159 "seccomp kill mode -> SIGSYS"   $P --seccomp-action kill -- "$PY" -c 'import os; os.unshare(os.CLONE_NEWUSER)'
else
  echo "  (python3 not found: skipping seccomp/network tests)"
fi

rm -rf "$W" /tmp/sbx-true "$SECRET_FILE" /var/tmp/sbx-pwn
echo "== $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
