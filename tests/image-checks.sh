#!/bin/sh
# Checks of the runtime image as shipped: default policy, sbx as PID 1.
# (The full suite runs in the test image; this covers what only the real
# image and container entrypoint can show.)
#
#   usage: tests/image-checks.sh IMAGE      (DOCKER, PLATFORM from the environment)
set -eu

image=${1:?usage: tests/image-checks.sh IMAGE}
docker=${DOCKER:?set DOCKER}
platform=${PLATFORM:?set PLATFORM}
pass=0
fail=0
ok() { pass=$((pass + 1)); echo "  ok   $1"; }
bad() { fail=$((fail + 1)); printf '  FAIL %s\n       %s\n' "$1" "$2"; }
# --pull=never: check the image just built. With --platform, podman otherwise
# pulls the tag from the registry if it exists there.
run() { "$docker" run --rm --pull=never --platform "$platform" "$@"; }

echo "== runtime image $image"

if out=$(run --entrypoint /usr/local/bin/sbx "$image" probe 2>&1); then
	ok "probe passes with the default policy"
else
	bad "probe passes with the default policy" "$out"
fi

out=$(run "$image" -- /bin/echo hello 2>&1) || true
case "$out" in *hello*) ok "runs a program as PID 1" ;; *) bad "runs a program as PID 1" "$out" ;; esac

out=$(run "$image" -- /usr/bin/id -u 2>/dev/null) || true
[ "$out" = 65534 ] && ok "program runs as uid 65534" || bad "program runs as uid 65534" "id -u: $out"

rc=0
out=$(run "$image" 2>&1) || rc=$?
[ "$rc" = 2 ] && ok "default CMD explains how to pass a program (exit 2)" || bad "default CMD" "rc=$rc $out"

rc=0
run "$image" -- /bin/cat /etc/hostname >/dev/null 2>&1 || rc=$?
[ "$rc" != 0 ] && ok "files outside the policy are unreadable" || bad "files outside the policy are unreadable" "rc=$rc"

start=$(date +%s)
run "$image" -- /bin/sh -c 'setsid /bin/sleep 300 >/dev/null 2>&1 & echo started' >/dev/null 2>&1 || true
took=$(($(date +%s) - start))
[ "$took" -lt 30 ] && ok "leftover processes are killed when the program exits" || bad "leftover processes" "container ran ${took}s"

cid=$("$docker" run -d --pull=never --platform "$platform" "$image" -- /bin/sleep 300)
sleep 1
"$docker" stop -t 10 "$cid" >/dev/null
code=$("$docker" inspect -f '{{.State.ExitCode}}' "$cid")
"$docker" rm "$cid" >/dev/null
[ "$code" = 143 ] && ok "docker stop is forwarded as SIGTERM (exit 143)" || bad "SIGTERM forwarding" "exit code $code"

rc=0
out=$(run -e SBX_POLICY_FILE=/etc/sbx/egress.example.toml "$image" -- /bin/true 2>&1) || rc=$?
if [ "$rc" = 125 ] && echo "$out" | grep -q CAP_SYS_PTRACE; then
	ok "egress mode refuses to start without CAP_SYS_PTRACE"
else
	bad "egress mode without CAP_SYS_PTRACE" "rc=$rc $out"
fi

if out=$(run --cap-add SYS_PTRACE -e SBX_POLICY_FILE=/etc/sbx/egress.example.toml \
	--entrypoint /usr/local/bin/sbx "$image" probe 2>&1); then
	ok "probe passes for the egress example with CAP_SYS_PTRACE"
else
	bad "probe for the egress example with CAP_SYS_PTRACE" "$out"
fi

rc=0
out=$(run -e SBX_TIMOUT=5 "$image" -- /bin/true 2>&1) || rc=$?
if [ "$rc" = 125 ] && echo "$out" | grep -q "unknown environment variable SBX_TIMOUT"; then
	ok "unknown SBX_* variables are refused"
else
	bad "unknown SBX_* variables are refused" "rc=$rc $out"
fi

echo "== $pass passed, $fail failed"
[ "$fail" = 0 ]
