#!/bin/sh
# Run tests/smoke.py on this Linux host, as root, inside a private mount
# namespace: the test volume is a fresh tmpfs over /mnt and /etc/resolv.conf
# is a throwaway copy (the DNS tests rewrite it), so the host is left untouched.
#
#   usage: tests/run-local.sh PATH-TO-SBX
set -eu

sbx=${1:?usage: tests/run-local.sh PATH-TO-SBX}
here=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" = 0 ] || { echo "run-local.sh: must run as root" >&2; exit 2; }
[ -f /etc/resolv.conf ] && [ ! -L /etc/resolv.conf ] || {
	echo "run-local.sh: /etc/resolv.conf must be a regular file (it is bind-mounted over)" >&2
	exit 2
}

work=$(mktemp -d /tmp/sbx-smoke.XXXXXX)
trap 'rm -rf "$work"' EXIT
chmod 755 "$work"
# The suite also runs sbx as uid 65534, so the binary must be reachable for it.
cp "$sbx" "$work/sbx"
chmod 755 "$work/sbx"
cp /etc/resolv.conf "$work/resolv.conf"

unshare --mount --propagation private -- sh -eu -c '
	mount -t tmpfs -o mode=0755 sbx-test-volume /mnt
	mount --bind "$1/resolv.conf" /etc/resolv.conf
	env -i PATH="$PATH" SBX="$1/sbx" TEST_VOLUME=/mnt python3 "$2/smoke.py"
' sh "$work" "$here"
