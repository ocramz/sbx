#!/usr/bin/env python3
"""Egress cases on the real network, run inside the sandbox on Cloud Run.

The cases assume the rules of the shipped egress example policies
(api.github.com:443, *.githubusercontent.com:443) plus RULES, which the caller
passes to sbx in SBX_EGRESS. Two callers:

  tests/live.py   one sbx run per case:  live_net.py one KIND HOST PORT
                  (exit 0 connected, 13 denied, 3 the name did not resolve),
                  then checks sbx's log line for the case
  tests/cloud-run.sh, job sbx-live-pid1: sbx is the container's PID 1 and runs
                  live_net.py job, which runs every case in that one sandbox
                  (sbx's log lines go to Cloud Logging, so only exit codes count)

live.py passes this file's source to `python3 -c`, so it imports nothing from
tests/.
"""

import errno
import os
import random
import select
import socket
import ssl
import struct
import sys

# Added to the example policy's rules. One line: tests/cloud-run.sh reads it with sed.
RULES = "1.1.1.1/32:443,www.github.com:443,metadata.google.internal:80"

# (name, probe kind, host, port, exit code, a line sbx logs for it or None)
CASES = [
    ("allowed name resolves and connects", "tcp", "api.github.com", 443, 0, "dns: api.github.com ->"),
    ("TLS to an allowed name verifies and gets an HTTP reply", "tls", "api.github.com", 443, 0, None),
    ("allowed name on another port is denied", "tcp", "api.github.com", 80, 13,
     "port 80 is not allowed for that name"),
    ("wildcard rule allows a name below it", "tcp", "raw.githubusercontent.com", 443, 0,
     "dns: raw.githubusercontent.com ->"),
    ("wildcard rule does not match the bare domain", "tcp", "githubusercontent.com", 443, 3,
     "dns: denied A githubusercontent.com"),
    ("CNAME answer is learned for the name asked", "tcp", "www.github.com", 443, 0, "dns: www.github.com ->"),
    ("CIDR rule allows its address", "tcp", "1.1.1.1", 443, 0, None),
    ("non-blocking connect to a remote address completes", "nonblock", "1.1.1.1", 443, 0, None),
    ("CIDR rule's address on another port is denied", "tcp", "1.1.1.1", 80, 13, "denied connect to 1.1.1.1:80"),
    ("address next to the CIDR rule is denied", "tcp", "1.0.0.1", 443, 13, "denied connect to 1.0.0.1:443"),
    ("public resolver over TCP is denied (no DNS bypass)", "tcp", "8.8.8.8", 53, 13, "denied connect to 8.8.8.8:53"),
    ("metadata server is denied", "tcp", "169.254.169.254", 80, 13, "denied connect to 169.254.169.254:80"),
    # On Cloud Run the name comes from /etc/hosts, so only the connect is filtered.
    ("allowed name for the metadata server cannot reach it", "tcp", "metadata.google.internal", 80, 13,
     "denied connect to 169.254.169.254:80"),
    ("link-local DNS answer for an allowed name is not learned", "dns", "metadata.google.internal", 80, 13,
     "not added to the egress allow-set"),
    ("unlisted name gets NXDOMAIN", "tcp", "example.com", 443, 3, "dns: denied A example.com"),
]


def resolve_via_proxy(host):
    """The A records for host, asked of resolv.conf's nameserver over TCP, bypassing /etc/hosts."""
    with open("/etc/resolv.conf") as f:
        ns = next(l.split()[1] for l in f if l.startswith("nameserver "))
    q = struct.pack("!HHHHHH", random.getrandbits(16), 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(l)]) + l.encode() for l in host.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
    with socket.create_connection((ns, 53), timeout=10) as s:
        s.sendall(struct.pack("!H", len(q)) + q)
        r = s.makefile("rb")
        m = r.read(struct.unpack("!H", r.read(2))[0])
    if m[:2] != q[:2] or m[3] & 0xf == 3:
        raise socket.gaierror(socket.EAI_NONAME, f"no answer for {host} (rcode {m[3] & 0xf})")

    def skip_name(i):
        while m[i] and m[i] & 0xc0 != 0xc0:
            i += 1 + m[i]
        return i + (2 if m[i] else 1)

    i, ips = skip_name(12) + 4, []
    for _ in range(struct.unpack("!H", m[6:8])[0]):
        i = skip_name(i)
        rtype, _, _, rdlen = struct.unpack("!HHIH", m[i:i + 10])
        if rtype == 1:
            ips.append(socket.inet_ntoa(m[i + 10:i + 14]))
        i += 10 + rdlen
    return ips


def probe(kind, host, port):
    """0 connected, 13 denied (EACCES), 3 the name did not resolve. Anything else raises."""
    try:
        if kind == "tcp":
            socket.create_connection((host, port), timeout=10).close()
        elif kind == "dns":
            ips = resolve_via_proxy(host)
            if not ips:
                raise socket.gaierror(socket.EAI_NODATA, f"no A records for {host}")
            socket.create_connection((ips[0], port), timeout=10).close()
        elif kind == "tls":
            # Any HTTP status will do: the point is a verified TLS session through the filter.
            with socket.create_connection((host, port), timeout=10) as raw, \
                    ssl.create_default_context().wrap_socket(raw, server_hostname=host) as s:
                s.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: sbx-live\r\nConnection: close\r\n\r\n"
                          .encode())
                line = s.makefile("rb").readline()
                if not line.startswith(b"HTTP/1.1 "):
                    raise RuntimeError(f"not an HTTP reply: {line[:80]!r}")
        elif kind == "nonblock":
            addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4]
            with socket.socket() as s:
                s.setblocking(False)
                rc = s.connect_ex(addr)
                if rc == errno.EACCES:
                    raise PermissionError(rc, os.strerror(rc))
                if rc != errno.EINPROGRESS:
                    raise RuntimeError(f"connect_ex: {errno.errorcode.get(rc, rc)}, want EINPROGRESS")
                if not select.select([], [s], [], 10)[1]:
                    raise RuntimeError("connect did not complete in 10s")
                err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err:
                    raise RuntimeError(f"SO_ERROR {errno.errorcode.get(err, err)}")
        else:
            raise ValueError(f"unknown probe kind {kind!r}")
    except PermissionError:
        return 13
    except socket.gaierror as e:
        print("gaierror", e, file=sys.stderr)
        return 3
    return 0


def job():
    """Every case in this sandbox, sbx being the container's PID 1 (job sbx-live-pid1)."""
    passed, failed = [], []

    def check(name, cond, detail=""):
        print(f"  ok   {name}" if cond else f"  FAIL {name}\n       {detail}", flush=True)
        (passed if cond else failed).append(name)

    check("sbx is PID 1 (the program's parent)", os.getppid() == 1, f"parent pid {os.getppid()}")
    check("runs as uid 65534", os.getuid() == 65534, f"uid {os.getuid()}")
    try:
        with open("sbx-live-probe", "w") as f:
            f.write("x")
        os.unlink("sbx-live-probe")
        check("the working directory volume is writable", True)
    except OSError as e:
        check("the working directory volume is writable", False, f"{os.getcwd()}: {e}")
    for name, kind, host, port, want, _ in CASES:
        try:
            rc = probe(kind, host, port)
        except Exception as e:
            rc = f"{type(e).__name__}: {e}"
        check(name, rc == want, f"{kind} {host}:{port}: got {rc}, want {want}")
    print(f"== {len(passed)} passed, {len(failed)} failed", flush=True)
    for name in failed:
        print(f"  failed: {name}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "one":
        sys.exit(probe(sys.argv[2], sys.argv[3], int(sys.argv[4])))
    if sys.argv[1:] == ["job"]:
        sys.exit(job())
    print("usage: live_net.py one KIND HOST PORT | job", file=sys.stderr)
    sys.exit(2)
