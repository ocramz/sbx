#!/usr/bin/env python3
"""HTTP front for the test suites on a Cloud Run service (see tests/cloud-run.sh).

A Cloud Run service has to serve HTTP on $PORT, so this server is the
container's entrypoint and runs one suite per request, as root, the way an
operator's server runs sbx:

  GET /             ok
  GET /suite/live   tests/live.py   (platform facts, egress on the real network)
  GET /suite/smoke  tests/smoke.py  (the integration suite)

The suite's output is streamed back while it runs and copied to stdout, so it
also reaches Cloud Logging. The response always ends with "== exit N".
One suite runs at a time; a request made meanwhile gets 409.

Required environment:
  PORT         set by Cloud Run
  TEST_VOLUME  the suites' volume; emptied before each smoke run
"""

import http.server
import os
import shutil
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
SUITES = {"/suite/live": "live.py", "/suite/smoke": "smoke.py"}
BUSY = threading.Lock()


def die(msg):
    print(f"live_server: {msg}", file=sys.stderr)
    sys.exit(2)


PORT = int(os.environ.get("PORT") or die("set PORT"))
VOLUME = os.environ.get("TEST_VOLUME") or die("set TEST_VOLUME")


def empty(path):
    for name in os.listdir(path):
        p = os.path.join(path, name)
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)
        else:
            os.unlink(p)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/":
            return self.reply(200, "ok\n")
        suite = SUITES.get(self.path)
        if suite is None:
            return self.reply(404, f"unknown path {self.path}; try one of {', '.join(SUITES)}\n")
        if not BUSY.acquire(blocking=False):
            return self.reply(409, "a suite is already running\n")
        try:
            self.run(suite)
        finally:
            BUSY.release()

    def reply(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def run(self, suite):
        if suite == "smoke.py":
            empty(VOLUME)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        self.client = True
        self.send(f"== suite {suite}\n".encode())
        p = subprocess.Popen([sys.executable, "-u", os.path.join(HERE, suite)], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout:
            self.send(line)
        self.send(f"== exit {p.wait()}\n".encode())
        if self.client:
            self.wfile.write(b"0\r\n\r\n")

    def send(self, data):
        """Copy one line to stdout and, while the client is still there, to the response."""
        sys.stdout.buffer.write(data)
        sys.stdout.flush()
        if not self.client:
            return
        try:
            self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
            self.wfile.flush()
        except OSError:
            # The suite keeps running and its output still reaches the logs.
            self.client = False


print(f"live_server: listening on port {PORT}", flush=True)
http.server.ThreadingHTTPServer(("", PORT), Handler).serve_forever()
