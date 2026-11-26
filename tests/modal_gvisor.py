#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["modal==1.6.4"]
# ///
"""Run tests/gvisor.py in a Modal sandbox under gVisor.

  usage: uv run tests/modal_gvisor.py [--runtime gvisor|vm] SBX

SBX is a static linux/amd64 sbx binary; `make gvisor` builds one and runs this
script. The sandbox image is Modal's debian_slim with SBX at
/usr/local/bin/sbx, the shipped policies in /etc/sbx and the suite in
/opt/sbx/tests. The suite runs as the sandbox's own command, as a wrapper runs
sbx there (under gVisor that command lacks CAP_SYS_PTRACE, unlike `exec`'d
ones). `--runtime vm` runs the same suite in a Modal VM, as a control.

Modal's client finds the credentials itself: ~/.modal.toml (`modal token
new`), or MODAL_TOKEN_ID and MODAL_TOKEN_SECRET. The app `sbx-gvisor` is
created if missing; the sandbox is terminated when the suite ends. Exit code:
the suite's (0: every check passed).
"""

import argparse
import struct
import sys
from pathlib import Path

import modal

REPO = Path(__file__).resolve().parent.parent
APP = "sbx-gvisor"
SUITE = "/opt/sbx/tests/gvisor.py"
EM_X86_64 = 62
PT_INTERP = 3


def check_static_amd64(path: Path) -> None:
    """Fail unless path is a static x86-64 ELF executable: Modal runs amd64,
    and the sandbox image has no musl loader."""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        sys.exit(f"modal_gvisor: {path} is not a 64-bit little-endian ELF file")
    (machine,) = struct.unpack_from("<H", data, 18)
    if machine != EM_X86_64:
        sys.exit(f"modal_gvisor: {path} is for ELF machine {machine}, not x86-64 ({EM_X86_64}); "
                 "build it with PLATFORM=linux/amd64")
    (phoff,) = struct.unpack_from("<Q", data, 32)
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    for i in range(phnum):
        (p_type,) = struct.unpack_from("<I", data, phoff + i * phentsize)
        if p_type == PT_INTERP:
            sys.exit(f"modal_gvisor: {path} is dynamically linked; sbx must be static")


def image(sbx: Path) -> modal.Image:
    img = modal.Image.debian_slim(python_version="3.13").add_local_file(sbx, "/usr/local/bin/sbx", copy=True)
    for policy in sorted((REPO / "policy").glob("*.toml")):
        img = img.add_local_file(policy, f"/etc/sbx/{policy.name}", copy=True)
    img = img.add_local_file(REPO / "tests" / "gvisor.py", SUITE, copy=True)
    return img.run_commands("chmod 0755 /usr/local/bin/sbx", "mkdir -p /workspace && chmod 1777 /workspace")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("sbx", type=Path, help="a static linux/amd64 sbx binary")
    ap.add_argument("--runtime", choices=["gvisor", "vm"], default="gvisor",
                    help="Modal's sandbox runtime (default gvisor; vm is the control)")
    args = ap.parse_args()
    check_static_amd64(args.sbx)

    app = modal.App.lookup(APP, create_if_missing=True)
    print(f"== Modal sandbox ({args.runtime}), app {APP}", flush=True)
    sb = modal.Sandbox.create("python3", "-u", SUITE, app=app, image=image(args.sbx), runtime=args.runtime,
                              timeout=600)
    try:
        for line in sb.stdout:
            print(line, end="", flush=True)
        sb.wait()
        err = sb.stderr.read()
        if err:
            print(err, end="", file=sys.stderr, flush=True)
        rc = sb.returncode
    finally:
        sb.terminate()
    print(f"== the suite exited {rc}", flush=True)
    return rc if isinstance(rc, int) else 1


if __name__ == "__main__":
    sys.exit(main())
