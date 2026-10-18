"""Startup preflight for the privileged telemetry mode.

Checks root, BCC, tracefs access, every required tracepoint and kernel
headers for BCC. When headers are missing and we are root, it attempts
`modprobe kheaders` (WSL does not keep the module loaded across restarts) and
reports the actual result. It never changes boot configuration.

Status values: PASS, FAIL, BLOCKED (cannot be checked/obtained without a
missing privilege or prerequisite), INFO (not required).

Usage: python3 -m processpulse.preflight [--no-modprobe]  (exit 0 iff ok)
"""

import json
import os
import platform
import shutil
import subprocess
import sys

from .syscalls import SYSCALLS

TRACEFS = "/sys/kernel/tracing"
REQUIRED = ("root", "bcc_import", "tracefs", "tracepoints", "kernel_headers")


def _headers_present():
    build = f"/lib/modules/{platform.release()}/build"
    if os.path.isdir(build):
        return build
    if os.path.exists("/sys/kernel/kheaders.tar.xz"):
        return "/sys/kernel/kheaders.tar.xz"
    return None


def _read_int(path):
    try:
        with open(path) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def run_preflight(attempt_modprobe=True):
    checks = []
    root = os.geteuid() == 0

    def add(name, status, detail):
        checks.append({"name": name, "status": status, "detail": detail})

    ubd = _read_int("/proc/sys/kernel/unprivileged_bpf_disabled")
    add("root", "PASS" if root else "BLOCKED",
        f"euid={os.geteuid()}; kernel.unprivileged_bpf_disabled={ubd}"
        + ("" if root else "; BCC requires root"))

    try:
        import bcc
        add("bcc_import", "PASS", f"bcc {getattr(bcc, '__version__', '?')} at {bcc.__file__}")
    except Exception as e:  # ImportError or a broken libbcc
        add("bcc_import", "FAIL", f"{type(e).__name__}: {e}")

    events = os.path.join(TRACEFS, "events")
    if os.access(events, os.R_OK | os.X_OK):
        add("tracefs", "PASS", f"{events} readable")
        wanted = [f"syscalls/sys_enter_{s}" for s in SYSCALLS] + ["sched/sched_process_exit"]
        missing = [w for w in wanted if not os.path.isdir(os.path.join(events, w))]
        add("tracepoints", "FAIL" if missing else "PASS",
            f"missing: {missing}" if missing else f"{len(wanted)} tracepoints present")
    else:
        add("tracefs", "BLOCKED" if not root else "FAIL", f"{events} not accessible")
        add("tracepoints", "BLOCKED", "tracefs not accessible")

    modprobe = None
    hdr = _headers_present()
    if hdr is None and root and attempt_modprobe:
        exe = shutil.which("modprobe") or "/usr/sbin/modprobe"
        r = subprocess.run([exe, "kheaders"], capture_output=True, text=True, timeout=60)
        modprobe = {"cmd": f"{exe} kheaders", "returncode": r.returncode,
                    "stderr": r.stderr.strip()}
        hdr = _headers_present()
    if hdr is not None:
        add("kernel_headers", "PASS", f"{hdr}" + (" (loaded via modprobe kheaders)" if modprobe else ""))
    elif not root:
        add("kernel_headers", "BLOCKED", "no headers; modprobe kheaders requires root")
    else:
        add("kernel_headers", "FAIL", f"no headers after modprobe attempt: {modprobe}")

    add("btf", "INFO", "present" if os.path.exists("/sys/kernel/btf/vmlinux") else "absent")
    docker = shutil.which("docker")
    if docker:
        try:
            r = subprocess.run([docker, "info", "--format", "{{.ServerVersion}}"],
                               capture_output=True, text=True, timeout=20)
            add("docker", "INFO", f"server {r.stdout.strip()}" if r.returncode == 0
                else f"docker info exit {r.returncode}: {r.stderr.strip()[:120]}")
        except subprocess.TimeoutExpired:
            add("docker", "INFO", "docker info timed out")
    else:
        add("docker", "INFO", "docker CLI not found")

    ok = all(c["status"] == "PASS" for c in checks if c["name"] in REQUIRED)
    return {"ok": ok, "kernel": platform.release(), "checks": checks, "kheaders_modprobe": modprobe}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    report = run_preflight(attempt_modprobe="--no-modprobe" not in argv)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
