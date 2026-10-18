"""Shared fixtures and environment gating for the ProcessPulse-C test suite."""

import ctypes
import os
import shutil
import subprocess
import sys
import time

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
COLLECTOR_BIN = os.environ.get("PPC_COLLECTOR_BIN", os.path.join(REPO_ROOT, "collector"))
HELPER_BIN = os.path.join(REPO_ROOT, "build", "sysc_helper")
IS_ROOT = os.geteuid() == 0


def _docker_ok():
    exe = shutil.which("docker")
    if not exe:
        return False
    try:
        return subprocess.run([exe, "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def pytest_collection_modifyitems(config, items):
    docker_ok = None
    for item in items:
        if "privileged" in item.keywords and not IS_ROOT:
            item.add_marker(pytest.mark.skip(reason="requires root (BCC); run 'make test-privileged' as root"))
        if "docker" in item.keywords:
            if docker_ok is None:
                docker_ok = _docker_ok()
            if not docker_ok:
                item.add_marker(pytest.mark.skip(reason="docker daemon not usable"))


@pytest.fixture(scope="session")
def collector_bin():
    if not os.path.isfile(COLLECTOR_BIN):
        pytest.skip(f"collector binary not found at {COLLECTOR_BIN}; run 'make'")
    return COLLECTOR_BIN


@pytest.fixture(scope="session")
def helper_bin():
    if not os.path.isfile(HELPER_BIN):
        pytest.skip(f"{HELPER_BIN} not found; run 'make helpers'")
    return HELPER_BIN


class Helper:
    """Drives tests/helpers/sysc_helper over its stdin/stdout protocol."""

    def __init__(self, argv):
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        ready = self.proc.stdout.readline().split()
        assert ready and ready[0] == "READY", f"helper did not start: {ready}"
        fields = dict(f.split("=") for f in ready[1:])
        self.reported_pid = int(fields["pid"])

    @property
    def pid(self):
        return self.proc.pid

    def do(self, cmd, n):
        self.proc.stdin.write(f"{cmd} {n}\n")
        self.proc.stdin.flush()
        reply = self.proc.stdout.readline().split()
        assert reply[:3] == ["DONE", cmd, str(n)], reply
        assert reply[3] == "errors=0", reply
        return reply

    def exit(self, timeout=10):
        if self.proc.poll() is None:
            try:
                self.proc.stdin.write("exit\n")
                self.proc.stdin.flush()
            except BrokenPipeError:
                pass
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        return self.proc.returncode


@pytest.fixture
def spawn_helper(helper_bin):
    started = []

    def _spawn(argv=None):
        h = Helper(argv or [helper_bin])
        started.append(h)
        return h

    yield _spawn
    for h in started:
        h.exit()


class NamedProcess:
    """A sleeping Python child whose comm was set with prctl(PR_SET_NAME)."""

    def __init__(self, name_bytes):
        code = (
            "import ctypes, sys, time\n"
            f"ctypes.CDLL(None).prctl(15, {name_bytes!r}, 0, 0, 0)\n"
            "print('ready', flush=True)\n"
            "time.sleep(60)\n"
        )
        self.proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
        assert self.proc.stdout.readline().strip() == "ready"

    @property
    def pid(self):
        return self.proc.pid

    def stop(self):
        self.proc.kill()
        self.proc.wait()


@pytest.fixture
def named_process():
    made = []

    def _make(name_bytes):
        p = NamedProcess(name_bytes)
        made.append(p)
        return p

    yield _make
    for p in made:
        p.stop()


def wait_until(pred, timeout=5.0, step=0.05):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(step)
    return pred()


def libc_syscall(nr, *args):
    return ctypes.CDLL(None, use_errno=True).syscall(nr, *args)
