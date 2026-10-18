"""Process and container identity (CLAUDE.md §5).

ProcessKey = (boot_id, distro_pidns_ino, distro_tgid, start_ticks). The C
collector supplies tgid and starttime_ticks from /proc; the BPF collector
derives the same tuple in-kernel (see bpf/syscall_counter.bpf.c), so the two
streams join without trusting PIDs alone.

Container attribution comes from the cgroup v2 path. BPF reports a cgroup id
(the cgroup directory's inode); CgroupResolver maps it back to a path.
"""

import os
import re
import time
from dataclasses import dataclass

CGROUP_ROOT = "/sys/fs/cgroup"

_DOCKER_PATTERNS = (
    re.compile(r"(?:^|/)docker-([0-9a-f]{64})\.scope$"),   # systemd cgroup driver
    re.compile(r"(?:^|/)docker/([0-9a-f]{64})$"),          # cgroupfs driver
)


@dataclass(frozen=True)
class ProcessKey:
    boot_id: str
    pidns_ino: int
    tgid: int
    start_ticks: int

    def as_dict(self):
        return {"boot_id": self.boot_id, "pidns_ino": self.pidns_ino,
                "tgid": self.tgid, "start_ticks": self.start_ticks}


def read_boot_id(path="/proc/sys/kernel/random/boot_id"):
    with open(path, encoding="ascii") as f:
        return f.read().strip()


def own_pidns_ino():
    return os.stat("/proc/self/ns/pid").st_ino


def clk_tck():
    return os.sysconf("SC_CLK_TCK")


def start_ticks_from_ns(start_boottime_ns, ticks_per_sec):
    """Kernel nsec_to_clock_t(): floor division to USER_HZ ticks."""
    return start_boottime_ns // (1_000_000_000 // ticks_per_sec)


def key_from_proc_record(proc, begin):
    """ProcessKey for a C-collector proc record and its sample_begin."""
    return ProcessKey(begin["boot_id"], begin["pidns_ino"], proc["pid"], proc["starttime_ticks"])


def parse_container(cgroup_path):
    """Returns (runtime, container_id) for a Docker cgroup path, else (None, None)."""
    if cgroup_path:
        for rx in _DOCKER_PATTERNS:
            m = rx.search(cgroup_path)
            if m:
                return "docker", m.group(1)
    return None, None


def container_identity(cgroup_id, cgroup_path, stale=False):
    if cgroup_path is None:
        return {"cgroup_id": cgroup_id, "cgroup_path": None, "container_id": None,
                "runtime": None, "attribution": "unknown", "stale": stale}
    runtime, cid = parse_container(cgroup_path)
    return {"cgroup_id": cgroup_id, "cgroup_path": cgroup_path, "container_id": cid,
            "runtime": runtime, "attribution": "docker" if cid else "host", "stale": stale}


class CgroupResolver:
    """Maps cgroup v2 ids (directory inodes) to paths relative to the cgroup root.

    A full rescan happens on a cache miss, at most once per min_rescan_s.
    Cached entries whose directory has disappeared (container exited) are
    still returned, flagged stale.
    """

    def __init__(self, root=CGROUP_ROOT, min_rescan_s=1.0, clock=time.monotonic):
        self.root = root
        self.min_rescan_s = min_rescan_s
        self._clock = clock
        self._cache = {}          # cgroup_id -> relative path ("/" for the root)
        self._last_scan = None
        self.rescans = 0

    def _scan(self):
        self._last_scan = self._clock()
        self.rescans += 1
        for dirpath, _dirs, _files in os.walk(self.root):
            try:
                ino = os.stat(dirpath).st_ino
            except OSError:
                continue
            rel = "/" + os.path.relpath(dirpath, self.root) if dirpath != self.root else "/"
            self._cache[ino] = rel

    def path_for(self, cgroup_id):
        """Returns (path or None, stale)."""
        path = self._cache.get(cgroup_id)
        if path is None and (self._last_scan is None or
                             self._clock() - self._last_scan >= self.min_rescan_s):
            self._scan()
            path = self._cache.get(cgroup_id)
        if path is None:
            return None, False
        try:
            stale = os.stat(os.path.join(self.root, path.lstrip("/"))).st_ino != cgroup_id
        except OSError:
            stale = True
        return path, stale

    def identity(self, cgroup_id):
        path, stale = self.path_for(cgroup_id)
        return container_identity(cgroup_id, path, stale)
