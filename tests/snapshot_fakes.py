"""Deterministic stand-in for SyscallCollector, for v2 snapshot-protocol tests.

It exposes the attributes and methods processpulse.snapshots.V2Emitter uses
(snapshot, take_removed, last_unreported, calibration and attach time), so the
protocol can be tested without root or BPF.
"""

import copy

BOOT = "d8272aeb-2d00-4ca0-9e4a-11dab89ea8cc"
INO = 4026532219
SYSCALLS = ("execve", "execveat", "open", "openat", "openat2", "clone", "clone3", "fork", "vfork")


def key(tgid, start_ticks=5000):
    return {"boot_id": BOOT, "pidns_ino": INO, "tgid": tgid, "start_ticks": start_ticks}


def make_proc(tgid, exited=False, level=2, **counts):
    return {
        "key": key(tgid),
        "host_tgid": tgid + 100000,
        "level": level,
        "container_pid": 1 if level > 2 else None,
        "comm": f"p{tgid}",
        "container": {"cgroup_id": 77, "cgroup_path": "/user.slice", "container_id": None,
                      "runtime": None, "attribution": "host", "stale": False},
        "counts": {s: counts.get(s, 0) for s in SYSCALLS},
        "exited": exited,
    }


class FakeCollector:
    boot_id = BOOT
    distro_level = 2
    distro_pidns_ino = INO

    def __init__(self, attached_since=1000):
        self.attached_since = attached_since
        self.procs = {}            # tgid -> proc payload (what the BPF maps would report)
        self.removed = {"exited": [], "self_excluded": []}
        self.fail = False
        self.last_unreported = 0
        self.health = {"map_entries": 0, "map_capacity": 16384, "counts_map_full": 0,
                       "info_map_full": 0, "unresolved_events": 0, "self_excluded_events": 0,
                       "exit_events": 0, "reclaimed": 0, "snapshot_ns": 10}

    # --- scenario helpers -------------------------------------------------
    def add(self, tgid, **counts):
        self.procs[tgid] = make_proc(tgid, **counts)

    def bump(self, tgid, syscall="openat", n=1):
        self.procs[tgid]["counts"][syscall] += n

    def exit(self, tgid):
        self.procs[tgid]["exited"] = True

    def reclaim(self, tgid):
        p = self.procs.pop(tgid)
        self.removed["exited"].append(copy.deepcopy(p["key"]))
        self.health["reclaimed"] += 1

    def purge(self, tgid):
        p = self.procs.pop(tgid)
        self.removed["self_excluded"].append(copy.deepcopy(p["key"]))

    # --- SyscallCollector interface ---------------------------------------
    def snapshot(self, resource_seq=None):
        if self.fail:
            raise OSError("injected map read failure")
        h = dict(self.health, map_entries=len(self.procs))
        return {"procs": [copy.deepcopy(self.procs[t]) for t in sorted(self.procs)], "health": h}

    def take_removed(self):
        out, self.removed = self.removed, {"exited": [], "self_excluded": []}
        return out


def truth(fake):
    """The live process state a correct consumer must hold after a complete snapshot."""
    from processpulse.snapshots import key_tuple
    return {key_tuple(p["key"]): p for p in fake.procs.values()}
