"""BCC syscall collector (producer of syscall_snapshot records).

Lifecycle:
  1. calibrate(): a one-shot getpid probe finds the distro pid-namespace level
     L_d and inode from the agent's own process (never assumed);
  2. start(): compiles bpf/syscall_counter.bpf.c with those constants and one
     per-syscall tracepoint per counted syscall (D-15);
  3. snapshot(): reads the cumulative counters at a userspace monotonic
     timestamp and returns a schema-v1 record; exited processes are reported
     once and reclaimed at the next snapshot if their counts did not change;
  4. close(): detaches everything.

Requires root and BCC (python3-bpfcc); see processpulse.preflight.
"""

import ctypes
import os
import platform
import time

from .identity import CgroupResolver, clk_tck, own_pidns_ino, read_boot_id, start_ticks_from_ns

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BPF_DIR = os.path.join(REPO_ROOT, "bpf")

# Order defines the SC_* indices compiled into the BPF program.
SYSCALLS = ("execve", "execveat", "open", "openat", "openat2", "clone", "clone3", "fork", "vfork")
FAMILIES = {
    "execve": ("execve", "execveat"),
    "open": ("open", "openat", "openat2"),
    "clone": ("clone", "clone3", "fork", "vfork"),
}
# health[] indices in syscall_counter.bpf.c.
HEALTH_FIELDS = ("counts_map_full", "info_map_full", "unresolved_events", "self_excluded_events",
                 "exit_events")

SYS_GETPID = {"x86_64": 39, "aarch64": 172}


class CalibrationError(RuntimeError):
    pass


def _read(name):
    with open(os.path.join(BPF_DIR, name), encoding="utf-8") as f:
        return f.read()


def calibrate():
    """Returns (distro_level, distro_pidns_ino) measured from this process."""
    from bcc import BPF

    nr = SYS_GETPID.get(platform.machine())
    if nr is None:
        raise CalibrationError(f"unsupported architecture {platform.machine()}")
    b = BPF(text=_read("calibrate.bpf.c"))
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        for _ in range(5):
            libc.syscall(nr)
        me, my_ino = os.getpid(), own_pidns_ino()
        for _k, c in b["cal"].items():
            for i in range(min(c.level, 7) + 1):
                if c.nr[i] == me and c.inum[i] == my_ino:
                    if i != c.level:
                        raise CalibrationError(
                            f"agent pid matched at level {i} but its active level is {c.level}")
                    return i, my_ino
        raise CalibrationError("no calibration event matched this process")
    finally:
        b.cleanup()


def family_totals(counts):
    return {fam: sum(counts[s] for s in members) for fam, members in FAMILIES.items()}


class SyscallCollector:
    def __init__(self, max_procs=16384, distro_inum_override=None, resolver=None):
        self.max_procs = max_procs
        self.distro_inum_override = distro_inum_override   # tests: force unresolved
        self.resolver = resolver or CgroupResolver()
        self.b = None
        self.seq = 0
        self.reclaimed = 0
        self._prev_t = None
        self._reported_exit = {}   # (start_ns, tgid) -> counts tuple at report time
        self._purged_self = 0      # events purged by exclude(), reported as self-excluded
        self.boot_id = read_boot_id()
        self.ticks = clk_tck()

    def start(self):
        from bcc import BPF

        self.distro_level, self.distro_pidns_ino = calibrate()
        inum = self.distro_inum_override or self.distro_pidns_ino
        probes = "".join(
            f"\nTRACEPOINT_PROBE(syscalls, sys_enter_{name})\n{{\n    return count_syscall({i});\n}}\n"
            for i, name in enumerate(SYSCALLS))
        cflags = [f"-DDISTRO_LEVEL={self.distro_level}", f"-DDISTRO_PIDNS_INUM={inum}U",
                  f"-DMAX_PROCS={self.max_procs}", f"-DNSYSCALLS={len(SYSCALLS)}"]
        self.b = BPF(text=_read("syscall_counter.bpf.c") + probes, cflags=cflags)
        self.attached_since = time.monotonic_ns()
        expected = len(SYSCALLS) + 1
        if self.b.num_open_tracepoints() != expected:
            n = self.b.num_open_tracepoints()
            self.close()
            raise RuntimeError(f"expected {expected} tracepoints attached, got {n}")
        self.exclude(os.getpid())
        return self

    def exclude(self, tgid):
        """Stops counting tgid (our own collectors) and purges entries it made
        before the exclusion took effect (e.g. the pre-exec execve of a freshly
        spawned collector). Purged events stay visible in self_excluded_events."""
        self.b["excluded"][ctypes.c_uint(tgid)] = ctypes.c_ubyte(1)
        counts_t, info_t = self.b["counts"], self.b["info"]
        for k, v in list(counts_t.items()):
            if k.tgid == tgid:
                self._purged_self += sum(v.c[i] for i in range(len(SYSCALLS)))
                for table in (counts_t, info_t):
                    try:
                        del table[k]
                    except KeyError:
                        pass

    def unexclude(self, tgid):
        try:
            del self.b["excluded"][ctypes.c_uint(tgid)]
        except KeyError:
            pass

    def close(self):
        if self.b is not None:
            self.b.cleanup()
            self.b = None

    def last_event_ktime(self, tgid):
        """bpf_ktime_get_ns() of tgid's most recent counted event (clock-contract tests)."""
        for k, v in self.b["info"].items():
            if k.tgid == tgid:
                return v.last_ktime
        return None

    def _health(self):
        h = self.b["health"]
        out = {name: h[ctypes.c_int(i)].value for i, name in enumerate(HEALTH_FIELDS)}
        out["self_excluded_events"] += self._purged_self
        return out

    def snapshot(self, resource_seq=None):
        t0 = time.monotonic_ns()
        counts_t, info_t = self.b["counts"], self.b["info"]
        counts = {(k.start_ns, k.tgid): tuple(v.c[i] for i in range(len(SYSCALLS)))
                  for k, v in counts_t.items()}
        infos = {(k.start_ns, k.tgid): (v.cgroup_id, v.host_tgid, v.level, v.container_pid,
                                        bool(v.exited), bytes(v.comm).split(b"\0", 1)[0])
                 for k, v in info_t.items()}

        # Phase 2 of exit handling: reclaim entries reported as exited last time
        # whose counts have not changed since (so no increment is lost).
        for key, prev in list(self._reported_exit.items()):
            cur = counts.get(key)
            if cur is None or cur == prev:
                k = counts_t.Key(key[0], key[1], 0)
                for table in (counts_t, info_t):
                    try:
                        del table[k]
                    except KeyError:
                        pass
                counts.pop(key, None)
                infos.pop(key, None)
                del self._reported_exit[key]
                self.reclaimed += 1

        procs = []
        for key, cvals in sorted(counts.items(), key=lambda kv: kv[0][1]):
            info = infos.get(key)
            if info is None:
                continue   # info insert pending or map full (counted in health)
            cgroup_id, host_tgid, level, cpid, exited, comm = info
            if exited:
                self._reported_exit[key] = cvals
            procs.append({
                "key": {"boot_id": self.boot_id, "pidns_ino": self.distro_pidns_ino,
                        "tgid": key[1], "start_ticks": start_ticks_from_ns(key[0], self.ticks)},
                "host_tgid": host_tgid,
                "level": level,
                "container_pid": cpid if level > self.distro_level else None,
                "comm": comm.decode("utf-8", "replace"),
                "container": self.resolver.identity(cgroup_id),
                "counts": dict(zip(SYSCALLS, cvals)),
                "exited": exited,
            })

        health = self._health()
        health.update({"map_entries": len(counts), "map_capacity": self.max_procs,
                       "reclaimed": self.reclaimed, "snapshot_ns": time.monotonic_ns() - t0})
        rec = {
            "type": "syscall_snapshot", "v": 1, "seq": self.seq, "t_mono_ns": t0,
            "interval_ns": None if self._prev_t is None else t0 - self._prev_t,
            "resource_seq": resource_seq,
            "probe": {"mode": "per_syscall_tracepoints", "syscalls": list(SYSCALLS),
                      "attached_since_mono_ns": self.attached_since},
            "calibration": {"boot_id": self.boot_id, "distro_level": self.distro_level,
                            "distro_pidns_ino": self.distro_pidns_ino},
            "procs": procs,
            "health": health,
        }
        self.seq += 1
        self._prev_t = t0
        return rec
