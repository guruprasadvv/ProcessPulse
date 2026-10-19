"""Unified, capability-flagged BPF collector (M1b S1).

One start() performs exactly two BCC compilations, both recorded in
`compilations`:
  1. "calibrate": a one-shot getpid probe finds the distro pid-namespace level
     L_d and inode from the agent's own process (never assumed); unloaded
     before step 2;
  2. "unified": ONE program assembled from bpf/common.h, the source of every
     enabled capability, bpf/core.bpf.c and the generated per-syscall probes,
     with -DPPC_CAP_<NAME> per capability.
S1 implements one capability, "counts" (the M1 syscall-entry counters). The
names of later capabilities are reserved and refused until their stage.

snapshot() returns the M1 schema-v1 syscall_snapshot record (unchanged);
exited processes are reported once and reclaimed at the next snapshot if
their counts did not change. Per-thread slots (bpf/common.h) are created on
attributed events and deleted when the thread exits or execs away from its
TID (F4); their counters are available from thread_health(), not in the v1
record. Process comm and cgroup are captured at the first event and
refreshed at exec (F9).

With track_removals=True the collector remembers every key it deletes from
the maps (exit reclaim, self-exclusion purge) until take_removed() collects
them (for processpulse.snapshots.V2Emitter). last_unreported is the number
of entries the last snapshot skipped because their info entry was missing.

Requires root and BCC (python3-bpfcc); see processpulse.preflight.
"""

import ctypes
import os
import platform
import threading
import time

from .identity import CgroupResolver, clk_tck, own_pidns_ino, read_boot_id, start_ticks_from_ns
from .vocab import VOCABULARY

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BPF_DIR = os.path.join(REPO_ROOT, "bpf")

SYSCALLS = VOCABULARY.syscalls
# health[] indices in bpf/common.h. The first five are the M1 fields of the
# v1 syscall_health record; the rest are reported by thread_health().
HEALTH_FIELDS = ("counts_map_full", "info_map_full", "unresolved_events", "self_excluded_events",
                 "exit_events", "thread_map_full", "thread_slot_stale", "thread_slots_cleaned",
                 "exec_refreshes")
V1_HEALTH_FIELDS = HEALTH_FIELDS[:5]

SCHED_TRACEPOINTS = ("sched:sched_process_exit", "sched:sched_process_exec")
CAPABILITIES = {
    # name: (source in bpf/, compile-time flag, tracepoints of its own)
    "counts": ("syscall_counter.bpf.c", "PPC_CAP_COUNTS",
               tuple(f"syscalls:sys_enter_{s}" for s in SYSCALLS)),
}
RESERVED_CAPABILITIES = ("bigrams", "priv", "net")    # later M1b stages

SYS_GETPID = {"x86_64": 39, "aarch64": 172}


class CalibrationError(RuntimeError):
    pass


def _read(name):
    with open(os.path.join(BPF_DIR, name), encoding="utf-8") as f:
        return f.read()


def _bpf_class():
    from bcc import BPF
    return BPF


def check_capabilities(capabilities):
    """Validated, ordered tuple of capability names (raises ValueError)."""
    caps = tuple(capabilities)
    if not caps:
        raise ValueError("at least one capability must be enabled")
    if len(set(caps)) != len(caps):
        raise ValueError(f"duplicate capability in {caps}")
    for c in caps:
        if c in RESERVED_CAPABILITIES:
            raise ValueError(f"capability {c!r} is not implemented in this stage")
        if c not in CAPABILITIES:
            raise ValueError(f"unknown capability {c!r}")
    return tuple(c for c in CAPABILITIES if c in caps)


def required_tracepoints(capabilities=("counts",)):
    """Every tracepoint the unified program attaches for these capabilities."""
    caps = check_capabilities(capabilities)
    return tuple(tp for c in caps for tp in CAPABILITIES[c][2]) + SCHED_TRACEPOINTS


def build_source(capabilities=("counts",)):
    """The single compilation unit: common.h, capabilities, core, probes."""
    caps = check_capabilities(capabilities)
    parts = [_read("common.h")]
    parts += [_read(CAPABILITIES[c][0]) for c in caps]
    parts.append(_read("core.bpf.c"))
    if "counts" in caps:
        parts += [f"\nTRACEPOINT_PROBE(syscalls, sys_enter_{name})\n{{\n    return count_syscall({i});\n}}\n"
                  for i, name in enumerate(SYSCALLS)]
    return "\n".join(parts)


def calibrate(compilations=None):
    """Returns (distro_level, distro_pidns_ino) measured from this process."""
    BPF = _bpf_class()
    nr = SYS_GETPID.get(platform.machine())
    if nr is None:
        raise CalibrationError(f"unsupported architecture {platform.machine()}")
    t0 = time.monotonic_ns()
    b = BPF(text=_read("calibrate.bpf.c"))
    if compilations is not None:
        compilations.append({"name": "calibrate", "ns": time.monotonic_ns() - t0})
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
    return {fam: sum(counts[s] for s in members) for fam, members in VOCABULARY.family_map().items()}


class BpfCollector:
    def __init__(self, capabilities=("counts",), max_procs=16384, max_threads=32768,
                 distro_inum_override=None, resolver=None, track_removals=False):
        self.capabilities = check_capabilities(capabilities)
        self.max_procs = max_procs
        self.max_threads = max_threads
        self.distro_inum_override = distro_inum_override   # tests: force unresolved
        self.resolver = resolver or CgroupResolver()
        self.track_removals = track_removals
        self.b = None
        self.seq = 0
        self.reclaimed = 0
        self.compilations = []     # [{"name", "ns"}] — one entry per BCC compilation
        self._prev_t = None
        self._reported_exit = {}   # (start_ns, tgid) -> counts tuple at report time
        self._purged_self = 0      # events purged by exclude(), reported as self-excluded
        self._removed = {"exited": [], "self_excluded": []}   # deleted keys not yet collected
        self._removed_lock = threading.Lock()                  # exclude() runs on another thread
        self.last_unreported = 0   # entries the last snapshot skipped (no info entry)
        self.boot_id = read_boot_id()
        self.ticks = clk_tck()

    # --- lifecycle --------------------------------------------------------
    def start(self):
        BPF = _bpf_class()
        self.distro_level, self.distro_pidns_ino = calibrate(self.compilations)
        inum = self.distro_inum_override or self.distro_pidns_ino
        cflags = [f"-DDISTRO_LEVEL={self.distro_level}", f"-DDISTRO_PIDNS_INUM={inum}U",
                  f"-DMAX_PROCS={self.max_procs}", f"-DMAX_THREADS={self.max_threads}",
                  f"-DNSYSCALLS={len(SYSCALLS)}"]
        cflags += [f"-D{CAPABILITIES[c][1]}=1" for c in self.capabilities]
        t0 = time.monotonic_ns()
        self.b = BPF(text=build_source(self.capabilities), cflags=cflags)
        self.compilations.append({"name": "unified", "ns": time.monotonic_ns() - t0})
        self.attached_since = time.monotonic_ns()
        want = sorted(required_tracepoints(self.capabilities))
        got = sorted(self.attached_tracepoints())
        if got != want:
            self.close()
            raise RuntimeError(f"attached tracepoints differ from the capability plan: "
                               f"missing {sorted(set(want) - set(got))}, extra {sorted(set(got) - set(want))}")
        self.exclude(os.getpid())
        return self

    def close(self):
        if self.b is not None:
            self.b.cleanup()
            self.b = None

    def attached_tracepoints(self):
        """'category:event' names BCC attached (its tracepoint_fds keys may be bytes)."""
        if self.b is None:
            return []
        return [k.decode() if isinstance(k, bytes) else k for k in self.b.tracepoint_fds]

    def build_info(self):
        return {"capabilities": list(self.capabilities), "compilations": list(self.compilations),
                "tracepoints": sorted(self.attached_tracepoints()),
                "open_tracepoints": self.b.num_open_tracepoints() if self.b is not None else 0,
                "vocabulary": VOCABULARY.id, "max_procs": self.max_procs,
                "max_threads": self.max_threads}

    # --- exclusion and removal bookkeeping ---------------------------------
    def exclude(self, tgid):
        """Stops counting tgid (our own collectors) and purges entries it made
        before the exclusion took effect (e.g. the pre-exec execve of a freshly
        spawned collector), including its thread slots. Purged events stay
        visible in self_excluded_events."""
        self.b["excluded"][ctypes.c_uint(tgid)] = ctypes.c_ubyte(1)
        counts_t, info_t, threads_t = self.b["counts"], self.b["info"], self.b["threads"]
        for k, v in list(counts_t.items()):
            if k.tgid == tgid:
                self._purged_self += sum(v.c[i] for i in range(len(SYSCALLS)))
                for table in (counts_t, info_t):
                    try:
                        del table[k]
                    except KeyError:
                        pass
                self._note_removed("self_excluded", (k.start_ns, k.tgid))
        for tid, s in list(threads_t.items()):
            if s.proc.tgid == tgid:
                try:
                    del threads_t[tid]
                except KeyError:
                    pass

    def unexclude(self, tgid):
        try:
            del self.b["excluded"][ctypes.c_uint(tgid)]
        except KeyError:
            pass

    def _key_dict(self, key):
        start_ns, tgid = key
        return {"boot_id": self.boot_id, "pidns_ino": self.distro_pidns_ino,
                "tgid": tgid, "start_ticks": start_ticks_from_ns(start_ns, self.ticks)}

    def _note_removed(self, reason, key):
        if not self.track_removals:
            return
        with self._removed_lock:
            self._removed[reason].append(self._key_dict(key))

    def take_removed(self):
        """Keys deleted from the maps since the last call, by reason (for the v2 emitter)."""
        with self._removed_lock:
            out, self._removed = self._removed, {"exited": [], "self_excluded": []}
        return out

    # --- inspection -------------------------------------------------------
    def last_event_ktime(self, tgid):
        """bpf_ktime_get_ns() of tgid's most recent counted event (clock-contract tests)."""
        for k, v in self.b["info"].items():
            if k.tgid == tgid:
                return v.last_ktime
        return None

    def _health_all(self):
        h = self.b["health"]
        out = {name: h[ctypes.c_int(i)].value for i, name in enumerate(HEALTH_FIELDS)}
        out["self_excluded_events"] += self._purged_self
        return out

    def _health(self):
        h = self._health_all()
        return {k: h[k] for k in V1_HEALTH_FIELDS}

    def thread_slots(self, tgid=None):
        """[(distro_tid, host_tid, thread_start_ns, (proc start_ns, proc tgid))] currently
        held. The host TID is the map key only (diagnostic, never identity)."""
        out = []
        for tid, s in self.b["threads"].items():
            if tgid is None or s.proc.tgid == tgid:
                out.append((s.tid, tid.value, s.thread_start_ns, (s.proc.start_ns, s.proc.tgid)))
        return sorted(out)

    def thread_health(self):
        h = self._health_all()
        out = {k: h[k] for k in HEALTH_FIELDS[5:]}
        out["thread_slots"] = len(self.b["threads"].items())
        out["thread_capacity"] = self.max_threads
        return out

    # --- snapshot (schema v1, unchanged from M1) ---------------------------
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
                self._note_removed("exited", key)

        procs = []
        unreported = 0
        for key, cvals in sorted(counts.items(), key=lambda kv: kv[0][1]):
            info = infos.get(key)
            if info is None:
                unreported += 1
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

        self.last_unreported = unreported
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
