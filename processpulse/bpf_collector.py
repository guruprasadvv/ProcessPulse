"""Unified, capability-flagged BPF collector (M1b S1).

One start() performs exactly two BCC compilations, both recorded in
`compilations`:
  1. "calibrate": a one-shot getpid probe finds the distro pid-namespace level
     L_d and inode from the agent's own process (never assumed); unloaded
     before step 2;
  2. "unified": ONE program assembled from bpf/common.h, the source of every
     enabled capability, bpf/core.bpf.c and the generated per-syscall probes,
     with -DPPC_CAP_<NAME> per capability.
Capabilities: "counts" (the M1 syscall-entry counters, S1) and "bigrams"
(pairs of consecutive observed calls per thread, S2.3; requires "counts",
adds no tracepoint). The names of later capabilities are reserved and
refused until their stage.

With "bigrams" the program is armed right after attach (arm=True): entries
before arming are counted but their pairs are lost and counted (U2a).
read_bigrams() reads the bigram map, groups the raw entries by process and
decodes them (processpulse.bigrams); zero-count entries are dropped and
reported (P-ZERO). bigram_health() returns the end-record health fields.
Exit reclaim requires the counts, pairs_lost and pair sum to be unchanged
since the exit report and deletes the key's bigram entries with it, adding
the removed values to reclaimed_totals; exclude() purges them and adds them
to the purge totals.

drain() is the final drain (S2.5, decision U3): it detaches every probe but
keeps the maps, waits for in-flight probe invocations (rcu_barrier()), then
reads every map twice and requires the reads to be equal (H-DRAIN). It ends the
epoch: exclude() is refused afterwards, and after a successful drain exactly
one more snapshot() is allowed, the drained snapshot (last_snapshot_drained),
which must read the same maps as the drain.

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
# v1 syscall_health record; 5-8 are reported by thread_health(), 9-11 (kept
# by the bigrams capability only) by bigram_health().
HEALTH_FIELDS = ("counts_map_full", "info_map_full", "unresolved_events", "self_excluded_events",
                 "exit_events", "thread_map_full", "thread_slot_stale", "thread_slots_cleaned",
                 "exec_refreshes", "bigram_map_full", "bigram_dropped", "pre_arm_events")
V1_HEALTH_FIELDS = HEALTH_FIELDS[:5]
THREAD_HEALTH_FIELDS = HEALTH_FIELDS[5:9]
# The bpf_snapshot_end.bigram_health fields (processpulse.snapshots.BIGRAM_HEALTH_FIELDS).
BIGRAM_HEALTH = ("bigram_dropped", "bigram_map_full", "thread_map_full", "pre_arm_events",
                 "thread_slot_stale", "purged_counts", "purged_pairs", "purged_pairs_lost")

SCHED_TRACEPOINTS = ("sched:sched_process_exit", "sched:sched_process_exec")
CAPABILITIES = {
    # name: (source in bpf/, compile-time flag, tracepoints of its own)
    "counts": ("syscall_counter.bpf.c", "PPC_CAP_COUNTS",
               tuple(f"syscalls:sys_enter_{s}" for s in SYSCALLS)),
    "bigrams": ("bigrams.bpf.c", "PPC_CAP_BIGRAMS", ()),
}
REQUIRES = {"bigrams": ("counts",)}                    # U9
SOURCE_ORDER = ("bigrams", "counts")                   # the counter calls the bigram hooks
RESERVED_CAPABILITIES = ("priv", "net")                # later M1b stages

SYS_GETPID = {"x86_64": 39, "aarch64": 172}
SYS_MEMBARRIER = {"x86_64": 324, "aarch64": 283}
MEMBARRIER_CMD_QUERY = 0
MEMBARRIER_CMD_GLOBAL = 1          # the kernel runs synchronize_rcu()


def rcu_barrier(_syscall=None):
    """Waits for an RCU grace period: membarrier(MEMBARRIER_CMD_GLOBAL), which
    makes the kernel run synchronize_rcu() (it returns at once on a single
    online CPU, where no probe can be running while we are).

    BPF programs on these tracepoints run inside trace_call_bpf(), under
    rcu_read_lock() and with preemption disabled. When this returns, every
    probe invocation that started before the call has finished, and every
    later one sees map updates made before the call. Raises if the kernel
    lacks the command (e.g. nohz_full), rather than purging without the
    guarantee. _syscall is a test seam."""
    if _syscall is None:
        nr = SYS_MEMBARRIER.get(platform.machine())
        if nr is None:
            raise RuntimeError(f"unsupported architecture {platform.machine()}")
        libc = ctypes.CDLL(None, use_errno=True)

        def _syscall(_nr, cmd, flags, cpu):
            return libc.syscall(nr, cmd, flags, cpu)
    supported = _syscall(None, MEMBARRIER_CMD_QUERY, 0, 0)
    if supported < 0 or not supported & MEMBARRIER_CMD_GLOBAL:
        raise RuntimeError("membarrier MEMBARRIER_CMD_GLOBAL is not available: the exclusion "
                           "purge cannot wait for in-flight probes")
    if _syscall(None, MEMBARRIER_CMD_GLOBAL, 0, 0) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"membarrier(MEMBARRIER_CMD_GLOBAL) failed: {os.strerror(err)}")


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
    for c in caps:
        missing = [r for r in REQUIRES.get(c, ()) if r not in caps]
        if missing:
            raise ValueError(f"capability {c!r} requires {missing}")
    return tuple(c for c in CAPABILITIES if c in caps)


def required_tracepoints(capabilities=("counts",)):
    """Every tracepoint the unified program attaches for these capabilities."""
    caps = check_capabilities(capabilities)
    return tuple(tp for c in caps for tp in CAPABILITIES[c][2]) + SCHED_TRACEPOINTS


def build_source(capabilities=("counts",)):
    """The single compilation unit: common.h, capabilities, core, probes."""
    caps = check_capabilities(capabilities)
    parts = [_read("common.h")]
    parts += [_read(CAPABILITIES[c][0]) for c in SOURCE_ORDER if c in caps]
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


def _tp_name(tp):
    """'category:event' of a BCC tracepoint_fds key (BCC may use bytes)."""
    return tp.decode() if isinstance(tp, bytes) else tp


def family_totals(counts):
    return {fam: sum(counts[s] for s in members) for fam, members in VOCABULARY.family_map().items()}


class BpfCollector:
    def __init__(self, capabilities=("counts",), max_procs=16384, max_threads=32768,
                 distro_inum_override=None, resolver=None, track_removals=False,
                 max_pairs=131072, arm=True):
        self.capabilities = check_capabilities(capabilities)
        self.has_bigrams = "bigrams" in self.capabilities
        self.max_procs = max_procs
        self.max_threads = max_threads
        self.max_pairs = max_pairs
        self._arm_at_start = arm
        self.armed_boot_ns = None
        self.purged = {"counts": 0, "pairs": 0, "pairs_lost": 0}   # bigrams: self-exclusion purges
        self.reclaimed_totals = {"counts": 0, "pairs": 0, "pairs_lost": 0}   # bigrams: exit reclaims
        self.last_bigrams = None   # bigrams: read_bigrams() result of the last snapshot()
        self.drain_result = None   # the last drain() result
        self.last_snapshot_drained = False   # the last snapshot() was the drained snapshot
        self._draining = False     # drain() was called: the epoch is over
        self._drain_state = None   # the stable read of a successful drain
        self._drained_snapshot_taken = False
        self._drain_lock = threading.Lock()   # serialises drain() and exclude()
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
        if self.has_bigrams:
            cflags.append(f"-DMAX_PAIRS={self.max_pairs}")
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
        if self.has_bigrams and self._arm_at_start:
            self.arm()
        self.exclude(os.getpid())
        return self

    def arm(self):
        """Starts pair tracking. Threads that started (CLOCK_BOOTTIME) before this
        moment begin with START_ATTACH, later ones with START_NEW. armed_boot_ns is
        written before armed, so no event sees armed with a stale boundary."""
        if not self.has_bigrams:
            raise RuntimeError("arm() needs the bigrams capability")
        table, zero = self.b["bglobal"], ctypes.c_int(0)
        st = table[zero]
        st.armed_boot_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        table[zero] = st
        st = table[zero]
        st.armed = 1
        table[zero] = st
        self.armed_boot_ns = st.armed_boot_ns
        return self.armed_boot_ns

    def close(self):
        if self.b is not None:
            self.b.cleanup()
            self.b = None

    def attached_tracepoints(self):
        """'category:event' names BCC attached (its tracepoint_fds keys may be bytes)."""
        if self.b is None:
            return []
        return [_tp_name(k) for k in self.b.tracepoint_fds]

    def build_info(self):
        info = {"capabilities": list(self.capabilities), "compilations": list(self.compilations),
                "tracepoints": sorted(self.attached_tracepoints()),
                "open_tracepoints": self.b.num_open_tracepoints() if self.b is not None else 0,
                "vocabulary": VOCABULARY.id, "max_procs": self.max_procs,
                "max_threads": self.max_threads}
        if self.has_bigrams:
            info.update({"max_pairs": self.max_pairs, "armed_boot_ns": self.armed_boot_ns})
        if self.b is not None:
            info["maps"] = self.map_memory()
        return info

    def map_memory(self):
        """Per map: max_entries and memlock (bytes) from /proc/self/fdinfo, or None
        where the kernel does not report the field (hypothesis H-MEMLOCK)."""
        out = {}
        for name in ("counts", "info", "threads", "excluded", "health", "bigrams", "bglobal"):
            try:
                fd = self.b[name].map_fd
            except KeyError:
                continue
            fields = {}
            try:
                with open(f"/proc/self/fdinfo/{fd}") as f:
                    for line in f:
                        k, _, v = line.partition(":")
                        fields[k.strip()] = v.strip()
            except OSError:
                pass
            out[name] = {k: int(fields[k]) if k in fields else None
                         for k in ("max_entries", "memlock")}
        return out

    # --- exclusion and removal bookkeeping ---------------------------------
    def exclude(self, tgid):
        """See _exclude(). Refused once drain() was called: the probes are (being)
        detached and the maps hold the epoch's final values, which a purge would
        change."""
        with self._drain_lock:
            if self._draining:
                raise RuntimeError("exclude() after drain(): the epoch's maps are final")
            self._exclude(tgid)

    def _exclude(self, tgid):
        """Stops counting tgid (our own collectors) and purges entries it made
        before the exclusion took effect (e.g. the pre-exec execve of a freshly
        spawned collector), including its thread slots. Purged events stay
        visible in self_excluded_events. With bigrams its pair entries are
        purged too and added to the purge totals (purged_counts, purged_pairs,
        purged_pairs_lost).

        Order (P-PURGE): (1) set the exclusion; (2) rcu_barrier(): probe
        invocations that missed the exclusion have finished, and later ones
        return before writing any entry of tgid (the syscall probes and the
        exec and exit hooks all check it first); (3) read and delete. The values
        read are final, and no BPF program holds a pointer into an entry being
        deleted, so a late update can neither be lost from the purge totals nor
        land in a deleted element that a preallocated map has already reused
        for another key."""
        self.b["excluded"][ctypes.c_uint(tgid)] = ctypes.c_ubyte(1)
        rcu_barrier()
        counts_t, info_t, threads_t = self.b["counts"], self.b["info"], self.b["threads"]
        for k, v in list(counts_t.items()):
            if k.tgid == tgid:
                n = sum(v.c[i] for i in range(len(SYSCALLS)))
                self._purged_self += n
                if self.has_bigrams:
                    self.purged["counts"] += n
                    self.purged["pairs_lost"] += v.pairs_lost
                for table in (counts_t, info_t):
                    try:
                        del table[k]
                    except KeyError:
                        pass
                self._note_removed("self_excluded", (k.start_ns, k.tgid))
        if self.has_bigrams:
            pairs_t = self.b["bigrams"]
            for k, v in list(pairs_t.items()):
                if k.proc.tgid == tgid:
                    self.purged["pairs"] += v.value
                    try:
                        del pairs_t[k]
                    except KeyError:
                        pass
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
        out = {k: h[k] for k in THREAD_HEALTH_FIELDS}
        out["thread_slots"] = len(self.b["threads"].items())
        out["thread_capacity"] = self.max_threads
        return out

    # --- bigrams ------------------------------------------------------------
    def global_losses(self):
        """The global loss counters the exact I-B3/I-B4 checks depend on
        (processpulse.bigrams.GLOBAL_LOSS_FIELDS), cumulative since this load;
        compare two readings with bigrams.loss_window()."""
        h = self._health_all()
        return {k: h[k] for k in ("counts_map_full", "thread_map_full", "bigram_map_full",
                                  "pre_arm_events")}

    def bigram_health(self):
        """The bpf_snapshot_end.bigram_health fields (cumulative)."""
        if not self.has_bigrams:
            raise RuntimeError("bigram_health() needs the bigrams capability")
        return self._bigram_health_from(self._health_all(), self.purged)

    @staticmethod
    def _bigram_health_from(h, purged):
        out = {k: h[k] for k in BIGRAM_HEALTH[:5]}
        out.update({"purged_counts": purged["counts"], "purged_pairs": purged["pairs"],
                    "purged_pairs_lost": purged["pairs_lost"]})
        return {k: out[k] for k in BIGRAM_HEALTH}

    def _pair_items(self):
        """(items, method) of the bigram map: one batch read, else per key (H-BATCH)."""
        table = self.b["bigrams"]
        try:
            return list(table.items_lookup_batch()), "batch"
        except Exception:                         # H-BATCH: fall back to one lookup per key
            return list(table.items()), "items"

    def _read_bigrams_raw(self):
        """(result, raw): the decoded per-process tables and, per process, the raw
        map keys (for deletion). Map reads are sequential, not atomic: values of a
        process that is still running may be mutually inconsistent."""
        from .bigrams import decode_entries          # here: bigrams -> snapshots -> syscalls -> us
        if not self.has_bigrams:
            raise RuntimeError("read_bigrams() needs the bigrams capability")
        t0 = time.monotonic_ns()
        items, method = self._pair_items()
        lost = {(k.start_ns, k.tgid): v.pairs_lost for k, v in self.b["counts"].items()}
        raw = {}
        for k, v in items:
            raw.setdefault((k.proc.start_ns, k.proc.tgid), []).append((k.a, k.b, v.value, k))
        tables = {key: {} for key in lost}
        zeros = orphans = 0
        for key, entries in raw.items():
            decoded, z = decode_entries([(a, b, n) for a, b, n, _k in entries])
            zeros += z
            if key in lost:
                tables[key] = decoded
            else:
                orphans += len(entries)            # no counts entry: not a process table
        return ({"tables": tables, "pairs_lost": lost, "zero_entries": zeros,
                 "orphan_entries": orphans, "entries": len(items), "method": method,
                 "read_ns": time.monotonic_ns() - t0}, raw)

    def read_bigrams(self):
        """Pair tables grouped by process (start_ns, tgid), decoded to names:
        {"tables": {key: {(a, b): n}} (an empty table for a process with a counts
        entry but no pair), "pairs_lost": {key: n}, "zero_entries", "orphan_entries",
        "entries", "method" ("batch" or "items"), "read_ns"}. Zero-count entries
        are dropped (P-ZERO) and counted; they are not loss."""
        return self._read_bigrams_raw()[0]

    # --- final drain (S2.5, U3) ----------------------------------------------
    def drain(self):
        """Ends the epoch with a stable final read of every map (U3, H-DRAIN):

        1. detach every tracepoint; the maps stay. Closing a probe's perf event
           removes the program from the tracepoint's prog array
           (perf_event_detach_bpf_prog, an RCU pointer swap); a probe that
           cannot be detached fails the drain;
        2. rcu_barrier(): invocations that still run from the old prog array
           (under rcu_read_lock(), see rcu_barrier) have finished when it
           returns, and none can start. A failure fails the drain;
        3. read every map (and the userspace purge and reclaim totals) twice.
           Equal reads are the drained state. Unequal reads mean something
           wrote after step 2, against the argument above: the status is
           "unstable", nothing is claimed, and no later read is accepted
           without a new barrier (a retry runs steps 1-3 again).

        Returns (and keeps as drain_result) {"status": "drained" | "unstable" |
        "failed", "drained", "reason", "detached", "still_attached", "barrier",
        "reads", "changed" (the maps whose two reads differed),
        "detached_mono_ns", "drain_ns", "accounting"}. "accounting" (bigrams
        only, and only when drained) holds the I-B2 terms of the stable read:
        live keys' counts, pairs and pairs_lost, the pair entries without a
        counts entry (orphans) and those with n = 0, plus copies of
        reclaimed_totals, the purge totals and bigram_health; see
        bigrams.check_ib2_drain_read. drained_processes() gives the per-key
        values for the quiescent checkers.

        The epoch is over once drain() starts: exclude() is refused. A drain
        that did not succeed may be retried; after the drained snapshot was
        taken it may not."""
        if self.b is None:
            raise RuntimeError("drain() needs a started collector")
        with self._drain_lock:
            if self._drained_snapshot_taken:
                raise RuntimeError("the drained snapshot was taken: it is the epoch's last")
            self._draining = True
            self._drain_state = None
            t0 = time.monotonic_ns()
            res = {"status": "failed", "drained": False, "reason": None, "detached": [],
                   "still_attached": [], "barrier": False, "reads": 0, "changed": [],
                   "detached_mono_ns": None, "drain_ns": None, "accounting": None}
            self.drain_result = res
            res["reason"] = self._drain_steps(res)
            if res["reason"] is None:
                res["status"], res["drained"] = "drained", True
            elif res["status"] != "unstable":
                res["status"] = "failed"
            res["drain_ns"] = time.monotonic_ns() - t0
            return res

    def _drain_steps(self, res):
        """Steps 1-3 of drain(); returns None on success or the reason it did not
        succeed (res["status"] is set to "unstable" for unequal reads)."""
        order = {tp: i for i, tp in enumerate(required_tracepoints(self.capabilities))}
        errors = []
        for tp in sorted(self.b.tracepoint_fds, key=lambda t: order.get(_tp_name(t), len(order))):
            try:
                self.b.detach_tracepoint(tp)
                res["detached"].append(_tp_name(tp))
            except Exception as e:                  # BCC raises a bare Exception
                errors.append(f"{_tp_name(tp)}: {e}")
        res["still_attached"] = sorted(self.attached_tracepoints())
        res["detached_mono_ns"] = time.monotonic_ns()
        if errors or res["still_attached"]:
            return f"probes still attached: {res['still_attached']} ({'; '.join(errors)})"[:300]
        try:
            rcu_barrier()
        except Exception as e:
            return f"{type(e).__name__}: {e}"[:300]
        res["barrier"] = True
        try:
            first = self._read_state()
            res["reads"] = 1
            second = self._read_state()
            res["reads"] = 2
        except Exception as e:                      # a map read failed
            return f"map read failed: {type(e).__name__}: {e}"[:300]
        if first != second:
            res["status"] = "unstable"
            res["changed"] = sorted(m for m in second if second[m] != first[m])
            return f"the two reads after the barrier differ in {res['changed']}"
        self._drain_state = first
        if self.has_bigrams:
            res["accounting"] = self._drain_accounting(first)
        return None

    def _read_state(self):
        """The complete content of every map a probe writes, and the userspace
        totals, in a form that compares equal iff nothing changed (drain()).
        Includes last_ktime (every counted event moves it), thread slots (prev),
        bglobal and every health counter. `excluded` is written only by
        userspace (exclude/unexclude) and is left out."""
        n = len(SYSCALLS)
        counts = sorted(((k.start_ns, k.tgid), tuple(v.c[i] for i in range(n))
                         + ((v.pairs_lost,) if self.has_bigrams else ()))
                        for k, v in self.b["counts"].items())
        info = sorted(((k.start_ns, k.tgid), (v.cgroup_id, v.last_ktime, v.host_tgid, v.level,
                                              v.container_pid, v.exited, bytes(v.comm)))
                      for k, v in self.b["info"].items())
        threads = sorted((tid.value, (s.thread_start_ns, s.proc.start_ns, s.proc.tgid, s.tid, s.prev))
                         for tid, s in self.b["threads"].items())
        state = {"counts": counts, "info": info, "threads": threads, "health": self._health_all(),
                 "userspace": {"reclaimed": self.reclaimed, "purged_self": self._purged_self}}
        if self.has_bigrams:
            items, _method = self._pair_items()
            state["bigrams"] = sorted(((k.proc.start_ns, k.proc.tgid, k.a, k.b), v.value)
                                      for k, v in items)
            g = self.b["bglobal"][ctypes.c_int(0)]
            state["bglobal"] = (g.armed_boot_ns, g.last_thread_full_ns, g.armed)
            state["userspace"].update(purged=dict(self.purged),
                                      reclaimed_totals=dict(self.reclaimed_totals))
        return state

    def _drain_accounting(self, state):
        """The I-B2 terms of a stable read (bigrams). Live terms come from the maps;
        reclaimed and purged terms are copies, so a later reclaim cannot alias them."""
        n = len(SYSCALLS)
        live = dict(state["counts"])
        acc = {"keys": len(live), "counts": sum(sum(v[:n]) for v in live.values()),
               "pairs": 0, "pairs_lost": sum(v[n] for v in live.values()),
               "orphan_entries": 0, "orphan_pairs": 0, "zero_entries": 0,
               "reclaimed": dict(state["userspace"]["reclaimed_totals"]),
               "purged": dict(state["userspace"]["purged"]),
               "bigram_health": self._bigram_health_from(state["health"],
                                                         state["userspace"]["purged"])}
        for (start, tgid, _a, _b), value in state["bigrams"]:
            if (start, tgid) not in live:
                acc["orphan_entries"] += 1
                acc["orphan_pairs"] += value
                continue
            acc["pairs"] += value
            acc["zero_entries"] += value == 0
        return acc

    def drained_processes(self):
        """{(start_ns, tgid): (proc, table)} for every counts entry of the stable
        drain read, ready for the quiescent checkers with quiescence "drained":
        proc = {"counts": {s: n}, "pairs_lost": n (None without bigrams),
        "exited": bool (None without an info entry)}; table = decoded pairs
        (raises bigrams.DecodeError on an I-B5 violation)."""
        from .bigrams import decode_entries
        if self._drain_state is None:
            raise RuntimeError("no successful drain: the maps were not read stably (not drained)")
        st, n = self._drain_state, len(SYSCALLS)
        exited = {key: bool(v[5]) for key, v in st["info"]}
        raw = {}
        for (start, tgid, a, b), value in st.get("bigrams", ()):
            raw.setdefault((start, tgid), []).append((a, b, value))
        out = {}
        for key, vals in st["counts"]:
            table = decode_entries(raw.get(key, []))[0] if self.has_bigrams else {}
            out[key] = ({"counts": dict(zip(SYSCALLS, vals[:n])),
                         "pairs_lost": vals[n] if self.has_bigrams else None,
                         "exited": exited.get(key)}, table)
        return out

    # --- snapshot (schema v1, unchanged from M1) ---------------------------
    def snapshot(self, resource_seq=None):
        """The v1 syscall_snapshot record. After a successful drain() this is the
        drained snapshot: its maps must equal the drain's stable read, it sets
        last_snapshot_drained, and no snapshot may follow it."""
        t0 = time.monotonic_ns()
        drained = self._drain_state is not None
        self.last_snapshot_drained = False
        if drained:
            if self._drained_snapshot_taken:
                raise RuntimeError("the drained snapshot was taken: it is the epoch's last")
            if self._read_state() != self._drain_state:
                raise RuntimeError("the maps changed after the drain: no drained snapshot")
            self._drained_snapshot_taken = True
        counts_t, info_t = self.b["counts"], self.b["info"]
        counts = {(k.start_ns, k.tgid): tuple(v.c[i] for i in range(len(SYSCALLS)))
                  for k, v in counts_t.items()}
        infos = {(k.start_ns, k.tgid): (v.cgroup_id, v.host_tgid, v.level, v.container_pid,
                                        bool(v.exited), bytes(v.comm).split(b"\0", 1)[0])
                 for k, v in info_t.items()}
        raw_pairs = {}
        if self.has_bigrams:
            self.last_bigrams, raw_pairs = self._read_bigrams_raw()
            bg = self.last_bigrams

            def fingerprint(key):              # counts, pairs_lost and pair sum (design §3.4)
                if key not in counts:
                    return None
                return (counts[key], bg["pairs_lost"].get(key),
                        sum(bg["tables"].get(key, {}).values()))
        else:
            fingerprint = counts.get

        # Phase 2 of exit handling: reclaim entries reported as exited last time
        # whose values have not changed since (so no increment is lost).
        for key, prev in list(self._reported_exit.items()):
            cur = fingerprint(key)
            if cur is None or cur == prev:
                k = counts_t.Key(key[0], key[1], 0)
                for table in (counts_t, info_t):
                    try:
                        del table[k]
                    except KeyError:
                        pass
                if self.has_bigrams:
                    if cur is not None:      # the values removed, unchanged since the exit report
                        self.reclaimed_totals["counts"] += sum(cur[0])
                        self.reclaimed_totals["pairs_lost"] += cur[1]
                        self.reclaimed_totals["pairs"] += cur[2]
                    pairs_t = self.b["bigrams"]
                    for _a, _b, _n, bk in raw_pairs.get(key, ()):
                        try:
                            del pairs_t[bk]
                        except KeyError:
                            pass
                    self.last_bigrams["tables"].pop(key, None)
                    self.last_bigrams["pairs_lost"].pop(key, None)
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
                self._reported_exit[key] = fingerprint(key)
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
        self.last_snapshot_drained = drained
        return rec
