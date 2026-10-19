"""Schema-v2 BPF snapshot protocol: producer and consumer (docs/telemetry-v2.md).

A snapshot is   bpf_snapshot_begin, bpf_proc*, bpf_reclaimed*, bpf_snapshot_end
with one seq. Counters are cumulative since the capability epoch
(run_id, attach_since_mono_ns) and are never deltas.

V2Emitter (agent side) turns the unchanged M1 SyscallCollector into v2
records. A bpf_proc carries the complete state of one process and is emitted
when the process is new or any of its fields differ from what was last
emitted (this includes the first exited=true), and for every tracked process
in a keyframe. The emitted state advances only when the caller invokes
commit() after writing every line, so a snapshot that was not completely
written changes nothing. A failed map read yields begin + end(status=failed)
and also changes nothing.

Keyframe rule (one emitter = one epoch; seq counts every snapshot attempt of
the epoch from 0):  keyframe(seq) <=> status ok and (seq % 60 == 0 or due).
`due` is set at the start of the epoch, when a snapshot with seq % 60 == 0
fails, and when the previous snapshot was never committed (it may be torn on
disk); it is cleared when a keyframe is committed. So the first successful
snapshot of an epoch is always a keyframe, a missed keyframe is recovered by
the next successful snapshot, and recovery keyframes do not move the cadence.

Reconstructor (consumer side) rebuilds the emitted state and, per snapshot,
reports which processes were emitted and which omitted ones are known to be
unchanged. Omission means "unchanged" only while the state is valid: a
keyframe was applied in this epoch, and since then every snapshot arrived
complete, in sequence, with matching end-of-snapshot tracked/totals.
Otherwise the state is invalid until the next keyframe.
"""

import json
import time
from dataclasses import dataclass, field

from .jsonl import MAX_RECORD_BYTES, RecordTooLarge, encode_record
from .syscalls import SYSCALLS
from .validate import v2_proc_semantic_errors

V = 2
KEYFRAME_INTERVAL = 60
CAPABILITY = "counts"
REMOVAL_REASONS = ("exited", "self_excluded", "vanished")
LOSS_FIELDS = ("counts_map_full", "info_map_full", "vanished_entries")
U64 = 1 << 64
_HEADER = ("type", "v", "seq")


def key_tuple(key):
    return (key["boot_id"], key["pidns_ino"], key["tgid"], key["start_ticks"])


def totals(payloads, names=SYSCALLS):
    """Per-syscall sums of cumulative counts over payloads, mod 2^64."""
    out = dict.fromkeys(names, 0)
    for p in payloads:
        for n in names:
            out[n] = (out[n] + p["counts"][n]) % U64
    return out


def chunk_records(make, items, limit=MAX_RECORD_BYTES):
    """make(chunk) for consecutive chunks of items, each record within limit bytes."""
    base = len(encode_record(make([]), limit).encode())       # includes the "[]"
    chunks, cur, size = [], [], base
    for it in items:
        n = len(json.dumps(it, separators=(",", ":")).encode())
        if cur and size + 1 + n > limit:
            chunks.append(cur)
            cur, size = [], base
        if size + n + (1 if cur else 0) > limit:
            raise RecordTooLarge(f"one item of {n} bytes cannot fit a record of {limit} bytes")
        size += n + (1 if cur else 0)
        cur.append(it)
    if cur:
        chunks.append(cur)
    return [make(c) for c in chunks]


class V2Emitter:
    def __init__(self, collector, run_id, keyframe_interval=KEYFRAME_INTERVAL,
                 limit=MAX_RECORD_BYTES, clock=time.monotonic_ns):
        if getattr(collector, "track_removals", True) is not True:
            raise ValueError("V2Emitter needs a collector created with track_removals=True")
        self.c = collector
        self.run_id = run_id
        self.keyframe_interval = keyframe_interval
        self.limit = limit
        self.clock = clock
        self.seq = 0
        self.live = {}          # key tuple -> payload last emitted (and committed)
        self.vanished = 0       # cumulative vanished_entries (committed)
        self._prev_t = None
        self._attach = collector.attached_since   # the epoch this emitter serves
        self._keyframe_due = True                  # first successful snapshot of the epoch
        self._uncommitted = False                  # previous build() not committed

    def _begin(self, seq, t0, interval, resource_seq, keyframe):
        c = self.c
        return {
            "type": "bpf_snapshot_begin", "v": V, "seq": seq, "t_mono_ns": t0,
            "interval_ns": interval, "resource_seq": resource_seq, "keyframe": keyframe,
            "calibration": {"boot_id": c.boot_id, "distro_level": c.distro_level,
                            "distro_pidns_ino": c.distro_pidns_ino},
            "capabilities": {CAPABILITY: {
                "status": "ok",
                "epoch": {"run_id": self.run_id, "attach_since_mono_ns": c.attached_since},
                "probe": {"mode": "per_syscall_tracepoints", "syscalls": list(SYSCALLS)},
            }},
        }

    def _end(self, seq, status, reason, procs, reclaimed, nkeys, live, loss, health, read_err):
        return {
            "type": "bpf_snapshot_end", "v": V, "seq": seq, "t_mono_ns": self.clock(),
            "status": status, "reason": reason, "procs_emitted": procs,
            "reclaimed_records": reclaimed, "reclaimed_keys": nkeys, "tracked": len(live),
            "totals": {"counts": totals(live.values())},
            "loss": loss, "health": health, "read_err": read_err,
        }

    def build(self, resource_seq=None):
        """Returns (records, commit). Write every record, then call commit()."""
        if self.c.attached_since != self._attach:
            raise RuntimeError("collector re-attached: a new epoch needs a new V2Emitter")
        if self._uncommitted:            # the previous snapshot may be torn on disk
            self._keyframe_due = True
        self._uncommitted = True
        seq = self.seq
        self.seq += 1
        scheduled = seq % self.keyframe_interval == 0
        t0 = self.clock()
        interval = None if self._prev_t is None else t0 - self._prev_t
        self._prev_t = t0
        try:
            snap = self.c.snapshot(resource_seq=resource_seq)
            removed = self.c.take_removed()
        except Exception as e:   # map read failure: report it, change nothing
            if scheduled:
                self._keyframe_due = True        # recover at the next successful snapshot
            reason = f"{type(e).__name__}: {e}"[:200]
            recs = [self._begin(seq, t0, interval, resource_seq, False),
                    self._end(seq, "failed", reason, 0, 0, 0, self.live, None, None, "EIO")]

            def commit_failed():
                self._uncommitted = False
            return recs, commit_failed

        procs = {}
        for p in snap["procs"]:
            procs[key_tuple(p["key"])] = p
        removals, gone = [], set()
        for reason in ("exited", "self_excluded"):
            for kd in removed.get(reason, ()):
                kt = key_tuple(kd)
                procs.pop(kt, None)          # a deletion wins over a value read before it
                if kt in self.live and kt not in gone:
                    removals.append((reason, self.live[kt]["key"]))
                    gone.add(kt)
        for kt, p in self.live.items():
            if kt not in gone and kt not in procs:
                removals.append(("vanished", p["key"]))
                gone.add(kt)
        vanished = self.vanished + sum(1 for r, _ in removals if r == "vanished")

        keyframe = scheduled or self._keyframe_due
        live = {kt: p for kt, p in self.live.items() if kt not in gone}
        emit = []
        for kt, p in procs.items():
            if keyframe or self.live.get(kt) != p:
                emit.append(p)
            live[kt] = p

        recs = [self._begin(seq, t0, interval, resource_seq, keyframe)]
        recs += [{"type": "bpf_proc", "v": V, "seq": seq, **p} for p in emit]
        chunks = []
        for reason in REMOVAL_REASONS:
            keys = [kd for r, kd in removals if r == reason]
            if keys:
                chunks += chunk_records(
                    lambda ks, r=reason: {"type": "bpf_reclaimed", "v": V, "seq": seq,
                                          "reason": r, "keys": ks}, keys, self.limit)
        recs += chunks
        h = snap["health"]
        loss = {"counts_map_full": h["counts_map_full"], "info_map_full": h["info_map_full"],
                "vanished_entries": vanished}
        health = {k: h[k] for k in ("map_entries", "map_capacity", "unresolved_events",
                                    "self_excluded_events", "exit_events", "reclaimed",
                                    "snapshot_ns")}
        health["unreported_entries"] = self.c.last_unreported
        recs.append(self._end(seq, "ok", None, len(emit), len(chunks), len(removals), live,
                              loss, health, None))

        def commit():
            self.live = live
            self.vanished = vanished
            self._uncommitted = False
            if keyframe:
                self._keyframe_due = False
        return recs, commit


@dataclass
class SnapshotView:
    """What one complete snapshot lets a consumer conclude."""
    seq: int
    status: str                      # "ok" | "failed"
    keyframe: bool
    valid: bool                      # state trustworthy after this snapshot
    emitted: set = field(default_factory=set)
    unchanged: set = field(default_factory=set)   # omitted and known unchanged
    loss_possible: object = None     # True/False, or None when it cannot be judged


class Reconstructor:
    STATS = ("snapshots_complete", "snapshots_failed", "snapshots_incomplete", "keyframes",
             "framing_errors", "seq_gaps", "epoch_changes", "totals_mismatch", "invalidations",
             "keyframe_schedule_violations")

    def __init__(self, keep_errors=50):
        self.state = {}
        self.valid = False
        self.epoch = None
        self.calibration = None
        self.last_seq = None         # seq of the last complete snapshot in this epoch
        self.last = None             # SnapshotView of the last complete snapshot
        self.stats = dict.fromkeys(self.STATS, 0)
        self.errors = []
        self._keep = keep_errors
        self._open = None
        self._last_loss = None
        self._kf_due = False         # producer owes a keyframe (only judged from an observed epoch start)

    # --- bookkeeping ------------------------------------------------------
    def _error(self, msg):
        if len(self.errors) < self._keep:
            self.errors.append(msg)

    def _invalidate(self, why):
        if self.valid:
            self.stats["invalidations"] += 1
        self._error(f"invalidated: {why}")
        self.valid = False
        self.state = {}
        self._last_loss = None

    def _incomplete(self, why):
        self.stats["snapshots_incomplete"] += 1
        self._open = None
        self._invalidate(f"incomplete snapshot: {why}")

    # --- input ------------------------------------------------------------
    def feed(self, rec):
        t = rec.get("type") if isinstance(rec, dict) else None
        if t == "bpf_snapshot_begin":
            if self._open is not None:
                self._incomplete(f"begin seq {rec.get('seq')} before end of seq "
                                 f"{self._open['begin'].get('seq')}")
            self._open = {"begin": rec, "procs": [], "reclaimed": []}
            return
        if t not in ("bpf_proc", "bpf_reclaimed", "bpf_snapshot_end"):
            self.stats["framing_errors"] += 1
            self._invalidate(f"unexpected record type {t!r}")
            return
        if self._open is None:
            self.stats["framing_errors"] += 1
            self._invalidate(f"{t} seq {rec.get('seq')} outside a snapshot")
            return
        if rec.get("seq") != self._open["begin"].get("seq"):
            self._incomplete(f"{t} seq {rec.get('seq')} inside snapshot "
                             f"{self._open['begin'].get('seq')}")
            return
        if t == "bpf_proc":
            if self._open["reclaimed"]:
                self._incomplete("bpf_proc after bpf_reclaimed")
                return
            self._open["procs"].append(rec)
        elif t == "bpf_reclaimed":
            self._open["reclaimed"].append(rec)
        else:
            snap, self._open = self._open, None
            try:
                self._close(snap["begin"], snap["procs"], snap["reclaimed"], rec)
            except (KeyError, TypeError) as e:
                self.stats["snapshots_incomplete"] += 1
                self._invalidate(f"malformed snapshot record: {type(e).__name__}: {e}")

    def finish(self):
        """End of stream: an open snapshot is incomplete."""
        if self._open is not None:
            self._incomplete(f"stream ended inside snapshot {self._open['begin'].get('seq')}")

    # --- applying a framed snapshot ---------------------------------------
    def _structure_problems(self, b, procs, recl, end):
        out = []
        if end["procs_emitted"] != len(procs):
            out.append(f"procs_emitted {end['procs_emitted']} != {len(procs)}")
        if end["reclaimed_records"] != len(recl):
            out.append(f"reclaimed_records {end['reclaimed_records']} != {len(recl)}")
        nkeys = sum(len(r["keys"]) for r in recl)
        if end["reclaimed_keys"] != nkeys:
            out.append(f"reclaimed_keys {end['reclaimed_keys']} != {nkeys}")
        pkeys = [key_tuple(p["key"]) for p in procs]
        rkeys = [key_tuple(k) for r in recl for k in r["keys"]]
        if len(set(pkeys)) != len(pkeys):
            out.append("duplicate bpf_proc key")
        if len(set(rkeys)) != len(rkeys):
            out.append("duplicate reclaimed key")
        if set(pkeys) & set(rkeys):
            out.append("key both emitted and reclaimed")
        if end["status"] == "failed" and (b["keyframe"] or procs or recl):
            out.append("failed snapshot carries a keyframe or records")
        for p in procs:
            out.extend(v2_proc_semantic_errors(b, p))
        return out

    def _matches(self, end):
        return (end["tracked"] == len(self.state)
                and end["totals"]["counts"] == totals(self.state.values()))

    def _close(self, b, procs, recl, end):
        seq = b["seq"]
        problems = self._structure_problems(b, procs, recl, end)
        if problems:
            self.stats["snapshots_incomplete"] += 1
            self._invalidate(f"snapshot {seq} rejected: {'; '.join(problems[:3])}")
            return

        cap = b["capabilities"][CAPABILITY]
        epoch = (cap["epoch"]["run_id"], cap["epoch"]["attach_since_mono_ns"])
        if epoch != self.epoch:
            if self.epoch is not None:
                self.stats["epoch_changes"] += 1
                self._error(f"epoch changed at seq {seq}: {self.epoch} -> {epoch}")
            self.epoch, self.calibration, self.last_seq = epoch, b["calibration"], None
            self.valid, self.state, self._last_loss = False, {}, None
            self._kf_due = seq == 0          # the epoch's start was observed
        elif b["calibration"] != self.calibration:
            self._invalidate(f"calibration changed within an epoch at seq {seq}")
            self.calibration = b["calibration"]
        if self.last_seq is not None and seq != self.last_seq + 1:
            self.stats["seq_gaps"] += 1
            self._invalidate(f"seq {self.last_seq} -> {seq}")
        self.last_seq = seq
        self.stats["snapshots_complete"] += 1
        scheduled = seq % KEYFRAME_INTERVAL == 0

        if end["status"] == "failed":
            if scheduled:
                self._kf_due = True          # the next successful snapshot must be a keyframe
            self.stats["snapshots_failed"] += 1
            if self.valid and not self._matches(end):
                self.stats["totals_mismatch"] += 1
                self._invalidate(f"failed snapshot {seq}: tracked/totals differ")
            self.last = SnapshotView(seq, "failed", False, self.valid)
            return

        if (scheduled or self._kf_due) and not b["keyframe"]:
            self.stats["keyframe_schedule_violations"] += 1    # counted once per missed keyframe
            self._error(f"snapshot {seq}: a keyframe was required")
            self._kf_due = False
        if b["keyframe"]:
            self.stats["keyframes"] += 1
            self._kf_due = False
            self.state = {key_tuple(p["key"]): _payload(p) for p in procs}
            self.valid = True
        elif self.valid:
            for p in procs:
                self.state[key_tuple(p["key"])] = _payload(p)
            for r in recl:
                for k in r["keys"]:
                    if self.state.pop(key_tuple(k), None) is None:
                        self._invalidate(f"snapshot {seq}: reclaimed key {k} is not tracked")
                        break
                if not self.valid:
                    break
        if self.valid and not self._matches(end):
            self.stats["totals_mismatch"] += 1
            self._invalidate(f"snapshot {seq}: tracked/totals differ from the end record")

        emitted = {key_tuple(p["key"]) for p in procs}
        loss_possible = None
        if self.valid and self._last_loss is not None:
            loss_possible = any(end["loss"][f] > self._last_loss[f] for f in LOSS_FIELDS)
        if self.valid:
            self._last_loss = end["loss"]
        self.last = SnapshotView(seq, "ok", bool(b["keyframe"]), self.valid, emitted,
                                 (set(self.state) - emitted) if self.valid else set(),
                                 loss_possible)


def _payload(p):
    return {k: v for k, v in p.items() if k not in _HEADER}
