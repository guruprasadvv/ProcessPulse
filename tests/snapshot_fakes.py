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


# --- S2 bigram records (consumer/validator tests only) ----------------------

class BigramFake(FakeCollector):
    """FakeCollector plus a pair table {(a, b): n} and pairs_lost per process."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.pairs = {}
        self.lost = {}

    def add(self, tgid, **counts):
        super().add(tgid, **counts)
        self.pairs[tgid] = {}
        self.lost[tgid] = 0

    def step_pair(self, tgid, a, b, n=1):
        """n recorded pairs (a, b); their second element is counted too."""
        self.bump(tgid, b, n)
        t = self.pairs[tgid]
        t[(a, b)] = t.get((a, b), 0) + n

    def lose_pair(self, tgid, syscall, n=1):
        """n entries counted whose pairs were lost (R-LOSS rows 2 and 3)."""
        self.bump(tgid, syscall, n)
        self.lost[tgid] += n


def pair_truth(fake):
    """The pair tables a correct consumer must hold after a complete snapshot."""
    from processpulse.snapshots import key_tuple
    return {key_tuple(p["key"]): fake.pairs[t] for t, p in fake.procs.items()}


def bigram_state_truth(fake):
    """truth(fake) with the per-process bigram fields of an available capability."""
    return {k: dict(p, pairs_lost=fake.lost[p["key"]["tgid"]], bigrams_err=None)
            for k, p in truth(fake).items()}


class BigramStandIn:
    """Test-only producer of S2 bigram snapshots around the S0 V2Emitter.

    It adds the bigrams capability to every snapshot the S0 emitter builds, so
    the schema and the Reconstructor can be tested before the real producer
    exists (a later S2 step). A table is emitted with its process's bpf_proc
    (design §3.7); end totals cover the committed state.
    """

    def __init__(self, fake, run_id="run-b", status="ok", err=None, reason=None,
                 max_items=None, limit=None):
        from processpulse.snapshots import BIGRAM_HEALTH_FIELDS, V2Emitter
        self.em = V2Emitter(fake, run_id=run_id)
        self.fake = fake
        self.status, self.err, self.reason = status, err, reason
        self.part_args = {k: v for k, v in (("max_items", max_items), ("limit", limit)) if v}
        self.health = dict.fromkeys(BIGRAM_HEALTH_FIELDS, 0)
        self.live = {}              # key tuple -> (table, pairs_lost), committed
        self.drain = False          # mark the next successful snapshot drained

    def build(self, resource_seq=None):
        from processpulse.snapshots import bigram_parts, bigram_totals, key_tuple
        recs, done = self.em.build(resource_seq=resource_seq)
        begin, end = recs[0], recs[-1]
        seq, ok, avail = begin["seq"], end["status"] == "ok", self.status == "ok"
        begin["capabilities"]["bigrams"] = {
            "status": self.status,
            "epoch": dict(begin["capabilities"]["counts"]["epoch"]) if avail else None,
            "err": self.err, "reason": self.reason}
        procs = [r for r in recs if r["type"] == "bpf_proc"]
        recl = [r for r in recs if r["type"] == "bpf_reclaimed"]
        live = {} if begin["keyframe"] else dict(self.live)
        for r in recl:
            for k in r["keys"]:
                live.pop(key_tuple(k), None)
        parts = []
        for p in procs:
            tgid = p["key"]["tgid"]
            if avail:
                table, lost = dict(self.fake.pairs[tgid]), self.fake.lost[tgid]
                p["pairs_lost"], p["bigrams_err"] = lost, None
                parts += bigram_parts(seq, p["key"], table, **self.part_args)
                live[key_tuple(p["key"])] = (table, lost)
            else:
                p["pairs_lost"], p["bigrams_err"] = None, self.err
        if not ok:
            live = self.live
        end["bigram_records"] = len(parts)
        end["totals"]["bigrams"] = (bigram_totals([{"pairs_lost": n} for _, n in live.values()],
                                                  [t for t, _ in live.values()])
                                    if avail else None)
        end["bigram_health"] = dict(self.health) if ok and avail else None
        end["drained"] = ok and self.drain

        def commit():
            done()
            if ok:
                self.live = live
        return [begin] + procs + parts + recl + [end], commit
