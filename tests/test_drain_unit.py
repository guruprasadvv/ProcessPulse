"""Final drain (M1b S2.5, decision U3): detach, wait, read until stable.

Unprivileged: BpfCollector runs against fake BCC objects whose map contents
are scripted read by read, so every outcome (stable at the second read, a
change seen only by the second read, never stable, detach/barrier/read
failure) is deterministic. The real kernel path is tested in
tests/test_drain_bpf.py.
"""

import copy
from types import SimpleNamespace

import pytest

from processpulse import bigrams as bg
from processpulse import bpf_collector as bc
from processpulse.vocab import SYSCALLS

TPS = bc.required_tracepoints(("counts", "bigrams"))
N = len(SYSCALLS)
OPENAT, EXECVE = SYSCALLS.index("openat"), SYSCALLS.index("execve")
START_NEW = bg.MARKER_CODES["START_NEW"]


# --- fake BCC objects -------------------------------------------------------------

def counts_val(pairs_lost=0, **calls):
    c = [0] * N
    for name, n in calls.items():
        c[SYSCALLS.index(name)] = n
    return SimpleNamespace(c=c, pairs_lost=pairs_lost)


def info_val(exited=0, ktime=1):
    return SimpleNamespace(cgroup_id=7, last_ktime=ktime, host_tgid=1, level=2, container_pid=0,
                           exited=exited, comm=b"p")


class Scripted:
    """A map whose items() returns the next scripted content on each call (the
    last one repeats); deletions are recorded and applied to that content."""

    def __init__(self, *contents, fail=False):
        self.contents = [list(c) for c in contents] or [[]]
        self.calls = 0
        self.fail = fail
        self.deleted = []
        self.log = None

    def _now(self):
        return self.contents[min(self.calls, len(self.contents) - 1)]

    def items(self):
        if self.fail:
            raise OSError("map read failed")
        if self.log is not None:
            self.log.append("read")
        out = list(self._now())
        self.calls += 1
        return out

    def items_lookup_batch(self):
        return iter(self.items())

    def keys(self):
        return [k for k, _v in self._now()]

    def Key(self, start, tgid, pad):                    # counts_t.Key(...) in snapshot()
        return SimpleNamespace(start_ns=start, tgid=tgid)

    def __delitem__(self, k):
        self.deleted.append(k)
        cur = self._now()
        ident = _ident(k)
        cur[:] = [(kk, v) for kk, v in cur if _ident(kk) != ident]


def _ident(k):
    if hasattr(k, "proc"):
        return ("pair", k.proc.start_ns, k.proc.tgid, k.a, k.b)
    if hasattr(k, "start_ns"):
        return ("proc", k.start_ns, k.tgid)
    return ("other", getattr(k, "value", k))


class Health:
    def __init__(self, values=None):
        self.values = dict(values or {})

    def __getitem__(self, idx):
        return SimpleNamespace(value=self.values.get(bc.HEALTH_FIELDS[idx.value], 0))


class BGlobal:
    """The one-entry bglobal array; a test may move last_thread_full_ns."""

    def __init__(self):
        self.state = SimpleNamespace(armed_boot_ns=100, last_thread_full_ns=0, armed=1)
        self.reads = 0
        self.full_after = None            # read number from which a full-time appears

    def __getitem__(self, idx):
        assert idx.value == 0
        self.reads += 1
        if self.full_after is not None and self.reads >= self.full_after:
            self.state.last_thread_full_ns = 999
        return self.state


class FakeBPF:
    def __init__(self, tables, log, fail_detach=()):
        self.tables = tables
        self.tracepoint_fds = {tp.encode(): i for i, tp in enumerate(TPS)}
        self.fail_detach = set(fail_detach)
        self.log = log

    def __getitem__(self, name):
        return self.tables[name]

    def detach_tracepoint(self, tp):
        self.log.append(("detach", tp.decode()))
        if tp.decode() in self.fail_detach:
            raise Exception("Failed to detach BPF from tracepoint")
        del self.tracepoint_fds[tp]

    def num_open_tracepoints(self):
        return len(self.tracepoint_fds)


class Resolver:
    def identity(self, cgroup_id):
        return {"cgroup_id": cgroup_id}


def ck(start, tgid):
    return SimpleNamespace(start_ns=start, tgid=tgid)


def pk(start, tgid, a, b):
    return SimpleNamespace(proc=SimpleNamespace(start_ns=start, tgid=tgid), a=a, b=b)


def pv(n):
    return SimpleNamespace(value=n)


def make(counts=([],), pairs=([],), info=None, caps=("counts", "bigrams"), health=None,
         fail_detach=(), monkeypatch=None, barrier=None):
    """A collector on fake maps; returns (collector, log)."""
    log = []
    c = bc.BpfCollector(capabilities=caps, resolver=Resolver())
    c.distro_level, c.distro_pidns_ino, c.attached_since = 2, 4026531836, 1
    tables = {"counts": Scripted(*counts),
              "info": Scripted(*(info if info is not None else
                                 [[(k, info_val()) for k, _v in counts[0]]])),
              "threads": Scripted([]), "health": Health(health)}
    if "bigrams" in caps:
        tables["bigrams"] = Scripted(*pairs)
        tables["bglobal"] = BGlobal()
    tables["counts"].log = log
    c.b = FakeBPF(tables, log, fail_detach)
    if monkeypatch is not None:
        monkeypatch.setattr(bc, "rcu_barrier", barrier or (lambda: log.append("barrier")))
    return c, log


# One idle process: 1 execve + 3 openat; pairs (START_NEW, execve) and (execve..)
IDLE_COUNTS = [(ck(1, 10), counts_val(execve=1, openat=3))]
IDLE_PAIRS = [(pk(1, 10, START_NEW, EXECVE), pv(1)), (pk(1, 10, EXECVE, OPENAT), pv(1)),
              (pk(1, 10, OPENAT, OPENAT), pv(2))]


# --- drain outcomes ----------------------------------------------------------------

def test_drain_detaches_every_probe_then_waits_then_reads_until_two_reads_agree(monkeypatch):
    c, log = make(counts=(IDLE_COUNTS,), pairs=(IDLE_PAIRS,), monkeypatch=monkeypatch)
    r = c.drain()
    assert r["status"] == "drained" and r["drained"] is True and r["reason"] is None
    assert r["reads"] == 2 and r["changed"] == []
    assert sorted(r["detached"]) == sorted(TPS) and r["still_attached"] == []
    assert r["barrier"] is True
    detaches = [i for i, e in enumerate(log) if isinstance(e, tuple)]
    assert len(detaches) == len(TPS)
    b = log.index("barrier")
    assert max(detaches) < b < log.index("read")                      # detach, wait, then read
    assert [d for _op, d in log[:len(TPS)]] == list(TPS)              # syscall probes first
    assert c.attached_tracepoints() == [] and c.b.num_open_tracepoints() == 0


def test_the_second_read_detects_a_change_the_first_missed(monkeypatch):
    late = [(ck(1, 10), counts_val(execve=1, openat=4))]             # one more entry in read 2
    late_pairs = IDLE_PAIRS[:2] + [(pk(1, 10, OPENAT, OPENAT), pv(3))]
    c, log = make(counts=(IDLE_COUNTS, late), pairs=(IDLE_PAIRS, late_pairs),
                  monkeypatch=monkeypatch)
    r = c.drain()
    assert r["status"] == "unstable" and r["drained"] is False
    assert r["reads"] == 2 and r["changed"] == ["bigrams", "counts"]
    assert "differ" in r["reason"]
    assert r["accounting"] is None                                    # nothing is claimed
    with pytest.raises(RuntimeError, match="drained"):
        c.drained_processes()
    assert bg.check_ib2_drain_read(r).status == bg.NOT_APPLICABLE
    # A retry waits for a new grace period before its own two reads.
    r2 = c.drain()
    assert log.count("barrier") == 2
    assert r2["status"] == "drained" and r2["reads"] == 2 and r2["changed"] == []
    assert r2["detached"] == [] and r2["still_attached"] == []
    assert c.drain_result is r2
    acc = r2["accounting"]                                            # the later, stable state
    assert (acc["counts"], acc["pairs"], acc["pairs_lost"]) == (5, 5, 0)


def test_a_late_write_to_bglobal_alone_is_detected(monkeypatch):
    """A row-2 event writes only last_thread_full_ns (plus health): bglobal is compared too."""
    c, _log = make(counts=(IDLE_COUNTS,), pairs=(IDLE_PAIRS,), monkeypatch=monkeypatch)
    c.b.tables["bglobal"].full_after = 2                              # appears in read 2
    r = c.drain()
    assert r["status"] == "unstable" and r["changed"] == ["bglobal"]


def test_a_map_that_keeps_changing_is_never_drained(monkeypatch):
    states = [[(ck(1, 10), counts_val(openat=i))] for i in range(1, 10)]
    c, _log = make(counts=states, info=[[(ck(1, 10), info_val())]], monkeypatch=monkeypatch)
    for _ in range(3):
        r = c.drain()
        assert r["status"] == "unstable" and r["changed"] == ["counts"]
    with pytest.raises(RuntimeError, match="not drained"):
        c.drained_processes()


def test_a_detach_failure_fails_the_drain_before_the_barrier_and_any_read(monkeypatch):
    c, log = make(counts=(IDLE_COUNTS,), pairs=(IDLE_PAIRS,), monkeypatch=monkeypatch,
                  fail_detach=("syscalls:sys_enter_openat",))
    r = c.drain()
    assert r["status"] == "failed" and r["drained"] is False
    assert r["still_attached"] == ["syscalls:sys_enter_openat"]
    assert "syscalls:sys_enter_openat" in r["reason"]
    assert len(r["detached"]) == len(TPS) - 1                         # the others are detached
    assert "barrier" not in log and "read" not in log
    assert r["barrier"] is False and r["reads"] == 0 and r["accounting"] is None


def test_a_barrier_failure_fails_the_drain_before_any_read(monkeypatch):
    log_holder = []

    def failing():
        log_holder.append("barrier")
        raise OSError(22, "membarrier failed")
    c, log = make(counts=(IDLE_COUNTS,), pairs=(IDLE_PAIRS,), monkeypatch=monkeypatch,
                  barrier=failing)
    r = c.drain()
    assert log_holder == ["barrier"] and "read" not in log
    assert r["status"] == "failed" and r["barrier"] is False and r["reads"] == 0
    assert "membarrier" in r["reason"] and r["still_attached"] == []


def test_a_read_failure_fails_the_drain(monkeypatch):
    c, _log = make(counts=(IDLE_COUNTS,), pairs=(IDLE_PAIRS,), monkeypatch=monkeypatch)
    c.b.tables["bigrams"].fail = True
    r = c.drain()
    assert r["status"] == "failed" and r["drained"] is False and r["accounting"] is None
    assert "map read failed" in r["reason"]


def test_drain_needs_a_started_collector():
    with pytest.raises(RuntimeError, match="started"):
        bc.BpfCollector(capabilities=("counts", "bigrams")).drain()


# --- accounting ----------------------------------------------------------------------

def test_empty_bigram_map_is_an_accounted_table_not_missing_data(monkeypatch):
    counts = [(ck(1, 10), counts_val(pairs_lost=4, execve=1, openat=3))]   # all pre-arm
    c, _log = make(counts=(counts,), pairs=([],), monkeypatch=monkeypatch)
    r = c.drain()
    acc = r["accounting"]
    assert (acc["keys"], acc["counts"], acc["pairs"], acc["pairs_lost"]) == (1, 4, 0, 4)
    assert acc["orphan_entries"] == 0 and acc["zero_entries"] == 0
    ((key, (proc, table)),) = c.drained_processes().items()
    assert key == (1, 10) and table == {} and proc["pairs_lost"] == 4
    assert bg.check_ib1_prime(proc, table, "drained").status == bg.PASS
    assert bg.check_ib2_drain_read(r).status == bg.PASS


def test_accounting_adds_live_reclaimed_and_purged_terms_once(monkeypatch):
    counts = IDLE_COUNTS + [(ck(2, 20), counts_val(pairs_lost=1, openat=2))]
    pairs = IDLE_PAIRS + [(pk(2, 20, START_NEW, OPENAT), pv(1)),
                          (pk(2, 20, OPENAT, OPENAT), pv(0))]        # zero entry: not loss
    c, _log = make(counts=(counts,), pairs=(pairs,), monkeypatch=monkeypatch)
    c.reclaimed_totals = {"counts": 7, "pairs": 6, "pairs_lost": 1}
    c.purged = {"counts": 5, "pairs": 3, "pairs_lost": 2}
    r = c.drain()
    acc = r["accounting"]
    assert (acc["keys"], acc["counts"], acc["pairs"], acc["pairs_lost"]) == (2, 6, 5, 1)
    assert acc["zero_entries"] == 1
    assert acc["reclaimed"] == {"counts": 7, "pairs": 6, "pairs_lost": 1}
    assert acc["purged"] == {"counts": 5, "pairs": 3, "pairs_lost": 2}
    assert acc["bigram_health"]["purged_pairs_lost"] == 2
    res = bg.check_ib2_drain_read(r)
    assert res.status == bg.PASS, res
    assert res.detail["lhs"] == res.detail["rhs"] == 6 + 7 + 5


@pytest.mark.parametrize("term,field,delta", [
    ("reclaimed", "counts", 4),          # a reclaimed key counted again on one side only
    ("purged", "pairs_lost", 1),         # purged_pairs_lost left out (S2.2 §8.5 A)
    ("reclaimed", "pairs", -1)])
def test_ib2_drain_read_fails_by_exactly_the_missing_or_double_term(monkeypatch, term, field, delta):
    c, _log = make(counts=(IDLE_COUNTS,), pairs=(IDLE_PAIRS,), monkeypatch=monkeypatch)
    c.reclaimed_totals = {"counts": 3, "pairs": 3, "pairs_lost": 0}
    c.purged = {"counts": 2, "pairs": 1, "pairs_lost": 1}
    r = c.drain()
    assert bg.check_ib2_drain_read(r).status == bg.PASS
    bad = copy.deepcopy(r)
    bad["accounting"][term][field] += delta
    res = bg.check_ib2_drain_read(bad)
    assert res.status == bg.FAIL
    lhs_terms = field == "counts"
    assert res.detail["lhs"] - res.detail["rhs"] == (delta if lhs_terms else -delta)


def test_pair_entries_without_a_counts_entry_fail_ib2(monkeypatch):
    c, _log = make(counts=(IDLE_COUNTS,), pairs=(IDLE_PAIRS + [(pk(9, 90, OPENAT, OPENAT), pv(2))],),
                   monkeypatch=monkeypatch)
    r = c.drain()
    assert r["accounting"]["orphan_entries"] == 1 and r["accounting"]["orphan_pairs"] == 2
    res = bg.check_ib2_drain_read(r)
    assert res.status == bg.FAIL and "without a counts entry" in res.reason


def test_ib2_drain_read_preconditions():
    assert bg.check_ib2_drain_read(None).status == bg.NOT_APPLICABLE
    assert bg.check_ib2_drain_read({"drained": False, "accounting": None}).status == bg.NOT_APPLICABLE
    res = bg.check_ib2_drain_read({"drained": True, "accounting": None})
    assert res.status == bg.NOT_APPLICABLE and "bigram" in res.reason


def test_drained_processes_feed_the_quiescent_checkers(monkeypatch):
    c, _log = make(counts=(IDLE_COUNTS,), pairs=(IDLE_PAIRS,), monkeypatch=monkeypatch)
    c.drain()
    procs = c.drained_processes()
    proc, table = procs[(1, 10)]
    assert table == {("START_NEW", "execve"): 1, ("execve", "openat"): 1, ("openat", "openat"): 2}
    assert proc["counts"]["openat"] == 3 and proc["exited"] is False
    for check in (bg.check_ib1, bg.check_ib1_prime, bg.check_ib3_prime):
        assert check(proc, table, "drained").status == bg.PASS
    assert bg.check_ib5(table).status == bg.PASS


def test_a_marker_as_second_element_in_the_drained_read_is_refused(monkeypatch):
    c, _log = make(counts=(IDLE_COUNTS,), pairs=([(pk(1, 10, OPENAT, START_NEW), pv(1))],),
                   monkeypatch=monkeypatch)
    assert c.drain()["status"] == "drained"                           # stability is about change
    with pytest.raises(bg.DecodeError, match="I-B5"):
        c.drained_processes()


def test_counts_only_drain_has_no_bigram_accounting(monkeypatch):
    c, log = make(counts=(IDLE_COUNTS,), caps=("counts",), monkeypatch=monkeypatch)
    r = c.drain()
    assert r["status"] == "drained" and r["accounting"] is None
    assert "bigrams" not in c.b.tables
    res = bg.check_ib2_drain_read(r)
    assert res.status == bg.NOT_APPLICABLE
    proc, table = c.drained_processes()[(1, 10)]
    assert proc["pairs_lost"] is None and table == {}


# --- exclusion and snapshots around the drain -------------------------------------------

def test_exclude_is_refused_once_a_drain_started(monkeypatch):
    c, log = make(counts=(IDLE_COUNTS,), pairs=(IDLE_PAIRS,), monkeypatch=monkeypatch,
                  fail_detach=("sched:sched_process_exit",))
    assert c.drain()["status"] == "failed"
    c.b.tables["excluded"] = Scripted()
    n = len(log)
    with pytest.raises(RuntimeError, match="drain"):
        c.exclude(10)
    assert log[n:] == []                                              # no barrier, no purge
    assert c.purged == {"counts": 0, "pairs": 0, "pairs_lost": 0}


def _exited_then_reclaimable(monkeypatch):
    """One idle live process and one exited process (1 execve + 2 open)."""
    counts = IDLE_COUNTS + [(ck(2, 20), counts_val(execve=1, open=2))]
    pairs = IDLE_PAIRS + [(pk(2, 20, START_NEW, EXECVE), pv(1)),
                          (pk(2, 20, EXECVE, SYSCALLS.index("open")), pv(1)),
                          (pk(2, 20, SYSCALLS.index("open"), SYSCALLS.index("open")), pv(1))]
    info = [(ck(1, 10), info_val()), (ck(2, 20), info_val(exited=1))]
    c, log = make(counts=(counts,), pairs=(pairs,), info=[info], monkeypatch=monkeypatch)
    c.track_removals = True
    return c, log


def test_reclaim_records_the_values_it_removes(monkeypatch):
    c, _log = _exited_then_reclaimable(monkeypatch)
    s1 = c.snapshot()
    assert [p["exited"] for p in s1["procs"]] == [False, True]
    assert c.reclaimed_totals == {"counts": 0, "pairs": 0, "pairs_lost": 0}
    c.snapshot()                                                      # unchanged: reclaimed
    assert c.reclaimed == 1
    assert c.reclaimed_totals == {"counts": 3, "pairs": 3, "pairs_lost": 0}
    assert len(c.b.tables["bigrams"].deleted) == 3


def test_reclaim_of_a_key_whose_entry_is_gone_adds_nothing(monkeypatch):
    c, _log = _exited_then_reclaimable(monkeypatch)
    c.snapshot()
    del c.b.tables["counts"][ck(2, 20)]                               # e.g. purged meanwhile
    c.snapshot()
    assert c.reclaimed == 1 and c.reclaimed_totals == {"counts": 0, "pairs": 0, "pairs_lost": 0}


def test_ib2_holds_across_reclaim_on_the_drained_read(monkeypatch):
    c, _log = _exited_then_reclaimable(monkeypatch)
    c.snapshot()
    c.snapshot()                                                      # key 20 reclaimed
    r = c.drain()
    assert r["accounting"]["keys"] == 1                               # 20 is gone from the maps
    res = bg.check_ib2_drain_read(r)
    assert res.status == bg.PASS and res.detail["lhs"] == 4 + 3       # live 4 + reclaimed 3


def test_the_drained_snapshot_is_cross_checked_and_is_the_last(monkeypatch):
    c, _log = _exited_then_reclaimable(monkeypatch)
    c.snapshot()                                                      # 20 reported exited
    assert c.last_snapshot_drained is False
    r = c.drain()
    assert r["drained"] and r["accounting"]["keys"] == 2
    s = c.snapshot()                                                  # the drained snapshot
    assert c.last_snapshot_drained is True
    assert [p["key"]["tgid"] for p in s["procs"]] == [10]             # 20 reclaimed in it
    assert c.take_removed()["exited"][0]["tgid"] == 20
    assert c.reclaimed_totals == {"counts": 3, "pairs": 3, "pairs_lost": 0}
    # The drain-time accounting is a copy: reclaiming 20 now must not count it twice.
    assert bg.check_ib2_drain_read(r).status == bg.PASS
    with pytest.raises(RuntimeError, match="last"):
        c.snapshot()
    with pytest.raises(RuntimeError, match="last"):
        c.drain()


def test_a_map_change_after_the_drain_fails_the_drained_snapshot(monkeypatch):
    c, _log = _exited_then_reclaimable(monkeypatch)
    assert c.drain()["drained"]
    c.b.tables["counts"].contents[-1][0] = (ck(1, 10), counts_val(execve=1, openat=9))
    with pytest.raises(RuntimeError, match="changed after the drain"):
        c.snapshot()
    assert c.last_snapshot_drained is False


def test_snapshots_after_an_unsuccessful_drain_are_ordinary(monkeypatch):
    states = [[(ck(1, 10), counts_val(openat=i))] for i in range(1, 10)]
    c, _log = make(counts=states, info=[[(ck(1, 10), info_val())]], monkeypatch=monkeypatch)
    assert c.drain()["status"] == "unstable"
    c.snapshot()
    c.snapshot()
    assert c.last_snapshot_drained is False


def test_counts_only_snapshot_path_is_unchanged_without_a_drain(monkeypatch):
    c, _log = make(counts=(IDLE_COUNTS,), caps=("counts",), monkeypatch=monkeypatch)
    rec = c.snapshot()
    assert rec["type"] == "syscall_snapshot" and rec["v"] == 1
    assert set(rec) == {"type", "v", "seq", "t_mono_ns", "interval_ns", "resource_seq", "probe",
                        "calibration", "procs", "health"}
    assert c.last_snapshot_drained is False
    assert c.reclaimed_totals == {"counts": 0, "pairs": 0, "pairs_lost": 0}
