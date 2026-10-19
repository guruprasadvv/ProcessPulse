"""Privileged tests of the bigrams capability (M1b S2.3): compilation and
attachment, exact pairs, markers, every R-LOSS path, thread lifecycle, exec,
thread-ID reuse, reclaim and self-exclusion purge.

Run as root:  make test-privileged

Exact assertions are made only on idle helpers (blocked reading stdin, which
is not a tracked call), so the sequential map reads see a quiescent process.
Loss paths are forced deterministically by filling one map from userspace
with entries that cannot belong to a process (tgid 0, host TIDs above
pid_max), then removing them.
"""

import os
import shutil

import pytest

from conftest import Helper
from processpulse import bigrams as bg
from processpulse import bpf_collector as bc
from processpulse.identity import CgroupResolver
from processpulse.vocab import SYSCALLS

pytestmark = [pytest.mark.privileged, pytest.mark.bpf]

CAPS = ("counts", "bigrams")
MARKERS = ("START_NEW", "START_ATTACH", "START_LOST", "EXEC")
# A helper started by the test: forked after arming, its only tracked call
# before its image runs is the execve that loads it.
LAUNCH = [("thread", "m", "new"), ("call", "m", "execve"), ("exec", "m")]


def bpf_prog_fds():
    n = 0
    for fd in os.listdir("/proc/self/fd"):
        try:
            if os.readlink(f"/proc/self/fd/{fd}") == "anon_inode:bpf-prog":
                n += 1
        except OSError:
            pass
    return n


@pytest.fixture(scope="module")
def col():
    c = bc.BpfCollector(capabilities=CAPS, resolver=CgroupResolver(min_rescan_s=0)).start()
    yield c
    c.close()


@pytest.fixture(scope="module")
def small():
    """Small maps for the loss paths; each test fills one map and empties it again."""
    c = bc.BpfCollector(capabilities=CAPS, max_procs=256, max_threads=256, max_pairs=256,
                        resolver=CgroupResolver(min_rescan_s=0)).start()
    yield c
    c.close()


@pytest.fixture
def exec_target(tmp_path, helper_bin):
    path = tmp_path / "ppc_execd"
    shutil.copy2(helper_bin, path)
    os.chmod(tmp_path, 0o755)
    return str(path)


def read_ready(h):
    line = h.proc.stdout.readline().split()
    assert line and line[0] == "READY", line
    return line


def key_of(c, pid):
    keys = [(k.start_ns, k.tgid) for k in c.b["counts"].keys() if k.tgid == pid]
    assert len(keys) == 1, keys
    return keys[0]


def counts_of(c, pid):
    for k, v in c.b["counts"].items():
        if k.tgid == pid:
            return dict(zip(SYSCALLS, list(v.c)[:len(SYSCALLS)]))
    return None


def state(c, pid):
    """(proc payload for the checkers, pair table) of an idle helper."""
    r = c.read_bigrams()
    k = key_of(c, pid)
    return {"counts": counts_of(c, pid), "pairs_lost": r["pairs_lost"][k]}, r["tables"][k]


def starts(table):
    return {m: sum(n for (a, _b), n in table.items() if a == m) for m in MARKERS}


def delta(t1, t0):
    out = {k: t1.get(k, 0) - t0.get(k, 0) for k in set(t1) | set(t0)}
    return {k: v for k, v in out.items() if v}


def assert_quiescent_invariants(p, t, zero_loss=True):
    assert bg.check_ib5(t).status == bg.PASS
    assert bg.check_ib1_prime(p, t, "asserted").status == bg.PASS, (p, t)
    assert bg.check_ib3_prime(p, t, "asserted").status == bg.PASS, (p, t)
    if zero_loss:
        r = bg.check_ib1(p, t, "asserted")
        assert r.status == bg.PASS, r


def fill(table, make_key, make_leaf):
    """Inserts entries until the map is full; returns them for removal."""
    keys = []
    for i in range(1, 1 << 20):
        k = make_key(table, i)
        try:
            table[k] = make_leaf(table)
        except Exception:                      # map full: update rejected by the kernel
            break
        keys.append(k)
    return keys


def drain_keys(table, keys):
    for k in keys:
        try:
            del table[k]
        except KeyError:
            pass


# --- compilation and attachment --------------------------------------------------

def test_two_compilations_same_tracepoints_and_one_extra_map(monkeypatch):
    import bcc
    calls = []

    class Counting(bcc.BPF):
        def __init__(self, *a, **kw):
            calls.append(kw.get("cflags", []))
            super().__init__(*a, **kw)

    monkeypatch.setattr(bc, "_bpf_class", lambda: Counting)
    fds0 = bpf_prog_fds()
    c = bc.BpfCollector(capabilities=CAPS).start()
    try:
        assert len(calls) == 2
        assert [x["name"] for x in c.compilations] == ["calibrate", "unified"]
        assert {"-DPPC_CAP_COUNTS=1", "-DPPC_CAP_BIGRAMS=1", "-DMAX_PAIRS=131072"} <= set(calls[1])
        info = c.build_info()
        assert info["capabilities"] == ["counts", "bigrams"]
        assert info["tracepoints"] == sorted(bc.required_tracepoints(("counts",)))
        assert info["open_tracepoints"] == len(SYSCALLS) + 2
        assert bpf_prog_fds() - fds0 == len(SYSCALLS) + 2           # no extra program
        assert info["maps"]["bigrams"]["max_entries"] == 131072
        assert info["armed_boot_ns"] is not None and info["vocabulary"] == "v1-3aba869d1752"
    finally:
        c.close()
    assert bpf_prog_fds() == fds0


def test_counts_only_build_has_no_bigram_map_and_keeps_its_counters_at_zero(spawn_helper):
    c = bc.BpfCollector(capabilities=("counts",)).start()
    try:
        assert "bigrams" not in c.build_info()["maps"] and "bglobal" not in c.build_info()["maps"]
        h = spawn_helper()
        h.do("openat", 5)
        h0 = c._health_all()
        assert (h0["bigram_map_full"], h0["bigram_dropped"], h0["pre_arm_events"]) == (0, 0, 0)
        with pytest.raises(RuntimeError):
            c.read_bigrams()
    finally:
        c.close()


# --- exact pairs, markers and invariants on an idle helper -------------------------

@pytest.mark.parametrize("n", [1, 1000])
def test_exact_pair_deltas_for_a_scripted_sequence(col, spawn_helper, n):
    h = spawn_helper()
    h.do("openat", 1)                                                # prev := openat
    p0, t0 = state(col, h.pid)
    for cmd, k in (("open", 2), ("openat", n), ("execve", 1), ("clone", 1)):
        h.do(cmd, k)
    p1, t1 = state(col, h.pid)
    want = {("openat", "open"): 1, ("open", "open"): 1, ("open", "openat"): 1,
            ("openat", "execve"): 1, ("execve", "clone"): 1}
    if n > 1:
        want[("openat", "openat")] = n - 1
    assert delta(t1, t0) == want
    assert {s: p1["counts"][s] - p0["counts"][s] for s in SYSCALLS if p1["counts"][s] != p0["counts"][s]} \
        == {"open": 2, "openat": n, "execve": 1, "clone": 1}
    assert p1["pairs_lost"] == p0["pairs_lost"] == 0
    assert_quiescent_invariants(p1, t1)


def test_markers_of_a_process_started_after_arming(col, spawn_helper):
    h = spawn_helper()
    h.do("openat", 2)
    p, t = state(col, h.pid)
    # The forked child's first observed call starts a START_NEW segment (at the
    # latest its execve); the helper image starts an EXEC segment.
    assert starts(t) == {"START_NEW": 1, "START_ATTACH": 0, "START_LOST": 0, "EXEC": 1}
    assert t[("EXEC", "openat")] == 1
    assert_quiescent_invariants(p, t)


def test_attach_and_pre_arm(helper_bin, spawn_helper):
    """A: idle before the program existed (START_ATTACH, nothing lost).
    B: active between attach and arming (counted, pairs lost, U2a)."""
    a = spawn_helper()
    c = bc.BpfCollector(capabilities=CAPS, arm=False).start()
    try:
        b = spawn_helper()
        b.do("openat", 2)
        pre = counts_of(c, b.pid)
        pb0, tb0 = state(c, b.pid)
        assert tb0 == {} and pb0["pairs_lost"] == sum(pre.values()) >= 3   # + its execve
        assert c.bigram_health()["pre_arm_events"] >= sum(pre.values())
        c.arm()
        a.do("openat", 1)
        b.do("openat", 1)
        pa, ta = state(c, a.pid)
        assert ta == {("START_ATTACH", "openat"): 1} and pa["pairs_lost"] == 0
        assert_quiescent_invariants(pa, ta)
        pb, tb = state(c, b.pid)
        assert tb == {("START_ATTACH", "openat"): 1}                 # pre-arm exec: no EXEC
        assert pb["pairs_lost"] == sum(pre.values())
        assert_quiescent_invariants(pb, tb, zero_loss=False)
        assert bg.check_ib1(pb, tb, "asserted").status == bg.NOT_APPLICABLE
    finally:
        c.close()


# --- R-LOSS paths, each forced on its own -------------------------------------------

def _dummy_count_key(t, i):
    k = t.Key()
    k.start_ns, k.tgid = i, 0
    return k


def _dummy_thread_key(t, i):
    return t.Key(0xF0000000 + i)


def _dummy_thread_leaf(t):
    leaf = t.Leaf()
    leaf.thread_start_ns = 1
    return leaf


def _dummy_pair_key(t, i):
    k = t.Key()
    k.proc.start_ns, k.proc.tgid, k.a, k.b = i, 0, 9, 0
    return k


def test_row_1_counts_map_full(small, spawn_helper):
    t = small.b["counts"]
    h0, full0 = small.bigram_health(), small._health_all()["counts_map_full"]
    g_before = small.global_losses()
    dummies = fill(t, _dummy_count_key, lambda t: t.Leaf())
    assert dummies
    try:
        h = spawn_helper()                                           # no counts entry possible
        h.do("openat", 2)
        assert counts_of(small, h.pid) is None
    finally:
        drain_keys(t, dummies)
    h1 = small.bigram_health()
    assert small._health_all()["counts_map_full"] - full0 >= 3      # execve + 2 openat at least
    assert h1["bigram_dropped"] - h0["bigram_dropped"] >= 3
    h.do("openat", 1)
    p, tb = state(small, h.pid)
    assert p["counts"]["openat"] == 1 and sum(p["counts"].values()) == 1
    assert tb == {("START_LOST", "openat"): 1}                       # row 1: next prev START_LOST
    assert p["pairs_lost"] == 0                                      # row 1 is not pairs_lost
    assert_quiescent_invariants(p, tb)
    # Exact I-B3/I-B4 must not claim anything here although pairs_lost is 0 (S2.3 audit 1).
    oracle = bg.expected_pairs(LAUNCH + [("call", "m", "openat")] * 3)
    losses = bg.loss_window(g_before, small.global_losses())
    assert losses["counts_map_full"] >= 3
    for check in (bg.check_ib3_exact, bg.check_ib4_exact):
        r = check(p, tb, oracle, "asserted", losses=losses)
        assert r.status == bg.NOT_APPLICABLE and "counts_map_full" in r.reason


def test_row_2_thread_map_full(small, spawn_helper):
    t = small.b["threads"]
    th0, bh0 = small.thread_health(), small.bigram_health()
    dummies = fill(t, _dummy_thread_key, _dummy_thread_leaf)
    assert dummies
    try:
        h = spawn_helper()                                           # no slot possible
        h.do("openat", 2)
        p, tb = state(small, h.pid)
        assert tb == {} and p["pairs_lost"] == sum(p["counts"].values()) >= 3
        assert small.thread_health()["thread_map_full"] - th0["thread_map_full"] >= 3
        assert small.bigram_health()["bigram_dropped"] - bh0["bigram_dropped"] >= 3
    finally:
        drain_keys(t, dummies)
    h.do("openat", 1)
    p, tb = state(small, h.pid)
    assert tb == {("START_LOST", "openat"): 1}                       # its first slot
    assert p["pairs_lost"] == sum(p["counts"].values()) - 1
    assert_quiescent_invariants(p, tb, zero_loss=False)


def test_row_3_bigram_map_full_keeps_prev(small, spawn_helper):
    t = small.b["bigrams"]
    bh0 = small.bigram_health()
    dummies = fill(t, _dummy_pair_key, lambda t: t.Leaf(1))
    assert dummies
    try:
        h = spawn_helper()
        h.do("openat", 2)
        p, tb = state(small, h.pid)
        assert tb == {} and p["pairs_lost"] == sum(p["counts"].values()) >= 3
        bh1 = small.bigram_health()
        assert bh1["bigram_map_full"] - bh0["bigram_map_full"] >= 3
        assert bh1["bigram_dropped"] - bh0["bigram_dropped"] >= 3
    finally:
        drain_keys(t, dummies)
    h.do("open", 1)
    p, tb = state(small, h.pid)
    assert tb == {("openat", "open"): 1}                             # prev advanced during row 3
    assert p["pairs_lost"] == sum(p["counts"].values()) - 1
    assert_quiescent_invariants(p, tb, zero_loss=False)


def test_exec_with_a_full_thread_map_loses_no_extra_pair(small, helper_bin, exec_target):
    """The execve entry loses its pair (row 2); the exec itself only fails to
    create a slot: thread_map_full rises, no pair is lost, and the thread's next
    slot starts at START_LOST (no EXEC marker without a slot)."""
    h = Helper([helper_bin, exec_target])
    t = small.b["threads"]
    try:
        h.do("openat", 1)
        (_tid, host, _start, _proc), = small.thread_slots(h.pid)
        p0, _t0 = state(small, h.pid)
        del t[t.Key(host)]                                       # so the exec must create a slot
        g0 = small._health_all()
        dummies = fill(t, _dummy_thread_key, _dummy_thread_leaf)
        assert dummies
        try:
            h.do("exec", 0)
            read_ready(h)
            g1 = small._health_all()
            p1, t1 = state(small, h.pid)
        finally:
            drain_keys(t, dummies)
        assert p1["counts"]["execve"] - p0["counts"]["execve"] == 1
        assert p1["pairs_lost"] - p0["pairs_lost"] == 1          # the execve entry only
        # Noise events that lose a pair raise both counters alike; the difference
        # counts slot failures that lose no pair, at least the helper's exec.
        slot_fail = g1["thread_map_full"] - g0["thread_map_full"]
        dropped = g1["bigram_dropped"] - g0["bigram_dropped"]
        assert slot_fail - dropped >= 1 and dropped >= 1
        h.do("openat", 1)
        p2, t2 = state(small, h.pid)
        assert delta(t2, t1) == {("START_LOST", "openat"): 1}
        assert p2["pairs_lost"] == p1["pairs_lost"]
        assert_quiescent_invariants(p2, t2, zero_loss=False)
    finally:
        h.exit()


def test_thread_map_full_before_arming_is_counted_once(spawn_helper):
    c = bc.BpfCollector(capabilities=CAPS, max_threads=256, arm=False).start()
    try:
        t = c.b["threads"]
        g0 = c._health_all()
        dummies = fill(t, _dummy_thread_key, _dummy_thread_leaf)
        assert dummies
        try:
            h = spawn_helper()
            h.do("openat", 2)
            p, tb = state(c, h.pid)
            g1 = c._health_all()
        finally:
            drain_keys(t, dummies)
        n = sum(p["counts"].values())
        assert n >= 3 and tb == {}
        assert p["pairs_lost"] == n                                  # once per entry, not twice
        d = {k: g1[k] - g0[k] for k in ("pre_arm_events", "bigram_dropped", "thread_map_full")}
        # Unarmed, every lost pair anywhere is a pre-arm event and is dropped once.
        assert d["bigram_dropped"] == d["pre_arm_events"] >= n
        assert d["thread_map_full"] >= n
    finally:
        c.close()


def test_v1_record_stays_valid_in_a_bigrams_build(col, spawn_helper):
    from processpulse.validate import Validator
    h = spawn_helper()
    h.do("openat", 3)
    snap = col.snapshot()
    assert snap["type"] == "syscall_snapshot" and snap["v"] == 1
    assert Validator().errors(snap) == []
    assert [p for p in snap["procs"] if p["key"]["tgid"] == h.pid]
    assert set(snap["health"]) == {"counts_map_full", "info_map_full", "unresolved_events",
                                   "self_excluded_events", "exit_events", "map_entries",
                                   "map_capacity", "reclaimed", "snapshot_ns"}


# --- thread lifecycle, exec, TID reuse -------------------------------------------------

def test_threads_start_new_segments_and_slots_are_cleaned(col, spawn_helper):
    h = spawn_helper()
    h.do("openat", 1)
    h.do("tspawn", 2)
    h.do("tjoin", 2)
    p, t = state(col, h.pid)
    assert starts(t)["START_NEW"] == 3                               # child pre-exec + 2 threads
    assert starts(t)["EXEC"] == 1 and t[("START_NEW", "openat")] >= 2
    assert {tid for tid, *_ in col.thread_slots(h.pid)} == {h.pid}
    assert_quiescent_invariants(p, t)


def test_leader_exec_starts_an_exec_segment(col, helper_bin, exec_target):
    h = Helper([helper_bin, exec_target])
    try:
        h.do("openat", 1)
        h.do("exec", 0)
        read_ready(h)
        h.do("openat", 1)
        p, t = state(col, h.pid)
        assert starts(t)["EXEC"] == 2 and t[("EXEC", "openat")] == 2
        assert t[("openat", "execve")] >= 1                          # the exec call itself
        assert_quiescent_invariants(p, t)
    finally:
        h.exit()


def test_non_leader_exec(col, helper_bin, exec_target):
    h = Helper([helper_bin, exec_target])
    try:
        h.do("openat", 1)
        stale0 = col.thread_health()["thread_slot_stale"]
        reply = h.do("texec", 0)
        old_tid = int(reply[4].split("=")[1])
        assert read_ready(h)[1] == f"pid={h.pid}"
        h.do("openat", 1)
        p, t = state(col, h.pid)
        assert starts(t)["START_NEW"] == 2                           # child pre-exec + exec thread
        assert starts(t)["EXEC"] == 2 and t[("EXEC", "openat")] == 2
        assert old_tid not in {tid for tid, *_ in col.thread_slots(h.pid)}
        assert col.thread_health()["thread_slot_stale"] == stale0
        assert_quiescent_invariants(p, t)
    finally:
        h.exit()


def test_reused_tid_is_a_new_thread(col, spawn_helper):
    h = spawn_helper()
    h.do("openat", 1)
    t = col.b["threads"]
    (tid, host, start, proc), = col.thread_slots(h.pid)
    leaf = t[t.Key(host)]
    leaf.thread_start_ns = start + 1                                 # an earlier owner's slot
    t[t.Key(host)] = leaf
    stale0 = col.thread_health()["thread_slot_stale"]
    _p0, t0 = state(col, h.pid)
    h.do("openat", 1)
    p, t1 = state(col, h.pid)
    assert col.thread_health()["thread_slot_stale"] - stale0 == 1
    assert delta(t1, t0) == {("START_NEW", "openat"): 1}             # classified as a new thread
    assert_quiescent_invariants(p, t1)


# --- reclaim and purge -----------------------------------------------------------------

def _entries_of(c, key):
    return [k for k in c.b["bigrams"].keys() if (k.proc.start_ns, k.proc.tgid) == key]


def test_exit_reclaims_the_pair_entries_with_the_process(col, spawn_helper):
    h = spawn_helper()
    h.do("openat", 3)
    key = key_of(col, h.pid)
    assert _entries_of(col, key)
    assert h.exit() == 0
    snap = col.snapshot()
    e = [x for x in snap["procs"] if x["key"]["tgid"] == key[1]]
    assert e and e[0]["exited"] is True
    assert col.last_bigrams["tables"][key]                           # still there when reported
    col.snapshot()                                                   # unchanged: reclaimed
    assert counts_of(col, key[1]) is None and _entries_of(col, key) == []
    assert key not in col.last_bigrams["tables"]


def test_self_exclusion_purges_pairs_into_the_purge_totals(col, spawn_helper):
    h = spawn_helper()
    h.do("openat", 3)
    p, t = state(col, h.pid)
    b0 = col.bigram_health()
    col.exclude(h.pid)
    try:
        b1 = col.bigram_health()
        assert b1["purged_counts"] - b0["purged_counts"] == sum(p["counts"].values())
        assert b1["purged_pairs"] - b0["purged_pairs"] == sum(t.values())
        assert b1["purged_pairs_lost"] - b0["purged_pairs_lost"] == p["pairs_lost"]
        assert counts_of(col, h.pid) is None
        assert not [k for k in col.b["bigrams"].keys() if k.proc.tgid == h.pid]
        h.do("openat", 1)
        assert not [k for k in col.b["bigrams"].keys() if k.proc.tgid == h.pid]
    finally:
        col.unexclude(h.pid)


def test_every_map_entry_decodes_and_markers_are_never_second(col):
    r = col.read_bigrams()
    assert r["method"] in ("batch", "items") and r["entries"] > 0
    for table in r["tables"].values():
        assert bg.check_ib5(table).status == bg.PASS
    raw_b = [k.b for k in col.b["bigrams"].keys()]
    assert raw_b and max(raw_b) < len(SYSCALLS)
