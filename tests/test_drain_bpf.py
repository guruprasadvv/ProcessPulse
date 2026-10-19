"""Privileged tests of the final drain (M1b S2.5, decision U3, hypothesis H-DRAIN).

drain() detaches every probe, waits for in-flight invocations (rcu_barrier)
and reads every map twice, requiring equal reads. These tests check
on the real kernel that:
- every probe is detached (no tracepoint, no perf_event fd left) and the
  maps stop changing although the traced processes keep running;
- a drain taken while helpers are busy in tight loops is stable and every
  key balances: I-B1' and I-B3' for every process of the distro, I-B1 for
  every key without pair loss, and I-B2 over the whole epoch;
- with scripted helpers (live, exited, reclaimed, purged) the drained values
  equal the script's ground truth, exactly;
- the double-read comparison sees real activity on attached probes (this
  shows the detector works; it is not a reproduction of a late writer);
- a counts-only drain behaves the same without bigram accounting.

Each drain ends its collector's epoch, so every test loads a fresh program.
Run as root:  make test-privileged
"""

import os

import pytest

from conftest import wait_until
from processpulse import bigrams as bg
from processpulse import bpf_collector as bc
from processpulse.identity import CgroupResolver
from processpulse.vocab import SYSCALLS

pytestmark = [pytest.mark.privileged, pytest.mark.bpf]

CAPS = ("counts", "bigrams")
LAUNCH = [("thread", "m", "new"), ("call", "m", "execve"), ("exec", "m")]
NO_LOSS = dict.fromkeys(bg.GLOBAL_LOSS_FIELDS, 0)


def fresh(caps=CAPS):
    return bc.BpfCollector(capabilities=caps, resolver=CgroupResolver(min_rescan_s=0)).start()


def perf_event_fds():
    n = 0
    for fd in os.listdir("/proc/self/fd"):
        try:
            if os.readlink(f"/proc/self/fd/{fd}") == "anon_inode:[perf_event]":
                n += 1
        except OSError:
            pass
    return n


def count_of(c, tgid, syscall):
    for k, v in c.b["counts"].items():
        if k.tgid == tgid:
            return v.c[SYSCALLS.index(syscall)]
    return None


def send(h, cmd, n):
    h.proc.stdin.write(f"{cmd} {n}\n")
    h.proc.stdin.flush()


def reply(h, cmd, n, timeout_note=""):
    r = h.proc.stdout.readline().split()
    assert r[:4] == ["DONE", cmd, str(n), "errors=0"], (r, timeout_note)


def wait_active(c, tgid, syscall, above):
    assert wait_until(lambda: (count_of(c, tgid, syscall) or 0) > above, timeout=30, step=0.001), \
        f"helper {tgid} never became active"


def of_pid(procs, pid):
    keys = [k for k in procs if k[1] == pid]
    assert len(keys) == 1, keys
    return procs[keys[0]]


def assert_every_key_balances(procs, record_property=None):
    """I-B5, I-B1', I-B3' for every key; I-B1 for every key without pair loss."""
    lossy = 0
    for key, (p, t) in procs.items():
        assert bg.check_ib5(t, key).status == bg.PASS
        for check in (bg.check_ib1_prime, bg.check_ib3_prime):
            r = check(p, t, "drained", key)
            assert r.status == bg.PASS, r
        r = bg.check_ib1(p, t, "drained", key)
        if p["pairs_lost"]:
            lossy += 1
            assert r.status == bg.NOT_APPLICABLE
        else:
            assert r.status == bg.PASS, r
    if record_property:
        record_property("keys", len(procs))
        record_property("keys_with_pairs_lost", lossy)
    return lossy


def test_drain_detaches_every_probe_and_freezes_the_maps(spawn_helper):
    c = fresh()
    try:
        h = spawn_helper()
        h.do("openat", 5)
        fds_before = perf_event_fds()
        assert len(c.attached_tracepoints()) == len(bc.required_tracepoints(CAPS))
        r = c.drain()
        assert r["status"] == "drained" and r["drained"] is True, r
        assert r["barrier"] is True and r["still_attached"] == [] and r["reads"] == 2
        assert sorted(r["detached"]) == sorted(bc.required_tracepoints(CAPS))
        assert c.attached_tracepoints() == [] and c.b.num_open_tracepoints() == 0
        assert perf_event_fds() == fds_before - len(bc.required_tracepoints(CAPS))
        p, t = of_pid(c.drained_processes(), h.pid)
        o = bg.expected_pairs(LAUNCH + [("call", "m", "openat")] * 5)
        assert p["counts"] == o.counts and t == o.pairs and p["pairs_lost"] == 0
        h.do("openat", 1000)                                  # no probe sees these
        h2 = spawn_helper()                                   # nor a new process
        h2.do("execve", 10)
        assert count_of(c, h.pid, "openat") == 5
        assert count_of(c, h2.pid, "execve") is None
        c.snapshot()                                          # raises if any map changed
        assert c.last_snapshot_drained is True
    finally:
        c.close()


@pytest.mark.parametrize("rep", range(3))
def test_a_drain_during_busy_loops_is_stable_and_every_key_balances(spawn_helper, record_property,
                                                                    rep):
    """Three helpers keep making tracked calls (openat, execve, and clone, whose
    children exit) while the probes are detached. The drain must be stable, and
    the values it reads must balance for every key of the distro (H-DRAIN): a
    probe cut off between its count and its pair would break I-B1'."""
    c = fresh()
    busy = [("openat", 3000000), ("execve", 3000000), ("clone", 40000)]
    helpers = []
    try:
        for cmd, n in busy:
            h = spawn_helper()
            send(h, cmd, n)
            helpers.append((h, cmd, n))
        for h, cmd, _n in helpers:
            wait_active(c, h.pid, cmd, 1000)
        r = c.drain()
        assert r["status"] == "drained", r
        procs = c.drained_processes()
        for h, cmd, n in helpers:                             # detached mid-loop
            p, _t = of_pid(procs, h.pid)
            at = p["counts"][cmd] - (1 if cmd == "execve" else 0)
            record_property(f"{cmd}_at_drain", at)
            assert 1000 < at < n, (cmd, at, n)
        record_property("reads", r["reads"])
        record_property("drain_ms", round(r["drain_ns"] / 1e6, 1))
        assert_every_key_balances(procs, record_property)
        ib2 = bg.check_ib2_drain_read(r)
        record_property("ib2_lhs", ib2.detail.get("lhs"))
        assert ib2.status == bg.PASS, ib2
        for h, cmd, n in helpers:                             # the loops end after the drain
            reply(h, cmd, n)
        rec = c.snapshot()                                    # raises if any map changed
        assert c.last_snapshot_drained is True
        for h, cmd, _n in helpers:
            (sp,) = [x for x in rec["procs"] if x["key"]["tgid"] == h.pid]
            assert sp["counts"] == of_pid(procs, h.pid)[0]["counts"]
        with pytest.raises(RuntimeError, match="last"):
            c.snapshot()
    finally:
        for h, _cmd, _n in helpers:
            h.exit(timeout=60)
        c.close()


def test_drained_values_equal_the_ground_truth_of_live_exited_reclaimed_and_purged(
        spawn_helper, record_property):
    c = fresh()
    try:
        g0 = c.global_losses()
        a, b, x, d = spawn_helper(), spawn_helper(), spawn_helper(), spawn_helper()
        a.do("openat", 10)
        b.do("open", 5)
        x.do("execve", 3)
        d.do("openat", 4)
        tally = (1 + 10) + (1 + 5) + (1 + 3) + (1 + 4)
        assert b.exit() == 0
        s1 = c.snapshot()                                     # b reported exited
        (pb,) = [p for p in s1["procs"] if p["key"]["tgid"] == b.pid and p["exited"]]
        (kb,) = [k for k in c.last_bigrams["tables"] if k[1] == b.pid]
        tb = c.last_bigrams["tables"][kb]
        pb = {"counts": pb["counts"], "pairs_lost": c.last_bigrams["pairs_lost"][kb]}
        reclaimed0 = c.reclaimed
        c.snapshot()                                          # b reclaimed
        assert c.reclaimed > reclaimed0
        assert count_of(c, b.pid, "open") is None
        assert x.exit() == 0
        c.snapshot()                                          # x reported exited, kept
        purged0 = dict(c.purged)
        c.exclude(d.pid)
        purged = {k: c.purged[k] - purged0[k] for k in purged0}
        c.unexclude(d.pid)
        assert purged == {"counts": 5, "pairs": 5, "pairs_lost": 0}

        r = c.drain()
        assert r["status"] == "drained", r
        losses = bg.loss_window(g0, c.global_losses())
        assert losses == NO_LOSS
        procs = c.drained_processes()
        pa, ta = of_pid(procs, a.pid)
        px, tx = of_pid(procs, x.pid)
        assert px["exited"] is True and pa["exited"] is False
        assert not [k for k in procs if k[1] in (b.pid, d.pid)]
        res = bg.check_ib2_ground_truth_scope([(pa, ta), (pb, tb), (px, tx)], tally, "drained",
                                              losses, purged)
        record_property("expected", tally)
        record_property("counts_side", res.detail.get("counts_side"))
        assert res.status == bg.PASS, res
        for p, t, cmd, n in ((pa, ta, "openat", 10), (pb, tb, "open", 5), (px, tx, "execve", 3)):
            o = bg.expected_pairs(LAUNCH + [("call", "m", cmd)] * n)
            assert p["counts"] == o.counts and t == o.pairs and p["pairs_lost"] == 0
            for check in (bg.check_ib3_exact, bg.check_ib4_exact):
                assert check(p, t, o, "drained", losses=losses).status == bg.PASS
        assert_every_key_balances(procs, record_property)
        assert bg.check_ib2_drain_read(r).status == bg.PASS

        with pytest.raises(RuntimeError, match="drain"):
            c.exclude(a.pid)
        reclaimed1 = c.reclaimed
        rec = c.snapshot()                                    # the drained snapshot reclaims x
        assert c.last_snapshot_drained is True
        assert c.reclaimed > reclaimed1
        assert not [p for p in rec["procs"] if p["key"]["tgid"] == x.pid]
    finally:
        c.close()


def test_the_double_read_sees_activity_on_attached_probes(spawn_helper):
    """Two consecutive reads of an attached program while a helper is busy differ,
    so an unequal pair is detected; this is the comparison drain() relies on."""
    c = fresh()
    h = spawn_helper()
    try:
        send(h, "openat", 3000000)
        wait_active(c, h.pid, "openat", 1000)
        first = c._read_state()
        second = c._read_state()
        assert first != second
        assert first["counts"] != second["counts"]
        reply(h, "openat", 3000000)
    finally:
        h.exit(timeout=60)
        c.close()


def test_counts_only_drain(spawn_helper):
    c = fresh(("counts",))
    try:
        h = spawn_helper()
        h.do("openat", 3)
        r = c.drain()
        assert r["status"] == "drained" and r["accounting"] is None
        assert bg.check_ib2_drain_read(r).status == bg.NOT_APPLICABLE
        p, t = of_pid(c.drained_processes(), h.pid)
        assert p["counts"] == dict(dict.fromkeys(SYSCALLS, 0), execve=1, openat=3)
        assert p["pairs_lost"] is None and t == {}
        h.do("openat", 100)
        rec = c.snapshot()                                    # raises if any map changed
        assert rec["type"] == "syscall_snapshot" and rec["v"] == 1
        assert c.last_snapshot_drained is True
    finally:
        c.close()
