"""Privileged: the v2 emitter on the real (unchanged) M1 BPF collector.

Run as root:  make test-privileged
"""

import pytest

from processpulse.snapshots import Reconstructor, V2Emitter
from processpulse.syscalls import SyscallCollector

pytestmark = [pytest.mark.privileged, pytest.mark.bpf]


@pytest.fixture(scope="module")
def sc():
    c = SyscallCollector(track_removals=True).start()
    yield c
    c.close()


def build(em, rc):
    recs, done = em.build()
    done()
    for r in recs:
        rc.feed(r)
    return recs


def by_tgid(recs, tgid):
    return [r for r in recs if r["type"] == "bpf_proc" and r["key"]["tgid"] == tgid]


def removed(recs, reason):
    return [k["tgid"] for r in recs if r["type"] == "bpf_reclaimed" and r["reason"] == reason
            for k in r["keys"]]


def test_exit_is_emitted_once_then_reclaimed(sc, spawn_helper):
    em, rc = V2Emitter(sc, run_id="t-exit"), Reconstructor()
    h = spawn_helper()
    h.do("openat", 5)
    first = build(em, rc)
    assert by_tgid(first, h.pid)[0]["counts"]["openat"] == 5
    assert by_tgid(build(em, rc), h.pid) == []                 # unchanged: omitted
    assert h.exit() == 0
    ex = by_tgid(build(em, rc), h.pid)
    assert len(ex) == 1 and ex[0]["exited"] is True and ex[0]["counts"]["openat"] == 5
    gone = build(em, rc)
    assert h.pid in removed(gone, "exited")                    # other processes may exit too
    assert rc.valid and not any(k[2] == h.pid for k in rc.state)
    assert rc.stats["invalidations"] == 0 and rc.stats["snapshots_incomplete"] == 0


def test_self_exclusion_purge_is_reported(sc, spawn_helper):
    em, rc = V2Emitter(sc, run_id="t-purge"), Reconstructor()
    h = spawn_helper()
    h.do("openat", 3)
    assert by_tgid(build(em, rc), h.pid)
    sc.exclude(h.pid)
    try:
        recs = build(em, rc)
        assert h.pid in removed(recs, "self_excluded") and by_tgid(recs, h.pid) == []
        assert rc.valid and not any(k[2] == h.pid for k in rc.state)
    finally:
        sc.unexclude(h.pid)


def test_v1_snapshot_records_are_unchanged_by_the_removal_bookkeeping(sc, spawn_helper):
    from processpulse.validate import Validator
    h = spawn_helper()
    h.do("openat", 1)
    snap = sc.snapshot()
    assert set(snap) == {"type", "v", "seq", "t_mono_ns", "interval_ns", "resource_seq", "probe",
                         "calibration", "procs", "health"}
    assert Validator().errors(snap) == []


def test_without_tracking_removals_do_not_accumulate(spawn_helper):
    c = SyscallCollector().start()
    try:
        h = spawn_helper()
        h.do("openat", 1)
        c.snapshot()
        h.exit()
        c.snapshot()
        c.snapshot()                           # the exited helper is reclaimed here
        assert c.reclaimed >= 1
        assert c.take_removed() == {"exited": [], "self_excluded": []}
    finally:
        c.close()
