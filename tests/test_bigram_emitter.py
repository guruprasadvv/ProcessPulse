"""The S2.6 bigram producer: V2Emitter with the bigrams capability.

Deterministic, unprivileged: the collector is tests.snapshot_fakes.
BigramCollectorFake, which has the BpfCollector interface (last_bigrams keyed
(start_ns, tgid), bigram_health(), drain(), last_snapshot_drained). Every
stream is checked record by record (Validator) and as a whole
(Reconstructor), and its reconstructed tables are compared with the fake's
truth.
"""

import pytest

from processpulse import bigrams as bg
from processpulse.jsonl import line_violations
from processpulse.snapshots import (BIGRAM_HEALTH_FIELDS, KEYFRAME_INTERVAL, Reconstructor,
                                    V2Emitter, key_tuple)
from processpulse.validate import Validator
from snapshot_fakes import (BigramCollectorFake, FakeCollector, bigram_state_truth, pair_truth,
                            truth)

V = Validator()


def step(em, commit=True, resource_seq=None):
    recs, done = em.build(resource_seq=resource_seq)
    for r in recs:
        assert V.errors(r) == [], (r["type"], V.errors(r))
        from processpulse.jsonl import encode_record
        assert line_violations(encode_record(r).encode()) == []
    if commit:
        done()
    return recs


def of(recs, t):
    return [r for r in recs if r["type"] == t]


def kinds(recs):
    return [r["type"] for r in recs]


def feed(rc, recs):
    for r in recs:
        rc.feed(r)


def fake3():
    f = BigramCollectorFake()
    for tgid in (10, 20, 30):
        f.add(tgid)
        f.step_pair(tgid, "START_NEW", "execve")
    f.step_pair(10, "execve", "openat")
    f.step_pair(10, "openat", "openat", 2)
    return f


def assert_consumer_matches(rc, f):
    assert rc.valid, rc.errors
    assert rc.state == bigram_state_truth(f)
    assert rc.pairs == pair_truth(f)


# --- selection and shape ------------------------------------------------------------

def test_counts_only_emitter_keeps_the_s0_shape():
    f = FakeCollector()
    f.add(10, openat=1)
    recs = step(V2Emitter(f, run_id="r"))
    assert "bigrams" not in recs[0]["capabilities"]
    assert all("pairs_lost" not in r for r in of(recs, "bpf_proc"))
    assert not of(recs, "bpf_bigrams")
    end = recs[-1]
    assert not any(k in end for k in ("bigram_records", "bigram_health", "drained"))
    assert "bigrams" not in end["totals"]


def test_a_bigram_collector_without_selection_keeps_the_s0_shape():
    recs = step(V2Emitter(fake3(), run_id="r"))
    assert "bigrams" not in recs[0]["capabilities"] and not of(recs, "bpf_bigrams")


def test_selection_is_checked():
    with pytest.raises(ValueError, match="bigrams"):
        V2Emitter(FakeCollector(), run_id="r", bigrams="ok")          # no capability
    with pytest.raises(ValueError):
        V2Emitter(fake3(), run_id="r", bigrams="maybe")
    with pytest.raises(ValueError, match="reason"):
        V2Emitter(fake3(), run_id="r", bigrams="unavailable")


def test_first_snapshot_is_a_keyframe_with_every_table_in_order():
    f = fake3()
    recs = step(V2Emitter(f, run_id="r", bigrams="ok"))
    assert recs[0]["keyframe"] is True
    cap = recs[0]["capabilities"]["bigrams"]
    assert cap == {"status": "ok", "epoch": recs[0]["capabilities"]["counts"]["epoch"],
                   "err": None, "reason": None}
    assert kinds(recs) == (["bpf_snapshot_begin"] + ["bpf_proc"] * 3 + ["bpf_bigrams"] * 3
                           + ["bpf_snapshot_end"])
    assert [r["key"]["tgid"] for r in of(recs, "bpf_bigrams")] == [10, 20, 30]
    assert all((r["part"], r["parts"]) == (0, 1) for r in of(recs, "bpf_bigrams"))
    end = recs[-1]
    assert end["bigram_records"] == 3 and end["drained"] is False
    assert tuple(end["bigram_health"]) == BIGRAM_HEALTH_FIELDS
    assert end["totals"]["bigrams"] == {"pairs": 6, "pairs_lost": 0}
    rc = Reconstructor()
    feed(rc, recs)
    assert_consumer_matches(rc, f)


def test_an_empty_table_is_one_empty_part_and_distinct_from_unavailable():
    f = BigramCollectorFake()
    f.add(10, openat=2)
    f.lost[10] = 2                                                   # every pair lost
    recs = step(V2Emitter(f, run_id="r", bigrams="ok"))
    (part,) = of(recs, "bpf_bigrams")
    assert part["pairs"] == [] and (part["part"], part["parts"]) == (0, 1)
    assert of(recs, "bpf_proc")[0]["pairs_lost"] == 2
    rc = Reconstructor()
    feed(rc, recs)
    assert rc.valid and rc.pairs == {key_tuple(part["key"]): {}}

    u = step(V2Emitter(f, run_id="r", bigrams="unavailable",
                       bigrams_reason="bigram program failed to load"))
    cap = u[0]["capabilities"]["bigrams"]
    assert cap == {"status": "unavailable", "epoch": None, "err": "UNSUPPORTED",
                   "reason": "bigram program failed to load"}
    assert not of(u, "bpf_bigrams")
    p = of(u, "bpf_proc")[0]
    assert p["pairs_lost"] is None and p["bigrams_err"] == "UNSUPPORTED"     # never 0
    end = u[-1]
    assert end["totals"]["bigrams"] is None and end["bigram_health"] is None
    assert end["bigram_records"] == 0 and end["drained"] is False
    rc = Reconstructor()
    feed(rc, u)
    assert rc.valid and rc.pairs == {}


# --- change detection (S2.3 audit, finding 4) ------------------------------------------

def _second(change):
    f = fake3()
    em = V2Emitter(f, run_id="r", bigrams="ok")
    rc = Reconstructor()
    feed(rc, step(em))
    change(f)
    recs = step(em)
    feed(rc, recs)
    assert_consumer_matches(rc, f)
    return recs, rc


def test_unchanged_processes_are_omitted_and_known_unchanged():
    recs, rc = _second(lambda f: None)
    assert not of(recs, "bpf_proc") and not of(recs, "bpf_bigrams")
    assert len(rc.last.unchanged) == 3


def test_a_count_change_reemits_the_process_and_its_table():
    recs, _ = _second(lambda f: f.step_pair(20, "execve", "clone"))
    assert [r["key"]["tgid"] for r in of(recs, "bpf_proc")] == [20]
    assert [r["key"]["tgid"] for r in of(recs, "bpf_bigrams")] == [20]


def test_a_pair_table_change_alone_reemits_the_process():
    """A late pair: the count was read in an earlier snapshot, the pair now."""
    def late_pair(f):
        f.pairs[30][("execve", "open")] = 1                         # counts unchanged
    recs, _ = _second(late_pair)
    assert [r["key"]["tgid"] for r in of(recs, "bpf_proc")] == [30]
    (part,) = of(recs, "bpf_bigrams")
    assert {"a": "execve", "b": "open", "n": 1} in part["pairs"]


def test_a_pairs_lost_change_alone_reemits_the_process():
    def lost(f):
        f.lost[20] += 1                                              # counts unchanged
    recs, _ = _second(lost)
    (p,) = of(recs, "bpf_proc")
    assert p["key"]["tgid"] == 20 and p["pairs_lost"] == 1


# --- removals, keyframes and failures --------------------------------------------------

def test_reclaim_and_purge_drop_tables_and_totals_follow():
    f = fake3()
    em = V2Emitter(f, run_id="r", bigrams="ok")
    rc = Reconstructor()
    feed(rc, step(em))
    f.exit(20)
    feed(rc, step(em))
    f.reclaim(20)
    f.purge(30)
    recs = step(em)
    feed(rc, recs)
    assert {r["reason"] for r in of(recs, "bpf_reclaimed")} == {"exited", "self_excluded"}
    assert_consumer_matches(rc, f)
    assert recs[-1]["totals"]["bigrams"] == {"pairs": 4, "pairs_lost": 0}
    assert recs[-1]["bigram_health"]["purged_counts"] == 1


def test_a_failed_scheduled_keyframe_is_recovered_with_every_table():
    f = fake3()
    em = V2Emitter(f, run_id="r", bigrams="ok")
    rc = Reconstructor()
    for _ in range(KEYFRAME_INTERVAL):
        feed(rc, step(em))
    f.fail = True
    failed = step(em)                                                # seq 60: scheduled, fails
    end = failed[-1]
    assert kinds(failed) == ["bpf_snapshot_begin", "bpf_snapshot_end"]
    assert failed[0]["keyframe"] is False and end["status"] == "failed"
    assert end["bigram_records"] == 0 and end["bigram_health"] is None
    assert end["drained"] is False
    assert end["totals"]["bigrams"] == {"pairs": 6, "pairs_lost": 0}  # committed state
    feed(rc, failed)
    assert rc.valid
    f.fail = False
    f.step_pair(10, "openat", "openat")
    recovery = step(em)
    assert recovery[0]["keyframe"] is True                           # due was not cleared
    assert len(of(recovery, "bpf_proc")) == len(of(recovery, "bpf_bigrams")) == 3
    feed(rc, recovery)
    assert_consumer_matches(rc, f)
    assert rc.stats["keyframe_schedule_violations"] == 0


def test_an_uncommitted_snapshot_forces_a_keyframe_with_tables():
    f = fake3()
    em = V2Emitter(f, run_id="r", bigrams="ok")
    step(em)
    step(em, commit=False)                                           # maybe torn on disk
    recs = step(em)
    assert recs[0]["keyframe"] is True and len(of(recs, "bpf_bigrams")) == 3


def test_a_health_read_failure_fails_the_snapshot_and_keeps_removals():
    f = fake3()
    em = V2Emitter(f, run_id="r", bigrams="ok")
    rc = Reconstructor()
    feed(rc, step(em))
    f.exit(20)
    feed(rc, step(em))
    f.reclaim(20)
    f.fail_health = True
    recs = step(em)
    assert recs[-1]["status"] == "failed" and "health" in recs[-1]["reason"]
    feed(rc, recs)
    f.fail_health = False
    recs = step(em)
    assert [r["reason"] for r in of(recs, "bpf_reclaimed")] == ["exited"]   # not vanished
    feed(rc, recs)
    assert_consumer_matches(rc, f)
    assert recs[-1]["loss"]["vanished_entries"] == 0


def test_multi_part_tables_through_the_emitter():
    f = BigramCollectorFake()
    f.add(10)
    names = ["execve", "execveat", "open", "openat", "openat2", "clone", "clone3", "fork",
             "vfork"]
    for a in names + ["START_NEW", "START_ATTACH", "START_LOST", "EXEC"]:
        for b in names:
            f.step_pair(10, a, b)                                    # all 117 pairs
    em = V2Emitter(f, run_id="r", bigrams="ok", max_pairs_per_record=50, limit=4000)
    recs = step(em)
    parts = of(recs, "bpf_bigrams")
    assert [(p["part"], p["parts"]) for p in parts] == [(i, len(parts)) for i in range(len(parts))]
    assert len(parts) >= 3 and all(len(p["pairs"]) <= 50 for p in parts)
    from processpulse.jsonl import encode_record
    assert all(len(encode_record(p, 4000).encode()) <= 4000 for p in parts)
    rc = Reconstructor()
    feed(rc, recs)
    assert_consumer_matches(rc, f)


# --- drained snapshot --------------------------------------------------------------------

def test_drained_is_true_only_on_the_snapshot_the_collector_marked():
    f = fake3()
    em = V2Emitter(f, run_id="r", bigrams="ok")
    rc = Reconstructor()
    for _ in range(3):
        recs = step(em)
        assert recs[-1]["drained"] is False
        feed(rc, recs)
    assert f.drain()["drained"]
    final = step(em)
    assert final[-1]["drained"] is True and final[-1]["status"] == "ok"
    feed(rc, final)
    assert rc.last.drained and rc.valid
    after = step(em)                                                 # the collector refuses
    assert after[-1]["status"] == "failed" and after[-1]["drained"] is False


def test_a_drained_snapshot_that_fails_its_cross_check_is_not_drained():
    f = fake3()
    em = V2Emitter(f, run_id="r", bigrams="ok")
    step(em)
    f.change_after_drain = True
    f.drain()
    recs = step(em)
    assert recs[-1]["status"] == "failed" and recs[-1]["drained"] is False
    assert "changed after the drain" in recs[-1]["reason"]


def test_an_unsuccessful_drain_never_marks_a_snapshot():
    for outcome in ("unstable", "failed"):
        f = fake3()
        em = V2Emitter(f, run_id="r", bigrams="ok")
        step(em)
        f.drain_outcome = outcome
        assert f.drain()["drained"] is False
        assert step(em)[-1]["drained"] is False


# --- stream-level invariants ------------------------------------------------------------------

def _balanced_epoch():
    """A loss-aware scripted epoch where every key balances (I-B1')."""
    f = BigramCollectorFake()
    for tgid in (10, 20, 30, 40):
        f.add(tgid)
        f.step_pair(tgid, "START_NEW", "execve")
    f.step_pair(10, "execve", "openat")
    f.step_pair(10, "openat", "openat", 4)
    f.lose_pair(10, "openat", 2)                                     # pairs_lost 2
    f.step_pair(20, "execve", "clone")
    f.step_pair(20, "clone", "clone", 2)
    f.step_pair(30, "execve", "open")
    f.step_pair(40, "execve", "openat")
    f.step_pair(40, "openat", "openat", 3)
    f.bhealth["bigram_dropped"] = 2
    em = V2Emitter(f, run_id="r", bigrams="ok")
    rc = Reconstructor()
    feed(rc, step(em))
    f.exit(20)
    feed(rc, step(em))
    f.reclaim(20)                                                    # reclaimed as exited
    f.purge(30)                                                      # purged
    feed(rc, step(em))
    f.step_pair(40, "openat", "openat", 7)
    feed(rc, step(em))
    f.drain()
    feed(rc, step(em))
    rc.finish()
    return f, rc


def test_ib2_and_the_quiescent_checks_pass_on_an_emitted_drained_stream():
    f, rc = _balanced_epoch()
    assert rc.valid and rc.epoch_intact and rc.last.drained
    r = bg.check_ib2_drained(rc)
    assert r.status == bg.PASS, r
    assert r.detail["keys_reclaimed_exited"] == 1 and r.detail["purged_counts"] == 2
    results = bg.check_quiescent_reports(rc)
    by = {}
    for x in results:
        by.setdefault(x.invariant, []).append(x.status)
    assert set(by["I-B5"]) == set(by["I-B1'"]) == set(by["I-B3'"]) == {bg.PASS}
    assert by["I-B1"].count(bg.NOT_APPLICABLE) == 1                  # tgid 10 lost pairs
    n = sum(sum(p["counts"].values()) for p in f.procs.values())
    assert bg.check_ib2_ground_truth(rc, n + 4 + 2).status == bg.PASS   # + reclaimed + purged


def test_ib2_on_the_emitted_stream_detects_a_missing_purge_term():
    f, rc = _balanced_epoch()
    rc.last_ok_end["bigram_health"]["purged_pairs_lost"] += 1
    assert bg.check_ib2_drained(rc).status == bg.FAIL


def test_ib2_is_not_applicable_without_a_drained_snapshot():
    f = fake3()
    em = V2Emitter(f, run_id="r", bigrams="ok")
    rc = Reconstructor()
    feed(rc, step(em))
    assert bg.check_ib2_drained(rc).status == bg.NOT_APPLICABLE
