"""Schema-v2 BPF snapshot protocol: producer (V2Emitter) and consumer (Reconstructor).

Contract: docs/telemetry-v2.md §3-§4 (M1b plan v3, decisions D1-D6, S0).
All tests use tests/snapshot_fakes.FakeCollector, so no root or BPF is needed.
"""

import copy
import json

import pytest

from processpulse.jsonl import MAX_RECORD_BYTES, encode_record, line_violations
from processpulse.snapshots import (KEYFRAME_INTERVAL, Reconstructor, V2Emitter, key_tuple,
                                    totals)
from processpulse.validate import Validator
from snapshot_fakes import FakeCollector, key, truth

U64 = 1 << 64


def step(em, fake=None, commit=True, resource_seq=None):
    recs, done = em.build(resource_seq=resource_seq)
    if commit:
        done()
    return recs


def kinds(recs):
    return [r["type"] for r in recs]


def procs_of(recs):
    return [r for r in recs if r["type"] == "bpf_proc"]


def removed_of(recs, reason=None):
    return [k for r in recs if r["type"] == "bpf_reclaimed" and reason in (None, r["reason"])
            for k in r["keys"]]


def end_of(recs):
    assert recs[-1]["type"] == "bpf_snapshot_end"
    return recs[-1]


def feed_all(rc, recs):
    for r in recs:
        rc.feed(r)


@pytest.fixture
def fake():
    f = FakeCollector()
    f.add(10, openat=1)
    f.add(20, openat=2)
    return f


@pytest.fixture
def em(fake):
    return V2Emitter(fake, run_id="run-a")


# --- producer -------------------------------------------------------------

def test_keyframe_interval_is_60():
    assert KEYFRAME_INTERVAL == 60


def test_emitter_refuses_a_collector_without_removal_tracking():
    from processpulse.syscalls import SyscallCollector
    plain = SyscallCollector()                 # not started: no BPF needed for this check
    assert plain.track_removals is False
    with pytest.raises(ValueError):
        V2Emitter(plain, run_id="x")


def test_keyframe_schedule_first_and_every_60(em):
    flags = [step(em)[0]["keyframe"] for _ in range(125)]
    assert [i for i, k in enumerate(flags) if k] == [0, 60, 120]


def test_keyframe_emits_every_tracked_process_others_only_changes(fake, em):
    first = step(em)
    assert len(procs_of(first)) == 2 and end_of(first)["tracked"] == 2
    assert procs_of(step(em)) == []                      # nothing changed
    fake.bump(10)
    changed = procs_of(step(em))
    assert [p["key"]["tgid"] for p in changed] == [10]
    assert changed[0]["counts"]["openat"] == 2           # cumulative, never a delta
    for _ in range(KEYFRAME_INTERVAL - 3):
        step(em)
    kf = step(em)
    assert kf[0]["keyframe"] and kf[0]["seq"] == 60 and len(procs_of(kf)) == 2


def test_record_order_and_counts(fake, em):
    step(em)
    fake.bump(10)
    fake.exit(20)
    recs = step(em)
    assert kinds(recs) == ["bpf_snapshot_begin", "bpf_proc", "bpf_proc", "bpf_snapshot_end"]
    fake.reclaim(20)
    fake.add(30, execve=1)
    recs = step(em)
    assert kinds(recs) == ["bpf_snapshot_begin", "bpf_proc", "bpf_reclaimed", "bpf_snapshot_end"]
    end = end_of(recs)
    assert (end["procs_emitted"], end["reclaimed_records"], end["reclaimed_keys"],
            end["tracked"]) == (1, 1, 1, 2)
    assert all(r["seq"] == recs[0]["seq"] for r in recs)


def test_first_exit_is_emitted_then_reclaim_listed(fake, em):
    step(em)
    fake.exit(20)
    p = procs_of(step(em))
    assert [(x["key"]["tgid"], x["exited"]) for x in p] == [(20, True)]
    assert procs_of(step(em)) == []                      # exited and unchanged: not repeated
    fake.reclaim(20)
    recs = step(em)
    assert removed_of(recs, "exited") == [key(20)] and end_of(recs)["tracked"] == 1


def test_new_process_is_emitted(fake, em):
    step(em)
    fake.add(30, clone=4)
    assert [p["key"]["tgid"] for p in procs_of(step(em))] == [30]


def test_removal_of_a_never_emitted_key_is_not_listed(fake, em):
    step(em)
    fake.add(40, openat=1)
    fake.purge(40)                                       # purged before any snapshot saw it
    recs = step(em)
    assert removed_of(recs) == [] and end_of(recs)["tracked"] == 2


def test_self_exclusion_purge_wins_over_a_value_read_before_it(fake, em):
    step(em)
    fake.bump(10)
    fake.removed["self_excluded"].append(key(10))        # purge raced with the map read
    recs = step(em)
    assert procs_of(recs) == [] and removed_of(recs, "self_excluded") == [key(10)]
    assert end_of(recs)["tracked"] == 1


def test_unexplained_disappearance_is_reported_as_vanished_loss(fake, em):
    step(em)
    del fake.procs[20]                                   # gone without reclaim or purge
    recs = step(em)
    assert removed_of(recs, "vanished") == [key(20)]
    assert end_of(recs)["loss"]["vanished_entries"] == 1
    assert end_of(step(em))["loss"]["vanished_entries"] == 1   # cumulative, not re-counted


def test_tracked_and_totals_cover_the_emitted_state_mod_2_64(fake, em):
    fake.procs[10]["counts"]["openat"] = U64 - 1
    fake.procs[20]["counts"]["openat"] = 5
    end = end_of(step(em))
    assert end["tracked"] == 2
    assert end["totals"]["counts"]["openat"] == (U64 - 1 + 5) % U64 == 4
    assert end["totals"]["counts"]["execve"] == 0


def test_failed_read_emits_begin_and_end_only_and_keeps_state(fake, em):
    step(em)
    fake.bump(10)
    fake.fail = True
    recs = step(em)
    assert kinds(recs) == ["bpf_snapshot_begin", "bpf_snapshot_end"]
    assert recs[0]["keyframe"] is False
    end = end_of(recs)
    assert end["status"] == "failed" and "injected map read failure" in end["reason"]
    assert end["loss"] is None and end["health"] is None and end["read_err"] == "EIO"
    assert end["tracked"] == 2 and end["totals"]["counts"]["openat"] == 3
    fake.fail = False
    p = procs_of(step(em))                               # the change is emitted after the failure
    assert [(x["key"]["tgid"], x["counts"]["openat"]) for x in p] == [(10, 2)]


def keyframe_seqs(em, fake, n, fail_at=()):
    """Runs n snapshots, failing the reads at the given seqs; returns keyframe seqs."""
    out = []
    for i in range(n):
        fake.fail = i in fail_at
        recs = step(em)
        if recs[0]["keyframe"]:
            assert end_of(recs)["status"] == "ok"
            out.append(recs[0]["seq"])
    fake.fail = False
    return out


def test_failed_scheduled_keyframe_is_recovered_by_the_next_ok_snapshot(fake, em):
    assert keyframe_seqs(em, fake, 125, fail_at={60}) == [0, 61, 120]   # cadence kept


def test_failed_first_snapshots_delay_the_epoch_keyframe_to_the_first_ok_one(fake, em):
    assert keyframe_seqs(em, fake, 65, fail_at={0, 1, 2}) == [3, 60]


def test_failed_unscheduled_snapshot_adds_no_keyframe(fake, em):
    assert keyframe_seqs(em, fake, 65, fail_at={30}) == [0, 60]


def test_failed_snapshot_is_never_a_keyframe(fake, em):
    fake.fail = True
    for _ in range(3):
        recs = step(em)
        assert recs[0]["keyframe"] is False and end_of(recs)["status"] == "failed"


def test_uncommitted_snapshot_does_not_advance_state_and_forces_a_keyframe(fake, em):
    step(em)
    fake.bump(10)
    lost = step(em, commit=False)                        # e.g. the write failed
    assert lost[0]["keyframe"] is False
    assert [p["key"]["tgid"] for p in procs_of(lost)] == [10]
    again = step(em)                                     # a consumer may hold a torn seq 1
    assert again[0]["seq"] == 2 and again[0]["keyframe"] is True
    assert {(p["key"]["tgid"], p["counts"]["openat"]) for p in procs_of(again)} == {(10, 2), (20, 2)}
    assert step(em)[0]["keyframe"] is False              # recovered; back to the cadence


def test_emitter_is_bound_to_one_epoch(fake, em):
    step(em)
    fake.attached_since += 1                             # collector re-attached
    with pytest.raises(RuntimeError):
        step(em)


def test_many_removed_keys_are_split_within_the_line_limit(em, fake):
    for t in range(1000, 4000):
        fake.add(t)
    step(em)
    for t in range(1000, 4000):
        fake.reclaim(t)
    recs = step(em)
    chunks = [r for r in recs if r["type"] == "bpf_reclaimed"]
    assert len(chunks) > 1
    assert removed_of(recs) == [key(t) for t in range(1000, 4000)]
    assert all(len(encode_record(r).encode()) <= MAX_RECORD_BYTES for r in recs)
    assert end_of(recs)["reclaimed_records"] == len(chunks)


def test_large_population_v1_too_big_v2_within_limit(em, fake):
    for t in range(1000, 3000):
        fake.add(t, openat=t)
    v1_like = json.dumps({"procs": [p for p in fake.procs.values()]}, separators=(",", ":"))
    assert len(v1_like.encode()) > MAX_RECORD_BYTES      # one v1 line would be oversize
    recs = step(em)
    assert all(line_violations(encode_record(r).encode()) == [] for r in recs)
    rc = Reconstructor()
    feed_all(rc, recs)
    assert rc.valid and rc.state == truth(fake)          # lossless


def test_every_emitted_record_is_schema_valid(fake, em):
    v = Validator()
    script = [lambda: None, lambda: fake.bump(10), lambda: fake.exit(20),
              lambda: fake.reclaim(20), lambda: setattr(fake, "fail", True),
              lambda: setattr(fake, "fail", False)]
    for act in script:
        act()
        for r in step(em):
            assert v.errors(r) == [], (r["type"], v.errors(r))


# --- consumer: normal operation -------------------------------------------

def run_scenario(n=130, seed=7):
    """Random but reproducible churn; yields (records, truth-after) per snapshot."""
    import random
    rnd = random.Random(seed)
    fake = FakeCollector()
    em = V2Emitter(fake, run_id="run-r")
    nxt = 100
    out = []
    for i in range(n):
        for t in list(fake.procs):
            p = fake.procs[t]
            if p["exited"] and rnd.random() < 0.7:
                fake.reclaim(t)
            elif not p["exited"] and rnd.random() < 0.1:
                fake.exit(t)
            elif not p["exited"] and rnd.random() < 0.5:
                fake.bump(t, rnd.choice(("openat", "execve", "clone")), rnd.randint(1, 5))
        for _ in range(rnd.randint(0, 3)):
            fake.add(nxt, openat=1)
            nxt += 1
        out.append((step(em), copy.deepcopy(truth(fake))))
    return out


def test_reconstruction_matches_truth_and_unchanged_is_exact():
    rc = Reconstructor()
    prev = {}
    for recs, want in run_scenario():
        feed_all(rc, recs)
        view = rc.last
        assert view.status == "ok" and rc.valid
        assert rc.state == want
        emitted = {key_tuple(p["key"]) for p in procs_of(recs)}
        assert view.emitted == emitted
        assert view.unchanged == set(want) - emitted
        for k in view.unchanged:                         # omitted => truly unchanged
            assert prev[k] == want[k]
        prev = want
    assert rc.stats["invalidations"] == 0 and rc.stats["snapshots_incomplete"] == 0


def test_consumer_starting_mid_stream_waits_for_a_keyframe():
    scen = run_scenario(n=130)
    rc = Reconstructor()
    for i, (recs, want) in enumerate(scen[25:], start=25):
        feed_all(rc, recs)
        if i < 60:
            assert not rc.valid and rc.last.unchanged == set()
        else:
            assert rc.valid and rc.state == want


# --- consumer: adversarial input ------------------------------------------

def stream(n=5):
    fake = FakeCollector()
    fake.add(10, openat=1)
    fake.add(20, openat=1)
    em = V2Emitter(fake, run_id="run-x")
    snaps = []
    for i in range(n):
        fake.bump(10)
        snaps.append(step(em))
    return fake, em, snaps


def consume(snaps):
    rc = Reconstructor()
    for s in snaps:
        feed_all(rc, s)
    rc.finish()
    return rc


def test_clean_stream_baseline():
    _f, _e, snaps = stream()
    rc = consume(snaps)
    assert rc.valid and rc.stats["snapshots_complete"] == 5


def test_missing_end_is_incomplete_and_invalidates():
    _f, _e, snaps = stream()
    snaps[2] = snaps[2][:-1]
    rc = Reconstructor()
    for s in snaps[:3]:
        feed_all(rc, s)
    rc.finish()
    assert rc.stats["snapshots_incomplete"] == 1 and not rc.valid


def test_truncated_final_snapshot_is_rejected_at_end_of_stream():
    _f, _e, snaps = stream()
    snaps[-1] = snaps[-1][:2]                            # crash after begin + one proc
    rc = consume(snaps)
    assert rc.stats["snapshots_incomplete"] == 1 and not rc.valid
    assert rc.last.seq == 3                              # nothing from seq 4 was applied


def test_duplicated_begin_is_incomplete():
    _f, _e, snaps = stream()
    snaps[1] = [snaps[1][0]] + snaps[1]
    rc = consume(snaps)
    assert rc.stats["snapshots_incomplete"] >= 1 and not rc.valid


def test_record_outside_a_snapshot_is_a_framing_error():
    _f, _e, snaps = stream()
    stray = procs_of(snaps[1])[0]
    snaps[2] = [stray] + snaps[2]
    rc = consume(snaps)
    assert rc.stats["framing_errors"] == 1 and not rc.valid


def test_reclaimed_before_proc_is_out_of_order():
    fake, em, snaps = stream(2)
    fake.bump(20)
    fake.exit(10)
    s2 = step(em)
    fake.reclaim(10)
    fake.bump(20)
    recs = step(em)
    assert kinds(recs)[1:3] == ["bpf_proc", "bpf_reclaimed"]
    recs[1], recs[2] = recs[2], recs[1]
    rc = consume(snaps + [s2, recs])
    assert rc.stats["seq_gaps"] == 0
    assert rc.stats["snapshots_incomplete"] == 1 and not rc.valid


def test_duplicate_proc_record_is_rejected():
    _f, _e, snaps = stream()
    p = procs_of(snaps[3])[0]
    snaps[3].insert(1, copy.deepcopy(p))
    end_of(snaps[3])["procs_emitted"] += 1
    rc = consume(snaps)
    assert rc.stats["snapshots_incomplete"] == 1 and not rc.valid


@pytest.mark.parametrize("field,delta", [("procs_emitted", 1), ("reclaimed_records", 1),
                                         ("reclaimed_keys", 1)])
def test_wrong_record_counts_reject_the_snapshot(field, delta):
    _f, _e, snaps = stream()
    end_of(snaps[2])[field] += delta
    rc = consume(snaps)
    assert rc.stats["snapshots_incomplete"] == 1 and not rc.valid


def test_wrong_tracked_invalidates():
    _f, _e, snaps = stream()
    end_of(snaps[2])["tracked"] += 1
    rc = consume(snaps)
    assert rc.stats["totals_mismatch"] == 1 and rc.stats["invalidations"] == 1 and not rc.valid


def test_wrong_totals_invalidate():
    _f, _e, snaps = stream()
    end_of(snaps[2])["totals"]["counts"]["openat"] += 1
    rc = consume(snaps)
    assert rc.stats["totals_mismatch"] == 1 and not rc.valid


def test_missing_whole_snapshot_is_a_seq_gap():
    _f, _e, snaps = stream()
    del snaps[2]
    rc = consume(snaps)
    assert rc.stats["seq_gaps"] == 1 and not rc.valid
    assert rc.last.unchanged == set()                    # omission no longer means unchanged


def test_replayed_snapshot_is_a_seq_gap():
    _f, _e, snaps = stream()
    snaps.insert(3, copy.deepcopy(snaps[2]))
    rc = consume(snaps)
    assert rc.stats["seq_gaps"] >= 1 and not rc.valid


def test_epoch_change_resets_state_and_revalidates_at_its_keyframe():
    _f, _e, snaps = stream(3)
    fake2 = FakeCollector(attached_since=99999)
    fake2.add(77, openat=9)
    em2 = V2Emitter(fake2, run_id="run-y")
    snaps2 = [step(em2), step(em2)]
    rc = Reconstructor()
    for s in snaps:
        feed_all(rc, s)
    feed_all(rc, snaps2[0])
    assert rc.stats["epoch_changes"] == 1 and rc.valid and rc.state == truth(fake2)
    feed_all(rc, snaps2[1])
    assert rc.valid


def test_epoch_change_without_keyframe_stays_invalid():
    _f, _e, snaps = stream(3)
    fake2 = FakeCollector(attached_since=99999)
    fake2.add(77)
    em2 = V2Emitter(fake2, run_id="run-y")
    step(em2)                                            # its keyframe is lost
    later = step(em2)
    rc = Reconstructor()
    for s in snaps:
        feed_all(rc, s)
    feed_all(rc, later)
    assert rc.stats["epoch_changes"] == 1 and not rc.valid and rc.state == {}


def test_failed_snapshot_keeps_validity_but_claims_nothing(fake, em):
    rc = Reconstructor()
    feed_all(rc, step(em))
    fake.fail = True
    feed_all(rc, step(em))
    assert rc.valid and rc.last.status == "failed"
    assert rc.last.emitted == set() and rc.last.unchanged == set()
    assert rc.stats["snapshots_failed"] == 1


def test_failed_snapshot_with_inconsistent_totals_invalidates(fake, em):
    rc = Reconstructor()
    feed_all(rc, step(em))
    fake.fail = True
    recs = step(em)
    end_of(recs)["tracked"] = 99
    feed_all(rc, recs)
    assert not rc.valid and rc.stats["totals_mismatch"] == 1


def test_failed_snapshot_must_not_claim_a_keyframe(fake, em):
    rc = Reconstructor()
    feed_all(rc, step(em))
    fake.fail = True
    recs = step(em)
    recs[0]["keyframe"] = True
    feed_all(rc, recs)
    assert rc.stats["snapshots_incomplete"] == 1 and not rc.valid


def test_reclaim_of_an_untracked_key_invalidates(fake, em):
    rc = Reconstructor()
    feed_all(rc, step(em))
    fake.exit(20)
    feed_all(rc, step(em))
    fake.reclaim(20)
    recs = step(em)
    for r in recs:
        if r["type"] == "bpf_reclaimed":
            r["keys"][0]["tgid"] = 999
    feed_all(rc, recs)
    assert not rc.valid and rc.stats["invalidations"] == 1


def test_key_both_emitted_and_reclaimed_is_rejected(fake, em):
    rc = Reconstructor()
    feed_all(rc, step(em))
    fake.exit(20)
    feed_all(rc, step(em))
    fake.reclaim(20)
    fake.bump(10)
    recs = step(em)
    for r in recs:
        if r["type"] == "bpf_reclaimed":
            r["keys"][0] = key(10)
    feed_all(rc, recs)
    assert rc.stats["snapshots_incomplete"] == 1 and not rc.valid


def test_semantic_identity_errors_reject_the_snapshot(fake, em):
    rc = Reconstructor()
    feed_all(rc, step(em))
    fake.bump(10)
    recs = step(em)
    procs_of(recs)[0]["container_pid"] = 5               # level == distro level
    feed_all(rc, recs)
    assert rc.stats["snapshots_incomplete"] == 1 and not rc.valid


def test_non_keyframe_content_is_not_applied_while_invalid():
    _f, _e, snaps = stream(5)
    del snaps[1]
    rc = Reconstructor()
    for s in snaps:
        feed_all(rc, s)
    assert not rc.valid and rc.state == {}


def test_state_is_rebuilt_exactly_at_the_next_keyframe():
    scen = run_scenario(n=125)
    rc = Reconstructor()
    for i, (recs, want) in enumerate(scen):
        if i == 30:
            continue                                     # one snapshot lost
        feed_all(rc, recs)
        if 30 < i < 60:
            assert not rc.valid
        if i >= 60:
            assert rc.valid and rc.state == want
    assert rc.stats["seq_gaps"] == 1 and rc.stats["invalidations"] == 1


def test_loss_possible_when_a_loss_counter_rises(fake, em):
    rc = Reconstructor()
    feed_all(rc, step(em))
    feed_all(rc, step(em))
    assert rc.last.loss_possible is False
    fake.health["counts_map_full"] += 1
    feed_all(rc, step(em))
    assert rc.last.loss_possible is True
    feed_all(rc, step(em))
    assert rc.last.loss_possible is False


# --- keyframe recovery seen by the consumer --------------------------------

def scripted(n, fail_at=(), uncommitted_at=()):
    """Snapshots as a consumer receives them: failed ones complete, uncommitted ones torn."""
    fake = FakeCollector()
    fake.add(10, openat=1)
    fake.add(20, openat=1)
    em = V2Emitter(fake, run_id="run-k")
    out = []
    for i in range(n):
        fake.bump(10)
        fake.fail = i in fail_at
        torn = i in uncommitted_at
        recs = step(em, commit=not torn)
        out.append((recs[:-1] if torn else recs, copy.deepcopy(truth(fake))))
    return out


def test_failed_first_snapshot_never_validates_and_first_ok_one_rebuilds():
    rc = Reconstructor()
    for i, (recs, want) in enumerate(scripted(5, fail_at={0, 1})):
        feed_all(rc, recs)
        if i < 2:
            assert not rc.valid and rc.last.status == "failed"
        else:
            assert rc.valid and rc.state == want
    assert rc.stats["keyframe_schedule_violations"] == 0


def test_failed_scheduled_keyframe_leaves_a_waiting_consumer_invalid_until_recovery():
    scen = scripted(64, fail_at={60})
    rc = Reconstructor()
    for i, (recs, want) in enumerate(scen[40:], start=40):   # joins mid-stream, no keyframe yet
        feed_all(rc, recs)
        if i <= 60:
            assert not rc.valid                              # the failed seq 60 validates nothing
        else:
            assert rc.valid and rc.state == want             # seq 61 is the recovery keyframe
    assert rc.stats["keyframes"] == 1


def test_failed_scheduled_keyframe_keeps_a_continuous_consumer_valid_and_correct():
    rc = Reconstructor()
    expected = None
    for recs, want in scripted(64, fail_at={60}):
        feed_all(rc, recs)
        if end_of(recs)["status"] == "ok":
            expected = want                                  # a failed read emits nothing
        assert rc.valid and rc.state == expected
    assert rc.stats["totals_mismatch"] == 0 and rc.stats["keyframe_schedule_violations"] == 0


def test_torn_snapshot_is_rejected_and_the_next_one_rebuilds():
    rc = Reconstructor()
    for i, (recs, want) in enumerate(scripted(6, uncommitted_at={2})):
        feed_all(rc, recs)
        if i < 2:
            assert rc.valid
        elif i > 2:                                          # seq 3 is the forced keyframe
            assert rc.valid and rc.state == want
    assert rc.stats["snapshots_incomplete"] == 1 and rc.stats["keyframes"] == 2


def test_torn_keyframe_is_rejected_and_the_next_one_rebuilds():
    rc = Reconstructor()
    for i, (recs, want) in enumerate(scripted(3, uncommitted_at={0})):
        feed_all(rc, recs)
        assert rc.valid == (i >= 1)
        if i >= 1:
            assert rc.state == want


def test_missing_scheduled_keyframe_is_a_schedule_violation():
    snaps = [recs for recs, _ in scripted(62)]
    snaps[60][0]["keyframe"] = False                         # producer skipped its cadence
    rc = consume(snaps)
    assert rc.stats["keyframe_schedule_violations"] == 1


def test_missing_recovery_keyframe_is_a_schedule_violation():
    snaps = [recs for recs, _ in scripted(63, fail_at={60})]
    assert snaps[61][0]["keyframe"] is True
    snaps[61][0]["keyframe"] = False
    end_of(snaps[61])["procs_emitted"] = len(procs_of(snaps[61]))
    rc = consume(snaps)
    assert rc.stats["keyframe_schedule_violations"] == 1


def test_epoch_seen_from_a_later_seq_has_no_start_obligation():
    snaps = [recs for recs, _ in scripted(10)]
    rc = consume(snaps[5:])                                  # epoch start not observed
    assert rc.stats["keyframe_schedule_violations"] == 0 and not rc.valid


def test_totals_helper_wraps_mod_2_64():
    a = {"counts": {"openat": U64 - 1, "execve": 0}}
    b = {"counts": {"openat": 2, "execve": 1}}
    assert totals([a, b], names=("openat", "execve")) == {"openat": 1, "execve": 1}
