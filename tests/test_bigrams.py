"""Bigram decoder, invariant checkers and scripted oracle (M1b S2.2).

Contract: docs/telemetry-v2.md §8.5-§8.6 (S2 design report, approved A8:
R-LOSS and I-B1..I-B5 with their preconditions). Synthetic data only: no
root, BPF or kernel access.
"""

import copy
import random

import pytest

from processpulse import bigrams as bg
from processpulse.bigrams import FAIL, NOT_APPLICABLE, PASS
from processpulse.snapshots import BIGRAM_MARKERS, Reconstructor, key_tuple
from processpulse.vocab import SYSCALLS, VOCABULARY
from snapshot_fakes import BigramFake, BigramStandIn, key

U64_MAX = (1 << 64) - 1


def proc(lost=0, exited=True, **counts):
    return {"counts": {s: counts.get(s, 0) for s in SYSCALLS}, "pairs_lost": lost,
            "exited": exited}


# One thread: START_NEW, openat, openat, openat, execve.
TABLE = {("START_NEW", "openat"): 1, ("openat", "openat"): 2, ("openat", "execve"): 1}
PROC = proc(openat=3, execve=1)


# --- decoding -------------------------------------------------------------------

def test_vocabulary_and_marker_codes_are_pinned():
    assert VOCABULARY.id == "v1-3aba869d1752"
    for i, s in enumerate(SYSCALLS):
        assert bg.code_of(s) == i and bg.name_of(i) == s
    assert [bg.code_of(m) for m in BIGRAM_MARKERS] == [9, 10, 11, 12]
    assert [bg.name_of(c) for c in (9, 10, 11, 12)] == list(BIGRAM_MARKERS)
    assert bg.MARKER_CODES == {"START_NEW": 9, "START_ATTACH": 10, "START_LOST": 11, "EXEC": 12}


def test_every_valid_pair_code_decodes_and_markers_never_second():
    n = 0
    for a in range(13):
        for b in range(13):
            if b < 9:
                assert bg.decode_pair(a, b) == (bg.name_of(a), SYSCALLS[b])
                n += 1
            else:
                with pytest.raises(bg.DecodeError, match="I-B5"):
                    bg.decode_pair(a, b)
    assert n == 117


@pytest.mark.parametrize("code", [-1, 13, 99, U64_MAX, True, False, 1.0, "1", None, [1]])
def test_unknown_or_malformed_codes_are_rejected(code):
    with pytest.raises(bg.DecodeError):
        bg.name_of(code)
    with pytest.raises(bg.DecodeError):
        bg.decode_pair(code, 3)


@pytest.mark.parametrize("name", ["read", "", "OPENAT", "start_new", None, 3])
def test_unknown_names_are_rejected(name):
    with pytest.raises(bg.DecodeError):
        bg.code_of(name)


def test_decode_entries_is_sparse_and_counts_zero_entries_separately():
    entries = [(3, 3, 5), (9, 3, 1), (3, 5, 0), (12, 0, 0)]
    table, zeros = bg.decode_entries(entries)
    assert table == {("openat", "openat"): 5, ("START_NEW", "openat"): 1}
    assert zeros == 2                        # insert-before-increment race, not loss


def test_decode_entries_empty():
    assert bg.decode_entries([]) == ({}, 0)


@pytest.mark.parametrize("entries", [
    [(3, 9, 1)],                             # marker second (I-B5)
    [(13, 3, 1)],                            # unknown first code
    [(3, 3, 1), (3, 3, 2)],                  # duplicate map key
    [(3, 3, -1)], [(3, 3, U64_MAX + 1)], [(3, 3, True)], [(3, 3, 1.5)],
    [(3, 3)], [(3, 3, 1, 0)], [None],
])
def test_decode_entries_rejects_malformed_input(entries):
    with pytest.raises(bg.DecodeError):
        bg.decode_entries(entries)


# --- I-B5 -----------------------------------------------------------------------------

def test_ib5_pass_and_fail():
    assert bg.check_ib5(TABLE).status == PASS
    assert bg.check_ib5({}).status == PASS
    for bad in ({("openat", "START_NEW"): 1}, {("openat", "EXEC"): 1},
                {("read", "openat"): 1}, {("openat", "read"): 1}):
        r = bg.check_ib5(bad)
        assert r.status == FAIL and r.invariant == "I-B5"


@pytest.mark.parametrize("check", [bg.check_ib1, bg.check_ib1_prime, bg.check_ib3_prime])
def test_checkers_fail_on_a_table_that_breaks_ib5_or_has_bad_counts(check):
    for bad in ({("openat", "START_NEW"): 1}, {("openat", "openat"): -1},
                {("openat", "openat"): "2"}):
        r = check(PROC, bad, "asserted")
        assert r.status == FAIL and "table" in r.reason


# --- I-B1, I-B1', I-B3' -------------------------------------------------------------

def test_ib1_pass_and_fail():
    assert bg.check_ib1(PROC, TABLE, "asserted").status == PASS
    bad = dict(TABLE)
    bad[("openat", "openat")] = 1                                  # one incoming pair missing
    r = bg.check_ib1(PROC, bad, "asserted")
    assert r.status == FAIL and r.detail["mismatch"] == {"openat": [2, 3]}


def test_ib1_is_not_applicable_with_losses():
    lossy = proc(lost=1, openat=4, execve=1)
    r = bg.check_ib1(lossy, TABLE, "asserted")
    assert r.status == NOT_APPLICABLE and "pairs_lost" in r.reason


def test_ib1_prime_pass_with_and_without_losses_and_fail():
    assert bg.check_ib1_prime(PROC, TABLE, "drained").status == PASS
    lossy = proc(lost=1, openat=4, execve=1)                      # one counted entry, pair lost
    assert bg.check_ib1_prime(lossy, TABLE, "drained").status == PASS
    r = bg.check_ib1_prime(proc(lost=0, openat=4, execve=1), TABLE, "drained")
    assert r.status == FAIL and r.detail == {"pairs": 4, "pairs_lost": 0, "counts": 5}


def test_ib3_prime_pass_with_losses_and_fail():
    assert bg.check_ib3_prime(PROC, TABLE, "reclaimed_exited").status == PASS
    lossy = proc(lost=2, openat=5, execve=1)
    assert bg.check_ib3_prime(lossy, TABLE, "reclaimed_exited").status == PASS
    over = dict(TABLE)
    over[("openat", "openat")] = 5                                  # row openat = 6 > count 3
    r = bg.check_ib3_prime(proc(openat=3, execve=1), over, "reclaimed_exited")
    assert r.status == FAIL and r.detail["exceeds"] == {"openat": [6, 3]}


ALL_PER_PROCESS = [bg.check_ib1, bg.check_ib1_prime, bg.check_ib3_prime]


@pytest.mark.parametrize("check", ALL_PER_PROCESS)
def test_live_processes_are_not_applicable(check):
    r = check(PROC, TABLE, None)                                   # live: non-atomic read
    assert r.status == NOT_APPLICABLE and "quiescent" in r.reason


@pytest.mark.parametrize("check", ALL_PER_PROCESS)
def test_unavailable_capability_is_not_applicable(check):
    r = check(dict(PROC, pairs_lost=None), {}, "drained")
    assert r.status == NOT_APPLICABLE and "unavailable" in r.reason


def test_unknown_quiescence_basis_is_a_programming_error():
    with pytest.raises(ValueError):
        bg.check_ib1(PROC, TABLE, "idle")


@pytest.mark.parametrize("check", ALL_PER_PROCESS)
def test_explicit_zero_entries_change_nothing(check):
    dense = dict(TABLE)
    dense.update({("EXEC", "openat"): 0, ("clone", "fork"): 0})
    assert check(PROC, dense, "asserted") == check(PROC, TABLE, "asserted")


def test_empty_tables():
    idle = proc()                                                  # no tracked call at all
    for check in ALL_PER_PROCESS:
        assert check(idle, {}, "drained").status == PASS
    all_lost = proc(lost=2, openat=2)
    assert bg.check_ib1_prime(all_lost, {}, "drained").status == PASS
    assert bg.check_ib3_prime(all_lost, {}, "drained").status == PASS
    assert bg.check_ib1(all_lost, {}, "drained").status == NOT_APPLICABLE
    assert bg.check_ib1(proc(openat=2), {}, "drained").status == FAIL


# --- oracle, I-B3 and I-B4 exact -----------------------------------------------------

def test_oracle_single_thread():
    o = bg.expected_pairs([("thread", 1, "new"), ("call", 1, "openat"), ("call", 1, "openat"),
                           ("call", 1, "execve")])
    assert o.pairs == {("START_NEW", "openat"): 1, ("openat", "openat"): 1,
                       ("openat", "execve"): 1}
    assert o.counts["openat"] == 2 and o.counts["execve"] == 1
    assert o.segment_starts == {"START_NEW": 1, "START_ATTACH": 0, "START_LOST": 0, "EXEC": 0}
    assert o.segment_ends["execve"] == 1 and sum(o.segment_ends.values()) == 1


def test_oracle_threads_attach_new_and_exit():
    o = bg.expected_pairs([
        ("thread", "main", "attach"), ("call", "main", "openat"),
        ("call", "main", "clone"), ("thread", "t2", "new"),
        ("call", "t2", "openat"), ("exit", "t2"),
        ("thread", "t3", "new"), ("exit", "t3"),                    # no call: no segment
        ("call", "main", "openat")])
    assert o.pairs == {("START_ATTACH", "openat"): 1, ("openat", "clone"): 1,
                       ("clone", "openat"): 1, ("START_NEW", "openat"): 1}
    assert o.segment_starts["START_ATTACH"] == 1 and o.segment_starts["START_NEW"] == 1
    assert o.segment_ends == {**dict.fromkeys(SYSCALLS, 0), "openat": 2}


def test_oracle_leader_exec():
    o = bg.expected_pairs([("thread", 1, "new"), ("call", 1, "execve"), ("exec", 1),
                           ("call", 1, "openat")])
    assert o.pairs == {("START_NEW", "execve"): 1, ("EXEC", "openat"): 1}
    assert o.segment_starts["EXEC"] == 1 and o.segment_ends["execve"] == 1


def test_oracle_non_leader_exec_ends_every_other_thread():
    o = bg.expected_pairs([
        ("thread", "leader", "attach"), ("call", "leader", "openat"),
        ("thread", "t2", "new"), ("call", "t2", "execve"), ("exec", "t2"),
        ("call", "t2", "openat")])
    assert o.pairs == {("START_ATTACH", "openat"): 1, ("START_NEW", "execve"): 1,
                       ("EXEC", "openat"): 1}
    with pytest.raises(ValueError):                                # the leader died in the exec
        bg.expected_pairs([("thread", "a", "attach"), ("thread", "b", "new"), ("exec", "b"),
                           ("call", "a", "openat")])


def test_oracle_exec_without_a_later_call_adds_no_exec_pair():
    o = bg.expected_pairs([("thread", 1, "new"), ("call", 1, "execve"), ("exec", 1)])
    assert o.segment_starts["EXEC"] == 0 and ("EXEC", "openat") not in o.pairs


def test_oracle_thread_id_reuse_is_a_new_thread():
    o = bg.expected_pairs([("thread", 5, "new"), ("call", 5, "fork"), ("exit", 5),
                           ("thread", 5, "new"), ("call", 5, "fork")])
    assert o.pairs == {("START_NEW", "fork"): 2} and o.segment_starts["START_NEW"] == 2


@pytest.mark.parametrize("script", [
    [("call", 1, "openat")],                                        # undeclared thread
    [("thread", 1, "new"), ("call", 1, "read")],                    # not in the vocabulary
    [("thread", 1, "new"), ("call", 1, "START_NEW")],
    [("thread", 1, "new"), ("thread", 1, "new")],                   # declared twice while live
    [("thread", 1, "new"), ("exit", 1), ("thread", 1, "attach")],   # a reused id is new
    [("thread", 1, "new"), ("exec", 1), ("thread", 2, "attach")],   # nothing pre-arm after exec
    [("thread", 1, "maybe")],
    [("thread", 1, "new"), ("exit", 1), ("exit", 1)],
    [("fork", 1)], [("call", 1)], "not a script",
])
def test_oracle_rejects_invalid_scripts(script):
    with pytest.raises(ValueError):
        bg.expected_pairs(script)


def observed_from(oracle, lost=0):
    return proc(lost=lost, **oracle.counts), dict(oracle.pairs)


def random_script(rnd, steps=60):
    script, live, nxt, execd = [], [], 0, False
    for _ in range(steps):
        r = rnd.random()
        if not live or r < 0.15:
            kind = "attach" if (not execd and rnd.random() < 0.3) else "new"
            script.append(("thread", nxt, kind))
            live.append(nxt)
            nxt += 1
        elif r < 0.75:
            script.append(("call", rnd.choice(live), rnd.choice(SYSCALLS)))
        elif r < 0.85:
            t = live.pop(rnd.randrange(len(live)))
            script.append(("exit", t))
        else:
            t = rnd.choice(live)
            script.append(("exec", t))
            live, execd = [t], True
    return script


@pytest.mark.parametrize("seed", range(20))
def test_oracle_output_satisfies_every_exact_invariant(seed):
    o = bg.expected_pairs(random_script(random.Random(seed)))
    p, t = observed_from(o)
    for check in (bg.check_ib5,):
        assert check(t).status == PASS
    for check in ALL_PER_PROCESS:
        assert check(p, t, "asserted").status == PASS
    assert bg.check_ib3_exact(p, t, o, "asserted", losses=NO_LOSS).status == PASS
    assert bg.check_ib4_exact(p, t, o, "asserted", losses=NO_LOSS).status == PASS
    assert bg.expected_pairs(random_script(random.Random(seed))) == o   # deterministic


SCRIPT = [("thread", "m", "attach"), ("call", "m", "openat"), ("call", "m", "clone"),
          ("thread", "w", "new"), ("call", "w", "openat"), ("call", "w", "openat"),
          ("exit", "w"), ("call", "m", "execve"), ("exec", "m"), ("call", "m", "openat")]


def test_ib3_and_ib4_exact_pass_against_the_oracle():
    o = bg.expected_pairs(SCRIPT)
    p, t = observed_from(o)
    r3 = bg.check_ib3_exact(p, t, o, "asserted", losses=NO_LOSS)
    r4 = bg.check_ib4_exact(p, t, o, "asserted", losses=NO_LOSS)
    assert r3.status == PASS and r4.status == PASS
    assert r4.detail["starts"] == {"START_NEW": 1, "START_ATTACH": 1, "START_LOST": 0, "EXEC": 1}


def test_ib3_exact_fails_on_an_unscripted_call():
    o = bg.expected_pairs(SCRIPT)
    p, t = observed_from(o)
    p["counts"]["clone"] += 1                                      # an unscripted clone after
    t[("openat", "clone")] += 1                                    # the final openat
    assert bg.check_ib1(p, t, "asserted").status == PASS           # consistent, so I-B1 passes
    r = bg.check_ib3_exact(p, t, o, "asserted", losses=NO_LOSS)
    assert r.status == FAIL
    assert r.detail["mismatch"] == {"openat": [1, 2], "clone": [1, 0]}


def test_ib4_exact_fails_on_a_wrong_start_marker():
    o = bg.expected_pairs(SCRIPT)
    p, t = observed_from(o)
    t[("START_NEW", "openat")] -= 1                                # the worker misclassified
    t[("START_ATTACH", "openat")] += 1
    r = bg.check_ib4_exact(p, t, o, "asserted", losses=NO_LOSS)
    assert r.status == FAIL
    assert r.detail["mismatch"] == {"START_NEW": [0, 1], "START_ATTACH": [2, 1]}
    assert bg.check_ib1(p, t, "asserted").status == PASS           # I-B1 cannot see it


def test_start_lost_is_never_expected_without_losses():
    o = bg.expected_pairs(SCRIPT)
    p, t = observed_from(o)
    t[("START_LOST", "openat")] = 1
    t[("START_ATTACH", "openat")] -= 1
    assert bg.check_ib4_exact(p, t, o, "asserted", losses=NO_LOSS).status == FAIL


def test_ib3_and_ib4_exact_preconditions():
    o = bg.expected_pairs(SCRIPT)
    p, t = observed_from(o)
    for check in (bg.check_ib3_exact, bg.check_ib4_exact):
        assert check(p, t, None, "asserted", losses=NO_LOSS).status == NOT_APPLICABLE  # no truth
        assert check(p, t, o, None, losses=NO_LOSS).status == NOT_APPLICABLE            # live
        lossy = dict(p, pairs_lost=1)
        r = check(lossy, t, o, "asserted", losses=NO_LOSS)
        assert r.status == NOT_APPLICABLE and "pairs_lost" in r.reason


# --- global-loss precondition of the exact checks (S2.3 audit, finding 1) -----------

NO_LOSS = dict.fromkeys(bg.GLOBAL_LOSS_FIELDS, 0)

# The audited row-1 case (S2.3 evidence, counts map full): the helper's own
# pairs_lost is 0, but its observed calls before the map had room were lost with
# their pairs (R-LOSS row 1 is not in pairs_lost), and its next pair is START_LOST.
ROW1_PROC = proc(lost=0, open=1)
ROW1_TABLE = {("START_LOST", "open"): 1}
ROW1_SCRIPT = [("thread", 1, "new"), ("call", 1, "execve"), ("exec", 1),
               ("call", 1, "openat"), ("call", 1, "openat"), ("call", 1, "open")]


def test_audited_row_1_case_is_not_applicable_for_exact_checks():
    o = bg.expected_pairs(ROW1_SCRIPT)
    losses = dict(NO_LOSS, counts_map_full=3)
    assert bg.check_ib1(ROW1_PROC, ROW1_TABLE, "asserted").status == PASS       # still exact
    for check in (bg.check_ib3_exact, bg.check_ib4_exact):
        r = check(ROW1_PROC, ROW1_TABLE, o, "asserted", losses=losses)
        assert r.status == NOT_APPLICABLE and "counts_map_full" in r.reason
        # without the global precondition the same data gave a false FAIL
        assert check(ROW1_PROC, ROW1_TABLE, o, "asserted", losses=NO_LOSS).status == FAIL


@pytest.mark.parametrize("field", ["counts_map_full", "thread_map_full", "bigram_map_full",
                                   "pre_arm_events"])
def test_each_global_loss_makes_exact_checks_not_applicable(field):
    o = bg.expected_pairs(SCRIPT)
    p, t = observed_from(o)
    for check in (bg.check_ib3_exact, bg.check_ib4_exact):
        r = check(p, t, o, "asserted", losses=dict(NO_LOSS, **{field: 1}))
        assert r.status == NOT_APPLICABLE and field in r.reason
        assert check(p, t, o, "asserted", losses=NO_LOSS).status == PASS


def test_exact_checks_without_loss_counters_are_not_applicable():
    o = bg.expected_pairs(SCRIPT)
    p, t = observed_from(o)
    for check in (bg.check_ib3_exact, bg.check_ib4_exact):
        r = check(p, t, o, "asserted")
        assert r.status == NOT_APPLICABLE and "global loss" in r.reason


@pytest.mark.parametrize("bad", [{"counts_map_full": 0}, dict(NO_LOSS, pre_arm_events=-1),
                                 dict(NO_LOSS, thread_map_full=True), "none"])
def test_malformed_loss_counters_are_a_programming_error(bad):
    o = bg.expected_pairs(SCRIPT)
    p, t = observed_from(o)
    with pytest.raises(ValueError):
        bg.check_ib4_exact(p, t, o, "asserted", losses=bad)


def test_other_checks_ignore_global_losses():
    """I-B1, I-B1' and I-B3' keep their approved preconditions (not weakened or tightened)."""
    for check in (bg.check_ib1, bg.check_ib1_prime, bg.check_ib3_prime):
        assert check(ROW1_PROC, ROW1_TABLE, "asserted").status == PASS


# --- ground truth over a closed scope (real helpers before the drain exists) -------

A = (proc(lost=0, openat=3, execve=1),
     {("START_NEW", "execve"): 1, ("EXEC", "openat"): 1, ("openat", "openat"): 2})
B = (proc(lost=1, open=2, execve=1),                                # one pair lost (row 2/3)
     {("START_NEW", "execve"): 1, ("EXEC", "open"): 1})
C_PURGED = {"counts": 3, "pairs": 2, "pairs_lost": 1}               # a purged process's totals
SCOPE_TALLY = 4 + 3 + 3                                             # counted by the script


def test_scope_ground_truth_passes_with_losses_and_a_purge():
    r = bg.check_ib2_ground_truth_scope([A, B], SCOPE_TALLY, "asserted", NO_LOSS, C_PURGED)
    assert r.status == PASS, r
    assert r.detail["counts_side"] == r.detail["pairs_side"] == SCOPE_TALLY


@pytest.mark.parametrize("processes,purged,tally,why", [
    ([A], C_PURGED, SCOPE_TALLY, "missing process"),
    ([A, B, B], C_PURGED, SCOPE_TALLY, "double-counted process"),
    ([A, B], None, SCOPE_TALLY, "purged process forgotten"),
    ([A, B], C_PURGED, SCOPE_TALLY + 1, "wrong tally"),
])
def test_scope_ground_truth_detects(processes, purged, tally, why):
    r = bg.check_ib2_ground_truth_scope(processes, tally, "asserted", NO_LOSS, purged)
    assert r.status == FAIL, why


def test_scope_ground_truth_preconditions():
    assert bg.check_ib2_ground_truth_scope([A, B], SCOPE_TALLY, None, NO_LOSS,
                                           C_PURGED).status == NOT_APPLICABLE       # live
    assert bg.check_ib2_ground_truth_scope([A, B], SCOPE_TALLY, "asserted", None,
                                           C_PURGED).status == NOT_APPLICABLE       # no counters
    r = bg.check_ib2_ground_truth_scope([A, B], SCOPE_TALLY, "asserted",
                                        dict(NO_LOSS, counts_map_full=1), C_PURGED)
    assert r.status == NOT_APPLICABLE and "counts_map_full" in r.reason
    other = dict(NO_LOSS, thread_map_full=5, bigram_map_full=2, pre_arm_events=3)
    assert bg.check_ib2_ground_truth_scope([A, B], SCOPE_TALLY, "asserted", other,
                                           C_PURGED).status == PASS         # in pairs_lost
    unavailable = (dict(A[0], pairs_lost=None), {})
    assert bg.check_ib2_ground_truth_scope([unavailable], 4, "asserted", NO_LOSS).status \
        == NOT_APPLICABLE
    with pytest.raises(ValueError):
        bg.check_ib2_ground_truth_scope([A], -1, "asserted", NO_LOSS)


def test_loss_window_and_epoch_losses():
    before = {"counts_map_full": 5, "thread_map_full": 1, "bigram_map_full": 0,
              "pre_arm_events": 7, "unrelated": 99}
    after = dict(before, counts_map_full=8, unrelated=100)
    assert bg.loss_window(before, after) == dict(NO_LOSS, counts_map_full=3)
    with pytest.raises(ValueError):
        bg.loss_window(after, before)                              # counters never decrease
    _f, _e, snaps = drained_run()
    rc = consume(snaps)
    assert bg.epoch_losses(rc) == {"counts_map_full": 0, "thread_map_full": 0,
                                   "bigram_map_full": 0, "pre_arm_events": 0}
    snaps[-1][-1]["bigram_health"]["pre_arm_events"] = 4
    assert bg.epoch_losses(consume(snaps))["pre_arm_events"] == 4
    f = BigramFake()
    f.add(10)
    un = BigramStandIn(f, status="unavailable", err="UNSUPPORTED", reason="r")
    assert bg.epoch_losses(consume([step(un)])) is None


# --- I-B2 and the final reports, through the Reconstructor --------------------------

def run_thread(fake, tgid, marker, calls, lose=()):
    """One thread segment with consistent R-LOSS accounting (row 3 for indexes in lose)."""
    prev = marker
    for i, s in enumerate(calls):
        if i in lose:
            fake.lose_pair(tgid, s)                                # counted, pair lost, prev := s
        else:
            fake.step_pair(tgid, prev, s)
        prev = s


def purge(fake, em, tgid):
    """Self-exclusion purge: the stand-in reports what the purged entry held."""
    em.health["purged_counts"] += sum(fake.procs[tgid]["counts"].values())
    em.health["purged_pairs"] += sum(fake.pairs[tgid].values())
    em.health["purged_pairs_lost"] += fake.lost[tgid]
    fake.purge(tgid)


def drained_run(n_before=3, mutate=None):
    """Exit+reclaim, a purge after emission (with pairs_lost), a purge before
    emission, losses on a live process, then a drained final snapshot."""
    f = BigramFake()
    em = BigramStandIn(f, run_id="run-ib2")
    snaps = []
    for t in (10, 20, 30, 40):
        f.add(t)
    run_thread(f, 10, "START_ATTACH", ["openat", "openat", "clone"], lose={1})
    run_thread(f, 20, "START_NEW", ["execve", "openat"])
    run_thread(f, 30, "START_NEW", ["openat", "fork", "openat"], lose={0})
    run_thread(f, 40, "START_NEW", ["clone"])
    snaps.append(step(em))
    f.exit(20)
    snaps.append(step(em))
    f.reclaim(20)                                                  # two-phase reclaim
    purge(f, em, 30)                                               # emitted, pairs_lost = 1
    f.add(50)
    run_thread(f, 50, "START_NEW", ["openat", "openat"], lose={1})
    purge(f, em, 50)                                               # never emitted
    run_thread(f, 10, "EXEC", ["openat"])
    snaps.append(step(em))
    for _ in range(n_before):
        snaps.append(step(em))
    if mutate:
        mutate(f, em)
    em.drain = True
    snaps.append(step(em))
    return f, em, snaps


def step(em):
    recs, done = em.build()
    done()
    return recs


def consume(snaps):
    rc = Reconstructor()
    for s in snaps:
        for r in s:
            rc.feed(r)
    rc.finish()
    return rc


def test_reconstructor_keeps_retired_values_and_epoch_intactness():
    _f, _e, snaps = drained_run()
    rc = consume(snaps)
    reasons = {k[2]: v["reason"] for k, v in rc.retired.items()}
    assert reasons == {20: "exited", 30: "self_excluded"}         # 50 was never emitted
    assert rc.retired[key_tuple(key(20))]["proc"]["exited"] is True
    assert rc.epoch_intact and rc.valid and rc.last.drained
    assert rc.last_ok_end["drained"] is True


def test_ib2_passes_on_the_drained_snapshot():
    _f, em, snaps = drained_run()
    r = bg.check_ib2_drained(consume(snaps))
    assert r.status == PASS, r
    d = r.detail
    assert d["purged_counts"] == 5 and d["purged_pairs"] == 3 and d["purged_pairs_lost"] == 2
    assert d["lhs"] == d["rhs"] and d["keys_reclaimed_exited"] == 1 and d["keys_live"] == 2


def test_ib2_needs_purged_pairs_lost_in_purged_b():
    _f, _e, snaps = drained_run()
    snaps[-1][-1]["bigram_health"]["purged_pairs_lost"] = 0
    r = bg.check_ib2_drained(consume(snaps))
    assert r.status == FAIL and r.detail["lhs"] - r.detail["rhs"] == 2


def test_ib2_sums_the_reclaimed_exited_values():
    _f, _e, snaps = drained_run()
    rc = consume(snaps)
    live = sum(sum(p["counts"].values()) for p in rc.state.values())
    reclaimed = sum(rc.retired[key_tuple(key(20))]["proc"]["counts"].values())
    assert bg.check_ib2_drained(rc).detail["counts"] == live + reclaimed
    rc.retired[key_tuple(key(20))]["pairs"][("START_NEW", "execve")] += 1
    assert bg.check_ib2_drained(rc).status == FAIL                 # its values are in the sums


def test_ib2_counts_a_purged_process_only_through_the_purge_totals():
    _f, _e, snaps = drained_run()
    rc = consume(snaps)
    rec = rc.retired[key_tuple(key(30))]
    rec["pairs"][("openat", "fork")] += 1                          # not summed: still balanced
    assert bg.check_ib2_drained(rc).status == PASS
    rec["reason"] = "exited"                                        # summed now: caught
    assert bg.check_ib2_drained(rc).status == FAIL


def test_ib2_cannot_see_a_balanced_key_missing():
    """Documented limit: I-B2 is the sum of per-key I-B1' identities plus the purge
    terms, so a key whose own values balance contributes 0 net. Coverage of keys
    comes from the Reconstructor (tracked/totals cross-checks, retired keys)."""
    _f, _e, snaps = drained_run()
    rc = consume(snaps)
    del rc.retired[key_tuple(key(20))]
    assert bg.check_ib2_drained(rc).status == PASS


@pytest.mark.parametrize("field,delta", [("purged_counts", 1), ("purged_pairs", 1)])
def test_ib2_fails_when_purge_accounting_is_wrong(field, delta):
    _f, _e, snaps = drained_run()
    snaps[-1][-1]["bigram_health"][field] += delta
    assert bg.check_ib2_drained(consume(snaps)).status == FAIL


def test_ib2_fails_when_a_pair_is_missing_without_loss_accounting():
    def drop_pair(f, em):
        f.bump(40, "openat")                                       # counted; pair neither
    _f, _e, snaps = drained_run(mutate=drop_pair)                  # recorded nor lost
    assert bg.check_ib2_drained(consume(snaps)).status == FAIL


# Observed entries drained_run scripts, counted from the script itself:
# 10: 3 + 1 (after the exec), 20: 2, 30: 3, 40: 1, 50: 2.
DRAINED_RUN_ENTRIES = 12


def test_ib2_ground_truth_passes():
    _f, _e, snaps = drained_run()
    r = bg.check_ib2_ground_truth(consume(snaps), DRAINED_RUN_ENTRIES)
    assert r.status == PASS, r
    assert r.detail["counts_side"] == r.detail["pairs_side"] == DRAINED_RUN_ENTRIES


def test_ib2_ground_truth_detects_a_missing_process():
    _f, _e, snaps = drained_run()
    rc = consume(snaps)
    del rc.retired[key_tuple(key(20))]                             # balanced, so plain I-B2 passes
    assert bg.check_ib2_drained(rc).status == PASS
    r = bg.check_ib2_ground_truth(rc, DRAINED_RUN_ENTRIES)
    assert r.status == FAIL and r.detail["counts_side"] == DRAINED_RUN_ENTRIES - 2


def test_ib2_ground_truth_detects_a_double_counted_process():
    _f, _e, snaps = drained_run()
    rc = consume(snaps)
    rc.retired[key_tuple(key(30))]["reason"] = "exited"            # also in purged_counts
    assert bg.check_ib2_drained(rc).status == PASS
    r = bg.check_ib2_ground_truth(rc, DRAINED_RUN_ENTRIES)
    assert r.status == FAIL and r.detail["counts_side"] == DRAINED_RUN_ENTRIES + 3


def test_ib2_ground_truth_detects_a_wrong_tally_and_shares_the_preconditions():
    _f, _e, snaps = drained_run()
    rc = consume(snaps)
    assert bg.check_ib2_ground_truth(rc, DRAINED_RUN_ENTRIES + 1).status == FAIL
    assert bg.check_ib2_ground_truth(consume(snaps[:-1]), DRAINED_RUN_ENTRIES).status \
        == NOT_APPLICABLE
    for bad in (-1, True, 1.5, None):
        with pytest.raises(ValueError):
            bg.check_ib2_ground_truth(rc, bad)


def test_ib2_ground_truth_counts_row_1_loss_on_both_sides():
    """R-LOSS row 1 (no counts entry): count and pair both lost, in counts_map_full."""
    f, em, snaps = drained_run()
    snaps[-1][-1]["loss"]["counts_map_full"] = 2                   # two more observed entries
    r = bg.check_ib2_ground_truth(consume(snaps), DRAINED_RUN_ENTRIES + 2)
    assert r.status == PASS and r.detail["counts_map_full"] == 2


def test_retire_from_a_keyframe_reclaim():
    f = BigramFake()
    f.add(10)
    f.add(20)
    run_thread(f, 20, "START_NEW", ["openat"])
    em = BigramStandIn(f, run_id="kf-retire")
    snaps = []
    for i in range(60):
        if i == 58:
            f.exit(20)
        snaps.append(step(em))
    f.reclaim(20)
    kf = step(em)
    assert kf[0]["seq"] == 60 and kf[0]["keyframe"]
    assert [k["tgid"] for r in kf if r["type"] == "bpf_reclaimed" for k in r["keys"]] == [20]
    rc = consume(snaps + [kf])
    ret = rc.retired[key_tuple(key(20))]
    assert ret["reason"] == "exited" and ret["proc"]["exited"] is True
    assert ret["pairs"] == {("START_NEW", "openat"): 1}
    assert rc.valid and rc.epoch_intact and key_tuple(key(20)) not in rc.state


def test_epoch_stays_intact_when_snapshot_0_fails():
    f = BigramFake()
    f.add(10)
    run_thread(f, 10, "START_NEW", ["openat"])
    em = BigramStandIn(f, run_id="fail-0")
    f.fail = True
    s0 = step(em)
    f.fail = False
    s1 = step(em)
    em.drain = True
    s2 = step(em)
    assert s0[-1]["status"] == "failed" and s1[0]["keyframe"]
    rc = consume([s0, s1, s2])
    assert rc.valid and rc.epoch_intact
    assert bg.check_ib2_drained(rc).status == PASS
    assert bg.check_ib2_ground_truth(rc, 1).status == PASS


def test_epoch_not_intact_when_the_first_ok_snapshot_is_not_a_keyframe():
    f = BigramFake()
    f.add(10)
    em = BigramStandIn(f, run_id="no-kf")
    f.fail = True
    s0 = step(em)
    f.fail = False
    s1 = step(em)
    s1[0]["keyframe"] = False                                      # producer broke the rule
    rc = consume([s0, s1])
    assert not rc.epoch_intact and rc.stats["keyframe_schedule_violations"] == 1


def test_ib2_not_applicable_before_the_drain():
    _f, _e, snaps = drained_run()
    r = bg.check_ib2_drained(consume(snaps[:-1]))
    assert r.status == NOT_APPLICABLE and "drained" in r.reason


def test_ib2_not_applicable_when_the_epoch_was_not_seen_whole():
    _f, _e, snaps = drained_run(n_before=60)                       # keyframe at seq 60
    del snaps[4]                                                   # lose one snapshot
    rc = consume(snaps)
    assert rc.valid and rc.last.drained and not rc.epoch_intact
    r = bg.check_ib2_drained(rc)
    assert r.status == NOT_APPLICABLE and "epoch" in r.reason


def test_ib2_not_applicable_when_started_mid_epoch():
    _f, _e, snaps = drained_run(n_before=60)
    rc = consume(snaps[2:])
    assert rc.valid and not rc.epoch_intact
    assert bg.check_ib2_drained(rc).status == NOT_APPLICABLE


def test_ib2_not_applicable_with_vanished_entries():
    def vanish(f, em):
        del f.procs[40]
    _f, _e, snaps = drained_run(mutate=vanish)
    r = bg.check_ib2_drained(consume(snaps))
    assert r.status == NOT_APPLICABLE and "vanished" in r.reason


def test_ib2_not_applicable_without_the_capability():
    f = BigramFake()
    f.add(10)
    em = BigramStandIn(f, status="unavailable", err="UNSUPPORTED", reason="r")
    em.drain = True
    r = bg.check_ib2_drained(consume([step(em)]))
    assert r.status == NOT_APPLICABLE and "unavailable" in r.reason


def test_ib2_not_applicable_when_the_state_is_invalid():
    _f, _e, snaps = drained_run()
    snaps[-1][-1]["totals"]["bigrams"]["pairs"] += 1
    rc = consume(snaps)
    assert not rc.valid
    assert bg.check_ib2_drained(rc).status == NOT_APPLICABLE


def statuses(results):
    return {(r.invariant, r.key[2] if r.key else None): r.status for r in results}


def test_quiescent_reports_cover_reclaimed_and_drained_processes():
    _f, _e, snaps = drained_run()
    st = statuses(bg.check_quiescent_reports(consume(snaps)))
    for t in (10, 20, 40):                                         # 20 reclaimed, 10/40 drained
        for inv in ("I-B5", "I-B1'", "I-B3'"):
            assert st[(inv, t)] == PASS, (inv, t)
    assert st[("I-B1", 20)] == PASS and st[("I-B1", 40)] == PASS
    assert st[("I-B1", 10)] == NOT_APPLICABLE                      # pairs_lost = 1
    assert not any(k[1] == 30 for k in st)                         # purged: in I-B2 only


def test_quiescent_reports_skip_live_processes_before_the_drain():
    _f, _e, snaps = drained_run()
    st = statuses(bg.check_quiescent_reports(consume(snaps[:-1])))
    assert {k[1] for k in st} == {20}                              # only the reclaimed one


def test_quiescent_reports_detect_a_broken_final_table():
    _f, _e, snaps = drained_run()
    rc = consume(snaps)
    rc.retired[key_tuple(key(20))]["pairs"][("START_NEW", "execve")] += 1
    st = statuses(bg.check_quiescent_reports(rc))
    assert st[("I-B1'", 20)] == FAIL and st[("I-B1", 20)] == FAIL


def test_reclaimed_record_not_marked_exited_is_not_applicable():
    _f, _e, snaps = drained_run()
    rc = consume(snaps)
    rc.retired[key_tuple(key(20))]["proc"]["exited"] = False
    st = statuses(bg.check_quiescent_reports(rc))
    assert st[("I-B1'", 20)] == NOT_APPLICABLE


def test_module_never_imports_bcc():
    import os
    import subprocess
    import sys
    code = ("import sys, processpulse.bigrams; "
            "print(','.join(sorted(m for m in sys.modules if m == 'bcc' or m.startswith('bcc.'))))")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = subprocess.run([sys.executable, "-c", code], cwd=root, capture_output=True, text=True,
                         check=True)
    assert out.stdout.strip() == ""


def test_result_is_explicit_about_status():
    r = bg.check_ib1(PROC, TABLE, None)
    assert r.status in (PASS, FAIL, NOT_APPLICABLE) and r.invariant == "I-B1" and r.reason
    assert copy.deepcopy(r) == r
