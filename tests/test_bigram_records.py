"""Schema-v2 bigram records (M1b S2.1): schema, chunking and reconstruction.

Contract: docs/telemetry-v2.md §8 (M1b plan v3 D2/D5, S2 design §3.7,
approved decisions U1, U4, U8, U10). Records come from
tests/snapshot_fakes.BigramStandIn, a test-only producer; no root or BPF.
"""

import copy
import json
import random

import pytest

from processpulse.jsonl import MAX_RECORD_BYTES, RecordTooLarge, encode_record, line_violations
from processpulse.snapshots import (BIGRAM_HEALTH_FIELDS, BIGRAM_MARKERS, MAX_PAIRS_PER_RECORD,
                                    Reconstructor, V2Emitter, bigram_parts, bigram_totals,
                                    chunk_records, key_tuple)
from processpulse.validate import SCHEMA_V2_PATH, Validator, load_schema
from processpulse.vocab import SYSCALLS
from snapshot_fakes import (BigramFake, BigramStandIn, FakeCollector, bigram_state_truth, key,
                            pair_truth, truth)

U64 = 1 << 64
U64_MAX = U64 - 1
FIRST = SYSCALLS + BIGRAM_MARKERS


def step(em, commit=True):
    recs, done = em.build()
    if commit:
        done()
    return recs


def kinds(recs):
    return [r["type"] for r in recs]


def of(recs, t):
    return [r for r in recs if r["type"] == t]


def feed_all(rc, recs):
    for r in recs:
        rc.feed(r)


def consume(snaps):
    rc = Reconstructor()
    for s in snaps:
        feed_all(rc, s)
    rc.finish()
    return rc


def bfake():
    f = BigramFake()
    f.add(10)
    f.add(20)
    f.step_pair(10, "START_ATTACH", "openat")
    f.step_pair(10, "openat", "openat", 3)
    f.step_pair(20, "START_NEW", "execve")
    f.lose_pair(20, "clone")
    return f


def full_table():
    """Every pair the vocabulary allows: (9 syscalls + 4 markers) x 9 = 117."""
    return {(a, b): i + 1 for i, (a, b) in enumerate((a, b) for a in FIRST for b in SYSCALLS)}


# --- schema ----------------------------------------------------------------

def test_schema_pair_elements_are_the_vocabulary_and_markers():
    d = load_schema(SCHEMA_V2_PATH)["$defs"]
    assert BIGRAM_MARKERS == ("START_NEW", "START_ATTACH", "START_LOST", "EXEC")
    assert tuple(d["bigram_first"]["enum"]) == FIRST
    assert tuple(d["bigram_second"]["enum"]) == SYSCALLS            # I-B5: no marker second
    assert d["bpf_bigrams"]["properties"]["pairs"]["maxItems"] == MAX_PAIRS_PER_RECORD == 1024
    health = d["bpf_snapshot_end"]["properties"]["bigram_health"]
    assert tuple(health["required"]) == BIGRAM_HEALTH_FIELDS


def scripted_bigram_stream():
    """ok keyframe, change, exit, reclaim, failed, recovery, drained: every record kind."""
    f = bfake()
    em = BigramStandIn(f, max_items=2)
    out = [step(em)]
    f.step_pair(10, "openat", "execve")
    out.append(step(em))
    f.exit(20)
    out.append(step(em))
    f.reclaim(20)
    out.append(step(em))
    f.fail = True
    out.append(step(em))
    f.fail = False
    em.health["bigram_dropped"] += 1
    em.drain = True
    out.append(step(em))
    return f, out


def test_every_bigram_snapshot_record_is_schema_valid():
    v = Validator()
    _f, snaps = scripted_bigram_stream()
    unavailable = BigramStandIn(bfake(), status="unavailable", err="UNSUPPORTED",
                                reason="bigrams not supported here")
    snaps += [step(unavailable), step(unavailable)]
    seen = set()
    for recs in snaps:
        for r in recs:
            assert v.errors(r) == [], (r["type"], v.errors(r))
            assert line_violations(encode_record(r).encode()) == []
            seen.add(r["type"])
    assert seen == {"bpf_snapshot_begin", "bpf_proc", "bpf_bigrams", "bpf_reclaimed",
                    "bpf_snapshot_end"}


def _fix():
    _f, snaps = scripted_bigram_stream()
    first = snaps[0]
    out = {"begin": first[0], "proc": of(first, "bpf_proc")[0],
           "bigrams": of(first, "bpf_bigrams")[0], "end": first[-1],
           "failed_end": snaps[4][-1]}
    un = step(BigramStandIn(bfake(), status="unavailable", err="UNSUPPORTED", reason="r"))
    out["un_begin"], out["un_proc"], out["un_end"] = un[0], of(un, "bpf_proc")[0], un[-1]
    return out


FIX = _fix()


def _mut(rec, path, value=..., delete=False):
    r = copy.deepcopy(rec)
    node = r
    for k in path[:-1]:
        node = node[k]
    if delete:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return r


SCHEMA_INVALID = [
    _mut(FIX["bigrams"], ["pairs", 0, "b"], "START_NEW"),            # I-B5: marker second
    _mut(FIX["bigrams"], ["pairs", 0, "b"], "EXEC"),
    _mut(FIX["bigrams"], ["pairs", 0, "a"], "read"),                 # not in the vocabulary
    _mut(FIX["bigrams"], ["pairs", 0, "b"], "read"),
    _mut(FIX["bigrams"], ["pairs", 0, "n"], 0),                      # sparse: no zero entries
    _mut(FIX["bigrams"], ["pairs", 0, "n"], U64),                    # above u64
    _mut(FIX["bigrams"], ["pairs", 0, "n"], True),
    _mut(FIX["bigrams"], ["pairs", 0, "extra"], 1),
    _mut(FIX["bigrams"], ["part"], -1),
    _mut(FIX["bigrams"], ["parts"], 0),
    _mut(FIX["bigrams"], ["parts"], delete=True),
    _mut(FIX["bigrams"], ["key"], delete=True),
    _mut(FIX["bigrams"], ["v"], 1),
    _mut(FIX["bigrams"], ["table"], {}),
    _mut(FIX["begin"], ["capabilities", "bigrams", "status"], "partial"),
    _mut(FIX["begin"], ["capabilities", "bigrams", "err"], "EACCES"),
    _mut(FIX["un_begin"], ["capabilities", "bigrams", "err"], "EIO"),  # reserved: no producer path
    _mut(FIX["un_proc"], ["bigrams_err"], "EIO"),
    _mut(FIX["un_proc"], ["bigrams_err"], "EACCES"),
    _mut(FIX["begin"], ["capabilities", "bigrams", "extra"], 1),
    _mut(FIX["begin"], ["capabilities", "bigrams"], delete=False, value={}),
    _mut(FIX["proc"], ["pairs_lost"], -1),
    _mut(FIX["proc"], ["bigrams_err"], "EWHAT"),
    _mut(FIX["end"], ["bigram_records"], -1),
    _mut(FIX["end"], ["drained"], 1),
    _mut(FIX["end"], ["bigram_health", "bigram_dropped"], -1),
    _mut(FIX["end"], ["bigram_health", "extra"], 0),
    _mut(FIX["end"], ["bigram_health", "pre_arm_events"], delete=True),
    _mut(FIX["end"], ["totals", "bigrams", "pairs"], U64),           # totals are mod 2^64
    _mut(FIX["end"], ["totals", "bigrams", "pairs_lost"], delete=True),
]

SEMANTIC_INVALID = [
    _mut(FIX["bigrams"], ["part"], 2),                               # part >= parts
    _mut(_mut(FIX["bigrams"], ["pairs"], []), ["parts"], 2),         # only a 1-part table is empty
    _mut(FIX["bigrams"], ["pairs"], FIX["bigrams"]["pairs"][:1] * 2),  # duplicate pair
    _mut(FIX["proc"], ["bigrams_err"], delete=True),                 # the two fields come together
    _mut(FIX["proc"], ["pairs_lost"], delete=True),
    _mut(FIX["proc"], ["pairs_lost"], None),                         # neither value nor error
    _mut(FIX["proc"], ["bigrams_err"], "UNSUPPORTED"),               # both value and error
    _mut(FIX["begin"], ["capabilities", "bigrams", "err"], "UNSUPPORTED"),  # ok carries no error
    _mut(FIX["begin"], ["capabilities", "bigrams", "reason"], "x"),
    _mut(FIX["begin"], ["capabilities", "bigrams", "epoch"], None),
    _mut(FIX["begin"], ["capabilities", "bigrams", "epoch", "attach_since_mono_ns"], 1),
    _mut(FIX["un_begin"], ["capabilities", "bigrams", "err"], None),  # unavailable needs why
    _mut(FIX["un_begin"], ["capabilities", "bigrams", "reason"], None),
    _mut(FIX["un_begin"], ["capabilities", "bigrams", "epoch"], FIX["begin"]["capabilities"]["counts"]["epoch"]),
    _mut(FIX["end"], ["bigram_records"], delete=True),               # all or none of the fields
    _mut(FIX["end"], ["drained"], delete=True),
    _mut(FIX["end"], ["bigram_health"], delete=True),
    _mut(FIX["end"], ["totals", "bigrams"], delete=True),
    _mut(FIX["end"], ["bigram_health"], None),                       # ok: totals and health together
    _mut(FIX["failed_end"], ["bigram_records"], 1),                  # failed carries no data
    _mut(FIX["failed_end"], ["bigram_health"], FIX["end"]["bigram_health"]),
    _mut(FIX["failed_end"], ["drained"], True),
]


@pytest.mark.parametrize("name", list(FIX))
def test_bigram_fixtures_valid(name):
    assert Validator().errors(FIX[name]) == []


@pytest.mark.parametrize("rec", SCHEMA_INVALID)
def test_bigram_schema_violations_rejected(rec):
    assert Validator().errors(rec)


@pytest.mark.parametrize("rec", SEMANTIC_INVALID)
def test_bigram_semantic_violations_rejected(rec):
    assert Validator().errors(rec)


def test_jsonschema_reference_agrees_on_bigram_records():
    jsonschema = pytest.importorskip("jsonschema")
    js = jsonschema.Draft202012Validator(load_schema(SCHEMA_V2_PATH))
    for rec in FIX.values():
        assert not list(js.iter_errors(rec)), rec["type"]
    for rec in SCHEMA_INVALID:
        assert list(js.iter_errors(rec)), rec


def test_max_items_is_enforced_by_the_stdlib_validator():
    v = Validator()
    pair = {"a": "openat", "b": "openat", "n": 1}
    at = _mut(FIX["bigrams"], ["pairs"], [pair] * MAX_PAIRS_PER_RECORD)
    over = _mut(FIX["bigrams"], ["pairs"], [pair] * (MAX_PAIRS_PER_RECORD + 1))
    assert not any("maxItems" in e for e in v.errors(at))     # (it is a duplicate, though)
    assert any("maxItems" in e for e in v.errors(over))


# --- chunking ----------------------------------------------------------------

def test_chunk_item_limit_boundaries():
    make = lambda c: {"type": "t", "items": c}                   # noqa: E731
    sizes = lambda n: [len(r["items"]) for r in chunk_records(make, list(range(n)),  # noqa: E731
                                                              max_items=1024)]
    assert sizes(1024) == [1024]
    assert sizes(1025) == [1024, 1]
    assert sizes(3000) == [1024, 1024, 952]
    assert sizes(0) == []
    assert [len(r["items"]) for r in chunk_records(make, list(range(10)))] == [10]  # S0 default


def test_byte_limit_still_applies_with_an_item_limit():
    make = lambda c: {"type": "t", "items": c}                   # noqa: E731
    items = ["x" * 100] * 50
    recs = chunk_records(make, items, limit=1000, max_items=1024)
    assert len(recs) > 1 and sum(len(r["items"]) for r in recs) == 50
    assert all(len(encode_record(r, 1000).encode()) <= 1000 for r in recs)


def test_worst_case_full_part_fits_the_byte_rule():
    """1,024 pairs of maximal width, with a maximal key and seq, stay within 65,536 bytes."""
    widest = {"a": max(FIRST, key=len), "b": max(SYSCALLS, key=len), "n": U64_MAX}
    k = {"boot_id": key(1)["boot_id"], "pidns_ino": U64_MAX, "tgid": U64_MAX,
         "start_ticks": U64_MAX}
    rec = {"type": "bpf_bigrams", "v": 2, "seq": U64_MAX, "key": k, "part": U64_MAX - 1,
           "parts": U64_MAX, "pairs": [widest] * MAX_PAIRS_PER_RECORD}
    assert len(encode_record(rec).encode()) <= MAX_RECORD_BYTES


def test_empty_table_is_one_empty_part():
    recs = bigram_parts(3, key(10), {})
    assert [(r["part"], r["parts"], r["pairs"]) for r in recs] == [(0, 1, [])]


def test_parts_are_canonical_sparse_and_complete():
    table = full_table()
    table[("EXEC", "openat")] = 0                                 # a zero entry is not a pair
    recs = bigram_parts(7, key(10), table)
    assert len(recs) == 1 and recs[0]["parts"] == 1
    pairs = recs[0]["pairs"]
    assert len(pairs) == 116
    order = [(FIRST.index(p["a"]), SYSCALLS.index(p["b"])) for p in pairs]
    assert order == sorted(order)
    assert {(p["a"], p["b"]): p["n"] for p in pairs} == {k: v for k, v in table.items() if v}


@pytest.mark.parametrize("max_items,limit", [(10, MAX_RECORD_BYTES), (1024, 400), (5, 300)])
def test_multi_part_tables_reassemble_exactly(max_items, limit):
    table = full_table()
    recs = bigram_parts(9, key(10), table, limit=limit, max_items=max_items)
    assert len(recs) >= 10                                         # part numbers of 2 digits
    assert [r["part"] for r in recs] == list(range(len(recs)))
    assert {r["parts"] for r in recs} == {len(recs)}
    v = Validator()
    for r in recs:
        assert len(r["pairs"]) <= max_items
        assert len(encode_record(r, limit).encode()) <= limit
        assert v.errors(r) == []
    assert {(p["a"], p["b"]): p["n"] for r in recs for p in r["pairs"]} == table


@pytest.mark.parametrize("pair", [("openat", "START_NEW"), ("openat", "EXEC"), ("read", "openat"),
                                  ("openat", "read")])
def test_bigram_parts_refuse_pairs_outside_the_vocabulary(pair):
    with pytest.raises(ValueError):
        bigram_parts(0, key(10), {pair: 1})


def test_a_part_that_cannot_fit_is_refused():
    with pytest.raises(RecordTooLarge):
        bigram_parts(0, key(10), {("openat", "openat"): 1}, limit=100)


# --- reconstruction ------------------------------------------------------------

def bigram_scenario(n=130, seed=11, max_items=None):
    """Random but reproducible churn with pairs; yields (records, truth, pair truth)."""
    rnd = random.Random(seed)
    fake = BigramFake()
    em = BigramStandIn(fake, run_id="run-br", max_items=max_items)
    nxt, out = 100, []
    for _ in range(n):
        for t in list(fake.procs):
            p = fake.procs[t]
            if p["exited"] and rnd.random() < 0.7:
                fake.reclaim(t)
            elif not p["exited"] and rnd.random() < 0.1:
                fake.exit(t)
            elif not p["exited"] and rnd.random() < 0.5:
                if rnd.random() < 0.2:
                    fake.lose_pair(t, rnd.choice(SYSCALLS))
                else:
                    fake.step_pair(t, rnd.choice(FIRST), rnd.choice(SYSCALLS), rnd.randint(1, 5))
        for _ in range(rnd.randint(0, 3)):
            fake.add(nxt)
            fake.step_pair(nxt, rnd.choice(BIGRAM_MARKERS), "openat")
            nxt += 1
        out.append((step(em), copy.deepcopy(bigram_state_truth(fake)),
                    copy.deepcopy(pair_truth(fake))))
    return out


@pytest.mark.parametrize("max_items", [None, 3])
def test_reconstruction_matches_truth_including_pair_tables(max_items):
    rc = Reconstructor()
    v = Validator()
    multipart = False
    for recs, want, want_pairs in bigram_scenario(max_items=max_items):
        feed_all(rc, recs)
        assert rc.valid and rc.last.status == "ok"
        assert rc.state == want and rc.pairs == want_pairs
        emitted = {key_tuple(p["key"]) for p in of(recs, "bpf_proc")}
        assert {key_tuple(b["key"]) for b in of(recs, "bpf_bigrams")} == emitted
        multipart |= any(b["parts"] > 1 for b in of(recs, "bpf_bigrams"))
        for r in recs:
            assert v.errors(r) == []
    assert multipart == (max_items is not None)
    assert rc.stats["invalidations"] == 0 and rc.stats["snapshots_incomplete"] == 0


def test_an_emitted_table_replaces_the_old_one():
    f = bfake()
    em = BigramStandIn(f)
    rc = Reconstructor()
    feed_all(rc, step(em))
    f.pairs[10] = {("EXEC", "openat"): 5}                         # replaced, not merged (D2)
    f.bump(10)
    feed_all(rc, step(em))
    assert rc.valid and rc.pairs[key_tuple(key(10))] == {("EXEC", "openat"): 5}


def test_reclaim_removes_the_pair_table():
    f = bfake()
    em = BigramStandIn(f)
    rc = Reconstructor()
    feed_all(rc, step(em))
    f.exit(20)
    feed_all(rc, step(em))
    f.reclaim(20)
    feed_all(rc, step(em))
    assert rc.valid and set(rc.pairs) == {key_tuple(key(10))} == set(rc.state)


def multipart_stream(n=4):
    """Process 10 has a 3-part table, 20 a 1-part one; both change, so both are
    emitted in every snapshot."""
    f = BigramFake()
    f.add(10)
    f.add(20)
    for i, b in enumerate(("openat", "execve", "clone", "fork", "vfork", "openat2")):
        f.step_pair(10, "openat", b, i + 1)
    f.step_pair(20, "START_NEW", "openat")
    em = BigramStandIn(f, max_items=2, run_id="run-mp")
    snaps = []
    for _ in range(n):
        f.step_pair(10, "openat", "openat")
        f.step_pair(20, "openat", "openat")
        snaps.append(step(em))
    return snaps


def parts_of(recs, tgid=10):
    return [i for i, r in enumerate(recs) if r["type"] == "bpf_bigrams" and r["key"]["tgid"] == tgid]


def _recount(recs):
    """Keeps end.bigram_records consistent, so only the part sequence is wrong."""
    recs[-1]["bigram_records"] = sum(1 for r in recs if r["type"] == "bpf_bigrams")


def _drop_middle(recs):
    del recs[parts_of(recs)[1]]
    _recount(recs)


def _drop_last(recs):
    del recs[parts_of(recs)[-1]]
    _recount(recs)


def _swap(recs):
    i, j = parts_of(recs)[:2]
    recs[i], recs[j] = recs[j], recs[i]


def _duplicate(recs):
    i = parts_of(recs)[0]
    recs.insert(i + 1, copy.deepcopy(recs[i]))
    _recount(recs)


def _inconsistent_parts(recs):
    recs[parts_of(recs)[1]]["parts"] = 4


def _interleave(recs):
    i = parts_of(recs)[1]
    j = parts_of(recs, 20)[0]
    recs.insert(i, recs.pop(j))


def _orphan_table(recs):
    p = [r for r in recs if r["type"] == "bpf_proc" and r["key"]["tgid"] == 20][0]
    recs.remove(p)
    recs[-1]["procs_emitted"] -= 1


def _missing_table(recs):
    for i in reversed(parts_of(recs, 20)):
        del recs[i]
    recs[-1]["bigram_records"] -= 1


def _dup_pair_across_parts(recs):
    a, b = parts_of(recs)[:2]
    recs[b]["pairs"][0] = dict(recs[a]["pairs"][0])


def _bigrams_before_proc(recs):
    i = parts_of(recs)[0]
    recs.insert(1, recs.pop(i))


def _bigrams_after_reclaimed(recs):
    part = recs.pop(parts_of(recs)[-1])
    recs.insert(len(recs) - 1, {"type": "bpf_reclaimed", "v": 2, "seq": recs[0]["seq"],
                                "reason": "vanished", "keys": [key(999)]})
    recs.insert(len(recs) - 1, part)


def _wrong_seq(recs):
    recs[parts_of(recs)[1]]["seq"] += 1


def _wrong_record_count(recs):
    recs[-1]["bigram_records"] += 1


TAMPER = [_drop_middle, _drop_last, _swap, _duplicate, _inconsistent_parts, _interleave,
          _orphan_table, _missing_table, _dup_pair_across_parts, _bigrams_before_proc,
          _bigrams_after_reclaimed, _wrong_seq, _wrong_record_count]


def test_multipart_fixture_is_clean():
    snaps = multipart_stream()
    assert all(len(parts_of(s)) == 3 and len(parts_of(s, 20)) == 1 for s in snaps)
    rc = consume(snaps)                                            # (6 pairs at 2 per part)
    assert rc.valid and rc.stats["snapshots_complete"] == 4


@pytest.mark.parametrize("tamper", TAMPER, ids=[t.__name__.strip("_") for t in TAMPER])
def test_damaged_bigram_parts_reject_the_snapshot(tamper):
    snaps = multipart_stream()
    tamper(snaps[2])
    rc = Reconstructor()
    feed_all(rc, snaps[0])
    feed_all(rc, snaps[1])
    before = copy.deepcopy(rc.pairs)
    feed_all(rc, snaps[2])
    rc.finish()
    assert rc.stats["snapshots_incomplete"] == 1 and not rc.valid
    assert rc.pairs == {} and rc.state == {}                      # nothing of it applied
    assert before                                                  # (state existed before)
    feed_all(rc, snaps[3])                                         # not a keyframe: stays invalid
    assert not rc.valid


@pytest.mark.parametrize("tamper,why", [(_drop_middle, "part 2/3 where 1/3"),
                                        (_drop_last, "2 of 3 parts"),
                                        (_duplicate, "part 0/3 where 1/3")])
def test_part_sequence_is_checked_on_its_own(tamper, why):
    snaps = multipart_stream()
    tamper(snaps[2])
    end = snaps[2][-1]
    assert end["bigram_records"] == len(of(snaps[2], "bpf_bigrams"))   # record count consistent
    rc = consume(snaps[:3])
    assert rc.stats["snapshots_incomplete"] == 1 and not rc.valid
    rejection = [e for e in rc.errors if "rejected" in e]
    assert len(rejection) == 1 and why in rejection[0]
    assert "bigram_records" not in rejection[0]


@pytest.mark.parametrize("bad", [[], "x", 7, None])
def test_malformed_capabilities_reject_the_snapshot_without_raising(bad):
    fake = FakeCollector()
    fake.add(10, openat=1)
    recs = step(V2Emitter(fake, run_id="run-m"))
    recs[0]["capabilities"] = bad
    rc = Reconstructor()
    feed_all(rc, recs)                                             # must not raise
    assert rc.stats["snapshots_incomplete"] == 1 and not rc.valid


def test_state_is_rebuilt_with_tables_at_the_next_keyframe():
    scen = bigram_scenario(n=125)
    rc = Reconstructor()
    for i, (recs, want, want_pairs) in enumerate(scen):
        if i == 30:                                                # lose one bigram part
            first = of(recs, "bpf_bigrams")
            assert first
            del recs[parts_of(recs, first[0]["key"]["tgid"])[0]]
        feed_all(rc, recs)
        if 30 <= i < 60:
            assert not rc.valid
        if i >= 60:
            assert rc.valid and rc.state == want and rc.pairs == want_pairs


def _stream(n=3, **kw):
    f = bfake()
    em = BigramStandIn(f, **kw)
    snaps = []
    for _ in range(n):
        f.step_pair(10, "openat", "openat")
        snaps.append(step(em))
    return f, em, snaps


@pytest.mark.parametrize("field", ["pairs", "pairs_lost"])
def test_wrong_bigram_totals_invalidate(field):
    _f, _e, snaps = _stream()
    snaps[1][-1]["totals"]["bigrams"][field] += 1
    rc = consume(snaps)
    assert rc.stats["totals_mismatch"] == 1 and not rc.valid


def test_wrong_pairs_lost_in_a_proc_record_is_a_totals_mismatch():
    _f, _e, snaps = _stream()
    of(snaps[1], "bpf_proc")[0]["pairs_lost"] += 1
    rc = consume(snaps)
    assert rc.stats["totals_mismatch"] == 1 and not rc.valid


def _set(path, value):
    def apply(recs):
        node = recs
        for k in path[:-1]:
            node = node[k]
        node[path[-1]] = value
    return apply


INCONSISTENT = {
    "bigram_epoch_differs": _set([0, "capabilities", "bigrams", "epoch", "attach_since_mono_ns"], 1),
    "proc_pairs_lost_null_while_ok": lambda r: of(r, "bpf_proc")[0].update(
        pairs_lost=None, bigrams_err="UNSUPPORTED"),
    "proc_lacks_bigram_fields": lambda r: [of(r, "bpf_proc")[0].pop(k) for k in
                                           ("pairs_lost", "bigrams_err")],
    "end_lacks_bigram_fields": lambda r: [r[-1].pop(k) for k in
                                          ("bigram_records", "bigram_health", "drained")],
    "end_lacks_bigram_totals": lambda r: r[-1]["totals"].pop("bigrams"),
    "ok_without_bigram_health": _set([-1, "bigram_health"], None),
}


@pytest.mark.parametrize("name", list(INCONSISTENT))
def test_inconsistent_bigram_metadata_rejects_the_snapshot(name):
    _f, _e, snaps = _stream()
    INCONSISTENT[name](snaps[1])
    rc = consume(snaps)
    assert rc.stats["snapshots_incomplete"] == 1 and not rc.valid


def test_capability_change_within_an_epoch_invalidates():
    f = bfake()
    em = BigramStandIn(f)
    snaps = [step(em), step(em)]
    em.status, em.err, em.reason = "unavailable", "UNSUPPORTED", "capability lost mid-epoch"
    snaps.append(step(em))
    rc = consume(snaps)
    assert rc.stats["invalidations"] == 1 and not rc.valid


def test_capability_added_within_an_epoch_invalidates():
    f = bfake()
    em = BigramStandIn(f)
    s0 = step(em)
    s0 = [r for r in s0 if r["type"] != "bpf_bigrams"]
    del s0[0]["capabilities"]["bigrams"]
    for r in s0:
        for k in ("pairs_lost", "bigrams_err", "bigram_records", "bigram_health", "drained"):
            r.pop(k, None)
    s0[-1]["totals"].pop("bigrams")
    rc = consume([s0, step(em)])
    assert rc.stats["snapshots_complete"] == 2
    assert rc.stats["invalidations"] == 1 and not rc.valid


def test_counts_only_snapshot_with_bigram_fields_is_rejected():
    fake = FakeCollector()
    fake.add(10, openat=1)
    em = V2Emitter(fake, run_id="run-c")
    good = step(em)
    for tamper in (lambda r: r[-1].update(drained=False),
                   lambda r: r[1].update(pairs_lost=0, bigrams_err=None),
                   lambda r: r[-1]["totals"].update(bigrams={"pairs": 0, "pairs_lost": 0}),
                   lambda r: r.insert(2, bigram_parts(r[0]["seq"], key(10), {})[0])):
        recs = copy.deepcopy(good)
        tamper(recs)
        rc = consume([recs])
        assert rc.stats["snapshots_incomplete"] == 1 and not rc.valid


def test_unavailable_capability_is_null_never_zero():
    f = bfake()
    em = BigramStandIn(f, status="unavailable", err="UNSUPPORTED", reason="no kernel support")
    rc = Reconstructor()
    for _ in range(3):
        f.step_pair(10, "openat", "openat")
        recs = step(em)
        assert of(recs, "bpf_bigrams") == []
        assert all(p["pairs_lost"] is None and p["bigrams_err"] == "UNSUPPORTED"
                   for p in of(recs, "bpf_proc"))
        end = recs[-1]
        assert end["totals"]["bigrams"] is None and end["bigram_health"] is None
        assert end["bigram_records"] == 0
        feed_all(rc, recs)
    assert rc.valid and rc.pairs == {}
    assert {k: p["counts"] for k, p in rc.state.items()} == \
        {k: p["counts"] for k, p in truth(f).items()}
    assert all(p["pairs_lost"] is None for p in rc.state.values())
    assert rc.last.pair_loss_possible is None


def test_unavailable_capability_must_not_carry_tables():
    f = bfake()
    em = BigramStandIn(f, status="unavailable", err="UNSUPPORTED", reason="r")
    recs = step(em)
    part = bigram_parts(recs[0]["seq"], key(10), {})[0]
    recs.insert(3, part)
    recs[-1]["bigram_records"] = 1
    rc = consume([recs])
    assert rc.stats["snapshots_incomplete"] == 1 and not rc.valid


def test_failed_snapshot_keeps_tables_and_checks_their_totals():
    f, em, snaps = _stream(2)
    rc = consume(snaps)
    tables = copy.deepcopy(rc.pairs)
    f.step_pair(10, "openat", "execve")
    f.fail = True
    failed = step(em)
    assert kinds(failed) == ["bpf_snapshot_begin", "bpf_snapshot_end"]
    feed_all(rc, failed)
    assert rc.valid and rc.last.status == "failed" and rc.pairs == tables
    f.fail = False
    feed_all(rc, step(em))
    assert rc.valid and rc.pairs == pair_truth(f)
    bad = copy.deepcopy(failed)
    bad[-1]["totals"]["bigrams"]["pairs"] += 1
    rc2 = consume(snaps + [bad])
    assert rc2.stats["totals_mismatch"] == 1 and not rc2.valid


def test_drained_snapshot_is_marked_and_ends_its_epoch():
    f, em, snaps = _stream(2)
    em.drain = True
    drained = step(em)
    assert drained[-1]["drained"] is True
    rc = consume(snaps + [drained])
    assert rc.valid and rc.last.drained is True
    em.drain = False
    feed_all(rc, step(em))                                         # same epoch after the drain
    assert rc.stats["snapshots_after_drain"] == 1 and not rc.valid


def test_new_epoch_after_a_drain_is_accepted():
    _f, em, snaps = _stream(2)
    em.drain = True
    snaps.append(step(em))
    f2 = bfake()
    f2.attached_since = 5555
    snaps.append(step(BigramStandIn(f2, run_id="run-next")))
    rc = consume(snaps)
    assert rc.valid and rc.stats["snapshots_after_drain"] == 0
    assert rc.stats["epoch_changes"] == 1 and rc.pairs == pair_truth(f2)


def test_pair_loss_possible_follows_bigram_dropped():
    _f, em, snaps = _stream(2)
    rc = consume(snaps)
    assert rc.last.pair_loss_possible is False
    em.health["bigram_dropped"] += 1
    feed_all(rc, step(em))
    assert rc.last.pair_loss_possible is True
    feed_all(rc, step(em))
    assert rc.last.pair_loss_possible is False
    assert rc.last.loss_possible is False                          # counts loss is separate


def test_bigram_totals_wrap_mod_2_64():
    t = bigram_totals([{"pairs_lost": U64_MAX}, {"pairs_lost": 2}],
                      [{("openat", "openat"): U64_MAX}, {("EXEC", "openat"): 3}])
    assert t == {"pairs": 2, "pairs_lost": 1}


# --- compatibility with S0 / counts-only telemetry -------------------------------

S0_FIELDS = {
    "bpf_snapshot_begin": {"type", "v", "seq", "t_mono_ns", "interval_ns", "resource_seq",
                           "keyframe", "calibration", "capabilities"},
    "bpf_proc": {"type", "v", "seq", "key", "host_tgid", "level", "container_pid", "comm",
                 "container", "counts", "exited"},
    "bpf_reclaimed": {"type", "v", "seq", "reason", "keys"},
    "bpf_snapshot_end": {"type", "v", "seq", "t_mono_ns", "status", "reason", "procs_emitted",
                         "reclaimed_records", "reclaimed_keys", "tracked", "totals", "loss",
                         "health", "read_err"},
}


def test_counts_only_records_keep_the_exact_s0_shape():
    fake = FakeCollector()
    fake.add(10, openat=1)
    fake.add(20, openat=1)
    em = V2Emitter(fake, run_id="run-s0")
    rc = Reconstructor()
    v = Validator()
    for i in range(5):
        if i == 2:
            fake.exit(20)
        if i == 3:
            fake.reclaim(20)
        fake.fail = i == 4
        for r in step(em):
            assert set(r) == S0_FIELDS[r["type"]]
            assert v.errors(r) == []
            if r["type"] == "bpf_snapshot_begin":
                assert set(r["capabilities"]) == {"counts"}
            if r["type"] == "bpf_snapshot_end":
                assert set(r["totals"]) == {"counts"}
            rc.feed(r)
    assert rc.valid and rc.pairs == {} and rc.last.drained is False
    assert rc.last.pair_loss_possible is None


def test_counts_only_and_bigram_streams_reconstruct_the_same_process_state():
    f1, f2 = bfake(), bfake()
    plain, rich = V2Emitter(f1, run_id="same"), BigramStandIn(f2, run_id="same")
    r1, r2 = Reconstructor(), Reconstructor()
    for i in range(6):
        for f in (f1, f2):
            f.step_pair(10, "openat", "openat", i + 1)
        feed_all(r1, step(plain))
        feed_all(r2, step(rich))
        strip = {k: {f: x for f, x in p.items() if f not in ("pairs_lost", "bigrams_err")}
                 for k, p in r2.state.items()}
        assert r1.valid and r2.valid and r1.state == strip
    assert json.dumps(r1.stats, sort_keys=True) == json.dumps(r2.stats, sort_keys=True)
