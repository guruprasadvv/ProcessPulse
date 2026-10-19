"""Adversarial checks of the bpf_bigrams size limits (S2.6 verification).

The byte rule (docs/telemetry-v2.md §1, CLAUDE.md §5): a record, i.e. its
UTF-8 bytes WITHOUT the terminating LF, is 1..65,536 bytes; the line written
is the record plus one LF. Items per bpf_bigrams record: at most 1,024. Every
check below measures the final serialization (processpulse.jsonl.
encode_record, the function the agent writes with), never an estimate.
"""

import json
import random

import pytest

from processpulse.jsonl import MAX_RECORD_BYTES, RecordTooLarge, encode_record, line_violations
from processpulse.snapshots import (BIGRAM_MARKERS, MAX_PAIRS_PER_RECORD, V2Emitter, bigram_parts,
                                    chunk_records)
from processpulse.vocab import SYSCALLS
from snapshot_fakes import BigramCollectorFake, key

U64_MAX = (1 << 64) - 1
FIRST = SYSCALLS + BIGRAM_MARKERS


def nbytes(rec):
    return len(encode_record(rec, limit=1 << 30).encode("utf-8"))


def full_table(seed=3):
    rnd = random.Random(seed)
    return {(a, b): rnd.choice([1, 9, 10 ** 6, U64_MAX]) for a in FIRST for b in SYSCALLS}


def sized(rec, table):
    """The record as bigram_parts sizes it: part and parts replaced by a
    placeholder as wide as the pair count (docs/telemetry-v2.md §8.3), so that
    filling in the real numbers can only shrink it."""
    width = max(sum(1 for n in table.values() if n), 1)
    return dict(rec, part=width, parts=width)


def check_parts(recs, table, limit, max_items):
    """Every part within both limits, contiguous, exact union, and maximal under
    the documented sizing: a part (but the last) could not have taken the next pair."""
    assert [r["part"] for r in recs] == list(range(len(recs)))
    assert {r["parts"] for r in recs} == {len(recs)}
    for i, r in enumerate(recs):
        assert len(r["pairs"]) <= max_items
        size = nbytes(r)
        assert size <= nbytes(sized(r, table)) <= limit, (i, size, limit)
        assert line_violations(encode_record(r, limit).encode()) == []
        if i + 1 < len(recs):
            nxt = recs[i + 1]["pairs"][0]
            grown = sized(dict(r, pairs=r["pairs"] + [nxt]), table)
            assert len(grown["pairs"]) > max_items or nbytes(grown) > limit, i
    assert {(p["a"], p["b"]): p["n"] for r in recs for p in r["pairs"]} == table


def test_exhaustive_limit_sweep_on_the_largest_possible_table():
    table = full_table()                                             # all 117 pairs, wide counts
    single = nbytes(bigram_parts(7, key(10), table)[0])
    smallest = max(nbytes(sized(r, table)) for r in bigram_parts(7, key(10), table, max_items=1))
    with pytest.raises(RecordTooLarge):                              # below it: refused, not cut
        bigram_parts(7, key(10), table, limit=smallest - 1)
    for limit in range(smallest, single + 2):
        for max_items in (MAX_PAIRS_PER_RECORD, 7):
            check_parts(bigram_parts(7, key(10), table, limit=limit, max_items=max_items),
                        table, limit, max_items)


def test_a_part_of_exactly_the_limit_is_kept_and_one_byte_less_splits_it():
    table = full_table()
    (whole,) = bigram_parts(7, key(10), table)
    exact = nbytes(sized(whole, table))
    assert len(bigram_parts(7, key(10), table, limit=exact)) == 1
    assert len(bigram_parts(7, key(10), table, limit=exact - 1)) == 2
    # The placeholder costs at most a few bytes of slack, never an oversize record.
    assert 0 <= exact - nbytes(whole) <= 2 * (len(str(len(table))) - 1)


def test_the_1024_pair_boundary_with_real_part_records():
    """A vocabulary table has at most 117 pairs, so the 1,024 boundary is driven
    with the producer's own make() through chunk_records (duplicates allowed here)."""
    widest = {"a": max(FIRST, key=len), "b": max(SYSCALLS, key=len), "n": U64_MAX}
    k = dict(key(10), pidns_ino=U64_MAX, tgid=U64_MAX, start_ticks=U64_MAX)

    def make(ps):
        return {"type": "bpf_bigrams", "v": 2, "seq": U64_MAX, "key": k, "part": U64_MAX,
                "parts": U64_MAX, "pairs": ps}
    for n, want in ((1024, [1024]), (1025, [1024, 1]), (2048, [1024, 1024])):
        recs = chunk_records(make, [widest] * n, max_items=MAX_PAIRS_PER_RECORD)
        assert [len(r["pairs"]) for r in recs] == want
        assert all(nbytes(r) <= MAX_RECORD_BYTES for r in recs)


def test_worst_case_part_leaves_room_for_the_line_terminator():
    """The widest possible full part, measured; reported with its margin."""
    widest = {"a": max(FIRST, key=len), "b": max(SYSCALLS, key=len), "n": U64_MAX}
    k = dict(key(10), pidns_ino=U64_MAX, tgid=U64_MAX, start_ticks=U64_MAX)
    rec = {"type": "bpf_bigrams", "v": 2, "seq": U64_MAX, "key": k, "part": U64_MAX - 1,
           "parts": U64_MAX, "pairs": [widest] * MAX_PAIRS_PER_RECORD}
    size = nbytes(rec)
    print(f"worst-case bpf_bigrams record: {size} bytes, line with LF: {size + 1}")
    assert size + 1 <= MAX_RECORD_BYTES                              # even counting the LF


@pytest.mark.parametrize("text", ["é" * 50, "  " * 30, '"\\' * 40, "\x01\x1f\n\r" * 20,
                                  "\U0001F600" * 25, "plain" * 20])
def test_escaping_and_unicode_overhead_is_measured_on_the_final_bytes(text):
    """chunk_records sizes items as JSON; the final record is ASCII JSON with
    \\u escapes, so non-ASCII and control characters cost up to 12 bytes each.
    Every record must still be within the limit, and no raw CR/LF may appear."""
    make = lambda c: {"type": "t", "k": "ключ", "items": c}          # noqa: E731
    items = [text[: i % len(text) + 1] for i in range(60)]
    smallest = max(nbytes(make([it])) for it in items)
    for limit in range(smallest, smallest + 400, 7):
        recs = chunk_records(make, items, limit=limit)
        assert sum(len(r["items"]) for r in recs) == len(items)
        for r in recs:
            raw = encode_record(r, limit).encode("utf-8")
            assert len(raw) <= limit and line_violations(raw, limit) == []
            assert raw.isascii()


def test_an_item_that_cannot_fit_is_refused_not_truncated():
    make = lambda c: {"type": "t", "items": c}                       # noqa: E731
    with pytest.raises(RecordTooLarge):
        chunk_records(make, ["x" * 200], limit=100)
    with pytest.raises(RecordTooLarge):
        bigram_parts(0, key(10), {("openat", "openat"): 1}, limit=100)


def test_an_unfittable_part_in_the_emitter_aborts_loudly_and_changes_nothing():
    """With a limit too small for one pair the emitter raises instead of writing a
    truncated or oversize line; the committed state is untouched."""
    f = BigramCollectorFake()
    f.add(10)
    f.step_pair(10, "START_NEW", "execve")
    em = V2Emitter(f, run_id="r", bigrams="ok", limit=150)
    with pytest.raises(RecordTooLarge):
        em.build()
    assert em.live == {} and em.tables == {}


def test_escaped_comm_in_bpf_proc_stays_within_the_rule():
    f = BigramCollectorFake()
    f.add(10)
    f.procs[10]["comm"] = ' "\\\x01é\U0001F600' * 3
    f.step_pair(10, "START_NEW", "execve")
    recs, _ = V2Emitter(f, run_id="r", bigrams="ok").build()
    for r in recs:
        raw = encode_record(r).encode("utf-8")
        assert raw.isascii() and line_violations(raw) == []
        assert json.loads(raw) == r
