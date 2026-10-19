"""Schema v2 (BPF snapshot protocol records) and versioned validator dispatch.

The v1 schema is frozen: its bytes are pinned, and the definitions v2 copies
from it must stay identical.
"""

import copy
import hashlib

import pytest

from processpulse.snapshots import V2Emitter
from processpulse.validate import (RECORD_TYPES, RECORD_TYPES_V2, SCHEMA_PATH, SCHEMA_V2_PATH,
                                   Validator, load_schema)
from snapshot_fakes import FakeCollector

V1_SHA256 = "770913bfd5ec1e6d266f228b520e66936766d320b3194370933a9d12fda5a20c"
U64_MAX = (1 << 64) - 1


def _fixtures():
    fake = FakeCollector()
    fake.add(10, openat=1)
    fake.add(20, openat=2, level=3)
    em = V2Emitter(fake, run_id="run-s")
    out = {}
    recs, done = em.build(resource_seq=0)
    done()
    out["begin"], out["proc"], out["proc_container"], out["end"] = recs
    fake.exit(20)
    em.build()[1]()
    fake.reclaim(20)
    recs, done = em.build()
    done()
    out["reclaimed"] = next(r for r in recs if r["type"] == "bpf_reclaimed")
    fake.fail = True
    out["failed_end"] = em.build()[0][-1]
    return out


FIX = _fixtures()


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


VALID = list(FIX.values())

INVALID = [
    _mut(FIX["begin"], ["v"], 1),                                   # v2 type, wrong version
    _mut(FIX["begin"], ["keyframe"], 1),                            # boolean required
    _mut(FIX["begin"], ["capabilities", "counts", "status"], "unavailable"),  # not in S0
    _mut(FIX["begin"], ["capabilities", "bigrams"], {}),            # incomplete bigrams entry (S2)
    _mut(FIX["begin"], ["capabilities", "priv"], {}),               # no other capability
    _mut(FIX["begin"], ["calibration", "boot_id"], "x"),
    _mut(FIX["proc"], ["counts", "openat"], -1),
    _mut(FIX["proc"], ["counts", "openat"], U64_MAX + 1),           # above u64
    _mut(FIX["proc"], ["procs"], []),                               # v1 field is not allowed
    _mut(FIX["proc"], ["exited"], delete=True),
    _mut(FIX["reclaimed"], ["reason"], "gone"),
    _mut(FIX["reclaimed"], ["keys", 0, "tgid"], 0),
    _mut(FIX["end"], ["status"], "partial"),
    _mut(FIX["end"], ["totals", "counts", "openat"], U64_MAX + 1),  # totals are mod 2^64
    _mut(FIX["end"], ["loss", "vanished_entries"], -1),
    _mut(FIX["end"], ["health", "extra"], 0),
    _mut(FIX["end"], ["read_err"], "EWHAT"),
]

SEMANTIC_INVALID = [
    _mut(FIX["end"], ["reason"], "why"),                            # ok carries no reason
    _mut(FIX["end"], ["loss"], None),                               # ok needs loss/health
    _mut(FIX["end"], ["read_err"], "EIO"),
    _mut(FIX["failed_end"], ["reason"], None),                      # failed needs a reason
    _mut(FIX["failed_end"], ["procs_emitted"], 1),                  # failed carries no data
    _mut(FIX["failed_end"], ["reclaimed_keys"], 1),
    _mut(FIX["failed_end"], ["loss"], FIX["end"]["loss"]),
    _mut(FIX["failed_end"], ["read_err"], None),
    _mut(FIX["reclaimed"], ["keys"], []),                           # empty chunk
]


def test_v1_schema_file_is_unchanged():
    with open(SCHEMA_PATH, "rb") as f:
        assert hashlib.sha256(f.read()).hexdigest() == V1_SHA256


def test_v2_declares_every_v2_type():
    schema = load_schema(SCHEMA_V2_PATH)
    assert set(RECORD_TYPES_V2) <= set(schema["$defs"])
    assert len(schema["oneOf"]) == len(RECORD_TYPES_V2)
    assert not set(RECORD_TYPES) & set(RECORD_TYPES_V2)


@pytest.mark.parametrize("name", ["process_key", "container_identity", "syscall_counts",
                                  "boot_id", "mono_ns", "u64_or_null", "err_or_null"])
def test_definitions_copied_from_v1_are_identical(name):
    assert load_schema(SCHEMA_V2_PATH)["$defs"][name] == load_schema()["$defs"][name]


@pytest.mark.parametrize("rec", VALID, ids=list(FIX))
def test_valid_v2_fixtures(rec):
    assert Validator().errors(rec) == []


@pytest.mark.parametrize("rec", INVALID)
def test_invalid_v2_fixtures_rejected(rec):
    assert Validator().errors(rec)


@pytest.mark.parametrize("rec", SEMANTIC_INVALID)
def test_semantic_v2_violations_rejected(rec):
    assert Validator().errors(rec)


def test_dispatch_is_by_type_and_version():
    v = Validator()
    assert v.errors(dict(FIX["proc"], v=1))                         # v2 type labelled v1
    from test_schemas import SNAPSHOT
    assert v.errors(dict(SNAPSHOT, v=2))                            # v1 type labelled v2
    assert v.errors(SNAPSHOT) == []                                 # v1 still validates


def test_maximum_keyword_supported():
    v = Validator()
    assert v.errors(_mut(FIX["proc"], ["counts", "openat"], U64_MAX)) == []
    assert v.errors(_mut(FIX["proc"], ["counts", "openat"], U64_MAX + 1))


def test_jsonschema_reference_agrees_on_v2():
    jsonschema = pytest.importorskip("jsonschema")
    js = jsonschema.Draft202012Validator(load_schema(SCHEMA_V2_PATH))
    for rec in VALID:
        assert not list(js.iter_errors(rec)), rec["type"]
    for rec in INVALID:
        assert list(js.iter_errors(rec)), rec
