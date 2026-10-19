"""End-to-end tests of the telemetry agent."""

import json
import os

import pytest

from processpulse.agent import Agent
from processpulse.validate import Validator

pytestmark = pytest.mark.integration


def load(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def test_resource_only_run(tmp_path, collector_bin):
    m = Agent(str(tmp_path), interval_ms=200, duration_s=1.5, use_bpf=False,
              collector=collector_bin).run()
    v = Validator()
    res = load(tmp_path / "resource.jsonl")
    health = load(tmp_path / "health.jsonl")
    assert m["counts"]["samples"] >= 3
    assert all(v.errors(r) == [] for r in res + health)
    assert all(h["syscall"] == {"available": False, "reason": "disabled (--no-bpf)"} for h in health)
    assert os.path.getsize(tmp_path / "syscall.jsonl") == 0
    assert m["resource_stats"]["schema_errors"] == 0


def _raw_lines(path):
    with open(path, "rb") as f:
        return f.read().split(b"\n")[:-1]


def test_resource_only_run_schema2(tmp_path, collector_bin):
    from processpulse.jsonl import line_violations
    m = Agent(str(tmp_path), interval_ms=200, duration_s=1.5, use_bpf=False,
              collector=collector_bin, schema=2).run()
    assert m["output_schema"] == {"resource": 1, "health": 1, "bpf": 2}
    assert os.path.getsize(tmp_path / "bpf.jsonl") == 0
    assert not os.path.exists(tmp_path / "syscall.jsonl")
    v = Validator()
    for name in ("resource.jsonl", "health.jsonl"):
        for raw in _raw_lines(tmp_path / name):
            assert line_violations(raw) == []
            assert v.errors(json.loads(raw)) == []


def test_schema1_manifest_is_unchanged(tmp_path, collector_bin):
    m = Agent(str(tmp_path), interval_ms=200, duration_s=0.5, use_bpf=False,
              collector=collector_bin).run()
    assert "output_schema" not in m and os.path.exists(tmp_path / "syscall.jsonl")


def test_unknown_schema_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Agent(str(tmp_path), schema=3)


@pytest.mark.privileged
@pytest.mark.bpf
def test_full_run_schema2_is_framed_and_reconstructs(tmp_path, collector_bin):
    from processpulse.jsonl import line_violations
    from processpulse.snapshots import Reconstructor
    m = Agent(str(tmp_path), interval_ms=200, duration_s=2.0, use_bpf=True,
              collector=collector_bin, schema=2).run()
    assert m["syscall_stream"] == {"available": True, "reason": None}
    v = Validator()
    raws = {n: _raw_lines(tmp_path / n) for n in ("resource.jsonl", "bpf.jsonl", "health.jsonl")}
    for name, lines in raws.items():
        for raw in lines:
            assert line_violations(raw) == [], name
            assert v.errors(json.loads(raw)) == [], name
    bpf = [json.loads(r) for r in raws["bpf.jsonl"]]
    res = [json.loads(r) for r in raws["resource.jsonl"]]
    rc = Reconstructor()
    for r in bpf:
        rc.feed(r)
    rc.finish()
    assert rc.valid and rc.stats["snapshots_incomplete"] == 0 and rc.stats["invalidations"] == 0
    begins = [r for r in bpf if r["type"] == "bpf_snapshot_begin"]
    ends = [r for r in res if r["type"] == "sample_end"]
    assert begins[0]["seq"] == 0 and begins[0]["keyframe"] is True
    assert [b["resource_seq"] for b in begins] == [e["seq"] for e in ends] == list(range(len(ends)))
    assert len(ends) == m["counts"]["samples"] >= 5
    own = {os.getpid()} | {r["collector_pid"] for r in res if r["type"] == "sample_begin"}
    assert not any(k[2] in own for k in rc.state)


@pytest.mark.privileged
@pytest.mark.bpf
def test_full_run_aligns_streams_and_excludes_itself(tmp_path, collector_bin):
    m = Agent(str(tmp_path), interval_ms=200, duration_s=2.0, use_bpf=True,
              collector=collector_bin).run()
    assert m["syscall_stream"] == {"available": True, "reason": None}
    v = Validator()
    res, sys_, health = (load(tmp_path / n) for n in ("resource.jsonl", "syscall.jsonl",
                                                       "health.jsonl"))
    assert all(v.errors(r) == [] for r in res + sys_ + health)
    ends = [r for r in res if r["type"] == "sample_end"]
    assert len(sys_) == len(ends) == m["counts"]["samples"] >= 5
    assert [s["resource_seq"] for s in sys_] == [e["seq"] for e in ends]
    skews = [h["alignment_skew_ns"] for h in health]
    assert all(0 <= s < 200_000_000 for s in skews), skews
    own = {os.getpid()} | {r["collector_pid"] for r in res if r["type"] == "sample_begin"}
    assert not any(p["key"]["tgid"] in own for s in sys_ for p in s["procs"])
    assert sys_[-1]["health"]["self_excluded_events"] > 0
    assert json.load(open(tmp_path / "preflight.json"))["ok"] is True
