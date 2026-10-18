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
