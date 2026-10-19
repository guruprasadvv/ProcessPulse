"""End-to-end agent runs with the bigrams capability (M1b S2.6), privileged.

The real agent (C collector, unified BPF program with counts+bigrams, V2
emitter, final drain) records a run while scripted helpers make known calls:
one stays alive and idle, one exits (reported exited, then reclaimed), one
stays alive, and one is busy in a tight loop through the end of the run, so
the drain happens under activity. The emitted bpf.jsonl is then checked as a
consumer would: every line against the schema and the byte rule, the whole
stream with the Reconstructor, the stream-level invariants
(processpulse.bigrams) on the drained snapshot, and the scripted helpers
against the oracle.

Run as root:  make test-privileged
"""

import json
import os
import threading
import time

import pytest

from conftest import wait_until
from processpulse import bigrams as bg
from processpulse.agent import Agent
from processpulse.jsonl import line_violations
from processpulse.snapshots import Reconstructor
from processpulse.validate import Validator

pytestmark = [pytest.mark.privileged, pytest.mark.bpf]

CAPS = ("counts", "bigrams")
LAUNCH = [("thread", "m", "new"), ("call", "m", "execve"), ("exec", "m")]


def raw_lines(path):
    with open(path, "rb") as f:
        return f.read().split(b"\n")[:-1]


def ends_written(path):
    try:
        return sum(1 for r in raw_lines(path) if b'"bpf_snapshot_end"' in r)
    except FileNotFoundError:
        return 0


def own_fds(kind):
    n = 0
    for fd in os.listdir("/proc/self/fd"):
        try:
            if os.readlink(f"/proc/self/fd/{fd}") == kind:
                n += 1
        except OSError:
            pass
    return n


def losses_at(end):
    h = end["bigram_health"]
    return {"counts_map_full": end["loss"]["counts_map_full"],
            "thread_map_full": h["thread_map_full"], "bigram_map_full": h["bigram_map_full"],
            "pre_arm_events": h["pre_arm_events"]}


def find(rc, pid):
    """(proc, table, basis) of pid: live after the drain, or reclaimed as exited."""
    live = [kt for kt in rc.state if kt[2] == pid]
    if live:
        (kt,) = live
        return rc.state[kt], rc.pairs[kt], "drained"
    (kt,) = [kt for kt, r in rc.retired.items() if kt[2] == pid]
    assert rc.retired[kt]["reason"] == "exited"
    return rc.retired[kt]["proc"], rc.retired[kt]["pairs"], "reclaimed_exited"


def test_agent_bigram_run_is_valid_drained_and_balanced(tmp_path, collector_bin, spawn_helper,
                                                        record_property):
    fds0 = (own_fds("anon_inode:[perf_event]"), own_fds("anon_inode:bpf-prog"),
            own_fds("anon_inode:bpf-map"))
    out = tmp_path / "run"
    agent = Agent(str(out), interval_ms=200, duration_s=120, collector=collector_bin, schema=2,
                  capabilities=CAPS)
    result = {}
    t = threading.Thread(target=lambda: result.setdefault("m", agent.run()))
    t.start()
    try:
        bpf = out / "bpf.jsonl"
        assert wait_until(lambda: ends_written(bpf) >= 2, timeout=120, step=0.1), "no snapshots"
        first_seen = ends_written(bpf)
        a, b, c, d = spawn_helper(), spawn_helper(), spawn_helper(), spawn_helper()
        a.do("openat", 10)
        b.do("open", 5)
        c.do("execve", 3)
        assert b.exit() == 0
        d.proc.stdin.write("openat 3000000\n")                     # busy through the drain
        d.proc.stdin.flush()
        # b must be reported exited and reclaimed before the end (two-phase reclaim).
        assert wait_until(lambda: ends_written(bpf) >= first_seen + 4, timeout=30, step=0.1)
        time.sleep(0.3)
    finally:
        agent.request_stop()
        t.join(timeout=120)
    assert not t.is_alive()
    m = result["m"]
    reply = d.proc.stdout.readline().split()
    assert reply[:4] == ["DONE", "openat", "3000000", "errors=0"], reply

    # 1. every line: schema and byte rule
    v = Validator()
    lines = raw_lines(out / "bpf.jsonl")
    for raw in lines:
        assert line_violations(raw) == []
        assert v.errors(json.loads(raw)) == []
    recs = [json.loads(r) for r in lines]
    record_property("bpf_lines", len(lines))
    record_property("max_line_bytes", max(len(r) for r in lines))

    # 2. the stream as a whole
    rc = Reconstructor()
    for r in recs:
        rc.feed(r)
    rc.finish()
    assert rc.valid and rc.epoch_intact, rc.errors
    assert all(rc.stats[k] == 0 for k in ("snapshots_incomplete", "framing_errors", "seq_gaps",
                                          "invalidations", "totals_mismatch",
                                          "keyframe_schedule_violations", "snapshots_after_drain"))
    begins = [r for r in recs if r["type"] == "bpf_snapshot_begin"]
    ends = [r for r in recs if r["type"] == "bpf_snapshot_end"]
    assert [e["drained"] for e in ends].count(True) == 1 and ends[-1]["drained"] is True
    assert begins[-1]["resource_seq"] is None and rc.last.drained
    assert all(r["capabilities"]["bigrams"]["status"] == "ok" for r in begins)
    parts = [r for r in recs if r["type"] == "bpf_bigrams"]
    assert all(len(p["pairs"]) <= 1024 for p in parts)
    record_property("snapshots", len(begins))
    record_property("bigram_records", len(parts))

    # 3. drain and manifest
    dr = m["drain"]
    assert dr["supervisor_stopped"] is True and dr["status"] == "drained" and dr["reads"] == 2
    assert dr["final_snapshot"]["drained"] is True
    assert m["bigrams"] == {"mode": "ok", "reason": None}
    assert bg.check_ib2_drain_read({"drained": True, "accounting": dr["accounting"]}).status \
        == bg.PASS

    # 4. stream-level invariants
    ib2 = bg.check_ib2_drained(rc)
    record_property("ib2_lhs", ib2.detail.get("lhs"))
    record_property("keys_live", ib2.detail.get("keys_live"))
    record_property("keys_reclaimed_exited", ib2.detail.get("keys_reclaimed_exited"))
    assert ib2.status == bg.PASS, ib2
    reports = bg.check_quiescent_reports(rc)
    assert not [r for r in reports if r.status == bg.FAIL], [r for r in reports
                                                             if r.status == bg.FAIL][:5]
    for inv in ("I-B5", "I-B1'", "I-B3'"):
        assert all(r.status == bg.PASS for r in reports if r.invariant == inv), inv
    record_property("ib1_na", sum(1 for r in reports
                                  if r.invariant == "I-B1" and r.status == bg.NOT_APPLICABLE))
    record_property("keys_checked", sum(1 for r in reports if r.invariant == "I-B1'"))

    # 5. scripted helpers against the oracle (b reclaimed as exited, a and c live)
    first_ok = next(e for e in ends if e["status"] == "ok" and e["seq"] >= first_seen - 1)
    losses = bg.loss_window(losses_at(first_ok), losses_at(ends[-1]))
    record_property("window_losses", sum(losses.values()))
    assert losses["counts_map_full"] == 0
    subjects = []
    for h, cmd, n in ((a, "openat", 10), (b, "open", 5), (c, "execve", 3)):
        p, tb, basis = find(rc, h.pid)
        o = bg.expected_pairs(LAUNCH + [("call", "m", cmd)] * n)
        assert p["counts"] == o.counts and tb == o.pairs and p["pairs_lost"] == 0, (cmd, p, tb)
        for check in (bg.check_ib3_exact, bg.check_ib4_exact):
            r = check(p, tb, o, basis, losses=losses)
            assert r.status in (bg.PASS, bg.NOT_APPLICABLE), r
            record_property(f"{r.invariant}_{cmd}", r.status)
        subjects.append((p, tb))
    assert find(rc, b.pid)[2] == "reclaimed_exited"
    gt = bg.check_ib2_ground_truth_scope(subjects, 11 + 6 + 4, "drained", losses)
    assert gt.status == bg.PASS, gt
    pd, td, _ = find(rc, d.pid)                                     # cut off by the drain
    record_property("busy_openat_at_drain", pd["counts"]["openat"])
    assert 1000 < pd["counts"]["openat"] < 3000000
    assert bg.check_ib1_prime(pd, td, "drained").status == bg.PASS

    # 6. self-exclusion and cleanup
    res = [json.loads(r) for r in raw_lines(out / "resource.jsonl")]
    own = {os.getpid()} | {r["collector_pid"] for r in res if r["type"] == "sample_begin"}
    assert not any(kt[2] in own for kt in rc.state)
    assert (own_fds("anon_inode:[perf_event]"), own_fds("anon_inode:bpf-prog"),
            own_fds("anon_inode:bpf-map")) == fds0
    assert agent._rc.stopped and agent._rc._proc.poll() is not None


def test_counts_only_schema2_run_keeps_the_s0_shape(tmp_path, collector_bin):
    m = Agent(str(tmp_path), interval_ms=200, duration_s=1.5, collector=collector_bin,
              schema=2).run()
    recs = [json.loads(r) for r in raw_lines(tmp_path / "bpf.jsonl")]
    assert recs and all("bigrams" not in r["capabilities"] for r in recs
                        if r["type"] == "bpf_snapshot_begin")
    assert not any("drained" in r or "bigram_health" in r for r in recs
                   if r["type"] == "bpf_snapshot_end")
    assert not any("pairs_lost" in r for r in recs if r["type"] == "bpf_proc")
    assert m["drain"] is None and m["bigrams"] is None and m["degraded"] is False
    assert m["capabilities"] == {"requested": ["counts"], "active": ["counts"], "failed": {}}
    assert all(r["resource_seq"] is not None for r in recs if r["type"] == "bpf_snapshot_begin")


# --- startup failure after the bigram program is loaded and attached (Phase 2C) ---------------

def fd_state():
    return (own_fds("anon_inode:[perf_event]"), own_fds("anon_inode:bpf-prog"),
            own_fds("anon_inode:bpf-map"))


@pytest.fixture
def bigram_start_fails_after_attach(monkeypatch):
    """BpfCollector.start() of the bigram build raises from its self-exclusion,
    i.e. after the unified program is loaded and its 11 tracepoints attached (as
    a membarrier failure would). The counts-only build is unaffected."""
    from processpulse import bpf_collector as bcm
    real = bcm.BpfCollector.exclude
    seen = {}

    def exclude(self, tgid):
        if self.has_bigrams:
            seen["attached"] = len(self.attached_tracepoints())
            raise OSError(22, "injected: membarrier(MEMBARRIER_CMD_GLOBAL) failed")
        return real(self, tgid)
    monkeypatch.setattr(bcm.BpfCollector, "exclude", exclude)
    return seen


def test_strict_startup_failure_releases_every_bpf_and_perf_handle(
        tmp_path, collector_bin, bigram_start_fails_after_attach):
    from processpulse.agent import StartupError
    before = fd_state()
    a = Agent(str(tmp_path), interval_ms=200, duration_s=1, collector=collector_bin, schema=2,
              capabilities=CAPS)
    with pytest.raises(StartupError) as ei:
        a.run()
    assert bigram_start_fails_after_attach["attached"] == 11          # it really was attached
    assert isinstance(ei.value.__cause__, OSError)
    assert fd_state() == before                                       # nothing leaked
    m = json.load(open(tmp_path / "manifest.json"))
    assert m["status"] == "failed" and "membarrier" in m["error"]["reason"]
    assert m["cleanup_errors"] == [] and os.path.getsize(tmp_path / "bpf.jsonl") == 0


def test_degraded_startup_failure_releases_the_failed_program_and_runs_counts_only(
        tmp_path, collector_bin, bigram_start_fails_after_attach):
    before = fd_state()
    m = Agent(str(tmp_path), interval_ms=200, duration_s=1.5, collector=collector_bin,
              schema=2, capabilities=CAPS, allow_degraded=True).run()
    assert fd_state() == before
    assert m["status"] == "ok" and m["degraded"] is True
    assert m["capabilities"]["active"] == ["counts"]
    assert "membarrier" in m["capabilities"]["failed"]["bigrams"]
    recs = [json.loads(r) for r in raw_lines(tmp_path / "bpf.jsonl")]
    v = Validator()
    assert recs and all(v.errors(r) == [] for r in recs)
    cap = recs[0]["capabilities"]["bigrams"]
    assert cap["status"] == "unavailable" and "membarrier" in cap["reason"]
    assert not [r for r in recs if r["type"] == "bpf_bigrams"]
    assert all(r["pairs_lost"] is None for r in recs if r["type"] == "bpf_proc")
