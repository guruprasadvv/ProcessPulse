"""Agent integration of the bigrams capability (M1b S2.6), without root.

The C collector is tests/helpers/fake_collector.py (PPC_FAKE_MODE=forever) and
the BPF collector is snapshot_fakes.BigramCollectorFake, injected through
Agent._start_bpf; preflight is replaced by a passing report. These tests
check the agent's own logic: option validation, the end-of-epoch order
(supervisor stopped and joined, then drain, then exactly one drained
snapshot), that no failure path is reported as drained, and cleanup. The
real kernel path is tests/test_agent_bigrams_bpf.py.
"""

import json
import os
import sys
import threading

import pytest

from processpulse import agent as agent_mod
from processpulse import bigrams as bg
from processpulse.agent import Agent, main
from processpulse.jsonl import line_violations
from processpulse.resource import ResourceCollector
from processpulse.snapshots import Reconstructor
from processpulse.validate import Validator
from snapshot_fakes import BigramCollectorFake

FAKE_C = [sys.executable, os.path.join(os.path.dirname(__file__), "helpers", "fake_collector.py")]
CAPS = ("counts", "bigrams")


def lines(path):
    with open(path, "rb") as f:
        return f.read().split(b"\n")[:-1]


def records(path):
    return [json.loads(r) for r in lines(path)]


def fake_bpf():
    f = BigramCollectorFake()
    for tgid in (10, 20):
        f.add(tgid)
        f.step_pair(tgid, "START_NEW", "execve")
    f.step_pair(10, "execve", "openat")
    return f


@pytest.fixture
def env(monkeypatch):
    """A passing preflight, the forever fake C collector, and a slot for the fake BPF collector."""
    monkeypatch.setenv("PPC_FAKE_MODE", "forever")
    monkeypatch.setattr(agent_mod, "run_preflight", lambda: {"ok": True, "checks": []})
    box = {"fake": fake_bpf(), "mode": "ok", "reason": None}

    def start_bpf(self, log):
        f = box["fake"]
        f.log.append("start")
        modes = {} if box["mode"] is None else {"bigrams": box["mode"]}
        return f, None, modes, box["reason"], None
    monkeypatch.setattr(Agent, "_start_bpf", start_bpf)
    return box


def run(tmp_path, duration=1.0, **kw):
    a = Agent(str(tmp_path), interval_ms=50, duration_s=duration, collector=FAKE_C,
              schema=kw.pop("schema", 2), capabilities=kw.pop("capabilities", CAPS), **kw)
    return a, a.run()


def check_stream(tmp_path):
    v = Validator()
    for raw in lines(tmp_path / "bpf.jsonl"):
        assert line_violations(raw) == []
        assert v.errors(json.loads(raw)) == []
    rc = Reconstructor()
    recs = records(tmp_path / "bpf.jsonl")
    for r in recs:
        rc.feed(r)
    rc.finish()
    assert rc.valid and rc.stats["snapshots_incomplete"] == 0, rc.errors
    return recs, rc


# --- options ----------------------------------------------------------------------------

def test_schema1_stays_the_default_and_bigrams_need_schema2(tmp_path):
    a = Agent(str(tmp_path))
    assert a.schema == 1 and a.capabilities == ("counts",)
    with pytest.raises(ValueError, match="schema 2"):
        Agent(str(tmp_path), capabilities=CAPS)
    with pytest.raises(ValueError, match="schema 2"):
        Agent(str(tmp_path), capabilities=("counts", "net"))         # net is schema 2 only too
    assert Agent(str(tmp_path), schema=2, capabilities=("counts", "net")).extras == ("net",)
    for bad in (("bigrams",), ("net",), ("counts", "priv"), (), ("counts", "counts")):
        with pytest.raises(ValueError):
            Agent(str(tmp_path), schema=2, capabilities=bad)
    with pytest.raises(ValueError, match="BPF"):
        Agent(str(tmp_path), schema=2, capabilities=CAPS, use_bpf=False)
    assert Agent(str(tmp_path), schema=2, capabilities=CAPS).allow_degraded is False


def test_cli_parses_and_refuses_capabilities(monkeypatch, tmp_path):
    seen = {}

    class Stub:
        def __init__(self, out, **kw):
            seen.update(kw)
            Agent(out, schema=kw["schema"], capabilities=kw["capabilities"])   # same validation

        def request_stop(self, *_):
            pass

        def run(self):
            return {"counts": {}, "syscall_stream": {}}
    monkeypatch.setattr(agent_mod, "Agent", Stub)
    assert main(["--out", str(tmp_path), "--schema", "2", "--capabilities", "counts,bigrams"]) == 0
    assert seen["capabilities"] == ("counts", "bigrams") and seen["schema"] == 2
    assert main(["--out", str(tmp_path)]) == 0
    assert seen["capabilities"] == ("counts",) and seen["schema"] == 1
    with pytest.raises(SystemExit):
        main(["--out", str(tmp_path), "--capabilities", "counts,bigrams"])     # schema 1
    with pytest.raises(SystemExit):
        main(["--out", str(tmp_path), "--capabilities", "counts,net"])          # schema 1
    with pytest.raises(SystemExit):
        main(["--out", str(tmp_path), "--schema", "2", "--capabilities", "net"])  # no counts
    assert main(["--out", str(tmp_path), "--schema", "2", "--capabilities", "counts,net"]) == 0
    assert seen["capabilities"] == ("counts", "net")
    with pytest.raises(SystemExit):
        main(["--out", str(tmp_path), "--schema", "2", "--capabilities", "counts,priv"])
    with pytest.raises(SystemExit):
        main(["--out", str(tmp_path), "--schema", "2", "--capabilities", "counts,bigrams",
              "--no-bpf"])
    assert main(["--out", str(tmp_path), "--schema", "2", "--capabilities", "counts,bigrams"]) == 0
    assert seen["allow_degraded"] is False                           # never silently degraded
    assert main(["--out", str(tmp_path), "--schema", "2", "--capabilities", "counts,bigrams",
                 "--allow-degraded"]) == 0
    assert seen["allow_degraded"] is True


# --- end of epoch -----------------------------------------------------------------------------

def test_normal_run_stops_the_supervisor_then_drains_then_emits_one_drained_snapshot(
        env, tmp_path, monkeypatch):
    f = env["fake"]
    real_stop, real_drain = ResourceCollector.stop, f.drain
    supervisor_alive_at_drain = []

    def stop(self, *a, **kw):
        f.log.append("rc.stop")
        return real_stop(self, *a, **kw)

    def drain():
        supervisor_alive_at_drain.append(
            any(t.name == "resource-collector" and t.is_alive() for t in threading.enumerate()))
        return real_drain()
    monkeypatch.setattr(ResourceCollector, "stop", stop)
    f.drain = drain
    _, m = run(tmp_path)
    assert f.log.index("rc.stop") < f.log.index("drain") < f.log.index("close")
    assert supervisor_alive_at_drain == [False]
    assert f.excluded                                             # on_spawn was wired
    recs, rc = check_stream(tmp_path)
    ends = [r for r in recs if r["type"] == "bpf_snapshot_end"]
    begins = [r for r in recs if r["type"] == "bpf_snapshot_begin"]
    assert [e["drained"] for e in ends].count(True) == 1 and ends[-1]["drained"] is True
    assert begins[-1]["resource_seq"] is None                     # not aligned to a sample
    assert all(b["resource_seq"] is not None for b in begins[:-1])
    assert rc.last.drained
    assert bg.check_ib2_drained(rc).status == bg.PASS
    d = m["drain"]
    assert d["supervisor_stopped"] is True and d["status"] == "drained" and d["drained"] is True
    assert d["final_snapshot"] == {"seq": begins[-1]["seq"], "status": "ok", "drained": True,
                                   "reason": None}
    assert m["bigrams"] == {"mode": "ok", "reason": None}
    assert m["capabilities"] == {"requested": list(CAPS), "active": list(CAPS), "failed": {}}
    assert m["status"] == "ok" and m["degraded"] is False
    assert m["counts"]["snapshots"] == m["counts"]["samples"] + 1


@pytest.mark.parametrize("outcome", ["unstable", "failed"])
def test_an_unsuccessful_drain_emits_no_final_snapshot_and_no_drained_flag(env, tmp_path, outcome):
    env["fake"].drain_outcome = outcome
    _, m = run(tmp_path)
    recs, rc = check_stream(tmp_path)
    assert not any(r.get("drained") for r in recs if r["type"] == "bpf_snapshot_end")
    assert all(r["resource_seq"] is not None for r in recs if r["type"] == "bpf_snapshot_begin")
    assert m["drain"]["status"] == outcome and m["drain"]["drained"] is False
    assert m["drain"]["final_snapshot"] is None
    assert bg.check_ib2_drained(rc).status == bg.NOT_APPLICABLE
    assert env["fake"].closed


def test_a_drained_snapshot_that_fails_is_written_as_failed_not_drained(env, tmp_path):
    env["fake"].change_after_drain = True
    _, m = run(tmp_path)
    recs, _ = check_stream(tmp_path)
    end = [r for r in recs if r["type"] == "bpf_snapshot_end"][-1]
    assert end["status"] == "failed" and end["drained"] is False
    assert m["drain"]["drained"] is True                          # the drain itself succeeded
    assert m["drain"]["final_snapshot"]["drained"] is False
    assert m["counts"]["failed_snapshots"] == 1


def test_a_drain_that_raises_is_reported_and_cleaned_up(env, tmp_path):
    def boom():
        raise RuntimeError("drain exploded")
    env["fake"].drain = boom
    _, m = run(tmp_path)
    assert m["drain"]["status"] == "error" and "drain exploded" in m["drain"]["reason"]
    assert m["drain"]["drained"] is False and env["fake"].closed


def test_no_drain_while_the_supervisor_is_still_running(env, tmp_path, monkeypatch):
    monkeypatch.setattr(ResourceCollector, "stopped", property(lambda self: False))
    _, m = run(tmp_path)
    assert env["fake"].drain_calls == 0
    assert m["drain"]["status"] == "skipped" and m["drain"]["supervisor_stopped"] is False
    recs, _ = check_stream(tmp_path)
    assert not any(r.get("drained") for r in recs if r["type"] == "bpf_snapshot_end")


def test_cancellation_ends_the_run_with_a_drain(env, tmp_path):
    a = Agent(str(tmp_path), interval_ms=50, duration_s=60, collector=FAKE_C, schema=2,
              capabilities=CAPS)
    threading.Timer(1.0, a.request_stop).start()
    m = a.run()
    assert m["duration_mono_ns"] < 30e9
    assert m["drain"]["status"] == "drained" and m["drain"]["final_snapshot"]["drained"] is True


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_a_supervisor_thread_that_dies_still_ends_with_a_drain(env, tmp_path, monkeypatch):
    """The C collector crashes once; on the restart, on_spawn (exclude) raises in
    the supervisor thread and ends it (purge follow-up 1). The run ends early,
    the thread is gone, and the drain still runs."""
    monkeypatch.setenv("PPC_FAKE_MODE", "crash_once")
    monkeypatch.setenv("PPC_FAKE_STATE", str(tmp_path / "crashed"))
    calls = []

    def exclude(pid):
        calls.append(pid)
        if len(calls) > 1:
            raise RuntimeError("membarrier failed")
    env["fake"].exclude = exclude
    _, m = run(tmp_path / "out", duration=20.0)
    assert len(calls) == 2 and m["duration_mono_ns"] < 15e9
    assert m["resource_stats"]["restarts"] == 1
    assert m["drain"]["supervisor_stopped"] is True and m["drain"]["status"] == "drained"
    assert m["drain"]["final_snapshot"]["drained"] is True


def test_a_startup_failure_of_the_supervisor_aborts_without_drain_and_cleans_up(env, tmp_path):
    def exclude(pid):
        raise RuntimeError("membarrier failed")
    env["fake"].exclude = exclude
    with pytest.raises(RuntimeError, match="membarrier"):
        run(tmp_path)
    assert env["fake"].drain_calls == 0 and env["fake"].closed


def test_an_error_during_collection_does_not_drain_and_cleans_up(env, tmp_path, monkeypatch):
    real_write = Agent._write
    procs = []

    def write(self, fh, rec):
        if rec["type"] == "bpf_snapshot_end":
            procs.append(self._rc._proc)
            raise ValueError("injected invalid record")
        return real_write(self, fh, rec)
    monkeypatch.setattr(Agent, "_write", write)
    with pytest.raises(ValueError, match="injected"):
        run(tmp_path)
    f = env["fake"]
    assert f.drain_calls == 0 and f.closed
    assert procs and procs[0].poll() is not None                  # C collector terminated


def test_unavailable_bigrams_are_null_with_an_error_and_never_drained(env, tmp_path):
    env["mode"], env["reason"] = "unavailable", "bigram collector failed to start: X"
    env["fake"].has_bigrams = False
    _, m = run(tmp_path, allow_degraded=True)
    recs, rc = check_stream(tmp_path)
    assert not [r for r in recs if r["type"] == "bpf_bigrams"]
    procs = [r for r in recs if r["type"] == "bpf_proc"]
    assert procs and all(p["pairs_lost"] is None and p["bigrams_err"] == "UNSUPPORTED"
                         for p in procs)
    ends = [r for r in recs if r["type"] == "bpf_snapshot_end"]
    assert all(e["totals"]["bigrams"] is None and e["bigram_health"] is None
               and e["drained"] is False for e in ends)
    assert m["bigrams"] == {"mode": "unavailable", "reason": "bigram collector failed to start: X"}
    assert m["drain"] is None and env["fake"].drain_calls == 0
    assert m["degraded"] is True and m["capabilities"] == {
        "requested": list(CAPS), "active": ["counts"],
        "failed": {"bigrams": "bigram collector failed to start: X"}}
    assert recs[0]["capabilities"]["bigrams"]["reason"] == "bigram collector failed to start: X"


def _patch_collectors(monkeypatch, events, close_error=None, counts_cls=None):
    """BpfCollector fails to start (after which close() runs); SyscallCollector is
    counts_cls or a recorder."""
    from processpulse import bpf_collector as bcm
    from processpulse import syscalls as sysm

    class FailingBigram:
        def __init__(self, **kw):
            events.append(("bigram", kw["capabilities"]))

        def start(self):
            raise RuntimeError("verifier rejected the program")

        def close(self):
            events.append("bigram.close")
            if close_error:
                raise OSError(close_error)

    class CountsOnly:
        def __init__(self, **kw):
            events.append(("counts", kw))

        def start(self):
            return self
    monkeypatch.setattr(bcm, "BpfCollector", FailingBigram)
    monkeypatch.setattr(sysm, "SyscallCollector", counts_cls or CountsOnly)


def test_by_default_a_bigram_start_failure_starts_nothing_else(monkeypatch, tmp_path):
    events = []
    _patch_collectors(monkeypatch, events)
    a = Agent(str(tmp_path), schema=2, capabilities=CAPS)
    with open(tmp_path / "log.txt", "w") as log:
        sc, reason, mode, why, err = a._start_bpf(log)
    assert sc is None and mode == {"bigrams": "unavailable"} and "verifier rejected" in why
    assert isinstance(err, RuntimeError)
    assert events == [("bigram", CAPS), "bigram.close"]               # no counts-only start


def test_allow_degraded_falls_back_to_counts_only_and_closes_the_failed_program(
        monkeypatch, tmp_path):
    events = []
    _patch_collectors(monkeypatch, events)
    a = Agent(str(tmp_path), schema=2, capabilities=CAPS, allow_degraded=True)
    with open(tmp_path / "log.txt", "w") as log:
        sc, reason, mode, why, err = a._start_bpf(log)
    assert reason is None and mode == {"bigrams": "unavailable"} and "verifier rejected" in why
    assert events[0] == ("bigram", CAPS) and events[1] == "bigram.close"
    assert events[-1][0] == "counts" and events[-1][1]["track_removals"] is True


def test_counts_only_schema2_run_has_no_drain_and_no_bigram_fields(env, tmp_path):
    env["mode"] = None
    _, m = run(tmp_path, capabilities=("counts",))
    recs, _ = check_stream(tmp_path)
    assert "bigrams" not in recs[0]["capabilities"]
    assert not any("drained" in r for r in recs if r["type"] == "bpf_snapshot_end")
    assert m["drain"] is None and env["fake"].drain_calls == 0


# --- tools/acceptance/validate_run.py on agent-produced bigram runs ---------------------------

VALIDATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "tools", "acceptance", "validate_run.py")


def validate(d, *extra):
    import subprocess
    p = subprocess.run([sys.executable, VALIDATE, str(d), "--min-span-s", "0", *extra],
                       capture_output=True, text=True)
    return p.returncode, json.loads(p.stdout)


def test_validate_run_accepts_a_drained_bigram_run_and_reports_its_invariants(env, tmp_path):
    run(tmp_path)
    rc, rep = validate(tmp_path, "--require-drained")
    assert rc == 0, rep["checks"]
    fs = rep["checks"]["final_snapshot"]
    assert fs["ok"] and fs["final_snapshot"]["drained"] is True
    bi = rep["checks"]["bigram_invariants"]
    assert bi["ok"] and bi["ib2"]["status"] == bg.PASS and bi["failures"] == []
    assert bi["summary"]["I-B1'"][bg.PASS] == 2                    # both live keys, drained
    assert rep["checks"]["alignment"]["ok"]


def test_validate_run_requires_the_drain_only_when_asked(env, tmp_path):
    env["fake"].drain_outcome = "unstable"
    run(tmp_path)
    rc, rep = validate(tmp_path)
    assert rc == 0 and rep["checks"]["bigram_invariants"]["ib2"]["status"] == bg.NOT_APPLICABLE
    rc, rep = validate(tmp_path, "--require-drained")
    assert rc == 1 and rep["checks"]["bigram_invariants"]["ok"] is False


def test_validate_run_rejects_an_unaligned_snapshot_before_the_end(env, tmp_path):
    run(tmp_path)
    path = tmp_path / "bpf.jsonl"
    recs = records(path)
    first = next(r for r in recs if r["type"] == "bpf_snapshot_begin")
    first["resource_seq"] = None
    with open(path, "w", encoding="utf-8", newline="") as f:
        for r in recs:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")
    rc, rep = validate(tmp_path)
    assert rc == 1 and rep["checks"]["final_snapshot"]["ok"] is False


def test_when_both_programs_fail_there_is_no_stream_and_the_reason_is_kept(monkeypatch, tmp_path):
    from processpulse import bpf_collector as bcm
    from processpulse import syscalls as sysm

    class Failing:
        def __init__(self, **kw):
            pass

        def start(self):
            raise RuntimeError("kheaders missing")

        def close(self):
            pass
    monkeypatch.setattr(bcm, "BpfCollector", Failing)
    monkeypatch.setattr(sysm, "SyscallCollector", Failing)
    a = Agent(str(tmp_path), schema=2, capabilities=CAPS, allow_degraded=True)
    with open(tmp_path / "log.txt", "w") as log:
        sc, reason, mode, why, err = a._start_bpf(log)
    assert sc is None and "syscall collector failed to start" in reason
    assert mode == {"bigrams": "unavailable"} and "kheaders missing" in why


# --- strict startup policy (default) and explicit degraded mode -------------------------------

def _strict_env(monkeypatch, preflight_ok=True):
    monkeypatch.setenv("PPC_FAKE_MODE", "forever")
    checks = [] if preflight_ok else [{"name": "kheaders", "status": "FAIL"}]
    monkeypatch.setattr(agent_mod, "run_preflight", lambda: {"ok": preflight_ok, "checks": checks})


def test_default_bigram_start_failure_fails_the_run_with_the_original_error(monkeypatch, tmp_path):
    _strict_env(monkeypatch)
    events = []
    _patch_collectors(monkeypatch, events)
    a = Agent(str(tmp_path), interval_ms=50, duration_s=1, collector=FAKE_C, schema=2,
              capabilities=CAPS)
    with pytest.raises(agent_mod.StartupError, match="verifier rejected") as ei:
        a.run()
    assert isinstance(ei.value.__cause__, RuntimeError)               # original error chained
    assert str(ei.value.__cause__) == "verifier rejected the program"
    assert events == [("bigram", CAPS), "bigram.close"]
    assert not hasattr(a, "_rc")                                      # no C collector started
    m = json.load(open(tmp_path / "manifest.json"))
    assert m["status"] == "failed" and m["degraded"] is False
    assert m["error"]["capability"] == "bigrams" and m["error"]["type"] == "RuntimeError"
    assert "verifier rejected the program" in m["error"]["reason"]
    assert m["capabilities"] == {"requested": list(CAPS), "active": [],
                                 "failed": {"bigrams": m["error"]["reason"]}}
    assert "counts" not in m and "drain" not in m                     # no run result
    assert os.path.getsize(tmp_path / "bpf.jsonl") == 0               # no telemetry at all
    assert "startup failed" in open(tmp_path / "agent.log").read()


def test_cleanup_errors_are_reported_without_hiding_the_original_failure(monkeypatch, tmp_path):
    _strict_env(monkeypatch)
    _patch_collectors(monkeypatch, [], close_error="detach failed: EBUSY")
    a = Agent(str(tmp_path), schema=2, capabilities=CAPS)
    with pytest.raises(agent_mod.StartupError) as ei:
        a.run()
    cause = ei.value.__cause__
    assert str(cause) == "verifier rejected the program"
    assert any("EBUSY" in n for n in cause.__notes__)
    m = json.load(open(tmp_path / "manifest.json"))
    assert len(m["cleanup_errors"]) == 1 and "EBUSY" in m["cleanup_errors"][0]


def test_main_exits_nonzero_and_reports_the_cause(monkeypatch, tmp_path, capsys):
    _strict_env(monkeypatch)
    _patch_collectors(monkeypatch, [])
    rc = main(["--out", str(tmp_path), "--schema", "2", "--capabilities", "counts,bigrams",
               "--collector", FAKE_C[0]])
    assert rc == 1
    err = json.loads(capsys.readouterr().err)
    assert err["status"] == "failed" and err["cause"] == "RuntimeError: verifier rejected the program"


def test_a_preflight_failure_with_bigrams_requested_fails_the_run(monkeypatch, tmp_path):
    _strict_env(monkeypatch, preflight_ok=False)
    a = Agent(str(tmp_path), schema=2, capabilities=CAPS)
    with pytest.raises(agent_mod.StartupError, match="preflight"):
        a.run()
    m = json.load(open(tmp_path / "manifest.json"))
    assert m["status"] == "failed" and set(m["capabilities"]["failed"]) == {"counts", "bigrams"}


def test_a_preflight_failure_with_allow_degraded_runs_resource_only(monkeypatch, tmp_path):
    _strict_env(monkeypatch, preflight_ok=False)
    a = Agent(str(tmp_path), interval_ms=50, duration_s=0.5, collector=FAKE_C, schema=2,
              capabilities=CAPS, allow_degraded=True)
    m = a.run()
    assert m["status"] == "ok" and m["degraded"] is True
    assert m["capabilities"]["active"] == [] and set(m["capabilities"]["failed"]) == {"counts",
                                                                                      "bigrams"}
    assert os.path.getsize(tmp_path / "bpf.jsonl") == 0 and m["counts"]["samples"] > 0


def test_allow_degraded_run_end_to_end_with_the_real_fallback_path(monkeypatch, tmp_path):
    """The real _start_bpf: the bigram program fails, the counts-only collector (a
    fake without the bigrams capability) runs; telemetry says unavailable, never 0."""
    _strict_env(monkeypatch)

    def counts_only(**kw):
        f = fake_bpf()
        f.has_bigrams = False
        f.start = lambda: f
        return f
    _patch_collectors(monkeypatch, [], counts_cls=counts_only)
    a = Agent(str(tmp_path), interval_ms=50, duration_s=1, collector=FAKE_C, schema=2,
              capabilities=CAPS, allow_degraded=True)
    m = a.run()
    recs, rc = check_stream(tmp_path)
    cap = recs[0]["capabilities"]["bigrams"]
    assert cap["status"] == "unavailable" and cap["err"] == "UNSUPPORTED"
    assert "verifier rejected the program" in cap["reason"]
    assert all(p["pairs_lost"] is None and p["bigrams_err"] == "UNSUPPORTED"
               for p in recs if p["type"] == "bpf_proc")
    assert not [r for r in recs if r["type"] == "bpf_bigrams"]
    assert m["degraded"] is True and m["capabilities"]["active"] == ["counts"]
    assert m["capabilities"]["failed"]["bigrams"] == cap["reason"]
    assert m["config"]["allow_degraded"] is True and m["drain"] is None
    assert rc.pairs == {}                                            # nothing claimed as empty


# --- adversarial: failures inside the final drained snapshot ----------------------------------

def _children_gone(a):
    return a._rc._proc is not None and a._rc._proc.poll() is not None


def test_a_write_error_on_the_drained_snapshot_propagates_commits_nothing_and_cleans_up(
        env, tmp_path, monkeypatch):
    real_write = Agent._write

    def write(self, fh, rec):
        if rec["type"] == "bpf_snapshot_begin" and rec["resource_seq"] is None:
            raise ValueError("injected write failure on the drained snapshot")
        return real_write(self, fh, rec)
    monkeypatch.setattr(Agent, "_write", write)
    a = Agent(str(tmp_path), interval_ms=50, duration_s=1, collector=FAKE_C, schema=2,
              capabilities=CAPS)
    with pytest.raises(ValueError, match="drained snapshot"):
        a.run()
    f = env["fake"]
    assert f.drain_calls == 1 and f.closed and _children_gone(a)
    recs = records(tmp_path / "bpf.jsonl")
    assert not any(r.get("drained") for r in recs if r["type"] == "bpf_snapshot_end")
    assert not os.path.exists(tmp_path / "manifest.json")             # no run result


def test_an_interrupt_during_the_drain_propagates_and_cleans_up(env, tmp_path):
    def interrupted():
        raise KeyboardInterrupt
    env["fake"].drain = interrupted
    a = Agent(str(tmp_path), interval_ms=50, duration_s=1, collector=FAKE_C, schema=2,
              capabilities=CAPS)
    with pytest.raises(KeyboardInterrupt):
        a.run()
    assert env["fake"].closed and _children_gone(a)
    assert not any(r.get("drained") for r in records(tmp_path / "bpf.jsonl")
                   if r["type"] == "bpf_snapshot_end")


def test_an_unfittable_drained_snapshot_is_never_written_as_drained(env, tmp_path, monkeypatch):
    from processpulse import snapshots as snapmod
    real = snapmod.bigram_parts
    state = {"drained": False}

    def parts(seq, key, table, limit, max_items):
        if state["drained"]:
            raise snapmod.RecordTooLarge("injected: a part cannot fit")
        return real(seq, key, table, limit, max_items)
    real_drain = env["fake"].drain

    def drain():
        state["drained"] = True
        env["fake"].step_pair(10, "openat", "openat")                # forces re-emission
        return real_drain()
    env["fake"].drain = drain
    monkeypatch.setattr(snapmod, "bigram_parts", parts)
    a = Agent(str(tmp_path), interval_ms=50, duration_s=1, collector=FAKE_C, schema=2,
              capabilities=CAPS)
    with pytest.raises(snapmod.RecordTooLarge):
        a.run()
    assert env["fake"].closed and _children_gone(a)
    assert not any(r.get("drained") for r in records(tmp_path / "bpf.jsonl")
                   if r["type"] == "bpf_snapshot_end")
