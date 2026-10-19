"""Net capability (M1b S3.1/S3.2), unprivileged: wiring, decoding, invariant
checkers, schema/validator, emitter and Reconstructor (fake collector)."""

import copy
import re

import pytest

from processpulse import bpf_collector as bc
from processpulse import net as nt
from processpulse.jsonl import encode_record, line_violations
from processpulse.snapshots import Reconstructor, V2Emitter
from processpulse.validate import Validator
from processpulse.vocab import (NET_CLASSES, NET_DEST_CLASSES, NET_HOOK_FIELDS, NET_RESULTS,
                                NET_SYSCALLS, VOCABULARY)
from snapshot_fakes import BigramCollectorFake

V = Validator()
NET_SRC = open(bc.BPF_DIR + "/net.bpf.c").read()


# --- wiring -------------------------------------------------------------------------

def test_syscall_vocabulary_is_unchanged():
    assert VOCABULARY.id == "v1-3aba869d1752"


def test_c_codes_match_the_python_vocabulary():
    def defines(prefix):
        return dict((m, int(v)) for m, v in re.findall(rf"#define ({prefix}\w*)\s+(\d+)\b", NET_SRC))
    nc = defines("NC_")
    assert [nc["NC_" + c.upper()] for c in NET_CLASSES] == list(range(len(NET_CLASSES)))
    nd = defines("ND")
    assert [nd["ND_" + d.upper()] for d in NET_DEST_CLASSES] == list(range(len(NET_DEST_CLASSES)))
    assert nd["NDEST"] == len(NET_DEST_CLASSES)
    ns = defines("NS_")
    assert [ns["NS_" + s.upper()] for s in NET_SYSCALLS] == list(range(len(NET_SYSCALLS)))
    nh = defines("NH")
    assert [nh["NH_" + f.upper()] for f in NET_HOOK_FIELDS] == list(range(len(NET_HOOK_FIELDS)))
    assert nh["NHF"] == len(NET_HOOK_FIELDS)
    assert bc.NNHEALTH == len(NET_SYSCALLS) * len(NET_HOOK_FIELDS) + 1


def test_struct_ncnt_matches_the_raw_field_order():
    body = NET_SRC[NET_SRC.index("struct ncnt {"):NET_SRC.index("};", NET_SRC.index("struct ncnt {"))]
    fields = re.findall(r"u64 (\w+)(\[\w+\])?;", body)
    flat = []
    for name, arr in fields:
        if name == "entry":
            flat += [f"entry_{s}" for s in NET_SYSCALLS]
        elif name == "dest":
            flat += [f"dest_{d}" for d in NET_DEST_CLASSES]
        else:
            flat.append(name)
    assert tuple(flat) == nt.RAW_FIELDS


def test_net_tracepoints_and_source_order():
    tps = bc.required_tracepoints(("counts", "net"))
    assert tps[-8:-2] == tuple(f"syscalls:sys_{d}_{s}" for s in NET_SYSCALLS
                               for d in ("enter", "exit"))
    assert len(tps) == len(bc.required_tracepoints(("counts",))) + 6
    src = bc.build_source(("counts", "bigrams", "net"))
    order = [src.index(m) for m in ("BPF_HASH(bigrams", "BPF_HASH(counts", "BPF_HASH(netc",
                                    "TRACEPOINT_PROBE(sched, sched_process_exit)")]
    assert order == sorted(order)
    for caps in (("counts",), ("counts", "bigrams")):           # nothing of net elsewhere
        s = bc.build_source(caps)
        assert "netc" not in s and "sys_exit_" not in s and "net_stash" not in s


def test_only_tracepoints_no_kprobes():
    for caps in (("counts", "net"), ("counts", "bigrams", "net")):
        s = bc.build_source(caps)
        for bad in ("kprobe", "kretprobe", "fentry", "fexit", "raw_tracepoint", "BPF_PROG("):
            assert bad not in s.lower().replace("tracepoint_probe", ""), bad


def test_no_port_is_ever_read_and_only_class_codes_are_stored():
    dest_fn = NET_SRC[NET_SRC.index("static __always_inline u16 net_dest"):]
    dest_fn = dest_fn[:dest_fn.index("\n}\n")]
    reads = re.findall(r"bpf_probe_read_user\(([^;]*)\);?", dest_fn)
    assert len(reads) == 3
    # family at offset 0, IPv4 address at offset 4, IPv6 address at offset 8: never the
    # port (offset 2) nor sin6_flowinfo/scope
    assert "ua + 4" in dest_fn and "ua + 8" in dest_fn and "ua + 2" not in dest_fn
    stash = NET_SRC[NET_SRC.index("struct nstash {"):NET_SRC.index("};", NET_SRC.index("struct nstash {"))]
    assert "addr" not in stash and "port" not in stash
    ncnt = NET_SRC[NET_SRC.index("struct ncnt {"):NET_SRC.index("};", NET_SRC.index("struct ncnt {"))]
    assert "addr" not in ncnt and "port" not in ncnt


def test_capability_defaults_and_memory_bounds():
    c = bc.BpfCollector(capabilities=("counts", "net"))
    assert c.max_net == bc.NET_DEFAULT_MAX == 32768 and c.max_net_stash == 32768


# --- decoding --------------------------------------------------------------------------------

def raw(entry=(0, 0, 0), results=(0,) * 6, dest=(0,) * 6):
    return tuple(entry) + tuple(results) + tuple(dest)


def test_decode_is_sparse_and_splits_entries_from_results():
    out = nt.decode_entries([
        (NET_CLASSES.index("unknown"), raw(entry=(3, 1, 2))),
        (NET_CLASSES.index("inet4_tcp"), raw(results=(1, 0, 1, 0, 0, 0), dest=(2, 0, 0, 0, 0, 0))),
        (NET_CLASSES.index("local_ipc"), raw(results=(0, 0, 0, 0, 2, 1))),
        (NET_CLASSES.index("inet6_udp"), raw())])                      # all zero: absent
    assert out["entry_observed"] == {"connect": 3, "accept": 1, "accept4": 2}
    assert list(out["classes"]) == ["inet4_tcp", "local_ipc"]
    assert out["classes"]["inet4_tcp"]["dest"]["loopback"] == 2
    assert "dest" not in out["classes"]["local_ipc"]
    assert nt.check_in1(out).status == nt.PASS
    assert nt.totals([out, None]) == {"entries": 6, "results": 5}


@pytest.mark.parametrize("bad", [
    [(99, raw())],                                                  # unknown class code
    [(0, raw()), (0, raw())],                                       # duplicate class
    [(0, raw(entry=(1, 0, 0)))],                                    # entry outside "unknown"
    [(NET_CLASSES.index("local_ipc"), raw(dest=(1, 0, 0, 0, 0, 0)))],  # dest on non-IP
    [(0, raw()[:-1])],                                              # malformed
    [(0, raw(results=(-1, 0, 0, 0, 0, 0)))]])
def test_decode_refuses_impossible_entries(bad):
    with pytest.raises(nt.NetDecodeError):
        nt.decode_entries(bad)


def test_in1_detects_destination_and_class_violations():
    ok = nt.expected_net([("connect", "inet4_udp", "public", "connect_ok")])
    assert nt.check_in1(ok).status == nt.PASS
    bad = copy.deepcopy(ok)
    bad["classes"]["inet4_udp"]["dest"]["public"] = 2                 # dest != results
    assert nt.check_in1(bad).status == nt.FAIL
    bad = copy.deepcopy(ok)
    bad["classes"]["local_ipc"] = dict(bad["classes"].pop("inet4_udp"))   # IPC with a dest
    assert nt.check_in1(bad).status == nt.FAIL
    assert nt.check_in1(None).status == nt.NOT_APPLICABLE


def test_expected_net_and_in6():
    script = [("connect", "inet4_tcp", "loopback", "connect_ok"),
              ("connect", "inet4_tcp", "loopback", "connect_refused"),
              ("accept4", "inet4_tcp", "accept_ok"), ("accept", "local_ipc", "accept_err"),
              ("connect", "unknown", None, "connect_err")]
    e = nt.expected_net(script)
    assert e["entry_observed"] == {"connect": 3, "accept": 1, "accept4": 1}
    assert e["classes"]["inet4_tcp"]["dest"]["loopback"] == 2
    zero = dict.fromkeys([f"{s}.{f}" for s in NET_SYSCALLS for f in nt.LOSS_FIELDS], 0)
    zero["net_map_full"] = 0
    assert nt.check_in6(e, copy.deepcopy(e), losses=zero).status == nt.PASS
    other = copy.deepcopy(e)
    other["classes"]["inet4_tcp"]["connect_ok"] += 1
    assert nt.check_in6(other, e, losses=zero).status == nt.FAIL
    assert nt.check_in6(e, e, losses=None).status == nt.NOT_APPLICABLE
    assert nt.check_in6(e, e, losses=dict(zero, net_map_full=1)).status == nt.NOT_APPLICABLE
    with pytest.raises(ValueError):
        nt.expected_net([("connect", "local_ipc", "public", "connect_ok")])


def test_in3_and_in5_are_not_applicable_before_s33():
    assert nt.check_in3().status == nt.NOT_APPLICABLE
    assert nt.check_in5().status == nt.NOT_APPLICABLE


def _terms():
    hook = dict.fromkeys(nt.HOOK_KEYS, 0)
    h = {sc: dict(hook) for sc in NET_SYSCALLS}
    rec = {"entry": {"connect": 5, "accept": 1, "accept4": 2}, "connect_results": 4,
           "accept_results": 2}
    h["connect"].update(seen_enter=7, unresolved_enter=1, excluded_enter=1, seen_exit=7,
                        unresolved_exit=1, excluded_exit=1, exit_without_entry=1,
                        stash_entries=5, matched=4, stash_live=1)
    h["accept"].update(seen_enter=1, seen_exit=1, stash_entries=1, matched=1)
    h["accept4"].update(seen_enter=3, dropped_enter=1, seen_exit=2, exit_without_entry=1,
                        stash_entries=2, matched=1, stash_orphaned=1)
    return {"drained": True, "recorded": rec, "hooks": h, "net_map_full": 1}


def test_in2_and_in4_hold_on_balanced_terms():
    t = _terms()
    r2, r4 = nt.check_in2(t), nt.check_in4(t)
    assert r2.status == nt.PASS, r2
    assert r4.status == nt.PASS, r4


@pytest.mark.parametrize("path,check", [
    (("hooks", "connect", "seen_enter"), "I-N2"), (("recorded", "connect_results"), "I-N2"),
    (("hooks", "accept4", "dropped_enter"), "I-N2"), (("hooks", "accept", "purged_results"), "I-N2"),
    (("hooks", "connect", "stash_live"), "I-N4"), (("hooks", "accept4", "stash_orphaned"), "I-N4"),
    (("hooks", "connect", "purged_stash"), "I-N4")])
def test_in2_and_in4_fail_on_any_missing_or_extra_term(path, check):
    t = _terms()
    node = t
    for k in path[:-1]:
        node = node[k]
    node[path[-1]] += 1
    fn = nt.check_in2 if check == "I-N2" else nt.check_in4
    assert fn(t).status == nt.FAIL


def test_in2_and_in4_need_a_drain_and_refuse_orphans():
    t = _terms()
    t["drained"] = False
    assert nt.check_in2(t).status == nt.check_in4(t).status == nt.NOT_APPLICABLE
    assert nt.check_in2(None).status == nt.NOT_APPLICABLE
    t = _terms()
    t["orphan_entries"] = 1
    assert nt.check_in2(t).status == nt.FAIL


# --- emitter, schema, validator, Reconstructor ------------------------------------------------------

def netfake():
    f = BigramCollectorFake()
    f.has_net = True
    for tgid in (10, 20, 30):
        f.add(tgid)
        f.step_pair(tgid, "START_NEW", "execve")
    return f


def step(em, commit=True):
    recs, done = em.build()
    for r in recs:
        assert V.errors(r) == [], (r["type"], V.errors(r))
        assert line_violations(encode_record(r).encode()) == []
    if commit:
        done()
    return recs


def of(recs, t):
    return [r for r in recs if r["type"] == t]


def feed(rc, recs):
    for r in recs:
        rc.feed(r)


def test_emitter_net_ok_shape_and_reconstruction():
    f = netfake()
    f.net_event(10, "connect", "inet4_tcp", "connect_ok", "loopback", n=2)
    f.net_event(20, "accept4", "local_ipc", "accept_ok")
    em = V2Emitter(f, run_id="r", bigrams="ok", net="ok")
    recs = step(em)
    cap = recs[0]["capabilities"]["net"]
    assert cap["status"] == "ok" and cap["epoch"] == recs[0]["capabilities"]["counts"]["epoch"]
    procs = {p["key"]["tgid"]: p for p in of(recs, "bpf_proc")}
    assert procs[10]["net"]["classes"]["inet4_tcp"]["connect_ok"] == 2 and procs[10]["net_err"] is None
    assert procs[30]["net"] == nt.empty_net()                           # touched no socket
    end = recs[-1]
    assert end["totals"]["net"] == {"entries": 3, "results": 3}
    assert end["net_health"]["hooks"]["connect"]["matched"] == 2 and end["drained"] is False
    rc = Reconstructor()
    feed(rc, recs)
    assert rc.valid, rc.errors


def test_counts_only_and_bigram_streams_keep_their_shape():
    f = netfake()
    recs = step(V2Emitter(f, run_id="r", bigrams="ok"))
    assert "net" not in recs[0]["capabilities"]
    assert not any("net" in p or "net_err" in p for p in of(recs, "bpf_proc"))
    assert "net_health" not in recs[-1] and "net" not in recs[-1]["totals"]
    assert "drained" in recs[-1]                                       # bigrams: as in S2
    recs = step(V2Emitter(f, run_id="r"))
    assert not any(k in recs[-1] for k in ("drained", "net_health", "bigram_health"))


def test_net_only_stream_carries_drained():
    f = netfake()
    recs = step(V2Emitter(f, run_id="r", net="ok"))
    assert "drained" in recs[-1] and "bigram_health" not in recs[-1]
    rc = Reconstructor()
    feed(rc, recs)
    assert rc.valid


def test_a_net_only_change_reemits_the_process():
    f = netfake()
    em = V2Emitter(f, run_id="r", net="ok")
    rc = Reconstructor()
    feed(rc, step(em))
    f.net_event(30, "connect", "inet6_udp", "connect_err", "unknown")   # counts unchanged
    recs = step(em)
    assert [p["key"]["tgid"] for p in of(recs, "bpf_proc")] == [30]
    feed(rc, recs)
    assert rc.valid and rc.last.unchanged == {k for k in rc.state if k[2] != 30}


def test_unavailable_net_is_null_with_an_error_never_zeros():
    f = netfake()
    recs = step(V2Emitter(f, run_id="r", net="unavailable", net_reason="program failed: X"))
    cap = recs[0]["capabilities"]["net"]
    assert cap == {"status": "unavailable", "epoch": None, "err": "UNSUPPORTED",
                   "reason": "program failed: X"}
    assert all(p["net"] is None and p["net_err"] == "UNSUPPORTED" for p in of(recs, "bpf_proc"))
    assert recs[-1]["totals"]["net"] is None and recs[-1]["net_health"] is None
    rc = Reconstructor()
    feed(rc, recs)
    assert rc.valid
    with pytest.raises(ValueError):
        V2Emitter(netfake(), run_id="r", net="unavailable")            # reason required
    plain = BigramCollectorFake()
    with pytest.raises(ValueError, match="net"):
        V2Emitter(plain, run_id="r", net="ok")                        # no capability


def test_failed_snapshot_with_net_changes_nothing():
    f = netfake()
    em = V2Emitter(f, run_id="r", net="ok")
    rc = Reconstructor()
    feed(rc, step(em))
    f.fail = True
    recs = step(em)
    end = recs[-1]
    assert end["status"] == "failed" and end["net_health"] is None and end["drained"] is False
    assert end["totals"]["net"] == {"entries": 0, "results": 0}
    feed(rc, recs)
    assert rc.valid


@pytest.mark.parametrize("mutate,why", [
    (lambda rs: rs[1].pop("net_err"), "net without net_err"),
    (lambda rs: rs[1].update(net=None), "net null while ok"),
    (lambda rs: rs[1]["net"]["classes"].update(
        other=dict.fromkeys(NET_RESULTS, 0)), "empty class object"),
    (lambda rs: rs[-1].pop("drained"), "drained missing"),
    (lambda rs: rs[-1]["totals"].update(net={"entries": 99, "results": 0}), "wrong totals"),
    (lambda rs: rs[-1].pop("net_health"), "net_health missing")])
def test_damaged_net_snapshots_are_rejected(mutate, why):
    f = netfake()
    f.net_event(10, "connect", "inet4_tcp", "connect_ok", "loopback")
    recs, _ = V2Emitter(f, run_id="r", net="ok").build()
    recs = copy.deepcopy(recs)
    mutate(recs)
    rc = Reconstructor()
    feed(rc, recs)
    assert not rc.valid, why


def test_validator_rejects_record_level_net_violations():
    f = netfake()
    f.net_event(10, "connect", "inet4_tcp", "connect_ok", "loopback")
    recs, _ = V2Emitter(f, run_id="r", net="ok").build()
    proc = copy.deepcopy(of(recs, "bpf_proc")[0])
    proc["net"]["classes"]["inet4_tcp"]["dest"]["public"] = 5
    assert any("I-N1" in e for e in V.errors(proc))
    proc = copy.deepcopy(of(recs, "bpf_proc")[0])
    proc["net"]["classes"]["inet4_tcp"]["port"] = 80                  # no raw port, ever
    assert V.errors(proc)
    end = copy.deepcopy(recs[-1])
    end.pop("drained")
    assert any("drained" in e for e in V.errors(end))


def test_stream_level_in2_in4_on_a_drained_net_stream():
    f = netfake()
    em = V2Emitter(f, run_id="r", net="ok")
    rc = Reconstructor()
    f.net_event(10, "connect", "inet4_tcp", "connect_ok", "loopback", n=3)
    f.net_event(20, "accept4", "inet6_tcp", "accept_ok", n=2)
    f.net_event(30, "connect", "local_ipc", "connect_err")
    feed(rc, step(em))
    f.exit(20)
    feed(rc, step(em))
    f.reclaim(20)                                                    # reclaimed as exited
    f.purge(30)                                                      # purged
    feed(rc, step(em))
    f.drain()
    feed(rc, step(em))
    rc.finish()
    terms = nt.terms_from_stream(rc)
    assert terms is not None
    assert nt.check_in2(terms).status == nt.PASS, nt.check_in2(terms)
    assert nt.check_in4(terms).status == nt.PASS
    for kt, p in rc.state.items():
        assert nt.check_in1(p["net"], kt).status == nt.PASS
    # a reclaimed key counted again, or a purge term dropped, is caught
    bad = copy.deepcopy(terms)
    bad["recorded"]["accept_results"] += 2
    assert nt.check_in2(bad).status == nt.FAIL
    rc.last_ok_end["net_health"]["hooks"]["connect"]["purged_results"] = 0
    assert nt.check_in2(nt.terms_from_stream(rc)).status == nt.FAIL


def test_terms_from_stream_needs_a_drained_snapshot():
    f = netfake()
    rc = Reconstructor()
    feed(rc, step(V2Emitter(f, run_id="r", net="ok")))
    assert nt.terms_from_stream(rc) is None
    assert nt.check_in2(None).status == nt.NOT_APPLICABLE


# --- agent ----------------------------------------------------------------------------------

import json  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402

from processpulse import agent as agent_mod  # noqa: E402
from processpulse.agent import Agent  # noqa: E402

FAKE_C = [sys.executable, os.path.join(os.path.dirname(__file__), "helpers", "fake_collector.py")]


@pytest.fixture
def agent_env(monkeypatch):
    monkeypatch.setenv("PPC_FAKE_MODE", "forever")
    monkeypatch.setattr(agent_mod, "run_preflight", lambda: {"ok": True, "checks": []})


def test_agent_net_run_is_drained_and_balanced(agent_env, monkeypatch, tmp_path):
    f = netfake()
    f.net_event(10, "connect", "inet4_tcp", "connect_ok", "loopback")
    f.net_event(20, "accept", "inet6_tcp", "accept_err")
    monkeypatch.setattr(Agent, "_start_bpf",
                        lambda self, log: (f, None, {"net": "ok"}, None, None))
    m = Agent(str(tmp_path), interval_ms=50, duration_s=1, collector=FAKE_C, schema=2,
              capabilities=("counts", "net")).run()
    assert m["net"] == {"mode": "ok", "reason": None} and m["bigrams"] is None
    assert m["capabilities"] == {"requested": ["counts", "net"], "active": ["counts", "net"],
                                 "failed": {}}
    assert m["drain"]["status"] == "drained" and m["drain"]["final_snapshot"]["drained"] is True
    recs = [json.loads(l) for l in open(tmp_path / "bpf.jsonl")]
    assert all(V.errors(r) == [] for r in recs)
    rc = Reconstructor()
    feed(rc, recs)
    rc.finish()
    assert rc.valid and rc.last.drained
    t = nt.terms_from_stream(rc)
    assert nt.check_in2(t).status == nt.PASS and nt.check_in4(t).status == nt.PASS


def test_agent_net_startup_failure_is_strict_by_default(agent_env, monkeypatch, tmp_path):
    from processpulse import bpf_collector as bcm

    class Failing:
        def __init__(self, **kw):
            assert kw["capabilities"] == ("counts", "net")

        def start(self):
            raise RuntimeError("compile failed: net.bpf.c")

        def close(self):
            pass
    monkeypatch.setattr(bcm, "BpfCollector", Failing)
    a = Agent(str(tmp_path), schema=2, capabilities=("counts", "net"))
    with pytest.raises(agent_mod.StartupError, match="net"):
        a.run()
    m = json.load(open(tmp_path / "manifest.json"))
    assert m["status"] == "failed" and m["error"]["capability"] == "net"
    assert "compile failed" in m["capabilities"]["failed"]["net"]


def test_agent_net_degraded_mode_marks_net_unavailable(agent_env, monkeypatch, tmp_path):
    from processpulse import bpf_collector as bcm
    from processpulse import syscalls as sysm

    class Failing:
        def __init__(self, **kw):
            pass

        def start(self):
            raise RuntimeError("compile failed: net.bpf.c")

        def close(self):
            pass

    def counts_only(**kw):
        f = netfake()
        f.has_net = False
        f.has_bigrams = False
        f.start = lambda: f
        return f
    monkeypatch.setattr(bcm, "BpfCollector", Failing)
    monkeypatch.setattr(sysm, "SyscallCollector", counts_only)
    m = Agent(str(tmp_path), interval_ms=50, duration_s=1, collector=FAKE_C, schema=2,
              capabilities=("counts", "bigrams", "net"), allow_degraded=True).run()
    assert m["degraded"] is True and m["capabilities"]["active"] == ["counts"]
    assert set(m["capabilities"]["failed"]) == {"bigrams", "net"}
    recs = [json.loads(l) for l in open(tmp_path / "bpf.jsonl")]
    cap = recs[0]["capabilities"]
    assert cap["net"]["status"] == cap["bigrams"]["status"] == "unavailable"
    assert all(p["net"] is None and p["net_err"] == "UNSUPPORTED" for p in recs
               if p["type"] == "bpf_proc")
    assert m["drain"] is None
