"""tools/acceptance/validate_run.py on synthetic v1 and v2 run directories.

v1 runs keep their M1 verdicts: oversize or CR-terminated v1 lines are
counted as legacy findings, not failures (M1b plan v3, decision A1). v2 runs
fail on any line-rule violation and on any snapshot-protocol violation.
"""

import copy
import hashlib
import json
import os
import subprocess
import sys

import pytest

from processpulse.jsonl import MAX_RECORD_BYTES
from processpulse.snapshots import V2Emitter
from snapshot_fakes import FakeCollector
from test_schemas import BEGIN, END, HEALTH, PROC, SNAPSHOT

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VALIDATE = os.path.join(REPO, "tools", "acceptance", "validate_run.py")
M1_RUN = os.path.join(REPO, "results", "raw", "m1-10min-20261018T205546")
M1_EVIDENCE = os.path.join(REPO, "results", "acceptance", "m1", "10min", "validation.json")


def dumps(r):
    return json.dumps(r, separators=(",", ":"))


def write(path, records, raw_lines=()):
    with open(path, "w", encoding="utf-8", newline="") as f:
        for r in records:
            f.write(dumps(r) + "\n")
        for line in raw_lines:
            f.write(line)


def oversize_v1_snapshot():
    snap = copy.deepcopy(SNAPSHOT)
    base = snap["procs"][0]
    snap["procs"] = [dict(copy.deepcopy(base), key=dict(base["key"], tgid=1000 + i))
                     for i in range(400)]
    assert len(dumps(snap).encode()) > MAX_RECORD_BYTES
    return snap


def make_v1_run(d, snapshot=None, extra_resource=()):
    write(d / "resource.jsonl", [BEGIN, PROC, END], extra_resource)
    write(d / "syscall.jsonl", [snapshot or SNAPSHOT])
    write(d / "health.jsonl", [HEALTH])


def make_v2_run(d, mutate=None, snapshots=3):
    fake = FakeCollector()
    fake.add(846, openat=1)
    em = V2Emitter(fake, run_id="run-v")
    res, bpf, health = [], [], []
    for seq in range(snapshots):
        b = dict(BEGIN, seq=seq, t_mono_ns=100 + seq * 1000)
        p = dict(PROC, seq=seq, t_mono_ns=101 + seq * 1000)
        e = dict(END, seq=seq, t_mono_ns=200 + seq * 1000)
        res += [b, p, e]
        fake.bump(846)
        recs, done = em.build(resource_seq=seq)
        done()
        bpf += recs
        health.append(dict(HEALTH, seq=seq, syscall={"available": True, "reason": None}))
    lines = [dumps(r) + "\n" for r in bpf]
    if mutate:
        lines = mutate(lines)
    write(d / "resource.jsonl", res)
    with open(d / "bpf.jsonl", "w", encoding="utf-8", newline="") as f:
        f.writelines(lines)
    write(d / "health.jsonl", health)


def validate(d, *extra):
    out = d / "report.json"
    r = subprocess.run([sys.executable, VALIDATE, str(d), "--min-span-s", "0", "--json", str(out),
                        *extra], capture_output=True, text=True, timeout=600)
    return r.returncode, json.loads(out.read_text())


# --- v1: legacy findings are reported, verdict unchanged -------------------

def test_v1_run_with_oversize_snapshot_keeps_its_verdict(tmp_path):
    make_v1_run(tmp_path, snapshot=oversize_v1_snapshot())
    rc, rep = validate(tmp_path)
    assert rc == 0 and rep["ok"] and rep["mode"] == "v1"
    assert rep["checks"]["schema"]["ok"]
    assert rep["line_limits"]["legacy_v1_oversize"] == 1
    assert rep["files"]["syscall.jsonl"]["max_line_bytes"] > MAX_RECORD_BYTES
    assert rep["checks"]["line_limits"] == {"ok": True, "policy": "v1: reported, not enforced"}


def test_v1_trailing_cr_is_a_legacy_finding(tmp_path):
    make_v1_run(tmp_path, extra_resource=[dumps(dict(BEGIN, seq=1)) + "\r\n",
                                          dumps(dict(END, seq=1, emitted=0)) + "\n"])
    rc, rep = validate(tmp_path)
    assert rep["line_limits"]["legacy_v1_cr"] == 1
    assert rep["checks"]["schema"]["ok"]


def test_clean_v1_run_reports_no_legacy_findings(tmp_path):
    make_v1_run(tmp_path)
    rc, rep = validate(tmp_path)
    assert rc == 0 and rep["line_limits"]["legacy_v1_oversize"] == 0


# --- v2: line rule and snapshot protocol are enforced ----------------------

def test_clean_v2_run_passes(tmp_path):
    make_v2_run(tmp_path)
    rc, rep = validate(tmp_path)
    assert rc == 0 and rep["ok"] and rep["mode"] == "v2", rep["errors"]
    sp = rep["checks"]["snapshot_protocol"]
    assert sp["ok"] and sp["stats"]["snapshots_complete"] == 3 and sp["stats"]["keyframes"] == 1
    assert rep["checks"]["alignment"]["ok"]


def test_v2_oversize_record_fails(tmp_path):
    def grow(lines):
        rec = json.loads(lines[1])
        rec["comm"] = "x" * MAX_RECORD_BYTES
        lines[1] = dumps(rec) + "\n"
        return lines
    make_v2_run(tmp_path, mutate=grow)
    rc, rep = validate(tmp_path)
    assert rc == 1 and not rep["checks"]["schema"]["ok"]
    assert any("oversize" in e for e in rep["errors"])


def test_v2_trailing_cr_fails(tmp_path):
    def cr(lines):
        lines[0] = lines[0][:-1] + "\r\n"
        return lines
    make_v2_run(tmp_path, mutate=cr)
    rc, rep = validate(tmp_path)
    assert rc == 1 and any("trailing_cr" in e for e in rep["errors"])


def test_v1_oversize_line_inside_a_v2_run_fails(tmp_path):
    make_v2_run(tmp_path)
    with open(tmp_path / "resource.jsonl", "a", encoding="utf-8") as f:
        f.write(dumps(dict(PROC, seq=99, comm="y" * MAX_RECORD_BYTES)) + "\n")
    rc, rep = validate(tmp_path)
    assert rc == 1 and rep["checks"]["line_limits"]["ok"] is False


def test_v2_crash_mid_snapshot_is_rejected(tmp_path):
    make_v2_run(tmp_path, mutate=lambda lines: lines[:-1])      # last end record lost
    rc, rep = validate(tmp_path)
    assert rc == 1
    sp = rep["checks"]["snapshot_protocol"]
    assert not sp["ok"] and sp["stats"]["snapshots_incomplete"] == 1


def test_v2_missing_snapshot_is_rejected(tmp_path):
    def drop_middle(lines):
        return [l for l in lines if json.loads(l)["seq"] != 1]
    make_v2_run(tmp_path, mutate=drop_middle)
    rc, rep = validate(tmp_path)
    assert rc == 1 and rep["checks"]["snapshot_protocol"]["stats"]["seq_gaps"] == 1


# --- recorded M1 evidence (local only; raw runs are gitignored) ------------

needs_m1_run = pytest.mark.skipif(not os.path.isfile(os.path.join(M1_RUN, "syscall.jsonl")),
                                  reason="recorded M1 10-minute run not present (results/raw is gitignored)")


@needs_m1_run
def test_recorded_m1_run_has_exactly_15_oversize_lines():
    path = os.path.join(M1_RUN, "syscall.jsonl")
    with open(M1_EVIDENCE) as f:
        want = json.load(f)["files"]["syscall.jsonl"]["sha256"]
    with open(path, "rb") as f:
        data = f.read()
    assert hashlib.sha256(data).hexdigest() == want            # the file M1 accepted
    lengths = [len(l) for l in data.split(b"\n")[:-1]]
    assert len(lengths) == 613
    assert sum(n > MAX_RECORD_BYTES for n in lengths) == 15
    assert max(lengths) == 311053                              # bytes without the LF


@needs_m1_run
@pytest.mark.slow
def test_recorded_m1_run_still_validates_with_legacy_report(tmp_path):
    out = tmp_path / "m1.json"
    r = subprocess.run([sys.executable, VALIDATE, M1_RUN, "--min-span-s", "600", "--json", str(out)],
                       capture_output=True, text=True, timeout=600)
    rep = json.loads(out.read_text())
    assert r.returncode == 0 and rep["ok"] and rep["mode"] == "v1"
    assert rep["totals"] == {"lines": 27803, "valid": 27803, "invalid": 0}
    assert rep["line_limits"]["legacy_v1_oversize"] == 15
