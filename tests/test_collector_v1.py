"""Integration tests for `collector --v1` (resource schema v1) and the M0
defect regressions D1/D2/D6 in both output modes."""

import json
import os
import signal
import subprocess
import sys
import time

import pytest

from conftest import IS_ROOT, wait_until
from processpulse.validate import Validator

pytestmark = pytest.mark.integration


def parse(stdout):
    text = stdout.decode("utf-8", errors="strict")   # D2: must always be valid UTF-8
    return [json.loads(line) for line in text.splitlines() if line]


def run(collector_bin, *args, timeout=60):
    return subprocess.run([collector_bin, *args], capture_output=True, timeout=timeout)


def samples(records):
    out, cur = [], None
    for r in records:
        if r["type"] == "sample_begin":
            assert cur is None
            cur = {"begin": r, "procs": []}
        elif r["type"] == "proc":
            cur["procs"].append(r)
        else:
            cur["end"] = r
            out.append(cur)
            cur = None
    assert cur is None, "output ended inside a sample"
    return out


def find_pid(records, pid):
    return [r for r in records if r.get("type") == "proc" and r["pid"] == pid]


def test_every_record_is_schema_valid(collector_bin):
    r = run(collector_bin, "--v1", "--count", "3", "--interval-ms", "50")
    assert r.returncode == 0, r.stderr
    v = Validator()
    recs = parse(r.stdout)
    bad = [(rec.get("type"), v.errors(rec)) for rec in recs if v.errors(rec)]
    assert not bad, bad[:5]


def test_jsonschema_agrees_on_real_output(collector_bin):
    jsonschema = pytest.importorskip("jsonschema")
    v = Validator()
    js = jsonschema.Draft202012Validator(v.schema)
    for rec in parse(run(collector_bin, "--v1", "--count", "1").stdout):
        assert not list(js.iter_errors(rec)), rec


def test_framing_sequence_and_counts(collector_bin):
    recs = parse(run(collector_bin, "--v1", "--count", "3", "--interval-ms", "50").stdout)
    ss = samples(recs)
    assert [s["begin"]["seq"] for s in ss] == [0, 1, 2]
    for s in ss:
        assert s["end"]["seq"] == s["begin"]["seq"]
        assert all(p["seq"] == s["begin"]["seq"] for p in s["procs"])
        assert s["end"]["emitted"] == len(s["procs"])
        assert s["end"]["pids_seen"] == (s["end"]["emitted"] + s["end"]["gone"] + s["end"]["denied"]
                                         + s["end"]["parse_errors"] + s["end"]["read_errors"])
        assert len({p["pid"] for p in s["procs"]}) == len(s["procs"]), "duplicate pid in a sample"


def test_monotonic_timestamps_share_python_clock(collector_bin):
    t_before = time.monotonic_ns()
    recs = parse(run(collector_bin, "--v1", "--count", "3", "--interval-ms", "50").stdout)
    t_after = time.monotonic_ns()
    ts = [r["t_mono_ns"] for r in recs]
    assert ts == sorted(ts), "t_mono_ns must be non-decreasing in emission order"
    assert t_before <= ts[0] and ts[-1] <= t_after
    begins = [r["t_mono_ns"] for r in recs if r["type"] == "sample_begin"]
    gaps = [b - a for a, b in zip(begins, begins[1:])]
    assert all(g >= 45_000_000 for g in gaps), gaps   # 50 ms interval, small timer slack


def test_bad_arguments_exit_2(collector_bin):
    for args in (["--bogus"], ["--v1", "--interval-ms", "5"], ["--v1", "--count", "-1"],
                 ["--interval-ms", "100"]):
        assert run(collector_bin, *args).returncode == 2, args


def test_d1_newline_in_comm_is_reported_both_modes(collector_bin, named_process):
    p = named_process(b"evil\nhidden")
    v1 = find_pid(parse(run(collector_bin, "--v1", "--count", "1").stdout), p.pid)
    assert len(v1) == 1 and v1[0]["comm"] == "evil\nhidden"
    legacy = [r for r in parse(run(collector_bin).stdout) if r["pid"] == p.pid]
    assert len(legacy) == 1 and legacy[0]["comm"] == "evil\nhidden"


def test_d2_invalid_utf8_comm_is_replaced_and_flagged(collector_bin, named_process):
    p = named_process(b"bad\xff\xfename")
    v1 = find_pid(parse(run(collector_bin, "--v1", "--count", "1").stdout), p.pid)
    assert v1[0]["comm"] == "bad��name"
    assert v1[0]["comm_utf8_valid"] is False
    legacy = [r for r in parse(run(collector_bin).stdout) if r["pid"] == p.pid]
    assert legacy[0]["comm"] == "bad��name"


def test_valid_utf8_and_paren_comm_preserved(collector_bin, named_process):
    p1 = named_process("café".encode())
    p2 = named_process(b"a) R 1 (b")
    recs = parse(run(collector_bin, "--v1", "--count", "1").stdout)
    r1, r2 = find_pid(recs, p1.pid)[0], find_pid(recs, p2.pid)[0]
    assert r1["comm"] == "café" and r1["comm_utf8_valid"] is True
    assert r2["comm"] == "a) R 1 (b" and r2["state"] in "RSD"


@pytest.mark.skipif(IS_ROOT, reason="checks unprivileged behaviour")
def test_unreadable_fields_are_null_with_error_not_zero(collector_bin):
    pid1 = find_pid(parse(run(collector_bin, "--v1", "--count", "1").stdout), 1)[0]
    assert pid1["uid_real"] == 0
    assert pid1["io"] is None and pid1["io_err"] == "EACCES"
    assert pid1["fd_count"] is None and pid1["fd_err"] == "EACCES"


def test_sigterm_finishes_sample_and_exits_0(collector_bin):
    p = subprocess.Popen([collector_bin, "--v1", "--interval-ms", "100"], stdout=subprocess.PIPE)
    lines = []
    while sum(1 for l in lines if b'"sample_end"' in l) < 2:
        lines.append(p.stdout.readline())
    p.send_signal(signal.SIGTERM)
    rest, _ = p.communicate(timeout=5)
    assert p.returncode == 0
    recs = parse(b"".join(lines) + rest)
    assert recs[-1]["type"] == "sample_end"
    samples(recs)   # framing intact


def test_closed_stdout_exits_3_promptly(collector_bin):
    p = subprocess.Popen([collector_bin, "--v1", "--interval-ms", "50"], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    p.stdout.readline()
    p.stdout.close()
    assert p.wait(timeout=5) == 3
    assert b"stdout write failed" in p.stderr.read()


def test_parent_death_stops_collector(collector_bin):
    # The parent is killed immediately, possibly before the collector arms
    # PR_SET_PDEATHSIG; PPC_SUPERVISOR_PID must close that race.
    code = (
        "import os, subprocess, sys, time\n"
        f"c = subprocess.Popen([{collector_bin!r}, '--v1', '--interval-ms', '100'],"
        " stdout=subprocess.DEVNULL,"
        " env=dict(os.environ, PPC_SUPERVISOR_PID=str(os.getpid())))\n"
        "print(c.pid, flush=True)\n"
        "time.sleep(60)\n"
    )
    parent = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    child_pid = int(parent.stdout.readline())
    parent.kill()
    parent.wait()

    def gone():
        try:
            with open(f"/proc/{child_pid}/stat") as f:
                return f.read().split(") ", 1)[1][0] == "Z"
        except FileNotFoundError:
            return True

    assert wait_until(gone, timeout=5), "collector survived its parent"


def test_legacy_mode_keeps_m0_schema(collector_bin):
    recs = parse(run(collector_bin).stdout)
    assert recs and all(set(r) == {"pid", "comm", "utime", "stime"} for r in recs)
