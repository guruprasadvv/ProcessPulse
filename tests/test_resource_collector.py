"""Supervisor tests for processpulse.resource using a scriptable fake
collector, plus one run against the real binary."""

import os
import sys
import time

import pytest

from conftest import wait_until
from processpulse.resource import ResourceCollector

FAKE = [sys.executable, os.path.join(os.path.dirname(__file__), "helpers", "fake_collector.py")]


def drain(rc, timeout=10.0):
    got, end = [], time.monotonic() + timeout
    while time.monotonic() < end:
        s = rc.get(timeout=0.1)
        if s is not None:
            got.append(s)
        elif rc.finished:
            break
    return got


@pytest.fixture
def fake(monkeypatch, tmp_path):
    def _make(mode, **kw):
        monkeypatch.setenv("PPC_FAKE_MODE", mode)
        monkeypatch.setenv("PPC_FAKE_STATE", str(tmp_path / "state"))
        kw.setdefault("count", 99)
        kw.setdefault("backoff_s", (0.05,))
        rc = ResourceCollector(FAKE, **kw)
        rc.start()
        return rc
    made = []
    yield lambda mode, **kw: made.append(_make(mode, **kw)) or made[-1]
    for rc in made:
        rc.stop()


def test_complete_samples_delivered_in_order(fake):
    rc = fake("ok:3")
    got = drain(rc)
    assert [s.seq for s in got] == [0, 1, 2]
    assert all(len(s.procs) == s.end["emitted"] == 2 for s in got)
    st = rc.stats()
    assert st["samples"] == 3 and st["restarts"] == 0 and st["last_exit_code"] == 0


def test_malformed_lines_counted_not_forwarded(fake):
    rc = fake("garbage")
    got = drain(rc)
    assert [s.seq for s in got] == [0, 1]
    st = rc.stats()
    assert st["malformed_json"] == 1
    assert st["invalid_utf8"] == 1
    assert st["not_object"] == 1
    assert st["oversize_lines"] == 1
    assert st["framing_errors"] == 0


def test_crash_mid_sample_discarded_and_restarted(fake):
    rc = fake("crash_once")
    got = drain(rc)
    assert [(s.epoch, s.seq) for s in got] == [(0, 0), (1, 0), (1, 1)]
    st = rc.stats()
    assert st["restarts"] == 1 and st["epoch"] == 1
    assert st["framing_errors"] == 1          # the incomplete sample from epoch 0


def test_schema_error_discards_sample(fake):
    rc = fake("schema_error")
    got = drain(rc)
    assert [s.seq for s in got] == [1]
    st = rc.stats()
    assert st["schema_errors"] == 1 and st["framing_errors"] == 1


def test_backpressure_drops_oldest(fake):
    rc = fake("ok:10", max_queue=2)
    assert wait_until(lambda: rc.stats()["samples"] == 10, timeout=10)
    got = drain(rc)
    assert [s.seq for s in got] == [8, 9]
    assert rc.stats()["dropped_samples"] == 8


def test_stop_terminates_child(fake):
    rc = fake("forever", count=0)
    assert wait_until(lambda: rc.stats()["samples"] >= 2)
    pid = rc.pid
    rc.stop()
    assert rc.stats()["alive"] is False
    assert not os.path.exists(f"/proc/{pid}") or open(f"/proc/{pid}/stat").read().split(") ")[1][0] == "Z"


@pytest.mark.integration
def test_real_collector_samples(collector_bin):
    rc = ResourceCollector(collector_bin, interval_ms=50, count=3)
    rc.start()
    got = drain(rc)
    rc.stop()
    assert [s.seq for s in got] == [0, 1, 2]
    st = rc.stats()
    assert st["schema_errors"] == 0 and st["framing_errors"] == 0 and st["last_exit_code"] == 0
