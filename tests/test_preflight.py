"""Preflight tests: unprivileged runs must report BLOCKED (never attempt
privileged actions); privileged runs must pass on the target environment."""

import pytest

from conftest import IS_ROOT
from processpulse.preflight import REQUIRED, run_preflight


def _status(report, name):
    return next(c["status"] for c in report["checks"] if c["name"] == name)


@pytest.mark.skipif(IS_ROOT, reason="checks unprivileged behaviour")
def test_unprivileged_reports_blocked_without_modprobe():
    r = run_preflight(attempt_modprobe=True)
    assert r["ok"] is False
    assert _status(r, "root") == "BLOCKED"
    assert r["kheaders_modprobe"] is None          # never attempted without root
    assert {c["name"] for c in r["checks"]} >= set(REQUIRED)


@pytest.mark.privileged
@pytest.mark.bpf
def test_privileged_preflight_passes():
    r = run_preflight(attempt_modprobe=True)
    failing = [c for c in r["checks"] if c["name"] in REQUIRED and c["status"] != "PASS"]
    assert not failing, failing
    assert r["ok"] is True
