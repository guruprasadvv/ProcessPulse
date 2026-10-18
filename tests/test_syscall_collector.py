"""Privileged tests for the BCC syscall collector (M1 acceptance subset).

Run as root:  make test-privileged
"""

import os
import subprocess

import pytest

from conftest import Helper
from processpulse.identity import own_pidns_ino
from processpulse.syscalls import FAMILIES, SYSCALLS, SyscallCollector, calibrate
from processpulse.validate import Validator

pytestmark = [pytest.mark.privileged, pytest.mark.bpf]

# helper command -> syscall it issues
COMMANDS = {"openat": "openat", "open": "open", "execve": "execve", "clone": "clone",
            "getpid": None}


@pytest.fixture(scope="module")
def sc():
    c = SyscallCollector().start()
    yield c
    c.close()


def entry(snap, tgid):
    found = [p for p in snap["procs"] if p["key"]["tgid"] == tgid]
    assert len(found) <= 1, found
    return found[0] if found else None


def counts(snap, tgid):
    e = entry(snap, tgid)
    return e["counts"] if e else {s: 0 for s in SYSCALLS}


def stat_starttime(pid):
    with open(f"/proc/{pid}/stat", "rb") as f:
        data = f.read()
    return int(data[data.rindex(b")") + 2:].split()[19])


def test_calibration_matches_procfs():
    level, ino = calibrate()
    assert ino == own_pidns_ino()
    assert level >= 0
    assert calibrate() == (level, ino)            # stable across loads


def test_snapshots_are_schema_valid(sc, spawn_helper):
    h = spawn_helper()
    h.do("openat", 3)
    snap = sc.snapshot()
    assert Validator().errors(snap) == []


@pytest.mark.parametrize("n", [1, 1000])
@pytest.mark.parametrize("cmd", ["openat", "open", "execve", "clone"])
def test_exact_entry_counts(sc, spawn_helper, record_property, cmd, n):
    h = spawn_helper()
    before = counts(sc.snapshot(), h.pid)
    h.do(cmd, n)
    after = counts(sc.snapshot(), h.pid)
    delta = {s: after[s] - before[s] for s in SYSCALLS}
    # Recorded in JUnit XML so acceptance repetitions keep the observed values.
    record_property("syscall", COMMANDS[cmd])
    record_property("expected", n)
    record_property("observed", delta[COMMANDS[cmd]])
    record_property("other_syscalls_delta", sum(v for s, v in delta.items() if s != COMMANDS[cmd]))
    assert delta[COMMANDS[cmd]] == n
    assert all(v == 0 for s, v in delta.items() if s != COMMANDS[cmd]), delta


@pytest.mark.slow
@pytest.mark.parametrize("cmd", ["openat", "execve", "clone"])
def test_exact_entry_counts_100000(sc, spawn_helper, record_property, cmd):
    h = spawn_helper()
    before = counts(sc.snapshot(), h.pid)
    h.do(cmd, 100000)
    after = counts(sc.snapshot(), h.pid)
    fam = next(f for f, members in FAMILIES.items() if COMMANDS[cmd] in members)
    record_property("syscall", COMMANDS[cmd])
    record_property("expected", 100000)
    record_property("observed", after[COMMANDS[cmd]] - before[COMMANDS[cmd]])
    record_property("family_delta", sum(after[s] - before[s] for s in FAMILIES[fam]))
    assert after[COMMANDS[cmd]] - before[COMMANDS[cmd]] == 100000
    assert sum(after[s] - before[s] for s in FAMILIES[fam]) == 100000


def test_identity_fields(sc, spawn_helper):
    h = spawn_helper()
    h.do("openat", 1)
    e = entry(sc.snapshot(), h.pid)
    assert e is not None
    assert e["key"]["tgid"] == h.pid == h.reported_pid
    assert e["key"]["pidns_ino"] == own_pidns_ino()
    assert e["level"] == sc.distro_level and e["container_pid"] is None
    assert e["comm"] == "sysc_helper"                     # refreshed after execve
    assert e["key"]["start_ticks"] == stat_starttime(h.pid)


@pytest.mark.slow
def test_start_ticks_match_procfs_for_1000_processes(sc, helper_bin):
    mismatches, checked = [], 0
    for _batch in range(5):
        helpers = [Helper([helper_bin]) for _ in range(200)]
        try:
            snap = sc.snapshot()
            for h in helpers:
                e = entry(snap, h.pid)
                assert e is not None, f"no BPF entry for helper {h.pid}"
                checked += 1
                if e["key"]["start_ticks"] != stat_starttime(h.pid):
                    mismatches.append((h.pid, e["key"]["start_ticks"], stat_starttime(h.pid)))
        finally:
            for h in helpers:
                h.exit()
    assert checked == 1000
    assert mismatches == []


def test_exit_reported_once_then_reclaimed(sc, spawn_helper):
    h = spawn_helper()
    h.do("openat", 5)
    final = counts(sc.snapshot(), h.pid)["openat"]
    assert h.exit() == 0
    s1 = sc.snapshot()
    e1 = entry(s1, h.pid)
    assert e1 is not None and e1["exited"] is True and e1["counts"]["openat"] == final
    reclaimed_before = s1["health"]["reclaimed"]
    s2 = sc.snapshot()
    assert entry(s2, h.pid) is None
    assert s2["health"]["reclaimed"] >= reclaimed_before + 1
    assert s2["health"]["exit_events"] >= 1


def test_own_events_are_excluded_and_counted(sc):
    before = sc.snapshot()["health"]["self_excluded_events"]
    for _ in range(10):
        try:
            os.open("/nonexistent-processpulse/self", os.O_RDONLY)
        except FileNotFoundError:
            pass
    snap = sc.snapshot()
    assert entry(snap, os.getpid()) is None
    assert snap["health"]["self_excluded_events"] - before >= 10


def test_namespace_inode_mismatch_is_unresolved_never_attributed(spawn_helper):
    bad = SyscallCollector(distro_inum_override=own_pidns_ino() ^ 1).start()
    try:
        h = spawn_helper()
        before = bad.snapshot()["health"]["unresolved_events"]
        h.do("openat", 100)
        snap = bad.snapshot()
        assert snap["procs"] == []
        assert snap["health"]["unresolved_events"] - before >= 100
    finally:
        bad.close()


def test_map_full_is_counted_not_fatal(spawn_helper):
    small = SyscallCollector(max_procs=4).start()
    try:
        for _ in range(10):
            spawn_helper().do("openat", 1)
        snap = small.snapshot()
        assert snap["health"]["map_entries"] <= 4
        assert snap["health"]["counts_map_full"] >= 1
    finally:
        small.close()


def test_kernel_timestamps_fall_between_userspace_reads(sc, spawn_helper):
    import time
    h = spawn_helper()
    h.do("openat", 1)
    for _ in range(20):
        t1 = time.monotonic_ns()
        h.do("openat", 1)
        t2 = time.monotonic_ns()
        k = sc.last_event_ktime(h.pid)
        assert t1 <= k <= t2, (t1, k, t2)
