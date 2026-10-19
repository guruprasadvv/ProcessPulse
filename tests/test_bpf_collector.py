"""Privileged tests of the unified BPF collector (M1b S1): compilation count and
capability selection, per-thread slot lifecycle (F4), metadata refresh at exec (F9).

Run as root:  make test-privileged
"""

import os
import shutil
import uuid

import pytest

from conftest import Helper
from processpulse import bpf_collector as bc
from processpulse.identity import CGROUP_ROOT, CgroupResolver, clk_tck, start_ticks_from_ns
from processpulse.vocab import SYSCALLS

pytestmark = [pytest.mark.privileged, pytest.mark.bpf]


def bpf_prog_fds():
    n = 0
    for fd in os.listdir("/proc/self/fd"):
        try:
            if os.readlink(f"/proc/self/fd/{fd}") == "anon_inode:bpf-prog":
                n += 1
        except OSError:
            pass
    return n


@pytest.fixture(scope="module")
def col():
    c = bc.BpfCollector(resolver=CgroupResolver(min_rescan_s=0)).start()
    yield c
    c.close()


def entry(snap, tgid):
    found = [p for p in snap["procs"] if p["key"]["tgid"] == tgid]
    assert len(found) <= 1
    return found[0] if found else None


def stat_starttime(pid):
    with open(f"/proc/{pid}/stat", "rb") as f:
        data = f.read()
    return int(data[data.rindex(b")") + 2:].split()[19])


def slot_tids(c, tgid):
    """Distro-namespace TIDs of the slots held for process tgid."""
    return {tid for tid, _host, _start, _proc in c.thread_slots(tgid)}


def read_ready(h):
    line = h.proc.stdout.readline().split()
    assert line and line[0] == "READY", line
    return line


@pytest.fixture
def exec_target(tmp_path, helper_bin):
    path = tmp_path / "ppc_execd"
    shutil.copy2(helper_bin, path)
    os.chmod(tmp_path, 0o755)
    return str(path)


# --- compilation count and capability selection ----------------------------

def test_exactly_two_compilations_and_the_planned_tracepoints(monkeypatch):
    import bcc
    calls = []

    class Counting(bcc.BPF):
        def __init__(self, *a, **kw):
            calls.append(kw.get("cflags", []))
            super().__init__(*a, **kw)

    monkeypatch.setattr(bc, "_bpf_class", lambda: Counting)
    fds0 = bpf_prog_fds()
    c = bc.BpfCollector().start()
    try:
        assert len(calls) == 2                                      # independent count
        assert [x["name"] for x in c.compilations] == ["calibrate", "unified"]
        assert "-DPPC_CAP_COUNTS=1" in calls[1] and not any("PPC_CAP" in f for f in calls[0])
        info = c.build_info()
        assert info["tracepoints"] == sorted(bc.required_tracepoints())
        assert info["open_tracepoints"] == len(SYSCALLS) + 2
        assert bpf_prog_fds() - fds0 == len(SYSCALLS) + 2           # calibration was unloaded
        assert info["vocabulary"] == bc.VOCABULARY.id
    finally:
        c.close()
    assert bpf_prog_fds() == fds0


# --- F4: per-thread slots ----------------------------------------------------

def test_thread_slots_follow_thread_lifetime_without_touching_counts(col, spawn_helper):
    h = spawn_helper()
    h.do("openat", 1)
    s0 = col.snapshot()
    e0 = entry(s0, h.pid)
    assert slot_tids(col, h.pid) == {h.pid}                         # the main thread
    cleaned0 = col.thread_health()["thread_slots_cleaned"]

    reply = h.do("tspawn", 4)
    tids = {int(t) for t in reply[4].split("=")[1].split(",")}
    assert len(tids) == 4 and h.pid not in tids
    assert slot_tids(col, h.pid) == {h.pid} | tids
    for _tid, _host, _start, (proc_start_ns, proc_tgid) in col.thread_slots(h.pid):
        assert proc_tgid == h.pid                                    # slot points at the process
        assert start_ticks_from_ns(proc_start_ns, clk_tck()) == e0["key"]["start_ticks"]
    s1 = col.snapshot()
    d = {s: entry(s1, h.pid)["counts"][s] - e0["counts"][s] for s in SYSCALLS}
    assert d["openat"] == 4                                          # one per thread
    assert d["clone"] + d["clone3"] == 4                             # pthread_create

    h.do("tjoin", 4)
    assert slot_tids(col, h.pid) == {h.pid}
    assert col.thread_health()["thread_slots_cleaned"] - cleaned0 >= 4
    s2 = col.snapshot()
    e2 = entry(s2, h.pid)
    assert e2["counts"] == entry(s1, h.pid)["counts"] and e2["exited"] is False

    assert h.exit() == 0
    assert slot_tids(col, h.pid) == set()
    e3 = entry(col.snapshot(), h.pid)
    assert e3["exited"] is True and e3["counts"] == e2["counts"]
    assert entry(col.snapshot(), h.pid) is None                      # reclaimed as in M1


def test_stale_slot_from_a_reused_tid_is_detected_and_replaced(col, spawn_helper):
    h = spawn_helper()
    h.do("openat", 1)
    t = col.b["threads"]
    (tid, host, start, proc), = col.thread_slots(h.pid)
    assert tid == h.pid                                              # the main thread
    leaf = t.Leaf()
    leaf.thread_start_ns = start + 1                                 # an earlier thread's slot
    leaf.proc.start_ns, leaf.proc.tgid = proc
    leaf.tid = 999999
    t[t.Key(host)] = leaf
    stale0 = col.thread_health()["thread_slot_stale"]
    before = entry(col.snapshot(), h.pid)["counts"]["openat"]
    h.do("openat", 3)
    assert col.thread_health()["thread_slot_stale"] - stale0 == 1
    assert col.thread_slots(h.pid) == [(tid, host, start, proc)]    # replaced by the real owner
    assert entry(col.snapshot(), h.pid)["counts"]["openat"] - before == 3


def test_exec_from_a_non_leader_thread_drops_the_old_tid_slot(col, helper_bin, exec_target):
    h = Helper([helper_bin, exec_target])
    try:
        h.do("openat", 1)
        e0 = entry(col.snapshot(), h.pid)
        stale0 = col.thread_health()["thread_slot_stale"]
        reply = h.do("texec", 0)
        old_tid = int(reply[4].split("=")[1])
        assert old_tid != h.pid
        assert read_ready(h)[1] == f"pid={h.pid}"                   # same process after exec
        assert old_tid not in slot_tids(col, h.pid)
        h.do("openat", 1)
        assert slot_tids(col, h.pid) == {h.pid}
        assert col.thread_health()["thread_slot_stale"] == stale0
        e1 = entry(col.snapshot(), h.pid)
        assert e1["key"] == e0["key"]                                # start time kept by de_thread
        assert e1["key"]["start_ticks"] == stat_starttime(h.pid)
        assert e1["counts"]["openat"] - e0["counts"]["openat"] == 2
        assert e1["comm"] == "ppc_execd"
    finally:
        h.exit()


def test_exclusion_purges_thread_slots(col, spawn_helper):
    h = spawn_helper()
    h.do("tspawn", 2)
    assert len(slot_tids(col, h.pid)) == 3
    col.exclude(h.pid)
    try:
        assert slot_tids(col, h.pid) == set()
        h.do("openat", 1)
        assert slot_tids(col, h.pid) == set()                        # excluded: no new slots
    finally:
        col.unexclude(h.pid)
        h.do("tjoin", 2)


# --- F9: metadata refreshed at exec, not per event ---------------------------

def test_exec_refreshes_comm_and_keeps_attribution(col, helper_bin, exec_target):
    h = Helper([helper_bin, exec_target])
    try:
        h.do("openat", 2)
        e0 = entry(col.snapshot(), h.pid)
        assert e0["comm"] == "sysc_helper"                           # refreshed at the first exec
        refresh0 = col.thread_health()["exec_refreshes"]
        h.do("exec", 0)
        read_ready(h)
        h.do("openat", 1)
        e1 = entry(col.snapshot(), h.pid)
        assert e1["comm"] == "ppc_execd"
        assert e1["key"] == e0["key"] and e1["host_tgid"] == e0["host_tgid"]
        assert e1["counts"]["openat"] - e0["counts"]["openat"] == 1
        assert e1["counts"]["execve"] - e0["counts"]["execve"] == 1  # the exec itself
        assert col.thread_health()["exec_refreshes"] - refresh0 >= 1
    finally:
        h.exit()


def test_rename_without_exec_is_not_refreshed(col, spawn_helper):
    h = spawn_helper()
    h.do("openat", 1)
    h.do("rename", 0)
    h.do("openat", 1)
    assert entry(col.snapshot(), h.pid)["comm"] == "sysc_helper"     # documented F9 limitation
    with open(f"/proc/{h.pid}/comm") as f:
        assert f.read().strip() == "ppc_renamed"


def test_cgroup_is_refreshed_at_exec_not_per_event(col, helper_bin, exec_target):
    cg = os.path.join(CGROUP_ROOT, f"ppc-s1-{uuid.uuid4().hex[:8]}")
    os.mkdir(cg)
    h = None
    try:
        h = Helper([helper_bin, exec_target])
        h.do("openat", 1)
        old = entry(col.snapshot(), h.pid)["container"]["cgroup_id"]
        with open(os.path.join(cg, "cgroup.procs"), "w") as f:
            f.write(str(h.pid))
        h.do("openat", 1)
        assert entry(col.snapshot(), h.pid)["container"]["cgroup_id"] == old   # not per event
        h.do("exec", 0)
        read_ready(h)
        e = entry(col.snapshot(), h.pid)
        assert e["container"]["cgroup_id"] == os.stat(cg).st_ino
        assert e["container"]["cgroup_path"] == "/" + os.path.basename(cg)
        assert e["container"]["attribution"] == "host"
    finally:
        if h is not None:
            h.exit()
        os.rmdir(cg)
