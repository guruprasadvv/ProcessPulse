"""DIT-1 — Docker Integration Acceptance Test (CLAUDE.md §9).

A static sysc_helper runs as PID 1 of a busybox:1.36 container and issues
exactly N syscalls on command. One module-scoped scenario records every
observation; each numbered check is its own test so results map 1:1 onto the
DIT-1 criteria. DIT-1 counts as passed only when all checks pass in three
consecutive runs of this module.

Run as root:  python3 -m pytest tests/test_dit1.py -v
"""

import json
import os
import shutil
import subprocess
import tempfile
import uuid

import pytest

from conftest import COLLECTOR_BIN, HELPER_BIN, Helper
from processpulse.identity import CGROUP_ROOT, own_pidns_ino, parse_container
from processpulse.syscalls import SyscallCollector

pytestmark = [pytest.mark.privileged, pytest.mark.bpf, pytest.mark.docker]

IMAGE = "busybox:1.36"
N = 1000


def _stat(pid):
    with open(f"/proc/{pid}/stat", "rb") as f:
        data = f.read()
    return int(data[data.rindex(b")") + 2:].split()[19])


def _collector_procs():
    out = subprocess.run([COLLECTOR_BIN, "--v1", "--count", "1"], capture_output=True,
                         check=True, timeout=30).stdout
    return {r["pid"]: r for r in map(json.loads, out.decode().splitlines()) if r["type"] == "proc"}


def _entry(snap, tgid):
    found = [p for p in snap["procs"] if p["key"]["tgid"] == tgid]
    assert len(found) <= 1
    return found[0] if found else None


@pytest.fixture(scope="module")
def obs():
    o = {}
    good = SyscallCollector().start()
    bad = SyscallCollector(distro_inum_override=own_pidns_ino() ^ 1).start()
    tmp = tempfile.mkdtemp(prefix="ppc-dit1-")
    shutil.copy2(HELPER_BIN, os.path.join(tmp, "sysc_helper"))
    os.chmod(tmp, 0o755)
    name = f"ppc-dit1-{uuid.uuid4().hex[:8]}"
    h = None
    try:
        h = Helper(["docker", "run", "--rm", "-i", "--name", name, "-v", f"{tmp}:/ppc:ro",
                    IMAGE, "/ppc/sysc_helper"])
        o["container_reported_pid"] = h.reported_pid
        insp = json.loads(subprocess.run(["docker", "inspect", name], capture_output=True,
                                         check=True, text=True).stdout)[0]
        pid = insp["State"]["Pid"]
        o["inspect_pid"], o["inspect_id"] = pid, insp["Id"]
        with open(f"/proc/{pid}/status") as f:
            o["nspid"] = [int(x) for x in next(l for l in f if l.startswith("NSpid:")).split()[1:]]
        o["container_pidns"] = os.stat(f"/proc/{pid}/ns/pid").st_ino
        o["distro_pidns"] = own_pidns_ino()
        with open(f"/proc/{pid}/cgroup") as f:
            o["cgroup_path"] = next(l for l in f if l.startswith("0::"))[3:].strip()
        o["cgroup_inode"] = os.stat(os.path.join(CGROUP_ROOT, o["cgroup_path"].lstrip("/"))).st_ino
        o["stat_starttime"] = _stat(pid)
        o["distro_level"] = good.distro_level

        s0, b0 = good.snapshot(), bad.snapshot()
        for cmd in ("openat", "execve", "clone"):
            h.do(cmd, N)
        s1, b1 = good.snapshot(), bad.snapshot()
        o["entry_before"], o["entry"] = _entry(s0, pid), _entry(s1, pid)
        o["bad_procs_for_pid"] = _entry(b1, pid)
        o["bad_unresolved_delta"] = (b1["health"]["unresolved_events"]
                                     - b0["health"]["unresolved_events"])
        o["collector_record"] = _collector_procs().get(pid)

        assert h.exit() == 0
        s2 = good.snapshot()
        o["entry_after_exit"] = _entry(s2, pid)
        s3 = good.snapshot()
        o["entry_after_reclaim"] = _entry(s3, pid)
        o["reclaimed_delta"] = s3["health"]["reclaimed"] - s2["health"]["reclaimed"]
        o["collector_after_exit"] = _collector_procs().get(pid)
        o["pid"] = pid
        yield o
    finally:
        if h is not None and h.proc.poll() is None:
            h.proc.kill()
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        good.close()
        bad.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_check1_container_visible_pid(obs):
    e = obs["entry"]
    assert obs["container_reported_pid"] == 1
    assert e is not None and e["container_pid"] == obs["container_reported_pid"]


def test_check2_distro_pid_agrees_everywhere(obs):
    assert obs["nspid"][0] == obs["inspect_pid"]
    assert obs["entry"]["key"]["tgid"] == obs["inspect_pid"]
    assert obs["collector_record"] is not None and obs["collector_record"]["pid"] == obs["inspect_pid"]


def test_check3_pid_namespace_identity(obs):
    assert obs["container_pidns"] != obs["distro_pidns"]
    assert obs["entry"]["level"] == obs["distro_level"] + 1
    assert obs["entry"]["key"]["pidns_ino"] == obs["distro_pidns"]
    assert obs["nspid"] == [obs["inspect_pid"], 1]


def test_check4_cgroup_and_container_id(obs):
    runtime, cid = parse_container(obs["cgroup_path"])
    assert runtime == "docker" and cid == obs["inspect_id"]
    c = obs["entry"]["container"]
    assert c["cgroup_id"] == obs["cgroup_inode"]
    assert c["cgroup_path"] == obs["cgroup_path"]
    assert c["container_id"] == obs["inspect_id"] and c["attribution"] == "docker"
    assert obs["collector_record"]["cgroup"] == obs["cgroup_path"]


def test_check5_exact_counts_and_start_time(obs):
    before = obs["entry_before"]["counts"] if obs["entry_before"] else {}
    after = obs["entry"]["counts"]
    for sc in ("openat", "execve", "clone"):
        assert after[sc] - before.get(sc, 0) == N, sc
    assert obs["entry"]["key"]["start_ticks"] == obs["stat_starttime"]
    assert obs["collector_record"]["starttime_ticks"] == obs["stat_starttime"]


def test_check6_exit_reported_once_then_reclaimed(obs):
    e = obs["entry_after_exit"]
    assert e is not None and e["exited"] is True
    assert e["counts"] == obs["entry"]["counts"]
    assert obs["entry_after_reclaim"] is None and obs["reclaimed_delta"] >= 1
    assert obs["collector_after_exit"] is None


def test_check7_namespace_mismatch_is_unresolved(obs):
    assert obs["bad_procs_for_pid"] is None
    assert obs["bad_unresolved_delta"] >= 3 * N
