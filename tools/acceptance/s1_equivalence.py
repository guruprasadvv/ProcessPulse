#!/usr/bin/env python3
"""M1b S1 behavioural-equivalence probe for the BPF syscall collector.

    sudo python3 tools/acceptance/s1_equivalence.py OUT.json

Runs one fixed scenario against processpulse.syscalls.SyscallCollector using
only the M1 interface and the M1 helper commands, so the same script runs
before and after the S1 port. It records normalised observations (no PIDs,
times or other run-specific values): exact count deltas, identity fields,
v1 record shape, exit reporting and reclaim, self-exclusion, the
unresolved path, map-full accounting, and the attached probe count.
Compare two outputs with:  python3 -c "..." or diff after json.load/dump.
"""

import json
import os
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)
from processpulse.identity import own_pidns_ino  # noqa: E402
from processpulse.syscalls import SYSCALLS, SyscallCollector  # noqa: E402
from processpulse.validate import Validator  # noqa: E402

HELPER = os.path.join(REPO, "build", "sysc_helper")


class Helper:
    def __init__(self):
        self.proc = subprocess.Popen([HELPER], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        assert self.proc.stdout.readline().startswith("READY")
        self.pid = self.proc.pid

    def do(self, cmd, n):
        self.proc.stdin.write(f"{cmd} {n}\n")
        self.proc.stdin.flush()
        reply = self.proc.stdout.readline().split()
        assert reply[:4] == ["DONE", cmd, str(n), "errors=0"], reply

    def exit(self):
        self.proc.stdin.write("exit\n")
        self.proc.stdin.flush()
        return self.proc.wait(timeout=10)


def entry(snap, tgid):
    found = [p for p in snap["procs"] if p["key"]["tgid"] == tgid]
    assert len(found) <= 1
    return found[0] if found else None


def stat_starttime(pid):
    with open(f"/proc/{pid}/stat", "rb") as f:
        data = f.read()
    return int(data[data.rindex(b")") + 2:].split()[19])


def main(out_path):
    v = Validator()
    out = {}
    sc = SyscallCollector().start()
    try:
        out["attached_tracepoints"] = sc.b.num_open_tracepoints()
        h = Helper()
        h.do("openat", 1)                         # ensure an entry exists before the baseline
        s0 = sc.snapshot()
        c0 = entry(s0, h.pid)["counts"]
        plan = [("openat", 1000), ("open", 10), ("execve", 50), ("clone", 20)]
        for cmd, n in plan:
            h.do(cmd, n)
        s1 = sc.snapshot()
        e = entry(s1, h.pid)
        out["count_deltas"] = {s: e["counts"][s] - c0[s] for s in SYSCALLS}
        out["identity"] = {
            "tgid_is_helper_pid": e["key"]["tgid"] == h.pid,
            "pidns_is_own": e["key"]["pidns_ino"] == own_pidns_ino(),
            "start_ticks_match_proc": e["key"]["start_ticks"] == stat_starttime(h.pid),
            "level_is_distro": e["level"] == sc.distro_level,
            "container_pid": e["container_pid"],
            "comm": e["comm"],
            "attribution": e["container"]["attribution"],
            "exited": e["exited"],
        }
        out["v1_shape"] = {"snapshot_keys": sorted(s1), "proc_keys": sorted(e),
                           "health_keys": sorted(s1["health"]), "schema_errors": v.errors(s1),
                           "probe": s1["probe"]["syscalls"]}
        final = e["counts"]
        out["helper_exit_rc"] = h.exit()
        s2 = sc.snapshot()
        e2 = entry(s2, h.pid)
        s3 = sc.snapshot()
        out["exit"] = {"reported_exited": e2 is not None and e2["exited"],
                       "final_counts_kept": e2 is not None and e2["counts"] == final,
                       "reclaimed_next_snapshot": entry(s3, h.pid) is None,
                       "reclaimed_delta_ge_1": s3["health"]["reclaimed"] - s2["health"]["reclaimed"] >= 1}
        before = sc.snapshot()["health"]["self_excluded_events"]
        for _ in range(10):
            try:
                os.open("/nonexistent-processpulse/s1", os.O_RDONLY)
            except FileNotFoundError:
                pass
        s4 = sc.snapshot()
        out["self_exclusion"] = {"own_pid_absent": entry(s4, os.getpid()) is None,
                                 "delta_ge_10": s4["health"]["self_excluded_events"] - before >= 10}
    finally:
        sc.close()

    bad = SyscallCollector(distro_inum_override=own_pidns_ino() ^ 1).start()
    try:
        h = Helper()
        b0 = bad.snapshot()["health"]["unresolved_events"]
        h.do("openat", 100)
        b1 = bad.snapshot()
        out["unresolved"] = {"nothing_attributed": b1["procs"] == [],
                             "delta_ge_100": b1["health"]["unresolved_events"] - b0 >= 100}
        h.exit()
    finally:
        bad.close()

    small = SyscallCollector(max_procs=4).start()
    try:
        hs = [Helper() for _ in range(10)]
        for x in hs:
            x.do("openat", 1)
        sm = small.snapshot()
        out["map_full"] = {"entries_le_4": sm["health"]["map_entries"] <= 4,
                           "counts_map_full_ge_1": sm["health"]["counts_map_full"] >= 1}
        for x in hs:
            x.exit()
    finally:
        small.close()

    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1])
