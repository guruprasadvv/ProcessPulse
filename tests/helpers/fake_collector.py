"""Scriptable stand-in for `collector --v1` used by test_resource_collector.py.

Behaviour is chosen with PPC_FAKE_MODE; PPC_FAKE_STATE names a file used to
make the first and later invocations differ (crash-then-recover).
Arguments (--v1, --interval-ms, --count) are accepted and ignored.
"""

import json
import os
import signal
import sys
import time

BOOT = "d8272aeb-2d00-4ca0-9e4a-11dab89ea8cc"


def out(rec):
    sys.stdout.write(json.dumps(rec) + "\n")


def proc(seq, pid=100, **over):
    rec = {"type": "proc", "v": 1, "seq": seq, "t_mono_ns": time.monotonic_ns(), "pid": pid,
           "comm": "fake", "comm_utf8_valid": True, "comm_truncated": False, "state": "S",
           "ppid": 1, "starttime_ticks": 10, "utime": 1, "stime": 1, "num_threads": 1,
           "rss_kb": 1, "rss_err": None, "uid_real": 0, "uid_eff": 0, "uid_err": None,
           "vol_ctxsw": 1, "nonvol_ctxsw": 0, "ctxsw_err": None, "io": None, "io_err": "EACCES",
           "fd_count": None, "fd_err": "EACCES", "cgroup": "/init.scope", "cgroup_err": None,
           "partial": False}
    rec.update(over)
    return rec


def begin(seq):
    out({"type": "sample_begin", "v": 1, "seq": seq, "t_mono_ns": time.monotonic_ns(),
         "t_wall_ns": time.time_ns(), "clk_tck": 100, "page_size": 4096, "boot_id": BOOT,
         "pidns_ino": 4026532219, "euid": 0, "collector_pid": os.getpid()})


def end(seq, emitted):
    out({"type": "sample_end", "v": 1, "seq": seq, "t_mono_ns": time.monotonic_ns(), "dur_ns": 1,
         "pids_seen": emitted, "emitted": emitted, "gone": 0, "denied": 0, "parse_errors": 0,
         "read_errors": 0, "io_denied": 0, "fd_denied": 0, "late_ns": 0, "readdir_err": None})


def sample(seq, nprocs=2):
    begin(seq)
    for i in range(nprocs):
        out(proc(seq, pid=100 + i))
    end(seq, nprocs)
    sys.stdout.flush()


def main():
    mode = os.environ.get("PPC_FAKE_MODE", "ok:3")
    state = os.environ.get("PPC_FAKE_STATE")
    if mode.startswith("ok:"):
        for seq in range(int(mode[3:])):
            sample(seq)
        return 0
    if mode == "garbage":
        sample(0)
        sys.stdout.write("not json\n")
        sys.stdout.flush()
        sys.stdout.buffer.write(b"\xff\xfe\n[1, 2]\n" + b"x" * 70000 + b"\n")
        sys.stdout.buffer.flush()
        sample(1)
        return 0
    if mode == "crash_once":
        if state and not os.path.exists(state):
            open(state, "w").close()
            sample(0)
            begin(1)
            out(proc(1))
            sys.stdout.flush()
            return 1
        sample(0)
        sample(1)
        return 0
    if mode == "schema_error":
        begin(0)
        bad = proc(0)
        del bad["comm"]
        out(bad)
        end(0, 1)
        sample(1)
        return 0
    if mode == "forever":
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        seq = 0
        while True:
            sample(seq)
            seq += 1
            time.sleep(0.05)
    return 2


if __name__ == "__main__":
    sys.exit(main())
