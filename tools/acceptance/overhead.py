#!/usr/bin/env python3
"""M1 acceptance C — telemetry overhead: 3 workloads x 3 intervals x 5 repetitions.

    sudo python3 tools/acceptance/overhead.py [--window-s 30] [--reps 5]

Instrumented run (45 = workloads x intervals x reps), for each combination:
  1. start the agent (BPF + C collector) at the given interval;
  2. wait for its first complete sample, so BPF compilation/attach is excluded;
  3. snapshot agent/collector CPU ticks and BPF program run time, run the
     workload for --window-s seconds, snapshot again;
  4. SIGTERM the agent and read its own timing/loss counters.
Baseline runs: the cpu and churn workloads alone (no agent) --reps times each;
the interval does not apply without an agent and idle has no throughput.

Metrics: agent+collector CPU (% of one CPU) from /proc/<pid>/stat deltas over
the measured window; peak RSS (VmHWM); in-kernel BPF time from per-program
run_time_ns (kernel.bpf_stats_enabled is set to 1 for the experiment and
restored afterwards); workload throughput relative to the baseline median;
collector sample duration, lateness, snapshot time and loss counters.

Writes results/acceptance/m1/overhead/{runs.csv,summary.json,summary.md,environment.json}.
Raw agent output goes to results/raw/overhead-<stamp>/ (gitignored).
"""

import argparse
import csv
import json
import os
import platform
import signal
import statistics
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(REPO, "results", "acceptance", "m1", "overhead")
WORKLOADS = ("idle", "cpu", "churn")
INTERVALS_MS = (250, 1000, 5000)
TICKS = os.sysconf("SC_CLK_TCK")

WORKLOAD_SRC = {
    # One CPU-bound process; throughput = sha256 digests of 4 KiB per second.
    "cpu": (
        "import hashlib, sys, time\n"
        "w = float(sys.argv[1]); t0 = time.monotonic(); end = t0 + w; buf = b'x' * 4096; n = 0\n"
        "while time.monotonic() < end:\n"
        "    for _ in range(200):\n"
        "        hashlib.sha256(buf).digest()\n"
        "    n += 200\n"
        "print(n / (time.monotonic() - t0))\n"
    ),
    # Process churn: spawn and reap /bin/true; exercises execve/clone/openat
    # probes and /proc enumeration. Throughput = processes per second.
    "churn": (
        "import os, sys, time\n"
        "w = float(sys.argv[1]); t0 = time.monotonic(); end = t0 + w; n = 0\n"
        "while time.monotonic() < end:\n"
        "    pid = os.posix_spawn('/bin/true', ['/bin/true'], {})\n"
        "    os.waitpid(pid, 0); n += 1\n"
        "print(n / (time.monotonic() - t0))\n"
    ),
}


def cpu_ticks(pid):
    with open(f"/proc/{pid}/stat", "rb") as f:
        data = f.read()
    fields = data[data.rindex(b")") + 2:].split()
    return int(fields[11]) + int(fields[12])          # utime + stime


def vm_kb(pid, key):
    """VmHWM (peak; for the agent this includes BCC's in-process LLVM compile)
    or VmRSS (current, i.e. steady state at the end of the window)."""
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith(key + ":"):
                return int(line.split()[1])
    return None


def bpf_prog_stats(pid):
    """Sum of run_time_ns / run_cnt over the BPF programs held by pid."""
    run_ns = run_cnt = progs = 0
    for fd in os.listdir(f"/proc/{pid}/fd"):
        try:
            if os.readlink(f"/proc/{pid}/fd/{fd}") != "anon_inode:bpf-prog":
                continue
            with open(f"/proc/{pid}/fdinfo/{fd}") as f:
                info = dict(l.split(":", 1) for l in f if ":" in l)
        except OSError:
            continue
        progs += 1
        run_ns += int(info.get("run_time_ns", "0"))
        run_cnt += int(info.get("run_cnt", "0"))
    return run_ns, run_cnt, progs


def run_workload(name, window_s):
    if name == "idle":
        time.sleep(window_s)
        return None
    r = subprocess.run([sys.executable, "-c", WORKLOAD_SRC[name], str(window_s)],
                       capture_output=True, text=True, check=True)
    return float(r.stdout.strip())


def wait_first_sample(path, proc, timeout=120):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if proc.poll() is not None:
            raise RuntimeError(f"agent exited early rc={proc.returncode}")
        try:
            with open(path, "rb") as f:
                if any(b'"sample_end"' in line for line in f):
                    return
        except OSError:
            pass
        time.sleep(0.2)
    raise TimeoutError("no sample within timeout")


def first_collector_pid(path):
    with open(path, "rb") as f:
        for line in f:
            if b'"sample_begin"' in line:
                return json.loads(line)["collector_pid"]
    return None


def instrumented(workload, interval_ms, rep, window_s, raw_root):
    out = os.path.join(raw_root, f"{workload}-{interval_ms}ms-rep{rep}")
    errlog = open(f"{out}.stderr", "w")
    agent = subprocess.Popen(
        [sys.executable, "-m", "processpulse.agent", "--duration", str(window_s + 120),
         "--interval-ms", str(interval_ms), "--out", out],
        cwd=REPO, stdout=subprocess.DEVNULL, stderr=errlog)
    try:
        res = os.path.join(out, "resource.jsonl")
        wait_first_sample(res, agent)
        cpid = first_collector_pid(res)
        a0, c0 = cpu_ticks(agent.pid), cpu_ticks(cpid)
        b0 = bpf_prog_stats(agent.pid)
        t0 = time.monotonic_ns()
        thr = run_workload(workload, window_s)
        t1 = time.monotonic_ns()
        a1, c1 = cpu_ticks(agent.pid), cpu_ticks(cpid)
        b1 = bpf_prog_stats(agent.pid)
        hwm_a, hwm_c = vm_kb(agent.pid, "VmHWM"), vm_kb(cpid, "VmHWM")
        rss_a, rss_c = vm_kb(agent.pid, "VmRSS"), vm_kb(cpid, "VmRSS")
    finally:
        agent.send_signal(signal.SIGTERM)
        try:
            rc = agent.wait(timeout=60)
        except subprocess.TimeoutExpired:
            agent.kill()
            rc = agent.wait()
        errlog.close()
    win = (t1 - t0) / 1e9
    ends, snaps, health = [], [], None
    with open(res) as f:
        for line in f:
            r = json.loads(line)
            if r["type"] == "sample_end" and t0 <= r["t_mono_ns"] <= t1:
                ends.append(r)
    with open(os.path.join(out, "syscall.jsonl")) as f:
        snaps = [s for s in map(json.loads, f) if t0 <= s["t_mono_ns"] <= t1]
    with open(os.path.join(out, "health.jsonl")) as f:
        for line in f:
            health = json.loads(line)
    return {
        "kind": "instrumented", "workload": workload, "interval_ms": interval_ms, "rep": rep,
        "window_s": round(win, 3), "agent_rc": rc,
        "agent_cpu_pct": round(100 * (a1 - a0) / TICKS / win, 3),
        "collector_cpu_pct": round(100 * (c1 - c0) / TICKS / win, 3),
        "total_user_cpu_pct": round(100 * ((a1 - a0) + (c1 - c0)) / TICKS / win, 3),
        "bpf_cpu_pct": round(100 * (b1[0] - b0[0]) / 1e9 / win, 4),
        "bpf_events": b1[1] - b0[1], "bpf_progs": b1[2],
        "bpf_ns_per_event": round((b1[0] - b0[0]) / max(1, b1[1] - b0[1]), 1),
        "agent_hwm_kb": hwm_a, "collector_hwm_kb": hwm_c,
        "agent_rss_kb": rss_a, "collector_rss_kb": rss_c,
        "throughput": thr,
        "samples_in_window": len(ends),
        "median_sample_dur_ms": round(statistics.median(e["dur_ns"] for e in ends) / 1e6, 3) if ends else None,
        "max_late_ms": round(max(e["late_ns"] for e in ends) / 1e6, 3) if ends else None,
        "procs_gone": sum(e["gone"] for e in ends),
        "median_snapshot_ms": round(statistics.median(s["health"]["snapshot_ns"] for s in snaps) / 1e6, 3) if snaps else None,
        "dropped_samples": health["resource"]["dropped_samples"] if health else None,
        "counts_map_full": snaps[-1]["health"]["counts_map_full"] if snaps else None,
        # Window delta; on WSL these come from WSL's own init (outside the distro pidns).
        "unresolved_events": (snaps[-1]["health"]["unresolved_events"]
                              - snaps[0]["health"]["unresolved_events"]) if len(snaps) > 1 else None,
    }


def baseline(workload, rep, window_s):
    t0 = time.monotonic_ns()
    thr = run_workload(workload, window_s)
    return {"kind": "baseline", "workload": workload, "interval_ms": None, "rep": rep,
            "window_s": round((time.monotonic_ns() - t0) / 1e9, 3), "throughput": thr}


def iqr(xs):
    if len(xs) < 2:
        return None
    q = statistics.quantiles(xs, n=4, method="inclusive")
    return round(q[2] - q[0], 4)


def summarize(rows):
    base = {w: statistics.median(r["throughput"] for r in rows
                                 if r["kind"] == "baseline" and r["workload"] == w)
            for w in ("cpu", "churn")}
    metrics = ("total_user_cpu_pct", "agent_cpu_pct", "collector_cpu_pct", "bpf_cpu_pct",
               "bpf_ns_per_event", "agent_hwm_kb", "collector_hwm_kb", "agent_rss_kb",
               "collector_rss_kb", "median_sample_dur_ms",
               "max_late_ms", "median_snapshot_ms", "throughput")
    out = []
    for w in WORKLOADS:
        for i in INTERVALS_MS:
            rs = [r for r in rows if r["kind"] == "instrumented" and r["workload"] == w
                  and r["interval_ms"] == i]
            cell = {"workload": w, "interval_ms": i, "reps": len(rs)}
            for m in metrics:
                xs = [r[m] for r in rs if r.get(m) is not None]
                cell[m] = {"median": round(statistics.median(xs), 4) if xs else None, "iqr": iqr(xs)}
            if w in base:
                cell["baseline_throughput_median"] = round(base[w], 2)
                med = cell["throughput"]["median"]
                cell["throughput_change_pct"] = round(100 * (med - base[w]) / base[w], 2)
            cell["loss"] = {k: sum(r[k] or 0 for r in rs) for k in
                            ("dropped_samples", "counts_map_full")}
            cell["agent_rc_nonzero"] = sum(1 for r in rs if r["agent_rc"] != 0)
            out.append(cell)
    return out


def abba(interval_ms, reps, window_s):
    """Order-balanced throughput check: per rep, baseline-instrumented-instrumented-
    baseline for the cpu and churn workloads. Each rep has a baseline both before
    and after the instrumented runs, so monotonic drift (e.g. CPU frequency or
    thermal state after a BCC compile) cancels in the paired comparison."""
    raw_root = os.path.join(REPO, "results", "raw", "overhead-abba-" + time.strftime("%Y%m%dT%H%M%S"))
    os.makedirs(raw_root)
    rows = []
    for rep in range(1, reps + 1):
        for w in ("cpu", "churn"):
            for pos, kind in enumerate(("B", "I", "I", "B")):
                r = (baseline(w, rep, window_s) if kind == "B"
                     else instrumented(w, interval_ms, f"{rep}{'ab'[pos - 1]}", window_s, raw_root))
                r["abba_pos"] = pos
                rows.append(r)
                print(json.dumps(r), flush=True)
    fields = sorted({k for r in rows for k in r})
    with open(os.path.join(OUT, "abba_runs.csv"), "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=fields)
        wr.writeheader()
        wr.writerows(rows)
    cells = []
    for w in ("cpu", "churn"):
        changes = []
        for rep in range(1, reps + 1):
            rs = [r for r in rows if r["workload"] == w and str(r["rep"]).startswith(str(rep))]
            b = statistics.mean(r["throughput"] for r in rs if r["kind"] == "baseline")
            i = statistics.mean(r["throughput"] for r in rs if r["kind"] == "instrumented")
            changes.append(100 * (i - b) / b)
        cells.append({"workload": w, "interval_ms": interval_ms, "reps": reps,
                      "paired_change_pct_per_rep": [round(c, 2) for c in changes],
                      "median_change_pct": round(statistics.median(changes), 2),
                      "iqr_change_pct": iqr(changes)})
    with open(os.path.join(OUT, "abba_summary.json"), "w") as f:
        json.dump({"design": "per rep: baseline, instrumented, instrumented, baseline",
                   "window_s": window_s, "cells": cells}, f, indent=2)
    print(json.dumps(cells, indent=2))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-s", type=float, default=30.0)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--abba", type=int, metavar="INTERVAL_MS", default=None,
                    help="run only the order-balanced throughput check at this interval")
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("overhead.py must run as root (BCC, /proc/<pid>/fdinfo)")
    if args.abba is not None:
        os.makedirs(OUT, exist_ok=True)
        stats_path = "/proc/sys/kernel/bpf_stats_enabled"
        orig = open(stats_path).read().strip()
        try:
            with open(stats_path, "w") as f:
                f.write("1")          # same condition as the main matrix
            return abba(args.abba, args.reps, args.window_s)
        finally:
            with open(stats_path, "w") as f:
                f.write(orig)

    os.makedirs(OUT, exist_ok=True)
    raw_root = os.path.join(REPO, "results", "raw", "overhead-" + time.strftime("%Y%m%dT%H%M%S"))
    os.makedirs(raw_root)
    stats_path = "/proc/sys/kernel/bpf_stats_enabled"
    stats_orig = open(stats_path).read().strip()
    env = {
        "kernel": platform.release(), "python": platform.python_version(),
        "nproc": os.cpu_count(), "clk_tck": TICKS,
        "cpu_model": next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo")
                           if l.startswith("model name")), None),
        "mem_total_kb": next(int(l.split()[1]) for l in open("/proc/meminfo") if l.startswith("MemTotal")),
        "window_s": args.window_s, "reps": args.reps, "workloads": WORKLOADS,
        "intervals_ms": INTERVALS_MS, "bpf_stats_enabled_original": stats_orig,
        "raw_dir": raw_root, "started_wall": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "order": "for rep: for workload: [baseline], then intervals 250/1000/5000",
    }
    rows = []
    try:
        with open(stats_path, "w") as f:
            f.write("1")
        for rep in range(1, args.reps + 1):
            for w in WORKLOADS:
                if w != "idle":
                    rows.append(baseline(w, rep, args.window_s))
                    print(json.dumps(rows[-1]), flush=True)
                for i in INTERVALS_MS:
                    rows.append(instrumented(w, i, rep, args.window_s, raw_root))
                    print(json.dumps(rows[-1]), flush=True)
    finally:
        with open(stats_path, "w") as f:
            f.write(stats_orig)
        env["bpf_stats_enabled_restored"] = open(stats_path).read().strip()
        env["finished_wall"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        fields = sorted({k for r in rows for k in r})
        with open(os.path.join(OUT, "runs.csv"), "w", newline="") as f:
            wr = csv.DictWriter(f, fieldnames=fields)
            wr.writeheader()
            wr.writerows(rows)
        with open(os.path.join(OUT, "environment.json"), "w") as f:
            json.dump(env, f, indent=2)

    summary = summarize(rows)
    n_instr = sum(1 for r in rows if r["kind"] == "instrumented")
    with open(os.path.join(OUT, "summary.json"), "w") as f:
        json.dump({"instrumented_runs": n_instr, "cells": summary}, f, indent=2)
    lines = ["| workload | interval | reps | agent+collector CPU % (median, IQR) | BPF CPU % (median, IQR) | "
             "BPF ns/event | agent RSS kB (HWM) | collector RSS kB (HWM) | sample dur ms | "
             "throughput change % vs baseline |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for c in summary:
        lines.append(
            f"| {c['workload']} | {c['interval_ms']} ms | {c['reps']} | "
            f"{c['total_user_cpu_pct']['median']} ({c['total_user_cpu_pct']['iqr']}) | "
            f"{c['bpf_cpu_pct']['median']} ({c['bpf_cpu_pct']['iqr']}) | "
            f"{c['bpf_ns_per_event']['median']} | "
            f"{c['agent_rss_kb']['median']} ({c['agent_hwm_kb']['median']}) | "
            f"{c['collector_rss_kb']['median']} ({c['collector_hwm_kb']['median']}) | "
            f"{c['median_sample_dur_ms']['median']} | {c.get('throughput_change_pct', 'n/a')} |")
    with open(os.path.join(OUT, "summary.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    ok = n_instr == len(WORKLOADS) * len(INTERVALS_MS) * args.reps and all(
        c["agent_rc_nonzero"] == 0 for c in summary)
    print(f"RESULT: {'COMPLETE' if ok else 'INCOMPLETE'} ({n_instr} instrumented runs)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
