"""Telemetry agent: supervises both collectors and records their streams.

    sudo python3 -m processpulse.agent --duration 10 --interval-ms 1000 [--out DIR] [--no-bpf]

For every complete resource sample from the C collector the agent takes one
BPF syscall snapshot (aligned to that sample's sample_end) and writes:

    resource.jsonl   sample_begin / proc / sample_end, exactly as produced
    syscall.jsonl    syscall_snapshot records
    health.jsonl     one health record per sample (both collectors)
    preflight.json   preflight report
    manifest.json    run metadata (versions, boot id, configuration, counts)
    agent.log        diagnostics (collector stderr, framing errors)

If preflight fails or --no-bpf is given, the resource stream still runs and
health records state why the syscall stream is unavailable. Records are
validated before they are written; invalid agent records abort the run.
"""

import argparse
import json
import os
import platform
import signal
import sys
import time
import uuid

from . import SCHEMA_VERSION
from .identity import read_boot_id
from .preflight import run_preflight
from .resource import ResourceCollector
from .validate import Validator

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _git_head(repo=REPO_ROOT):
    """Commit hash from .git without invoking git (the agent may run as root)."""
    try:
        with open(os.path.join(repo, ".git", "HEAD")) as f:
            head = f.read().strip()
        if head.startswith("ref: "):
            with open(os.path.join(repo, ".git", head[5:])) as f:
                return f.read().strip()
        return head
    except OSError:
        return None


class Agent:
    def __init__(self, out_dir, interval_ms=1000, duration_s=10.0, use_bpf=True,
                 collector=os.path.join(REPO_ROOT, "collector"), max_procs=16384):
        self.out_dir = out_dir
        self.interval_ms = interval_ms
        self.duration_s = duration_s
        self.use_bpf = use_bpf
        self.collector_bin = collector
        self.max_procs = max_procs
        self.validator = Validator()
        self._stop = False

    def request_stop(self, *_):
        self._stop = True

    def _write(self, fh, rec):
        errs = self.validator.errors(rec)
        if errs:
            raise ValueError(f"agent produced an invalid {rec.get('type')} record: {errs[:3]}")
        fh.write(json.dumps(rec, separators=(",", ":")) + "\n")

    def run(self):
        os.makedirs(self.out_dir, exist_ok=True)
        files = {n: open(os.path.join(self.out_dir, n), "w", encoding="utf-8")
                 for n in ("resource.jsonl", "syscall.jsonl", "health.jsonl", "agent.log")}
        log = files["agent.log"]
        started_wall = time.time()
        t_start = time.monotonic_ns()

        preflight = run_preflight() if self.use_bpf else None
        if preflight is not None:
            with open(os.path.join(self.out_dir, "preflight.json"), "w") as f:
                json.dump(preflight, f, indent=2)

        sc, sc_reason = None, None
        if not self.use_bpf:
            sc_reason = "disabled (--no-bpf)"
        elif not preflight["ok"]:
            bad = [c for c in preflight["checks"] if c["status"] in ("FAIL", "BLOCKED")]
            sc_reason = "preflight: " + "; ".join(f"{c['name']} {c['status']}" for c in bad)
        else:
            from .syscalls import SyscallCollector
            try:
                sc = SyscallCollector(max_procs=self.max_procs).start()
            except Exception as e:
                sc_reason = f"syscall collector failed to start: {type(e).__name__}: {e}"
                sc = None
        if sc_reason:
            log.write(f"{time.monotonic_ns()} syscall stream unavailable: {sc_reason}\n")

        rc = ResourceCollector(self.collector_bin, interval_ms=self.interval_ms, diag=log)
        if sc is not None:
            rc.on_spawn = sc.exclude
        counters = {"samples": 0, "snapshots": 0}
        try:
            rc.start()
            # Duration counts from the start of collection, not from agent start
            # (preflight and BCC compilation take seconds).
            deadline = time.monotonic_ns() + int(self.duration_s * 1e9)
            while not self._stop and time.monotonic_ns() < deadline:
                sample = rc.get(timeout=0.2)
                if sample is None:
                    if rc.finished:
                        break
                    continue
                for rec in [sample.begin, *sample.procs, sample.end]:
                    files["resource.jsonl"].write(json.dumps(rec, separators=(",", ":")) + "\n")
                counters["samples"] += 1
                skew = None
                if sc is not None:
                    snap = sc.snapshot(resource_seq=sample.seq)
                    self._write(files["syscall.jsonl"], snap)
                    counters["snapshots"] += 1
                    skew = snap["t_mono_ns"] - sample.end["t_mono_ns"]
                self._write(files["health.jsonl"], {
                    "type": "health", "v": SCHEMA_VERSION, "seq": sample.seq,
                    "t_mono_ns": time.monotonic_ns(), "resource": rc.stats(),
                    "syscall": {"available": sc is not None, "reason": sc_reason},
                    "alignment_skew_ns": skew,
                })
                for fh in files.values():
                    fh.flush()
        finally:
            rc.stop()
            if sc is not None:
                sc.close()
            final_stats = rc.stats()
            for fh in files.values():
                fh.close()

        manifest = {
            "run_id": os.path.basename(os.path.normpath(self.out_dir)),
            "schema_version": SCHEMA_VERSION,
            "started_wall": started_wall,
            "duration_mono_ns": time.monotonic_ns() - t_start,
            "boot_id": read_boot_id(),
            "kernel": platform.release(),
            "python": platform.python_version(),
            "git_head": _git_head(),
            "config": {"interval_ms": self.interval_ms, "duration_s": self.duration_s,
                       "use_bpf": self.use_bpf, "collector": self.collector_bin,
                       "max_procs": self.max_procs},
            "syscall_stream": {"available": sc is not None, "reason": sc_reason},
            "counts": counters,
            "resource_stats": final_stats,
        }
        with open(os.path.join(self.out_dir, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)
        return manifest


def main(argv=None):
    ap = argparse.ArgumentParser(description="ProcessPulse-C telemetry agent (M1)")
    ap.add_argument("--duration", type=float, default=10.0, help="seconds to record")
    ap.add_argument("--interval-ms", type=int, default=1000)
    ap.add_argument("--out", default=None, help="output directory (default results/raw/<run id>)")
    ap.add_argument("--no-bpf", action="store_true", help="resource stream only")
    ap.add_argument("--collector", default=os.path.join(REPO_ROOT, "collector"))
    args = ap.parse_args(argv)

    out = args.out or os.path.join(
        REPO_ROOT, "results", "raw", time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:6])
    agent = Agent(out, interval_ms=args.interval_ms, duration_s=args.duration,
                  use_bpf=not args.no_bpf, collector=args.collector)
    signal.signal(signal.SIGTERM, agent.request_stop)
    signal.signal(signal.SIGINT, agent.request_stop)
    manifest = agent.run()
    print(json.dumps({"out": out, "counts": manifest["counts"],
                      "syscall_stream": manifest["syscall_stream"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
