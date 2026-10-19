"""Telemetry agent: supervises both collectors and records their streams.

    sudo python3 -m processpulse.agent --duration 10 --interval-ms 1000 [--out DIR] [--no-bpf]
                                       [--schema {1,2}] [--capabilities counts[,bigrams]]
                                       [--allow-degraded]

For every complete resource sample from the C collector the agent takes one
BPF syscall snapshot (aligned to that sample's sample_end) and writes:

    resource.jsonl   sample_begin / proc / sample_end, exactly as produced
    syscall.jsonl    syscall_snapshot records                  (--schema 1, default)
    bpf.jsonl        framed v2 BPF snapshots, docs/telemetry-v2.md (--schema 2)
    health.jsonl     one health record per sample (both collectors)
    preflight.json   preflight report
    manifest.json    run metadata (versions, boot id, configuration, counts)
    agent.log        diagnostics (collector stderr, framing errors)

If preflight fails or --no-bpf is given, the resource stream still runs and
health records state why the syscall stream is unavailable. Records are
validated before they are written; invalid agent records abort the run.
With --schema 2 every line is also held to the 64 KiB byte rule (a record
that would break it aborts the run), and a snapshot's emitted state is
committed only after all of its lines were written and flushed.

--capabilities counts,bigrams (S2.6; schema 2 only, U8/U9) adds syscall
bigrams to bpf.jsonl (docs/telemetry-v2.md §8). If the bigram program cannot
be started (or preflight fails), the run fails: whatever was started is
closed, manifest.json says status failed with the exact reason, and
StartupError (exit status 1) chains the original error. Only with
--allow-degraded does the agent run counts-only instead, marking bigrams
unavailable (pairs_lost null, bigrams_err UNSUPPORTED, reason in the begin
record) and recording requested/active/failed capabilities in the
manifest. At the normal end of
a bigram run the epoch is drained (U3): the resource supervisor, which calls
exclude() on every spawn, is stopped and joined; then the BPF collector's
drain(); after a successful drain exactly one more snapshot is written, the
drained snapshot (resource_seq null, end.drained true only if the collector
took it as its drained snapshot). The outcome is in manifest["drain"]. An
error during collection ends the run without a drain.
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
from .bpf_collector import check_capabilities
from .identity import read_boot_id
from .jsonl import encode_record
from .preflight import run_preflight
from .resource import ResourceCollector
from .snapshots import KEYFRAME_INTERVAL, V2Emitter
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


class StartupError(RuntimeError):
    """A requested capability could not be initialised; the run produced no result."""


class Agent:
    def __init__(self, out_dir, interval_ms=1000, duration_s=10.0, use_bpf=True,
                 collector=os.path.join(REPO_ROOT, "collector"), max_procs=16384, schema=1,
                 capabilities=("counts",), allow_degraded=False):
        if schema not in (1, 2):
            raise ValueError(f"unsupported output schema {schema!r} (1 or 2)")
        caps = check_capabilities(capabilities)             # U9, N3; priv refused
        extras = [c for c in caps if c != "counts"]
        if extras and schema != 2:
            raise ValueError(f"the {', '.join(extras)} capability needs schema 2 (U8)")
        if extras and not use_bpf:
            raise ValueError(f"the {', '.join(extras)} capability needs BPF "
                             "(--no-bpf contradicts it)")
        self.capabilities = caps
        self.extras = tuple(extras)          # capabilities beyond counts (schema 2 only)
        self.allow_degraded = bool(allow_degraded)
        self._cleanup_errors = []           # close() failures after a failed start
        self.out_dir = out_dir
        self.interval_ms = interval_ms
        self.duration_s = duration_s
        self.use_bpf = use_bpf
        self.collector_bin = collector
        self.max_procs = max_procs
        self.schema = schema
        self.validator = Validator()
        self._stop = False

    def request_stop(self, *_):
        self._stop = True

    def _line(self, rec):
        if self.schema == 2:
            return encode_record(rec) + "\n"     # raises if the byte rule would break
        return json.dumps(rec, separators=(",", ":")) + "\n"

    def _write(self, fh, rec):
        errs = self.validator.errors(rec)
        if errs:
            raise ValueError(f"agent produced an invalid {rec.get('type')} record: {errs[:3]}")
        fh.write(self._line(rec))

    def _started(self, collector):
        """collector.start(); a collector whose start fails is closed (its program
        may already be loaded and attached) before the original error propagates.
        A failing close() is not hidden: it is recorded in _cleanup_errors and added
        to the original exception as a note."""
        try:
            return collector.start()
        except BaseException as e:
            try:
                collector.close()
            except Exception as ce:
                note = f"cleanup after the failed start also failed: {type(ce).__name__}: {ce}"
                self._cleanup_errors.append(note)
                e.add_note(note)
            raise

    def _start_bpf(self, log):
        """(collector or None, why there is no stream, modes, reason, exception).
        modes: {capability: "ok" | "unavailable"} for every capability beyond
        counts (bigrams, net). They live in one unified program, so they start or
        fail together. Without allow_degraded a failure returns at once, with no
        collector (the run then fails); with it, the counts-only collector is
        started instead and every extra capability is unavailable."""
        from .bpf_collector import BpfCollector
        from .syscalls import SyscallCollector
        modes, why, err = {}, None, None
        if self.extras:
            try:
                sc = self._started(BpfCollector(capabilities=self.capabilities,
                                                max_procs=self.max_procs, track_removals=True))
                return sc, None, dict.fromkeys(self.extras, "ok"), None, None
            except Exception as e:
                modes, err = dict.fromkeys(self.extras, "unavailable"), e
                why = (f"{'+'.join(self.extras)} collector failed to start: "
                       f"{type(e).__name__}: {e}")[:300]
                if not self.allow_degraded:       # counts were not attempted: not a failure
                    return None, None, modes, why, err
                log.write(f"{time.monotonic_ns()} {why}; --allow-degraded: counts only\n")
        try:
            sc = self._started(SyscallCollector(max_procs=self.max_procs,
                                                track_removals=self.schema == 2))
        except Exception as e:
            return (None, f"syscall collector failed to start: {type(e).__name__}: {e}", modes,
                    why, err)
        return sc, None, modes, why, err

    def _capability_report(self, sc, sc_reason, modes, why):
        """Requested, active and failed capabilities (manifest)."""
        active = [] if sc is None else ["counts"] + [c for c in self.extras
                                                      if modes.get(c) == "ok"]
        failed = {}
        if self.use_bpf and sc is None and sc_reason:
            failed["counts"] = sc_reason
        for c in self.extras:
            if modes.get(c) != "ok":
                failed[c] = why or sc_reason
        return {"requested": list(self.capabilities), "active": active, "failed": failed}

    def _fail_startup(self, files, started_wall, report, reason, error):
        """Strict policy: a capability beyond counts was requested and could not be
        initialised. Closes
        the output files, writes a manifest with status failed (no run result) and
        raises StartupError chained to the original exception."""
        files["agent.log"].write(f"{time.monotonic_ns()} startup failed: {reason}\n")
        for fh in files.values():
            fh.close()
        manifest = {
            "run_id": os.path.basename(os.path.normpath(self.out_dir)),
            "status": "failed",
            "started_wall": started_wall,
            "error": {"stage": "startup", "capability": ",".join(report["failed"].keys()
                                                                 - {"counts"}) or "counts",
                      "reason": reason,
                      "type": type(error).__name__ if error is not None else None},
            "cleanup_errors": list(self._cleanup_errors),
            "capabilities": report,
            "degraded": False,
            "config": {"schema": self.schema, "allow_degraded": self.allow_degraded,
                       "use_bpf": self.use_bpf},
            "boot_id": read_boot_id(), "kernel": platform.release(), "git_head": _git_head(),
        }
        with open(os.path.join(self.out_dir, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)
        raise StartupError(f"{', '.join(self.extras)} requested but not available: {reason} "
                           "(use --allow-degraded to run counts-only)") from error

    def _final_drain(self, rc, sc, emitter, stream, log, counters):
        """End of a bigram epoch (U3). The supervisor calls exclude() on every
        spawn, so it is stopped and its thread joined first; without that no drain
        is attempted. After a successful drain exactly one more snapshot is
        built; its end record is drained only if the collector took it as the
        drained snapshot. Nothing else is reported as drained."""
        info = {"supervisor_stopped": False, "status": None, "drained": False, "reason": None,
                "final_snapshot": None}
        rc.stop()
        if not rc.stopped:
            info.update(status="skipped", reason="resource supervisor still running after stop()")
            log.write(f"{time.monotonic_ns()} drain skipped: {info['reason']}\n")
            return info
        info["supervisor_stopped"] = True
        try:
            res = sc.drain()
        except Exception as e:
            info.update(status="error", reason=f"{type(e).__name__}: {e}"[:300])
            log.write(f"{time.monotonic_ns()} drain error: {info['reason']}\n")
            return info
        for k in ("status", "reason", "reads", "changed", "still_attached", "drain_ns",
                  "accounting", "net_terms"):
            info[k] = res.get(k)
        info["drained"] = res.get("drained") is True
        if not info["drained"]:
            log.write(f"{time.monotonic_ns()} drain {res.get('status')}: {res.get('reason')}\n")
            return info
        recs, commit = emitter.build(resource_seq=None)
        for r in recs:
            self._write(stream, r)
        stream.flush()
        commit()
        counters["snapshots"] += 1
        end = recs[-1]
        if end["status"] == "failed":
            counters["failed_snapshots"] += 1
            log.write(f"{time.monotonic_ns()} drained snapshot {recs[0]['seq']} failed: "
                      f"{end['reason']}\n")
        info["final_snapshot"] = {"seq": recs[0]["seq"], "status": end["status"],
                                  "drained": end["drained"], "reason": end["reason"]}
        return info

    def run(self):
        os.makedirs(self.out_dir, exist_ok=True)
        stream_name = "syscall.jsonl" if self.schema == 1 else "bpf.jsonl"
        files = {n: open(os.path.join(self.out_dir, n), "w", encoding="utf-8")
                 for n in ("resource.jsonl", stream_name, "health.jsonl", "agent.log")}
        stream = files[stream_name]
        log = files["agent.log"]
        started_wall = time.time()
        t_start = time.monotonic_ns()

        preflight = run_preflight() if self.use_bpf else None
        if preflight is not None:
            with open(os.path.join(self.out_dir, "preflight.json"), "w") as f:
                json.dump(preflight, f, indent=2)

        sc, sc_reason, modes, why, start_error = None, None, {}, None, None
        if not self.use_bpf:
            sc_reason = "disabled (--no-bpf)"
        elif not preflight["ok"]:
            bad = [c for c in preflight["checks"] if c["status"] in ("FAIL", "BLOCKED")]
            sc_reason = "preflight: " + "; ".join(f"{c['name']} {c['status']}" for c in bad)
            modes, why = dict.fromkeys(self.extras, "unavailable"), sc_reason
        else:
            sc, sc_reason, modes, why, start_error = self._start_bpf(log)
        if any(modes.get(c) != "ok" for c in self.extras) and not self.allow_degraded:
            self._fail_startup(files, started_wall,
                               self._capability_report(sc, sc_reason, modes, why),
                               why or sc_reason, start_error)
        bigrams, net = modes.get("bigrams"), modes.get("net")
        bigrams_reason = why if bigrams == "unavailable" else None
        net_reason = why if net == "unavailable" else None
        if sc_reason:
            log.write(f"{time.monotonic_ns()} syscall stream unavailable: {sc_reason}\n")

        rc = ResourceCollector(self.collector_bin, interval_ms=self.interval_ms, diag=log)
        self._rc = rc
        if sc is not None:
            rc.on_spawn = sc.exclude
        counters = {"samples": 0, "snapshots": 0}
        emitter = None
        drain = None
        if self.schema == 2:
            counters["failed_snapshots"] = 0
            if sc is not None:
                emitter = V2Emitter(sc, run_id=os.path.basename(os.path.normpath(self.out_dir)),
                                    bigrams=bigrams, bigrams_reason=bigrams_reason, net=net,
                                    net_reason=net_reason)
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
                    files["resource.jsonl"].write(self._line(rec))
                counters["samples"] += 1
                skew = None
                if emitter is not None:
                    recs, commit = emitter.build(resource_seq=sample.seq)
                    for r in recs:
                        self._write(stream, r)
                    stream.flush()
                    commit()          # only after every line of the snapshot is written
                    counters["snapshots"] += 1
                    if recs[-1]["status"] == "failed":
                        counters["failed_snapshots"] += 1
                        log.write(f"{time.monotonic_ns()} bpf snapshot {recs[0]['seq']} failed: "
                                  f"{recs[-1]['reason']}\n")
                    skew = recs[0]["t_mono_ns"] - sample.end["t_mono_ns"]
                elif sc is not None:
                    snap = sc.snapshot(resource_seq=sample.seq)
                    self._write(stream, snap)
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
            if emitter is not None and "ok" in (bigrams, net):   # normal end of collection only
                drain = self._final_drain(rc, sc, emitter, stream, log, counters)
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
        if self.schema == 2:
            manifest["output_schema"] = {"resource": 1, "health": 1, "bpf": 2}
            manifest["bpf_stream"] = {"file": stream_name, "keyframe_interval": KEYFRAME_INTERVAL}
            report = self._capability_report(sc, sc_reason, modes, why)
            manifest["status"] = "ok"
            manifest["config"]["allow_degraded"] = self.allow_degraded
            manifest["capabilities"] = report
            manifest["degraded"] = any(c in report["failed"] for c in self.extras)
            manifest["bigrams"] = (None if "bigrams" not in self.capabilities
                                   else {"mode": bigrams, "reason": bigrams_reason})
            manifest["net"] = (None if "net" not in self.capabilities
                               else {"mode": net, "reason": net_reason})
            manifest["drain"] = drain
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
    ap.add_argument("--schema", type=int, choices=(1, 2), default=1,
                    help="BPF stream format: 1 = syscall.jsonl (M1), 2 = framed bpf.jsonl")
    ap.add_argument("--capabilities", default="counts",
                    help="BPF capabilities, comma-separated: counts (default), plus bigrams "
                         "and/or net (both need --schema 2 and counts)")
    ap.add_argument("--allow-degraded", action="store_true",
                    help="if the bigrams/net program cannot start, run counts-only and mark "
                         "them unavailable instead of failing (default: fail)")
    args = ap.parse_args(argv)
    caps = tuple(c.strip() for c in args.capabilities.split(",") if c.strip())
    try:
        check_capabilities(caps)
        extras = [c for c in caps if c != "counts"]
        if extras and args.schema != 2:
            raise ValueError(f"the {', '.join(extras)} capability needs --schema 2")
        if extras and args.no_bpf:
            raise ValueError(f"the {', '.join(extras)} capability needs BPF "
                             "(--no-bpf contradicts it)")
    except ValueError as e:
        ap.error(str(e))

    out = args.out or os.path.join(
        REPO_ROOT, "results", "raw", time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:6])
    agent = Agent(out, interval_ms=args.interval_ms, duration_s=args.duration,
                  use_bpf=not args.no_bpf, collector=args.collector, schema=args.schema,
                  capabilities=check_capabilities(caps), allow_degraded=args.allow_degraded)
    signal.signal(signal.SIGTERM, agent.request_stop)
    signal.signal(signal.SIGINT, agent.request_stop)
    try:
        manifest = agent.run()
    except StartupError as e:
        cause = e.__cause__
        print(json.dumps({"out": out, "status": "failed", "error": str(e),
                          "cause": None if cause is None else f"{type(cause).__name__}: {cause}",
                          "notes": list(getattr(cause, "__notes__", []))}, indent=2),
              file=sys.stderr)
        return 1
    print(json.dumps({"out": out, "counts": manifest["counts"],
                      "syscall_stream": manifest["syscall_stream"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
