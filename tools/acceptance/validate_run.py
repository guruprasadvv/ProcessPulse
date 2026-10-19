#!/usr/bin/env python3
"""Validate every record of a recorded agent run (M1 acceptance A; M1b S0 for v2 runs).

    python3 tools/acceptance/validate_run.py RUN_DIR [--min-span-s 600] [--json OUT]

Mode: v2 if RUN_DIR has bpf.jsonl (agent --schema 2), else v1 (syscall.jsonl).
Checks, without skipping anything:
  * every line is newline-terminated, strict UTF-8, a JSON object, and valid
    against its schema version (processpulse.validate, incl. cross-field rules);
  * the byte rule (docs/telemetry-v2.md §1: at most 65,536 bytes without the LF,
    no CR) on every line. A v2 record that breaks it is invalid. A v1 record
    that breaks it is a legacy finding: counted and reported, but in a v1 run
    it does not change the verdict (M1 recorded oversize syscall_snapshot lines;
    M1b plan v3, decision A1). In a v2 run every line must satisfy the rule;
  * resource framing: sample_begin / proc* / sample_end with matching seq,
    emitted == number of proc records, seq strictly increasing;
  * one syscall snapshot (v1) or one BPF snapshot (v2, by begin.resource_seq)
    and one health record per sample, aligned by seq;
  * v2 only: the snapshot protocol (processpulse.snapshots.Reconstructor): no
    incomplete snapshot, framing error, seq gap, epoch change, invalidation or
    tracked/totals mismatch, and a valid reconstructed state at the end;
  * v2 only: a final snapshot after the last sample (resource_seq null: the
    drained snapshot of a bigram run, S2.6) is allowed once, as the last
    snapshot, and is not part of the per-sample alignment;
  * v2 with bigrams: the emitted-stream invariants (processpulse.bigrams):
    I-B2 on the drained snapshot and I-B5/I-B1'/I-B3'/I-B1 for every key whose
    values are final. Any FAIL fails the run; NOT_APPLICABLE is reported with
    its reason. --require-drained also requires a drained final snapshot;
  * collection span (first sample_begin -> last sample_end) >= --min-span-s;
  * the collector's own stream was clean: the agent filters invalid collector
    lines, so their counters (schema/framing/malformed/...) must all be 0.
Loss and gap counters are reported separately: schema validity does not imply
that no telemetry was lost.
Exit 0 iff every check passes.
"""

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from processpulse import bigrams as bg  # noqa: E402
from processpulse.jsonl import MAX_RECORD_BYTES, line_violations  # noqa: E402
from processpulse.snapshots import Reconstructor  # noqa: E402
from processpulse.validate import Validator  # noqa: E402

FILES_V1 = ("resource.jsonl", "syscall.jsonl", "health.jsonl")
FILES_V2 = ("resource.jsonl", "bpf.jsonl", "health.jsonl")
STREAM_CLEAN = ("schema_errors", "framing_errors", "malformed_json", "invalid_utf8",
                "oversize_lines", "partial_tail", "not_object")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_records(path, v, report):
    stats = {"lines": 0, "valid": 0, "invalid": 0, "unterminated_tail": 0, "bytes": os.path.getsize(path),
             "max_line_bytes": 0, "legacy_v1_oversize": 0, "legacy_v1_cr": 0}
    errors, records = [], []
    with open(path, "rb") as f:
        data = f.read()
    lines = data.split(b"\n")
    if lines and lines[-1] != b"":
        stats["unterminated_tail"] = 1
        errors.append("file does not end with a newline (truncated record)")
    for i, raw in enumerate(lines[:-1] if lines else []):
        stats["lines"] += 1
        stats["max_line_bytes"] = max(stats["max_line_bytes"], len(raw))
        bad = line_violations(raw)
        try:
            rec = json.loads(raw.decode("utf-8", errors="strict"))
            errs = v.errors(rec)
        except (UnicodeDecodeError, ValueError) as e:
            rec, errs = None, [f"{type(e).__name__}: {e}"]
        if bad:
            if isinstance(rec, dict) and rec.get("v") == 1:
                stats["legacy_v1_oversize"] += "oversize" in bad
                stats["legacy_v1_cr"] += "trailing_cr" in bad or "embedded_cr" in bad
            else:
                errs = errs + [f"framing rule: {bad}"]
        if errs:
            stats["invalid"] += 1
            if len(errors) < 20:
                errors.append(f"line {i + 1}: {errs[:3]}")
        else:
            stats["valid"] += 1
            records.append(rec)
    stats["sha256"] = sha256(path)
    report["files"][os.path.basename(path)] = stats
    report["errors"].extend(f"{os.path.basename(path)}: {e}" for e in errors)
    return records


def bigram_report(rc, final, require_drained):
    """Emitted-stream invariants of a bigram run (processpulse.bigrams)."""
    ib2 = bg.check_ib2_drained(rc)
    per_key = bg.check_quiescent_reports(rc)
    summary = {}
    for r in [ib2] + per_key:
        s = summary.setdefault(r.invariant, {bg.PASS: 0, bg.FAIL: 0, bg.NOT_APPLICABLE: 0})
        s[r.status] += 1
    na_reasons = sorted({r.reason for r in per_key if r.status == bg.NOT_APPLICABLE})
    fails = [f"{r.invariant} {r.key}: {r.reason}" for r in [ib2] + per_key if r.status == bg.FAIL]
    drained = bool(final and final["drained"])
    return {"ok": not fails and (drained or not require_drained),
            "drained_final_snapshot": drained, "require_drained": require_drained,
            "ib2": {"status": ib2.status, "reason": ib2.reason, "detail": ib2.detail},
            "summary": summary, "not_applicable_reasons": na_reasons[:20], "failures": fails[:20],
            "epoch_losses": bg.epoch_losses(rc)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--min-span-s", type=float, default=600.0)
    ap.add_argument("--json", default=None, help="write the report here")
    ap.add_argument("--require-drained", action="store_true",
                    help="v2 bigram run: the run must end with a drained snapshot")
    args = ap.parse_args()

    mode = "v2" if os.path.exists(os.path.join(args.run_dir, "bpf.jsonl")) else "v1"
    files = FILES_V2 if mode == "v2" else FILES_V1
    v = Validator()
    report = {"run_dir": os.path.abspath(args.run_dir), "mode": mode, "files": {}, "errors": [],
              "checks": {}}
    recs = {name: read_records(os.path.join(args.run_dir, name), v, report) for name in files}

    # Byte rule on every line (v1 legacy findings are reported, not enforced).
    legacy = {k: sum(f[k] for f in report["files"].values())
              for k in ("legacy_v1_oversize", "legacy_v1_cr")}
    report["line_limits"] = {"max_record_bytes": MAX_RECORD_BYTES, **legacy,
                             "max_line_bytes": max(f["max_line_bytes"] for f in report["files"].values())}
    if mode == "v1":
        report["checks"]["line_limits"] = {"ok": True, "policy": "v1: reported, not enforced"}
    else:
        report["checks"]["line_limits"] = {"ok": not any(legacy.values()),
                                           "policy": "v2: every line within the byte rule"}

    # Resource framing.
    samples, cur, framing = [], None, []
    for r in recs["resource.jsonl"]:
        t = r["type"]
        if t == "sample_begin":
            if cur is not None:
                framing.append(f"seq {cur['seq']}: begin before end")
            cur = {"seq": r["seq"], "begin": r, "procs": 0}
        elif t == "proc":
            if cur is None or r["seq"] != cur["seq"]:
                framing.append(f"proc seq {r['seq']} outside its sample")
            else:
                cur["procs"] += 1
        elif t == "sample_end":
            if cur is None or r["seq"] != cur["seq"]:
                framing.append(f"end seq {r['seq']} without begin")
            elif r["emitted"] != cur["procs"]:
                framing.append(f"seq {r['seq']}: emitted {r['emitted']} != {cur['procs']} procs")
            else:
                cur["end"] = r
                samples.append(cur)
            cur = None
        else:
            framing.append(f"unexpected type {t} in resource.jsonl")
    if cur is not None:
        framing.append(f"seq {cur['seq']}: run ends inside a sample")
    seqs = [s["seq"] for s in samples]
    if seqs != sorted(set(seqs)):
        framing.append("sample seq not strictly increasing")
    report["checks"]["resource_framing"] = {"ok": not framing, "samples": len(samples),
                                            "problems": framing[:20]}

    # Stream alignment, and (v2) the snapshot protocol.
    if mode == "v1":
        snap_seqs = [s["resource_seq"] for s in recs["syscall.jsonl"]]
    else:
        bpf = recs["bpf.jsonl"]
        begins = [r for r in bpf if r["type"] == "bpf_snapshot_begin"]
        ends = [r for r in bpf if r["type"] == "bpf_snapshot_end"]
        unaligned = [i for i, b in enumerate(begins) if b["resource_seq"] is None]
        final = None
        if unaligned:
            last_end = ends[-1] if ends and ends[-1]["seq"] == begins[-1]["seq"] else None
            final = {"seq": begins[-1]["seq"], "status": last_end and last_end["status"],
                     "drained": bool(last_end and last_end.get("drained"))}
        report["checks"]["final_snapshot"] = {
            "ok": unaligned in ([], [len(begins) - 1]), "final_snapshot": final,
            "policy": "resource_seq null only on the last snapshot (the drained snapshot)"}
        snap_seqs = [b["resource_seq"] for b in begins if b["resource_seq"] is not None]
        rc = Reconstructor()
        for r in bpf:
            rc.feed(r)
        rc.finish()
        st = rc.stats
        bad = ("snapshots_incomplete", "framing_errors", "seq_gaps", "epoch_changes",
               "totals_mismatch", "invalidations", "keyframe_schedule_violations",
               "snapshots_after_drain")
        report["checks"]["snapshot_protocol"] = {
            "ok": not any(st[k] for k in bad) and st["keyframes"] >= 1 and rc.valid,
            "stats": st, "final_state_valid": rc.valid, "tracked_at_end": len(rc.state),
            "problems": rc.errors[:20]}
        if begins and "bigrams" in begins[0]["capabilities"]:
            report["checks"]["bigram_invariants"] = bigram_report(rc, final, args.require_drained)
    health_seqs = [h["seq"] for h in recs["health.jsonl"]]
    report["checks"]["alignment"] = {"ok": snap_seqs == seqs and health_seqs == seqs,
                                     "samples": len(seqs), "snapshots": len(snap_seqs),
                                     "health": len(health_seqs)}

    # Collection span (CLOCK_MONOTONIC, from the records themselves).
    span_s = ((samples[-1]["end"]["t_mono_ns"] - samples[0]["begin"]["t_mono_ns"]) / 1e9
              if samples else 0.0)
    report["checks"]["span"] = {"ok": span_s >= args.min_span_s, "span_s": round(span_s, 3),
                                "required_s": args.min_span_s}

    # The collector stream itself must have been clean (agent filters bad lines).
    last_health = recs["health.jsonl"][-1] if recs["health.jsonl"] else None
    res = last_health["resource"] if last_health else {}
    dirty = {k: res.get(k) for k in STREAM_CLEAN if res.get(k)}
    report["checks"]["collector_stream_clean"] = {"ok": last_health is not None and not dirty,
                                                  "nonzero": dirty}

    # Loss / gap counters (reported, not part of schema validity).
    ends = [s["end"] for s in samples]
    loss = {
        "resource_dropped_samples": res.get("dropped_samples"),
        "resource_restarts": res.get("restarts"),
        "proc_gone_total": sum(e["gone"] for e in ends),
        "proc_denied_total": sum(e["denied"] for e in ends),
        "proc_parse_errors_total": sum(e["parse_errors"] for e in ends),
        "proc_read_errors_total": sum(e["read_errors"] for e in ends),
        "max_late_ms": round(max((e["late_ns"] for e in ends), default=0) / 1e6, 3),
        "max_sample_dur_ms": round(max((e["dur_ns"] for e in ends), default=0) / 1e6, 3),
    }
    if mode == "v1":
        snaps = recs["syscall.jsonl"]
        if snaps:
            h = snaps[-1]["health"]
            loss.update({f"bpf_{k}": h[k] for k in ("counts_map_full", "info_map_full",
                                                     "unresolved_events", "self_excluded_events",
                                                     "exit_events", "reclaimed", "map_entries")})
            loss["bpf_max_snapshot_ms"] = round(max(s["health"]["snapshot_ns"] for s in snaps) / 1e6, 3)
    else:
        oks = [r for r in recs["bpf.jsonl"] if r["type"] == "bpf_snapshot_end" and r["status"] == "ok"]
        loss["bpf_failed_snapshots"] = sum(1 for r in recs["bpf.jsonl"]
                                           if r["type"] == "bpf_snapshot_end" and r["status"] == "failed")
        if oks:
            last = oks[-1]
            loss.update({f"bpf_{k}": last["loss"][k] for k in last["loss"]})
            loss.update({f"bpf_{k}": last["health"][k] for k in ("unresolved_events",
                                                                  "self_excluded_events", "exit_events",
                                                                  "reclaimed", "map_entries")})
            loss["bpf_max_unreported_entries"] = max(r["health"]["unreported_entries"] for r in oks)
            loss["bpf_max_snapshot_ms"] = round(max(r["health"]["snapshot_ns"] for r in oks) / 1e6, 3)
    report["loss_counters"] = loss

    totals = {k: sum(f[k] for f in report["files"].values()) for k in ("lines", "valid", "invalid")}
    report["totals"] = totals
    schema_ok = totals["invalid"] == 0 and all(f["unterminated_tail"] == 0
                                               for f in report["files"].values())
    report["checks"]["schema"] = {"ok": schema_ok}
    report["ok"] = all(c["ok"] for c in report["checks"].values())

    text = json.dumps(report, indent=2)
    print(text)
    if args.json:
        with open(args.json, "w") as f:
            f.write(text + "\n")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
