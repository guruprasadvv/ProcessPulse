#!/usr/bin/env python3
"""Tabulate exact-count repetitions from JUnit XML (see exact_counts.sh).

    python3 tools/acceptance/summarize_exact_counts.py OUT_DIR REPS

Writes OUT_DIR/summary.json and OUT_DIR/summary.md. Exit 0 iff every expected
configuration ran REPS times and every run observed exactly the expected count.
"""

import glob
import json
import os
import statistics
import sys
import xml.etree.ElementTree as ET

# Configurations required by CLAUDE.md §11 (N in {1, 1000, 100000} per family).
EXPECTED = ([f"test_exact_entry_counts[{c}-{n}]" for n in (1, 1000)
             for c in ("openat", "open", "execve", "clone")]
            + [f"test_exact_entry_counts_100000[{c}]" for c in ("openat", "execve", "clone")])


def main():
    out, reps = sys.argv[1], int(sys.argv[2])
    rows = {name: [] for name in EXPECTED}
    for path in sorted(glob.glob(os.path.join(out, "run-*.xml"))):
        run = os.path.basename(path)[4:-4]
        for tc in ET.parse(path).getroot().iter("testcase"):
            name = tc.get("name")
            if name not in rows:
                continue
            props = {p.get("name"): p.get("value") for p in tc.iter("property")}
            failed = tc.find("failure") is not None or tc.find("error") is not None
            skipped = tc.find("skipped") is not None
            rows[name].append({
                "run": run, "time_s": float(tc.get("time")),
                "expected": int(props["expected"]) if "expected" in props else None,
                "observed": int(props["observed"]) if "observed" in props else None,
                "status": "SKIP" if skipped else "FAIL" if failed else "PASS",
            })

    summary, ok = [], True
    for name in EXPECTED:
        runs = rows[name]
        exact = [r for r in runs if r["status"] == "PASS" and r["observed"] == r["expected"]]
        cfg_ok = len(runs) == reps and len(exact) == reps
        ok &= cfg_ok
        summary.append({
            "config": name, "runs": len(runs), "exact": len(exact),
            "expected": runs[0]["expected"] if runs else None,
            "observed": sorted({r["observed"] for r in runs}),
            "median_time_s": round(statistics.median(r["time_s"] for r in runs), 3) if runs else None,
            "failures": [r for r in runs if r not in exact],
            "ok": cfg_ok,
        })
    report = {"reps": reps, "ok": ok, "configs": summary}
    with open(os.path.join(out, "summary.json"), "w") as f:
        json.dump(report, f, indent=2)
    lines = ["| configuration | runs | exact | expected | observed values | median s |",
             "|---|---|---|---|---|---|"]
    for s in summary:
        lines.append(f"| {s['config']} | {s['runs']} | {s['exact']} | {s['expected']} | "
                     f"{s['observed']} | {s['median_time_s']} |")
    lines.append(f"\nRESULT: {'PASS' if ok else 'FAIL'} ({reps} repetitions required)")
    with open(os.path.join(out, "summary.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
