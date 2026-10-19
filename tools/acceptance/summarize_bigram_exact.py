#!/usr/bin/env python3
"""Tabulate the S2.4 bigram acceptance repetitions (see bigram_exact.sh).

    python3 tools/acceptance/summarize_bigram_exact.py OUT_DIR REPS

Writes OUT_DIR/summary.json and OUT_DIR/summary.md. Exit 0 iff every
configuration ran REPS times and passed every time (exact pair table, counts,
I-B5/I-B1/I-B1'/I-B3', exact I-B3/I-B4, scoped I-B2 ground truth, no global
loss, no stale slot), and every repetition's counts-only equivalence output
equals the S1 baseline field for field.
"""

import glob
import json
import os
import statistics
import sys
import xml.etree.ElementTree as ET

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BASELINE = os.path.join(REPO, "results", "acceptance", "m1b", "s1", "equivalence-post-s1.json")
EXPECTED = ([f"test_exact_pairs[{c}-{n}]" for c in ("openat", "open", "execve", "clone")
             for n in (1, 1000)]
            + [f"test_exact_pairs_100000[{c}]" for c in ("openat", "execve", "clone")]
            + ["test_exact_pairs_mixed_sequence", "test_exact_pairs_across_an_exec",
               "test_ground_truth_over_a_scope_with_exit_and_purge"])


def flat(d, prefix=""):
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out.update(flat(v, prefix + k + "."))
        else:
            out[prefix + k] = v
    return out


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
            rows[name].append({"run": run, "time_s": float(tc.get("time")),
                               "expected": int(props["expected"]) if "expected" in props else None,
                               "observed": int(props["observed"]) if "observed" in props else None,
                               "status": "SKIP" if skipped else "FAIL" if failed else "PASS"})
    summary, ok = [], True
    for name in EXPECTED:
        runs = rows[name]
        passed = [r for r in runs if r["status"] == "PASS" and r["observed"] == r["expected"]]
        cfg_ok = len(runs) == reps and len(passed) == reps
        ok &= cfg_ok
        summary.append({"config": name, "runs": len(runs), "passed": len(passed),
                        "expected_entries": runs[0]["expected"] if runs else None,
                        "observed_entries": sorted({r["observed"] for r in runs}),
                        "median_time_s": round(statistics.median(r["time_s"] for r in runs), 3)
                        if runs else None,
                        "failures": [r for r in runs if r not in passed], "ok": cfg_ok})

    with open(BASELINE) as f:
        base = flat(json.load(f))
    equiv = []
    for i in range(1, reps + 1):
        path = os.path.join(out, f"equivalence-{i:02d}.json")
        if not os.path.exists(path):
            equiv.append({"run": f"{i:02d}", "ok": False, "missing": True})
            continue
        with open(path) as f:
            cur = flat(json.load(f))
        diff = sorted(k for k in set(cur) | set(base) if cur.get(k) != base.get(k))
        equiv.append({"run": f"{i:02d}", "fields": len(cur), "identical": len(cur) - len(diff),
                      "different": diff, "ok": not diff and len(cur) == len(base)})
    equiv_ok = len(equiv) == reps and all(e["ok"] for e in equiv)
    ok &= equiv_ok

    report = {"reps": reps, "ok": ok, "configs": summary,
              "equivalence": {"baseline": os.path.relpath(BASELINE, REPO), "ok": equiv_ok,
                              "runs": equiv}}
    with open(os.path.join(out, "summary.json"), "w") as f:
        json.dump(report, f, indent=2)
    lines = ["| configuration | runs | passed | expected entries | observed entries | median s |",
             "|---|---|---|---|---|---|"]
    for s in summary:
        lines.append(f"| {s['config']} | {s['runs']} | {s['passed']} | {s['expected_entries']} "
                     f"| {s['observed_entries']} | {s['median_time_s']} |")
    lines += ["", "| equivalence run | fields | identical | different |", "|---|---|---|---|"]
    for e in equiv:
        lines.append(f"| {e['run']} | {e.get('fields')} | {e.get('identical')} "
                     f"| {e.get('different', 'missing')} |")
    lines += ["", f"RESULT: {'PASS' if ok else 'FAIL'} ({reps} repetitions required)"]
    with open(os.path.join(out, "summary.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
