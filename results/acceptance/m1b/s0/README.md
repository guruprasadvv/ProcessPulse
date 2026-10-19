# M1b S0 evidence: framing rule and v2 BPF snapshot protocol (2026-10-19)

Working tree on top of `3df5819` (uncommitted). Environment as in M1: WSL2 Ubuntu
26.04, kernel 6.18.33.2-microsoft-standard-WSL2, system Python 3.14.4 + BCC 0.35.0,
Python 3.12.15 venv. Contract: `docs/telemetry-v2.md`.

## T-F6: 10-minute v2 run (`tools/acceptance/run_s0_10min.sh 600`, as root)

- Agent: `python3 -m processpulse.agent --schema 2 --duration 615 --interval-ms 1000`,
  raw output `results/raw/m1b-s0-10min-20261019T042927` (gitignored). Agent rc 0,
  0 leftover collector processes.
- `validation.json`: **ok**, mode v2. 23,271 / 23,271 lines valid (resource 21,076,
  bpf 1,579, health 616). Longest line 2,100 bytes; 0 lines break the byte rule.
  616 samples, 616 BPF snapshots, 616 health records aligned 1:1; span 615.006 s
  (required 600). Snapshot protocol: 616 complete, 0 failed, 0 incomplete,
  11 keyframes, 0 framing errors, 0 seq gaps, 0 epoch changes, 0 totals
  mismatches, 0 invalidations; valid state at the end.
- Loss counters: 0 dropped samples, 0 restarts, 0 counts/info map full,
  0 vanished entries, 0 unreported entries; 87 unresolved events, 87 reclaimed.
- **Limitation of this run:** the system was idle (no concurrent workload), so the
  run exercised few processes; the largest line was 2,100 bytes. Large
  populations (thousands of processes, removal lists split across records) are
  covered by unit tests (`tests/test_snapshots.py`), not by this run.

## Negative check: crash while writing the final snapshot

`validation-truncated.json`: the recorded `bpf.jsonl` cut right after the final
snapshot's begin record is **rejected** (validate_run rc 1; snapshot protocol:
1 incomplete, 1 invalidation, "stream ended inside snapshot 615").

`run.log` keeps the history: the harness's first version of this check cut
after "begin + one record", which on an idle system's final snapshot (begin +
end only) removed nothing, so the copy validated (rc 0) and the script reported
FAIL. That was a defect in the harness, not in the product. The harness was
fixed (cut after the begin, assert that something was removed) and the check
re-run alone with `run_s0_10min.sh --negative-only <run dir>` → PASS. The
10-minute run was not repeated.

## Recorded M1 run under the new validator

`tests/test_validate_run.py` (local evidence, skipped where `results/raw` is
absent): the accepted M1 file `results/raw/m1-10min-20261018T205546/syscall.jsonl`
(sha256 equal to `results/acceptance/m1/10min/validation.json`) has exactly 15 of
613 lines over 65,536 bytes; the largest record is **311,053 bytes** without its
LF (the M1b planning reports said 311,054, which counted the LF). The whole M1
run still validates (ok, 27,803 / 27,803 valid) and reports
`legacy_v1_oversize = 15`.

## Re-validation after the keyframe correction

The keyframe rule was corrected after review (`docs/telemetry-v2.md` §3). The
recorded run above was produced before the correction; it contains no failed or
uncommitted snapshot, which are the only paths the correction changes, and it
was **not re-run**. Re-validated with the corrected validator:
`validation-recheck.json` ok (23,271 / 23,271 valid, 616 complete snapshots,
11 keyframes, 0 keyframe schedule violations, 0 incomplete / gaps /
invalidations); `validation-truncated-recheck.json` still rejected
(1 incomplete snapshot, "stream ended inside snapshot 615").
