# M1b S2.4 evidence: exact-check preconditions and repeated scripted acceptance (2026-10-19)

Working tree on top of `391c988` (S1), uncommitted, with S2.1–S2.4.
Environment: WSL2 Ubuntu 26.04, kernel 6.18.33.2, 16 possible CPUs, Python
3.14.4 + BCC 0.35.0 (root runs), Python 3.12.15 venv. Before the repeated run:
WSL MemAvailable 6,265,476 kB; Windows free physical memory 1,622 MB. That is
below the plan's 2 GiB gate, but the gate applies only to the order-balanced
throughput check (`--abba`), which was not run.

## Repeated scripted acceptance (`exact/`)

Command (as root):
`PYTHONUSERBASE=/home/mypc/.local bash tools/acceptance/bigram_exact.sh 10`.
There were 10 sequential repetitions (09:03:12 to 09:24:49 UTC). Each
repetition was a fresh pytest process, so a fresh BPF load, running
`tests/test_bigrams_acceptance.py`, followed by one counts-only equivalence
probe (`tools/acceptance/s1_equivalence.py`).

Files: `run-NN.xml` (JUnit, with expected and observed entries per
configuration), `run-NN.log`, `equivalence-NN.json`/`.log`, `preflight.json`,
`runs.log` (memory, `bpf_stats_enabled` and cleanup state), `summary.json`/`.md`
(from `tools/acceptance/summarize_bigram_exact.py`).

**Result: PASS, 10 of 10 for every configuration.**

| Configuration | Passed | Expected = observed entries | Median s |
|---|---|---|---|
| `test_exact_pairs[{openat,open,execve,clone}-1]` | 10/10 each | 2 | 0.035–10.8* |
| `test_exact_pairs[{openat,open,execve,clone}-1000]` | 10/10 each | 1,001 | 0.038–0.56 |
| `test_exact_pairs_100000[{openat,execve,clone}]` | 10/10 each | 100,001 | 0.43 / 0.45 / 49.2 |
| `test_exact_pairs_mixed_sequence` | 10/10 | 12 | 0.042 |
| `test_exact_pairs_across_an_exec` | 10/10 | 5 | 0.094 |
| `test_ground_truth_over_a_scope_with_exit_and_purge` | 10/10 | 21 | 0.95 |
| counts-only equivalence vs `../s1/equivalence-post-s1.json` | 10/10 | 34 of 34 fields identical each time | — |

\* The first configuration's time includes the module fixture (calibration
and unified compile). Expected entries = 1 (the execve that loads the
helper) + N.

Each passing configuration asserted all of the following:
- the helper's complete pair table equals the oracle built from the script;
- its counts equal the oracle's counts;
- `pairs_lost` = 0;
- the global loss counters did not rise over the helper's lifetime window;
- `thread_slot_stale` did not rise;
- I-B5, I-B1, I-B1′ and I-B3′ PASS;
- exact I-B3 and I-B4 PASS;
- the scoped ground truth of I-B2 PASS.

The scope configuration covers three helpers: one live, one exited and not yet
reclaimed, and one purged. Its counts side and pairs side equal the script's
21 entries, the purge totals are exactly {counts 4, pairs 4, pairs_lost 0}, and
the same data with the purged helper left out, or with a helper counted twice,
FAILs.

Run-to-run time variation (repetitions took 48–157 s) comes from the 100,000
`clone` configuration (37–122 s) and the compile (8–58 s); every other
configuration stays under 1.1 s. It is host load, not a correctness signal.

Cleanup: `bpf_stats_enabled` 0 at start and end; 0 `ppc-*` cgroups; 0 containers.

## Regression (`regression/`)

| Log | Result |
|---|---|
| `make-test-py3.14.log` (`make test`) | 74 C checks, 0 failures; 521 passed, 1 skipped (D8), 75 deselected; the 2 warnings are BCC's own `DeprecationWarning`s |
| `make-test-py-py3.12.log` (`make test-py`, 3.12 venv) | 521 passed, 1 skipped, 75 deselected |
| `make-check.log` | rc 0, no compiler warning |
| `privileged.log` (as root, `pytest tests/ -m privileged`) | 75 passed (M1, DIT-1, S0, S1, S2.3 + S2.4, and the acceptance file once) in 276 s; `bpf_stats_enabled` 0 before and after; 0 cgroups; 0 containers |

An earlier run of the same privileged suite (75 passed in 243 s) and the
first unprivileged run were seen in the session but not saved. These logs
come from re-running them so that the evidence exists as files.

## Scope limits (not reductions)

- **I-B2 ground truth over a whole epoch** (`check_ib2_ground_truth`) needs a
  drained snapshot, which S2.5 implements, and a v2 bigram stream, which S2.6
  emits. Until then it is validated on synthetic streams (`tests/test_bigrams.py`).
  On real helpers the same equation is checked over a closed scope
  (`check_ib2_ground_truth_scope`).
- **Thread creation is not covered by the exact oracle runs**: whether the
  helper's `pthread_create` enters `clone` or `clone3` is not known
  independently. Threads, non-leader exec and thread-ID reuse are covered by
  the invariant tests in `tests/test_bigrams_bpf.py`.
- **The purge race** in `BpfCollector.exclude()` (S2.3 audit, finding 2) is
  **open** and is required before S2.5. The scope configuration purges an
  idle helper, which the race cannot affect.
