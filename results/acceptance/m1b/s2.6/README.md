# M1b S2.6 evidence: bigram emitter and agent integration (2026-10-19)

Base: `d1d7eac` (S2.5). Environment: WSL2 Ubuntu 26.04, kernel
6.18.33.2-microsoft-standard-WSL2, Python 3.14.4 + BCC 0.35.0 (root runs),
Python 3.12.15 venv.

## Phase 1: S2.1–S2.5 committed in order (authorized, option 1)

| Commit | Subject |
|---|---|
| `5f0d376` | feat(m1b): implement S2.1-S2.4 bounded syscall bigram storage and map accounting |
| `1f763de` | fix(m1b): synchronize in-flight BPF readers before purge |
| `d1d7eac` | feat(m1b): implement S2.5 final-drain protocol and double-read map accounting |

How the commit states were built:
- **State B (commit 2):** the pre-S2.5 copies of the six files S2.5 touched.
- **State A (commit 1):** state B with the purge-fix edits reversed. The
  edits were taken verbatim from the earlier session's transcript; each
  reversal had to match exactly once, and the changelog section appended
  by the shell had to match byte for byte.
- **Commit 3:** the working tree.

Each state was staged as blobs (`git update-index`), so the working tree
was never modified.

Checks, all passed before each commit:
- The staged index equalled a full tree built from HEAD plus that state, in
  both directions (A: 172 files, B: 190 files, 0 differences).
- Those trees passed `make test` (`phase1/tree-make-test-A.log`: 519
  passed, 3 skipped; `tree-make-test-B.log`: 523 passed, 3 skipped). The 2
  extra skips need the gitignored `results/raw/` M1 run.
- Tree B passed the privileged purge and bigram tests (`tree-priv-B.log`:
  24 passed).
- Commit 3 equals the reviewed `../s2.5/s2.5-changes.patch` (1,209 of 1,209
  changed lines).
- No M1 log and nothing under `results/raw/` was staged.
- `git diff --cached --check` reported only blank context lines inside that
  `.patch` evidence file, which unified diff format requires; rc 0 without
  that file.

File lists: `phase1/commit-file-lists.txt`.

## Scope (S2 design step 6, plus the review refinements)

- **Emitter:** `V2Emitter(bigrams="ok")` writes `bpf_bigrams` tables. A
  process is re-emitted on any change of counts, `pairs_lost` or its pair
  table. `drained` is true only on the snapshot the collector took as its
  drained snapshot.
- **Agent:** `--schema 2 --capabilities counts,bigrams`; the defaults stay
  schema 1 / counts. At the end of an epoch: supervisor stopped and joined,
  then `drain()`, then one drained snapshot.
- **Strict startup policy (review refinement):** if bigrams are requested
  and cannot be initialised (start failure or preflight failure), the run
  fails. The agent:
  - writes a manifest with `status: failed` and the exact reason;
  - raises `StartupError` chained to the original error, and the CLI exits
    with status 1;
  - releases every handle, and writes no telemetry;
  - adds cleanup errors to the original exception as notes and lists them
    in the manifest.

  Counts-only operation needs `--allow-degraded`. The manifest then records
  the requested, active and failed capabilities, and the telemetry says
  bigrams are `unavailable` (null with `bigrams_err`, never an empty
  table). `--no-bpf` together with bigrams is refused.
- **Validation:** `validate_run.py` checks bigram streams.

Not done: no network or privilege hooks, no ML features, no schema change.

## Results (final code)

| Run | Command | Result |
|---|---|---|
| Before the implementation | new emitter / agent tests | 18 of 20 failed / 3 failed + 12 errors (`baseline/`) |
| Unprivileged, py3.14 | `make test` | 74 C checks, 0 failures; **613 passed, 1 skipped** (D8), rc 0 (`regression/make-test-py3.14.log`) |
| Unprivileged, py3.12 | `make test-py PYTHON=~/.venvs/processpulse-py312/bin/python` | **613 passed, 1 skipped**, rc 0 |
| Static | `make check` | rc 0 |
| Privileged, as root | `PYTHONUSERBASE=/home/mypc/.local make test-privileged` | **91 passed** in 425 s, rc 0 (`regression/make-test-privileged.log`) |
| End-to-end agent tests (JUnit) | `pytest tests/test_agent_bigrams_bpf.py -m privileged` | 4 passed (`e2e/agent-bigrams-bpf.xml`) |
| CLI, bigrams | `agent --duration 30 --interval-ms 500 --schema 2 --capabilities counts,bigrams`, background process churn; `validate_run.py --min-span-s 25 --require-drained` | agent rc 0, validate rc 0, every check ok (`e2e/validation-bigrams.json`, `manifest-bigrams.json`) |
| CLI, counts-only v2 | `agent --duration 10 --schema 2`; `validate_run.py --min-span-s 8` | rc 0 / rc 0 |
| CLI, default (schema 1) | `agent --duration 10`; `validate_run.py --min-span-s 8` | rc 0 / rc 0, v1 mode |
| Counts-only equivalence | `tools/acceptance/s1_equivalence.py` vs `../s1/equivalence-post-s1.json` | **34 of 34** identical (`regression/equivalence.txt`) |

Runs made before the strict policy, kept for the record, are in
`pre-strict-policy/` (590 passed unprivileged, 89 privileged, the same CLI
checks).

## Adversarial verification (Phase 2)

**A. Serialized chunk limits** (`tests/test_bigram_chunk_limits.py`, 13 tests):
- **Exhaustive sweep:** every limit from the smallest viable one up to the
  size of the largest possible table (all 117 pairs, counts up to 2^64−1),
  with `max_items` 1,024 and 7. Each part was within both limits,
  contiguous, exactly reassembling the table, and maximal under the
  documented sizing. Below the smallest viable limit the pair is refused
  (`RecordTooLarge`), never truncated.
- **Exact boundary:** a part of exactly the limit is kept, and one byte less
  splits it. The placeholder sizing of part numbers costs at most 4 bytes
  of slack, never an oversize record.
- **1,024 boundary:** 1,024 / 1,025 / 2,048 pairs give 1 / 2 / 2 parts.
- **Worst case:** the widest possible part (1,024 maximal pairs, maximal
  key, seq and part numbers) is **62,739 bytes, 62,740 with its LF**, below
  65,536 even counting the LF.
- **Unicode and escaping:** non-ASCII, U+2028/2029, quotes, backslashes,
  control characters, CR/LF and astral characters were measured on the
  final ASCII-escaped bytes at many limits. Every record was within the
  limit, contained no raw CR/LF, and round-tripped.
- **In the emitter:** a part that cannot fit raises before anything is
  written or committed.
- **Contract note:** the approved byte rule (CLAUDE.md §5, S0/A1) measures
  the record *without* its LF, so a general v2 record may be 65,536 bytes
  plus LF. For `bpf_bigrams` the 1,024-pair cap binds first, so the line
  with its LF stays at most 62,740 bytes. Changing the rule to include the
  LF would be a contract change and was not made.

**B. Final-snapshot failure paths** (`tests/test_agent_bigrams.py`):
- unstable, failed and raising drains;
- a supervisor that does not stop (no drain);
- a failed cross-check (written as failed, not drained);
- a write error on the drained snapshot (propagates, nothing committed, no
  manifest);
- `KeyboardInterrupt` in the drain;
- an unfittable part in the drained snapshot.

None of them produces a `drained: true` record, and in every case the BPF
collector is closed and the C collector child is terminated.

**C. Resource cleanup (real kernel)** (`tests/test_agent_bigrams_bpf.py`):
- The bigram program is made to fail after it is loaded and its 11
  tracepoints are attached.
- In strict mode (`StartupError`, manifest `failed`, no telemetry) and in
  degraded mode (counts-only run), this process's `[perf_event]`,
  `bpf-prog` and `bpf-map` fd counts return exactly to their values before
  the agent ran.
- The normal end-to-end run checks the same, and that the C collector
  child exited.
- `bpftool` is not installed, so the `bpf_progs_total` field in the logs is
  not a measurement.

## Emitted-stream invariants

The 30 s CLI bigram run (`e2e/validation-bigrams.json`): 1,247 bpf lines
(max 1,372 bytes), 62 snapshots, and a drained final snapshot (seq 61). 437
keys have final values: 3 live after the drain and 434 reclaimed as exited.
The e2e test run had 4 such keys plus scripted ground truth.

| Invariant | Result | Preconditions and notes |
|---|---|---|
| I-B5 | **PASS**, 437/437 (CLI), 4/4 (e2e) | unconditional; also a schema rule on every line |
| I-B1′ | **PASS**, 437/437 and 4/4 | quiescent: drained (live keys) or reclaimed as exited. Includes a helper busy through the drain (564,469 openat at the drain, e2e) |
| I-B3′ | **PASS**, 437/437 and 4/4 | same |
| I-B1 | **PASS**, 437/437 and 4/4 | quiescent and `pairs_lost` = 0. No emitted key had pair loss; the epoch's 2 pre-arm events are in the purged entries (`purged_pairs_lost` 2) |
| I-B2 (`check_ib2_drained`, emitted stream) | **PASS**: CLI 7,200 = 7,200; e2e 564,494 | drained snapshot applied, valid state, whole epoch from seq 0, no vanished entry |
| I-B2 drain read (manifest accounting) | **PASS** (e2e) | collector-side form of the same equation |
| I-B2 ground truth, scoped | **PASS** (e2e): 21 = 21 | three scripted helpers; `counts_map_full` did not rise |
| I-B3 / I-B4 exact | **PASS** for the openat/open/execve helpers (e2e) | quiescent, `pairs_lost` 0, oracle, global losses over the window 0. **NOT APPLICABLE** to the CLI run (no ground truth) |

## Drain and final snapshot

- **CLI bigram run:** `manifest.drain` = supervisor stopped, `drained`,
  reads 2; `final_snapshot` {seq 61, ok, drained true}; exactly one end
  record is drained, and it is the last one.
- **Manifest:** `status: ok`, `degraded: false`, `capabilities` requested =
  active = counts,bigrams, failed {}.

## Limitations and follow-ups

- **No drained snapshot on error:** a run that stops on an error during
  collection, or whose drain is not `drained`, has no drained snapshot, so
  stream-level I-B2 is NOT APPLICABLE for it.
- **Exit status 1 is unit-tested only:** the CLI's exit status 1 on a strict
  startup failure is unit-tested through `main()`. On the real kernel the
  failure path is tested through `Agent.run()`, because a real startup
  failure cannot be injected through the CLI without code changes.
- **Purge-race follow-ups 1–5 unchanged:**
  1. a barrier failure ends the supervisor thread (tested: the run still
     ends with a drain);
  2. the `rcu_barrier()` name;
  3. `argtypes`;
  4. TID reuse during a purge;
  5. PID-based exclusion.
- **H-DRAIN:** the barrier's necessity is still not demonstrated (S2.5).
- **Raw runs:** in gitignored `results/raw/s2.6-*`.
