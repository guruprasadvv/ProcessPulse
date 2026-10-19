# M1b S2.5 evidence: final drain (detach, barrier, double read) (2026-10-19)

Working tree on top of `391c988` (S1), uncommitted, with S2.1–S2.4 and the
purge-race fix. Environment: WSL2 Ubuntu 26.04, kernel
6.18.33.2-microsoft-standard-WSL2, Python 3.14.4 + BCC 0.35.0 (root runs),
Python 3.12.15 venv.

Contract: decision U3 (detach the probes, keep the maps, read twice and
require equal reads before claiming I-B2; hypothesis H-DRAIN), design
§3.6. Design and kernel-source argument: `docs/bpf-collector.md`, "Final
drain". Changes made in this step only: `s2.5-changes.patch` (made against
copies of the files saved before this session's first edit).

## Files

| Path | Content |
|---|---|
| `baseline/make-test-py3.14.log` | `make test` before any change: 525 passed, 1 skipped, rc 0 |
| `baseline/drain-unit-before-implementation.log` | the new unit tests before the implementation: 26 failed |
| `regression/make-test-py3.14.log` | `make test` on the final tree: 74 C checks, 0 failures; 551 passed, 1 skipped (D8), 87 deselected; rc 0 |
| `regression/make-test-py-py3.12.log` | `make test-py` with the 3.12 venv: 551 passed, 1 skipped; rc 0 |
| `regression/make-check.log` | `make check` rc 0 |
| `regression/privileged-suite.log`, `.xml` | as root, `pytest tests/ -m privileged`: **87 passed** (80 earlier + 7 new) in 589.95 s; rc 0 |
| `regression/equivalence.json`, `.txt` | counts-only S1 equivalence probe: **34 of 34** fields identical to `../s1/equivalence-post-s1.json` |
| `drain/drain-bpf-run-01.*`, `drain-bpf-run-02.*` | two more root runs of `tests/test_drain_bpf.py`: 7 passed each, rc 0 |
| `drain/summary.json` | per-test status and recorded values of the three final drain runs (the suite run and runs 01–02) |
| `final-root-sequence.log` | exit codes of the root sequence |
| `superseded/` | runs of a first version (see "Audit correction"): privileged suite 87 passed; drain file 7 passed. Not used as acceptance evidence. |

Every root log records `bpf_stats_enabled` 0 before and after, 0 `ppc-*`
cgroups and 0 containers at the end.

## Results (final code, 3 runs of the drain file)

| Test | Result | Measured |
|---|---|---|
| Detach and freeze | 3/3 PASS | all 11 probes detached; perf_event fds −11; `reads` 2; a helper's later 1,000 openat and a new helper's 10 execve not counted; the drained snapshot's cross-check passes |
| Drain during busy loops (×3 per run) | **9/9 PASS** | status `drained` at read 2 in every case. Cut off mid-loop: openat 171,011–214,344 of 3,000,000; execve 108,983–135,056 of 3,000,000; clone 2,107–2,381 of 40,000. Keys in the drain read: 3 (one case 7, other distro processes); `pairs_lost` 0 on every key. Detach + barrier + two reads: 1,316–1,470 ms |
| Ground truth: live, exited, reclaimed, purged | 3/3 PASS | counts side = pairs side = script's 26 entries; purge {5, 5, 0}; global losses 0 |
| Double read on attached probes | 3/3 PASS | two reads differ while a helper is busy |
| Counts-only drain | 3/3 PASS | drained, no bigram accounting, v1 snapshot after it |

## Invariants

| Invariant | Result | Where |
|---|---|---|
| I-B5 | PASS on every key of every drain read | busy and ground-truth tests |
| I-B1′ | PASS on every key with quiescence `drained`, including the busy helpers cut off mid-loop | busy tests (9 drains), ground truth |
| I-B3′ | PASS on every key | same |
| I-B1 | PASS on every key (all had `pairs_lost` 0) | same |
| I-B2 | `check_ib2_drain_read` PASS on all 9 busy drains and 3 ground-truth drains (whole epoch: live + reclaimed + purged terms). Scoped ground truth `check_ib2_ground_truth_scope` (quiescence `drained`) PASS 3/3 | `drain/summary.json` (`ib2_lhs`, `counts_side`) |
| I-B3 / I-B4 exact | PASS for the three scripted helpers (live, exited, reclaimed) against the oracle, zero global losses in the window | ground-truth test |
| Stream form (`check_ib2_drained` on a Reconstructor) | NOT TESTED on real data: needs the S2.6 emitter | — |

The unit tests (`tests/test_drain_unit.py`, 26) cover the outcomes the
kernel did not produce:
- unequal reads giving `unstable`, and a retry that waits for a new barrier;
- a `bglobal`-only change;
- detach, barrier and read failures;
- orphan pair entries;
- I-B2 failing by exactly a missing or double term;
- a reclaim after the drain not counting a key twice;
- the drained snapshot being the last one.

## Audit correction (before acceptance)

The first version read up to five times and accepted the first equal
consecutive pair. U3 says "read twice". A read pair taken after an unequal
pair has no new barrier behind it, so the drain was changed to exactly two
reads: unequal reads give `unstable`, and a retry re-runs detach, barrier
and both reads. `bglobal` was also added to the compared state (row-2
events write it). Every final number above is from the corrected code; the
earlier runs are in `superseded/`.

## Limitations (not fixed here)

- **H-DRAIN:** the detach → barrier argument is from kernel source (tag
  `linux-msft-wsl-6.18.33.2`, `perf_event_detach_bpf_prog`). It assumes
  that BCC's fd is the perf event's last reference, so the release happens
  inside `close()`. No unequal pair occurred after the barrier, so a late
  writer was never observed. The tests do not show whether the barrier was
  needed in these runs; the double read's sensitivity was shown on attached
  probes.
- **Scope of the busy runs:** in 8 of the 9 busy drains the drain read held
  only the three helpers, because no other distro process made a tracked
  call. The whole-distro claim is limited to what was running.
- **No end-record `drained` yet:** nothing writes `drained: true` until the
  S2.6 emitter. Before S2.6, a `V2Emitter` built on a drained collector
  emits the drained snapshot without the flag. Its next `build()` gets a
  `RuntimeError` from `snapshot()` and emits a failed snapshot.
- **Concurrency:** `drain()` and `snapshot()` must run on one thread (the
  agent's loop). `exclude()` from another thread is serialised by a lock
  and refused after the drain starts.
- **BCC detach failure:** if BCC closes the fd but fails later, the key stays
  in `tracepoint_fds`. The drain then fails (`still_attached`), and
  `close()` would close that fd number again.

**Purge-race follow-ups (unchanged, still open before S2.6):**
- (1) A barrier failure leaves the exclusion set and can end the supervisor
  thread. A drain barrier failure gives status `failed`.
- (2) `rcu_barrier()` provides `synchronize_rcu()` semantics despite its
  name.
- (3) `libc.syscall` is called without `argtypes`.
- (4) Thread-ID reuse during a purge is not formally excluded.
- (5) Exclusion is by PID.

**Requirements for S2.6:**
- emit `drained: true` only when `last_snapshot_drained` is true;
- stop the resource supervisor (which calls `exclude()`) before `drain()`;
- compare pair tables and `pairs_lost` as well as counts in change
  detection (S2.3 audit, finding 4).
