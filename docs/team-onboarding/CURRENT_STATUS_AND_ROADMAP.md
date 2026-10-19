# Current status and roadmap

[← Onboarding index](README.md) · history: [DEVELOPMENT_HISTORY.md](DEVELOPMENT_HISTORY.md)

**As of 2026-10-19.** Verified from `git log`, `git status` and the saved
evidence in `results/acceptance/`. If you read this later, re-check with the
commands in [SETUP_AND_TESTING.md §3](SETUP_AND_TESTING.md#3-inspect-repository-state-always-first).

## 1. Repository state

GitHub (private): https://github.com/guruprasadvv/ProcessPulse.

| Branch | Contents | Status |
|---|---|---|
| `master` | M0 → S2.6, the onboarding package, the S3 network plan, `docs/commit-hash-map.md` | committed; **the only branch the owner merges into** |
| `wip/s3.2-network` | `master`, plus the S3.1/S3.2 code and its evidence in commit `5b6231b` (see §3) | **not merged, not accepted** |

- **History rewrite:** on 2026-10-19 the history was rewritten once, to
  remove an AI co-author line from the commit messages. Files, authors and
  dates are unchanged, but every hash changed. Older documents
  (`CLAUDE.md`, the changelog, evidence READMEs and recorded manifests)
  cite the old hashes. Translate them with
  [`docs/commit-hash-map.md`](../commit-hash-map.md).
- **What the S3.1/S3.2 commit contains:**
  - modified files: `CLAUDE.md`, `ENGINEERING_CHANGELOG.md`,
    `bpf/core.bpf.c`, `docs/bpf-collector.md`, `docs/telemetry-v2.md`;
  - `processpulse/agent.py`, `bpf_collector.py`, `schemas/telemetry.v2.json`,
    `snapshots.py`, `validate.py`, `vocab.py`;
  - `tests/snapshot_fakes.py`, `tests/test_agent_bigrams.py`,
    `tests/test_bpf_collector_unit.py`;
  - new files: `bpf/net.bpf.c`, `processpulse/net.py`,
    `tests/test_net_unit.py`, `tests/test_net_bpf.py`,
    `tests/helpers/net_helper.py`, `results/acceptance/m1b/s3-plan/`,
    `results/acceptance/m1b/s3.2/`.
- **The owner's machine only:** the same S3.1/S3.2 changes are also
  uncommitted in the owner's working tree, together with the 15 intentional
  M1 evidence logs (never staged, not in git). `results/raw/` is
  gitignored everywhere.

## 2. Accepted and committed

| Milestone | Commit | Old hash (in older docs) | Accepted? |
|---|---|---|---|
| M0 | `a1be2b9` | `795c945` | accepted with documented defects (D8–D10 open) |
| M1 | `1256d0d` | `3df5819` | **accepted** (`results/acceptance/m1/`) |
| M1b S0 | `610702a` | `d9b9e9b` | accepted |
| M1b S1 | `4346fab` | `391c988` | committed |
| M1b S2.1–S2.4 | `d1ff507` | `5f0d376` | committed |
| Purge-race fix | `615896d` | `1f763de` | committed |
| M1b S2.5 | `ecbe7d2` | `d1d7eac` | committed (formally accepted, per the owner) |
| M1b S2.6 | `5a45db3` | `699c2c8` | committed (accepted, per the owner, with the strict startup policy) |

M1b as a whole is **not** complete: network (S3.x), privilege signals and
the final M1b acceptance (S7 in the old plan) are still open.

## 3. Implemented but not accepted: S3.1/S3.2 (network: connect/accept)

**Where:** branch `wip/s3.2-network`, commit `5b6231b`. The evidence paths below
exist only on that branch.

**Status: NOT READY FOR REVIEW.** Verification checklist on the **final**
code:

| Check | State | Evidence |
|---|---|---|
| Unprivileged suite, py3.14 + py3.12 | **done**: 657 passed, 1 skipped each; 74 C checks, 0 failures; `make check` rc 0 | `results/acceptance/m1b/s3.2/regression/make-test-*.log`, `make-check.log` |
| Agent unit tests after the last edit | **done**: 73 passed | `regression/post-edit-agent-unit.log` |
| Full `make test-privileged` | **incomplete**: stopped by the tooling at 18 % (20 passed, 0 failed) because host memory was low; WSL restarted | `regression/make-test-privileged.log`, `post-kill-state.txt` |
| Network BPF tests (`tests/test_net_bpf.py`) | **development run only**: 16/16 passed, but **before** two late edits (manifest `drain.net_terms`, one added e2e assertion). The final recorded run never ran | `net-bpf-dev.log` |
| S1 counts-only equivalence | **not run** for S3.2 | — |
| Resource cleanup (fd baselines after strict/degraded startup failure, e2e) | passed **in the development run only** | `net-bpf-dev.log` |
| Invariant audit I-N1–I-N6 | I-N1/I-N2/I-N4 PASS and I-N6 exact equality in the development run; I-N3/I-N5 NOT APPLICABLE; the **S3.2 interpretations still need review** | `README.md` in `s3.2/`; plan §11 |
| fd-reuse race assessment | **not done**. Only a qualitative note: the socket class is read at entry through the fd table, so another thread closing and reusing that fd could misclassify it. No test, and no source-level analysis | `docs/bpf-collector.md` "Network capability" |
| Privacy audit (no address or port retained) | **done** (static review) | `privacy-audit.txt` |
| Verifier output and map memory | **done** | `verifier-counts,net.txt`, `verifier-counts,bigrams,net.txt` |

### Current blockers
1. Re-run `make test-privileged` on the final code once the host has enough
   free memory, with the owner's authorization
   ([checklist](SETUP_AND_TESTING.md#61-preflight-checklist-before-expensive-privileged-runs)).
2. Re-run `tests/test_net_bpf.py` with `--junitxml` on the final code.
3. Run the S1 counts-only equivalence probe; the expected result is 34/34
   identical.
4. **Decisions needed** from the owner on the plan §11 interpretations:
   - reading the socket class through the fd table;
   - the added `special` destination class; port classes not implemented;
   - I-N2 scope; the I-N4 purge term; the I-N6 window;
   - the `drained` field rule;
   - the BCC header shim.
5. An fd-reuse race assessment, if the reviewers require one before
   acceptance.

## 4. Known technical risks

- **Purge-race follow-ups** (documented, open):
  1. a barrier failure leaves the exclusion set and can end the supervisor
     thread;
  2. the name `rcu_barrier()` is misleading: it provides `synchronize_rcu()`
     semantics;
  3. `libc.syscall` is called without explicit `argtypes`;
  4. thread-ID reuse during a purge is not formally excluded;
  5. exclusion is PID-based, so a reused PID stays excluded until
     `unexclude()`.
- **H-DRAIN:** the drain's barrier argument is from kernel source; no late
  writer was ever observed, so it is not demonstrated whether the barrier
  was needed.
- **Host memory:** heavy privileged runs can be stopped by the tooling
  (M1's ABBA check, the S3.2 regression).
- **Workload throughput impact** of the agent is not attributable (M1
  limitation).
- **D8:** the minimum-record test is always skipped in WSL.
- **S3.2 fd-reuse misclassification window:** see above.
- **Toolchain:** the network capability depends on a header shim for BCC
  0.35 + kernel 6.18.

## 5. Deferred scope (not to be implemented without approval)

- **S3.3:** network bytes, send/receive, sendto partial sends,
  `inet_sock_set_state` (SYN_SENT).
- **S3c:** interface counters from `/proc/<pid>/net/dev` (an optional
  separate decision).
- Port classes for destinations.
- The privilege-indicator stage (D-6).
- M2–M7: features, datasets and simulations, Isolation Forest, SHAP/LIME,
  TUI/HTML, final evaluation.

## 6. Recommended next steps

1. With authorization, after the memory checklist: complete the three
   verification runs listed under blockers, then write the results into
   `results/acceptance/m1b/s3.2/README.md` and the changelog.
2. The owner decides on the plan §11 items.
3. Only then: review → the owner merges `wip/s3.2-network` into `master`
   through a pull request (authorization required).
4. Then plan S3.3 (needs explicit approval).

## Documentation conflicts

These existing documents disagree with the repository state. They were
**not** changed by this package:
- [`README.md`](../../README.md): below a short current-status note at its
  top, the body still says "Current milestone: M1 complete" and "Schema v2
  (M1b stage S0, uncommitted)". S0–S2.6 are committed. Its M0-era sections
  (prerequisites, limitations, project structure) describe the M0 layout
  only.
- `CLAUDE.md` on `master` still lists S2.6 as "uncommitted, under review".
  The newer `CLAUDE.md` on `wip/s3.2-network` has the S3.1/S3.2 row but the
  same stale S2.6 row.
- **Old commit hashes:** `CLAUDE.md`, the changelog, `docs/`, and
  `results/acceptance/*` cite pre-rewrite hashes. Recorded evidence is
  deliberately not edited; use [`docs/commit-hash-map.md`](../commit-hash-map.md).
- [`docs/architecture.md`](../architecture.md) describes only M0: a single
  `collector.c` with no header files. The C collector has since been split
  into `procfs.c/h` and `jsonl.c/h`, and the BPF and agent layers exist.
- [`ENGINEERING_CHANGELOG.md`](../../ENGINEERING_CHANGELOG.md): the
  "Milestone acceptance status" table at the top says S2.1–S2.4 are
  uncommitted and "S2.5+ … not started". The later entries in the same file
  record commits through S2.6 and the S3.2 work.
- The S3 plan doc labels network "S3", while the older M1b plan v3 (kept
  only in session transcripts) called it S5. See plan §0.
