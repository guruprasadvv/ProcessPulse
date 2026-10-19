# Team task breakdown

[← Onboarding index](README.md) · rules: [CONTRIBUTING_WITH_AI.md](CONTRIBUTING_WITH_AI.md)

These are **suggested** workstreams. Nobody is assigned to them by this
document. They are cut so that people can work in parallel without editing
the same hot-spot files at the same time. Every file path below exists in
the repository (checked 2026-10-19). Every workstream needs the owner's
go-ahead before its work starts. Nothing is committed without
authorization.

> **Hot-spot files (one editor at a time, coordinated):** `bpf/*.c`,
> `bpf/common.h`, `processpulse/bpf_collector.py`,
> `processpulse/snapshots.py`, `processpulse/validate.py`,
> `processpulse/schemas/telemetry.v2.json`, `processpulse/agent.py`,
> `CLAUDE.md`, `ENGINEERING_CHANGELOG.md`.

---

## A. Verification and acceptance evidence (S3.1/S3.2)

- **Prerequisites:** WSL2 setup; root access (or the owner runs the root
  steps); [SETUP_AND_TESTING.md](SETUP_AND_TESTING.md) read; the memory
  checklist passes.
- **Scope:** complete the missing verification on the final S3.1/S3.2 code:
  1. full `make test-privileged`;
  2. `tests/test_net_bpf.py` with `--junitxml`;
  3. the S1 counts-only equivalence probe;
  4. cleanup state before and after.
- **Files likely involved:** `results/acceptance/m1b/s3.2/` (new logs,
  README update), `ENGINEERING_CHANGELOG.md` and `CLAUDE.md` §1 (status
  text only, coordinated); `tools/acceptance/s1_equivalence.py` (run only).
- **Deliverables:** saved logs; an updated `s3.2/README.md` with exact
  counts; a clear PASS / FAIL / NOT RUN per check.
- **Required tests:** the runs above. Nothing new.
- **Dependencies:** enough host memory; the owner's authorization for root
  runs.
- **Must not:** change implementation code or tests to make them pass;
  overwrite earlier evidence; run `overhead.py --abba`; commit.
- **Done when:** every row of the S3.2 checklist in
  [CURRENT_STATUS_AND_ROADMAP.md](CURRENT_STATUS_AND_ROADMAP.md#3-implemented-but-not-accepted-s31s32-network-connectaccept)
  is filled with evidence, or explicitly marked blocked with the reason.

## B. BPF and network correctness review (read-only first)

- **Prerequisites:** C; eBPF basics ([GLOSSARY.md](GLOSSARY.md));
  [TELEMETRY_AND_INVARIANTS.md](TELEMETRY_AND_INVARIANTS.md).
- **Scope:**
  - review `bpf/net.bpf.c`, the `PPC_CAP_NET` part of `bpf/core.bpf.c`, and
    the net parts of `processpulse/bpf_collector.py` against
    `docs/m1b-s3-network-plan.md` (§5, §11);
  - write the **fd-reuse race assessment** for reading the socket class
    through the fd table (can the class be wrong, how likely, is it
    detectable, does it affect any invariant);
  - evaluate the §11 interpretations of I-N2, I-N4 and I-N6.
- **Files likely involved:** read the above. Write a new review document
  (for example under `results/acceptance/m1b/s3.2/` or `docs/`, as agreed).
- **Deliverables:** a review report with findings (file:line, failure
  scenario, severity); proposed tests for any real gap.
- **Required tests:** none to run for a review. Proposed new tests go
  through workstream A or the hot-spot owner.
- **Dependencies:** none for reading. Code changes need the hot-spot owner
  and the owner's approval.
- **Must not:** edit the BPF or collector files directly while others work
  on them; add kprobes; read or store ports or addresses; start S3.3.
- **Done when:** the owner has a written assessment and a decision list.

## C. Schema and validator review

- **Prerequisites:** JSON Schema basics; [`docs/telemetry-v2.md`](../telemetry-v2.md)
  §1–§9.
- **Scope:**
  - check `processpulse/schemas/telemetry.v2.json` against
    `processpulse/validate.py`, the `Reconstructor` in
    `processpulse/snapshots.py`, and `processpulse/net.py`;
  - confirm counts-only and bigram streams keep their exact shapes with net
    absent;
  - confirm unavailable is never zero;
  - confirm the `drained` presence rule.
- **Files likely involved:** read the above, plus `tests/test_schemas_v2.py`,
  `tests/test_bigram_records.py`, `tests/test_net_unit.py`,
  `tools/acceptance/validate_run.py`.
- **Deliverables:** a findings report; new **unprivileged** regression tests
  in a new test file if gaps are found (coordinate before touching shared
  test fakes in `tests/snapshot_fakes.py`).
- **Required tests:** `make test` and the Python 3.12 `make test-py`, with
  logs.
- **Dependencies:** none.
- **Must not:** change the schema or validator semantics without approval;
  weaken a rule to accept data.
- **Done when:** the findings are reviewed, and any new tests pass on both
  interpreters.

## D. Documentation and developer setup

- **Prerequisites:** this package; a working WSL2 setup.
- **Scope:**
  - fix the stale documents listed in
    [CURRENT_STATUS_AND_ROADMAP.md](CURRENT_STATUS_AND_ROADMAP.md#documentation-conflicts):
    the top-level `README.md`, `docs/architecture.md`, and the changelog
    status table;
  - try the setup steps on a fresh machine and record what differs.
- **Files likely involved:** `README.md`, `docs/architecture.md`,
  `docs/team-onboarding/*` (`ENGINEERING_CHANGELOG.md` is a hot spot).
- **Deliverables:** updated docs; a "fresh setup" report with versions.
- **Required tests:** link and path checks; commands copied from the docs
  actually run (non-privileged) and give the documented result.
- **Dependencies:** the owner's approval to rewrite the top-level README.
- **Must not:** change code, tests or schemas; claim results the evidence
  doesn't show.
- **Done when:** a new teammate can follow the docs from zero to
  `make test` passing.

## E. Future ML and explainability planning (planning only)

- **Prerequisites:** Python; [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md);
  `CLAUDE.md` §7 (detection contract) and §8 (SHAP/LIME contracts);
  [GLOSSARY.md](GLOSSARY.md) ML terms.
- **Scope:**
  - a written plan for M2 features (from counts, bigrams, network and
    resource records), M3 datasets and simulations, and M4/M5 experiment
    design;
  - which records feed which features; how windows, gaps and the
    "unavailable" values are handled;
  - how SHAP's background set and LIME are configured per the contract.
- **Files likely involved:** a new planning document (location agreed with
  the owner); `requirements/` only after approval (ML packages are pinned
  when M4/M5 start, per `requirements/README.md`).
- **Deliverables:** a plan document with the decisions that need approval.
- **Required tests:** none (no code).
- **Dependencies:** a stable telemetry schema. `CLAUDE.md` §12 forbids
  implementing ML while the telemetry is unvalidated.
- **Must not:** implement features or models now; import BCC in the ML
  layer; use raw PIDs or container IDs as features (`CLAUDE.md` §5); create
  the Python 3.12 environment with Python 3.14 (D-14).
- **Done when:** the owner has a reviewed plan for M2.

## Coordination checklist for any workstream

- [ ] The owner approved the scope.
- [ ] You know who owns each hot-spot file you might touch.
- [ ] Your assistant was given the safety rules
  ([CONTRIBUTING_WITH_AI.md §1](CONTRIBUTING_WITH_AI.md#1-safety-rules-non-negotiable)).
- [ ] The evidence is saved under `results/`.
- [ ] `git status --short` and `git diff --stat` are included in your
  handover. Nothing is staged.
