# ProcessPulse-C: team onboarding

Start here if you are new to the project. This package explains why the
project exists, how it works, what has been built, what is still open, how
to set up and test safely, and how to contribute with an AI coding
assistant.

> **Status of this package.** Written on 2026-10-19 from the repository as
> it stood then: branch `master`, HEAD `699c2c8`, with uncommitted S3.1/S3.2
> work in the working tree. Facts are cited to files and commits. Anything
> owner-reported or unverified is labelled. When this package disagrees with
> the code, the code and `CLAUDE.md` win.

## What is ProcessPulse-C?

ProcessPulse-C is an **operating-systems course project** (VIT, team of
three). It aims at *explainable behavioral anomaly detection for
containerized applications*. In plain words, it will:

1. **watch what processes do** on a Linux machine, including processes
   inside Docker containers: CPU and memory use, which system calls they
   make, which network connections they open;
2. **learn what "normal" looks like** from that telemetry (planned:
   Isolation Forest, a machine-learning anomaly detector);
3. **flag unusual behavior** (planned: for example, cryptomining,
   privilege-escalation attempts, data exfiltration);
4. **explain why** something was flagged (planned: SHAP and LIME
   explanations), so a human analyst can judge the alert.

**Why process behavior?** Signature-based tools look for known bad files or
patterns. A new attack has no signature yet, but it still has to *behave*:
start processes, open files, connect to the network. Recording that behavior
precisely, with no silent gaps, is the foundation everything else is built
on.

## Where the project is now

| Layer | State |
|---|---|
| Telemetry collection (C `/proc` collector, eBPF syscall counts, syscall bigrams, agent, JSONL protocol) | **Implemented and committed** (M1, M1b S0–S2.6) |
| Network telemetry, part 1 (connect/accept tracking, S3.1/S3.2) | **Implemented, uncommitted, not accepted.** Final verification is incomplete; see [CURRENT_STATUS_AND_ROADMAP.md](CURRENT_STATUS_AND_ROADMAP.md) |
| Feature engineering, ML detection, explanations, dashboard (M2–M7) | **Planned only.** No code exists |

## Architecture at a glance

```
   Docker containers ──┐
   host processes ─────┤  (one shared Linux kernel)
                       │
     ┌─────────────────┴──────────────────────┐
     │ C /proc collector (src/)               │ resource stream (schema v1)
     │ eBPF program via BCC (bpf/)            │ syscall counts, bigrams,
     │                                        │ connect/accept (schema v2)
     └─────────────────┬──────────────────────┘
                       ▼
     processpulse agent (Python, runs as root):
     supervises, frames, validates, records JSONL + manifest
                       ▼
     results/raw/<run>/  (recorded telemetry, not in git)
                       ▼
     ── planned ────────────────────────────────────────────
     features (M2) → Isolation Forest (M4) → SHAP + LIME (M5)
     → alerts / curses TUI / static HTML report (M6)
```

## Reading order

| # | Document | Read it to learn |
|---|---|---|
| 1 | [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) | the problem, goals, scope, and what is built vs planned |
| 2 | [ARCHITECTURE.md](ARCHITECTURE.md) | every component, grounded in the source code |
| 3 | [GLOSSARY.md](GLOSSARY.md) | eBPF, tracepoints, keyframes, invariants... (keep it open) |
| 4 | [SETUP_AND_TESTING.md](SETUP_AND_TESTING.md) | WSL2 setup, running tests safely, reading evidence |
| 5 | [TELEMETRY_AND_INVARIANTS.md](TELEMETRY_AND_INVARIANTS.md) | what the data means and how correctness is checked |
| 6 | [DEVELOPMENT_HISTORY.md](DEVELOPMENT_HISTORY.md) | how M0 → S3.2 was built, and why |
| 7 | [CURRENT_STATUS_AND_ROADMAP.md](CURRENT_STATUS_AND_ROADMAP.md) | what is accepted, what is blocked, what is next |
| 8 | [CONTRIBUTING_WITH_AI.md](CONTRIBUTING_WITH_AI.md) | **the mandatory team collaboration and AI-assisted development protocol**: safety rules, the task template, the discover → plan → implement → verify → report → stop workflow, definition of done, prompts |
| 9 | [TEAM_TASK_BREAKDOWN.md](TEAM_TASK_BREAKDOWN.md) | independent workstreams you can pick up |

## Authoritative sources (outside this package)

- [`CLAUDE.md`](../../CLAUDE.md): the master project instructions. It holds
  the status table, approved decisions D-1–D-15, contracts, milestones and
  working rules. When it conflicts with anything else, it wins.
- [`ENGINEERING_CHANGELOG.md`](../../ENGINEERING_CHANGELOG.md): verified
  history, with the commands that were run and their results.
- [`docs/telemetry-v2.md`](../telemetry-v2.md): the schema-v2 protocol,
  bigram records (§8) and network records (§9).
- [`docs/bpf-collector.md`](../bpf-collector.md): the eBPF program design,
  including the purge, drain and network sections.
- [`docs/m1b-s3-network-plan.md`](../m1b-s3-network-plan.md): the S3 network
  plan (N1–N10 approved), with the implementation decisions in §11
  (uncommitted).
- `results/acceptance/`: saved test evidence for each stage.

## How to use this package

- **Before your first task,** read and follow the
  [team collaboration protocol](CONTRIBUTING_WITH_AI.md). Every task starts
  from its [task assignment template](CONTRIBUTING_WITH_AI.md#4-the-task-assignment-template).
- **Don't treat it as a substitute for reading code.** Every document points
  to the source files behind it.
- **Labels used throughout:**
  - **verified**: checked against git or saved evidence;
  - **owner-reported**: stated by the project owner, not independently
    re-checked;
  - **proposal**: not approved;
  - **unresolved**: needs a decision.
- **Historical vs current:** test numbers in these documents come from saved
  evidence on a stated date. They are not a promise that tests pass on your
  machine today; run them.
- **Known stale docs:** some older documents predate later milestones and
  disagree with this package:
  - the top-level [`README.md`](../../README.md) still says "M1 complete,
    S0 uncommitted";
  - [`docs/architecture.md`](../architecture.md) describes only M0;
  - the status table at the top of the changelog says S2.5+ has not
    started.

  These were not changed here. See
  [CURRENT_STATUS_AND_ROADMAP.md](CURRENT_STATUS_AND_ROADMAP.md#documentation-conflicts).
