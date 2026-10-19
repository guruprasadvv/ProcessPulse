# Team collaboration and AI-assisted development protocol

[← Onboarding index](README.md) · see also: [TEAM_TASK_BREAKDOWN.md](TEAM_TASK_BREAKDOWN.md)

This is the **permanent working protocol** for everyone on ProcessPulse-C,
and for every AI coding assistant they use (Claude Code, Cursor, or any
other). The project was built largely with an AI assistant under a strict,
approval-gated workflow. This protocol keeps it that way as more people and
more assistants join.

You are joining an **ongoing** project. Before you change anything, you
need to understand what exists, what was decided, what is proven, and what
is still open.

```
 ┌──────────┐   ┌──────┐   ┌───────────┐   ┌────────┐   ┌────────┐   ┌──────┐
 │ A        │   │ B    │   │ C         │   │ D      │   │ E      │   │ F    │
 │ Discover │──▶│ Plan │──▶│ Implement │──▶│ Verify │──▶│ Report │──▶│ STOP │
 └──────────┘   └──┬───┘   └───────────┘   └────────┘   └────────┘   └──────┘
   read-only       │  owner approves the plan        nothing staged,
                   └─ before any file is edited      nothing committed
```

**Contents**
1. [Safety rules (non-negotiable)](#1-safety-rules-non-negotiable)
2. [Engineering principles](#2-engineering-principles)
3. [Mandatory onboarding before any task](#3-mandatory-onboarding-before-any-task)
4. [The task assignment template](#4-the-task-assignment-template)
5. [The required workflow, phase by phase](#5-the-required-workflow-phase-by-phase)
6. [Testing and evidence policy](#6-testing-and-evidence-policy)
7. [Using an AI assistant responsibly](#7-using-an-ai-assistant-responsibly)
8. [Definition of done](#8-definition-of-done)
9. [Copy-paste prompts](#9-copy-paste-prompts)

---

## 1. Safety rules (non-negotiable)

Give these to your assistant at the start of every session; the template
in §4 already includes them. They come from `CLAUDE.md` §12 and from
decisions the owner made during M1b. Breaking one of them needs the
owner's explicit authorization **for that specific action**. Approval for
one action never carries over to the next.

**Git and the shared working tree**
1. Assume every uncommitted change belongs to a teammate or is valuable
   work. Identify which changes you made and which already existed.
2. **No destructive git:**
   - never `git clean` or `git reset --hard`;
   - never use `git checkout -- <file>` / `git restore` on work that isn't
     yours;
   - never rewrite history (rebase, amend of pushed or accepted commits,
     force-push).
3. **Never `git add .` or `git add -A`.** Stage only explicitly authorized
   paths, and only when a commit has been authorized.
4. **No commit, merge, rebase, stash or push** without explicit
   authorization in the task's "Commit authorization" field. The default
   is **none**.
   - **The usual grant:** commit to your own task branch, push that branch,
     and open a **draft** pull request (§7.3).
   - **Never push to `master` or `wip/s3.2-network` directly.** Never
     force-push a shared branch, never push tags, and never delete remote
     branches.
   - **Only the owner merges into `master`,** after review.
   - **No AI co-author or attribution lines** in commits or pull requests.
     Claude Code, for example, adds `Co-Authored-By: Claude …` by default.
     Remove it, and check before pushing:
     `git log origin/master..HEAD --format=%B | grep -i co-authored-by`
     must print nothing.
5. Don't overwrite, revert, reformat, rename, delete or regenerate files
   outside your task. If the working tree differs from what you expected,
   **stop and report it**. Never try to "make the repository clean".

**Evidence**
6. **Preserve evidence:**
   - the 15 intentional untracked M1 logs under `results/acceptance/m1/`
     (they exist on the owner's machine only);
   - everything in `results/raw/`;
   - every existing `results/acceptance/*` directory.

   Several acceptance scripts write straight into those directories (see
   [SETUP_AND_TESTING.md §7](SETUP_AND_TESTING.md#7-focused-acceptance-tools-toolsacceptance)).
   Check a script's output paths before running it. New evidence goes to a
   separate, approved location.

**Honest status**
7. **Never claim a test passed unless it actually ran** and its output was
   read. "Should pass" is not a result, and skipped is not passed. A
   partial suite is not full acceptance.
8. **Never silently weaken an assertion,** invariant, precondition or
   acceptance criterion to make a test pass. If a test is wrong, say so,
   explain why, and change it openly, with approval.
9. **The S3.1/S3.2 work on `wip/s3.2-network` is not accepted.** Don't
   merge it into `master`, and don't describe it, or build on it, as if it
   were accepted (see
   [CURRENT_STATUS_AND_ROADMAP.md](CURRENT_STATUS_AND_ROADMAP.md)). Never call
   something production-ready because it compiles or passes unit tests.

**Resources and privileges**
10. **Don't start privileged or resource-intensive runs without
    authorization.** That includes `make test-privileged`, root pytest
    runs, `overhead.py` (never `--abba`) and the acceptance harnesses.
    - Always pass the
      [memory checklist](SETUP_AND_TESTING.md#61-preflight-checklist-before-expensive-privileged-runs)
      first.
    - Never run two heavy suites at once.
    - If the tooling stops a job for memory, report it; don't restart it
      on your own.
    - Never rerun an earlier expensive benchmark without explicit approval.

**Scope and contracts**
11. **Don't modify accepted commits, schemas or contracts silently.** A
    schema change needs the owner's approval and a changelog entry.
12. **Network telemetry is tracepoint-only.** No kprobes, kretprobes,
    fentry or raw tracepoints (decision N2).
13. **Never persist or emit raw IP addresses or ports,** or any other
    sensitive telemetry field without design approval. That covers maps,
    JSONL, manifests, logs and test evidence. Only coarse classes are kept.
14. **Don't start S3.3** (or S3c, or anything beyond the approved stage),
    and don't add adjacent features, without explicit approval.

## 2. Engineering principles

Preserve these in every change:
- **Correctness:**
  - correctness before feature count;
  - explicit contracts before implementation changes;
  - backward compatibility unless a deliberate change is approved.
- **Evidence:**
  - evidence before acceptance claims;
  - keep implemented, tested, accepted and planned clearly apart. Use the
    `CLAUDE.md` status vocabulary: `[IMPLEMENTED]` only if the code exists
    *and* its tests pass; `[VERIFIED]` only with inspected output and a date;
    `[PLANNED]` is never "working".
- **Operation:**
  - bounded resource use and predictable failure behavior;
  - reproducible experiments and traceable decisions (changelog,
    evidence READMEs);
  - privacy-conscious telemetry (rule 13).

**Before touching telemetry code**, understand the concepts it relies on.
Each is explained in [TELEMETRY_AND_INVARIANTS.md](TELEMETRY_AND_INVARIANTS.md)
and [GLOSSARY.md](GLOSSARY.md):
- process identity (ProcessKey);
- monotonic timestamps;
- JSONL schema versions and the byte rule;
- loss accounting (R-LOSS / R-NLOSS);
- BPF map lifecycle and two-phase reclaim;
- exclusion and purge synchronization;
- the final drain;
- the applicable invariants;
- the difference between *unavailable* (`null` + `*_err`) and a genuine
  zero.

**Before touching ML or explainability** (planned, `CLAUDE.md` §7–§8):
- the Isolation Forest is trained on benign data only;
- `score_samples` values are anomaly scores, **not probabilities**;
- the threshold τ is calibrated separately, on benign validation runs;
- SHAP and LIME must explain the **same** scoring function on the **same**
  feature representation.

## 3. Mandatory onboarding before any task

1. **Read this package:** [README.md](README.md), then
   [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md), [ARCHITECTURE.md](ARCHITECTURE.md),
   [DEVELOPMENT_HISTORY.md](DEVELOPMENT_HISTORY.md),
   [SETUP_AND_TESTING.md](SETUP_AND_TESTING.md),
   [TELEMETRY_AND_INVARIANTS.md](TELEMETRY_AND_INVARIANTS.md),
   [CURRENT_STATUS_AND_ROADMAP.md](CURRENT_STATUS_AND_ROADMAP.md), this file,
   [TEAM_TASK_BREAKDOWN.md](TEAM_TASK_BREAKDOWN.md) and
   [GLOSSARY.md](GLOSSARY.md). Then read `CLAUDE.md`, the master
   instructions.
2. **Read the real code:** the source, schemas, tests, `Makefile`, git
   history and acceptance evidence relevant to your task. Documentation,
   including this package, is a starting point, not proof. If a document
   conflicts with code, evidence or git history, **report the conflict**
   instead of silently picking one side.
3. **Inspect the repository state:**
   ```sh
   git fetch origin
   git status -sb               # branch, and ahead/behind GitHub
   git log -1 --oneline
   git status --short
   git diff --stat
   git diff --cached --stat     # should be empty
   ```
4. **Compare with the expected baseline** (last updated 2026-10-19):
   - `origin/master` contains everything through S2.6 and the onboarding
     docs;
   - `origin/wip/s3.2-network` holds S3.1/S3.2, not accepted;
   - your task branch was created from the branch named in your task;
   - nothing is staged.

   Commit hashes cited in older documents predate the 2026-10-19 history
   rewrite; translate them with
   [`docs/commit-hash-map.md`](../commit-hash-map.md). If the state differs
   from what your task assumes, stop and report it before doing anything
   else.
5. **Classify what you find,** separately:
   - committed;
   - uncommitted;
   - accepted with evidence;
   - pending verification;
   - known limitations;
   - planned.
6. **Confirm ownership:** which files you may modify, and whether a teammate
   is working on them (§7.2).

You are ready to plan only when you can explain the component you will
change: its inputs and outputs, its invariants, and how your change will be
verified.

## 4. The task assignment template

Every task, for a person or an assistant, starts with these five fields
filled in by the task owner. An assistant that receives the template with a
field still blank must **ask for it** and not guess.

```
ProcessPulse-C task. Follow docs/team-onboarding/CONTRIBUTING_WITH_AI.md (read it first)
and CLAUDE.md. Its §1 safety rules apply in full.

Assigned task:            <one bounded task, with explicit non-goals>
Permitted files:          <exact paths you may modify; everything else is read-only>
Authorized test scope:    <e.g. "documentation validation only" | "unprivileged: make test,
                           make test-py" | "privileged: tests/test_net_bpf.py once, as root,
                           after the memory checklist">
Completion boundary:      <DOCUMENTATION ONLY | PLAN ONLY | IMPLEMENTATION ONLY |
                           IMPLEMENTATION AND TESTS | OTHER: ...>
Working branch:           <your branch, e.g. <name>/schema-review, created from master
                           (or from wip/s3.2-network for S3.2 work)>
Commit authorization:     NONE   (or, if the owner writes it here: "commit and push to
                           my working branch only; open a draft PR; no merge")

No AI co-author or attribution lines in commits or PRs.

Begin with a read-only inspection (§3). Do not modify any file yet. Your first response
must contain the seven items of §5.1 of the protocol. Then wait for explicit
authorization before editing.
```

## 5. The required workflow, phase by phase

### 5.1 Phase A: Discover (read-only)

Do §3, then send the **first response**. Every assistant's first response
on a new task must contain:
1. A concise summary of the project and its **current verified** status.
2. The architecture and data flow of the components relevant to the task.
3. The files inspected, and the evidence behind each claim (file, command
   output, commit, evidence path). Each claim is labelled *verified*,
   *inferred* or *unverified*.
4. The current git state, and the pre-existing changes that must be
   preserved.
5. The proposed plan (§5.2) and the file-ownership boundary.
6. The proposed acceptance criteria and tests (§6).
7. Risks, unknowns, and the decisions that need approval.

No file is modified in this phase. It ends when the owner explicitly
authorizes implementation.

### 5.2 Phase B: Plan

The plan states:
1. the problem and the intended outcome;
2. the existing behavior and the relevant source files;
3. the requirements and invariants that must stay true;
4. the files to modify;
5. the files and areas explicitly out of scope;
6. the tests and acceptance criteria;
7. the resources, privileges, cleanup and failure risks involved;
8. the documentation updates required;
9. dependencies on teammates or on unfinished work.

Keep the scope narrow. Don't add adjacent features, redesign the
architecture or change schemas because an assistant suggests it. If a
requirement is ambiguous or contradicts an existing contract, **ask** before
making an irreversible design decision.

### 5.3 Phase C: Implement (only what was authorized)

- Follow the existing architecture, naming and conventions. Prefer small,
  reviewable changes over rewrites.
- **Test first** (`CLAUDE.md` §12):
  1. write a test that fails and shows the problem;
  2. make the smallest coherent change;
  3. run the focused tests.
- **Test the failure paths too:**
  - error paths;
  - edge cases;
  - partial failure;
  - resource cleanup;
  - concurrency and races, where relevant.
- **Keep schema compatibility,** and document any intentional change. No
  new dependencies or unsupported kernel assumptions without approval.
- **Don't hide failures:** no suppressed errors, no skipped relevant tests,
  no redefined acceptance criteria.
- **BPF work:**
  - passing the verifier is not behavioral correctness;
  - never claim a race is impossible without a defensible technical
    argument and appropriate evidence.
- **Drain and purge logic:** reason explicitly about in-flight events,
  synchronization, loss counters and resource lifecycle.
- **For every significant change,** be able to say what changed, why it is
  correct, which assumptions it relies on, and what is still unverified.

### 5.4 Phase D: Verify

- Run only the authorized tests (§6), smallest and safest first.
- Inspect the diff:
  - `git diff`, `git diff --stat`, `git status --short`;
  - `git diff --check` (whitespace);
  - review every generated file.
- Confirm the diff contains only the intended changes. The evidence, the
  M1 logs and `results/raw/` must be untouched, and leftover processes,
  containers and BPF handles cleaned up.

### 5.5 Phase E: Report

The report includes:
- a summary of the change and its rationale;
- the changed files, each with its purpose;
- for every test: the exact command, exit code, environment and result
  (pass / fail / skip counts), and the log path;
- the tests **not run**, and why;
- whether each result was obtained by you or recorded by someone else;
- unresolved risks and assumptions;
- the final `git status --short` and `git diff --stat`, and an explicit
  statement of whether anything was staged or committed.

### 5.6 Phase F: Stop

Stop at the authorized boundary. Don't continue to the next stage or
milestone, commit, or pick up an unrelated improvement without new
approval.

## 6. Testing and evidence policy

Read [SETUP_AND_TESTING.md](SETUP_AND_TESTING.md) before running anything.
Classify every planned test, and get authorization for the classes you
need:

| Class | Examples in this repository | Needs |
|---|---|---|
| Static inspection / syntax validation | `git diff --check`, link checks, `make check` | the task's normal scope |
| Unit / unprivileged | `make test`, `make test-py PYTHON=...` (pytest `-m "not privileged"`), `make test-c` | the task's normal scope |
| Integration (unprivileged) | pytest marker `integration` (runs the compiled collector), part of `make test` | the task's normal scope |
| Root-only / privileged | `make test-privileged`, `tests/test_net_bpf.py`, markers `privileged`, `bpf`, `docker` | explicit authorization, root, the memory checklist |
| Resource-intensive acceptance | `tools/acceptance/*` harnesses, `overhead.py`, long agent recordings | explicit authorization, the memory checklist, an approved output location |

Rules:
- Check memory, kernel prerequisites (`kheaders`), container state and
  output paths **before** expensive tests.
- **Record every test run:** the exact command, exit code, environment
  (Python version, root or not), result, and limitations.
- **When a suite stops early** (memory, privileges, environment), report
  separately:
  - where it stopped;
  - the checks that completed;
  - the failures;
  - the checks that were never run.
- Save durable logs under `results/` in an approved location, not only in
  `/tmp`: WSL restarts can clear `/tmp`.
- Never overwrite accepted evidence to make a new run fit an existing
  report.

## 7. Using an AI assistant responsibly

### 7.1 The assistant is a collaborator, not an authority

Require the assistant to:
- **read the actual source** before recommending edits, and trace the call
  paths and data contracts involved;
- **state its assumptions and uncertainties,** and label claims *verified*,
  *inferred* or *unverified*;
- **explain a change before making it,** then produce a focused diff with
  targeted tests;
- **report what it actually ran** and the actual output;
- **never invent** files, APIs, kernel behavior, test results or repository
  state.

Don't accept "I verified this" on the assistant's word: open the code,
output, test or evidence yourself.

Practical tips:
- **Give it the repository, not a summary.** Claude Code loads `CLAUDE.md`
  automatically. With other assistants, tell them to read `CLAUDE.md` and
  this file first.
- **Bound the task:** one subsystem, one behavior, explicit non-goals.
  "Implement S3.3" is too big; "add a failing test for X in file Y" is the
  right size.
- **Review the diff yourself** before reporting to the owner.

### 7.2 File ownership and concurrent edits

These are **shared hot spots**:
- the BPF sources (`bpf/*.c`, `bpf/common.h`);
- `processpulse/agent.py`, `processpulse/bpf_collector.py`,
  `processpulse/snapshots.py` and `processpulse/validate.py`;
- the v2 schema;
- `CLAUDE.md` and `ENGINEERING_CHANGELOG.md`.

Rules:
- **One owner per file per task.** Agree it with the team, and record it in
  the task's "Permitted files" field.
- **Don't let an assistant edit files owned by someone else** without
  coordination.
- **Never run two assistants or sessions in the same working tree** at the
  same time. Each person works in their own clone, on their own branch
  (§7.3), and changes meet only through reviewed pull requests.
- **Never run two privileged test runs at once:** they share kernel state,
  `make` artifacts and memory.

### 7.3 GitHub workflow: branches and pull requests

The repository is https://github.com/guruprasadvv/ProcessPulse. Setup is in
[SETUP_AND_TESTING.md §2](SETUP_AND_TESTING.md#2-get-the-code-clone-from-github).

```
 master ──●───────────────────────────────●──   (only the owner merges, after review)
           \                             ↑
            ●──●──●  <you>/<task>  ── draft PR ── review ── ready ──┘
```

1. **Start from an up-to-date base:**
   ```sh
   git fetch origin
   git switch -c <you>/<short-task> origin/master   # or origin/wip/s3.2-network for S3.2 work
   ```
2. **Work in small commits** on that branch, only if your task grants
   commit authorization. Stage explicit paths
   (`git add path/one path/two`), and write clear messages with no AI
   co-author lines.
3. **Before pushing,** check that nothing unintended is included. If you
   started from the WIP branch, use `origin/wip/s3.2-network` instead of
   `origin/master` here.
   ```sh
   git status --short
   git log origin/master..HEAD --stat
   git log origin/master..HEAD --format=%B | grep -i co-authored-by   # must print nothing
   ```
4. **Push your branch only:** `git push -u origin <you>/<short-task>`.
5. **Open a draft pull request** into the branch you started from. Use
   **Create draft pull request**, not "Create pull request". The
   description must say:
   - what changed and why;
   - the exact test commands and results;
   - what was **not** run, and why;
   - risks and open questions.

   Mark it **Ready for review** only when the definition of done (§8) is met.
6. **Keep your branch current:** `git fetch origin`, then
   `git merge origin/master`. Don't rebase or force-push a branch that
   others may have pulled.
7. **The owner reviews and merges.** After the merge, delete your branch
   (on GitHub, and locally with `git branch -d <you>/<short-task>`).

GitHub shows a yellow **"had recent pushes … Compare & pull request"**
banner after any push. It is only a suggestion. In particular, **don't
merge `wip/s3.2-network`** until S3.2 is accepted (see
[CURRENT_STATUS_AND_ROADMAP.md](CURRENT_STATUS_AND_ROADMAP.md)).

## 8. Definition of done

A task is **done** only when all of these hold. Otherwise report it as
**partially complete** or **blocked**, and name the unmet items.

- [ ] The requested behavior is implemented, within scope.
- [ ] Relevant invariants and compatibility requirements are preserved.
- [ ] Appropriate tests exist, the authorized ones were run, and their
  results are reported exactly.
- [ ] Failure cases and cleanup were considered.
- [ ] The documentation matches the implementation. For a stage change,
  that usually means:
  - a `results/acceptance/<stage>/README.md` with the commands, results,
    limitations, and what was **not** run;
  - an `ENGINEERING_CHANGELOG.md` entry (Changes / Tests / Validation),
    marked *uncommitted*;
  - a `CLAUDE.md` §1 status row with the correct status vocabulary.
- [ ] The diff contains only intended changes, and `git diff --check` is
  clean.
- [ ] No unrelated work or evidence was damaged: the 15 M1 logs,
  `results/raw/` and `results/acceptance/*` are intact.
- [ ] Remaining limitations and follow-up work are written down.
- [ ] The final git state is reported. **Nothing is staged, committed or
  pushed** unless authorized. If it was authorized, the work is on your own
  branch with a draft pull request, contains no AI co-author lines, and
  nothing was pushed to `master` or `wip/s3.2-network`. The owner decides
  what is merged.

## 9. Copy-paste prompts

Use these **after** the §4 template has set the task, or on their own for
read-only work. Replace `<...>`. Each prompt restates the key rules, because
a fresh session doesn't know them.

### 9.1 Learning the project
```
You are helping me learn the ProcessPulse-C repository (VIT OS course project).
Read, in this order: CLAUDE.md, docs/team-onboarding/README.md, ARCHITECTURE.md,
then skim processpulse/agent.py and bpf/common.h. Do not edit any file and do not run
privileged commands. Explain: (1) what the system does end to end, (2) the role of each
directory, (3) what is committed vs uncommitted (run git status / git log yourself),
(4) three things you are unsure about. Label every claim as verified (you read it in a
file or command output) or inferred.
```

### 9.2 Exploring one subsystem
```
Explain the <final drain | exclusion purge | bigram R-LOSS | network stash> subsystem of
ProcessPulse-C. Read the actual source first (<files>), then the matching docs
(docs/bpf-collector.md, docs/telemetry-v2.md). Trace one concrete example step by step.
List the tests that cover it (grep tests/) and what each asserts. Do not edit anything.
Point out any place where the docs and code disagree.
```

### 9.3 Implementing one bounded task
```
Task: <one sentence>. Permitted files: only <files>. Non-goals: <list>. Test scope:
<authorized tests>. Commit authorization: NONE. Read CLAUDE.md §12 and
docs/team-onboarding/CONTRIBUTING_WITH_AI.md §1 and follow them (no destructive git,
no commits, no staging, no weakened assertions, tracepoint-only, no raw IPs/ports,
no S3.3). First: inspect the code read-only and reply with the §5.1 first response
(plan, files, functions, tests, contracts affected). Wait for my approval. Then: write
a failing test, show it failing, implement the smallest change, run the focused tests
and `make test`, and report exact commands, exit codes and counts. Do not run
privileged tests unless I say so.
```

### 9.4 Writing regression tests
```
Write regression tests for <behavior> in ProcessPulse-C. Read the implementation and the
existing tests in <tests/...> first and follow their style (fakes in tests/snapshot_fakes.py
for unprivileged tests; real helpers for privileged ones). Each test must check the
contract (an equation, a field rule, an error path), not an implementation detail. Show
each new test failing against a deliberately broken copy or explain why it cannot fail.
Do not modify production code. Report the commands you ran and their results.
```

### 9.5 Reviewing an uncommitted diff
```
Review the uncommitted diff of ProcessPulse-C (git diff; git status --short for new files).
Read CLAUDE.md, the relevant contracts (docs/telemetry-v2.md, docs/bpf-collector.md,
docs/m1b-s3-network-plan.md) and every changed file. Report, most severe first:
contract violations, loss-accounting errors (anything that could lose or double-count
an event silently), missing failure paths, schema regressions, privacy problems (raw
address/port), tests that assert implementation details or were weakened, and changes
outside the stated scope. For each finding give file:line and a concrete failure
scenario. Do not edit files.
```

### 9.6 Debugging a failing test
```
The test <tests/...::name> fails with: <paste output>. Investigate in ProcessPulse-C
without changing the test's assertion. Read the test and the code it exercises, form
hypotheses, and confirm one with the smallest experiment (a focused pytest run, a print
in a scratch copy, or reading kernel/tracepoint formats). Tell me whether the bug is in
the code, the test, or the environment (e.g. kheaders not loaded, not root, low memory).
Propose a fix and wait for approval before editing. Never run privileged suites without
asking.
```

### 9.7 Preparing an evidence-based handover report
```
Prepare a handover report for the work in this session on ProcessPulse-C. Run and include:
git rev-parse HEAD, git status --short, git diff --stat, git diff --cached --stat. List
files changed and the purpose of each. For every test claim give the exact command, exit
code, pass/fail/skip counts and the saved log path under results/; mark anything not run
as NOT RUN with the reason. Separate verified facts, assumptions and open questions.
Confirm the 15 M1 logs and results/raw/ were not modified and that nothing was staged or
committed. Do not commit.
```
