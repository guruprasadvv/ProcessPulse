# Development history

[← Onboarding index](README.md) · see also: [CURRENT_STATUS_AND_ROADMAP.md](CURRENT_STATUS_AND_ROADMAP.md)

Sources: `git log` (verified), [`ENGINEERING_CHANGELOG.md`](../../ENGINEERING_CHANGELOG.md)
and the READMEs under `results/acceptance/`.
- **Hashes:** the history was rewritten once on 2026-10-19 (only commit
  messages changed). The *Commit* column shows the current hashes; older
  documents and evidence cite the *Old hash* (full table:
  [`docs/commit-hash-map.md`](../commit-hash-map.md)).
- **Dates:** all commits carry the date 2026-10-19; there is no earlier git
  history. The changelog's dates are local time (IST).
- **Test numbers** below are **historical**: what the saved evidence recorded
  at that stage, not the current state.

## Timeline at a glance

| Stage | Commit | Old hash | Subject (from `git log`) |
|---|---|---|---|
| M0 | `a1be2b9` | `795c945` | chore: initial baseline commit of M0 snapshot collector and PPT requirements |
| (docs) | `b67abc2` | `67af42d` | docs: establish master CLAUDE.md architecture and ML contracts |
| M1 | `1256d0d` | `3df5819` | feat: complete M1 telemetry foundations and acceptance tests |
| M1b S0 | `610702a` | `d9b9e9b` | feat(m1b): implement S0 telemetry v2 framing, validation, and snapshot protocol |
| M1b S1 | `4346fab` | `391c988` | refactor(m1b): implement S1 unified bpf compilation and per-thread lifecycle tracking |
| M1b S2.1–S2.4 | `d1ff507` | `5f0d376` | feat(m1b): implement S2.1-S2.4 bounded syscall bigram storage and map accounting |
| purge fix | `615896d` | `1f763de` | fix(m1b): synchronize in-flight BPF readers before purge |
| M1b S2.5 | `ecbe7d2` | `d1d7eac` | feat(m1b): implement S2.5 final-drain protocol and double-read map accounting |
| M1b S2.6 | `5a45db3` | `699c2c8` | feat(m1b): implement S2.6 agent integration and schema v2 bigram emitter |
| (docs) | `cc546ab` | `9a628a3` | docs: add team onboarding package, collaboration protocol and S3 network plan |
| (docs) | `69b9005` | — | docs: add commit hash map for the rewritten history |
| M1b S3.1/S3.2 (**only on branch `wip/s3.2-network`**) | `5b6231b` | `3a2451e` | wip(m1b): S3.1/S3.2 network capability (connect/accept) - NOT ACCEPTED |

S2.1–S2.4, the purge fix and S2.5 were developed uncommitted and then
committed afterwards in three separate commits, each verified against a
tested file tree (`results/acceptance/m1b/s2.6/phase1/`).

---

## M0: snapshot collector (`a1be2b9`)
- **Purpose:** prove the data-collection layer: enumerate `/proc`, read CPU
  ticks, emit one JSON object per process.
- **Implementation:** a single-file C collector; tests in
  `tests/test_collector.py`.
- **Evidence:** an audit on 2026-10-19 found 0 warnings with strict flags,
  `-fanalyzer` and ASan+UBSan; the tests gave 20 passed, 1 skipped.
- **Known defects D1–D10:** for example, D1: a `comm` containing a newline
  dropped the process; D2: invalid UTF-8 was emitted raw.
- **Limitation:** D8 is still open: `test_minimum_record_count` is always
  skipped in WSL, which exposes fewer than 100 processes.
- **Enabled:** M1 fixed D1–D6 test-first.
- `docs/architecture.md` and `docs/os-concepts.md` date from this stage.

## eBPF feasibility gate (before M1, no commit)
- `tools/bpf_smoke.py` passed tests A–F.
- **Findings that shaped the identity design:**
  - the WSL distro is pid-namespace level 2;
  - `bpf_get_ns_current_pid_tgid()` fails with EINVAL in nested namespaces;
  - `thread_pid->numbers[2].nr` gives the distro PID.

## M1: telemetry foundations (`1256d0d`)
- **Purpose:** streaming telemetry with exact eBPF syscall counts and proven
  identity.
- **Main changes:**
  - C collector split into `procfs`/`jsonl`, with a `--v1` streaming mode;
  - schema v1 and the stdlib validator;
  - Python package: `resource.py`, `syscalls.py`, `identity.py`,
    `preflight.py`, `agent.py`;
  - BPF programs `calibrate.bpf.c`, `syscall_counter.bpf.c`.
- **Key decisions:**
  - in-kernel identity resolution with a namespace-inode check;
  - two-phase exit reclaim;
  - self-exclusion with purge;
  - CLOCK_MONOTONIC throughout;
  - `null` + error instead of 0.
- **Acceptance** (`results/acceptance/m1/README.md`):
  - 10-minute run, 27,803/27,803 lines valid;
  - exact counts 110/110 over 10 repetitions;
  - start_ticks equal for 1000/1000 processes;
  - overhead matrix 45/45 measured;
  - **DIT-1** (Docker integration test) passed 3 consecutive runs.
- **Limitations:**
  - the workload-throughput impact is not attributable: the order-balanced
    ABBA re-check was stopped for low host memory and is inconclusive;
  - **F1:** 15 of 613 `syscall_snapshot` lines exceeded 65,536 bytes; this
    was discovered later and fixed for v2 by S0.
- **Enabled:** everything in M1b.

## M1b S0: v2 framing and snapshot protocol (`610702a`)
- **Purpose:** fix F1 and define a robust consumer contract.
- **Changes:**
  - the byte rule (`jsonl.py`);
  - `telemetry.v2.json`;
  - `V2Emitter` + `Reconstructor` (`snapshots.py`);
  - `agent --schema 2` (schema 1 stays the default);
  - `validate_run.py` v2 mode.
- **Key decisions:**
  - cumulative counters;
  - changed-only emission;
  - keyframes every 60 snapshots or when "due";
  - explicit removals;
  - commit-after-write.

  A same-day **keyframe correction** made a failed scheduled keyframe keep
  "due" set.
- **Evidence:** a 10-minute v2 run (23,271/23,271 lines valid, 11
  keyframes); unprivileged 213 passed / 1 skipped; privileged 34 passed
  (`results/acceptance/m1b/s0/`).
- **Enabled:** S2.1's additive bigram fields.

## M1b S1: unified BPF program (`4346fab`)
- **Purpose:** one capability-flagged program instead of separate ones.
- **Changes:**
  - `bpf/common.h` (identity, slots, health), `core.bpf.c` (scheduler hooks);
  - `BpfCollector` with exactly 2 compilations per start;
  - per-thread slots (F4);
  - comm/cgroup refreshed at exec (F9);
  - `vocab.py` (vocabulary id `v1-3aba869d1752`).
- **Evidence:**
  - counts-only **equivalence probe**
    (`tools/acceptance/s1_equivalence.py`): 33/34 fields identical with the
    pre-S1 code; the one difference is the added `sched_process_exec` hook;
  - unprivileged 245/1; privileged 42 (`results/acceptance/m1b/s1/`).
- **Enabled:** S2.3 plugs bigrams into the same program. The equivalence
  baseline `equivalence-post-s1.json` is the regression reference for every
  later stage.

## M1b S2.1–S2.4: syscall bigrams (`d1ff507`)
- **S2.1, schema and consumer:**
  - additive v2 fields (`bpf_bigrams` records, `pairs_lost`, bigram health,
    `drained`);
  - the chunking rule (at most 1,024 pairs and 65,536 bytes per record);
  - Reconstructor support.

  Unprivileged 360 passed.
- **S2.2, checkers:** `processpulse/bigrams.py` decoder, the I-B1–I-B5
  checkers, and a scripted oracle; synthetic data only. Unprivileged 472
  passed.
- **S2.3, BPF capability:** `bigrams.bpf.c`, R-LOSS rows 1–3, pre-arm
  accounting (decision U2), markers, exec/exit/TID reuse. Privileged 58
  passed; counts-only equivalence 34/34.
- **S2.4, exact preconditions:**
  - the exact I-B3/I-B4 checks need zero *global* losses in the window;
  - `tools/acceptance/bigram_exact.sh`: 14 configurations passed 10/10;
  - privileged 75 passed (`results/acceptance/m1b/s2.3/`,
    `results/acceptance/m1b/s2.4/`).
- **Approved decisions:** A8 (R-LOSS and the invariants) and U1–U10. See
  [TELEMETRY_AND_INVARIANTS.md](TELEMETRY_AND_INVARIANTS.md).

## Purge synchronization fix (`615896d`): why it matters
- **The bug (an S2.3 audit finding):** `exclude()` set the exclusion flag
  and immediately read and deleted the process's map entries. A probe that
  had passed the exclusion check a moment earlier could still be running on
  another CPU. Its late write could:
  - be missing from the purge totals, breaking conservation (I-B2);
  - recreate a deleted entry;
  - land in a deleted slot that the preallocated hash map had already reused
    for **another process**, silently corrupting it.

  Separately, the exit hook wrote `exited` without checking the exclusion.
- **The fix:**
  - every writer checks the exclusion first, the exit hook included;
  - `exclude()` sets the flag, then calls `rcu_barrier()`
    (`membarrier(MEMBARRIER_CMD_GLOBAL)`, which runs `synchronize_rcu()`),
    then reads and deletes;
  - if the barrier is unavailable, `exclude()` raises rather than purge
    unsafely.
- **Evidence:** `results/acceptance/m1b/purge-race/`. The audit `AUDIT.md`
  verifies the argument against the matching WSL kernel source tag.
- **Honest limits:**
  - the race was never reproduced in a test; the guarantee rests on kernel
    RCU semantics argued from source;
  - follow-ups 1–5 are open. For example, a barrier failure ends the
    supervisor thread, and exclusion is by PID
    ([CURRENT_STATUS_AND_ROADMAP.md](CURRENT_STATUS_AND_ROADMAP.md)).

## M1b S2.5: final drain (`ecbe7d2`): why it matters
- **Problem:** map reads are not atomic. While processes run, a count can be
  read before its pair is recorded, so whole-epoch conservation (I-B2) cannot
  be checked on a live read.
- **Protocol (decision U3):**
  1. detach every tracepoint (keep the maps);
  2. `rcu_barrier()`;
  3. read every map twice; the drain is `drained` only if both reads are
     equal.

  Then exactly one **drained snapshot** is allowed, and it must match the
  drain read.
- **Audit correction:** a first version accepted any two equal reads out of
  five. Because U3 says "read twice", it was tightened to exactly two (the
  superseded runs are kept in `results/acceptance/m1b/s2.5/superseded/`).
- **Evidence:** 9/9 drains under busy loops were stable, with
  I-B1/I-B1′/I-B3′/I-B2 PASS; ground truth 3/3; privileged 87 passed
  (`results/acceptance/m1b/s2.5/`).
- **Limitation:** no late writer was ever observed, so it is not shown
  whether the barrier was necessary in those runs.

## M1b S2.6: agent integration and bigram emitter (`5a45db3`)
- **Changes:**
  - `V2Emitter(bigrams=...)` writes `bpf_bigrams` and re-emits a process
    when counts, `pairs_lost` **or** its pair table change;
  - agent `--capabilities counts,bigrams` (schema 2 only);
  - end of a run: stop the supervisor → `drain()` → one drained snapshot;
  - `validate_run.py` bigram checks and `--require-drained`.
- **Review refinement, strict startup policy:** if a requested capability
  fails to start, the run fails (manifest `status: failed`, exit 1), unless
  `--allow-degraded` is given.
- **Evidence:**
  - unprivileged 613/1; privileged 91;
  - a 30-second CLI run with every invariant PASS on 437 keys;
  - the widest possible bigram record is 62,739 bytes;
  - counts-only equivalence 34/34 (`results/acceptance/m1b/s2.6/`).

## M1b S3.1/S3.2: network capability (branch `wip/s3.2-network`, **not accepted**)
- **Where:** commit `5b6231b`, only on `wip/s3.2-network`; pushed for team
  verification and review, not merged into `master`.
- **Plan:** [`docs/m1b-s3-network-plan.md`](../m1b-s3-network-plan.md). In
  the earlier M1b plan v3, network was stage S5; the owner chose it as "S3"
  (decision N1; A17 allows any order).
- **Changes:**
  - `bpf/net.bpf.c` (connect/accept/accept4 tracepoints, class read through
    the fd table, coarse destination class, `netc`/`net_stash`/`nhealth`);
  - `processpulse/net.py` (I-N1–I-N6 checkers);
  - additive schema-v2 net fields;
  - agent `--capabilities counts,net`.
- **Evidence so far** (`results/acceptance/m1b/s3.2/`):
  - unprivileged 657/1 on both interpreters;
  - privileged network tests 16/16 in a **development run**;
  - a verifier log; a privacy audit.
- **Not done:** the full privileged regression was stopped by the tooling
  for low memory; the final network run and the S1 equivalence probe never
  ran. Details are in
  [CURRENT_STATUS_AND_ROADMAP.md](CURRENT_STATUS_AND_ROADMAP.md).
