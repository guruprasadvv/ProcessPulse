# Architecture

[← Onboarding index](README.md) · prev: [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) · next: [GLOSSARY.md](GLOSSARY.md)

This describes what **exists in the repository**: everything on `master`
(through S2.6), plus the S3.1/S3.2 network work, which is only on branch `wip/s3.2-network`
(not merged, not accepted) and is marked as such.
Planned layers are listed at the end and clearly labelled. The deep design
references are [`docs/bpf-collector.md`](../bpf-collector.md) and
[`docs/telemetry-v2.md`](../telemetry-v2.md).

## 1. Data flow

```
                    ┌────────────────────────── Linux kernel (WSL2, 6.18) ──────────────────────────┐
 processes ───────► │ /proc/<pid>/{stat,status,io,cgroup,fd}       tracepoints:                      │
 (host + Docker)    │                                              syscalls:sys_enter_<9 syscalls>   │
                    │                                              sched:sched_process_exit / _exec  │
                    │                                              syscalls:sys_{enter,exit}_        │
                    │                                                {connect,accept,accept4} (S3.2) │
                    └──────────┬───────────────────────────────────────────────┬────────────────────┘
                               │ read                                          │ eBPF programs write BPF maps
                               ▼                                               ▼
              ┌──────────────────────────────┐        ┌──────────────────────────────────────────────┐
              │ C collector  ./collector --v1 │        │ BpfCollector (processpulse/bpf_collector.py) │
              │ (src/collector.c, procfs.c)   │        │  one unified BPF program (bpf/*.c, *.h)      │
              │ stdout: schema-v1 JSONL       │        │  reads maps: counts, info, threads, bigrams,  │
              └──────────────┬────────────────┘        │  bglobal, health, netc, net_stash, nhealth   │
                             │ pipe                    └─────────────────────┬────────────────────────┘
                             ▼                                               │ snapshot() / drain()
              ┌──────────────────────────────┐                               ▼
              │ ResourceCollector (resource.py)│              ┌───────────────────────────────────┐
              │ supervise, frame, validate,    │              │ V2Emitter (snapshots.py)           │
              │ restart with backoff           │              │ framed v2 snapshots, keyframes,    │
              └──────────────┬────────────────┘              │ bigram parts, net fields           │
                             │ samples                       └─────────────────┬─────────────────┘
                             ▼                                                 ▼
              ┌────────────────────────────────────────────────────────────────────────────┐
              │ Agent (processpulse/agent.py): one BPF snapshot per resource sample;        │
              │ every record validated (validate.py) before writing; final drain at end    │
              └──────────────────────────────────────┬─────────────────────────────────────┘
                                                     ▼
       results/raw/<run>/ resource.jsonl, bpf.jsonl (schema 2) or syscall.jsonl (schema 1),
                          health.jsonl, preflight.json, manifest.json, agent.log
                                                     ▼
       tools/acceptance/validate_run.py + Reconstructor + invariant checkers (bigrams.py, net.py)
```

## 2. Components and boundaries

### C resource collector: `src/`
- **Files:** `src/collector.c` (main loop, modes), `src/procfs.c` + `src/procfs.h` (pure
  parsers for stat, status, io, cgroup v2), `src/jsonl.c` + `src/jsonl.h` (UTF-8-safe
  JSON escaping).
- **Modes:** with no arguments it keeps the original M0 one-snapshot output.
  `--v1 [--interval-ms N] [--count K]` streams schema-v1 samples
  (`sample_begin` / `proc` / `sample_end`).
- **Rules:** it reports only facts read from procfs, never rates. An
  unreadable value is `null` with an `*_err` code (`EACCES`, `ENOENT`,
  `ESRCH`, `EPARSE`, `EIO`, `UNSUPPORTED`). Time is `CLOCK_MONOTONIC`.
- **Boundary:** the collector knows nothing about eBPF. It is supervised by
  `processpulse/resource.py` (restarts, backpressure; `stopped` property
  since S2.6).
- **Tests:** `tests/c/test_procfs.c` (74 C checks under ASan/UBSan),
  `tests/test_collector*.py`, `tests/test_resource_collector.py`.

### Process and thread identity: `processpulse/identity.py`, `bpf/common.h`
- **ProcessKey** = `(boot_id, distro_pidns_inode, distro_tgid, start_ticks)`
  (`CLAUDE.md` §5). A reused PID has a different start time, so it gets a
  new key.
- **Resolution in the kernel:** `resolve()` in `bpf/common.h` walks
  `task->group_leader->thread_pid->numbers[DISTRO_LEVEL]`. It accepts the
  event only if that level's namespace inode equals the distro's. Anything
  else counts as `unresolved` and is never attributed.
- **Calibration:** `DISTRO_LEVEL` and the namespace inode are measured from
  the agent's own process by a one-shot calibration program
  (`bpf/calibrate.bpf.c`, `calibrate()` in `bpf_collector.py`); they are not
  assumed.
- **Start time:** start ticks from the kernel equal `/proc/<pid>/stat` field
  22, verified for 1000/1000 processes in M1.
- **Threads:** per-thread slots (`threads` map, keyed by host TID, which is
  never emitted) detect a reused TID by its start time (S1, "F4").

### Unified eBPF program: `bpf/` + `processpulse/bpf_collector.py`
- **One BCC compilation per start, plus calibration.** Exactly 2 per start
  (tested). `build_source()` concatenates:
  `common.h` → `bigrams.bpf.c` (if enabled) → `syscall_counter.bpf.c` →
  `net.bpf.c` (if enabled; WIP branch) → `core.bpf.c` → generated
  per-syscall probes.
- **Capabilities** (`CAPABILITIES`, `REQUIRES`, `check_capabilities()`):

  | Capability | Source | Requires | Adds tracepoints | State |
  |---|---|---|---|---|
  | `counts` | `syscall_counter.bpf.c` | — | 9 `sys_enter_*` (+ 2 sched hooks shared) | committed |
  | `bigrams` | `bigrams.bpf.c` | counts (U9) | none | committed |
  | `net` | `net.bpf.c` | counts (N3) | 6 connect/accept/accept4 entry+exit | **WIP branch, not accepted** |
  | `priv` | — | — | — | reserved, refused |

- **Scheduler hooks** (`core.bpf.c`): `sched_process_exit` deletes the
  thread's slot (and, with net, its stash entry). For the last thread it
  marks the process `exited`, unless the process is excluded.
  `sched_process_exec` refreshes comm/cgroup and handles a non-leader exec.
- **Maps:** listed in [`docs/bpf-collector.md`](../bpf-collector.md), with
  measured memory. For example, `bigrams` is 12.0 MiB at 131,072 entries;
  `netc` is 6.5 MiB and `net_stash` 3.25 MiB at 32,768 each (WIP branch).
- **Boundary:** the BPF side keeps cumulative counters only. Deltas, rates
  and features are always computed downstream.

### Lifecycle handling
- **Exit (two-phase reclaim):** `snapshot()` reports an exited process once.
  At the next snapshot it deletes the entries, but only if every value
  (counts, `pairs_lost`, pair sum, net counters) is unchanged, so no late
  increment is lost.
- **Self-exclusion and purge:** the agent excludes its own process and every
  C collector it spawns.
  - `exclude()` sets the exclusion, then waits for an RCU grace period
    (`rcu_barrier()` = `membarrier(MEMBARRIER_CMD_GLOBAL)`), then reads and
    deletes the process's entries. The values deleted are added to purge
    totals.
  - **Why the barrier matters:** without it, a probe that had already passed
    the exclusion check could write into a deleted entry. A preallocated map
    reuses that slot immediately, possibly for another process's counter
    (commit `615896d`, cited in older docs as `1f763de`; audit `results/acceptance/m1b/purge-race/audit/AUDIT.md`).
- **Exec:** the process key is unchanged across exec (the leader's start time
  is kept). Bigrams start a new segment with the `EXEC` marker.

### Snapshots, keyframes and the final drain: `processpulse/snapshots.py`
- **`V2Emitter`** turns each collector snapshot into a framed snapshot:
  `bpf_snapshot_begin`, `bpf_proc`*, `bpf_bigrams`*, `bpf_reclaimed`*,
  `bpf_snapshot_end`.
  - Only processes that changed are emitted, except in a **keyframe**
    (every 60th snapshot, or when one is due), which carries everything.
  - The emitted state advances only after the caller has written and flushed
    every line (`commit()`).
- **`Reconstructor`** is the consumer. It rebuilds the state, rejects
  incomplete or inconsistent snapshots, checks `tracked`/`totals`, and knows
  when "omitted" may be read as "unchanged".
- **Final drain** (`BpfCollector.drain()`, S2.5):
  1. detach every tracepoint (keeping the maps);
  2. `rcu_barrier()`;
  3. read every map twice; the drain succeeds only if both reads are equal.

  Exactly one more snapshot (the **drained snapshot**) is then allowed. The
  agent stops the resource supervisor first, because it calls `exclude()`.
  Whole-epoch accounting checks such as I-B2 are valid only on that
  snapshot.

### Versioned JSONL schemas
- **v1:** `processpulse/schemas/telemetry.v1.json`: resource records and the
  M1 `syscall_snapshot`. It is the agent's **default** (`--schema 1`).
- **v2:** `processpulse/schemas/telemetry.v2.json`: the framed BPF snapshot
  protocol.
  - Additive extensions, with `v` still 2: bigram fields (S2.1, decision U1)
    and network fields (S3.1, decision N6; WIP branch, not accepted).
  - **Byte rule:** a record's UTF-8 bytes, without the LF, are 1..65,536,
    with no CR or LF inside (`processpulse/jsonl.py`).
- **Validator:** `processpulse/validate.py`, stdlib only. It implements the
  subset of JSON Schema the files use, plus cross-field rules. Tests
  cross-check it against the `jsonschema` package.

### Agent, manifests and evidence
- **CLI:** `processpulse/agent.py`, run as `python3 -m processpulse.agent`.
  Flags: `--duration`, `--interval-ms`, `--out`, `--no-bpf`, `--collector`,
  `--schema {1,2}`, `--capabilities counts[,bigrams][,net]`,
  `--allow-degraded`.
- **Manifest** (`manifest.json`): run metadata, capabilities
  requested/active/failed, the drain outcome, and `status: failed` on a
  strict startup failure.
- **Preflight** (`processpulse/preflight.py`): root, BCC import, tracefs,
  every required tracepoint, kernel headers. As root it attempts
  `modprobe kheaders`.
- **Run validation:** `tools/acceptance/validate_run.py` checks every line,
  framing, alignment, the snapshot protocol and (v2) the bigram invariants.
- **Acceptance evidence** lives under `results/acceptance/<milestone>/`.
  Raw runs live in `results/raw/`, which git ignores.

### Bigram telemetry (committed, S2)
- **What it records:** per thread, the pair (previous observed syscall or
  segment marker, current syscall), counted per process in the `bigrams`
  map.
- **Markers** (`START_NEW`, `START_ATTACH`, `START_LOST`, `EXEC`) open a
  segment.
- **Loss accounting:** every counted entry whose pair could not be recorded
  goes into that process's `pairs_lost` and the `bigram_dropped` health
  counter (rule R-LOSS).
- **Decoding and checks:** `processpulse/bigrams.py` decodes the pairs and
  checks I-B1–I-B5
  ([TELEMETRY_AND_INVARIANTS.md](TELEMETRY_AND_INVARIANTS.md)).

### Network telemetry (S3.1/S3.2, on branch `wip/s3.2-network`, **not accepted**)
- **Source:** `bpf/net.bpf.c`.
- **Hooks:** `sys_{enter,exit}_{connect,accept,accept4}`. A per-thread stash
  pairs each entry with its exit.
- **Socket class:** read from the socket behind the fd (fd table → file →
  socket → sock) with kernel-memory reads inside the tracepoint, because the
  tracepoints carry no family or protocol. **No kprobes.**
- **Destination class:** computed from the connect sockaddr. Only the family
  and address bytes are read; the port never is; only the class code is
  stored.
- **Accounting:** R-NLOSS counters per syscall in `nhealth`.
- **Userspace:** `read_net()`, `net_health()`, purge, reclaim and drain
  terms in `bpf_collector.py`; decoding and the I-N1–I-N6 checkers in
  `processpulse/net.py`; schema fields per
  [`docs/telemetry-v2.md` §9](../telemetry-v2.md).

## 3. Planned layers (not implemented)

Contracts exist in `CLAUDE.md` §7–§8. There is no code.
- **M2 features:** cleaning, normalization, frequency, temporal, sequence
  and container aggregates; a versioned feature schema and transform `T`.
  Python 3.12 venv; never imports BCC.
- **M4 detection:**
  - the score is `F(x) = IsolationForest.score_samples(T(x))`; lower means
    more anomalous;
  - the threshold τ is a quantile of benign validation runs only;
  - sklearn's `predict()`/`contamination` are not used for decisions.
- **M5 explanations:** `shap.PermutationExplainer` on that same `F`
  (primary); LIME (`LimeTabularExplainer`, regression mode) on the same `F`
  (mandatory secondary); validation rules listed in §8.
- **M6 presentation:** curses TUI and a static HTML report (D-10).

## 4. Where to look in the code first

| Question | Start at |
|---|---|
| How is an event attributed to a process? | `bpf/common.h` `resolve()` |
| What happens on each syscall? | `bpf/syscall_counter.bpf.c` `count_syscall()` |
| How are bigrams recorded and lost? | `bpf/bigrams.bpf.c` (R-LOSS comment at the top) |
| How do exit/exec work? | `bpf/core.bpf.c`, `BpfCollector.snapshot()` |
| How is a purge made safe? | `BpfCollector._exclude()`, `rcu_barrier()` |
| How does the drain work? | `BpfCollector.drain()` / `_drain_steps()` |
| How are records framed and checked? | `processpulse/snapshots.py` (`V2Emitter`, `Reconstructor`) |
| How does a run start and end? | `processpulse/agent.py` `Agent.run()`, `_final_drain()` |
| Network (WIP branch `wip/s3.2-network`) | `bpf/net.bpf.c`, `processpulse/net.py` |
