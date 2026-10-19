# Telemetry and invariants

[← Onboarding index](README.md) · deep references: [`docs/telemetry-v2.md`](../telemetry-v2.md), [`docs/bpf-collector.md`](../bpf-collector.md)

This explains what the recorded data *means* and how the project proves it
is correct. The equations are copied from the approved contracts. Where the
S3.2 implementation interprets a contract, that is said explicitly, and it
is **awaiting review**.

## 1. JSON Lines and schema versions

- **Format:** every stream is **JSON Lines**: one JSON object per line,
  UTF-8, terminated by `\n`. Every record has `"type"` and `"v"` (the schema
  version).
- **Schema v1** (`processpulse/schemas/telemetry.v1.json`): the C
  collector's resource samples (`sample_begin`, `proc`, `sample_end`), the
  M1 `syscall_snapshot`, and `health`. **The agent's default.**
- **Schema v2** (`processpulse/schemas/telemetry.v2.json`): the framed BPF
  snapshot protocol (`bpf_snapshot_begin`, `bpf_proc`, `bpf_bigrams`,
  `bpf_reclaimed`, `bpf_snapshot_end`). Opt-in with `--schema 2`.
- **Byte rule** (from S0): a record's UTF-8 bytes **without** the final LF
  are 1..65,536 bytes, with no CR or LF inside. v2 writers enforce it
  (`encode_record()`); v1 recordings that break it are reported as legacy
  findings. The widest possible `bpf_bigrams` record was measured at 62,739
  bytes (S2.6 evidence).
- **Additive extensions:** the bigram fields (decision U1) and the network
  fields (N6, uncommitted) were added without bumping `v`. They are present
  **iff** their capability is selected, so a counts-only v2 stream keeps
  exactly the S0 shape.

## 2. The three kinds of data

| Data | Capability | What one number means |
|---|---|---|
| **Counts** | `counts` | cumulative count of syscall **entries** (attempts, not successes) per process and syscall, for 9 syscalls |
| **Bigrams** | `bigrams` (requires counts, U9) | cumulative count of the pair (previous observed call or marker, observed call) per process. Example: `{"a": "openat", "b": "openat", "n": 42}` |
| **Network** (uncommitted) | `net` (requires counts, N3) | per process and socket class: connect/accept results and coarse destination classes; per process: syscall entries observed |

Counters are **cumulative and never reset** within an *epoch* (one load of
the BPF program). Deltas and rates are computed downstream from Δcounter /
measured Δt, never from an assumed interval.

## 3. "Empty" vs "unavailable": never confuse them

- **Available but empty:** the capability works and nothing happened. A
  bigram table is one record with `pairs: []`; a net object has
  `classes: {}`. Zero here is a *measurement*.
- **Unavailable:** the capability isn't running in this epoch. The value is
  `null` with an error field: `pairs_lost: null` + `bigrams_err:
  "UNSUPPORTED"`, or `net: null` + `net_err: "UNSUPPORTED"`. **Never zeros.**

This follows the general rule in `CLAUDE.md` §5: an unread value is `null`
plus an `*_err` code, and 0 is never substituted for it.

## 4. Capabilities and startup

- **Dependencies:** `bigrams` and `net` each require `counts`. Both require
  `--schema 2`. `priv` is reserved and refused.
- **Strict startup (default, since S2.6):** if a requested capability cannot
  start (compile error, failed preflight, startup error), the run **fails**:
  - exit status 1;
  - `manifest.json` has `status: failed` with the reason;
  - every handle already opened is released;
  - no telemetry is written.
- **Explicit degraded mode:** `--allow-degraded` runs counts-only instead,
  marks the other capabilities `unavailable` (with the reason) in the
  telemetry, and records `requested`, `active` and `failed` capabilities in
  the manifest.

## 5. Snapshots, keyframes and the final drain

- **Changed-only emission:** each BPF snapshot is framed: begin, procs,
  bigram parts, reclaimed keys, end. Only processes whose values changed are
  emitted.
- **Keyframes:** a keyframe re-emits everything. It happens when the snapshot
  succeeds and either `seq % 60 == 0` or a keyframe is "due". Due is set at
  the epoch start, after a failed scheduled keyframe, and after an
  uncommitted snapshot. So a consumer that joins late, or loses a snapshot,
  can always resynchronize.
- **Consumer validity:** the consumer (`Reconstructor`) may read an omitted
  process as "unchanged" only while its state is valid. Any gap,
  inconsistency or failed check invalidates the state until the next
  keyframe.
- **Final drain:** live map reads are not atomic, so a count may be read
  before its pair. The final drain (S2.5):
  1. detaches every probe;
  2. waits for in-flight probes (`rcu_barrier()`);
  3. reads every map twice and requires equal reads.

  The one **drained snapshot** afterwards has `drained: true`, and
  whole-epoch checks are valid only there. A failed or unstable drain never
  produces `drained: true`.

## 6. Loss accounting: why silent loss is unacceptable

Maps have fixed capacity and probes run concurrently, so some events *will*
be lost under pressure. The rule is: **every loss is counted, never hidden,
and never misattributed.**
- An unresolvable event goes to `unresolved_events`. It is never guessed
  onto a process.
- Events of the agent's own processes go to `self_excluded_events`, or to
  the purge totals if they were recorded first.
- Map-full events have their own counters.

Without these counters, a "normal-looking" quiet process could really be a
process whose events were dropped, and an anomaly detector would learn the
wrong baseline.

### R-LOSS (bigrams; approved as A8; `bpf/bigrams.bpf.c`)

For each observed entry *s* of process *K*:

| Path | Count | Pair | `pairs_lost` | Health | Next `prev` |
|---|---|---|---|---|---|
| row 1: no counts entry | lost | lost | — | `counts_map_full`, `bigram_dropped` | `START_LOST` |
| row 2: no thread slot | recorded | lost | +1 | `thread_map_full`, `bigram_dropped` | next slot `START_LOST` |
| row 3: bigram map full | recorded | lost | +1 | `bigram_map_full`, `bigram_dropped` | *s* |
| before arming (U2a) | recorded | lost | +1 | `pre_arm_events`, `bigram_dropped` | unchanged |
| ok | recorded | recorded | — | — | *s* |

### R-NLOSS (network; S3 plan §5; S3.2 implementation, uncommitted)

Per hook invocation, counted in `nhealth` per syscall:
1. `seen_*` is incremented first, before any lookup;
2. unresolved identity → `unresolved_*`, then stop;
3. our own excluded process → `excluded_*`, then stop;
4. if the counts/info/net entry cannot be created → `dropped_*` and
   `net_map_full`, then stop.

Stash outcomes: `stash_full`, `stash_overwrite`, `stash_orphaned` (also on
thread exit), and `exit_without_entry`. The full list is in
[`docs/bpf-collector.md`, "Network capability"](../bpf-collector.md).

## 7. Invariants: how correctness is checked

An invariant is an equation that must hold if no event was silently lost or
double-counted. Each checker returns:
- **PASS:** the equation holds.
- **FAIL:** it does not. This is a bug, or a precondition the caller lied
  about.
- **NOT APPLICABLE:** a precondition is not met (for example, the process is
  still running, so a live read cannot be exact). This is *neither* a pass
  nor a fail, and reports must keep it separate.

**Quiescence** (`processpulse/bigrams.py`): exact per-process checks need a
process whose values are final. The caller must state why:
- `drained`: the drained snapshot;
- `reclaimed_exited`: the last values of a process reclaimed after its exit
  report;
- `asserted`: a scripted helper known to be idle.

### Bigram invariants (approved, A8; definitions from [`docs/telemetry-v2.md` §8.5–8.6](../telemetry-v2.md))

Notation:
- *V*: the 9 vocabulary syscalls;
- *M*: the markers {START_NEW, START_ATTACH, START_LOST, EXEC};
- *C′[s]*: the process's count for *s*;
- *B(x,s)*: the count of pair (x, s).

| ID | Equation | Preconditions |
|---|---|---|
| I-B5 | names in V ∪ M; markers only as the first element | none (also a schema rule) |
| I-B1 | ∀ s ∈ V: Σₓ B(x,s) = C′[s] | quiescent, `pairs_lost` = 0 |
| I-B1′ | ΣB + `pairs_lost` = Σₛ C′[s] | quiescent (holds even with losses) |
| I-B3′ | ∀ x ∈ V: Σₛ B(x,s) ≤ C′[x] | quiescent |
| I-B3 (exact) | ∀ x ∈ V: C′[x] − Σₛ B(x,s) = number of thread segments ending in x | quiescent, `pairs_lost` = 0, scripted oracle, **no global loss in the window** |
| I-B4 (exact) | ∀ m ∈ M: Σₛ B(m,s) = number of segments starting with m (`START_LOST`: 0) | as I-B3 |
| I-B2 | ΣC′ + `purged_counts` = ΣB + Σ`pairs_lost` + `purged_pairs` + `purged_pairs_lost` (over live keys of the drained state and keys reclaimed as exited) | drained snapshot applied, state valid, whole epoch observed from seq 0, capability ok, no vanished entry |

- **Why "no global loss in the window" for exact I-B3/I-B4 (S2.4):** a row-1
  loss and a thread-map-full event can change a process's pairs without
  touching its own `pairs_lost`.
- **Why `purged_pairs_lost` is in I-B2 (S2.2):** without it, the equation
  fails by the purged processes' `pairs_lost`.
- **Variants:** a ground-truth form (`check_ib2_ground_truth`, against a
  scripted entry count) and a collector-side form on the drain read
  (`check_ib2_drain_read`).

### Network invariants (S3 plan §5, approved under N5; **S3.2 interpretations awaiting review**)

The plan's definitions, quoted:

| ID | Plan statement | When |
|---|---|---|
| I-N1 | class exclusivity: every socket-layer event is in exactly one class; `local_ipc` events never appear in `inet*` classes | always |
| I-N2 | event conservation per socket hook: `net_events_seen` = Σ(`*_ok` + `*_err` + `rx_peek` + `rx_trunc`) over live and reclaimed keys + `net_unresolved` + `net_self_excluded` + `net_dropped_events` + purged events | drained snapshot only |
| I-N3 | byte conservation per direction: `net_bytes_seen` = Σ `*_bytes` (live + reclaimed) + `net_dropped_bytes` + purged bytes + unresolved and excluded bytes | drained snapshot only |
| I-N4 | stash balance per stashed syscall: entries = matched exits + `stash_full` + `stash_overwrite` + `stash_orphaned` + stash entries left at the drain | drained snapshot only |
| I-N5 | partial-send bounds per key and class: `sendto_partial` ≤ `sendto_exit`; `sendto_attempted_bytes` ≥ the bytes of those exits | quiescent process |
| I-N6 | scripted ground truth: helper tally = counters, exactly | scripted tests, zero loss in the window |

How S3.2 (connect/accept only) applies them (`processpulse/net.py`; plan
§11). **These are interpretations, not yet reviewed:**
- **I-N1:** the checks are that class names are known, that only IP classes
  carry destination counts, and that per IP class Σ dest = Σ connect
  results.
- **I-N2:** the same conservation equation, applied to the six
  connect/accept **syscall** hooks (the socket hooks arrive in S3.3).
  `exit_without_entry` is a term for exits; accept and accept4 exits are
  pooled.
- **I-N3 and I-N5:** NOT APPLICABLE until S3.3 (no byte or sendto counters
  exist).
- **I-N4:** adds a `purged_stash` term (stash entries removed by a
  self-exclusion purge), which the plan's equation did not list.
- **I-N6:** the loss window excludes `unresolved_*`, which can never belong
  to a resolvable helper process.

**Unresolved:** whether these interpretations are accepted as the
definitions for S3.2. They are listed for decision in
[CURRENT_STATUS_AND_ROADMAP.md](CURRENT_STATUS_AND_ROADMAP.md).

## 8. Privacy rule for network data

No raw IP address or port is ever stored in a map, emitted in JSONL,
written to a manifest or logged:
- the BPF code reads only the sockaddr family and the address bytes, into
  locals, to compute a class code;
- it never reads the port;
- the schema has no field for an address (`additionalProperties: false`).

Evidence: `results/acceptance/m1b/s3.2/privacy-audit.txt`, and
`tests/test_net_unit.py::test_no_port_is_ever_read_and_only_class_codes_are_stored`.
