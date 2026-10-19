# Telemetry schema v2: framing rule and BPF snapshot protocol (M1b S0)

Status: implemented in the working tree (M1b stage S0), opt-in with
`python3 -m processpulse.agent --schema 2`. Source of the contract: the M1b
plan v3 (decisions D1–D6, keyframe interval 60, framing decision A1).
Code: `processpulse/jsonl.py` (byte rule), `processpulse/schemas/telemetry.v2.json`,
`processpulse/validate.py` (versioned dispatch), `processpulse/snapshots.py`
(producer and consumer), `tools/acceptance/validate_run.py` (run validation).

## 1. The byte rule (all versions)

A **record** is the UTF-8 encoded bytes of one JSON object, excluding the
terminating `0x0A`. A record is valid when

- `1 ≤ len(record_bytes) ≤ 65,536` (`MAX_RECORD_BYTES = 64 × 1024`), so a stored
  line including its LF is at most 65,537 bytes;
- it contains no `0x0D` (CR) and no `0x0A` (LF).

Length is always counted on encoded bytes, never on characters.

| Component | Enforcement |
|---|---|
| C collector (`--v1`, M0 mode) | Bounded by construction: worst case is computed from the C constants by `tests/test_c_record_bound.py` (T-F5). No runtime check. |
| `JsonlFramer` (agent reading the C stream) | Unchanged from M1: lines over 65,536 bytes are skipped and counted (`oversize_lines`); a trailing CR is tolerated (legacy). |
| Agent, `--schema 2` | Every line of every stream is produced by `encode_record()`, which raises `RecordTooLarge`/`ValueError` instead of writing a line that breaks the rule. That aborts the run, as an invalid record already did in M1. |
| Agent, `--schema 1` (default) | Unchanged from M1: no line check (M1 runs contain oversize `syscall_snapshot` lines). |
| `validate_run.py` | Checks every line with `line_violations()`. A v2 record that breaks the rule is invalid. A v1 record that breaks it is counted as `legacy_v1_oversize` / `legacy_v1_cr`: reported, and in a v1 run it does not change the verdict. In a v2 run every line, of any version, must satisfy the rule. |

## 2. v1 and v2 differences

| | v1 (`--schema 1`, M1) | v2 (`--schema 2`, S0) |
|---|---|---|
| BPF stream file | `syscall.jsonl` | `bpf.jsonl` |
| Records per snapshot | one `syscall_snapshot` holding every process | `bpf_snapshot_begin`, `bpf_proc`*, `bpf_bigrams`* (S2, §8), `bpf_reclaimed`*, `bpf_snapshot_end` |
| Line size | unbounded (15 of 613 lines in the accepted M1 10-minute run exceed 65,536 bytes; the largest record is 311,053 bytes without its LF) | at most 65,536 bytes, enforced by the writer |
| Processes per snapshot | all entries in the map | keyframe: all tracked; otherwise only new or changed ones |
| Removals | implicit (an entry stops appearing) | explicit `bpf_reclaimed` with a reason |
| Failed map read | the run aborts | `status: failed` snapshot; the run continues |
| Consistency check | none | `tracked` and per-syscall `totals` (mod 2^64) in every end record |
| Resource and health records | v1 | v1, unchanged |
| Schema file | `telemetry.v1.json` (frozen; sha256 pinned by a test) | `telemetry.v2.json`; definitions shared with v1 are copied verbatim and a test keeps them identical |

`processpulse.validate.Validator` dispatches on `type` to the schema version
that defines it; the record's `v` must then match (a v1 type labelled `v: 2`
is invalid, and vice versa).

## 3. Producer rules (`V2Emitter`)

- **Cumulative counters (D1).** Every counter is cumulative since the epoch
  (`run_id`, `attach_since_mono_ns`), i.e. one load of the BPF program. No
  record contains a delta. Consumers never subtract across epochs.
- **Framing (D2).** All records of a snapshot share `seq`, in this order:
  begin, procs, reclaimed, end. `seq` counts every snapshot attempt of the
  epoch from 0, including failed ones.
- **Keyframes (D3).** A keyframe emits every tracked process. `seq` (the snapshot
  number) and keyframes are distinct: `seq` counts every snapshot attempt of
  the epoch from 0, successful or not, and one emitter serves exactly one
  epoch. The rule is

  > keyframe(seq) ⇔ status = ok ∧ (seq mod 60 = 0 ∨ due)

  where `due` is **set** at the start of the epoch, when a snapshot with
  `seq mod 60 = 0` fails, and when the previous snapshot was never committed
  (its lines may be torn on disk), and is **cleared** only when a keyframe
  snapshot is committed. Consequences:
  - the first successful, complete snapshot of an epoch is a keyframe, whatever
    its `seq` (e.g. seq 3 if seq 0–2 failed);
  - the cadence stays anchored to `seq mod 60`: a missed keyframe at seq 60 is
    recovered at the next successful snapshot (e.g. seq 61), and the next
    regular keyframe is still seq 120;
  - a failed snapshot is never a keyframe; a failure at a non-scheduled `seq`
    adds no keyframe (it does not disturb a valid consumer state).
- **Changed-only emission (D3).** Outside keyframes a `bpf_proc` is emitted when
  the process is new or any field of its record differs from the last emitted
  one (this includes the first `exited: true`). This is a superset of "any
  counter differs": identity fields such as `container.stale` also cause an
  emission, so an omitted record never hides a change.
- **Complete records.** Each `bpf_proc` holds the complete state of one process.
- **Removals.** `bpf_reclaimed` lists keys removed from tracking in this
  snapshot, with a reason:
  - `exited`: reported as exited and unchanged since (the M1 two-phase reclaim);
  - `self_excluded`: purged when the agent excluded one of its own collectors;
  - `vanished`: disappeared without either. This should not happen; it is
    counted in `loss.vanished_entries` rather than hidden.
  A deletion that races with the map read wins: the key is listed as removed
  and its stale value is not emitted. Keys that were never emitted are not
  listed. Lists are split across records so each stays within the byte rule.
- **End record.** `tracked` = number of tracked processes after this snapshot;
  `totals.counts` = per-syscall sums over them, mod 2^64; `loss` =
  {`counts_map_full`, `info_map_full`, `vanished_entries`} (cumulative);
  `health` = the remaining BPF health counters, including `unreported_entries`
  (map entries skipped this time because their info entry was missing, as in
  M1). `unresolved_events` and `self_excluded_events` are health, not loss: by
  the identity contract they are not events of any tracked process.
- **Failed reads.** If reading the maps raises, the snapshot is
  `begin(keyframe=false)` + `end(status=failed, reason, read_err=EIO, loss=null,
  health=null)` with the unchanged `tracked`/`totals`. Nothing is emitted and the
  emitted state is unchanged, so the next snapshot reports every change since
  the last successful one.
- **Commit after write.** `build()` returns the records and a `commit()`
  function. The agent writes and flushes every line first and only then
  commits. A snapshot that was not completely written therefore never
  advances the emitted state.
- **Capability unavailable.** In S0 the only capability is the M1 syscall
  counter. If it is unavailable (preflight failure, `--no-bpf`), no BPF records
  are written and the health records state why, as in v1. The per-capability
  `null` + `*_err` representation belongs to S2, when there is more than one
  capability.

## 4. Consumer rules (`Reconstructor`)

The consumer keeps the emitted state and a `valid` flag.

1. **Snapshot completeness.** A snapshot is applied only as a whole, at its end
   record. It is rejected (`snapshots_incomplete`) and the state is invalidated
   if: a record has another `seq`, a second begin arrives before the end, the
   stream ends inside it, a `bpf_proc` follows a `bpf_reclaimed`, the end
   record's `procs_emitted` / `reclaimed_records` / `reclaimed_keys` do not
   match, a key appears twice or is both emitted and reclaimed, a failed
   snapshot carries a keyframe or records, or a `bpf_proc` breaks an identity
   rule (`container_pid` iff `level > distro_level`; key namespace and boot id
   equal the calibration). A record outside any snapshot is a framing error and
   also invalidates.
2. **Epochs.** A new epoch clears the state; it becomes valid at that epoch's
   first applied keyframe. A calibration change inside an epoch invalidates.
3. **Sequence.** Within an epoch each complete snapshot must have
   `seq = previous + 1`. A gap or repeat invalidates.
4. **Keyframe.** Replaces the state with its records and makes it valid.
5. **Non-keyframe.** Applied only while the state is valid: emitted records
   replace their process's state; reclaimed keys are removed (an unknown key
   invalidates).
6. **Cross-check.** After applying, `tracked` and `totals` must equal the
   consumer's own count and sums; otherwise the state is invalidated
   (`totals_mismatch`).
7. **Failed snapshot.** Changes nothing and keeps validity, but claims nothing
   either (no process is "unchanged" in that snapshot). Its `tracked`/`totals`
   must still match a valid state.
8. **Omitted = unchanged** only when the state is valid after the snapshot.
   Invalid state lasts until the next keyframe; a consumer that starts in the
   middle of a stream also waits for one.
9. **Loss.** `loss_possible` is true for a snapshot when any `loss` counter rose
   since the previous successful snapshot, `null` when it cannot be judged.
9a. **Keyframe obligation (producer conformance).** When the consumer has
   observed an epoch's start (its first snapshot has seq 0), or a failed
   snapshot at `seq mod 60 = 0`, the next successful snapshot must be a
   keyframe; so must every successful snapshot at `seq mod 60 = 0`. A missing
   one is counted once in `keyframe_schedule_violations` (it does not by itself
   invalidate a valid state). A failed scheduled keyframe never validates
   anything: a consumer that was waiting stays invalid until the recovery
   keyframe; a consumer whose state was already valid keeps it, because a
   failed snapshot changed nothing and its `tracked`/`totals` are still checked.
10. **Restart.** Start at the latest keyframe of the current epoch at or before
    the resume point and apply complete snapshots in order.

## 5. Illustrative sequence

All values are illustrative, not measured. Keyframes at seq 0 (and 60, 120, …).

| seq | Records after begin | End: tracked, emitted, reclaimed | Consumer state |
|---|---|---|---|
| 0 | keyframe: A{openat 10}, B{openat 5} | 2, 2, 0 | valid; A 10, B 5 |
| 1 | A{openat 12} | 2, 1, 0 | A 12; B omitted = unchanged |
| 2 | B{openat 6, exited} | 2, 1, 0 | B final 6 |
| 3 | C{openat 1}; reclaimed(exited) [B] | 2, 1, 1 | A 12, C 1 |
| 4 | none, status failed | 2, 0, 0 | unchanged and valid; no claims for seq 4 |
| 5 | A{openat 15}, then the stream ends without an end record | — | seq 5 rejected; invalid until a keyframe |

## 6. Validating a recorded run

`python3 tools/acceptance/validate_run.py RUN_DIR [--min-span-s S]` selects v2 mode
when `RUN_DIR/bpf.jsonl` exists. In v2 mode it additionally requires every line
to satisfy the byte rule, BPF snapshots aligned 1:1 with resource samples by
`resource_seq`, and a snapshot protocol with no incomplete snapshot, framing
error, seq gap, epoch change, invalidation, totals mismatch or keyframe
schedule violation, at least one keyframe, and a valid state at the end. Failed snapshots are counted
(`bpf_failed_snapshots`) but are a legitimate protocol state.

## 7. Known limitations of S0

- The agent's default stays `--schema 1`; M1 harnesses (`run_10min.sh`,
  `overhead.py`) read `syscall.jsonl`. Switching the default is a separate decision.
- v1 recordings keep their oversize lines; this is recorded as an M1 limitation.
- `bpf_bigrams` and multi-capability records are not part of S0; the bigram
  records are added additively in S2 (§8).
- The C-collector bound (T-F5) is computed from constants and checked against
  real output; no real 4 KiB cgroup path was exercised.
- The consumer has no partial recovery: any invalidation lasts until the next
  keyframe. The producer cannot see consumer-side invalidations (e.g. a lost
  file segment); it forces a recovery keyframe only after its own failed
  scheduled keyframe or uncommitted snapshot.
- The keyframe obligation (§4 9a) is checked only from an observed epoch start
  or an observed failed scheduled keyframe; a consumer joining mid-epoch
  cannot check the epoch's first keyframe.

## 8. Bigram records (M1b S2.1: schema and consumer)

Status: schema, validator, chunking rule and `Reconstructor` (S2.1); BPF
capability (S2.3); producer `V2Emitter(bigrams=...)` and the agent option
`--schema 2 --capabilities counts,bigrams` (S2.6, §8.7). Contract sources: M1b plan v3 D2/D5/D12/D13, the S2 design report
§3.7, and the approved decisions U1 (additive v2 extension), U4
(`bigram_dropped` = every lost pair), U5 (the nine-syscall vocabulary
`v1-3aba869d1752`), U8 (schema 2 and explicit selection only) and U10 (bigram
health and drain metadata in the end record).

### 8.1 Additive rule

`v` stays 2. Every new field is optional in the schema and is present **iff**
`bpf_snapshot_begin.capabilities.bigrams` is present. A counts-only snapshot
therefore has exactly the S0 records, fields and meanings (tested field by
field), and a snapshot that carries any bigram field without the capability is
rejected.

### 8.2 Records

| Record | Field | Meaning |
|---|---|---|
| begin | `capabilities.bigrams` | `{status, epoch, err, reason}`. `ok`: `epoch` equals the counts epoch (one unified BPF program, S1), `err`/`reason` null. `unavailable`: `epoch` null, `err` = `UNSUPPORTED`, `reason` set. `EIO` (plan v3 D5: failure during a run) is **reserved**: no producer path emits it yet, so the schema rejects it until a producer contract is approved. |
| `bpf_proc` | `pairs_lost`, `bigrams_err` | `pairs_lost` = cumulative entries of this process whose pair was not recorded (R-LOSS `pairs_lost_K`). Exactly one of the two is non-null: `ok` → `pairs_lost` set, `bigrams_err` null; `unavailable` → `pairs_lost` null, `bigrams_err` = the capability's `err`. Never 0 for "unknown". |
| `bpf_bigrams` | `key`, `part`, `parts`, `pairs` | One part of the complete cumulative pair table of `key`. `pairs` = `[{a, b, n}]`: `a` ∈ the 9 vocabulary syscalls ∪ {`START_NEW`, `START_ATTACH`, `START_LOST`, `EXEC`}; `b` ∈ the 9 syscalls only (I-B5, a schema rule); `n` ≥ 1 (a sparse table has no zero entries). At most 1,024 pairs per record (`maxItems`) and the byte rule (§1). No duplicate `(a, b)` within a table. An empty table is one part with `pairs: []`. |
| end | `bigram_records` | Number of `bpf_bigrams` records in the snapshot. |
| end | `totals.bigrams` | `{pairs, pairs_lost}`: Σ of every pair count and Σ `pairs_lost` over the tracked processes after the snapshot, mod 2^64. `null` iff unavailable. |
| end | `bigram_health` | Cumulative `bigram_dropped` (every pair not recorded: R-LOSS rows 1–3 and pre-arm events), its causes `bigram_map_full`, `thread_map_full`, `pre_arm_events`, plus `thread_slot_stale` and the self-exclusion purge totals `purged_counts`, `purged_pairs`, `purged_pairs_lost`. `null` when unavailable or when the snapshot failed. |
| end | `drained` | `true` only on the final snapshot after the probes are detached and the maps read stably (U3). A failed snapshot is never drained. |

Order inside a snapshot (D2): begin, all `bpf_proc`, all `bpf_bigrams`, all
`bpf_reclaimed`, end. The parts of one key are consecutive, numbered
`0 … parts−1` with the same `parts`. A failed snapshot carries no
`bpf_bigrams`, `bigram_records` = 0, `bigram_health` null, `drained` false, and
the unchanged `totals.bigrams`.

### 8.3 Producer rule (`bigram_parts`)

`bigram_parts(seq, key, table)` turns `{(a, b): n}` into parts: pairs sorted
by (vocabulary index of `a`, markers after the syscalls; index of `b`), zero
entries dropped, split by `chunk_records(..., max_items=1024)` so that each
record holds ≤ 1,024 pairs **and** ≤ 65,536 bytes. Part numbers are sized with
a placeholder at least as wide as the real ones, so filling them in never
grows a record past the limit. A pair outside the vocabulary or with a marker
second raises. With the current vocabulary a table has at most
(9 + 4) × 9 = 117 pairs, so real tables are one part; a full part of 1,024
maximal-width pairs with a maximal key is still within the byte rule (tested).
Whenever the producer emits a `bpf_proc` it emits that process's full table.

**Requirement for the S2.6 emitter (S2.3 audit, finding 4; implemented in
S2.6, §8.7).** Design §3.7's
"a pair change implies a count change" does not hold for live reads: a probe
increments the count first and the pair (or `pairs_lost`) second, and the maps
are read one after the other. A snapshot can therefore see a count without
its pair, and the pair only in a later snapshot whose counts are unchanged.
The emitter's change detection must compare the pair table and `pairs_lost`
as well as the counts. Otherwise a late pair of an exiting process is
missing from its final report. The collector's exit reclaim already compares
counts, `pairs_lost` and the pair sum (S2.3).

### 8.4 Consumer rules (additions to §4)

1. **Rejection (whole snapshot, state invalid until a keyframe):** a
   `bpf_proc` after a `bpf_bigrams`, a `bpf_bigrams` after a `bpf_reclaimed`
   or with another `seq`; a missing, reordered, duplicated or non-contiguous
   part, or inconsistent `parts`; a duplicate pair across parts; a table whose
   key has no `bpf_proc` in the snapshot, or an emitted `bpf_proc` without its
   table (capability `ok`); `bigram_records` ≠ the number of parts; bigram
   fields without the capability, or missing with it; `pairs_lost` null while
   `ok`, or non-null / with another error while `unavailable`; tables, totals
   or health while `unavailable`; a bigram epoch different from the counts
   epoch.
2. **Apply:** a keyframe replaces all tables; otherwise each emitted table
   replaces the old one (never merged) and reclaimed keys drop theirs
   (`Reconstructor.pairs`, key → `{(a, b): n}`).
3. **Cross-check:** after applying, `totals.bigrams` must equal the consumer's
   own sums (`totals_mismatch` otherwise), also on failed snapshots.
4. **Capability per epoch:** the bigram selection and status (`status`,
   `err`) are fixed for an epoch; any change invalidates.
5. **Drain:** `SnapshotView.drained` reports the drained snapshot. Any later
   snapshot of the same epoch is counted in `snapshots_after_drain`,
   invalidates, and is not applied; a new epoch starts normally.
   Producer side (S2.5): `BpfCollector.drain()` detaches the probes,
   waits for in-flight invocations, then reads the maps twice and requires
   the reads to be equal;
   the one `snapshot()` allowed after it is the drained snapshot
   (`last_snapshot_drained`; `docs/bpf-collector.md`, "Final drain"). The
   S2.6 emitter writes `drained: true` exactly for that snapshot (§8.7).
6. **Loss:** `SnapshotView.pair_loss_possible` is true when `bigram_dropped`
   rose since the previous successful snapshot, `null` when it cannot be
   judged (no bigram health, or no previous value). `loss_possible` keeps its
   S0 meaning (counts loss fields only).

7. **Retained values (S2.2):** `Reconstructor.retired` keeps, per key removed
   by `bpf_reclaimed` while the state was valid, its reason and last applied
   payload and table; `epoch_intact` is true while the epoch was observed from
   seq 0 with every successful snapshot applied and no invalidation;
   `last_ok_end` is the end record of the last applied successful snapshot.

`validate_run.py` checks bigram streams since S2.6 (§8.7).

### 8.5 Resolved contract points (S2.2)

**A. I-B2 purge accounting.** Every term counts observed syscall entries of
keys that had a counts entry (R-LOSS row 1 events are in neither side):

- ΣC′ = Σ over the counted keys of Σₛ C′[K][s]; ΣB = Σ of their pair counts;
  Σ`pairs_lost_K` = Σ of their `pairs_lost`. The counted keys are the live keys
  of the drained state and the keys reclaimed with reason `exited` ("reclaimed
  keys" in D13 is the two-phase reclaim of D5), with their last emitted values.
- `purged_C` = `purged_counts`: Σₛ C′[K][s] of purged entries at purge time.
- `purged_B` = `purged_pairs` + `purged_pairs_lost`: the pair counts **and**
  the `pairs_lost` of those entries.
- Keys removed as `self_excluded` are counted **only** through these totals,
  never also with their last emitted values (that would count them twice).

Why `purged_B` must include `purged_pairs_lost`: by R-LOSS every counted
entry of K adds 1 either to B[K] or to `pairs_lost_K`, so at quiescence
ΣC′[K] = ΣB[K] + `pairs_lost_K` (I-B1′). Removing a purged K removes
ΣC′[K] from the left and ΣB[K] + `pairs_lost_K` from the right; with
`purged_B` = `purged_pairs` alone, I-B2 would fail by Σ `pairs_lost` of the
purged keys (a test shows a difference of exactly 2). This is the approved
equation with its terms defined, not a new invariant.

Producer requirement **P-PURGE** (for the later emitter/collector step): a
purge reads an entry's counts, pairs and `pairs_lost` after its exclusion has
taken effect, so no event of that key is in flight between the read and the
delete; otherwise the purged values need not balance.

Consequence (tested): I-B2 is the sum of the per-key identities plus the purge
terms, so a key whose own values balance contributes 0 net, and its absence
or duplication is invisible to I-B2. Key coverage comes from the
Reconstructor (`tracked`/`totals` cross-checks, `retired`), and in scripted
tests from `check_ib2_ground_truth` (§8.6), which compares both sides with
the number of observed entries counted by the script and so detects a
missing or double-counted process (tested).

**B. Zero-count entries.** Producer invariant **P-ZERO**: an emitted table is
sparse; a map entry read with n = 0 (between its insertion and its first
increment) is left out, and is not loss. The schema requires n ≥ 1. The
decoder (`bigrams.decode_entries`) drops such entries and reports them
separately as `zero_entries`; checkers treat an absent pair as 0, so an
omitted zero entry changes no sum and is never read as loss. Loss is only
`pairs_lost` and `bigram_health`.

**C. Names and representation.** Unchanged from §8.2: an empty table is one
part with `pairs: []`; `bigram_health`, `purged_counts`, `purged_pairs`,
`purged_pairs_lost`, `pairs_lost`, `bigrams_err`. No contradiction found.

**D. Capability status.** Fixed per epoch (§8.4 rule 4): a change of
selection, `status` or `err` invalidates. No `ok → EIO` transition is defined;
the unified program has no separate bigram failure mode while counts continue.
A failed map read remains a failed snapshot. Consequently `err` and
`bigrams_err` accept only `UNSUPPORTED`; `EIO` is reserved (schema
`$defs/bigram_err`).

### 8.6 Checkers (`processpulse/bigrams.py`, S2.2)

Stdlib only (never imports BCC). Codes: 0–8 = the vocabulary syscalls in
order (`v1-3aba869d1752`), 9–12 = `START_NEW`, `START_ATTACH`, `START_LOST`,
`EXEC`; unknown, non-integer or boolean codes raise `DecodeError`, and so does
a marker as the second element (I-B5). Each checker returns `PASS`, `FAIL` or
`NOT_APPLICABLE` (precondition unmet, with the reason). A malformed table
(I-B5 or a bad count) is a `FAIL`.

The quiescence basis is given by the caller: `drained`, `reclaimed_exited`
(last values of a key reclaimed as exited, whose last record is marked
exited) or `asserted` (a scripted helper idle outside the vocabulary). `None`
(a live process, including an exited one not yet reclaimed) gives
`NOT_APPLICABLE`: live reads are not atomic.

| Checker | Equation | Preconditions |
|---|---|---|
| `check_ib5` | names in V ∪ M; markers only first | none |
| `check_ib1` | ∀s∈V: Σₓ B(x,s) = C′[s] | quiescent, `pairs_lost` = 0 |
| `check_ib1_prime` | ΣB + `pairs_lost` = Σₛ C′[s] | quiescent |
| `check_ib3_prime` | ∀x∈V: Σₛ B(x,s) ≤ C′[x] | quiescent |
| `check_ib3_exact` | ∀x∈V: C′[x] − Σₛ B(x,s) = segments ending in x | quiescent, `pairs_lost` = 0, oracle, **no global loss in the window** |
| `check_ib4_exact` | ∀m∈M: Σₛ B(m,s) = segments starting with m (`START_LOST`: 0) | quiescent, `pairs_lost` = 0, oracle, **no global loss in the window** |
| `check_ib2_drained` | §8.5 A | drained snapshot applied, state valid, `epoch_intact`, capability ok, no vanished entry |
| `check_ib2_ground_truth` | ΣC′ + `purged_counts` + `counts_map_full` = N = ΣB + Σ`pairs_lost` + `purged_pairs` + `purged_pairs_lost` + `counts_map_full`, with N the observed entries counted by the script itself (v2 §4 form of I-B2) | as `check_ib2_drained`, plus a known N (only scripted helpers tracked) |
| `check_ib2_ground_truth_scope` (S2.4) | the same equation over a closed scope of scripted processes: their entries (live or exited) plus the purge totals they caused = N | scope quiescent; `counts_map_full` did not rise (row 1 cannot be attributed to a scope); usable before the drained snapshot exists |
| `check_ib2_drain_read` (S2.5) | the `check_ib2_drained` equation on the collector's own drained read: live C′ + reclaimed C′ + `purged_counts` = live B + live `pairs_lost` + reclaimed B + reclaimed `pairs_lost` + `purged_pairs` + `purged_pairs_lost`; live terms from the stable map read, reclaimed terms from `BpfCollector.reclaimed_totals` (values of keys reclaimed as exited) | `BpfCollector.drain()` status `drained` (all probes detached, barrier, two equal reads); bigrams selected; a pair entry without a counts entry is a FAIL |

**Global-loss precondition of the exact checks (S2.4; S2.3 audit, finding 1).**
"Zero losses" (plan v3 D13) cannot be read from the process's own
`pairs_lost`:
- R-LOSS row 1 loses an entry and its pair without touching `pairs_lost`;
- every thread that started before the last slot-map-full event gets
  `START_LOST`, even if it lost nothing.

`check_ib3_exact` and `check_ib4_exact` therefore take `losses`: the
increases of `counts_map_full`, `thread_map_full`, `bigram_map_full` and
`pre_arm_events` over the window the claim covers. They return
NOT_APPLICABLE when `losses` is missing or any of these rose. The helpers:
- `loss_window(before, after)` gives the increases between two readings, for
  example `BpfCollector.global_losses()` read before a scripted process starts
  and after it finishes;
- `epoch_losses(rc)` reads the values of the current epoch from the last end
  record (cumulative since the epoch's load).

A window that starts after arming is the tighter choice: the agent's own
pre-arm events then do not apply. The equations and the preconditions of
the other checks are unchanged. Regression: the measured row-1 case (S2.3
evidence), which has `pairs_lost` 0 and a `START_LOST` pair, gave a false
FAIL before this change and gives NOT_APPLICABLE after it.
| `check_quiescent_reports` | I-B5, I-B1′, I-B3′, I-B1 | every key reclaimed as exited; every live key after the drain |

I-B3 is checked in its original v2 §4 form (count minus row sum = number of
segments ending in x); v3's short wording "row sums = number of segments
ending in x" states the same comparison less precisely.

**Oracle (`expected_pairs`).** A scripted, loss-free lifecycle of one process:
`("thread", t, "attach"|"new")`, `("call", t, s)`, `("exec", t)`,
`("exit", t)`. A thread's first observed call pairs with its start marker;
an exec ends every other thread and continues the calling thread with
`EXEC` (also for a non-leader exec); exit ends the thread; a reused id is a
new thread; nothing is `attach` after an exec. It returns the expected
pairs, counts, segment starts and segment ends. It does not model losses or
calls the script does not list (for example a helper's own startup calls),
so it is ground truth only for a zero-loss run whose script lists every
observed call.

### 8.7 Producer and agent integration (S2.6)

**Selection (U8, U9).**
- `agent --schema 2 --capabilities counts,bigrams` selects bigrams.
- `--capabilities` defaults to `counts` and `--schema` to 1, so the default
  output is unchanged.
- Refused, both by the CLI and by `Agent`:
  - bigrams without schema 2;
  - bigrams without counts;
  - `priv` or `net`;
  - an empty or duplicate list.

**Startup failure (strict by default).** If bigrams are requested and the
bigram program cannot be started, or preflight fails, the run fails:
- whatever was started is closed. A close error is not hidden: it is added
  to the original exception as a note and to the manifest's
  `cleanup_errors`;
- no other collector is started and no telemetry is written;
- `manifest.json` has `status: failed`, an `error` with the capability, the
  exact reason and the exception type, and the `requested`, `active` and
  `failed` capabilities;
- `Agent.run()` raises `StartupError` chained to the original exception,
  and the CLI exits with status 1.

`--no-bpf` together with bigrams is refused.

**Explicit degraded mode (`--allow-degraded`).** Only with this flag does
the agent close the failed bigram program and run the counts-only collector.
`manifest.json` then records `status: ok`, `degraded: true`,
`config.allow_degraded`, and `capabilities` `{requested, active, failed:
{bigrams: reason}}`. Bigrams are `unavailable` for the whole epoch:
- `capabilities.bigrams` = `{status: unavailable, epoch: null, err:
  UNSUPPORTED, reason}`;
- every `bpf_proc` has `pairs_lost: null` and `bigrams_err: UNSUPPORTED`;
- no `bpf_bigrams` records;
- the end record has `totals.bigrams` null, `bigram_health` null and
  `drained` false.

An available, empty table is a different thing: one part with `pairs: []`.

**Emitter (`V2Emitter(bigrams="ok")`).**
- **Tables:** each snapshot's tables come from the collector's
  `last_bigrams`, read in the same `snapshot()` as the counts. The health
  comes from `bigram_health()`, read right after. If either read fails, or a
  reported process has no table, the snapshot is `failed`: nothing is
  emitted, the emitted state does not change, and removals are kept for the
  next snapshot.
- **Change detection (§8.3):** a process, with its full table, is emitted
  when it is new, in a keyframe, or when any `bpf_proc` field changed. That
  includes the counts and `pairs_lost`, or the pair table alone.
- **Order:** begin, all `bpf_proc`, all parts (`bigram_parts`, at most 1,024
  pairs and the byte rule per record), all `bpf_reclaimed`, end.
- **Size, measured:** the widest possible part (1,024 pairs of maximal
  width, maximal key and numbers) is 62,739 bytes, or 62,740 bytes with its
  LF, so a `bpf_bigrams` line stays under 65,536 bytes even with the LF.
  - Parts are sized with placeholder part numbers, so a part can be split a
    few bytes before the limit, but it never exceeds it.
  - A pair that cannot fit in any record raises `RecordTooLarge` and aborts
    the run; it is never truncated.

  (`tests/test_bigram_chunk_limits.py`)
- **Keyframes:** the keyframe and `due` rules of §4 are unchanged. A failed
  scheduled keyframe keeps `due`, and the recovery keyframe carries every
  table.
- **`drained`** is true only when the collector took this very snapshot as
  its drained snapshot (`last_snapshot_drained` after the `snapshot()` call),
  and only if the snapshot succeeded.

**End of a bigram epoch (agent).** At the normal end of collection, in this
order:
1. Stop the resource supervisor and check that its thread has ended
   (`ResourceCollector.stopped`). It calls `exclude()` on every spawn.
   Otherwise there is no drain (`skipped`).
2. Call `drain()`. A failure or `unstable` result ends the run without
   another snapshot.
3. After a successful drain, build exactly one more snapshot with
   `resource_seq` null. Its end record is `drained: true` only if the
   collector marked it; a failed cross-check is written as a `failed`
   snapshot.

`manifest.json` `drain` records the outcome: `supervisor_stopped`, `status`,
`drained`, `reason`, `reads`, `accounting` and `final_snapshot` (`seq`,
`status`, `drained`). An error during collection propagates without a drain;
both collectors are always stopped and closed.

**Validation (`tools/acceptance/validate_run.py`).**
- A snapshot with `resource_seq` null is allowed only as the last one, and
  is not part of the per-sample alignment.
- On bigram runs it reports `check_ib2_drained` and
  `check_quiescent_reports` per invariant. Any FAIL fails the run.
- `--require-drained` also requires a drained final snapshot.
