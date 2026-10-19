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
| Records per snapshot | one `syscall_snapshot` holding every process | `bpf_snapshot_begin`, `bpf_proc`*, `bpf_reclaimed`*, `bpf_snapshot_end` |
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
- `bpf_bigrams` and multi-capability records are not part of S0 (S2/S4).
- The C-collector bound (T-F5) is computed from constants and checked against
  real output; no real 4 KiB cgroup path was exercised.
- The consumer has no partial recovery: any invalidation lasts until the next
  keyframe. The producer cannot see consumer-side invalidations (e.g. a lost
  file segment); it forces a recovery keyframe only after its own failed
  scheduled keyframe or uncommitted snapshot.
- The keyframe obligation (§4 9a) is checked only from an observed epoch start
  or an observed failed scheduled keyframe; a consumer joining mid-epoch
  cannot check the epoch's first keyframe.
