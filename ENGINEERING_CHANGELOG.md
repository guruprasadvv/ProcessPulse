# Engineering Changelog

Verified history only. Every entry names the commands that were run and their
actual results. Dates are local (IST). "Uncommitted" means present in the
working tree but not yet in a commit.

## Milestone acceptance status

| MS | Status | Evidence |
|---|---|---|
| M0 | Accepted with documented defects | 2026-10-19 audit (below) |
| M1 | **Accepted 2026-10-19** | M1 foundations + M1 acceptance (below); `results/acceptance/m1/` |
| M1b | S0 accepted (`d9b9e9b`); S1 committed (`391c988`); S2.1–S2.4 and the purge-race fix implemented (uncommitted, under review); S2.5+ and S3–S7 not started | M1b S0, S1, S2.1–S2.3 (below); `results/acceptance/m1b/` |
| M2–M7 | Not started | — |

---

## M0 — baseline (pre-history)

- No git history existed before 2026-10-19; source authorship dates unknown.
- 2026-10-12: review PPT exported (PDF metadata `CreateDate`).
- 2026-10-19 audit, on a /tmp copy: `make` and strict flags
  (`-Wformat=2 -Wconversion -Wshadow …`), `-fanalyzer`, ASan+UBSan → 0 warnings,
  clean run; `pytest tests/ -v -rs` → 20 passed, 1 skipped
  (`test_minimum_record_count`: WSL exposes ~30 processes < 100).
- Defects found: D1 comm with `\n` drops the process; D2 bytes ≥ 0x80 emitted raw
  (invalid UTF-8); D3 `%lu` accepts `-1`; D4 unit tests exercise a Python mirror,
  not the C parser; D5 comm truncated at 31 bytes; D6 collection gaps invisible,
  exit 0 on failure; D7 readdir errors not distinguished; D8 min-record test always
  skipped in WSL; D9 doc inaccuracies; D10 stdout fully buffered.

## 2026-10-19 — eBPF feasibility gate

- Installed (authorized, via `wsl -d Ubuntu -u root`): `docker.io` 29.1.3,
  `bpfcc-tools` + `python3-bpfcc` 0.35.0; `modprobe kheaders` → exit 0.
- `tools/bpf_smoke.py` (per-syscall `sys_enter_getpid`): tests A–F PASS,
  2 runs × 3 iterations + an error-path iteration, 0 failing checks.
- Findings: distro is pid-namespace level 2; `bpf_get_ns_current_pid_tgid()`
  returns EINVAL (22) for nested namespaces; `thread_pid->numbers[2].nr` gives the
  distro PID for direct and nested processes; glibc 2.43 `os.getpid()` reaches the
  tracepoint (1000 calls → 1000 events).

## 2026-10-19 — git baseline and master instructions

- `795c945` chore: initial baseline commit of M0 snapshot collector and PPT
  requirements (10 files incl. `.gitattributes`: `* text=auto eol=lf`, `*.pdf binary`).
- `67af42d` docs: establish master CLAUDE.md architecture and ML contracts. The
  lowercase `claude.md` (never committed) was retired and archived verbatim
  (sha256 `9fddf4b7…`) at `docs/archive/claude-md-m0-superseded.md`.

## 2026-10-19 — M1 telemetry foundations (uncommitted)

### Changes
- **C collector** split into `src/procfs.{c,h}` (pure parsers: stat, status, io,
  cgroup v2), `src/jsonl.{c,h}` (UTF-8-safe JSON escaping) and `src/collector.c`.
  - No-argument mode keeps the M0 schema; parsing fixes apply to both modes.
  - `--v1 [--interval-ms N] [--count K]`: schema-v1 samples (`sample_begin`,
    `proc`, `sample_end`), CLOCK_MONOTONIC per record, absolute-deadline sleeping
    with `late_ns`, flush per sample, SIGTERM/SIGINT finish the current sample,
    `PR_SET_PDEATHSIG` plus `PPC_SUPERVISOR_PID` race check, SIGPIPE ignored →
    exit 3 on a closed stdout, exit 2 on bad arguments.
  - Unreadable values are `null` + `*_err` (`EACCES`, `ENOENT`, `ESRCH`, `EPARSE`,
    `EIO`, `UNSUPPORTED`); gap counters in `sample_end`.
- **Defect fixes:** D1 (read whole file), D2 (valid UTF-8 kept, invalid bytes →
  U+FFFD, `comm_utf8_valid` flag), D3 (strict unsigned parsing), D4 (C unit tests),
  D5 (64-byte comm + `comm_truncated`), D6 (gap counters, exit codes, stdout error
  check), D7 for v1 (`readdir_err`).
- **Schema** `processpulse/schemas/telemetry.v1.json` ($defs: process_key,
  container_identity, sample_begin, proc, sample_end, syscall_snapshot, health);
  stdlib validator `processpulse/validate.py` with cross-field rules.
- **Python package** `processpulse/`: `jsonl.py` (framing), `identity.py`
  (ProcessKey, Docker cgroup parsing, CgroupResolver with stale flag),
  `resource.py` (supervisor: restart/backoff/epoch, drop-oldest backpressure),
  `syscalls.py` + `bpf/{calibrate,syscall_counter}.bpf.c` (per-syscall tracepoints
  for the execve/open/clone families, in-kernel identity with namespace-inode check,
  two-phase exit reclaim, self-exclusion, health counters), `preflight.py`
  (root/BCC/tracefs/tracepoints/headers; attempts `modprobe kheaders` when root),
  `agent.py` (records resource/syscall/health JSONL + manifest).
- **Environment:** `tools/setup_py312_env.sh` installed user-level `uv` 0.13.1 and
  CPython 3.12.15 → `~/.venvs/processpulse-py312`
  (`requirements/py312-dev.txt`: pytest 8.4.2, jsonschema 4.25.1).
  No system packages installed in this step.
- Build: `Makefile` targets `helpers`, `test-c`, `test-py`, `test-privileged`,
  `check`; `.gitignore` adds `build/`, `results/raw/`; `pytest.ini` adds
  `pythonpath` and markers.

### Defects found and fixed during M1 work
- BPF `comm` was captured at the first event (the pre-exec `execve`), so it showed
  `python3`. Fix: refresh comm on every event.
- Parent-death race: a supervisor killed before the collector armed PDEATHSIG went
  undetected (failed under Python 3.14). Fix: `PPC_SUPERVISOR_PID`. Afterwards
  20/20 passes per interpreter.
- Self-exclusion race: a newly spawned collector's pre-exec `execve` was counted
  before exclusion. Fix: `exclude()` purges existing entries and counts them as
  self-excluded.
- Agent duration started before preflight and BCC compilation (0 samples in a 2 s
  run). Fix: the deadline starts when collection starts.

### Validation (commands and results)
- Test-first: new D1/D2/D6 tests run against the M0 binary rebuilt from `795c945`
  → 3 failed, 1 passed (legacy schema shape), as expected.
- `make clean; make all helpers; make check` → 0 warnings.
- `make test-c` → `test_procfs: 74 checks, 0 failures` (ASan+UBSan).
- `tests/test_collector.py` (M0 suite, unchanged) → 20 passed, 1 skipped.
- Unprivileged suite `pytest -m "not privileged"`: Python 3.12.15 → 81 passed,
  1 skipped; system Python 3.14.4 (`make test`) → 81 passed, 1 skipped
  (2 DeprecationWarnings from BCC's own `disassembler.py`).
- Privileged suite as root (`pytest -m privileged`) → 29 passed:
  - exact entry counts, N ∈ {1, 1000} for openat/open/execve/clone and
    N = 100000 for openat/execve/clone: deltas exact, other syscalls 0;
  - start_ticks equal to `/proc/<pid>/stat` field 22 for 1000/1000 processes;
  - exit reported once then reclaimed; self-exclusion; namespace-inode mismatch →
    unresolved, never attributed; map-full counted; `bpf_ktime_get_ns()` falls
    between userspace `time.monotonic_ns()` reads (20/20);
  - agent end-to-end: streams aligned 1:1, records schema-valid, own processes excluded.
- **DIT-1:** three consecutive independent runs → 7/7 checks each; 0 leftover containers.

### Pending at that point (completed in the next entry)
- 10-minute run, 10/10 exact-count repetitions, overhead matrix.

### Known limitations
- `comm` in syscall snapshots is the comm of whichever thread made the most recent
  counted call; threads can carry different names.
- Syscall counts are entry attempts, not successes; 32-bit compat syscalls are not counted.
- Processes outside the distro pid namespace (WSL init, other distros) count only
  as `unresolved_events`.

## 2026-10-19 — M1 acceptance

Full evidence: `results/acceptance/m1/README.md`. Product code was unchanged
during this step; earlier evidence (unprivileged 81 passed on py3.12/3.14,
privileged 29 passed, DIT-1 three consecutive passes) stayed valid and was not
re-run for reassurance.

### Changes
- `tests/test_syscall_collector.py`: the exact-count tests record `expected` /
  `observed` via `record_property` (assertions unchanged) so every repetition's
  values are kept in JUnit XML.
- New `tools/acceptance/`: `validate_run.py` (validates every record of a run:
  schema, framing, alignment, span, clean collector stream; reports loss counters
  separately), `run_10min.sh` (background agent + polling monitor + SIGTERM +
  validation), `exact_counts.sh` + `summarize_exact_counts.py` (10 independent
  repetitions), `overhead.py` (3 × 3 × 5 matrix, plus an `--abba` order-balanced check).
- Evidence files under `results/acceptance/m1/` (small); raw telemetry stays in
  the gitignored `results/raw/`.

### Results
- **A. 10-minute run — PASS.** 612.0 s span, 27 803 / 27 803 lines schema-valid,
  613 aligned samples, SIGTERM → rc 0, 0 leftover processes, clean collector stream.
  Validator negative tests: all corruptions rejected.
- **B. Exact counts — PASS.** 11 configurations × 10 independent runs = 110 / 110 exact
  (N = 1 and 1000 for openat/open/execve/clone; N = 100 000 for openat/execve/clone).
- **C. Overhead — PASS (measured).** 45 / 45 instrumented runs + 10 baselines, rc 0,
  0 dropped samples, 0 map-full. Agent + collector CPU: idle 0.23 % (5 s) / 0.80 % (1 s) /
  2.97 % (250 ms) of one CPU; churn (~930 processes/s) 8.9–11.0 %. BPF in-kernel time:
  ≤ 0.034 % idle, ≈ 1.42 % under churn (≈ 0.5 µs/event idle, ≈ 2.3–2.5 µs/event under
  churn). Collector RSS ≈ 2 MB; agent RSS ≈ 219 MB (BCC/LLVM).
  **Limitation:** the workload-throughput change against the baseline is confounded by
  run order and is not attributable to the agent. The order-balanced re-check was stopped
  by Claude Code because the host was low on memory (not a failure, not restarted); its
  13 completed runs are inconclusive. No performance target is defined for M1.

### Observations
- WSL's `init` (pid-namespace level 0) calls `open` once per process created in the
  distro; those events are correctly counted as unresolved (diagnosed with reason codes).
- The harness's temporary `kernel.bpf_stats_enabled=1` was left set when the ABBA job was
  killed; it was restored to the original 0 and verified.
- Tier-1 smoke runs checked the harnesses: a 20 s monitor run before A started, and a
  3 s-window overhead run while A and B were running. Their evidence files were
  overwritten and are not counted. The overhead smoke's numbers were visibly contaminated
  by the concurrent runs, which is why C ran alone.

## 2026-10-19 — M1b S0: framing rule and v2 BPF snapshot protocol (uncommitted)

Scope: stage S0 of the M1b plan v3 only (decisions A1 framing, A2 snapshot
contract D1–D6, A3 keyframe interval 60). No BPF program, kernel hook, C
source or Makefile changed; no S1–S7 functionality.

### Defect addressed
- **F1 (M1 limitation):** 15 of 613 `syscall_snapshot` lines of the accepted M1
  10-minute run exceed the 65,536-byte limit; the largest record is 311,053 bytes
  without its LF (the planning reports said 311,054, which counted the LF).
  Neither the agent writer nor `validate_run.py` checked line length. M1's
  acceptance is not re-judged.

### Changes
- `processpulse/jsonl.py`: `MAX_RECORD_BYTES`, `line_violations()` (oversize,
  CR, LF, empty; counted on bytes), `encode_record()` / `RecordTooLarge`. The v1
  stream framer is unchanged (still tolerates a trailing CR).
- **Schema v2** `processpulse/schemas/telemetry.v2.json` (new; `v: 2`):
  `bpf_snapshot_begin`, `bpf_proc`, `bpf_reclaimed`, `bpf_snapshot_end`. Shared
  definitions are copied verbatim from v1; `telemetry.v1.json` is unchanged
  (sha256 `770913bf…` pinned by a test).
- `processpulse/validate.py`: dispatch on record type to the defining schema
  version; `maximum` keyword; v2 cross-field rules; `v2_proc_semantic_errors()`.
- `processpulse/snapshots.py` (new): `V2Emitter` (cumulative counters per epoch,
  changed-only emission with keyframes per the rule in "Keyframe correction"
  below, explicit removals
  with reason exited / self_excluded / vanished, `tracked` + per-syscall `totals`
  mod 2^64, failed snapshots, commit after write, removal lists split to stay
  within the byte rule) and `Reconstructor` (whole-snapshot application,
  rejection of incomplete or inconsistent snapshots, seq-gap and epoch
  handling, invalid-until-keyframe, "omitted = unchanged" only while valid,
  `loss_possible`).
- `processpulse/syscalls.py`: `track_removals` option (default off) records keys
  deleted by exit reclaim and self-exclusion purge for `take_removed()`;
  `last_unreported`. The v1 `syscall_snapshot` record and the BPF program are
  unchanged; without `track_removals` nothing accumulates.
- `processpulse/agent.py`: `--schema {1,2}`, default 1 (M1 behaviour and the M1
  harnesses `run_10min.sh` / `overhead.py` unchanged). With 2: `bpf.jsonl`,
  every line written through `encode_record()`, commit after write+flush,
  failed snapshots counted, manifest `output_schema` / `bpf_stream`.
- `tools/acceptance/validate_run.py`: per-line byte rule; v1 mode reports
  `legacy_v1_oversize` / `legacy_v1_cr` without changing the verdict; v2 mode
  (auto-selected by `bpf.jsonl`) enforces the rule on every line and checks
  the snapshot protocol with the `Reconstructor`.
- `tools/acceptance/run_s0_10min.sh` (new): T-F6 run + crash-truncation check.
- Docs: `docs/telemetry-v2.md` (new), `CLAUDE.md` §1 and §5, `README.md`.

### Validation (commands and results)
- Baseline before any change: `make test` → 81 passed, 1 skipped.
- Test-first: the new test modules failed at import before implementation
  (`ImportError: cannot import name 'MAX_RECORD_BYTES'`).
- `make test` (system Python 3.14.4; includes `test-c` 74 checks, 0 failures) →
  201 passed, 1 skipped (M0 `test_minimum_record_count`, D8).
- `~/.venvs/processpulse-py312/bin/python -m pytest tests/ -m "not privileged"` →
  201 passed, 1 skipped.
- `make check` → rc 0, no warnings.
- As root, `PYTHONUSERBASE=/home/mypc/.local make test-privileged` → 34 passed
  (M1: 20 syscall-collector, 7 DIT-1, 1 preflight, 1 agent; new: 1 agent v2,
  4 snapshot/BPF), 0 leftover containers, `bpf_stats_enabled` 0. An earlier run
  of the same suite (33 passed) preceded the `track_removals` change and is
  superseded.
- T-F6 `run_s0_10min.sh 600` as root: 10-minute v2 run valid (23,271 / 23,271
  lines, longest 2,100 bytes, 616 complete snapshots, 11 keyframes, 0
  incomplete / gaps / invalidations / mismatches, span 615.006 s). The script's
  crash-truncation check was defective (removed nothing on an idle final
  snapshot); fixed and re-run with `--negative-only` → truncated copy rejected
  (rc 1). Details: `results/acceptance/m1b/s0/README.md`.
- Recorded M1 run: validates unchanged (27,803 / 27,803) with
  `legacy_v1_oversize = 15`.

### Known limitations
- The agent default is still schema 1; switching it is a separate decision.
- The 10-minute v2 run was on an idle system (few processes); large
  populations are covered by unit tests only.
- T-F5 (C collector worst-case record < 64 KiB) is computed from source
  constants and checked against real output; no real 4 KiB cgroup path ran.
- The consumer has no partial recovery before a keyframe; the producer forces a
  recovery keyframe only after its own failed scheduled keyframe or uncommitted
  snapshot (it cannot see consumer-side losses).
- Not run: `--abba` overhead re-check, overhead matrix for v2, DIT-1 three
  consecutive runs (one DIT-1 pass inside the privileged suite).

### Keyframe correction (review, same day, uncommitted)
- **Defect:** the emitter used `keyframe = status ok and seq % 60 == 0`. A failed
  seq 0 (or any failed scheduled keyframe) left no keyframe until 60 snapshots
  later, and a test asserted that behaviour.
- **Rule now** (`processpulse/snapshots.py`, `docs/telemetry-v2.md` §3):
  keyframe(seq) ⇔ status ok ∧ (seq mod 60 = 0 ∨ due); `due` is set at the epoch
  start, when a seq-mod-60 snapshot fails, and when the previous snapshot was not
  committed; cleared only when a keyframe is committed. The cadence stays on
  `seq mod 60`. One emitter serves one epoch (re-attach raises).
- **Consumer:** `keyframe_schedule_violations` counts a missing required keyframe
  (from an observed epoch start or failed scheduled keyframe, and every
  successful seq-mod-60 snapshot), once per miss; `validate_run.py` fails on it.
- **Approved decisions recorded:** default `--schema 1`; re-emit on any field
  change; removal reasons `self_excluded` (distinct from exit) and `vanished`
  (loss).
- **Validation:** new or changed tests failed first (12 failed, 45 passed in
  `tests/test_snapshots.py`), then `tests/test_snapshots.py`
  `tests/test_validate_run.py` `tests/test_schemas_v2.py` → 111 passed;
  `make test` → 213 passed, 1 skipped (74 C checks, 0 failures); py3.12 venv →
  213 passed, 1 skipped; as root `make test-privileged` → 34 passed, 0 leftover
  containers, `bpf_stats_enabled` 0. The recorded 10-minute v2 run was
  re-validated with the corrected validator (not re-run; the changed emitter
  paths, failures and uncommitted snapshots, did not occur in it): ok,
  0 keyframe schedule violations; its truncated copy is still rejected.

## 2026-10-19 — M1b S0 accepted and committed

- `d9b9e9b` feat(m1b): implement S0 telemetry v2 framing, validation, and snapshot
  protocol — 28 files staged by explicit path; the 15 intentional M1 logs and
  `results/raw/` excluded. Accepted limitations: the 10-minute v2 evidence
  predates the keyframe correction (re-validated, not re-run); no end-to-end
  `validate_run.py` test for keyframe schedule violations.

## 2026-10-19 — M1b S1: unified, capability-flagged BPF collector (uncommitted)

### Changes
- `processpulse/vocab.py` (new): ordered syscall vocabulary with canonical JSON
  serialisation and `id` = `v<version>-<sha256[:12]>`; current `v1-3aba869d1752`
  (the M1 set, unchanged).
- `bpf/common.h` (new): process key (M1 layout), `resolve()`, exclusion map,
  per-thread slot map, health array (M1 indices 0–4 unchanged, 5–8 new).
  `bpf/syscall_counter.bpf.c` is now the "counts" capability (map layouts
  unchanged); `bpf/core.bpf.c` (new) holds the scheduler hooks and dispatches
  to compiled-in capabilities.
- `processpulse/bpf_collector.py` (new): `BpfCollector` — 2 compilations per start
  (calibrate, unified), capability selection (`counts` only; `bigrams`, `priv`,
  `net` reserved and refused), attached tracepoints checked against
  `required_tracepoints()`, `build_info()`, `thread_slots()`, `thread_health()`.
  `processpulse/syscalls.py` is now the M1 interface over it (`SyscallCollector`
  = counts only). `processpulse/preflight.py` checks every attached tracepoint
  (adds `sched/sched_process_exec`).
- **F4:** per-thread slots created on attributed events, deleted at every thread
  exit and for the old TID on non-leader exec; stale-TID detection; purged with
  self-exclusion. Counters via `thread_health()` (not in v1/v2 records).
- **F9:** `comm` and `cgroup_id` captured at entry creation and refreshed at
  `sched_process_exec` instead of on every event; not refreshed by
  `prctl(PR_SET_NAME)` or a cgroup move without exec (documented, tested).
  `last_ktime` is still per event.
- `tests/helpers/sysc_helper.c`: `tspawn`, `tjoin`, `exec`, `texec`, `rename`
  commands (M1 commands unchanged); `Makefile` builds it with `-pthread`.
- `tools/acceptance/s1_equivalence.py` (new); docs `docs/bpf-collector.md` (new),
  `CLAUDE.md` §1.

### Validation
- Pre-S1 baseline captured on the S0 code before any S1 edit
  (`results/acceptance/m1b/s1/equivalence-pre-s1.json`).
- `make test` → 245 passed, 1 skipped (D8); py3.12 venv → 245 passed, 1 skipped;
  74 C checks, 0 failures; `make check` rc 0.
- As root `make test-privileged` → 42 passed, 0 leftover containers.
- Equivalence post-S1: 33 of 34 fields identical; `attached_tracepoints` 10 → 11
  (added `sched_process_exec`).
- First privileged run of the new S1 tests: 2 failed because the tests compared
  slot TIDs (host-namespace map keys) with distro PIDs; fixed by recording the
  distro TID in the slot (informational) and comparing that → 8 passed.
- Not run: `--abba`, overhead matrix, 10-minute run, DIT-1 ×3, 10× exact counts.

## 2026-10-19 — M1b S1 committed

- `391c988` refactor(m1b): implement S1 unified bpf compilation and per-thread
  lifecycle tracking (recorded here afterwards; verified with `git log`).

## 2026-10-19 — M1b S2.1: bigram records in schema v2 and the Reconstructor (uncommitted)

Contract: S2 design report (recovered from the M1b planning session) with the
approved decisions A8 and U1–U10. Step 1 of the S2 sequence only: no BPF,
emitter, agent or kernel change.

### Schema change (additive, `v` stays 2)
- Approved as U1 ("extend telemetry v2 additively; preserve existing S0
  compatibility"), as an exception to the CLAUDE.md §5 rule that a schema
  change bumps `v`.
- `telemetry.v2.json`: new type `bpf_bigrams` (`key`, `part`, `parts`,
  `pairs: [{a, b, n}]`, `maxItems` 1,024; `a` ∈ vocabulary ∪ 4 markers, `b` ∈
  vocabulary: I-B5 as a schema rule; `n` ≥ 1); optional
  `capabilities.bigrams`; optional `bpf_proc.pairs_lost` / `bigrams_err`;
  optional end fields `bigram_records`, `totals.bigrams`, `bigram_health`
  (U4/U10 counters), `drained`. All new fields present iff the capability is
  selected. v1 schema untouched (sha256 test unchanged).
- `processpulse/validate.py`: `maxItems` keyword; `bpf_bigrams` dispatch;
  cross-field rules (part < parts, empty only as a single part, no duplicate
  pair, value-xor-error for `pairs_lost`, capability ok/unavailable shape,
  bigram epoch = counts epoch, all-or-none end fields, failed snapshot carries
  no bigram data).
- `processpulse/snapshots.py`: `chunk_records(max_items=)`, `bigram_parts()`,
  `bigram_totals()`, Reconstructor support (section order, part sequence and
  contiguity, table ↔ `bpf_proc` pairing, replace-not-merge, totals
  cross-check, capability fixed per epoch, `snapshots_after_drain`,
  `SnapshotView.drained` / `pair_loss_possible`, `Reconstructor.pairs`).
- Tests: `tests/test_bigram_records.py` (new), `tests/snapshot_fakes.py`
  (`BigramFake`, `BigramStandIn`, a test-only producer around `V2Emitter`),
  one comment and one extra invalid fixture in `tests/test_schemas_v2.py`.
- Docs: `docs/telemetry-v2.md` §8.

### Validation
- Baseline before any edit (HEAD `391c988`): `make test` → 245 passed,
  1 skipped; py3.12 venv → 245 passed, 1 skipped; recorded S0 10-minute v2 run
  (`results/raw/m1b-s0-10min-20261019T042927`) → `validate_run.py` rc 0,
  23,271/23,271 lines valid, 616 complete snapshots, 11 keyframes, 0 protocol
  errors.
- New tests failed before the implementation (ImportError), then passed.
- After: `make test` → 74 C checks, 0 failures; 360 passed, 1 skipped (D8);
  py3.12 venv `make test-py` → 360 passed, 1 skipped; `jsonschema`
  cross-checks ran on both (4.19.2 / 4.25.1); `make check` rc 0, 0 warnings.
- Recorded S0 run re-validated with the new code: verdict, line counts and
  every protocol counter identical to the baseline; the only report difference
  is the new `snapshots_after_drain` = 0; `bpf.jsonl` sha256 unchanged.
- Not run (out of scope for S2.1): privileged suite, any BPF or agent run.

## 2026-10-19 — M1b S2.2: bigram decoder and invariant checkers (uncommitted)

Step 2 of the S2 sequence. No BPF, emitter, agent or kernel change.

### Resolved contract points (docs/telemetry-v2.md §8.5)
- A: I-B2 terms defined: `purged_C` = `purged_counts`, `purged_B` =
  `purged_pairs` + `purged_pairs_lost`; counted keys = live keys at the drain
  plus keys reclaimed as `exited` (last emitted values); `self_excluded` keys
  only through the purge totals. Producer requirement P-PURGE recorded.
- B: producer invariant P-ZERO (sparse tables, n = 0 entries dropped, not loss).
- C: S2.1 names and the one-empty-part representation kept unchanged.
- D: capability status fixed per epoch; no `ok → EIO` transition defined.

### Changes
- `processpulse/bigrams.py` (new): code/name decoding (0–8 syscalls, 9–12
  markers), `decode_pair`, `decode_entries` (drops and counts n = 0 entries),
  `Result` with PASS / FAIL / NOT_APPLICABLE, `check_ib5`, `check_ib1`,
  `check_ib1_prime`, `check_ib3_prime`, `check_ib3_exact`, `check_ib4_exact`,
  `check_ib2_drained`, `check_quiescent_reports`, oracle `expected_pairs`.
- `processpulse/snapshots.py`: Reconstructor keeps `retired` (reason, last
  payload and table of removed keys), `epoch_intact` and `last_ok_end`.
- `tests/test_bigrams.py` (new); `docs/telemetry-v2.md` §8.4 rule 7, §8.5, §8.6.

### Finding
- I-B2 is the sum of the per-key I-B1′ identities plus the purge terms, so it
  cannot detect a missing or duplicated key whose own values balance (tested
  and documented). It does detect wrong purge totals, a key whose final
  values do not balance, and a counted entry with neither pair nor loss.

### Validation
- `make test` (py3.14.4) → 74 C checks, 0 failures; 472 passed, 1 skipped (D8);
  py3.12 venv `make test-py` → 472 passed, 1 skipped; `tests/test_bigrams.py`
  → 112 passed on both; `make check` rc 0, 0 warnings.
- Recorded S0 10-minute run re-validated: identical to the S2.1 baseline
  (only `snapshots_after_drain` = 0 added); `bpf.jsonl` sha256 unchanged.
- Synthetic data only; no privileged, BPF or agent run.

## 2026-10-19 — S2.1/S2.2 audit fixes, then M1b S2.3: BPF bigram capability (uncommitted)

### Audit fixes (S2.1/S2.2 read-only audit, minor findings 1–6)
1. `Reconstructor.feed`: `AttributeError` from malformed records (e.g. a
   non-object `capabilities`) is now an incomplete snapshot, as in S1, not an
   uncaught exception. Test: `test_malformed_capabilities_reject_the_snapshot_without_raising`.
2. The drop-middle, drop-last and duplicate-part tamper fixtures keep
   `bigram_records` consistent. A new test pins each rejection to its
   part-sequence reason.
3. New tests: a reclaim listed inside a keyframe is retired; `epoch_intact`
   holds when snapshot 0 fails and seq 1 is the keyframe, and is lost when the
   first successful snapshot is not a keyframe.
4. `bigrams.check_ib2_ground_truth` (the v2 §4 form of I-B2: both sides equal
   the observed entries counted by the script, plus `counts_map_full`). It
   detects a missing (−2) and a double-counted (+3) process that plain I-B2
   cannot see.
5. `CLAUDE.md` §5: the additive-extension exception (U1) is recorded next to
   the versioning rule.
6. `EIO` is reserved: `$defs/bigram_err` = {`UNSUPPORTED`, null} for
   `capabilities.bigrams.err` and `bpf_proc.bigrams_err` (schema-v2 change,
   still additive and unreleased). Docs updated.

### S2.3 changes
- `bpf/bigrams.bpf.c` (new): `bigrams` map (`max_pairs`, default 131,072), `bglobal`
  (arming, last slot-map-full time), markers 9–12, slot classification,
  R-LOSS rows 1–3 and pre-arm accounting, EXEC at `sched_process_exec`.
- `bpf/common.h`: health 9–11 (`bigram_map_full`, `bigram_dropped`,
  `pre_arm_events`), `tslot.prev` (from the padding; size unchanged),
  `thread_touch()` returns the slot and whether it was created.
- `bpf/syscall_counter.bpf.c`: `pairs_lost` in the counts value and the
  bigram hooks, both only under `PPC_CAP_BIGRAMS`. `bpf/core.bpf.c`: exec hook.
- `processpulse/bpf_collector.py`: capability `bigrams` (requires `counts`;
  `priv`/`net` still reserved), source order, `arm()`, `read_bigrams()`
  (grouped by process, then decoded; zero and orphan entries counted),
  `bigram_health()`, the reclaim fingerprint (counts, `pairs_lost`, pair
  sum) with deletion of pair entries, pair purge in `exclude()`,
  `map_memory()` in `build_info()`.
- Tests: `tests/test_bpf_collector_unit.py` (rewritten for two capabilities),
  `tests/test_bigrams_bpf.py` (new, 16 privileged). Docs:
  `docs/bpf-collector.md` (S2.3 section).

### Validation (commands in the S2.3 review report)
- Unprivileged suite: 502 passed, 1 skipped (D8) on py3.14 (`make test`, 74 C
  checks, 0 failures) and on py3.12; `make check` rc 0, 0 warnings.
- As root, `pytest tests/ -m privileged` → 58 passed (S1's 42 + 16 new) in 247 s;
  `bpf_stats_enabled` 0 before and after; 0 `ppc-*` cgroups; 0 containers.
- Counts-only equivalence (`tools/acceptance/s1_equivalence.py` as root) vs
  `results/acceptance/m1b/s1/equivalence-post-s1.json`: 34 of 34 fields identical.
- Measured once: unified compile 6.70 s, calibrate 9.81 s; `bigrams` map
  memlock 12,585,664 bytes (131,072 entries); batch lookup works (H-BATCH);
  fdinfo reports `memlock` (H-MEMLOCK).
- Not run: `--abba`, overhead, 10-minute run, DIT-1 ×3, repeated exact counts
  (S2.4 scope).

## 2026-10-19 — M1b S2.4: exact-check preconditions and repeated scripted acceptance (uncommitted)

### Phase 1: global-loss precondition (S2.3 audit, finding 1)
- `processpulse/bigrams.py`: `check_ib3_exact` and `check_ib4_exact` take
  `losses`, the increases of `counts_map_full`, `thread_map_full`,
  `bigram_map_full` and `pre_arm_events` over the window the claim covers.
  They return NOT_APPLICABLE when it is missing or any counter rose. New
  helpers: `loss_window()`, `epoch_losses()` (epoch-relative values from the
  last end record) and `GLOBAL_LOSS_FIELDS`. `BpfCollector.global_losses()`
  reads the four counters. The equations and the other checks' preconditions
  are unchanged.
- Regression: the audited row-1 case (`pairs_lost` 0, a `START_LOST` pair)
  gave a false FAIL and now gives NOT_APPLICABLE, both synthetic and on a
  real helper (`test_row_1_counts_map_full`).
- New `check_ib2_ground_truth_scope`: the ground-truth equation of I-B2 over
  a closed scope of quiescent scripted processes, with their purge totals.
  It is usable before the drain exists. Row-1 losses cannot be attributed to
  a scope, so it is NOT_APPLICABLE when `counts_map_full` rose.

### Phase 2: test gaps (S2.3 audit, finding 6)
- `tests/test_bigrams_bpf.py`: the v1 record stays schema-valid in a bigrams
  build; an exec with a full thread map raises `thread_map_full` and loses
  exactly one pair (the execve entry's); a thread-map-full event before arming
  is counted once (`pairs_lost` = entries, Δ`bigram_dropped` =
  Δ`pre_arm_events`); the global-loss precondition holds on the real row-1
  case.

### Phase 3: documentation and evidence
- Correction: the S2.3 report gave the total BPF map memory as "≈ 20.7 MiB".
  The measured total is 20,730,392 bytes = **19.77 MiB (20.73 MB)**
  (`docs/bpf-collector.md`; the bucket array and per-CPU spare elements
  explain the gap to the 10 MiB design estimate).
- `docs/telemetry-v2.md` §8.3: requirement for the S2.6 emitter. Its change
  detection must include the pair table and `pairs_lost`, because design
  §3.7's "a pair change implies a count change" is false for live reads.
- `results/acceptance/m1b/s2.3/`: the S2.3 evidence that existed as files
  (build info, map memory, per-path loss results, counts-only equivalence,
  S0-run re-validations) with a README. Test totals and cleanup state were
  only seen as command output; they are transcribed and marked as such.
- The purge race (S2.3 audit, finding 2) stays **OPEN, required before S2.5**
  (`docs/bpf-collector.md`, known limitations).

### Phase 4: repeated scripted acceptance
- `tests/test_bigrams_acceptance.py` (14 privileged configurations): the
  complete pair table and counts of a real helper equal the script's oracle,
  for openat/open/execve/clone × N ∈ {1, 1000} and openat/execve/clone ×
  N = 100,000, a mixed sequence, an exec, and a three-helper ground-truth scope
  with an exit and a purge. Each configuration also checks I-B5, I-B1, I-B1′,
  I-B3′, exact I-B3/I-B4, the scoped I-B2 ground truth, zero global losses and
  no stale slot.
- `tools/acceptance/bigram_exact.sh` + `summarize_bigram_exact.py`: 10
  repetitions in fresh processes, each followed by the S1 equivalence probe.
- **Result: 10 of 10 for all 14 configurations; equivalence 34 of 34 fields in
  10 of 10** (`results/acceptance/m1b/s2.4/exact/summary.md`).

### Validation
- Stored logs in `results/acceptance/m1b/s2.4/regression/`:
  - `make test` (py3.14) → 74 C checks, 0 failures; 521 passed, 1 skipped (D8);
  - py3.12 `make test-py` → 521 passed, 1 skipped;
  - `make check` rc 0;
  - root `pytest tests/ -m privileged` → 75 passed; `bpf_stats_enabled` 0;
    no cgroups or containers left.
- Not run: `--abba`, overhead, drain, emitter, whole-epoch I-B2 (S2.5/S2.6).

## 2026-10-19 — Exclusion-purge race fixed (S2.3 audit, finding 2; before S2.5; uncommitted)

### Root cause
1. `BpfCollector.exclude()` read and deleted the process's entries right
   after setting the exclusion, with no guarantee that probe invocations
   which had already passed the check had finished. Their late updates could
   be lost from the purge totals, recreate an entry, or land in a deleted
   element that a preallocated hash map had already reused for another key.
2. The `sched_process_exit` hook wrote `info.exited` without checking the
   exclusion, so it could race the purge even when it began afterwards.
   Shown deterministically before the fix: an excluded process's info entry
   got `exited = 1`.

### Fix
- `bpf/core.bpf.c`: the exit hook checks the exclusion before
  `counts_on_exit`, after deleting its own thread slot. Every BPF writer of a
  process's entries now checks the exclusion first.
- `processpulse/bpf_collector.py`: `rcu_barrier()`
  (`membarrier(MEMBARRIER_CMD_GLOBAL)`, for which the kernel runs
  `synchronize_rcu()`; raises if unsupported). `exclude()` now sets the
  exclusion, calls `rcu_barrier()`, then reads and deletes.
- Basis: programs on these tracepoints run in `trace_call_bpf()` under
  `rcu_read_lock()` with preemption disabled. This is kernel-source
  reasoning, not inspected on this build; `CONFIG_PREEMPT_RCU=y`, and the
  query mask includes the command.

### Tests
- `tests/test_bpf_collector_unit.py`: exclusion then barrier then purge
  (counts-only and bigrams builds); barrier failure handling; the exit-hook
  gate's position in the source.
- `tests/test_exclusion_purge.py` (new, 5 privileged): an idle exclusion with
  exact purge totals; 10 exclusions of busy helpers while another stays exact;
  20 exclusions right after `Popen`, as the agent does; the exit-hook gate
  (failed before the fix, passes after); a counts-only build with busy
  exclusions.
- The busy-exclusion tests also passed on the unfixed code, so the race was
  not reproducible there; they are regression checks.

### Validation (`results/acceptance/m1b/purge-race/`)
- Purge tests: 5 passed twice (194.55 s, then 49.06 s; the difference is host
  load, the barrier costs 8–28 ms).
- Root `pytest tests/ -m privileged`: 80 passed; `bpf_stats_enabled` 0; no
  cgroups or containers left.
- Counts-only equivalence: 34 of 34 fields identical to S1.
- `make test` (py3.14): 74 C checks, 0 failures; 525 passed, 1 skipped.
  py3.12 `make test-py`: 525 passed, 1 skipped. `make check` rc 0.

## 2026-10-19 — M1b S2.5: final drain (detach, barrier, double read) (uncommitted)

Contract: decision U3 (approved with A8/U1–U10): detach every probe, keep the
maps, read twice and require equal reads before any I-B2 claim (hypothesis
H-DRAIN); design §3.6 (`drain()` in the collector), §4 test matrix row
"I-B2 drained". No schema, emitter, agent or BPF-source change: writing
`drained: true` into the end record is S2.6.

### Changes
- `processpulse/bpf_collector.py`:
  - `drain()`:
    1. detaches every tracepoint (BCC `detach_tracepoint`, syscall probes
       first) and fails if any stays attached;
    2. calls `rcu_barrier()` (the purge's `membarrier(MEMBARRIER_CMD_GLOBAL)`)
       and fails if it fails;
    3. reads every map a probe writes (`counts` with `pairs_lost`, `info`
       with `last_ktime`, `threads` with `prev`, `bigrams`, `bglobal`, all
       health counters) plus the userspace purge and reclaim totals, twice.

    Equal reads mean `drained`; unequal reads mean `unstable` (no claim,
    `changed` lists the maps); any failure is `failed`. A retry re-runs all
    three steps, including the barrier.
  - `accounting` (bigrams only, only when drained) holds the I-B2 terms of
    the stable read, with copies of the reclaim and purge totals;
    `drained_processes()` gives per-key values for the quiescent checkers.
  - `reclaimed_totals` (counts, pairs, `pairs_lost` of keys removed by the
    two-phase exit reclaim; a key whose counts entry is already gone adds
    nothing).
  - Epoch end:
    - `exclude()` is refused once `drain()` starts (a lock serialises them);
      the purge body is unchanged (now `_exclude()`, flag → barrier → purge);
    - after a successful drain exactly one `snapshot()` is allowed (the
      drained snapshot): its read must equal the drain's, and it sets
      `last_snapshot_drained`;
    - a later `snapshot()`/`drain()` raises.
- `processpulse/bigrams.py`: `check_ib2_drain_read()`. It is the approved
  I-B2 equation (S2.2 §8.5 A) on the drained read, with live terms from the
  maps and reclaimed terms from `reclaimed_totals`. A pair entry without a
  counts entry is a FAIL.
- Docs: `docs/bpf-collector.md` "Final drain" (steps, source argument from
  tag `linux-msft-wsl-6.18.33.2`, `perf_event_detach_bpf_prog` at
  `kernel/trace/bpf_trace.c:1950-1972`, state rules); `docs/telemetry-v2.md`
  §8.4 rule 5 and §8.6 table.
- Audit correction made before acceptance: a first version accepted any two
  consecutive equal reads out of up to five. U3 says "read twice"; reads
  after an unequal pair have no new barrier behind them, so the drain now
  reads exactly twice. The superseded runs on that version are kept under
  `results/acceptance/m1b/s2.5/superseded/`.

### Tests
- `tests/test_drain_unit.py` (new, 26, unprivileged, fake BCC objects):
  - order: detach, then barrier, then reads;
  - a change seen only by the second read means unstable, and the retry
    waits for a new barrier;
  - a late `bglobal`-only write is detected; maps that keep changing never
    drain;
  - detach, barrier and read failures;
  - empty vs non-empty pair maps; live/reclaimed/purged accounting, and
    FAILs by exactly a missing or double term; orphan pair entries FAIL;
  - reclaim bookkeeping; the drained snapshot (cross-check, last,
    reclaim inside it without double counting); `exclude()` refused;
  - counts-only drain and the unchanged v1 snapshot.
- `tests/test_drain_bpf.py` (new, 7, privileged):
  - a drain detaches all 11 probes (11 fewer perf_event fds) and the maps
    stay unchanged while traced processes keep running;
  - a drain during busy openat/execve/clone loops (3 repetitions) is stable,
    and I-B5/I-B1′/I-B3′/I-B1 and I-B2 hold;
  - ground truth with live, exited, reclaimed and purged helpers, exact;
  - two reads of an attached program under activity differ;
  - counts-only drain.

### Validation (`results/acceptance/m1b/s2.5/`)
- Baseline before any change: `make test` 525 passed, 1 skipped. The new
  unit tests failed (26 of 26) before the implementation.
- Root `pytest tests/ -m privileged`: 87 passed (80 earlier + 7 new);
  `tests/test_drain_bpf.py` twice more, 7 passed each.
  - 9 of 9 busy drains: `drained` at read 2, with the helpers cut off
    mid-loop (openat 171,011–214,344 of 3,000,000; execve 108,983–135,056;
    clone 2,107–2,381 of 40,000);
  - every key balanced (I-B5, I-B1′, I-B3′, and I-B1 with `pairs_lost` 0
    on all keys), and I-B2 on the drain read PASS;
  - ground truth 26 = 26, 3 of 3;
  - detach + barrier + reads took 1.32–1.47 s.

  `bpf_stats_enabled` 0, no cgroups or containers left.
- Counts-only equivalence: 34 of 34 fields identical to S1.
- `make test` (py3.14): 74 C checks, 0 failures; 551 passed, 1 skipped.
  py3.12 `make test-py`: 551 passed, 1 skipped. `make check` rc 0.
- Not shown: a late writer was never observed (no unequal pair after the
  barrier), so whether the barrier was necessary in these runs is not
  demonstrated; the second read's detection was shown on attached probes
  only.

## 2026-10-19 — S2.1–S2.5 committed in three commits; M1b S2.6: bigram emitter and agent integration (S2.6 uncommitted)

### Commits (authorized, option 1)
- `5f0d376` feat(m1b): implement S2.1-S2.4 bounded syscall bigram storage and map accounting
- `1f763de` fix(m1b): synchronize in-flight BPF readers before purge
- `d1d7eac` feat(m1b): implement S2.5 final-drain protocol and double-read map accounting

How the states were split:
- **Commit 1 (S2.1–S2.4):** the purge-fix edits, taken verbatim from the
  session transcript, were reversed out of the pre-S2.5 file copies.
- **Commit 2 (purge fix):** the pre-S2.5 copies.
- **Commit 3 (S2.5):** the working tree.
- Each state was staged as blobs (`git update-index`), so the working tree
  was not touched.

Verification before committing:
- Each staged index equalled a full tree that had passed `make test`: state
  A 519 passed / 3 skipped, state B 523 / 3. The two extra skips read
  gitignored `results/raw/`.
- State B also passed the privileged purge and bigram tests: 24 passed.
- Commit 3's changes are line-identical to the reviewed
  `s2.5-changes.patch` (1,209 / 1,209).
- `git diff --cached --check` findings were only blank context lines inside
  that patch file, which unified diff format requires.

Evidence: `results/acceptance/m1b/s2.6/phase1/`.

### S2.6 changes
- `processpulse/snapshots.py` `V2Emitter(bigrams=None|"ok"|"unavailable",
  bigrams_reason, max_pairs_per_record)`:
  - **tables:** the collector's `last_bigrams` (same `snapshot()` read as the
    counts) and `bigram_health()`, read before `take_removed()`. A read
    failure, or a reported process without a table, gives a `failed`
    snapshot that changes nothing and keeps removals;
  - **change detection:** a process is re-emitted, with its full table, on
    any payload change (counts, `pairs_lost`) or a pair-table change
    (S2.3 audit finding 4);
  - **order:** procs, `bigram_parts`, reclaimed, end;
  - **end record:** `bigram_records`, `totals.bigrams`, `bigram_health`,
    and `drained` = the collector's `last_snapshot_drained` and status ok;
  - **unavailable:** `pairs_lost` null + `bigrams_err` UNSUPPORTED, no
    tables, null totals and health. Without selection the S0 records are
    unchanged.
- `processpulse/agent.py`:
  - `--capabilities` / `Agent(capabilities=)`: bigrams require schema 2 and
    counts; `priv`/`net` are refused; the defaults stay schema 1 / counts;
  - `_start_bpf()`: a collector whose start fails is closed, and a failing
    close() is recorded and attached to the original exception as a note.
    Strict policy (review refinement): if bigrams were requested and their
    program (or preflight) fails, the run fails. Nothing else is started and
    no telemetry is written; the manifest says `status: failed` with the
    exact reason; `StartupError` is chained to the original error, and the
    CLI exits 1. Only `--allow-degraded` runs counts-only with bigrams
    `unavailable`, recording requested/active/failed capabilities.
    `--no-bpf` with bigrams is refused;
  - `_final_drain()` at the normal end of a bigram run: stop the resource
    supervisor and require its thread to have ended, then `drain()`, then
    exactly one snapshot after a successful drain (`resource_seq` null);
  - manifest `capabilities`, `bigrams`, `drain`. Errors during collection
    end the run without a drain; both collectors are always stopped and
    closed.
- `processpulse/resource.py`: `ResourceCollector.stopped`.
- `tools/acceptance/validate_run.py`:
  - a `resource_seq`-null final snapshot is allowed only last;
  - `snapshots_after_drain` is a protocol failure;
  - bigram runs get `check_ib2_drained` + `check_quiescent_reports` (any
    FAIL fails the run), and `--require-drained`.
- Docs: `docs/telemetry-v2.md` §8.7 (new) and status lines;
  `docs/bpf-collector.md`.

### Tests
- `tests/test_bigram_emitter.py` (20, unprivileged).
- `tests/test_agent_bigrams.py` (29, unprivileged, fake C and BPF
  collectors): strict failure, exit status, chained cause, cleanup error
  notes, preflight failure, degraded mode end to end, and failures inside
  the drained snapshot (write error, interrupt, unfittable part).
- `tests/test_bigram_chunk_limits.py` (13, unprivileged):
  - exhaustive limit sweep with exact-boundary and maximal-split checks;
  - the 1,024/1,025 boundary;
  - the widest possible part, 62,739 bytes, which fits even with its LF;
  - Unicode and escape overhead measured on the final bytes;
  - unfittable pairs refused.
- `tests/test_agent_bigrams_bpf.py` (4, privileged, the real agent):
  - the drained, balanced end-to-end run;
  - a counts-only v2 run;
  - a strict and a degraded startup failure after the program was loaded
    and attached, both returning perf_event, bpf-prog and bpf-map fds to
    their baseline.
- `tests/snapshot_fakes.py`: `BigramCollectorFake`.

### Validation (`results/acceptance/m1b/s2.6/`)
- `make test` (py3.14): 74 C checks, 0 failures; 613 passed, 1 skipped.
  py3.12 `make test-py`: 613 passed, 1 skipped. `make check` rc 0.
- Root `make test-privileged`: 91 passed; `bpf_stats_enabled` 0; no cgroups
  or containers.
- CLI runs, each with `validate_run.py` rc 0:
  - **30 s bigram run** (`--require-drained`): 1,247 bpf lines, max 1,372
    bytes; drained final snapshot; I-B2 PASS (7,200 = 7,200);
    I-B5/I-B1′/I-B3′/I-B1 PASS on 437 keys (3 live after the drain, 434
    reclaimed as exited);
  - 10 s counts-only v2 run;
  - 10 s default schema-1 run.
- Counts-only S1 equivalence: 34 of 34.
