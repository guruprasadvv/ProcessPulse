# Engineering Changelog

Verified history only. Every entry names the commands that were run and their
actual results. Dates are local (IST). "Uncommitted" means present in the
working tree but not yet in a commit.

## Milestone acceptance status

| MS | Status | Evidence |
|---|---|---|
| M0 | Accepted with documented defects | 2026-10-19 audit (below) |
| M1 | **Accepted 2026-10-19** | M1 foundations + M1 acceptance (below); `results/acceptance/m1/` |
| M1b–M7 | Not started | — |

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
