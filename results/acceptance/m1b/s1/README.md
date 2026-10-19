# M1b S1 evidence: unified, capability-flagged BPF collector (2026-10-19)

Working tree on top of `d9b9e9b` (S0), uncommitted. Design: `docs/bpf-collector.md`.
Environment as in M1/S0 (WSL2 Ubuntu 26.04, kernel 6.18.33.2, Python 3.14.4 +
BCC 0.35.0; Python 3.12.15 venv).

## Behavioural equivalence (pre-S1 vs post-S1)

`tools/acceptance/s1_equivalence.py` runs one fixed scenario through the M1
interface (`SyscallCollector`) with the M1 helper commands only, and records
normalised observations (no PIDs or times). It was run as root on the S0 code
**before** any S1 change (`equivalence-pre-s1.json`) and on the S1 code
(`equivalence-post-s1.json`).

Result: 34 fields compared, 33 identical, 1 different:
`attached_tracepoints` 10 → 11 — the added `sched:sched_process_exec` hook (F9 and
the exec half of F4). Identical: exact count deltas (openat 1000, open 10,
execve 50, clone 20, others 0), identity (tgid, pidns, start_ticks = /proc
field 22, level, container_pid null, comm `sysc_helper`, attribution host),
v1 record shape and schema validity, exit reported once with final counts and
reclaimed at the next snapshot, self-exclusion, unresolved path (nothing
attributed, ≥ 100 unresolved), map-full accounting.

## Compilation count and capability selection

`build_info.json` (one `BpfCollector().start()` as root): capabilities
`["counts"]`; compilations `calibrate` then `unified` (2 in total; wall time of
this single start 7.33 s and 7.51 s — one observation, not a benchmark; M1
never measured compile time); 11 tracepoints attached, exactly
`required_tracepoints()`; 11 BPF program fds held while running, 0 after close
(the calibration program was unloaded); vocabulary `v1-3aba869d1752`.
`tests/test_bpf_collector.py::test_exactly_two_compilations_and_the_planned_tracepoints`
counts the BCC constructor calls independently (2) and checks the flags.

## Test runs (final code)

- `make test` (py3.14, incl. 74 C checks) → 245 passed, 1 skipped (D8:
  `tests/test_collector.py::…::test_minimum_record_count`, 35 < 100 processes).
- py3.12 venv `pytest tests/ -m "not privileged"` → 245 passed, 1 skipped (same).
- `make check` → rc 0, no warnings; `make helpers` (now `-pthread`) → no warnings.
- As root `make test-privileged` → 42 passed (M1: 20 syscall-collector incl. exact
  counts N ∈ {1, 1000, 100000} and 1000/1000 start_ticks, 7 DIT-1, 1 preflight;
  S0: 2 agent, 4 snapshot/BPF; S1: 8), 0 leftover containers, bpf_stats 0,
  0 leftover `ppc-s1-*` cgroups.

## Not run

`--abba`; overhead matrix; a 10-minute run; DIT-1 three consecutive times (one
pass inside the privileged suite); 10× exact-count repetitions.
