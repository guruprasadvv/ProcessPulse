# Exclusion-purge race fix (S2.3 audit, finding 2) — evidence (2026-10-19)

Working tree on top of `391c988`, uncommitted, with S2.1–S2.4. Design and
reasoning: `docs/bpf-collector.md`, "Exclusion purge". Kernel 6.18.33.2,
16 CPUs, `CONFIG_PREEMPT_RCU=y`, `CONFIG_MEMBARRIER=y`, no `nohz_full`;
`membarrier` query mask 1023, which includes `MEMBARRIER_CMD_GLOBAL`.

| File | Content |
|---|---|
| `exclusion-purge-tests.log` | First root run of `tests/test_exclusion_purge.py` after the fix: 5 passed in 194.55 s (host-load variance, see the next row); cleanup state before and after |
| `exclusion-purge-tests-2.log` | Second root run with `--durations=0`: 5 passed in 49.06 s; the longest test took 19.8 s |
| `barrier_timing.json` | `rcu_barrier()` and `exclude()` latency, idle and with two busy helpers (as root, one run): barrier median 8.0 ms idle and 16.0 ms busy, max 28.0 ms; `exclude()` median 27.2 / 30.6 ms, max 50.6 ms |
| `privileged-suite.log` | Root `pytest tests/ -m privileged`: 80 passed (M1, DIT-1, S0, S1, S2.3, S2.4 acceptance once, the purge tests) in 472.97 s; `bpf_stats_enabled` 0 before and after, 0 `ppc-*` cgroups, 0 containers |
| `equivalence-after-fix.json`, `equivalence-after-fix.txt` | Counts-only S1 equivalence probe: 34 of 34 fields identical to `../s1/equivalence-post-s1.json` |
| `make-test-py3.14.log`, `make-test-py-py3.12.log`, `make-check.log` | 74 C checks, 0 failures; 525 passed, 1 skipped (D8) on both interpreters; `make check` rc 0. The 2 py3.14 warnings are BCC's own `DeprecationWarning`s |

## Before the fix (observed in the session, not saved as files)

- `test_exit_hook_does_not_touch_an_excluded_process` **failed**
  (`assert 1 == 0`): the unfixed exit hook set `exited = 1` on an info entry of
  an excluded process. After the fix it passes in both runs.
- The four busy-process tests **passed** on the unfixed code (61.50 s): the
  in-flight race was not reproduced. They are exact regression checks; they
  do not show that the barrier is needed.
- The unit tests for the barrier order, failure handling and the exit-hook
  gate failed (4 failed) before the implementation existed.

## Limitations

- The guarantee rests on kernel behaviour argued from source:
  `trace_call_bpf()` runs programs under `rcu_read_lock()` with preemption
  disabled, and `MEMBARRIER_CMD_GLOBAL` runs `synchronize_rcu()`. It was not
  inspected on this build, and the race could not be forced in a test.
- Exclusion is by distro tgid, as in S1: a different process that later
  reuses the tgid is excluded too, until `unexclude()`.
