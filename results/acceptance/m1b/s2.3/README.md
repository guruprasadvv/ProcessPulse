# M1b S2.3 evidence: BPF bigram capability (2026-10-19)

Working tree on top of `391c988` (S1), uncommitted, together with S2.1 and S2.2.
Design: `docs/bpf-collector.md` (section "Bigrams capability"). Environment:
WSL2 Ubuntu 26.04, kernel 6.18.33.2, 16 possible CPUs, Python 3.14.4 + BCC 0.35.0
(root runs), Python 3.12.15 venv. Saved after the S2.3 audit (S2.4, Phase 3).

## Stored files (copied unchanged from the session's scratch directory)

| File | What it is |
|---|---|
| `build_info_and_loss_paths.json` | Output of `s23_evidence.py` (one root run): build info (capabilities, the 2 compilations with times, 11 open tracepoints, vocabulary `v1-3aba869d1752`, capacities, per-map `max_entries` and `memlock`), a no-loss helper, the read method, and each forced loss path (rows 1–3) with the helper's counts/pairs/`pairs_lost` and the global counter deltas while the map was full |
| `s23_evidence.py` | The script that produced it (run as root: `PYTHONUSERBASE=/home/mypc/.local python3 -W ignore s23_evidence.py OUT.json`; its paths point at the repository and the session scratch directory) |
| `equivalence-post-s2.3.json` | `tools/acceptance/s1_equivalence.py` output on the S2.3 code (counts-only collector) |
| `equivalence_compare.sh` | The root script that ran the probe and compared it field by field with `results/acceptance/m1b/s1/equivalence-post-s1.json` |
| `s0-run-validation-before-s2.1.json`, `…-after-s2.1.json`, `…-after-s2.2.json` | `validate_run.py` reports of the recorded S0 10-minute v2 run (`results/raw/m1b-s0-10min-20261019T042927`, gitignored) on the S1 code, after S2.1 and after S2.2. They are evidence that the S2.1/S2.2 schema and consumer changes kept recorded-run validation unchanged. |

## Results

- **Compilation and attachment:** 2 compilations (`calibrate` 9.81 s, `unified`
  6.70 s; one observation), 11 open tracepoints. In
  `tests/test_bigrams_bpf.py::test_two_compilations_same_tracepoints_and_one_extra_map`
  the BCC constructor calls are counted independently (2), no extra BPF program
  is loaded (prog fds +11), and the flags include `-DPPC_CAP_BIGRAMS=1`.
- **Map memory (`memlock`, bytes):** counts 2,625,216; info 2,100,416; threads
  3,410,752; excluded 7,616; health 400; bigrams 12,585,664 (12.00 MiB);
  bglobal 328. Total **20,730,392 bytes = 19.77 MiB (20.73 MB)**. The S2.3
  report said "≈ 20.7 MiB", which was wrong: that is the decimal MB value. All
  five hash maps fit (entries + 16) × (48 + key + value) + buckets × 16 + 1,472
  bytes. This model is fitted to these measurements, not taken from kernel
  source.
- **Loss paths** (`build_info_and_loss_paths.json`): every loss path matches
  R-LOSS. The exec's slot failure explains `thread_map_full` +4 against
  `bigram_dropped` +3.

  | Path | Helper afterwards | Counter deltas while full |
  |---|---|---|
  | row 1 | counts `open` 1, `pairs_lost` 0, `START_LOST→open` | `counts_map_full` +3, `bigram_dropped` +3 |
  | row 2 | counts execve 1, openat 2, open 1; `pairs_lost` 3; `START_LOST→open` | `thread_map_full` +4, `bigram_dropped` +3 |
  | row 3 | same counts, `pairs_lost` 3, `openat→open` | `bigram_map_full` +3, `bigram_dropped` +3 |

- **Counts-only equivalence:** 34 of 34 fields identical to the S1 baseline
  (`equivalence-post-s2.3.json` vs `../s1/equivalence-post-s1.json`).
- **Read method:** `batch` (`items_lookup_batch` works; H-BATCH answered).

## Not stored as files (transcribed from the session's command output)

These were observed in the S2.3 session but not saved as raw logs at the
time; they cannot be recovered as files, so they are recorded here only as
transcriptions:

- `make test` (py3.14) → `test_procfs: 74 checks, 0 failures`; `502 passed, 1 skipped, 58 deselected`.
- `make test-py PYTHON=~/.venvs/processpulse-py312/bin/python` → `502 passed, 1 skipped, 58 deselected`.
- `make check` → rc 0, 0 warnings.
- As root, `pytest tests/test_bigrams_bpf.py -m privileged` → `16 passed`;
  `pytest tests/ -m privileged` → `58 passed` in 246.94 s.
- Cleanup around the root runs (`priv_run.sh`): `bpf_stats_enabled` 0 before
  and after, 0 `ppc-*` cgroups before and after, 0 containers in any state.

The S2.4 runs (`../s2.4/`) save their logs and JUnit XML as files.

## Open item

The purge race in `BpfCollector.exclude()` (S2.3 audit, finding 2) is **not
fixed**. It is a required fix before S2.5; see `docs/bpf-collector.md`, "Known
limitations".
