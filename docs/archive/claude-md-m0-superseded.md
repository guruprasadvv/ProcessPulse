> **SUPERSEDED — historical record only, not project instructions.**
> This is the original M0-era `claude.md`, retired on 2026-10-19 when the
> canonical `CLAUDE.md` was established (decision D-13). Its milestone plan
> (SQLite/MAD/z-score/rule-based explainer) and its "do not add eBPF/ML" list
> were replaced by the approved PPT-driven architecture. Kept verbatim below.

---

# ProcessPulse-C — Claude Code Context

## Project

Explainable Behavioral Anomaly Detection for Containerized Applications.
A student OS-course project built in stages (milestones M0–M6).

## Current state: M0 complete

M0 delivers a Linux process collector in C11. It reads `/proc`, parses
`/proc/<pid>/stat`, and emits one JSON record per process to stdout.

## Build environment

- **Required:** Linux kernel with `/proc`. On Windows, use WSL2 (Ubuntu).
- **Toolchain:** GCC, C11, Python 3.10+, pytest.
- **Build:** `make` (produces `./collector`). **Test:** `make test`.
- **No root required.** No external C libraries. No database. No Docker socket.

## Key files

| File | Role |
|------|------|
| `src/collector.c` | Only C source. All functions are `static` except `main`. |
| `tests/test_collector.py` | Unit tests (parser spec) + integration tests (binary output). |
| `Makefile` | Build and test targets. |
| `docs/architecture.md` | Design decisions and known limitations. |
| `docs/os-concepts.md` | /proc, jiffies, TOCTOU — concepts students must understand. |

## Critical parsing decisions

1. **Use `strrchr(line, ')')`** to find the end of the `comm` field.
   `strchr` breaks when `comm` contains `)`. All fields after `comm`
   are integers — no `)` can appear there — making `strrchr` unambiguous.

2. **Field numbering:** After the last `)`, fields are 0-indexed tokens.
   `utime` is token 11, `stime` is token 12 (fields 14 and 15 in the
   kernel documentation's 1-based numbering).

3. **`sscanf` with `%*` skip operators** to jump fields 3–13 in one call.
   Returns 2 on success (the two stored values). Any other return -> malformed.

4. **TOCTOU:** `ENOENT`/`EACCES` on `fopen` of a stat file is expected
   (process exited between `readdir` and `fopen`). Skip silently.

## Milestone plan

| Milestone | Description |
|-----------|-------------|
| **M0** done | C collector: /proc enumeration, stat parsing, JSON output |
| M1 | Add poll interval, timestamp, memory/IO/FD fields |
| M2 | Container detection via /proc/pid/cgroup; delta-based feature extraction |
| M3 | SQLite-backed baseline engine (rolling mean, MAD) per process name |
| M4 | Modified z-score anomaly detector |
| M5 | Rule-based explainer generating human-readable anomaly reports |
| M6 | Terminal dashboard and evaluation on synthetic anomalies |

## What NOT to add without explicit approval

- eBPF, Kubernetes, Kafka, Redis, Docker SDK, ML frameworks.
- Any external C library before M1.
- Daemon mode or signal handling before M1.
- Web UI, REST API, or persistent processes before M6.
