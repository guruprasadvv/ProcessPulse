# M1b S3.1/S3.2 evidence: network capability, connect/accept (2026-10-19)

Base `699c2c8` (S2.6). Uncommitted. Status: **NOT READY FOR REVIEW**. The
full privileged regression did not complete (see the last section).
Environment: WSL2 Ubuntu 26.04, kernel 6.18.33.2-microsoft-standard-WSL2,
Python 3.14.4 + BCC 0.35.0 (root), Python 3.12.15 venv.

## Files

| File | Content |
|---|---|
| `m1-logs-before.txt` | the 15 untracked M1 logs: names, sizes, mtimes and sha256, recorded before any S3 edit |
| `tracefs-formats.txt` | formats of the 6 hooks, read as root before writing any BPF code |
| `compile-probe-dev.log` | first load of `counts,net` and `counts,bigrams,net`: 17 tracepoints, 2 compilations, map memlock, prog fdinfo |
| `verifier-counts,net.txt`, `verifier-counts,bigrams,net.txt` | kernel verifier summary for every program (BCC `DEBUG_BPF`), and build info |
| `net-bpf-dev.log` | root `pytest tests/test_net_bpf.py`: **16 passed** in 98 s (development run, see below) |
| `regression/make-test-py3.14.log` | `make test`: 74 C checks, 0 failures; **657 passed, 1 skipped**, rc 0 |
| `regression/make-test-py-py3.12.log` | `make test-py` (3.12 venv): **657 passed, 1 skipped**, rc 0 |
| `regression/make-check.log` | rc 0 |
| `regression/post-edit-agent-unit.log` | after the last one-line agent edit: `test_net_unit.py` + `test_agent_bigrams.py`, 73 passed |
| `regression/make-test-privileged.log` | the full privileged run, **stopped at 18 %** (20 passed, 0 failed) |
| `post-kill-state.txt` | WSL state after the stop: no leftover processes, no BPF programs except systemd's own, 0 containers, 3 default Docker networks |
| `privacy-audit.txt` | search for any address or port retention, and for kprobes, with the reviewer conclusion |

## Verifier and memory

- **Verifier:** 17 programs per build. `counts,net`: 160–1,033 instructions
  processed, 393–700 for the net probes. `counts,bigrams,net`: 413–1,035. At
  most 81 states (limit 1,000,000 instructions).
- **Map memlock (fdinfo):**
  - `netc` 6,820,288 B (32,768 entries);
  - `net_stash` 3,410,752 B (32,768);
  - `nhealth` 648 B.

  The net capability adds 9.75 MiB.

## Invariants

| Invariant | Result | Applicability |
|---|---|---|
| I-N1 | PASS on every key of every privileged test, and of both agent end-to-end streams | always |
| I-N2 | PASS: drained read with reclaim, purge and an accept in flight; drained reads after a full map and a full stash; both emitted end-to-end streams | drained only; applied to the S3.2 syscall hooks (plan §11.3) |
| I-N3 | NOT APPLICABLE | byte counters are S3.3 |
| I-N4 | PASS, in the same runs as I-N2 | drained only; includes `purged_stash` (plan §11.4) |
| I-N5 | NOT APPLICABLE | sendto counters are S3.3 |
| I-N6 | the net object equals the script exactly for every helper (asserted); the status is PASS, or NOT APPLICABLE when an unrelated loss rose in the window | scripted helpers |

## Containers and networks

None were created: S3.2 uses only host loopback, UDP `connect()` (which
sends no packet) and local sockets. The state before and after shows 0
containers and the 3 default Docker networks.

## Why this is not ready

- The full root `make test-privileged` on the final code was stopped by the
  Claude Code session at 18 % because host memory was critically low
  (Windows free about 1.9 GB of 14 GB afterwards). The WSL VM restarted.
- The final JUnit run of `tests/test_net_bpf.py` and the counts-only S1
  equivalence probe never ran.
- `net-bpf-dev.log` (16 passed) predates two late edits: `drain.net_terms`
  copied into the manifest, and one assertion added to the e2e test.

All of these must be re-run (with your authorization, after freeing memory)
before review.
