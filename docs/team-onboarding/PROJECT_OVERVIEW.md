# Project overview

[← Onboarding index](README.md) · next: [ARCHITECTURE.md](ARCHITECTURE.md)

## 1. The problem

Containers (Docker) package applications so that many of them share one
Linux kernel. That makes deployment easy and monitoring hard:

- processes come and go quickly, and process IDs are reused;
- a container sees its own process IDs, while the host sees different ones;
- traditional signature-based tools miss attacks they have no signature for;
- machine-learning detectors that do catch unusual behavior are usually
  black boxes, so an analyst cannot tell *why* an alert fired.

The review deck that defines the project,
[`ProcessPulse-C_Review_with_References.pdf`](../../ProcessPulse-C_Review_with_References.pdf)
(13 slides; version-controlled under decision D-12), frames this as an
**interpretability gap**: detection and explanation need to come together,
in the container context.

## 2. Goals

From the deck's objectives, as traced in `CLAUDE.md` Appendix A:

1. **Monitoring framework:** collect process behavior from the host,
   including containerized processes.
2. **Features:** turn system calls and resource use into features.
3. **Detection:** apply machine learning to detect anomalies in containers.
4. **Explainable alerts:** attach human-readable evidence to each alert,
   for root-cause analysis.

## 3. Intended users and use cases

- **Users:** the course team and reviewers; a security analyst or operator
  watching a container host (the persona the deck's evaluation implies).
- **Planned evaluation scenarios** (`CLAUDE.md` §10), all *simulations*,
  safe and inside the team's own containers only:
  - cryptomining: a CPU-bound hash loop, with no miner and no pool traffic;
  - privilege escalation: failing or benign attempts (setuid-family calls,
    `su`, reads of protected files);
  - data exfiltration: burst file reads sent to a local sink container.

## 4. The four layers

Keep these separate in your head. Each consumes the output of the previous
one.

| Layer | Question it answers | Where | State |
|---|---|---|---|
| **Telemetry collection** | What did each process do, exactly, and what was lost? | `src/`, `bpf/`, `processpulse/` | implemented (M1, M1b S0–S2.6); network part S3.1/S3.2 on branch `wip/s3.2-network`, not accepted |
| **Anomaly detection** | Is this window of behavior unusual compared with benign runs? | planned M2 (features), M4 (Isolation Forest) | planned |
| **Explainability** | Which features pushed this window toward "anomalous"? | planned M5 (SHAP primary, LIME secondary) | planned |
| **Presentation** | How does an analyst see and act on it? | planned M6 (curses TUI + static HTML report) | planned |

`CLAUDE.md` §12 forbids skipping ahead: no ML, SHAP or dashboard work while
the telemetry is unvalidated.

## 5. Capabilities: implemented vs planned

### Implemented (in commits)
- C collector (`src/collector.c`, `procfs.c`, `jsonl.c`):
  - per-process resource samples from `/proc` (CPU ticks, memory, I/O, file
    descriptors, cgroup path) as schema-v1 JSON Lines;
  - an unreadable value is `null` plus an error code, never 0.
- eBPF syscall-entry counts per process for 9 syscalls (execve, execveat,
  open, openat, openat2, clone, clone3, fork, vfork), through per-syscall
  tracepoints.
- Process identity that survives PID reuse:
  `(boot_id, pid-namespace inode, tgid, start_ticks)`.
- Docker attribution from the cgroup path. The DIT-1 acceptance test passed
  three consecutive runs in M1 (`CLAUDE.md` §1, §9).
- Exit handling (report once, then reclaim), self-exclusion of the agent's
  own processes, and health and loss counters.
- Schema v2: a framed, versioned snapshot protocol with keyframes, a
  consumer (Reconstructor) and a validator.
- Syscall **bigrams**: counts of consecutive syscall pairs per process, with
  exact loss accounting.
- A **final drain** that ends a recording with a provably stable read.
- An agent CLI with a strict startup policy and an explicit
  `--allow-degraded` mode.

### Implemented, not yet accepted (S3.1/S3.2, on branch `wip/s3.2-network`)
- A network capability: per-process counts of `connect()` / `accept()` /
  `accept4()` results, split by socket class (IPv4/IPv6 × TCP/UDP/other,
  local IPC, other, unknown) and by coarse destination class (loopback,
  private, link-local, special, public, unknown). **No IP address or port is
  ever stored.**

### Planned (approved in `CLAUDE.md`, no code yet)
- Network bytes, send/receive, TCP state (S3.3); interface counters (S3c,
  optional).
- Privilege-escalation signals (uid/euid changes, setuid-family calls;
  decision D-6).
- Feature engineering (M2), datasets and attack simulations (M3), Isolation
  Forest detection (M4), SHAP + LIME (M5), alerts, TUI and HTML report (M6),
  final evaluation (M7).

## 6. Scope boundaries and non-goals

- **No Kubernetes** (D-7): Docker plus cgroup attribution only.
- **eBPF through BCC, per-syscall tracepoints first** (D-15). The network
  stage is **tracepoint-only**: no kprobes (approved decision N2).
- **Resource metrics come from the C `/proc` collector**, not eBPF (D-1, a
  deliberate substitution for one slide of the deck).
- **No raw IP addresses or ports** are persisted (the S3 plan, §4 and §11).
- **No real malware and no external targets**, ever (`CLAUDE.md` §10).
- **Not a production product:** no sockets, brokers, databases or web
  servers unless a measured need appears (`CLAUDE.md` §3).
- **Raw PIDs and container IDs are never ML features** (`CLAUDE.md` §5).

## 7. What makes it technically hard

- **Exactness under concurrency.** Kernel probes run on many CPUs while
  userspace reads maps. The project insists on knowing exactly what was
  lost, so it uses loss counters, two-phase reclaim, RCU barriers and a
  final drain ([TELEMETRY_AND_INVARIANTS.md](TELEMETRY_AND_INVARIANTS.md)).
- **Identity across namespaces.** WSL2 puts the Ubuntu distro at pid-namespace
  level 2, and containers sit deeper. `bpf_get_current_pid_tgid()` returns
  host IDs, and `bpf_get_ns_current_pid_tgid()` fails with EINVAL for nested
  namespaces (verified, M1). Identity is resolved by walking kernel pid
  structures and is calibrated at startup.
- **Kernel/toolchain friction.** BCC 0.35 against a 6.18 kernel needed a
  small header shim for the network capability. Kernel headers come from the
  `kheaders` module, which must be loaded after each WSL restart.
- **Resource limits.** The development machine has limited memory. Several
  heavy runs were stopped by the tooling because of low memory (M1's ABBA
  check; the S3.2 privileged regression). See
  [SETUP_AND_TESTING.md](SETUP_AND_TESTING.md#61-preflight-checklist-before-expensive-privileged-runs).
- **Evidence discipline.** Every claim must be backed by a saved command
  output. "It probably works" is not accepted.

## 8. Metrics the project will report (planned, M4–M7)

Precision, recall, F1, false-positive rate on benign runs, detection
latency, explanation usefulness (indicator hit@3, D-11), LIME fidelity,
inference and explanation latency, collector CPU/RSS overhead, and event
loss. No numeric performance target is claimed before a reproducible
baseline exists (`CLAUDE.md` §10).
