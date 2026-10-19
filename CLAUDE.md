# ProcessPulse-C — Master Project Instructions

Explainable Behavioral Anomaly Detection for Containerized Applications.
VIT Operating Systems course project (team of three).

**Source of truth:** the review deck `ProcessPulse-C_Review_with_References.pdf`
(13 slides) plus the approved decisions and contracts below. Every PPT
commitment is traced in the appendix; none may be dropped or silently merged.
Scope changes require the user's explicit approval.

Status vocabulary used in this file:
- **[VERIFIED]** — demonstrated by a command whose output was inspected (date given).
- **[IMPLEMENTED]** — code exists in the repo *and* its tests pass.
- **[PLANNED]** — approved requirement, not yet implemented.
- **[LIMITATION]** — known gap or caveat.
- **[UNRESOLVED]** — needs a decision; do not invent an answer.

Never describe a [PLANNED] item as working.

---

## 1. Current status (update only with evidence)

| Item | Status |
|---|---|
| M0 snapshot collector (`src/collector.c`) | [IMPLEMENTED] one snapshot per run, JSON Lines `pid, comm, utime, stime`. 20 tests pass, 1 skip (min-record threshold: WSL shows ~30 processes < 100). Zero warnings with strict flags, `-fanalyzer`, ASan+UBSan. [VERIFIED 2026-10-19] |
| M0 known defects | D1 comm containing `\n` drops the process (fgets); D2 bytes ≥0x80 emitted raw (invalid UTF-8); D3 `%lu` accepts `-1`; D4 unit tests exercise a Python mirror, not the C parser; D5 comm truncated at 31 bytes; D6 collection gaps invisible / exit 0 on failure; D7 readdir errors not distinguished; D8 min-record test always skipped in WSL; D9 doc inaccuracies; D10 stdout fully buffered. To be fixed test-first in M1. |
| eBPF feasibility (BCC, per-syscall tracepoint, map counting, PID attribution, cleanup) | [VERIFIED 2026-10-19] `tools/bpf_smoke.py`: tests A–F pass, 2 runs × 3 iterations + error-path iteration. |
| Docker runtime in the distro | [VERIFIED 2026-10-19] docker.io 29.1.3, cgroup v2, systemd driver; container processes visible in distro `/proc` with nested pidns. |
| M0 defects D1–D6 | [IMPLEMENTED 2026-10-19] fixed test-first in M1 (whole-file reads, UTF-8-safe escaping, strict number parsing, C unit tests, gap counters, exit codes). D7 fixed for v1 (`readdir_err`). D8–D10 remain as documented. |
| M1 telemetry foundations | **[VERIFIED 2026-10-19] M1 accepted.** `collector --v1`, schema v1 + validator, framing, resource supervisor, BCC syscall collector (calibration, identity, exit reclaim, health), preflight, agent. Acceptance: 10-minute run 27 803/27 803 lines valid over 612 s; exact counts 110/110 over 10 repetitions; start_ticks 1000/1000; overhead matrix 45/45 measured. [LIMITATION] workload-throughput impact not attributable (run-order confound). Evidence: `results/acceptance/m1/README.md`. |
| Docker *attribution* | [VERIFIED 2026-10-19] **DIT-1 passed three consecutive runs (7/7 checks each).** Limits: PID reuse is checked by key semantics, not forced physically; M1 has no feature windows, so "final window exited" is checked as the snapshot's `exited` flag. |
| M1 framing limitation (F1) | [LIMITATION] 15 of 613 `syscall_snapshot` lines of the accepted M1 10-minute run exceed the 65,536-byte line limit (largest record 311,053 bytes); neither the agent nor `validate_run.py` checked line length. M1's acceptance is not re-judged; v1 recordings are reported as `legacy_v1_oversize`. Fixed for schema v2 by M1b S0. |
| M1b S1 unified BPF collector | [IMPLEMENTED 2026-10-19, uncommitted, under review] `processpulse/bpf_collector.py` + `vocab.py`, `bpf/common.h` + `core.bpf.c`; 2 compilations per start (calibrate, unified), capability `counts` only; F4 per-thread slots, F9 metadata refresh at exec. Unprivileged 245 passed / 1 skip (py3.14 and py3.12), privileged 42 passed; pre/post equivalence 33/34 identical (tracepoints 10 → 11, `sched_process_exec` added). Evidence: `results/acceptance/m1b/s1/README.md`, design `docs/bpf-collector.md`. |
| M1b S0 framing + v2 BPF snapshot protocol | [IMPLEMENTED 2026-10-19, accepted, committed `d9b9e9b`] byte rule, `telemetry.v2.json`, versioned validator, `processpulse/snapshots.py` (emitter + reconstructor), `agent --schema 2` (opt-in; default stays 1), `validate_run.py` v2 mode. After the keyframe correction: unprivileged 213 passed / 1 skip (py3.14 and py3.12), privileged 34 passed; recorded 10-minute v2 run valid (re-validated, not re-run). Awaiting review. Evidence: `results/acceptance/m1b/s0/README.md`. |
| M1b S1–S7, M2 … M7 | [PLANNED] — see §11. |

## 2. Approved decisions (authoritative — do not reopen)

| ID | Decision |
|---|---|
| D-1 | Resource telemetry comes from the **C /proc collector** (deliberate substitution for slide 8's "resource metrics via eBPF"; capability preserved). |
| D-2 | **Isolation Forest** (scikit-learn) is the primary detector. |
| D-3 | **SHAP** primary explainer; **LIME mandatory** secondary explainer. |
| D-4 | Network activity via **eBPF**, process-attributed (M1b). |
| D-5 | Syscall **sequence** features via bounded in-kernel **bigram** counting. |
| D-6 | Privilege-escalation identity/context fields and signals (uid/euid, setuid-family syscalls). |
| D-7 | **Kubernetes is out of scope.** Docker + cgroup attribution only. |
| D-8 | Docker (docker.io inside the Ubuntu distro) is the container runtime. |
| D-9 | A privileged **full-telemetry** mode is supported (root). |
| D-10 | Dashboard = lightweight **curses TUI** + **static HTML** experiment report. |
| D-11 | Explanation usefulness metric = **indicator hit@3** (indicators pre-registered). |
| D-12 | The original PPT PDF is version-controlled. |
| D-13 | This file is the canonical master instruction file (lowercase `claude.md` retired; archived verbatim at `docs/archive/claude-md-m0-superseded.md`). |
| D-14 | The ML environment uses **Python 3.12**; do not build it on Python 3.14. |
| D-15 | eBPF uses **per-syscall tracepoints** (`syscalls:sys_enter_*` / `sys_exit_*`) first. |

## 3. Architecture

```
Docker containers ─┐
host processes ────┤ (shared kernel)
                   ├─ C /proc collector (src/)  ── JSONL stdout ──┐
                   └─ BCC eBPF collector (bpf/) ── map snapshots ─┤
                                                                  ▼
                 processpulse agent (Python, root in full mode): supervise, frame,
                 validate, record raw JSONL + health + run manifest
                                                                  ▼  (recorded or streamed)
                 features (M2) → Isolation Forest (M4) → SHAP + LIME (M5) → alerts / TUI / HTML (M6)
```

- **Runtime model:** one Python agent supervises the C collector as a subprocess
  (stdout = telemetry only, stderr = diagnostics) and hosts the BCC collector
  in-process. Both raw streams are recorded so later stages can replay them
  deterministically. No sockets, shared memory, brokers, databases, web servers
  or Kubernetes unless a measured requirement justifies it.
- **Separation:** the C collector reports only facts it read from procfs (no
  derived rates). The BPF program keeps cumulative counters only. Features,
  models and explanations are strictly downstream and consume versioned records.
- **Privileges:** BCC needs root (`unprivileged_bpf_disabled=2`, tracefs
  root-only). Full mode runs the agent and C collector as root so
  `/proc/<pid>/io`, `/fd`, `/ns/*` of root-owned (container) processes are
  readable. Unprivileged mode is allowed for the C collector alone and reports
  those fields as unavailable — never as 0.

## 4. Environment and dependency boundary

- Target: **WSL2 Ubuntu 26.04**, kernel `6.18.33.2-microsoft-standard-WSL2`,
  x86_64, glibc 2.43, cgroup v2 only. Build and test **inside WSL**
  (`wsl -d Ubuntu`); MSYS2/Git-Bash `/proc` is not Linux `/proc`.
- `sudo` requires a password. Privileged steps are run by the user, or through
  `wsl -d Ubuntu -u root -- <cmd>` when the user has authorized that step.
- **Telemetry layer** (agent, collectors, their tests): system `/usr/bin/python3`
  (3.14) because BCC is only available as the apt package `python3-bpfcc` 0.35.
  Stdlib only beyond BCC. Code must remain Python 3.12-compatible.
- **ML / offline layer** (M2+): Python **3.12** virtual environment; dependencies
  pinned in `requirements/`. It consumes recorded JSONL and never imports BCC.
  Created by `tools/setup_py312_env.sh` (user-level `uv`; CPython 3.12.15 at
  `~/.venvs/processpulse-py312`), because Ubuntu 26.04 has no python3.12 package.
- **Tests:** `make test` (unprivileged; also run it with the 3.12 venv's python).
  Privileged: as root, `PYTHONUSERBASE=/home/<user>/.local make test-privileged`
  (root's python has no pytest; the user-level pytest is reused, nothing installed).
- **Kernel headers for BCC:** provided by the `kheaders` module
  (`/sys/kernel/kheaders.tar.xz`). It does **not** persist across WSL restarts;
  the agent preflight attempts `modprobe kheaders` (root only) and reports the
  result. Do not change boot configuration without approval.
- No external C libraries. No Docker SDK (use the `docker` CLI when metadata is
  needed). No GPU requirement.

## 5. Telemetry contracts (versioned JSON Lines)

**Framing:** UTF-8, one JSON object per line, `\n`-terminated, every record has
`"type"` and `"v"` (schema version). Byte rule: a record (the UTF-8 bytes
without the terminating LF) is 1..65,536 bytes and contains no CR or LF;
counted on bytes, never characters. v2 writers enforce it; v1 recordings
that break it are reported as legacy findings, not re-judged
(`docs/telemetry-v2.md` §1). Partial trailing lines are
discarded and counted. Malformed lines are counted and logged to diagnostics,
never forwarded. Schemas live in `processpulse/schemas/*.json`; a schema change
bumps `v` and is recorded in `ENGINEERING_CHANGELOG.md`.

**BPF snapshot protocol (schema v2, `agent --schema 2`):** begin / proc* /
reclaimed* / end per snapshot, cumulative counters per epoch, changed-only
emission, keyframe iff status ok and (`seq % 60 == 0` or a keyframe is due:
epoch start, failed scheduled keyframe, uncommitted previous snapshot),
explicit removals (exited / self_excluded / vanished = loss), `tracked` and
`totals` cross-checks, failed snapshots, commit-after-write. Consumer rules
(when an omitted process may be read as unchanged, invalidation, rebuild at
keyframes): `docs/telemetry-v2.md`, implemented in `processpulse/snapshots.py`.

**Missing values:** `null` plus an `*_err` code (`EACCES`, `ENOENT`, `ESRCH`,
`EPARSE`, `UNSUPPORTED`). Never substitute 0 for an unread value. Never fabricate.

**Time contract**
- C: `clock_gettime(CLOCK_MONOTONIC)`; Python: `time.monotonic_ns()` (same clock,
  verified). Wall clock (`CLOCK_REALTIME`) only for human display.
- Kernel timestamps (`bpf_ktime_get_ns`) are diagnostics only; syscall windows
  use the userspace snapshot time. The distro is in the initial time namespace
  (verified); clock relationship must still be validated by test.
- Rates are always Δcounter / measured Δt, never an assumed interval.
- CPU ticks use USER_HZ = 100 (`getconf CLK_TCK`, verified); `CONFIG_HZ`=250 is irrelevant.

**Process identity**
- PID-namespace levels (verified): L0 host, L1 WSL utility ns, **L_d = 2 Ubuntu
  distro** (the PIDs the C collector sees), L_d+1.. containers.
- `bpf_get_current_pid_tgid()` returns L0 IDs — diagnostics only.
- `bpf_get_ns_current_pid_tgid()` fails with EINVAL for nested pidns (verified) — do not use for identity.
- Distro TGID = `group_leader->thread_pid->numbers[L_d].nr`, valid only if
  `level ≥ L_d` **and** `numbers[L_d].ns->ns.inum` equals the distro pidns inode
  (sibling WSL distros share level 2). L_d and the inode are **calibrated at
  startup** from the agent's own process and checked against `/proc/self/ns/pid`.
- Container-visible PID = `numbers[level].nr` when `level > L_d` (informational).
- Start time: C reads `/proc/<pid>/stat` field 22 (ticks since boot); eBPF reads
  `group_leader->start_boottime` (ns) and normalizes `start_ticks = ns / 10_000_000`.
  Equality must be validated by test.
- **ProcessKey = (boot_id, distro_pidns_inode, distro_tgid, start_ticks).**
- **Never assign an unresolved event to a guessed process.** Unresolvable events
  increment `unresolved_events`.
- Raw PIDs / container IDs are never model features.

**Container identity (Docker)**
- C emits the raw cgroup v2 path (`0::/system.slice/docker-<64hex>.scope`, systemd
  driver verified); `container_id` is parsed in Python (`docker-<id>.scope`, also
  `/docker/<id>` for the cgroupfs driver). No match ⇒ host / non-container.
- eBPF records `bpf_get_current_cgroup_id()`; userspace maps it to a cgroup
  directory by inode. Mappings whose directory has disappeared are kept from
  cache and flagged `stale`.

**Lifecycle and event loss**
- Counters are cumulative and never reset; deltas are computed downstream.
- `sched_process_exit` marks exits; exited entries are reported once, then
  reclaimed (two-phase delete — no lost increments).
- Health counters are always emitted: map-full drops, unresolved events,
  self-excluded events, exit/reclaim counts, probe attach state, C collector
  gaps (`gone`, `denied`, parse errors), malformed lines, restarts, dropped samples.
- First window after probe attach or process start is `partial`; zero counts are
  only valid if the probe was healthy for the whole window.
- Syscall counts are **entry counts (attempts)**, not successes.

## 6. Network accounting (M1b) [PLANNED]

| Quantity | Hook | Rule |
|---|---|---|
| Successful socket payload bytes (tx/rx) | `sock:sock_send_length` / `sock:sock_recv_length` (fields `sk, family, protocol, ret, flags`; present on this kernel) | `ret > 0` adds bytes; `ret < 0` counts errors by errno class (`EAGAIN` separate); `MSG_PEEK` (flags & 2) excluded. "Successful" = accepted by the local socket layer, **not** delivered/acknowledged. |
| Attempted bytes | `sys_enter_sendto` `len` only | iovec totals of `sendmsg`/`sendmmsg` and `write()` to sockets are not collected (documented gap). |
| Partial sends | `sys_enter_sendto` → `sys_exit_sendto` `ret` via bounded per-TID stash | partial when `0 ≤ ret < len`. |
| Socket-level counts | enter/exit `connect`, `accept4`; enter `send*/recv*` | connect result: 0 ok / `-EINPROGRESS` pending / errno. Family read from sockaddr. |
| TCP connection attempts | `sock:inet_sock_set_state` → `SYN_SENT` only | other transitions may run in softirq context and are not process-attributed. |
| Interface traffic | `/proc/<pid>/net/dev` per netns (C collector) | includes headers/retransmits; container-level only, not process-attributed. |

Network families (`AF_INET`, `AF_INET6`) are separated from local IPC
(`AF_UNIX`, `AF_NETLINK`, `AF_VSOCK`). Known blind spots: AF_XDP/zero-copy,
`PACKET_MMAP`, kernel-originated traffic, retransmits at the socket layer,
`sendfile`/`splice` paths (to validate), `docker-proxy` relaying published ports,
other distros / Windows / Docker Desktop, NAT/bridge forwarding.

M1b acceptance tests: TCP and UDP exact-byte tests to a sink container (sender tx
= sink rx = N, 10/10 runs); non-blocking small `SO_SNDBUF` partial-send invariant
(Σret = bytes received, partial count > 0); `AF_UNIX` excluded from network
counters; `connect` to a closed port counted as error; `MSG_PEEK` adds 0 bytes;
interface tx ≥ socket payload (relationship, not equality); per-syscall-path
coverage documented (`write`, `send`, `sendmsg`, `sendmmsg`, `sendfile`, `splice`).

## 7. Detection contract (M4) [PLANNED]

- Explained/decision scalar: **F(x) = IsolationForest.score_samples(T(x))**, with
  `T` the fitted, versioned preprocessing and `x` the raw feature vector in the
  fixed `feature_schema` order.
- **Lower F ⇒ more anomalous.** F is an anomaly score — not a probability, not
  causal evidence.
- Decision: anomalous iff **F(x) < τ**. τ = empirical q-quantile of F on
  **benign validation runs only**; q derives from a false-positive budget α
  recorded before the test set is examined. sklearn `predict()`,
  `contamination` and `offset_` are not used for decisions.
- Fit on benign training runs only; splits grouped by run (no overlapping-window
  leakage). No automatic retraining on live data; unreviewed anomalies never
  enter the benign baseline. Model, `T`, feature schema, τ/q/α, background set
  and training metadata are versioned together (artifact hash).
- Compare against a simple MAD/robust-z baseline during evaluation; IF remains
  primary unless evidence justifies a documented change.

## 8. Explainability contracts (M5) [PLANNED]

**SHAP (primary)**
- `shap.PermutationExplainer` on the exact callable **F**, masker
  `shap.maskers.Independent(B)`. Efficiency: Σφᵢ = F(x) − mean_{b∈B} F(b).
- `shap.KernelExplainer` on the same F and B only as a convergence cross-check.
- `TreeExplainer` is **not** assumed to support `score_samples`; it may only be
  used as a separately labelled path-length attribution after an additivity
  test identifies the exact output it explains.
- φᵢ is in `score_samples` units; **negative φᵢ pushes toward anomalous**.
  Present signed, ranked by |φᵢ|, with raw value and benign p50/p95.
  Interventional/independent masking evaluates off-manifold points for correlated
  features — document this.
- Background B: **benign training windows only** (never validation/test),
  balanced per run, deterministic seed, deduplicated, same feature order and `T`;
  stored with the artifact (hash, size, seed, source runs).
- |B| chosen by sweep {25, 50, 100, 200, 500} on stability (top-3 Jaccard,
  Spearman, L1 vs |B|=500), latency and peak RSS against a criterion recorded
  **before** the sweep. Explainer cached per model version.
- Validation: additivity residual ≤ 1e-8 (float64); 5-seed variance; dummy
  constant feature ⇒ φ = 0; model-randomization sanity test; feature order and
  `T` hash equal to inference.

**LIME (mandatory secondary)**
- `LimeTabularExplainer(mode="regression", discretize_continuous=False,
  training_data=benign training windows, fixed random_state)` explaining the
  **same F** on the **same ordered raw feature vector**; `num_samples` ∈ {1000, 5000}.
- Report surrogate weights + intercept, **local fidelity R²**, surrogate
  prediction vs F(x), seed stability. LIME is not additive. Negative weight ⇒
  toward anomalous.
- SHAP–LIME agreement per alert: sign agreement and top-3 Jaccard.

**Explanation record:** method, explained function (`score_samples∘T`), F(x), τ,
expected value / intercept, additivity residual or R², background config,
latency, model/preprocessing/feature-schema versions, top-k with signs.

## 9. DIT-1 — Docker Integration Acceptance Test (gate for Docker attribution)

A static helper inside a `busybox:1.36` container performs exactly N syscalls on
command and reports its container-visible PID. DIT-1 passes only if, in **three
consecutive runs**:
1. container-visible PID = `numbers[level].nr`;
2. distro PID = `docker inspect .State.Pid` = `NSpid[0]` = C-collector PID;
3. container pidns inode ≠ distro inode; BPF `level` = L_d+1; ns inode at L_d matches the distro;
4. cgroup path is `…/docker-<id>.scope`; parsed `container_id` = `docker inspect .Id`; BPF `cgroup_id` = scope-directory inode;
5. BPF count deltas = N exactly on the correct ProcessKey; eBPF `start_ticks` = C field 22;
6. after stop: entry flagged exited, reported once, reclaimed; C stops reporting; final window `exited`; PID reuse ⇒ new key;
7. a synthetic ns-inode mismatch ⇒ `unresolved`, never attributed.

The getpid smoke test does **not** substitute for DIT-1.

## 10. Attack simulations and evaluation (M3/M7) [PLANNED]

Safe, controlled, inside our own containers only — never against systems
without authorization, no real malware, no external targets:
- **Cryptomining simulation:** CPU-bound hash loop (no miner, no pool traffic).
- **Privilege-escalation simulation:** failing/benign escalation attempts
  (setuid-family calls, `su`/setuid-binary execs, reads of protected files) in
  our container; observed as attempts.
- **Data-exfiltration simulation:** burst file reads sent to a local sink
  container over the Docker network.
Anomalies are injected into representative benign workloads with a monotonic
ground-truth injection log. Labels never enter feature files.

Metrics: precision, recall, F1 (window- and episode-level, per scenario,
bootstrap CIs over runs); false-positive rate on benign held-out runs; detection
latency (first alert − injection time); explanation usefulness = indicator
hit@3; LIME fidelity; inference and explanation latency; collector CPU/RSS
overhead; event loss. No performance target is claimed before a reproducible
baseline exists; measured results are kept separate from goals.

## 11. Milestones

| MS | Scope | Entry | Measurable acceptance |
|---|---|---|---|
| M0 | Existing snapshot collector | — | 20 pass / 1 documented skip; zero warnings; defects recorded. **Met.** |
| M1 | Telemetry foundations: C v1 streaming schema, BCC process-level syscall counts (execve/openat/clone families), agent, identity, health, preflight | M0 committed | 100% schema-valid lines over a 10-min run; exact count deltas for N ∈ {1, 1000, 100000} per family in 10/10 runs; start_ticks equal for 1000/1000 spawned processes; 0 misattributions; unresolved counted; **DIT-1 passes 3 consecutive runs**; overhead measured (3 workloads × 3 intervals × 5 reps, median/IQR). **Met 2026-10-19.** |
| M1b | Network telemetry, syscall bigrams, privilege-escalation signals | M1 accepted | §6 tests; exact bigram counts for a known sequence; uid/euid change and setuid-family counts verified. |
| M2 | Feature engineering (cleaning, normalization, noise filtering, frequency, temporal, sequence, container aggregates) | M1 (+M1b for those features) | Byte-identical golden-file output; tests for counter reset, zero-length window, gaps, PID reuse, ephemeral processes, stale data; feature schema and `T` versioned. |
| M3 | Datasets and the three attack simulations | M2, DIT-1 passed | ≥3 benign workload types; each scenario ≥5 runs; manifests complete; run-grouped splits; reproducible summaries within a pre-registered tolerance; safety review. |
| M4 | Isolation Forest detection | M3, Python 3.12 env | Deterministic artifacts; τ from validation only; per-scenario metrics with CIs vs MAD baseline. |
| M5 | SHAP + LIME | M4 | §8 validation; |B| sweep; latency/memory measured; hit@3 per scenario. |
| M6 | Alerts, curses TUI, static HTML report | M5 | Alerts traceable to source records; component-failure tests; data-quality warnings visible; end-to-end scenarios. |
| M7 | Final evaluation and hardening | M6 | All evaluation requirements carry measured evidence or explicit [UNRESOLVED]; churn/permission/failure tests; independent re-run reproduces main tables. |

## 12. Working rules

- **Git:** never `git add .` / `git add -A`; stage explicit paths only after
  reviewing them. Commit, push, branch or remote changes only when the user
  authorizes them. Exclude binaries (`collector`), caches, run data
  (`results/raw/`), secrets. `.gitattributes` enforces LF.
- **Test first:** write the failing test, then the smallest coherent change.
  Preserve M0 behavior: `./collector` with no arguments keeps its M0 output.
- **Evidence:** report exact commands, exit codes and outputs; distinguish PASS,
  FAIL, BLOCKED, NOT TESTED. Never fabricate output or claim untested behavior.
- Do not replace eBPF with /proc or rule-based substitutes; do not skip ahead
  (ML/SHAP/dashboard) while telemetry is unvalidated.
- Do not install unrelated packages or alter boot/system configuration without approval.
- Record every change, schema change, measurement and decision in
  `ENGINEERING_CHANGELOG.md`.

---

## Appendix A — PPT traceability (compact; full rationale in the reviewed matrix)

Format: `ID | slide | requirement | MS | status`. Status: P = [PLANNED],
V = verified with M1 acceptance evidence (2026-10-19), Pa = partial (M1 part verified,
later milestones pending), F = feasibility verified only, U = [UNRESOLVED], X = descoped (D-7),
C = context/doc. 110 identified requirements = 106 IDs + 4 justified links;
PPT-085/086 are grouping rows.

```
001|1|Explainable behavioral anomaly detection for containerized apps (name ProcessPulse-C linked)|all|P
002|1|OS course project review deliverable|all|C
003|2|Containers raise monitoring/security complexity|M1|C
004|2|Traditional methods miss behavioral threats|-|C
005|2|Cloud-native vulnerabilities (threat model)|M3|C
006|2|Define behavioral anomaly detection for containers|M1|P
007|2|Survey container security + XAI literature (slide-5 headings linked)|M1|Pa
008|2|Identify interpretability gap|M1|Pa
009|2|Combine syscall analysis with explainable ML|M1,M4,M5|P
010|3|Namespaces/cgroups -> container identity|M1|V (DIT-1)
011|3|Shared host kernel -> host-side observation|M1|V (DIT-1)
012|3|System calls reveal behavior|M1|V (syscall telemetry; features M2)
013|3|Resource use reveals behavior|M0,M1|V (resource telemetry; features M2)
014|3|Network activity reveals behavior|M1b|P
015|3|Baseline profiles enable detection|M3,M4|P
016|3|ML detects subtle deviations (high-dim telemetry)|M4|P
017|3|XAI opens black box|M5|P
018|3|Analysts validate alerts / understand threats|M6|P
019|3|Diagram CONTAINERS->SYSCALLS->ML->XAI|all|P
020|4|Behavior-based, evades-signature problem|M4|P
021|4|Adaptive detection for zero-day|M4|P
022|4|Noisy telemetry|M2|P
023|4|Orchestration shifts baselines (drift)|M2,M4,M7|U
024|4|Black-box lacks transparency|M5|P
025|4|High false positives|M4,M7|P
026|4|Alerts lack explanation|M6|P
027|4|Alert-to-remediation gap|M6|P
028|5|Falco (rule-based syscall monitoring); optional comparator|M1,M7|P
029|5|Abed 2015 syscall frequency|M2|P
030|5|Lin 2018 namespaces/seccomp (privesc design)|M3|P
031|5|Combe 2016 attack surfaces (threat model)|M3|P
032|5|Creech&Hu syscall patterns -> bigrams|M1b,M2|P
033|5|DeepLog|future|U
034|5|LIME|M5|P
035|5|SHAP|M5|P
036|6|Qualitative literature mapping (4 categories; placeholder labels defect linked)|M1|U
087|6|Chart is qualitative, not experimental data|M1,M7|P
037|7|Gap: integrated telemetry + real-time detection + explainability|M6,M7|P
038|7|Detection and explanation together in container context|M5,M6|P
039|7|Actionable incident-response insight|M6|P
040|7|Obj01 design monitoring framework|M0,M1|Pa
041|7|Obj02 features from syscalls + resource use|M2|P
042|7|Obj03 ML detection for containers|M2,M4|P
043|7|Obj04 explainable alerts for root-cause analysis|M5,M6|P
044|8|Syscalls via eBPF|M1|V
045|8|Resource metrics via eBPF -> C /proc (D-1)|M1|P
046|8|Network activity via eBPF|M1b|P
047|8|Preprocessing: cleaning|M2|P
048|8|Preprocessing: normalization|M2,M4|P
049|8|Preprocessing: noise filtering (undefined)|M2|U
050|8|Features: sequences|M1b,M2|P
051|8|Features: frequency patterns|M2|P
052|8|Features: temporal|M2|P
053|8|Baseline: ML profiles of normal behavior|M4|P
054|8|Deviation detection ("real-time" linked to 091/076)|M4,M6|P
055|8|Human-readable SHAP evidence|M5,M6|P
088|8|Human-readable LIME evidence|M5,M6|P
056|8|Alert output: context for analyst review|M6|P
057|8|Two-phase method|all|P
058|9|Docker runtime layer|M1,M3|Pa (DIT-1; M3 workloads pending)
089|9|Kubernetes runtime|-|X
059|9|Telemetry collectors module|M1|V
060|9|Profiles|M2,M4|P
090|9|Temporal encoding|M2|P
061|9|"ML classifier" -> IF + threshold (D-2)|M4|P
091|9|Real-time inference|M4,M6|P
062|9|SHAP/LIME attribution module|M5|P
063|9|Dashboard & alert interface|M6|P
064|9|Two-layer flow|all|P
065|10|Representative container workloads|M3|P
094|10|Injected anomalies with ground-truth timing|M3|P
066|10|Cryptomining simulation|M3|P
067|10|Privilege-escalation simulation|M3|P
068|10|Data-exfiltration simulation|M3|P
069|10|Precision|M4,M7|P
070|10|Recall|M4,M7|P
071|10|F1|M4,M7|P
072|10|False-positive rate|M4,M7|P
073|10|Detection latency|M6,M7|P
074|10|Explanation usefulness score (hit@3, D-11)|M5,M7|P
075|10|High accuracy (no numeric target)|M7|U
092|10|Minimal false positives (target value)|M7|U
076|10|Production-suitable real-time latency (no target)|M7|U
077|10|Expert-validated explanations (raters undefined)|M7|U
093|10|Interpretable explanations|M5,M7|P
078|11|Contribution: eBPF + interpretable ML workflow|M7|P
079|11|Contribution: modular real-time architecture, human-readable evidence|M1-M6|P
080|11|Contribution: accuracy + transparency|M7|P
081|11|Plan01 implementation: probes, features, ML integration|M1,M2,M4|Pa (probes done)
082|11|Plan02 dataset: benign + simulated attacks|M3|P
083|11|Plan03 experiments: accuracy, explanations|M7|P
095|11|Plan03 experiments: overhead|M1,M7|Pa (M1 matrix measured; M7 pending)
084|11|Plan04 refinement from empirical findings|M7|P
085.1-085.7|12|Literature refs [1]-[7] (Abed, Combe, Lin, Creech&Hu, Du, Ribeiro, Lundberg&Lee)|M1|P (DOIs unverified)
086.1-086.6|12|Tool refs [8]-[13] (Falco, eBPF.io, Docker security, K8s security, SHAP, LIME)|M1|P (URLs unverified)
```

Mastery-prompt requirements (not PPT): MP-01 versioned C collector, MP-02 BCC
collector, MP-03 monotonic time, MP-04 PID+start-time identity, MP-05 Isolation
Forest, MP-06 SHAP background set, MP-07 overhead, MP-08 changelog, MP-09 MAD
baseline comparator, MP-10 visible event loss, MP-11 reproducibility.
