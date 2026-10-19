# Glossary

[← Onboarding index](README.md)

Written for someone who can program but has never worked with eBPF. Terms
are grouped by topic; *(planned)* marks roadmap concepts with no code yet.

## Kernel and eBPF

- **Kernel / userspace:** the kernel is the core of the operating system
  and runs privileged code; userspace is where ordinary programs (and our
  agent) run.
- **System call (syscall):** a program's request to the kernel, such as
  `openat` (open a file), `execve` (run a program), `clone` (create a
  process or thread), `connect` (connect a socket).
- **Syscall entry / exit:** the moment a syscall starts (arguments known)
  and the moment it returns (result known). ProcessPulse-C counts
  **entries**, which are attempts, not successes.
- **eBPF (extended Berkeley Packet Filter):** a way to run small, verified
  programs *inside* the Linux kernel when certain events happen, without
  writing a kernel module.
- **BPF program / probe:** one such small program, attached to an event.
- **Verifier:** the kernel component that checks a BPF program is safe
  (bounded loops, valid memory access) before it is allowed to run. Its log
  reports how many instructions it "processed".
- **BCC (BPF Compiler Collection):** the toolkit used here (Python package
  `bcc`, apt `python3-bpfcc` 0.35). It compiles C-like BPF source at
  runtime with clang and loads it. It needs kernel headers, provided by the
  `kheaders` module on this WSL kernel.
- **Tracepoint:** a stable, named hook point in the kernel, for example
  `syscalls:sys_enter_openat` or `sched:sched_process_exit`. Its *format*
  (in tracefs) lists the fields a program can read. The project uses
  **tracepoints only**, no kprobes (D-15, N2).
- **kprobe / kretprobe / fentry:** hooks on arbitrary kernel functions.
  They are more powerful and less stable, and are **not used** here.
- **tracefs:** a virtual filesystem (`/sys/kernel/tracing`) that exposes
  tracepoints and their formats. Root only.
- **BPF map:** a key → value store shared between BPF programs and
  userspace. Examples: `counts` (process → syscall counters), `bigrams`,
  `netc`. Maps have a **fixed capacity**: when full, an insert fails, which
  must be counted.
- **Preallocated hash map:** a map whose slots exist up front. A deleted
  slot can be reused *immediately*, which is why the purge needs an RCU
  barrier.
- **RCU (Read-Copy-Update) and grace period:** a kernel synchronization
  scheme. `synchronize_rcu()` waits until every reader that started before
  the call has finished. The project reaches it from userspace through
  `membarrier(MEMBARRIER_CMD_GLOBAL)`, wrapped as `rcu_barrier()` in
  `bpf_collector.py`.
- **Unified BPF program:** since S1, one compiled program contains every
  enabled capability, selected with `-DPPC_CAP_<NAME>` flags.
- **Capability:** a selectable part of that program: `counts`, `bigrams`,
  `net` (S3.1/S3.2, on branch `wip/s3.2-network`, not accepted). `priv` is reserved.
- **Detach:** removing a program from its tracepoint while keeping its
  maps. This is step 1 of the final drain.

## Processes and identity

- **PID (process ID) / TGID (thread-group ID):** the number of a process.
  In Linux a process is a *thread group*, and its ID is the TGID.
- **TID (thread ID):** the number of one thread. The main thread's TID
  equals the TGID.
- **PID namespace:** a separate numbering of processes. Containers have
  their own, so a process has one PID per namespace level. In WSL2 the
  Ubuntu distro is at level 2.
- **PID reuse:** after a process exits, its PID can be given to a new
  process. Identifying a process by PID alone is therefore wrong.
- **Process identity (ProcessKey):** `(boot_id, distro pid-namespace inode,
  distro tgid, start_ticks)`. The start time distinguishes a reused PID.
- **start_ticks:** the process start time in clock ticks since boot
  (USER_HZ = 100), equal to field 22 of `/proc/<pid>/stat`.
- **Unresolved event:** an event whose process can't be identified in the
  distro namespace (for example, WSL's own `init`). It is counted, never
  attributed.
- **Self-exclusion:** the agent excludes its own processes from the
  telemetry; entries recorded before the exclusion are **purged** and
  counted.
- **Two-phase reclaim:** an exited process is reported once with its final
  values, then deleted at the next snapshot, but only if nothing changed in
  between.
- **cgroup / container attribution:** a Docker container's processes live
  in a cgroup such as `docker-<id>.scope`. The container ID is parsed from
  that path.
- **DIT-1:** the Docker integration acceptance test (`CLAUDE.md` §9). It
  passed 3 consecutive runs in M1.

## Per-thread state

- **Thread slot:** a per-thread entry (`threads` map) that remembers the
  previous syscall, for bigrams, and detects a reused TID.
- **Per-thread stash:** a per-thread entry (`net_stash`, S3.2) that carries
  information from a syscall's *entry* (socket class, destination class) to
  its *exit* (result). Outcomes: matched, full, overwritten, orphaned, exit
  without entry.

## Telemetry format

- **JSONL (JSON Lines):** one JSON object per line.
- **Schema:** a machine-readable definition of a record's fields, in
  `processpulse/schemas/telemetry.v1.json` and `.v2.json`. `"v"` is the
  version.
- **Byte rule:** at most 65,536 bytes per record (without the LF), and no
  CR or LF inside.
- **Snapshot:** one framed reading of the BPF maps: begin, process records,
  removals, end.
- **Keyframe:** a snapshot that re-sends every process, so a consumer can
  (re)build the full state.
- **Epoch:** one load of the BPF program. Counters only compare within an
  epoch.
- **Manifest:** `manifest.json`, the run metadata: configuration,
  capabilities, drain outcome, `status`.
- **Final drain / drained snapshot:** the end-of-run procedure (detach, RCU
  barrier, two equal reads) and the single snapshot taken after it, marked
  `drained: true`.

## Bigrams and network data

- **Bigram:** a pair of consecutive observed syscalls of one thread (or a
  segment marker followed by a syscall), counted per process.
- **Segment marker:** `START_NEW` (thread started after arming),
  `START_ATTACH` (thread existed before), `START_LOST` (a pair may have been
  lost), `EXEC` (first call after exec).
- **`pairs_lost`:** per process, the counted entries whose pair could not be
  recorded.
- **Socket class (net):** `inet4_tcp`, `inet4_udp`, `inet4_other`, the same
  for `inet6`, `local_ipc` (Unix/netlink/vsock), `other`, `unknown`.
- **Destination class (net):** `loopback`, `private`, `link_local`,
  `special`, `public`, `unknown`. Raw addresses and ports are never kept.

## Correctness and evidence

- **Loss counters:** health counters recording every event that couldn't be
  recorded, and why. Examples: `counts_map_full`, `bigram_dropped`,
  `net_map_full`, `stash_full`.
- **R-LOSS / R-NLOSS:** the approved rules saying exactly which counter each
  kind of loss goes to, for bigrams and network data.
- **Invariant:** an equation that must hold if nothing was silently lost or
  double-counted (I-B1–I-B5, I-N1–I-N6). The result is PASS, FAIL or NOT
  APPLICABLE.
- **Quiescent:** a process whose values are final (drained, reclaimed after
  exit, or a known-idle helper). Exact checks need it.
- **Ground truth / oracle:** an independent count of what *should* have been
  recorded, usually a scripted helper's own tally. It is never computed from
  the collector's data.
- **Equivalence probe:** `tools/acceptance/s1_equivalence.py`, which checks
  that counts-only behavior is unchanged (34 fields against the S1
  baseline).
- **Strict startup / degraded mode:** by default a requested capability
  that fails to start fails the run; `--allow-degraded` continues counts-only
  and marks the rest unavailable.
- **Acceptance evidence:** saved outputs under `results/acceptance/` that
  back every claim.

## Git and GitHub workflow

- **`master`:** the main branch on GitHub. It holds committed work, and
  only the owner merges into it.
- **`wip/s3.2-network`:** the work-in-progress branch holding the unfinished,
  **not accepted** S3.1/S3.2 network capability.
- **Task branch:** your own branch for one task (`<name>/<task>`), created
  from `master` or from the WIP branch.
- **Draft pull request (PR):** a proposal to merge your branch. "Draft"
  means it is not ready and can't be merged by accident. Teammates review
  and comment there.
- **History rewrite / hash map:** on 2026-10-19 every commit hash changed
  once (only commit messages were edited). `docs/commit-hash-map.md`
  translates the old hashes that older documents cite.

## Machine learning and explanations *(planned, M4–M5)*

- **Feature:** a number computed from telemetry for one time window, such
  as the openat rate or the bigram frequency.
- **Isolation Forest:** an anomaly detector that isolates unusual points
  with random splits. The project's score is
  `F(x) = score_samples(T(x))`; a lower score means more anomalous (D-2).
- **Threshold τ:** an empirical quantile of F on benign validation runs; a
  window is anomalous if F(x) < τ.
- **SHAP:** assigns each feature a contribution φᵢ to the score; with this
  project's convention, negative φᵢ pushes toward anomalous. Primary
  explainer (D-3).
- **LIME:** fits a simple local surrogate model around one point to explain
  it. Mandatory secondary explainer.
- **hit@3:** an explanation-usefulness metric: whether a pre-registered
  indicator appears in the top 3 features (D-11).
