# Purge synchronization proof — verification audit (2026-10-19)

Scope: verify that the exclusion-purge fix (`BpfCollector.exclude()`: set the
exclusion → `rcu_barrier()` → read and delete; the `sched_process_exit` hook
gated by the exclusion) is correct on the running WSL2 kernel. This was a
verification only: no implementation file was changed. Source references
below are to tag `linux-msft-wsl-6.18.33.2` of
https://github.com/microsoft/WSL2-Linux-Kernel (commit
`c21a03b2943d147c280bdf32530d4fe6badfd6bd`), for example
`https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.18.33.2/kernel/sched/membarrier.c#L651-L657`.

**Verdict: PURGE SYNCHRONIZATION PROOF VERIFIED**, with the residual risks in §G
(none of them breaks the guarantee for in-flight writers of the excluded process).

## A. Kernel identity and source correspondence — VERIFIED (with one stated limit)

| Evidence | File here | Result |
|---|---|---|
| `uname -a`, `/proc/version` | `kernel-identity.txt` | `6.18.33.2-microsoft-standard-WSL2`, `root@f1bbfb02316b`, gcc 13.2.0 / binutils 2.41, `#1 SMP PREEMPT_DYNAMIC Thu Jun 18 21:54:43 UTC 2026` |
| Tag exists for exactly this release | (`git ls-remote`) | `refs/tags/linux-msft-wsl-6.18.33.2` → `c21a03b2…`; Makefile 6.18.33, EXTRAVERSION `.2`; `CONFIG_LOCALVERSION="-microsoft-standard-WSL2"` |
| Build config | `source-correspondence.txt` | `/proc/config.gz` vs the tag's `arch/x86/configs/config-wsl`: **6,914 of 6,914** normalized option lines identical (including `CONFIG_CC_VERSION_TEXT`) |
| Headers embedded in the running kernel (`/sys/kernel/kheaders.tar.xz`) | `kheaders-vs-tag-normalized.txt` | After the comment stripping the tag's `kernel/gen_kheaders.sh:36-41` applies: **6,491 of 6,491** headers identical; only 9 build-generated headers are not in the tree. Identical: `tracepoint.h`, `trace/perf.h`, `bpf.h`, `rcupdate.h`, `preempt.h`, `cleanup.h`, `uapi/linux/membarrier.h`. (`kheaders-vs-tag.txt` is the raw comparison before stripping; it differs, as expected.) |
| Build strings in kheaders | `symbols-and-build-strings.txt` | `UTS_RELEASE`, compile host `f1bbfb02316b` and compiler equal `/proc/version` |
| Functions of the proof present in the binary (`/proc/kallsyms`) | `symbols-and-build-strings.txt` | `trace_call_bpf`, `perf_syscall_enter`, `perf_call_bpf_enter`, `perf_trace_run_bpf_submit`, `__x64_sys_membarrier`, `synchronize_rcu`, `htab_map_delete_elem`, `htab_map_update_elem`, `pcpu_freelist_push`, `__perf_event_set_bpf_prog`, `perf_event_attach_bpf_prog`: 1 each. `perf_sysenter_enable`: 0 (static; *inference*: inlined) |
| Sources inspected | `source-correspondence.txt` | sha256 of every source file used |

Limit: the `.c` files (membarrier, bpf_trace, trace_syscalls, events/core,
hashtab, rcu/tree) are bound to the binary by provenance: the same tag whose
release string, config, compiler, build host and every embedded header match.
Byte-level identity of the compiled `.c` code was not proven; that would need
a reproducible build or disassembly of the shipped kernel.

## B. MEMBARRIER_CMD_GLOBAL — VERIFIED

- `kernel/sched/membarrier.c:651-657`: `case MEMBARRIER_CMD_GLOBAL:` returns
  `-EINVAL` if `tick_nohz_full_enabled()`. Otherwise, `if (num_online_cpus() > 1)
  synchronize_rcu(); return 0;`
- `:643-649`: `QUERY` returns `MEMBARRIER_CMD_BITMASK` with the `GLOBAL` bit cleared
  under nohz_full. `:634-636`: non-zero flags give `-EINVAL`; we pass 0.
- Live: no `nohz_full` (`CONFIG_NO_HZ_FULL` not set); 16 CPUs online. `QUERY`
  returns 1023, which equals `MEMBARRIER_CMD_BITMASK` for this config:
  `membarrier.c:142-165` with `CONFIG_RSEQ=y` and
  `CONFIG_ARCH_HAS_MEMBARRIER_SYNC_CORE=y` covers bits 0–9 of
  `uapi/linux/membarrier.h:150-159`. So the call really reaches membarrier with
  `cmd=QUERY`. `GLOBAL` returns 0 and took 4.6–28 ms
  (`../barrier_timing.json`), consistent with a grace-period wait and not with
  the single-CPU immediate return.
- The guarantee needed is the **grace-period** guarantee of
  `synchronize_rcu()`, not callback completion (the kernel's `rcu_barrier()`).
  `kernel/rcu/tree.c:3303-3340` (contract):
  - it returns after all pre-existing RCU read-side critical sections
    completed, including preempt-disabled regions (v5.0+);
  - each CPU whose critical section extends beyond the return executed a full
    memory barrier after the call began and before that section began.
- Single-CPU case (`num_online_cpus() == 1`): no wait. That is sound only
  because the programs run with preemption disabled (C), so no program can be
  mid-flight while the caller runs on the only CPU.
- Naming note: the project's Python function is called `rcu_barrier()` but
  provides the `synchronize_rcu()` guarantee, not the kernel `rcu_barrier()`
  one.

## C. BPF tracepoint execution under RCU — VERIFIED

- Live (`attach-types.txt`): the collector holds 11 `BPF_PROG_TYPE_TRACEPOINT`
  programs, 11 `perf_event` fds and no bpf links. BCC attaches through perf
  events (`PERF_EVENT_IOC_SET_BPF`); `core.c:11282-11290` admits only
  `TRACEPOINT` programs on tracepoint and syscall perf events.
- **Syscall entry** (`syscalls:sys_enter_*`, 9 probes):
  - the tracepoint itself is faultable: `__DECLARE_TRACE_SYSCALL` uses
    `guard(rcu_tasks_trace)` (`tracepoint.h:288-304`), a flavour
    `synchronize_rcu()` does **not** wait for;
  - but `perf_sysenter_enable()` registers `perf_syscall_enter`
    (`trace_syscalls.c:652-661`), which disables preemption with
    `guard(preempt_notrace)()` (`:609-610`) and calls `perf_call_bpf_enter()`
    → `trace_call_bpf()` (`:590`, `:640-641`).
- **Scheduler hooks** (`sched_process_exit`, `sched_process_exec`): classic
  tracepoints; `__do_trace_##name` → `guard(preempt_notrace)()`
  (`tracepoint.h:271-276`) → `perf_trace_##call` → `perf_trace_run_bpf_submit()`
  (`trace/perf.h:53`) → `trace_call_bpf()` (`events/core.c:10977-10979`).
- `trace_call_bpf()` (`bpf_trace.c:109-153`): `cant_sleep()`; the programs run
  only in `rcu_read_lock(); bpf_prog_run_array(...); rcu_read_unlock();`
  (`:144-147`). `bpf_prog_run_array()` (`bpf.h:2296-2324`, header identical to
  the binary's) runs each program synchronously in that section. The recursion
  path (`:115-127`) runs no program at all.
- So every map lookup and write of our programs happens inside one classic RCU
  read-side critical section that also has preemption disabled.
  `synchronize_rcu()` waits for it whether or not the tasks-trace guard around
  the syscall tracepoint is still active.

## D. Ordering and late readers — VERIFIED

1. The exclusion is set: `bpf_collector.py:325`, a BCC map write, which is a
   synchronous `bpf(BPF_MAP_UPDATE_ELEM)`. The element is published with
   `hlist_nulls_add_head_rcu` (`hashtab.c:1174`) before the syscall returns.
2. Then `rcu_barrier()` runs (`:326`) on the same thread, and every failure
   raises (F).
3. A program invocation whose critical section began before
   `synchronize_rcu()` began has completed all its map accesses when it
   returns (B, C).
4. An invocation still running after the return began its critical section
   after a full barrier that follows the start of `synchronize_rcu()`
   (`tree.c:3325-3328`), so its lockless RCU lookup (`hashtab.c:665-694`) of
   `excluded` sees the published entry. Every writer of the excluded
   process's entries checks the exclusion before its first write in the same
   invocation (E), so it writes nothing. Invocations that start later are
   covered the same way.
5. Preallocated hash maps reuse a deleted element immediately
   (`free_htab_elem` → `pcpu_freelist_push`, `hashtab.c:933-940`, from
   `htab_map_delete_elem` `:1446-1447`), so the barrier is necessary. After
   it, no program can hold a pointer into an element of the excluded process:
   (3) covers the invocations that missed the flag and (4) the ones that see
   it. The read and delete loops (`:328-355`) therefore read final values and
   free elements nothing can write through.

## E. Map-write inventory — VERIFIED (complete for the four maps)

Attached programs: exactly 9 `sys_enter_*` probes and 2 scheduler hooks. No
`sys_exit_*`, raw tracepoint, kprobe or fentry programs (`attach-types.txt`;
11 tracepoints).

| # | Path | Maps written | Exclusion check vs. writes | Inside the RCU section? | Can write after exclusion or element reuse? |
|---|---|---|---|---|---|
| 1 | `count_syscall` (`syscall_counter.bpf.c:38-90`), all 9 `sys_enter_*` probes | threads: create/replace (`common.h:143`), `prev` (`bigrams.bpf.c:84,92,126`); counts: create (`:61`), increment (`:69`), `pairs_lost` (`bigrams.bpf.c:107,112,122`); bigrams: create (`:118`), increment (`:124`); info: insert (`:83`), `last_ktime` (`:86`); bglobal (`bigrams.bpf.c:80`, an array, never deleted) | **before** every write (`syscall_counter.bpf.c:52`) | yes | no |
| 2 | `sched_process_exec` (`core.bpf.c:30-48`) | threads: delete of the exec'ing thread's own former TID (`common.h:166`, **before** the check, a delete only); after the check (`core.bpf.c:38`): info `cgroup_id`/`comm` (`syscall_counter.bpf.c:107-108`), thread create + `prev = EXEC` (`bigrams.bpf.c:132-140`) | before all writes; the delete before it holds no pointer afterwards | yes | no |
| 3 | `sched_process_exit` (`core.bpf.c:9-28`) | threads: delete of its own slot (`common.h:156`, before the check, a delete only); info `exited` (`syscall_counter.bpf.c:96`) **after** the new check (`core.bpf.c:22`) | before the write (fixed in this change; before the fix it wrote unconditionally, shown by the failing test) | yes | no |
| 4 | `exclude()` (userspace, `bpf_collector.py:309-355`) | excluded: set; then counts/info/bigrams/threads deletes | n/a: this is the purge, after the barrier | n/a | — |
| 5 | `unexclude()` (`:357-361`) | excluded: delete | — | n/a | re-enables counting with fresh entries |
| 6 | `snapshot()` exit reclaim (two-phase) | counts/info/bigrams deletes of keys reported exited and unchanged since | no barrier; safe by argument: an exited group has no running threads, the exit hook's `exited` store (observed by the previous snapshot) is its last access to the element, and the hook runs once per group (`group_dead`); keys are unique per process (start time) | n/a | no |
| 7 | `arm()` | bglobal (array): in-place writes | not deleted | n/a | no |
| — | tests only | dummy fills, planted slots/info entries | test setup | — | — |

## F. Failure behaviour — VERIFIED (fail-closed), with side effects noted

- Every failure in `rcu_barrier()` raises before the first read or delete in
  `exclude()` (`bpf_collector.py:325-327`):
  - unsupported architecture → `RuntimeError` (`:95-97`);
  - `QUERY` < 0 or no `GLOBAL` bit (nohz_full) → `RuntimeError` (`:102-105`);
  - `GLOBAL` ≠ 0 → `OSError` with errno (`:106-108`).

  No unsafe purge can run. The unit tests cover each failure and the order.
- Side effects of a failure:
  - the exclusion stays set and nothing is purged, so the process's
    already-counted entries stay live; with the gated exit hook they are
    never marked exited, so they are never reclaimed;
  - in the agent, an exception from `on_spawn` on the restart path
    (`resource.py:184` → `_spawn` → `:147`) ends the supervisor thread;
  - `start()` (which excludes the agent itself) raises and leaves the program
    loaded until `close()`.

  These are robustness issues, not unsafe purges.
- `libc.syscall` is called without `argtypes`, so integers are passed as C
  `int` to a function taking `long`. It works on this system (the query mask
  is exactly 1023, and `GLOBAL` waits 4.6–28 ms) but is not portable by
  construction.

## G. Scope and residual risks

Purge correctness (the obligation) is distinct from the exclusion *policy*.

| Risk | Kind | Assessment |
|---|---|---|
| R1 Thread-slot ABA in the purge: slots are keyed by host TID and deleted by key after `items()`; if an excluded thread exits **and** its host TID is reused by a new thread that creates its own slot between that read and the delete, the new owner's slot would be deleted while its program may hold a pointer | userspace race, not an in-flight writer of the excluded process | TIDs are allocated cyclically (`kernel/pid.c:231-239`, `idr_alloc_cyclic`), so reuse needs `pid_max` allocations within the window. The host namespace's `pid_max` is not observable from the distro (the distro reads 4,194,304; at least 32,768 assumed). The fastest fork rate seen in this project is about 2,500/s (100,000 clones in about 40 s, S2.4), so reuse would take about 13 s at minimum, against at most 51 ms for `exclude()`. Not reachable in practice, but not formally excluded by the barrier. |
| R2 `exclude()` of an already-exited process racing a concurrent reclaim (the supervisor thread against the snapshot thread): the same key counted as purged and as reclaimed | userspace race | I-B2 would fail loudly. Not reachable in current use: the agent excludes only freshly spawned collectors and itself. |
| R3 Correspondence of the `.c` code by provenance (A) | evidence limit | Mitigated by config, compiler, build host, 6,491 headers and symbol presence. |
| R4 Failure-path side effects (F) | robustness | Fail-closed for safety. |
| R5 `libc.syscall` without `argtypes` (F) | portability | Works here. |
| R6 Exclusion by distro tgid; the agent never unexcludes dead collectors, so a later process reusing such a tgid is silently not counted; the exclusion map holds 64 entries (when full, `exclude()` raises before the barrier) | policy (S1) | Unchanged by the fix. |

## Evidence for the fix (verified against stored files)

- Stored (`../`):
  - `exclusion-purge-tests.log`: 5 passed, 194.55 s;
  - `exclusion-purge-tests-2.log`: 5 passed, 49.06 s, with durations;
  - `privileged-suite.log`: 80 passed, `rc=0`;
  - `make-test-py3.14.log`: 74 C checks, 0 failures; 525 passed, 1 skipped, `rc=0`;
  - `make-test-py-py3.12.log`: 525 passed, 1 skipped, `rc=0`;
  - `make-check.log`: `rc=0`;
  - `equivalence-after-fix.json`/`.txt`: 34 of 34 (the `.txt` begins with a UTF-8 BOM);
  - `barrier_timing.json`.

  Each pytest log records `bpf_stats_enabled` 0 and 0 cgroups and 0
  containers before and after.
- **Only transcribed, not stored:** the pre-fix exit-hook failure
  (`assert 1 == 0`), the busy tests passing on the unfixed code (61.50 s),
  and the 4 unit-test failures before the implementation. The README says so.
- The in-flight race was **never reproduced**; the busy tests are exact
  regression checks, not evidence that the barrier is needed.

## Commands run in this audit (all exit 0 unless noted)

| Command | Exit |
|---|---|
| `git rev-parse --show-toplevel`, `rev-parse HEAD`, `branch --show-current`, `diff --cached --name-only`, `diff --check`, `status --short` | 0 |
| `wsl -l -v` (Ubuntu was Stopped; the first command below started it, no explicit restart) | 0 |
| `kernel_identity.sh` → `kernel-identity.txt` | 0 (a first attempt through PowerShell `>` garbled the encoding; that file was removed and rewritten from inside WSL) |
| `git ls-remote --tags https://github.com/microsoft/WSL2-Linux-Kernel` | 0 |
| `fetch_src.sh` (blobless sparse clone of the tag into `~/ppc-audit-wsl-src`) | 0 |
| `config_compare.sh` → `source-correspondence.txt` (first run used the symlink `Microsoft/config-wsl`, which was not checked out, so the comparison was empty; corrected to `arch/x86/configs/config-wsl`) | 0 |
| `show.sh` / `grep` on the tag sources (read-only; one PowerShell-quoted `sed` attempt failed with exit 2 and was replaced by `show.sh`) | 0 |
| As root: `attach_types.py` → `attach-types.txt`; `cat /sys/kernel/debug/sched/preempt` (`(none) voluntary full lazy`) | 0 |
| As root: `kheaders_compare.sh` → `kheaders-vs-tag.txt`; `kheaders_compare2.sh` → `kheaders-vs-tag-normalized.txt` | 0 |
| `git sparse-checkout add /kernel/gen_kheaders.sh`, `/include`, `/kernel/pid.c` | 0 |
| As root: `symbols_check.sh` → `symbols-and-build-strings.txt` | 0 |

The downloaded and extracted sources stay outside the repository
(`~/ppc-audit-wsl-src`, `/root/ppc-audit-kheaders`, `/root/ppc-audit-tagcopy`)
and were only read.
