# Unified BPF collector (M1b S1)

Status: S1 committed (`391c988`); the `bigrams` capability (S2.3) is in the working tree, uncommitted.
Code: `processpulse/bpf_collector.py`, `processpulse/vocab.py`, `bpf/common.h`,
`bpf/syscall_counter.bpf.c`, `bpf/core.bpf.c`. `processpulse/syscalls.py` keeps
the M1 interface (`SyscallCollector`, `calibrate`, `SYSCALLS`, `FAMILIES`) on top.

## Compilation units

`BpfCollector.start()` performs exactly **two** BCC compilations, recorded in
`compilations` and in `build_info()`:

1. `calibrate` — `bpf/calibrate.bpf.c`, a one-shot `getpid` probe that measures the
   distro pid-namespace level and inode from the agent's own process. It is
   unloaded before step 2. (It reads raw pid levels before the distro level is
   known, so it does not use `common.h`.)
2. `unified` — one program assembled as
   `common.h` + the source of every enabled capability + `core.bpf.c` + generated
   per-syscall probes, compiled with `-DPPC_CAP_<NAME>=1` per capability and
   `DISTRO_LEVEL`, `DISTRO_PIDNS_INUM`, `MAX_PROCS`, `MAX_THREADS`, `NSYSCALLS`.

Shared definitions live once in `common.h`: the process key (`struct pkey`, the
M1 layout), `resolve()` (the identity check of CLAUDE.md §5), the exclusion map,
the per-thread slot map, the health array and `hinc()`. A tracepoint can carry
only one probe per program, so the scheduler hooks (`sched_process_exit`,
`sched_process_exec`) live in `core.bpf.c` and dispatch to the capabilities that
were compiled in.

## Capabilities

| Name | Status | Source | Tracepoints |
|---|---|---|---|
| `counts` | implemented (the M1 syscall-entry counters) | `syscall_counter.bpf.c` | `syscalls:sys_enter_<v>` for every vocabulary entry |
| `bigrams` | implemented (M1b S2.3); requires `counts` | `bigrams.bpf.c` | none of its own |
| `priv`, `net` | reserved; refused with "not implemented in this stage" | — | — |

Valid selections are `("counts",)` and `("counts", "bigrams")` (any order,
normalised). `bigrams` without `counts`, duplicates, empty, unknown or
reserved names are refused before compiling. Sources are assembled as
`common.h`, `bigrams.bpf.c` (if selected), `syscall_counter.bpf.c`,
`core.bpf.c`, probes: the counter calls the bigram hooks, so their source
comes first.

Every program also attaches `sched:sched_process_exit` and `sched:sched_process_exec`.
`start()` refuses to run unless the attached set equals
`required_tracepoints(capabilities)` exactly; preflight checks the same list.
Map key/value layouts of `counts` and `info` are the M1 layouts, so the
schema-v1 `syscall_snapshot` record is unchanged.

## Vocabulary

`processpulse/vocab.py` defines the ordered syscall set (index = counter slot)
and families; `VOCABULARY.id` = `v<version>-<first 12 hex of sha256(canonical JSON)>`.
The current vocabulary is the M1 set: `v1-3aba869d1752`. Changing the version,
a name, the order or a family changes the identifier (tests pin it).

## Per-thread slots (F4)

`threads` (in `common.h`) maps the host TID — a map key only, never emitted as
identity — to `{thread start_boottime, process key, distro TID}`.

- **Created** on the first attributed, non-excluded counted event of a thread.
- **Deleted** at `sched_process_exit` for every exiting thread (not only when the
  whole group dies), and at `sched_process_exec` for the old TID when a non-leader
  thread execs (`de_thread` gives it the leader's TID; its old TID never exits).
- **Stale detection:** a slot whose recorded start time differs from the current
  thread's belongs to an earlier thread with the same TID; it is replaced and
  counted (`thread_slot_stale`).
- **Self-exclusion** purges the excluded process's slots with its counters.
- Process-level counters and exit/reclaim handling do not depend on the slots.

Counters (`thread_map_full`, `thread_slot_stale`, `thread_slots_cleaned`,
`exec_refreshes`) and the slot count are available from `thread_health()`. They
are **not** in the v1 or v2 records (both schemas are fixed); exposing them is
left to the stage that consumes the slots.

## Process metadata refresh (F9)

`comm` and `cgroup_id` are captured when the process's entry is created (its
first counted event) and refreshed at `sched_process_exec` — no longer on every
counted event. `last_ktime` (diagnostic, used by the clock-contract test) is
still updated on every event.

Fields that are **not** refreshed without an exec:

| Field | Changes without exec when… | Effect |
|---|---|---|
| `comm` | the process renames itself (`prctl(PR_SET_NAME)`, writes to `/proc/<pid>/comm`) | the record keeps the name from creation or the last exec (tested) |
| `comm` | threads carry different names | the record shows the name of the thread that created the entry or exec'd |
| `cgroup_id` (and so `container`) | the process is moved to another cgroup (`cgroup.procs` write) | the record keeps the creation/last-exec cgroup until the next exec (tested) |
| `level`, `container_pid`, `host_tgid` | never for a given process (pid namespaces are fixed at creation) | — |

Container start is unaffected: `runc init` joins the container's cgroup and
then execs the container program, so the exec refresh records the container
scope (DIT-1 check 4).

## Bigrams capability (M1b S2.3)

Contract: `docs/telemetry-v2.md` §8 and the S2 design (R-LOSS, markers,
I-B1–I-B5, approved as A8; decisions U2, U4, U5, U7, U9). Kernel side:
`bpf/bigrams.bpf.c` plus `#ifdef PPC_CAP_BIGRAMS` hooks in
`syscall_counter.bpf.c` and `core.bpf.c`. Userspace: `BpfCollector`
(`capabilities=("counts", "bigrams")`). Records are not emitted yet; the
emitter and the agent option are a later S2 step.

### Maps and layouts

| Map | Key | Value | Capacity |
|---|---|---|---|
| `bigrams` | `struct bkey {pkey proc; u16 a; u16 b; u32 pad}` (24 bytes, no implicit padding, zero-initialised) | `u64` count | `max_pairs`, default 131,072 |
| `bglobal` (array) | 0 | `{u64 armed_boot_ns; u64 last_thread_full_ns; u32 armed; u32 pad}` | 1 |
| `counts` (bigram builds only) | `pkey` | `c[NSYSCALLS]` + `u64 pairs_lost` (U7) | `max_procs` |
| `threads` | host TID | `tslot`; `u16 prev` uses half of the S1 padding, so the slot stays 32 bytes in every build | `max_threads` |

Counts-only builds compile none of this: the `counts` value keeps the M1
layout and there is no `bigrams`/`bglobal` map (tested on the assembled
source and on a running program). The health array has 12 entries in every
build; indices 9–11 (`bigram_map_full`, `bigram_dropped`, `pre_arm_events`)
stay 0 without the capability.

Measured on this kernel (one start, `/proc/self/fdinfo` `memlock`; H-MEMLOCK:
the field exists): `bigrams` 12,585,664 bytes (12.00 MiB) at 131,072
entries; all seven maps of a bigram build 20,730,392 bytes = **19.77 MiB
(20.73 MB)**. Evidence: `results/acceptance/m1b/s2.3/`. The design estimate of
about 10 MiB for the bigram map counted only the entries (80 bytes × 131,072).
Every hash map's measured value fits (entries + 16) × (48 + key + value) +
buckets × 16 + 1,472 bytes on this 16-CPU host, a model fitted to the five
measured maps (not taken from kernel source): the bucket array (2 MiB for
131,072 buckets) and one spare element per possible CPU account for the
difference.

### Codes

`a` and `b` are codes: 0–8 the vocabulary syscalls in `vocab.py` order
(`v1-3aba869d1752`), then the markers `M_START_NEW` 9, `M_START_ATTACH` 10,
`M_START_LOST` 11, `M_EXEC` 12 (`NSYSCALLS + 0..3`; a unit test checks them
against `processpulse.bigrams.MARKER_CODES`). `b` is always the observed call;
a marker is only ever stored in `prev`, so it can only be a first element
(I-B5). The decoder rejects a marker as second element.

### Per-thread state and markers

A slot's `prev` is set when the slot is created (first attributed,
non-excluded event of the thread, or its exec), from the thread's
`start_boottime`:
- `START_LOST` if it started before the last thread-map-full event
  (`last_thread_full_ns`);
- else `START_NEW` if armed and it started at or after `armed_boot_ns`;
- else `START_ATTACH` (existed before arming, or created before arming).

A stale slot (same host TID, different start time) is a new thread and is
classified the same way (`thread_slot_stale` counted). `sched_process_exec`
(after S1 dropped the old TID's slot) finds or creates the exec'ing thread's
slot and, when armed, sets `prev = EXEC`; before arming the slot keeps its
marker. Thread exit deletes the slot (S1).

### R-LOSS and health

| Path | Count | Pair | `pairs_lost` | Health | Next `prev` |
|---|---|---|---|---|---|
| row 1: no counts entry | lost | lost | — | `counts_map_full`, `bigram_dropped` | `START_LOST` |
| row 2: no slot | recorded | lost | +1 | `thread_map_full` (in `thread_touch`), `bigram_dropped`; `last_thread_full_ns` set | next slot `START_LOST` |
| row 3: bigram map full | recorded | lost | +1 | `bigram_map_full`, `bigram_dropped` | s |
| before arming (U2a) | recorded | lost | +1 | `pre_arm_events`, `bigram_dropped` | unchanged |
| ok | recorded | recorded | — | — | s |

`thread_map_full` counts slot-creation failures, which include an exec that
finds no room. An exec is not a syscall entry, so it loses no pair: for
example, a helper that ran entirely with a full slot map gave
`thread_map_full` +4 and `bigram_dropped` +3.

### Arming

`start()` arms right after the tracepoints are verified (`arm=False`
defers it, so `arm()` can be called later). `arm()` reads `CLOCK_BOOTTIME`
(the clock of `start_boottime` and `bpf_ktime_get_boot_ns()`), writes
`armed_boot_ns`, then sets `armed`. Disarming and the final drain are not
implemented (drain is a later S2 step).

### Reading, reclaim and purge

- `read_bigrams()` reads the map (`items_lookup_batch()`, else per-key
  `items()`; H-BATCH: batch works on this kernel), groups raw entries by
  process `(start_ns, tgid)` and then decodes them. Every process with a counts
  entry has a table (empty if it has no pair). Entries with n = 0 (read between
  insertion and increment) are dropped and counted in `zero_entries` (P-ZERO);
  entries whose process has no counts entry are counted in `orphan_entries`.
  The reads are sequential, not atomic.
- Exit reclaim (two-phase): an exited process is reclaimed only when its
  counts, `pairs_lost` and pair sum are unchanged since its exit report; its
  pair entries are deleted with it. `snapshot()` keeps the decoded tables
  of that read in `last_bigrams`.
- `exclude()` sets the exclusion first, then deletes the process's counts,
  info, slots and pair entries, adding them to `purged_counts`,
  `purged_pairs` and `purged_pairs_lost` (P-PURGE).
- `bigram_health()` returns the eight `bigram_health` end-record fields.

### Known limitations

- `last_thread_full_ns` and `bglobal` are written without compare-and-swap.
  Two CPUs racing can leave an older full-time, so a thread can be classified
  `START_NEW` although an earlier pair of it was lost. Its `pairs_lost` still
  shows the loss, so I-B1′ is unaffected, and exact I-B4 applies only when
  `pairs_lost` = 0.
- `START_LOST` is assigned to every thread that started before the last
  slot-map-full event, including threads that lost nothing.
- **Exclusion purge race (S2.3 audit, finding 2): fixed, see "Exclusion
  purge" below.** The fix relies on a kernel RCU guarantee, which is argued
  from kernel source, not inspected on this build; the race itself was never
  reproduced.

### Exclusion purge

**The problem had two causes:**
1. `exclude()` used to set the exclusion and immediately read and delete the
   process's counts, info, pair entries and slots. A probe invocation that
   passed the exclusion check just before could still be running. Its late
   update could be lost from the purge totals, recreate an entry, or land in a
   deleted element that a preallocated hash map had already reused for another
   key: another process's counter or another thread's `prev`.
2. The `sched_process_exit` hook wrote `info.exited` without checking the
   exclusion at all, so even an exit that began after the exclusion could race
   the purge. A deterministic test showed this before the fix: an info entry
   of an excluded process got `exited = 1`.

**The fix:**
1. Every BPF path that writes an entry of a process now checks the exclusion
   first: the syscall probes (S1), the exec hook (S1), and the exit hook
   before `counts_on_exit` (new). The exit hook still deletes its own thread
   slot first, but a delete holds no pointer afterwards.
2. `exclude()` sets the exclusion, then calls `rcu_barrier()`, then reads and
   deletes. `rcu_barrier()` is `membarrier(MEMBARRIER_CMD_GLOBAL)`, for which
   the kernel runs `synchronize_rcu()`.

**Why it is sufficient:**
- BPF programs on these tracepoints (perf-attached by BCC) run inside
  `trace_call_bpf()` under `rcu_read_lock()`, with preemption disabled.
  `synchronize_rcu()` waits for every reader that began before it, including
  preempt-disabled regions; `CONFIG_PREEMPT_RCU=y` here.
- By the RCU grace-period guarantee, a reader that does not finish before the
  barrier returns started after it began, so it sees the exclusion entry
  published before the call and returns without writing.
- So after the barrier, no program holds a pointer into an entry of that
  process. The values read are final (purged counts = purged pairs + purged
  `pairs_lost`, the per-entry identity) and no later write can reach a deleted
  element.

**Requirements and cost:**
- Needs `MEMBARRIER_CMD_GLOBAL`: `query` reports it on this kernel, and there
  is no `nohz_full`. If it is unavailable, `exclude()` raises instead of
  purging unsafely, and `start()`, which excludes the agent itself, fails
  early.
- Measured (`results/acceptance/m1b/purge-race/barrier_timing.json`): the
  barrier takes 8 ms median idle (max 16) and 16 ms median with two busy
  helpers (max 28). `exclude()` takes 27–31 ms median (max 51).

**Tests (`tests/test_exclusion_purge.py`):**
- excluding an idle process, giving exact purge totals;
- 10 exclusions of busy processes while another helper stays busy; the
  purge stays balanced, no entry survives or reappears, and the other helper's
  counts and pair table stay exact;
- 20 exclusions right after `Popen`, as the agent does;
- the exit-hook gate, deterministically;
- a counts-only build with busy exclusions.

The busy-process tests passed before the fix as well: the in-flight window is
microseconds, and the old purge read milliseconds after setting the flag. They
are exact regression checks; the barrier's guarantee rests on the RCU argument
above and on `test_exclude_sets_the_flag_then_waits_then_purges`, which
requires the barrier before any read or delete.
- Map reads are not atomic; exact checks require an idle process. The drained
  final snapshot (U3, H-DRAIN) is not implemented yet.
