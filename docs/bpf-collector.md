# Unified BPF collector (M1b S1)

Status: implemented in the working tree (M1b stage S1), not committed.
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
| `bigrams`, `priv`, `net` | reserved; refused with "not implemented in this stage" | — | — |

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
