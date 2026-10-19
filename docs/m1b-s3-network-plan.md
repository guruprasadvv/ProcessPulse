# M1b S3: network telemetry: engineering plan

Status: decisions N1–N10 approved. S3.1/S3.2 are implemented (uncommitted;
see §11 for the implementation decisions). S3.3+ is [PLANNED]. Sections 1–10
are the plan as reviewed; facts are marked **FACT**. Date: 2026-10-19.
Base: `699c2c8` (S2.6).

## 0. Sources and labels

**Contract sources (authoritative):**
- `CLAUDE.md` §6 (network accounting table, blind spots, M1b acceptance
  tests);
- decisions D-4 (network via eBPF, process-attributed), D-15 (per-syscall
  tracepoints first), D-7 (no Kubernetes);
- §5 contracts: missing values are `null` + `*_err`, ProcessKey, health
  counters, byte rule.

**Planning sources (not in the repo; transcript `a487fe14`):**
- M1b plan v2 §3: hook table and validation matrix V1–V15.
- M1b plan v3:
  - D15: socket counters are separate from interface counters;
  - D16: the `entry_observed` / `exit_observed` naming;
  - hypotheses H-N1–H-N8;
  - decisions A13 (io_uring out), A14 (test resources), A15 (connect
    destinations classified in-kernel, no raw IPs or ports).

None of A13–A15 is recorded as approved.

**Stage label (needs confirmation).** In plan v3 the stages are S3 =
privilege indicators and S5 = network. A17 allows S3–S5 "in any order after
S2", and you asked for network next, labelled S3. This plan uses **S3 =
network**; the privilege stage keeps its own later number. The renumbering
should be recorded in `ENGINEERING_CHANGELOG.md` when approved.

**Architecture difference from plan v3.** Plan v3 D7 proposed one `BPF()`
compile per capability. S1 instead built a single unified program with
`PPC_CAP_*` flags (accepted, `391c988`), and S2 followed it. This plan
follows the implemented design (§2).

## 1. Facts gathered for this plan

Evidence: `results/acceptance/m1b/s3-plan/`.

| Item | Result | Evidence |
|---|---|---|
| H-FMT (network hooks): tracefs formats exist with the fields §6 expects | **FACT** | `tracefs-formats.txt` (read as root, 2026-10-19) |
| `sock:sock_send_length` / `sock_recv_length` | `sk, family (u16), protocol (u16), ret (int), flags (int)` | same |
| `sock:inet_sock_set_state` | `skaddr, oldstate, newstate, sport, dport, family, protocol, saddr[4], daddr[4], saddr_v6[16], daddr_v6[16]` | same |
| `syscalls:sys_{enter,exit}_{sendto,recvfrom,connect,accept4,socket}`, `sys_enter_{sendmsg,sendmmsg,recvmsg,recvmmsg,accept,write,sendfile64,splice}` | present, with the argument fields listed in the file | same |
| H-N1 (send-side flags) | **FACT (source)**: `call_trace_sock_send_length(sk, ret, 0)` always passes `flags = 0`, so send `MSG_*` flags are invisible at this hook | `socket-c-excerpts.txt` (`net/socket.c` of tag `c21a03b2943d`) |
| H-N3 for `write()`/`read()` on sockets | **source suggests yes**: `sock_write_iter` → `__sock_sendmsg`, `sock_read_iter` → `sock_recvmsg`. Not tested | same |
| H-N3 for `splice` reads from a socket | **source suggests a gap**: `sock_splice_read` → `ops->splice_read` bypasses `sock_recvmsg`. `splice_write` → `splice_to_socket` must be tested | same |
| LSM-denied sends and receives | **source**: `security_socket_sendmsg` / `_recvmsg` fail before the tracepoint, so they are invisible at the socket layer (still visible as syscall entries) | same |
| Kernel symbols `sock_sendmsg`, `sock_recvmsg`, `tcp_connect`, `inet_stream_connect`, `__sys_connect` | present | `tracefs-formats.txt` |

Everything else in §6 (H-N2, H-N4–H-N8, every path in V15) is **unverified**.

## 2. Architecture

**Capability `net`.**
- New source `bpf/net.bpf.c`, compile flag `PPC_CAP_NET`, assembled into the
  one unified program (`bpf_collector.build_source`) after `common.h`.
- Compilations per start stay at 2 (calibrate, unified); tested as in S1/S2.
- `CAPABILITIES["net"]` lists the network tracepoints (§3). `net` leaves
  `RESERVED_CAPABILITIES`.
- Valid selections: `("counts",)`, `("counts","bigrams")`,
  `("counts","net")`, `("counts","bigrams","net")`.

**Dependency: `net` requires `counts` (proposed, like U9).**
- Every bpf_proc today is built from a `counts` entry, and identity metadata
  (comm, cgroup, level, exited) lives in the `info` map.
- A process that only does network I/O would otherwise have no record. The
  net probes therefore ensure the process has `counts` and `info` entries
  (`lookup_or_try_init`). An all-zero `counts` entry is then a measured zero
  (probes attached, nothing observed); it is not a substitute for an unread
  value.
- If that insertion fails, the event is lost and counted (`net_map_full`,
  §5), never attributed.
- Counts-only builds compile none of this (U6 equivalence must stay 34/34).

**Shared machinery reused unchanged:**
- identity `resolve()` (unresolved events counted, never attributed);
- exclusion check before every write;
- purge after `rcu_barrier()`;
- two-phase exit reclaim, with the net values added to the reclaim
  fingerprint;
- the S2.5 drain (net maps added to `_read_state()`);
- the S2.6 emitter (the payload comparison automatically re-emits on any
  net change).

**Userspace:**
- `BpfCollector.read_net()` reads the maps (batch read, else per item) and
  groups by process.
- `net_health()` reads the health counters.
- The v2 emitter adds the net fields (§6).
- The agent takes `--capabilities counts,net` (schema 2 only, like U8), with
  the S2.6 strict startup policy and `--allow-degraded`.

**Not in S3 core:**
- Interface counters from `/proc/<pid>/net/dev` (§6 row 6). This is a C
  collector and resource-stream change and is proposed as optional **S3c**
  (§8), with its own decision.

## 3. Hooks (tracepoints only)

D-15 applies, and no kprobes are proposed. Every hook below exists on this
kernel (FACT). kprobe or fentry alternatives (`tcp_connect`,
`inet_stream_connect`) are **not** needed for the §6 scope and would need a
separate approval.

| Hook | Use | Context and attribution |
|---|---|---|
| `sock:sock_send_length` | `ret > 0` → `tx_bytes += ret`, `tx_ok += 1`; `ret < 0` → `tx_err` by errno class (`EAGAIN`/`EWOULDBLOCK` separate, `EPIPE`, `ECONNRESET`, other); class from `family`/`protocol` | calling task (process context, H-N5 to verify); kernel threads resolve to no distro key → `unresolved` |
| `sock:sock_recv_length` | same for rx. `flags & MSG_PEEK (0x2)` → `rx_peek` only, 0 bytes added. `flags & MSG_TRUNC (0x20)` on UDP → `rx_trunc` and `rx_trunc_bytes`, not added to `rx_bytes` (H-N2) | same |
| `sock:inet_sock_set_state` | `newstate == TCP_SYN_SENT` → `tcp_syn_sent += 1`; every other transition ignored (may run in softirq) | H-N6: `SYN_SENT` happens in the `connect()` caller's context; if false, the field is dropped (plan v3) |
| `syscalls:sys_enter_sendto` / `sys_exit_sendto` | attempted bytes (`len`) and partial sends (`0 ≤ ret < len`) via the per-TID stash (§4); `ret` cross-checked with `sock_send_length` (H-N8) | same task |
| `syscalls:sys_enter_connect` / `sys_exit_connect` | entry count; family read from `uservaddr` (`bpf_probe_read_user`, first 2 bytes) at entry, stashed; at exit: `0` → ok, `-EINPROGRESS` → pending, `-ECONNREFUSED` → refused, other → err class | same task |
| `syscalls:sys_enter_accept4`, `sys_exit_accept4`, `sys_enter_accept`, `sys_exit_accept` | entry count; exit `ret ≥ 0` → ok, else err class | same task |
| `syscalls:sys_enter_{sendmsg,sendmmsg,recvfrom,recvmsg,recvmmsg}` | entry counts only (`entry_observed`, D16) | same task |

**Total:** 16 new tracepoints (3 `sock:` + 13 `syscalls:`), all present on this kernel (FACT, `tracefs-formats.txt`), all compiled only with `PPC_CAP_NET`. The S1
unit test `test_no_later_stage_hooks_are_present` (which forbids
`sock_send_length` and `sys_exit_`) is changed to apply only to builds
without `net`.

**Coverage the hooks give (to be measured, V15):**
- `sock_*_length` should fire for `send`, `sendto`, `sendmsg`, each message
  of `sendmmsg`, `write`/`writev` on sockets, and the receive counterparts.
- `splice`-from-socket is a likely gap (source).
- `sendfile`/`splice` into a socket goes through `splice_to_socket` and must
  be tested.
- io_uring is out of scope (A13).

## 4. Maps and storage

All maps are preallocated BPF hashes with zeroed padding. Capacities are
configurable, as in S2. Measured with the S2.3 method (fdinfo `memlock`).

| Map | Key | Value | Capacity (proposed) |
|---|---|---|---|
| `net` | `struct nkey {struct pkey proc; u16 cls; u16 pad1; u32 pad2}` (24 B) | `struct ncnt` (below) | `MAX_NET` = 32,768 entries |
| `net_stash` | host TID (u32, a map key only, as `threads`) | `{u64 thread_start_ns; u64 len; u32 sc; u16 family; u16 protocol; u32 seen_sock; u32 pad}` | `MAX_THREADS` (32,768) |
| health (existing array) | new indices for the net counters (§5) | u64 | — |

**Classes (`cls`), from the socket's `family` and `protocol`:**
- `inet4_tcp`, `inet4_udp`, `inet4_other`;
- `inet6_tcp`, `inet6_udp`, `inet6_other`;
- `local_ipc` (`AF_UNIX`, `AF_NETLINK`, `AF_VSOCK`);
- `other`;
- `unknown` (syscall-level events whose socket layer never fired).

The network families never contain local IPC (§6, V4).

**`struct ncnt` (per process and class, all cumulative u64; about 168 B):**
- socket layer: `tx_ok, tx_bytes, tx_err, tx_eagain, rx_ok, rx_bytes,
  rx_err, rx_eagain, rx_peek, rx_trunc, rx_trunc_bytes`;
- sendto: `sendto_exit, sendto_attempted_bytes, sendto_partial`;
- connect: `connect_ok, connect_pending, connect_refused, connect_err`;
- `accept_ok, accept_err, tcp_syn_sent`.

The per-syscall `entry_observed` counts (sendto, sendmsg, sendmmsg,
recvfrom, recvmsg, recvmmsg, connect, accept, accept4) are stored under
`cls = unknown`, because the family is not known at entry.

**Why sparse `(process, class)` keys instead of one wide value per
process:** most processes never touch a socket. A dense per-process value of
9 classes × 21 counters at `MAX_PROCS` 16,384 would preallocate about
25 MiB. The sparse map at 32,768 entries is estimated at about 7–8 MiB
using the S2.3 memlock model; this is an estimate, to be measured.

**Per thread.** Only the stash. A thread's in-flight `sendto`/`connect`
entry state carries:
- `len` and `sc`;
- `family`/`protocol`, filled in by `sock_send_length` firing inside the
  same syscall (`seen_sock`). Attempted bytes and partial sends are then
  classified by family, so `AF_UNIX` `sendto` never pollutes network
  counters, and a call that never reached the socket layer goes to
  `unknown`;
- `thread_start_ns`, for TID-reuse detection (as `tslot`).

**Endpoints.** No raw IP addresses or ports are stored (A15 proposal;
CLAUDE.md never makes them features). If A15 is approved, add per class the
destination classes at connect time (`loopback`, `private` RFC1918/ULA,
`link_local`, `public`) and the port class (`well_known` < 1024,
`registered`, `ephemeral`) as extra counters. That decision is open (§8).

## 5. Accounting invariants (proposed; need approval like A8)

**Loss rule (R-NLOSS, mirroring R-LOSS).** For every network hook
invocation by a non-excluded task:
1. If identity is unresolved → `net_unresolved += 1` and stop (never
   attributed).
2. If excluded → `net_self_excluded += 1` and stop.
3. If the process's `counts`/`info` entry or its `net` entry cannot be
   created → `net_map_full += 1`, `net_dropped_events += 1`, and for a
   positive `ret`, `net_dropped_bytes += ret`.
4. Stash failures → `stash_full`; an entry found already present at entry →
   `stash_overwrite`; an exit without an entry → `exit_without_entry`; a
   thread exiting with an entry → `stash_orphaned`.

A global `net_events_seen[hook]` and `net_bytes_seen[dir]` (per-CPU arrays)
are incremented **first**, before any lookup, to give a closed total.

**Invariants.** Exact checks only at quiescence or on the drained snapshot,
as for the bigrams.

| ID | Statement | When |
|---|---|---|
| I-N1 | Class exclusivity: every socket-layer event is in exactly one class; `local_ipc` events never appear in `inet*` classes | always (by construction; V4 checks it) |
| I-N2 | Event conservation per socket hook: `net_events_seen` = Σ(`*_ok` + `*_err` + `rx_peek` + `rx_trunc`) over live and reclaimed keys + `net_unresolved` + `net_self_excluded` + `net_dropped_events` + purged events | drained snapshot only |
| I-N3 | Byte conservation per direction: `net_bytes_seen` = Σ `*_bytes` (live + reclaimed) + `net_dropped_bytes` + purged bytes + unresolved and excluded bytes | drained snapshot only |
| I-N4 | Stash balance per stashed syscall: entries = matched exits + `stash_full` + `stash_overwrite` + `stash_orphaned` + stash entries left at the drain | drained snapshot only |
| I-N5 | Partial-send bounds per key and class: `sendto_partial` ≤ `sendto_exit`; `sendto_attempted_bytes` ≥ the bytes of those exits | quiescent process |
| I-N6 | Scripted ground truth: helper tally = counters, exactly (V1–V12) | scripted tests, zero loss in the window |
| — | Interface ≥ socket bytes (D15) is **not** an invariant: checked only in V13, under controlled conditions | — |

**Purge (P-PURGE for net).** `exclude()` purges the process's `net` and
stash entries after the barrier, adding them to `purged_net_events` and
`purged_net_bytes` so that I-N2 and I-N3 still close.

## 6. JSONL schema (additive v2, needs approval like U1)

`v` stays 2. The new fields are present **iff** `capabilities.net` is
selected, so counts-only and bigram streams keep their exact shapes (tested
field by field, as in S2.1).

**`bpf_snapshot_begin.capabilities.net`** = `{status, epoch, err, reason}`
(same rules as `bigrams`).

**`bpf_proc.net`, plus `net_err`:**
- `ok`: an object;
- `unavailable`: `net: null`, `net_err: "UNSUPPORTED"`.

The object, when ok:

```json
"net": {
  "classes": {"inet4_tcp": {"tx_ok": 3, "tx_bytes": 65536, "tx_err": 0, "tx_eagain": 0,
                            "rx_ok": 0, "rx_bytes": 0, "rx_err": 0, "rx_eagain": 0,
                            "rx_peek": 0, "rx_trunc": 0, "rx_trunc_bytes": 0,
                            "sendto_exit": 3, "sendto_attempted_bytes": 65536, "sendto_partial": 0,
                            "connect_ok": 1, "connect_pending": 0, "connect_refused": 0,
                            "connect_err": 0, "accept_ok": 0, "accept_err": 0, "tcp_syn_sent": 1}},
  "entry_observed": {"sendto": 3, "sendmsg": 0, "sendmmsg": 0, "recvfrom": 0, "recvmsg": 0,
                     "recvmmsg": 0, "connect": 1, "accept": 0, "accept4": 0}
}
```

- **Sparse classes:** a class that saw no event is absent. Because the
  capability is ok, an absent class means 0 observed, which is the same
  rule as sparse bigram tables. An all-zero class is never emitted.
- **Size:** worst case 9 classes × 21 counters at 20 digits each is about
  6 KiB, so a `bpf_proc` stays far under 65,536 bytes. A worst-case record
  test is required, as in S2.1.

**End record `bpf_snapshot_end`:**
- `net_health`: `net_events_seen`, `net_bytes_seen` (per hook / direction),
  `net_unresolved`, `net_self_excluded`, `net_map_full`,
  `net_dropped_events`, `net_dropped_bytes`, `stash_full`,
  `stash_overwrite`, `stash_orphaned`, `exit_without_entry`,
  `purged_net_events`, `purged_net_bytes`. `null` when unavailable or the
  snapshot failed.
- `totals.net`: `{tx_bytes, rx_bytes, events}` over the tracked processes,
  checked by the Reconstructor like `totals.bigrams`.

**Consumer rules.** As in §8.4:
- capability fixed per epoch;
- `net` replaces, never merges;
- totals cross-check;
- I-N2–I-N4 only on the drained snapshot.

**`netdev` records (S3c only, if approved).** Per network-namespace
interface counters, with `scope: "interface_level"` (D15). They are never
added to socket counters. This touches the C collector's v1 resource
stream, which is a v1 schema change and needs its own decision.

## 7. Tests and acceptance (from CLAUDE.md §6 and plan v2 V1–V15)

The oracle is always the helper's own userspace tally. "10/10" = exact in
10 independent runs. Test resources per A14 (approval needed): a temporary
bridge network, a sink container (`busybox:1.36` plus a static helper, as
DIT-1), and runs with `--user 1000`.

| # | Case | Expected |
|---|---|---|
| V1 | TCP/IPv4, blocking, N ∈ {1, 65,536, 10 MiB}, sender container → sink container | sender `inet4_tcp.tx_bytes` = Σret = N = sink `rx_bytes`, 10/10 |
| V2 | TCP/IPv6 loopback | `inet6_tcp` tx = rx = N; `inet4_*` unchanged, 10/10 |
| V3 | UDP/IPv4, k datagrams of size s | `tx_ok` = k, `tx_bytes` = k·s; rx as the sink received, 10/10 |
| V4 | Unix stream and datagram, N bytes | `local_ipc` = N; every `inet*` unchanged (I-N1), 10/10 |
| V5 | Non-blocking, small `SO_SNDBUF` | Σret = sink bytes = `tx_bytes`; `sendto_partial` > 0; attempted ≥ Σret, 10/10 |
| V6 | `connect` to a closed port | `connect_refused` = 1, `tcp_syn_sent` = 1, bytes 0, 10/10 |
| V7 | `EAGAIN` on an empty non-blocking receive; send after reset | `rx_eagain` = 1; `tx_err` = 1; bytes 0, 10/10 |
| V8 | `MSG_PEEK` k bytes, then a receive of k | `rx_bytes` = k, `rx_peek` = 1, 10/10 |
| V9 | UDP 100 B into 10 B with `MSG_TRUNC` | `rx_trunc` = 1 with its own bytes, not in `rx_bytes`, 10/10 |
| V10 | Short-lived sender (fork, send N, exit) | reported once with N and exited, then reclaimed, 10/10 |
| V11 | Inherited socket: parent N1, child N2 | parent N1, child N2, 10/10 |
| V12 | Two threads each send N | process 2N, 10/10 |
| V13 | Container attribution (V1) | PIDs = `docker inspect .State.Pid`; `container_id`; each `eth0` change ≥ N (relationship only), 10/10 |
| V14 | Forced namespace-inode mismatch | 0 attributed; `net_unresolved` rises, 3/3 |
| V15 | Paths: `write`, `send`, `sendto`, `sendmsg`, `sendmmsg`, `sendfile`, `splice` and the receive counterparts | each PASS (exact) or a documented gap, 3/3 |

**Additional tests:**
- every R-NLOSS path forced: small maps, a thread-map-full stash, TID reuse,
  a planted stash entry;
- I-N2–I-N4 on a drained epoch with reclaim and purge;
- exclusion purge under load (`test_exclusion_purge` pattern);
- H-N8 cross-check (sendto exit `ret` = `sock_send_length` `ret`);
- schema/Reconstructor rejection tests;
- counts-only and bigram equivalence (34/34 and the S2 suites unchanged);
- the S2.6 strict-startup tests extended to `net`.

## 8. Step sequence (each reviewed separately, as in S2)

1. **S3.1 Contract and schema:** v2 additive fields, validator,
   Reconstructor (`net` replace, totals). Unprivileged only.
2. **S3.2 Decoder and checkers** (stdlib): I-N1–I-N5, scripted oracle.
   Synthetic data.
3. **S3.3 BPF capability:** `net.bpf.c`, maps, R-NLOSS, health, stash,
   identity insertion; compile and attach tests; counts-only and bigram
   equivalence.
4. **S3.4 Privileged scripted tests:** V2–V12, V14 on host helpers; every
   loss path; H-N1/N2/N5/N6/N8 answered.
5. **S3.5 Drain and purge integration:** I-N2–I-N4 on the drained snapshot.
6. **S3.6 Emitter, agent and `validate_run`:** `--capabilities counts,net`,
   strict startup policy, end to end.
7. **S3.7 Docker and paths:** V1, V13 (NIT, like DIT-1), V15 path coverage;
   full regression; evidence; stop for review.
8. **S3c (optional, separate decision):** C collector `/proc/<pid>/net/dev`
   per netns as `netdev` records.

## 9. Risks

- **Hot-path cost:** `sock_send_length` / `sock_recv_length` fire on every
  socket send and receive in the distro (Docker daemon, WSL services
  included), and the `sys_exit_*` hooks double the cost per call. CPU and
  per-event time must be measured against the plan v3 [P] rules before
  acceptance.
- **Verifier:** the identity resolution plus class logic is inlined into 16
  probes; program size must be watched (bigrams added about 10 map
  operations per probe without trouble).
- **Map memory:** the sparse design is estimated, not measured; the S2.3
  fdinfo `memlock` method applies.
- **Attribution limits:**
  - `docker-proxy` relays published ports, so the bytes are counted again
    in `docker-proxy`;
  - NAT/bridge forwarding and kernel-originated traffic are not process
    sends;
  - TCP retransmits are not socket-layer events.

  All are documented blind spots (§6).
- **WSL2:** loopback and the bridge are inside the utility VM; other
  distros, Windows and Docker Desktop are out of scope.

## 10. Decisions requested before S3 code

1. **N1:** Label: S3 = network (A17 permits the order; plan v3 numbering
   moves).
2. **N2:** Tracepoints only (no kprobes or fentry) for S3; the 16-hook list
   in §3.
3. **N3:** `net` requires `counts`, and net probes create zero `counts`
   entries for network-only processes.
4. **N4:** Sparse `(process, class)` map, the class list, and capacities
   (`MAX_NET` 32,768).
5. **N5:** R-NLOSS and invariants I-N1–I-N6 with their preconditions (the
   analogue of A8).
6. **N6:** Additive v2 schema for `capabilities.net`, `bpf_proc.net`/`net_err`,
   `net_health`, `totals.net` (the analogue of U1).
7. **N7:** No raw endpoints; whether to add A15 destination and port
   classes.
8. **N8:** Test resources A14: bridge network, sink container, `--user
   1000`.
9. **N9:** Whether S3c (`netdev` via the C collector) is in M1b scope.
10. **N10:** [P] budgets (CPU, map memory, per-event time) for the net
    capability (plan v3 A5).
11. **N11:** io_uring stays out (A13); the splice-read gap is documented if
    V15 confirms it.

## 11. Implementation notes, S3.1/S3.2 (2026-10-19, for review)

N1–N10 were approved. S3.1 (wiring, maps, schema) and S3.2 (connect and
accept) are implemented and uncommitted. The following points are
implementation decisions or interpretations of this plan. Each is flagged
for review.

1. **Socket class from the fd (not in §3's text).** The connect/accept
   tracepoints carry no socket family or protocol
   (`results/acceptance/m1b/s3.2/tracefs-formats.txt`). The approved
   protocol-split classes (N4) therefore need the socket itself, which is
   read inside the tracepoint program through `task->files->fdt->fd[fd]` →
   `file` → `socket` → `sock` (`bpf_probe_read_kernel`, as `resolve()`
   does). This is not a kprobe or any new hook type (N2 kept). A failed read
   or a non-socket fd gives class `unknown`. The sockaddr family is used
   only for the destination class.
2. **Destination classes (N7).** Implemented: `loopback`, `private`,
   `link_local`, `public`, plus `special` (0/8, multicast, 240/4 including
   broadcast, ::, ff00::/8) and `unknown`. `special` was added because
   multicast, broadcast and unspecified addresses are not public unicast.
   **Port classes are not implemented:** N7 does not clearly approve them,
   and S3.2 never reads a port. They can be added later with the same
   privacy rule.
3. **I-N2 scope.** §5 wrote I-N2 for the socket hooks, which S3.3 adds. The
   same conservation equation is applied to S3.2's six syscall hooks.
   Accept and accept4 exits are pooled, because the plan's result fields
   (`accept_ok`/`accept_err`) are shared.
4. **I-N4 purge term.** §5's stash balance did not list stash entries
   removed by a self-exclusion purge. The equation includes them as
   `purged_stash`; they are the stash part of P-PURGE.
5. **I-N6 loss window.** `unresolved_*` are not in the precondition window:
   they are tasks outside the distro pid namespace and cannot touch a
   scripted helper's values. The window covers `dropped_*`, `stash_full`,
   `stash_overwrite`, `stash_orphaned`, `exit_without_entry` and
   `net_map_full`.
6. **`drained` field.** It is present iff bigrams or net is selected (the
   S2.1 rule extended). Bigram streams are unchanged; a counts-only stream
   still has no `drained`.
7. **Net requires schema 2**, like bigrams (U8). Startup is strict, and
   `--allow-degraded` runs counts-only with every extra capability
   unavailable (the unified program starts or fails as one unit).
8. **Build shim.** `<net/sock.h>` does not compile with BCC 0.35 against
   6.18 headers unless `struct bpf_task_work` is declared. It is declared
   exactly as in the running kernel's uapi header.
9. **Not in S3.2, as approved:** byte counters, send/receive, sendto stash,
   `inet_sock_set_state`, `/proc/<pid>/net/dev` (S3c), containers and bridge
   networks (V1/V13 belong to S3.7).
