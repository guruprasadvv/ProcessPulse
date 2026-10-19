/*
 * syscall_counter.bpf.c — capability "counts": per-process syscall-ENTRY
 * counters (M1; ported to the unified program in M1b S1).
 *
 * Compiled after common.h (see there), with:
 *   MAX_PROCS          capacity of the counts/info maps
 *   NSYSCALLS          number of counted syscalls (processpulse/vocab.py)
 * processpulse/bpf_collector.py appends one
 * TRACEPOINT_PROBE(syscalls, sys_enter_<name>) { return count_syscall(i); }
 * per vocabulary entry. core.bpf.c calls counts_on_exit() / counts_on_exec().
 *
 * Counters are cumulative and never reset; userspace computes deltas and
 * reclaims exited entries after reporting them once. Map layouts are the
 * M1 layouts. Process metadata (comm, cgroup) is captured when the entry is
 * created and refreshed at exec, not on every event (F9).
 */

struct pcounts {
    u64 c[NSYSCALLS];
};

struct pinfo {
    u64 cgroup_id;         /* bpf_get_current_cgroup_id() at creation / last exec */
    u64 last_ktime;        /* bpf_ktime_get_ns() at the last event (diagnostic) */
    u32 host_tgid;         /* initial-namespace tgid (diagnostic) */
    u32 level;             /* pid-namespace level of the thread-group leader */
    u32 container_pid;     /* pid in the task's own namespace if level > DISTRO_LEVEL */
    u32 exited;            /* set by sched_process_exit when the group is dead */
    char comm[16];         /* task comm at creation / last exec */
};

BPF_HASH(counts, struct pkey, struct pcounts, MAX_PROCS);
BPF_HASH(info, struct pkey, struct pinfo, MAX_PROCS);

static __always_inline int count_syscall(int sc)
{
    struct pkey k = {};
    struct pcounts zero = {};
    struct pcounts *c;
    struct pinfo *pi;
    u32 level = 0, cpid = 0;

    if (resolve(&k, &level, &cpid) != 0) {
        hinc(H_UNRESOLVED);
        return 0;
    }
    if (excluded.lookup(&k.tgid)) {
        hinc(H_SELF);
        return 0;
    }
    thread_touch(&k);
    c = counts.lookup_or_try_init(&k, &zero);
    if (c == NULL) {
        hinc(H_COUNTS_FULL);
        return 0;
    }
    __sync_fetch_and_add(&c->c[sc], 1);

    pi = info.lookup(&k);
    if (pi == NULL) {
        struct pinfo ni = {};
        ni.cgroup_id = bpf_get_current_cgroup_id();
        ni.last_ktime = bpf_ktime_get_ns();
        ni.host_tgid = bpf_get_current_pid_tgid() >> 32;
        ni.level = level;
        ni.container_pid = cpid;
        bpf_get_current_comm(&ni.comm, sizeof(ni.comm));
        if (info.insert(&k, &ni) != 0)
            hinc(H_INFO_FULL);
    } else {
        pi->last_ktime = bpf_ktime_get_ns();
    }
    return 0;
}

static __always_inline void counts_on_exit(struct pkey *k)
{
    struct pinfo *pi = info.lookup(k);

    if (pi)
        pi->exited = 1;
}

/* exec replaces the program: comm changes, and the cgroup is the one the new
 * program runs in (e.g. a container's scope after runc init). */
static __always_inline void counts_on_exec(struct pkey *k)
{
    struct pinfo *pi = info.lookup(k);

    if (pi == NULL)
        return;
    pi->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&pi->comm, sizeof(pi->comm));
    hinc(H_EXEC_REFRESH);
}
