/*
 * syscall_counter.bpf.c — per-process syscall-ENTRY counters (M1).
 *
 * Compiled by BCC from processpulse/syscalls.py, which defines:
 *   DISTRO_LEVEL       pid-namespace level of the Ubuntu distro (calibrated)
 *   DISTRO_PIDNS_INUM  inode of the distro pid namespace (calibrated)
 *   MAX_PROCS          capacity of the counts/info maps
 *   NSYSCALLS          number of counted syscalls; SC_<NAME> indices
 * and appends one TRACEPOINT_PROBE(syscalls, sys_enter_<name>) per syscall.
 *
 * Identity is resolved in-kernel (CLAUDE.md §5): an event is attributed only
 * if the task's pid has a number at DISTRO_LEVEL *in the distro namespace*
 * (sibling WSL distros share the level, so the inode is checked). Anything
 * else increments H_UNRESOLVED and is never assigned to a process.
 *
 * Counters are cumulative and never reset; userspace computes deltas and
 * reclaims exited entries after reporting them once.
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>

#define MAX_LEVEL 8

/* health[] indices — must match HEALTH_FIELDS in processpulse/syscalls.py */
#define H_COUNTS_FULL   0
#define H_INFO_FULL     1
#define H_UNRESOLVED    2
#define H_SELF          3
#define H_EXIT          4
#define NHEALTH         5

struct pkey {
    u64 start_ns;          /* group_leader->start_boottime */
    u32 tgid;              /* tgid in the distro pid namespace */
    u32 pad;
};

struct pcounts {
    u64 c[NSYSCALLS];
};

struct pinfo {
    u64 cgroup_id;         /* bpf_get_current_cgroup_id() at the last event */
    u64 last_ktime;        /* bpf_ktime_get_ns() at the last event (diagnostic) */
    u32 host_tgid;         /* initial-namespace tgid (diagnostic) */
    u32 level;             /* pid-namespace level of the thread-group leader */
    u32 container_pid;     /* pid in the task's own namespace if level > DISTRO_LEVEL */
    u32 exited;            /* set by sched_process_exit when the group is dead */
    char comm[16];         /* task comm at the most recent event */
};

BPF_HASH(counts, struct pkey, struct pcounts, MAX_PROCS);
BPF_HASH(info, struct pkey, struct pinfo, MAX_PROCS);
BPF_HASH(excluded, u32, u8, 64);        /* distro tgids of our own collectors */
BPF_ARRAY(health, u64, NHEALTH);

static __always_inline void hinc(int idx)
{
    u64 *v = health.lookup(&idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

/* Returns 0 and fills k/level/cpid when the current task resolves. */
static __always_inline int resolve(struct pkey *k, u32 *level_out, u32 *cpid_out)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *leader = NULL;
    struct pid *p = NULL;
    unsigned int level = 0, inum = 0;
    struct upid up = {};
    u64 start = 0;

    bpf_probe_read_kernel(&leader, sizeof(leader), &task->group_leader);
    if (leader == NULL)
        return -1;
    bpf_probe_read_kernel(&p, sizeof(p), &leader->thread_pid);
    if (p == NULL)
        return -1;
    bpf_probe_read_kernel(&level, sizeof(level), &p->level);
    if (level < DISTRO_LEVEL || level >= MAX_LEVEL)
        return -1;
    bpf_probe_read_kernel(&up, sizeof(up), &p->numbers[DISTRO_LEVEL]);
    if (up.ns == NULL)
        return -1;
    bpf_probe_read_kernel(&inum, sizeof(inum), &up.ns->ns.inum);
    if (inum != DISTRO_PIDNS_INUM || up.nr <= 0)
        return -1;
    bpf_probe_read_kernel(&start, sizeof(start), &leader->start_boottime);

    k->start_ns = start;
    k->tgid = (u32)up.nr;
    k->pad = 0;
    *level_out = level;
    *cpid_out = 0;
    if (level > DISTRO_LEVEL) {
        struct upid own = {};
        bpf_probe_read_kernel(&own, sizeof(own), &p->numbers[level]);
        *cpid_out = (u32)own.nr;
    }
    return 0;
}

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
        /* Refresh: execve changes comm, and a process can move cgroups. */
        pi->cgroup_id = bpf_get_current_cgroup_id();
        pi->last_ktime = bpf_ktime_get_ns();
        bpf_get_current_comm(&pi->comm, sizeof(pi->comm));
    }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit)
{
    struct pkey k = {};
    struct pinfo *pi;
    u32 level = 0, cpid = 0;

    if (!args->group_dead)
        return 0;
    if (resolve(&k, &level, &cpid) != 0)
        return 0;
    hinc(H_EXIT);
    pi = info.lookup(&k);
    if (pi)
        pi->exited = 1;
    return 0;
}
