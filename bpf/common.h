/*
 * common.h — definitions shared by every capability of the unified BPF
 * program built by processpulse/bpf_collector.py (M1b S1).
 *
 * The collector compiles ONE program per start: this file, then the source
 * of every enabled capability (e.g. syscall_counter.bpf.c), then core.bpf.c
 * (the scheduler hooks), then generated per-syscall probes. Compile-time
 * constants come from cflags:
 *   DISTRO_LEVEL       pid-namespace level of the Ubuntu distro (calibrated)
 *   DISTRO_PIDNS_INUM  inode of the distro pid namespace (calibrated)
 *   MAX_THREADS        capacity of the per-thread slot map
 *   PPC_CAP_<NAME>     one per enabled capability
 * Source order: common.h, bigrams.bpf.c (if enabled), syscall_counter.bpf.c,
 * core.bpf.c, probes. The counter calls the bigram hooks, so the bigram
 * source precedes it.
 *
 * Identity is resolved in-kernel (CLAUDE.md §5): an event is attributed only
 * if the task's pid has a number at DISTRO_LEVEL *in the distro namespace*
 * (sibling WSL distros share the level, so the inode is checked). Anything
 * else increments H_UNRESOLVED and is never assigned to a process.
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>

#define MAX_LEVEL 8

/* health[] indices — must match HEALTH_FIELDS in processpulse/bpf_collector.py.
 * 0-4 are the M1 counters (same order; reported in the v1 snapshot record). */
#define H_COUNTS_FULL     0
#define H_INFO_FULL       1
#define H_UNRESOLVED      2
#define H_SELF            3
#define H_EXIT            4
#define H_THREAD_FULL     5   /* a thread slot could not be created */
#define H_THREAD_STALE    6   /* a slot belonged to an earlier thread with the same TID */
#define H_THREAD_CLEANED  7   /* slots deleted at thread exit or after exec */
#define H_EXEC_REFRESH    8   /* process metadata refreshed at exec */
/* 9-11: maintained only by bigrams.bpf.c (stay 0 in other builds). */
#define H_BIGRAM_FULL     9   /* R-LOSS row 3: the bigram map was full */
#define H_BIGRAM_DROPPED 10   /* every pair not recorded (rows 1-3 and pre-arm events) */
#define H_PRE_ARM        11   /* counted entries before arming; their pairs are lost */
#define NHEALTH          12

struct pkey {
    u64 start_ns;          /* group_leader->start_boottime */
    u32 tgid;              /* tgid in the distro pid namespace */
    u32 pad;
};

/* Per-thread state. Keyed by the host (initial-namespace) TID, which is used
 * only as a map key here and never emitted as identity. The thread's own
 * start time distinguishes a reused TID from the thread that owned the slot. */
struct tslot {
    u64 thread_start_ns;   /* task->start_boottime of this thread */
    struct pkey proc;      /* the process the thread belongs to */
    u32 tid;               /* thread id in the distro pid namespace (informational) */
    u16 prev;              /* bigrams: code of the previous observed call or marker */
    u16 pad;
};

BPF_HASH(excluded, u32, u8, 64);        /* distro tgids of our own collectors */
BPF_HASH(threads, u32, struct tslot, MAX_THREADS);
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

/* Ensures the current thread has a slot for process k (called for attributed,
 * non-excluded events only). Returns the slot, or NULL when the slot map is
 * full; *created is 1 when a new slot was made (a replaced stale slot is a
 * new thread). A capability that keeps state in the slot initialises it. */
static __always_inline struct tslot *thread_touch(const struct pkey *k, int *created)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 start = 0;
    struct tslot *s;
    struct tslot ns = {};
    struct pid *tp = NULL;
    struct upid up = {};

    *created = 0;
    bpf_probe_read_kernel(&start, sizeof(start), &task->start_boottime);
    s = threads.lookup(&tid);
    if (s) {
        if (s->thread_start_ns == start)
            return s;
        hinc(H_THREAD_STALE);   /* the previous owner of this TID left without an exit */
    }
    /* Threads share the leader's pid namespaces, already checked by resolve(). */
    bpf_probe_read_kernel(&tp, sizeof(tp), &task->thread_pid);
    if (tp != NULL)
        bpf_probe_read_kernel(&up, sizeof(up), &tp->numbers[DISTRO_LEVEL]);
    ns.thread_start_ns = start;
    ns.proc = *k;
    ns.tid = (u32)up.nr;
    if (threads.update(&tid, &ns) != 0) {
        hinc(H_THREAD_FULL);
        return NULL;
    }
    *created = 1;
    return threads.lookup(&tid);
}

/* sched_process_exit runs for every exiting thread: drop its slot. */
static __always_inline void thread_exit(void)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();

    if (threads.delete(&tid) == 0)
        hinc(H_THREAD_CLEANED);
}

/* A non-leader thread that execs takes over the leader's TID (de_thread);
 * its old TID never exits, so its slot is dropped here. */
static __always_inline void thread_exec(u32 old_tid)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();

    if (old_tid != tid && threads.delete(&old_tid) == 0)
        hinc(H_THREAD_CLEANED);
}
