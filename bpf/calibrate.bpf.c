/*
 * calibrate.bpf.c — one-shot PID-namespace calibration (loaded by
 * processpulse/syscalls.py before the counter program).
 *
 * The agent calls getpid() a few times; for every caller this records the
 * thread-group leader's pid-namespace level and, for each level, the PID
 * number and the namespace inode. Userspace finds the level whose
 * (nr, inode) equals (getpid(), stat("/proc/self/ns/pid").st_ino): that is
 * the distro level L_d used by the counter program.
 */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>

#define CAL_LEVELS 8

struct cal_t {
    u32 level;
    u32 nr[CAL_LEVELS];
    u32 inum[CAL_LEVELS];
};

BPF_HASH(cal, u32, struct cal_t, 256);   /* key: host tgid */

TRACEPOINT_PROBE(syscalls, sys_enter_getpid)
{
    struct cal_t c = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *leader = NULL;
    struct pid *p = NULL;
    unsigned int level = 0;
    u32 host_tgid = bpf_get_current_pid_tgid() >> 32;

    bpf_probe_read_kernel(&leader, sizeof(leader), &task->group_leader);
    bpf_probe_read_kernel(&p, sizeof(p), &leader->thread_pid);
    if (p == NULL)
        return 0;
    bpf_probe_read_kernel(&level, sizeof(level), &p->level);
    c.level = level;
#pragma unroll
    for (int i = 0; i < CAL_LEVELS; i++) {
        if (i <= level) {
            struct upid up = {};
            unsigned int inum = 0;
            bpf_probe_read_kernel(&up, sizeof(up), &p->numbers[i]);
            bpf_probe_read_kernel(&inum, sizeof(inum), &up.ns->ns.inum);
            c.nr[i] = up.nr;
            c.inum[i] = inum;
        }
    }
    cal.update(&host_tgid, &c);
    return 0;
}
