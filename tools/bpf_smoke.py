#!/usr/bin/env python3
"""
bpf_smoke.py — ProcessPulse-C eBPF feasibility gate (isolated PoC).

Not part of the pipeline. Verifies, on the running kernel, that a BCC program
can attach to a per-syscall tracepoint, count events in a BPF hash map, and
attribute them to the right process across PID namespaces.

Run as root (BCC needs CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN here):
    sudo python3 tools/bpf_smoke.py [--repeat 3] [--calls 1000]

Tests reported:
  A  BCC import + compile          D  PID attribution (distro pidns)
  B  tracepoint attachment         E  cleanup/detach, child exit, error path
  C  map read + exact count delta  F  nested pidns (unshare --pid) attribution

The workload triggers getpid with a raw syscall(SYS_getpid) through libc's
syscall() wrapper, so no libc caching or vDSO path can hide the event.
os.getpid() is measured separately and reported for information only.
"""

import argparse
import os
import platform
import select
import shutil
import subprocess
import sys
import textwrap
import traceback

TRACEPOINT_DIR = "/sys/kernel/tracing/events/syscalls/sys_enter_getpid"
SYS_GETPID = {"x86_64": 39, "aarch64": 172}
LEVELS = 4  # pid-namespace levels recorded per event (0 = initial/host ns)

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>

struct key_t {
    u32 host_tgid;          /* bpf_get_current_pid_tgid() >> 32 (initial pidns) */
    u32 host_tid;           /* bpf_get_current_pid_tgid() & 0xffffffff         */
    u32 ns_tgid;            /* bpf_get_ns_current_pid_tgid() in the distro ns  */
    u32 ns_pid;
    u32 ns_err;             /* -return of that helper; 0 = matched             */
    u32 level;              /* pidns level of the thread-group leader          */
    u32 lvl_nr[LEVELS];     /* leader's pid number at each level 0..level      */
    u32 syscall_nr;         /* args->__syscall_nr, validates the arg layout    */
};

BPF_HASH(counts, struct key_t, u64, 4096);
BPF_ARRAY(drops, u64, 1);

TRACEPOINT_PROBE(syscalls, sys_enter_getpid)
{
    struct key_t k = {};
    u64 id = bpf_get_current_pid_tgid();
    k.host_tgid = id >> 32;
    k.host_tid = (u32)id;
    k.syscall_nr = args->__syscall_nr;

    struct bpf_pidns_info ns = {};
    long r = bpf_get_ns_current_pid_tgid(PIDNS_DEV, PIDNS_INO, &ns, sizeof(ns));
    if (r == 0) {
        k.ns_tgid = ns.tgid;
        k.ns_pid = ns.pid;
    } else {
        k.ns_err = (u32)(-r);
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *leader = NULL;
    struct pid *p = NULL;
    unsigned int level = 0;
    bpf_probe_read_kernel(&leader, sizeof(leader), &task->group_leader);
    bpf_probe_read_kernel(&p, sizeof(p), &leader->thread_pid);
    bpf_probe_read_kernel(&level, sizeof(level), &p->level);
    k.level = level;
#pragma unroll
    for (int i = 0; i < LEVELS; i++) {
        if (i <= level) {
            int nr = 0;
            bpf_probe_read_kernel(&nr, sizeof(nr), &p->numbers[i].nr);
            k.lvl_nr[i] = nr;
        }
    }

    u64 zero = 0;
    u64 *v = counts.lookup_or_try_init(&k, &zero);
    if (v) {
        __sync_fetch_and_add(v, 1);
    } else {
        int z = 0;
        u64 *d = drops.lookup(&z);
        if (d)
            __sync_fetch_and_add(d, 1);
    }
    return 0;
}
"""

# Child workload. Protocol on stdin/stdout, one line per message:
#   child -> READY <syscall_getpid> <os.getpid>
#   parent -> SYSCALL n | OSGETPID n | EXIT ;  child -> DONE
CHILD_SRC = textwrap.dedent("""
    import ctypes, os, sys
    libc = ctypes.CDLL(None, use_errno=True)
    NR = int(sys.argv[1])
    print("READY", libc.syscall(NR), os.getpid(), flush=True)
    for line in sys.stdin:
        cmd, *rest = line.split()
        if cmd == "SYSCALL":
            for _ in range(int(rest[0])):
                libc.syscall(NR)
        elif cmd == "OSGETPID":
            for _ in range(int(rest[0])):
                os.getpid()
        elif cmd == "EXIT":
            sys.exit(0)
        print("DONE", flush=True)
""")


class Result:
    def __init__(self):
        self.rows = []  # (test, status, detail)

    def add(self, test, ok, detail, status=None):
        st = status or ("PASS" if ok else "FAIL")
        self.rows.append((test, st, detail))
        print(f"  [{st}] {test}: {detail}", flush=True)
        return ok


def bpf_fd_count():
    """Count this process's fds that refer to BPF objects or perf events."""
    n = 0
    for fd in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            continue
        if target.startswith("anon_inode:bpf") or target == "anon_inode:[perf_event]":
            n += 1
    return n


def read_line(proc, timeout=15.0):
    r, _, _ = select.select([proc.stdout], [], [], timeout)
    if not r:
        raise TimeoutError("child did not answer within %.0fs" % timeout)
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("child closed stdout (exit=%s)" % proc.poll())
    return line.split()


def send(proc, msg):
    proc.stdin.write(msg + "\n")
    proc.stdin.flush()


def entries_for(table, pred):
    return [(k, v.value) for k, v in table.items() if pred(k)]


def total(entries):
    return sum(v for _, v in entries)


def describe(k):
    lv = [k.lvl_nr[i] for i in range(min(k.level, LEVELS - 1) + 1)]
    return (f"host_tgid={k.host_tgid} host_tid={k.host_tid} ns_tgid={k.ns_tgid} "
            f"ns_err={k.ns_err} level={k.level} lvl_nr={lv} nr={k.syscall_nr}")


def stop_child(proc):
    if proc is None:
        return
    if proc.poll() is None:
        try:
            send(proc, "EXIT")
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
            proc.wait(timeout=5)


def preflight(res):
    print("== preflight", flush=True)
    arch = platform.machine()
    nr = SYS_GETPID.get(arch)
    res.add("preflight.arch", nr is not None, f"machine={arch} SYS_getpid={nr}")
    res.add("preflight.root", os.geteuid() == 0, f"euid={os.geteuid()}")
    try:
        fmt = open(os.path.join(TRACEPOINT_DIR, "format")).read()
    except OSError as e:
        res.add("preflight.tracepoint", False, f"{TRACEPOINT_DIR}: {e}")
        return None
    ok = "field:int __syscall_nr;" in fmt
    res.add("preflight.tracepoint", ok,
            "syscalls:sys_enter_getpid present, __syscall_nr field " + ("found" if ok else "MISSING"))
    hdr = "/usr/include/x86_64-linux-gnu/asm/unistd_64.h"
    if arch == "x86_64" and os.path.exists(hdr):
        found = any(l.split()[1:3] == ["__NR_getpid", "39"] for l in open(hdr) if l.startswith("#define"))
        res.add("preflight.nr_header", found, f"{hdr} defines __NR_getpid 39: {found}")
    return nr


def run_iteration(it, args, nr, res, pidns, inject_error=False):
    print(f"== iteration {it}" + (" (error-path injection)" if inject_error else ""), flush=True)
    tag = f"it{it}"
    fds_before = bpf_fd_count()
    b = None
    child = None
    nested = None
    fds_during = None
    try:
        from bcc import BPF
        cflags = [f"-DPIDNS_DEV={pidns.st_dev}ULL", f"-DPIDNS_INO={pidns.st_ino}ULL", f"-DLEVELS={LEVELS}"]
        b = BPF(text=BPF_TEXT, cflags=cflags)
        res.add(f"A.compile.{tag}", True, "BPF(text=...) compiled and loaded")

        n_tp = b.num_open_tracepoints()
        fds_during = bpf_fd_count()
        res.add(f"B.attach.{tag}", n_tp == 1 and fds_during > 0,
                f"num_open_tracepoints={n_tp}; bpf/perf fds while attached={fds_during}")

        counts = b["counts"]
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)

        # Calibrate: our own raw getpid calls give the distro pidns level.
        me = os.getpid()
        for _ in range(10):
            libc.syscall(nr)
        mine = entries_for(counts, lambda k: k.ns_tgid == me)
        distro_level = mine[0][0].level if mine else None
        res.add(f"B.self_event.{tag}", total(mine) >= 10,
                f"parent pid {me}: {total(mine)} events; key {describe(mine[0][0]) if mine else '-'}")

        # Workload child in the distro pidns.
        child = subprocess.Popen([sys.executable, "-I", "-c", CHILD_SRC, str(nr)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        _, sc_pid, os_pid = read_line(child)
        sc_pid, os_pid = int(sc_pid), int(os_pid)
        is_child = lambda k: k.ns_tgid == child.pid or (
            k.level < LEVELS and k.lvl_nr[k.level] == child.pid)
        c0 = total(entries_for(counts, is_child))
        send(child, f"SYSCALL {args.calls}")
        read_line(child)
        c1 = total(entries_for(counts, is_child))
        if inject_error:
            raise RuntimeError("injected error while probe attached and child alive")
        send(child, f"OSGETPID {args.calls}")
        read_line(child)
        c2 = total(entries_for(counts, is_child))
        res.add(f"C.map_delta_syscall.{tag}", c1 - c0 == args.calls,
                f"{args.calls} x syscall({nr}) -> map delta {c1 - c0} (before={c0}, after={c1})")
        res.add(f"C.info_os_getpid.{tag}", True,
                f"{args.calls} x os.getpid() -> map delta {c2 - c1} (informational)", status="INFO")

        ents = entries_for(counts, is_child)
        k = ents[0][0] if ents else None
        ok = (k is not None and len(ents) == 1 and sc_pid == os_pid == child.pid
              and k.ns_tgid == child.pid and k.ns_err == 0
              and k.lvl_nr[k.level] == child.pid and k.lvl_nr[0] == k.host_tgid
              and k.host_tid == k.host_tgid and k.syscall_nr == nr)
        res.add(f"D.pid_attribution.{tag}", ok,
                f"Popen.pid={child.pid} child syscall getpid={sc_pid} os.getpid={os_pid}; "
                f"keys={len(ents)}; {describe(k) if k else 'no key'}")

        stop_child(child)
        gone = not os.path.exists(f"/proc/{child.pid}")
        res.add(f"E.child_exit.{tag}", child.returncode == 0 and gone,
                f"returncode={child.returncode}, /proc/{child.pid} gone={gone}")
        child = None

        # Nested pid namespace: what Docker does to container processes.
        if shutil.which("unshare"):
            nested = subprocess.Popen(["unshare", "--pid", "--fork", "--kill-child",
                                       sys.executable, "-I", "-c", CHILD_SRC, str(nr)],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            _, n_sc, n_os = read_line(nested)
            kids = open(f"/proc/{nested.pid}/task/{nested.pid}/children").read().split()
            gpid = int(kids[0]) if kids else -1
            is_nested = lambda k: (distro_level is not None and k.level > distro_level
                                   and k.lvl_nr[distro_level] == gpid)
            n0 = total(entries_for(counts, is_nested))
            send(nested, f"SYSCALL {args.calls}")
            read_line(nested)
            n1 = total(entries_for(counts, is_nested))
            nents = entries_for(counts, is_nested)
            nk = nents[0][0] if nents else None
            ok = (nk is not None and n1 - n0 == args.calls and int(n_sc) == 1
                  and nk.lvl_nr[nk.level] == 1 and nk.lvl_nr[distro_level] == gpid)
            res.add(f"F.nested_pidns.{tag}", ok,
                    f"grandchild distro pid={gpid}, its own-ns getpid={n_sc}; map delta {n1 - n0}; "
                    f"{describe(nk) if nk else 'no key'}; ns helper matched distro ns: "
                    f"{'yes' if nk and nk.ns_err == 0 else 'no (err=%s)' % (nk.ns_err if nk else '-')}")
            stop_child(nested)
            res.add(f"E.nested_exit.{tag}", nested.returncode == 0,
                    f"unshare returncode={nested.returncode}")
            nested = None
        else:
            res.add(f"F.nested_pidns.{tag}", False, "unshare not found", status="NOT TESTED")

        d = b["drops"][ctypes.c_int(0)].value
        res.add(f"C.map_drops.{tag}", d == 0, f"map-full drops={d}, entries={len(counts)}")
    except Exception as e:
        if inject_error and "injected error" in str(e):
            print(f"  (expected) {e}", flush=True)
        else:
            res.add(f"error.{tag}", False, f"{type(e).__name__}: {e}")
            traceback.print_exc()
    finally:
        for p in (child, nested):
            if p is not None and p.poll() is None:
                p.kill()
                p.wait(timeout=5)
        if child is not None:
            res.add(f"E.child_reaped_on_error.{tag}", child.poll() is not None
                    and not os.path.exists(f"/proc/{child.pid}"),
                    f"child returncode={child.returncode}")
        if b is not None:
            b.cleanup()
            after_tp = b.num_open_tracepoints()
        else:
            after_tp = 0
        fds_after = bpf_fd_count()
        res.add(f"E.detach.{tag}", after_tp == 0 and fds_after == fds_before and bool(fds_during),
                f"open tracepoints after cleanup={after_tp}; bpf/perf fds before={fds_before} "
                f"during={fds_during} after={fds_after}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--calls", type=int, default=1000)
    args = ap.parse_args()

    res = Result()
    print(f"kernel={platform.release()} python={platform.python_version()}", flush=True)
    try:
        import bcc
        res.add("A.import", True, f"bcc {getattr(bcc, '__version__', '?')} from {bcc.__file__}")
    except Exception as e:
        res.add("A.import", False, f"{type(e).__name__}: {e}")
        return 2

    nr = preflight(res)
    if nr is None or os.geteuid() != 0:
        print("preflight failed; not attaching", flush=True)
        return 2
    pidns = os.stat("/proc/self/ns/pid")
    print(f"distro pidns: {os.readlink('/proc/self/ns/pid')} (dev={pidns.st_dev})", flush=True)

    for it in range(1, args.repeat + 1):
        run_iteration(it, args, nr, res, pidns)
    run_iteration(args.repeat + 1, args, nr, res, pidns, inject_error=True)

    print("== summary", flush=True)
    fails = [r for r in res.rows if r[1] == "FAIL"]
    for test, st, _ in res.rows:
        print(f"  {st:10s} {test}")
    print(f"RESULT: {'PASS' if not fails else 'FAIL'} ({len(fails)} failing checks)", flush=True)
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
