# Linux /proc Concepts — ProcessPulse-C

## The /proc virtual filesystem

`/proc` is a **virtual filesystem** mounted by the Linux kernel at boot. No data is stored on disk; every read triggers a kernel function that constructs the response on-the-fly from live kernel data structures.

From the collector's perspective, `/proc` behaves like a normal directory tree: `opendir("/proc")`, `readdir()`, `fopen("/proc/42/stat", "r")`. The kernel handles the rest.

## PID directories

Every running process has a numbered directory `/proc/<pid>/`. The directory name is the process's PID (Process ID), a positive integer assigned by the kernel's scheduler when `fork()` or `clone()` is called.

**How the collector finds PIDs:** `readdir("/proc")` returns all directory entries, including non-PID entries (`self`, `net`, `sys`, `meminfo`, etc.). We filter by testing whether the directory name consists entirely of decimal digits with `isdigit()`. This correctly identifies all PID directories.

**PID range:** On Linux, the default maximum PID is 32768 (`/proc/sys/kernel/pid_max`). It can be raised to 4194304 on 64-bit systems. A buffer of 20 characters is always sufficient for the path `/proc/<pid>/stat`.

## /proc/\<pid\>/stat

The most important file for process monitoring. It is a single line of space-separated fields. The kernel documentation (`man 5 proc`) numbers them 1–52 (as of Linux 5.x).

### The comm field problem

Field 2, the process name (`comm`), is wrapped in parentheses: `1 (systemd) S 0 ...`. The name can be up to 15 characters (kernel constant `TASK_COMM_LEN - 1`), and processes can set it freely via `prctl(PR_SET_NAME, ...)`.

**The trap:** `comm` can contain spaces and parentheses. A process can name itself `bad (name) here`. This means:
- A whitespace split of the stat line gives wrong results.
- `strchr(line, ')')` finds the first `)`, which may be inside the comm name.

**The correct approach:** Use `strrchr(line, ')')` to find the **last** `)` in the line. All fields after comm (state, ppid, pgrp, …) are integers and never contain `)`. Therefore the last `)` is always the comm closing delimiter.

### Fields 14 and 15: utime and stime

```
(14) utime  — CPU time spent in user mode, in clock ticks
(15) stime  — CPU time spent in kernel mode, in clock ticks
```

**Clock ticks:** The kernel counts CPU time in units called *jiffies* (also called clock ticks). The tick rate is set at compile time (`CONFIG_HZ`, typically 100, 250, or 1000 Hz on desktops). The POSIX constant `sysconf(_SC_CLK_TCK)` returns this value at runtime.

To convert ticks to seconds: `seconds = ticks / sysconf(_SC_CLK_TCK)`

**These are cumulative counters,** not rates. To compute CPU percentage, you must read the values twice, delta them, and divide by elapsed wall-clock time. M0 only reads raw ticks; M2 will compute rates.

**Field indexing:** The fields are 1-indexed in documentation but 0-indexed in the string after you split. After the comm closing `)`, the fields in order are:

| After `)` token index | Field number | Name     |
|-----------------------|--------------|----------|
| 0                     | 3            | state    |
| 1                     | 4            | ppid     |
| 2                     | 5            | pgrp     |
| 3                     | 6            | session  |
| 4                     | 7            | tty_nr   |
| 5                     | 8            | tpgid    |
| 6                     | 9            | flags    |
| 7                     | 10           | minflt   |
| 8                     | 11           | cminflt  |
| 9                     | 12           | majflt   |
| 10                    | 13           | cmajflt  |
| **11**                | **14**       | **utime**|
| **12**                | **15**       | **stime**|

## TOCTOU: the unavoidable race condition

TOCTOU stands for *Time Of Check To Time Of Use*.

The collector does:
1. `readdir("/proc")` — sees PID 4821
2. `fopen("/proc/4821/stat", "r")` — process 4821 has exited by now → `ENOENT`

This is **expected and normal**. Processes exit constantly. The correct response is to skip the PID silently. Treating `ENOENT` on a stat file as an error would flood the log on any busy system.

The reverse also happens: a new PID can appear between the `opendir()` call and when `readdir()` reaches its range. That PID will be collected on the next run. Both races are inherent to polling-based observation — you are always reading a snapshot, not a freeze-frame.

## Zombie processes

When a process exits, it briefly enters the **zombie state** (`Z` in the state field). Its entry in `/proc` remains until the parent calls `wait()`. Zombie entries have valid `stat` files. The collector will successfully read and emit them — the `comm` and CPU times reflect the process's last known state.

## Process permissions and /proc

Most `/proc/<pid>/stat` files are world-readable. Exceptions:
- Processes owned by other users on some hardened systems
- Processes inside user namespaces with restricted visibility

The collector handles `EACCES` the same as `ENOENT`: skip silently.

## Why not read /proc/self/stat?

`/proc/self` is a symlink that resolves to the calling process's own PID directory. The collector uses `readdir("/proc")` and explicitly parses each PID directory instead, giving access to *all* processes on the system rather than just itself.
