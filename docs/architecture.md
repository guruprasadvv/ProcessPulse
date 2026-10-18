# Architecture and Design Decisions — M0

## Scope

M0 implements the data collection layer only: enumerate all processes, read raw CPU counters, emit JSON. No feature extraction, no baseline, no detection.

## Component: collector

A single-threaded C program. Runs once, prints all accessible processes to stdout, exits.

```
/proc/
 ├── 1/stat       ─┐
 ├── 47/stat       ├─ opendir → readdir → filter numeric → fopen → fgets → parse → printf
 ├── 3821/stat    ─┘
 └── ...
```

### Data flow

```
readdir("/proc")
  → is_numeric(d_name)         filter: only PID directories
  → read_proc_stat(pid, &rec)  open + fgets /proc/<pid>/stat
  → parse_proc_stat(line, &rec) extract pid, comm, utime, stime
  → emit_json(&rec)             printf JSON to stdout
```

### Why C?

This layer sits at the kernel interface. Using C gives us:
- Direct `opendir`/`readdir`/`fopen` syscalls, no abstraction overhead.
- Fine-grained control over buffer sizes and error handling.
- Measurable, low overhead: the collector spends most of its time in `fopen` + `fgets`, not in computation.

Downstream analysis (feature extraction, baseline, detection) will use Python for faster iteration.

### Why one record per process per run?

M0 emits a snapshot. Each subsequent milestone will add the concept of a *tick* (repeated polling at an interval). Separating snapshot from polling simplifies testing: you can verify the snapshot format before adding timing logic.

### Why newline-delimited JSON (NDJSON)?

- Each line is independently parseable; a crash mid-run does not corrupt prior output.
- `cat`, `jq .`, `python3 -c "import sys,json; [print(json.loads(l)) for l in sys.stdin]"` all work with zero configuration.
- Easy to pipe into the Python analysis pipeline in M1.

### JSON schema (M0)

```json
{
  "pid":   integer,   // process ID, always > 0
  "comm":  string,    // process name, up to 15 chars, JSON-escaped
  "utime": integer,   // user-mode CPU ticks since process start (field 14)
  "stime": integer,   // kernel-mode CPU ticks since process start (field 15)
}
```

`utime` and `stime` are **raw cumulative counters in clock ticks**, not rates. Divide by `sysconf(_SC_CLK_TCK)` (typically 100) to convert to seconds. Rates require two samples (M2).

## Key design decisions

### 1. strrchr vs strchr for comm parsing

`strchr(line, ')')` finds the *first* `)`. If the process is named `db(worker)`, this returns the `)` inside the name, not the closing delimiter. `strrchr(line, ')')` finds the *last* `)`. Because all fields after `comm` are integers, no `)` can appear there. `strrchr` is always correct.

### 2. sscanf with assignment suppression for field skipping

After the closing `)`, we need fields 14 and 15 but must skip 11 fields first. Alternatives:

| Approach | Problem |
|---|---|
| `strtok` | Modifies the string; not safe on a const buffer |
| `strsep` | Non-portable |
| Manual loop with `strtol` | More code, same result |
| `sscanf` with `%*` (skip) | Standard C11, no allocations, single call |

We use `sscanf` with `%*c`, `%*d`, `%*u`, `%*lu` to skip each field by type. The return value is the count of *stored* conversions (2: utime and stime). Any value other than 2 signals a malformed line.

### 3. TOCTOU handling

`fopen` on a disappearing `/proc/<pid>/stat` returns `NULL` with `errno = ENOENT`. We skip silently. Logging every such event would produce noise proportional to system process churn. Unexpected errors (`errno` is something other than `ENOENT` or `EACCES`) are logged to stderr.

### 4. No root requirement

`/proc/<pid>/stat` is world-readable for all processes owned by the current user, and readable by root for all processes. M0 does not require root. Processes owned by other users on hardened systems may return `EACCES`; they are skipped.

### 5. Why no header file?

All functions are `static` within `collector.c`. There is no inter-file API in M0. A header would add complexity with no current benefit. If M1 splits parsing into a separate compilation unit, a `parse.h` will be introduced then.

## Known limitations (M0)

1. **Snapshot only.** No polling interval. Each run is a single point-in-time snapshot.
2. **No container detection.** Container identity from `/proc/<pid>/cgroup` is planned for M2.
3. **No timestamp in output.** Records have no `sample_time` field; M1 will add one.
4. **CPU rates impossible from single snapshot.** `utime`/`stime` are cumulative; you need two samples to compute CPU%.
5. **No `/proc/<pid>/io` or `/proc/<pid>/status`.** Memory, I/O, FD count are M1 features.
6. **Ordering is filesystem order.** PID order is not guaranteed by `readdir`.
7. **No rate-limiting or maximum process count.** On a system with thousands of processes, stdout could be large.
