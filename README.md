# ProcessPulse-C

Explainable Behavioral Anomaly Detection for Containerized Applications.

**Current milestone: M1 complete (2026-10-19)** — telemetry foundations: streaming /proc
collector (schema v1) and BCC syscall collector; acceptance evidence in
[results/acceptance/m1/README.md](results/acceptance/m1/README.md). Next: M1b (network
telemetry, syscall bigrams, privilege-escalation signals). Architecture, contracts and
milestones: [CLAUDE.md](CLAUDE.md). Verified history: [ENGINEERING_CHANGELOG.md](ENGINEERING_CHANGELOG.md).

### M1 quick start (WSL2 Ubuntu)

```sh
make all helpers test-c        # collector, static test helper, C unit tests
make test                      # unprivileged pytest suite
./collector --v1 --count 2 --interval-ms 500    # schema v1 samples
sudo python3 -m processpulse.preflight          # BCC/tracepoint/header checks
sudo python3 -m processpulse.agent --duration 10 # record both streams to results/raw/
```

Privileged tests: as root, `PYTHONUSERBASE=/home/<user>/.local make test-privileged`.
Python 3.12 environment for the ML layer: `tools/setup_py312_env.sh`.

The sections below describe the original M0 snapshot mode, which `./collector`
without arguments still provides.

## Prerequisites

- Linux (kernel 4.x+) with `/proc` mounted — required, not optional.
- GCC with C11 support (`gcc --version` ≥ 4.9 recommended ≥ 9.0).
- Python 3.10+ and pytest (`pip3 install pytest`).

On Windows, use WSL2 (Ubuntu 22.04+). Do not attempt to build on MSYS2 or Cygwin — their `/proc` shim does not provide the Linux stat format.

## Build

```sh
make          # produces ./collector
make test     # builds then runs all pytest tests
make clean    # removes ./collector
```

Manual build:
```sh
gcc -std=c11 -Wall -Wextra -Wpedantic -D_POSIX_C_SOURCE=200809L \
    -o collector src/collector.c
```

## Usage

```sh
./collector                    # print all accessible processes to stdout
./collector | jq .             # pretty-print with jq
./collector | wc -l            # count processes
./collector | jq '.pid'        # print all PIDs
./collector | python3 -c "
import sys, json
for line in sys.stdin:
    r = json.loads(line)
    total = r['utime'] + r['stime']
    if total > 1000:
        print(f\"{r['pid']:>6}  {r['comm']:<16}  ticks={total}\")
"
```

## JSON output schema

One JSON object per line (newline-delimited JSON / NDJSON). One object per process per run.

```json
{
  "pid":   42,
  "comm":  "nginx",
  "utime": 1234,
  "stime": 567
}
```

| Field   | Type    | Description |
|---------|---------|-------------|
| `pid`   | integer | Process ID. Always > 0. |
| `comm`  | string  | Process name from `/proc/<pid>/stat` field 2. Up to 15 characters. Set by the process itself via `prctl(PR_SET_NAME)`; may differ from the executable filename. JSON-escaped. |
| `utime` | integer | CPU time spent in user mode, in **clock ticks** (jiffies). Divide by `sysconf(_SC_CLK_TCK)` — typically 100 on Linux — to convert to seconds. This is a **cumulative counter** since the process started, not a rate. |
| `stime` | integer | CPU time spent in kernel mode, in **clock ticks**. Same units as `utime`. |

### Notes on utime and stime

- These are **monotonically increasing** counters. They never decrease.
- To compute CPU%, take two snapshots, delta the values, and divide by elapsed wall-clock ticks.
- `utime` counts time executing application code. `stime` counts time in syscalls made on behalf of this process (file I/O, memory mapping, network, etc.).
- A high `stime/utime` ratio often indicates I/O-intensive or syscall-heavy behavior — a useful anomaly signal.

## Running tests

```sh
make test
# or directly:
python3 -m pytest tests/ -v
```

Unit tests run without the binary (they test the parsing spec via a Python reference implementation). Integration tests require `./collector` to exist; they are skipped with an explanatory message if the binary is absent or the environment has fewer than 100 accessible processes.

## Known limitations (M0)

- **Single snapshot per run.** No polling interval or daemon mode.
- **No container detection.** Container IDs from `/proc/<pid>/cgroup` are planned for M2.
- **No timestamp in output.** Each record has no wall-clock timestamp; M1 will add `sample_time_ns`.
- **No memory, I/O, or FD metrics.** Only CPU ticks are collected. M1 adds `/proc/<pid>/status` and `/proc/<pid>/io`.
- **CPU rates require two samples.** `utime`/`stime` are cumulative; rates are impossible from a single run.
- **Output order is not guaranteed.** `readdir` returns entries in filesystem order.
- **No root requirement, but some processes may be skipped.** Processes owned by other users on hardened systems return `EACCES` on their stat file; they are silently skipped.

## Project structure

```
src/collector.c          — C11 collector: /proc enumeration, stat parsing, JSON output
tests/test_collector.py  — pytest: unit tests (parser spec) + integration tests
docs/architecture.md     — design decisions and data-flow for M0
docs/os-concepts.md      — /proc concepts, clock ticks, TOCTOU, zombie processes
Makefile                 — build and test targets
```

## Development environment

This project targets Linux. CI should run on Ubuntu 22.04+ or equivalent.
WSL2 with Ubuntu is supported for Windows development.
