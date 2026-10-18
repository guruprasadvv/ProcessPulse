# M1 acceptance evidence (2026-10-19)

Environment: WSL2 Ubuntu 26.04, kernel 6.18.33.2-microsoft-standard-WSL2, 16 vCPU
(AMD Ryzen 7 5700U), 6.7 GiB RAM, system Python 3.14.4 + BCC 0.35.0, run as root.
Raw telemetry is kept outside git in `results/raw/` (paths below); this directory
holds the small evidence files.

| Item | Status | Evidence |
|---|---|---|
| A. 10-minute schema-validity run | **PASS** | `10min/` |
| B. Exact counts, 10 repetitions | **PASS** | `exact_counts/` |
| C. Overhead matrix 3 × 3 × 5 | **PASS** (measured; see limitations) | `overhead/` |

## A. Continuous run — `tools/acceptance/run_10min.sh 600`

- Agent: `python3 -m processpulse.agent --duration 3600 --interval-ms 1000 --out results/raw/m1-10min-20261018T205546`,
  started in the background by the monitor, which polled every 15 s and sent SIGTERM once
  600 s of collection had elapsed (CLOCK_MONOTONIC from the first `sample_begin`).
- Collection span 612.004 s (first `sample_begin` → last `sample_end`); agent rc 0 about 1 s
  after SIGTERM; 0 leftover collector processes.
- `tools/acceptance/validate_run.py`: 27 803 / 27 803 lines valid (resource 26 577,
  syscall 613, health 613), 0 unterminated tails; framing ok (613 samples);
  1:1 alignment of samples, snapshots and health records; collector stream clean
  (every filtered-line counter 0). SHA-256 values are in `10min/validation.json`.
- Loss counters (not part of schema validity): 0 dropped samples, 0 restarts, 0 map-full,
  337 processes vanished mid-sample, 9 070 unresolved events, max lateness 1.1 ms.
  The unresolved events come from WSL's own `init` (pid-namespace level 0, outside the
  distro), which calls `open` once per process created in the distro; per the identity
  contract they are counted and never attributed. Diagnosed with a reason-coded copy of
  the identity checks: 100/100 unresolved events during 100 spawns were `level < distro`,
  comm `init`.
- The exact-count repetitions (B) ran concurrently, so the run saw heavy process churn
  (~1 M short-lived processes).
- Validator negative tests (truncated line, invalid value, dropped proc record, missing
  snapshot, span below the minimum) were all rejected.

## B. Exact counts — `tools/acceptance/exact_counts.sh 10`

10 independent pytest processes (fresh BPF load each) of the existing
`test_exact_entry_counts` / `test_exact_entry_counts_100000`; observed values are
recorded in each `run-NN.xml`. **110 / 110 exact**:

| configuration | runs | exact | expected | observed |
|---|---|---|---|---|
| openat / open / execve / clone, N = 1 | 10 each | 10 each | 1 | {1} |
| openat / open / execve / clone, N = 1000 | 10 each | 10 each | 1000 | {1000} |
| openat / execve / clone, N = 100 000 | 10 each | 10 each | 100 000 | {100 000} |

The 1000-process start-time identity test is a separate property (1000/1000 matched,
see `ENGINEERING_CHANGELOG.md`). It was not repeated, because its criterion is not
"10 runs" and the identity code is unchanged.

## C. Overhead — `tools/acceptance/overhead.py --window-s 30 --reps 5`

45 instrumented runs (idle / cpu / churn × 250 / 1000 / 5000 ms × 5) plus 10 baseline runs
(cpu and churn without the agent), each with a 30 s measured window that starts after the
agent's first complete sample (so BCC compilation is excluded). `kernel.bpf_stats_enabled`
was 1 during the experiment and restored to 0 afterwards. All 45 agent runs exited 0;
0 dropped samples and 0 map-full events in every run. Medians over 5 repetitions (IQR in
`overhead/summary.json`; per-run values in `overhead/runs.csv`):

| workload | interval | agent + collector CPU (% of one CPU) | BPF in-kernel CPU % | BPF ns/event | sample duration | snapshot |
|---|---|---|---|---|---|---|
| idle | 250 ms | 2.97 | 0.034 | 504 | 2.9 ms | 0.3 ms |
| idle | 1 s | 0.80 | 0.012 | 528 | 2.9 ms | 0.3 ms |
| idle | 5 s | 0.23 | 0.007 | 681 | 2.9 ms | 0.4 ms |
| cpu | 250 ms | 2.96 | 0.033 | 492 | 2.9 ms | 0.3 ms |
| cpu | 1 s | 0.77 | 0.011 | 560 | 3.0 ms | 0.3 ms |
| cpu | 5 s | 0.23 | 0.005 | 679 | 2.9 ms | 0.4 ms |
| churn (~930 proc/s) | 250 ms | 10.99 | 1.42 | 2256 | 2.7 ms | 9.8 ms |
| churn | 1 s | 10.33 | 1.42 | 2470 | 2.5 ms | 44 ms |
| churn | 5 s | 8.86 | 1.43 | 2506 | 2.6 ms | 256 ms |

Memory: collector RSS ≈ 2.0 MB. Agent RSS ≈ 219 MB, which is mostly BCC/LLVM resident in
the agent process (VmHWM ≈ 220–235 MB).

### Limitation: workload-throughput change is not attributable

`summary.md` also lists the throughput change against a baseline (cpu −4.5 … −7.3 %,
churn ≈ −10 %). These numbers are **confounded by run order** and are not reported as
agent overhead:

- every baseline ran first in its repetition, and every instrumented run followed a
  CPU-heavy BCC compile on a laptop CPU with frequency boost;
- the cpu slowdown grows with position in the run order (first instrumented run
  −3.5 … −6.0 %, later ones −4.7 … −9.4 %) instead of with agent activity: the 5 s interval
  uses about 13× less agent CPU than 250 ms, yet shows the same or a larger slowdown.

An order-balanced check (baseline, instrumented, instrumented, baseline at 1 s; 5 reps) was
started, but Claude Code stopped it because the Windows host ran critically low on memory.
That was not a failure of the check, and it was not restarted. Its 13 completed runs
(`overhead/abba_progress.log`): cpu paired change −0.4 % and +2.3 %, while consecutive
baselines drifted by up to 12 %; churn, one complete pair, −5.5 %. That is too little data to
quantify workload impact. A real cost is plausible for syscall-heavy churn (BPF ≈ 2.4 µs per
event; agent ≈ 10 % of one CPU) and undetectable for the cpu workload. The directly measured
CPU, BPF-time, RSS and loss figures above are unaffected by this confound. No performance
target exists for M1; a controlled workload-impact measurement belongs to M7 (PPT-095).
