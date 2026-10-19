# Setup and testing

[← Onboarding index](README.md) · see also: [TELEMETRY_AND_INVARIANTS.md](TELEMETRY_AND_INVARIANTS.md)

Every command here was checked against the repository's
[`Makefile`](../../Makefile), [`pytest.ini`](../../pytest.ini),
`tests/conftest.py` and the scripts in `tools/`. Environment versions are
the ones **recorded in the saved evidence** (verified for the owner's
machine); yours may differ, and differences must be noted in any evidence
you produce.

## 1. The development environment

| Item | Recorded value (evidence) | Required? |
|---|---|---|
| OS | Windows + **WSL2**, distro **Ubuntu 26.04** | required: build and test *inside* WSL. Git Bash/MSYS2 `/proc` is not Linux `/proc` |
| Kernel | `6.18.33.2-microsoft-standard-WSL2`, cgroup v2 only | required: any change must be re-verified |
| C toolchain | `gcc` + `make` (C11; `-static` helper needs static libc) | required |
| System Python | `/usr/bin/python3` **3.14.4** | required (telemetry layer, BCC) |
| BCC | apt `python3-bpfcc` **0.35.0** (+ `bpfcc-tools`) | required for privileged tests |
| Kernel headers for BCC | `kheaders` module (`/sys/kernel/kheaders.tar.xz`) | required; **not persistent across WSL restarts** |
| Python 3.12 venv | CPython **3.12.15** at `~/.venvs/processpulse-py312` (made by `tools/setup_py312_env.sh` with user-level `uv`) | required for `make test-py` and future ML work (D-14) |
| pytest, jsonschema | user-level for the system Python; pinned in `requirements/py312-dev.txt` for the venv (pytest 8.4.2, jsonschema 4.25.1) | required |
| Docker | `docker.io` 29.1.3, image `busybox:1.36` | optional: Docker tests are **skipped** (not passed) when the daemon is unusable (`tests/conftest.py`) |
| `bpftool` | not installed | optional; nothing depends on it |

`sudo` asks for a password on the owner's machine. The project's privileged
steps were run either by the user or from Windows with
`wsl -d Ubuntu -u root -- <cmd>`, once that step was authorized.

## 2. Find and enter the repository in WSL

The repo lives on the Windows drive. The path contains spaces, so quote it.

```sh
# from a WSL shell (replace <you> and the path with yours)
cd "/mnt/c/Users/<you>/Desktop/vit/5th sem/os/os project/os project"
```

From Windows PowerShell you can run a single WSL command:
`wsl -d Ubuntu -- bash -c 'cd "/mnt/c/.../os project" && make test'`.
For anything longer than one command, put it in a script file and run
`wsl -d Ubuntu -- bash /mnt/c/.../script.sh`. Nested quoting through
PowerShell or Git Bash breaks easily, and Git Bash rewrites `/mnt/...`
arguments unless you prefix `MSYS_NO_PATHCONV=1`.

## 3. Inspect repository state (always first)

```sh
git branch --show-current
git log --oneline -n 10
git status --short          # what is modified / untracked
git diff --stat             # size of uncommitted changes
git diff --cached --stat    # anything staged? (should normally be nothing)
```

**Expected untracked files you must leave alone:** the 15 intentional M1
evidence logs:
- `results/acceptance/m1/10min/*.stderr.log`;
- `results/acceptance/m1/exact_counts/run-*.log`;
- `results/acceptance/m1/overhead/{abba_stderr,progress,stderr}.log`.

`results/raw/` is ignored by git and holds raw recordings. Never delete,
stage or "clean" either of them.

## 4. Build

```sh
make            # ./collector
make helpers    # build/sysc_helper (static, -pthread; used by tests and DIT-1)
make test-c     # C unit tests under ASan+UBSan: expect "test_procfs: 74 checks, 0 failures"
make check      # extra static analysis (-Wconversion, -fanalyzer); expect rc 0
```

## 5. Non-privileged tests (safe, run often)

```sh
make test                                                     # builds, C tests, then pytest -m "not privileged" (system Python)
make test-py PYTHON=$HOME/.venvs/processpulse-py312/bin/python  # same pytest selection on Python 3.12
python3 -m pytest tests/test_net_unit.py -v                  # one file
python3 -m pytest tests/test_snapshots.py -k keyframe -v     # by keyword
```

**Historical reference** (from saved evidence; your counts change as tests
are added):
- **S2.6:** 613 passed, 1 skipped.
- **S3.2 working tree:** 657 passed, 1 skipped, on both Python 3.14.4 and
  3.12.15 (`results/acceptance/m1b/s3.2/regression/`).
- The 1 skip is the known M0 defect D8 (`test_minimum_record_count`).
- Other skips mean a missing prerequisite. Read the skip reason.

## 6. Privileged tests (root, BCC): run deliberately

Privileged tests load real eBPF programs into the kernel and spawn helper
processes. Some take minutes and use a lot of memory. Use the checklist in
§6.1 first.

```sh
# as root, reusing the normal user's pytest (root's Python has no pytest installed)
sudo PYTHONUSERBASE=/home/<you>/.local make test-privileged
# a single file, e.g. the network tests (uncommitted S3.2 work):
sudo PYTHONUSERBASE=/home/<you>/.local python3 -m pytest tests/test_net_bpf.py -m privileged -v
# keep machine-readable results:
sudo PYTHONUSERBASE=/home/<you>/.local python3 -m pytest tests/test_net_bpf.py -m privileged -v \
     --junitxml=results/raw/net-bpf.xml
```

The preflight on its own: `sudo python3 -m processpulse.preflight`. It
exits 0 iff root, BCC, tracefs, every tracepoint and the kernel headers are
OK; as root it attempts `modprobe kheaders`.

### 6.1 Preflight checklist before expensive privileged runs

Two heavy runs in this project's history were stopped by the tooling for
low host memory: M1's order-balanced overhead check and the S3.2 privileged
regression. Check, record and decide **before** starting:

- [ ] **WSL memory:** `grep MemAvailable /proc/meminfo`.
- [ ] **Windows memory:** in PowerShell,
  `(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB`
  (in MB). The old M1b plan used a 2 GiB gate for the heaviest benchmark;
  treat low free memory as a reason to wait, not to retry.
- [ ] **No other heavy job running:** never run two privileged suites (or a
  build plus a privileged suite) at the same time. They also race on
  `make` artifacts.
- [ ] **No leftover test processes:** `ps -eo pid,etimes,cmd | grep -E
  "pytest|net_helper|sysc_helper|collector --v1" | grep -v grep`. If there
  are any, find out whose they are before doing anything.
- [ ] **No leftover BPF handles held by our tools:** list the processes
  holding `bpf-prog` / `perf_event` fds:
  `for p in /proc/[0-9]*; do n=$(ls -l $p/fd 2>/dev/null | grep -c bpf-prog); [ "$n" != 0 ] && echo "$(basename $p) $(tr '\0' ' ' < $p/cmdline | cut -c1-60) $n"; done`.
  `/sbin/init` (systemd) normally holds a few of its own; that is expected.
- [ ] `cat /proc/sys/kernel/bpf_stats_enabled` is `0`. Some harnesses set
  it temporarily and must restore it.
- [ ] `ls /sys/fs/cgroup | grep -c '^ppc-'` is `0`, and
  `docker ps -a` / `docker network ls` show nothing created by tests.
- [ ] `kheaders` is loaded, or you are root so the preflight can load it.

**Never** "fix" leftovers with blind commands: no `pkill python3`, no
`docker rm -f $(docker ps -aq)`, no `docker network prune`, no deleting
under `results/`. Identify what each item is and who owns it first, and
ask the owner.

## 7. Focused acceptance tools (`tools/acceptance/`)

| Tool | What it does | Notes |
|---|---|---|
| `validate_run.py RUN_DIR [--min-span-s S] [--json OUT] [--require-drained]` | validates every line of a recorded run (schema, byte rule, framing, alignment, snapshot protocol, bigram invariants) | unprivileged; exit 0 iff all checks pass |
| `s1_equivalence.py OUT.json` | counts-only behavior probe (root) | compare with `results/acceptance/m1b/s1/equivalence-post-s1.json` (below) |
| `bigram_exact.sh [REPS]` | repeated scripted exact-bigram acceptance (root) | **writes into `results/acceptance/m1b/s2.4/exact/`**: running it overwrites that stage's evidence. Use a copy or ask first |
| `exact_counts.sh`, `run_10min.sh`, `run_s0_10min.sh` | M1/S0 acceptance harnesses | **they write straight into accepted evidence:** `results/acceptance/m1/exact_counts/` (which holds 10 of the 15 intentional M1 logs), `results/acceptance/m1/10min/` and `results/acceptance/m1b/s0/`. Running them overwrites that evidence. Don't run them without the owner's authorization and a plan for where the output goes |
| `overhead.py` | overhead matrix; writes `results/acceptance/m1/overhead/` (accepted M1 evidence) | **don't run `--abba`** (the order-balanced benchmark) or the matrix without explicit authorization (memory, and it overwrites evidence) |

**Counts-only equivalence check** (as root). Write the output outside the
committed evidence:

```sh
sudo python3 -W ignore tools/acceptance/s1_equivalence.py /tmp/equiv.json
python3 - /tmp/equiv.json <<'EOF'
import json, sys
sys.path.insert(0, "tools/acceptance")
from summarize_bigram_exact import BASELINE, flat
cur, base = flat(json.load(open(sys.argv[1]))), flat(json.load(open(BASELINE)))
diff = sorted(k for k in set(cur) | set(base) if cur.get(k) != base.get(k))
print(f"identical {len(cur) - len(diff)} of {len(base)}; different: {diff}")
EOF
```

Every stage since S2.3 reported **34 of 34 identical**. S3.2 has **not**
run it yet.

## 8. Recording and validating a run

```sh
sudo python3 -m processpulse.agent --duration 30 --interval-ms 500 --schema 2 \
     --capabilities counts,bigrams --out results/raw/my-run
python3 tools/acceptance/validate_run.py results/raw/my-run --min-span-s 25 --require-drained
```

- Default `--schema 1` writes `syscall.jsonl`; `--schema 2` writes
  `bpf.jsonl`.
- **Strict startup:** a requested capability that cannot start makes the
  agent exit 1 and write `manifest.json` with `status: failed`.
- `--allow-degraded` is the only way to run counts-only after such a
  failure.

## 9. Reading results and evidence

- **pytest:** `-v` shows each test; `-rs` shows skip reasons. A skip is
  **not** a pass. `--junitxml` stores per-test properties, which some tests
  record with `record_property`.
- **Verifier output:** BCC prints nothing from the verifier on success. The
  S3.2 evidence captured it by loading with BCC `DEBUG_BPF`:
  `results/acceptance/m1b/s3.2/verifier-counts,net.txt` has one "processed N
  insns" line per program. A compile or verifier failure appears as an
  exception from `BPF(...)` with the clang or verifier message above it.
- **Map memory:** `BpfCollector(...).start().build_info()["maps"]` reports
  `max_entries` and `memlock` per map, from `/proc/self/fdinfo`.
- **Evidence:** every stage has `results/acceptance/<stage>/README.md`, with
  the commands, exit codes, counts and limitations. Read the README before
  the raw logs.

## 10. Common setup failures (seen in this repository's history)

| Symptom | Cause | What to do |
|---|---|---|
| Tests about `/proc` behave strangely or fail on Windows | running in Git Bash/MSYS2 instead of WSL | run inside WSL (`CLAUDE.md` §4) |
| Privileged tests all **skipped** | not root (`tests/conftest.py`) | run as root, with `PYTHONUSERBASE` |
| `No module named pytest` as root | root's Python has no pytest | `PYTHONUSERBASE=/home/<you>/.local` |
| BCC compile error about missing kernel headers; preflight `kernel_headers` FAIL | `kheaders` not loaded after a WSL restart | `sudo modprobe kheaders` (the preflight tries this as root) |
| BCC compile error `invalid application of 'sizeof' to an incomplete type 'struct bpf_task_work'` | BCC 0.35 vs 6.18 headers via `<net/sock.h>` | already handled by a declaration in `bpf/net.bpf.c`; see `docs/bpf-collector.md`, "Network capability" |
| `membarrier MEMBARRIER_CMD_GLOBAL is not available` | kernel without the command (e.g. `nohz_full`) | the purge refuses to run without it, by design; report it, don't work around it |
| Docker tests skipped | Docker daemon unusable | optional; DIT-1 is then **not** verified |
| A long run disappears; the tool reports low memory | host memory pressure | do not auto-restart; use the §6.1 checklist and ask |
| Commands fail with odd paths from Git Bash | MSYS path conversion | prefix `MSYS_NO_PATHCONV=1`, or use a script file |
