#!/bin/bash
# M1b S2.4 acceptance — exact pair tables and counts-only equivalence, REPS
# independent repetitions (default 10; the criterion is 10 of 10).
#
# Run as root:  PYTHONUSERBASE=/home/<user>/.local bash tools/acceptance/bigram_exact.sh [REPS]
# Each repetition is a separate pytest process (fresh BPF load) running
# tests/test_bigrams_acceptance.py (exact pairs for N in {1, 1000, 100000},
# a mixed sequence, an exec, and a ground-truth scope), followed by one run
# of tools/acceptance/s1_equivalence.py (counts-only behaviour, U6). Runs are
# sequential. summarize_bigram_exact.py tabulates JUnit XML and compares each
# equivalence output with the S1 baseline.
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPS="${1:-10}"
OUT="$REPO/results/acceptance/m1b/s2.4/exact"
mkdir -p "$OUT"
cd "$REPO" || exit 1
export PYTHONDONTWRITEBYTECODE=1

python3 -m processpulse.preflight > "$OUT/preflight.json" || { echo "preflight failed"; exit 2; }
{
    echo "start_wall: $(date -Is) reps=$REPS"
    echo "bpf_stats_enabled: $(cat /proc/sys/kernel/bpf_stats_enabled)"
    echo "mem_available_kb: $(awk '/MemAvailable/ {print $2}' /proc/meminfo)"
} > "$OUT/runs.log"
for i in $(seq -w 1 "$REPS"); do
    python3 -m pytest -p no:cacheprovider -q -W ignore::DeprecationWarning \
        tests/test_bigrams_acceptance.py --junitxml="$OUT/run-$i.xml" > "$OUT/run-$i.log" 2>&1
    rc_t=$?
    python3 -W ignore tools/acceptance/s1_equivalence.py "$OUT/equivalence-$i.json" \
        > "$OUT/equivalence-$i.log" 2>&1
    rc_e=$?
    echo "run $i pytest_rc=$rc_t equivalence_rc=$rc_e $(tail -1 "$OUT/run-$i.log")" | tee -a "$OUT/runs.log"
done
{
    echo "end_wall: $(date -Is)"
    echo "bpf_stats_enabled: $(cat /proc/sys/kernel/bpf_stats_enabled)"
    echo "ppc_cgroups: $(ls /sys/fs/cgroup | grep -c '^ppc-')"
    echo "containers: $(docker ps -aq 2>/dev/null | wc -l)"
} >> "$OUT/runs.log"
python3 tools/acceptance/summarize_bigram_exact.py "$OUT" "$REPS"
