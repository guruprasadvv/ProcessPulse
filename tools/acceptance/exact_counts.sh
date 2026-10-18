#!/bin/bash
# M1 acceptance B — exact syscall-entry counts, 10 independent repetitions.
#
# Run as root:  PYTHONUSERBASE=/home/<user>/.local bash tools/acceptance/exact_counts.sh [REPS]
# Each repetition is a separate pytest process (fresh BPF load) running the
# existing tests: test_exact_entry_counts (openat/open/execve/clone x N=1,1000)
# and test_exact_entry_counts_100000 (openat/execve/clone). Per-run JUnit XML
# keeps the observed counts; summarize_exact_counts.py tabulates them.
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPS="${1:-10}"
OUT="$REPO/results/acceptance/m1/exact_counts"
mkdir -p "$OUT"
cd "$REPO" || exit 1
export PYTHONDONTWRITEBYTECODE=1

python3 -m processpulse.preflight > "$OUT/preflight.json" || { echo "preflight failed"; exit 2; }
echo "start_wall: $(date -Is) reps=$REPS" > "$OUT/runs.log"
for i in $(seq -w 1 "$REPS"); do
    python3 -m pytest -p no:cacheprovider -q -W ignore::DeprecationWarning \
        tests/test_syscall_collector.py -k "test_exact_entry_counts" \
        --junitxml="$OUT/run-$i.xml" > "$OUT/run-$i.log" 2>&1
    echo "run $i rc=$? $(tail -1 "$OUT/run-$i.log")" | tee -a "$OUT/runs.log"
done
echo "end_wall: $(date -Is)" >> "$OUT/runs.log"
python3 tools/acceptance/summarize_exact_counts.py "$OUT" "$REPS"
