#!/bin/bash
# M1b S0 acceptance (T-F6) — 10-minute agent run with --schema 2, then validation.
#
# Run as root from anywhere:  bash tools/acceptance/run_s0_10min.sh [MIN_SECONDS]
#                             bash tools/acceptance/run_s0_10min.sh --negative-only RUN_DIR
# The agent runs in the foreground for MIN_SECONDS + 15 s of collection (its
# --duration counts from the start of collection), then the run is validated
# in v2 mode with --min-span-s MIN_SECONDS. A truncated copy of the recorded
# bpf.jsonl (the stream cut right after the final snapshot's begin record, as
# if the agent crashed while writing it) is validated as well: it must be
# rejected. --negative-only repeats just that check on an existing run.
# Raw telemetry stays in results/raw/ (gitignored).
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EVID="$REPO/results/acceptance/m1b/s0"
mkdir -p "$EVID"
cd "$REPO" || exit 1
export PYTHONDONTWRITEBYTECODE=1

negative_check() {   # $1 = recorded v2 run dir; sets trc
    local run="$1" cut="$1-truncated"
    mkdir -p "$cut"
    cp "$run/resource.jsonl" "$run/health.jsonl" "$cut/"
    python3 - "$run/bpf.jsonl" "$cut/bpf.jsonl" <<'EOF' >> "$EVID/run.log"
import json, sys
lines = open(sys.argv[1], "rb").read().split(b"\n")[:-1]
last_begin = max(i for i, l in enumerate(lines) if json.loads(l)["type"] == "bpf_snapshot_begin")
keep = lines[:last_begin + 1]          # the final snapshot's begin, nothing after it
assert len(keep) < len(lines), "nothing was cut"
open(sys.argv[2], "wb").write(b"\n".join(keep) + b"\n")
print(f"truncated copy: kept {len(keep)} of {len(lines)} lines (cut after the final begin)")
EOF
    python3 tools/acceptance/validate_run.py "$cut" --min-span-s 0 \
        --json "$EVID/validation-truncated.json" > /dev/null
    trc=$?
    echo "validate_run on truncated copy rc=$trc (expected 1)" >> "$EVID/run.log"
}

if [ "${1:-}" = "--negative-only" ]; then
    echo "negative-only check on ${2:?run dir} at $(date -Is)" >> "$EVID/run.log"
    negative_check "$2"
    [ "$trc" -eq 1 ] && status=PASS || status=FAIL
    echo "NEGATIVE RESULT: $status" | tee -a "$EVID/run.log"
    [ "$status" = PASS ]
    exit
fi

MIN_S="${1:-600}"
RUN="$REPO/results/raw/m1b-s0-10min-$(date +%Y%m%dT%H%M%S)"
mkdir -p "$RUN"
CMD=(python3 -m processpulse.agent --schema 2 --duration "$((MIN_S + 15))" --interval-ms 1000 --out "$RUN")
{
    echo "command: ${CMD[*]}"
    echo "start_wall: $(date -Is)"
} > "$EVID/run.log"
"${CMD[@]}" > "$RUN/agent.stdout.log" 2> "$RUN/agent.stderr.log"
rc=$?
echo "agent rc=$rc end_wall=$(date -Is)" >> "$EVID/run.log"
leftover=$(pgrep -f "$REPO/collector --v1" | wc -l)
echo "leftover collector processes: $leftover" >> "$EVID/run.log"

python3 tools/acceptance/validate_run.py "$RUN" --min-span-s "$MIN_S" --json "$EVID/validation.json" > /dev/null
vrc=$?
echo "validate_run rc=$vrc" >> "$EVID/run.log"
negative_check "$RUN"

cp "$RUN/manifest.json" "$EVID/manifest.json"
cp "$RUN/preflight.json" "$EVID/preflight.json"
echo "raw_run_dir: $RUN" >> "$EVID/run.log"
if [ "$rc" -eq 0 ] && [ "$vrc" -eq 0 ] && [ "$trc" -eq 1 ] && [ "$leftover" -eq 0 ]; then
    status=PASS
else
    status=FAIL
fi
echo "RESULT: $status" | tee -a "$EVID/run.log"
[ "$status" = PASS ]
