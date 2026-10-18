#!/bin/bash
# M1 acceptance A — continuous 10-minute agent run with full schema validation.
#
# Run as root from anywhere:  bash tools/acceptance/run_10min.sh [MIN_SECONDS]
# The agent is started in the background with a generous --duration upper
# bound; this monitor polls it, and once at least MIN_SECONDS (default 600) of
# collection have elapsed — measured on CLOCK_MONOTONIC from the first
# sample_begin — it requests graceful shutdown with SIGTERM, waits, and then
# validates every record. Telemetry (JSONL) and diagnostics (logs) are kept in
# separate files. An early agent exit is reported as FAIL, never restarted.
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIN_S="${1:-600}"
STAMP="$(date +%Y%m%dT%H%M%S)"
RUN="$REPO/results/raw/m1-10min-$STAMP"          # raw telemetry (gitignored)
EVID="$REPO/results/acceptance/m1/10min"          # small evidence files
mkdir -p "$RUN" "$EVID"
cd "$REPO" || exit 1
export PYTHONDONTWRITEBYTECODE=1

CMD=(python3 -m processpulse.agent --duration 3600 --interval-ms 1000 --out "$RUN")
mono() { python3 -c 'import time; print(time.monotonic_ns())'; }
first_begin_ns() {
    python3 - "$RUN/resource.jsonl" <<'EOF'
import json, sys
try:
    with open(sys.argv[1], "rb") as f:
        line = f.readline()
    print(json.loads(line)["t_mono_ns"] if line.endswith(b"\n") else "")
except (OSError, ValueError, KeyError):
    print("")
EOF
}

echo "command: ${CMD[*]}"            > "$EVID/monitor.log"
echo "start_wall: $(date -Is)"      >> "$EVID/monitor.log"
"${CMD[@]}" > "$RUN/agent.stdout.log" 2> "$RUN/agent.stderr.log" &
PID=$!
echo "agent_pid: $PID"              >> "$EVID/monitor.log"

status=RUNNING
t0=""
while :; do
    sleep 15
    if ! kill -0 "$PID" 2>/dev/null; then
        wait "$PID"; rc=$?
        echo "agent exited early rc=$rc at $(date -Is)" >> "$EVID/monitor.log"
        status=FAIL_EARLY_EXIT
        break
    fi
    [ -z "$t0" ] && t0="$(first_begin_ns)"
    size=$(stat -c %s "$RUN/resource.jsonl" 2>/dev/null || echo 0)
    if [ -n "$t0" ]; then
        elapsed=$(( ($(mono) - t0) / 1000000000 ))
        echo "$(date -Is) alive elapsed_s=$elapsed resource_bytes=$size" >> "$EVID/monitor.log"
        if [ "$elapsed" -ge "$MIN_S" ]; then
            break
        fi
    else
        echo "$(date -Is) alive, waiting for first sample (resource_bytes=$size)" >> "$EVID/monitor.log"
    fi
done

if [ "$status" = RUNNING ]; then
    echo "sending SIGTERM at $(date -Is)" >> "$EVID/monitor.log"
    kill -TERM "$PID"
    for _ in $(seq 1 60); do kill -0 "$PID" 2>/dev/null || break; sleep 1; done
    if kill -0 "$PID" 2>/dev/null; then
        echo "agent did not exit within 60 s; sending SIGKILL" >> "$EVID/monitor.log"
        kill -KILL "$PID"; status=FAIL_NO_GRACEFUL_EXIT
    fi
    wait "$PID"; rc=$?
    echo "agent rc=$rc end_wall=$(date -Is)" >> "$EVID/monitor.log"
    [ "$rc" -ne 0 ] && [ "$status" = RUNNING ] && status=FAIL_EXIT_CODE
fi

leftover=$(pgrep -f "$REPO/collector --v1" | wc -l)
echo "leftover collector processes: $leftover" >> "$EVID/monitor.log"

python3 tools/acceptance/validate_run.py "$RUN" --min-span-s "$MIN_S" --json "$EVID/validation.json" \
    > /dev/null 2> "$EVID/validator.stderr.log"
vrc=$?
cp "$RUN/manifest.json" "$EVID/manifest.json" 2>/dev/null
cp "$RUN/agent.stderr.log" "$EVID/agent.stderr.log" 2>/dev/null
cp "$RUN/agent.stdout.log" "$EVID/agent.stdout.log" 2>/dev/null
cp "$RUN/preflight.json" "$EVID/preflight.json" 2>/dev/null
echo "raw_run_dir: $RUN" >> "$EVID/monitor.log"

if [ "$status" = RUNNING ] && [ "$vrc" -eq 0 ] && [ "$leftover" -eq 0 ]; then
    status=PASS
elif [ "$status" = RUNNING ]; then
    status=FAIL_VALIDATION
fi
echo "RESULT: $status (validator rc=$vrc)" | tee -a "$EVID/monitor.log"
[ "$status" = PASS ]
