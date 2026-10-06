#!/usr/bin/env bash
# Stop the SSL Checker web UI started by start.sh.
set -euo pipefail
cd "$(dirname "$0")"

PID_FILE=".ssl-checker.pid"

stop_pid() {
  local pid="$1"
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "PID $pid not running."
    return 1
  fi
  echo "Stopping PID $pid..."
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do
    kill -0 "$pid" 2>/dev/null || { echo "Stopped."; return 0; }
    sleep 0.25
  done
  echo "Force-killing $pid..."
  kill -9 "$pid" 2>/dev/null || true
  echo "Stopped."
}

if [[ -f "$PID_FILE" ]]; then
  PID="$(cat "$PID_FILE")"
  if stop_pid "$PID"; then
    rm -f "$PID_FILE"
    exit 0
  else
    rm -f "$PID_FILE"
  fi
fi

# Fallback: find a leftover serve process by pattern.
LEFTOVER="$(pgrep -f "app.py serve" | head -n 1 || true)"
if [[ -n "${LEFTOVER:-}" ]]; then
  stop_pid "$LEFTOVER" || true
  exit 0
fi

echo "Not running (no $PID_FILE, no matching process)."
