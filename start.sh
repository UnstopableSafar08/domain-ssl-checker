#!/usr/bin/env bash
# Start the SSL Checker web UI (+ 5-min scheduler) in the background.
# Usage: ./start.sh [--allow-private] [--host 127.0.0.1] [--port 5000]
# Env overrides: HOST, PORT, SSL_DOMAINS_FILE, SSL_DB_PATH,
#   SSL_CHECK_INTERVAL_SECONDS (default 300), TEAMS_WEBHOOK_URL
set -euo pipefail
cd "$(dirname "$0")"

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-5000}"
PID_FILE=".ssl-checker.pid"
LOG_FILE="ssl-checker.log"

# Parse optional flags (env vars still win if set explicitly is fine — flags update them).
EXTRA_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    *) EXTRA_ARGS+=("$1"); shift ;;
  esac
done

if [[ -f "$PID_FILE" ]]; then
  OLD_PID="$(cat "$PID_FILE")"
  if kill -0 "$OLD_PID" 2>/dev/null; then
    echo "Already running (PID $OLD_PID) -> http://$HOST:$PORT"
    exit 0
  else
    echo "Removing stale PID file."
    rm -f "$PID_FILE"
  fi
fi

if [[ ! -x ".venv/bin/python" ]]; then
  echo "Creating virtualenv (.venv)..."
  python3 -m venv .venv
fi
echo "Installing dependencies..."
.venv/bin/pip install -q -r requirements.txt
export SSL_DB_PATH="${SSL_DB_PATH:-data/ssl_checker.db}"
export SSL_CHECK_INTERVAL_SECONDS="${SSL_CHECK_INTERVAL_SECONDS:-300}"

echo "Starting SSL Checker on http://$HOST:$PORT ..."
# shellcheck disable=SC2086
nohup .venv/bin/python app.py serve --host "$HOST" --port "$PORT" ${EXTRA_ARGS[@]:-} > "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
echo "PID $(cat "$PID_FILE") (log: $LOG_FILE)"

# Wait for health (max ~15s).
for i in $(seq 1 30); do
  if curl -sf "http://$HOST:$PORT/health" >/dev/null 2>&1; then
    echo "Up: http://$HOST:$PORT (health OK)"
    exit 0
  fi
  sleep 0.5
done
echo "Started but /health not responding yet — check $LOG_FILE"
tail -n 20 "$LOG_FILE" || true
exit 1
