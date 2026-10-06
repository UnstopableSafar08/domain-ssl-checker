#!/usr/bin/env bash
# Restart the SSL Checker web UI: stop (if running), then start.
# Usage: ./restart.sh [--host 127.0.0.1] [--port 5000] [--allow-private ...]
# Any extra flags are forwarded to start.sh.
set -euo pipefail
cd "$(dirname "$0")"

./stop.sh || true
exec ./start.sh "$@"
