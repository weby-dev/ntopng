#!/bin/bash
# =============================================================================
# scripts/run_analyzer.sh — Cron Wrapper
#
# Crontab (twice an hour):
#   0,30 * * * * /opt/ntopng-analyzer/scripts/run_analyzer.sh >> /var/log/ntopng_analyzer/cron.log 2>&1
# =============================================================================

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PYTHON="${PYTHON_BIN:-/usr/bin/python3}"
VENV="${PROJECT_DIR}/.venv"
LOG_DIR="/var/log/ntopng_analyzer"
LOCK_FILE="/var/run/ntopng_analyzer.lock"

# Victim CC emails — comma separated, no spaces
VICTIM_CC_EMAILS="${VICTIM_CC_EMAILS:-noc@yourdomain.com,security@yourdomain.com}"

# Optional: restrict to a single server IP (leave blank to process all)
TARGET_SERVER="${TARGET_SERVER:-}"

# ── Setup ─────────────────────────────────────────────────────────────────────
mkdir -p "$LOG_DIR"

# Use venv if present
if [ -f "$VENV/bin/python3" ]; then
    PYTHON="$VENV/bin/python3"
fi

# ── Lock — prevent overlapping runs ──────────────────────────────────────────
if [ -e "$LOCK_FILE" ]; then
    PID=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        echo "[$(date -u +%FT%TZ)] Previous run (PID $PID) still active — skipping." >&2
        exit 0
    fi
fi
echo $$ > "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"' EXIT

# ── Run ───────────────────────────────────────────────────────────────────────
echo "[$(date -u +%FT%TZ)] ── ntopng-analyzer cron started (PID=$$) ──"

cd "$PROJECT_DIR"

ARGS="--victim-cc $VICTIM_CC_EMAILS"
if [ -n "$TARGET_SERVER" ]; then
    ARGS="$ARGS --server $TARGET_SERVER"
fi

"$PYTHON" -m scripts.analyzer $ARGS
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "[$(date -u +%FT%TZ)] ── Run SUCCESSFUL ──"
else
    echo "[$(date -u +%FT%TZ)] ── Run FAILED (exit $EXIT_CODE) ──" >&2
fi

exit $EXIT_CODE
