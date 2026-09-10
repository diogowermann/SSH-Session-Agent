#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APP_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
PYTHON_BIN=$(command -v python3)
exec env PYTHONPATH="$APP_DIR/src" "$PYTHON_BIN" -m ssh_session_agent \
    --config /etc/ssh-session-agent/config.json preflight
