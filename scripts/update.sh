#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APP_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
PYTHON_BIN=$(command -v python3)
command -v runuser >/dev/null 2>&1 || { echo "Missing prerequisite: runuser" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    echo "update.sh must run as root" >&2
    exit 1
fi

test -f /etc/ssh-session-agent/config.json || { echo "Production config not found" >&2; exit 1; }
runuser -u ssh-session-agent -- env PYTHONPATH="$APP_DIR/src" "$PYTHON_BIN" -m ssh_session_agent \
    --config /etc/ssh-session-agent/config.json preflight
systemctl restart ssh-session-agent.service
systemctl is-active ssh-session-agent.service
