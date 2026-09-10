#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
APP_DIR="$REPO_DIR"
CONFIG_SOURCE=""
START=0

usage() {
    echo "Usage: sudo bash scripts/install.sh [--app-dir PATH] [--config-source FILE] [--start]"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --app-dir) APP_DIR="$2"; shift 2 ;;
        --config-source) CONFIG_SOURCE="$2"; shift 2 ;;
        --start) START=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must run as root" >&2
    exit 1
fi

for command in python3 systemctl journalctl loginctl runuser; do
    command -v "$command" >/dev/null 2>&1 || { echo "Missing prerequisite: $command" >&2; exit 1; }
done
PYTHON_BIN=$(command -v python3)

if [ ! -f "$APP_DIR/src/ssh_session_agent/__main__.py" ]; then
    echo "SSH Session Agent source not found in $APP_DIR" >&2
    exit 1
fi

if ! getent group ssh-session-agent >/dev/null; then
    groupadd --system ssh-session-agent
fi
if ! id ssh-session-agent >/dev/null 2>&1; then
    useradd --system --gid ssh-session-agent --home-dir /nonexistent --shell /usr/sbin/nologin ssh-session-agent
fi
if getent group systemd-journal >/dev/null; then
    usermod -a -G systemd-journal ssh-session-agent
else
    echo "systemd-journal group not found" >&2
    exit 1
fi

install -d -o root -g ssh-session-agent -m 0750 /etc/ssh-session-agent
install -d -o ssh-session-agent -g ssh-session-agent -m 0700 /var/lib/ssh-session-agent

if [ -n "$CONFIG_SOURCE" ]; then
    test -f "$CONFIG_SOURCE" || { echo "Config source not found" >&2; exit 1; }
    install -o root -g ssh-session-agent -m 0640 "$CONFIG_SOURCE" /etc/ssh-session-agent/config.json
elif [ ! -f /etc/ssh-session-agent/config.json ]; then
    echo "No production config exists. Pass --config-source FILE." >&2
    exit 1
fi

sed \
    -e "s|@@APP_DIR@@|$APP_DIR|g" \
    -e "s|@@PYTHON_BIN@@|$PYTHON_BIN|g" \
    "$APP_DIR/deploy/ssh-session-agent.service.in" \
    > /etc/systemd/system/ssh-session-agent.service
chmod 0644 /etc/systemd/system/ssh-session-agent.service
systemctl daemon-reload
systemctl enable ssh-session-agent.service >/dev/null

runuser -u ssh-session-agent -- env PYTHONPATH="$APP_DIR/src" "$PYTHON_BIN" -m ssh_session_agent \
    --config /etc/ssh-session-agent/config.json preflight

if [ "$START" -eq 1 ]; then
    systemctl restart ssh-session-agent.service
    systemctl --no-pager --full status ssh-session-agent.service
else
    echo "Installed and enabled. Service was not started; use --start after preflight/credentials are approved."
fi
