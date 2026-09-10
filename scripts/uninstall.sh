#!/usr/bin/env bash
set -euo pipefail

PURGE_STATE=0
PURGE_CONFIG=0
for arg in "$@"; do
    case "$arg" in
        --purge-state) PURGE_STATE=1 ;;
        --purge-config) PURGE_CONFIG=1 ;;
        *) echo "Unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall.sh must run as root" >&2
    exit 1
fi

systemctl disable --now ssh-session-agent.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/ssh-session-agent.service
systemctl daemon-reload

if [ "$PURGE_STATE" -eq 1 ]; then
    rm -rf /var/lib/ssh-session-agent
fi
if [ "$PURGE_CONFIG" -eq 1 ]; then
    rm -rf /etc/ssh-session-agent
fi

echo "Service removed. State/config were preserved unless explicitly purged."
