from __future__ import annotations

import subprocess
from dataclasses import dataclass

from .models import normalize_ip


@dataclass(frozen=True)
class LogindSession:
    session_id: str
    username: str
    remote_host: str | None
    tty: str | None
    leader_pid: str | None

    @property
    def provider_session_id(self) -> str:
        return f"logind:{self.session_id}"

    @property
    def source_ip(self) -> str | None:
        return normalize_ip(self.remote_host)


def _properties(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


class LogindCollector:
    def list_ssh_sessions(self) -> list[LogindSession]:
        listed = subprocess.run(
            ["loginctl", "list-sessions", "--no-legend", "--no-pager"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if listed.returncode != 0:
            raise RuntimeError("loginctl list-sessions failed")

        session_ids = []
        for line in listed.stdout.splitlines():
            parts = line.split()
            if parts:
                session_ids.append(parts[0])

        sessions: list[LogindSession] = []
        for session_id in session_ids:
            shown = subprocess.run(
                [
                    "loginctl",
                    "show-session",
                    session_id,
                    "--no-pager",
                    "--property=Name",
                    "--property=Remote",
                    "--property=RemoteHost",
                    "--property=Service",
                    "--property=State",
                    "--property=TTY",
                    "--property=Leader",
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if shown.returncode != 0:
                continue
            props = _properties(shown.stdout)
            service = props.get("Service", "").casefold()
            state = props.get("State", "").casefold()
            if props.get("Remote", "").casefold() != "yes":
                continue
            if service not in {"ssh", "sshd"}:
                continue
            if state not in {"active", "online"}:
                continue
            username = props.get("Name", "").strip()
            if not username:
                continue
            sessions.append(
                LogindSession(
                    session_id=session_id,
                    username=username,
                    remote_host=(props.get("RemoteHost") or None),
                    tty=(props.get("TTY") or None),
                    leader_pid=(props.get("Leader") or None),
                )
            )
        return sessions
