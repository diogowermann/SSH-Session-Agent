from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import AuthObservation, SessionObservation


@dataclass
class AgentState:
    boot_id: str | None = None
    journal_cursor: str | None = None
    active_sessions: dict[str, SessionObservation] = field(default_factory=dict)
    auth_observations: list[AuthObservation] = field(default_factory=list)
    last_snapshot_at: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "boot_id": self.boot_id,
            "journal_cursor": self.journal_cursor,
            "active_sessions": {key: value.as_dict() for key, value in self.active_sessions.items()},
            "auth_observations": [item.as_dict() for item in self.auth_observations],
            "last_snapshot_at": self.last_snapshot_at,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AgentState":
        sessions = {
            key: SessionObservation.from_dict(value)
            for key, value in dict(raw.get("active_sessions") or {}).items()
        }
        auth = [AuthObservation.from_dict(item) for item in list(raw.get("auth_observations") or [])]
        return cls(
            boot_id=raw.get("boot_id"),
            journal_cursor=raw.get("journal_cursor"),
            active_sessions=sessions,
            auth_observations=auth,
            last_snapshot_at=raw.get("last_snapshot_at"),
        )


class StateStore:
    def __init__(self, state_dir: Path):
        self.state_dir = Path(state_dir)
        self.path = self.state_dir / "state.json"

    def load(self) -> AgentState:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return AgentState()
        if not isinstance(raw, dict):
            raise ValueError("state file root must be an object")
        return AgentState.from_dict(raw)

    def save(self, state: AgentState) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix="state-", suffix=".json", dir=self.state_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state.as_dict(), handle, separators=(",", ":"), sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, self.path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
