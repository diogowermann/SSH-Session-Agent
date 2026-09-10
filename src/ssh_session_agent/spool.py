from __future__ import annotations

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol


class Sender(Protocol):
    def post(self, endpoint: str, payload: dict[str, Any]) -> None: ...


class SpoolQueue:
    def __init__(self, state_dir: Path):
        self.directory = Path(state_dir) / "spool"
        self.dead_letter = Path(state_dir) / "dead-letter"

    def enqueue(self, endpoint: str, payload: dict[str, Any]) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        name = f"{stamp}-{uuid.uuid4().hex}.json"
        target = self.directory / name
        item = {"version": 1, "endpoint": endpoint, "payload": payload}

        fd, temp_name = tempfile.mkstemp(prefix="spool-", suffix=".tmp", dir=self.directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(item, handle, separators=(",", ":"), sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, target)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
        return target

    def pending(self) -> list[Path]:
        if not self.directory.exists():
            return []
        return sorted(path for path in self.directory.glob("*.json") if path.is_file())

    def flush(self, sender: Sender, *, limit: int = 100) -> dict[str, int | str | None]:
        sent = 0
        failed = 0
        quarantined = 0
        last_error_code: str | None = None
        for path in self.pending()[:limit]:
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
                endpoint = str(item["endpoint"])
                payload = item["payload"]
                if not isinstance(payload, dict):
                    raise ValueError("spool payload must be an object")
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                self.dead_letter.mkdir(parents=True, exist_ok=True)
                os.replace(path, self.dead_letter / path.name)
                quarantined += 1
                continue

            try:
                sender.post(endpoint, payload)
            except Exception as exc:
                failed += 1
                status_code = getattr(exc, "status_code", None)
                last_error_code = (
                    f"http_{status_code}"
                    if isinstance(status_code, int)
                    else type(exc).__name__
                )
                break
            path.unlink()
            sent += 1
        return {
            "sent": sent,
            "failed": failed,
            "quarantined": quarantined,
            "pending": len(self.pending()),
            "last_error_code": last_error_code,
        }
