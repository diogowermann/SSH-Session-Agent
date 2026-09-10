from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .models import AuthObservation, PamSignal, format_utc, normalize_ip

logger = logging.getLogger(__name__)

_ACCEPTED_RE = re.compile(
    r"^Accepted\s+(?P<method>\S+)\s+for\s+(?P<username>\S+)\s+from\s+"
    r"(?P<ip>\S+)\s+port\s+(?P<port>\d+)\s+ssh2(?::|\s|$)"
)
_PAM_OPEN_RE = re.compile(r"^pam_unix\(sshd:session\): session opened for user (?P<username>[^\s(]+)")
_PAM_CLOSE_RE = re.compile(r"^pam_unix\(sshd:session\): session closed for user (?P<username>[^\s(]+)")


@dataclass(frozen=True)
class JournalBatch:
    observations: list[AuthObservation]
    cursor: str | None
    pam_signals: list[PamSignal] = field(default_factory=list)


def _journal_timestamp(raw: object) -> str:
    try:
        micros = int(str(raw))
    except (TypeError, ValueError):
        return format_utc(datetime.now(timezone.utc))
    return format_utc(datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc))


def parse_journal_entry(entry: dict) -> AuthObservation | None:
    message = str(entry.get("MESSAGE") or "")
    match = _ACCEPTED_RE.match(message)
    if match is None:
        return None

    source_ip = normalize_ip(match.group("ip"))
    if source_ip is None:
        return None

    try:
        source_port = int(match.group("port"))
    except ValueError:
        source_port = None
    if source_port is not None and not 1 <= source_port <= 65535:
        source_port = None

    cursor = str(entry.get("__CURSOR") or "").strip()
    if not cursor:
        return None

    # Deliberately discard the remainder of the sshd line. Public-key
    # fingerprint, key type and other authentication detail are not persisted.
    return AuthObservation(
        cursor=cursor,
        pid=(str(entry.get("_PID")) if entry.get("_PID") is not None else None),
        username=match.group("username"),
        source_ip=source_ip,
        source_port=source_port,
        occurred_at=_journal_timestamp(entry.get("__REALTIME_TIMESTAMP")),
        method=match.group("method")[:32],
    )


def parse_pam_signal(entry: dict) -> PamSignal | None:
    message = str(entry.get("MESSAGE") or "")
    kind = None
    match = _PAM_OPEN_RE.match(message)
    if match is not None:
        kind = "OPEN"
    else:
        match = _PAM_CLOSE_RE.match(message)
        if match is not None:
            kind = "CLOSE"
    if match is None or kind is None:
        return None
    cursor = str(entry.get("__CURSOR") or "").strip()
    if not cursor:
        return None
    return PamSignal(
        kind=kind,
        cursor=cursor,
        pid=(str(entry.get("_PID")) if entry.get("_PID") is not None else None),
        username=match.group("username"),
        occurred_at=_journal_timestamp(entry.get("__REALTIME_TIMESTAMP")),
    )


class JournalReader:
    def __init__(self, unit: str, *, initial_lookback_seconds: int = 300):
        self.unit = unit
        self.initial_lookback_seconds = initial_lookback_seconds

    def _command(self, cursor: str | None) -> list[str]:
        command = ["journalctl", "--no-pager", "--output=json", "--unit", self.unit]
        if cursor:
            command.extend(["--after-cursor", cursor])
        else:
            command.append(f"--since=-{self.initial_lookback_seconds}s")
        return command

    def read(self, cursor: str | None) -> JournalBatch:
        result = subprocess.run(
            self._command(cursor), check=False, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )
        if result.returncode != 0 and cursor:
            logger.warning("journal cursor unavailable; falling back to bounded lookback")
            result = subprocess.run(
                self._command(None), check=False, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
            )
        if result.returncode != 0:
            raise RuntimeError("journalctl failed for configured SSH unit")

        observations: list[AuthObservation] = []
        pam_signals: list[PamSignal] = []
        last_cursor = cursor
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            entry_cursor = str(entry.get("__CURSOR") or "").strip()
            if entry_cursor:
                last_cursor = entry_cursor
            observation = parse_journal_entry(entry)
            if observation is not None:
                observations.append(observation)
                continue
            signal = parse_pam_signal(entry)
            if signal is not None:
                pam_signals.append(signal)
        return JournalBatch(observations=observations, cursor=last_cursor, pam_signals=pam_signals)
