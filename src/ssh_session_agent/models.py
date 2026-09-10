from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_ip(value: str | None) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        address = ip_address(text)
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified:
        return None
    return str(address)


@dataclass
class AuthObservation:
    cursor: str
    pid: str | None
    username: str
    source_ip: str
    source_port: int | None
    occurred_at: str
    method: str
    pam_opened_at: str | None = None
    pam_closed_at: str | None = None
    claimed_by: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AuthObservation":
        return cls(**value)


@dataclass(frozen=True)
class PamSignal:
    kind: str
    cursor: str
    pid: str | None
    username: str
    occurred_at: str


@dataclass
class SessionObservation:
    provider_session_id: str
    username: str
    source_ip: str | None
    source_port: int | None
    logon_at: str | None
    tty: str | None = None
    leader_pid: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SessionObservation":
        return cls(**value)

    def snapshot_dict(self) -> dict[str, Any]:
        return {
            "provider_session_id": self.provider_session_id,
            "username": self.username,
            "domain": None,
            "state": "ACTIVE",
            "logon_at": self.logon_at,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
        }
