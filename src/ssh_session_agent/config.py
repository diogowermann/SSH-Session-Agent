from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_CONFIG_PATH = Path("/etc/ssh-session-agent/config.json")


class ConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    api_base_url: str
    server_id: str
    agent_secret: str
    state_dir: Path = Path("/var/lib/ssh-session-agent")
    poll_seconds: int = 10
    snapshot_seconds: int = 30
    request_timeout_seconds: int = 10
    auth_match_window_seconds: int = 180
    max_batch_events: int = 100
    journal_unit: str | None = None
    ca_file: str | None = None

    @classmethod
    def from_file(cls, path: str | Path = DEFAULT_CONFIG_PATH) -> "Settings":
        source = Path(path)
        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ConfigurationError(f"configuration file not found: {source}") from exc
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"invalid JSON configuration: {source}") from exc

        if not isinstance(raw, dict):
            raise ConfigurationError("configuration root must be an object")

        required = ("api_base_url", "server_id", "agent_secret")
        missing = [key for key in required if not str(raw.get(key, "")).strip()]
        if missing:
            raise ConfigurationError(f"missing required configuration: {', '.join(missing)}")

        base_url = str(raw["api_base_url"]).strip().rstrip("/")
        parsed = urlparse(base_url)
        if parsed.scheme.lower() != "https" or not parsed.netloc:
            raise ConfigurationError("api_base_url must be an absolute HTTPS URL")

        server_id = str(raw["server_id"]).strip()
        agent_secret = str(raw["agent_secret"]).strip()
        if len(server_id) > 64:
            raise ConfigurationError("server_id exceeds 64 characters")
        if len(agent_secret) < 16:
            raise ConfigurationError("agent_secret must contain at least 16 characters")

        settings = cls(
            api_base_url=base_url,
            server_id=server_id,
            agent_secret=agent_secret,
            state_dir=Path(raw.get("state_dir", "/var/lib/ssh-session-agent")),
            poll_seconds=int(raw.get("poll_seconds", 10)),
            snapshot_seconds=int(raw.get("snapshot_seconds", 30)),
            request_timeout_seconds=int(raw.get("request_timeout_seconds", 10)),
            auth_match_window_seconds=int(raw.get("auth_match_window_seconds", 180)),
            max_batch_events=int(raw.get("max_batch_events", 100)),
            journal_unit=(str(raw["journal_unit"]).strip() if raw.get("journal_unit") else None),
            ca_file=(str(raw["ca_file"]).strip() if raw.get("ca_file") else None),
        )
        settings._validate_ranges()
        return settings

    def _validate_ranges(self) -> None:
        ranges = {
            "poll_seconds": (self.poll_seconds, 1, 300),
            "snapshot_seconds": (self.snapshot_seconds, 5, 3600),
            "request_timeout_seconds": (self.request_timeout_seconds, 1, 120),
            "auth_match_window_seconds": (self.auth_match_window_seconds, 30, 1800),
            "max_batch_events": (self.max_batch_events, 1, 500),
        }
        for name, (value, minimum, maximum) in ranges.items():
            if value < minimum or value > maximum:
                raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
