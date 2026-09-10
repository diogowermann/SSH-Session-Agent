from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any

from . import __version__
from .config import Settings


class TransportError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class ApiClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.ssl_context = ssl.create_default_context(cafile=settings.ca_file or None)

    def post(self, endpoint: str, payload: dict[str, Any]) -> None:
        url = f"{self.settings.api_base_url}{endpoint}"
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"ssh-session-agent/{__version__}",
                "X-Server-ID": self.settings.server_id,
                "Authorization": f"Bearer {self.settings.agent_secret}",
            },
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=self.settings.request_timeout_seconds,
                context=self.ssl_context,
            ) as response:
                status = int(getattr(response, "status", 0))
                if status < 200 or status >= 300:
                    raise TransportError("Remote Session API returned non-success status", status_code=status)
                response.read(1024)
        except urllib.error.HTTPError as exc:
            # Do not include response bodies or request headers in exceptions/logs.
            raise TransportError("Remote Session API rejected the request", status_code=exc.code) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportError("Remote Session API is unavailable") from exc
