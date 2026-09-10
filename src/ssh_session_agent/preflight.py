from __future__ import annotations

import os
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .config import Settings
from .platform import read_boot_id


@dataclass(frozen=True)
class PreflightResult:
    name: str
    ok: bool
    detail: str


def detect_ssh_unit(explicit: str | None = None) -> str:
    candidates = [explicit] if explicit else ["ssh.service", "sshd.service"]
    for unit in candidates:
        if not unit:
            continue
        result = subprocess.run(
            ["systemctl", "show", unit, "--property=LoadState", "--value"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode == 0 and result.stdout.strip() == "loaded":
            return unit
    raise RuntimeError("no supported OpenSSH systemd unit found (ssh.service/sshd.service)")


def _os_release() -> tuple[bool, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    except OSError as exc:
        return False, f"cannot read /etc/os-release: {exc}"

    os_id = values.get("ID", "").casefold()
    id_like = {item.casefold() for item in values.get("ID_LIKE", "").split()}
    supported = os_id in {"debian", "ubuntu"} or bool(id_like & {"debian", "ubuntu"})
    detail = values.get("PRETTY_NAME") or values.get("NAME") or os_id or "unknown"
    return supported, detail


def _systemd_active(unit: str) -> bool:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", unit],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def _api_health(settings: Settings) -> tuple[bool, str]:
    url = f"{settings.api_base_url}/api/v2/health"
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "ssh-session-agent-preflight"},
    )
    try:
        context = ssl.create_default_context(cafile=settings.ca_file or None)
        with urllib.request.urlopen(
            request,
            timeout=settings.request_timeout_seconds,
            context=context,
        ) as response:
            status = int(getattr(response, "status", 0))
            response.read(1024)
        return (200 <= status < 300), f"HTTPS health returned {status}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTPS health returned {exc.code}"
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
        return False, f"HTTPS health unavailable: {type(exc).__name__}"


def run_preflight(settings: Settings) -> list[PreflightResult]:
    results: list[PreflightResult] = []
    results.append(
        PreflightResult(
            "python",
            sys.version_info >= (3, 10),
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        )
    )

    os_ok, os_detail = _os_release()
    results.append(PreflightResult("os", os_ok, os_detail))

    for command in ("systemctl", "journalctl", "loginctl"):
        found = shutil.which(command)
        results.append(PreflightResult(command, found is not None, found or "not found"))

    logind_active = _systemd_active("systemd-logind.service")
    results.append(
        PreflightResult(
            "systemd_logind",
            logind_active,
            "active" if logind_active else "not active",
        )
    )

    try:
        unit = detect_ssh_unit(settings.journal_unit)
        results.append(PreflightResult("ssh_unit", True, unit))
        ssh_active = _systemd_active(unit)
        results.append(PreflightResult("ssh_active", ssh_active, "active" if ssh_active else "not active"))
    except Exception as exc:
        unit = settings.journal_unit or "ssh.service"
        results.append(PreflightResult("ssh_unit", False, str(exc)))
        results.append(PreflightResult("ssh_active", False, "OpenSSH unit unresolved"))

    try:
        boot_id = read_boot_id()
        results.append(PreflightResult("boot_id", True, boot_id))
    except Exception as exc:
        results.append(PreflightResult("boot_id", False, str(exc)))

    if shutil.which("journalctl"):
        probe = subprocess.run(
            ["journalctl", "--no-pager", "--output=json", "--unit", unit, "--lines=1"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        results.append(
            PreflightResult(
                "journal_access",
                probe.returncode == 0,
                "readable" if probe.returncode == 0 else "journal is not readable by service account",
            )
        )

    state_target = settings.state_dir if settings.state_dir.exists() else settings.state_dir.parent
    state_ok = state_target.exists() and os.access(state_target, os.W_OK | os.X_OK)
    results.append(
        PreflightResult(
            "state_dir",
            state_ok,
            f"{state_target} {'writable' if state_ok else 'not writable'}",
        )
    )

    if settings.ca_file:
        ca_path = Path(settings.ca_file)
        ca_ok = ca_path.is_file() and os.access(ca_path, os.R_OK)
        results.append(
            PreflightResult(
                "ca_file",
                ca_ok,
                "readable" if ca_ok else "configured CA file is not readable by service account",
            )
        )

    api_ok, api_detail = _api_health(settings)
    results.append(PreflightResult("api_health", api_ok, api_detail))
    return results
