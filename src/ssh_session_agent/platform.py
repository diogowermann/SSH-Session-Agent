from __future__ import annotations

import socket
from pathlib import Path


def read_boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    if not value:
        raise RuntimeError("kernel boot_id is unavailable")
    return value


def host_metadata() -> tuple[str, str | None, str | None]:
    hostname = socket.gethostname()
    fqdn = socket.getfqdn() or None
    os_version = None
    try:
        values = {}
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
        os_version = values.get("PRETTY_NAME") or values.get("NAME")
    except OSError:
        pass
    return hostname, fqdn, os_version
