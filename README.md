# SSH-Session-Agent

Linux SSH session telemetry agent for the Remote Session API v2.

Phase 7 of Launer's Remote Session Monitoring expansion adds SSH visibility without changing the existing Windows/RDP ingestion path. The agent is deliberately low-intrusion: it reads OpenSSH journald metadata and `systemd-logind`, keeps a durable local checkpoint/spool, and sends outbound HTTPS only.

## MVP support

- Debian / Ubuntu
- systemd + journald
- systemd-logind
- OpenSSH server
- Python 3.10+
- Remote Session API `/api/v2`

Other distributions require explicit homologation.

## What is collected

- `LOGON` / `LOGOFF`
- username
- source IPv4/IPv6 when available
- source TCP port when OpenSSH provides it
- kernel `boot_id`
- opaque `provider_session_id` from logind
- timestamps
- hostname/FQDN/OS metadata in snapshots

No commands, passwords, key material, terminal content or clipboard data are collected. See [SECURITY.md](SECURITY.md).

## Lifecycle model

`systemd-logind` is the primary authority for persistent SSH sessions. OpenSSH `Accepted ...` and PAM open/close records enrich those sessions; they are not emitted independently when the same connection is visible in logind. This prevents `Accepted ...` and PAM session-open messages from producing duplicate LOGONs. A bounded `Accepted + PAM open + PAM close` pair is used only to recover a short SSH session that opened and closed entirely between logind polls.

The first agent start sends existing sessions by snapshot only. It does not invent historical LOGONs.

## API contract

Events are sent to `POST /api/v2/agent/events`:

```json
{
  "contract_version": 2,
  "agent_version": "0.1.0",
  "platform": "linux",
  "protocol": "SSH",
  "boot_id": "kernel-boot-id",
  "agent_time_utc": "2026-09-10T11:00:05Z",
  "events": [
    {
      "type": "LOGON",
      "provider_session_id": "logind:42",
      "provider_event_id": "logind:42:logon",
      "username": "example.user",
      "domain": null,
      "source_ip": "192.0.2.20",
      "source_port": 53122,
      "occurred_at": "2026-09-10T11:00:00Z"
    }
  ]
}
```

Snapshots are sent to `POST /api/v2/agent/snapshot` and are used for reconciliation, not as the primary lifecycle source.

Authentication uses the existing per-server model:

- `X-Server-ID: <server UUID>`
- `Authorization: Bearer <per-server secret>`

## Local durability

State: `/var/lib/ssh-session-agent/state.json`

Spool: `/var/lib/ssh-session-agent/spool/`

Production config: `/etc/ssh-session-agent/config.json`

Outbound payloads are atomically spooled before the local session checkpoint advances. API failure therefore does not lose telemetry.

## Installation

Clone the repository to `/opt/SSH-Session-Agent`, create a production config from `config.example.json`, then run:

```bash
sudo bash scripts/install.sh \
  --app-dir /opt/SSH-Session-Agent \
  --config-source /root/ssh-session-agent-config.json
```

The installer deliberately does not start the service by default. After reviewing preflight output:

```bash
sudo systemctl start ssh-session-agent.service
sudo systemctl status ssh-session-agent.service --no-pager
```

To install and start in one controlled step, add `--start`.

See [docs/installation.md](docs/installation.md), [docs/runbook.md](docs/runbook.md) and [docs/phase7-mvp.md](docs/phase7-mvp.md).

## Preflight

```bash
sudo env PYTHONPATH=/opt/SSH-Session-Agent/src python3 -m ssh_session_agent \
  --config /etc/ssh-session-agent/config.json preflight
```

Preflight performs no telemetry write.

## Upgrade

Update the checked-out release/commit first, then:

```bash
sudo bash scripts/update.sh
```

The production config and spool are preserved.

## Uninstall / rollback

```bash
sudo bash scripts/uninstall.sh
```

By default this removes only the systemd unit and preserves config/state/spool for rollback or investigation. Destructive removal requires explicit `--purge-state` and/or `--purge-config`.

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```
