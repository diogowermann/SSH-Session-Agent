# Installation and rollback

## 1. Prerequisites

The Phase 7 MVP requires Debian/Ubuntu, Python 3.10+, systemd, journald, systemd-logind and OpenSSH server. A dedicated Remote Session API server identity and secret must exist before production start.

The host needs outbound HTTPS reachability to the Remote Session API. No inbound firewall rule is required. Installation preflight is executed as the dedicated service account and performs a read-only HTTPS check against `/api/v2/health`; it never sends the agent bearer credential.

## 2. Configuration

Copy `config.example.json` to a root-only staging path and set:

- `api_base_url`: HTTPS base URL of the Remote Session API;
- `server_id`: server UUID registered in the API;
- `agent_secret`: dedicated per-server bearer secret;
- `ca_file`: optional CA bundle/path if the internal PKI is not already trusted by the operating system. If used, the file must be readable by the `ssh-session-agent` service account; placing it under `/etc/ssh-session-agent/` is the simplest controlled option.

Do not commit the production config.

## 3. Preflight/install

Recommended production checkout:

```bash
cd /opt/SSH-Session-Agent
sudo bash scripts/install.sh \
  --app-dir /opt/SSH-Session-Agent \
  --config-source /root/ssh-session-agent-config.json
```

The installer creates:

- system user/group `ssh-session-agent`;
- membership in `systemd-journal` for read-only journal access;
- `/etc/ssh-session-agent/config.json` as `root:ssh-session-agent` mode `0640`;
- `/var/lib/ssh-session-agent` as service-owned mode `0700`;
- `/etc/systemd/system/ssh-session-agent.service`.

It enables but does not start the unit unless `--start` is supplied.

## 4. First-start gate

Before start, confirm preflight contains no `FAIL`. Then:

```bash
sudo systemctl start ssh-session-agent.service
sudo systemctl is-active ssh-session-agent.service
sudo journalctl -u ssh-session-agent.service -n 30 --no-pager
```

Do not print `/etc/ssh-session-agent/config.json` in shared logs because it contains the agent secret.

On first start, existing sessions are represented by snapshot only; no historical LOGON is manufactured.

## 5. Upgrade

After switching the checkout to the approved commit:

```bash
sudo bash /opt/SSH-Session-Agent/scripts/update.sh
```

This reruns preflight against the updated checkout and restarts the unit. Config/state/spool remain untouched.

## 6. Rollback

Immediate containment:

```bash
sudo systemctl stop ssh-session-agent.service
```

Full unit removal while preserving evidence/config:

```bash
sudo bash /opt/SSH-Session-Agent/scripts/uninstall.sh
```

Only use purge flags when telemetry/spool/config destruction is explicitly intended.
