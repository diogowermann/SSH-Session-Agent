# Operational runbook

This runbook covers routine operation, incident containment, upgrade and recovery of SSH Session Agent on supported Debian/Ubuntu hosts.

## Runtime inventory

| Item | Value |
|---|---|
| Unit | `ssh-session-agent.service` |
| Application checkout | `/opt/SSH-Session-Agent` |
| Configuration | `/etc/ssh-session-agent/config.json` |
| State | `/var/lib/ssh-session-agent/state.json` |
| Durable spool | `/var/lib/ssh-session-agent/spool` |
| Service account | `ssh-session-agent` |

The production configuration contains the per-server bearer secret. Never print it in shared logs or copy it into tickets.

## Routine health check

```bash
sudo systemctl is-enabled ssh-session-agent.service
sudo systemctl is-active ssh-session-agent.service
sudo systemctl status ssh-session-agent.service --no-pager --full
sudo journalctl -u ssh-session-agent.service --since '-30 minutes' --no-pager
sudo find /var/lib/ssh-session-agent/spool -maxdepth 1 -type f -printf '%TY-%Tm-%Td %TH:%TM:%TS %s %f\n' | sort
```

Healthy operation means the unit is enabled and active, journald shows successful polling/delivery without a repeating error, spool does not grow continuously, and the API server record has recent `last_seen` and snapshot timestamps.

Run the read-only preflight as the service account:

```bash
sudo env PYTHONPATH=/opt/SSH-Session-Agent/src \
  runuser -u ssh-session-agent -- \
  python3 -m ssh_session_agent \
  --config /etc/ssh-session-agent/config.json preflight
```

Preflight checks platform, journal/logind visibility, configuration and API v2 health without sending telemetry.

## Incident triage

### Unit inactive or restarting

```bash
sudo systemctl status ssh-session-agent.service --no-pager --full
sudo journalctl -u ssh-session-agent.service -n 100 --no-pager
sudo systemctl show ssh-session-agent.service \
  -p ActiveState -p SubState -p Result -p NRestarts
```

Then run preflight. Correct the first failing dependency before restarting the unit.

### Spool growing

Spool contains recoverable telemetry and is written before checkpoint advancement. Do not delete it during ordinary diagnosis. Check:

1. DNS and outbound HTTPS connectivity;
2. system trust or the configured `ca_file`;
3. API v2 health;
4. server ID and per-server secret pairing;
5. reverse-proxy/API logs;
6. disk capacity and ownership below `/var/lib/ssh-session-agent`.

After repair:

```bash
sudo systemctl restart ssh-session-agent.service
sudo journalctl -u ssh-session-agent.service -f
```

Stop following the log with `Ctrl+C` after confirming replay. API ingestion is idempotent.

### API returns 401 or 403

The identity is disabled or the server ID and secret do not match. Never reuse another host's credential. Rotate/register this server identity centrally, install the corrected root-only configuration, run preflight and restart the unit.

### TLS failure

Install the issuing CA into the operating-system trust store or configure a controlled `ca_file` readable by the service account. Never disable certificate validation.

### Journal or logind access failure

```bash
id ssh-session-agent
sudo -u ssh-session-agent journalctl -n 5 --no-pager
loginctl list-sessions --no-legend
systemctl is-active systemd-logind.service
```

The account must retain read-only membership in `systemd-journal`; the service requires `systemd-logind`.

### No source IP or missing short session

Confirm OpenSSH/PAM records are present in journald and that the configured journal filter has not excluded the SSH unit. Source IP depends on available OpenSSH metadata. Do not invent an IP from current DNS, ARP or a later lease.

## Upgrade

1. Record current `VERSION`, unit state and spool count.
2. Switch `/opt/SSH-Session-Agent` to the approved release/commit.
3. Run:

```bash
sudo bash /opt/SSH-Session-Agent/scripts/update.sh
```

4. Confirm the unit is active, inspect recent logs and verify API `last_seen`.

The update procedure preserves production configuration, state and spool.

## Containment and rollback

Immediate containment without deleting evidence:

```bash
sudo systemctl stop ssh-session-agent.service
```

For rollback, switch the application checkout to the last approved release and run its `scripts/update.sh`. If the unit itself must be removed:

```bash
sudo bash /opt/SSH-Session-Agent/scripts/uninstall.sh
```

The default uninstall preserves config, state and spool. Never use `--purge-state` or `--purge-config` unless destruction is explicitly approved.

## Credential rotation

1. Rotate the per-server token centrally.
2. Update `/etc/ssh-session-agent/config.json` through a root-only staging file.
3. Restore `root:ssh-session-agent` ownership and mode `0640`.
4. Run preflight and restart the service.
5. Confirm acknowledgement and a stable/decreasing spool.

## Escalation evidence

Collect hostname, Agent version, unit status/result/restart count, sanitized recent logs, spool count/oldest timestamp/total size, preflight results and relevant HTTP status. Never collect the config, bearer secret or full telemetry payloads.

## Post-recovery gate

- service enabled and active without a restart loop;
- preflight contains no `FAIL`;
- pending spool is stable or decreasing;
- API `last_seen` and snapshot time advance;
- a controlled SSH login/logout appears once with the correct lifecycle;
- no credentials or sensitive telemetry were exposed.
