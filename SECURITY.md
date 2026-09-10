# Security policy

## Telemetry boundary

SSH-Session-Agent records session metadata only: server identity, SSH session lifecycle, username, source IP/port, boot identifier and timestamps.

It intentionally does **not** collect or persist:

- commands or terminal content;
- passwords, private/public keys, key material or authentication secrets;
- clipboard/screen content;
- shell environment variables;
- command arguments from user processes.

When parsing an OpenSSH `Accepted ...` journal entry, the parser retains only authentication method, username, source IP, source port and timestamp. The remainder of the journal message (including public-key fingerprint/type) is discarded before persistence.

## Credentials

Each server uses its own Remote Session API credential. Production configuration is stored at `/etc/ssh-session-agent/config.json`, owned by root and readable only by the dedicated `ssh-session-agent` group. The service never logs the credential or HTTP Authorization header.

## Network model

The agent opens no listening socket. Telemetry is outbound HTTPS only. `api_base_url` rejects plain HTTP configuration.

## Local privilege model

The service runs as the dedicated unprivileged `ssh-session-agent` account with membership in `systemd-journal` for read-only journal access. systemd hardening restricts filesystem writes to `/var/lib/ssh-session-agent`.
