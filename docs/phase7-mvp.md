# Phase 7 - SSH-Session-Agent MVP

## Contract

The MVP targets Debian/Ubuntu hosts using systemd, systemd-logind and OpenSSH. It sends Remote Session API `/api/v2` payloads with `platform=linux` and `protocol=SSH`. SSH lifecycle is limited to `LOGON` and `LOGOFF`, matching the existing v2 server contract.

## Authority and deduplication

`systemd-logind` is the primary authority for persistent remote SSH sessions. OpenSSH journald records are **evidence**, not parallel lifecycle events for a connection already visible in logind.

This deliberately avoids duplicate LOGONs from the usual pair:

1. `Accepted publickey/password ... from <ip> port <port>`
2. `pam_unix(sshd:session): session opened ...`

The Accepted record enriches the corresponding newly observed logind session with source port and a more accurate login timestamp. The agent emits at most one LOGON for the new logind session.

A short non-interactive SSH connection may open and close entirely between two logind polls. In that narrow case, a complete `Accepted + PAM open + PAM close` sequence produces one deterministic ephemeral LOGON/LOGOFF pair. Exact sshd leader PID matching takes precedence over username/IP fallback, including the small race where logind still exposes a session after PAM close, preventing duplicate lifecycle emission.

Persistent `provider_session_id` is `logind:<session-id>`; ephemeral provider ids are deterministic `sshd:<pid>:<accepted-cursor-hash>` values. `boot_id` comes from `/proc/sys/kernel/random/boot_id`, so a reused logind numeric id across reboots is not the same API session identity.

## Bootstrap behavior

On first start, currently active SSH sessions are sent only in the v2 snapshot. The agent does not manufacture historical LOGON events for sessions that began before observation.

## Durability

The persistent state contains:

- kernel boot id;
- journald cursor;
- currently observed SSH sessions;
- bounded recent authentication observations;
- last snapshot timestamp.

Events/snapshots are atomically spooled under `/var/lib/ssh-session-agent/spool` **before** the state checkpoint advances. A crash in the small interval between those operations can queue a duplicate, but API v2 idempotency (`boot_id` + `provider_event_id`) makes replay safe. A crash cannot silently advance the checkpoint past telemetry that was never spooled.

If the API is unavailable or rejects authentication, the item remains in the spool. The agent stops flushing at the first failed item so ordering is preserved.

## Reconciliation and reboot

A periodic v2 snapshot is sent every 30 seconds by default. Sessions missing from a later snapshot are closed centrally with reconciliation semantics. When the kernel `boot_id` changes, the first snapshot of the new boot lets the API close sessions from the prior boot with `end_reason=REBOOT`; the Linux agent does not invent stale LOGOFF events after reboot.

## Privacy boundary

The journal parser retains only method, username, source IP, source port and timestamp from Accepted records. Any public-key fingerprint/type or other tail data is discarded. No password, key, command or terminal content is collected.

## Phase 7 canary gate

Before rollout beyond one non-critical Linux host:

1. preflight passes for Python/systemd/journald/logind/OpenSSH;
2. bootstrap snapshot creates no false historical LOGON;
3. public-key login produces one LOGON with correct IP/port and no key material;
4. password login produces one LOGON with no password material;
5. simultaneous SSH sessions remain independent;
6. normal logout produces one LOGOFF;
7. API outage preserves spool and recovery replays without duplicates;
8. reboot closes old sessions as REBOOT;
9. API v1/RDP ingestion remains unaffected;
10. seven days of pilot are required before broader Linux rollout (Phase 9).
