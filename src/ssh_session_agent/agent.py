from __future__ import annotations

import hashlib
import logging
import signal
import time
from dataclasses import replace
from datetime import timedelta
from typing import Iterable

from . import __version__
from .config import Settings
from .journal import JournalReader
from .logind import LogindCollector, LogindSession
from .models import AuthObservation, PamSignal, SessionObservation, format_utc, parse_utc, utc_now
from .platform import host_metadata, read_boot_id
from .spool import SpoolQueue
from .state import AgentState, StateStore
from .transport import ApiClient

logger = logging.getLogger("ssh_session_agent")


def _merge_auth(existing: list[AuthObservation], incoming: list[AuthObservation]) -> list[AuthObservation]:
    by_cursor = {item.cursor: item for item in existing}
    for item in incoming:
        if item.cursor not in by_cursor:
            by_cursor[item.cursor] = item
    return sorted(by_cursor.values(), key=lambda item: item.occurred_at)


def _apply_pam_signals(observations: list[AuthObservation], signals: list[PamSignal]) -> None:
    for signal in signals:
        candidates = [
            item for item in observations
            if item.pid == signal.pid and item.username.casefold() == signal.username.casefold()
        ]
        if signal.kind == "OPEN":
            candidates = [item for item in candidates if item.pam_opened_at is None]
        else:
            candidates = [
                item for item in candidates
                if item.pam_opened_at is not None and item.pam_closed_at is None
            ]
        if not candidates:
            continue
        target = max(candidates, key=lambda item: item.occurred_at)
        if signal.kind == "OPEN":
            target.pam_opened_at = signal.occurred_at
        else:
            target.pam_closed_at = signal.occurred_at


def _prune_auth(observations: list[AuthObservation], *, now, window_seconds: int) -> list[AuthObservation]:
    cutoff = now - timedelta(seconds=max(window_seconds * 4, 900))
    return [item for item in observations if parse_utc(item.occurred_at) >= cutoff]


def _session_sort_key(session: LogindSession):
    return (0, int(session.session_id)) if session.session_id.isdigit() else (1, session.session_id)


def _match_auth(
    session: LogindSession,
    observations: list[AuthObservation],
    *,
    now,
    window_seconds: int,
) -> AuthObservation | None:
    source_ip = session.source_ip
    cutoff = now - timedelta(seconds=window_seconds)
    candidates = [
        item
        for item in observations
        if item.claimed_by is None
        and item.username.casefold() == session.username.casefold()
        and cutoff <= parse_utc(item.occurred_at) <= now + timedelta(seconds=5)
    ]
    if not candidates:
        return None

    if session.leader_pid:
        # The sshd child PID is a stronger join than RemoteHost. It also lets
        # Accepted metadata recover the source IP when logind exposes no usable
        # address (or briefly retains the session after PAM close).
        pid_matches = [item for item in candidates if item.pid == session.leader_pid]
        if pid_matches:
            return min(pid_matches, key=lambda item: item.occurred_at)

    if source_ip is None:
        return None

    # Without the strong PID join, require the same source IP and never attach a
    # completed authentication by username/IP alone; it may be a prior short session.
    open_candidates = [
        item for item in candidates
        if item.pam_closed_at is None and item.source_ip == source_ip
    ]
    if not open_candidates:
        return None
    return min(open_candidates, key=lambda item: item.occurred_at)


def _resolve_sessions(
    raw_sessions: Iterable[LogindSession],
    previous: dict[str, SessionObservation],
    auth_observations: list[AuthObservation],
    *,
    now,
    auth_window_seconds: int,
) -> dict[str, SessionObservation]:
    current: dict[str, SessionObservation] = {}

    for raw in sorted(raw_sessions, key=_session_sort_key):
        provider_id = raw.provider_session_id
        old = previous.get(provider_id)
        if old is not None and old.username.casefold() == raw.username.casefold():
            current[provider_id] = replace(
                old,
                source_ip=raw.source_ip or old.source_ip,
                tty=raw.tty or old.tty,
                leader_pid=raw.leader_pid or old.leader_pid,
            )
            continue

        matched = _match_auth(raw, auth_observations, now=now, window_seconds=auth_window_seconds)
        if matched is not None:
            matched.claimed_by = provider_id

        current[provider_id] = SessionObservation(
            provider_session_id=provider_id,
            username=raw.username,
            source_ip=raw.source_ip or (matched.source_ip if matched else None),
            source_port=matched.source_port if matched else None,
            logon_at=(matched.pam_opened_at or matched.occurred_at) if matched else format_utc(now),
            tty=raw.tty,
            leader_pid=raw.leader_pid,
        )

    return current


def _event(event_type: str, session: SessionObservation, *, occurred_at: str) -> dict:
    return {
        "type": event_type,
        "provider_session_id": session.provider_session_id,
        "provider_event_id": f"{session.provider_session_id}:{event_type.lower()}",
        "username": session.username,
        "domain": None,
        "source_ip": session.source_ip,
        "source_port": session.source_port,
        "occurred_at": occurred_at,
    }


def _ephemeral_provider_id(observation: AuthObservation) -> str:
    digest = hashlib.sha256(observation.cursor.encode("utf-8")).hexdigest()[:16]
    pid = observation.pid or "unknown"
    return f"sshd:{pid}:{digest}"


def _completed_ephemeral_events(
    observations: list[AuthObservation], *, bootstrap: bool
) -> list[dict]:
    events: list[dict] = []
    for observation in observations:
        if observation.claimed_by is not None:
            continue
        if observation.pam_opened_at is None or observation.pam_closed_at is None:
            continue
        provider_id = _ephemeral_provider_id(observation)
        if bootstrap:
            observation.claimed_by = f"bootstrap-ignored:{provider_id}"
            continue
        session = SessionObservation(
            provider_session_id=provider_id,
            username=observation.username,
            source_ip=observation.source_ip,
            source_port=observation.source_port,
            logon_at=observation.pam_opened_at,
            leader_pid=observation.pid,
        )
        events.append(_event("LOGON", session, occurred_at=observation.pam_opened_at))
        events.append(_event("LOGOFF", session, occurred_at=observation.pam_closed_at))
        observation.claimed_by = f"closed:{provider_id}"
    return events


def _close_time_for_session(provider_id: str, observations: list[AuthObservation], fallback: str) -> str:
    for observation in observations:
        if observation.claimed_by == provider_id and observation.pam_closed_at:
            observation.claimed_by = f"closed:{provider_id}"
            return observation.pam_closed_at
    return fallback


def _event_envelope(events: list[dict], *, boot_id: str, now) -> dict:
    return {
        "contract_version": 2,
        "agent_version": __version__,
        "platform": "linux",
        "protocol": "SSH",
        "boot_id": boot_id,
        "agent_time_utc": format_utc(now),
        "events": events,
    }


def _snapshot_envelope(sessions: dict[str, SessionObservation], *, boot_id: str, now) -> dict:
    hostname, fqdn, os_version = host_metadata()
    return {
        "contract_version": 2,
        "agent_version": __version__,
        "platform": "linux",
        "protocol": "SSH",
        "boot_id": boot_id,
        "agent_time_utc": format_utc(now),
        "hostname": hostname,
        "fqdn": fqdn,
        "os_version": os_version,
        "sessions": [sessions[key].snapshot_dict() for key in sorted(sessions)],
    }


def _snapshot_due(state: AgentState, *, now, interval_seconds: int) -> bool:
    if state.last_snapshot_at is None:
        return True
    return (now - parse_utc(state.last_snapshot_at)).total_seconds() >= interval_seconds


class Agent:
    def __init__(
        self,
        settings: Settings,
        *,
        journal_reader: JournalReader,
        logind_collector: LogindCollector | None = None,
        state_store: StateStore | None = None,
        spool: SpoolQueue | None = None,
        client: ApiClient | None = None,
    ):
        self.settings = settings
        self.journal = journal_reader
        self.logind = logind_collector or LogindCollector()
        self.state_store = state_store or StateStore(settings.state_dir)
        self.spool = spool or SpoolQueue(settings.state_dir)
        self.client = client or ApiClient(settings)

    def run_cycle(self) -> dict:
        now = utc_now()
        now_text = format_utc(now)
        boot_id = read_boot_id()
        state = self.state_store.load()
        bootstrap = state.boot_id is None
        boot_changed = state.boot_id is not None and state.boot_id != boot_id
        same_boot = state.boot_id == boot_id

        journal_batch = self.journal.read(state.journal_cursor)
        state.journal_cursor = journal_batch.cursor
        if boot_changed:
            # PID/session values can be reused after reboot; never carry authentication
            # evidence across kernel boot boundaries.
            state.auth_observations = []
        state.auth_observations = _merge_auth(state.auth_observations, journal_batch.observations)
        _apply_pam_signals(state.auth_observations, journal_batch.pam_signals)
        state.auth_observations = _prune_auth(
            state.auth_observations,
            now=now,
            window_seconds=self.settings.auth_match_window_seconds,
        )

        previous = state.active_sessions if same_boot else {}
        raw_sessions = self.logind.list_ssh_sessions()
        current = _resolve_sessions(
            raw_sessions,
            previous,
            state.auth_observations,
            now=now,
            auth_window_seconds=self.settings.auth_match_window_seconds,
        )

        events: list[dict] = []
        if not bootstrap:
            for provider_id in sorted(set(current) - set(previous)):
                session = current[provider_id]
                events.append(_event("LOGON", session, occurred_at=session.logon_at or now_text))
            if same_boot:
                for provider_id in sorted(set(previous) - set(current)):
                    session = previous[provider_id]
                    close_at = _close_time_for_session(provider_id, state.auth_observations, now_text)
                    events.append(_event("LOGOFF", session, occurred_at=close_at))

        # Sessions that opened and closed entirely between logind polls are recovered
        # from the Accepted + PAM open/close journal sequence.
        events.extend(_completed_ephemeral_events(state.auth_observations, bootstrap=bootstrap))

        queued_events = 0
        for start in range(0, len(events), self.settings.max_batch_events):
            batch = events[start : start + self.settings.max_batch_events]
            self.spool.enqueue("/api/v2/agent/events", _event_envelope(batch, boot_id=boot_id, now=now))
            queued_events += len(batch)

        force_snapshot = bootstrap or boot_changed
        snapshot_due = force_snapshot or _snapshot_due(
            state, now=now, interval_seconds=self.settings.snapshot_seconds
        )
        if snapshot_due:
            self.spool.enqueue("/api/v2/agent/snapshot", _snapshot_envelope(current, boot_id=boot_id, now=now))
            state.last_snapshot_at = now_text

        state.boot_id = boot_id
        state.active_sessions = current
        self.state_store.save(state)

        delivery = self.spool.flush(self.client, limit=max(100, self.settings.max_batch_events))
        result = {
            "bootstrap": bootstrap,
            "boot_changed": boot_changed,
            "journal_observations": len(journal_batch.observations),
            "pam_signals": len(journal_batch.pam_signals),
            "active_sessions": len(current),
            "events_queued": queued_events,
            "snapshot_queued": bool(snapshot_due),
            "spool": delivery,
        }
        logger.info(
            "cycle bootstrap=%s boot_changed=%s active=%d events=%d snapshot=%s "
            "spool_pending=%d spool_failed=%d spool_error=%s",
            bootstrap,
            boot_changed,
            len(current),
            queued_events,
            snapshot_due,
            delivery["pending"],
            delivery["failed"],
            delivery["last_error_code"] or "none",
        )
        return result


def run_daemon(agent: Agent, *, poll_seconds: int) -> int:
    stop = False

    def request_stop(signum, frame) -> None:
        nonlocal stop
        stop = True
        logger.info("stop requested")

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    while not stop:
        started = time.monotonic()
        try:
            agent.run_cycle()
        except Exception:
            logger.exception("agent cycle failed")
        elapsed = time.monotonic() - started
        deadline = time.monotonic() + max(0.0, poll_seconds - elapsed)
        while not stop and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))
    return 0
