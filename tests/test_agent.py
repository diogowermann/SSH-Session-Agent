import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from ssh_session_agent.agent import Agent
from ssh_session_agent.config import Settings
from ssh_session_agent.journal import JournalBatch
from ssh_session_agent.logind import LogindSession
from ssh_session_agent.models import AuthObservation, PamSignal, format_utc


class FakeJournal:
    def __init__(self, batches):
        self.batches = list(batches)

    def read(self, cursor):
        if self.batches:
            return self.batches.pop(0)
        return JournalBatch([], cursor)


class FakeLogind:
    def __init__(self, cycles):
        self.cycles = list(cycles)

    def list_ssh_sessions(self):
        return self.cycles.pop(0) if self.cycles else []


class CapturingClient:
    def __init__(self):
        self.posts = []

    def post(self, endpoint, payload):
        self.posts.append((endpoint, payload))


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.settings = Settings(
            api_base_url="https://api.example.test",
            server_id="server-1",
            agent_secret="x" * 24,
            state_dir=Path(self.temp.name),
            poll_seconds=10,
            snapshot_seconds=30,
            auth_match_window_seconds=180,
        )
        self.t0 = datetime(2026, 9, 10, 11, 0, 0, tzinfo=timezone.utc)

    def _auth(self, cursor, username="diogo", ip="192.0.2.20", port=50000, at=None):
        return AuthObservation(
            cursor=cursor,
            pid="100",
            username=username,
            source_ip=ip,
            source_port=port,
            occurred_at=format_utc(at or self.t0),
            method="publickey",
        )

    def _session(self, session_id="42", username="diogo", ip="192.0.2.20"):
        return LogindSession(
            session_id=session_id,
            username=username,
            remote_host=ip,
            tty="pts/2",
            leader_pid="100",
        )

    @patch("ssh_session_agent.agent.host_metadata", return_value=("linux-1", "linux-1.example", "Debian GNU/Linux 12"))
    @patch("ssh_session_agent.agent.read_boot_id", return_value="boot-a")
    def test_bootstrap_snapshot_does_not_invent_logon(self, boot_mock, host_mock):
        client = CapturingClient()
        agent = Agent(
            self.settings,
            journal_reader=FakeJournal([JournalBatch([self._auth("c1")], "c1")]),
            logind_collector=FakeLogind([[self._session()]]),
            client=client,
        )
        with patch("ssh_session_agent.agent.utc_now", return_value=self.t0):
            result = agent.run_cycle()

        self.assertTrue(result["bootstrap"])
        self.assertEqual(result["events_queued"], 0)
        self.assertEqual([endpoint for endpoint, _ in client.posts], ["/api/v2/agent/snapshot"])
        snapshot = client.posts[0][1]
        self.assertEqual(snapshot["sessions"][0]["source_port"], 50000)

    @patch("ssh_session_agent.agent.host_metadata", return_value=("linux-1", "linux-1.example", "Debian GNU/Linux 12"))
    @patch("ssh_session_agent.agent.read_boot_id", return_value="boot-a")
    def test_new_session_emits_one_logon_then_no_duplicate(self, boot_mock, host_mock):
        client = CapturingClient()
        journal = FakeJournal([
            JournalBatch([], "base"),
            JournalBatch([self._auth("c2", at=self.t0 + timedelta(seconds=10))], "c2"),
            JournalBatch([], "c2"),
        ])
        logind = FakeLogind([
            [],
            [self._session()],
            [self._session()],
        ])
        agent = Agent(self.settings, journal_reader=journal, logind_collector=logind, client=client)

        with patch("ssh_session_agent.agent.utc_now", side_effect=[self.t0, self.t0 + timedelta(seconds=10), self.t0 + timedelta(seconds=20)]):
            agent.run_cycle()
            second = agent.run_cycle()
            third = agent.run_cycle()

        self.assertEqual(second["events_queued"], 1)
        self.assertEqual(third["events_queued"], 0)
        event_posts = [payload for endpoint, payload in client.posts if endpoint.endswith("/events")]
        self.assertEqual(len(event_posts), 1)
        event = event_posts[0]["events"][0]
        self.assertEqual(event["type"], "LOGON")
        self.assertEqual(event["provider_session_id"], "logind:42")
        self.assertEqual(event["provider_event_id"], "logind:42:logon")
        self.assertEqual(event["source_ip"], "192.0.2.20")
        self.assertEqual(event["source_port"], 50000)

    @patch("ssh_session_agent.agent.host_metadata", return_value=("linux-1", None, "Debian"))
    @patch("ssh_session_agent.agent.read_boot_id", return_value="boot-a")
    def test_accepted_ip_fills_missing_logind_remote_host_by_pid(self, boot_mock, host_mock):
        client = CapturingClient()
        no_host = LogindSession(
            session_id="42", username="diogo", remote_host=None, tty="pts/2", leader_pid="100"
        )
        agent = Agent(
            self.settings,
            journal_reader=FakeJournal([
                JournalBatch([], "base"),
                JournalBatch([self._auth("accepted", at=self.t0 + timedelta(seconds=5))], "accepted"),
            ]),
            logind_collector=FakeLogind([[], [no_host]]),
            client=client,
        )
        with patch("ssh_session_agent.agent.utc_now", side_effect=[
            self.t0, self.t0 + timedelta(seconds=10)
        ]):
            agent.run_cycle()
            agent.run_cycle()

        event_posts = [payload for endpoint, payload in client.posts if endpoint.endswith("/events")]
        event = event_posts[0]["events"][0]
        self.assertEqual(event["source_ip"], "192.0.2.20")
        self.assertEqual(event["source_port"], 50000)

    @patch("ssh_session_agent.agent.host_metadata", return_value=("linux-1", None, "Ubuntu"))
    @patch("ssh_session_agent.agent.read_boot_id", return_value="boot-a")
    def test_removed_session_emits_one_logoff(self, boot_mock, host_mock):
        client = CapturingClient()
        journal = FakeJournal([
            JournalBatch([], "base"),
            JournalBatch([self._auth("c2", at=self.t0 + timedelta(seconds=10))], "c2"),
            JournalBatch([], "c2"),
        ])
        logind = FakeLogind([[], [self._session()], []])
        agent = Agent(self.settings, journal_reader=journal, logind_collector=logind, client=client)
        with patch("ssh_session_agent.agent.utc_now", side_effect=[self.t0, self.t0 + timedelta(seconds=10), self.t0 + timedelta(seconds=20)]):
            agent.run_cycle()
            agent.run_cycle()
            result = agent.run_cycle()
        self.assertEqual(result["events_queued"], 1)
        events = [payload["events"][0] for endpoint, payload in client.posts if endpoint.endswith("/events")]
        self.assertEqual([event["type"] for event in events], ["LOGON", "LOGOFF"])
        self.assertEqual(events[1]["provider_event_id"], "logind:42:logoff")

    @patch("ssh_session_agent.agent.host_metadata", return_value=("linux-1", None, "Debian"))
    @patch("ssh_session_agent.agent.read_boot_id", side_effect=["boot-a", "boot-b"])
    def test_reboot_uses_snapshot_without_stale_logoff(self, boot_mock, host_mock):
        client = CapturingClient()
        journal = FakeJournal([
            JournalBatch([self._auth("c1")], "c1"),
            JournalBatch([], "c2"),
        ])
        logind = FakeLogind([[self._session()], []])
        agent = Agent(self.settings, journal_reader=journal, logind_collector=logind, client=client)
        with patch("ssh_session_agent.agent.utc_now", side_effect=[self.t0, self.t0 + timedelta(minutes=1)]):
            agent.run_cycle()
            second = agent.run_cycle()
        self.assertTrue(second["boot_changed"])
        self.assertEqual(second["events_queued"], 0)
        self.assertEqual(len([1 for endpoint, _ in client.posts if endpoint.endswith("/events")]), 0)
        self.assertEqual(len([1 for endpoint, _ in client.posts if endpoint.endswith("/snapshot")]), 2)

    @patch("ssh_session_agent.agent.host_metadata", return_value=("linux-1", None, "Debian"))
    @patch("ssh_session_agent.agent.read_boot_id", return_value="boot-a")
    def test_closed_pam_evidence_visible_in_logind_does_not_duplicate_lifecycle(self, boot_mock, host_mock):
        auth = self._auth("accepted", at=self.t0 + timedelta(seconds=5))
        opened = PamSignal(
            kind="OPEN", cursor="opened", pid="100", username="diogo",
            occurred_at=format_utc(self.t0 + timedelta(seconds=6)),
        )
        closed = PamSignal(
            kind="CLOSE", cursor="closed", pid="100", username="diogo",
            occurred_at=format_utc(self.t0 + timedelta(seconds=8)),
        )
        client = CapturingClient()
        agent = Agent(
            self.settings,
            journal_reader=FakeJournal([
                JournalBatch([], "base"),
                JournalBatch([auth], "closed", pam_signals=[opened, closed]),
                JournalBatch([], "closed"),
            ]),
            logind_collector=FakeLogind([[], [self._session()], []]),
            client=client,
        )
        with patch("ssh_session_agent.agent.utc_now", side_effect=[
            self.t0,
            self.t0 + timedelta(seconds=10),
            self.t0 + timedelta(seconds=20),
        ]):
            agent.run_cycle()
            second = agent.run_cycle()
            third = agent.run_cycle()

        self.assertEqual(second["events_queued"], 1)
        self.assertEqual(third["events_queued"], 1)
        event_posts = [payload for endpoint, payload in client.posts if endpoint.endswith("/events")]
        events = [event for payload in event_posts for event in payload["events"]]
        self.assertEqual([event["type"] for event in events], ["LOGON", "LOGOFF"])
        self.assertEqual({event["provider_session_id"] for event in events}, {"logind:42"})
        self.assertEqual(events[0]["occurred_at"], format_utc(self.t0 + timedelta(seconds=6)))
        self.assertEqual(events[1]["occurred_at"], format_utc(self.t0 + timedelta(seconds=8)))
        self.assertEqual(events[0]["source_port"], 50000)

    @patch("ssh_session_agent.agent.host_metadata", return_value=("linux-1", None, "Debian"))
    @patch("ssh_session_agent.agent.read_boot_id", return_value="boot-a")
    def test_open_pam_plus_logind_emits_only_one_logon(self, boot_mock, host_mock):
        auth = self._auth("accepted", at=self.t0 + timedelta(seconds=5))
        opened = PamSignal(
            kind="OPEN", cursor="opened", pid="100", username="diogo",
            occurred_at=format_utc(self.t0 + timedelta(seconds=6)),
        )
        client = CapturingClient()
        agent = Agent(
            self.settings,
            journal_reader=FakeJournal([
                JournalBatch([], "base"),
                JournalBatch([auth], "opened", pam_signals=[opened]),
            ]),
            logind_collector=FakeLogind([[], [self._session()]]),
            client=client,
        )
        with patch("ssh_session_agent.agent.utc_now", side_effect=[
            self.t0, self.t0 + timedelta(seconds=10)
        ]):
            agent.run_cycle()
            second = agent.run_cycle()

        self.assertEqual(second["events_queued"], 1)
        event_posts = [payload for endpoint, payload in client.posts if endpoint.endswith("/events")]
        events = [event for payload in event_posts for event in payload["events"]]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "LOGON")
        self.assertEqual(events[0]["provider_session_id"], "logind:42")
        self.assertEqual(events[0]["occurred_at"], format_utc(self.t0 + timedelta(seconds=6)))

    @patch("ssh_session_agent.agent.host_metadata", return_value=("linux-1", None, "Debian"))
    @patch("ssh_session_agent.agent.read_boot_id", return_value="boot-a")
    def test_multiple_same_user_sessions_get_independent_ports(self, boot_mock, host_mock):
        client = CapturingClient()
        auth1 = self._auth("c1", port=50001, at=self.t0 + timedelta(seconds=5))
        auth2 = self._auth("c2", port=50002, at=self.t0 + timedelta(seconds=6))
        sessions = [self._session("42"), self._session("43")]
        agent = Agent(
            self.settings,
            journal_reader=FakeJournal([JournalBatch([], "base"), JournalBatch([auth1, auth2], "c2")]),
            logind_collector=FakeLogind([[], sessions]),
            client=client,
        )
        with patch("ssh_session_agent.agent.utc_now", side_effect=[self.t0, self.t0 + timedelta(seconds=10)]):
            agent.run_cycle()
            agent.run_cycle()
        event_posts = [payload for endpoint, payload in client.posts if endpoint.endswith("/events")]
        events = event_posts[0]["events"]
        self.assertEqual(len(events), 2)
        self.assertEqual({event["source_port"] for event in events}, {50001, 50002})
        self.assertEqual({event["provider_session_id"] for event in events}, {"logind:42", "logind:43"})

class EphemeralSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.settings = Settings(
            api_base_url="https://api.example.test",
            server_id="server-1",
            agent_secret="x" * 24,
            state_dir=Path(self.temp.name),
            poll_seconds=10,
            snapshot_seconds=30,
            auth_match_window_seconds=180,
        )
        self.t0 = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

    @patch("ssh_session_agent.agent.host_metadata", return_value=("linux-1", None, "Debian"))
    @patch("ssh_session_agent.agent.read_boot_id", return_value="boot-a")
    def test_short_session_between_polls_is_recovered_once(self, boot_mock, host_mock):
        auth = AuthObservation(
            cursor="accepted",
            pid="555",
            username="automation",
            source_ip="192.0.2.55",
            source_port=44001,
            occurred_at=format_utc(self.t0 + timedelta(seconds=5)),
            method="publickey",
        )
        opened = PamSignal(
            kind="OPEN", cursor="opened", pid="555", username="automation",
            occurred_at=format_utc(self.t0 + timedelta(seconds=6)),
        )
        closed = PamSignal(
            kind="CLOSE", cursor="closed", pid="555", username="automation",
            occurred_at=format_utc(self.t0 + timedelta(seconds=8)),
        )
        client = CapturingClient()
        agent = Agent(
            self.settings,
            journal_reader=FakeJournal([
                JournalBatch([], "base"),
                JournalBatch([auth], "closed", pam_signals=[opened, closed]),
                JournalBatch([], "closed"),
            ]),
            logind_collector=FakeLogind([[], [], []]),
            client=client,
        )
        with patch("ssh_session_agent.agent.utc_now", side_effect=[
            self.t0,
            self.t0 + timedelta(seconds=10),
            self.t0 + timedelta(seconds=20),
        ]):
            agent.run_cycle()
            second = agent.run_cycle()
            third = agent.run_cycle()

        self.assertEqual(second["events_queued"], 2)
        self.assertEqual(third["events_queued"], 0)
        event_posts = [payload for endpoint, payload in client.posts if endpoint.endswith("/events")]
        self.assertEqual(len(event_posts), 1)
        events = event_posts[0]["events"]
        self.assertEqual([event["type"] for event in events], ["LOGON", "LOGOFF"])
        self.assertEqual(events[0]["provider_session_id"], events[1]["provider_session_id"])
        self.assertTrue(events[0]["provider_session_id"].startswith("sshd:555:"))
        self.assertEqual(events[0]["source_port"], 44001)
