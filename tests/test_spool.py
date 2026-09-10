import tempfile
import unittest
from pathlib import Path

from ssh_session_agent.spool import SpoolQueue


class CapturingSender:
    def __init__(self, fail=False):
        self.fail = fail
        self.posts = []

    def post(self, endpoint, payload):
        if self.fail:
            raise RuntimeError("offline")
        self.posts.append((endpoint, payload))


class SpoolTests(unittest.TestCase):
    def test_successful_flush_removes_item(self):
        with tempfile.TemporaryDirectory() as temp:
            spool = SpoolQueue(Path(temp))
            spool.enqueue("/api/v2/agent/events", {"contract_version": 2})
            sender = CapturingSender()
            result = spool.flush(sender)
            self.assertEqual(result["sent"], 1)
            self.assertEqual(result["pending"], 0)
            self.assertIsNone(result["last_error_code"])
            self.assertEqual(len(sender.posts), 1)

    def test_failure_preserves_item(self):
        with tempfile.TemporaryDirectory() as temp:
            spool = SpoolQueue(Path(temp))
            spool.enqueue("/api/v2/agent/events", {"contract_version": 2})
            result = spool.flush(CapturingSender(fail=True))
            self.assertEqual(result["failed"], 1)
            self.assertEqual(result["pending"], 1)
            self.assertEqual(result["last_error_code"], "RuntimeError")

    def test_corrupt_item_moves_to_dead_letter(self):
        with tempfile.TemporaryDirectory() as temp:
            spool = SpoolQueue(Path(temp))
            spool.directory.mkdir(parents=True)
            bad = spool.directory / "000-bad.json"
            bad.write_text("{broken", encoding="utf-8")
            result = spool.flush(CapturingSender())
            self.assertEqual(result["quarantined"], 1)
            self.assertTrue((spool.dead_letter / bad.name).exists())
