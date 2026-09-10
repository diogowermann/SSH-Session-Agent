import json
import tempfile
import unittest
from pathlib import Path

from ssh_session_agent.config import ConfigurationError, Settings


class ConfigTests(unittest.TestCase):
    def _write(self, payload):
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "config.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        self.addCleanup(directory.cleanup)
        return path

    def test_https_required(self):
        path = self._write({
            "api_base_url": "http://example.test",
            "server_id": "server-1",
            "agent_secret": "x" * 24,
        })
        with self.assertRaises(ConfigurationError):
            Settings.from_file(path)

    def test_valid_config(self):
        path = self._write({
            "api_base_url": "https://example.test/",
            "server_id": "server-1",
            "agent_secret": "x" * 24,
            "poll_seconds": 5,
        })
        settings = Settings.from_file(path)
        self.assertEqual(settings.api_base_url, "https://example.test")
        self.assertEqual(settings.poll_seconds, 5)
