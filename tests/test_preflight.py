import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ssh_session_agent.config import Settings
from ssh_session_agent.preflight import _api_health


class FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, limit=-1):
        return b'{"status":"ok"}'


class PreflightTests(unittest.TestCase):
    def settings(self, *, ca_file=None):
        return Settings(
            api_base_url="https://rdp-api.example.test",
            server_id="server-1",
            agent_secret="x" * 24,
            state_dir=Path("/tmp/ssh-agent-test"),
            ca_file=ca_file,
        )

    @patch("ssh_session_agent.preflight.ssl.create_default_context")
    @patch("ssh_session_agent.preflight.urllib.request.urlopen", return_value=FakeResponse())
    def test_health_probe_sends_no_agent_credential(self, urlopen_mock, context_mock):
        ok, detail = _api_health(self.settings())
        self.assertTrue(ok)
        self.assertEqual(detail, "HTTPS health returned 200")
        request = urlopen_mock.call_args.args[0]
        headers = {key.casefold(): value for key, value in request.header_items()}
        self.assertNotIn("authorization", headers)
        self.assertNotIn("x-server-id", headers)
        self.assertEqual(request.full_url, "https://rdp-api.example.test/api/v2/health")

    @patch("ssh_session_agent.preflight.ssl.create_default_context", side_effect=FileNotFoundError("missing CA"))
    def test_invalid_ca_is_reported_not_raised(self, context_mock):
        ok, detail = _api_health(self.settings(ca_file="/missing/ca.pem"))
        self.assertFalse(ok)
        self.assertIn("FileNotFoundError", detail)


if __name__ == "__main__":
    unittest.main()
