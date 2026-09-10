import unittest

from ssh_session_agent.journal import parse_journal_entry, parse_pam_signal


class JournalParserTests(unittest.TestCase):
    def _entry(self, message, cursor="cursor-1", pid="123"):
        return {
            "MESSAGE": message,
            "__CURSOR": cursor,
            "__REALTIME_TIMESTAMP": "1789041600000000",
            "_PID": pid,
        }

    def test_password_accept(self):
        item = parse_journal_entry(self._entry(
            "Accepted password for diogo from 192.0.2.10 port 55123 ssh2"
        ))
        self.assertIsNotNone(item)
        self.assertEqual(item.method, "password")
        self.assertEqual(item.username, "diogo")
        self.assertEqual(item.source_ip, "192.0.2.10")
        self.assertEqual(item.source_port, 55123)

    def test_publickey_discards_fingerprint_tail(self):
        fingerprint = "SHA256:THIS-MUST-NOT-BE-PERSISTED"
        item = parse_journal_entry(self._entry(
            f"Accepted publickey for diogo from 2001:db8::20 port 41234 ssh2: ED25519 {fingerprint}"
        ))
        self.assertIsNotNone(item)
        self.assertEqual(item.method, "publickey")
        self.assertEqual(item.source_ip, "2001:db8::20")
        self.assertNotIn(fingerprint, repr(item))
        self.assertNotIn("ED25519", repr(item))

    def test_unrelated_pam_line_is_not_lifecycle_event(self):
        item = parse_journal_entry(self._entry(
            "pam_unix(sshd:session): session opened for user diogo(uid=1000) by (uid=0)"
        ))
        self.assertIsNone(item)

    def test_pam_open_and_close_are_metadata_signals(self):
        opened = parse_pam_signal(self._entry(
            "pam_unix(sshd:session): session opened for user diogo(uid=1000) by (uid=0)",
            cursor="open",
        ))
        closed = parse_pam_signal(self._entry(
            "pam_unix(sshd:session): session closed for user diogo",
            cursor="close",
        ))
        self.assertEqual(opened.kind, "OPEN")
        self.assertEqual(opened.username, "diogo")
        self.assertEqual(closed.kind, "CLOSE")
        self.assertEqual(closed.username, "diogo")

    def test_invalid_ip_not_persisted(self):
        item = parse_journal_entry(self._entry(
            "Accepted password for diogo from not-an-ip port 55123 ssh2"
        ))
        self.assertIsNone(item)
