import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from ssh_auth_log_summary import main, matching_addresses, summarize


class MatchingTests(unittest.TestCase):
    def test_matches_and_nonmatches(self):
        lines = [
            "sshd[1]: Failed password for alice from 198.51.100.23 port 22 ssh2",
            "sshd[2]: Failed password for invalid user guest from 198.51.100.23 port 2222 ssh2",
            "sshd[3]: Accepted password for alice from 203.0.113.8 port 22 ssh2",
            "kernel: Failed password for alice from 192.0.2.4 port 22 ssh2",
            "sshd[4]: Failed publickey for alice from 192.0.2.4 port 22 ssh2",
            "sshd[5]: Failed password for alice from not-an-ip port 22 ssh2",
        ]
        self.assertEqual(matching_addresses(lines), {"198.51.100.23": 2})

    def test_ipv4_and_ipv6_are_normalized_and_counted(self):
        lines = [
            "sshd: Failed password for a from 203.0.113.10 port 22 ssh2",
            "sshd: Failed password for b from 2001:db8::7 port 22 ssh2",
        ]
        self.assertEqual(matching_addresses(lines), {"203.0.113.10": 1, "2001:db8::7": 1})

    def test_threshold_and_order_are_count_descending_then_ip_ascending(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text(
                "sshd: Failed password for a from 198.51.100.2 port 22 ssh2\n"
                "sshd: Failed password for a from 198.51.100.10 port 22 ssh2\n"
                "sshd: Failed password for a from 198.51.100.10 port 22 ssh2\n"
                "sshd: Failed password for a from 2001:db8::1 port 22 ssh2\n"
                "sshd: Failed password for a from 2001:db8::1 port 22 ssh2\n",
                encoding="utf-8",
            )
            self.assertEqual(
                summarize(path, threshold=2),
                [("198.51.100.10", 2), ("2001:db8::1", 2)],
            )
            self.assertEqual(summarize(path, threshold=2, limit=1), [("198.51.100.10", 2)])
            self.assertEqual(summarize(path, threshold=3), [])


class CliTests(unittest.TestCase):
    def test_invalid_threshold_is_cli_error(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            main(["missing.log", "--threshold", "0"])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("--threshold must be at least 1", stderr.getvalue())

    def test_missing_file_is_cli_error(self):
        with tempfile.TemporaryDirectory() as directory:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
                main([str(Path(directory) / "does-not-exist.log")])
            self.assertEqual(caught.exception.code, 2)
            self.assertIn("cannot read", stderr.getvalue())

    def test_invalid_limit_is_cli_error(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            main(["some.log", "--limit", "-1"])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("--limit must be at least 1", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
