import json
import time
import unittest

import support  # noqa: F401  (sets up the import path)
from agent_sentinel.leaks import find_secrets, redact

# Made-up values with the right shape. None of them is a real credential.
AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5" * 4
SLACK_TOKEN = "xoxb-" + "1234567890-abcdefghij"
PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nAAAEbm9uZQ==\n-----END OPENSSH PRIVATE KEY-----"


class FindSecrets(unittest.TestCase):
    def test_each_kind_is_recognised(self):
        self.assertEqual(find_secrets(f"key={AWS_KEY}"), ["AWS access key"])
        self.assertEqual(find_secrets(f"token {GITHUB_TOKEN} here"), ["GitHub token"])
        self.assertEqual(find_secrets(SLACK_TOKEN), ["Slack token"])
        self.assertEqual(find_secrets(PRIVATE_KEY), ["private key"])
        self.assertEqual(find_secrets("-----BEGIN RSA PRIVATE KEY-----"), ["private key"])

    def test_several_kinds_are_each_reported_once(self):
        self.assertEqual(find_secrets(f"{AWS_KEY} {AWS_KEY} {GITHUB_TOKEN}"), ["AWS access key", "GitHub token"])

    def test_ordinary_text_has_no_secrets(self):
        ordinary = [
            "Please summarise the attached report by Friday.",
            "git commit 3f2a9c1e5b7d4e8a9c217d4e5f6a8b90aabbccdd",
            "The public key is in id_rsa.pub; never share the private key.",
            "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg\n-----END PUBLIC KEY-----",
            "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+g\n-----END CERTIFICATE-----",
            "sk-short and ghp_short are too short to be tokens",
            "AKIAlowercaseisnotakey12",
        ]
        for text in ordinary:
            with self.subTest(text=text):
                self.assertEqual(find_secrets(text), [])


class Redact(unittest.TestCase):
    def test_secrets_are_replaced_by_a_marker(self):
        redacted = redact(f"use {AWS_KEY} and {GITHUB_TOKEN}")
        self.assertEqual(redacted, "use [redacted AWS access key] and [redacted GitHub token]")

    def test_a_whole_private_key_is_removed(self):
        redacted = redact(f"before\n{PRIVATE_KEY}\nafter")
        self.assertEqual(redacted, "before\n[redacted private key]\nafter")

    def test_a_private_key_without_an_end_line_loses_its_begin_line(self):
        self.assertEqual(redact("-----BEGIN RSA PRIVATE KEY-----\nMIIE"), "[redacted private key]\nMIIE")

    def test_text_without_secrets_is_unchanged(self):
        text = 'A normal sentence with "quotes" and a path /home/me/notes.txt'
        self.assertEqual(redact(text), text)

    def test_redacting_json_text_keeps_it_valid_json(self):
        record = {"args": {"key": PRIVATE_KEY, "note": "kept", "token": GITHUB_TOKEN}, "half": "-----BEGIN PRIVATE KEY-----"}
        restored = json.loads(redact(json.dumps(record)))
        self.assertEqual(restored["args"]["note"], "kept")
        self.assertEqual(restored["args"]["key"], "[redacted private key]")
        self.assertEqual(restored["args"]["token"], "[redacted GitHub token]")
        self.assertEqual(restored["half"], "[redacted private key]")


class HostileInputIsHandledQuickly(unittest.TestCase):
    LIMIT_SECONDS = 5

    def test_repetitive_input_does_not_stall(self):
        cases = {
            "many key headers": "-----BEGIN RSA PRIVATE KEY-----\n" * 30_000,
            "long token-like run": "ghp_" + "a" * 1_000_000,
            "many prefixes": "sk-ant-" * 150_000,
            "plain text": "a" * 1_000_000,
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                started = time.perf_counter()
                find_secrets(text)
                redact(text)
                self.assertLess(time.perf_counter() - started, self.LIMIT_SECONDS)


if __name__ == "__main__":
    unittest.main()
