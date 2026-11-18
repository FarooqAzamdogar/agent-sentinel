import json
import time
import unittest

import support  # noqa: F401  (sets up the import path)
from agent_sentinel.leaks import find_secrets, redact, redact_value

# Made-up values with the right shape. None of them is a real credential.
AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5" * 4
SLACK_TOKEN = "xoxb-" + "1234567890-abcdefghij"
API_KEY = "sk-" + "a1B2c3D4" * 5
PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nAAAEbm9uZQ==\n-----END OPENSSH PRIVATE KEY-----"


class FindSecrets(unittest.TestCase):
    def test_each_kind_is_recognised(self):
        self.assertEqual(find_secrets(f"key={AWS_KEY}"), ["AWS access key"])
        self.assertEqual(find_secrets(f"token {GITHUB_TOKEN} here"), ["GitHub token"])
        self.assertEqual(find_secrets(SLACK_TOKEN), ["Slack token"])
        self.assertEqual(find_secrets(API_KEY), ["API key"])
        self.assertEqual(find_secrets(PRIVATE_KEY), ["private key"])

    def test_several_kinds_are_each_reported_once(self):
        self.assertEqual(find_secrets(f"{AWS_KEY} {AWS_KEY} {GITHUB_TOKEN}"), ["AWS access key", "GitHub token"])

    def test_a_token_glued_to_other_text_is_still_found(self):
        glued = {
            "after an underscore": f"token_{GITHUB_TOKEN}",
            "before an underscore": f"{GITHUB_TOKEN}_x",
            "after a written-out newline": f"my token:\\n{GITHUB_TOKEN}",
            "space percent-encoded": f"https://x.example/?q=key%20{AWS_KEY}",
            "equals sign percent-encoded": f"https://x.example/?q=token%3D{GITHUB_TOKEN}",
            "percent-encoded twice": f"q=key%2520{AWS_KEY}",
            "in a JSON string": json.dumps({"note": f"line one\n{GITHUB_TOKEN}"}),
        }
        for name, text in glued.items():
            with self.subTest(case=name):
                self.assertTrue(find_secrets(text))

    def test_ordinary_text_has_no_secrets(self):
        ordinary = [
            "Please summarise the attached report by Friday.",
            "git commit 3f2a9c1e5b7d4e8a9c217d4e5f6a8b90aabbccdd",
            "550e8400-e29b-41d4-a716-446655440000",
            "The public key is in id_rsa.pub; never share the private key.",
            "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg\n-----END PUBLIC KEY-----",
            "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+g\n-----END CERTIFICATE-----",
            "sk-short and ghp_short are too short to be tokens",
            "AKIAlowercaseisnotakey12",
            # Things that only look like a key at a glance:
            "https://shop.example.com/p/sk-hynix-platinum-p41-2tb-nvme-internal-ssd",
            "class='sk-spinner sk-spinner-three-bounce sk-fade-in-quarter-second'",
            "OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "AKIAIOSFODNN7EXAMPLE is the key shown in the AWS documentation",
            'if "-----BEGIN RSA PRIVATE KEY-----" in text: raise ValueError("do not paste keys here")',
            "how do I create a -----BEGIN OPENSSH PRIVATE KEY----- file",
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

    def test_a_private_key_without_an_end_line_is_removed_as_far_as_it_may_reach(self):
        self.assertEqual(redact("-----BEGIN RSA PRIVATE KEY-----\nMIIEvAIBADANBg\nkqhkiG9w0BAQEF"), "[redacted private key]")

    def test_a_very_long_key_block_leaves_no_key_lines_behind(self):
        body = "\n".join("mQINBGR" + "abcdefgh" * 7 for _ in range(320))  # about 20,000 characters
        block = f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n{body}\n-----END PGP PRIVATE KEY BLOCK-----"
        self.assertEqual(redact(block), "[redacted private key]")

    def test_a_key_header_alone_is_removed_from_a_log_although_it_does_not_block_a_call(self):
        mention = "see -----BEGIN RSA PRIVATE KEY----- in the docs"
        self.assertEqual(find_secrets(mention), [])
        self.assertTrue(redact(mention).startswith("see [redacted private key]"))

    def test_text_without_secrets_is_unchanged(self):
        text = 'A normal sentence with "quotes" and a path /home/me/notes.txt'
        self.assertEqual(redact(text), text)


class RedactValue(unittest.TestCase):
    def test_strings_and_keys_are_redacted_at_any_depth_and_the_shape_is_kept(self):
        value = {"a": [1, {"b": GITHUB_TOKEN, GITHUB_TOKEN: None}], "c": ("x", AWS_KEY), "d": 2.5, "e": True}
        self.assertEqual(redact_value(value), {
            "a": [1, {"b": "[redacted GitHub token]", "[redacted GitHub token]": None}],
            "c": ["x", "[redacted AWS access key]"], "d": 2.5, "e": True,
        })

    def test_the_order_of_keys_is_kept(self):
        self.assertEqual(list(redact_value({"z": 1, "a": {"y": 2, "b": 3}, "m": 4})), ["z", "a", "m"])

    def test_the_original_is_not_changed(self):
        value = {"k": [GITHUB_TOKEN]}
        redact_value(value)
        self.assertEqual(value, {"k": [GITHUB_TOKEN]})

    def test_a_token_at_the_start_of_a_line_is_redacted(self):
        # As JSON text this reads "...\nghp_...", and the "n" used to hide the token.
        for separator in ("\n", "\t", "\r"):
            with self.subTest(separator=repr(separator)):
                line = json.dumps(redact_value({"q": f"my token:{separator}{GITHUB_TOKEN}{separator}"}))
                self.assertNotIn(GITHUB_TOKEN, line)

    def test_the_result_always_serialises_to_valid_json(self):
        # A carriage return before "k_live_..." used to become "\rk_live_..." in the
        # JSON text, and replacing "rk_live_..." there left an invalid escape.
        tricky = {"q": "\rk_live_" + "a" * 24, "w": "\\" + GITHUB_TOKEN, 'x"y': PRIVATE_KEY + '"'}
        self.assertEqual(set(json.loads(json.dumps(redact_value(tricky)))), {"q", "w", 'x"y'})

    def test_very_deep_nesting_does_not_overflow(self):
        value = GITHUB_TOKEN
        for _ in range(50_000):
            value = [value]
        redacted = redact_value(value)
        for _ in range(50_000):
            redacted = redacted[0]
        self.assertEqual(redacted, "[redacted GitHub token]")


class HostileInputIsHandledQuickly(unittest.TestCase):
    LIMIT_SECONDS = 5

    def test_repetitive_input_does_not_stall(self):
        cases = {
            "many key headers": "-----BEGIN RSA PRIVATE KEY-----\n" * 30_000,
            "long token-like run": "ghp_" + "a" * 1_000_000,
            "many prefixes": "sk-ant-" * 150_000,
            "many generic prefixes": "sk-" * 300_000,
            "long lowercase run after sk-": "sk-" + "a" * 1_000_000,
            "many percent escapes": "%25" * 300_000,
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
