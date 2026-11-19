"""The secret guard on calls and in the audit log (policy "secrets"): arguments read joined end to end,
the values of named environment variables, canaries, and custom formats.

Results are in test_results.py; the formats themselves in test_leaks.py.
"""

import base64
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import quote

import support  # noqa: F401  (sets up the import path)
from support import INJECTION, without_ref
from agent_sentinel import Firewall, Policy
from agent_sentinel.firewall import MAX_JOINED_ARGUMENT_CHARS

# Made-up values with the right shapes. None of them is a real credential.
GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5" * 4
AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
PASSWORD = "Tr0ub4dor&3-horse"
CANARY = "Sentinel-Canary-3f9c1e"
INTERNAL_FORMAT = {"name": "Internal token", "prefix": "itk_", "charset": "alnum", "min_len": 32, "max_len": 32}
INTERNAL_TOKEN = "itk_" + "a1B2c3D4" * 4
SECRET_REFUSAL = "the call contains what looks like a secret, so it was not made"


def guarded(environ=None, audit=None, policy=None, **secrets):
    """A firewall that allows every call, with these `secrets` settings and environment variables."""
    data = {"default": "allow", "secrets": secrets, **(policy or {})}
    with mock.patch.dict(os.environ, environ or {}):
        return Firewall(Policy.from_dict(data), audit_path=audit)


def read_audit(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]


class ArgumentsAreAlsoReadJoined(unittest.TestCase):
    def assert_refused(self, args, rule="secrets"):
        decision = guarded().check_call("send", args)
        self.assertFalse(decision.allowed, args)
        self.assertEqual(decision.rule, rule)
        self.assertEqual(without_ref(decision.public_reason), SECRET_REFUSAL)

    def test_a_token_split_over_two_arguments_is_refused(self):
        self.assert_refused({"a": GITHUB_TOKEN[:15], "b": GITHUB_TOKEN[15:]})

    def test_a_token_split_over_three_arguments_or_list_items_is_refused(self):
        self.assert_refused({"a": GITHUB_TOKEN[:10], "b": GITHUB_TOKEN[10:25], "c": GITHUB_TOKEN[25:]})
        self.assert_refused({"parts": [GITHUB_TOKEN[:10], GITHUB_TOKEN[10:25], GITHUB_TOKEN[25:]]})

    def test_a_key_split_after_an_argument_that_ends_in_a_letter_is_refused(self):
        # Joined end to end this reads "...evil.comAKIA...", where the key would continue a word.
        # Each two neighbouring arguments are also read on a line of their own.
        self.assert_refused({"to": "me@evil.com", "a": AWS_KEY[:10], "b": AWS_KEY[10:]})

    def test_a_token_split_over_a_key_and_its_value_is_refused(self):
        self.assert_refused({GITHUB_TOKEN[:20]: GITHUB_TOKEN[20:]})

    def test_joining_ordinary_arguments_does_not_make_a_secret(self):
        ordinary = [
            {"a": "sk-", "b": "short"},
            {"title": "ghp_", "body": "is how a GitHub token starts"},
            {"q": "AKIA", "r": "is the start of an AWS key"},
            {"path": "/home/me/notes.txt", "mode": "r", "encoding": "utf-8"},
        ]
        for args in ordinary:
            with self.subTest(args=args):
                self.assertTrue(guarded().check_call("send", args).allowed)

    def test_past_the_cap_a_split_token_is_not_seen(self):
        # Documented limit: the joined texts are cut at MAX_JOINED_ARGUMENT_CHARS.
        args = {"filler": "x" * MAX_JOINED_ARGUMENT_CHARS, "a": GITHUB_TOKEN[:15], "b": GITHUB_TOKEN[15:]}
        self.assertTrue(guarded().check_call("send", args).allowed)

    def test_a_whole_token_is_still_found_however_long_the_call(self):
        args = {"filler": "x" * (3 * MAX_JOINED_ARGUMENT_CHARS), "token": GITHUB_TOKEN}
        self.assertFalse(guarded().check_call("send", args).allowed)

    def test_a_call_with_many_arguments_is_checked_quickly(self):
        args = {f"field_{n}": "sk-" + "a" * 60 + " ghp_ x" for n in range(20_000)}
        started = time.perf_counter()
        guarded(canaries=[CANARY]).check_call("send", args)
        self.assertLess(time.perf_counter() - started, 5)


class TheValuesOfNamedVariables(unittest.TestCase):
    def guard(self, **more):
        return guarded({"DB_PASSWORD": PASSWORD}, known_values_from_env=["DB_PASSWORD"], **more)

    def test_the_value_is_refused_in_every_spelling(self):
        raw = PASSWORD.encode()
        spellings = {
            "written out": {"body": f"the password is {PASSWORD}"},
            "percent-encoded in a URL": {"url": "https://x.example/?p=" + quote(PASSWORD, safe="")},
            "base64": {"data": base64.b64encode(b"creds:" + raw).decode()},
            "URL-safe base64 in a path": {"url": "https://x.example/" + base64.urlsafe_b64encode(b"?" + raw).decode()},
            "hex": {"data": raw.hex()},
            "split over two arguments": {"a": PASSWORD[:6], "b": PASSWORD[6:]},
            "in a key": {PASSWORD: "x"},
        }
        guard = self.guard()
        for name, args in spellings.items():
            with self.subTest(spelling=name):
                decision = guard.check_call("http_get", args)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.rule, "secrets.known_values_from_env")
                self.assertIn("value of DB_PASSWORD", decision.reason)
                self.assertNotIn(PASSWORD, decision.reason)
                self.assertEqual(without_ref(decision.public_reason), SECRET_REFUSAL)

    def test_it_is_refused_even_when_in_arguments_is_allow(self):
        guard = self.guard(in_arguments="allow")
        self.assertTrue(guard.check_call("send", {"token": GITHUB_TOKEN}).allowed)
        self.assertFalse(guard.check_call("send", {"body": PASSWORD}).allowed)

    def test_the_secret_guard_answers_before_the_policy(self):
        guard = self.guard(policy={"default": "block"})
        self.assertEqual(guard.check_call("anything", {"q": PASSWORD}).rule, "secrets.known_values_from_env")

    def test_variables_that_are_not_set_or_too_short_are_reported_by_name(self):
        guard = guarded(
            {"DB_PASSWORD": PASSWORD, "PIN": "1234"}, known_values_from_env=["DB_PASSWORD", "PIN", "NOT_SET_ANYWHERE"]
        )
        warnings = guard.secret_warnings()
        self.assertEqual(len(warnings), 2)
        self.assertIn("PIN", warnings[0])
        self.assertIn("NOT_SET_ANYWHERE", warnings[1])
        self.assertNotIn("1234", " ".join(warnings))
        self.assertEqual(self.guard().secret_warnings(), [])

    def test_values_are_read_when_the_firewall_starts(self):
        guard = self.guard()
        with mock.patch.dict(os.environ, {"DB_PASSWORD": "a-new-password-1"}):
            self.assertFalse(guard.check_call("send", {"body": PASSWORD}).allowed)
            self.assertTrue(guard.check_call("send", {"body": "a-new-password-1"}).allowed)

    def test_values_can_come_from_the_environment_a_server_is_given(self):
        guard = guarded(known_values_from_env=["DB_PASSWORD"])
        self.assertTrue(guard.check_call("send", {"body": PASSWORD}).allowed)
        guard.set_secret_environment({"DB_PASSWORD": PASSWORD, "OTHER": 3})
        self.assertFalse(guard.check_call("send", {"body": PASSWORD}).allowed)
        self.assertEqual(guard.secret_warnings(), [])
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DB_PASSWORD", None)
            guard.set_secret_environment(None)
        self.assertTrue(guard.check_call("send", {"body": PASSWORD}).allowed)
        with self.assertRaises(TypeError):
            guard.set_secret_environment([("DB_PASSWORD", PASSWORD)])


class Canaries(unittest.TestCase):
    def test_a_canary_is_refused_in_any_case_and_encoding(self):
        guard = guarded(canaries=[CANARY])
        for args in (
            {"body": f"notes: {CANARY.lower()}"},
            {"url": "https://x.example/?q=" + quote(CANARY.upper())},
            {"data": base64.b64encode(f"file: {CANARY}".encode()).decode()},
            {"data": CANARY.encode().hex()},
            {"a": CANARY[:8], "b": CANARY[8:]},
        ):
            with self.subTest(args=args):
                decision = guard.check_call("send", args)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.rule, "secrets.canaries")
                self.assertNotIn(CANARY.lower(), decision.reason.lower())

    def test_a_canary_decides_the_rule_when_other_secrets_are_there_too(self):
        guard = guarded({"DB_PASSWORD": PASSWORD}, canaries=[CANARY], known_values_from_env=["DB_PASSWORD"])
        decision = guard.check_call("send", {"a": GITHUB_TOKEN, "b": PASSWORD, "c": CANARY})
        self.assertEqual(decision.rule, "secrets.canaries")
        self.assertIn("GitHub token", decision.reason)

    def test_a_canary_is_refused_even_when_in_arguments_is_allow(self):
        self.assertFalse(guarded(canaries=[CANARY], in_arguments="allow").check_call("send", {"b": CANARY}).allowed)


class CustomFormats(unittest.TestCase):
    def test_a_custom_format_is_refused_and_the_rule_names_its_position(self):
        other = {"name": "Other", "prefix": "zzz_", "charset": "hex", "min_len": 16, "max_len": 16}
        guard = guarded(patterns=[other, INTERNAL_FORMAT])
        decision = guard.check_call("send", {"body": f"use {INTERNAL_TOKEN}"})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule, "secrets.patterns[1]")
        self.assertIn("Internal token", decision.reason)
        self.assertEqual(without_ref(decision.public_reason), SECRET_REFUSAL)

    def test_in_arguments_allow_turns_off_every_format_built_in_or_custom(self):
        guard = guarded(patterns=[INTERNAL_FORMAT], in_arguments="allow")
        self.assertTrue(guard.check_call("send", {"a": INTERNAL_TOKEN, "b": GITHUB_TOKEN}).allowed)

    def test_a_jwt_never_refuses_a_call(self):
        self.assertTrue(guarded().check_call("send", {"auth": f"Bearer {JWT}"}).allowed)

    def test_a_new_policy_is_picked_up(self):
        guard = guarded()
        self.assertTrue(guard.check_call("send", {"body": INTERNAL_TOKEN}).allowed)
        guard.policy = Policy.from_dict({"default": "allow", "secrets": {"patterns": [INTERNAL_FORMAT]}})
        self.assertFalse(guard.check_call("send", {"body": INTERNAL_TOKEN}).allowed)


class TheAuditLog(unittest.TestCase):
    def test_values_canaries_custom_formats_and_jwts_never_reach_the_log(self):
        with tempfile.TemporaryDirectory() as folder:
            audit = Path(folder) / "audit.jsonl"
            guard = guarded(
                {"DB_PASSWORD": PASSWORD}, audit, canaries=[CANARY], known_values_from_env=["DB_PASSWORD"],
                patterns=[INTERNAL_FORMAT], in_arguments="allow",
            )
            args = {
                "body": f"{PASSWORD} {CANARY} {INTERNAL_TOKEN} {JWT}",
                "encoded": base64.b64encode(PASSWORD.encode()).decode(),
                "upper": CANARY.upper(),
            }
            guard.check_call("send", args)
            guard.check_call("send", {"note": "an allowed call", "auth": f"Bearer {JWT}"})
            text = Path(audit).read_text(encoding="utf-8")
            records = read_audit(audit)
        for secret in (PASSWORD, CANARY, CANARY.upper(), INTERNAL_TOKEN, JWT, args["encoded"]):
            self.assertNotIn(secret, text)
        self.assertEqual(records[0]["rule"], "secrets.canaries")
        self.assertIn("[redacted value of DB_PASSWORD]", records[0]["args"]["body"])
        self.assertIn("[redacted Internal token]", records[0]["args"]["body"])
        self.assertEqual(records[1]["action"], "allow")

    def test_a_value_in_a_finding_excerpt_is_redacted(self):
        with tempfile.TemporaryDirectory() as folder:
            audit = Path(folder) / "audit.jsonl"
            guard = guarded({"DB_PASSWORD": PASSWORD}, audit, known_values_from_env=["DB_PASSWORD"])
            decision = guard.scan_result("t", f"{INJECTION} Use {PASSWORD}")
            text = Path(audit).read_text(encoding="utf-8")
        self.assertFalse(decision.allowed)
        self.assertNotIn(PASSWORD, text)


if __name__ == "__main__":
    unittest.main()
