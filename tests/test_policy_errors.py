"""Tests for the error messages of a policy that cannot be loaded (policy_errors.py).

The messages help; they never relax anything. Every policy refused before
is still refused, with a better explanation.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from support import ROOT
from agent_sentinel import Policy, PolicyError
from agent_sentinel.policy_errors import did_you_mean, file_error_message, json_error_message

BACKSLASH = "\\"


def error_for(data):
    with unittest.TestCase().assertRaises(PolicyError) as caught:
        Policy.from_dict(data)
    return str(caught.exception)


class FileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "policy.json"

    def error_for_text(self, text, encoding="utf-8"):
        self.path.write_bytes(text.encode(encoding))
        with self.assertRaises(PolicyError) as caught:
            Policy.from_file(self.path)
        return str(caught.exception)


class Suggestions(unittest.TestCase):
    def test_an_unknown_key_suggests_the_key_that_was_meant(self):
        message = error_for({"defualt": "block"})
        self.assertIn("unknown key 'defualt' in the policy; did you mean 'default'?", message)
        self.assertIn("Allowed keys: default, deny_args, tools", message)

    def test_a_misspelt_key_inside_a_rule_or_entry_is_found_too(self):
        self.assertIn("did you mean 'deny_args'?", error_for({"tools": {"x": {"action": "allow", "deny_arg": []}}}))
        message = error_for({"deny_args": [{"arg": "*", "patern": "x"}]})
        self.assertIn("unknown key 'patern' in deny_args[0]; did you mean 'pattern'?", message)

    def test_an_unknown_key_with_nothing_close_lists_the_allowed_keys_only(self):
        message = error_for({"zzzzzz": 1})
        self.assertIn("unknown key 'zzzzzz' in the policy.", message)
        self.assertNotIn("did you mean", message)

    def test_many_unknown_keys_give_a_message_of_bounded_length(self):
        message = error_for({f"key{number}": 1 for number in range(10_000)})
        self.assertIn("And 9995 more unknown key(s).", message)
        self.assertLess(len(message), 1000)

    def test_a_misspelt_action_suggests_the_action(self):
        message = error_for({"tools": {"read_file": {"action": "alow"}}})
        self.assertEqual(
            message, "tools.read_file.action must be 'allow', 'ask' or 'block', got 'alow'; did you mean 'allow'?"
        )

    def test_another_word_for_an_action_suggests_the_policy_word(self):
        for word, meant in (("deny", "block"), ("reject", "block"), ("permit", "allow"), ("confirm", "ask"),
                            ("approval", "ask")):
            with self.subTest(word=word):
                self.assertIn(f"did you mean '{meant}'?", error_for({"default": word}))

    def test_an_action_in_capitals_is_told_to_be_lowercase(self):
        message = error_for({"tools": {"run_shell": "Block"}})
        self.assertIn("got 'Block'", message)
        self.assertIn("lowercase", message)
        self.assertIn("'block'", message)

    def test_a_value_that_is_not_text_says_what_it_is(self):
        other_args_true = {"tools": {"x": {"action": "allow", "other_args": True}}}
        self.assertIn("got true, which is true or false", error_for(other_args_true))
        self.assertIn("got 5, which is a number", error_for({"default": 5}))
        self.assertIn("got a list", error_for({"tools": []}))
        self.assertIn("got a number", error_for({"tools": {"x": 5}}))

    def test_a_suggestion_is_never_applied(self):
        for data in ({"default": "Block"}, {"defualt": "block"}, {"tools": {"x": "deny"}}):
            with self.subTest(data=data), self.assertRaises(PolicyError):
                Policy.from_dict(data)

    def test_other_choices_get_suggestions_too(self):
        self.assertIn("did you mean 'block'?", error_for({"secrets": {"in_arguments": "deny"}}))
        self.assertIn("did you mean 'high'?", error_for({"injection": {"block_severity": "hihg"}}))
        self.assertIn("null turns blocking off", error_for({"injection": {"block_severity": "max"}}))

    def test_a_long_word_is_not_compared(self):
        started = time.perf_counter()
        self.assertIsNone(did_you_mean("a" * 1_000_000, ["allow", "ask", "block"]))
        self.assertLess(time.perf_counter() - started, 1)


class WhereTheMistakeIs(FileTest):
    def test_every_error_from_a_file_starts_with_its_name(self):
        message = self.error_for_text('{"tools": {"read_file": "alow"}}')
        self.assertTrue(message.startswith(f"{self.path}: tools.read_file must be"), message)

    def test_a_json_error_shows_line_column_the_line_and_a_caret_under_the_mistake(self):
        text = '{\n  "default": "block",\n  "deny_args": [{"arg": "*", "pattern": "' + BACKSLASH + '.ssh"}]\n}\n'
        lines = self.error_for_text(text).splitlines()
        self.assertEqual(lines[0], f"{self.path}:3:42: not valid JSON: Invalid {BACKSLASH}escape")
        source, caret = lines[1], lines[2]
        self.assertEqual(source, '      "deny_args": [{"arg": "*", "pattern": "' + BACKSLASH + '.ssh"}]')
        self.assertEqual(source[caret.index("^")], BACKSLASH)
        self.assertEqual(lines[3], 'In JSON a backslash must be doubled. For the regular expression '
                                   + BACKSLASH + '.ssh write "' + BACKSLASH * 2 + '.ssh".')

    def test_the_caret_stays_under_the_mistake_after_a_tab_or_a_control_character(self):
        text = '{"a":\t"x", "b": "\x1b", "c": "' + BACKSLASH + 'q"}'
        lines = self.error_for_text(text).splitlines()
        self.assertNotIn("\x1b", "\n".join(lines))
        self.assertEqual(lines[1][lines[2].index("^")], BACKSLASH)

    def test_a_long_line_is_shown_around_the_mistake_only(self):
        text = '{"a": "' + "x" * 200_000 + BACKSLASH + 'q' + "y" * 200_000 + '"}'
        started = time.perf_counter()
        lines = self.error_for_text(text).splitlines()
        self.assertLess(time.perf_counter() - started, 2)
        self.assertLess(len(lines[1]), 150)
        self.assertEqual(lines[1][lines[2].index("^")], BACKSLASH)

    def test_a_trailing_comma_gets_a_hint(self):
        for text in ('{"default": "block",}', '{"deny_args": [{"arg": "*", "pattern": "x"},]}'):
            with self.subTest(text=text):
                self.assertIn("no comma after the last item", self.error_for_text(text))

    def test_single_quotes_and_comments_get_hints(self):
        self.assertIn("double quotes", self.error_for_text("{'default': 'block'}"))
        self.assertIn("no comments", self.error_for_text('{"default": "block" // safe\n}'))

    def test_a_utf16_file_is_named_as_such(self):
        self.assertIn("saved as UTF-16; save it as UTF-8", self.error_for_text('{"default": "block"}', "utf-16"))

    def test_bytes_that_are_not_utf8_are_reported(self):
        self.path.write_bytes(b'{"default": "\xff"}')
        with self.assertRaises(PolicyError) as caught:
            Policy.from_file(self.path)
        self.assertIn("not valid UTF-8 text", str(caught.exception))

    def test_a_duplicate_key_is_still_named(self):
        self.assertIn("duplicate key 'default'", self.error_for_text('{"default": "block", "default": "allow"}'))


class MissingFiles(unittest.TestCase):
    def test_a_missing_file_is_named_with_its_full_path_and_the_current_folder(self):
        try:
            Policy.from_file("no_such_policy.json")
        except OSError as exc:  # still OSError, as open() raises, for code that catches it
            message = file_error_message("no_such_policy.json", exc)
        self.assertIn(os.path.abspath("no_such_policy.json"), message)
        self.assertIn(f"the current folder is {os.getcwd()}", message)
        self.assertNotIn(BACKSLASH * 2, message)

    def test_other_file_errors_give_the_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            try:
                Policy.from_file(tmp)  # a folder
            except OSError as exc:
                message = file_error_message(tmp, exc)
        self.assertIn(f"cannot read the policy file {os.path.abspath(tmp)}", message)


class OnTheCommandLine(unittest.TestCase):
    def run_cli(self, *args):
        command = [sys.executable, "-m", "agent_sentinel", *args]
        return subprocess.run(command, capture_output=True, cwd=ROOT, timeout=60)

    def test_validate_prints_the_line_and_the_caret_on_lines_of_their_own(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text('{"deny_args": [{"arg": "*", "pattern": "' + BACKSLASH + '.env"}]}', encoding="utf-8")
            result = self.run_cli("validate", str(path))
        self.assertEqual(result.returncode, 2)
        lines = result.stderr.decode().splitlines()
        self.assertTrue(lines[0].startswith("Invalid policy: "))
        self.assertEqual(lines[1][lines[2].index("^")], BACKSLASH)
        self.assertIn("must be doubled", lines[3])

    def test_validate_names_a_missing_file_in_full(self):
        result = self.run_cli("validate", "no_such_file.json")
        self.assertEqual(result.returncode, 2)
        self.assertIn(str(ROOT / "no_such_file.json"), result.stderr.decode())

    def test_the_proxy_reports_a_bad_policy_line_by_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text('{"default": "block",}', encoding="utf-8")
            result = self.run_cli("proxy", "--policy", str(path), "--", "anything")
        self.assertEqual(result.returncode, 2)
        stderr = result.stderr.decode()
        self.assertIn("cannot load policy:", stderr)
        self.assertIn("no comma after the last item", stderr)


class TheJsonErrorRendererOnItsOwn(unittest.TestCase):
    def test_an_error_on_a_line_that_does_not_exist_is_still_reported(self):
        error = json.JSONDecodeError("Expecting value", "", 0)
        self.assertIn("not valid JSON: Expecting value", json_error_message("p.json", error))


if __name__ == "__main__":
    unittest.main()
