"""Strict JSON reading shared by the library and the commands (agent_sentinel/jsonutil.py)."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

import support  # noqa: F401
from cli_support import TempFolderTest
from agent_sentinel import Firewall, Policy, PolicyError, jsonutil
from agent_sentinel.cli_common import CommandError, strict_json

ROOT = Path(__file__).resolve().parent.parent

LOOSE = {
    "a repeated key": '{"a": 1, "a": 2}',
    "NaN": '{"a": NaN}',
    "Infinity": '{"a": -Infinity}',
    "a number too large to be one": '{"a": 1e999}',
    "an integer of thousands of digits": '{"a": ' + "9" * 5000 + "}",
}


class Reading(unittest.TestCase):
    def test_what_python_reads_but_json_does_not_mean_is_refused_everywhere(self):
        for name, text in LOOSE.items():
            with self.subTest(name):
                with self.assertRaises(ValueError):
                    jsonutil.loads(text)
                with self.assertRaises(CommandError):
                    strict_json(text, "x.json")

    def test_plain_json_is_read(self):
        self.assertEqual(jsonutil.loads('{"a": [1, 2.5, -1e2, true, null, "x"]}'),
                         {"a": [1, 2.5, -100.0, True, None, "x"]})

    def test_the_digit_limit_is_the_same_with_or_without_a_sign_and_whatever_the_interpreter_allows(self):
        limit = jsonutil.MAX_INT_DIGITS
        # Python before 3.10.7 has no limit of its own, and it can be turned off; the count here must not need it.
        previous = sys.get_int_max_str_digits() if hasattr(sys, "get_int_max_str_digits") else None
        if previous is not None:
            sys.set_int_max_str_digits(0)
        try:
            for sign in ("", "-"):
                with self.subTest(sign=sign):
                    self.assertEqual(jsonutil.loads(sign + "7" * limit), int(sign + "7" * limit))
                    for digits in (limit + 1, limit + 2):
                        with self.assertRaisesRegex(ValueError, f"a number with more than {limit} digits"):
                            jsonutil.loads(sign + "7" * digits)
        finally:
            if previous is not None:
                sys.set_int_max_str_digits(previous)

    def test_a_repeated_key_names_the_key(self):
        with self.assertRaises(jsonutil.RepeatedKeyError) as caught:
            jsonutil.loads('{"run_shell": "block", "run_shell": "allow"}')
        self.assertEqual(caught.exception.key, "run_shell")
        self.assertIn("appears twice", str(caught.exception))


class EveryReaderIsStrict(TempFolderTest):
    def test_a_policy_with_nan_or_a_huge_number_does_not_load(self):
        for name, text in LOOSE.items():
            path = self.write("policy.json", '{"default": "block", "limits": ' + text + "}")
            with self.subTest(name), self.assertRaises(PolicyError):
                Policy.from_file(path)


class TheAuditLogIsAlwaysJson(TempFolderTest):
    def test_nan_or_infinity_in_a_call_never_makes_a_line_that_is_not_json(self):
        audit = self.folder / "audit.jsonl"
        firewall = Firewall(Policy.from_dict({"default": "allow"}), audit_path=audit)
        firewall.check_call("measure", {"value": float("nan"), "limit": float("inf"), "unit": "cm"})

        def refuse(name):
            raise ValueError(name)

        (line,) = audit.read_text(encoding="utf-8").splitlines()
        record = json.loads(line, parse_constant=refuse)  # strict: NaN or Infinity would raise
        self.assertEqual(record["args"], "[arguments not logged: they hold NaN or Infinity, which JSON cannot hold]")
        self.assertEqual(record["tool"], "measure")


class TheLibraryDoesNotLoadTheCommandLine(unittest.TestCase):
    def test_importing_the_package_loads_no_command_module(self):
        code = ("import sys; sys.path.insert(0, sys.argv[1]); before = set(sys.modules); import agent_sentinel; "
                "print(' '.join(sorted(set(sys.modules) - before)))")
        loaded = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT)], capture_output=True, text=True,
                                timeout=60, check=True).stdout.split()
        for module in ("agent_sentinel.cli_common", "argparse", "subprocess", "shlex", "textwrap"):
            with self.subTest(module=module):
                self.assertNotIn(module, loaded)


if __name__ == "__main__":
    unittest.main()
