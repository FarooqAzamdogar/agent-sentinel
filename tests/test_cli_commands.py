"""The layout of the command line: one module per command, put together by __main__.py."""

import unittest

from cli_support import run_cli
from support import EXAMPLE_POLICY_PATH
from agent_sentinel import __main__ as cli


class EveryCommand(unittest.TestCase):
    def test_each_command_module_has_what_the_dispatcher_needs(self):
        for name, module in cli._COMMANDS:
            with self.subTest(command=name):
                self.assertTrue(module.HELP)
                self.assertTrue(callable(module.add_arguments))
                self.assertTrue(callable(module.run))

    def test_each_command_has_a_help_page(self):
        for name, _ in cli._COMMANDS:
            with self.subTest(command=name):
                code, out, _ = run_cli(name, "--help")
                self.assertEqual(code, 0)
                self.assertIn(f"agent-sentinel {name}", out)

    def test_the_list_of_commands_names_them_all(self):
        _, out, _ = run_cli("--help")
        for name in ("proxy", *(name for name, _ in cli._COMMANDS)):
            self.assertIn(name, out)

    def test_extra_words_are_refused_by_commands_that_take_none(self):
        code, _, err = run_cli("validate", EXAMPLE_POLICY_PATH, "extra")
        self.assertEqual(code, 2)
        self.assertIn("agent-sentinel validate: error: unrecognized arguments: extra", err)

    def test_a_missing_command_is_an_error(self):
        self.assertEqual(run_cli()[0], 2)
        self.assertEqual(run_cli("frobnicate")[0], 2)


if __name__ == "__main__":
    unittest.main()
