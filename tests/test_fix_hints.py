"""What an operator can do about a block, by kind of rule (agent_sentinel/fix_hints.py)."""

import unittest

from support import POLICY
from agent_sentinel import Policy
from agent_sentinel.fix_hints import PROTECTIVE_KINDS, classify, fix_hint
from agent_sentinel.textutil import printable


class ReadingRuleIds(unittest.TestCase):
    def test_every_kind_of_rule_id_is_recognised(self):
        for rule, kind, tool_rule in (
            ("default", "default", None),
            ("tools.send_email", "tool", "send_email"),
            ("tools.delete_*", "tool", "delete_*"),
            ("tools.github.search", "tool", "github.search"),
            ("deny_args[0]", "deny_global", None),
            ("tools.read_file.deny_args[1]", "deny_tool", "read_file"),
            ("tools.send_email.allow_args[0]", "allow_tool", "send_email"),
            ("tools.send_email.other_args", "other_args", "send_email"),
            ("tools.send_email.max_calls_per_minute", "limit_tool", "send_email"),
            ("limits.max_calls_per_minute", "limit_global", None),
            ("flows[2]", "flow", None),
            ("server_requests.sampling/createMessage", "server_request", None),
            ("client_requests.completion/complete", "client_request", None),
            ("secrets", "secrets", None),
            ("secrets.patterns[0]", "secret_pattern", None),
            ("injection", "injection", None),
            ("quarantine", "quarantine", None),
            ("malformed", "malformed", None),
        ):
            with self.subTest(rule=rule):
                found = classify(rule)
                self.assertEqual(found.kind, kind)
                self.assertEqual(found.tool_rule, tool_rule)

    def test_anything_else_is_unknown_or_none_and_never_raises(self):
        self.assertEqual(classify(None).kind, "none")
        self.assertEqual(classify("").kind, "none")
        self.assertEqual(classify({"a": 1}).kind, "none")
        for rule in ("deny_args[00]", "deny_args[" + "9" * 5000 + "]", "tools.", "flows[x]", "x" * 10_000, "bogus"):
            with self.subTest(rule=rule[:30]):
                self.assertEqual(classify(rule).kind, "unknown")

    def test_blocks_that_protect_are_marked_so(self):
        for kind in ("deny_global", "secrets", "injection", "quarantine", "flow"):
            self.assertIn(kind, PROTECTIVE_KINDS)
        for kind in ("default", "tool", "allow_tool"):
            self.assertNotIn(kind, PROTECTIVE_KINDS)


class Hints(unittest.TestCase):
    def test_the_default_hint_names_the_exact_rule_to_add(self):
        hint = fix_hint("default", tool="list_issues")
        self.assertIn('"list_issues": "allow"', hint)
        self.assertIn("suggest", hint)

    def test_a_wildcard_block_is_answered_with_an_exact_rule(self):
        hint = fix_hint("tools.delete_*", tool="delete_draft", policy=POLICY)
        self.assertIn("An exact rule beats every wildcard", hint)
        self.assertIn('"delete_draft": "ask"', hint)

    def test_an_ask_rule_points_to_an_approver(self):
        self.assertIn("--approve-with", fix_hint("tools.send_email", tool="send_email", policy=POLICY))

    def test_a_rule_that_is_gone_says_so(self):
        self.assertIn("no tool rule 'gone' now", fix_hint("tools.gone", tool="gone", policy=POLICY))

    def test_a_missing_required_argument_is_told_apart_from_a_value_not_accepted(self):
        missing = fix_hint("tools.send_email.allow_args[0]", matched_arg="to", args={})
        self.assertIn('"optional": true', missing)
        refused = fix_hint("tools.send_email.allow_args[0]", matched_arg="to", args={"to": "x"})
        self.assertIn("WHOLE value", refused)

    def test_protective_blocks_are_not_presented_as_mistakes(self):
        self.assertIn("doing its job", fix_hint("deny_args[0]", matched_arg="path"))
        self.assertIn("do not loosen this", fix_hint("secrets.canaries"))
        self.assertIn("not recommended", fix_hint("injection"))

    def test_hostile_parts_of_a_record_come_back_printable(self):
        hint = fix_hint("default", tool="evil\x1b[2J‮" + "x" * 1000, matched_arg="\x07")
        self.assertEqual(hint, printable(hint, limit=len(hint)))
        self.assertNotIn("\x1b", hint)
        self.assertLess(len(hint), 1000)
        for rule in (None, 5, ["x"], "tools.\x1b.other_args", "client_requests.\x1b"):
            with self.subTest(rule=rule):
                self.assertNotIn("\x1b", fix_hint(rule, tool=["odd"], matched_arg={"odd": 1}, args="odd"))



class HookHints(unittest.TestCase):
    def test_a_refusal_by_the_claude_code_hook_itself_is_explained(self):
        self.assertEqual(classify("hook_failed").kind, "hook_failed")
        self.assertIn("hook_failed", PROTECTIVE_KINDS)
        hint = fix_hint("hook_failed")
        self.assertIn("Claude Code hook could not finish its checks", hint)
        self.assertIn("no policy rule changes this", hint)

    def test_rate_limit_and_ask_hints_mention_hook_mode(self):
        self.assertIn("per Claude Code session", fix_hint("tools.Bash.max_calls_per_minute"))
        policy = Policy.from_dict({"tools": {"Bash": "ask"}})
        self.assertIn("bypassPermissions", fix_hint("tools.Bash", tool="Bash", policy=policy))


if __name__ == "__main__":
    unittest.main()
