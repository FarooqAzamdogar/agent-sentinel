import tempfile
import unittest
from pathlib import Path

from support import POLICY
from agent_sentinel import Policy, PolicyError


def action(tool, args):
    return POLICY.evaluate(tool, args).action


class ToolRules(unittest.TestCase):
    def test_allowed_tool(self):
        self.assertEqual(action("read_file", {"path": "notes.txt"}), "allow")

    def test_glob_rules(self):
        self.assertEqual(action("delete_everything", {}), "block")
        self.assertEqual(action("search_web", {"q": "soup"}), "allow")

    def test_unknown_tool_uses_the_default(self):
        self.assertEqual(action("launch_rocket", {}), "block")

    def test_exact_name_beats_glob(self):
        policy = Policy.from_dict({"tools": {"delete_*": "block", "delete_draft": "allow"}})
        self.assertEqual(policy.evaluate("delete_draft", {}).action, "allow")

    def test_default_is_block_when_omitted(self):
        self.assertEqual(Policy.from_dict({}).evaluate("anything", {}).action, "block")


class DenyArgs(unittest.TestCase):
    def test_denied_value(self):
        self.assertEqual(action("read_file", {"path": "C:/Users/me/.ssh/id_rsa"}), "block")

    def test_any_arg_rule_sees_other_and_nested_arguments(self):
        # The example policy uses "arg": "*", so the value cannot hide elsewhere.
        self.assertEqual(action("read_file", {"path": "a.txt", "paths": ["/home/me/.ssh/id_rsa"]}), "block")
        self.assertEqual(action("read_file", {"path": "a.txt", "options": {"extra": {".env": 1}}}), "block")

    def test_named_arg_rule_sees_nested_values(self):
        policy = Policy.from_dict({"tools": {"read": {"deny_args": [{"arg": "path", "pattern": "secret"}]}}})
        self.assertEqual(policy.evaluate("read", {"path": ["ok.txt", "my-secret.txt"]}).action, "block")
        self.assertEqual(policy.evaluate("read", {"path": "ok.txt", "note": "secret"}).action, "allow")

    def test_reason_does_not_reveal_the_pattern(self):
        reason = POLICY.evaluate("read_file", {"path": ".ssh/id_rsa"}).reason
        self.assertNotIn("id_rsa", reason)


class AllowArgs(unittest.TestCase):
    def test_matching_value_passes_to_the_rule_action(self):
        self.assertEqual(action("send_email", {"to": "a@example.com"}), "ask")

    def test_other_value_or_missing_argument_is_blocked(self):
        self.assertEqual(action("send_email", {"to": "a@evil.example"}), "block")
        self.assertEqual(action("send_email", {}), "block")

    def test_the_whole_value_must_match(self):
        # Each of these contains an allowed address but is not only that address.
        for to in [
            "x@evil.example, a@example.com",
            "x@evil.example\na@example.com",
            "a@example.com\n",
            "a@example.com.evil.example",
        ]:
            with self.subTest(to=to):
                self.assertEqual(action("send_email", {"to": to}), "block")

    def test_every_value_in_a_list_must_match(self):
        self.assertEqual(action("send_email", {"to": ["a@example.com", "b@example.com"]}), "ask")
        self.assertEqual(action("send_email", {"to": ["a@example.com", "x@evil.example"]}), "block")
        self.assertEqual(action("send_email", {"to": []}), "block")


class Loading(unittest.TestCase):
    def assert_rejected(self, data):
        with self.assertRaises(PolicyError):
            Policy.from_dict(data)

    def test_wrong_values_are_rejected(self):
        self.assert_rejected({"default": "maybe"})
        self.assert_rejected({"tools": {"x": {"action": "permit"}}})
        self.assert_rejected({"tools": {"x": {"deny_args": [{"arg": "a", "pattern": "("}]}}})
        self.assert_rejected({"injection": {"block_severity": "extreme"}})

    def test_wrong_shapes_are_rejected(self):
        self.assert_rejected([])
        self.assert_rejected({"tools": []})
        self.assert_rejected({"tools": {"x": 5}})
        self.assert_rejected({"tools": {"x": {"deny_args": "path"}}})
        self.assert_rejected({"tools": {"x": {"deny_args": [{"arg": "a"}]}}})

    def test_typos_are_rejected_instead_of_ignored(self):
        self.assert_rejected({"defualt": "block"})
        self.assert_rejected({"tools": {"x": {"deny_arg": [{"arg": "a", "pattern": "b"}]}}})
        self.assert_rejected({"tools": {"x": {"deny_args": [{"arg": "a", "patern": "b"}]}}})
        self.assert_rejected({"injection": {"block_severty": "high"}})

    def test_any_arg_is_only_for_deny_rules(self):
        self.assert_rejected({"tools": {"x": {"allow_args": [{"arg": "*", "pattern": "a"}]}}})

    def test_file_that_is_not_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_bytes(b"\xff\xfe not json")
            with self.assertRaises(PolicyError):
                Policy.from_file(path)


if __name__ == "__main__":
    unittest.main()
