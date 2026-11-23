"""`agent-sentinel suggest`: exact-name rules drafted from a monitor-mode log (agent_sentinel/cli_suggest.py)."""

import json
import unittest

from cli_support import TempFolderTest, run_cli
from support import audit_records
from agent_sentinel import Firewall, Policy
from agent_sentinel.cli_suggest import MIN_LIMIT

BASE_POLICY = {"default": "block", "tools": {"read_file": "allow", "delete_*": "block"},
               "deny_args": [{"arg": "*", "contains": "id_rsa"}]}


def call(tool, action="would_block", rule="default", minute=0, second=0, **fields):
    record = {"time": f"2026-11-18T10:{minute:02d}:{second:02d}+00:00", "event": "call", "tool": tool,
              "action": action, "rule": rule, "reason": "r"}
    record.update(fields)
    return record


class Suggesting(TempFolderTest):
    def setUp(self):
        super().setUp()
        self.policy = self.write("policy.json", BASE_POLICY)

    def suggest(self, records, *options):
        log = self.write_log("audit.jsonl", records)
        code, out, err = run_cli("suggest", log, "--policy", self.policy, *options)
        self.assertEqual(code, 0, err)
        return out

    def test_calls_blocked_only_by_the_default_become_exact_rules_in_a_diff(self):
        out = self.suggest([call("list_issues", args={"repo": "a/b"}), call("get_issue", args={"number": 5})])
        self.assertIn("+    \"get_issue\": {", out)
        self.assertIn("+    \"list_issues\": {", out)
        self.assertIn("arguments: repo (text)", out)
        self.assertIn("arguments: number (a number)", out)
        self.assertIn("Nothing was written", out)
        self.assertEqual(json.loads(self.policy.read_text(encoding="utf-8")), BASE_POLICY)  # never edited

    def test_out_writes_a_new_policy_that_loads_and_allows_the_tools(self):
        out_file = self.folder / "suggested.json"
        self.suggest([call("list_issues")], "--out", out_file)
        policy = Policy.from_file(out_file)
        self.assertEqual(policy.evaluate("list_issues", {}).action, "allow")
        self.assertEqual(policy.evaluate("delete_file", {}).action, "block")  # the rest is as it was
        self.assertEqual(json.loads(self.policy.read_text(encoding="utf-8")), BASE_POLICY)

    def test_out_must_be_a_new_file_and_never_the_policy(self):
        log = self.write_log("audit.jsonl", [call("list_issues")])
        existing = self.write("existing.json", "{}")
        for out_file, expected in ((existing, "already exists"), (self.policy, "never changes the policy file")):
            with self.subTest(out=out_file.name):
                code, _, err = run_cli("suggest", log, "--policy", self.policy, "--out", out_file)
                self.assertEqual(code, 2)
                self.assertIn(expected, err)
        self.assertEqual(existing.read_text(encoding="utf-8"), "{}")

    def test_blocks_with_a_reason_are_never_loosened(self):
        records = [
            call("read_file", rule="deny_args[0]", matched_arg="path"),
            call("send_mail", rule="secrets"),
            call("delete_file", rule="tools.delete_*"),
            call("send_email", rule="tools.send_email.allow_args[0]"),
            call("poisoned", rule="quarantine"),
            call("sink_tool", rule="flows[0]"),
            call("busy_tool", rule="limits.max_calls_per_minute"),
            call("older_log_tool", rule=None),
        ]
        out = self.suggest(records)
        self.assertIn("Nothing to suggest", out)
        held = out.split("Blocked for a reason")[1]
        for rule in ("deny_args[0]", "secrets", "tools.delete_*", "quarantine", "flows[0]", "limits.max_calls"):
            self.assertIn(rule, held)
        self.assertNotIn("+    ", out)

    def test_a_name_with_a_star_never_becomes_a_wildcard(self):
        out = self.suggest([call("delete_*"), call("*")])
        self.assertIn("'delete_*': the name has a '*'", out)
        self.assertIn("Nothing to suggest", out)

    def test_odd_and_broad_names_are_left_out(self):
        records = [call(name) for name in (
            "resources/read", "prompts/get", "read file", " read_file", "reаd_file", "x" * 129, "evil\x1b[2J",
        )]
        out = self.suggest(records)
        self.assertIn("Nothing to suggest", out)
        self.assertIn("ANY resource", out)
        self.assertIn("ANY prompt", out)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("а", out)  # the look-alike letter is shown escaped
        self.assertIn("'re\\u0430d_file'", out)

    def test_a_tool_whose_description_or_result_was_flagged_is_left_out(self):
        records = [
            call("poisoned_tool"),
            {"event": "tool_description", "tool": "poisoned_tool", "action": "would_block", "rule": "injection"},
            call("fetch_page"),
            {"event": "result", "tool": "fetch_page", "action": "would_block", "rule": "injection"},
            call("changed_tool"),
            {"event": "tool_changed", "tool": "changed_tool", "action": "block", "rule": "quarantine"},
        ]
        out = self.suggest(records)
        self.assertIn("'poisoned_tool': its description was flagged", out)
        self.assertIn("'fetch_page': a result was blocked", out)
        self.assertIn("'changed_tool': its definition changed", out)
        self.assertIn("Nothing to suggest", out)

    def test_a_tool_that_has_a_rule_now_is_not_suggested_again(self):
        out = self.suggest([call("read_file"), call("delete_draft")])
        self.assertIn("'read_file': the policy has a rule for it now (read_file)", out)
        self.assertIn("'delete_draft': the policy has a rule for it now (delete_*)", out)

    def test_allowed_and_asked_calls_are_not_counted(self):
        out = self.suggest([call("x", action="allow"), call("y", action="ask")])
        self.assertIn("0 blocked call(s)", out)

    def test_the_rate_limit_is_twice_the_busiest_minute(self):
        records = [call("busy", second=second) for second in range(0, 40, 3)]  # 14 calls within a minute
        records += [call("busy", minute=5)]
        out_file = self.folder / "suggested.json"
        out = self.suggest(records, "--out", out_file)
        self.assertIn("busiest minute 14 call(s)", out)
        rule = json.loads(out_file.read_text(encoding="utf-8"))["tools"]["busy"]
        self.assertEqual(rule, {"action": "allow", "max_calls_per_minute": 28})

    def test_a_quiet_tool_gets_the_lowest_limit(self):
        out_file = self.folder / "suggested.json"
        self.suggest([call("quiet")], "--out", out_file)
        self.assertEqual(json.loads(out_file.read_text(encoding="utf-8"))["tools"]["quiet"]["max_calls_per_minute"],
                         MIN_LIMIT)

    def test_as_ask_and_no_limits(self):
        out_file = self.folder / "suggested.json"
        self.suggest([call("x")], "--as", "ask", "--no-limits", "--out", out_file)
        self.assertEqual(json.loads(out_file.read_text(encoding="utf-8"))["tools"]["x"], "ask")

    def test_server_chooses_the_calls_of_one_server(self):
        out = self.suggest([call("files_tool", server="files"), call("mail_tool", server="mail")], "--server", "files")
        self.assertIn("files_tool", out)
        self.assertNotIn("mail_tool", out)

    def test_an_ask_that_was_refused_or_could_not_be_asked_is_never_turned_into_allow(self):
        # A firewall with default "ask" logs a refused ask as a block by rule "default".
        audit = self.folder / "real.jsonl"
        refusing = Firewall(Policy.from_dict({"default": "ask"}), audit_path=audit, approver=lambda *_: False)
        refusing.check_call("delete_repository", {"repo": "acme/prod"})
        Firewall(Policy.from_dict({"default": "ask"}), audit_path=audit).check_call("drop_table", {})
        records = audit_records(audit)
        self.assertEqual([record.get("approval") for record in records], ["refused", "unavailable"])
        out = self.suggest(records)  # judged against a policy whose default is "block"
        self.assertIn("Nothing to suggest", out)
        held = out.split("Blocked for a reason")[1]
        self.assertIn("default (ask, refused)  (delete_repository)", held)
        self.assertIn("default (ask, unavailable)  (drop_table)", held)
        self.assertNotIn("+    ", out)

    def test_a_policy_whose_default_is_ask_gets_no_rules_proposed(self):
        self.policy = self.write("ask.json", {"default": "ask"})
        for action in ("allow", "ask"):
            with self.subTest(action=action):
                out = self.suggest([call("delete_repository")], "--as", action)
                self.assertIn('default is "ask"', out)
                self.assertIn("Nothing to suggest", out)
                self.assertNotIn("+    ", out)

    def test_a_policy_whose_default_is_allow_needs_no_rules(self):
        self.policy = self.write("allow.json", {"default": "allow"})
        out = self.suggest([call("x")])
        self.assertIn('default is "allow" now', out)
        self.assertIn("Nothing to suggest", out)

    def test_a_policy_without_tools_gets_a_tools_section(self):
        self.policy = self.write("empty.json", {})
        out_file = self.folder / "suggested.json"
        self.suggest([call("x")], "--out", out_file)
        self.assertIn("x", json.loads(out_file.read_text(encoding="utf-8"))["tools"])

    def test_a_hostile_log_does_not_crash(self):
        records = ["not json", "[" * 100_000, json.dumps([1]), json.dumps({"event": "call", "action": "would_block",
                   "rule": "default", "tool": 5}), json.dumps(call("ok_tool", args={"\x1b": [1] * 10}))]
        records += [call(f"tool_{n}", args={f"a{m}": m for m in range(50)}) for n in range(3)]
        out = self.suggest(records)
        self.assertIn("WARNING: 3 line(s)", out)  # not JSON, nested too deep, and not an object
        self.assertIn("1 call(s) whose tool name in the log is not text", out)
        self.assertIn("a7 (a number), ... (+12 more)", out)
        self.assertIn("ok_tool", out)
        self.assertNotIn("\x1b", out)

    def test_a_blocked_line_whose_event_is_not_text_does_not_end_the_command(self):
        # An object or a list is no key of the table of flagging events: the look-up must not raise.
        odd = [{"event": value, "action": "would_block", "rule": "default", "tool": "odd_tool", "reason": "r"}
               for value in ({"a": 1}, {}, [], ["result"], [[]], 5, None)]
        out = self.suggest([*odd, call("ok_tool")])
        self.assertIn("ok_tool", out)
        self.assertNotIn("odd_tool", out)  # not a call, so nothing is proposed for it

    def test_a_real_monitor_log(self):
        audit = self.folder / "real.jsonl"
        monitor = Firewall(Policy.from_file(self.policy), audit_path=audit, monitor=True)
        monitor.check_call("list_issues", {"repo": "a/b"})
        monitor.check_call("read_file", {"path": "~/.ssh/id_rsa"})
        code, out, _ = run_cli("suggest", audit, "--policy", self.policy)
        self.assertEqual(code, 0)
        self.assertIn('+    "list_issues": {', out)
        self.assertIn("deny_args[0]  (read_file)", out)

    def test_a_policy_with_a_mistake_is_an_error(self):
        log = self.write_log("audit.jsonl", [call("x")])
        code, _, err = run_cli("suggest", log, "--policy", self.write("bad.json", '{"tools": []}'))
        self.assertEqual(code, 2)
        self.assertIn("Invalid policy", err)


if __name__ == "__main__":
    unittest.main()
