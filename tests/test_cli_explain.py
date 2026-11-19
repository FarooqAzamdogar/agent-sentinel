"""`agent-sentinel explain`: why calls were blocked, from the audit log (agent_sentinel/cli_explain.py)."""

import json
import unittest

from cli_support import TempFolderTest, run_cli
from support import EXAMPLE_POLICY_PATH, INJECTION, POLICY
from agent_sentinel import BlockedError, Firewall
from agent_sentinel.cli_explain import MAX_REF_MATCHES, parse_ref
from agent_sentinel.cli_common import CommandError

EXAMPLE = str(EXAMPLE_POLICY_PATH)


class ExplainingARealLog(TempFolderTest):
    def setUp(self):
        super().setUp()
        self.audit = self.folder / "audit.jsonl"
        self.firewall = Firewall(POLICY, audit_path=self.audit, server_name="files")

    def test_the_ref_the_agent_saw_finds_the_record_with_its_rule_and_a_hint(self):
        decision = self.firewall.check_call("read_file", {"path": "/home/me/.ssh/id_rsa"})
        code, out, _ = run_cli("explain", self.audit, "--ref", decision.ref)
        self.assertEqual(code, 0, out)
        self.assertIn(f"ref {decision.ref}", out)
        self.assertIn("BLOCKED  call read_file", out)
        self.assertIn('arguments:   path="/home/me/.ssh/id_rsa"', out)
        self.assertIn("decided by:  deny_args[0], argument 'path'", out)
        self.assertIn("to allow:", out)
        self.assertIn("server files", out)

    def test_the_ref_can_be_pasted_as_the_agent_saw_it(self):
        decision = self.firewall.check_call("delete_file", {"path": "a"})
        pasted = decision.public_reason[decision.public_reason.index("(ref"):]
        self.assertEqual(run_cli("explain", self.audit, "--ref", pasted.upper())[0], 0)

    def test_with_the_policy_the_rule_is_described_and_the_call_checked_again(self):
        decision = self.firewall.check_call("send_email", {"to": "eve@evil.example"})
        code, out, _ = run_cli("explain", self.audit, "--ref", decision.ref, "--policy", EXAMPLE)
        self.assertEqual(code, 0)
        self.assertIn("rule now:    tool rule 'send_email', allow rule for argument 'to'", out)
        self.assertIn("policy now:  BLOCK (tools.send_email.allow_args[0])", out)
        # After the operator widens the rule, explain says the call would pass now.
        widened = self.write("widened.json", {"tools": {"send_email": "allow"}})
        _, out, _ = run_cli("explain", self.audit, "--ref", decision.ref, "--policy", widened)
        self.assertIn("this policy has no such rule now", out)
        self.assertIn("policy now:  ALLOW (tools.send_email)", out)

    def test_last_explains_the_latest_blocks(self):
        self.firewall.check_call("delete_file", {"path": "first"})
        self.firewall.check_call("read_file", {"path": "fine.txt"})
        self.firewall.check_call("run_shell", {"command": "second"})
        code, out, _ = run_cli("explain", self.audit, "--last", "1")
        self.assertEqual(code, 0)
        self.assertIn("run_shell", out)
        self.assertNotIn("delete_file", out)
        self.assertNotIn("fine.txt", out)
        _, out, _ = run_cli("explain", self.audit)  # the default: the last few
        self.assertIn("delete_file", out)

    def test_a_refused_approval_shows_the_ask_and_the_answer(self):
        pending = self.firewall.check_call("send_email", {"to": "bob@example.com"}, defer_ask=True)
        self.firewall.finish_approval(pending, False, "dialog")
        _, out, _ = run_cli("explain", self.audit, "--ref", pending.ref)
        self.assertIn(f"2 records have ref {pending.ref}", out)
        self.assertIn("WAITING FOR APPROVAL", out)
        self.assertIn("REFUSED when a person was asked", out)
        self.assertEqual(out.count("to allow:"), 1)  # the hint belongs to the answer

    def test_a_withheld_result_shows_its_findings(self):
        with self.assertRaises(BlockedError) as caught:
            self.firewall.run("fetch_page", {"url": "https://x"}, lambda url: INJECTION)
        _, out, _ = run_cli("explain", self.audit, "--ref", caught.exception.decision.ref)
        self.assertIn("result fetch_page", out)
        self.assertIn("findings:    [HIGH  ] instruction_override", out)

    def test_monitor_mode_records_say_they_were_let_through(self):
        monitor = Firewall(POLICY, audit_path=self.audit, monitor=True)
        monitor.check_call("unknown_tool", {})
        _, out, _ = run_cli("explain", self.audit, "--last", "1")
        self.assertIn("WOULD BE BLOCKED (monitor mode let it through)", out)
        self.assertIn('"unknown_tool": "allow"', out)


class FindingNothing(TempFolderTest):
    def test_an_unknown_ref_exits_1(self):
        code, out, _ = run_cli("explain", self.write_log("a.jsonl", []), "--ref", "12345678")
        self.assertEqual(code, 1)
        self.assertIn("No record in the log has ref 12345678", out)

    def test_a_log_without_blocks_exits_1(self):
        log = self.write_log("a.jsonl", [{"event": "call", "tool": "x", "action": "allow"}])
        self.assertEqual(run_cli("explain", log)[0], 1)

    def test_something_that_is_not_a_ref_is_an_error(self):
        for text in ("zz", "123456789", "ref", "", "(ref 7f3a9c2)", "7f3a9c21; rm -rf"):
            with self.subTest(text=text):
                with self.assertRaises(CommandError):
                    parse_ref(text)
        self.assertEqual(parse_ref(" (ref 7F3A9C21) "), "7f3a9c21")

    def test_ref_and_last_cannot_be_given_together(self):
        log = self.write_log("a.jsonl", [])
        self.assertEqual(run_cli("explain", log, "--ref", "12345678", "--last", "2")[0], 2)

    def test_a_missing_log_is_an_error(self):
        code, _, err = run_cli("explain", self.folder / "none.jsonl")
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", err)


class HostileLogs(TempFolderTest):
    def test_odd_records_are_explained_without_crashing_or_escapes(self):
        records = [
            {"time": "t", "event": "call", "tool": "evil\x1b[2J", "action": "block", "rule": "default\x1b[31m",
             "matched_arg": "\x07", "reason": "r‮", "args": "[123 characters of arguments not logged]"},
            {"event": "call", "tool": ["not", "text"], "action": "block", "rule": {"a": 1}, "args": [1, 2]},
            {"event": "call", "tool": "t", "action": "block", "rule": "tools." + "x" * 5000, "args": {"a": 1}},
            {"event": "call", "tool": "t", "action": "block", "rule": "deny_args[" + "9" * 5000 + "]"},
            {"event": "result", "tool": "t", "action": "block", "rule": "injection",
             "findings": [None, {"rule": "\x1b", "severity": 5, "excerpt": ["x"]}, *([{}] * 20)]},
            {"event": "call", "tool": "t", "action": "block", "rule": "default", "args": "[not logged]"},
            "[" * 100_000,
            "not json",
        ]
        log = self.write_log("audit.jsonl", records)
        for options in ([], ["--policy", EXAMPLE]):
            with self.subTest(options=options):
                code, out, err = run_cli("explain", log, "--last", "10", *options)
                self.assertEqual(code, 0, err)
                self.assertNotIn("\x1b", out)
                self.assertNotIn("\x07", out)
                self.assertNotIn("‮", out)
                self.assertIn("2 line(s) of the log could not be read", out)
                self.assertIn("findings:    [5     ] \\x1b", out)
                self.assertEqual("cannot check the call again" in out, bool(options))

    def test_a_ref_shared_by_very_many_records_shows_a_bounded_number(self):
        record = {"event": "call", "tool": "t", "action": "block", "rule": "default", "ref": "aaaaaaaa"}
        log = self.write_log("audit.jsonl", [record] * (MAX_REF_MATCHES + 5))
        _, out, _ = run_cli("explain", log, "--ref", "aaaaaaaa")
        self.assertIn(f"{MAX_REF_MATCHES + 5} records have ref aaaaaaaa; the first {MAX_REF_MATCHES} are shown", out)
        self.assertEqual(out.count("ref aaaaaaaa  "), MAX_REF_MATCHES)

    def test_a_log_from_before_rule_ids_is_explained_from_its_reason(self):
        old = {"time": "t", "event": "call", "tool": "read_file", "action": "block",
               "reason": "an argument has a value the policy denies"}
        _, out, _ = run_cli("explain", self.write_log("audit.jsonl", [json.dumps(old)]))
        self.assertIn("(not named: a log written before 0.5)", out)
        self.assertIn("names no rule", out)


if __name__ == "__main__":
    unittest.main()
