"""Tests for what the proxy tells the operator on stderr (proxy_report.py and its use in mcp_proxy.py).

The startup summary, one line per block with the rule and the reference,
--quiet and --verbose, the limit on lines about traffic, and the advice for a
policy file that is not found. The last classes start the real proxy, and
one of them approves calls through a real --approve-with command.
"""

import contextlib
import io
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from support import EXAMPLE_POLICY_PATH, INJECTION, POLICY, ROOT
from test_approvers import write_program
from test_proxy import Harness, call, reply, request, text_result
from agent_sentinel import Firewall, Policy, __version__, mcp_proxy, proxy_report
from agent_sentinel.proxy_report import LineBudget, Startup, missing_policy_hint, startup_lines

FAKE_SERVER = ROOT / "examples" / "fake_mcp_server.py"


# ---- the line budget --------------------------------------------------------------------------------

class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class TheLineBudget(unittest.TestCase):
    def setUp(self):
        self.lines = []
        self.clock = Clock()
        self.budget = LineBudget(lambda text, limit: self.lines.append(text), has_audit=True, limit=3, window=10,
                                 clock=self.clock)

    def test_lines_past_the_limit_are_left_out_with_one_notice(self):
        for n in range(10):
            self.budget.line(f"block {n}")
        self.assertEqual(self.lines[:3], ["block 0", "block 1", "block 2"])
        self.assertEqual(len(self.lines), 4)
        self.assertIn("more than 3 lines in 10 seconds", self.lines[3])
        self.assertIn("the audit log has every block", self.lines[3])

    def test_the_next_window_starts_by_saying_how_many_were_left_out(self):
        for n in range(10):
            self.budget.line(f"block {n}")
        self.clock.now += 10
        self.budget.line("later")
        self.assertIn("left out 7 line(s)", self.lines[4])
        self.assertEqual(self.lines[5], "later")

    def test_flush_says_how_many_were_left_out_and_nothing_when_none_were(self):
        self.budget.flush()
        self.assertEqual(self.lines, [])
        for n in range(5):
            self.budget.line(f"block {n}")
        self.budget.flush()
        self.assertIn("left out 2 line(s)", self.lines[-1])
        self.budget.flush()
        self.assertEqual(sum(line.startswith("left out") for line in self.lines), 1)

    def test_without_an_audit_log_the_notice_says_how_to_keep_them(self):
        lines = []
        budget = LineBudget(lambda text, limit: lines.append(text), has_audit=False, limit=1)
        budget.line("a")
        budget.line("b")
        self.assertIn("--audit FILE", lines[-1])

    def test_lines_from_many_threads_are_counted_exactly(self):
        budget = LineBudget(lambda text, limit: self.lines.append(text), has_audit=True, limit=20, window=60)
        threads = [threading.Thread(target=lambda: [budget.line("x") for _ in range(50)]) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        budget.flush()
        self.assertEqual(self.lines.count("x"), 20)
        self.assertIn("left out 380 line(s)", self.lines[-1])  # 400 lines, 20 shown


# ---- one line per block --------------------------------------------------------------------------------

class OneLinePerBlock(unittest.TestCase):
    def test_a_blocked_call_gets_a_line_with_the_rule_and_the_ref_the_agent_saw(self):
        h = Harness()
        h.from_client(call(1, "delete_file", {"path": "notes.txt"}))
        text = h.sent_to_client()[0]["result"]["content"][0]["text"]
        ref = text[-9:-1]
        self.assertIn(f"blocked tools/call 'delete_file': rule 'delete_*' says block [rule tools.delete_*, ref {ref}]",
                      h.warnings.getvalue())

    def test_a_secret_and_a_policy_wide_deny_are_reported_with_their_rules(self):
        h = Harness()
        h.from_client(call(1, "read_file", {"path": "~/.ssh/id_rsa"}))
        h.from_client(call(2, "read_file", {"path": "ghp_" + "a1B2c3D4e5" * 4}))
        output = h.warnings.getvalue()
        self.assertIn("[rule deny_args[0], ref ", output)
        self.assertIn("[rule secrets, ref ", output)
        self.assertNotIn("a1B2c3D4e5", output)  # the reason names the kind of secret, never the secret

    def test_a_blocked_result_gets_a_line_too(self):
        h = Harness()
        delivered = h.round_trip(call(1, "fetch_page", {"url": "u"}), text_result(INJECTION))
        ref = delivered["result"]["content"][0]["text"][-9:-1]
        self.assertRegex(h.warnings.getvalue(),
                         rf"blocked the reply to tools/call 'fetch_page': possible prompt injection \(.*\) "
                         rf"\[rule injection, ref {ref}\]")

    def test_a_refused_server_request_and_a_blocked_client_request_name_their_rules(self):
        h = Harness(Firewall(Policy.from_dict({"client_requests": {"logging/*": "block"},
                                               "server_requests": {"sampling/*": "block"}})))
        h.from_client(request(1, "logging/setLevel", {"level": "debug"}))
        h.from_server(request(9, "sampling/createMessage", {"messages": []}))
        output = h.warnings.getvalue()
        self.assertIn("blocked logging/setLevel: client_requests rule 'logging/*' says block "
                      "[rule client_requests.logging/*, ref ", output)
        self.assertIn("refused a 'sampling/createMessage' message from the server", output)
        self.assertIn("[rule server_requests.sampling/*, ref ", output)

    def test_too_many_requests_waiting_is_a_block_with_a_ref_a_line_and_a_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "audit.jsonl"
            h = Harness(Firewall(POLICY, audit_path=audit))
            with mock.patch.object(mcp_proxy, "MAX_PENDING_REQUESTS", 1):
                h.from_client(call(1, "read_file", {"path": "a"}))
                h.from_client(call(2, "read_file", {"path": "b"}))
            (refusal,) = h.sent_to_client()
            ref = refusal["result"]["content"][0]["text"][-9:-1]
            records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
        self.assertIn(f"too many requests are waiting for a reply [rule malformed, ref {ref}]", h.warnings.getvalue())
        self.assertEqual(records[-1]["ref"], ref)

    def test_an_internal_error_reply_carries_a_ref_the_audit_log_has(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "audit.jsonl"
            h = Harness(Firewall(POLICY, audit_path=audit))
            with mock.patch.object(Firewall, "check_call", side_effect=RuntimeError("bug")):
                h.from_client(call(1, "read_file", {"path": "a"}))
            h.from_client(call(2, "read_file", {"path": "a"}))
            h.sent_to_server()
            with mock.patch.object(Firewall, "check_result", side_effect=RuntimeError("bug")):
                h.from_server(reply(2, text_result("hello")))
            first, second = (m["error"]["message"] for m in h.sent_to_client())
            refs = {json.loads(line).get("ref") for line in audit.read_text(encoding="utf-8").splitlines()}
        self.assertRegex(first, r"internal error while checking the request \(ref [0-9a-f]{8}\)\Z")
        self.assertRegex(second, r"internal error while checking the reply \(ref [0-9a-f]{8}\)\Z")
        self.assertTrue({first[-9:-1], second[-9:-1]} <= refs)

    def test_a_hostile_tool_name_cannot_carry_escape_codes_into_the_line(self):
        h = Harness()
        h.from_client(call(1, "delete\x1b[2J‮_file", {}))
        self.assertIn("blocked tools/call 'delete\\x1b[2J\\u202e_file'", h.warnings.getvalue())

    def test_a_flood_of_blocks_is_cut_to_twenty_lines_and_the_rest_counted(self):
        h = Harness()
        for n in range(30):
            h.from_client(call(n, "delete_file", {"path": "x"}))
        lines = h.warnings.getvalue().splitlines()
        self.assertEqual(sum("blocked tools/call" in line for line in lines), proxy_report.LINES_PER_WINDOW)
        self.assertIn("the next ones are left out", lines[-1])
        stopping = io.StringIO()
        with contextlib.redirect_stderr(stopping):
            h.proxy.close_report()  # what the proxy says when it stops
        self.assertIn("left out 10 line(s)", stopping.getvalue())


class QuietAndVerbose(unittest.TestCase):
    def test_quiet_leaves_out_blocks_and_notices_but_not_errors(self):
        h = Harness(report=proxy_report.QUIET)
        h.from_client(call(1, "delete_file", {"path": "x"}))
        h.sent_to_client()
        h.round_trip(request(2, "tools/list"), {"tools": [{"name": "evil", "description": INJECTION}]})
        self.assertEqual(h.warnings.getvalue(), "")
        with mock.patch.object(Firewall, "check_call", side_effect=RuntimeError("bug")):
            h.from_client(call(3, "read_file", {"path": "a"}))
        self.assertIn("internal error", h.warnings.getvalue())

    def test_verbose_lists_every_call_let_through(self):
        h = Harness(report=proxy_report.VERBOSE)
        h.from_client(call(1, "read_file", {"path": "a"}))
        h.from_client(request(2, "resources/read", {"uri": "file:///notes.txt"}))
        output = h.warnings.getvalue()
        self.assertIn("allowed tools/call 'read_file' [rule tools.read_file]", output)
        self.assertIn("allowed resources/read 'file:///notes.txt' [rule tools.resources/read]", output)

    def test_normal_does_not_list_allowed_calls(self):
        h = Harness()
        h.from_client(call(1, "read_file", {"path": "a"}))
        self.assertEqual(h.warnings.getvalue(), "")

    def test_monitor_mode_says_what_it_would_have_blocked(self):
        h = Harness(Firewall(POLICY, monitor=True))
        h.from_client(call(1, "delete_file", {"path": "x"}))
        self.assertIn("would block tools/call 'delete_file' (monitor mode lets it through): rule 'delete_*' says "
                      "block [rule tools.delete_*]", h.warnings.getvalue())

    def test_an_unknown_level_is_refused(self):
        with self.assertRaises(ValueError):
            Harness(report="loud")


# ---- the startup summary --------------------------------------------------------------------------------

def start(**changes):
    values = dict(version="9.9", name="files", policy_path=str(EXAMPLE_POLICY_PATH), policy=POLICY,
                  audit_path=str(ROOT / "audit.jsonl"), pins_path=None, pins_enabled=True,
                  server_command=["/usr/bin/node", "server.js"])
    values.update(changes)
    return Startup(**values)


class TheStartupSummary(unittest.TestCase):
    def test_it_names_the_version_the_name_the_policy_the_audit_log_the_pins_and_the_server(self):
        lines = startup_lines(start())
        self.assertEqual(lines[0], "proxy starting (agent-sentinel 9.9)")
        text = "\n".join(lines)
        self.assertIn("  name      files", text)
        self.assertIn(f"  policy    {EXAMPLE_POLICY_PATH}: default block, 7 tool rule(s) (4 allow, 1 ask, 2 block)",
                      text)
        self.assertIn("1 policy-wide deny rule(s), 1 flow rule(s), at most 120 calls a minute, injections blocked from "
                      "high", text)
        self.assertIn(f"  audit     {ROOT / 'audit.jsonl'}", text)
        self.assertIn("  pins      in memory", text)
        self.assertIn("  server    /usr/bin/node server.js", text)
        self.assertIn("  hidden    left out of the tool list, as the policy blocks them outright: delete_*, run_shell, "
                      "every tool without a rule", text)

    def test_ask_rules_without_an_approver_are_warned_about(self):
        text = "\n".join(startup_lines(start()))
        self.assertIn('warning: the policy says "ask" for send_email, and no --approve-with is given, so these calls '
                      "are refused", text)
        with_approver = "\n".join(startup_lines(start(approvers=[("dialog", None)], approval_timeout=60)))
        self.assertNotIn('says "ask"', with_approver)
        self.assertIn("  approval  dialog; no answer within 60 s refuses the call", with_approver)
        monitor = "\n".join(startup_lines(start(monitor=True)))
        self.assertNotIn('says "ask"', monitor)
        self.assertNotIn("hidden", monitor)

    def test_the_default_and_flows_that_ask_count_as_ask_rules(self):
        policy = Policy.from_dict({"default": "ask", "tools": {"send_mail": {"action": "allow", "labels": ["sink"]},
                                                               "fetch": {"action": "allow", "labels": ["untrusted"]}},
                                   "flows": [{"after": ["untrusted"], "action": "ask"}]})
        self.assertEqual(proxy_report.asks_in(policy), ["every tool without a rule", "flows[0]"])

    def test_an_approver_that_cannot_ask_here_is_warned_about(self):
        text = "\n".join(startup_lines(start(approvers=[("dialog", "no display is set"), ("command /x", None)])))
        self.assertIn("  approval  dialog, else command /x;", text)
        self.assertIn("warning: --approve-with dialog cannot ask on this machine: no display is set", text)

    def test_a_missing_audit_log_and_relative_paths_are_warned_about(self):
        text = "\n".join(startup_lines(start(audit_path=None, pins_path="pins.json", policy_path="policy.json")))
        self.assertIn("  audit     none", text)
        self.assertIn("warning: no --audit file, so blocked calls are reported here but recorded nowhere", text)
        self.assertIn("warning: the --policy path 'policy.json' is relative", text)
        self.assertIn("warning: the --pins path 'pins.json' is relative", text)
        self.assertIn(f"(now {os.getcwd()})", text)
        missing = "\n".join(startup_lines(start(audit_path=str(ROOT / "no_such_folder_xyz" / "audit.jsonl"))))
        self.assertIn("the folder of the --audit file does not exist", missing)

    def test_risky_policy_settings_are_warned_about(self):
        policy = Policy.from_dict({"default": "allow", "injection": {"block_severity": None},
                                   "secrets": {"in_arguments": "allow"}})
        text = "\n".join(startup_lines(start(policy=policy, approval_timeout_given=True)))
        for expected in ("text with injection findings is logged, never blocked",
                         'secrets.in_arguments is "allow"', 'warning: default is "allow"',
                         "--approval-timeout has no effect without --approve-with"):
            self.assertIn(expected, text)

    def test_no_pins_is_said_plainly(self):
        self.assertIn("  pins      off (--no-pins)", "\n".join(startup_lines(start(pins_enabled=False))))

    def test_a_token_in_the_server_command_is_not_copied_into_the_log(self):
        token = "ghp_" + "a1B2c3D4e5" * 4
        text = "\n".join(startup_lines(start(server_command=["/usr/bin/node", "server.js", "--token", token])))
        self.assertNotIn(token, text)
        self.assertIn("[redacted", text)

    def test_hostile_rule_names_are_made_printable(self):
        policy = Policy.from_dict({"tools": {"x\x1b[2J": "ask"}, "hide_blocked_tools": True})
        text = "\n".join(startup_lines(start(policy=policy)))
        self.assertNotIn("\x1b", text)


class AdviceForAMissingPolicy(unittest.TestCase):
    def test_a_relative_path_gets_advice_and_an_absolute_one_does_not(self):
        self.assertIn("MCP clients start servers in a folder of their own choosing", missing_policy_hint("policy.json"))
        self.assertIn(os.path.join(".agent-sentinel", "policy.json"), missing_policy_hint("policy.json"))
        # The folder `init` writes to, also when AGENT_SENTINEL_HOME moves it.
        moved = os.path.join(os.path.abspath(os.sep), "as-home-probe")
        with mock.patch.dict(os.environ, {"AGENT_SENTINEL_HOME": moved}):
            self.assertIn(os.path.join(moved, "policy.json"), missing_policy_hint("policy.json"))
        with mock.patch.dict(os.environ, {"AGENT_SENTINEL_HOME": "relative"}):
            self.assertIn("/full/path/to/policy.json", missing_policy_hint("policy.json"))
        self.assertIsNone(missing_policy_hint(str(ROOT / "nope.json")))


# ---- the real proxy -----------------------------------------------------------------------------------------

def run_proxy(proxy_args, messages=(), cwd=ROOT, server=FAKE_SERVER):
    """Run the real proxy in `cwd` (it finds the package through PYTHONPATH); return (replies, stderr, exit code)."""
    proc = subprocess.run(
        [sys.executable, "-m", "agent_sentinel", "proxy", *proxy_args, "--", sys.executable, str(server)],
        input="".join(json.dumps(m) + "\n" for m in messages).encode(), capture_output=True, cwd=cwd, timeout=60,
        env=dict(os.environ, PYTHONPATH=str(ROOT)),
    )
    replies = {m["id"]: m for m in map(json.loads, proc.stdout.decode().splitlines()) if "id" in m}
    return replies, proc.stderr.decode(errors="replace"), proc.returncode


class TheRealProxyReports(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.audit = str(Path(self.tmp.name) / "audit.jsonl")

    def test_the_summary_comes_first_and_every_line_is_labelled(self):
        _, stderr, code = run_proxy(["--policy", str(EXAMPLE_POLICY_PATH), "--name", "files", "--audit", self.audit],
                                    [call(1, "delete_file", {"path": "x"})])
        self.assertEqual(code, 0, stderr)
        lines = stderr.splitlines()
        self.assertEqual(lines[0], f"agent-sentinel[files]: proxy starting (agent-sentinel {__version__})")
        self.assertTrue(all(line.startswith("agent-sentinel[files]: ") for line in lines), stderr)
        self.assertIn(f"agent-sentinel[files]:   audit     {self.audit}", stderr)
        self.assertIn(f"{sys.executable}", stderr)

    def test_the_ref_in_the_block_line_is_the_one_the_agent_and_the_audit_log_have(self):
        replies, stderr, _ = run_proxy(["--policy", str(EXAMPLE_POLICY_PATH), "--audit", self.audit],
                                       [call(1, "delete_file", {"path": "x"})])
        ref = replies[1]["result"]["content"][0]["text"][-9:-1]
        self.assertIn(f"[rule tools.delete_*, ref {ref}]", stderr)
        records = [json.loads(line) for line in Path(self.audit).read_text(encoding="utf-8").splitlines()]
        self.assertIn(ref, [record.get("ref") for record in records])

    def test_quiet_prints_nothing_when_nothing_goes_wrong(self):
        replies, stderr, code = run_proxy(["--policy", str(EXAMPLE_POLICY_PATH), "--quiet"],
                                          [call(1, "delete_file", {"path": "x"}), call(2, "read_file", {"path": "a"})])
        self.assertEqual((code, stderr), (0, ""))
        self.assertTrue(replies[1]["result"]["isError"])

    def test_verbose_lists_allowed_calls(self):
        _, stderr, _ = run_proxy(["--policy", str(EXAMPLE_POLICY_PATH), "--verbose"],
                                 [call(1, "read_file", {"path": "a"})])
        self.assertIn("allowed tools/call 'read_file' [rule tools.read_file]", stderr)

    def test_quiet_and_verbose_cannot_be_given_together(self):
        _, stderr, code = run_proxy(["--policy", str(EXAMPLE_POLICY_PATH), "--quiet", "--verbose"])
        self.assertEqual(code, 2)
        self.assertIn("not allowed with argument", stderr)

    def test_a_relative_policy_that_is_not_found_gets_the_full_path_and_advice(self):
        _, stderr, code = run_proxy(["--policy", "no_such_policy.json"], cwd=self.tmp.name)
        self.assertEqual(code, 2)
        self.assertRegex(stderr, r"cannot load policy: there is no policy file at .*no_such_policy\.json "
                                 r"\(the current folder is .*\)")
        self.assertIn("MCP clients start servers in a folder of their own choosing", stderr)

    def test_an_absolute_policy_that_is_not_found_gets_no_advice_about_folders(self):
        _, stderr, code = run_proxy(["--policy", str(Path(self.tmp.name) / "nope.json")])
        self.assertEqual(code, 2)
        self.assertNotIn("MCP clients start servers", stderr)

    def test_bad_approval_flags_stop_the_proxy(self):
        program = write_program(self.tmp.name, "print('approve')\n")
        for args, expected in (
            (["--approve-with", "popup"], "argument --approve-with: unknown approver 'popup'"),
            (["--approve-with", "command:no_such_program_xyz"], "cannot find the program"),
            (["--approve-with", f"command:{os.path.join('rel', 'approve')}"], "relative path"),
            (["--approve-with", "dialog", "--approve-with", "dialog"], "--approve-with dialog is given twice"),
            (["--approve-with", f"command:{program}", "--approve-with", f"command:{program}"], "given twice"),
            (["--approval-timeout", "0"], "must be 1 to 3600 seconds"),
            (["--approval-timeout", "3601"], "must be 1 to 3600 seconds"),
            (["--approval-timeout", "soon"], "must be a whole number of seconds"),
        ):
            with self.subTest(args=args):
                _, stderr, code = run_proxy(["--policy", str(EXAMPLE_POLICY_PATH), *args])
                self.assertEqual(code, 2)
                self.assertIn(expected, stderr)


class ApprovingThroughARealCommand(unittest.TestCase):
    """The real proxy, the fake server and an approver program, talking as a client would (one message at a time)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def converse(self, approver_body, messages, expected_replies):
        program = write_program(self.tmp.name, approver_body)
        proc = subprocess.Popen(
            [sys.executable, "-m", "agent_sentinel", "proxy", "--policy", str(EXAMPLE_POLICY_PATH), "--name", "mail",
             "--approve-with", f"command:{program}", "--approval-timeout", "30",
             "--", sys.executable, str(FAKE_SERVER)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT,
        )
        lines = queue.Queue()
        threading.Thread(target=lambda: [lines.put(line) for line in proc.stdout], daemon=True).start()
        for message in messages:
            proc.stdin.write(json.dumps(message).encode() + b"\n")
        proc.stdin.flush()
        replies = {}
        try:
            while len(replies) < expected_replies:
                message = json.loads(lines.get(timeout=45))
                replies[message["id"]] = message
        finally:
            proc.stdin.close()
            stderr = proc.stderr.read().decode(errors="replace")
            proc.wait(timeout=30)
            proc.stdout.close()
            proc.stderr.close()
        return replies, stderr

    def test_a_program_that_approves_lets_the_call_through(self):
        replies, stderr = self.converse(
            "import json, sys\n"
            "request = json.loads(sys.stdin.readline())\n"
            "print('approve' if request['arguments'].get('to') == 'bob@example.com' else 'no')\n",
            [call(1, "send_email", {"to": "bob@example.com"}), call(2, "send_email", {"to": "amy@example.com"})],
            expected_replies=2,
        )
        self.assertFalse(replies[1]["result"]["isError"])
        self.assertTrue(replies[2]["result"]["isError"])
        self.assertIn("approved tools/call 'send_email'", stderr)
        self.assertIn("refused by command (the program did not print 'approve')", stderr)
        self.assertIn("  approval  command ", stderr)


if __name__ == "__main__":
    unittest.main()
