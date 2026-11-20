"""Tests for flow rules: labels in tool rules, the "flows" section, and how
the firewall and the proxy set marks and apply the rules.

The attack these rules exist for: the agent reads an attacker's web page,
then reads a private file, then sends what it read somewhere. Each call is
harmless alone.
"""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from support import INJECTION, without_ref
from test_proxy import Harness, call, request, text_result
from agent_sentinel import BlockedError, Firewall, Policy, PolicyError
from agent_sentinel.policy import NOT_PERMITTED, FlowRule, ToolRule
from agent_sentinel.session import FileSessionStore, MemorySessionStore, SessionMarks, SessionStateError

TOOLS = {
    "fetch_page": {"action": "allow", "labels": ["untrusted"]},
    "read_file": {"action": "allow", "labels": ["private"]},
    "send_email": {"action": "allow", "labels": ["sink"]},
    "search_notes": "allow",
}
TRIFECTA = [
    {"after": ["untrusted"], "then": "sink", "action": "ask"},
    {"after": ["untrusted", "private"], "then": "sink", "action": "block"},
]


def flow_policy(tools=None, flows=None, **more):
    return Policy.from_dict({"tools": TOOLS if tools is None else tools, "flows": TRIFECTA if flows is None else flows,
                             **more})


def load_error(data):
    """The message of the error that loading `data` must raise."""
    try:
        Policy.from_dict(data)
    except PolicyError as exc:
        return str(exc)
    raise AssertionError("the policy loaded, but an error was expected")


def read_audit(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]


# ---- the policy file ----------------------------------------------------------------

class FlowsInThePolicyFile(unittest.TestCase):
    def test_labels_and_flows_load(self):
        policy = flow_policy()
        self.assertEqual(policy.flows[1], FlowRule(("untrusted", "private"), "sink", "block"))
        self.assertEqual(policy.tool_labels("fetch_page"), {"untrusted"})
        self.assertTrue(policy.classify_by_annotations)

    def test_then_defaults_to_sink(self):
        policy = flow_policy(flows=[{"after": ["untrusted"], "action": "block"}])
        self.assertEqual(policy.flows[0].then, "sink")

    def test_without_flows_nothing_changes(self):
        policy = Policy.from_dict({"tools": {"x": "allow"}})
        self.assertEqual(policy.flows, ())
        self.assertIsNone(policy.flow_verdict("x", ["untrusted"]))

    def test_mistakes_in_flows_are_errors(self):
        cases = {
            "flows must be a list": {"flows": {"after": ["untrusted"]}},
            "flows[0] must be a JSON object": {"flows": ["untrusted"]},
            "did you mean 'after'": {"flows": [{"afte": ["untrusted"], "action": "block"}]},
            "needs 'after'": {"flows": [{"then": "sink", "action": "block"}]},
            "needs 'after' (a list of labels) and 'action'": {"flows": [{"after": ["untrusted"]}]},
            "must name at least one label": {"flows": [{"after": [], "action": "block"}]},
            "'sink' describes what a tool does": {"flows": [{"after": ["sink"], "action": "block"}]},
            # A misspelt label is valid (custom labels exist): the warnings catch it. Capitals are not.
            "did you mean 'untrusted'?": {"flows": [{"after": ["Untrusted"], "action": "block"}]},
            "flows[0].after must be a list of labels": {"flows": [{"after": "untrusted", "action": "block"}]},
            "flows[0].then must be a label": {"flows": [{"after": ["untrusted"], "then": ["sink"], "action": "block"}]},
            "a flow rule can only add a restriction": {"flows": [{"after": ["untrusted"], "action": "allow"}]},
            "did you mean 'block'?": {"flows": [{"after": ["untrusted"], "action": "deny"}]},
            "listed twice": {"flows": [{"after": ["private", "private"], "action": "block"}]},
        }
        for expected, data in cases.items():
            with self.subTest(expected=expected):
                self.assertIn(expected, load_error(data))

    def test_mistakes_in_tool_labels_are_errors(self):
        cases = {
            "tools.x.labels must be a list of labels": {"x": {"action": "allow", "labels": "untrusted"}},
            "these words are written|must be a label": {"x": {"action": "allow", "labels": ["Untrusted"]}},
            "listed twice": {"x": {"action": "allow", "labels": ["sink", "sink"]}},
            "got 7": {"x": {"action": "allow", "labels": [7]}},
        }
        for expected, tools in cases.items():
            with self.subTest(expected=expected):
                self.assertRegex(load_error({"tools": tools}), expected)

    def test_classify_by_annotations_must_be_true_or_false(self):
        self.assertIn("true or false", load_error({"classify_by_annotations": "yes"}))
        self.assertFalse(Policy.from_dict({"classify_by_annotations": False}).classify_by_annotations)

    def test_a_hostile_label_is_refused_quickly_with_a_short_message(self):
        message = load_error({"tools": {"x": {"action": "allow", "labels": ["u" * 1_000_000]}}})
        self.assertLess(len(message), 600)

    def test_rules_built_in_code_are_checked_too(self):
        with self.assertRaises(PolicyError):
            Policy(flows=(FlowRule(("untrusted",), "sink", "allow"),))
        with self.assertRaises(PolicyError):
            Policy(flows=(FlowRule((), "sink", "block"),))
        with self.assertRaises(PolicyError):
            Policy(tools=[ToolRule("x", "allow", labels=("Bad",))])
        policy = Policy(flows=(FlowRule(["untrusted"], "sink", "block"),))  # a list is accepted
        self.assertEqual(policy.flows[0].after, ("untrusted",))


class FlowVerdicts(unittest.TestCase):
    def setUp(self):
        self.policy = flow_policy()

    def test_nothing_applies_before_anything_was_read(self):
        self.assertEqual(self.policy.evaluate("send_email", {}, marks=[]).action, "allow")

    def test_untrusted_content_makes_a_sink_ask_and_private_data_too_makes_it_block(self):
        asked = self.policy.evaluate("send_email", {}, marks=["untrusted"])
        refused = self.policy.evaluate("send_email", {}, marks=["untrusted", "private"])
        self.assertEqual((asked.action, asked.rule), ("ask", "flows[0]"))
        self.assertEqual((refused.action, refused.rule), ("block", "flows[1]"))

    def test_tools_that_are_not_the_target_are_not_affected(self):
        for tool in ("fetch_page", "read_file", "search_notes"):
            with self.subTest(tool=tool):
                self.assertEqual(self.policy.evaluate(tool, {}, marks=["untrusted", "private"]).action, "allow")

    def test_without_marks_the_flows_are_left_out(self):
        self.assertEqual(self.policy.evaluate("send_email", {}).rule, "tools.send_email")

    def test_a_flow_never_lifts_a_block_by_the_rules(self):
        policy = flow_policy(tools={**TOOLS, "send_email": {"action": "block", "labels": ["sink"]}})
        verdict = policy.evaluate("send_email", {}, marks=["untrusted"])
        self.assertEqual((verdict.action, verdict.rule), ("block", "tools.send_email"))

    def test_an_argument_block_still_names_the_argument(self):
        tools = {**TOOLS, "send_email": {"action": "allow", "labels": ["sink"],
                                         "allow_args": [{"arg": "to", "ends_with": "@example.com"}]}}
        verdict = flow_policy(tools=tools).evaluate("send_email", {"to": "x@evil.example"}, marks=["untrusted"])
        self.assertEqual(verdict.matched_arg, "to")

    def test_a_flow_that_asks_wins_a_tie_with_a_rule_that_asks(self):
        policy = flow_policy(tools={**TOOLS, "send_email": {"action": "ask", "labels": ["sink"]}})
        self.assertEqual(policy.evaluate("send_email", {}, marks=["untrusted"]).rule, "flows[0]")

    def test_the_first_of_equally_strict_flows_names_itself(self):
        flows = [{"after": ["private"], "action": "block"}, {"after": ["untrusted"], "action": "block"}]
        verdict = flow_policy(flows=flows).evaluate("send_email", {}, marks=["untrusted", "private"])
        self.assertEqual(verdict.rule, "flows[0]")

    def test_labels_add_up_over_exact_and_wildcard_rules(self):
        tools = {"post_*": {"action": "allow", "labels": ["sink"]}, "post_draft": "allow"}
        policy = flow_policy(tools=tools)
        # The exact rule decides the action, but it does not drop the wildcard's label.
        self.assertEqual(policy.tool_labels("post_draft"), {"sink"})
        self.assertEqual(policy.evaluate("post_draft", {}, marks=["untrusted", "private"]).action, "block")

    def test_then_can_be_any_label(self):
        tools = {**TOOLS, "fetch_page": {"action": "allow", "labels": ["untrusted", "web"]}}
        policy = flow_policy(tools=tools, flows=[{"after": ["private"], "then": "web", "action": "block"}])
        self.assertEqual(policy.evaluate("fetch_page", {}, marks=["private"]).action, "block")
        self.assertEqual(policy.evaluate("send_email", {}, marks=["private"]).action, "allow")

    def test_extra_labels_count_like_the_policy_s_own(self):
        verdict = self.policy.evaluate("search_notes", {}, marks=["untrusted", "private"], extra_labels={"sink"})
        self.assertEqual(verdict.action, "block")

    def test_a_session_that_cannot_be_trusted_applies_every_flow(self):
        verdict = self.policy.evaluate("send_email", {}, marks=SessionMarks.untrusted("the file is missing"))
        self.assertEqual(verdict.action, "block")
        self.assertIn("the file is missing", verdict.reason)

    def test_the_agent_is_told_nothing_about_flows(self):
        verdict = self.policy.evaluate("send_email", {}, marks=["untrusted", "private"])
        self.assertEqual(verdict.public, NOT_PERMITTED)

    def test_the_reason_says_what_was_read_where_from_and_when(self):
        store = MemorySessionStore()
        store.add(["untrusted"], "fetch_page")
        store.add(["private"], "read\x1b[31m_file")
        verdict = self.policy.evaluate("send_email", {}, marks=store.read())
        self.assertIn("'untrusted' content from 'fetch_page' at 20", verdict.reason)
        self.assertNotIn("\x1b", verdict.reason)  # tool names may be chosen by a server
        self.assertIn("'send_email' is labelled 'sink'", verdict.reason)

    def test_a_tool_name_that_is_not_text_has_no_labels(self):
        self.assertEqual(self.policy.tool_labels(None), frozenset())
        self.assertIsNone(self.policy.flow_verdict(["send_email"], ["untrusted"]))


class FlowWarnings(unittest.TestCase):
    def test_a_clean_flow_policy_has_no_warnings(self):
        # Since 0.6 every allowed tool says its labels, and one that fetches is also a sink.
        tools = {**TOOLS, "fetch_page": {"action": "allow", "labels": ["untrusted", "sink"]},
                 "search_notes": {"action": "allow", "labels": ["private"]}}
        self.assertEqual(flow_policy(tools=tools).warnings(), [])
        warnings = flow_policy().warnings()
        self.assertEqual(len(warnings), 2)
        self.assertIn("tools.fetch_page: it is labelled 'untrusted' but not 'sink'", warnings[0])
        self.assertIn("tools.search_notes: it is allowed but has no flow labels", warnings[1])

    def test_a_label_no_rule_has_is_reported_with_a_suggestion(self):
        tools = {"fetch": {"action": "allow", "labels": ["web-content"]},
                 "send": {"action": "allow", "labels": ["sink"]}}
        warnings = flow_policy(tools=tools, flows=[{"after": ["web_content"], "action": "block"}]).warnings()
        self.assertTrue(any("no tool rule has the label 'web_content'" in w and "'web-content'" in w for w in warnings))

    def test_untrusted_and_sink_may_come_from_annotations(self):
        policy = flow_policy(tools={"read_file": {"action": "allow", "labels": ["private"]}})
        self.assertEqual(policy.warnings(), [])
        without = flow_policy(tools={"read_file": {"action": "allow", "labels": ["private"]}},
                              classify_by_annotations=False)
        self.assertTrue(any("'untrusted'" in w for w in without.warnings()))

    def test_a_tool_label_no_flow_uses_is_reported(self):
        tools = {**TOOLS, "get_issue": {"action": "allow", "labels": ["untrsted"]}}
        warnings = flow_policy(tools=tools).warnings()
        self.assertIn("tools.get_issue.labels: no flow rule uses the label 'untrsted'; did you mean 'untrusted'?",
                      warnings)

    def test_a_tool_that_a_flow_locks_after_one_use_is_reported(self):
        tools = {**TOOLS, "github_*": {"action": "allow", "labels": ["untrusted", "private", "sink"]}}
        warnings = flow_policy(tools=tools).warnings()
        self.assertTrue(any(w.startswith("tools.github_*: it has the labels") and "flows[1]" in w for w in warnings))

    def test_describe_rule_explains_a_flow(self):
        self.assertEqual(
            flow_policy().describe_rule("flows[1]"),
            "flow rule: after 'untrusted' and 'private' content reached the agent, a call to a tool labelled 'sink' "
            "is refused",
        )
        self.assertIsNone(flow_policy().describe_rule("flows[9]"))


# ---- the firewall ---------------------------------------------------------------------

def page(url):
    return "Lentil soup recipe."


def read(path):
    return "my private notes"


class FlowsInTheFirewall(unittest.TestCase):
    def setUp(self):
        self.firewall = Firewall(flow_policy())

    def test_a_sink_is_refused_after_untrusted_content_and_private_data_were_delivered(self):
        self.assertTrue(self.firewall.check_call("send_email", {}).allowed)
        self.firewall.run("fetch_page", {"url": "u"}, page)
        self.firewall.run("read_file", {"path": "p"}, read)
        decision = self.firewall.check_call("send_email", {})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule, "flows[1]")
        self.assertEqual(without_ref(decision.public_reason), NOT_PERMITTED)

    def test_a_flow_ask_goes_to_the_approver_with_the_reason(self):
        seen = []
        firewall = Firewall(flow_policy(), approver=lambda tool, args, reason: seen.append(reason) or True)
        firewall.run("fetch_page", {"url": "u"}, page)
        self.assertTrue(firewall.check_call("send_email", {}).allowed)
        self.assertIn("'untrusted' content from 'fetch_page'", seen[0])

    def test_a_refused_call_sets_no_marks(self):
        firewall = Firewall(flow_policy(tools={**TOOLS, "fetch_page": {"action": "block", "labels": ["untrusted"]}}))
        with self.assertRaises(BlockedError):
            firewall.run("fetch_page", {"url": "u"}, page)
        self.assertEqual(firewall.session_marks().labels, frozenset())

    def test_a_withheld_result_sets_no_marks(self):
        with self.assertRaises(BlockedError):
            self.firewall.run("fetch_page", {"url": "u"}, lambda url: INJECTION)
        self.assertEqual(self.firewall.session_marks().labels, frozenset())

    def test_an_error_that_reaches_the_caller_sets_marks(self):
        def failing(url):
            raise ValueError("502 from the upstream page")

        with self.assertRaises(ValueError):
            self.firewall.run("fetch_page", {"url": "u"}, failing)
        self.assertEqual(self.firewall.session_marks().labels, {"untrusted"})

    def test_an_error_that_is_withheld_sets_no_marks(self):
        def failing(url):
            raise ValueError(INJECTION)

        with self.assertRaises(BlockedError):
            self.firewall.run("fetch_page", {"url": "u"}, failing)
        self.assertEqual(self.firewall.session_marks().labels, frozenset())

    def test_run_async_sets_marks_too(self):
        async def fetch(url):
            return "page"

        asyncio.run(self.firewall.run_async("fetch_page", {"url": "u"}, fetch))
        self.assertEqual(self.firewall.session_marks().labels, {"untrusted"})

    def test_scanning_alone_sets_no_marks_and_mark_delivered_does(self):
        self.assertTrue(self.firewall.scan_result("fetch_page", "page").allowed)
        self.assertEqual(self.firewall.session_marks().labels, frozenset())
        self.firewall.mark_delivered("fetch_page")
        self.assertEqual(self.firewall.session_marks().labels, {"untrusted"})
        self.firewall.mark_delivered("file:///notes.txt", {"private"})  # marks worked out earlier, any cause text
        self.assertEqual(self.firewall.session_marks().marks["private"].tool, "file:///notes.txt")

    def test_marks_for_leaves_out_sink(self):
        firewall = Firewall(flow_policy(tools={"fetch": {"action": "allow", "labels": ["untrusted", "sink"]}}))
        self.assertEqual(firewall.tool_labels("fetch"), {"untrusted", "sink"})
        self.assertEqual(firewall.marks_for("fetch"), {"untrusted"})

    def test_without_flows_no_marks_are_kept(self):
        store = MemorySessionStore()
        firewall = Firewall(Policy.from_dict({"tools": TOOLS}), session_store=store)
        firewall.run("fetch_page", {"url": "u"}, page)
        self.assertEqual(store.read().labels, frozenset())

    def test_monitor_mode_logs_a_flow_block_as_would_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "audit.jsonl"
            firewall = Firewall(flow_policy(), audit_path=audit, monitor=True)
            firewall.run("fetch_page", {"url": "u"}, page)
            firewall.run("read_file", {"path": "p"}, read)
            self.assertTrue(firewall.check_call("send_email", {}).allowed)
            record = read_audit(audit)[-1]
        self.assertEqual((record["action"], record["rule"]), ("would_block", "flows[1]"))

    def test_a_flow_block_is_audited_with_its_rule_and_the_cause(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / "audit.jsonl"
            firewall = Firewall(flow_policy(), audit_path=audit)
            firewall.run("fetch_page", {"url": "u"}, page)
            firewall.run("read_file", {"path": "p"}, read)
            decision = firewall.check_call("send_email", {"to": "a@example.com"})
            record = read_audit(audit)[-1]
        self.assertEqual((record["action"], record["rule"], record["ref"]), ("block", "flows[1]", decision.ref))
        self.assertIn("from 'read_file'", record["reason"])

    def test_a_store_that_cannot_record_withholds_the_result(self):
        class Broken(MemorySessionStore):
            def add(self, labels, tool):
                raise SessionStateError("disk full")

        firewall = Firewall(flow_policy(), session_store=Broken())
        with self.assertRaises(BlockedError) as caught:
            firewall.run("fetch_page", {"url": "u"}, page)
        self.assertEqual(caught.exception.decision.rule, "session")
        self.assertNotIn("session", str(caught.exception))  # the agent learns nothing about tracking
        self.assertNotIn("disk full", str(caught.exception))

    def test_a_store_that_cannot_be_read_applies_every_flow(self):
        class Unreadable(MemorySessionStore):
            def read(self):
                raise RuntimeError("bug")

        decision = Firewall(flow_policy(), session_store=Unreadable()).check_call("send_email", {})
        self.assertEqual((decision.allowed, decision.rule), (False, "flows[1]"))


class MarksFromAnnotations(unittest.TestCase):
    def test_annotations_add_labels(self):
        firewall = Firewall(flow_policy(tools={"read_file": {"action": "allow", "labels": ["private"]},
                                               "web_fetch": "allow", "post": "allow"}))
        firewall.learn_annotations("web_fetch", {"openWorldHint": True, "readOnlyHint": True})
        firewall.learn_annotations("post", {"destructiveHint": True})
        self.assertEqual(firewall.tool_labels("web_fetch"), {"untrusted", "sink"})
        firewall.run("web_fetch", {"url": "u"}, page)
        firewall.run("read_file", {"path": "p"}, read)
        self.assertEqual(firewall.check_call("post", {}).rule, "flows[1]")
        self.assertEqual(firewall.check_call("web_fetch", {}).rule, "flows[1]")  # it is a sink too

    def test_annotations_can_only_add_labels(self):
        firewall = Firewall(flow_policy())
        firewall.learn_annotations("fetch_page", {"openWorldHint": True})
        firewall.learn_annotations("fetch_page", {"openWorldHint": False, "readOnlyHint": True})
        self.assertEqual(firewall.tool_labels("fetch_page"), {"untrusted", "sink"})

    def test_annotations_are_ignored_when_the_policy_says_so(self):
        firewall = Firewall(flow_policy(classify_by_annotations=False))
        firewall.learn_annotations("search_notes", {"openWorldHint": True})
        self.assertEqual(firewall.tool_labels("search_notes"), frozenset())

    def test_more_annotated_tools_than_can_be_remembered_makes_unknown_tools_untrusted_sinks(self):
        from agent_sentinel import firewall as firewall_module

        firewall = Firewall(flow_policy())
        original = firewall_module.MAX_ANNOTATED_TOOLS
        firewall_module.MAX_ANNOTATED_TOOLS = 2
        try:
            for name in ("a", "b", "c"):
                firewall.learn_annotations(name, {"destructiveHint": True})
        finally:
            firewall_module.MAX_ANNOTATED_TOOLS = original
        self.assertEqual(firewall.tool_labels("a"), {"sink"})
        self.assertEqual(firewall.tool_labels("c"), {"untrusted", "sink"})
        self.assertEqual(firewall.tool_labels("never_listed"), {"untrusted", "sink"})


class OneSessionAcrossProcesses(unittest.TestCase):
    """Hook mode: each check is a new process, so each gets a new Firewall over the same file store."""

    def test_marks_set_by_one_firewall_refuse_a_call_in_the_next(self):
        with tempfile.TemporaryDirectory() as tmp:
            FileSessionStore(tmp, "claude-session-1").begin()

            def firewall():
                store = FileSessionStore(tmp, "claude-session-1")
                return Firewall(flow_policy(), session_id="claude-session-1", session_store=store)

            firewall().run("fetch_page", {"url": "u"}, page)
            firewall().run("read_file", {"path": "p"}, read)
            self.assertEqual(firewall().check_call("send_email", {}).rule, "flows[1]")
            # Another session is not affected.
            other = FileSessionStore(tmp, "claude-session-2")
            other.begin()
            self.assertTrue(Firewall(flow_policy(), session_store=other).check_call("send_email", {}).allowed)

    def test_a_deleted_session_file_refuses_sinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = FileSessionStore(tmp, "s")
            store.begin()
            store.path.unlink()
            decision = Firewall(flow_policy(), session_store=FileSessionStore(tmp, "s")).check_call("send_email", {})
        self.assertEqual(decision.rule, "flows[1]")
        self.assertIn("missing", decision.reason)


# ---- the proxy: one proxy process is one session ------------------------------------

class FlowsInTheProxy(unittest.TestCase):
    def setUp(self):
        self.h = Harness(Firewall(flow_policy()))

    def test_a_sink_call_is_refused_after_untrusted_and_private_results_were_delivered(self):
        self.h.round_trip(call(1, "fetch_page", {"url": "u"}), text_result("a page"))
        self.h.round_trip(call(2, "read_file", {"path": "p"}), text_result("secret plans"))
        self.h.from_client(call(3, "send_email", {"to": "x@evil.example"}))
        self.assertEqual(self.h.sent_to_server(), [])  # never reaches the server
        (refusal,) = self.h.sent_to_client()
        self.assertTrue(refusal["result"]["isError"])
        self.assertIn(NOT_PERMITTED, refusal["result"]["content"][0]["text"])

    def test_a_flow_ask_is_refused_in_the_proxy_without_an_approver(self):
        self.h.round_trip(call(1, "fetch_page", {"url": "u"}), text_result("a page"))
        self.h.from_client(call(2, "send_email", {}))
        self.assertEqual(self.h.sent_to_server(), [])

    def test_a_blocked_result_sets_no_marks(self):
        delivered = self.h.round_trip(call(1, "fetch_page", {"url": "u"}), text_result(INJECTION))
        self.assertTrue(delivered["result"]["isError"])
        self.assertEqual(self.h.firewall.session_marks().labels, frozenset())

    def test_a_call_that_is_never_answered_sets_no_marks(self):
        self.h.from_client(call(1, "fetch_page", {"url": "u"}))
        self.assertEqual(self.h.firewall.session_marks().labels, frozenset())

    def test_an_error_reply_sets_marks(self):
        self.h.from_client(call(1, "fetch_page", {"url": "u"}))
        self.h.sent_to_server()
        self.h.from_server({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "upstream said no"}})
        self.assertEqual(self.h.firewall.session_marks().labels, {"untrusted"})

    def test_annotations_from_the_tool_list_label_the_tools(self):
        tools = [
            {"name": "web_fetch", "description": "Fetch a URL.", "annotations": {"openWorldHint": True}},
            {"name": "search_notes", "description": "Search my notes."},
        ]
        self.h.round_trip(request(1, "tools/list"), {"tools": tools})
        self.assertEqual(self.h.firewall.tool_labels("web_fetch"), {"untrusted", "sink"})
        self.assertEqual(self.h.firewall.tool_labels("search_notes"), frozenset())

    def test_a_removed_tool_teaches_the_firewall_nothing(self):
        tools = [{"name": "web_fetch", "description": INJECTION, "annotations": {"openWorldHint": True}}]
        self.h.round_trip(request(1, "tools/list"), {"tools": tools})
        self.assertEqual(self.h.firewall.tool_labels("web_fetch"), frozenset())

    def test_resource_reads_mark_with_the_labels_of_the_resources_read_rule(self):
        tools = {**TOOLS, "resources/read": {"action": "allow", "labels": ["private"]}}
        h = Harness(Firewall(flow_policy(tools=tools)))
        h.round_trip(request(1, "resources/subscribe", {"uri": "file:///a"}), {})
        self.assertEqual(h.firewall.session_marks().labels, frozenset())  # a subscription returns no content
        h.round_trip(request(2, "resources/read", {"uri": "file:///notes.txt"}),
                     {"contents": [{"uri": "file:///notes.txt", "text": "notes"}]})
        marks = h.firewall.session_marks()
        self.assertEqual(marks.labels, {"private"})
        self.assertEqual(marks.marks["private"].tool, "file:///notes.txt")

    def test_other_replies_set_no_marks(self):
        self.h.round_trip(request(1, "prompts/list"), {"prompts": []})
        self.assertEqual(self.h.firewall.session_marks().labels, frozenset())

    def test_a_reply_whose_marks_cannot_be_recorded_is_withheld(self):
        class Broken(MemorySessionStore):
            def add(self, labels, tool):
                raise SessionStateError("disk full")

        h = Harness(Firewall(flow_policy(), session_store=Broken()))
        delivered = h.round_trip(call(1, "fetch_page", {"url": "u"}), text_result("a page"))
        self.assertTrue(delivered["result"]["isError"])
        self.assertNotIn("a page", json.dumps(delivered))
        self.assertIn("withheld a reply", h.warnings.getvalue())


if __name__ == "__main__":
    unittest.main()
