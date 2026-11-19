"""Tests for the MCP protocol revisions the proxy knows (mcp_protocol.py and the proxy code that uses it).

The 2026-07-28 revision has no handshake: every request names its protocol
version and the client's capabilities in params._meta, every result has a
resultType, a server asks the client for input inside its reply
("input_required" with inputRequests), subscriptions/listen replaces
resources/subscribe, and server/discover describes the server. Most tests
drive a Proxy through the Harness of test_proxy.py; the last class runs the
real proxy in front of examples/fake_mcp_server.py, in both eras.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import EXAMPLE_POLICY_PATH, INJECTION, POLICY, ROOT
from test_proxy import Harness, call, initialize, reply, request, text_result
from agent_sentinel import Firewall, Policy, mcp_proxy
from agent_sentinel import mcp_protocol as protocol

MODERN = "2026-07-28"
SECRET_TOKEN = "ghp_" + "a1B2c3D4e5" * 4

ELICITATION = {
    "method": "elicitation/create",
    "params": {"mode": "form", "message": "Which folder?",
               "requestedSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}},
}
SAMPLING = {
    "method": "sampling/createMessage",
    "params": {"messages": [{"role": "user", "content": {"type": "text", "text": "Summarise the chat."}}],
               "maxTokens": 100},
}
ROOTS = {"method": "roots/list"}


def modern(msg_id, method, params=None, version=MODERN, capabilities=None):
    """A 2026-07-28 request: its protocol version and the client's capabilities travel in params._meta."""
    params = dict(params or {})
    params["_meta"] = {protocol.PROTOCOL_VERSION_KEY: version, protocol.CLIENT_CAPABILITIES_KEY: capabilities or {}}
    return request(msg_id, method, params)


def modern_call(msg_id, name, arguments, **params):
    return modern(msg_id, "tools/call", {"name": name, "arguments": arguments, **params})


def input_required(requests=None, state="opaque-state"):
    """An input_required result; None leaves a member out."""
    result = {"resultType": "input_required"}
    if requests is not None:
        result["inputRequests"] = requests
    if state is not None:
        result["requestState"] = state
    return result


def complete(text):
    return dict(text_result(text), resultType="complete")


def read_audit(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]


class WithAnAuditLog(unittest.TestCase):
    """Tests whose Harness has a firewall that writes an audit log in a temporary folder."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.audit = Path(self.tmp.name) / "audit.jsonl"

    def harness(self, policy=POLICY, monitor=False):
        return Harness(Firewall(policy, audit_path=self.audit, monitor=monitor))

    def records(self):
        return read_audit(self.audit) if self.audit.exists() else []


# ---- protocol versions (C32) -------------------------------------------------------------

class ProtocolVersions(unittest.TestCase):
    def setUp(self):
        self.h = Harness()

    def forwarded_initialize(self, message):
        self.h.from_client(message)
        (forwarded,) = self.h.sent_to_server()
        return forwarded["params"]

    def test_an_initialize_asking_for_an_unknown_version_asks_for_the_newest_known_one(self):
        params = self.forwarded_initialize(initialize(1, "2099-01-01"))
        self.assertEqual(params["protocolVersion"], protocol.NEWEST_LEGACY_VERSION)
        self.assertIn("2099-01-01", self.h.warnings.getvalue())
        self.assertIn(f"asking the server for {protocol.NEWEST_LEGACY_VERSION} instead", self.h.warnings.getvalue())

    def test_an_initialize_asking_for_the_modern_version_is_downgraded_too(self):
        # 2026-07-28 has no handshake, so an initialize cannot ask for it.
        self.assertEqual(self.forwarded_initialize(initialize(1, MODERN))["protocolVersion"], "2025-11-25")

    def test_every_known_legacy_version_is_passed_on_unchanged(self):
        for version in ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"):
            with self.subTest(version=version):
                self.assertEqual(self.forwarded_initialize(initialize(1, version))["protocolVersion"], version)
        self.assertEqual(self.h.warnings.getvalue(), "")

    def test_an_initialize_without_a_protocol_version_is_refused(self):
        for params in ({}, {"protocolVersion": 20250618}, {"protocolVersion": None}, None, ["2025-06-18"]):
            with self.subTest(params=params):
                message = {"jsonrpc": "2.0", "id": 1, "method": "initialize"}
                if params is not None:
                    message["params"] = params
                self.h.from_client(message)
                self.assertEqual(self.h.sent_to_server(), [])
                (refusal,) = self.h.sent_to_client()
                self.assertEqual(refusal["error"]["code"], protocol.INVALID_PARAMS)
                self.assertIn("the request is malformed", refusal["error"]["message"])

    def test_an_initialize_reply_naming_an_unknown_version_is_refused(self):
        result = {"protocolVersion": "2099-01-01", "capabilities": {}, "serverInfo": {"name": "s", "version": "1"}}
        delivered = self.h.round_trip(initialize(1), result)
        self.assertNotIn("result", delivered)
        self.assertEqual(delivered["error"]["code"], protocol.INVALID_PARAMS)
        self.assertIn("a protocol version this proxy does not support", delivered["error"]["message"])
        self.assertIn("'2099-01-01', which this proxy does not know", self.h.warnings.getvalue())

    def test_an_initialize_reply_must_name_its_version(self):
        for result in ({"capabilities": {}}, {"protocolVersion": 5}, "2025-06-18", [INJECTION]):
            with self.subTest(result=result):
                delivered = self.h.round_trip(initialize(1), result)
                self.assertIn("malformed", delivered["error"]["message"])
                self.assertNotIn("evil.example", json.dumps(delivered))

    def test_an_initialize_reply_naming_a_known_version_is_delivered(self):
        result = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "s"}}
        self.assertEqual(self.h.round_trip(initialize(1, "2025-03-26"), result)["result"], result)

    def test_a_request_naming_an_unknown_version_is_answered_as_a_modern_server_would(self):
        self.h.from_client(modern(1, "tools/list", version="2099-01-01"))
        self.assertEqual(self.h.sent_to_server(), [])
        (answer,) = self.h.sent_to_client()
        self.assertEqual(answer, {"jsonrpc": "2.0", "id": 1, "error": {
            "code": -32022, "message": "Unsupported protocol version",
            "data": {"supported": ["2026-07-28"], "requested": "2099-01-01"},
        }})

    def test_a_notification_naming_an_unknown_version_is_dropped(self):
        notification = modern(1, "notifications/cancelled", {"requestId": 5}, version="2099-01-01")
        del notification["id"]
        self.h.from_client(notification)
        self.assertEqual((self.h.sent_to_server(), self.h.sent_to_client()), ([], []))

    def test_a_hostile_version_is_shortened_in_the_answer_and_escaped_in_the_warning(self):
        version = "\x1b[2J\x1b[31m" + "9" * 5000
        self.h.from_client(modern(1, "tools/list", version=version))
        (answer,) = self.h.sent_to_client()
        self.assertLessEqual(len(answer["error"]["data"]["requested"]), protocol.MAX_VERSION_CHARS)
        self.assertNotIn("\x1b", self.h.warnings.getvalue())

    def test_a_known_legacy_version_in_meta_is_passed_on(self):
        message = modern(1, "tools/list", version="2025-11-25")
        self.h.from_client(message)
        self.assertEqual(self.h.sent_to_server(), [message])

    def test_malformed_request_metadata_is_refused(self):
        for meta in ("2026-07-28", ["2026-07-28"], {protocol.PROTOCOL_VERSION_KEY: 20260728},
                     {protocol.PROTOCOL_VERSION_KEY: None}):
            with self.subTest(meta=meta):
                self.h.from_client(request(1, "tools/list", {"_meta": meta}))
                self.assertEqual(self.h.sent_to_server(), [])
                (refusal,) = self.h.sent_to_client()
                self.assertEqual(refusal["error"]["code"], protocol.INVALID_PARAMS)

    def test_a_discover_reply_lists_only_the_versions_the_proxy_knows(self):
        versions = ["2099-01-01", MODERN, "2025-11-25", MODERN, "1999-01-01"]
        result = {"resultType": "complete", "supportedVersions": versions, "capabilities": {}}
        delivered = self.h.round_trip(modern(1, "server/discover"), result)
        self.assertEqual(delivered["result"]["supportedVersions"], [MODERN, "2025-11-25"])

    def test_a_discover_reply_with_no_version_the_proxy_knows_is_refused(self):
        result = {"resultType": "complete", "supportedVersions": ["2099-01-01"], "capabilities": {}}
        delivered = self.h.round_trip(modern(1, "server/discover"), result)
        self.assertIn("a protocol version this proxy does not support", delivered["error"]["message"])

    def test_a_discover_reply_with_malformed_versions_is_refused(self):
        too_many = [MODERN] * (protocol.MAX_SUPPORTED_VERSIONS + 1)
        for versions in (None, MODERN, [MODERN, 5], {"0": MODERN}, too_many):
            with self.subTest(versions=str(versions)[:40]):
                result = {"resultType": "complete", "capabilities": {}}
                if versions is not None:
                    result["supportedVersions"] = versions
                delivered = self.h.round_trip(modern(1, "server/discover"), result)
                self.assertIn("malformed", delivered["error"]["message"])


# ---- result types (C02, C32, C43) -----------------------------------------------------------

class ResultTypes(unittest.TestCase):
    def setUp(self):
        self.h = Harness()

    def answer_call(self, result):
        return self.h.round_trip(modern_call(1, "read_file", {"path": "a"}), result)

    def test_a_result_of_a_type_the_proxy_does_not_know_is_refused(self):
        for kind in ("stream", "Complete", "input-required", ""):
            with self.subTest(kind=kind):
                delivered = self.answer_call(dict(complete("hi"), resultType=kind))
                self.assertNotIn("result", delivered)
                self.assertIn("a reply this proxy cannot check", delivered["error"]["message"])

    def test_a_result_type_that_is_not_text_is_malformed(self):
        for kind in (5, None, ["complete"], {"type": "complete"}, True):
            with self.subTest(kind=kind):
                delivered = self.answer_call(dict(complete("hi"), resultType=kind))
                self.assertIn("malformed", delivered["error"]["message"])

    def test_a_complete_result_is_delivered(self):
        self.assertEqual(self.answer_call(complete("hello"))["result"], complete("hello"))

    def test_a_legacy_result_without_a_type_is_delivered(self):
        delivered = self.h.round_trip(call(1, "read_file", {"path": "a"}), text_result("hi"))
        self.assertEqual(delivered["result"], text_result("hi"))

    def test_a_task_is_refused_because_tasks_are_not_supported(self):
        task = {"taskId": "t-1", "status": "working", "ttlMs": 60000}
        for message, result in (
            (modern_call(1, "read_file", {"path": "a"}), {"resultType": "task", "task": task}),
            (call(1, "read_file", {"path": "a"}), {"task": task}),  # a 2025-11-25 task handle
        ):
            with self.subTest(result=result):
                delivered = self.h.round_trip(message, result)
                self.assertNotIn("result", delivered)
                self.assertNotIn("t-1", json.dumps(delivered))
        self.assertIn("tasks are not supported", self.h.warnings.getvalue())

    def test_a_tool_result_with_content_is_not_mistaken_for_a_task(self):
        result = dict(text_result("hello"), task={"note": "not a handle"})
        self.assertEqual(self.h.round_trip(call(1, "read_file", {"path": "a"}), result)["result"], result)

    def test_an_unknown_type_is_shown_safely(self):
        self.answer_call(dict(complete("hi"), resultType="\x1b[2Jx"))
        self.assertIn("unknown resultType", self.h.warnings.getvalue())
        self.assertNotIn("\x1b", self.h.warnings.getvalue())


class RefusalsTheProxyBuilds(unittest.TestCase):
    """A result the proxy writes itself says what kind of result it is, when the request was a modern one."""

    def setUp(self):
        self.h = Harness()

    def test_a_refused_modern_tool_call_is_a_complete_result(self):
        self.h.from_client(modern_call(1, "delete_file", {"path": "x"}))
        (refusal,) = self.h.sent_to_client()
        self.assertEqual(refusal["result"]["resultType"], "complete")
        self.assertTrue(refusal["result"]["isError"])

    def test_a_refused_legacy_tool_call_has_no_result_type(self):
        self.h.from_client(call(1, "delete_file", {"path": "x"}))
        (refusal,) = self.h.sent_to_client()
        self.assertNotIn("resultType", refusal["result"])

    def test_a_withheld_modern_tool_result_is_a_complete_result(self):
        delivered = self.h.round_trip(modern_call(1, "fetch_page", {"url": "u"}), complete(INJECTION))
        self.assertEqual(delivered["result"]["resultType"], "complete")
        self.assertTrue(delivered["result"]["isError"])
        self.assertNotIn("evil.example", json.dumps(delivered))

    def test_a_refusal_when_too_many_requests_wait_is_a_complete_result(self):
        with mock.patch.object(mcp_proxy, "MAX_PENDING_REQUESTS", 0):
            self.h.from_client(modern_call(1, "read_file", {"path": "a"}))
        (refusal,) = self.h.sent_to_client()
        self.assertEqual(refusal["result"]["resultType"], "complete")


# ---- input requests inside replies (C02) ----------------------------------------------------

class InputRequests(WithAnAuditLog):
    def setUp(self):
        super().setUp()
        self.h = self.harness()

    def answer_call(self, result, message=None):
        message = message or modern_call(1, "read_file", {"path": "a.txt"})
        return self.h.round_trip(message, result)

    def test_an_allowed_input_request_reaches_the_client_with_its_state_unchanged(self):
        state = "AEAD-protected blob +/= é"
        delivered = self.answer_call(input_required({"folder": ELICITATION, "roots": ROOTS}, state))
        self.assertEqual(delivered["result"], input_required({"folder": ELICITATION, "roots": ROOTS}, state))

    def test_a_sampling_request_inside_a_reply_is_refused_like_a_request_of_its_own(self):
        delivered = self.answer_call(input_required({"s": SAMPLING}))
        self.assertTrue(delivered["result"]["isError"])
        self.assertEqual(delivered["result"]["resultType"], "complete")
        self.assertIn("the server asked for input that is not permitted", json.dumps(delivered))
        self.assertNotIn("Summarise", json.dumps(delivered))
        self.assertNotIn("sampling", json.dumps(delivered))  # the agent is not told which rule

    def test_the_refusal_is_audited_like_a_refused_server_request_of_the_same_call(self):
        self.answer_call(input_required({"s": SAMPLING}))
        records = self.records()
        (call_record,) = [r for r in records if r["event"] == "call"]
        (refused,) = [r for r in records if r["event"] == "server_request"]
        self.assertEqual(refused["tool"], "server:sampling/createMessage")
        self.assertEqual(refused["action"], "block")
        self.assertEqual(refused["rule"], "server_requests.sampling/createMessage")
        self.assertEqual(refused["call_id"], call_record["call_id"])

    def test_one_refused_entry_refuses_the_whole_reply(self):
        delivered = self.answer_call(input_required({"folder": ELICITATION, "s": SAMPLING}))
        self.assertNotIn("inputRequests", json.dumps(delivered))
        self.assertNotIn("Which folder", json.dumps(delivered))

    def test_for_prompts_and_resources_the_refusal_is_an_error(self):
        for message in (modern(1, "prompts/get", {"name": "summary"}),
                        modern(1, "resources/read", {"uri": "file:///notes.txt"})):
            with self.subTest(method=message["method"]):
                delivered = self.answer_call(input_required({"s": SAMPLING}), message)
                self.assertIn("the server asked for input that is not permitted", delivered["error"]["message"])

    def test_a_policy_can_refuse_elicitation_or_roots_the_same_way(self):
        refused = {"elicitation/create": "block", "roots/list": "block"}
        h = Harness(Firewall(Policy.from_dict({"default": "allow", "server_requests": refused})))
        for entry in (ELICITATION, ROOTS):
            with self.subTest(method=entry["method"]):
                delivered = h.round_trip(modern_call(1, "read_file", {}), input_required({"x": entry}))
                self.assertTrue(delivered["result"]["isError"])
        delivered = h.round_trip(modern_call(2, "read_file", {}), input_required({"s": SAMPLING}))
        self.assertIn("inputRequests", delivered["result"])

    def test_an_injection_in_an_input_request_is_refused(self):
        poisoned = {"method": "elicitation/create", "params": {"mode": "form", "message": INJECTION}}
        delivered = self.answer_call(input_required({"e": poisoned}))
        self.assertTrue(delivered["result"]["isError"])
        self.assertNotIn("evil.example", json.dumps(delivered))

    def test_an_injection_in_the_request_state_is_refused(self):
        delivered = self.answer_call(input_required({"folder": ELICITATION}, state=INJECTION))
        self.assertNotIn("evil.example", json.dumps(delivered))

    def test_entries_are_rebuilt_from_their_method_and_params(self):
        entry = dict(ELICITATION, jsonrpc="2.0", id=99, note="carried along")
        delivered = self.answer_call(input_required({"folder": entry}))
        self.assertEqual(delivered["result"]["inputRequests"], {"folder": ELICITATION})

    def test_a_reply_with_only_a_request_state_is_delivered(self):
        delivered = self.answer_call(input_required(None, "come back later"))
        self.assertEqual(delivered["result"], input_required(None, "come back later"))

    def test_monitor_mode_lets_a_refused_entry_through_and_logs_it(self):
        h = self.harness(monitor=True)
        delivered = h.round_trip(modern_call(1, "read_file", {}), input_required({"s": SAMPLING}))
        self.assertEqual(delivered["result"]["inputRequests"], {"s": SAMPLING})
        self.assertIn("would_block", [r["action"] for r in self.records() if r["event"] == "server_request"])

    def test_input_required_is_refused_on_a_request_that_cannot_take_it(self):
        for message in (modern(1, "tools/list"), modern(1, "completion/complete"), modern(1, "server/discover")):
            with self.subTest(method=message["method"]):
                delivered = self.answer_call(input_required({"folder": ELICITATION}), message)
                self.assertIn("malformed", delivered["error"]["message"])
                self.assertNotIn("Which folder", json.dumps(delivered))

    def test_input_requests_in_a_result_of_another_kind_are_refused(self):
        for result in (dict(complete("done"), inputRequests={"s": SAMPLING}),
                       dict(text_result("done"), inputRequests={"s": SAMPLING})):  # no resultType: complete
            with self.subTest(result=result):
                delivered = self.answer_call(result)
                self.assertIn("malformed", delivered["error"]["message"])
                self.assertNotIn("Summarise", json.dumps(delivered))

    def test_input_required_is_refused_on_a_legacy_request(self):
        delivered = self.answer_call(input_required({"folder": ELICITATION}), call(1, "read_file", {"path": "a"}))
        self.assertIn("malformed", delivered["error"]["message"])

    def test_hostile_input_requests_are_refused(self):
        too_many = {f"k{number}": ROOTS for number in range(protocol.MAX_INPUT_ENTRIES + 1)}
        hostile = {
            "neither member": {"resultType": "input_required"},
            "a list": input_required([ELICITATION]),
            "a text": input_required(INJECTION),
            "null": {"resultType": "input_required", "inputRequests": None},
            "too many entries": input_required(too_many),
            "an empty key": input_required({"": ROOTS}),
            "an over-long key": input_required({"k" * (protocol.MAX_KEY_CHARS + 1): ROOTS}),
            "an entry that is not an object": input_required({"x": "elicitation/create"}),
            "an entry without a method": input_required({"x": {"params": {}}}),
            "a tools/call entry": input_required({"x": {"method": "tools/call", "params": {"name": "delete_file"}}}),
            "a ping entry": input_required({"x": {"method": "ping"}}),
            "a method that is not text": input_required({"x": {"method": 5}}),
            "params that are not an object": input_required({"x": {"method": "roots/list", "params": [INJECTION]}}),
            "a state that is not text": input_required({"x": ROOTS}, state={"s": 1}),
            "an over-long state": input_required({"x": ROOTS}, state="s" * (protocol.MAX_REQUEST_STATE_CHARS + 1)),
        }
        for name, result in hostile.items():
            with self.subTest(name):
                delivered = self.answer_call(result)
                self.assertIn("malformed", delivered["error"]["message"])
                self.assertNotIn("evil.example", json.dumps(delivered))
                self.assertNotIn("delete_file", json.dumps(delivered))

    def test_the_largest_allowed_maps_and_state_are_accepted(self):
        most = {f"k{number}": ROOTS for number in range(protocol.MAX_INPUT_ENTRIES)}
        delivered = self.answer_call(input_required(most, "s" * protocol.MAX_REQUEST_STATE_CHARS))
        self.assertEqual(len(delivered["result"]["inputRequests"]), protocol.MAX_INPUT_ENTRIES)


# ---- what the client sends back (C17) -------------------------------------------------------

class AnswersInARetriedRequest(WithAnAuditLog):
    """A 2026-07-28 client answers input requests by sending its request again with inputResponses."""

    def setUp(self):
        super().setUp()
        self.h = self.harness()

    def retry(self, responses, state="opaque-state", method="tools/call"):
        params = {"inputResponses": responses, "requestState": state}
        if method == "tools/call":
            return modern_call(2, "read_file", {"path": "a.txt"}, **params)
        return modern(2, method, dict(params, name="summary", uri="file:///notes.txt"))

    def test_a_clean_answer_is_forwarded_with_the_request_state_unchanged(self):
        message = self.retry({"folder": {"action": "accept", "content": {"folder": "notes"}}}, state="x+/=é")
        self.h.from_client(message)
        self.assertEqual(self.h.sent_to_server(), [message])

    def test_an_answer_carrying_a_secret_is_not_sent(self):
        sampled = {"role": "assistant", "content": {"type": "text", "text": f"The key is {SECRET_TOKEN}"}}
        self.h.from_client(self.retry({"s": sampled}))
        self.assertEqual(self.h.sent_to_server(), [])
        (refusal,) = self.h.sent_to_client()
        self.assertTrue(refusal["result"]["isError"])
        self.assertEqual(refusal["result"]["resultType"], "complete")
        self.assertIn("looks like a secret", json.dumps(refusal))
        self.assertNotIn(SECRET_TOKEN, json.dumps(refusal))
        (record,) = [r for r in self.records() if r["action"] == "block"]
        self.assertEqual((record["tool"], record["rule"]), ("read_file", "secrets"))

    def test_a_secret_in_a_key_of_an_answer_is_found(self):
        self.h.from_client(self.retry({"e": {"action": "accept", "content": {SECRET_TOKEN: True}}}))
        self.assertEqual(self.h.sent_to_server(), [])

    def test_the_answers_of_a_retried_prompt_or_resource_read_are_checked_too(self):
        answer = {"e": {"action": "accept", "content": {"t": SECRET_TOKEN}}}
        for method in ("prompts/get", "resources/read"):
            with self.subTest(method=method):
                self.h.from_client(self.retry(answer, method=method))
                self.assertEqual(self.h.sent_to_server(), [])
                (refusal,) = self.h.sent_to_client()
                self.assertIn("looks like a secret", refusal["error"]["message"])

    def test_with_secrets_allowed_in_arguments_answers_are_not_checked(self):
        policy = Policy.from_dict({"default": "allow", "secrets": {"in_arguments": "allow"}})
        h = Harness(Firewall(policy))
        message = self.retry({"e": {"action": "accept", "content": {"t": SECRET_TOKEN}}})
        h.from_client(message)
        self.assertEqual(h.sent_to_server(), [message])

    def test_monitor_mode_forwards_an_answer_with_a_secret_and_logs_it(self):
        h = self.harness(monitor=True)
        h.from_client(self.retry({"e": {"action": "accept", "content": {"t": SECRET_TOKEN}}}))
        self.assertEqual(len(h.sent_to_server()), 1)
        self.assertIn("would_block", [r["action"] for r in self.records()])

    def test_the_request_state_is_never_written_to_the_audit_log(self):
        marker = "STATE-" + "7f3a" * 8
        self.h.from_client(self.retry({"e": {"action": "decline"}}, state=marker))
        self.h.from_client(self.retry({"e": {"action": "accept", "content": {"t": SECRET_TOKEN}}}, state=marker))
        self.assertTrue(self.records())
        self.assertNotIn(marker, self.audit.read_text(encoding="utf-8"))

    def test_hostile_answers_are_refused_before_they_reach_the_server(self):
        too_many = {f"k{number}": {} for number in range(protocol.MAX_INPUT_ENTRIES + 1)}
        hostile = {
            "a list": ([{"action": "accept"}], "s"),
            "a text": ("accept", "s"),
            "too many entries": (too_many, "s"),
            "an empty key": ({"": {}}, "s"),
            "an over-long key": ({"k" * (protocol.MAX_KEY_CHARS + 1): {}}, "s"),
            "an answer that is not an object": ({"e": "accept"}, "s"),
            "a state that is not text": ({"e": {}}, 5),
            "an over-long state": ({"e": {}}, "s" * (protocol.MAX_REQUEST_STATE_CHARS + 1)),
        }
        for name, (responses, state) in hostile.items():
            with self.subTest(name):
                self.h.from_client(self.retry(responses, state))
                self.assertEqual(self.h.sent_to_server(), [])
                (refusal,) = self.h.sent_to_client()
                self.assertEqual(refusal["error"]["code"], protocol.INVALID_PARAMS)

    def test_the_largest_allowed_answers_are_accepted(self):
        most = {f"k{number}": {"action": "decline"} for number in range(protocol.MAX_INPUT_ENTRIES)}
        message = self.retry(most, "s" * protocol.MAX_REQUEST_STATE_CHARS)
        self.h.from_client(message)
        self.assertEqual(self.h.sent_to_server(), [message])


class AnswersToServerRequests(WithAnAuditLog):
    """A legacy client answers the server's own requests (sampling, elicitation, roots) with a reply."""

    def setUp(self):
        super().setUp()
        self.h = self.harness()
        self.h.from_server(request(7, "roots/list"))
        self.h.sent_to_client()

    def answer(self, message):
        self.h.from_client(message)
        (forwarded,) = self.h.sent_to_server()
        return forwarded

    def test_an_answer_carrying_a_secret_is_replaced_by_a_refusal(self):
        roots = {"roots": [{"uri": f"file:///home/me/{SECRET_TOKEN}", "name": "home"}]}
        forwarded = self.answer(reply(7, roots))
        self.assertEqual(forwarded, {"jsonrpc": "2.0", "id": 7, "error": {
            "code": -32000, "message": "Blocked by agent-sentinel: request refused"}})
        (record,) = [r for r in self.records() if r["event"] == "client_reply"]
        self.assertEqual((record["tool"], record["rule"], record["action"]), ("server:roots/list", "secrets", "block"))
        self.assertNotIn(SECRET_TOKEN, self.audit.read_text(encoding="utf-8"))

    def test_a_secret_in_an_error_or_its_data_is_found(self):
        for error in ({"code": -1, "message": "no", "data": {"token": SECRET_TOKEN}},
                      {"code": -1, "message": f"no {SECRET_TOKEN}"}):
            with self.subTest(error=error):
                self.h.from_server(request(8, "elicitation/create", {"message": "Your name?"}))
                self.h.sent_to_client()
                forwarded = self.answer({"jsonrpc": "2.0", "id": 8, "error": error})
                self.assertNotIn(SECRET_TOKEN, json.dumps(forwarded))

    def test_an_answer_is_rebuilt_from_its_result_or_error(self):
        forwarded = self.answer({"jsonrpc": "1.0", "id": 7, "result": {"roots": []}, "note": "rides along"})
        self.assertEqual(forwarded, {"jsonrpc": "2.0", "id": 7, "result": {"roots": []}})
        self.h.from_server(request(8, "roots/list"))
        self.h.sent_to_client()
        forwarded = self.answer({"jsonrpc": "2.0", "id": 8, "error": {"code": -1, "message": "no", "data": 1, "x": 2}})
        self.assertEqual(forwarded["error"], {"code": -1, "message": "no", "data": 1})

    def test_a_malformed_answer_is_replaced_by_a_refusal(self):
        for number, value in enumerate((
            {"result": ["root"]}, {"result": "ok"}, {"error": "no"}, {"error": {"message": "no"}},
            {"error": {"code": "1", "message": "no"}}, {"error": {"code": True, "message": "no"}},
            {"error": {"code": 1, "message": 5}},
        )):
            with self.subTest(value=value):
                self.h.from_server(request(100 + number, "roots/list"))
                self.h.sent_to_client()
                forwarded = self.answer(dict({"jsonrpc": "2.0", "id": 100 + number}, **value))
                self.assertEqual(forwarded["error"]["message"], "Blocked by agent-sentinel: request refused")
        self.assertIn("malformed client reply", self.audit.read_text(encoding="utf-8"))

    def test_monitor_mode_forwards_an_answer_with_a_secret(self):
        h = self.harness(monitor=True)
        h.from_server(request(7, "roots/list"))
        h.sent_to_client()
        answer = reply(7, {"roots": [{"uri": f"file:///{SECRET_TOKEN}"}]})
        h.from_client(answer)
        self.assertEqual(h.sent_to_server(), [answer])


# ---- subscriptions/listen (C02) ---------------------------------------------------------------

class Subscriptions(WithAnAuditLog):
    def setUp(self):
        super().setUp()
        self.h = self.harness()

    def listen(self, notifications, msg_id=1):
        return modern(msg_id, "subscriptions/listen", {"notifications": notifications})

    def refused(self, message):
        self.h.from_client(message)
        self.assertEqual(self.h.sent_to_server(), [], "the request reached the server")
        (refusal,) = self.h.sent_to_client()
        return refusal

    def test_a_subscription_needs_the_permission_to_read_each_uri(self):
        refusal = self.refused(self.listen({"resourceSubscriptions": ["file:///home/me/.ssh/id_rsa"]}))
        self.assertIn("Blocked by agent-sentinel", refusal["error"]["message"])
        message = self.listen({"resourceSubscriptions": ["file:///notes.txt", "file:///todo.txt"]}, msg_id=2)
        self.h.from_client(message)
        self.assertEqual(self.h.sent_to_server(), [message])

    def test_one_denied_uri_refuses_the_whole_request(self):
        self.refused(self.listen({"toolsListChanged": True,
                                  "resourceSubscriptions": ["file:///notes.txt", "file:///home/me/.aws/credentials"]}))

    def test_a_percent_encoded_uri_does_not_get_round_a_deny_rule(self):
        self.refused(self.listen({"resourceSubscriptions": ["file:///home/me/%2Essh/id%5Frsa"]}))

    def test_list_change_filters_alone_need_no_permission(self):
        message = self.listen({"toolsListChanged": True, "promptsListChanged": False, "resourcesListChanged": True})
        self.h.from_client(message)
        self.assertEqual(self.h.sent_to_server(), [message])

    def test_each_uri_is_checked_and_logged_as_a_read_once(self):
        self.h.from_client(self.listen({"resourceSubscriptions": ["file:///a.txt", "file:///b.txt", "file:///a.txt"]}))
        calls = [r for r in self.records() if r["event"] == "call"]
        self.assertEqual([(r["tool"], r["args"]["uri"]) for r in calls],
                         [("resources/read", "file:///a.txt"), ("resources/read", "file:///b.txt")])

    def test_the_acknowledgement_and_updates_reach_the_client_after_a_scan(self):
        self.h.from_client(self.listen({"resourceSubscriptions": ["file:///notes.txt"]}))
        meta = {"io.modelcontextprotocol/subscriptionId": 1}
        ack = {"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged",
               "params": {"_meta": meta, "notifications": {"resourceSubscriptions": ["file:///notes.txt"]}}}
        update = {"jsonrpc": "2.0", "method": "notifications/resources/updated",
                  "params": {"_meta": meta, "uri": "file:///notes.txt", "title": INJECTION}}
        self.h.from_server(ack)
        self.h.from_server(update)
        self.assertEqual(self.h.sent_to_client(), [ack])

    def test_hostile_subscription_requests_are_refused(self):
        too_many = [f"file:///{number}.txt" for number in range(protocol.MAX_SUBSCRIBED_URIS + 1)]
        hostile = {
            "no filter": modern(1, "subscriptions/listen"),
            "a filter that is a list": self.listen(["toolsListChanged"]),
            "a filter that is text": self.listen("everything"),
            "an unknown filter": self.listen({"tasks": True}),
            "a logging filter": self.listen({"logging": True}),
            "a flag that is not true or false": self.listen({"toolsListChanged": "yes"}),
            "URIs that are text": self.listen({"resourceSubscriptions": "file:///notes.txt"}),
            "a URI that is a number": self.listen({"resourceSubscriptions": [5]}),
            "an empty URI": self.listen({"resourceSubscriptions": [""]}),
            "too many URIs": self.listen({"resourceSubscriptions": too_many}),
            "params that are a list": request(1, "subscriptions/listen", ["file:///notes.txt"]),
        }
        for name, message in hostile.items():
            with self.subTest(name):
                refusal = self.refused(message)
                self.assertEqual(refusal["error"]["code"], protocol.INVALID_PARAMS)
        self.assertEqual([r for r in self.records() if r["event"] == "call"], [], "no URI should have been checked")


# ---- server/discover and capabilities (C02, C31) --------------------------------------------

class Discovery(unittest.TestCase):
    def setUp(self):
        self.h = Harness()

    def discover(self, **members):
        result = {"resultType": "complete", "supportedVersions": [MODERN], "capabilities": {"tools": {}}}
        return self.h.round_trip(modern(1, "server/discover"), dict(result, **members))

    def test_poisoned_instructions_in_a_discover_reply_are_removed_and_the_rest_delivered(self):
        delivered = self.discover(instructions=INJECTION)
        self.assertNotIn("instructions", delivered["result"])
        self.assertEqual(delivered["result"]["capabilities"], {"tools": {}})
        self.assertIn("removed the server's instructions", self.h.warnings.getvalue())

    def test_clean_instructions_are_kept(self):
        self.assertEqual(self.discover(instructions="Use read_file.")["result"]["instructions"], "Use read_file.")

    def test_tasks_are_removed_from_the_servers_capabilities(self):
        capabilities = {"tools": {}, "extensions": {protocol.TASKS_EXTENSION: {}, "io.modelcontextprotocol/ui": {}}}
        delivered = self.discover(capabilities=capabilities)
        self.assertEqual(delivered["result"]["capabilities"],
                         {"tools": {}, "extensions": {"io.modelcontextprotocol/ui": {}}})
        result = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}, "tasks": {"list": {}}}}
        self.assertEqual(self.h.round_trip(initialize(2), result)["result"]["capabilities"], {"tools": {}})

    def test_malformed_server_capabilities_are_refused(self):
        for capabilities in ("all", ["tools"], {"extensions": [protocol.TASKS_EXTENSION]}):
            with self.subTest(capabilities=capabilities):
                self.assertIn("malformed", self.discover(capabilities=capabilities)["error"]["message"])

    def test_a_discover_result_that_is_not_an_object_is_refused(self):
        delivered = self.h.round_trip(modern(1, "server/discover"), [INJECTION])
        self.assertIn("malformed", delivered["error"]["message"])


class CapabilityMinimisation(unittest.TestCase):
    """The client's capabilities lose what the policy would refuse anyway, in the copy sent to the server."""

    EVERYTHING = {
        "sampling": {"tools": {}}, "elicitation": {"form": {}, "url": {}}, "roots": {"listChanged": True},
        "tasks": {"requests": {"sampling": {}}}, "experimental": {"x": {}},
    }

    def forwarded(self, message, firewall=None):
        h = Harness(firewall)
        h.from_client(message)
        (forwarded,) = h.sent_to_server()
        return forwarded

    def test_capabilities_whose_requests_the_policy_blocks_are_not_offered(self):
        # The example policy blocks sampling and allows every other server request.
        forwarded = self.forwarded(initialize(1, capabilities=self.EVERYTHING))
        expected = {"elicitation": {"form": {}, "url": {}}, "roots": {"listChanged": True}, "experimental": {"x": {}}}
        self.assertEqual(forwarded["params"]["capabilities"], expected)

    def test_every_modern_request_is_minimised_the_same_way(self):
        extensions = {protocol.TASKS_EXTENSION: {}, "io.modelcontextprotocol/ui": {}}
        capabilities = dict(self.EVERYTHING, extensions=extensions)
        forwarded = self.forwarded(modern(1, "tools/list", capabilities=capabilities))
        sent = forwarded["params"]["_meta"][protocol.CLIENT_CAPABILITIES_KEY]
        self.assertNotIn("sampling", sent)
        self.assertNotIn("tasks", sent)
        self.assertEqual(sent["extensions"], {"io.modelcontextprotocol/ui": {}})
        self.assertEqual(forwarded["params"]["_meta"][protocol.PROTOCOL_VERSION_KEY], MODERN)

    def test_a_policy_that_blocks_every_server_request_offers_none_of_them(self):
        policy = Policy.from_dict({"default": "allow", "server_requests": {"*": "block"}})
        forwarded = self.forwarded(initialize(1, capabilities=self.EVERYTHING), Firewall(policy))
        self.assertEqual(forwarded["params"]["capabilities"], {"experimental": {"x": {}}})

    def test_monitor_mode_offers_everything_but_tasks(self):
        forwarded = self.forwarded(initialize(1, capabilities=self.EVERYTHING), Firewall(POLICY, monitor=True))
        expected = {name: value for name, value in self.EVERYTHING.items() if name != "tasks"}
        self.assertEqual(forwarded["params"]["capabilities"], expected)

    def test_malformed_capabilities_are_refused(self):
        for message in (initialize(1, capabilities=["sampling"]),
                        initialize(1, capabilities="all"),
                        modern(1, "tools/list", capabilities=["sampling"]),
                        modern(1, "tools/list", capabilities={"extensions": ["io.modelcontextprotocol/ui"]})):
            with self.subTest(message=message):
                h = Harness()
                h.from_client(message)
                self.assertEqual(h.sent_to_server(), [])
                self.assertEqual(h.sent_to_client()[0]["error"]["code"], protocol.INVALID_PARAMS)

    def test_the_callers_capabilities_object_is_not_changed(self):
        capabilities = {"sampling": {}, "tasks": {}}
        protocol.minimised_capabilities(capabilities, {"sampling/createMessage"})
        self.assertEqual(capabilities, {"sampling": {}, "tasks": {}})


# ---- the session's era (C02) ----------------------------------------------------------------

class ModernSessions(WithAnAuditLog):
    """On stdio, a 2026-07-28 server must not send requests: it asks for input inside its replies."""

    def setUp(self):
        super().setUp()
        self.h = self.harness()

    def server_request_is_refused(self, h=None, message=None):
        """Send a request from the server; check it does not reach the client and return what the server is told."""
        h = h or self.h
        h.from_server(message or request(70, "roots/list"))
        self.assertEqual(h.sent_to_client(), [])
        (answer,) = h.sent_to_server()
        return answer

    def test_a_server_request_in_a_modern_session_is_refused(self):
        self.h.round_trip(modern(1, "tools/list"), {"resultType": "complete", "tools": []})
        answer = self.server_request_is_refused()
        self.assertEqual(answer["error"], {"code": protocol.METHOD_NOT_FOUND,
                                           "message": "Blocked by agent-sentinel: request refused"})
        (record,) = [r for r in self.records() if r["event"] == "server_request"]
        self.assertEqual((record["tool"], record["rule"]), ("server:roots/list", "malformed"))
        self.assertIn("protocol violation", record["reason"])

    def test_server_notifications_still_reach_the_client(self):
        self.h.from_client(modern_call(1, "read_file", {"path": "a.txt"}))
        progress = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": 5, "progress": 1}}
        self.h.from_server(progress)
        self.assertEqual(self.h.sent_to_client(), [progress])

    def test_a_discover_result_makes_the_session_modern(self):
        self.h.round_trip(request(1, "server/discover"), {"supportedVersions": [MODERN], "capabilities": {}})
        self.server_request_is_refused()

    def test_a_client_that_falls_back_to_initialize_has_a_legacy_session(self):
        # A dual-era client probes with server/discover; a legacy server answers with an error.
        self.h.from_client(modern(1, "server/discover"))
        self.h.from_server({"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "Method not found"}})
        self.h.sent_to_server()
        self.h.sent_to_client()
        self.h.round_trip(initialize(2), {"protocolVersion": "2025-06-18", "capabilities": {}})
        self.h.from_server(request(70, "roots/list"))
        self.assertEqual([m["method"] for m in self.h.sent_to_client()], ["roots/list"])

    def test_before_the_client_shows_its_era_server_requests_follow_the_policy(self):
        self.h.from_server(request(70, "roots/list"))
        self.assertEqual(len(self.h.sent_to_client()), 1)
        self.h.from_server(request(71, "sampling/createMessage", SAMPLING["params"]))
        self.assertEqual(self.h.sent_to_client(), [])

    def test_monitor_mode_does_not_lift_the_refusal(self):
        h = self.harness(monitor=True)
        h.round_trip(modern(1, "tools/list"), {"resultType": "complete", "tools": []})
        self.server_request_is_refused(h)

    def test_a_tasks_request_from_the_server_is_refused_in_a_legacy_session_too(self):
        self.h.round_trip(initialize(1), {"protocolVersion": "2025-11-25", "capabilities": {}})
        answer = self.server_request_is_refused(message=request(70, "tasks/get", {"taskId": "t-1"}))
        self.assertEqual(answer["error"]["code"], protocol.METHOD_NOT_FOUND)
        self.assertIn("tasks are not supported", self.h.warnings.getvalue())


# ---- tasks (C43: fail closed) -----------------------------------------------------------------

class Tasks(unittest.TestCase):
    def setUp(self):
        self.h = Harness()

    def test_tasks_requests_from_the_client_are_answered_method_not_found(self):
        for method in ("tasks/get", "tasks/result", "tasks/update", "tasks/cancel", "tasks/list"):
            with self.subTest(method=method):
                self.h.from_client(modern(1, method, {"taskId": "t-1"}))
                self.assertEqual(self.h.sent_to_server(), [])
                (refusal,) = self.h.sent_to_client()
                self.assertEqual(refusal["error"]["code"], protocol.METHOD_NOT_FOUND)
                self.assertIn("this request is not supported", refusal["error"]["message"])

    def test_a_task_augmented_tool_call_is_refused(self):
        self.h.from_client(request(1, "tools/call", {"name": "read_file", "arguments": {}, "task": {"ttl": 60000}}))
        self.assertEqual(self.h.sent_to_server(), [])
        (refusal,) = self.h.sent_to_client()
        self.assertIn("not supported", refusal["result"]["content"][0]["text"])


# ---- end to end, against examples/fake_mcp_server.py ----------------------------------------

FAKE_SERVER = ROOT / "examples" / "fake_mcp_server.py"


def run_proxy(messages, policy=EXAMPLE_POLICY_PATH):
    """Send messages through a real proxy process; return (replies by id, notifications, stderr)."""
    raw = "\n".join(json.dumps(m) for m in messages) + "\n"
    proxy = [sys.executable, "-m", "agent_sentinel", "proxy", "--policy", str(policy)]
    proc = subprocess.run(
        [*proxy, "--", sys.executable, str(FAKE_SERVER)], input=raw.encode("utf-8"), capture_output=True, cwd=ROOT,
        timeout=60,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stderr.decode(errors="replace"))
    sent = [json.loads(line) for line in proc.stdout.decode("utf-8").splitlines()]
    return {m["id"]: m for m in sent if "id" in m}, [m for m in sent if "id" not in m], proc.stderr.decode()


class BothErasEndToEnd(unittest.TestCase):
    def test_a_whole_modern_session(self):
        state = "search_with_approval:soup"
        approve = {"confirm": {"action": "accept", "content": {"confirm": True}}}
        leak = {"confirm": {"action": "accept", "content": {"confirm": True, "note": SECRET_TOKEN}}}
        replies, notifications, stderr = run_proxy([
            modern(1, "server/discover", capabilities={"sampling": {}, "elicitation": {}}),
            modern(2, "tools/list"),
            modern_call(3, "search_with_approval", {"query": "soup"}),
            modern_call(4, "search_with_approval", {"query": "soup"}, inputResponses=approve, requestState=state),
            modern_call(5, "search_with_summary", {"query": "soup"}),
            modern_call(6, "search_with_approval", {"query": "soup"}, inputResponses=leak, requestState=state),
            modern(7, "subscriptions/listen", {"notifications": {"resourceSubscriptions": ["file:///home/me/.ssh/x"]}}),
            modern(8, "subscriptions/listen", {"notifications": {"toolsListChanged": True,
                                                                 "resourceSubscriptions": ["file:///notes.txt"]}}),
            modern(9, "tools/list", version="2099-01-01"),
            modern(10, "tasks/get", {"taskId": "t-1"}),
        ])
        discovered = replies[1]["result"]
        self.assertEqual(discovered["supportedVersions"][0], MODERN)
        self.assertNotIn(protocol.TASKS_EXTENSION, discovered["capabilities"]["extensions"])
        listed = {tool["name"] for tool in replies[2]["result"]["tools"]}
        self.assertLessEqual({"read_file", "search_with_approval", "search_with_summary"}, listed)
        self.assertNotIn("search_notes", listed)  # its description is poisoned
        self.assertEqual(replies[3]["result"]["resultType"], "input_required")
        self.assertEqual(replies[3]["result"]["inputRequests"]["confirm"]["method"], "elicitation/create")
        self.assertEqual(replies[4]["result"]["content"][0]["text"], "found 2 notes about soup")
        self.assertIn("the server asked for input that is not permitted", replies[5]["result"]["content"][0]["text"])
        self.assertIn("looks like a secret", replies[6]["result"]["content"][0]["text"])
        self.assertIn("Blocked by agent-sentinel", replies[7]["error"]["message"])
        self.assertNotIn(8, replies)  # the subscription stays open
        self.assertEqual([n["method"] for n in notifications], ["notifications/subscriptions/acknowledged"])
        self.assertEqual(replies[9]["error"]["code"], -32022)
        self.assertEqual(replies[10]["error"]["code"], protocol.METHOD_NOT_FOUND)
        self.assertIn("asks the client for 'sampling/createMessage'", stderr)

    def test_a_legacy_session_asking_for_an_unknown_version_gets_the_newest_known_one(self):
        replies, _, stderr = run_proxy([
            initialize(1, "2099-01-01", capabilities={"sampling": {}, "roots": {}}),
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            request(2, "tools/list"),
            call(3, "read_file", {"path": "notes.txt"}),
        ])
        self.assertEqual(replies[1]["result"]["protocolVersion"], "2025-11-25")
        self.assertIn("asking the server for 2025-11-25 instead", stderr)
        listed = {tool["name"] for tool in replies[2]["result"]["tools"]}
        self.assertIn("read_file", listed)
        self.assertNotIn("search_with_approval", listed)  # only a 2026-07-28 client can answer its input request
        self.assertEqual(replies[3]["result"]["content"][0]["text"], "contents of notes.txt")


if __name__ == "__main__":
    unittest.main()
