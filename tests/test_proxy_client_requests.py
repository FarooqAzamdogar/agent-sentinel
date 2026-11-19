"""Tests for what the proxy does with client requests other than tool calls and resource reads.

* the policy's client_requests section (Policy.client_request_verdict);
* prompts/get, checked like a call of a tool named "prompts/get" once the policy opts in;
* the secret guard on completion/complete, which carries what the user is typing.
"""

import json
import tempfile
import unittest
from pathlib import Path

from support import INJECTION, POLICY, without_ref
from test_proxy import Harness, call, reply, request
from agent_sentinel import Firewall, Policy

SECRET_TOKEN = "ghp_" + "a1B2c3D4e5" * 4


def read_audit(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]


def completion(msg_id, value, context=None):
    params = {"ref": {"type": "ref/prompt", "name": "summarize"}, "argument": {"name": "path", "value": value}}
    if context is not None:
        params["context"] = {"arguments": context}
    return request(msg_id, "completion/complete", params)


def prompt(msg_id, name, arguments=None):
    params = {"name": name}
    if arguments is not None:
        params["arguments"] = arguments
    return request(msg_id, "prompts/get", params)


class WithAnAuditLog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.audit = Path(self.tmp.name) / "audit.jsonl"

    def harness(self, policy, monitor=False):
        return Harness(Firewall(Policy.from_dict(policy) if isinstance(policy, dict) else policy,
                                audit_path=self.audit, monitor=monitor))

    def records(self):
        return read_audit(self.audit) if self.audit.exists() else []

    def refused(self, h, message):
        """Send a request that must be refused; return the client's answer."""
        h.from_client(message)
        self.assertEqual(h.sent_to_server(), [], "the request reached the server")
        (answer,) = h.sent_to_client()
        return answer

    def forwarded(self, h, message):
        h.from_client(message)
        self.assertEqual(h.sent_to_server(), [message], "the request was not forwarded as it was")
        self.assertEqual(h.sent_to_client(), [])


# ---- client_requests ----------------------------------------------------------------------------

GATED = {"default": "allow", "client_requests": {"completion/complete": "block", "notifications/roots/*": "block",
                                                 "logging/setLevel": "allow"}}


class TheClientRequestsSection(WithAnAuditLog):
    def test_a_method_the_policy_blocks_is_answered_method_not_found(self):
        answer = self.refused(self.harness(GATED), completion(1, "no"))
        self.assertEqual(answer["error"]["code"], -32601)
        self.assertEqual(without_ref(answer["error"]["message"]),
                         "Blocked by agent-sentinel: this call is not permitted by the policy")
        (record,) = self.records()
        self.assertEqual((record["event"], record["tool"], record["rule"]),
                         ("client_request", "completion/complete", "client_requests.completion/complete"))

    def test_a_blocked_notification_is_dropped_without_an_answer(self):
        h = self.harness(GATED)
        h.from_client({"jsonrpc": "2.0", "method": "notifications/roots/list_changed"})
        self.assertEqual(h.sent_to_server(), [])
        self.assertEqual(h.sent_to_client(), [])

    def test_methods_the_policy_allows_or_does_not_name_are_forwarded(self):
        h = self.harness(GATED)
        self.forwarded(h, request(1, "logging/setLevel", {"level": "info"}))
        self.forwarded(h, request(2, "ping"))

    def test_without_the_section_every_method_is_forwarded_as_before(self):
        h = self.harness({"default": "allow"})
        self.forwarded(h, completion(1, "no"))
        self.forwarded(h, {"jsonrpc": "2.0", "method": "notifications/roots/list_changed"})

    def test_monitor_mode_forwards_a_blocked_method_and_logs_it(self):
        h = self.harness(GATED, monitor=True)
        self.forwarded(h, completion(1, "no"))
        self.assertEqual(self.records()[0]["action"], "would_block")

    def test_tool_calls_and_resource_reads_are_left_to_the_tools_rules(self):
        policy = {"default": "allow", "client_requests": {"*": "block", "initialize": "allow"}}
        h = self.harness(policy)
        self.forwarded(h, call(1, "search", {}))
        self.forwarded(h, request(2, "resources/read", {"uri": "file:///notes.txt"}))
        self.assertEqual(self.refused(h, request(3, "ping"))["error"]["code"], -32601)


# ---- prompts/get ----------------------------------------------------------------------------------

# Prompts are allowed by name. "arguments" is an object, which allow_args cannot judge,
# so it is left to other_args (allow by default) and to deny rules, which read inside it.
PROMPT_RULE = {
    "default": "block",
    "tools": {
        "prompts/get": {"action": "allow", "allow_args": [{"arg": "name", "one_of": ["summarize"]}],
                        "labels": ["untrusted"]},
    },
}


class PromptsGet(WithAnAuditLog):
    def test_prompts_are_forwarded_unchecked_when_the_policy_does_not_opt_in(self):
        # The example policy has no client_requests section and no "prompts/get" rule (the default is block).
        h = Harness(Firewall(POLICY))
        self.forwarded(h, prompt(1, "anything", {"path": "a.txt"}))

    def test_with_a_prompts_get_rule_a_prompt_is_checked_like_a_call(self):
        h = self.harness(PROMPT_RULE)
        self.forwarded(h, prompt(1, "summarize", {"path": "a.txt"}))
        answer = self.refused(h, prompt(2, "delete_everything"))
        self.assertIn("argument 'name' has a value the policy does not permit", answer["error"]["message"])
        records = self.records()
        self.assertEqual([(r["event"], r["tool"], r["action"]) for r in records],
                         [("call", "prompts/get", "allow"), ("call", "prompts/get", "block")])
        self.assertEqual(records[1]["args"], {"name": "delete_everything", "arguments": {}})

    def test_with_a_client_requests_section_and_no_prompt_rule_the_default_decides(self):
        h = self.harness({"default": "block", "client_requests": {}})
        self.refused(h, prompt(1, "summarize"))
        h = self.harness({"default": "allow", "client_requests": {}})
        self.forwarded(h, prompt(1, "summarize"))

    def test_client_requests_can_refuse_prompts_altogether(self):
        h = self.harness({"default": "allow", "client_requests": {"prompts/get": "block"}})
        self.assertEqual(self.refused(h, prompt(1, "summarize"))["error"]["code"], -32601)

    def test_a_prompt_argument_carrying_a_secret_is_refused_once_prompts_are_checked(self):
        h = self.harness(PROMPT_RULE)
        answer = self.refused(h, prompt(1, "summarize", {"path": SECRET_TOKEN}))
        self.assertIn("looks like a secret", answer["error"]["message"])
        self.assertNotIn(SECRET_TOKEN, json.dumps(answer))

    def test_a_malformed_prompts_get_is_refused(self):
        h = self.harness({"default": "allow"})
        for params in ({}, {"name": ""}, {"name": 5}, {"name": "summarize", "arguments": ["a"]}, {"name": "x" * 300}):
            with self.subTest(params=params):
                answer = self.refused(h, request(1, "prompts/get", params))
                self.assertEqual(answer["error"]["code"], -32602)

    def test_a_tool_cannot_borrow_the_prompts_get_rule_by_its_name(self):
        answer = self.refused(self.harness(PROMPT_RULE), call(1, "prompts/get", {"name": "summarize"}))
        self.assertIn("reserved", answer["result"]["content"][0]["text"])

    def test_the_reply_is_scanned_and_its_marks_are_set_when_it_is_delivered(self):
        h = self.harness(dict(PROMPT_RULE, flows=[{"after": ["untrusted"], "then": "sink", "action": "block"}]))
        h.from_client(prompt(1, "summarize"))
        h.sent_to_server()
        self.assertFalse(h.firewall.session_marks().has("untrusted"))
        h.from_server(reply(1, {"messages": [{"role": "user", "content": {"type": "text", "text": "Summarise."}}]}))
        self.assertEqual(len(h.sent_to_client()), 1)
        self.assertTrue(h.firewall.session_marks().has("untrusted"))

        h.from_client(prompt(2, "summarize"))
        h.sent_to_server()
        h.from_server(reply(2, {"messages": [{"role": "user", "content": {"type": "text", "text": INJECTION}}]}))
        self.assertIn("prompt injection", h.sent_to_client()[0]["error"]["message"])


# ---- completion/complete ------------------------------------------------------------------------------

class CompletionSecrets(WithAnAuditLog):
    def test_a_completion_request_carrying_a_secret_is_refused(self):
        for message in (completion(1, SECRET_TOKEN), completion(1, "notes", context={"token": SECRET_TOKEN})):
            with self.subTest(message=message["params"]):
                answer = self.refused(self.harness({"default": "allow"}), message)
                self.assertIn("looks like a secret", answer["error"]["message"])
                self.assertNotIn(SECRET_TOKEN, json.dumps(answer))
        self.assertEqual({(r["event"], r["rule"]) for r in self.records()}, {("client_request", "secrets")})

    def test_a_completion_request_without_a_secret_is_forwarded(self):
        self.forwarded(self.harness({"default": "block"}), completion(1, "no", context={"folder": "notes"}))

    def test_secrets_are_let_through_when_the_policy_allows_them_in_arguments(self):
        h = self.harness({"default": "allow", "secrets": {"in_arguments": "allow"}})
        self.forwarded(h, completion(1, SECRET_TOKEN))

    def test_the_secret_guard_answers_before_the_policy(self):
        # Otherwise the two answers would tell a probing agent whether the policy blocks the method.
        answer = self.refused(self.harness(GATED), completion(1, SECRET_TOKEN))
        self.assertIn("looks like a secret", answer["error"]["message"])


if __name__ == "__main__":
    unittest.main()
