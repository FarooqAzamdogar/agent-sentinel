"""Tests for the MCP proxy.

`ProxyUnitTests` drive a Proxy directly with in-memory streams, playing both
the client and the server. `ProxyEndToEndTests` start the real proxy process
in front of examples/fake_mcp_server.py.
"""

import contextlib
import io
import json
import subprocess
import sys
import threading
import unittest
from unittest import mock

from support import EXAMPLE_POLICY_PATH, INJECTION, POLICY, ROOT
from agent_sentinel import Firewall, mcp_proxy
from agent_sentinel.mcp_proxy import Proxy


def request(msg_id, method, params=None):
    return {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}}


def call(msg_id, name, arguments):
    return request(msg_id, "tools/call", {"name": name, "arguments": arguments})


def reply(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def text_result(text):
    return {"content": [{"type": "text", "text": text}], "isError": False}


class Harness:
    """A Proxy wired to in-memory streams, with helpers to play both sides."""

    def __init__(self):
        self.to_client = io.BytesIO()
        self.to_server = io.BytesIO()
        self.proxy = Proxy(Firewall(POLICY), client_out=self.to_client, server_in=self.to_server)
        self.warnings = io.StringIO()

    def _feed(self, handle_line, message):
        line = message if isinstance(message, bytes) else json.dumps(message).encode()
        with contextlib.redirect_stderr(self.warnings):
            handle_line(line)

    def from_client(self, message):
        self._feed(self.proxy.handle_client_line, message)

    def from_server(self, message):
        self._feed(self.proxy.handle_server_line, message)

    @staticmethod
    def _drain(stream):
        messages = [json.loads(line) for line in stream.getvalue().splitlines()]
        stream.seek(0)
        stream.truncate()
        return messages

    def sent_to_client(self):
        return self._drain(self.to_client)

    def sent_to_server(self):
        return self._drain(self.to_server)

    def round_trip(self, client_message, server_result):
        """Send a request, answer it as the server, and return what the client got."""
        self.from_client(client_message)
        assert self.sent_to_server() == [client_message], "the request was not forwarded"
        self.from_server(reply(client_message["id"], server_result))
        (delivered,) = self.sent_to_client()
        return delivered


class ProxyUnitTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()

    # ---- tool calls ---------------------------------------------------------

    def test_allowed_call_and_clean_result_pass_through(self):
        delivered = self.h.round_trip(call(1, "read_file", {"path": "notes.txt"}), text_result("hello"))
        self.assertEqual(delivered["result"]["content"][0]["text"], "hello")

    def test_call_blocked_by_policy_never_reaches_the_server(self):
        self.h.from_client(call(1, "delete_file", {"path": "notes.txt"}))
        self.assertEqual(self.h.sent_to_server(), [])
        (refusal,) = self.h.sent_to_client()
        self.assertTrue(refusal["result"]["isError"])
        self.assertIn("Blocked by agent-sentinel", refusal["result"]["content"][0]["text"])

    def test_injected_result_is_replaced(self):
        delivered = self.h.round_trip(call(1, "fetch_page", {"url": "u"}), text_result(INJECTION))
        self.assertTrue(delivered["result"]["isError"])
        self.assertNotIn("evil.example", json.dumps(delivered))

    def test_injected_error_reply_is_replaced(self):
        self.h.from_client(call(1, "fetch_page", {"url": "u"}))
        self.h.from_server({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": INJECTION}})
        (delivered,) = self.h.sent_to_client()
        self.assertNotIn("evil.example", json.dumps(delivered))

    def test_malformed_calls_are_refused(self):
        self.h.from_client(call(1, "read_file", ".ssh/id_rsa"))          # arguments are not an object
        self.h.from_client(request(2, "tools/call", {"arguments": {}}))  # no tool name
        self.h.from_client(request(3, "tools/call", "read_file"))        # params are not an object
        self.assertEqual(self.h.sent_to_server(), [])
        self.assertEqual([m["id"] for m in self.h.sent_to_client()], [1, 2, 3])

    # ---- resource reads -----------------------------------------------------

    def test_resource_read_is_checked_by_the_policy(self):
        delivered = self.h.round_trip(
            request(1, "resources/read", {"uri": "file:///notes.txt"}),
            {"contents": [{"uri": "file:///notes.txt", "text": "Plain notes."}]},
        )
        self.assertEqual(delivered["result"]["contents"][0]["text"], "Plain notes.")

        self.h.from_client(request(2, "resources/read", {"uri": "file:///home/me/.ssh/id_rsa"}))
        self.assertEqual(self.h.sent_to_server(), [])
        (refusal,) = self.h.sent_to_client()
        self.assertIn("Blocked by agent-sentinel", refusal["error"]["message"])

    def test_injected_resource_is_blocked(self):
        delivered = self.h.round_trip(
            request(1, "resources/read", {"uri": "file:///notes.txt"}),
            {"contents": [{"uri": "file:///notes.txt", "text": INJECTION}]},
        )
        self.assertIn("prompt injection", delivered["error"]["message"])

    # ---- tool lists ---------------------------------------------------------

    def test_poisoned_tool_is_removed_and_cannot_be_called(self):
        tools = [
            {"name": "search_web", "description": "Search the web."},
            {"name": "search_notes", "description": f"Search notes. {INJECTION}"},
        ]
        delivered = self.h.round_trip(request(1, "tools/list"), {"tools": tools})
        self.assertEqual([t["name"] for t in delivered["result"]["tools"]], ["search_web"])

        self.h.from_client(call(2, "search_notes", {"q": "soup"}))  # the policy allows search_*
        self.assertEqual(self.h.sent_to_server(), [])
        (refusal,) = self.h.sent_to_client()
        self.assertIn("poisoned", refusal["result"]["content"][0]["text"])

    def test_quarantine_survives_a_later_clean_listing(self):
        self.h.round_trip(request(1, "tools/list"), {"tools": [{"name": "search_notes", "description": INJECTION}]})
        self.h.round_trip(request(2, "tools/list"), {"tools": [{"name": "search_notes", "description": "Search."}]})
        self.h.from_client(call(3, "search_notes", {}))
        self.assertEqual(self.h.sent_to_server(), [])

    def test_tool_call_waits_for_the_tool_list_to_be_checked(self):
        self.h.from_client(request(1, "tools/list"))
        self.h.sent_to_server()
        caller = threading.Thread(target=self.h.from_client, args=(call(2, "search_notes", {}),))
        caller.start()
        caller.join(timeout=0.3)
        self.assertTrue(caller.is_alive(), "the call should wait for the list")

        self.h.from_server(reply(1, {"tools": [{"name": "search_notes", "description": INJECTION}]}))
        caller.join(timeout=5)
        self.assertFalse(caller.is_alive())
        self.assertEqual(self.h.sent_to_server(), [])  # it was quarantined in time

    def test_call_is_blocked_if_the_tool_list_never_arrives(self):
        self.h.from_client(request(1, "tools/list"))
        self.h.sent_to_server()
        with mock.patch.object(mcp_proxy, "TOOL_LIST_WAIT_SECONDS", 0.05):
            self.h.from_client(call(2, "search_web", {}))
            self.assertEqual(self.h.sent_to_server(), [])
            self.assertIn("timed out", self.h.sent_to_client()[0]["result"]["content"][0]["text"])
            # Later calls are not held up by the same missing list.
            self.h.from_client(call(3, "search_web", {}))
            self.assertEqual(len(self.h.sent_to_server()), 1)

    def test_cancelled_tool_list_does_not_hold_up_calls(self):
        self.h.from_client(request(1, "tools/list"))
        self.h.from_client({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}})
        self.h.from_client(call(2, "search_web", {}))
        self.assertEqual([m.get("method") for m in self.h.sent_to_server()],
                         ["tools/list", "notifications/cancelled", "tools/call"])

    def test_other_lists_are_filtered_item_by_item(self):
        prompts = [{"name": "summarize", "description": "Summarize text."}, {"name": "x", "description": INJECTION}]
        delivered = self.h.round_trip(request(1, "prompts/list"), {"prompts": prompts})
        self.assertEqual([p["name"] for p in delivered["result"]["prompts"]], ["summarize"])

    # ---- everything else the server sends -----------------------------------

    def test_poisoned_server_instructions_are_removed(self):
        result = {"serverInfo": {"name": "files"}, "instructions": INJECTION}
        delivered = self.h.round_trip(request(1, "initialize"), result)
        self.assertEqual(delivered["result"], {"serverInfo": {"name": "files"}})

    def test_clean_server_instructions_are_kept(self):
        result = {"serverInfo": {"name": "files"}, "instructions": "Use read_file for text files."}
        self.assertEqual(self.h.round_trip(request(1, "initialize"), result)["result"], result)

    def test_any_other_reply_is_scanned_too(self):
        delivered = self.h.round_trip(request(1, "completion/complete"), {"completion": {"values": [INJECTION]}})
        self.assertIn("prompt injection", delivered["error"]["message"])

    def test_reply_that_matches_no_request_is_dropped(self):
        self.h.from_server(reply(99, text_result("hello")))
        self.assertEqual(self.h.sent_to_client(), [])
        # ...including a second reply to a request that was already answered.
        self.h.round_trip(call(1, "read_file", {"path": "a.txt"}), text_result("first"))
        self.h.from_server(reply(1, text_result(INJECTION)))
        self.assertEqual(self.h.sent_to_client(), [])

    def test_injected_server_request_is_refused(self):
        sampling = request(7, "sampling/createMessage",
                           {"messages": [{"role": "user", "content": {"type": "text", "text": INJECTION}}]})
        self.h.from_server(sampling)
        self.assertEqual(self.h.sent_to_client(), [])
        (answer,) = self.h.sent_to_server()  # the server is told, so it is not left waiting
        self.assertEqual(answer["id"], 7)
        self.assertIn("error", answer)

    def test_clean_server_request_and_its_answer_pass_through(self):
        ping = request(7, "ping")
        self.h.from_server(ping)
        self.assertEqual(self.h.sent_to_client(), [ping])
        answer = reply(7, {})
        self.h.from_client(answer)
        self.assertEqual(self.h.sent_to_server(), [answer])

    def test_injected_notification_is_dropped(self):
        self.h.from_server({"jsonrpc": "2.0", "method": "notifications/message", "params": {"data": INJECTION}})
        self.assertEqual(self.h.sent_to_client(), [])

    # ---- malformed traffic --------------------------------------------------

    def test_malformed_client_traffic_is_never_forwarded(self):
        blocked = call(9, "delete_file", {"path": "x"})
        for line in [
            json.dumps([blocked]).encode(),                      # a JSON-RPC batch
            json.dumps(blocked).encode()[:-1] + b",}",           # invalid JSON
            b'{"jsonrpc":"2.0","id":NaN,"method":"ping"}',       # NaN is not JSON
            json.dumps(call([1], "read_file", {})).encode(),     # invalid id
            json.dumps(call(True, "read_file", {})).encode(),    # a boolean is not an id
            b'"just a string"',
            b'{"jsonrpc":"2.0","id":1}',                         # neither request nor reply
            b'{"jsonrpc":"2.0","id":1,"method":5}',              # invalid method
            b"[" * 100_000,                                      # nesting too deep to parse
            b"\xff\xfe\x00",                                     # not text at all
        ]:
            with self.subTest(line=line[:40]):
                self.h.from_client(line)
                self.assertEqual(self.h.sent_to_server(), [])
        errors = [m for group in self.h.sent_to_client() for m in (group if isinstance(group, list) else [group])]
        self.assertEqual([m["id"] for m in errors], [9])  # only the batch gets an answer
        self.assertIn("batched", errors[0]["error"]["message"])

    def test_malformed_server_traffic_is_never_delivered(self):
        for line in [b"not json", b"[1, 2]", b'"text"', b'{"jsonrpc":"2.0","id":[1],"result":{}}']:
            with self.subTest(line=line):
                self.h.from_server(line)
                self.assertEqual(self.h.sent_to_client(), [])

    def test_a_bug_in_a_check_fails_closed(self):
        with mock.patch.object(Firewall, "check_call", side_effect=RuntimeError("bug")):
            self.h.from_client(call(1, "read_file", {"path": "a.txt"}))
        self.assertEqual(self.h.sent_to_server(), [])
        self.assertIn("internal error", self.h.sent_to_client()[0]["error"]["message"])

        self.h.from_client(call(2, "read_file", {"path": "a.txt"}))
        self.h.sent_to_server()
        with mock.patch.object(Firewall, "scan_result", side_effect=RuntimeError("bug")):
            self.h.from_server(reply(2, text_result("hello")))
        self.assertIn("internal error", self.h.sent_to_client()[0]["error"]["message"])

    def test_warnings_cannot_carry_terminal_escape_codes(self):
        tools = [{"name": "evil\x1b[2J\x1b[31m", "description": INJECTION}]
        self.h.round_trip(request(1, "tools/list"), {"tools": tools})
        self.assertIn("removed", self.h.warnings.getvalue())
        self.assertNotIn("\x1b", self.h.warnings.getvalue())


class ProxyEndToEndTests(unittest.TestCase):
    def run_proxy(self, messages):
        """Send messages through a real proxy process; return (replies by id, stderr)."""
        raw = "\n".join(json.dumps(m) for m in messages) + "\n"
        proc = subprocess.run(
            [
                sys.executable, "-m", "agent_sentinel", "proxy", "--policy", str(EXAMPLE_POLICY_PATH),
                "--", sys.executable, str(ROOT / "examples" / "fake_mcp_server.py"),
            ],
            input=raw.encode("utf-8"), capture_output=True, cwd=ROOT, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        replies = {m["id"]: m for m in map(json.loads, proc.stdout.decode().splitlines())}
        return replies, proc.stderr.decode()

    def test_a_whole_session(self):
        replies, stderr = self.run_proxy([
            request(1, "initialize"),
            request(2, "tools/list"),
            call(3, "read_file", {"path": "notes.txt"}),
            call(4, "delete_file", {"path": "notes.txt"}),
            call(5, "fetch_page", {"url": "https://evil.example"}),
            call(6, "fetch_page", {"url": "https://good.example"}),
            call(7, "search_notes", {"q": "soup"}),
            request(8, "resources/read", {"uri": "file:///good.txt"}),
            request(9, "resources/read", {"uri": "file:///evil.txt"}),
        ])
        self.assertEqual(set(replies), set(range(1, 10)))
        self.assertEqual(replies[1]["result"]["serverInfo"]["name"], "fake")
        self.assertEqual([t["name"] for t in replies[2]["result"]["tools"]], ["read_file", "fetch_page", "delete_file"])
        self.assertIn("removed 'search_notes'", stderr)
        self.assertEqual(replies[3]["result"]["content"][0]["text"], "contents of notes.txt")
        self.assertTrue(replies[4]["result"]["isError"])   # blocked by the policy
        self.assertTrue(replies[5]["result"]["isError"])   # the result contained an injection
        self.assertFalse(replies[6]["result"]["isError"])
        self.assertTrue(replies[7]["result"]["isError"])   # the tool was quarantined
        self.assertEqual(replies[8]["result"]["contents"][0]["text"], "Plain notes.")
        self.assertIn("prompt injection", replies[9]["error"]["message"])

    def test_bad_policy_file_stops_the_proxy(self):
        proc = subprocess.run(
            [sys.executable, "-m", "agent_sentinel", "proxy", "--policy", "no_such_policy.json", "--", "anything"],
            input=b"", capture_output=True, cwd=ROOT, timeout=60,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"cannot load policy", proc.stderr)


if __name__ == "__main__":
    unittest.main()
