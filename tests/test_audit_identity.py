"""Tests for where an audit record comes from: "server", "session" and "call_id".

Several proxies, and every hook process, can write to one log. These fields
let a person answer "which server did this?" and "what came back from that
call?" from the log alone.
"""

import json
import tempfile
import unittest
from pathlib import Path

from support import INJECTION, POLICY, audit_records
from test_proxy import Harness, call, reply, request, text_result
from agent_sentinel import BlockedError, Firewall


def read_audit(path):
    return audit_records(Path(path))


class AuditSetup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.audit = Path(self.tmp.name) / "audit.jsonl"

    def records(self):
        return read_audit(self.audit)


class ServerAndSession(AuditSetup):
    def test_every_record_names_the_server_and_the_session(self):
        firewall = Firewall(POLICY, audit_path=self.audit, server_name="github")
        firewall.check_call("read_file", {"path": "a.txt"})
        firewall.scan_result("fetch_page", INJECTION)
        firewall.refuse("?", "dropped a message", event="dropped")
        records = self.records()
        self.assertEqual({r["server"] for r in records}, {"github"})
        self.assertEqual({r["session"] for r in records}, {firewall.session_id})

    def test_without_a_server_name_there_is_no_server_field(self):
        firewall = Firewall(POLICY, audit_path=self.audit)
        firewall.check_call("read_file", {"path": "a.txt"})
        self.assertNotIn("server", self.records()[0])

    def test_each_firewall_is_its_own_random_session_unless_one_is_given(self):
        one, two = Firewall(POLICY), Firewall(POLICY)
        self.assertRegex(one.session_id, r"\A[0-9a-f]{16}\Z")
        self.assertNotEqual(one.session_id, two.session_id)
        self.assertEqual(Firewall(POLICY, session_id="claude-1234").session_id, "claude-1234")

    def test_server_names_are_checked_like_proxy_name(self):
        for good in ("github", "my-server_2.0", "a" * 64):
            with self.subTest(name=good):
                Firewall(POLICY, server_name=good)
        for bad in ("", "a" * 65, "has space", "../x", "naïve", "x\n", 5):
            with self.subTest(name=bad):
                with self.assertRaises(ValueError):
                    Firewall(POLICY, server_name=bad)

    def test_session_ids_must_be_short_text(self):
        for bad in ("", "x" * 257, 5):
            with self.subTest(session_id=bad):
                with self.assertRaises(ValueError):
                    Firewall(POLICY, session_id=bad)

    def test_a_hostile_session_id_cannot_break_the_record(self):
        Firewall(POLICY, audit_path=self.audit, session_id="s\n\x1b[2J ").check_call("read_file", {"path": "a"})
        raw = self.audit.read_text(encoding="utf-8")
        lines = raw.splitlines()
        self.assertEqual(len(lines), 2)  # the new log's chain_start (which names the session too), then the call
        self.assertNotIn("\x1b", raw)
        self.assertEqual(json.loads(lines[-1])["session"], "s\n\x1b[2J ")


class CallIds(AuditSetup):
    def test_a_call_and_its_result_share_a_call_id(self):
        firewall = Firewall(POLICY, audit_path=self.audit)
        firewall.run("read_file", {"path": "a.txt"}, lambda path: "hello")
        firewall.run("read_file", {"path": "b.txt"}, lambda path: "hello")
        first_call, first_result, second_call, second_result = self.records()
        self.assertEqual(first_call["call_id"], first_result["call_id"])
        self.assertEqual(second_call["call_id"], second_result["call_id"])
        self.assertNotEqual(first_call["call_id"], second_call["call_id"])
        self.assertRegex(first_call["call_id"], r"\A[0-9a-f]{16}\Z")

    def test_a_blocked_result_and_a_scanned_error_share_the_call_id(self):
        firewall = Firewall(POLICY, audit_path=self.audit)
        with self.assertRaises(BlockedError):
            firewall.run("fetch_page", {"url": "u"}, lambda url: INJECTION)

        def failing(url):
            raise ValueError(INJECTION)

        with self.assertRaises(BlockedError):
            firewall.run("fetch_page", {"url": "u"}, failing)
        records = self.records()
        self.assertEqual(records[0]["call_id"], records[1]["call_id"])
        self.assertEqual(records[2]["call_id"], records[3]["call_id"])
        self.assertEqual(records[3]["event"], "tool_error")

    def test_every_call_record_has_a_call_id_even_a_refused_one(self):
        firewall = Firewall(POLICY, audit_path=self.audit)
        firewall.check_call("delete_file", {"path": "x"})
        firewall.check_call("read_file", "not an object")
        firewall.block("x", "the program said no")
        self.assertTrue(all("call_id" in record for record in self.records()))

    def test_records_that_belong_to_no_call_have_no_call_id(self):
        firewall = Firewall(POLICY, audit_path=self.audit)
        firewall.scan_result("search_notes", {"name": "x", "description": INJECTION}, event="tool_description")
        firewall.refuse("?", "dropped", event="dropped")
        self.assertFalse(any("call_id" in record for record in self.records()))

    def test_a_caller_can_give_its_own_call_id(self):
        firewall = Firewall(POLICY, audit_path=self.audit)
        decision = firewall.check_call("read_file", {"path": "a"}, call_id="toolu_01ABC")
        firewall.scan_result("read_file", "hello", call_id="toolu_01ABC")
        self.assertEqual(decision.call_id, "toolu_01ABC")
        self.assertEqual([r["call_id"] for r in self.records()], ["toolu_01ABC", "toolu_01ABC"])

    def test_a_call_id_must_be_short_text(self):
        for bad in ("", "x" * 257, 5):
            with self.subTest(call_id=bad):
                with self.assertRaises(ValueError):
                    Firewall(POLICY).check_call("read_file", {}, call_id=bad)

    def test_monitor_mode_keeps_the_call_id(self):
        decision = Firewall(POLICY, monitor=True).check_call("delete_file", {"path": "x"}, call_id="c1")
        self.assertEqual((decision.allowed, decision.call_id), (True, "c1"))


class InTheProxy(AuditSetup):
    def test_a_tool_call_and_its_result_share_a_call_id(self):
        h = Harness(Firewall(POLICY, audit_path=self.audit, server_name="files"))
        h.list_tools("read_file", "fetch_page")  # else, under the example policy's flow rule, they count as sinks too
        h.round_trip(call(1, "read_file", {"path": "notes.txt"}), text_result("hello"))
        h.round_trip(call(2, "fetch_page", {"url": "u"}), text_result(INJECTION))
        records = self.records()
        self.assertEqual([r["event"] for r in records], ["call", "result", "call", "result"])
        self.assertEqual(records[0]["call_id"], records[1]["call_id"])
        self.assertEqual(records[2]["call_id"], records[3]["call_id"])
        self.assertNotEqual(records[0]["call_id"], records[2]["call_id"])
        self.assertEqual({r["server"] for r in records}, {"files"})

    def test_a_resource_read_and_its_result_share_a_call_id(self):
        h = Harness(Firewall(POLICY, audit_path=self.audit))
        h.round_trip(request(1, "resources/read", {"uri": "file:///a"}), {"contents": []})
        first, second = self.records()
        self.assertEqual(first["call_id"], second["call_id"])

    def test_replies_to_other_requests_have_no_call_id(self):
        h = Harness(Firewall(POLICY, audit_path=self.audit))
        h.from_client(request(1, "prompts/get", {"name": "p"}))
        h.sent_to_server()
        h.from_server(reply(1, {"messages": [{"role": "user", "content": {"type": "text", "text": INJECTION}}]}))
        (record,) = self.records()
        self.assertNotIn("call_id", record)


if __name__ == "__main__":
    unittest.main()
