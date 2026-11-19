"""`agent-sentinel demo` (agent_sentinel/cli_demo.py) and its fake server (agent_sentinel/demo_server.py)."""

import io
import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

from cli_support import TempFolderTest, run_cli
from support import ROOT
from agent_sentinel import Policy, demo_server
from agent_sentinel.cli_common import CommandError
from agent_sentinel.cli_demo import DEMO_POLICY, _ProxyProcess


class TheDemo(TempFolderTest):
    def test_it_runs_in_a_temporary_folder_that_is_deleted_and_ends_with_next_steps(self):
        env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONIOENCODING="utf-8")
        result = subprocess.run(
            [sys.executable, "-m", "agent_sentinel", "demo"], capture_output=True, cwd=self.folder, env=env,
            timeout=120,
        )
        out = result.stdout.decode("utf-8")
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(list(self.folder.iterdir()), [])  # nothing written where it was started
        folder = re.search(r"Files are written to (.+) \(deleted at the end\)", out).group(1).strip('"')
        self.assertFalse(Path(folder).exists())
        # The library part, the proxy part and the log part all happened.
        self.assertIn("BLOCKED. The agent is told: argument 'path' has a value the policy does not permit (ref ", out)
        self.assertIn("removed by the proxy: search_notes", out)
        self.assertIn("the agent reads: Blocked by agent-sentinel: argument 'path' has a value the policy does not "
                      "permit", out)
        self.assertIn("the agent reads: contents of notes/todo.txt", out)
        self.assertIn("Top reasons for blocks:", out)
        self.assertIn("decided by:  deny_args[0], argument 'path'", out)
        self.assertIn("=== Next steps ===", out)
        self.assertIn("agent-sentinel check policy.json", out)
        # Hostile text from the fake server never reaches the terminal raw.
        self.assertNotIn("<IMPORTANT>", out)
        self.assertNotIn("\x1b", out)

    def test_keep_writes_the_policy_and_the_log_to_the_folder_given(self):
        kept = self.folder / "demo files"
        code, out, err = run_cli("demo", "--keep", kept)
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(path.name for path in kept.iterdir()), ["audit.jsonl", "policy.json"])
        Policy.from_file(kept / "policy.json")  # a policy the user can start from
        records = [json.loads(line) for line in (kept / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertTrue(any(record.get("event") == "tool_description" for record in records))  # from the proxy
        self.assertTrue(any(record.get("tool") == "send_email" for record in records))  # from the library
        self.assertIn(f'kept at "{kept.resolve() / "policy.json"}"', out)  # the full path, ready to copy

    def test_keep_refuses_a_folder_that_has_files_in_it(self):
        self.write("precious.txt", "keep me")
        code, _, err = run_cli("demo", "--keep", self.folder)
        self.assertEqual(code, 2)
        self.assertIn("is not empty", err)
        self.assertEqual((self.folder / "precious.txt").read_text(encoding="utf-8"), "keep me")
        code, _, err = run_cli("demo", "--keep", self.folder / "precious.txt")
        self.assertEqual(code, 2)
        self.assertIn("is a file", err)

    def test_a_proxy_that_stops_early_is_reported_with_what_it_said(self):
        bad_policy = self.write("policy.json", '{"default": "maybe"}')
        proxy = _ProxyProcess(bad_policy, self.folder / "audit.jsonl")
        try:
            with self.assertRaises(CommandError) as caught:
                proxy.request(1, "initialize", {})
        finally:
            proxy.close()
        self.assertIn("the proxy stopped before it answered the initialize request", str(caught.exception))
        self.assertIn("cannot load policy", str(caught.exception))

    def test_the_demo_policy_loads_and_blocks_what_the_demo_says(self):
        policy = Policy.from_dict(json.loads(json.dumps(DEMO_POLICY)))
        self.assertEqual(policy.evaluate("read_file", {"path": "/home/me/.ssh/id_rsa"}).rule, "deny_args[0]")
        self.assertEqual(policy.evaluate("send_email", {"to": "boss@example.com"}).action, "ask")
        self.assertEqual(policy.evaluate("send_email", {"to": "attacker@evil.example"}).action, "block")


class TheDemoServer(unittest.TestCase):
    def test_it_answers_initialize_list_and_call(self):
        info = demo_server.answer({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(info["result"]["serverInfo"]["name"], demo_server.SERVER_NAME)
        listed = demo_server.answer({"id": 2, "method": "tools/list"})
        self.assertIn("search_notes", [tool["name"] for tool in listed["result"]["tools"]])
        called = demo_server.answer({"id": 3, "method": "tools/call",
                                     "params": {"name": "fetch_page", "arguments": {"url": "https://evil.x"}}})
        self.assertEqual(called["result"]["content"][0]["text"], demo_server.POISONED_PAGE)

    def test_notifications_and_odd_messages_get_no_answer(self):
        for message in ({"method": "notifications/initialized"}, [1], "x", None):
            self.assertIsNone(demo_server.answer(message))
        odd = demo_server.answer({"id": 4, "method": "tools/call", "params": "not an object"})
        self.assertIn("unknown tool", odd["result"]["content"][0]["text"])

    def test_it_serves_lines_and_skips_what_is_not_json(self):
        stdin = io.StringIO('not json\n{"id": 1, "method": "tools/list"}\n{"method": "notifications/x"}\n')
        stdout = io.StringIO()
        demo_server.serve(stdin, stdout)
        replies = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual([reply["id"] for reply in replies], [1])


if __name__ == "__main__":
    unittest.main()
