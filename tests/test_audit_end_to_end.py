"""End-to-end: the audit chain, its key, rotation, --audit-required and the session records, through real processes.

The real `agent-sentinel proxy` runs in front of examples/fake_mcp_server.py
and the real `agent-sentinel hook claude-code` answers events, each in a
temporary home folder (see test_end_to_end.py); `agent-sentinel audit verify`
then checks what they wrote.
"""

import hashlib
import json
import os
import shutil
import sys
import unittest

from test_end_to_end import EXAMPLE_POLICY, REF, EndToEndTest, text_of

KEY = bytes(range(32))


class TheAuditTrailOfAProxy(EndToEndTest):
    def setUp(self):
        super().setUp()
        self.audit = self.folder / "audit.jsonl"
        self.key = self.folder / "keys" / "audit.key"
        self.key.parent.mkdir()
        self.key.write_bytes(KEY)
        if sys.platform != "win32":
            self.key.chmod(0o600)

    def everything(self, path):
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    def rotated_files(self):
        numbered = sorted(self.folder.glob("audit.jsonl.*"), key=lambda path: int(path.suffix[1:]))
        return [*numbered, self.audit]

    def test_a_signed_rotated_log_with_session_records_verifies_and_an_edit_is_found(self):
        proxy = self.proxy("--policy", EXAMPLE_POLICY, "--audit", self.audit, "--audit-key-file", self.key,
                           "--audit-max-bytes", "4096", "--name", "files")
        proxy.initialize()
        self.assertEqual(text_of(proxy.call(1, "read_file", {"path": "notes.txt"})), "contents of notes.txt")
        for msg_id in range(2, 14):
            self.assertRegex(text_of(proxy.call(msg_id, "delete_file", {"path": f"f{msg_id}"})),
                             r"\ABlocked by agent-sentinel: .* " + REF + r"\Z")
        self.assertEqual(proxy.stop(), 0)
        self.assertIn("records signed with a key; rotated past 4096 bytes", proxy.stderr)

        files = self.rotated_files()
        self.assertGreater(len(files), 2)
        records = [record for path in files for record in self.everything(path)]
        events = [record["event"] for record in records]
        self.assertEqual(events.count("session_start"), 1)
        self.assertEqual(events.count("protocol"), 1)
        self.assertEqual(events[-1], "session_end")
        start = next(record for record in records if record["event"] == "session_start")
        policy_sha256 = hashlib.sha256(EXAMPLE_POLICY.read_bytes()).hexdigest()
        self.assertEqual((start["server"], start["version"], start["policy_sha256"], start["monitor"], start["signed"]),
                         ("files", start["version"], policy_sha256, False, True))
        self.assertRegex(start["server_argv_sha256"], r"\A[0-9a-f]{64}\Z")
        self.assertEqual(start["server_program"].lower(), os.path.basename(sys.executable).lower())
        self.assertNotIn(str(self.folder), json.dumps(start))  # names, hashes and counts: no path
        self.assertTrue(start["host"])
        protocol = next(record for record in records if record["event"] == "protocol")
        self.assertEqual((protocol["client_info"], protocol["server_info"]),
                         ({"name": "e2e", "version": "1"}, {"name": "fake", "version": "0"}))
        end = records[-1]
        self.assertEqual(end["server_exit_code"], 0)
        blocks = [record for record in records if record.get("action") == "block"]
        self.assertEqual({record["policy"] for record in blocks}, {policy_sha256[:12]})
        every_byte = b"".join(path.read_bytes() for path in files)
        self.assertNotIn(KEY, every_byte)
        self.assertNotIn(str(self.key).encode(), every_byte)

        code, out, err = self.cli("audit", "verify", *files, "--key-file", self.key)
        self.assertEqual(code, 0, out + err)
        self.assertIn("INTACT", out)
        code, out, _ = self.cli("report", self.audit)
        self.assertIn("Integrity: hash chain intact", out)

        lines = files[0].read_bytes().splitlines(keepends=True)
        lines[1] = lines[1].replace(b'"session_start"', b'"session_stop"')
        files[0].write_bytes(b"".join(lines))
        code, out, _ = self.cli("audit", "verify", *files, "--key-file", self.key)
        self.assertEqual(code, 1)
        self.assertIn("BROKEN: ", out)
        self.assertIn("line 2: it was changed after it was written", out)

    def test_audit_required_refuses_to_start_without_a_writable_log(self):
        missing = self.folder / "no-such-folder" / "audit.jsonl"
        proxy = self.proxy("--policy", EXAMPLE_POLICY, "--audit", missing, "--audit-required")
        self.assertEqual(proxy.stop(), 2)
        self.assertIn("not starting: the audit log cannot be written, and --audit-required was given", proxy.stderr)
        proxy = self.proxy("--policy", EXAMPLE_POLICY, "--audit", missing)  # without it: it starts, and says so
        proxy.initialize()
        self.assertEqual(text_of(proxy.call(1, "read_file", {"path": "notes.txt"})), "contents of notes.txt")
        self.assertEqual(proxy.stop(), 0)
        self.assertIn("cannot write audit log", proxy.stderr)

    def test_audit_required_refuses_calls_while_the_log_cannot_be_written(self):
        proxy = self.proxy("--policy", EXAMPLE_POLICY, "--audit", self.audit, "--audit-required")
        proxy.initialize()
        self.assertEqual(text_of(proxy.call(1, "read_file", {"path": "notes.txt"})), "contents of notes.txt")
        kept = self.folder / "kept.jsonl"
        shutil.move(str(self.audit), str(kept))
        self.audit.mkdir()  # the log's name is now a folder: every write fails
        refused = proxy.call(2, "read_file", {"path": "notes.txt"})
        self.assertRegex(text_of(refused),
                         r"\ABlocked by agent-sentinel: the call could not be checked, so it was not made " + REF)
        self.audit.rmdir()
        self.assertEqual(text_of(proxy.call(3, "read_file", {"path": "notes.txt"})), "contents of notes.txt")
        self.assertEqual(proxy.stop(), 0)
        self.assertIn("what cannot be recorded is refused", proxy.stderr)

    def test_a_key_file_that_cannot_be_used_stops_the_proxy_before_the_server_starts(self):
        short = self.write("short.key", b"too short")
        proxy = self.proxy("--policy", EXAMPLE_POLICY, "--audit", self.audit, "--audit-key-file", short)
        self.assertEqual(proxy.stop(), 2)
        self.assertIn("cannot use --audit-key-file", proxy.stderr)
        self.assertNotIn("too short", proxy.stderr)
        self.assertFalse(self.audit.exists())
        proxy = self.proxy("--policy", EXAMPLE_POLICY, "--audit-required")
        self.assertEqual(proxy.stop(), 2)
        self.assertIn("need --audit FILE", proxy.stderr)

    @unittest.skipIf(sys.platform == "win32", "POSIX permissions")
    def test_on_posix_a_key_others_can_read_is_refused_and_the_log_is_owner_only(self):
        self.key.chmod(0o644)
        proxy = self.proxy("--policy", EXAMPLE_POLICY, "--audit", self.audit, "--audit-key-file", self.key)
        self.assertEqual(proxy.stop(), 2)
        self.assertIn("other users", proxy.stderr)
        proxy = self.proxy("--policy", EXAMPLE_POLICY, "--audit", self.audit)
        proxy.initialize()
        self.assertEqual(proxy.stop(), 0)
        self.assertEqual(self.audit.stat().st_mode & 0o777, 0o600)


class TheAuditTrailOfTheHook(EndToEndTest):
    def test_hook_processes_share_one_signed_chain(self):
        policy = self.write("policy.json", {"default": "block", "tools": {"Bash": "allow"}})
        audit, state = self.folder / "audit.jsonl", self.folder / "state"
        key = self.write("audit.key", KEY)
        if sys.platform != "win32":
            key.chmod(0o600)
        options = ("--policy", policy, "--audit", audit, "--state-dir", state, "--audit-key-file", key,
                   "--audit-required")
        events = [
            {"hook_event_name": "SessionStart", "source": "startup"},
            {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"},
             "tool_use_id": "t1", "permission_mode": "default"},
            {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": "x"},
             "tool_use_id": "t2", "permission_mode": "default"},
        ]
        for event in events:
            code, out, err = self.cli("hook", "claude-code", *options,
                                      stdin=json.dumps({"session_id": "s-1", **event}).encode())
            self.assertEqual(code, 0, err)
        records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([record["event"] for record in records], ["chain_start", "session_start", "call", "call"])
        code, out, err = self.cli("audit", "verify", audit, "--key-file", key)
        self.assertEqual(code, 0, out + err)


if __name__ == "__main__":
    unittest.main()
