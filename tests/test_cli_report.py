"""`agent-sentinel report`: filters, --show-args, JSON, --follow, --by server, top reasons (cli_report.py)."""

import contextlib
import io
import json
import unittest
from datetime import datetime, timedelta, timezone

from cli_support import TempFolderTest, run_cli
from support import POLICY
from agent_sentinel import Firewall
from agent_sentinel.auditlog import MAX_LINE_BYTES, RecordFilter
from agent_sentinel.cli_report import MAX_TABLE_ROWS, follow


def record(tool="read_file", action="block", event="call", **fields):
    base = {"time": "2026-11-18T10:00:00+00:00", "event": event, "tool": tool, "action": action, "reason": "r"}
    base.update(fields)
    return base


class Filters(TempFolderTest):
    def report(self, records, *options):
        code, out, err = run_cli("report", self.write_log("audit.jsonl", records), *options)
        self.assertEqual(code, 0, err)
        return out

    def test_the_tool_filter_takes_a_wildcard(self):
        out = self.report([record("read_file"), record("read_dir"), record("send_email")], "--tool", "read_*")
        self.assertIn("Filter: tool read_*", out)
        self.assertIn("2 records (of 3 in the log)", out)
        self.assertNotIn("send_email", out)

    def test_server_action_and_event_filters(self):
        records = [
            record(server="files", action="allow"), record(server="files"), record(server="mail"),
            record(event="result", tool="fetch_page", server="files"),
        ]
        out = self.report(records, "--server", "files", "--action", "block", "--event", "call")
        self.assertIn("1 records (of 4 in the log)", out)

    def test_since_and_until_choose_a_time_range(self):
        now = datetime.now(timezone.utc)
        old = record(tool="old_tool", time=(now - timedelta(days=3)).isoformat())
        new = record(tool="new_tool", time=(now - timedelta(minutes=5)).isoformat())
        no_time = record(tool="no_time", time="yesterday")
        out = self.report([old, new, no_time], "--since", "1h")
        self.assertIn("new_tool", out)
        self.assertNotIn("old_tool", out)
        self.assertNotIn("no_time", out)  # a time that cannot be read is outside every range
        until = (now - timedelta(days=1)).strftime("%Y-%m-%d")
        self.assertNotIn("new_tool", self.report([old, new], "--until", until))

    def test_a_filter_that_matches_nothing_says_so(self):
        self.assertIn("None of the 1 records matches the filter", self.report([record()], "--tool", "zzz"))

    def test_a_time_that_cannot_be_read_is_an_error(self):
        audit = self.write_log("audit.jsonl", [record()])
        for since in ("soon", "2026-13-45", "99999999999w", "x" * 100):
            with self.subTest(since=since):
                code, _, err = run_cli("report", audit, "--since", since)
                self.assertEqual(code, 2)
                self.assertNotIn("Traceback", err)

    def test_an_unknown_action_is_refused(self):
        code, _, _ = run_cli("report", self.write_log("audit.jsonl", [record()]), "--action", "deny")
        self.assertEqual(code, 2)


class WhatIsShown(TempFolderTest):
    def test_show_args_lists_the_arguments_of_each_block(self):
        with_args = record(args={"path": "/home/me/.ssh/id_rsa"}, rule="deny_args[0]", ref="7f3a9c21")
        audit = self.write_log("audit.jsonl", [with_args])
        _, plain, _ = run_cli("report", audit)
        self.assertNotIn("id_rsa", plain)
        _, out, _ = run_cli("report", audit, "--show-args")
        self.assertIn('args: path="/home/me/.ssh/id_rsa"', out)
        self.assertIn("[deny_args[0]; ref 7f3a9c21]", out)

    def test_top_reasons_come_with_a_way_to_fix_each(self):
        records = [record(rule="default", reason="no rule for 'x'")] * 3 + [record(rule="tools.delete_*")]
        _, out, _ = run_cli("report", self.write_log("audit.jsonl", records))
        top = out.split("Top reasons for blocks:")[1]
        self.assertLess(top.index("default"), top.index("tools.delete_*"))  # most common first
        self.assertIn("     3  default: no rule for 'x'", top)
        self.assertIn("How to fix:", top)
        self.assertIn('"read_file": "allow"', top)  # one tool: the hint names it

    def test_by_server_groups_the_calls(self):
        records = [record(server="files"), record(server="mail", action="allow"), record()]
        _, out, _ = run_cli("report", self.write_log("audit.jsonl", records), "--by", "server")
        self.assertIn("Tool calls, by server", out)
        names = ("files", "mail", "(no")
        rows = {line.split()[0]: line.split()[1:] for line in out.splitlines() if line.startswith(names)}
        self.assertEqual(rows["files"][:2], ["0", "1"])
        self.assertEqual(rows["mail"][:2], ["1", "0"])
        self.assertIn("(no", rows)

    def test_an_asked_column_appears_only_when_calls_waited_for_approval(self):
        _, out, _ = run_cli("report", self.write_log("a.jsonl", [record()]))
        self.assertNotIn("asked", out)
        _, out, _ = run_cli("report", self.write_log("b.jsonl", [record(action="ask")]))
        self.assertIn("asked", out)
        row = next(line for line in out.splitlines() if line.startswith("read_file"))
        self.assertEqual(row.split()[1:], ["0", "0", "0", "1", "0"])

    def test_a_log_with_very_many_names_is_counted_in_a_bounded_table(self):
        records = [record(tool=f"tool_{number}") for number in range(MAX_TABLE_ROWS + 50)]
        _, out, _ = run_cli("report", self.write_log("audit.jsonl", records), "--last", "0")
        self.assertIn("(other names)", out)
        self.assertLessEqual(sum(1 for line in out.splitlines() if line.startswith("tool_")), MAX_TABLE_ROWS)

    def test_a_real_log_reads_back(self):
        audit = self.folder / "audit.jsonl"
        firewall = Firewall(POLICY, audit_path=audit, server_name="files")
        firewall.check_call("read_file", {"path": "~/.ssh/id_rsa"})
        firewall.check_call("delete_file", {"path": "a"})
        _, out, _ = run_cli("report", audit, "--show-args")
        self.assertIn("deny_args[0]", out)
        self.assertIn("server files", out)


class JsonOutput(TempFolderTest):
    def test_the_json_is_valid_and_every_field_is_printable(self):
        hostile = record(tool="evil\x1b[2J", reason="r\x1b[31m‮", rule="default", args={"a": "\x07"})
        _, out, _ = run_cli("report", self.write_log("audit.jsonl", [hostile, "not json"]), "--format", "json",
                            "--show-args")
        data = json.loads(out)
        self.assertEqual(data["records"], 1)
        self.assertEqual(data["unreadable_lines"], 1)
        self.assertEqual(data["blocked"][0]["tool"], "evil\\x1b[2J")
        self.assertIn("\\x1b", data["blocked"][0]["reason"])
        self.assertIn("\\u202e", data["blocked"][0]["reason"])
        self.assertEqual(data["blocked"][0]["args"], 'a="\\u0007"')  # arguments are shown as JSON writes them
        self.assertEqual(data["calls"]["evil\\x1b[2J"]["block"], 1)
        self.assertTrue(data["top_reasons"][0]["how_to_fix"])
        self.assertTrue(out.isascii())

    def test_the_json_names_the_filter(self):
        _, out, _ = run_cli("report", self.write_log("audit.jsonl", [record()]), "--format", "json", "--tool", "r*")
        self.assertEqual(json.loads(out)["filter"]["tool"], "r*")


class Follow(TempFolderTest):
    def follow_while_writing(self, lines_to_add, chosen=RecordFilter(), show_args=False, output="text"):
        """Run follow() on a log, appending `lines_to_add` (bytes) one batch per poll, and return what it printed."""
        audit = self.write_log("audit.jsonl", [record(tool="before_follow")])
        batches = list(lines_to_add)
        polls = []

        def sleep(_seconds):
            polls.append(1)
            if batches:
                with open(audit, "ab") as handle:
                    handle.write(batches.pop(0))

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            follow(str(audit), chosen, show_args, output, stop=lambda: len(polls) > len(lines_to_add) + 2, sleep=sleep)
        return out.getvalue()

    def line(self, **fields):
        return (json.dumps(record(**fields)) + "\n").encode()

    def test_new_blocks_are_printed_one_line_each(self):
        out = self.follow_while_writing([
            self.line(tool="read_file", rule="deny_args[0]", ref="7f3a9c21", args={"path": "~/.ssh/id_rsa"}),
            self.line(tool="allowed_tool", action="allow"),
        ], show_args=True)
        self.assertNotIn("before_follow", out)  # only what is added from now on
        self.assertNotIn("allowed_tool", out)  # only blocks
        self.assertIn("BLOCK  call  read_file", out)
        self.assertIn('path="~/.ssh/id_rsa"  [deny_args[0]]  ref 7f3a9c21', out)

    def test_with_an_action_filter_every_matching_record_is_printed(self):
        out = self.follow_while_writing([self.line(tool="allowed_tool", action="allow")],
                                        chosen=RecordFilter(actions=("allow",)))
        self.assertIn("allowed_tool", out)

    def test_a_line_written_in_two_parts_is_read_once_complete(self):
        whole = self.line(tool="split_tool")
        out = self.follow_while_writing([whole[:10], whole[10:]])
        self.assertEqual(out.count("split_tool"), 1)

    def test_a_line_that_is_too_long_is_skipped_and_reported(self):
        long_line = b'{"tool": "' + b"x" * (MAX_LINE_BYTES + 10) + b'"}\n'
        out = self.follow_while_writing([long_line, self.line(tool="after_long")])
        self.assertIn("could not be read", out)
        self.assertIn("after_long", out)

    def test_hostile_fields_are_printed_safely_and_the_line_is_capped(self):
        out = self.follow_while_writing([self.line(tool="evil\x1b[2J" + "y" * 5000, reason="\x07")])
        self.assertNotIn("\x1b", out)
        self.assertTrue(all(len(line) <= 503 for line in out.splitlines()))

    def test_json_lines_can_be_followed(self):
        out = self.follow_while_writing([self.line(tool="t1")], output="json")
        printed = [json.loads(line) for line in out.splitlines()[1:]]
        self.assertEqual(printed[0]["tool"], "t1")


if __name__ == "__main__":
    unittest.main()
