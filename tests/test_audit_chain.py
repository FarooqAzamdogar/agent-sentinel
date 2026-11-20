"""The audit log's hash chain, MACs, rotation, audit_required, file permissions and provenance records.

(agent_sentinel/audit_chain.py, firewall.py, cli_audit.py, and what report, explain and suggest make of it.)
"""

import contextlib
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from cli_support import TempFolderTest, run_cli
from support import POLICY, ROOT, audit_records
from agent_sentinel import Firewall, Policy, auditlog
from agent_sentinel import audit_chain
from agent_sentinel.audit_chain import (
    GENESIS,
    MAX_PROBLEMS_KEPT,
    AuditKeyError,
    chained_line,
    check_files,
    parse_max_bytes,
    parse_trailer,
    read_key_file,
)

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
_CHAIN_FIELDS = re.compile(rb', "seq": [0-9]+, "prev": "[0-9a-f]{64}", "hash": "[0-9a-f]{64}"(, "mac": "[0-9a-f]{64}")?\}$')


def raw_lines(path):
    """The lines of a file as bytes, each with its newline."""
    return Path(path).read_bytes().splitlines(keepends=True)


def all_records(path):
    """Every record of a log, the chain_start and session records included."""
    return [json.loads(line) for line in raw_lines(path)]


def unchained(line):
    """A chained line as it was before its chain fields were added (what an attacker would edit)."""
    return _CHAIN_FIELDS.sub(b"}", line.rstrip(b"\n")).decode("utf-8")


def rechain(lines, start, key=None):
    """Work out seq, prev, hash (and with a key, mac) again from line `start` on: what anyone who can write the
    file can do without the key, and what a key holder can do with it."""
    lines = list(lines)
    previous = parse_trailer(lines[start - 1].rstrip(b"\n")) if start else None
    seq, prev = (previous.seq + 1, previous.digest) if previous else (0, GENESIS)
    for index in range(start, len(lines)):
        lines[index], prev = chained_line(unchained(lines[index]), seq, prev, key)
        seq += 1
    return lines


class LogTest(TempFolderTest):
    def setUp(self):
        super().setUp()
        self.audit = self.folder / "audit.jsonl"
        self.key_file = self.folder / "audit.key"
        self.key_file.write_bytes(KEY)
        if sys.platform != "win32":
            self.key_file.chmod(0o600)

    def firewall(self, policy=POLICY, **options):
        return Firewall(policy, audit_path=self.audit, **options)

    def write_calls(self, count, firewall=None, **options):
        firewall = firewall or self.firewall(**options)
        for number in range(count):
            firewall.check_call("read_file" if number % 2 else "delete_file", {"path": f"f{number}"})
        return firewall

    def check(self, *paths, key=None):
        return check_files([str(path) for path in (paths or (self.audit,))], key)


# ---- writing --------------------------------------------------------------------------------------------

class Writing(LogTest):
    def test_a_new_log_starts_with_chain_start_and_each_record_links_to_the_one_before(self):
        self.write_calls(5)
        lines = raw_lines(self.audit)
        records = [json.loads(line) for line in lines]
        start = records[0]
        self.assertEqual((start["event"], start["action"], start["start"], start["chain"]),
                         ("chain_start", "note", "new", 1))
        self.assertEqual((start["seq"], start["prev"]), (0, GENESIS))
        self.assertNotIn("tool", start)
        self.assertEqual([record["seq"] for record in records], list(range(6)))
        for before, after in zip(lines, lines[1:]):
            self.assertEqual(json.loads(after)["prev"], json.loads(before)["hash"])
        self.assertEqual(list(records[1])[-3:], ["seq", "prev", "hash"])  # the chain fields come last
        self.assertEqual(self.check().state, "intact")

    def test_the_hash_is_of_the_line_without_hash_and_mac(self):
        self.write_calls(1, audit_key_file=self.key_file)
        line = raw_lines(self.audit)[-1].rstrip(b"\n")
        record = json.loads(line)
        body = line[: line.index(b', "hash": ')] + b"}"
        self.assertEqual(record["hash"], hashlib.sha256(body).hexdigest())
        import hmac
        self.assertEqual(record["mac"], hmac.new(KEY, body, hashlib.sha256).hexdigest())

    def test_a_damaged_last_line_starts_a_new_chain_and_never_fails_the_calls(self):
        self.write_calls(2)
        with open(self.audit, "ab") as handle:
            handle.write(b'{"time": "2026-11-20T10:00:00+00:00", "event": "call", "tool": "x", "act')  # cut short
        decision = self.firewall().check_call("read_file", {"path": "a"})
        self.assertTrue(decision.allowed)
        start = [record for record in self.records_after(2) if record.get("event") == "chain_start"]
        self.assertEqual([(record["start"], record["seq"], record["prev"]) for record in start],
                         [("restart", 0, GENESIS)])
        self.assertIn("incomplete", start[0]["reason"])
        report = self.check()
        self.assertEqual((report.state, report.problem_count), ("broken", 1))  # only the damaged line
        self.assertEqual(report.problems[0], "line 4: it is not a JSON object")  # the damaged line, ended

    def records_after(self, count):
        """The records after the first `count` lines, skipping a line that is not JSON."""
        found = []
        for line in raw_lines(self.audit)[count:]:
            try:
                found.append(json.loads(line))
            except ValueError:
                continue
        return found

    def test_a_log_written_before_the_chain_gets_a_restart_and_checks_as_intact(self):
        old = {"time": "2026-11-18T10:00:00+00:00", "session": "s", "event": "call", "tool": "t", "action": "allow",
               "reason": "r"}
        self.audit.write_bytes((json.dumps(old) + "\n").encode() * 3)
        self.write_calls(2)
        records = all_records(self.audit)
        self.assertEqual((records[3]["event"], records[3]["start"]), ("chain_start", "restart"))
        self.assertIn("no chain fields", records[3]["reason"])
        report = self.check()
        self.assertEqual((report.state, report.unchained_prefix, report.chained), ("intact", 3, 3))

    def test_a_record_far_longer_than_the_end_that_is_read_is_still_linked(self):
        firewall = self.firewall(Policy.from_dict({"default": "allow"}))
        firewall.check_call("write", {"text": "x" * 90_000})  # a line much longer than TAIL_BYTES
        firewall.check_call("write", {"text": "y"})
        events = [record["event"] for record in all_records(self.audit)]
        self.assertEqual(events, ["chain_start", "call", "call"])  # no restart
        self.assertEqual(self.check().state, "intact")

    def test_appending_to_a_huge_log_reads_only_its_end(self):
        with open(self.audit, "wb") as handle:
            handle.write((b"x" * 1_000_000 + b"\n") * 30)  # 30 MB of lines that are not records
        reads = []
        real_read = audit_chain._read_exactly

        def counting(handle, count):
            reads.append(count)
            return real_read(handle, count)

        started = time.perf_counter()
        with mock.patch.object(audit_chain, "_read_exactly", counting):
            self.assertTrue(self.firewall().check_call("read_file", {"path": "a"}).allowed)
        self.assertLess(time.perf_counter() - started, 2)
        self.assertEqual(reads, [audit_chain.TAIL_BYTES])
        tail = raw_lines(self.audit)[-2:]
        self.assertEqual(json.loads(tail[0])["start"], "restart")

    def test_threads_sharing_a_log_never_fork_the_chain(self):
        def work():
            self.write_calls(40, firewall=self.firewall())

        threads = [threading.Thread(target=work) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        report = self.check()
        self.assertEqual((report.state, report.chained, report.last_seq), ("intact", 161, 160))

    def test_processes_sharing_a_log_never_fork_the_chain(self):
        script = (
            "import sys\n"
            "from agent_sentinel import Firewall, Policy\n"
            "firewall = Firewall(Policy.from_dict({'default': 'allow'}), audit_path=sys.argv[1],"
            " audit_key_file=sys.argv[2])\n"
            "for number in range(25):\n"
            "    firewall.check_call('t', {'n': number})\n"
        )
        environment = {**os.environ, "PYTHONPATH": str(ROOT)}
        environment.pop("AGENT_SENTINEL_HOME", None)
        processes = [subprocess.Popen([sys.executable, "-c", script, str(self.audit), str(self.key_file)],
                                      env=environment) for _ in range(3)]
        for process in processes:
            self.assertEqual(process.wait(timeout=60), 0)
        report = self.check(key=KEY)
        self.assertEqual((report.state, report.chained, report.mac_mismatches), ("intact", 76, 0))


class FilePermissions(LogTest):
    def test_the_log_and_a_rotated_file_are_created_owner_only(self):
        modes = {}
        real_open = os.open

        def recording(path, flags, mode=0o777, *args, **kwargs):
            if flags & os.O_CREAT:
                modes[Path(path).name] = mode
            return real_open(path, flags, mode, *args, **kwargs)

        with mock.patch("agent_sentinel.audit_chain.os.open", recording):
            self.write_calls(30, audit_max_bytes=4096)
        self.assertEqual(modes["audit.jsonl"], 0o600)
        self.assertEqual(modes["audit.jsonl.1"], 0o600)

    @unittest.skipIf(sys.platform == "win32", "POSIX permissions")
    def test_on_posix_the_files_are_0600(self):
        old = os.umask(0o022)
        try:
            self.write_calls(30, audit_max_bytes=4096)
        finally:
            os.umask(old)
        for path in (self.audit, self.folder / "audit.jsonl.1"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


# ---- checking --------------------------------------------------------------------------------------------

class Verifying(LogTest):
    def setUp(self):
        super().setUp()
        self.write_calls(8, audit_key_file=self.key_file)
        self.lines = raw_lines(self.audit)

    def tampered(self, lines):
        self.audit.write_bytes(b"".join(lines))
        return self.check(), self.check(key=KEY)

    def test_an_untouched_log_is_intact_with_and_without_the_key(self):
        plain, keyed = self.check(), self.check(key=KEY)
        self.assertEqual((plain.state, keyed.state), ("intact", "intact"))
        self.assertEqual((plain.macs_present, keyed.mac_mismatches), (9, 0))
        self.assertEqual(keyed.last_hash, json.loads(self.lines[-1])["hash"])

    def test_an_edited_record_no_longer_matches_its_hash(self):
        lines = list(self.lines)
        lines[4] = lines[4].replace(b'"action": "allow"', b'"action": "block"')  # line 5: an allowed call
        plain, keyed = self.tampered(lines)
        self.assertEqual(plain.state, "broken")
        self.assertIn("line 5: it was changed after it was written", plain.problems[0])
        self.assertEqual(keyed.mac_mismatches, 1)

    def test_an_edit_with_its_hash_worked_out_again_breaks_the_next_link(self):
        lines = list(self.lines)
        edited = unchained(lines[4]).replace('"action": "allow"', '"action": "block"')
        record = json.loads(lines[4])
        lines[4] = chained_line(edited, record["seq"], record["prev"], None)[0]
        plain, _ = self.tampered(lines)
        self.assertIn("line 6: it does not link to the record before it", plain.problems[0])

    def test_without_the_key_a_full_rewrite_is_not_detected_and_with_it_every_line_is(self):
        lines = list(self.lines)
        lines[4] = unchained(lines[4]).replace('"action": "allow"', '"action": "block"').encode() + b"\n"
        lines = rechain(lines, 4)  # the attacker recomputes every hash after the edit, but has no key
        plain, keyed = self.tampered(lines)
        self.assertEqual(plain.state, "intact")  # the honest limit of a chain without a key
        self.assertEqual(keyed.state, "broken")
        self.assertEqual(keyed.mac_mismatches, len(lines) - 4)
        self.assertIn("has no MAC, though a key was given", keyed.problems[0])

    def test_a_rewrite_with_another_key_is_named(self):
        self.audit.unlink()
        self.key_file.write_bytes(OTHER_KEY)
        self.write_calls(2, audit_key_file=self.key_file)
        report = self.check(key=KEY)
        self.assertEqual(report.mac_mismatches, 3)
        self.assertIn("another key", " ".join(report.notes))

    def test_a_removed_record_is_reported_as_missing(self):
        report, _ = self.tampered(self.lines[:4] + self.lines[5:])
        self.assertEqual(report.problems[0], "line 5: 1 record(s) are missing before it (seq 4 to 4)")

    def test_moved_inserted_and_repeated_records_are_out_of_order(self):
        swapped = self.lines[:3] + [self.lines[4], self.lines[3]] + self.lines[5:]
        repeated = self.lines[:5] + [self.lines[2]] + self.lines[5:]
        for lines in (swapped, repeated):
            with self.subTest(count=len(lines)):
                report, _ = self.tampered(lines)
                self.assertEqual(report.state, "broken")
                self.assertTrue(any("out of order" in problem for problem in report.problems), report.problems)

    def test_an_inserted_line_without_chain_fields_is_reported(self):
        forged = json.dumps({"time": "t", "event": "call", "tool": "x", "action": "allow", "reason": "r"}).encode()
        report, _ = self.tampered(self.lines[:4] + [forged + b"\n"] + self.lines[4:])
        self.assertEqual(report.problems[0], "line 5: it has no chain fields: it was inserted, or written by "
                                             "agent-sentinel 0.5 or earlier")

    def test_records_cut_from_the_start_are_reported(self):
        report, _ = self.tampered(self.lines[3:])
        self.assertIn("line 1: the file does not start with a chain_start record", report.problems[0])

    def test_records_cut_from_the_end_are_not_detected(self):
        report, keyed = self.tampered(self.lines[:-3])  # the documented limit: keep the last seq and hash elsewhere
        self.assertEqual((report.state, keyed.state), ("intact", "intact"))
        self.assertEqual(report.last_seq, 5)

    def test_a_repeated_key_or_a_cut_line_is_broken(self):
        line = self.lines[2].rstrip(b"\n")
        repeated = line[:-1] + b', "action": "block"}\n'  # not the chain's text any more, so no chain fields found
        doubled = b'{"action": "block", ' + line[1:] + b"\n"  # chain fields intact, a key repeated
        for lines, words in ((self.lines[:2] + [repeated] + self.lines[3:], "no chain fields"),
                             (self.lines[:2] + [doubled] + self.lines[3:], "repeats a key"),
                             (self.lines[:-1] + [self.lines[-1].rstrip(b"\n")], "incomplete")):
            with self.subTest(words=words):
                report, _ = self.tampered(lines)
                self.assertTrue(any(words in problem for problem in report.problems), report.problems)

    def test_a_restart_in_the_middle_of_an_intact_chain_is_reported(self):
        self.audit.write_bytes(b"".join(self.lines))
        start = json.loads(self.lines[0])
        start.update(start="restart", reason="forged")
        for name in ("seq", "prev", "hash", "mac"):
            start.pop(name)
        forged = chained_line(json.dumps(start), 0, GENESIS, KEY)[0]
        report, _ = self.tampered(self.lines + [forged])
        self.assertIn("a new chain starts although the record before it is intact", report.problems[0])

    def test_problems_are_counted_but_only_the_first_few_kept(self):
        lines = [line.replace(b'"action"', b'"action" ') for line in self.lines]  # every hash now wrong
        self.write_calls(40, audit_key_file=self.key_file)
        lines += [line.replace(b'"action"', b'"action" ') for line in raw_lines(self.audit)[len(self.lines):]]
        report, _ = self.tampered(lines)
        self.assertEqual(len(report.problems), MAX_PROBLEMS_KEPT)
        self.assertGreater(report.problem_count, MAX_PROBLEMS_KEPT)

    def test_a_carriage_return_at_the_end_of_a_chained_line_is_reported_once(self):
        lines = [line.replace(b"\n", b"\r\n") for line in self.lines]
        report, _ = self.tampered(lines)
        self.assertEqual(report.problem_count, len(lines))
        self.assertIn("carriage return", report.problems[0])

    def test_a_hostile_log_is_checked_quickly(self):
        with open(self.audit, "wb") as handle:
            handle.write(b'{"a": 1, "seq": 5}\n' * 100_000)
            handle.write(b"[" * 1_000_000 + b"\n")
            handle.write(b'{"n": ' + b"9" * 3_000_000 + b"}\n")
            handle.write((b', "seq": 1' * 200_000) + b"\n")
        started = time.perf_counter()
        report = self.check()
        self.assertLess(time.perf_counter() - started, 10)
        self.assertEqual(report.state, "broken")


class Rotation(LogTest):
    def rotated(self):
        """The rotated files then the log, oldest first."""
        numbered = sorted(self.folder.glob("audit.jsonl.*"), key=lambda path: int(path.suffix[1:]))
        return [*numbered, self.audit]

    def test_the_log_is_moved_aside_and_its_chain_goes_on_in_the_next_file(self):
        self.write_calls(40, audit_key_file=self.key_file, audit_max_bytes=4096)
        files = self.rotated()
        self.assertGreater(len(files), 3)
        for path in files:
            self.assertLessEqual(path.stat().st_size, 4096 + 2000)
        calls = sum(len(audit_records(path)) for path in files)
        self.assertEqual(calls, 40)  # nothing was deleted
        first = all_records(files[1])[0]
        self.assertEqual((first["event"], first["start"], first["previous_file"]),
                         ("chain_start", "rotated", "audit.jsonl.1"))
        self.assertEqual(first["prev"], all_records(files[0])[-1]["hash"])
        report = self.check(*files, key=KEY)
        self.assertEqual((report.state, report.first_seq), ("intact", 0), report.problems)
        alone = self.check()
        self.assertEqual(alone.state, "intact")
        self.assertIn("give the older files first", alone.notes[0])

    def test_files_given_out_of_order_or_with_one_missing_are_broken(self):
        self.write_calls(40, audit_max_bytes=4096)
        files = self.rotated()
        for order in ([files[1], files[0], *files[2:]], [files[0], *files[2:]]):
            with self.subTest(order=[path.name for path in order]):
                report = self.check(*order)
                self.assertEqual(report.state, "broken")
                self.assertIn("does not continue the file before it", " ".join(report.problems))

    def test_a_file_already_at_a_rotated_name_is_never_overwritten(self):
        taken = self.folder / "audit.jsonl.1"
        taken.write_bytes(b"someone else's file\n")
        self.write_calls(20, audit_max_bytes=4096)
        self.assertEqual(taken.read_bytes(), b"someone else's file\n")
        self.assertTrue((self.folder / "audit.jsonl.2").exists())

    def test_the_size_must_be_a_whole_number_in_range(self):
        self.assertEqual(parse_max_bytes("1048576"), 1048576)
        for text in ("0", "100", "1023", "abc", "-5", "1e6", "9" * 20, " 2048", ""):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_max_bytes(text)
        for value in (100, True, 2.5e6, "4096"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Firewall(POLICY, audit_path=self.audit, audit_max_bytes=value)


class Keys(LogTest):
    def test_a_line_ending_after_the_key_is_not_part_of_it(self):
        for data, key in ((b"a" * 32 + b"\n", b"a" * 32), (b"b" * 32 + b"\r\n", b"b" * 32), (KEY, KEY)):
            self.key_file.write_bytes(data)
            self.assertEqual(read_key_file(self.key_file), key)

    def test_a_key_that_cannot_be_used_is_refused_without_naming_the_file(self):
        cases = {"short": b"x" * 15 + b"\n", "large": b"x" * 2000}
        for name, data in cases.items():
            self.key_file.write_bytes(data)
            with self.subTest(name=name), self.assertRaises(AuditKeyError) as caught:
                read_key_file(self.key_file)
            self.assertNotIn(str(self.folder), str(caught.exception))
        for path in (self.folder / "missing.key", self.folder):
            with self.subTest(path=path.name), self.assertRaises(AuditKeyError) as caught:
                read_key_file(path)
            self.assertNotIn(str(self.folder), str(caught.exception))

    @unittest.skipIf(sys.platform == "win32", "POSIX permissions")
    def test_on_posix_a_key_others_can_read_or_write_is_refused(self):
        for mode in (0o640, 0o604, 0o620, 0o666):
            self.key_file.chmod(mode)
            with self.subTest(mode=oct(mode)), self.assertRaisesRegex(AuditKeyError, "other users"):
                read_key_file(self.key_file)
        self.key_file.chmod(0o400)
        self.assertEqual(read_key_file(self.key_file), KEY)

    def test_the_key_never_reaches_the_log_and_the_options_need_a_log(self):
        self.write_calls(3, audit_key_file=self.key_file)
        log = self.audit.read_bytes()
        self.assertNotIn(KEY, log)
        self.assertNotIn(KEY.hex().encode(), log)
        self.assertNotIn(str(self.key_file).encode(), log)
        self.assertEqual(all_records(self.audit)[0]["key_id"], audit_chain.key_id(KEY))
        self.assertNotEqual(audit_chain.key_id(KEY), audit_chain.key_id(OTHER_KEY))
        for options in ({"audit_key_file": self.key_file}, {"audit_required": True}, {"audit_max_bytes": 4096}):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, "need an audit_path"):
                Firewall(POLICY, **options)


# ---- audit_required ---------------------------------------------------------------------------------------

class AuditRequired(LogTest):
    UNCHECKED = r"\Athe call could not be checked, so it was not made \(ref [0-9a-f]{8}\)\Z"

    def failing(self):
        """While active, every append fails as it does on a full disk."""
        return mock.patch("agent_sentinel.firewall.append_chained", side_effect=OSError(28, "No space left on device"))

    def test_without_it_a_write_error_is_reported_once_and_calls_go_on(self):
        firewall = self.firewall()
        with self.failing(), contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertTrue(firewall.check_call("read_file", {"path": "a"}).allowed)
            self.assertTrue(firewall.check_call("read_file", {"path": "b"}).allowed)
        self.assertEqual(stderr.getvalue().count("cannot write audit log"), 1)

    def test_with_it_what_cannot_be_recorded_is_refused_in_neutral_words(self):
        firewall = self.firewall(audit_required=True)
        with self.failing(), contextlib.redirect_stderr(io.StringIO()) as stderr:
            refused = firewall.check_call("read_file", {"path": "a"})
            blocked = firewall.check_call("delete_file", {"path": "a"})
            result = firewall.check_result("read_file", "hello")
        self.assertEqual((refused.allowed, refused.rule), (False, "audit_required"))
        self.assertRegex(refused.public_reason, self.UNCHECKED)
        self.assertEqual(blocked.rule, "tools.delete_*")  # a block stays the block it was
        self.assertEqual((result.decision.allowed, result.content), (False, None))
        self.assertTrue(result.decision.public_reason.startswith("the content could not be checked, so it was withheld"))
        self.assertIn("what cannot be recorded is refused", stderr.getvalue())
        self.assertTrue(firewall.check_call("read_file", {"path": "a"}).allowed)  # writable again: back to normal

    def test_monitor_mode_does_not_lift_it(self):
        firewall = self.firewall(audit_required=True, monitor=True)
        with self.failing(), contextlib.redirect_stderr(io.StringIO()):
            for tool in ("read_file", "delete_file"):
                decision = firewall.check_call(tool, {"path": "a"})
                self.assertEqual((decision.allowed, decision.rule), (False, "audit_required"))

    def test_a_call_waiting_for_approval_and_an_approval_need_their_records_too(self):
        policy = Policy.from_dict({"tools": {"send": "ask"}})
        firewall = self.firewall(policy, audit_required=True)
        with self.failing(), contextlib.redirect_stderr(io.StringIO()):
            refused = firewall.check_call("send", {}, defer_ask=True)
        self.assertEqual((refused.pending, refused.allowed, refused.rule), (False, False, "audit_required"))
        pending = firewall.check_call("send", {}, defer_ask=True)
        self.assertTrue(pending.pending)
        with self.failing(), contextlib.redirect_stderr(io.StringIO()):
            final = firewall.finish_approval(pending, True, "a person")
        self.assertEqual((final.allowed, final.rule, final.ref), (False, "audit_required", pending.ref))

    def test_the_refusal_is_recorded_when_the_log_comes_back(self):
        firewall = self.firewall(audit_required=True)
        calls = []

        def once(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise OSError("busy")
            return audit_chain.append_chained(*args, **kwargs)

        with mock.patch("agent_sentinel.firewall.append_chained", once), contextlib.redirect_stderr(io.StringIO()):
            refused = firewall.check_call("read_file", {"path": "a"})
        (record,) = audit_records(self.audit)
        self.assertEqual((record["rule"], record["ref"], record["action"]), ("audit_required", refused.ref, "block"))


# ---- provenance -------------------------------------------------------------------------------------------

class Provenance(LogTest):
    def test_a_block_names_the_policy_file_it_was_decided_by(self):
        policy_file = self.write("policy.json", {"default": "block", "tools": {"read_file": "allow"}})
        digest = hashlib.sha256(policy_file.read_bytes()).hexdigest()
        policy = Policy.from_file(policy_file)
        self.assertEqual(policy.source_sha256, digest)
        firewall = self.firewall(policy, monitor=False)
        firewall.check_call("read_file", {"path": "a"})
        firewall.check_call("write_file", {"path": "a"})
        allowed, blocked = audit_records(self.audit)
        self.assertNotIn("policy", allowed)
        self.assertEqual(blocked["policy"], digest[:12])
        self.assertEqual(Firewall(policy).policy_sha256, digest)
        self.assertIsNone(Policy.from_dict({}).source_sha256)
        self.assertIsNone(Firewall(Policy()).policy_sha256)

    def test_a_session_record_has_the_identity_fields_and_its_details(self):
        firewall = self.firewall(server_name="files", session_id="s-1")
        token = "ghp_" + "a1B2c3D4e5" * 4
        written = firewall.provenance("session_start", "the proxy started",
                                      {"version": "1", "argv": [token], "nothing": None, "seq": 99, "mac": "x"})
        self.assertTrue(written)
        record = all_records(self.audit)[-1]
        self.assertEqual({key: record[key] for key in ("server", "session", "event", "action", "reason", "version")},
                         {"server": "files", "session": "s-1", "event": "session_start", "action": "note",
                          "reason": "the proxy started", "version": "1"})
        self.assertNotIn("tool", record)
        self.assertNotIn("nothing", record)
        self.assertEqual((record["seq"], "mac" in record), (1, False))  # a detail cannot pose as a chain field
        self.assertEqual(self.check().state, "intact")
        self.assertNotIn(token, self.audit.read_text(encoding="utf-8"))
        self.assertTrue(auditlog.is_meta(record))
        self.assertTrue(Firewall(POLICY).provenance("session_end", "no log"))

    def test_the_helpers_bound_and_mask_what_they_record(self):
        info = audit_chain.peer_info({"name": "x\x1b[2J" + "y" * 500, "version": 3, "other": "z"})
        self.assertEqual(set(info), {"name"})
        self.assertNotIn("\x1b", info["name"])
        self.assertLess(len(info["name"]), 200)
        self.assertIsNone(audit_chain.peer_info("not an object"))
        token = "ghp_" + "a1B2c3D4e5" * 4
        masked = audit_chain.argv_sha256(["server", "--token", token], Firewall(POLICY).redact)
        same = audit_chain.argv_sha256(["server", "--token", "ghp_" + "Z9y8X7w6V5" * 4], Firewall(POLICY).redact)
        self.assertEqual(masked, same)  # the secret is masked before hashing
        self.assertEqual(audit_chain.file_sha256(self.key_file), hashlib.sha256(KEY).hexdigest())
        self.assertIsNone(audit_chain.file_sha256(self.folder / "missing"))


# ---- what the readers make of it -------------------------------------------------------------------------

class Readers(LogTest):
    def test_report_prints_the_state_and_leaves_the_chain_and_session_records_out(self):
        firewall = self.write_calls(4)
        firewall.provenance("session_start", "started", {"version": "1"})
        code, out, err = run_cli("report", self.audit)
        self.assertEqual(code, 0, err)
        self.assertIn("Integrity: hash chain intact, seq 0 to 5; no MACs (written without a key).", out)
        self.assertIn("4 records from", out)
        self.assertNotIn("chain_start", out)
        self.assertNotIn("session_start", out)
        data = json.loads(run_cli("report", self.audit, "--format", "json")[1])
        self.assertEqual((data["records"], data["integrity"]["state"], data["integrity"]["chain_and_session_records"]),
                         (4, "intact", 2))

    def test_report_and_explain_say_when_the_chain_is_broken_or_absent(self):
        self.write_calls(4)
        lines = raw_lines(self.audit)
        self.audit.write_bytes(b"".join(lines[:2] + lines[3:]))
        for command in (("report",), ("explain",)):
            with self.subTest(command=command):
                _, out, _ = run_cli(*command, self.audit)
                self.assertIn("Integrity: BROKEN at line 3: 1 record(s) are missing before it (seq 2 to 2). "
                              "Details: agent-sentinel audit verify", out)
        old = self.write_log("old.jsonl", [{"event": "call", "tool": "t", "action": "block", "reason": "r"}])
        for command in ("report", "explain"):
            with self.subTest(command=command):
                self.assertIn("Integrity: no hash chain", run_cli(command, old)[1])

    def test_suggest_and_explain_read_a_log_with_every_kind_of_record(self):
        policy_file = self.write("policy.json", {"default": "block"})
        firewall = self.firewall(Policy.from_file(policy_file), monitor=True)
        firewall.provenance("session_start", "started", {"version": "1"})
        firewall.check_call("search", {"q": "x"})
        firewall.provenance("protocol", "handshake", {"client_info": {"name": "c"}})
        firewall.provenance("session_end", "stopped", {"server_exit_code": 0})
        code, out, err = run_cli("suggest", self.audit, "--policy", policy_file)
        self.assertEqual(code, 0, err)
        self.assertIn('"search"', out)
        code, out, err = run_cli("explain", self.audit)
        self.assertEqual(code, 0, err)
        self.assertIn("WOULD BE BLOCKED", out)


# ---- agent-sentinel audit verify ----------------------------------------------------------------------------

class TheCommand(LogTest):
    def verify(self, *args):
        return run_cli("audit", "verify", *args)

    def test_an_intact_log_exits_0_and_prints_what_to_keep(self):
        self.write_calls(3, audit_key_file=self.key_file)
        code, out, err = self.verify(self.audit, "--key-file", self.key_file)
        self.assertEqual(code, 0, err)
        self.assertIn("INTACT", out)
        self.assertIn("every chained record's MAC matches", out)
        last = all_records(self.audit)[-1]
        self.assertIn(f"Last record: seq 3, hash {last['hash']}", out)
        code, out, _ = self.verify(self.audit)
        self.assertEqual(code, 0)
        self.assertIn("not checked: the records carry MACs", out)

    def test_a_broken_or_unchained_log_exits_1(self):
        self.write_calls(5, audit_key_file=self.key_file)
        lines = raw_lines(self.audit)
        self.audit.write_bytes(b"".join(lines[:2] + lines[3:]))
        code, out, _ = self.verify(self.audit, "--key-file", self.key_file)
        self.assertEqual(code, 1)
        self.assertIn("BROKEN: line 3: 1 record(s) are missing before it", out)
        old = self.write_log("old.jsonl", [{"event": "call"}])
        code, out, _ = self.verify(old)
        self.assertEqual(code, 1)
        self.assertIn("NOT VERIFIABLE", out)
        self.assertEqual(self.verify(self.write("empty.jsonl", ""))[0], 0)

    def test_a_wrong_key_exits_1_and_names_the_mismatches(self):
        self.write_calls(2, audit_key_file=self.key_file)
        other = self.write("other.key", "z" * 40)
        if sys.platform != "win32":
            other.chmod(0o600)
        code, out, _ = self.verify(self.audit, "--key-file", other)
        self.assertEqual(code, 1)
        self.assertIn("MAC mismatches: 3", out)

    def test_rotated_files_are_checked_in_the_order_given(self):
        self.write_calls(30, audit_max_bytes=4096)
        numbered = sorted(self.folder.glob("audit.jsonl.*"), key=lambda path: int(path.suffix[1:]))
        self.assertEqual(self.verify(*numbered, self.audit)[0], 0)
        self.assertEqual(self.verify(*reversed(numbered), self.audit)[0], 1)

    def test_usage_and_read_errors_exit_2(self):
        self.write_calls(1)
        bad_key = self.write("bad.key", "short")
        for args in ((self.folder / "missing.jsonl",), (self.folder,), (self.audit, "--key-file", bad_key),
                     (self.audit, "--key-file", self.folder / "missing.key"), ()):
            with self.subTest(args=args):
                code, out, err = self.verify(*args)
                self.assertEqual(code, 2, out + err)
                self.assertNotIn("Traceback", err)
        _, out, _ = run_cli("audit", "verify", "--help")
        self.assertIn("0  intact (or empty)", out)
        self.assertIn("2  a usage error", out)

    def test_hostile_text_in_a_log_is_printed_safely(self):
        self.write_calls(2)
        with open(self.audit, "ab") as handle:
            handle.write(b'{"event": "call\x1b[2J", "seq": 3}\n\xff\xfe\x1b[31m\n')
        code, out, _ = self.verify(self.audit)
        self.assertEqual(code, 1)
        self.assertNotIn("\x1b", out)


# ---- the proxy's protocol records and the hook's options ------------------------------------------------------

class TheProxysProtocolRecords(LogTest):
    def harness(self):
        from test_proxy import Harness

        return Harness(self.firewall(server_name="files"))

    def protocol_records(self):
        return [record for record in all_records(self.audit) if record.get("event") == "protocol"]

    def test_the_handshake_is_recorded_with_both_sides_names_made_printable(self):
        from test_proxy import initialize

        h = self.harness()
        server_info = {"name": "evil\x1b[2J" + "s" * 300, "version": "9", "icons": "x", "extra": "dropped"}
        h.round_trip(initialize(1), {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": server_info})
        (record,) = self.protocol_records()
        self.assertEqual((record["server"], record["action"], record["method"], record["protocol_version"]),
                         ("files", "note", "initialize", "2025-06-18"))
        self.assertEqual(record["client_info"], {"name": "test", "version": "0"})
        self.assertEqual(set(record["server_info"]), {"name", "version"})
        self.assertNotIn("\x1b", self.audit.read_text(encoding="utf-8"))
        self.assertLess(len(record["server_info"]["name"]), 200)

    def test_a_discovery_is_recorded_and_a_client_that_repeats_the_handshake_cannot_fill_the_log(self):
        from test_protocol import modern
        from test_proxy import initialize

        h = self.harness()
        result = {"resultType": "complete", "supportedVersions": ["2026-07-28"], "capabilities": {},
                  "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "modern-server", "version": "2"}}}
        h.round_trip(modern(1, "server/discover"), result)
        (record,) = self.protocol_records()
        self.assertEqual((record["method"], record["supported_versions"], record["server_info"]),
                         ("server/discover", ["2026-07-28"], {"name": "modern-server", "version": "2"}))
        for msg_id in range(2, 40):
            h.round_trip(initialize(msg_id), {"protocolVersion": "2025-06-18", "capabilities": {}})
        from agent_sentinel.mcp_proxy import MAX_PROTOCOL_RECORDS

        self.assertEqual(len(self.protocol_records()), MAX_PROTOCOL_RECORDS)

    def test_a_refused_handshake_is_not_recorded_as_one(self):
        from test_proxy import initialize

        h = self.harness()
        h.round_trip(initialize(1), {"protocolVersion": "1999-01-01", "capabilities": {}})
        self.assertEqual(self.protocol_records(), [])


class TheHooksAuditOptions(LogTest):
    def setUp(self):
        super().setUp()
        self.policy = self.write("policy.json", {"default": "block", "tools": {"Bash": "allow", "Read": "allow"}})
        self.state = self.folder / "state"

    def hook(self, event, *options, audit=None):
        event = {"session_id": "s-1", **event}
        code, out, err = run_cli("hook", "claude-code", "--policy", self.policy, "--audit", audit or self.audit,
                                 "--state-dir", self.state, *options, stdin=json.dumps(event).encode())
        self.assertIn(code, (0, 2))
        return code, (json.loads(out) if out.strip() else None), err

    def pre(self, *options, tool="Bash", audit=None):
        event = {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": {"command": "ls"},
                 "tool_use_id": "toolu_1", "permission_mode": "default"}
        return self.hook(event, *options, audit=audit)

    def test_session_start_is_recorded_and_signed_records_verify(self):
        code, _, err = self.hook({"hook_event_name": "SessionStart", "source": "startup"},
                                 "--audit-key-file", self.key_file)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.pre("--audit-key-file", self.key_file)[1], None)
        self.pre("--audit-key-file", self.key_file, tool="Write")
        records = all_records(self.audit)
        self.assertEqual([record["event"] for record in records], ["chain_start", "session_start", "call", "call"])
        start = records[1]
        self.assertEqual((start["server"], start["session"], start["source"], start["signed"]),
                         ("claude-code", "s-1", "startup", True))
        self.assertEqual(start["policy_sha256"], hashlib.sha256(self.policy.read_bytes()).hexdigest())
        self.assertEqual(records[3]["policy"], start["policy_sha256"][:12])
        self.assertEqual(check_files([str(self.audit)], KEY).state, "intact")

    def test_with_audit_required_a_call_whose_record_cannot_be_written_is_denied(self):
        unwritable = self.folder / "a-folder"
        unwritable.mkdir()
        code, answer, _ = self.pre("--audit-required", audit=unwritable)
        self.assertEqual(code, 0)
        decision = answer["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "deny")
        self.assertRegex(decision["permissionDecisionReason"],
                         r"\ABlocked by agent-sentinel: the call could not be checked, so it was not made "
                         r"\(ref [0-9a-f]{8}\)\Z")
        self.assertIsNone(self.pre(audit=unwritable)[1])  # without the option: let through, as before
        code, _, err = self.hook({"hook_event_name": "SessionStart", "source": "startup"}, "--audit-required",
                                 audit=unwritable)
        self.assertEqual(code, 2)
        self.assertIn("--audit-required", err)

    def test_a_key_file_that_cannot_be_used_blocks_and_the_refusal_is_still_recorded(self):
        bad = self.write("bad.key", "short")
        code, answer, err = self.pre("--audit-key-file", bad)
        self.assertEqual(code, 2)
        self.assertNotIn("short", err)
        (record,) = audit_records(self.audit)
        self.assertEqual((record["rule"], record["action"]), ("hook_failed", "block"))
        self.assertNotIn("mac", record)  # written without the key: audit verify --key-file reports it

    def test_the_audit_options_need_an_audit_log(self):
        event = {"session_id": "s-1", "hook_event_name": "PreToolUse", "tool_name": "Bash",
                 "tool_input": {"command": "ls"}}
        code, _, _ = run_cli("hook", "claude-code", "--policy", self.policy, "--state-dir", self.state,
                             "--audit-required", stdin=json.dumps(event).encode())
        self.assertEqual(code, 2)

    def test_install_writes_the_options_into_the_hook_entries(self):
        from agent_sentinel import cli_hook

        handler = cli_hook.hook_handler("python", True, "p.json", "a.jsonl", "state",
                                        audit_options=cli_hook.audit_options("k.key", True, 1_000_000))
        self.assertEqual(handler["args"][-5:],
                         ["--audit-key-file", "k.key", "--audit-required", "--audit-max-bytes", "1000000"])
        self.assertEqual(cli_hook.audit_options(None, False, None), [])
        self.assertTrue(cli_hook.is_our_handler(handler))


if __name__ == "__main__":
    unittest.main()
