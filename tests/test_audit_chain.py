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
ROTATE_AT = audit_chain.MIN_MAX_BYTES  # the smallest --audit-max-bytes
PAD = 3000  # characters of padding in each call's arguments, so that a few dozen calls fill ROTATE_AT
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
        self.addCleanup(audit_chain._rotation_paused.clear)  # a failed rotation pauses rotation in this process

    def firewall(self, policy=POLICY, **options):
        return Firewall(policy, audit_path=self.audit, **options)

    def write_calls(self, count, firewall=None, pad=0, **options):
        """`count` calls, half of them blocked; `pad` characters of padding in each one's arguments."""
        firewall = firewall or self.firewall(**options)
        for number in range(count):
            args = {"path": f"f{number}", "note": "p" * pad} if pad else {"path": f"f{number}"}
            firewall.check_call("read_file" if number % 2 else "delete_file", args)
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

    def test_a_log_written_before_the_chain_gets_a_restart_and_is_only_partly_checked(self):
        old = {"time": "2026-11-18T10:00:00+00:00", "session": "s", "event": "call", "tool": "t", "action": "allow",
               "reason": "r"}
        self.audit.write_bytes((json.dumps(old) + "\n").encode() * 3)
        size = self.audit.stat().st_size
        self.write_calls(2)
        records = all_records(self.audit)
        restart = records[3]
        self.assertEqual((restart["event"], restart["start"]), ("chain_start", "restart"))
        self.assertIn("no chain fields", restart["reason"])
        self.assertEqual((restart["after_seq"], restart["after_hash"], restart["scanned"]), (None, None, size))
        report = self.check()
        self.assertEqual((report.state, report.unchained_prefix, report.chained), ("partial", 3, 3))
        self.assertIn("the first 3 line(s) have no chain fields", report.unchecked())

    def test_a_restart_names_the_last_chained_record_before_it(self):
        self.write_calls(3)
        last = all_records(self.audit)[-1]
        with open(self.audit, "ab") as handle:
            handle.write(b'{"note": "not a record"}\n')
        self.write_calls(1)
        restart = all_records(self.audit)[-2]
        self.assertEqual((restart["start"], restart["after_seq"], restart["after_hash"]),
                         ("restart", last["seq"], last["hash"]))
        self.assertEqual(restart["scanned"], self.audit.stat().st_size - len(raw_lines(self.audit)[-1])
                         - len(raw_lines(self.audit)[-2]))
        report = self.check()
        self.assertEqual(report.problem_count, 1)  # only the inserted line: the restart follows the record it names
        self.assertIn("line 5: it has no chain fields", report.problems[0])

    def test_a_restart_searches_a_bounded_end_of_the_log(self):
        self.write_calls(1)
        with open(self.audit, "ab") as handle:
            handle.write((b"x" * 1000 + b"\n") * 100)  # 100 kB of lines that are not records
        reads = []
        real_read = audit_chain._read_exactly

        def counting(handle, count):
            reads.append(count)
            return real_read(handle, count)

        with mock.patch.object(audit_chain, "_read_exactly", counting):
            self.write_calls(1)
        self.assertEqual(reads, [audit_chain.TAIL_BYTES, audit_chain.RESTART_SCAN_BYTES])
        restart = json.loads(raw_lines(self.audit)[-2])
        self.assertEqual((restart["after_seq"], restart["after_hash"], restart["scanned"]),
                         (None, None, audit_chain.RESTART_SCAN_BYTES))

    def test_a_log_this_process_may_append_to_but_not_read_still_gets_every_record(self):
        self.write_calls(2)
        real_open = os.open

        def append_only(path, flags, *args, **kwargs):
            if Path(path) == self.audit and flags & os.O_RDWR:
                raise PermissionError(13, "Permission denied")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(audit_chain.os, "open", append_only):
            self.write_calls(3, pad=PAD, audit_max_bytes=ROTATE_AT)  # past the size, but it cannot be copied
            self.write_calls(30, pad=PAD, audit_max_bytes=ROTATE_AT)
        self.assertEqual(list(self.folder.glob("audit.jsonl.*")), [])
        records = all_records(self.audit)
        self.assertEqual(len(audit_records(self.audit)), 35)
        restarts = [record for record in records if record.get("start") == "restart"]
        self.assertEqual(len(restarts), 33)  # one before each record written without reading
        self.assertEqual({(r["after_seq"], r["after_hash"], r["scanned"]) for r in restarts}, {(None, None, 0)})
        self.assertIn("may append to the log but not read it", restarts[0]["reason"])
        report = self.check()
        self.assertEqual((report.state, report.problem_count, report.unlinked), ("partial", 0, 33))
        self.assertIn("33 restart(s) were written by a process that could not read the log", report.unchecked())

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
        # Its end, and as its last line is not a record, the end a restart searches for the record before it.
        self.assertEqual(reads, [audit_chain.TAIL_BYTES, audit_chain.RESTART_SCAN_BYTES])
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
            self.write_calls(30, pad=PAD, audit_max_bytes=ROTATE_AT)
        self.assertEqual(modes["audit.jsonl"], 0o600)
        self.assertEqual(modes["audit.jsonl.1"], 0o600)

    @unittest.skipIf(sys.platform == "win32", "POSIX permissions")
    def test_on_posix_the_files_are_0600(self):
        old = os.umask(0o022)
        try:
            self.write_calls(30, pad=PAD, audit_max_bytes=ROTATE_AT)
        finally:
            os.umask(old)
        for path in (self.audit, self.folder / "audit.jsonl.1"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_a_log_the_user_may_append_to_but_not_read_still_gets_its_records(self):
        self.write_calls(1)
        self.deny_reading(self.audit)
        decision = self.firewall().check_call("read_file", {"path": "a"})
        self.assertTrue(decision.allowed)
        self.allow_reading(self.audit)
        records = all_records(self.audit)
        self.assertEqual([record["event"] for record in records], ["chain_start", "call", "chain_start", "call"])
        self.assertEqual((records[2]["start"], records[2]["scanned"]), ("restart", 0))
        self.assertEqual(self.check().state, "partial")

    def deny_reading(self, path):
        """Let this user append to the file but not read it (an append-only ACL; mode 0200 on POSIX)."""
        if sys.platform == "win32":
            import getpass

            done = subprocess.run(["icacls", str(path), "/deny", f"{getpass.getuser()}:(RD)"], capture_output=True)
            if done.returncode != 0:
                self.skipTest("icacls could not deny reading")
        else:
            if os.geteuid() == 0:
                self.skipTest("root reads any file")
            path.chmod(0o200)
        self.addCleanup(self.allow_reading, path)
        with self.assertRaises(PermissionError):
            path.read_bytes()

    def allow_reading(self, path):
        """Let this user read the file again. A cleanup runs after tearDown, which has already deleted the
        temporary folder, so a file that is no longer there has nothing left to put back."""
        if sys.platform == "win32":
            import getpass

            subprocess.run(["icacls", str(path), "/remove:d", getpass.getuser()], capture_output=True)
        elif path.exists():
            path.chmod(0o600)


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

    def force_a_restart(self, junk=b'{"note": "x"}\n'):
        """What someone who may write the log but has no key can do: add a line that is not a record, so that
        the next record restarts the chain. The lines of the log afterwards, and the index of the restart."""
        with open(self.audit, "ab") as handle:
            handle.write(junk)
        self.write_calls(3, audit_key_file=self.key_file)
        lines = raw_lines(self.audit)
        return lines, next(index for index, line in enumerate(lines) if b'"start": "restart"' in line)

    def test_records_cut_before_a_forced_restart_are_found(self):
        lines, at = self.force_a_restart()
        old = json.dumps({"time": "2020-01-01T00:00:00+00:00", "event": "call", "tool": "read_file",
                          "action": "allow", "reason": "r"}).encode() + b"\n"  # looks like a line from 0.5
        cases = {
            "the whole head": ([old] + lines[at:], "line 2: the chain before it is missing: it follows seq 8, "
                                                   "which is not in the log"),
            "the records just before": (lines[:7] + lines[9:], "it follows seq 8, but the last chained record "
                                                               "before it is seq 6"),
        }
        for name, (tampered, words) in cases.items():
            with self.subTest(name=name):
                plain, keyed = self.tampered(tampered)
                for report in (plain, keyed):
                    self.assertEqual(report.state, "broken")
                    self.assertTrue(any(words in problem for problem in report.problems), report.problems)
                self.assertEqual(keyed.mac_mismatches, 0)  # every signed record left is genuine
                code, out, _ = run_cli("audit", "verify", self.audit, "--key-file", self.key_file,
                                       "--allow-unchecked")
                self.assertEqual(code, 1, out)

    def test_after_a_restart_that_names_no_record_a_cut_head_is_only_partly_checked(self):
        # The limit: past what a restart searches (RESTART_SCAN_BYTES), it cannot name the record before it.
        count = audit_chain.RESTART_SCAN_BYTES // 1000 + 5
        lines, at = self.force_a_restart((b'{"note": "' + b"x" * 1000 + b'"}\n') * count)
        self.assertIsNone(json.loads(lines[at])["after_hash"])
        _, keyed = self.tampered(lines[len(self.lines):])  # every signed record before the attacker's lines cut
        self.assertEqual((keyed.state, keyed.unchained_prefix, keyed.mac_mismatches), ("partial", count, 0))
        code, out, _ = run_cli("audit", "verify", self.audit, "--key-file", self.key_file)
        self.assertEqual(code, 1)
        self.assertIn(f"PARTLY CHECKED: the chain is intact, but the first {count} line(s) have no chain fields", out)
        self.assertIn("--allow-unchecked", out)
        code, out, _ = run_cli("audit", "verify", self.audit, "--key-file", self.key_file, "--allow-unchecked")
        self.assertEqual(code, 0, out)
        self.assertNotIn("This exits 1", out)

    def test_a_restart_that_does_not_name_the_record_before_it_is_reported(self):
        start = json.loads(self.lines[0])
        start.update(start="restart", reason="forged")
        for name in ("seq", "prev", "hash", "mac", "key_id"):
            start.pop(name)
        forged = chained_line(json.dumps(start), 0, GENESIS, None)[0]
        for extra, words in (({}, "a restart must name the record before it"),
                             ({"after_seq": "8", "after_hash": "z"}, "a restart must name the record before it"),
                             ({"after_seq": 10**30, "after_hash": "a" * 64}, "a restart must name the record before"),
                             ({"after_seq": 3, "after_hash": "a" * 64}, "it follows seq 3, but the last chained "
                                                                       "record before it is seq 8")):
            line = forged if not extra else chained_line(json.dumps({**start, **extra}), 0, GENESIS, None)[0]
            with self.subTest(extra=extra):
                report, _ = self.tampered(self.lines + [b'{"note": "x"}\n', line])
                self.assertTrue(any(words in problem for problem in report.problems), report.problems)

    def test_a_forged_last_line_at_the_end_of_the_seq_range_does_not_discredit_the_records_after_it(self):
        # The chain fields hold a seq of 18 digits. A writer that linked to the largest one would write a seq
        # of 19 digits, which nothing reads as chain fields: a genuine, signed record would look inserted.
        top = audit_chain.MAX_SEQ
        self.assertEqual(len(str(top)), 18)
        for seq in (top, top - 1, top - 2):
            with self.subTest(seq=seq):
                self.audit.write_bytes(b"".join(self.lines))
                with open(self.audit, "ab") as handle:  # no key is needed for this line, and any hash will do
                    handle.write(b'{"event": "call", "tool": "x", "action": "allow", "seq": %d, "prev": "%s", '
                                 b'"hash": "%s"}\n' % (seq, b"a" * 64, b"b" * 64))
                self.write_calls(2, audit_key_file=self.key_file)
                self.write_calls(1, audit_key_file=self.key_file)
                forged = len(self.lines) + 1
                genuine = raw_lines(self.audit)[forged:]
                for line in genuine:  # each can be read back as chained, and is signed
                    trailer = parse_trailer(line.rstrip(b"\n"))
                    self.assertIsNotNone(trailer, line[-200:])
                    self.assertIsNotNone(trailer.mac)
                    self.assertLessEqual(trailer.seq, top)
                starts = [json.loads(line) for line in genuine if b'"event": "chain_start"' in line]
                self.assertEqual([(start["start"], start["seq"]) for start in starts], [("restart", 0)])
                self.assertIn("seq at the end of the range", starts[0]["reason"])
                report = self.check(key=KEY)
                self.assertEqual(report.state, "broken")
                self.assertTrue(all(problem.startswith(f"line {forged}: ") for problem in report.problems),
                                report.problems)  # only the forged line: nothing after it is called inserted
                self.assertEqual(report.mac_mismatches, 1)
                self.assertEqual(report.chained, len(self.lines) + 1 + len(genuine))

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
        self.write_calls(80, pad=PAD, audit_key_file=self.key_file, audit_max_bytes=ROTATE_AT)
        files = self.rotated()
        self.assertGreater(len(files), 3)
        for path in files:
            self.assertLessEqual(path.stat().st_size, ROTATE_AT)
        calls = sum(len(audit_records(path)) for path in files)
        self.assertEqual(calls, 80)  # nothing was deleted
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
        self.write_calls(80, pad=PAD, audit_max_bytes=ROTATE_AT)
        files = self.rotated()
        for order in ([files[1], files[0], *files[2:]], [files[0], *files[2:]]):
            with self.subTest(order=[path.name for path in order]):
                report = self.check(*order)
                self.assertEqual(report.state, "broken")
                self.assertIn("does not continue the file before it", " ".join(report.problems))

    def test_an_emptied_or_replaced_file_is_broken_even_when_every_file_is_given(self):
        # Review AUD2-1: the next file's signed first record says how many records came before it.
        self.write_calls(80, pad=PAD, audit_key_file=self.key_file, audit_max_bytes=ROTATE_AT)
        files = self.rotated()
        self.assertGreater(len(files), 3)
        old = json.dumps({"time": "2020-01-01T00:00:00+00:00", "event": "call", "tool": "read_file",
                          "action": "allow", "reason": "r"}).encode() + b"\n"  # looks like a line from 0.5
        cases = {
            "the oldest emptied": (0, b"", ["audit.jsonl.1: it is empty, but a rotated file",
                                            "audit.jsonl.2 line 1: it continues seq "]),
            "the oldest replaced by an unchained line": (0, old, ["audit.jsonl.2 line 1: it continues seq "]),
            "the oldest replaced by blank lines": (0, b"\n\n", ["audit.jsonl.1 line 1: it is not a JSON object"]),
            "a middle one emptied": (1, b"", ["audit.jsonl.2: it is empty",
                                              "it does not continue the file before it"]),
            "the log emptied": (len(files) - 1, b"", ["audit.jsonl: it is empty"]),
        }
        names = [path.name for path in files]
        for name, (index, content, words) in cases.items():
            with self.subTest(name=name):
                kept = files[index].read_bytes()
                files[index].write_bytes(content)
                try:
                    plain, keyed = self.check(*files), self.check(*files, key=KEY)
                    for report in (plain, keyed):
                        self.assertEqual(report.state, "broken")
                        problems = " | ".join(problem.replace(str(self.folder) + os.sep, "")
                                              for problem in report.problems)
                        for word in words:
                            self.assertIn(word, problems)
                    self.assertEqual(keyed.mac_mismatches, 0)  # every signed record left is genuine
                    code, out, _ = run_cli("audit", "verify", *files, "--key-file", self.key_file,
                                           "--allow-unchecked")
                    self.assertEqual(code, 1, out)
                    self.assertIn("BROKEN", out)
                finally:
                    files[index].write_bytes(kept)
        self.assertEqual(self.check(*files, key=KEY).state, "intact", names)

    def test_the_first_file_given_may_continue_files_that_were_not_given(self):
        self.write_calls(80, pad=PAD, audit_max_bytes=ROTATE_AT)
        files = self.rotated()
        report = self.check(*files[1:])  # checked without audit.jsonl.1: said, not taken as broken
        self.assertEqual(report.state, "intact", report.problems)
        self.assertIn("the first file continues audit.jsonl.1 (seq ", report.notes[0])
        self.assertIn("give the older files first", report.notes[0])
        one_empty = self.write("empty.jsonl", "")
        self.assertEqual(self.check(one_empty).state, "empty")  # one empty file alone: nothing to check
        self.assertEqual(self.check(one_empty, one_empty).state, "broken")

    def test_a_rotated_start_that_neither_continues_nor_starts_a_chain_is_reported(self):
        start = json.dumps({"time": "t", "event": "chain_start", "action": "note", "start": "rotated",
                            "reason": "r", "previous_file": "audit.jsonl.1", "chain": 1})
        for seq, prev in ((5, GENESIS), (0, "a" * 64)):
            with self.subTest(seq=seq):
                self.audit.write_bytes(chained_line(start, seq, prev, None)[0])
                report = self.check()
                self.assertEqual(report.state, "broken")
                self.assertIn("must continue the chain (seq above 0, with the hash before it) or start one",
                              report.problems[0])

    def test_a_log_from_0_5_is_rotated_into_a_new_chain_and_only_partly_checked(self):
        old = {"time": "2020-01-01T00:00:00+00:00", "event": "call", "tool": "t", "action": "allow", "reason": "r"}
        self.write_log("audit.jsonl", [{**old, "args": {"note": "o" * PAD}}] * 25)
        self.fill(5)
        files = self.rotated()
        first = all_records(files[1])[0]
        self.assertEqual((first["start"], first["seq"], first["prev"]), ("rotated", 0, GENESIS))
        report = self.check(*files)
        self.assertEqual((report.state, report.unchained_prefix), ("partial", 25), report.problems)

    def test_a_file_that_starts_a_chain_of_its_own_says_that_the_file_before_it_was_not_checked(self):
        old = {"time": "2020-01-01T00:00:00+00:00", "event": "call", "tool": "t", "action": "allow", "reason": "r"}
        self.write_log("audit.jsonl", [{**old, "args": {"note": "o" * PAD}}] * 25)
        self.fill(5)
        alone = self.check()  # without audit.jsonl.1
        self.assertEqual(alone.state, "intact", alone.problems)
        self.assertIn("the first file starts a chain of its own after audit.jsonl.1", alone.notes[0])
        self.assertIn("that file was not checked", alone.notes[0])
        code, out, _ = run_cli("audit", "verify", self.audit)
        self.assertEqual(code, 0)
        self.assertIn("Note: the first file starts a chain of its own after audit.jsonl.1", out)
        self.assertEqual(self.check(*self.rotated()).notes, [])  # every file given: nothing was left unchecked

    def almost_full(self, **options):
        """A log one call short of being rotated, and the firewall that wrote it."""
        firewall = self.firewall(audit_max_bytes=ROTATE_AT, **options)
        while not self.audit.exists() or self.audit.stat().st_size < ROTATE_AT - PAD - 1000:
            firewall.check_call("read_file", {"path": "f", "note": "p" * PAD})
        self.assertEqual(self.rotated(), [self.audit])
        return firewall

    def test_a_rotation_that_cannot_continue_the_chain_names_the_last_record_before_it(self):
        # Someone who may write the log adds a line that is no record just before the log is rotated, so that
        # the next file starts a chain of its own; then replaces the rotated file. The signed first record of
        # the next file says which record came last, so the replacement is found.
        firewall = self.almost_full(audit_key_file=self.key_file)
        last = all_records(self.audit)[-1]
        with open(self.audit, "ab") as handle:
            handle.write(b'{"note": "x"}\n')
        firewall.check_call("read_file", {"path": "f", "note": "p" * PAD})
        rotated, log = self.rotated()
        start = all_records(log)[0]
        self.assertEqual((start["start"], start["seq"], start["prev"]), ("rotated", 0, GENESIS))
        self.assertEqual((start["after_seq"], start["after_hash"]), (last["seq"], last["hash"]))
        report = self.check(rotated, log, key=KEY)  # as it was written: only the added line is reported
        self.assertEqual((report.state, report.problem_count), ("broken", 1), report.problems)
        self.assertIn("it has no chain fields", report.problems[0])
        old = json.dumps({"time": "2020-01-01T00:00:00+00:00", "event": "call", "tool": "read_file",
                          "action": "allow", "reason": "r"}).encode() + b"\n"  # looks like a line from 0.5
        kept = raw_lines(rotated)
        cases = {"replaced by an unchained line": ([old], f"it follows seq {last['seq']}, which is not in the log"),
                 "its last records removed": (kept[:-4] + kept[-1:], f"it follows seq {last['seq']}, but the last "
                                                                      f"chained record before it is seq "
                                                                      f"{last['seq'] - 3}")}
        for name, (lines, words) in cases.items():
            with self.subTest(name=name):
                rotated.write_bytes(b"".join(lines))
                report = self.check(rotated, log, key=KEY)
                self.assertEqual(report.state, "broken")
                self.assertTrue(any(words in problem for problem in report.problems), report.problems)
                self.assertEqual(report.mac_mismatches, 0)  # every signed record left is genuine

    def test_a_forged_line_at_the_end_of_the_seq_range_before_a_rotation_discredits_only_itself(self):
        # The file after it cannot continue such a line, so it starts a chain of its own and names that line:
        # its genuine, signed first record must not be reported as failing to continue the file before it.
        firewall = self.almost_full(audit_key_file=self.key_file)
        with open(self.audit, "ab") as handle:
            handle.write(b'{"event": "call", "tool": "x", "action": "allow", "seq": %d, "prev": "%s", "hash": "%s"}\n'
                         % (audit_chain.MAX_SEQ, b"a" * 64, b"b" * 64))
        firewall.check_call("read_file", {"path": "f", "note": "p" * PAD})
        rotated, log = self.rotated()
        start = all_records(log)[0]
        self.assertEqual((start["start"], start["seq"], start["after_seq"]), ("rotated", 0, audit_chain.MAX_SEQ))
        forged = len(raw_lines(rotated))
        report = self.check(rotated, log, key=KEY)
        self.assertEqual(report.state, "broken")
        self.assertTrue(all(f"audit.jsonl.1 line {forged}: " in problem for problem in report.problems),
                        report.problems)
        self.assertEqual(report.mac_mismatches, 1)  # the forged line's, which has none

    def test_records_larger_than_the_limit_do_not_each_get_a_file(self):
        # Review AUD2-2: arguments may be 100,000 characters, more than the smallest --audit-max-bytes.
        self.write_calls(30, pad=90_000, audit_max_bytes=ROTATE_AT)
        files = self.rotated()
        self.assertLessEqual(len(files) - 1, 30 // audit_chain.ROTATE_MIN_RECORDS)
        for path in files[:-1]:
            self.assertGreaterEqual(len(audit_records(path)), audit_chain.ROTATE_MIN_RECORDS)
        self.assertEqual(sum(len(audit_records(path)) for path in files), 30)  # nothing was deleted
        self.assertEqual(self.check(*files).state, "intact")

    def test_a_log_is_rotated_before_the_limit_once_it_holds_a_few_records_of_that_size(self):
        should = audit_chain._should_rotate
        self.assertTrue(should(60_000, 6_000, ROTATE_AT))  # the next record takes it past the limit
        self.assertFalse(should(50_000, 6_000, ROTATE_AT))  # it does not
        self.assertFalse(should(0, 90_000, ROTATE_AT))  # an empty log is never rotated
        self.assertFalse(should(90_400, 90_400, ROTATE_AT))  # one record of that size: it grows past the limit
        self.assertTrue(should(4 * 90_400, 90_400, ROTATE_AT))

    def fill(self, count=30):
        """Enough calls to take the log past ROTATE_AT at least once, with rotation on."""
        return self.write_calls(count, pad=PAD, audit_max_bytes=ROTATE_AT)

    def calls_kept(self):
        """Every call recorded, in the log and in every rotated file (that is a file)."""
        return sum(len(audit_records(path)) for path in self.rotated() if path.is_file())

    def test_a_file_already_at_a_rotated_name_is_never_overwritten(self):
        taken = self.folder / "audit.jsonl.1"
        taken.write_bytes(b"someone else's file\n")
        self.fill()
        self.assertEqual(taken.read_bytes(), b"someone else's file\n")
        self.assertTrue((self.folder / "audit.jsonl.2").exists())

    def test_a_folder_at_a_rotated_name_is_passed_over(self):
        (self.folder / "audit.jsonl.1").mkdir()  # os.open(O_EXCL) on it fails with PermissionError on Windows
        self.fill()
        self.assertTrue((self.folder / "audit.jsonl.2").is_file())
        self.assertEqual(self.calls_kept(), 30)
        files = [path for path in self.rotated() if path.is_file()]
        self.assertEqual(self.check(*files).state, "intact")

    def test_new_numbers_follow_the_highest_one_even_after_older_files_are_deleted(self):
        (self.folder / "audit.jsonl.7").write_bytes(b"")
        (self.folder / "AUDIT.JSONL.9" if sys.platform == "win32" else self.folder / "audit.jsonl.9").write_bytes(b"")
        (self.folder / "audit.jsonl.99999").write_bytes(b"")  # past MAX_ROTATED_FILES: not one of ours
        self.fill()
        self.assertTrue((self.folder / "audit.jsonl.10").is_file())
        self.assertFalse((self.folder / "audit.jsonl.1").exists())

    def test_a_rotation_lists_the_folder_once_and_makes_one_file_however_many_were_rotated(self):
        for number in range(1, 501):
            (self.folder / f"audit.jsonl.{number}").write_bytes(b"")
        firewall = self.write_calls(1, pad=ROTATE_AT, audit_max_bytes=ROTATE_AT)  # a new log: not rotated yet
        exclusive, listings = [], []
        real_open, real_scandir = os.open, os.scandir

        def recording_open(path, flags, *args, **kwargs):
            if flags & os.O_EXCL:
                exclusive.append(Path(path).name)
            return real_open(path, flags, *args, **kwargs)

        def recording_scandir(*args, **kwargs):
            listings.append(args)
            return real_scandir(*args, **kwargs)

        with mock.patch.object(audit_chain.os, "open", recording_open), \
                mock.patch.object(audit_chain.os, "scandir", recording_scandir):
            self.write_calls(1, firewall=firewall)
        self.assertEqual((exclusive, len(listings)), (["audit.jsonl.501"], 1))

    def test_when_no_number_is_free_the_log_grows_and_is_not_listed_on_every_call(self):
        listings = []
        real_scandir = os.scandir

        def recording_scandir(*args, **kwargs):
            listings.append(args)
            return real_scandir(*args, **kwargs)

        with mock.patch.object(audit_chain, "MAX_ROTATED_FILES", 3):
            for number in range(1, 4):
                (self.folder / f"audit.jsonl.{number}").write_bytes(b"taken\n")
            with mock.patch.object(audit_chain.os, "scandir", recording_scandir):
                self.fill(40)
        self.assertEqual(len(listings), 1)  # then rotation pauses for ROTATION_RETRY_SECONDS
        self.assertEqual(len(audit_records(self.audit)), 40)
        self.assertGreater(self.audit.stat().st_size, ROTATE_AT)
        self.assertEqual(self.check().state, "intact")

    def test_a_rotation_that_fails_never_fails_the_call_and_leaves_no_partial_copy(self):
        failures = {
            "every number refused": ("open", PermissionError(13, "Permission denied")),
            "the disk is full": ("fsync", OSError(28, "No space left on device")),
            "the folder cannot be listed": ("scandir", PermissionError(13, "Permission denied")),
        }
        for name, (function, error) in failures.items():
            with self.subTest(name=name):
                audit_chain._rotation_paused.clear()
                if self.audit.exists():
                    self.audit.unlink()
                real = getattr(os, function)

                def failing(*args, _real=real, _function=function, _error=error, **kwargs):
                    if _function != "open" or args[1] & os.O_EXCL:
                        raise _error
                    return _real(*args, **kwargs)

                with mock.patch.object(audit_chain.os, function, failing), \
                        contextlib.redirect_stderr(io.StringIO()) as stderr:
                    firewall = self.fill()
                    self.assertTrue(firewall.check_call("read_file", {"path": "a"}).allowed)
                self.assertEqual(stderr.getvalue(), "")
                self.assertEqual(list(self.folder.glob("audit.jsonl.*")), [])
                self.assertEqual(len(audit_records(self.audit)), 31)
                self.assertEqual(self.check().state, "intact")
        audit_chain._rotation_paused.clear()
        self.fill(1)  # the cause gone and the pause over: rotated again
        self.assertTrue((self.folder / "audit.jsonl.1").is_file())

    def test_the_size_must_be_a_whole_number_in_range(self):
        self.assertEqual(parse_max_bytes("1048576"), 1048576)
        self.assertEqual(parse_max_bytes(str(ROTATE_AT)), ROTATE_AT)
        self.assertEqual(parse_max_bytes(str(audit_chain.MAX_MAX_BYTES)), 256 * 1024 * 1024)
        for text in ("0", "100", "1023", "4096", str(ROTATE_AT - 1), str(audit_chain.MAX_MAX_BYTES + 1),
                     "abc", "-5", "1e6", "9" * 20, " 2048", ""):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_max_bytes(text)
        for value in (100, 4096, True, 2.5e6, "65536", 1 << 40):
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

    def test_anything_but_a_regular_file_is_refused_before_it_is_opened(self):
        opened = []
        real_open = os.open

        def recording(path, flags, *args, **kwargs):
            opened.append((Path(path).name, flags))
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(audit_chain.os, "open", recording):
            with self.assertRaisesRegex(AuditKeyError, "not a regular file"):
                read_key_file(self.folder)
            self.assertEqual(opened, [])
            self.assertEqual(read_key_file(self.key_file), KEY)
        (name, flags), = opened
        self.assertEqual(name, "audit.key")
        self.assertEqual(flags & getattr(os, "O_NONBLOCK", 0), getattr(os, "O_NONBLOCK", 0))  # never waits

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes (POSIX)")
    def test_a_named_pipe_in_place_of_the_key_is_refused_without_waiting(self):
        pipe = self.folder / "pipe.key"
        os.mkfifo(pipe, 0o600)
        outcome = []

        def read():
            try:
                read_key_file(pipe)
            except AuditKeyError as exc:
                outcome.append(str(exc))

        thread = threading.Thread(target=read, daemon=True)
        thread.start()
        thread.join(5)
        self.assertFalse(thread.is_alive(), "reading the key waited for a writer")
        self.assertEqual(outcome, ["the audit key file is not a regular file"])
        with mock.patch.object(audit_chain.os, "stat", return_value=os.stat(self.key_file)):  # swapped after stat
            with self.assertRaisesRegex(AuditKeyError, "not a regular file"):
                read_key_file(pipe)

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
        for options in ({"audit_key_file": self.key_file}, {"audit_required": True}, {"audit_max_bytes": ROTATE_AT}):
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

    def test_a_value_that_is_neither_true_nor_false_is_refused_rather_than_taken_as_off(self):
        # 1 or "yes" (from an environment variable, a configuration value) once meant "off", without a word.
        for value in (1, 0, "yes", "no", "", None, [True]):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "audit_required must be True or False"):
                    self.firewall(audit_required=value)
                with self.assertRaisesRegex(ValueError, "audit_required must be True or False"):
                    Firewall(POLICY, audit_required=value)  # without a log as well
        self.assertIs(self.firewall(audit_required=True).audit_required, True)
        self.assertIs(self.firewall(audit_required=False).audit_required, False)
        self.assertIs(self.firewall().audit_required, False)

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

    def test_report_and_explain_say_when_the_chain_is_only_partly_checked(self):
        self.write_log("audit.jsonl", [{"event": "call", "tool": "t", "action": "block", "reason": "r"}] * 2)
        self.write_calls(3)
        for command in ("report", "explain"):
            with self.subTest(command=command):
                out = run_cli(command, self.audit)[1]
                line = next(line for line in out.splitlines() if line.startswith("Integrity:"))
                self.assertIn("Integrity: PARTLY CHECKED: chain intact, seq 0 to 3, but the first 2 line(s) have no "
                              "chain fields. Details: agent-sentinel audit verify", line)
                self.assertLess(len(line.split(" Details: ")[0]), 110)  # review AUD2-5: one short line
        integrity = json.loads(run_cli("report", self.audit, "--format", "json")[1])["integrity"]
        self.assertEqual((integrity["state"], integrity["unchained_prefix"], integrity["unlinked_restarts"]),
                         ("partial", 2, 0))

    def test_report_and_explain_read_each_line_once(self):
        # Review AUD2-3: the record the chain check read is the one counted; the line is not parsed again.
        self.write_calls(6)
        for command in ("report", "explain"):
            with self.subTest(command=command), \
                    mock.patch.object(auditlog, "parse_record", wraps=auditlog.parse_record) as again:
                code, out, err = run_cli(command, self.audit)
                self.assertEqual((code, again.call_count), (0, 0), err)
                self.assertIn("Integrity: hash chain intact, seq 0 to 6", out)
        self.assertIn("6 records from", run_cli("report", self.audit)[1])
        lines = raw_lines(self.audit)
        doubled = b'{"action": "allow", ' + lines[2][1:]  # its chain fields intact, a key repeated: not strict JSON
        self.audit.write_bytes(b"".join(lines[:2] + [doubled] + lines[3:]))
        with mock.patch.object(auditlog, "parse_record", wraps=auditlog.parse_record) as again:
            code, out, _ = run_cli("report", self.audit)
        self.assertEqual(again.call_count, 1)  # read leniently, as before 0.6, and still counted
        self.assertIn("6 records from", out)
        self.assertIn("Integrity: BROKEN at line 3: it is not a valid JSON object (or it repeats a key)", out)

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


class ReadersOfARotatedLog(LogTest):
    def rotated(self):
        return sorted(self.folder.glob("audit.jsonl.*"), key=lambda path: int(path.suffix[1:]))

    def test_explain_finds_a_reference_in_the_file_the_log_was_just_rotated_to(self):
        firewall = self.firewall(audit_max_bytes=ROTATE_AT)
        blocked = firewall.check_call("delete_file", {"path": "the one asked about"})
        self.write_calls(40, firewall, pad=PAD)
        rotated = self.rotated()
        self.assertTrue(rotated)
        self.assertNotIn(blocked.ref, self.audit.read_text(encoding="utf-8"))  # it is in audit.jsonl.1 now
        code, out, err = run_cli("explain", self.audit, "--ref", blocked.ref)
        self.assertEqual(code, 0, out + err)
        self.assertIn("audit.jsonl.1, a file this log was rotated to. Its chain is not checked here", out)
        self.assertIn("BLOCKED  call delete_file", out)
        self.assertIn("the one asked about", out)

    def test_explain_reads_a_bounded_number_of_rotated_files_and_says_which(self):
        from agent_sentinel.cli_explain import MAX_ROTATED_SEARCHED
        firewall = self.firewall(audit_max_bytes=ROTATE_AT)
        oldest = firewall.check_call("delete_file", {"path": "long ago"})
        self.write_calls(30 * (MAX_ROTATED_SEARCHED + 2), firewall, pad=PAD)
        rotated = self.rotated()
        self.assertGreater(len(rotated), MAX_ROTATED_SEARCHED + 1)
        code, out, _ = run_cli("explain", self.audit, "--ref", "00000000")
        self.assertEqual(code, 1)
        read = ", ".join(path.name for path in rotated[::-1][:MAX_ROTATED_SEARCHED])
        self.assertIn(f"No record in the log has ref 00000000, nor do the rotated files that were read ({read}); "
                      f"{len(rotated) - MAX_ROTATED_SEARCHED} older rotated file(s) were not read", out)
        self.assertIn("audit.jsonl.1", out.split("the oldest is")[1])
        code, out, _ = run_cli("explain", self.audit, "--ref", oldest.ref)  # too far back: said, not searched
        self.assertEqual(code, 1)
        self.assertIn("older rotated file(s) were not read", out)
        code, out, _ = run_cli("explain", rotated[0], "--ref", oldest.ref)  # where it says to look
        self.assertEqual(code, 0, out)

    def test_explain_passes_over_what_rotation_cannot_have_written(self):
        from agent_sentinel import cli_explain
        self.write_log("audit.jsonl", [{"event": "call", "tool": "x", "action": "allow"}])
        block = {"event": "call", "tool": "x", "action": "block", "ref": "0badf00d", "reason": "r"}
        self.write_log("audit.jsonl.1", [block])
        (self.folder / "audit.jsonl.2").mkdir()  # not a file
        self.write_log("audit.jsonl.3", [{**block, "tool": "planted"}] * 3)
        with mock.patch.object(cli_explain, "MAX_ROTATED_FILE_BYTES", 150):  # audit.jsonl.3 is "huge"
            code, out, err = run_cli("explain", self.audit, "--ref", "0badf00d")
        self.assertEqual(code, 0, out + err)
        self.assertIn("audit.jsonl.1, a file this log was rotated to", out)
        self.assertNotIn("planted", out)
        if hasattr(os, "mkfifo"):  # a pipe would never end: it is not opened
            os.mkfifo(self.folder / "audit.jsonl.4")
            code, out, _ = run_cli("explain", self.audit, "--ref", "0badf00d")
            self.assertEqual(code, 0, out)

    def test_explain_without_blocks_says_where_the_older_records_are(self):
        self.write_log("audit.jsonl", [{"event": "call", "tool": "x", "action": "allow"}])
        code, out, _ = run_cli("explain", self.audit)
        self.assertEqual((code, out.splitlines()[-1]), (1, "The log has no blocked calls."))
        self.write_log("audit.jsonl.1", [{"event": "call", "tool": "x", "action": "block"}])
        self.write_log("audit.jsonl.2", [{"event": "call", "tool": "x", "action": "block"}])
        self.write_log("audit.jsonl.007", [])  # not a name rotation writes
        code, out, _ = run_cli("explain", self.audit)
        self.assertEqual(code, 1)
        self.assertIn("The log has no blocked calls. Older records are in the 2 file(s) it was rotated to (the "
                      "newest is ", out)
        self.assertIn("audit.jsonl.2): run explain on one of them.", out)

    def test_the_rotated_files_are_listed_oldest_first_by_number(self):
        for name in ("audit.jsonl.10", "audit.jsonl.2", "audit.jsonl.1", "audit.jsonl.007", "audit.jsonl.x",
                     "audit.jsonl.0", "other.jsonl.3", "audit.jsonl.99999"):
            self.write(name, "")
        self.assertEqual([path.name for path in audit_chain.rotated_files(self.audit)],
                         ["audit.jsonl.1", "audit.jsonl.2", "audit.jsonl.10"])
        self.assertEqual(audit_chain.rotated_files(self.folder / "missing" / "audit.jsonl"), [])
        self.assertEqual(audit_chain._next_rotated_number(self.audit), 11)  # the highest number still counts


class ReadingALogWhileItIsRotated(LogTest):
    """A writer rotates the log (copies it aside, empties it, starts it again) while a reader is part-way through.

    The reader then holds half of a file that is no longer the log. It must
    read again, or say that the log changed: never call a healthy log broken.
    """

    def setUp(self):
        super().setUp()
        self.writer = self.firewall(audit_max_bytes=ROTATE_AT)
        self.rotate()  # audit.jsonl.1 exists, and the log continues it

    def rotated(self):
        return sorted(self.folder.glob("audit.jsonl.*"), key=lambda path: int(path.suffix[1:]))

    def call(self):
        return self.writer.check_call("delete_file", {"path": "f", "note": "p" * PAD})

    def rotate(self, more=0):
        """Calls until the log has been rotated once more, then `more` calls into the new file."""
        before = len(self.rotated())
        for _ in range(200):
            self.call()
            if len(self.rotated()) > before:
                break
        else:
            self.fail("the log was never rotated")
        for _ in range(more):
            self.call()

    def fill(self):
        """A log of several buffers' worth, short of being rotated."""
        while self.audit.stat().st_size < ROTATE_AT // 2:
            self.call()

    def rotating_under_the_reader(self, times=1, more=0, line=3):
        """While active, the log is rotated when a reader has read `line` lines of a file (the first `times`)."""
        left = [times]
        real = auditlog.iter_lines

        def reading(handle, limit=auditlog.MAX_LINE_BYTES):
            for number, raw in enumerate(real(handle, limit)):
                if number == line and left[0] > 0:
                    left[0] -= 1
                    self.rotate(more)
                yield raw

        return mock.patch.object(auditlog, "iter_lines", reading)

    def test_a_check_of_the_log_reads_it_again_and_finds_it_intact(self):
        for more in (0, 12):  # 12: the new file is already longer than what the reader had read
            with self.subTest(more=more):
                self.fill()
                files = len(self.rotated())
                with self.rotating_under_the_reader(more=more):
                    report = self.check()
                self.assertEqual(len(self.rotated()), files + 1)  # it was rotated during the check
                self.assertEqual((report.state, report.problems), ("intact", []))
                self.assertEqual(report.lines, len(raw_lines(self.audit)))  # the log as it is now, all of it
        self.assertEqual(self.check(*self.rotated(), self.audit).state, "intact")

    def test_verify_report_and_explain_never_call_it_broken(self):
        for command, words in ((("audit", "verify"), "INTACT: every record is as it was written"),
                               (("report",), "Integrity: hash chain intact"),
                               (("explain",), "Integrity: hash chain intact")):
            with self.subTest(command=command):
                self.fill()
                with self.rotating_under_the_reader():
                    code, out, err = run_cli(*command, self.audit)
                self.assertEqual(code, 0, out + err)
                self.assertIn(words, out)
                self.assertNotIn("BROKEN", out)
                self.assertNotIn("could not be read", out)  # the half line of the first read is not counted
        policy_file = self.write("policy.json", {"default": "block"})
        self.fill()
        with self.rotating_under_the_reader():
            code, out, err = run_cli("suggest", self.audit, "--policy", policy_file)
        self.assertEqual(code, 0, err)
        self.assertNotIn("could not be read", out)

    def test_report_counts_the_log_as_it_is_after_the_rotation(self):
        self.fill()
        with self.rotating_under_the_reader(more=2):
            data = json.loads(run_cli("report", self.audit, "--format", "json")[1])
        self.assertEqual(data["records"], len(audit_records(self.audit)))
        self.assertEqual((data["unreadable_lines"], data["integrity"]["state"]), (0, "intact"))

    def test_a_record_being_appended_as_the_check_reaches_the_end_is_not_a_write_cut_short(self):
        self.fill()
        whole = self.audit.read_bytes()
        self.audit.write_bytes(whole[:-150])  # the reader will get half of the last record ...
        real, left = auditlog.iter_lines, [whole[-150:]]

        def reading(handle, limit=auditlog.MAX_LINE_BYTES):
            yield from real(handle, limit)
            if left:
                with open(self.audit, "ab") as writer:  # ... which its writer then finishes
                    writer.write(left.pop())

        with mock.patch.object(auditlog, "iter_lines", reading):
            report = self.check()
        self.assertEqual((report.state, report.problems), ("intact", []))
        self.audit.write_bytes(whole[:-150])  # a write that really was cut short is still reported
        report = self.check()
        self.assertEqual(report.state, "broken")
        self.assertIn("it is incomplete: it has no newline at its end", report.problems[0])

    def test_a_log_that_keeps_changing_is_an_error_not_a_verdict(self):
        self.fill()
        with self.rotating_under_the_reader(times=50, line=1):
            with self.assertRaises(auditlog.LogChangedError):
                self.check()
        self.fill()
        with self.rotating_under_the_reader(times=50, line=1):
            code, out, err = run_cli("audit", "verify", self.audit)
        self.assertEqual(code, 2, out)
        self.assertIn("the log changed while it was read (rotated, cut, or a record half written), run the command "
                      "again", err)
        self.assertNotIn("BROKEN", out + err)
        self.fill()
        for command in ("report", "explain"):
            with self.subTest(command=command), self.rotating_under_the_reader(times=50, line=1):
                code, out, err = run_cli(command, self.audit)
                self.assertEqual(code, 2, out)
                self.assertIn("the log changed while it was read", err)
                self.assertNotIn("Traceback", err)

    def test_with_several_files_a_rotation_during_the_check_is_an_error_that_says_to_list_them_again(self):
        self.fill()
        files = [*self.rotated(), self.audit]
        with self.rotating_under_the_reader():  # while the first file is read, the log gets one more file
            with self.assertRaises(auditlog.LogChangedError) as raised:
                self.check(*files)
        self.assertEqual(raised.exception.filename, str(self.audit))
        self.fill()
        files = [*self.rotated(), self.audit]
        with self.rotating_under_the_reader():
            code, out, err = run_cli("audit", "verify", *files)
        self.assertEqual(code, 2, out)
        self.assertIn("after a rotation the log has one more file (FILE.N)", err)
        self.assertNotIn("BROKEN", out + err)
        self.assertEqual(self.check(*self.rotated(), self.audit).state, "intact")  # listed again: all is well

    def test_with_several_files_one_read_through_a_pipe_is_opened_once(self):
        # `audit verify <(zcat audit.jsonl.1.gz) audit.jsonl`: what was read from a pipe is gone, so the start
        # of each file is looked at beforehand only for regular files.
        files = [*self.rotated(), self.audit]
        piped = str(files[0])
        content, opened = files[0].read_bytes(), []
        real_open, real_stat = open, os.stat

        class Pipe(io.BytesIO):
            def seekable(self):
                return False

        def fake_open(path, mode="r", *args, **kwargs):
            if str(path) != piped:
                return real_open(path, mode, *args, **kwargs)
            opened.append(path)
            return io.BufferedReader(Pipe(content if len(opened) == 1 else b""))  # once read, it is gone

        def fake_stat(path, *args, **kwargs):
            if str(path) != piped:
                return real_stat(path, *args, **kwargs)
            return os.stat_result((stat.S_IFIFO | 0o600, 0, 0, 1, 0, 0, 0, 0, 0, 0))

        with mock.patch.object(auditlog, "open", fake_open, create=True), mock.patch("os.stat", fake_stat):
            report = self.check(*files)
        self.assertEqual((report.state, report.problems), ("intact", []))
        self.assertEqual(len(opened), 1)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are a POSIX matter")
    def test_with_several_files_named_pipes_are_read_once_through(self):
        files = [*self.rotated(), self.audit]
        pipes = []
        for number, file in enumerate(files):
            pipe = self.folder / f"pipe{number}"
            os.mkfifo(pipe)
            pipes.append((pipe, file.read_bytes()))

        def feed(pipe, content):
            try:
                pipe.write_bytes(content)
            except OSError:  # the reader went away
                pass

        def unblock():  # a reader still waiting in open() gets the end of the file
            for pipe, _ in pipes:
                try:
                    os.close(os.open(pipe, os.O_WRONLY | os.O_NONBLOCK))
                except OSError:
                    pass

        for pipe in pipes:
            threading.Thread(target=feed, args=pipe, daemon=True).start()
        found = []
        checking = threading.Thread(target=lambda: found.append(self.check(*(str(pipe) for pipe, _ in pipes))),
                                    daemon=True)
        checking.start()
        checking.join(timeout=60)
        unblock()
        self.assertFalse(checking.is_alive(), "the check waited for a pipe that had been read already")
        self.assertEqual((found[0].state, found[0].problems), ("intact", []))

    @unittest.skipUnless(sys.platform == "win32", "only Windows refuses to read a locked byte")
    def test_on_windows_a_check_waits_for_a_writer_that_holds_the_lock(self):
        from agent_sentinel.filelock import lock_file, unlock_file
        with open(self.audit, "a+b", buffering=0) as writer:
            lock_file(writer)
            release = threading.Timer(0.3, lambda: unlock_file(writer))
            release.start()
            try:
                code, out, err = run_cli("audit", "verify", self.audit)
            finally:
                release.join()
        self.assertEqual(code, 0, out + err)
        with open(self.audit, "a+b", buffering=0) as writer:
            lock_file(writer)
            try:
                with mock.patch.object(auditlog, "LOCKED_READ_SECONDS", 0.2):
                    code, out, err = run_cli("audit", "verify", self.audit)
            finally:
                unlock_file(writer)
        self.assertEqual(code, 2, out)
        self.assertIn("a writer held the log's lock", err)
        self.assertIn("audit.jsonl", err)


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
        self.write_calls(60, pad=PAD, audit_max_bytes=ROTATE_AT)
        numbered = sorted(self.folder.glob("audit.jsonl.*"), key=lambda path: int(path.suffix[1:]))
        self.assertEqual(self.verify(*numbered, self.audit)[0], 0)
        self.assertEqual(self.verify(*reversed(numbered), self.audit)[0], 1)

    def test_files_given_in_another_order_are_told_the_order_their_names_give(self):
        from agent_sentinel.cli_audit import oldest_first
        from agent_sentinel.cli_common import shown_path
        self.write_calls(60, pad=PAD, audit_max_bytes=ROTATE_AT)
        numbered = sorted(self.folder.glob("audit.jsonl.*"), key=lambda path: int(path.suffix[1:]))
        self.assertGreater(len(numbered), 1)
        in_order = " ".join(shown_path(path) for path in (*numbered, self.audit))
        as_a_shell_lists_them = sorted([*numbered, self.audit], key=str)  # audit.jsonl first
        code, out, _ = self.verify(*as_a_shell_lists_them)
        self.assertEqual(code, 1)
        self.assertIn("BROKEN", out)
        self.assertIn("  The files are checked in the order given, and must be given oldest first. Going by their "
                      f"names, that is: {in_order}", out)
        code, out, _ = self.verify(*numbered[1:], self.audit, numbered[0])
        self.assertIn(f"that is: {in_order}", out)
        code, out, _ = self.verify(*numbered, self.audit)  # in order: nothing to say
        self.assertEqual(code, 0)
        self.assertNotIn("oldest first. Going by", out)
        code, out, _ = self.verify(numbered[0], self.audit)  # in order, one missing: broken, and no hint
        self.assertEqual(code, 1)
        self.assertNotIn("oldest first. Going by", out)
        self.assertIn(f"it names {numbered[-1].name} as the file before it: give every file of the log, oldest "
                      "first (FILE.1 FILE.2 ... FILE)", out)
        self.assertEqual(oldest_first(["a.jsonl", "a.jsonl.1", "a.jsonl.10", "a.jsonl.2"]),
                         ["a.jsonl.1", "a.jsonl.2", "a.jsonl.10", "a.jsonl"])
        self.assertEqual(oldest_first(["a.jsonl.10", "a.jsonl.9"]), ["a.jsonl.9", "a.jsonl.10"])
        for names in (["a.jsonl"], ["a.jsonl", "b.jsonl"], ["a.1", "b.2"], ["a.jsonl", "a.jsonl"],
                      ["a.jsonl", "a.jsonl.x"], ["a.jsonl.1", "a.jsonl.1"]):
            with self.subTest(names=names):
                self.assertIsNone(oldest_first(names))

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
        self.assertIn("1  broken, not chained at all, or only partly checked (see --allow-unchecked)", out)
        self.assertIn("2  a usage error", out)

    def test_a_partly_checked_log_exits_1_unless_it_is_allowed(self):
        self.write_log("audit.jsonl", [{"event": "call", "tool": "t", "action": "allow", "reason": "r"}])
        self.write_calls(2, audit_key_file=self.key_file)
        code, out, _ = self.verify(self.audit, "--key-file", self.key_file)
        self.assertEqual(code, 1)
        self.assertIn("PARTLY CHECKED: the chain is intact, but the first 1 line(s) have no chain fields", out)
        self.assertNotIn("INTACT:", out)
        code, out, _ = self.verify(self.audit, "--key-file", self.key_file, "--allow-unchecked")
        self.assertEqual(code, 0)
        self.assertIn("PARTLY CHECKED", out)
        self.write_calls(2, audit_key_file=self.key_file)  # --allow-unchecked never lets a broken log through
        lines = raw_lines(self.audit)
        self.audit.write_bytes(b"".join(lines[:3] + lines[4:]))
        self.assertEqual(self.verify(self.audit, "--allow-unchecked")[0], 1)

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
