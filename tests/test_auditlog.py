"""Reading audit logs: bounded lines, records, times, filters (agent_sentinel/auditlog.py)."""

import io
import json
import os
import sys
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from cli_support import TempFolderTest
from agent_sentinel import auditlog
from agent_sentinel.auditlog import RecordFilter, glob_matches, iter_lines, parse_record, parse_when, record_time


class Lines(unittest.TestCase):
    def test_a_line_longer_than_the_limit_is_skipped_and_the_next_one_read(self):
        data = b"short\n" + b"x" * 100 + b"\nafter\n"
        self.assertEqual(list(iter_lines(io.BytesIO(data), limit=50)), [b"short\n", None, b"after\n"])

    def test_a_last_line_without_a_newline_is_read(self):
        self.assertEqual(list(iter_lines(io.BytesIO(b"a\nb"), limit=50)), [b"a\n", b"b"])


class Records(unittest.TestCase):
    def test_only_json_objects_are_records(self):
        self.assertEqual(parse_record(b'{"a": 1}\n'), {"a": 1})
        for line in (b"[1]", b"not json", b"[" * 100_000, b'{"n": ' + b"9" * 5000 + b"}", b"\xff\xfe"):
            with self.subTest(line=line[:20]):
                self.assertIsNone(parse_record(line))

    def test_a_huge_number_is_refused_quickly_on_every_python(self):
        started = time.perf_counter()
        self.assertIsNone(parse_record(b'{"n": ' + b"9" * 3_000_000 + b"}"))
        self.assertLess(time.perf_counter() - started, 2)


class Times(unittest.TestCase):
    def test_record_times_are_read_with_or_without_a_zone(self):
        utc = datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc)
        for text in ("2026-11-18T10:00:00+00:00", "2026-11-18T10:00:00Z", "2026-11-18T10:00:00"):
            self.assertEqual(record_time({"time": text}), utc)
        for value in ("yesterday", 5, None, "2" * 100):
            self.assertIsNone(record_time({"time": value}))

    def test_since_takes_a_duration_or_a_date(self):
        now = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
        self.assertEqual(parse_when("2h", now=now), now - timedelta(hours=2))
        self.assertEqual(parse_when("30m", now=now), now - timedelta(minutes=30))
        self.assertEqual(parse_when("1w", now=now), now - timedelta(weeks=1))
        self.assertEqual(parse_when("2026-11-18T10:00Z"), datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc))
        start = parse_when("2026-11-18")
        self.assertEqual(parse_when("2026-11-18", end_of_day=True) - start, timedelta(days=1))

    def test_the_same_times_are_read_on_every_python_version(self):
        # Python 3.11+ would read 20261118 and 2026-W47-3 through fromisoformat; 3.10 would not.
        for text in ("20261118", "2026-W47-3", "2026-11-18T1430", "2026-11-18T14", "2026-11-18Z",
                     "2026-11-18T14:30+0500", "2026-11-18T14:30:00+24:00", "\uff12026-11-18"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    parse_when(text)
                self.assertIsNone(record_time({"time": text}))
        utc = timezone.utc
        for text, expected in (
            ("2026-11-18 14:30:00.5z", datetime(2026, 11, 18, 14, 30, 0, 500000, tzinfo=utc)),
            ("2026-11-18t14:30Z", datetime(2026, 11, 18, 14, 30, tzinfo=utc)),
            ("2026-11-18T14:30:05-05:30", datetime(2026, 11, 18, 20, 0, 5, tzinfo=utc)),
        ):
            with self.subTest(text=text):
                self.assertEqual(parse_when(text), expected)
                self.assertEqual(record_time({"time": text}), expected)

    def test_until_a_date_means_its_end_and_until_a_time_means_that_time(self):
        self.assertEqual(parse_when("2026-11-18", end_of_day=True) - parse_when("2026-11-18"), timedelta(days=1))
        self.assertEqual(parse_when("2026-11-18T00:00", end_of_day=True), parse_when("2026-11-18"))

    def test_a_time_that_cannot_be_read_raises_a_readable_error(self):
        for text in ("soon", "2026-13-01", "999999w", "9" * 50, "2h ago"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError) as caught:
                    parse_when(text)
                self.assertTrue(str(caught.exception))


class Names(unittest.TestCase):
    def test_only_the_star_is_special(self):
        self.assertTrue(glob_matches("read_*", "read_file"))
        self.assertTrue(glob_matches("*", ""))
        self.assertTrue(glob_matches("a*b*c", "aXbYc"))
        self.assertFalse(glob_matches("a*b*c", "aXcYb"))
        self.assertFalse(glob_matches("read_?", "read_x"))
        self.assertTrue(glob_matches("read_[x]", "read_[x]"))
        self.assertFalse(glob_matches("Read_*", "read_file"))

    def test_the_filter_uses_the_policys_own_rule_for_names(self):
        from agent_sentinel import auditlog, policy
        self.assertIs(auditlog.glob_matches, policy.glob_matches)
        self.assertIn("note", auditlog.RECORD_ACTIONS)  # what Firewall.note writes

    def test_a_long_hostile_name_is_matched_quickly(self):
        started = time.perf_counter()
        glob_matches("*_a_*_b_*_c_*", "_a_" * 200_000)
        self.assertLess(time.perf_counter() - started, 1)


class Filters(unittest.TestCase):
    def test_every_part_of_a_filter_must_match(self):
        record = {"tool": "read_file", "server": "files", "action": "block", "event": "call",
                  "time": "2026-11-18T10:00:00+00:00"}
        self.assertTrue(RecordFilter().matches(record))
        self.assertTrue(RecordFilter(tool="read_*", servers=("files", "mail"), actions=("block",)).matches(record))
        self.assertFalse(RecordFilter(events=("result",)).matches(record))
        self.assertFalse(RecordFilter(servers=("mail",)).matches(record))
        since = datetime(2026, 11, 18, 11, 0, tzinfo=timezone.utc)
        self.assertFalse(RecordFilter(since=since).matches(record))

    def test_fields_of_the_wrong_type_never_match(self):
        odd = {"tool": ["read_file"], "server": 5, "action": None}
        self.assertFalse(RecordFilter(tool="*").matches(odd))
        self.assertFalse(RecordFilter(servers=("5",)).matches(odd))
        for event in ({}, []):  # an object or a list is no key of a table: no look-up may raise
            odd = {"event": event, "action": "note"}
            self.assertFalse(RecordFilter(events=("chain_start",)).matches(odd))
            self.assertFalse(auditlog.is_meta(odd))

    def test_an_event_or_action_that_is_not_text_is_no_kind_of_record(self):
        # A JSON object or a list cannot be looked up in a set: the test must not raise.
        for value in ({}, {"a": 1}, [], ["chain_start"], [[]], 5, 1.5, True, None):
            with self.subTest(value=value):
                self.assertFalse(auditlog.is_meta({"event": value, "action": "note"}))
                self.assertFalse(auditlog.is_meta({"event": "chain_start", "action": value}))
                self.assertFalse(auditlog.is_block({"event": "call", "action": value}))
                self.assertFalse(RecordFilter(events=("call",), actions=("block",)).matches(
                    {"event": value, "action": value}))
        self.assertTrue(auditlog.is_meta({"event": "chain_start", "action": "note"}))


class ALogThatChangesWhileItIsRead(TempFolderTest):
    """A writer may rotate the log (copy it aside, empty it, start it again) while a reader is part-way through."""

    def lines(self, first, count):
        return b"".join(json.dumps({"n": number, "pad": "x" * 900}).encode() + b"\n"
                        for number in range(first, first + count))

    def rotating_after(self, lines_read, new_content, times=1):
        """A stand-in for iter_lines that replaces the log's content once `lines_read` lines were yielded."""
        left = [times]

        def reading(handle, limit=auditlog.MAX_LINE_BYTES):
            for number, line in enumerate(iter_lines(handle, limit)):
                if number == lines_read and left[0] > 0:
                    left[0] -= 1
                    with open(self.audit, "r+b") as writer:  # in place, as a rotation does it
                        writer.truncate(0)
                        writer.write(new_content)
                yield line

        return mock.patch.object(auditlog, "iter_lines", reading)

    def setUp(self):
        super().setUp()
        self.audit = self.write("audit.jsonl", self.lines(0, 40))  # about 37 KiB: several reads of the buffer

    def test_a_log_emptied_during_the_read_is_reported_as_changed_not_as_its_first_half(self):
        with self.rotating_after(3, self.lines(100, 2)):
            with self.assertRaises(auditlog.LogChangedError) as raised:
                list(auditlog.iter_records(str(self.audit)))
        self.assertIn("the log changed while it was read", raised.exception.strerror)
        self.assertEqual(raised.exception.filename, str(self.audit))

    def test_a_log_that_grew_back_past_the_reader_is_reported_as_changed_too(self):
        # As long as before, so its size says nothing: it no longer starts with the same bytes.
        with self.rotating_after(3, self.lines(100, 40)):
            with self.assertRaises(auditlog.LogChangedError):
                list(auditlog.iter_records(str(self.audit)))

    def test_it_is_read_again_from_its_start_a_bounded_number_of_times(self):
        def numbers():  # None: the line the first read was cut off in
            return [record["n"] for record in auditlog.iter_records(str(self.audit)) if record is not None]

        with self.rotating_after(3, self.lines(100, 5)):
            self.assertEqual(auditlog.read_again_if_changed(numbers), [100, 101, 102, 103, 104])
        attempts = []

        def always_changed():
            attempts.append(1)
            raise auditlog.LogChangedError(0, "changed", "x")

        with self.assertRaises(auditlog.LogChangedError):
            auditlog.read_again_if_changed(always_changed)
        self.assertEqual(len(attempts), auditlog.READ_ATTEMPTS)

    def test_a_log_that_only_grows_is_read_once_and_whole(self):
        calls = []

        def numbers():
            calls.append(1)
            found = []
            for record in auditlog.iter_records(str(self.audit)):
                if record["n"] == 3:
                    with open(self.audit, "ab") as writer:
                        writer.write(self.lines(40, 2))
                found.append(record["n"])
            return found

        self.assertEqual(auditlog.read_again_if_changed(numbers), list(range(42)))
        self.assertEqual(len(calls), 1)

    def finishing_the_last_record(self, rest):
        """A stand-in for iter_lines: once the reader has reached the end, the writer appends `rest`."""
        left = [rest]

        def reading(handle, limit=auditlog.MAX_LINE_BYTES):
            yield from iter_lines(handle, limit)
            if left:
                with open(self.audit, "ab") as writer:
                    writer.write(left.pop())

        return mock.patch.object(auditlog, "iter_lines", reading)

    def test_a_record_that_was_being_appended_when_the_reader_reached_the_end_is_read_again(self):
        # The reader got half of the last record. That is a write in progress, not a write cut short.
        whole = self.lines(0, 3)
        self.audit.write_bytes(whole[:-200])
        with self.finishing_the_last_record(whole[-200:]):
            with self.assertRaises(auditlog.LogChangedError):
                list(auditlog.iter_records(str(self.audit)))
        self.audit.write_bytes(whole[:-200])
        with self.finishing_the_last_record(whole[-200:]):
            found = auditlog.read_again_if_changed(lambda: list(auditlog.iter_records(str(self.audit))))
        self.assertEqual([record["n"] for record in found], [0, 1, 2])

    def test_a_last_line_that_stays_cut_short_is_read_as_it_is(self):
        self.audit.write_bytes(self.lines(0, 3)[:-200])
        calls = []

        def read():
            calls.append(1)
            return list(auditlog.iter_records(str(self.audit)))

        found = auditlog.read_again_if_changed(read)
        self.assertEqual(([record and record["n"] for record in found], len(calls)), ([0, 1, None], 1))

    def test_an_empty_log_and_one_without_a_last_newline_are_read_as_they_are(self):
        empty = self.write("empty.jsonl", b"")
        self.assertEqual(list(auditlog.iter_records(str(empty))), [])
        cut = self.write("cut.jsonl", b'{"n": 1}\n{"n": 2')
        self.assertEqual(list(auditlog.iter_records(str(cut))), [{"n": 1}, None])

    def test_a_pipe_is_read_once_through(self):
        # A log read through a pipe (`report <(zcat audit.jsonl.gz)`) cannot be looked at twice, and is not.
        class Pipe(io.BytesIO):
            def seekable(self):
                return False

        with mock.patch.object(auditlog, "open", lambda path, mode: io.BufferedReader(Pipe(self.lines(0, 3))),
                               create=True):
            self.assertEqual([record["n"] for record in auditlog.iter_records("a pipe")], [0, 1, 2])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are a POSIX matter")
    def test_a_named_pipe_is_read_once_through(self):
        pipe = self.folder / "log.pipe"
        os.mkfifo(pipe)
        writer = threading.Thread(target=lambda: pipe.write_bytes(self.lines(0, 3)))
        writer.start()
        try:
            self.assertEqual([record["n"] for record in auditlog.iter_records(str(pipe))], [0, 1, 2])
        finally:
            writer.join(timeout=10)


class AWritersLock(TempFolderTest):
    """On Windows a byte a writer has locked cannot be read: the first byte of the log, for a moment at a time."""

    def test_a_refused_read_is_tried_again_until_it_works(self):
        answers = [PermissionError(13, "Permission denied"), PermissionError(13, "Permission denied"), b"data"]

        def read():
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer

        self.assertEqual(auditlog._despite_lock(read, "audit.jsonl"), b"data")

    def test_a_read_refused_for_too_long_says_that_a_writer_holds_the_lock(self):
        def read():
            raise PermissionError(13, "Permission denied")

        with mock.patch.object(auditlog, "LOCKED_READ_SECONDS", 0.2):
            started = time.monotonic()
            with self.assertRaises(PermissionError) as raised:
                auditlog._despite_lock(read, "audit.jsonl")
        self.assertLess(time.monotonic() - started, 5)
        self.assertIn("a writer held the log's lock", raised.exception.strerror)
        self.assertEqual(raised.exception.filename, "audit.jsonl")

    def test_any_other_error_is_not_waited_for(self):
        def read():
            raise IsADirectoryError(21, "Is a directory")

        with self.assertRaises(IsADirectoryError):
            auditlog._despite_lock(read, "audit.jsonl")

    @unittest.skipUnless(sys.platform == "win32", "only Windows refuses to read a locked byte")
    def test_on_windows_a_log_is_read_once_its_writer_lets_go_of_the_lock(self):
        from agent_sentinel.filelock import lock_file, unlock_file
        audit = self.write_log("audit.jsonl", [{"n": 1}, {"n": 2}])
        with open(audit, "a+b", buffering=0) as writer:
            lock_file(writer)
            with self.assertRaises(PermissionError):  # what a reader met before it waited
                with open(audit, "rb") as plain:
                    plain.read(1)
            release = threading.Timer(0.3, lambda: unlock_file(writer))
            release.start()
            try:
                self.assertEqual(list(auditlog.iter_records(str(audit))), [{"n": 1}, {"n": 2}])
            finally:
                release.join()

    @unittest.skipUnless(sys.platform == "win32", "only Windows refuses to read a locked byte")
    def test_on_windows_a_lock_that_is_never_let_go_is_an_error_that_names_it(self):
        from agent_sentinel.filelock import lock_file, unlock_file
        audit = self.write_log("audit.jsonl", [{"n": 1}])
        with open(audit, "a+b", buffering=0) as writer:
            lock_file(writer)
            try:
                with mock.patch.object(auditlog, "LOCKED_READ_SECONDS", 0.2):
                    with self.assertRaises(PermissionError) as raised:
                        list(auditlog.iter_records(str(audit)))
            finally:
                unlock_file(writer)
        self.assertIn("a writer held the log's lock", raised.exception.strerror)


class Following(TempFolderTest):
    def test_a_log_that_is_cut_is_read_again_from_its_start(self):
        audit = self.write_log("audit.jsonl", [{"n": 1}, {"n": 2}])
        steps = []

        def sleep(_seconds):
            steps.append(1)
            if len(steps) == 1:
                audit.write_text(json.dumps({"n": 3}) + "\n", encoding="utf-8")  # shorter than before

        found = list(auditlog.follow_records(str(audit), stop=lambda: len(steps) > 3, sleep=sleep))
        self.assertEqual(found, [{"n": 3}])


if __name__ == "__main__":
    unittest.main()
