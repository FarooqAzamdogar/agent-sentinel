"""Reading audit logs: bounded lines, records, times, filters (agent_sentinel/auditlog.py)."""

import io
import json
import time
import unittest
from datetime import datetime, timedelta, timezone

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
