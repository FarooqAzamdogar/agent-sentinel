"""Tests for session.py: labels, marks, and the two session stores.

The file store is what hook mode relies on, one process per check, so most
tests here are about it failing closed: a session file that is missing,
damaged, swapped or shrunk must count as "every mark set".
"""

import json
import subprocess
import sys
import tempfile
import threading
import unittest
import warnings
from pathlib import Path
from unittest import mock

import support  # noqa: F401  (puts the project on the path)
from agent_sentinel import Firewall, Policy, session
from agent_sentinel.session import (
    FileSessionStore,
    Mark,
    MemorySessionStore,
    SessionMarks,
    SessionStateError,
    is_label,
    labels_from_annotations,
)


class Labels(unittest.TestCase):
    def test_a_label_is_a_short_lowercase_word(self):
        for good in ("untrusted", "private", "sink", "pii", "web-content", "tier_2", "a" * 40):
            with self.subTest(label=good):
                self.assertTrue(is_label(good))
        for bad in ("", "Untrusted", "2fa", "-x", "has space", "a" * 41, "ünicode", None, 7, ["sink"]):
            with self.subTest(label=bad):
                self.assertFalse(is_label(bad))

    def test_an_open_world_tool_is_untrusted_and_a_sink(self):
        self.assertEqual(labels_from_annotations({"openWorldHint": True}), {"untrusted", "sink"})

    def test_a_destructive_tool_is_a_sink_unless_it_is_read_only(self):
        self.assertEqual(labels_from_annotations({"destructiveHint": True}), {"sink"})
        self.assertEqual(labels_from_annotations({"destructiveHint": True, "readOnlyHint": True}), frozenset())

    def test_only_an_explicit_true_counts(self):
        # The spec's defaults (openWorldHint true when absent) are not applied, and a truthy text is not true.
        for annotations in ({}, {"openWorldHint": "true"}, {"openWorldHint": 1}, {"openWorldHint": False}, None, [],
                            "openWorldHint"):
            with self.subTest(annotations=annotations):
                self.assertEqual(labels_from_annotations(annotations), frozenset())


class Marks(unittest.TestCase):
    def test_everything_counts_as_every_label(self):
        marks = SessionMarks.untrusted("test")
        self.assertTrue(marks.has("anything") and marks.has_all(["untrusted", "private"]))
        self.assertEqual(marks.labels, frozenset())

    def test_marks_are_read_only(self):
        marks = SessionMarks.of(["untrusted"])
        with self.assertRaises(TypeError):
            marks.marks["private"] = Mark("private", "x", "")

    def test_plain_labels_become_marks_without_a_cause_and_sink_is_dropped(self):
        marks = SessionMarks.of(["untrusted", "sink"])
        self.assertEqual(marks.labels, {"untrusted"})
        self.assertEqual(marks.marks["untrusted"].tool, "")

    def test_a_text_is_not_taken_for_a_list_of_labels(self):
        with self.assertRaises(TypeError):
            SessionMarks.of("untrusted")


class MemoryStore(unittest.TestCase):
    def test_marks_add_up_and_keep_their_first_cause(self):
        store = MemorySessionStore()
        self.assertEqual(store.read().labels, frozenset())
        store.add(["untrusted"], "fetch_page")
        store.add(["untrusted", "private"], "read_file")
        marks = store.read()
        self.assertEqual(marks.labels, {"untrusted", "private"})
        self.assertEqual(marks.marks["untrusted"].tool, "fetch_page")
        self.assertEqual(marks.marks["private"].tool, "read_file")
        self.assertFalse(marks.everything)

    def test_sink_is_never_a_mark(self):
        store = MemorySessionStore()
        store.add(["sink"], "send_email")
        self.assertEqual(store.read().labels, frozenset())

    def test_an_invalid_label_is_a_programming_error(self):
        with self.assertRaises(ValueError):
            MemorySessionStore().add(["Untrusted"], "x")

    def test_a_long_tool_name_is_shortened(self):
        store = MemorySessionStore()
        store.add(["untrusted"], "t" * 10_000)
        self.assertLessEqual(len(store.read().marks["untrusted"].tool), 210)

    def test_more_marks_than_can_be_tracked_means_everything(self):
        store = MemorySessionStore()
        with mock.patch.object(session, "MAX_MARKS", 2):
            store.add(["a", "b", "c"], "x")
        self.assertTrue(store.read().everything)


class StoresWrittenForAnEarlierVersion(unittest.TestCase):
    """0.5 documented a session store as two operations, read() and add(labels, tool), and asked for no base class."""

    POLICY = {
        "default": "block",
        "tools": {"read_file": {"action": "allow", "labels": ["private"]},
                  "fetch": {"action": "allow", "labels": ["untrusted"]},
                  "send": {"action": "allow", "labels": ["sink"]}},
        "flows": [{"after": ["untrusted", "private"], "then": "sink", "action": "block"}],
    }

    class TwoOperations:
        """Written against the 0.5 documentation, without subclassing SessionStore."""

        def __init__(self):
            self.inner = MemorySessionStore()
            self.added = []

        def read(self):
            return self.inner.read()

        def add(self, labels, tool):
            self.added.append((sorted(labels), tool))
            return self.inner.add(labels, tool)

    def firewall(self, store, **policy):
        return Firewall(Policy.from_dict({**self.POLICY, **policy}), session_store=store)

    def test_a_store_with_the_two_operations_still_works_with_one_warning(self):
        # Review of 0.6: every result raised AttributeError ('... has no attribute read_state').
        store = self.TwoOperations()
        with self.assertWarns(RuntimeWarning) as caught:
            firewall = self.firewall(store)
        self.assertIn("TwoOperations has read() and add() but not add_marks(), read_state() and update_state()",
                      str(caught.warning))
        self.assertEqual(caught.filename, __file__)  # it points at the program that made the Firewall
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # nothing more is warned about, whatever is checked
            for tool, text in (("read_file", "the memo"), ("fetch", "a page")):
                self.assertTrue(firewall.check_call(tool, {"path": "a"}).allowed)
                self.assertTrue(firewall.check_result(tool, text, cross_message=True).decision.allowed)
                firewall.mark_delivered(tool)
            refused = firewall.check_call("send", {"to": "x"})
            self.assertEqual((refused.allowed, refused.rule), (False, "flows[0]"))
            self.assertEqual(firewall.run("fetch", {"url": "https://example.com"}, lambda **kw: "page text"),
                             "page text")
        self.assertEqual(store.added[:2], [(["private"], "read_file"), (["untrusted"], "fetch")])
        self.assertEqual(firewall.session_marks().labels, {"private", "untrusted"})

    def test_what_such_a_store_cannot_hold_is_skipped_or_refused_never_an_error(self):
        store = self.TwoOperations()
        with self.assertWarns(RuntimeWarning):
            firewall = self.firewall(store, limits={"max_calls_per_session": 5})
        # A session limit cannot be counted, so the call it counts is refused (fail closed), with a reason.
        refused = firewall.check_call("fetch", {"url": "https://example.com"})
        self.assertFalse(refused.allowed)
        self.assertIn("could not be counted", refused.reason)
        with self.assertRaises(SessionStateError):
            firewall.session_store.read_state()
        self.assertEqual(firewall._kept_tail("result"), ())  # no tail: text split over two results is not looked for

    def test_a_session_store_is_used_as_it_is_and_one_with_every_operation_gets_no_warning(self):
        own = MemorySessionStore()
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            self.assertIs(self.firewall(own).session_store, own)

            class Complete(self.TwoOperations):
                def add_marks(self, marks, tail=None):
                    return self.inner.add_marks(marks, tail)

                def read_state(self):
                    return self.inner.read_state()

                def update_state(self, change):
                    return self.inner.update_state(change)

            firewall = self.firewall(Complete(), limits={"max_calls_per_session": 1})
            self.assertTrue(firewall.check_call("fetch", {"url": "a"}).allowed)
            self.assertFalse(firewall.check_call("fetch", {"url": "b"}).allowed)  # counted in the store's own state
            self.assertTrue(firewall.session_store.read_state().counts)

    def test_an_object_that_is_no_store_is_refused_when_the_firewall_is_made(self):
        for store in (object(), "memory", {"read": 1}, type("OnlyRead", (), {"read": lambda self: None})()):
            with self.subTest(store=store), self.assertRaises(TypeError) as caught:
                self.firewall(store)
            self.assertIn("read() and add(labels, tool)", str(caught.exception))


class FileStoreSetup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name) / "state"

    def store(self, session_id="session-1"):
        return FileSessionStore(self.folder, session_id)


class FileStore(FileStoreSetup):
    def test_a_begun_session_starts_empty_and_keeps_its_marks_across_processes(self):
        self.assertEqual(self.store().begin().labels, frozenset())
        self.store().add(["untrusted"], "fetch_page")  # another "process": a new object
        marks = self.store().read()
        self.assertEqual(marks.labels, {"untrusted"})
        self.assertEqual(marks.marks["untrusted"].tool, "fetch_page")
        self.assertFalse(marks.everything)

    def test_begin_is_idempotent_and_does_not_clear_marks(self):
        self.store().begin()
        self.store().add(["private"], "read_file")
        self.store().begin()  # e.g. a second SessionStart for the same session
        self.assertEqual(self.store().read().labels, {"private"})

    def test_a_session_that_was_never_begun_counts_as_every_mark_set(self):
        marks = self.store().read()
        self.assertTrue(marks.everything)
        self.assertIn("missing", marks.why)

    def test_a_deleted_session_file_counts_as_every_mark_set(self):
        store = self.store()
        store.begin()
        store.add(["untrusted"], "fetch_page")
        store.path.unlink()
        self.assertTrue(store.read().everything)
        self.assertTrue(self.store().read().everything)  # and for a fresh process too

    def test_adding_to_a_broken_session_never_repairs_it(self):
        store = self.store()
        store.begin()
        store.path.unlink()
        self.assertTrue(store.add(["untrusted"], "fetch_page").everything)
        self.assertFalse(store.path.exists())

    def test_marks_that_disappear_from_the_file_are_noticed(self):
        store = self.store()
        store.begin()
        store.add(["untrusted", "private"], "fetch_page")
        document = json.loads(store.path.read_text(encoding="ascii"))
        del document["marks"]["untrusted"]
        store.path.write_text(json.dumps(document), encoding="ascii")
        marks = store.read()
        self.assertTrue(marks.everything)
        self.assertIn("disappeared", marks.why)

    def test_a_file_from_another_session_is_not_accepted(self):
        self.store("session-1").begin()
        other = self.store("session-2")
        other.begin()
        # Copying a clean file over this session's file must not clear its marks.
        mine = self.store("session-1")
        mine.add(["untrusted"], "fetch_page")
        mine.path.write_bytes(other.path.read_bytes())
        self.assertTrue(self.store("session-1").read().everything)

    def test_damaged_files_count_as_every_mark_set(self):
        store = self.store()
        store.begin()
        good = json.loads(store.path.read_text(encoding="ascii"))
        damaged = {
            "not json": b"{not json",
            "not utf-8": b"\xff\xfe{}",
            "a list": b"[]",
            "an extra key": json.dumps({**good, "extra": 1}).encode(),
            "a missing key": json.dumps({k: v for k, v in good.items() if k != "started"}).encode(),
            "another version": json.dumps({**good, "version": 3}).encode(),
            "marks not an object": json.dumps({**good, "marks": []}).encode(),
            "a bad label": json.dumps({**good, "marks": {"Bad Label": {"tool": "x", "time": "t"}}}).encode(),
            "sink as a mark": json.dumps({**good, "marks": {"sink": {"tool": "x", "time": "t"}}}).encode(),
            "a bad cause": json.dumps({**good, "marks": {"untrusted": {"tool": 5, "time": "t"}}}).encode(),
            "a cause with more keys": json.dumps(
                {**good, "marks": {"untrusted": {"tool": "x", "time": "t", "note": ""}}}
            ).encode(),
            "a repeated key": b'{"format": "a", "format": "b"}',
            "too large": b" " * (session.MAX_STATE_FILE_BYTES + 1),
            "deeply nested": b"[" * 100_000,
        }
        for name, content in damaged.items():
            with self.subTest(damage=name):
                store.path.write_bytes(content)
                marks = self.store().read()
                self.assertTrue(marks.everything)
                self.assertTrue(marks.why)

    def test_too_many_marks_in_the_file_is_damage(self):
        store = self.store()
        store.begin()
        document = json.loads(store.path.read_text(encoding="ascii"))
        document["marks"] = {f"l{i}": {"tool": "x", "time": "t"} for i in range(session.MAX_MARKS + 1)}
        store.path.write_text(json.dumps(document), encoding="ascii")
        self.assertTrue(self.store().read().everything)

    def test_a_hostile_session_id_stays_inside_the_folder(self):
        for hostile in ("../../escape", "C:\\Windows\\x", "\x00nul", "con", "a/b", "\ud800"):
            with self.subTest(session_id=hostile):
                store = self.store(hostile)
                store.begin()
                self.assertEqual(store.path.parent, self.folder)
                self.assertRegex(store.path.name, r"\Asession-[0-9a-f]{32}\.json\Z")
                self.assertFalse(store.read().everything)

    def test_session_ids_must_be_short_text(self):
        for bad in ("", "x" * 257, None, 5):
            with self.subTest(session_id=bad):
                with self.assertRaises(ValueError):
                    FileSessionStore(self.folder, bad)

    def test_a_missing_folder_reads_as_every_mark_set(self):
        store = FileSessionStore(Path(self.tmp.name) / "nowhere", "s")
        self.assertTrue(store.read().everything)
        self.assertIn("missing", store.read().why)
        # Nothing to record then: every mark already counts as set.
        self.assertTrue(store.add(["untrusted"], "fetch_page").everything)

    def test_marks_that_cannot_be_written_raise(self):
        store = self.store()
        store.begin()
        with mock.patch("agent_sentinel.filelock.os.replace", side_effect=PermissionError("read-only")), \
                mock.patch("agent_sentinel.filelock.time.sleep"):
            with self.assertRaises(SessionStateError):
                store.add(["untrusted"], "fetch_page")
        self.assertEqual(self.store().read().labels, frozenset())  # the old file is intact
        self.assertEqual([path.name for path in store.path.parent.iterdir() if path.suffix == ".tmp"], [])

    def test_begin_reports_a_folder_that_cannot_be_made(self):
        blocker = Path(self.tmp.name) / "a_file"
        blocker.write_text("x", encoding="utf-8")
        with self.assertRaises(SessionStateError):
            FileSessionStore(blocker / "state", "s").begin()

    def test_the_file_holds_no_more_than_labels_causes_and_hashed_state(self):
        # Changed in 0.6: version 2 adds the server and channel of a cause, and the session state.
        store = self.store()
        store.begin()
        store.add(["private"], "read_file")
        document = json.loads(store.path.read_text(encoding="ascii"))
        self.assertEqual(set(document), {"format", "version", "session", "started", "marks", "tails", "counts",
                                         "distinct", "identical", "refusals"})
        self.assertEqual(document["version"], 2)
        self.assertEqual(set(document["marks"]["private"]), {"tool", "time", "server", "channel"})

    def test_a_tool_name_that_utf8_cannot_encode_is_still_written(self):
        store = self.store()
        store.begin()
        store.add(["untrusted"], "fetch\ud800")
        self.assertEqual(self.store().read().marks["untrusted"].tool, "fetch\ud800")


class FileStoreConcurrency(FileStoreSetup):
    def test_threads_adding_different_marks_lose_none(self):
        self.store().begin()
        labels = [f"label{i}" for i in range(20)]
        threads = [threading.Thread(target=self.store().add, args=([label], "t")) for label in labels]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(self.store().read().labels, set(labels))

    def test_processes_adding_different_marks_lose_none(self):
        self.store().begin()
        script = (
            "import sys; sys.path.insert(0, sys.argv[1]);"
            "from agent_sentinel.session import FileSessionStore;"
            "store = FileSessionStore(sys.argv[2], 'session-1');"
            "[store.add([sys.argv[3] + str(i)], 'tool') for i in range(5)]"
        )
        processes = [
            subprocess.Popen([sys.executable, "-c", script, str(support.ROOT), str(self.folder), f"p{n}x"])
            for n in range(4)
        ]
        for process in processes:
            self.assertEqual(process.wait(timeout=120), 0)
        expected = {f"p{n}x{i}" for n in range(4) for i in range(5)}
        self.assertEqual(self.store().read().labels, expected)


if __name__ == "__main__":
    unittest.main()
