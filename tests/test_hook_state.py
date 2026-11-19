"""Rate-limit counts kept in a file for hook mode (agent_sentinel/hook_state.py)."""

import json
import threading
from unittest import mock

from cli_support import TempFolderTest
from agent_sentinel import Firewall, Policy, hook_state
from agent_sentinel.hook_state import FileRateLimiter, RateLimitStateError

START = 1_800_000_000  # a wall-clock second


class Clock:
    """A clock the test moves by hand."""

    def __init__(self, now=START):
        self.now = now

    def __call__(self):
        return self.now


class RateTest(TempFolderTest):
    def setUp(self):
        super().setUp()
        self.clock = Clock()
        self.state = self.folder / "state"

    def limiter(self, session="s1"):
        """A new limiter object, as a new hook process would make."""
        return FileRateLimiter(self.state, session, clock=self.clock)

    def count(self, limits, session="s1"):
        return self.limiter(session).over_limit(limits, 0.0)

    def stored(self, session="s1"):
        return json.loads(self.limiter(session).path.read_text(encoding="utf-8"))


class Counting(RateTest):
    def test_counts_carry_from_one_process_to_the_next(self):
        limits = [("*", 3), ("rule:Bash", 2)]
        self.assertIsNone(self.count(limits))
        self.assertIsNone(self.count(limits))
        self.assertEqual(self.count(limits), "rule:Bash")
        self.assertEqual(self.count([("*", 3)]), None)
        self.assertEqual(self.count([("*", 3)]), "*")

    def test_a_full_bucket_counts_nothing(self):
        self.count([("rule:a", 1)])
        self.assertEqual(self.count([("*", 10), ("rule:a", 1)]), "rule:a")
        self.assertNotIn("*", self.stored()["buckets"], "a refused call is not counted in the other buckets")

    def test_calls_older_than_the_window_stop_counting(self):
        self.count([("*", 1)])
        self.clock.now += 30
        self.assertEqual(self.count([("*", 1)]), "*")
        self.clock.now += 30  # whole seconds: a call may count up to a second longer than a minute, never less
        self.assertEqual(self.count([("*", 1)]), "*")
        self.clock.now += 1
        self.assertIsNone(self.count([("*", 1)]))

    def test_a_call_counted_in_the_future_counts_as_made_now(self):
        self.count([("*", 1)])
        self.clock.now -= 3600  # the clock was set back an hour
        self.assertEqual(self.count([("*", 1)]), "*")
        self.clock.now += 60
        self.assertEqual(self.count([("*", 1)]), "*")
        self.clock.now += 1  # a minute after it was seen, not an hour
        self.assertIsNone(self.count([("*", 1)]))

    def test_each_session_counts_on_its_own(self):
        self.count([("*", 1)], session="s1")
        self.assertIsNone(self.count([("*", 1)], session="s2"))
        self.assertEqual(self.count([("*", 1)], session="s1"), "*")

    def test_without_limits_no_file_is_touched(self):
        self.assertIsNone(self.count([]))
        self.assertFalse(self.state.exists())

    def test_the_file_holds_at_most_one_entry_per_second_of_the_window(self):
        for _ in range(300):
            self.clock.now += 1
            self.count([("*", 1_000_000)])
            self.count([("*", 1_000_000)])
        entries = self.stored()["buckets"]["*"]
        self.assertLessEqual(len(entries), 61)
        self.assertTrue(all(count == 2 for _, count in entries))

    def test_threads_and_processes_counting_at_once_lose_no_call(self):
        def worker():
            for _ in range(25):
                FileRateLimiter(self.state, "s1").over_limit([("*", 1_000_000)], 0.0)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(count for _, count in self.stored()["buckets"]["*"]), 100)


class FailingClosed(RateTest):
    def damage(self, content, session="s1"):
        """Put this content where the session's rate-limit file belongs; return its path."""
        path = self.limiter(session).path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else json.dumps(content).encode("utf-8"))
        return path

    def good_document(self, **changes):
        document = {"format": "agent-sentinel-rate", "version": 1, "session": "s1",
                    "buckets": {"*": [[START, 1]]}}
        document.update(changes)
        return document

    def test_a_file_that_is_not_exactly_what_was_written_is_refused_and_never_repaired(self):
        for name, content in (
            ("not JSON", b"{oops"),
            ("not UTF-8", b'{"format": "\xff"}'),
            ("a list", []),
            ("an unknown key", {**self.good_document(), "extra": 1}),
            ("a missing key", {k: v for k, v in self.good_document().items() if k != "buckets"}),
            ("another format", self.good_document(format="something-else")),
            ("another version", self.good_document(version=2)),
            ("another session", self.good_document(session="s2")),
            ("a count that is true", self.good_document(buckets={"*": [[START, True]]})),
            ("a count of zero", self.good_document(buckets={"*": [[START, 0]]})),
            ("a negative second", self.good_document(buckets={"*": [[-5, 1]]})),
            ("a float second", self.good_document(buckets={"*": [[START + 0.5, 1]]})),
            ("an entry of three", self.good_document(buckets={"*": [[START, 1, 2]]})),
            ("too many entries", self.good_document(buckets={"*": [[START - i, 1] for i in range(62)]})),
            ("a huge count", self.good_document(buckets={"*": [[START, 10 ** 12]]})),
            ("a long bucket name", self.good_document(buckets={"x" * 1001: [[START, 1]]})),
            ("buckets that are a list", self.good_document(buckets=[["*", 1]])),
            ("a repeated key", b'{"format": "agent-sentinel-rate", "format": "x", "version": 1, "session": "s1", '
                               b'"buckets": {}}'),
            ("deep nesting", b"[" * 100_000 + b"]" * 100_000),
        ):
            with self.subTest(name):
                path = self.damage(content)
                before = path.read_bytes()
                with self.assertRaises(RateLimitStateError) as caught:
                    self.count([("*", 10)])
                self.assertIn("delete it to start the counts again", str(caught.exception))
                self.assertEqual(path.read_bytes(), before)

    def test_an_oversized_file_is_refused(self):
        self.damage(b" " * (hook_state.MAX_RATE_FILE_BYTES + 1))
        with self.assertRaisesRegex(RateLimitStateError, "too large"):
            self.count([("*", 10)])

    def test_a_folder_that_cannot_be_written_is_refused(self):
        self.state = self.write("state", "a file where the folder should be")
        with self.assertRaisesRegex(RateLimitStateError, "cannot use the rate-limit file"):
            self.count([("*", 10)])

    def test_a_missing_file_starts_the_counts_again(self):
        path = self.damage(b"{oops")
        path.unlink()
        self.assertIsNone(self.count([("*", 10)]))

    def test_too_many_buckets_are_refused(self):
        with mock.patch.object(hook_state, "MAX_BUCKETS", 3):
            self.count([("a", 9), ("b", 9), ("c", 9)])
            with self.assertRaisesRegex(RateLimitStateError, "more than 3 rate limits"):
                self.count([("d", 9)])

    def test_a_session_id_must_be_short_text(self):
        for session in ("", "x" * 257, None, 5):
            with self.subTest(session=session), self.assertRaises(ValueError):
                FileRateLimiter(self.state, session)


class WithTheFirewall(RateTest):
    def test_the_firewall_counts_in_the_limiter_it_is_given(self):
        policy = Policy.from_dict({"default": "allow", "limits": {"max_calls_per_minute": 2}})
        for _ in range(2):
            self.assertTrue(Firewall(policy, rate_limiter=self.limiter()).check_call("x", {}).allowed)
        decision = Firewall(policy, rate_limiter=self.limiter()).check_call("x", {})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule, "limits.max_calls_per_minute")

    def test_a_firewall_without_one_counts_in_memory_as_before(self):
        policy = Policy.from_dict({"default": "allow", "limits": {"max_calls_per_minute": 1}})
        self.assertTrue(Firewall(policy).check_call("x", {}).allowed)
        self.assertTrue(Firewall(policy).check_call("x", {}).allowed)
