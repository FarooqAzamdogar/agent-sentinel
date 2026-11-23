"""State kept in files for hook mode (agent_sentinel/hook_state.py): rate-limit counts and settings snapshots."""

import json
import os
import threading
from unittest import mock

from cli_support import TempFolderTest
from agent_sentinel import Firewall, Policy, hook_state
from agent_sentinel.hook_state import FileRateLimiter, RateLimitStateError, SettingsSnapshot

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


# ---- settings snapshots (ConfigChange) ----------------------------------------------------------------

class SettingsSnapshots(TempFolderTest):
    def setUp(self):
        super().setUp()
        self.state = self.folder / "state"
        self.settings = self.write("project/.claude/settings.json", {"model": "opus", "env": {"KEY": "secret-value"}})

    def snapshot(self, session="s1"):
        """A new snapshot object, as a new hook process would make."""
        return SettingsSnapshot(self.state, session)

    def test_a_change_is_named_by_key_and_the_snapshot_follows_kept_changes(self):
        self.snapshot().take([self.settings])
        self.write("project/.claude/settings.json", {"model": "sonnet", "hooks": {}})
        changes = self.snapshot().compare(self.settings, keep=False)
        self.assertEqual((changes.known, changes.changed, changes.added, changes.removed),
                         (True, ("model",), ("hooks",), ("env",)))
        self.assertEqual(self.snapshot().compare(self.settings, keep=True).changed, ("model",))
        self.assertEqual(self.snapshot().compare(self.settings, keep=True).changed, ())

    def test_values_are_never_stored_and_each_snapshot_has_its_own_salt(self):
        self.snapshot().take([self.settings])
        first = json.loads(self.snapshot().path.read_text(encoding="utf-8"))
        self.assertNotIn("secret-value", json.dumps(first))
        self.assertNotIn("opus", json.dumps(first))
        self.snapshot().take([self.settings])
        second = json.loads(self.snapshot().path.read_text(encoding="utf-8"))
        self.assertNotEqual(first["salt"], second["salt"])
        (entry,) = second["files"].values()
        self.assertNotEqual(entry, next(iter(first["files"].values())))

    def test_a_missing_file_and_a_file_that_appears(self):
        later = self.folder / "project" / ".claude" / "settings.local.json"
        self.snapshot().take([self.settings, later])
        self.write("project/.claude/settings.local.json", {"permissions": {}})
        changes = self.snapshot().compare(later, keep=True)
        self.assertEqual((changes.known, changes.added), (True, ("permissions",)))
        later.unlink()
        changes = self.snapshot().compare(later, keep=True)
        self.assertTrue(changes.now.missing)
        self.assertEqual(changes.removed, ("permissions",))

    def test_a_snapshot_of_another_session_or_a_damaged_one_counts_as_none(self):
        self.snapshot("other").take([self.settings])
        self.assertIsNone(self.snapshot("s1").compare(self.settings, keep=False).before)
        self.snapshot().take([self.settings])
        for damage in ("{not json", json.dumps({"format": "x"}), "[]"):
            with self.subTest(damage=damage):
                self.snapshot().path.write_text(damage, encoding="utf-8")
                changes = self.snapshot().compare(self.settings, keep=False)
                self.assertIsNone(changes.before)
                self.assertFalse(changes.known)

    def test_files_that_cannot_be_read_say_why(self):
        for content, problem in ((b"{oops", "is not valid JSON"), (b"[1]", "is not a JSON object"),
                                 (b'{"a": 1, "a": 2}', "is not valid JSON"),
                                 (b"x" * (hook_state.MAX_SETTINGS_BYTES + 1), "is not a regular file of at most")):
            with self.subTest(problem=problem):
                self.settings.write_bytes(content)
                keys = hook_state.read_settings_keys(self.settings, "0" * 32)
                self.assertIsNone(keys.hashes)
                self.assertIn(problem, keys.problem)
        # A folder: Windows refuses to open it at all, POSIX opens it and fstat says what it is.
        self.assertRegex(hook_state.read_settings_keys(self.folder, "0" * 32).problem,
                         "not a regular file|cannot be read")
        self.assertEqual(hook_state.read_settings_keys("relative/settings.json", "0" * 32).problem,
                         "is not named by a full path")

    def test_the_number_of_files_remembered_is_bounded(self):
        count = hook_state.MAX_SNAPSHOT_FILES + 4
        paths = [self.write(f"p{index}/settings.json", {"a": index}) for index in range(count)]
        self.snapshot().take(paths)
        self.assertEqual(len(json.loads(self.snapshot().path.read_text(encoding="utf-8"))["files"]),
                         hook_state.MAX_SNAPSHOT_FILES)
        for path in paths:
            self.snapshot().compare(path, keep=True)
        self.assertEqual(len(json.loads(self.snapshot().path.read_text(encoding="utf-8"))["files"]),
                         hook_state.MAX_SNAPSHOT_FILES)

    def test_paths_are_compared_as_the_system_compares_them(self):
        self.snapshot().take([self.settings])
        spelled = str(self.settings).upper() if os.name == "nt" else str(self.settings)
        self.assertTrue(self.snapshot().compare(spelled, keep=False).known)


class PrivateStateFolder(TempFolderTest):
    """Whichever store is the first to need the state folder makes it, and the folders above it, owner-only."""

    def modes_of_folders_made(self, action):
        """The name and the mode of each folder that `action` makes, in the order they are made."""
        import pathlib

        made = []
        real = pathlib.Path.mkdir

        def recording(path, mode=0o777, parents=False, exist_ok=False):
            existed = path.is_dir()
            real(path, mode, parents, exist_ok)
            if not existed:
                made.append((path.name, mode))

        with mock.patch.object(pathlib.Path, "mkdir", recording):
            action()
        return made

    def test_a_settings_snapshot_makes_the_folder_private(self):
        settings = self.write("project/.claude/settings.json", {"model": "opus"})
        for name, action in (
            ("take", lambda state: SettingsSnapshot(state, "s1").take([settings])),
            ("compare", lambda state: SettingsSnapshot(state, "s1").compare(settings, keep=True)),
            ("the policy record", lambda state: hook_state.PolicyRecord(state, "s1").seen("0" * 64, "block")),
        ):
            with self.subTest(name):
                state = self.folder / name / "home" / "hook-state"
                made = self.modes_of_folders_made(lambda: action(state))
                self.assertEqual([folder for folder, _ in made], [name, "home", "hook-state"])
                self.assertEqual({mode for _, mode in made}, {0o700})
                if os.name == "posix":
                    for folder in (state, state.parent, state.parent.parent):
                        self.assertEqual(folder.stat().st_mode & 0o777, 0o700, folder)


class PolicyRecords(TempFolderTest):
    FIRST, SECOND = "a" * 64, "b" * 64

    def setUp(self):
        super().setUp()
        self.state = self.folder / "state"

    def record(self, session="s1", clock=None):
        """A new record object, as a new hook process would make."""
        return hook_state.PolicyRecord(self.state, session, **({"clock": clock} if clock else {}))

    def test_the_first_policy_seen_is_kept_whatever_comes_later(self):
        self.assertEqual(self.record().seen(self.FIRST, "block"), hook_state.SeenPolicy(self.FIRST, "block"))
        self.assertEqual(self.record().seen(self.SECOND, "audit"), hook_state.SeenPolicy(self.FIRST, "block"))
        self.assertEqual(self.record("s2").seen(self.SECOND, "audit"), hook_state.SeenPolicy(self.SECOND, "audit"))
        stored = json.loads(self.record().path.read_text(encoding="utf-8"))
        self.assertEqual(stored, {"format": "agent-sentinel-session-policy", "version": 1, "session": "s1",
                                  "sha256": self.FIRST, "policy_changes": "block"})

    def test_a_new_session_replaces_the_record(self):
        self.record().seen(self.FIRST, "block")
        self.record().remember(self.SECOND, "audit")
        self.assertEqual(self.record().seen(self.FIRST, "block"), hook_state.SeenPolicy(self.SECOND, "audit"))

    def test_a_record_that_is_not_what_was_written_is_refused_and_never_repaired(self):
        self.record().seen(self.FIRST, "block")
        path = self.record().path
        good = json.loads(path.read_text(encoding="utf-8"))
        for name, content in (("not JSON", "{"), ("another format", json.dumps({**good, "format": "x"})),
                              ("a newer version", json.dumps({**good, "version": 2})),
                              ("another session", json.dumps({**good, "session": "s2"})),
                              ("an extra key", json.dumps({**good, "extra": 1})),
                              ("a hash in capitals", json.dumps({**good, "sha256": "A" * 64})),
                              ("a setting that is not one", json.dumps({**good, "policy_changes": True})),
                              ("too large", json.dumps(good) + " " * hook_state.MAX_POLICY_RECORD_BYTES)):
            with self.subTest(name):
                path.write_text(content, encoding="utf-8")
                with self.assertRaisesRegex(hook_state.PolicyRecordError, "is not valid"):
                    self.record().seen(self.FIRST, "block")
                self.assertEqual(path.read_text(encoding="utf-8"), content)

    def test_a_folder_that_cannot_be_used_and_values_that_are_not_a_policy_are_refused(self):
        self.write("state", "a file, not a folder")
        for action in (lambda: self.record().seen(self.FIRST, "block"),
                       lambda: self.record().remember(self.FIRST, "block")):
            with self.assertRaises(hook_state.PolicyRecordError):
                action()
        self.state = self.folder / "state-two"
        for sha256, setting in ((None, "block"), ("abc", "block"), (self.FIRST, "ask")):
            with self.subTest(sha256=sha256, setting=setting), self.assertRaises(ValueError):
                self.record().seen(sha256, setting)
        with self.assertRaises(ValueError):
            hook_state.PolicyRecord(self.state, "")

    def test_a_record_in_use_is_kept_fresh_about_once_a_day(self):
        clock = Clock()
        self.record(clock=clock).seen(self.FIRST, "block")
        path = self.record().path
        os.utime(path, (START, START))
        clock.now = START + 3600
        self.record(clock=clock).seen(self.FIRST, "block")
        self.assertEqual(path.stat().st_mtime, START)
        clock.now = START + 25 * 3600
        self.record(clock=clock).seen(self.FIRST, "block")
        self.assertEqual(path.stat().st_mtime, START + 25 * 3600)


class OldStateFiles(TempFolderTest):
    DAY = 24 * 60 * 60

    def setUp(self):
        super().setUp()
        self.state = self.folder / "state"
        self.state.mkdir()

    def place(self, name, age_days, content="{}"):
        path = self.state / name
        path.write_text(content, encoding="utf-8")
        os.utime(path, (START - age_days * self.DAY, START - age_days * self.DAY))
        return path

    def session_files(self, digest, age_days, kinds=("session", "rate", "settings", "policy")):
        return [self.place(f"{kind}-{digest}.json", age_days) for kind in kinds]

    def test_only_sessions_whose_files_are_all_old_are_removed(self):
        old = self.session_files("a" * 32, 45)
        recent = self.session_files("b" * 32, 5)
        in_use = self.session_files("c" * 32, 45, kinds=("session", "rate", "settings"))
        in_use.append(self.place("policy-" + "c" * 32 + ".json", 0))  # the session's record was looked at today
        self.assertEqual(hook_state.prune_state_files(self.state, now=START), 4)
        self.assertEqual([path.exists() for path in old], [False] * 4)
        self.assertEqual([path.exists() for path in (*recent, *in_use)], [True] * 8)
        self.assertEqual(hook_state.prune_state_files(self.state, now=START), 0)
        self.assertEqual(hook_state.prune_state_files(self.state, now=START + 26 * self.DAY), 4, "now b is old")

    def test_nothing_but_the_hooks_own_state_files_is_touched(self):
        kept = [self.place(name, 400) for name in (
            "notes.txt", "session-short.json", "policy-" + "A" * 32 + ".json", "session-" + "a" * 32 + ".json.bak",
            "audit-" + "a" * 32 + ".json", "sessions.lock", "session-" + "a" * 33 + ".json",
        )]
        folder = self.state / ("rate-" + "d" * 32 + ".json")
        folder.mkdir()
        inside = self.state / "more" / ("session-" + "e" * 32 + ".json")
        inside.parent.mkdir()
        inside.write_text("{}", encoding="utf-8")
        os.utime(inside, (0, 0))
        outside = self.folder / ("session-" + "f" * 32 + ".json")
        outside.write_text("{}", encoding="utf-8")
        os.utime(outside, (0, 0))
        self.assertEqual(hook_state.prune_state_files(self.state, now=START), 0)
        for path in (*kept, folder, inside, outside):
            self.assertTrue(path.exists(), path)
        self.assertEqual(hook_state.prune_state_files(self.folder / "no-such-folder", now=START), 0)

    def test_one_run_removes_a_bounded_number_of_files(self):
        for index in range(30):
            self.session_files(f"{index:032x}", 60, kinds=("session", "rate"))
        with mock.patch.object(hook_state, "MAX_PRUNED_FILES", 25):
            self.assertEqual(hook_state.prune_state_files(self.state, now=START), 25)
            self.assertEqual(len(list(self.state.glob("*-*.json"))), 35)
            self.assertEqual(hook_state.prune_state_files(self.state, now=START), 25)
            self.assertEqual(hook_state.prune_state_files(self.state, now=START), 10)
        with mock.patch.object(hook_state, "MAX_PRUNE_ENTRIES", 0):
            self.session_files("a" * 32, 60)
            self.assertEqual(hook_state.prune_state_files(self.state, now=START), 0)
