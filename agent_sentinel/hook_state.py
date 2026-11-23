"""State kept in files for hook mode, where every event is answered by a new process.

Three kinds of state live here, next to the session file
(session.FileSessionStore: the flow marks and, since its format version 2,
the tails of the tail scan, the session-limit counts and approval memory):
the rate-limit counts (FileRateLimiter), a snapshot of Claude Code's
settings files (SettingsSnapshot) and which policy file the session began
with (PolicyRecord). Each kind has its own file, format name and version,
and all of them share the folder's lock file. prune_state_files, at the end,
removes the files of sessions that are long over.

Rate limits
-----------
The proxy and the library count calls in memory (firewall._RateLimiter). A
hook process lives for one call, so its memory forgets every call before it,
and "max_calls_per_minute" would never be reached. `FileRateLimiter` keeps
the counts of one session in a file instead:

    <state folder>/rate-<hash of the session id>.json

next to the session's flow marks (session.FileSessionStore), under the same
lock file, so that hook processes running at the same moment take turns.

The file holds, for each bucket ("*" for all tools together, "rule:<name>"
for one tool rule, as Policy.call_limits names them), how many calls were
made in each second of the last minute. Seconds are wall-clock time, which
every process agrees on.

Failing closed:

  * a file that cannot be read, locked or written, or that is not exactly
    what this module writes (another session's, another format, too large,
    a count that makes no sense), raises RateLimitStateError. The hook then
    refuses the call: it cannot tell how many calls were made;
  * a missing file is a session with no calls yet. Deleting the file
    therefore starts the counts again: keep the state folder out of the
    agent's reach (the same advice as for the flow marks);
  * a call counted in the future (the clock was set back) counts as made
    now, so it still counts for a full minute.

Settings snapshots
------------------
Claude Code's ConfigChange event says which settings file changed, not what
changed in it. So at SessionStart the hook notes the top-level keys of the
user's and the project's settings files, each with a salted hash of its value
(never the value), and at ConfigChange it compares the file with that note:

    <state folder>/settings-<hash of the session id>.json

The snapshot only feeds the audit record. A snapshot that is missing or
damaged makes the record say that what changed is not known; it never lets
anything through that would otherwise be refused. Its version
(SETTINGS_FILE_VERSION) is its own: the session file's version
(session.FILE_VERSION) can change without it, and the other way round.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from . import jsonutil
from .filelock import locked, make_private_folder, replace_file
from .firewall import RATE_WINDOW_SECONDS
from .policy import POLICY_CHANGES
from .session import LOCK_FILE_NAME, MAX_SESSION_ID_CHARS

RATE_FILE_FORMAT = "agent-sentinel-rate"
RATE_FILE_VERSION = 1
# A policy has a handful of rate limits; these bounds are for a file someone tampered with.
MAX_RATE_FILE_BYTES = 256 * 1024
MAX_BUCKETS = 1_000
MAX_BUCKET_NAME_CHARS = 1_000
MAX_COUNT = 1_000_000_000


class RateLimitStateError(Exception):
    """The rate-limit counts of a session cannot be read or recorded, so the call cannot be judged."""


class FileRateLimiter:
    """Counts calls per bucket over the last minute, in a file shared by every hook process of one session.

    Has the method the Firewall calls (see Firewall's `rate_limiter`):
    over_limit(limits, now) returns the name of a bucket that is full, or
    None after counting the call in every bucket. `now` is ignored: it is
    the calling process's monotonic clock, which another process cannot
    compare with; the file uses `clock` (wall-clock seconds) instead.
    """

    def __init__(self, directory: str | Path, session_id: str, clock: Callable[[], float] = time.time) -> None:
        if not isinstance(session_id, str) or not 0 < len(session_id) <= MAX_SESSION_ID_CHARS:
            raise ValueError(f"the session id must be text of 1 to {MAX_SESSION_ID_CHARS} characters")
        self.directory = Path(directory)
        self.session_id = session_id
        # Hashed like the session file's name: the id comes from the client and must not shape a path.
        digest = hashlib.sha256(session_id.encode("utf-8", errors="surrogatepass")).hexdigest()[:32]
        self.path = self.directory / f"rate-{digest}.json"
        self._lock_path = self.directory / LOCK_FILE_NAME
        self._clock = clock
        self._thread_lock = threading.Lock()

    def over_limit(self, limits: list[tuple[str, int]], now: float) -> str | None:
        """Count one call in every bucket, unless one is full; then return that bucket. See the class docstring."""
        if not limits:
            return None  # nothing to count: the file is not even opened
        second = int(self._clock())
        try:
            make_private_folder(self.directory)  # owner-only, the missing folders above it too
            with self._thread_lock, locked(self._lock_path):
                buckets = _recent(self._read(), second)
                full = next(
                    (bucket for bucket, limit in limits if sum(count for _, count in buckets.get(bucket, ())) >= limit),
                    None,
                )
                if full is None:
                    for bucket, _ in limits:
                        buckets[bucket] = _counted(buckets.get(bucket, []), second)
                if len(buckets) > MAX_BUCKETS:
                    raise RateLimitStateError(f"more than {MAX_BUCKETS} rate limits are counting calls")
                # Written back even for a refused call: a count from the future is stored as made now,
                # so it ends a minute from now (not when the clock catches up), and old counts go.
                self._write(buckets)
        except OSError as exc:
            raise RateLimitStateError(f"cannot use the rate-limit file {self.path}: {exc}") from exc
        return full

    # ---- the file ---------------------------------------------------------------------

    def _read(self) -> dict[str, list[list[int]]]:
        """The buckets in the file: {} when there is no file yet. RateLimitStateError when it is not valid."""
        try:
            with open(self.path, "rb") as handle:
                data = handle.read(MAX_RATE_FILE_BYTES + 1)
        except FileNotFoundError:
            return {}
        if len(data) > MAX_RATE_FILE_BYTES:
            raise RateLimitStateError(f"the rate-limit file {self.path} is too large")
        problem, buckets = self._parse(data)
        if problem is not None:
            raise RateLimitStateError(
                f"the rate-limit file {self.path} is not valid ({problem}); delete it to start the counts again"
            )
        return buckets

    def _parse(self, data: bytes) -> tuple[str | None, dict[str, list[list[int]]]]:
        """Read the file's bytes. Returns (what is wrong, or None; the buckets)."""
        try:
            document = jsonutil.loads(data.decode("utf-8"))
        except (ValueError, RecursionError):  # includes UnicodeDecodeError and a repeated key
            return "not JSON", {}
        if not isinstance(document, dict) or set(document) != {"format", "version", "session", "buckets"}:
            return "unexpected contents", {}
        if document["format"] != RATE_FILE_FORMAT or document["version"] != RATE_FILE_VERSION:
            return "unknown format or version", {}
        if document["session"] != self.session_id:
            return "it belongs to another session", {}
        buckets = document["buckets"]
        if not isinstance(buckets, dict) or len(buckets) > MAX_BUCKETS:
            return "unexpected contents", {}
        for name, entries in buckets.items():
            if len(name) > MAX_BUCKET_NAME_CHARS or not _valid_entries(entries):
                return "a count is malformed", {}
        return None, buckets

    def _write(self, buckets: dict[str, list[list[int]]]) -> None:
        """Replace the file. Atomic: a crash leaves the old file or the new one."""
        document = {
            "format": RATE_FILE_FORMAT, "version": RATE_FILE_VERSION, "session": self.session_id, "buckets": buckets,
        }
        data = json.dumps(document, ensure_ascii=True).encode("ascii")
        if len(data) > MAX_RATE_FILE_BYTES:
            raise RateLimitStateError("the rate-limit counts would not fit in the rate-limit file")
        replace_file(self.path, data)


def _valid_entries(entries: Any) -> bool:
    """A bucket's entries: at most one per second of the window, each [second, count] with sensible numbers."""
    if not isinstance(entries, list) or len(entries) > RATE_WINDOW_SECONDS + 1:
        return False
    for entry in entries:
        if not (isinstance(entry, list) and len(entry) == 2 and all(_whole(number) for number in entry)):
            return False
        if entry[0] < 0 or not 0 < entry[1] <= MAX_COUNT:
            return False
    return True


def _whole(value: Any) -> bool:
    # bool is a subclass of int in Python, and `true` is not a count.
    return isinstance(value, int) and not isinstance(value, bool)


def _recent(buckets: dict[str, list[list[int]]], second: int) -> dict[str, list[list[int]]]:
    """The counts that still fall in the window ending at `second`; empty buckets are dropped.

    Kept: the seconds from `second - RATE_WINDOW_SECONDS` on. A call made up to
    a second more than a minute ago may still count, never the other way
    round. A second after `second` (the clock went back) counts as `second`.
    """
    kept: dict[str, list[list[int]]] = {}
    for name, entries in buckets.items():
        per_second: dict[int, int] = {}
        for at, count in entries:
            if at >= second - RATE_WINDOW_SECONDS:
                at = min(at, second)
                per_second[at] = min(per_second.get(at, 0) + count, MAX_COUNT)
        if per_second:
            kept[name] = [[at, count] for at, count in sorted(per_second.items())]
    return kept


def _counted(entries: list[list[int]], second: int) -> list[list[int]]:
    """The entries with one more call in `second` (entries are sorted, and none is later than `second`)."""
    if entries and entries[-1][0] == second:
        return [*entries[:-1], [second, min(entries[-1][1] + 1, MAX_COUNT)]]
    return [*entries, [second, 1]]


# ---- settings snapshots (ConfigChange) ------------------------------------------------------

SETTINGS_FILE_FORMAT = "agent-sentinel-settings"
SETTINGS_FILE_VERSION = 1
# Bounds. A Claude Code settings file is a few kilobytes with a dozen top-level keys;
# a larger one is not read, and the record says so.
MAX_SETTINGS_BYTES = 1024 * 1024
MAX_SETTINGS_KEYS = 200
MAX_SETTINGS_KEY_CHARS = 200
MAX_SETTINGS_PATH_CHARS = 4096
MAX_SNAPSHOT_FILES = 16  # settings files remembered for one session
MAX_SNAPSHOT_BYTES = 256 * 1024
MAX_PROBLEM_CHARS = 300
_HASH_CHARS = 32
_SALT_CHARS = 32


@dataclass(frozen=True)
class SettingsKeys:
    """The top-level keys of one settings file, each with a salted hash of its value.

    hashes:  key -> hash; None when the keys could not be read (`problem` says why).
    missing: the file did not exist (hashes is then empty).
    """

    hashes: Mapping[str, str] | None
    problem: str = ""
    missing: bool = False


@dataclass(frozen=True)
class KeyChanges:
    """How the top-level keys of a settings file differ from the snapshot, by name (never by value).

    before:  what the snapshot held for the file; None when it held nothing (no snapshot of
             that file, or a snapshot that could not be read).
    now:     the file as it is now.
    known:   both sides could be read, so changed, added and removed say what changed.
    """

    before: SettingsKeys | None
    now: SettingsKeys
    known: bool = False
    changed: tuple[str, ...] = ()  # keys whose value differs
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()


def key_changes(before: SettingsKeys | None, now: SettingsKeys) -> KeyChanges:
    """Compare two readings of one settings file, key by key."""
    if before is None or before.hashes is None or now.hashes is None:
        return KeyChanges(before, now)
    old, new = before.hashes, now.hashes
    return KeyChanges(
        before, now, known=True,
        changed=tuple(sorted(key for key in new if key in old and old[key] != new[key])),
        added=tuple(sorted(key for key in new if key not in old)),
        removed=tuple(sorted(key for key in old if key not in new)),
    )


class SettingsSnapshot:
    """The top-level keys of Claude Code's settings files for one session, in a file in the state folder.

    take(paths)            at SessionStart: a new snapshot of these files (a new salt).
    compare(path, keep)    at ConfigChange: the file now against the snapshot; with keep,
                           the snapshot then holds the file as it is now (the change was
                           applied), so the next change is compared with this one.

    Both raise OSError when the state folder or the snapshot file cannot be
    used; a snapshot file that is not what this class writes counts as no
    snapshot. Values are never stored: only a hash of each, salted with a
    random value per snapshot, so that the file says nothing about a value
    that a dictionary of common values could recover.
    """

    def __init__(self, directory: str | Path, session_id: str) -> None:
        if not isinstance(session_id, str) or not 0 < len(session_id) <= MAX_SESSION_ID_CHARS:
            raise ValueError(f"the session id must be text of 1 to {MAX_SESSION_ID_CHARS} characters")
        self.directory = Path(directory)
        self.session_id = session_id
        digest = hashlib.sha256(session_id.encode("utf-8", errors="surrogatepass")).hexdigest()[:32]
        self.path = self.directory / f"settings-{digest}.json"
        self._lock_path = self.directory / LOCK_FILE_NAME
        self._thread_lock = threading.Lock()

    def take(self, paths: Iterable[str | Path]) -> None:
        """Note the top-level keys of each file now (at most MAX_SNAPSHOT_FILES), replacing any earlier snapshot."""
        salt = secrets.token_hex(_SALT_CHARS // 2)
        files: dict[str, dict[str, Any]] = {}
        for path in paths:
            name = settings_path_key(path)
            if name is not None and name not in files and len(files) < MAX_SNAPSHOT_FILES:
                files[name] = _entry(read_settings_keys(path, salt))
        make_private_folder(self.directory)  # owner-only, the missing folders above it too
        with self._thread_lock, locked(self._lock_path):
            self._write(salt, files)

    def compare(self, path: str | Path, keep: bool) -> KeyChanges:
        """The file at `path` now against the snapshot; with `keep`, remember it as it is now."""
        name = settings_path_key(path)
        make_private_folder(self.directory)  # owner-only, the missing folders above it too
        with self._thread_lock, locked(self._lock_path):
            salt, files = self._read()
            if salt is None:
                salt, files = secrets.token_hex(_SALT_CHARS // 2), {}
            now = read_settings_keys(path, salt)
            before = _keys_of(files.get(name)) if name is not None else None
            if keep and name is not None:
                files.pop(name, None)
                while len(files) >= MAX_SNAPSHOT_FILES:
                    del files[next(iter(files))]  # the oldest entry makes room
                files[name] = _entry(now)
                self._write(salt, files)
        return key_changes(before, now)

    # ---- the file ------------------------------------------------------------------------

    def _read(self) -> tuple[str | None, dict[str, dict[str, Any]]]:
        """(salt, files) from the snapshot file; (None, {}) when there is none, or it is not what _write writes."""
        try:
            with open(self.path, "rb") as handle:
                data = handle.read(MAX_SNAPSHOT_BYTES + 1)
        except FileNotFoundError:
            return None, {}
        if len(data) > MAX_SNAPSHOT_BYTES:
            return None, {}
        try:
            document = jsonutil.loads(data.decode("utf-8"))
        except (ValueError, RecursionError):
            return None, {}
        if not isinstance(document, dict) or set(document) != {"format", "version", "session", "salt", "files"}:
            return None, {}
        if (document["format"], document["version"], document["session"]) != (
            SETTINGS_FILE_FORMAT, SETTINGS_FILE_VERSION, self.session_id
        ):
            return None, {}
        salt, files = document["salt"], document["files"]
        if not isinstance(salt, str) or len(salt) != _SALT_CHARS or not isinstance(files, dict):
            return None, {}
        if len(files) > MAX_SNAPSHOT_FILES or not all(
            isinstance(name, str) and len(name) <= MAX_SETTINGS_PATH_CHARS and _keys_of(entry) is not None
            for name, entry in files.items()
        ):
            return None, {}
        return salt, files

    def _write(self, salt: str, files: dict[str, dict[str, Any]]) -> None:
        document = {
            "format": SETTINGS_FILE_FORMAT, "version": SETTINGS_FILE_VERSION, "session": self.session_id,
            "salt": salt, "files": files,
        }
        data = json.dumps(document, ensure_ascii=True, indent=1).encode("ascii")
        if len(data) > MAX_SNAPSHOT_BYTES:
            raise OSError("the settings snapshot would be larger than the snapshot file may be")
        replace_file(self.path, data)


def settings_path_key(path: str | Path) -> str | None:
    """How a settings file is named in a snapshot: its full path, spelled as the system compares paths.

    None for a path that is not text, not a full path, or too long.
    """
    text = str(path) if isinstance(path, (str, Path)) else None
    if not text or len(text) > MAX_SETTINGS_PATH_CHARS or "\0" in text or not os.path.isabs(text):
        return None
    return os.path.normcase(os.path.normpath(text))


def read_settings_keys(path: str | Path, salt: str) -> SettingsKeys:
    """The top-level keys of the JSON settings file at `path`, each with a hash of its value. Never raises.

    Only a regular file of at most MAX_SETTINGS_BYTES is read, in strict JSON
    (jsonutil); it must be an object of at most MAX_SETTINGS_KEYS keys, each at
    most MAX_SETTINGS_KEY_CHARS long. Anything else gives a SettingsKeys with
    no hashes and a problem.
    """
    if settings_path_key(path) is None:
        return SettingsKeys(None, "is not named by a full path")
    try:
        data = _read_regular_file(Path(path), MAX_SETTINGS_BYTES)
    except FileNotFoundError:
        return SettingsKeys({}, missing=True)
    except OSError as exc:
        return SettingsKeys(None, _shortened(f"cannot be read ({type(exc).__name__}: {exc.strerror or exc})"))
    if data is None:
        return SettingsKeys(None, f"is not a regular file of at most {MAX_SETTINGS_BYTES} bytes")
    try:
        document = jsonutil.loads(data.decode("utf-8-sig"))
    except (ValueError, RecursionError):  # includes UnicodeDecodeError and a repeated key
        return SettingsKeys(None, "is not valid JSON")
    if not isinstance(document, dict):
        return SettingsKeys(None, "is not a JSON object")
    if len(document) > MAX_SETTINGS_KEYS:
        return SettingsKeys(None, f"has more than {MAX_SETTINGS_KEYS} top-level keys")
    if any(len(key) > MAX_SETTINGS_KEY_CHARS for key in document):
        return SettingsKeys(None, f"has a top-level key longer than {MAX_SETTINGS_KEY_CHARS} characters")
    try:
        return SettingsKeys({key: _value_hash(salt, value) for key, value in document.items()})
    except (ValueError, RecursionError):
        return SettingsKeys(None, "has a value that cannot be compared")


def _read_regular_file(path: Path, limit: int) -> bytes | None:
    """The bytes of a regular file of at most `limit` bytes; None for anything else (a folder, a pipe, a larger file).

    Opened without waiting (O_NONBLOCK where there is one), so that a named
    pipe put in place of a settings file cannot hold the hook.
    """
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    handle = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(handle).st_mode):
            return None
        with os.fdopen(handle, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
    finally:
        os.close(handle)
    return data if len(data) <= limit else None


def _value_hash(salt: str, value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(f"{salt}\0{canonical}".encode("ascii")).hexdigest()[:_HASH_CHARS]


def _entry(keys: SettingsKeys) -> dict[str, Any]:
    """A file's entry in the snapshot file."""
    if keys.missing:
        return {"missing": True}
    if keys.hashes is None:
        return {"problem": keys.problem}
    return {"keys": dict(keys.hashes)}


def _keys_of(entry: Any) -> SettingsKeys | None:
    """The SettingsKeys an entry of the snapshot file holds; None for an entry that is not one _entry writes."""
    if not isinstance(entry, dict) or len(entry) != 1:
        return None
    if entry.get("missing") is True:
        return SettingsKeys({}, missing=True)
    problem = entry.get("problem")
    if isinstance(problem, str) and len(problem) <= MAX_PROBLEM_CHARS:
        return SettingsKeys(None, problem)
    keys = entry.get("keys")
    if not isinstance(keys, dict) or len(keys) > MAX_SETTINGS_KEYS:
        return None
    for key, digest in keys.items():
        if len(key) > MAX_SETTINGS_KEY_CHARS or not isinstance(digest, str) or len(digest) != _HASH_CHARS:
            return None
    return SettingsKeys(keys)


def _shortened(text: str) -> str:
    return text if len(text) <= MAX_PROBLEM_CHARS else text[:MAX_PROBLEM_CHARS - 3] + "..."


# ---- the policy a session began with ---------------------------------------------------------

POLICY_FILE_FORMAT = "agent-sentinel-session-policy"
POLICY_FILE_VERSION = 1
MAX_POLICY_RECORD_BYTES = 4096
_SHA256_CHARS = 64
# The record's own time is brought up to date this often, so that a long session's record is not taken
# for an old session's (prune_state_files).
_RECORD_REFRESH_SECONDS = 24 * 60 * 60


class PolicyRecordError(Exception):
    """The record of the policy a session began with cannot be read or written, so the event cannot be judged."""


@dataclass(frozen=True)
class SeenPolicy:
    """The policy a session began with: the SHA-256 of its file, and its hook.policy_changes then."""

    sha256: str
    policy_changes: str


class PolicyRecord:
    """Which policy file a session began with, in a file in the state folder.

        <state folder>/policy-<hash of the session id>.json

    The hook reads the policy file anew for every event. Without this record,
    an agent that managed to rewrite the policy would be judged by its own
    policy from the next event on. remember() writes the record when a new
    session starts; seen() returns it, writing it first for a session that
    has none (state written by an older version, or lost). The caller
    compares the SHA-256 with the file it has just loaded.

    Failing closed: a record that cannot be read, locked or written, or that
    is not exactly what this class writes, raises PolicyRecordError, and the
    hook refuses the event. A missing record is a session not seen before,
    so deleting it makes the session take the policy as it is now: the state
    folder needs the same care as the policy file itself.
    """

    def __init__(self, directory: str | Path, session_id: str, clock: Callable[[], float] = time.time) -> None:
        if not isinstance(session_id, str) or not 0 < len(session_id) <= MAX_SESSION_ID_CHARS:
            raise ValueError(f"the session id must be text of 1 to {MAX_SESSION_ID_CHARS} characters")
        self.directory = Path(directory)
        self.session_id = session_id
        digest = hashlib.sha256(session_id.encode("utf-8", errors="surrogatepass")).hexdigest()[:32]
        self.path = self.directory / f"policy-{digest}.json"
        self._lock_path = self.directory / LOCK_FILE_NAME
        self._clock = clock
        self._thread_lock = threading.Lock()

    def remember(self, sha256: str, policy_changes: str) -> SeenPolicy:
        """A new session: record this policy, replacing what an earlier session of the same id left."""
        seen = _seen_policy(sha256, policy_changes)
        try:
            make_private_folder(self.directory)
            with self._thread_lock, locked(self._lock_path):
                self._write(seen)
        except OSError as exc:
            raise PolicyRecordError(f"cannot use the policy record {self.path}: {exc}") from exc
        return seen

    def seen(self, sha256: str, policy_changes: str) -> SeenPolicy:
        """The policy the session began with; for a session with no record, this one, which is recorded."""
        current = _seen_policy(sha256, policy_changes)
        try:
            make_private_folder(self.directory)
            with self._thread_lock, locked(self._lock_path):
                recorded = self._read()
                if recorded is None:
                    self._write(current)
                    return current
                self._refresh()
                return recorded
        except OSError as exc:
            raise PolicyRecordError(f"cannot use the policy record {self.path}: {exc}") from exc

    # ---- the file ------------------------------------------------------------------------

    def _read(self) -> SeenPolicy | None:
        """The record in the file; None when there is no file. PolicyRecordError when it is not valid."""
        try:
            with open(self.path, "rb") as handle:
                data = handle.read(MAX_POLICY_RECORD_BYTES + 1)
        except FileNotFoundError:
            return None
        problem = "too large" if len(data) > MAX_POLICY_RECORD_BYTES else None
        document: Any = None
        if problem is None:
            try:
                document = jsonutil.loads(data.decode("utf-8"))
            except (ValueError, RecursionError):  # includes UnicodeDecodeError and a repeated key
                problem = "not JSON"
        if problem is None and (not isinstance(document, dict) or set(document) != {
                "format", "version", "session", "sha256", "policy_changes"}):
            problem = "unexpected contents"
        if problem is None and (document["format"], document["version"]) != (POLICY_FILE_FORMAT, POLICY_FILE_VERSION):
            problem = "unknown format or version"
        if problem is None and document["session"] != self.session_id:
            problem = "it belongs to another session"
        if problem is None:
            try:
                return _seen_policy(document["sha256"], document["policy_changes"])
            except ValueError:
                problem = "unexpected contents"
        raise PolicyRecordError(
            f"the policy record {self.path} is not valid ({problem}); delete it and start a new Claude Code session"
        )

    def _write(self, seen: SeenPolicy) -> None:
        document = {
            "format": POLICY_FILE_FORMAT, "version": POLICY_FILE_VERSION, "session": self.session_id,
            "sha256": seen.sha256, "policy_changes": seen.policy_changes,
        }
        replace_file(self.path, json.dumps(document, ensure_ascii=True).encode("ascii"))

    def _refresh(self) -> None:
        """Bring the record's time up to date once a day (best effort): the session is still in use."""
        try:
            now = self._clock()
            if now - os.stat(self.path).st_mtime > _RECORD_REFRESH_SECONDS:
                os.utime(self.path, (now, now))
        except OSError:
            pass


def _seen_policy(sha256: Any, policy_changes: Any) -> SeenPolicy:
    """A SeenPolicy from values that may come from a file; ValueError for anything but a SHA-256 and a setting."""
    if not (isinstance(sha256, str) and len(sha256) == _SHA256_CHARS and all(ch in "0123456789abcdef" for ch in sha256)):
        raise ValueError("the policy's SHA-256 must be 64 lowercase hexadecimal characters")
    if policy_changes not in POLICY_CHANGES:
        raise ValueError(f"policy_changes must be one of {', '.join(POLICY_CHANGES)}")
    return SeenPolicy(sha256, policy_changes)


# ---- old state files --------------------------------------------------------------------------

# The files this module and session.FileSessionStore write for one session: a kind, and the hash of its id.
_STATE_FILE = re.compile(r"(session|rate|settings|policy)-([0-9a-f]{32})\.json")
# A session whose files were all left alone for this long is over: its files are removed.
MAX_STATE_AGE_SECONDS = 30 * 24 * 60 * 60
# Bounds on one run of prune_state_files: names looked at, and files removed.
MAX_PRUNE_ENTRIES = 20_000
MAX_PRUNED_FILES = 400


def prune_state_files(directory: str | Path, now: float | None = None,
                      max_age: float = MAX_STATE_AGE_SECONDS) -> int:
    """Remove the state files of sessions that have not been used for `max_age` seconds; return how many.

    Only regular files in `directory` itself whose names are exactly what the
    hook writes for a session (session-, rate-, settings- and policy-<hash>.json)
    are looked at; nothing else is touched, and no folder is entered. A
    session's files go together, and only when every one of them is old: a
    session still in use keeps its policy record fresh (PolicyRecord). At most
    MAX_PRUNE_ENTRIES names are looked at and MAX_PRUNED_FILES files removed in
    one run; the rest waits for the next. Best effort: a file that cannot be
    looked at or removed is left, and OSError is raised only when the folder
    cannot be locked.
    """
    folder = Path(directory)
    if not folder.is_dir():
        return 0
    limit = (time.time() if now is None else now) - max_age
    removed = 0
    with locked(folder / LOCK_FILE_NAME):
        sessions: dict[str, list[tuple[str, float]]] = {}
        try:
            with os.scandir(folder) as entries:
                for count, entry in enumerate(entries):
                    if count >= MAX_PRUNE_ENTRIES:
                        break
                    found = _STATE_FILE.fullmatch(entry.name)
                    if found is None:
                        continue
                    try:
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        modified = entry.stat(follow_symlinks=False).st_mtime
                    except OSError:
                        continue
                    sessions.setdefault(found.group(2), []).append((entry.name, modified))
        except OSError:
            return 0
        for files in sessions.values():
            if any(modified >= limit for _, modified in files):
                continue
            for name, _ in files:
                if removed >= MAX_PRUNED_FILES:
                    return removed
                try:
                    os.remove(folder / name)
                    removed += 1
                except OSError:
                    pass
    return removed

