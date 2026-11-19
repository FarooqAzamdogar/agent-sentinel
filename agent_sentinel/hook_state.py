"""Rate-limit counts kept in a file, for hook mode, where every tool call is checked by a new process.

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
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .filelock import locked
from .firewall import RATE_WINDOW_SECONDS
from .session import LOCK_FILE_NAME, MAX_SESSION_ID_CHARS

RATE_FILE_FORMAT = "agent-sentinel-rate"
RATE_FILE_VERSION = 1
# A policy has a handful of rate limits; these bounds are for a file someone tampered with.
MAX_RATE_FILE_BYTES = 256 * 1024
MAX_BUCKETS = 1_000
MAX_BUCKET_NAME_CHARS = 1_000
MAX_COUNT = 1_000_000_000

# os.replace can fail on Windows for a moment while another program has the file open.
_REPLACE_ATTEMPTS = 5
_REPLACE_PAUSE_SECONDS = 0.05


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
            self.directory.mkdir(parents=True, exist_ok=True)
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
            document = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_keys)
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
        temporary = self.path.with_name(self.path.name + ".tmp")
        temporary.write_bytes(data)
        for attempt in range(_REPLACE_ATTEMPTS):
            try:
                os.replace(temporary, self.path)
                return
            except PermissionError:
                if attempt == _REPLACE_ATTEMPTS - 1:
                    raise
                time.sleep(_REPLACE_PAUSE_SECONDS)


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


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """A JSON object in which no key repeats (a repeated key would hide one of two values)."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("repeated key")
        result[key] = value
    return result
