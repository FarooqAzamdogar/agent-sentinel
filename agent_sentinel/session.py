"""Session state for flow rules: what kinds of content the agent has read so far.

Most of the policy judges each call on its own. A flow rule (the "flows"
section, see policy.py) also looks back: "once the agent has read untrusted
content, it may not call a tool that sends data out". That is the usual shape
of a real attack: read an attacker's issue or web page, read private data,
send it somewhere. Each call in that chain looks harmless alone.

Labels
------
A label describes a tool. The policy gives labels in a tool rule
("labels": [...]), and MCP tool annotations can add some
(`labels_from_annotations`). Three labels have a fixed meaning:

    untrusted   its results may carry text chosen by someone else (web pages, issues, e-mail)
    private     its results hold data that must not leave (files, databases, an inbox)
    sink        it can send data out or act on the world (e-mail, HTTP requests, posting)

Any other label made of lowercase letters, digits, "_" and "-" works the same way.

Marks
-----
When a result of a tool reaches the agent, the session gains one mark for
each of the tool's labels except "sink", which says what the tool does, not
what it returns. A mark is never removed, and the first cause that set it is
kept so the audit log can say where the content came from: the tool (or
resource), the server, and the channel ("result", "notification", ... and,
for a mark that came from the content itself or from the server's labels,
"(injection.mark_at)" or "(server_labels)"). Marks are set only for results
that are actually delivered: a refused call or a withheld result teaches the
agent nothing.

Other session state
-------------------
A session also keeps (`SessionState`): the end of the text last delivered on
each channel (the "tail", at most TAIL_CHARS characters, which the next
result is read together with, see tail_scan.py), the counts of the policy's
session limits, and the asks a person refused (approval memory). Values and
calls are kept as hashes, never as text. Everything has a fixed bound.

Stores
------
`MemorySessionStore` keeps the marks in memory: one process is one session
(the library, one proxy). `FileSessionStore` keeps them in a JSON file per
session id, for hook mode, where every check runs in a new process.

The file store fails closed. A session file that is missing, unreadable,
malformed, written for another session, or that has lost marks this process
saw counts as "every mark set", so every flow rule applies, and its other
state cannot be read: the session limits refuse the calls they count.
Anyone who can write the folder can still rewrite the file consistently:
keep it outside every folder the agent's tools can reach.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterable, Iterator, Mapping, TypeVar

from . import jsonutil
from .filelock import locked, replace_file

UNTRUSTED = "untrusted"
PRIVATE = "private"
SINK = "sink"  # describes a tool, never content: it is never a mark
BUILTIN_LABELS = (UNTRUSTED, PRIVATE, SINK)

MAX_LABEL_CHARS = 40
# A label is a short lowercase word: it is written in policies and in audit reasons.
_LABEL = re.compile(r"[a-z][a-z0-9_-]{0,39}")

# Bounds on what a session holds. Marks come from the policy's labels, so a
# real session has a handful; the bounds are for a file someone tampered with.
MAX_MARKS = 256
MAX_CAUSE_TOOL_CHARS = 200
MAX_CAUSE_TEXT_CHARS = 100  # the server and the channel of a mark's cause
MAX_SESSION_ID_CHARS = 256
MAX_STATE_FILE_BYTES = 1024 * 1024

# The tail: how much of the end of the text last delivered is kept, per channel.
TAIL_CHARS = 512
TAIL_CHANNELS = ("result", "notification")
# Bounds on the rest of the session state (SessionState). Past the first three the
# session limits refuse the call (they cannot count it); the last two forget the oldest.
MAX_COUNTERS = 1_000  # counters and sets of values of the session limits
MAX_DISTINCT_VALUES = 4_096  # values kept for max_distinct, over all its sets
MAX_COUNT = 10**15  # the largest count (calls or bytes)
MAX_IDENTICAL_KEYS = 2_000  # different calls counted for max_identical_calls
MAX_REFUSALS = 1_000  # refused asks remembered
_HASH = re.compile(r"[0-9a-f]{32}")

FILE_FORMAT = "agent-sentinel-session"
FILE_VERSION = 2
# Version 1 (0.5) has marks only. It is still read; it is written as version 2 the next time.
READABLE_FILE_VERSIONS = (1, 2)
LOCK_FILE_NAME = "sessions.lock"

_MISSING = "the session file is missing (the session was never begun, or it was deleted)"

_T = TypeVar("_T")


class SessionStateError(Exception):
    """The marks of a session could not be recorded.

    Raised by `SessionStore.add` (and so by `Firewall.mark_delivered`). The
    result whose marks were being recorded must then be withheld from the
    agent: if it were delivered, the session would hold content it does not
    know about, and a flow rule would let a call through that it should refuse.
    """


def is_label(value: Any) -> bool:
    """True if `value` is a valid label: a lowercase letter, then letters, digits, "_" or "-"; at most 40 characters."""
    return isinstance(value, str) and _LABEL.fullmatch(value) is not None


def labels_from_annotations(annotations: Any) -> frozenset[str]:
    """The labels an MCP tool's `annotations` imply. Only an explicit `true` counts.

        openWorldHint: true    -> untrusted and sink: it reads from and talks to the outside world
        destructiveHint: true  -> sink, unless readOnlyHint is also true (the MCP spec says
                                  destructiveHint means nothing for a read-only tool)

    Annotations come from the server, which is not trusted, so they may only
    add labels, never remove one the policy gives. A server that leaves them
    out (the spec's defaults are not applied) gets no labels from them: label
    the tools that matter in the policy.
    """
    if not isinstance(annotations, dict):
        return frozenset()
    labels: set[str] = set()
    if annotations.get("openWorldHint") is True:
        labels.update((UNTRUSTED, SINK))
    if annotations.get("destructiveHint") is True and annotations.get("readOnlyHint") is not True:
        labels.add(SINK)
    return frozenset(labels)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _bounded_tool(tool: Any) -> str:
    text = tool if isinstance(tool, str) else str(tool)
    return text if len(text) <= MAX_CAUSE_TOOL_CHARS else text[:MAX_CAUSE_TOOL_CHARS] + "..."


def _bounded_text(text: Any) -> str:
    """The server or channel of a mark's cause, kept short."""
    text = text if isinstance(text, str) else str(text)
    return text if len(text) <= MAX_CAUSE_TEXT_CHARS else text[:MAX_CAUSE_TEXT_CHARS] + "..."


def _checked_labels(labels: Iterable[str]) -> list[str]:
    """The labels to add as marks, in order, without "sink". A label that is not valid is a programming error."""
    if isinstance(labels, str):
        raise TypeError("labels must be a collection of labels, not one text")
    found = []
    for label in labels:
        if not is_label(label):
            raise ValueError(f"not a valid label: {label!r}")
        if label != SINK and label not in found:
            found.append(label)
    return found


# ---- what a session holds -----------------------------------------------------

@dataclass(frozen=True)
class Mark:
    """One mark of a session: the label, and the first delivered content that set it.

    server and channel say more about that cause, for the audit reason of a
    flow block: the server it came from (proxy --name; "" when not known)
    and how it arrived ("result", "notification", ...; for a mark that the
    content itself or the server's labels set, "(injection.mark_at)" or
    "(server_labels)" follows).
    """

    label: str
    tool: str  # the tool (or, in the proxy, the resource URI) whose result set it; may be agent- or server-chosen text
    time: str  # when, as UTC ISO 8601 to the second; "" if not known
    server: str = ""
    channel: str = ""


def _checked_marks(marks: Iterable[Mark]) -> list[Mark]:
    """Marks to record, with bounded causes, without "sink" and without a second mark of one label."""
    found: dict[str, Mark] = {}
    for mark in marks:
        if not isinstance(mark, Mark) or not is_label(mark.label):
            raise ValueError(f"not a valid mark: {mark!r}")
        if mark.label != SINK and mark.label not in found:
            found[mark.label] = Mark(
                mark.label, _bounded_tool(mark.tool), _bounded_text(mark.time)[:40], _bounded_text(mark.server),
                _bounded_text(mark.channel),
            )
    return list(found.values())


@dataclass(frozen=True)
class SessionMarks:
    """The marks of one session at one moment. Read-only.

    `everything` is True when the session state could not be trusted (see
    the module docstring); then every label counts as marked, and `why`
    says what went wrong, for the audit log.
    """

    marks: Mapping[str, Mark] = field(default_factory=dict)
    everything: bool = False
    why: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "marks", MappingProxyType(dict(self.marks)))

    @classmethod
    def of(cls, labels: Iterable[str]) -> "SessionMarks":
        """Marks with no known cause, e.g. to ask the policy "what if the session had read untrusted content?"."""
        return cls({label: Mark(label, "", "") for label in _checked_labels(labels)})

    @classmethod
    def untrusted(cls, why: str) -> "SessionMarks":
        """The fail-closed answer: every mark counts as set."""
        return cls({}, everything=True, why=why)

    @property
    def labels(self) -> frozenset[str]:
        """The labels that are marked (empty when `everything` is set: then every label counts)."""
        return frozenset(self.marks)

    def has(self, label: str) -> bool:
        return self.everything or label in self.marks

    def has_all(self, labels: Iterable[str]) -> bool:
        return all(self.has(label) for label in labels)


@dataclass
class SessionState:
    """What a session keeps besides its marks. Plain data; a store hands out copies.

    tails:     channel ("result" or "notification") -> at most TAIL_CHARS characters: the
               end of the text the model read on it, runs of blanks as one (see tail_scan.py).
    counts:    counter of a session limit (a hash of its name) -> calls or bytes counted.
    distinct:  set of a max_distinct limit (a hash of its name) -> hashes of the values seen.
    identical: hash of a call (tool and arguments) -> how many times it was made;
               the least recently made first.
    refusals:  [hash of the tool, hash of the call, when (seconds since 1970)] of each
               ask a person refused, oldest first.
    """

    tails: dict[str, str] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    distinct: dict[str, list[str]] = field(default_factory=dict)
    identical: dict[str, int] = field(default_factory=dict)
    refusals: list[list[Any]] = field(default_factory=list)

    def copy(self) -> "SessionState":
        return SessionState(
            dict(self.tails), dict(self.counts), {key: list(values) for key, values in self.distinct.items()},
            dict(self.identical), [list(entry) for entry in self.refusals],
        )

    def as_json(self) -> dict[str, Any]:
        """The state as the session file holds it."""
        return {
            "tails": dict(self.tails), "counts": dict(self.counts), "distinct": dict(self.distinct),
            "identical": dict(self.identical), "refusals": [list(entry) for entry in self.refusals],
        }

    @classmethod
    def from_json(cls, document: Mapping[str, Any]) -> tuple[str | None, "SessionState"]:
        """Read the state from the session file's members. Returns (what is wrong, or None; the state)."""
        state = cls(document["tails"], document["counts"], document["distinct"], document["identical"],
                    document["refusals"])
        problem = state.problem()
        return problem, (cls() if problem else state.copy())

    def problem(self) -> str | None:
        """What makes this state impossible (a tampered file, or a bug), or None. Every bound is checked."""
        tails, counts, distinct, identical, refusals = (
            self.tails, self.counts, self.distinct, self.identical, self.refusals
        )
        if not isinstance(tails, dict) or any(
            channel not in TAIL_CHANNELS or not isinstance(text, str) or len(text) > TAIL_CHARS
            for channel, text in tails.items()
        ):
            return "a tail is malformed"
        if not _counter_map(counts, MAX_COUNTERS, lowest=0):
            return "a count is malformed"
        if not isinstance(distinct, dict) or len(distinct) > MAX_COUNTERS:
            return "a set of values is malformed"
        total = 0
        for key, values in distinct.items():
            if not _is_hash(key) or not isinstance(values, list) or not all(_is_hash(value) for value in values):
                return "a set of values is malformed"
            if len(set(values)) != len(values):
                return "a set of values repeats a value"
            total += len(values)
        if total > MAX_DISTINCT_VALUES:
            return "too many values are kept"
        if not _counter_map(identical, MAX_IDENTICAL_KEYS, lowest=1):
            return "a count of identical calls is malformed"
        if not isinstance(refusals, list) or len(refusals) > MAX_REFUSALS or not all(
            _valid_refusal(entry) for entry in refusals
        ):
            return "a refused ask is malformed"
        return None


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def _whole(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _counter_map(value: Any, most: int, lowest: int) -> bool:
    return isinstance(value, dict) and len(value) <= most and all(
        _is_hash(key) and _whole(count) and lowest <= count <= MAX_COUNT for key, count in value.items()
    )


def _valid_refusal(entry: Any) -> bool:
    if not isinstance(entry, list) or len(entry) != 3:
        return False
    tool, call, when = entry
    is_number = isinstance(when, (int, float)) and not isinstance(when, bool)
    return _is_hash(tool) and _is_hash(call) and is_number and math.isfinite(when) and when >= 0


# ---- stores -----------------------------------------------------------------------

class SessionStore:
    """Where the marks of one session are kept, with the rest of its state.

    Every operation is safe to call from several threads:

        read()                    -> SessionMarks   never raises; fails closed (everything marked)
        add(labels, tool)         -> SessionMarks   records marks; raises SessionStateError if it cannot
        add_marks(marks, tail)    -> SessionMarks   records marks with their causes, and a tail
        read_state()              -> SessionState   a copy; SessionStateError when it cannot be trusted
        update_state(change)      -> what change() returns: change(state) edits a copy, which is
                                     then kept, all under the store's lock; SessionStateError as above

    `add` ignores "sink" and labels already marked, and keeps the first cause.
    A store written before 0.6 implements read() and add() only: add_marks
    then goes through add() (the server, the channel and the tail are not
    kept), and the session state cannot be read, so the session limits
    refuse the calls they count.
    """

    def read(self) -> SessionMarks:
        raise NotImplementedError

    def add(self, labels: Iterable[str], tool: str) -> SessionMarks:
        raise NotImplementedError

    def add_marks(self, marks: Iterable[Mark], tail: tuple[str, str] | None = None) -> SessionMarks:
        """Record marks, each with its own cause, and (channel, text) as that channel's tail."""
        by_cause: dict[str, list[str]] = {}
        for mark in _checked_marks(marks):
            by_cause.setdefault(mark.tool, []).append(mark.label)
        current = None
        for tool, labels in by_cause.items():
            current = self.add(labels, tool)
        return current if current is not None else self.read()

    def read_state(self) -> SessionState:
        raise SessionStateError("this session store keeps no session state")

    def update_state(self, change: Callable[[SessionState], _T]) -> _T:
        raise SessionStateError("this session store keeps no session state")


def _checked_tail(tail: tuple[str, str] | None) -> tuple[str, str] | None:
    if tail is None:
        return None
    channel, text = tail
    if channel not in TAIL_CHANNELS or not isinstance(text, str):
        raise ValueError(f"not a tail: {tail!r}")
    return channel, text[-TAIL_CHARS:]


def _changed_state(state: SessionState, change: Callable[[SessionState], _T]) -> tuple[_T, SessionState]:
    """Run `change` on a copy of the state; (its answer, the copy). SessionStateError if the copy breaks a bound."""
    working = state.copy()
    answer = change(working)
    problem = working.problem()
    if problem is not None:
        raise SessionStateError(f"the session state cannot be kept: {problem}")
    return answer, working


class MemorySessionStore(SessionStore):
    """Marks kept in memory: the session lasts as long as the process (the default for a Firewall)."""

    def __init__(self) -> None:
        self._marks: dict[str, Mark] = {}
        self._overflowed = False
        self._state = SessionState()
        self._lock = threading.Lock()

    def read(self) -> SessionMarks:
        with self._lock:
            return self._snapshot()

    def add(self, labels: Iterable[str], tool: str, *, server: str = "", channel: str = "") -> SessionMarks:
        marks = [Mark(label, tool, _now(), server, channel) for label in _checked_labels(labels)]
        return self._record(_checked_marks(marks), None)

    def add_marks(self, marks: Iterable[Mark], tail: tuple[str, str] | None = None) -> SessionMarks:
        wanted, kept = _checked_marks(marks), _checked_tail(tail)
        if _add_replaced(self, MemorySessionStore):
            # A subclass (or a test double) that records marks its own way keeps doing so; the tail is kept here.
            current = super().add_marks(wanted)
            return self._record([], kept) if kept is not None else current
        return self._record(wanted, kept)

    def read_state(self) -> SessionState:
        with self._lock:
            return self._state.copy()

    def update_state(self, change: Callable[[SessionState], _T]) -> _T:
        with self._lock:
            answer, self._state = _changed_state(self._state, change)
            return answer

    def _record(self, marks: list[Mark], tail: tuple[str, str] | None) -> SessionMarks:
        with self._lock:
            for mark in marks:
                if mark.label in self._marks:
                    continue
                if len(self._marks) >= MAX_MARKS:
                    self._overflowed = True  # cannot remember another one: from now on, everything counts
                    break
                self._marks[mark.label] = mark
            if tail is not None:
                self._state.tails[tail[0]] = tail[1]
            return self._snapshot()

    def _snapshot(self) -> SessionMarks:
        if self._overflowed:
            return SessionMarks(self._marks, everything=True, why="more marks than can be tracked")
        return SessionMarks(self._marks)


class FileSessionStore(SessionStore):
    """Marks and session state kept in a JSON file, one per session id, for checks that each run in a new process.

    The file is `<directory>/session-<hash of the id>.json`; every process
    takes the lock file `<directory>/sessions.lock` before it reads or writes.
    Files of version 1 (marks only, written by 0.5) are read as a session with
    no other state, and written as version 2 the next time.

    Call `begin()` once, when the session really starts (for Claude Code: the
    SessionStart hook with source "startup" or "clear"; not "resume" or
    "compact", or a file the agent deleted would quietly come back empty).
    After that, and without it, a missing file counts as every mark set.

    Fail closed, in detail. `read()` reports every mark set when the file is
    missing, cannot be read or locked, is larger than MAX_STATE_FILE_BYTES,
    is not the expected JSON (any unexpected key, type or bound), belongs to
    another session id, or has lost a mark this object saw earlier. Then
    `read_state()` and `update_state()` raise SessionStateError. `add()`
    never repairs such a file: the session stays fully marked until a new one
    begins. A process that cannot write a mark gets SessionStateError.

    Not covered: someone who can write the folder can replace the file with
    a consistent one that has fewer marks, between two processes. Keep the
    folder outside the agent's reach.
    """

    def __init__(self, directory: str | Path, session_id: str) -> None:
        if not isinstance(session_id, str) or not 0 < len(session_id) <= MAX_SESSION_ID_CHARS:
            raise ValueError(f"the session id must be text of 1 to {MAX_SESSION_ID_CHARS} characters")
        self.directory = Path(directory)
        self.session_id = session_id
        # The id comes from the client: hashed, it cannot reach outside the folder or collide with a name.
        digest = hashlib.sha256(session_id.encode("utf-8", errors="surrogatepass")).hexdigest()[:32]
        self.path = self.directory / f"session-{digest}.json"
        self._lock_path = self.directory / LOCK_FILE_NAME
        self._thread_lock = threading.Lock()
        self._seen: dict[str, Mark] = {}  # every mark this object has read or written: for spotting lost ones
        self._started = ""

    # ---- the operations ---------------------------------------------------------

    def begin(self) -> SessionMarks:
        """Start the session: create the folder and an empty session file, unless the file exists.

        Idempotent. An existing file is kept as it is, valid or not, and read.
        Raises SessionStateError if the folder or the file cannot be written.
        """
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            with self._exclusive():
                if not self.path.exists():
                    self._started = _now()
                    self._write({}, SessionState())
                return self._load_unlocked()[0]
        except OSError as exc:
            raise SessionStateError(f"cannot start the session file {self.path}: {exc}") from exc

    def read(self) -> SessionMarks:
        try:
            with self._exclusive():
                return self._load_unlocked()[0]
        except FileNotFoundError:  # the folder itself is gone, so the lock file cannot be opened
            return SessionMarks.untrusted(_MISSING)
        except OSError as exc:
            return SessionMarks.untrusted(f"the session file cannot be read ({type(exc).__name__}: {exc})")

    def add(self, labels: Iterable[str], tool: str, *, server: str = "", channel: str = "") -> SessionMarks:
        marks = [Mark(label, tool, _now(), server, channel) for label in _checked_labels(labels)]
        return self._record(_checked_marks(marks), None)

    def add_marks(self, marks: Iterable[Mark], tail: tuple[str, str] | None = None) -> SessionMarks:
        wanted, kept = _checked_marks(marks), _checked_tail(tail)
        if _add_replaced(self, FileSessionStore):
            current = super().add_marks(wanted)
            return self._record([], kept) if kept is not None else current
        return self._record(wanted, kept)

    def read_state(self) -> SessionState:
        try:
            with self._exclusive():
                return self._trusted_unlocked()[1].copy()
        except OSError as exc:
            raise SessionStateError(f"the session file cannot be read: {exc}") from exc

    def update_state(self, change: Callable[[SessionState], _T]) -> _T:
        try:
            with self._exclusive():
                marks, state = self._trusted_unlocked()
                answer, changed = _changed_state(state, change)
                if changed != state:
                    self._write(dict(marks.marks), changed)
                return answer
        except OSError as exc:
            raise SessionStateError(f"cannot record the session state in {self.path}: {exc}") from exc

    # ---- internals --------------------------------------------------------------

    def _record(self, wanted: list[Mark], tail: tuple[str, str] | None) -> SessionMarks:
        try:
            with self._exclusive():
                current, state = self._load_unlocked()
                if current.everything or state is None:
                    return current  # a broken file is never repaired
                new = [mark for mark in wanted if mark.label not in current.marks]
                keeps_tail = tail is None or state.tails.get(tail[0]) == tail[1]
                if not new and keeps_tail:
                    return current  # nothing to add
                marks = dict(current.marks)
                for mark in new:
                    if len(marks) >= MAX_MARKS:
                        raise SessionStateError("more marks than can be tracked")
                    marks[mark.label] = mark
                if tail is not None:
                    state.tails[tail[0]] = tail[1]
                self._write(marks, state)
                self._seen.update(marks)
                return SessionMarks(marks)
        except FileNotFoundError:
            # The folder is gone: like a missing file, every mark counts as set, so nothing needs recording.
            return SessionMarks.untrusted(_MISSING)
        except OSError as exc:
            raise SessionStateError(f"cannot record marks in {self.path}: {exc}") from exc

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        """One thread of this process, and one process, at a time."""
        with self._thread_lock, locked(self._lock_path):
            yield

    def _trusted_unlocked(self) -> tuple[SessionMarks, SessionState]:
        """The marks and the state, or SessionStateError when the file cannot be trusted."""
        marks, state = self._load_unlocked()
        if marks.everything or state is None:
            raise SessionStateError(f"the session state cannot be used: {marks.why}")
        return marks, state

    def _load_unlocked(self) -> tuple[SessionMarks, SessionState | None]:
        """The file's marks, and its state (None when the file cannot be trusted: the marks say why)."""
        try:
            with open(self.path, "rb") as handle:
                data = handle.read(MAX_STATE_FILE_BYTES + 1)
        except FileNotFoundError:
            if self._seen or self._started:
                return SessionMarks.untrusted("the session file disappeared"), None
            return SessionMarks.untrusted(_MISSING), None
        if len(data) > MAX_STATE_FILE_BYTES:
            return SessionMarks.untrusted("the session file is too large"), None
        problem, marks, state = self._parse(data)
        if problem is not None:
            return SessionMarks.untrusted(f"the session file is not valid: {problem}"), None
        lost = [label for label in self._seen if label not in marks]
        if lost:
            return SessionMarks.untrusted("marks disappeared from the session file"), None
        self._seen.update(marks)
        return SessionMarks(marks), state

    def _parse(self, data: bytes) -> tuple[str | None, dict[str, Mark], SessionState]:
        """Read the file's bytes. Returns (what is wrong, or None; the marks; the rest of the state)."""
        empty = SessionState()
        try:
            document = jsonutil.loads(data.decode("utf-8"))
        except (ValueError, RecursionError):  # includes UnicodeDecodeError and a repeated key
            return "not JSON", {}, empty
        if not isinstance(document, dict) or document.get("version") not in READABLE_FILE_VERSIONS:
            return "unknown format or version", {}, empty
        version = document["version"]
        if set(document) != _FILE_KEYS[version]:
            return "unexpected contents", {}, empty
        if document["format"] != FILE_FORMAT or type(version) is not int:
            return "unknown format or version", {}, empty
        if document["session"] != self.session_id:
            return "it belongs to another session", {}, empty
        started, entries = document["started"], document["marks"]
        if not isinstance(started, str) or len(started) > 40 or not isinstance(entries, dict):
            return "unexpected contents", {}, empty
        if len(entries) > MAX_MARKS:
            return "too many marks", {}, empty
        marks = {}
        for label, cause in entries.items():
            if not is_label(label) or label == SINK or not _valid_cause(cause, version):
                return "a mark is malformed", {}, empty
            marks[label] = Mark(label, cause["tool"], cause["time"], cause.get("server", ""), cause.get("channel", ""))
        state = empty
        if version >= 2:
            problem, state = SessionState.from_json(document)
            if problem is not None:
                return problem, {}, empty
        self._started = started
        return None, marks, state

    def _write(self, marks: dict[str, Mark], state: SessionState) -> None:
        """Replace the session file with these marks and this state. Atomic: a crash leaves the old or the new."""
        document = {
            "format": FILE_FORMAT,
            "version": FILE_VERSION,
            "session": self.session_id,
            "started": self._started or _now(),
            "marks": {
                label: {"tool": mark.tool, "time": mark.time, "server": mark.server, "channel": mark.channel}
                for label, mark in marks.items()
            },
            **state.as_json(),
        }
        # ensure_ascii: a tool name with a lone surrogate must not stop the file from being written.
        data = json.dumps(document, ensure_ascii=True, indent=1).encode("ascii")
        if len(data) > MAX_STATE_FILE_BYTES:
            raise SessionStateError("the session state would not fit in the session file")
        replace_file(self.path, data)


# The add() of each store as written here. A subclass that overrides add(), or a test that replaces it,
# records marks through its own add() (see add_marks).
_NATIVE_ADD = {MemorySessionStore: MemorySessionStore.add, FileSessionStore: FileSessionStore.add}


def _add_replaced(store: SessionStore, native: type) -> bool:
    return getattr(type(store), "add", None) is not _NATIVE_ADD[native]


# The members of a session file, by version.
_FILE_KEYS = {
    1: {"format", "version", "session", "started", "marks"},
    2: {"format", "version", "session", "started", "marks", "tails", "counts", "distinct", "identical", "refusals"},
}
# The members of a mark's cause: version 1 has the tool and the time; version 2 also the server and the channel.
_CAUSE_KEYS = ({"tool", "time"}, {"tool", "time", "server", "channel"})


def _valid_cause(cause: Any, version: int) -> bool:
    if not isinstance(cause, dict) or set(cause) not in (_CAUSE_KEYS if version >= 2 else _CAUSE_KEYS[:1]):
        return False
    limits = {"tool": MAX_CAUSE_TOOL_CHARS + 3, "time": 40, "server": MAX_CAUSE_TEXT_CHARS + 3,
              "channel": MAX_CAUSE_TEXT_CHARS + 3}
    return all(isinstance(value, str) and len(value) <= limits[key] for key, value in cause.items())
