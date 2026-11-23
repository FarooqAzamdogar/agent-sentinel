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
each channel (the "tail", which the next result is read together with, see
tail_scan.py), the counts of the policy's session limits, and the asks a
person refused (approval memory). The values and calls the limits and the
approval memory count are kept as hashes, never as text. The tail is TEXT:
up to TAIL_TEXTS ends of TAIL_CHARS characters each, cut from what the
agent read (with the secrets the firewall's guard knows replaced). So in
hook mode the session file holds the end of the last tool output in clear
text; like every file agent-sentinel writes, it can be read by its owner
only on POSIX (0600), and on Windows it has the permissions of its folder.
Everything has a fixed bound.

Stores
------
`MemorySessionStore` keeps the marks in memory: one process is one session
(the library, one proxy). `FileSessionStore` keeps them in a JSON file per
session id, for hook mode, where every check runs in a new process.
`GroupSessionStore` keeps the marks of a group of proxies (proxy
--session-group) in one file, so that what one server delivered counts for
the calls of another server of the same MCP client (see "Session groups").

The file stores fail closed. A session file that is missing, unreadable,
malformed, written for another session, or that has lost marks this process
saw counts as "every mark set", so every flow rule applies, and its other
state cannot be read: the session limits refuse the calls they count.
Anyone who can write the folder can still rewrite the file consistently:
keep it outside every folder the agent's tools can reach.

Session groups
--------------
The proxies of one MCP client each run in a process of their own, and each
was one session until 0.6. With --session-group NAME they share the file
<home>/sessions/NAME.json, under the lock file NAME.lock beside it. A run of
the client is told by the client process and the time it started
(client_run.py), and the file keeps a session for each run: two windows of
one client, or a client started again while the old one still runs, each
have their own. When a proxy starts (GroupSessionStore.join), under the lock:

* no file: it begins a new run, with no marks;
* a file with a session of the same run: it joins it, and never resets it
  (a proxy the client restarts keeps the marks the others set);
* a file without one: it begins a new run, with no marks, beside the
  others. The file keeps at most MAX_GROUP_RUNS runs: past that, the run
  begun first is removed;
* a file that cannot be read: it begins a new run only if the file was last
  written before this client started (so it cannot belong to this run);
  otherwise every mark counts as set until the file is deleted.

A proxy that cannot find its client is in the run "unknown"
(UNKNOWN_RUN, client_run.UNKNOWN). It may belong to any client run, so the marks of every
run in the file count for it, and the marks of the run "unknown" count for
every other run (GroupSessionStore._visible): stricter than needed, never
laxer.

After joining, a file that is missing, damaged, too large or of another
group, or from which this run was removed or in which it was begun again,
counts as every mark set. A proxy that cannot take the lock in time gets
every mark set when it reads, and SessionStateError when it writes, so the
call or the result is refused. Each mark records the member (proxy --name)
whose result set it, and each member writes its name into its run's list of
members (at most MAX_GROUP_MEMBERS). The proxy joins once nothing can refuse
to start its server any more, just before it starts it; if the server then
cannot be started, the proxy takes its name off the list again
(GroupSessionStore.leave).

A group shares the MARKS only, each with its whole cause (the tool, the
member as its server, the channel). The rest of the session state (the
tail, the counts of the session limits, approval memory) stays with each
proxy, in memory, as for a proxy without a group: a tail is the end of what
one server delivered, and each proxy counts its own calls. So in a group
the session limits and approval memory are per proxy, not per client run.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import os
import re
import threading
import time
import warnings
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_hex
from types import MappingProxyType
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence, TypeVar

from . import jsonutil
from .filelock import locked, make_private_folder, replace_file

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

# The tail: how much of the end of the text last delivered is kept, per channel: up to TAIL_TEXTS texts
# (tail_scan.py keeps one for each kind of the detector's matching views) of TAIL_CHARS characters each.
TAIL_CHARS = 512
TAIL_TEXTS = 8
TAIL_CHANNELS = ("result", "notification")
# Bounds on the rest of the session state (SessionState). Past the first three the
# session limits refuse the call (they cannot count it); the last two forget the oldest.
MAX_COUNTERS = 1_000  # counters and sets of values of the session limits
MAX_DISTINCT_VALUES = 4_096  # values kept for max_distinct, over all its sets
MAX_COUNT = 10**15  # the largest count (calls or bytes)
MAX_IDENTICAL_KEYS = 2_000  # different calls counted for max_identical_calls
MAX_REFUSALS = 1_000  # refused asks remembered
_HASH = re.compile(r"[0-9a-f]{32}")

# A tail as Decision.tail and add_marks pass it: (channel, the texts kept for it).
ChannelTail = tuple[str, Sequence[str]]

FILE_FORMAT = "agent-sentinel-session"
FILE_VERSION = 2
# Version 1 (0.5) has marks only. It is still read; it is written as version 2 the next time.
READABLE_FILE_VERSIONS = (1, 2)
LOCK_FILE_NAME = "sessions.lock"

# Session groups (GroupSessionStore).
GROUP_FILE_FORMAT = "agent-sentinel-session-group"
GROUP_FILE_VERSION = 1
# A group's name, as proxy --session-group takes it: it names a file, so the characters of a server name only.
# It is folded to lower case (group_name), since Windows and macOS file names ignore case.
GROUP_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
MEMBER_NAME = GROUP_NAME  # a member is a proxy --name, which allows the same characters
# Names that Windows gives to devices, not files, with any extension: "nul.json" may not be a file there.
_DEVICE_NAME = re.compile(r"(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?")
GROUP_NAME_RULE = "1 to 64 letters, digits, '_', '-' or '.', and not a Windows device name such as 'nul' or 'com1'"
MAX_GROUP_MEMBERS = 64
# The client runs a group file holds at once; past it, the run begun first is removed to make room.
MAX_GROUP_RUNS = 32
MAX_RUN_ID_CHARS = 200
# The run of a proxy whose client could not be found: client_run.UNKNOWN, written out here because this
# module is part of the library, which does not load the command line's modules (client_run starts programs).
UNKNOWN_RUN = "unknown"
# The largest a group file may be. It holds marks only, and every proxy of the group reads it under the
# group's lock before a call a flow rule may apply to, so it is kept smaller than a session file
# (MAX_STATE_FILE_BYTES, which also holds the tails and counts of a hook session). One run with
# MAX_MARKS marks of the longest causes fits; past it, the runs of other clients are dropped.
MAX_GROUP_FILE_BYTES = 256 * 1024
# How long a proxy waits for the group's lock before it refuses what it was doing.
GROUP_LOCK_SECONDS = 5.0
# A file written less than this many seconds before the client started may still belong to it
# (clocks and file times are not exact), so a damaged one is not replaced.
_MTIME_SLACK_SECONDS = 2.0
# What GroupSessionStore.join found.
NEW_RUN = "new"  # the file had no session of this client run: a new run begins
JOINED = "joined"  # the file has a session of this client run
REPLACED = "replaced"  # the file was damaged and older than this run: it is replaced, and a new run begins
UNUSABLE = "unusable"  # the file is damaged and may belong to this run: every mark counts as set

_MISSING = "the session file is missing (the session was never begun, or it was deleted)"

_T = TypeVar("_T")


class SessionStateError(Exception):
    """The marks of a session could not be recorded.

    Raised by `SessionStore.add` (and so by `Firewall.mark_delivered`). The
    result whose marks were being recorded must then be withheld from the
    agent: if it were delivered, the session would hold content it does not
    know about, and a flow rule would let a call through that it should refuse.
    """


def group_name(text: Any) -> str | None:
    """The name of the session group `text` names (GROUP_NAME_RULE), in lower case; None if it names none.

    Lower case because the group names a file, and on Windows and macOS
    "Team" and "team" are one file: told apart here, the second proxy would
    find the first's file and take it for another group's.
    """
    if not isinstance(text, str) or not GROUP_NAME.fullmatch(text):
        return None
    folded = text.lower()
    return None if _DEVICE_NAME.fullmatch(folded) else folded


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
    flow block: the server it came from (proxy --name; "" when not known; in
    a session group always the member whose content set the mark)
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

    tails:     channel ("result" or "notification") -> a list of at most TAIL_TEXTS texts of
               at most TAIL_CHARS characters: the end of the text the model read on it, in
               each kind of the detector's views (see tail_scan.py; a text may hold
               tail_scan.SEAM, a control character, where two short texts met).
    counts:    counter of a session limit (a hash of its name) -> calls or bytes counted.
    distinct:  set of a max_distinct limit (a hash of its name) -> hashes of the values seen.
    identical: hash of a call (tool and arguments) -> how many times it was made;
               the least recently made first.
    refusals:  [hash of the tool, hash of the call, when (seconds since 1970)] of each
               ask a person refused, oldest first.
    """

    tails: dict[str, list[str]] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    distinct: dict[str, list[str]] = field(default_factory=dict)
    identical: dict[str, int] = field(default_factory=dict)
    refusals: list[list[Any]] = field(default_factory=list)

    def copy(self) -> "SessionState":
        return SessionState(
            {channel: list(texts) for channel, texts in self.tails.items()}, dict(self.counts),
            {key: list(values) for key, values in self.distinct.items()}, dict(self.identical),
            [list(entry) for entry in self.refusals],
        )

    def as_json(self) -> dict[str, Any]:
        """The state as the session file holds it."""
        return {
            "tails": {channel: list(texts) for channel, texts in self.tails.items()}, "counts": dict(self.counts),
            "distinct": dict(self.distinct), "identical": dict(self.identical),
            "refusals": [list(entry) for entry in self.refusals],
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
        if not isinstance(tails, dict) or not all(
            channel in TAIL_CHANNELS and _valid_tail(texts) for channel, texts in tails.items()
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


def _valid_tail(texts: Any) -> bool:
    return isinstance(texts, list) and len(texts) <= TAIL_TEXTS and all(
        isinstance(text, str) and len(text) <= TAIL_CHARS for text in texts
    )


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
    refuse the calls they count. A store with those two operations that is
    no SessionStore (0.5 did not ask for the base class) is wrapped by the
    Firewall and behaves the same (as_session_store). GroupSessionStore keeps
    the marks in a file several proxies share, and the rest of the state in
    memory.
    """

    def read(self) -> SessionMarks:
        raise NotImplementedError

    def add(self, labels: Iterable[str], tool: str) -> SessionMarks:
        raise NotImplementedError

    def add_marks(self, marks: Iterable[Mark], tail: ChannelTail | None = None) -> SessionMarks:
        """Record marks, each with its own cause, and (channel, texts) as that channel's tail."""
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


_NEWER_OPERATIONS = ("add_marks", "read_state", "update_state")


class _WrappedStore(SessionStore):
    """A session store that is no SessionStore but has its operations: the 0.5 ones, or all of them.

    read() and add() go to the store. So do add_marks(), read_state() and
    update_state() when it has them; when it does not (a store written for
    0.5, whose documentation asked for the two operations only), they are
    SessionStore's own: marks go through add(), and there is no session
    state.
    """

    def __init__(self, store: Any) -> None:
        self.store = store
        self.complete = all(callable(getattr(store, name, None)) for name in _NEWER_OPERATIONS)

    def read(self) -> SessionMarks:
        return self.store.read()

    def add(self, labels: Iterable[str], tool: str) -> SessionMarks:
        return self.store.add(labels, tool)

    def add_marks(self, marks: Iterable[Mark], tail: ChannelTail | None = None) -> SessionMarks:
        return self.store.add_marks(marks, tail) if self.complete else super().add_marks(marks, tail)

    def read_state(self) -> SessionState:
        return self.store.read_state() if self.complete else super().read_state()

    def update_state(self, change: Callable[[SessionState], _T]) -> _T:
        return self.store.update_state(change) if self.complete else super().update_state(change)


def as_session_store(store: Any) -> SessionStore:
    """`store` as the SessionStore a Firewall works with; TypeError if it has no read() and add().

    A SessionStore is returned as it is. Any other object with the
    operations is wrapped. One written for 0.5, with read() and add() only,
    keeps working as far as it can, and a warning (once, a RuntimeWarning)
    says what it cannot do: marks are recorded through add(), without the
    server and the channel of their cause; the end of a result is not kept,
    so text split over two results is not looked for; approval memory
    remembers nothing; and a call that one of the policy's session limits
    counts is refused, since it cannot be counted.
    """
    if isinstance(store, SessionStore):
        return store
    if not callable(getattr(store, "read", None)) or not callable(getattr(store, "add", None)):
        raise TypeError("a session store needs read() and add(labels, tool): subclass "
                        "agent_sentinel.session.SessionStore")
    wrapped = _WrappedStore(store)
    if not wrapped.complete:
        warnings.warn(
            f"the session store {type(store).__name__} has read() and add() but not add_marks(), read_state() and "
            "update_state(), which agent-sentinel uses since 0.6. It still records the flow marks, through add(); "
            "text split over two results is not looked for, approval memory is off, and a call that a session limit "
            "of the policy counts is refused. Subclass agent_sentinel.session.SessionStore and add the three "
            "operations to get them.",
            RuntimeWarning, stacklevel=3,
        )
    return wrapped


def _checked_tail(tail: ChannelTail | None) -> tuple[str, list[str]] | None:
    """(channel, texts) as a store keeps it, each text cut to its last TAIL_CHARS characters; ValueError if not."""
    if tail is None:
        return None
    channel, texts = tail
    if (
        channel not in TAIL_CHANNELS or not isinstance(texts, (list, tuple)) or len(texts) > TAIL_TEXTS
        or not all(isinstance(text, str) for text in texts)
    ):
        raise ValueError("not a tail: (channel, at most TAIL_TEXTS texts) was expected")
    return channel, [text[-TAIL_CHARS:] for text in texts]


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

    def add_marks(self, marks: Iterable[Mark], tail: ChannelTail | None = None) -> SessionMarks:
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

    def _record(self, marks: list[Mark], tail: tuple[str, list[str]] | None) -> SessionMarks:
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
            make_private_folder(self.directory)  # owner-only, the missing folders above it too
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

    def add_marks(self, marks: Iterable[Mark], tail: ChannelTail | None = None) -> SessionMarks:
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

    def _record(self, wanted: list[Mark], tail: tuple[str, list[str]] | None) -> SessionMarks:
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
# ---- session groups -------------------------------------------------------------------

@dataclass(frozen=True)
class GroupJoin:
    """What GroupSessionStore.join found and did, for the operator.

    status:   NEW_RUN, JOINED, REPLACED or UNUSABLE.
    members:  the members of the run this proxy is now in, itself included (empty for UNUSABLE).
    replaced: for REPLACED, the members of the run that was replaced; for NEW_RUN, those of the
              oldest run, if it was removed to make room (MAX_GROUP_RUNS).
    detail:   for REPLACED and UNUSABLE, why.
    others:   how many other client runs the file holds besides this one.
    """

    status: str
    members: tuple[str, ...] = ()
    replaced: tuple[str, ...] = ()
    detail: str = ""
    others: int = 0


@dataclass(frozen=True)
class _GroupRun:
    """One client run in a session group file: its members and its marks."""

    run: str
    instance: str  # random, new each time a run begins: a run begun again is told apart from the one joined
    started: str
    members: tuple[str, ...]
    marks: dict[str, Mark]


@dataclass(frozen=True)
class _GroupFile:
    """The contents of a session group file (see _parse_group_file): the runs, the one begun first first."""

    group: str
    runs: tuple[_GroupRun, ...]

    def run_of(self, run_id: str) -> _GroupRun | None:
        return next((run for run in self.runs if run.run == run_id), None)

    def with_run(self, changed: _GroupRun) -> "_GroupFile":
        """The same file, with the run of the same id replaced by `changed`."""
        return dataclasses.replace(self, runs=tuple(changed if run.run == changed.run else run for run in self.runs))


class GroupSessionStore(SessionStore):
    """The marks of a group of proxies, shared through one file (proxy --session-group; see "Session groups").

    Call `join()` once, when the proxy starts. Until it has joined, and when
    it found a file it could not use, every mark counts as set.

    Only the marks are in the file. The rest of the session state
    (read_state, update_state, and the tail add_marks is given) is this
    proxy's own, in memory, as in a MemorySessionStore: it can always be
    read, also while the file cannot be used.
    """

    def __init__(
        self,
        directory: str | Path,
        group: str,
        run_id: str,
        member: str,
        run_started: float | None = None,
        lock_timeout: float = GROUP_LOCK_SECONDS,
    ) -> None:
        """
        directory:   the folder of the group files (<home>/sessions).
        group:       the group's name (GROUP_NAME_RULE), taken in lower case (group_name): the file is
                     <directory>/<group>.json.
        run_id:      the client run this proxy belongs to (client_run.py); "unknown" when it cannot be told.
        member:      this proxy's --name; it marks the marks this proxy sets.
        run_started: when the client process started (seconds since the epoch), if known: a damaged file
                     last written before then is replaced at join.
        """
        folded = group_name(group)
        if folded is None:
            raise ValueError(f"the group must be {GROUP_NAME_RULE}")
        if not isinstance(run_id, str) or not 0 < len(run_id) <= MAX_RUN_ID_CHARS or not run_id.isprintable():
            raise ValueError(f"the run id must be printable text of 1 to {MAX_RUN_ID_CHARS} characters")
        if not isinstance(member, str) or not MEMBER_NAME.fullmatch(member):
            raise ValueError("the member name must be 1 to 64 letters, digits, '_', '-' or '.'")
        self.directory = Path(directory)
        self.group = folded
        self.run_id = run_id
        self.member = member
        self.path = self.directory / f"{folded}.json"
        self._lock_path = self.directory / f"{folded}.lock"
        self._run_started = run_started
        self._lock_timeout = lock_timeout
        self._thread_lock = threading.Lock()
        self._seen: dict[str, Mark] = {}  # every mark this object has read or written: for spotting lost ones
        # The marks of other runs that count for this proxy too (_visible), once seen: they stay, like any mark.
        # Past MAX_MARKS of them, every mark counts as set from then on.
        self._borrowed: dict[str, Mark] = {}
        self._borrowed_overflowed = False
        self._instance: str | None = None  # the instance of the run joined; None until join() has succeeded
        # The tails, the session limits' counts and approval memory: this proxy's own, never in the file.
        self._state = SessionState()
        self._state_lock = threading.Lock()
        self._why_unusable = "the session group was not joined"

    def join(self) -> GroupJoin:
        """Begin a new run or join the current one, following the rules in "Session groups".

        Raises SessionStateError if the folder or the file cannot be written,
        or the lock cannot be had in time.
        """
        try:
            make_private_folder(self.directory)  # owner-only, the missing folders above it too
            with self._exclusive():
                found, problem = self._load()
                if found is None and problem is None:
                    return self._begin(NEW_RUN, None)
                if found is None or found.group != self.group:
                    problem = problem or "it names another group"
                    if self._older_than_this_run():
                        return self._begin(REPLACED, None, detail=f"{problem}, and it was last written before this "
                                                                  "client started")
                    self._why_unusable = (f"the session group file is not valid ({problem}) and may belong to this "
                                          "client run, so every mark counts as set until it is deleted")
                    return GroupJoin(UNUSABLE, detail=self._why_unusable)
                mine = found.run_of(self.run_id)
                if mine is None:
                    return self._begin(NEW_RUN, found)
                if self.member not in mine.members and len(mine.members) < MAX_GROUP_MEMBERS:
                    mine = dataclasses.replace(mine, members=(*mine.members, self.member))
                    self._write(found.with_run(mine))
                self._instance = mine.instance
                self._seen.update(mine.marks)
                return GroupJoin(JOINED, members=mine.members, others=len(found.runs) - 1)
        except OSError as exc:
            raise SessionStateError(f"cannot join the session group file {self.path}: {exc}") from exc

    def leave(self) -> None:
        """Take this proxy's name off the members of the run it joined: its server never ran. Never raises.

        For a proxy that joined and then could not start its server. Only
        the name is removed, and only from the run this proxy joined: the run
        and its marks stay, for the other proxies of the client run. A file
        that cannot be read or written, or that no longer holds that run, is
        left as it is. Afterwards every mark counts as set, as before join().
        """
        if self._instance is None:
            return
        instance, self._instance = self._instance, None
        self._why_unusable = "the session group was left"
        try:
            with self._exclusive():
                found, _ = self._load()
                mine = found.run_of(self.run_id) if found is not None and found.group == self.group else None
                if mine is None or mine.instance != instance or self.member not in mine.members:
                    return
                members = tuple(name for name in mine.members if name != self.member)
                self._write(found.with_run(dataclasses.replace(mine, members=members)))
        except (OSError, SessionStateError):
            pass  # the name stays listed: nothing reads it but doctor's hint about a lone member

    def read(self) -> SessionMarks:
        if self._instance is None:
            return SessionMarks.untrusted(self._why_unusable)
        try:
            with self._exclusive():
                return self._visible(*self._checked())
        except OSError as exc:  # includes a lock not had in time
            return SessionMarks.untrusted(f"the session group file cannot be read ({type(exc).__name__}: {exc})")

    def add(self, labels: Iterable[str], tool: str, *, server: str = "", channel: str = "") -> SessionMarks:
        """Record marks whose cause is `tool`, delivered by this member. `server` is not used: it is the member."""
        marks = [Mark(label, tool, _now(), self.member, channel) for label in _checked_labels(labels)]
        return self._record(_checked_marks(marks), None)

    def add_marks(self, marks: Iterable[Mark], tail: ChannelTail | None = None) -> SessionMarks:
        """Record marks in the group's file, each with its cause, and keep `tail` (in memory, for this proxy).

        The server of each mark's cause is this member, whatever the mark
        says. With no mark to record the file is not opened (a lock that the
        result of an unlabelled tool need not wait for): the tail is kept,
        and the answer is the fail-closed one, since the marks were not read.
        SessionStateError when the marks cannot be recorded; the tail of that
        content is then not kept either (the content is withheld).
        """
        wanted, kept = _checked_marks(marks), _checked_tail(tail)
        if not wanted:
            self._keep_tail(kept)
            return SessionMarks.untrusted("the session group's marks were not read: there was no mark to record")
        return self._record([dataclasses.replace(mark, server=self.member) for mark in wanted], kept)

    def read_state(self) -> SessionState:
        with self._state_lock:
            return self._state.copy()

    def update_state(self, change: Callable[[SessionState], _T]) -> _T:
        with self._state_lock:
            answer, self._state = _changed_state(self._state, change)
            return answer

    # ---- internals --------------------------------------------------------------

    def _keep_tail(self, tail: tuple[str, list[str]] | None) -> None:
        if tail is not None:
            with self._state_lock:
                self._state.tails[tail[0]] = tail[1]

    def _record(self, wanted: list[Mark], tail: tuple[str, list[str]] | None) -> SessionMarks:
        """Write the marks the run does not have yet (under the group's lock), then keep the tail."""
        current = self._record_marks(wanted)
        self._keep_tail(tail)
        return current

    def _record_marks(self, wanted: list[Mark]) -> SessionMarks:
        if self._instance is None:
            return SessionMarks.untrusted(self._why_unusable)  # every mark counts as set: nothing to record
        try:
            with self._exclusive():
                current, found = self._checked()
                # Against the marks of this run alone: one that only another run has (_visible) is recorded here too.
                new = [mark for mark in wanted if mark.label not in current.marks]
                if found is None or current.everything or not new:
                    return self._visible(current, found)  # nothing to add; and a broken file is never repaired
                marks = dict(current.marks)
                for mark in new:
                    if len(marks) >= MAX_MARKS:
                        raise SessionStateError("more marks than can be tracked")
                    marks[mark.label] = mark
                mine = found.run_of(self.run_id)
                assert mine is not None  # _checked found it
                self._write(found.with_run(dataclasses.replace(mine, marks=marks)))
                self._seen.update(marks)
                return self._visible(SessionMarks(marks), found)
        except FileNotFoundError:
            # The folder is gone: every mark counts as set when it is read, so nothing needs recording.
            return SessionMarks.untrusted("the session group folder disappeared")
        except OSError as exc:
            raise SessionStateError(f"cannot record marks in {self.path}: {exc}") from exc

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        """One thread of this process, and one process of the group, at a time; OSError if not in time."""
        with self._thread_lock, locked(self._lock_path, timeout=self._lock_timeout):
            yield

    def _begin(self, status: str, found: _GroupFile | None, detail: str = "") -> GroupJoin:
        """Begin this client run, with no marks and this proxy as its only member. Called with the lock held.

        The runs of other clients in `found` are kept, but for the one begun
        first when there are MAX_GROUP_RUNS of them.
        """
        run = _GroupRun(self.run_id, token_hex(8), _now(), (self.member,), {})
        others = [other for other in found.runs if other.run != self.run_id] if found is not None else []
        removed = others[:max(0, len(others) - (MAX_GROUP_RUNS - 1))]
        others = others[len(removed):]
        others = self._write(_GroupFile(self.group, (*others, run)))
        self._instance = run.instance
        self._seen = {}
        replaced = removed[-1].members if removed else ()
        return GroupJoin(status, members=run.members, replaced=replaced, detail=detail, others=others)

    def _older_than_this_run(self) -> bool:
        """Whether the file was last written before the client started, so it cannot hold this run's marks."""
        if self._run_started is None:
            return False
        try:
            written = os.stat(self.path).st_mtime
        except OSError:
            return False
        return written < self._run_started - _MTIME_SLACK_SECONDS

    def _visible(self, own: SessionMarks, found: _GroupFile | None) -> SessionMarks:
        """The marks that count for this proxy: its run's, and those of the runs it cannot be told from.

        A proxy whose client could not be found (the run "unknown") may
        belong to any client run of the group, so the marks of every run in
        the file count for it. For the same reason the marks of the run
        "unknown" count for every other run: one of its members may be a
        proxy of this client. Too strict, never too lax. A mark seen once
        stays for this proxy, also when the run it came from is removed from
        the file later. `own` is what _checked gave (returned as it is when
        the file cannot be used), `found` the file. Called with the lock held.
        """
        if found is None or own.everything:
            return own
        too_many = SessionMarks.untrusted("the session group file holds more marks than can be tracked")
        for run in found.runs:
            if run.run != self.run_id and UNKNOWN_RUN in (run.run, self.run_id):
                for label, mark in run.marks.items():
                    if label not in self._borrowed and len(self._borrowed) >= MAX_MARKS:
                        self._borrowed_overflowed = True  # a mark seen and not kept: for good, every mark counts
                    if not self._borrowed_overflowed:
                        self._borrowed.setdefault(label, mark)
        if self._borrowed_overflowed:
            return too_many
        if not self._borrowed:
            return own
        marks = {**self._borrowed, **own.marks}
        return too_many if len(marks) > MAX_MARKS else SessionMarks(marks)

    def _checked(self) -> tuple[SessionMarks, _GroupFile | None]:
        """The marks of this proxy's run, or every mark set when it is not the run this proxy joined. Lock held."""
        found, problem = self._load()
        if found is None:
            return SessionMarks.untrusted(f"the session group file is not valid: {problem}" if problem
                                          else "the session group file disappeared"), None
        if found.group != self.group:
            return SessionMarks.untrusted("the session group file names another group"), None
        mine = found.run_of(self.run_id)
        if mine is None:
            return SessionMarks.untrusted("this client run was removed from the session group file (later client "
                                          "runs made room, or the file was replaced)"), None
        if mine.instance != self._instance:
            return SessionMarks.untrusted("this client run was begun again in the session group file after this "
                                          "proxy joined it"), None
        if any(label not in mine.marks for label in self._seen):
            return SessionMarks.untrusted("marks disappeared from the session group file"), None
        self._seen.update(mine.marks)
        return SessionMarks(mine.marks), found

    def _load(self) -> tuple[_GroupFile | None, str | None]:
        """(the file's contents, None), (None, what is wrong with it), or (None, None) when there is no file."""
        try:
            with open(self.path, "rb") as handle:
                data = handle.read(MAX_GROUP_FILE_BYTES + 1)
        except FileNotFoundError:
            return None, None
        if len(data) > MAX_GROUP_FILE_BYTES:
            return None, "it is too large"
        return _parse_group_file(data)

    def _write(self, found: _GroupFile) -> int:
        """Replace the file; return how many runs it holds besides this proxy's. Atomic: a crash leaves old or new.

        If it would be larger than a reader takes (MAX_GROUP_FILE_BYTES), the
        runs of other clients are dropped, the one begun first first.
        """
        runs = list(found.runs)
        while True:
            data = _group_file_bytes(found.group, runs)
            others = [run for run in runs if run.run != self.run_id]
            if len(data) <= MAX_GROUP_FILE_BYTES or not others:
                break
            runs.remove(others[0])
        if len(data) > MAX_GROUP_FILE_BYTES:
            raise SessionStateError("the session group file would be too large")
        replace_file(self.path, data)
        return len(others)


def _group_file_bytes(group: str, runs: Iterable[_GroupRun]) -> bytes:
    """What a session group file holds, as written."""
    document = {
        "format": GROUP_FILE_FORMAT,
        "version": GROUP_FILE_VERSION,
        "group": group,
        "runs": [{
            "run": run.run,
            "instance": run.instance,
            "started": run.started,
            "members": list(run.members),
            "marks": {label: {"tool": mark.tool, "time": mark.time, "server": mark.server, "channel": mark.channel}
                      for label, mark in run.marks.items()},
        } for run in runs],
    }
    return json.dumps(document, ensure_ascii=True, indent=1).encode("ascii")


def group_members(directory: str | Path, group: str) -> tuple[str, ...] | None:
    """The members of the latest client run in a session group's file, for doctor; None if there is no usable file.

    The latest run is the one begun last. Only reads: the file is never
    locked or changed, so what it says may be a moment old.
    """
    folded = group_name(group)
    if folded is None:
        return None
    try:
        with open(Path(directory) / f"{folded}.json", "rb") as handle:
            data = handle.read(MAX_GROUP_FILE_BYTES + 1)
    except OSError:
        return None
    found, _ = _parse_group_file(data) if len(data) <= MAX_GROUP_FILE_BYTES else (None, None)
    return found.runs[-1].members if found is not None and found.group == folded else None


_GROUP_KEYS = {"format", "version", "group", "runs"}
_RUN_KEYS = {"run", "instance", "started", "members", "marks"}
_INSTANCE = re.compile(r"[0-9a-f]{16}")


def _parse_group_file(data: bytes) -> tuple[_GroupFile | None, str | None]:
    """Read a session group file's bytes: (contents, None) or (None, what is wrong). Strict, like FileSessionStore."""
    try:
        document = jsonutil.loads(data.decode("utf-8"))
    except (ValueError, RecursionError):  # includes UnicodeDecodeError and a repeated key
        return None, "it is not JSON"
    if not isinstance(document, dict) or set(document) != _GROUP_KEYS:
        return None, "unexpected contents"
    # The version is a whole number: `true` and 1.0 compare equal to 1, and are not what this program writes.
    version = document["version"]
    if document["format"] != GROUP_FILE_FORMAT or type(version) is not int or version != GROUP_FILE_VERSION:
        return None, "unknown format or version"
    group, entries = document["group"], document["runs"]
    if not isinstance(group, str) or not GROUP_NAME.fullmatch(group):
        return None, "unexpected contents"
    if not isinstance(entries, list) or not 0 < len(entries) <= MAX_GROUP_RUNS:
        return None, "the list of client runs is malformed"
    runs = []
    for entry in entries:
        run, problem = _parse_group_run(entry)
        if run is None:
            return None, problem
        runs.append(run)
    if len({run.run for run in runs}) != len(runs):
        return None, "a client run is listed twice"
    return _GroupFile(group, tuple(runs)), None


def _parse_group_run(entry: Any) -> tuple[_GroupRun | None, str]:
    """One client run of a session group file: (the run, "") or (None, what is wrong)."""
    if not isinstance(entry, dict) or set(entry) != _RUN_KEYS:
        return None, "a client run is malformed"
    run, instance, started = entry["run"], entry["instance"], entry["started"]
    members, marked = entry["members"], entry["marks"]
    if (not isinstance(run, str) or not 0 < len(run) <= MAX_RUN_ID_CHARS
            or not isinstance(instance, str) or not _INSTANCE.fullmatch(instance)
            or not isinstance(started, str) or len(started) > 40):
        return None, "a client run is malformed"
    if (not isinstance(members, list) or len(members) > MAX_GROUP_MEMBERS or len(set(map(str, members))) != len(members)
            or not all(isinstance(name, str) and MEMBER_NAME.fullmatch(name) for name in members)):
        return None, "the list of members is malformed"
    if not isinstance(marked, dict) or len(marked) > MAX_MARKS:
        return None, "the marks are malformed"
    marks = {}
    for label, cause in marked.items():
        # A cause as a session file of version 2 has it (the tool, the time, the server, the channel),
        # and the server is a member's name.
        if not is_label(label) or label == SINK or not _valid_cause(cause, FILE_VERSION) or len(cause) != 4:
            return None, "a mark is malformed"
        server = cause["server"]
        if server != "" and not MEMBER_NAME.fullmatch(server):
            return None, "a mark is malformed"
        marks[label] = Mark(label, cause["tool"], cause["time"], server, cause["channel"])
    return _GroupRun(run, instance, started, tuple(members), marks), ""
