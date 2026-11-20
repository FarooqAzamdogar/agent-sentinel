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
what it returns. A mark is never removed, and the first tool that set it is
kept so the audit log can say where the content came from. Marks are set
only for results that are actually delivered: a refused call or a withheld
result teaches the agent nothing.

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
saw counts as "every mark set", so every flow rule applies. Anyone who can
write the folder can still rewrite the file consistently: keep it outside
every folder the agent's tools can reach.

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

After joining, a file that is missing, damaged, too large or of another
group, or from which this run was removed or in which it was begun again,
counts as every mark set. A proxy that cannot take the lock in time gets
every mark set when it reads, and SessionStateError when it writes, so the
call or the result is refused. Each mark records the member (proxy --name)
whose result set it, and each member writes its name into its run's list of
members (at most MAX_GROUP_MEMBERS).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from secrets import token_hex
from types import MappingProxyType
from typing import Any, Iterable, Iterator, Mapping

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
MAX_SESSION_ID_CHARS = 256
MAX_STATE_FILE_BYTES = 256 * 1024

FILE_FORMAT = "agent-sentinel-session"
FILE_VERSION = 1
LOCK_FILE_NAME = "sessions.lock"

# Session groups (GroupSessionStore).
GROUP_FILE_FORMAT = "agent-sentinel-session-group"
GROUP_FILE_VERSION = 1
# A group's name, as proxy --session-group takes it: it names a file, so the characters of a server name only.
GROUP_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
MEMBER_NAME = GROUP_NAME  # a member is a proxy --name, which allows the same characters
MAX_GROUP_MEMBERS = 64
# The client runs a group file holds at once; past it, the run begun first is removed to make room.
MAX_GROUP_RUNS = 32
MAX_RUN_ID_CHARS = 200
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
    """One mark of a session: the label, and the first delivered result that set it."""

    label: str
    tool: str  # the tool (or, in the proxy, the resource URI) whose result set it; may be agent- or server-chosen text
    time: str  # when, as UTC ISO 8601 to the second; "" if not known
    server: str = ""  # in a session group: the member (proxy --name) whose result set it; "" otherwise


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


# ---- stores -----------------------------------------------------------------------

class SessionStore:
    """Where the marks of one session are kept.

    Two operations, both safe to call from several threads:

        read()                -> SessionMarks   never raises; fails closed (everything marked)
        add(labels, tool)     -> SessionMarks   records marks; raises SessionStateError if it cannot

    `add` ignores "sink" and labels already marked, and keeps the first cause.
    """

    def read(self) -> SessionMarks:
        raise NotImplementedError

    def add(self, labels: Iterable[str], tool: str) -> SessionMarks:
        raise NotImplementedError


class MemorySessionStore(SessionStore):
    """Marks kept in memory: the session lasts as long as the process (the default for a Firewall)."""

    def __init__(self) -> None:
        self._marks: dict[str, Mark] = {}
        self._overflowed = False
        self._lock = threading.Lock()

    def read(self) -> SessionMarks:
        with self._lock:
            return self._snapshot()

    def add(self, labels: Iterable[str], tool: str) -> SessionMarks:
        wanted = _checked_labels(labels)
        with self._lock:
            for label in wanted:
                if label in self._marks:
                    continue
                if len(self._marks) >= MAX_MARKS:
                    self._overflowed = True  # cannot remember another one: from now on, everything counts
                    break
                self._marks[label] = Mark(label, _bounded_tool(tool), _now())
            return self._snapshot()

    def _snapshot(self) -> SessionMarks:
        if self._overflowed:
            return SessionMarks(self._marks, everything=True, why="more marks than can be tracked")
        return SessionMarks(self._marks)


class FileSessionStore(SessionStore):
    """Marks kept in a JSON file, one per session id, for checks that each run in a new process.

    The file is `<directory>/session-<hash of the id>.json`; every process
    takes the lock file `<directory>/sessions.lock` before it reads or writes.

    Call `begin()` once, when the session really starts (for Claude Code: the
    SessionStart hook with source "startup" or "clear"; not "resume" or
    "compact", or a file the agent deleted would quietly come back empty).
    After that, and without it, a missing file counts as every mark set.

    Fail closed, in detail. `read()` reports every mark set when the file is
    missing, cannot be read or locked, is larger than MAX_STATE_FILE_BYTES,
    is not the expected JSON (any unexpected key or type), belongs to another
    session id, or has lost a mark this object saw earlier. `add()` never
    repairs such a file: the session stays fully marked until a new one
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

    # ---- the three operations -------------------------------------------------

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
                    self._write({})
                return self._read_unlocked()
        except OSError as exc:
            raise SessionStateError(f"cannot start the session file {self.path}: {exc}") from exc

    def read(self) -> SessionMarks:
        try:
            with self._exclusive():
                return self._read_unlocked()
        except FileNotFoundError:  # the folder itself is gone, so the lock file cannot be opened
            return SessionMarks.untrusted(_MISSING)
        except OSError as exc:
            return SessionMarks.untrusted(f"the session file cannot be read ({type(exc).__name__}: {exc})")

    def add(self, labels: Iterable[str], tool: str) -> SessionMarks:
        wanted = _checked_labels(labels)
        try:
            with self._exclusive():
                current = self._read_unlocked()
                if current.everything or all(label in current.marks for label in wanted):
                    return current  # nothing to add; and a broken file is never repaired
                marks = dict(current.marks)
                for label in wanted:
                    if label not in marks:
                        if len(marks) >= MAX_MARKS:
                            raise SessionStateError("more marks than can be tracked")
                        marks[label] = Mark(label, _bounded_tool(tool), _now())
                self._write(marks)
                self._seen.update(marks)
                return SessionMarks(marks)
        except FileNotFoundError:
            # The folder is gone: like a missing file, every mark counts as set, so nothing needs recording.
            return SessionMarks.untrusted(_MISSING)
        except OSError as exc:
            raise SessionStateError(f"cannot record marks in {self.path}: {exc}") from exc

    # ---- internals --------------------------------------------------------------

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        """One thread of this process, and one process, at a time."""
        with self._thread_lock, locked(self._lock_path):
            yield

    def _read_unlocked(self) -> SessionMarks:
        try:
            with open(self.path, "rb") as handle:
                data = handle.read(MAX_STATE_FILE_BYTES + 1)
        except FileNotFoundError:
            if self._seen or self._started:
                return SessionMarks.untrusted("the session file disappeared")
            return SessionMarks.untrusted(_MISSING)
        if len(data) > MAX_STATE_FILE_BYTES:
            return SessionMarks.untrusted("the session file is too large")
        problem, marks = self._parse(data)
        if problem is not None:
            return SessionMarks.untrusted(f"the session file is not valid: {problem}")
        lost = [label for label in self._seen if label not in marks]
        if lost:
            return SessionMarks.untrusted("marks disappeared from the session file")
        self._seen.update(marks)
        return SessionMarks(marks)

    def _parse(self, data: bytes) -> tuple[str | None, dict[str, Mark]]:
        """Read the file's bytes. Returns (what is wrong, or None; the marks)."""
        try:
            document = jsonutil.loads(data.decode("utf-8"))
        except (ValueError, RecursionError):  # includes UnicodeDecodeError and a repeated key
            return "not JSON", {}
        if not isinstance(document, dict) or set(document) != {"format", "version", "session", "started", "marks"}:
            return "unexpected contents", {}
        if document["format"] != FILE_FORMAT or document["version"] != FILE_VERSION:
            return "unknown format or version", {}
        if document["session"] != self.session_id:
            return "it belongs to another session", {}
        started, entries = document["started"], document["marks"]
        if not isinstance(started, str) or len(started) > 40 or not isinstance(entries, dict):
            return "unexpected contents", {}
        if len(entries) > MAX_MARKS:
            return "too many marks", {}
        marks = {}
        for label, cause in entries.items():
            if not is_label(label) or label == SINK or not _valid_cause(cause):
                return "a mark is malformed", {}
            marks[label] = Mark(label, cause["tool"], cause["time"])
        self._started = started
        return None, marks

    def _write(self, marks: dict[str, Mark]) -> None:
        """Replace the session file with these marks. Atomic: a crash leaves the old file or the new one."""
        document = {
            "format": FILE_FORMAT,
            "version": FILE_VERSION,
            "session": self.session_id,
            "started": self._started or _now(),
            "marks": {label: {"tool": mark.tool, "time": mark.time} for label, mark in marks.items()},
        }
        # ensure_ascii: a tool name with a lone surrogate must not stop the file from being written.
        replace_file(self.path, json.dumps(document, ensure_ascii=True, indent=1).encode("ascii"))


def _valid_cause(cause: Any) -> bool:
    return (
        isinstance(cause, dict) and set(cause) == {"tool", "time"}
        and isinstance(cause["tool"], str) and len(cause["tool"]) <= MAX_CAUSE_TOOL_CHARS + 3
        and isinstance(cause["time"], str) and len(cause["time"]) <= 40
    )


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
        group:       the group's name (GROUP_NAME): the file is <directory>/<group>.json.
        run_id:      the client run this proxy belongs to (client_run.py); "unknown" when it cannot be told.
        member:      this proxy's --name; it marks the marks this proxy sets.
        run_started: when the client process started (seconds since the epoch), if known: a damaged file
                     last written before then is replaced at join.
        """
        if not isinstance(group, str) or not GROUP_NAME.fullmatch(group):
            raise ValueError("the group must be 1 to 64 letters, digits, '_', '-' or '.'")
        if not isinstance(run_id, str) or not 0 < len(run_id) <= MAX_RUN_ID_CHARS or not run_id.isprintable():
            raise ValueError(f"the run id must be printable text of 1 to {MAX_RUN_ID_CHARS} characters")
        if not isinstance(member, str) or not MEMBER_NAME.fullmatch(member):
            raise ValueError("the member name must be 1 to 64 letters, digits, '_', '-' or '.'")
        self.directory = Path(directory)
        self.group = group
        self.run_id = run_id
        self.member = member
        self.path = self.directory / f"{group}.json"
        self._lock_path = self.directory / f"{group}.lock"
        self._run_started = run_started
        self._lock_timeout = lock_timeout
        self._thread_lock = threading.Lock()
        self._seen: dict[str, Mark] = {}  # every mark this object has read or written: for spotting lost ones
        self._instance: str | None = None  # the instance of the run joined; None until join() has succeeded
        self._why_unusable = "the session group was not joined"

    def join(self) -> GroupJoin:
        """Begin a new run or join the current one, following the rules in "Session groups".

        Raises SessionStateError if the folder or the file cannot be written,
        or the lock cannot be had in time.
        """
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
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

    def read(self) -> SessionMarks:
        if self._instance is None:
            return SessionMarks.untrusted(self._why_unusable)
        try:
            with self._exclusive():
                return self._checked()[0]
        except OSError as exc:  # includes a lock not had in time
            return SessionMarks.untrusted(f"the session group file cannot be read ({type(exc).__name__}: {exc})")

    def add(self, labels: Iterable[str], tool: str) -> SessionMarks:
        wanted = _checked_labels(labels)
        if self._instance is None:
            return SessionMarks.untrusted(self._why_unusable)  # every mark counts as set: nothing to record
        try:
            with self._exclusive():
                current, found = self._checked()
                if found is None or current.everything or all(label in current.marks for label in wanted):
                    return current  # nothing to add; and a broken file is never repaired
                marks = dict(current.marks)
                for label in wanted:
                    if label not in marks:
                        if len(marks) >= MAX_MARKS:
                            raise SessionStateError("more marks than can be tracked")
                        marks[label] = Mark(label, _bounded_tool(tool), _now(), self.member)
                mine = found.run_of(self.run_id)
                assert mine is not None  # _checked found it
                self._write(found.with_run(dataclasses.replace(mine, marks=marks)))
                self._seen.update(marks)
                return SessionMarks(marks)
        except FileNotFoundError:
            # The folder is gone: every mark counts as set when it is read, so nothing needs recording.
            return SessionMarks.untrusted("the session group folder disappeared")
        except OSError as exc:
            raise SessionStateError(f"cannot record marks in {self.path}: {exc}") from exc

    # ---- internals --------------------------------------------------------------

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
                data = handle.read(MAX_STATE_FILE_BYTES + 1)
        except FileNotFoundError:
            return None, None
        if len(data) > MAX_STATE_FILE_BYTES:
            return None, "it is too large"
        return _parse_group_file(data)

    def _write(self, found: _GroupFile) -> int:
        """Replace the file; return how many runs it holds besides this proxy's. Atomic: a crash leaves the old or the new.

        If it would be larger than a reader takes (MAX_STATE_FILE_BYTES), the
        runs of other clients are dropped, the one begun first first.
        """
        runs = list(found.runs)
        while True:
            data = _group_file_bytes(found.group, runs)
            others = [run for run in runs if run.run != self.run_id]
            if len(data) <= MAX_STATE_FILE_BYTES or not others:
                break
            runs.remove(others[0])
        if len(data) > MAX_STATE_FILE_BYTES:
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
            "marks": {label: {"tool": mark.tool, "time": mark.time, "server": mark.server}
                      for label, mark in run.marks.items()},
        } for run in runs],
    }
    return json.dumps(document, ensure_ascii=True, indent=1).encode("ascii")


def group_members(directory: str | Path, group: str) -> tuple[str, ...] | None:
    """The members of the latest client run in a session group's file, for doctor; None if there is no usable file.

    The latest run is the one begun last. Only reads: the file is never
    locked or changed, so what it says may be a moment old.
    """
    if not isinstance(group, str) or not GROUP_NAME.fullmatch(group):
        return None
    try:
        with open(Path(directory) / f"{group}.json", "rb") as handle:
            data = handle.read(MAX_STATE_FILE_BYTES + 1)
    except OSError:
        return None
    found, _ = _parse_group_file(data) if len(data) <= MAX_STATE_FILE_BYTES else (None, None)
    return found.runs[-1].members if found is not None and found.group == group else None


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
    if document["format"] != GROUP_FILE_FORMAT or document["version"] != GROUP_FILE_VERSION:
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
        if (not is_label(label) or label == SINK or not isinstance(cause, dict)
                or set(cause) != {"tool", "time", "server"}):
            return None, "a mark is malformed"
        server = cause["server"]
        if not _valid_cause({"tool": cause["tool"], "time": cause["time"]}) or not (
                isinstance(server, str) and (server == "" or MEMBER_NAME.fullmatch(server))):
            return None, "a mark is malformed"
        marks[label] = Mark(label, cause["tool"], cause["time"], server)
    return _GroupRun(run, instance, started, tuple(members), marks), ""
