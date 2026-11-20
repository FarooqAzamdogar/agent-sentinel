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

The file store fails closed. A session file that is missing, unreadable,
malformed, written for another session, or that has lost marks this process
saw counts as "every mark set", so every flow rule applies. Anyone who can
write the folder can still rewrite the file consistently: keep it outside
every folder the agent's tools can reach.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Iterator, Mapping

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
MAX_SESSION_ID_CHARS = 256
MAX_STATE_FILE_BYTES = 256 * 1024

FILE_FORMAT = "agent-sentinel-session"
FILE_VERSION = 1
LOCK_FILE_NAME = "sessions.lock"

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
            make_private_folder(self.directory)  # owner-only, the missing folders above it too
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


