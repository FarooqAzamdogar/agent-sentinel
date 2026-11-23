"""Reading an audit log: bounded line reads, records, times and filters.

Used by the `report`, `explain` and `suggest` commands. An audit log is a
plain file that anyone with access to it can edit, and its records hold text
chosen by the agent and by the server, so nothing read here is trusted:

  * lines are read with a size limit (MAX_LINE_BYTES). A longer line is
    skipped and counted as unreadable, so one hostile line cannot fill memory;
  * a record is any JSON object, and its fields may hold any type. Callers
    read a field with `text_of` or `field_text`, never by assuming a type;
  * everything shown to a person goes through `printable`;
  * the log may be written while it is read. A reader that finds it cut or
    rotated under it (--audit-max-bytes copies the log aside and empties it)
    has read part of an older file: it reads again from the start rather than
    report on that (iter_whole_file, read_again_if_changed). On Windows a
    writer's lock makes the start of the file unreadable for a moment: the
    read waits for it, up to LOCKED_READ_SECONDS.

A record, as firewall.py writes it, looks like this (keys in this order, the
ones in brackets only when they apply):

    time, [server], session, event, tool, [call_id], action, [rule],
    [matched_arg], [ref], [policy], reason, [redacted], [approval], [args],
    [findings], seq, prev, hash, [mac]

"policy" (blocks only) is the start of the policy's SHA-256. The last four
are the integrity chain (audit_chain.py), on every record since 0.6.

Some records are not about a call or a check (META_EVENTS, all with action
"note" and no tool): "chain_start" starts a chain (a new or rotated file),
and "session_start", "protocol" and "session_end" say who wrote what follows
(the version, the policy's hash, the peers' names). `report` leaves them out
of its counts.
"""

from __future__ import annotations

import errno
import json
import os
import re
import stat
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, BinaryIO, Callable, Iterator, TypeVar

from .filelock import lock_file, unlock_file
from .jsonutil import bounded_int
from .policy import glob_matches
from .policy_errors import quoted
from .textutil import printable

# Longer than any record the firewall writes: arguments are left out of a record
# past 100,000 characters, and even with every character escaped that stays far below.
MAX_LINE_BYTES = 4 * 1024 * 1024
# How much of the start of a log a reader remembers, to tell at the end whether what it read is still
# that file: a rotation starts the log again with another first record.
HEAD_BYTES = 4096
# How many times in all a log is read from its start when it is cut or rotated during the read.
READ_ATTEMPTS = 3
# How long a read waits for a writer that holds the log's lock. Only Windows refuses to read a locked
# byte; a writer holds the lock for one append, or for the copy a rotation makes.
LOCKED_READ_SECONDS = 5.0

_Read = TypeVar("_Read")

BLOCK_ACTIONS = ("block", "would_block")
# The "action" of an audit record (not policy.ACTIONS, which are what a rule may say): "note" is a
# record that blocks nothing (Firewall.note), "would_block" a block that monitor mode let through.
RECORD_ACTIONS = ("allow", "ask", "block", "would_block", "note")
# The events of the records that are not a call or a check (see above).
CHAIN_START = "chain_start"
SESSION_START = "session_start"
PROTOCOL = "protocol"
SESSION_END = "session_end"
META_EVENTS = frozenset({CHAIN_START, SESSION_START, PROTOCOL, SESSION_END})

_RELATIVE_TIME = re.compile(r"([0-9]{1,6})\s*([mhdw])")
_UNITS = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
# The only ways a time is read, on every Python version: a date (2026-11-18), or a date and a
# time of day (2026-11-18T14:30, 2026-11-18 14:30:05.5), with a zone or not (Z, z, +05:00).
# datetime.fromisoformat is not used: Python 3.11 and later accept far more (20261118,
# 2026-W47-3) than 3.10, so the same command line would mean something on one and fail on the other.
_TIMESTAMP = re.compile(
    r"(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})"
    r"(?:[Tt ](?P<clock>[0-9]{2}:[0-9]{2})(?::(?P<seconds>[0-9]{2})(?:\.(?P<fraction>[0-9]{1,6}))?)?"
    r"(?P<zone>[Zz]|[+-][0-9]{2}:[0-9]{2})?)?"
)


# ---- lines and records ---------------------------------------------------------------

def iter_lines(handle: BinaryIO, limit: int = MAX_LINE_BYTES) -> Iterator[bytes | None]:
    """Yield each line of a binary file; None in place of a line longer than `limit` bytes, which is skipped."""
    while True:
        line = handle.readline(limit + 1)
        if not line:
            return
        if len(line) > limit and not line.endswith(b"\n"):
            _skip_rest_of_line(handle)
            yield None
        else:
            yield line


def _skip_rest_of_line(handle: BinaryIO) -> None:
    while True:
        chunk = handle.readline(65536)
        if not chunk or chunk.endswith(b"\n"):
            return


class LogChangedError(OSError):
    """The log was cut or rotated while it was read: what was read is part of a file that is no longer the log."""


def _changed(path: str) -> LogChangedError:
    return LogChangedError(
        errno.EAGAIN, "the log changed while it was read (rotated, cut, or a record half written), run the command "
                      "again; after a rotation the log has one more file (FILE.N)", str(path))


def _despite_lock(read: Callable[[], bytes], path: str) -> bytes:
    """What `read` returns, tried again for LOCKED_READ_SECONDS while a writer's lock refuses it (Windows).

    Only a read is tried again, never an open: a file this user may not read
    is refused at once. PermissionError, naming the lock, when the wait is over.
    """
    deadline = time.monotonic() + LOCKED_READ_SECONDS
    pause = 0.001
    while True:
        try:
            return read()
        except PermissionError as exc:
            if time.monotonic() >= deadline:
                raise PermissionError(
                    exc.errno, f"a writer held the log's lock for {LOCKED_READ_SECONDS:g} seconds, so it could not "
                               "be read (Permission denied); try again", str(path)) from None
        time.sleep(pause)
        pause = min(pause * 2, 0.05)


def file_head(path: str) -> bytes | None:
    """The first bytes of the file at `path` (HEAD_BYTES at most; fewer from a shorter file). Raises OSError.

    None for anything but a regular file, which is not opened here: what is
    read from a pipe (`audit verify <(zcat FILE.1.gz) FILE`) is gone, and
    nobody rotates a pipe.
    """
    if not stat.S_ISREG(os.stat(path).st_mode):
        return None
    with open(path, "rb") as handle:
        return _despite_lock(lambda: handle.peek(1), path)[:HEAD_BYTES]


def iter_whole_file(path: str, known_head: bytes | None = None) -> Iterator[bytes | None]:
    """iter_lines over the file at `path`; LogChangedError at the end if it was cut or rotated meanwhile.

    A rotation empties the log in place and starts it again, so a reader that
    was part-way through gets the end of the file in the middle of a line, or
    the middle of the new file: neither is what the log holds. It shows in
    two ways, both looked at once the last line was read: the file is shorter
    than what was read, or it no longer starts with the bytes it started with.
    A third case is a reader that reaches the end while a record is being
    appended and gets half of it: when the last line has no newline, the size
    is looked at again under the writers' lock (_grew_since).
    known_head: the start of the file as it was when the caller first looked
    (file_head); the file must still start with it when it is opened here.
    Raises OSError if the file cannot be opened or read.
    """
    with open(path, "rb") as handle:
        if not handle.seekable():  # a pipe: nobody rotates it, and its start cannot be looked at twice
            yield from iter_lines(handle)
            return
        # One read of the start of the file, kept in the handle's buffer: the lines below begin there.
        head = _despite_lock(lambda: handle.peek(1), path)[:HEAD_BYTES]
        if known_head is not None and not head.startswith(known_head):
            raise _changed(path)
        last: bytes | None = b"\n"
        for last in iter_lines(handle):
            yield last
        read = handle.tell()
        if os.fstat(handle.fileno()).st_size < read:
            raise _changed(path)
        if last is not None and not last.endswith(b"\n") and _grew_since(path, read):
            raise _changed(path)
        handle.seek(0)
        if _despite_lock(lambda: handle.read(len(head)), path) != head:
            raise _changed(path)


def _grew_since(path: str, read: int) -> bool:
    """Whether the file is longer than the `read` bytes a reader got, looked at while no writer is appending.

    For a last line without a newline: either a writer was in the middle of
    appending it (the file is longer once that writer is done), or a write
    was cut short long ago and the line is damage to report. The size is
    read under the lock every writer appends under (audit_chain.append_chained).
    False when the lock cannot be had in LOCKED_READ_SECONDS: the line is
    then judged as it was read.
    """
    try:
        with open(path, "rb", buffering=0) as handle:
            lock_file(handle, timeout=LOCKED_READ_SECONDS)
            try:
                return os.fstat(handle.fileno()).st_size > read
            finally:
                unlock_file(handle)
    except OSError:
        return False


def read_again_if_changed(read: Callable[[], _Read]) -> _Read:
    """What `read` returns; it is called again when it raises LogChangedError, READ_ATTEMPTS times in all.

    read: reads a log from its start and keeps nothing from an earlier call.
    The last LogChangedError is raised when every attempt found the log changed.
    """
    for _ in range(READ_ATTEMPTS - 1):
        try:
            return read()
        except LogChangedError:
            pass
    return read()


def parse_record(line: bytes) -> dict[str, Any] | None:
    """The record on one line of the log, or None if the line is not a JSON object.

    A number of thousands of digits makes the line unreadable rather than slow
    to read (Python 3.11 and later refuse such numbers anyway).
    """
    try:
        record = json.loads(line.decode("utf-8", errors="replace"), parse_int=bounded_int)
    except (ValueError, RecursionError):  # not JSON, nested absurdly deep, or a huge number
        return None
    return record if isinstance(record, dict) else None


def iter_records(
    path: str, on_line: Callable[[bytes | None], dict[str, Any] | None] | None = None
) -> Iterator[dict[str, Any] | None]:
    """Yield each record of the log at `path`, in order; None for each line that cannot be read.

    Blank lines are skipped. Raises OSError if the file cannot be opened, and
    LogChangedError (an OSError) after the last record when the log was cut
    or rotated while it was read: what was yielded is then no account of the
    log, and the caller reads it again (read_again_if_changed).
    on_line: called with every line as it was read (blank ones too), before
    its record is yielded: for a check of the chain in the same pass
    (audit_chain.ChainChecker.add). When it returns a record, that record is
    yielded rather than reading the line a second time; it must be the record
    parse_record gives for the line (None: the line is read here).
    """
    for line in iter_whole_file(path):
        record = on_line(line) if on_line is not None else None
        if line is None:
            yield None
        elif line.strip():
            yield record if record is not None else parse_record(line)


def follow_records(
    path: str, *, stop: Callable[[], bool], sleep: Callable[[float], None], poll_seconds: float = 0.5
) -> Iterator[dict[str, Any] | None]:
    """Yield the records added to the log from now on, until `stop()` is true; None for an unreadable line.

    Like `tail -f`, but each line is read with the same size limit as above:
    a line that grows past MAX_LINE_BYTES without ending is dropped. A line
    still being written (no newline yet) is held back until it is complete.
    When the file becomes shorter than what was read (it was cut or replaced),
    reading starts again from its beginning.
    """
    handle = open(path, "rb")
    try:
        handle.seek(0, os.SEEK_END)
        pending = b""
        skipping = False  # inside a line that was too long, until its newline
        while not stop():
            # After a cut the read starts at the first byte again, which a writer's lock covers (Windows).
            chunk = _despite_lock(lambda: handle.readline(MAX_LINE_BYTES + 1 - len(pending)), path)
            if chunk:
                if skipping:
                    skipping = not chunk.endswith(b"\n")
                    continue
                pending += chunk
                if pending.endswith(b"\n"):
                    line, pending = pending, b""
                    if line.strip():
                        yield parse_record(line)
                elif len(pending) > MAX_LINE_BYTES:
                    pending, skipping = b"", True
                    yield None
                continue
            if _was_cut(path, handle.tell()):
                handle.close()
                handle = open(path, "rb")
                pending, skipping = b"", False
                continue
            sleep(poll_seconds)
    finally:
        handle.close()


def _was_cut(path: str, position: int) -> bool:
    try:
        return os.path.getsize(path) < position
    except OSError:  # gone for a moment (being replaced): look again later
        return False


# ---- fields ---------------------------------------------------------------------------

def text_of(record: dict[str, Any], name: str) -> str | None:
    """The field if it is text, else None. For comparing and grouping, never for printing as it is."""
    value = record.get(name)
    return value if isinstance(value, str) else None


def field_text(record: dict[str, Any], name: str, limit: int = 200, missing: str = "?") -> str:
    """A field ready to print: any type, shortened and made printable; `missing` if it is absent."""
    if name not in record:
        return missing
    return printable(record[name], limit=limit)


def is_block(record: dict[str, Any]) -> bool:
    return record.get("action") in BLOCK_ACTIONS


def is_meta(record: dict[str, Any]) -> bool:
    """Whether the record starts a chain or describes the session, rather than a call or a check (META_EVENTS).

    The event is read as text first: a line may hold any JSON there, and an
    object or a list cannot be looked up in a set.
    """
    event = record.get("event")
    return isinstance(event, str) and event in META_EVENTS and record.get("action") == "note"


def parse_timestamp(text: str) -> tuple[datetime, bool] | None:
    """(the time, whether it is a plain date) for a text _TIMESTAMP accepts; None for any other text.

    A time written without a zone comes back without one (naive): what that
    means is the caller's choice (UTC in a record, local time on a command line).
    """
    found = _TIMESTAMP.fullmatch(text)
    if found is None:
        return None
    year, month, day = (int(part) for part in found["date"].split("-"))
    hour = minute = second = microsecond = 0
    if found["clock"] is not None:
        hour, minute = (int(part) for part in found["clock"].split(":"))
        second = int(found["seconds"] or 0)
        microsecond = int((found["fraction"] or "0").ljust(6, "0"))
    try:
        zone = _zone(found["zone"])
        return datetime(year, month, day, hour, minute, second, microsecond, tzinfo=zone), found["clock"] is None
    except ValueError:  # month 13, hour 25, an offset of a day or more
        return None


def _zone(text: str | None) -> timezone | None:
    if text is None:
        return None
    if text in ("Z", "z"):
        return timezone.utc
    offset = timedelta(hours=int(text[1:3]), minutes=int(text[4:6]))
    return timezone(-offset if text[0] == "-" else offset)


def record_time(record: dict[str, Any]) -> datetime | None:
    """When the record was written, or None if its "time" cannot be read. A time without a zone is UTC."""
    text = text_of(record, "time")
    parsed = parse_timestamp(text) if text is not None and len(text) <= 64 else None
    if parsed is None:
        return None
    when = parsed[0]
    return when if when.tzinfo is not None else when.replace(tzinfo=timezone.utc)


def clock_time(record: dict[str, Any]) -> str:
    """The record's time of day in local time ("20:46:26"), for a live view; the raw field if it cannot be read."""
    when = record_time(record)
    if when is None:
        return field_text(record, "time", limit=32)
    try:
        return when.astimezone().strftime("%H:%M:%S")
    except (OverflowError, OSError, ValueError):  # a time at the edge of what the clock can show
        return field_text(record, "time", limit=32)


def parse_when(text: str, now: datetime | None = None, end_of_day: bool = False) -> datetime:
    """Read a --since or --until value: "30m", "2h", "7d", "1w" ago, or a date or time such as
    "2026-11-18" or "2026-11-18T14:30". A date or time without a zone is local time.

    end_of_day: a plain date means the end of that day, not its start (for --until).
    Raises ValueError with a message for the person who typed it.
    """
    now = now or datetime.now(timezone.utc)
    spelled = text.strip()
    relative = _RELATIVE_TIME.fullmatch(spelled.lower())
    if relative:
        amount, unit = int(relative.group(1)), _UNITS[relative.group(2)]
        try:
            return now - timedelta(**{unit: amount})
        except OverflowError:
            raise ValueError(f"{quoted(spelled, limit=40)} reaches back before the year 1") from None
    if len(spelled) > 40:
        raise ValueError("a time is at most 40 characters")
    parsed = parse_timestamp(spelled)
    if parsed is None:
        raise ValueError(
            f"cannot read {quoted(spelled, limit=40)} as a time: write a number with m, h, d or w "
            "(for example 2h), or a date such as 2026-11-18 or 2026-11-18T14:30"
        )
    when, plain_date = parsed
    try:
        if end_of_day and plain_date:
            when += timedelta(days=1)
        return when if when.tzinfo is not None else when.astimezone()  # a time without a zone is the local time
    except (OverflowError, OSError, ValueError):  # a date at the very edge of what the clock can show
        raise ValueError(f"{quoted(spelled, limit=40)} is too far from today to compare with") from None


# ---- names with wildcards ----------------------------------------------------------------

# glob_matches (imported above) is the policy's own rule for tool names: only "*" is special, and
# plain string search, so a long hostile name cannot make it slow.


# ---- filters -----------------------------------------------------------------------------

@dataclass(frozen=True)
class RecordFilter:
    """Which records a command looks at. An empty filter takes every record.

    tool:    a name in which "*" stands for anything ("read_*")
    servers, actions, events: a record must have one of these (when any are given)
    since, until: the record's time must be in this range; a record whose time
             cannot be read is left out when either is set (see `matches`)
    """

    tool: str | None = None
    servers: tuple[str, ...] = ()
    actions: tuple[str, ...] = ()
    events: tuple[str, ...] = ()
    since: datetime | None = None
    until: datetime | None = None

    @property
    def active(self) -> bool:
        return any((self.tool is not None, self.servers, self.actions, self.events, self.since, self.until))

    @property
    def needs_time(self) -> bool:
        return self.since is not None or self.until is not None

    def matches(self, record: dict[str, Any]) -> bool:
        if self.tool is not None:
            tool = text_of(record, "tool")
            if tool is None or not glob_matches(self.tool, tool):
                return False
        for wanted, name in ((self.servers, "server"), (self.actions, "action"), (self.events, "event")):
            if wanted and text_of(record, name) not in wanted:
                return False
        if self.needs_time:
            when = record_time(record)
            if when is None:
                return False
            if self.since is not None and when < self.since:
                return False
            if self.until is not None and when > self.until:
                return False
        return True

    def describe(self) -> str:
        """The filter in words, for the top of a report."""
        parts = []
        if self.tool is not None:
            parts.append(f"tool {printable(self.tool, limit=80)}")
        for wanted, name in ((self.servers, "server"), (self.actions, "action"), (self.events, "event")):
            if wanted:
                parts.append(f"{name} {' or '.join(printable(value, limit=60) for value in wanted)}")
        if self.since is not None:
            parts.append(f"since {self.since.isoformat(timespec='seconds')}")
        if self.until is not None:
            parts.append(f"until {self.until.isoformat(timespec='seconds')}")
        return ", ".join(parts)
