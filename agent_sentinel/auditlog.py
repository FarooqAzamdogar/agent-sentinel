"""Reading an audit log: bounded line reads, records, times and filters.

Used by the `report`, `explain` and `suggest` commands. An audit log is a
plain file that anyone with access to it can edit, and its records hold text
chosen by the agent and by the server, so nothing read here is trusted:

  * lines are read with a size limit (MAX_LINE_BYTES). A longer line is
    skipped and counted as unreadable, so one hostile line cannot fill memory;
  * a record is any JSON object, and its fields may hold any type. Callers
    read a field with `text_of` or `field_text`, never by assuming a type;
  * everything shown to a person goes through `printable`.

A record, as firewall.py writes it, looks like this (keys in this order, the
ones in brackets only when they apply):

    time, [server], session, event, tool, [call_id], action, [rule],
    [matched_arg], [ref], reason, [args], [findings]
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, BinaryIO, Callable, Iterator

from .cli_common import bounded_int
from .policy_errors import quoted
from .textutil import printable

# Longer than any record the firewall writes: arguments are left out of a record
# past 100,000 characters, and even with every character escaped that stays far below.
MAX_LINE_BYTES = 4 * 1024 * 1024

BLOCK_ACTIONS = ("block", "would_block")
ACTIONS = ("allow", "ask", "block", "would_block")

_RELATIVE_TIME = re.compile(r"([0-9]{1,6})\s*([mhdw])")
_PLAIN_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_UNITS = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


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


def iter_records(path: str) -> Iterator[dict[str, Any] | None]:
    """Yield each record of the log at `path`, in order; None for each line that cannot be read.

    Blank lines are skipped. Raises OSError if the file cannot be opened.
    """
    with open(path, "rb") as handle:
        for line in iter_lines(handle):
            if line is None:
                yield None
            elif line.strip():
                yield parse_record(line)


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
            chunk = handle.readline(MAX_LINE_BYTES + 1 - len(pending))
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


def record_time(record: dict[str, Any]) -> datetime | None:
    """When the record was written, or None if its "time" cannot be read. A time without a zone is UTC."""
    text = text_of(record, "time")
    if text is None or len(text) > 64:
        return None
    try:
        when = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError:
        return None
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
    try:
        when = datetime.fromisoformat(spelled[:-1] + "+00:00" if spelled.endswith(("Z", "z")) else spelled)
    except ValueError:
        raise ValueError(
            f"cannot read {quoted(spelled, limit=40)} as a time: write a number with m, h, d or w "
            "(for example 2h), or a date such as 2026-11-18 or 2026-11-18T14:30"
        ) from None
    try:
        if end_of_day and _PLAIN_DATE.fullmatch(spelled):
            when += timedelta(days=1)
        return when if when.tzinfo is not None else when.astimezone()  # a time without a zone is the local time
    except (OverflowError, OSError, ValueError):  # a date at the very edge of what the clock can show
        raise ValueError(f"{quoted(spelled, limit=40)} is too far from today to compare with") from None


# ---- names with wildcards ----------------------------------------------------------------

def glob_matches(pattern: str, text: str) -> bool:
    """True if `text` matches `pattern`, in which only "*" is special (anything, or nothing). Case matters.

    The same rule as tool names in a policy. Plain string search, so a long
    hostile name cannot make it slow.
    """
    pieces = pattern.split("*")
    if len(pieces) == 1:
        return text == pattern
    first, last = pieces[0], pieces[-1]
    if len(text) < len(first) + len(last) or not text.startswith(first) or not text.endswith(last):
        return False
    position, end = len(first), len(text) - len(last)
    for piece in pieces[1:-1]:
        found = text.find(piece, position, end)
        if found < 0:
            return False
        position = found + len(piece)
    return True


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
