"""The audit log's integrity chain: how records are linked when they are written, and how a log is checked.

Every line the firewall appends ends with chain fields, written in this order:

    {..., "seq": 41, "prev": "<64 hex>", "hash": "<64 hex>", "mac": "<64 hex>"}

  seq    the record's number in the chain: one more than the record before it
  prev   the `hash` of the record before it (64 zeros for the first record of a chain)
  hash   SHA-256 of this line as it was before "hash" and "mac" were added: the
         line up to and including "prev", closed with "}"
  mac    only with a key: HMAC-SHA256 of the same bytes under the key

So editing a record changes its hash; removing, inserting or moving one
breaks the link (`prev`) of the record after it, or the order of `seq`.
`hash` lets the next writer link to a record by reading only the end of
the file (TAIL_BYTES, a bounded seek from the end), however long the
record is.

A chain starts with a "chain_start" record ("start" says why):

  new      the first record of a new file (prev is 64 zeros, seq 0);
  rotated  the first record of the file after rotation (--audit-max-bytes):
           it continues the chain of the file that was moved aside (FILE.1,
           FILE.2, ...), whose name it gives in "previous_file". When that
           file's last line could not be linked to, it starts a chain of its
           own (seq 0) and names the last chained record found in the end of
           that file, as a restart does ("after_seq", "after_hash", "scanned");
  restart  the last line of the log could not be linked to (damaged, cut
           short, or written by agent-sentinel 0.5 or earlier), or this
           process may append to the log but not read it: a new chain starts
           after it, rather than failing every call. It names the last
           chained record found in the end of the log ("after_seq" and
           "after_hash", or null when there is none in the "scanned" bytes;
           "scanned" is 0 when the log could not be read), so that records
           removed before it are still found.

What the chain can and cannot show (also in SECURITY.md):

  * without a key it detects naive edits only: anyone who can write the
    file can work out every hash again;
  * a key detects any change, but only if the agent's tools cannot read it;
  * records cut from the end of the log are not detected by either: keep
    the last seq and hash somewhere else (`audit verify` prints them);
  * lines without chain fields at the start of a log (agent-sentinel 0.5 or
    earlier wrote them, or they replace records that were removed) cannot
    be checked: a log that has them is only "partly" checked.

`append_chained` writes; `ChainChecker` checks (`agent-sentinel audit verify`,
and the one-line state that `report` and `explain` print). Provenance helpers
for the session records (session_start, protocol, session_end) are at the end.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import re
import socket
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Callable, Sequence

from .auditlog import CHAIN_START, PROTOCOL, SESSION_END, SESSION_START, iter_lines, parse_record  # noqa: F401
from .auditlog import file_head, iter_whole_file, read_again_if_changed
from .filelock import lock_file, unlock_file
from .jsonutil import loads as strict_json
from .textutil import printable

NEW, ROTATED, RESTART = "new", "rotated", "restart"
CHAIN_FORMAT = 1  # "chain" in a chain_start record: the version of this format

GENESIS = "0" * 64  # `prev` of the first record of a new chain
CHAIN_FIELDS = frozenset({"seq", "prev", "hash", "mac"})  # added to a line when it is written: no record may have them
# How much of the end of the log is read to find the last record's chain fields. The fields
# are the last ~300 bytes of a line, so this is plenty; the read never goes past it.
TAIL_BYTES = 4096
# When a chain restarts, how much of the end of the log is searched for the last chained record (the
# restart names it, so that records removed before the restart are still found).
RESTART_SCAN_BYTES = 64 * 1024
# The size of a chunk when a log is copied aside on rotation.
COPY_CHUNK_BYTES = 1024 * 1024
# --audit-max-bytes: the smallest and largest size a log may grow to before it is rotated. The smallest
# holds about a hundred records; the largest bounds the copy made under the lock at each rotation (other
# writers wait for it: on Windows they give up after filelock.LOCK_TIMEOUT_SECONDS).
MIN_MAX_BYTES = 64 * 1024
MAX_MAX_BYTES = 256 * 1024 * 1024
# Rotated files are FILE.1, FILE.2, ... up to this number. Past it, the log is not rotated (it keeps growing).
MAX_ROTATED_FILES = 10_000
# A rotation lists the log's folder once to find the highest FILE.N; in a folder with more entries than
# this, the log is not rotated.
MAX_LISTED_ENTRIES = 100_000
# How many numbers after the highest one a rotation tries (each is created with O_EXCL) before giving up.
ROTATE_ATTEMPTS = 8
# After a rotation fails, or no number is free, this process appends without rotating for this long.
ROTATION_RETRY_SECONDS = 60.0
# A log is rotated only once it is at least this many times the size of the record that would take it past
# --audit-max-bytes: a record near or above that size (arguments may be 100,000 characters) never gets a
# rotated file of its own, so records cannot use up the rotation numbers, or make a copy, one at a time.
ROTATE_MIN_RECORDS = 4
_MAX_PAUSED_LOGS = 64
# A key file: 16 bytes at the least (128 bits), and small.
MIN_KEY_BYTES = 16
MAX_KEY_FILE_BYTES = 1024
_KEY_ID_LABEL = b"agent-sentinel audit key id"
# How many problems a check keeps the text of (all of them are counted).
MAX_PROBLEMS_KEPT = 20

# The largest seq the chain fields hold: 18 digits (_TRAILER). The writer never links to a line whose seq
# leaves no room for the records after it (see _read_tail), so it never writes a seq it could not read back.
MAX_SEQ = 10**18 - 1

_HEX64 = rb"[0-9a-f]{64}"
# The chain fields at the end of a line: rfind(_TRAILER_START) finds where they begin.
_TRAILER_START = b', "seq": '
_TRAILER = re.compile(
    rb', "seq": (?P<seq>0|[1-9][0-9]{0,17}), "prev": "(?P<prev>' + _HEX64 + rb')"'
    rb', "hash": "(?P<hash>' + _HEX64 + rb')"(?:, "mac": "(?P<mac>' + _HEX64 + rb')")?\}'
)


class AuditKeyError(ValueError):
    """An audit key file that cannot be used. The message never holds the key, nor the file's path."""


# ---- the key --------------------------------------------------------------------------------------

def read_key_file(path: str | Path) -> bytes:
    """The key in an audit key file, for the records' MACs. AuditKeyError when it cannot be used.

    The key is the file's bytes, without a line ending at the end (so that
    `openssl rand -hex 32 > key` works), and must be 16 to 1024 bytes. On
    POSIX the file must be readable and writable by its owner only (0600 or
    0400): a key others can read lets them sign records too.

    Anything but a regular file is refused before it is opened, and the open
    does not wait (O_NONBLOCK): a named pipe in its place cannot hang the start.
    """
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            raise AuditKeyError("the audit key file is not a regular file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    except OSError as exc:
        raise AuditKeyError(f"the audit key file cannot be opened ({exc.strerror or type(exc).__name__})") from None
    with open(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise AuditKeyError("the audit key file is not a regular file")
        if sys.platform != "win32" and info.st_mode & 0o077:
            raise AuditKeyError(
                f"the audit key file can be read or written by other users (mode {stat.S_IMODE(info.st_mode):04o}); "
                "make it owner-only: chmod 600"
            )
        data = handle.read(MAX_KEY_FILE_BYTES + 1)
    if len(data) > MAX_KEY_FILE_BYTES:
        raise AuditKeyError(f"the audit key file is larger than {MAX_KEY_FILE_BYTES} bytes")
    key = data[:-2] if data.endswith(b"\r\n") else data[:-1] if data.endswith(b"\n") else data
    if len(key) < MIN_KEY_BYTES:
        raise AuditKeyError(f"the audit key is shorter than {MIN_KEY_BYTES} bytes")
    return key


def key_id(key: bytes) -> str:
    """A short name for a key, written into chain_start records: it tells the keys apart and reveals nothing of one."""
    return hmac.new(key, _KEY_ID_LABEL, hashlib.sha256).hexdigest()[:16]


def parse_max_bytes(text: str) -> int:
    """--audit-max-bytes: a whole number of bytes from MIN_MAX_BYTES to MAX_MAX_BYTES. ValueError otherwise."""
    if not text.isdigit() or len(text) > 16:
        raise ValueError("must be a whole number of bytes")
    return checked_max_bytes(int(text))


def checked_max_bytes(value: Any) -> int | None:
    """The size past which a log is rotated (None: never). ValueError for anything else than a whole number in range."""
    if value is None:
        return None
    if type(value) is not int or not MIN_MAX_BYTES <= value <= MAX_MAX_BYTES:
        raise ValueError(f"must be a whole number of bytes from {MIN_MAX_BYTES} to {MAX_MAX_BYTES}")
    return value


# ---- writing --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class _Tail:
    """What the end of the log says: the last record's seq and hash, or why it cannot be linked to."""

    seq: int | None = None
    digest: str | None = None
    problem: str | None = None
    unterminated: bool = False  # the file does not end with a newline: one is written first


def append_chained(
    path: Path,
    line: str,
    start_line: Callable[[dict[str, Any]], str],
    key: bytes | None = None,
    max_bytes: int | None = None,
) -> None:
    """Append one record to the log at `path`, linked to the record before it. Raises OSError.

    line:       the record as one line of JSON, without its chain fields (a JSON object, so ending in "}").
    start_line: makes the line of a chain_start record from its fields ("start", "reason", ...),
                for when one is needed (see the module docstring).
    key:        the key of the MACs, or None for no MAC.
    max_bytes:  rotate the log first when this record would take it past this size (see _should_rotate).

    Everything happens under the operating-system lock on the log, so the
    processes that share it (proxies, hook processes) never overwrite each
    other's records (on Windows an append is "seek to the end, then write")
    and never link two records to the same one. The lock is held by the one
    handle that reads the end and appends: on Windows a locked byte cannot be
    read through another handle. A new log is created readable by its owner
    only (0600 on POSIX).

    A log this process may append to but not read (an append-only ACL, mode
    0200) is still written, as before 0.6: each record then starts a chain of
    its own (a restart that says the log could not be read), and the log is
    not rotated.
    """
    handle, readable = _open_log(path)
    with handle:
        lock_file(handle)
        try:
            size = handle.seek(0, os.SEEK_END)
            tail = _read_tail(handle, size) if readable else _UNREAD if size else _Tail()
            start: dict[str, Any] | None = None
            if readable and max_bytes is not None and _should_rotate(size, len(line) + 400, max_bytes):
                # Looked for before the log is emptied: a chain that cannot continue the file names the last
                # chained record in its end, as a restart does, so that records removed from it are found.
                unlinked = _last_link(handle, size) if tail.problem is not None else {}
                rotated = _rotate(handle, path, size)
                if rotated is not None:
                    size = 0
                    start = {"start": ROTATED, "reason": f"the log was rotated: the records before are in {rotated}",
                             "previous_file": rotated, **unlinked}
            if start is None and size == 0:
                start = {"start": NEW, "reason": "a new audit log"}
            elif start is None and tail.problem is not None:
                start = {"start": RESTART, "reason": f"a new chain starts: {tail.problem}",
                         **(_last_link(handle, size) if readable else _NO_LINK)}
            # An incomplete last line is ended first, so that the records after it start lines of their own.
            pieces = [b"\n"] if size > 0 and tail.unterminated else []
            if start is None:
                assert tail.seq is not None and tail.digest is not None
                seq, prev = tail.seq + 1, tail.digest
            else:
                linked = start["start"] == ROTATED and tail.problem is None and tail.digest is not None
                seq, prev = (tail.seq + 1, tail.digest) if linked and tail.seq is not None else (0, GENESIS)
                start["chain"] = CHAIN_FORMAT
                if key is not None:
                    start["key_id"] = key_id(key)
                chained, prev = chained_line(start_line(start), seq, prev, key)
                pieces.append(chained)
                seq += 1
            pieces.append(chained_line(line, seq, prev, key)[0])
            handle.seek(0, os.SEEK_END)
            _write_all(handle, b"".join(pieces))
        finally:
            unlock_file(handle)


def chained_line(line: str, seq: int, prev: str, key: bytes | None) -> tuple[bytes, str]:
    """A record's line with its chain fields, as bytes ending in a newline, and its hash."""
    if not line.endswith("}"):
        raise ValueError("an audit record must be a JSON object")
    body = (line[:-1] + f', "seq": {seq}, "prev": "{prev}"}}').encode("utf-8", errors="backslashreplace")
    digest = hashlib.sha256(body).hexdigest()
    trailer = f', "hash": "{digest}"'
    if key is not None:
        trailer += f', "mac": "{hmac.new(key, body, hashlib.sha256).hexdigest()}"'
    return body[:-1] + trailer.encode("ascii") + b"}\n", digest


def _open_log(path: Path) -> tuple[BinaryIO, bool]:
    """The log, opened to append, and whether it can be read too. Created if missing, owner-only (0600 on POSIX).

    When reading is refused (PermissionError), the log is opened to append
    only, as agent-sentinel 0.5 did: the record is written, unlinked.
    """
    common = os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0)
    try:
        descriptor, readable = os.open(path, os.O_RDWR | common, 0o600), True
    except PermissionError:
        descriptor, readable = os.open(path, os.O_WRONLY | common, 0o600), False
    try:
        # Unbuffered: reads and writes go straight to the file.
        return open(descriptor, "a+b" if readable else "ab", buffering=0), readable
    except BaseException:
        os.close(descriptor)
        raise


# The end of a log this process cannot read, and the restart that follows it.
_UNREAD = _Tail(problem="this process may append to the log but not read it (an append-only log), so it cannot "
                        "link to the record before")
_NO_LINK: dict[str, Any] = {"after_seq": None, "after_hash": None, "scanned": 0}


def _last_link(handle: BinaryIO, size: int) -> dict[str, Any]:
    """For a restart: the last chained record in the last RESTART_SCAN_BYTES of the log, and how much was searched.

    Only whole lines are searched (an incomplete last line is left out). A
    record found there must be the last chained record before the restart
    when the log is checked, so a cut of the records before the restart is
    found even though the restart does not link to them.
    """
    begin = max(0, size - RESTART_SCAN_BYTES)
    handle.seek(begin)
    data = _read_exactly(handle, size - begin)
    end = data.rfind(b"\n")
    if end >= 0:
        for line in reversed(data[:end].split(b"\n")):
            found = parse_trailer(line)
            if found is not None:
                return {"after_seq": found.seq, "after_hash": found.digest, "scanned": len(data)}
    return {"after_seq": None, "after_hash": None, "scanned": len(data)}


def _read_tail(handle: BinaryIO, size: int) -> _Tail:
    """The chain fields of the last line, read from at most the last TAIL_BYTES of the file."""
    if size == 0:
        return _Tail()
    start = max(0, size - TAIL_BYTES)
    handle.seek(start)
    data = _read_exactly(handle, size - start)
    if not data.endswith(b"\n"):
        return _Tail(problem="the last line of the log is incomplete (a write was cut short, or the file was edited)",
                     unterminated=True)
    found = parse_trailer(data[:-1])
    if found is None:
        return _Tail(problem="the last line of the log has no chain fields (agent-sentinel 0.5 or earlier wrote it, "
                             "or it is damaged)")
    # Two numbers are kept free after it: a rotation writes a chain_start and then the record.
    if found.seq > MAX_SEQ - 2:
        return _Tail(problem="the last line of the log has a seq at the end of the range, so no record can follow "
                             "it (agent-sentinel did not write it, or it is damaged)")
    return _Tail(seq=found.seq, digest=found.digest)


def _read_exactly(handle: BinaryIO, count: int) -> bytes:
    parts, left = [], count
    while left > 0:
        chunk = handle.read(left)
        if not chunk:
            break
        parts.append(chunk)
        left -= len(chunk)
    return b"".join(parts)


def _write_all(handle: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = handle.write(view)
        if not written:
            raise OSError("the audit log accepted no more bytes")
        view = view[written:]


def _should_rotate(size: int, estimate: int, max_bytes: int) -> bool:
    """Whether a log of `size` bytes is rotated before a record of about `estimate` bytes (with its chain fields).

    Before the record would take it past max_bytes, but only once the log is
    ROTATE_MIN_RECORDS times the record's size: with records that large, the
    log grows past max_bytes (to a few records) before it is rotated.
    """
    return size > 0 and size + estimate > max_bytes and size >= ROTATE_MIN_RECORDS * estimate


# Logs this process does not try to rotate for a while (see ROTATION_RETRY_SECONDS): path -> time.monotonic() deadline.
_rotation_paused: dict[str, float] = {}


def _rotate(handle: BinaryIO, path: Path, size: int) -> str | None:
    """Copy the log to a new FILE.N, then empty it; the name of the copy, or None when it was not rotated.

    Copied, not renamed: another process may hold the log open (Windows
    refuses to rename it then, and on POSIX that process would go on writing
    to the renamed file). Nothing is ever deleted: the copy is complete and
    on disk before the log is emptied, under the lock.

    When no number is free or anything fails, the log is not rotated (it
    grows), and this process does not try again for ROTATION_RETRY_SECONDS:
    a failed rotation is never paid on every append, and never fails one.
    """
    paused = os.path.normcase(os.path.abspath(path))
    now = time.monotonic()
    if _rotation_paused.get(paused, 0.0) > now:
        return None
    rotated = _rotate_now(handle, path, size)
    if rotated is None:
        if len(_rotation_paused) >= _MAX_PAUSED_LOGS:
            _rotation_paused.clear()
        _rotation_paused[paused] = now + ROTATION_RETRY_SECONDS
    return rotated


def _rotate_now(handle: BinaryIO, path: Path, size: int) -> str | None:
    """Copy the log to the first number after the highest FILE.N there is; its name, or None."""
    first = _next_rotated_number(path)
    if first is None:
        return None
    for number in range(first, min(first + ROTATE_ATTEMPTS, MAX_ROTATED_FILES + 1)):
        target = path.with_name(f"{path.name}.{number}")
        try:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        except OSError:  # it exists, it is a folder, it is being deleted, it may not be created: not free
            continue
        return target.name if _copy_aside(handle, descriptor, target, size) else None
    return None


def _next_rotated_number(path: Path) -> int | None:
    """One more than the highest N of the FILE.N beside the log (1 if none), or None when none can be used.

    One listing of the folder, not one attempt per number: the cost does not
    grow with the files already rotated. New numbers keep growing even when
    older rotated files were deleted, so the numbers stay in the order the
    files were written.
    """
    numbers = _rotated_numbers(path)
    if numbers is None:
        return None
    highest = max((int(number) for number in numbers), default=0)
    return highest + 1 if highest < MAX_ROTATED_FILES else None


def _rotated_numbers(path: Path) -> list[str] | None:
    """The N of every FILE.N beside the log, as its name spells it; None when the folder cannot be listed
    (or holds more than MAX_LISTED_ENTRIES entries)."""
    prefix = os.path.normcase(f"{path.name}.")
    found = []
    try:
        with os.scandir(path.parent) as entries:
            for count, entry in enumerate(entries):
                if count >= MAX_LISTED_ENTRIES:
                    return None
                name = os.path.normcase(entry.name)
                if not name.startswith(prefix):
                    continue
                number = name[len(prefix):]
                if number.isascii() and number.isdigit() and len(number) <= 5 and int(number) <= MAX_ROTATED_FILES:
                    found.append(number)
    except OSError:
        return None
    return found


def rotated_files(path: str | Path) -> list[Path]:
    """The files a log was rotated to (FILE.1, FILE.2, ...), oldest first; none when the folder cannot be listed.

    Only the names rotation itself writes (FILE.7, not FILE.007). The log's
    folder is listed once; nothing is opened.
    """
    log = Path(path)
    numbers = _rotated_numbers(log) or []
    return [log.with_name(f"{log.name}.{number}")
            for number in sorted({int(text) for text in numbers if text == str(int(text)) and int(text) >= 1})]


def _copy_aside(handle: BinaryIO, descriptor: int, target: Path, size: int) -> bool:
    """Copy the log's `size` bytes to the new file `target` (open as `descriptor`), on disk, then empty the log.

    If anything fails, the copy is removed (every record is still in the
    log, which was not emptied) and False is returned.
    """
    try:
        with open(descriptor, "wb") as copy:
            handle.seek(0)
            left = size
            while left > 0:
                chunk = handle.read(min(COPY_CHUNK_BYTES, left))
                if not chunk:
                    break
                copy.write(chunk)
                left -= len(chunk)
            copy.flush()
            os.fsync(copy.fileno())
        handle.truncate(0)
        return True
    except OSError:
        try:
            os.remove(target)
        except OSError:
            pass
        return False


# ---- reading the chain fields ------------------------------------------------------------------------

@dataclass(frozen=True)
class Trailer:
    """The chain fields at the end of one line, and the bytes `hash` and `mac` were computed over."""

    seq: int
    prev: str
    digest: str
    mac: str | None
    body: bytes


def parse_trailer(line: bytes) -> Trailer | None:
    """The chain fields at the end of a line (given without its newline), or None if it has none."""
    at = line.rfind(_TRAILER_START)
    if at < 0:
        return None
    found = _TRAILER.fullmatch(line, at)
    if found is None:
        return None
    body = line[: found.end("prev") + 1] + b"}"
    mac = found.group("mac")
    return Trailer(
        int(found.group("seq")), found.group("prev").decode("ascii"), found.group("hash").decode("ascii"),
        mac.decode("ascii") if mac is not None else None, body,
    )


# ---- checking a log ------------------------------------------------------------------------------------

INTACT, PARTIAL, BROKEN, UNCHAINED, EMPTY = "intact", "partial", "broken", "unchained", "empty"
_HEX64_TEXT = re.compile(r"[0-9a-f]{64}")


@dataclass
class ChainReport:
    """What a check of one log (or of several, in order) found.

    state is "partial" when the chain is intact where it can be checked, but
    some lines cannot be linked to it: lines without chain fields at the start
    (`unchained_prefix`), or restarts written by a process that could not read
    the log (`unlinked`). Records removed there would not be detected.
    """

    lines: int = 0
    chained: int = 0
    unchained_prefix: int = 0  # lines without chain fields before the first chained record
    unlinked: int = 0  # restarts after an intact record, by a writer that could not read the log
    first_seq: int | None = None
    last_seq: int | None = None
    last_hash: str | None = None
    problems: list[str] = field(default_factory=list)  # the first MAX_PROBLEMS_KEPT, each "line N: ..."
    problem_count: int = 0
    mac_mismatches: int = 0
    macs_present: int = 0  # chained records that carry a MAC
    key_given: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def state(self) -> str:
        if self.problem_count:  # first: an empty file among several is a problem (ChainChecker.start_file)
            return BROKEN
        if self.lines == 0:
            return EMPTY
        if self.chained == 0:
            return UNCHAINED
        if self.unchained_prefix or self.unlinked:
            return PARTIAL
        return INTACT

    def unchecked(self, short: bool = False) -> str:
        """What a "partial" check could not link to the chain, in words (`short`: without the reasons)."""
        parts = []
        if self.unchained_prefix:
            why = "" if short else (" (agent-sentinel 0.5 or earlier wrote them, or they replace records that "
                                    "were removed)")
            parts.append(f"the first {self.unchained_prefix} line(s) have no chain fields{why}")
        if self.unlinked:
            why = "" if short else " were written by a process that could not read the log, so they"
            parts.append(f"{self.unlinked} restart(s){why} do not link to the record before")
        return "; ".join(parts)

    def one_line(self, command: str) -> str:
        """The state in one short line, for `report` and `explain`. `command` is how to run `audit verify` on the log."""
        state = self.state
        if state == EMPTY:
            return "Integrity: the log is empty."
        if state == UNCHAINED:
            return "Integrity: no hash chain (written by agent-sentinel 0.5 or earlier, or by another program)."
        if state == BROKEN:
            first = self.problems[0] if self.problems else "a problem"
            more = f" (and {self.problem_count - 1} more)" if self.problem_count > 1 else ""
            return f"Integrity: BROKEN at {first}{more}. Details: {command}"
        if state == PARTIAL:
            return (f"Integrity: PARTLY CHECKED: chain intact, seq {self.first_seq} to {self.last_seq}, but "
                    f"{self.unchecked(short=True)}. Details: {command}")
        if self.key_given:
            macs = "every MAC matches the key"
        elif self.macs_present:
            macs = "MACs not checked here (audit verify --key-file checks them)"
        else:
            macs = "no MACs (written without a key)"
        return f"Integrity: hash chain intact, seq {self.first_seq} to {self.last_seq}; {macs}."


class ChainChecker:
    """Checks a log line by line, as it is read: `start_file`, then `add` each raw line, then `finish`.

    Several files (FILE.1, FILE.2, ..., FILE) can be checked as one chain by
    calling start_file before each, oldest first. Then each file must hold
    records, and a rotated file's first record must continue the last record
    of the file given before it: the writer never leaves a rotated file, or
    the log after a rotation, empty. Memory stays bounded: the checker keeps
    the last link and a few problem texts.
    """

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key
        self._key_id = key_id(key) if key is not None else None
        self.report = ChainReport(key_given=key is not None)
        self._previous: Any = None  # None (nothing yet), "unchained", "bad", or (seq, hash) of the last record
        # (seq, hash) of the last line with chain fields, however many lines ago: what a restart names.
        self._last_chained: tuple[int, str] | None = None
        self._seen_chain = False
        self._label = ""
        self._line = 0
        self._files = 0
        self._other_keys: set[str] = set()

    def start_file(self, label: str = "") -> None:
        """Begin the next file; `label` names it in problems when several files are checked."""
        if self._files and self._line == 0:  # the file before this one held nothing
            self._empty_file()
        self._label = label
        self._line = 0
        self._files += 1

    def add(self, raw: bytes | None) -> dict[str, Any] | None:
        """Check one line as the file holds it (with its newline); None for a line too long to read.

        Returns the record the check read from the line (a JSON object), so
        that a reader in the same pass (report, explain) need not read the
        line again: it is the record auditlog.parse_record gives. None when
        the line holds no JSON object, or one that is not strict JSON.
        """
        self._line += 1
        self.report.lines += 1
        at_start = self._line == 1
        if raw is None:
            self._bad("it is too long to read")
            return None
        if not raw.endswith(b"\n"):
            self._bad("it is incomplete: it has no newline at its end (a write was cut short, or the file was edited)")
            return None
        content = raw[:-1]
        carriage_return = content.endswith(b"\r")
        if carriage_return:
            content = content[:-1]
        trailer = parse_trailer(content)
        if trailer is None:
            return self._unchained(content)
        record = self._parsed(content)
        if record is None:
            self._last_chained = (trailer.seq, trailer.digest)  # as the writer saw it when it looked for a link
            return None
        if carriage_return:  # the record is intact, but the file is not as it was written
            self._problem("it ends with a carriage return: a program changed the file's line ends")
        self._check_hash_and_mac(trailer, record)
        self._check_link(trailer, record, at_start)
        self._previous = self._last_chained = (trailer.seq, trailer.digest)
        self._seen_chain = True
        report = self.report
        report.chained += 1
        if report.first_seq is None:
            report.first_seq = trailer.seq
        report.last_seq, report.last_hash = trailer.seq, trailer.digest
        return record

    def finish(self) -> ChainReport:
        if self._files > 1 and self._line == 0:  # the last of several files held nothing
            self._empty_file()
        if self._other_keys:
            self.report.notes.append(
                f"{len(self._other_keys)} chain start(s) name another key (key id "
                f"{', '.join(sorted(self._other_keys)[:3])}): those records were signed with a different key"
            )
        return self.report

    # ---- one line ----

    def _where(self) -> str:
        return f"{self._label} line {self._line}" if self._label else f"line {self._line}"

    def _problem(self, text: str, where: str | None = None) -> None:
        report = self.report
        report.problem_count += 1
        if len(report.problems) < MAX_PROBLEMS_KEPT:
            report.problems.append(f"{where or self._where()}: {text}")

    def _bad(self, text: str) -> None:
        self._problem(text)
        self._previous = "bad"

    def _empty_file(self) -> None:
        """One of several files holds nothing. The writer never leaves a rotated file empty, nor the log after a
        rotation (the rotated chain_start is written at once): its records were removed."""
        self._problem("it is empty, but a rotated file, and the log after a rotation, always hold records: they "
                      "were removed", where=self._label or f"file {self._files}")

    def _unchained(self, content: bytes) -> dict[str, Any] | None:
        record = parse_record(content)
        if record is None:  # not JSON, not an object, absurdly nested, a huge number
            self._bad("it is not a JSON object")
            return None
        if self._seen_chain:
            self._problem("it has no chain fields: it was inserted, or written by agent-sentinel 0.5 or earlier")
        else:
            self.report.unchained_prefix += 1
        self._previous = "unchained"
        return record

    def _parsed(self, content: bytes) -> dict[str, Any] | None:
        """The record on a line with chain fields, read strictly (no repeated keys); None, after a problem, if not."""
        try:
            record = strict_json(content.decode("utf-8"))
        except (ValueError, RecursionError):
            record = None
        if not isinstance(record, dict):
            self._bad("it is not a valid JSON object (or it repeats a key)")
            return None
        return record

    def _check_hash_and_mac(self, trailer: Trailer, record: dict[str, Any]) -> None:
        if not hmac.compare_digest(hashlib.sha256(trailer.body).hexdigest(), trailer.digest):
            self._problem("it was changed after it was written (its hash does not match its content)")
        if trailer.mac is not None:
            self.report.macs_present += 1
        if self._key is None:
            return
        if trailer.mac is None:
            self.report.mac_mismatches += 1
            self._problem("it has no MAC, though a key was given")
        elif not hmac.compare_digest(hmac.new(self._key, trailer.body, hashlib.sha256).hexdigest(), trailer.mac):
            self.report.mac_mismatches += 1
            self._problem("its MAC does not match: it was changed, or signed with another key")
        if record.get("event") == CHAIN_START and isinstance(record.get("key_id"), str):
            if record["key_id"] != self._key_id and len(self._other_keys) < 10:
                self._other_keys.add(printable(record["key_id"], limit=20))

    def _check_link(self, trailer: Trailer, record: dict[str, Any], at_start: bool) -> None:
        previous = self._previous
        if record.get("event") == CHAIN_START:
            self._check_start(trailer, record, at_start, previous)
            return
        if isinstance(previous, tuple):
            self._check_follows(trailer, previous)
        elif previous == "bad":
            pass  # the damaged line before it was reported; the link to it cannot be checked
        elif at_start:
            self._problem("the file does not start with a chain_start record: records before it are missing")
        else:
            self._problem("the start of its chain is missing: the record before it is not a chained record")

    def _check_follows(self, trailer: Trailer, previous: tuple[int, str]) -> None:
        seq, digest = previous
        if trailer.prev == digest and trailer.seq == seq + 1:
            return
        if trailer.seq > seq + 1:
            missing = trailer.seq - seq - 1
            self._problem(f"{missing} record(s) are missing before it (seq {seq + 1} to {trailer.seq - 1})")
        elif trailer.seq <= seq:
            self._problem(f"it is out of order: seq {trailer.seq} after seq {seq} (a record was inserted, repeated "
                          "or moved)")
        else:
            self._problem("it does not link to the record before it: that record was changed or replaced")

    def _check_start(self, trailer: Trailer, record: dict[str, Any], at_start: bool, previous: Any) -> None:
        start = record.get("start")
        fresh = trailer.seq == 0 and trailer.prev == GENESIS
        if start == NEW:
            if not at_start:
                self._problem("a new chain starts in the middle of the file: records before it may have been removed")
            elif isinstance(previous, tuple):
                self._problem("this file starts a new chain instead of continuing the file before it")
            elif not fresh:
                self._problem("a new chain must start at seq 0 with no previous hash")
        elif start == ROTATED:
            self._check_rotated(trailer, record, at_start, previous)
        elif start == RESTART:
            if not fresh:
                self._problem("a restarted chain must start at seq 0 with no previous hash")
            elif at_start:
                self._problem("the file starts with a chain restart: the line before it is missing")
            elif isinstance(previous, tuple):
                if _could_not_read(record):  # a writer that may only append: it did not know the record before
                    self.report.unlinked += 1
                elif previous[0] > MAX_SEQ - 2:
                    # No seq is left after the record before it, so the writer could only start again (_read_tail).
                    # That record did not follow what was before it, and was reported there.
                    self._check_restart_follows(record)
                else:
                    self._problem("a new chain starts although the record before it is intact: records may have "
                                  "been removed here")
            else:
                self._check_restart_follows(record)
        else:
            self._problem("it is a chain_start record of an unknown kind")

    def _check_rotated(self, trailer: Trailer, record: dict[str, Any], at_start: bool, previous: Any) -> None:
        """The first record of a file after rotation continues the last record of the file before it (seq above 0,
        with that record's hash), or starts afresh (seq 0, no previous hash) when that file's end could not be
        linked to (damaged, or written by agent-sentinel 0.5 or earlier)."""
        fresh = trailer.seq == 0 and trailer.prev == GENESIS
        if not at_start:
            self._problem("a rotated file's first record is in the middle of a file")
        elif isinstance(previous, tuple) and not (fresh and previous[0] > MAX_SEQ - 2):
            # (A file that ends in a record at the end of the seq range cannot be continued: the next one starts
            # a chain of its own (_read_tail) and names that record, which is checked below.)
            if trailer.prev != previous[1] or trailer.seq != previous[0] + 1:
                named = record.get("previous_file")
                expected = (f"; it names {printable(named, limit=80)} as the file before it" if isinstance(named, str)
                            and named else "")
                self._problem(f"it does not continue the file before it (whose last record is seq {previous[0]})"
                              f"{expected}: give every file of the log, oldest first (FILE.1 FILE.2 ... FILE)")
        elif fresh and previous is None and self._files == 1:  # the first file given: the older ones were not given
            shown = printable(record.get("previous_file", "an older file"), limit=80)
            self.report.notes.append(
                f"the first file starts a chain of its own after {shown}, whose last line could not be linked to; "
                "that file was not checked: give the older files first, oldest first, to check it too"
            )
        elif fresh and "after_hash" in record:
            # The file before ended in a line that cannot be linked to (unchained, or damaged and reported
            # there): the start names the last chained record its writer found before that line.
            self._check_restart_follows(record, "a rotated file's first record that starts a chain")
        elif fresh or previous == "bad":
            pass  # as above, from a writer that named no record; or it continues a damaged line (reported there)
        elif trailer.seq == 0 or trailer.prev == GENESIS:
            self._problem("a rotated file's first record must continue the chain (seq above 0, with the hash "
                          "before it) or start one (seq 0, no previous hash)")
        elif previous is None and self._files == 1:  # the first file given: the older ones were not given
            shown = printable(record.get("previous_file", "an older file"), limit=80)
            self.report.notes.append(
                f"the first file continues {shown} (seq {trailer.seq - 1} and before), which was not checked: give "
                "the older files first, oldest first, to check the link"
            )
        else:  # the files given before it are empty, or end in lines without chain fields
            self._problem(f"it continues seq {trailer.seq - 1}, which is not in the files given before it: those "
                          "records were removed")

    def _check_restart_follows(self, record: dict[str, Any], what: str = "a restart") -> None:
        """A restart after a damaged or unchained line names the last chained record its writer found before it
        (after_seq, after_hash), or null when there was none in what it searched: that record must be here.
        The same holds for a rotated file's first record that starts a chain of its own (`what` names it)."""
        if "after_hash" not in record or "after_seq" not in record:
            self._problem(f"{what} must name the record before it (after_seq and after_hash)")
            return
        after_seq, after_hash = record["after_seq"], record["after_hash"]
        if after_hash is None and after_seq is None:
            return  # no chained record in the end of the log its writer searched (a log from 0.5, or a long line)
        if (type(after_seq) is not int or not 0 <= after_seq <= MAX_SEQ or not isinstance(after_hash, str)
                or not _HEX64_TEXT.fullmatch(after_hash)):
            self._problem(f"{what} must name the record before it (after_seq and after_hash)")
            return
        last = self._last_chained
        if last is None:
            self._problem(f"the chain before it is missing: it follows seq {after_seq}, which is not in the log "
                          "(records before it were removed)")
        elif last != (after_seq, after_hash):
            self._problem(f"it follows seq {after_seq}, but the last chained record before it is seq {last[0]}: "
                          "records before it were removed or changed")


def _could_not_read(record: dict[str, Any]) -> bool:
    """Whether a restart says its writer could not read the log (scanned 0 bytes, and so names no record)."""
    scanned = record.get("scanned")
    return (type(scanned) is int and scanned == 0 and record.get("after_hash", "") is None
            and record.get("after_seq", "") is None)


def check_files(paths: Sequence[str], key: bytes | None = None) -> ChainReport:
    """Check one log, or several in order (oldest first). Raises OSError if one cannot be read.

    A writer may rotate the log during the check. What a reader then holds is
    part of a file that is no longer the log, and would look damaged, so it
    is never judged: one file is read again from its start (auditlog.READ_ATTEMPTS
    times at most). With several files the check stops with
    auditlog.LogChangedError (an OSError): the log has one more file now, and
    the caller has to list them again.
    """
    if len(paths) == 1:
        return read_again_if_changed(lambda: _check_once(paths, [None], key))
    # The start of every file as it is now: a log rotated before its turn comes no longer starts like this.
    return _check_once(paths, [file_head(path) for path in paths], key)


def _check_once(paths: Sequence[str], heads: Sequence[bytes | None], key: bytes | None) -> ChainReport:
    checker = ChainChecker(key)
    for path, head in zip(paths, heads):
        checker.start_file(printable(path, limit=200) if len(paths) > 1 else "")
        for raw in iter_whole_file(path, known_head=head):
            checker.add(raw)
    return checker.finish()


# ---- provenance ---------------------------------------------------------------------------------------

MAX_PROVENANCE_TEXT = 100  # a name or version from a peer, the user name, the host name
MAX_HASHED_FILE_BYTES = 64 * 1024 * 1024  # the policy and pins files are smaller (pins.MAX_FILE_BYTES)


def file_sha256(path: str | Path | None) -> str | None:
    """SHA-256 of a file's bytes, or None when there is no such file, it cannot be read, or it is too large."""
    if path is None:
        return None
    try:
        with open(path, "rb") as handle:
            digest = hashlib.sha256()
            left = MAX_HASHED_FILE_BYTES + 1
            while left > 0:
                chunk = handle.read(min(COPY_CHUNK_BYTES, left))
                if not chunk:
                    return digest.hexdigest()
                digest.update(chunk)
                left -= len(chunk)
    except OSError:
        return None
    return None  # larger than MAX_HASHED_FILE_BYTES


def argv_sha256(argv: Sequence[str], redact: Callable[[str], str]) -> str:
    """SHA-256 of a command line (as JSON) with the secrets `redact` recognises masked first, so the hash cannot
    be used to guess one of those. A short secret it does not recognise (--pin=1234) stays in what is hashed,
    and can be found by hashing every candidate."""
    masked = [redact(word) for word in argv]
    return hashlib.sha256(json.dumps(masked, ensure_ascii=False).encode("utf-8", "backslashreplace")).hexdigest()


def os_user() -> str | None:
    """The name of the user this process runs as, made printable; None when it cannot be found."""
    try:
        return printable(getpass.getuser(), limit=MAX_PROVENANCE_TEXT)
    except Exception:  # no such user, no environment variable: getuser raises several kinds of error
        return None


def host_name() -> str | None:
    """This machine's name, made printable; None when it cannot be found."""
    try:
        return printable(socket.gethostname(), limit=MAX_PROVENANCE_TEXT)
    except OSError:
        return None


def peer_info(value: Any) -> dict[str, str] | None:
    """A clientInfo or serverInfo as a record keeps it: its name, title and version, each printable and short."""
    if not isinstance(value, dict):
        return None
    kept = {name: printable(value[name], limit=MAX_PROVENANCE_TEXT)
            for name in ("name", "title", "version") if isinstance(value.get(name), str)}
    return kept or None
