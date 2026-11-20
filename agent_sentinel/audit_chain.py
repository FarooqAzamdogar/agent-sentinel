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
           FILE.2, ...), whose name it gives in "previous_file";
  restart  the last line of the log could not be linked to (damaged, cut
           short, or written by agent-sentinel 0.5 or earlier): a new chain
           starts after it, rather than failing every call.

What the chain can and cannot show (also in SECURITY.md):

  * without a key it detects naive edits only: anyone who can write the
    file can work out every hash again;
  * a key detects any change, but only if the agent's tools cannot read it;
  * records cut from the end of the log are not detected by either: keep
    the last seq and hash somewhere else (`audit verify` prints them).

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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Callable, Sequence

from .auditlog import CHAIN_START, PROTOCOL, SESSION_END, SESSION_START, iter_lines, parse_record  # noqa: F401
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
# The size of a chunk when a log is copied aside on rotation.
COPY_CHUNK_BYTES = 1024 * 1024
# --audit-max-bytes: the smallest and largest size a log may grow to before it is rotated.
MIN_MAX_BYTES = 1024
MAX_MAX_BYTES = 1 << 40
# Rotated files are FILE.1, FILE.2, ... up to this number. Past it, the log is not rotated (it keeps growing).
MAX_ROTATED_FILES = 10_000
# A key file: 16 bytes at the least (128 bits), and small.
MIN_KEY_BYTES = 16
MAX_KEY_FILE_BYTES = 1024
_KEY_ID_LABEL = b"agent-sentinel audit key id"
# How many problems a check keeps the text of (all of them are counted).
MAX_PROBLEMS_KEPT = 20

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
    """
    try:
        handle = open(path, "rb")
    except OSError as exc:
        raise AuditKeyError(f"the audit key file cannot be opened ({exc.strerror or type(exc).__name__})") from None
    with handle:
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
    max_bytes:  rotate the log first when this record would take it past this size.

    Everything happens under the operating-system lock on the log, so the
    processes that share it (proxies, hook processes) never overwrite each
    other's records (on Windows an append is "seek to the end, then write")
    and never link two records to the same one. The lock is held by the one
    handle that reads the end and appends: on Windows a locked byte cannot be
    read through another handle. A new log is created readable by its owner
    only (0600 on POSIX).
    """
    handle = _open_log(path)
    with handle:
        lock_file(handle)
        try:
            size = handle.seek(0, os.SEEK_END)
            tail = _read_tail(handle, size)
            start: dict[str, Any] | None = None
            estimate = len(line) + 400
            if max_bytes is not None and size > 0 and size + estimate > max_bytes:
                rotated = _rotate(handle, path, size)
                if rotated is not None:
                    size = 0
                    start = {"start": ROTATED, "reason": f"the log was rotated: the records before are in {rotated}",
                             "previous_file": rotated}
            if start is None and size == 0:
                start = {"start": NEW, "reason": "a new audit log"}
            elif start is None and tail.problem is not None:
                start = {"start": RESTART, "reason": f"a new chain starts: {tail.problem}"}
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


def _open_log(path: Path) -> BinaryIO:
    """The log, opened to read and append, created if missing with owner-only permissions (0600 on POSIX)."""
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        return open(descriptor, "a+b", buffering=0)  # unbuffered: reads and writes go straight to the file
    except BaseException:
        os.close(descriptor)
        raise


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


def _rotate(handle: BinaryIO, path: Path, size: int) -> str | None:
    """Copy the log to the next free FILE.N, then empty it; the name of the copy, or None when none is free.

    Copied, not renamed: another process may hold the log open (Windows
    refuses to rename it then, and on POSIX that process would go on writing
    to the renamed file). Nothing is ever deleted: the copy is complete and
    on disk before the log is emptied, under the lock.
    """
    for number in range(1, MAX_ROTATED_FILES + 1):
        target = path.with_name(f"{path.name}.{number}")
        try:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        except FileExistsError:
            continue
        break
    else:
        return None
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
    return target.name


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

INTACT, BROKEN, UNCHAINED, EMPTY = "intact", "broken", "unchained", "empty"


@dataclass
class ChainReport:
    """What a check of one log (or of several, in order) found."""

    lines: int = 0
    chained: int = 0
    unchained_prefix: int = 0  # lines without chain fields before the first chained record
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
        if self.lines == 0:
            return EMPTY
        if self.problem_count:
            return BROKEN
        if self.chained == 0:
            return UNCHAINED
        return INTACT

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
        if self.key_given:
            macs = "every MAC matches the key"
        elif self.macs_present:
            macs = "MACs not checked here (audit verify --key-file checks them)"
        else:
            macs = "no MACs (written without a key)"
        older = f"; {self.unchained_prefix} older line(s) before it" if self.unchained_prefix else ""
        return f"Integrity: hash chain intact, seq {self.first_seq} to {self.last_seq}{older}; {macs}."


class ChainChecker:
    """Checks a log line by line, as it is read: `start_file`, then `add` each raw line, then `finish`.

    Several files (FILE.1, FILE.2, ..., FILE) can be checked as one chain by
    calling start_file before each, oldest first. Memory stays bounded: the
    checker keeps the last link and a few problem texts.
    """

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key
        self._key_id = key_id(key) if key is not None else None
        self.report = ChainReport(key_given=key is not None)
        self._previous: Any = None  # None (nothing yet), "unchained", "bad", or (seq, hash) of the last record
        self._seen_chain = False
        self._label = ""
        self._line = 0
        self._files = 0
        self._other_keys: set[str] = set()

    def start_file(self, label: str = "") -> None:
        """Begin the next file; `label` names it in problems when several files are checked."""
        self._label = label
        self._line = 0
        self._files += 1

    def add(self, raw: bytes | None) -> None:
        """Check one line as the file holds it (with its newline); None for a line too long to read."""
        self._line += 1
        self.report.lines += 1
        at_start = self._line == 1
        if raw is None:
            self._bad("it is too long to read")
            return
        if not raw.endswith(b"\n"):
            self._bad("it is incomplete: it has no newline at its end (a write was cut short, or the file was edited)")
            return
        content = raw[:-1]
        carriage_return = content.endswith(b"\r")
        if carriage_return:
            content = content[:-1]
        trailer = parse_trailer(content)
        if trailer is None:
            self._unchained(content)
            return
        record = self._parsed(content)
        if record is None:
            return
        if carriage_return:  # the record is intact, but the file is not as it was written
            self._problem("it ends with a carriage return: a program changed the file's line ends")
        self._check_hash_and_mac(trailer, record)
        self._check_link(trailer, record, at_start)
        self._previous = (trailer.seq, trailer.digest)
        self._seen_chain = True
        report = self.report
        report.chained += 1
        if report.first_seq is None:
            report.first_seq = trailer.seq
        report.last_seq, report.last_hash = trailer.seq, trailer.digest

    def finish(self) -> ChainReport:
        if self._other_keys:
            self.report.notes.append(
                f"{len(self._other_keys)} chain start(s) name another key (key id "
                f"{', '.join(sorted(self._other_keys)[:3])}): those records were signed with a different key"
            )
        return self.report

    # ---- one line ----

    def _where(self) -> str:
        return f"{self._label} line {self._line}" if self._label else f"line {self._line}"

    def _problem(self, text: str) -> None:
        report = self.report
        report.problem_count += 1
        if len(report.problems) < MAX_PROBLEMS_KEPT:
            report.problems.append(f"{self._where()}: {text}")

    def _bad(self, text: str) -> None:
        self._problem(text)
        self._previous = "bad"

    def _unchained(self, content: bytes) -> None:
        if parse_record(content) is None:  # not JSON, not an object, absurdly nested, a huge number
            self._bad("it is not a JSON object")
            return
        if self._seen_chain:
            self._problem("it has no chain fields: it was inserted, or written by agent-sentinel 0.5 or earlier")
        else:
            self.report.unchained_prefix += 1
        self._previous = "unchained"

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
            if not at_start:
                self._problem("a rotated file's first record is in the middle of a file")
            elif isinstance(previous, tuple):
                if trailer.prev != previous[1] or trailer.seq != previous[0] + 1:
                    self._problem(f"it does not continue the file before it (whose last record is seq {previous[0]})")
            elif previous is None and not fresh:
                shown = printable(record.get("previous_file", "an older file"), limit=80)
                self.report.notes.append(
                    f"the first file continues {shown}, which was not checked: give the older files first, oldest "
                    "first, to check the link"
                )
        elif start == RESTART:
            if at_start:
                self._problem("the file starts with a chain restart: the line before it is missing")
            elif isinstance(previous, tuple):
                self._problem("a new chain starts although the record before it is intact: records may have been "
                              "removed here")
            elif not fresh:
                self._problem("a restarted chain must start at seq 0 with no previous hash")
        else:
            self._problem("it is a chain_start record of an unknown kind")


def check_files(paths: Sequence[str], key: bytes | None = None) -> ChainReport:
    """Check one log, or several in order (oldest first). Raises OSError if one cannot be read."""
    checker = ChainChecker(key)
    for path in paths:
        checker.start_file(printable(path, limit=200) if len(paths) > 1 else "")
        with open(path, "rb") as handle:
            for raw in iter_lines(handle):
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
    """SHA-256 of a command line (as JSON) with what looks like a secret masked first, so the hash cannot be
    used to guess a short secret."""
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
