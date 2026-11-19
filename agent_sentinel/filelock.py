"""Operating-system file locks, for files that several processes write, and replacing a file in one step.

Two things need the locks: the audit log, which several proxies may share,
and the session state of flow rules (session.py), which every hook process
reads and updates. Each lock covers one byte at the start of the file,
whatever the file's length, so a lock file may be empty.

`replace_file` is how every file agent-sentinel rewrites is written (pins,
session state, rate-limit counts, client configurations).
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator

# How long to wait for a lock on Windows before giving up with OSError.
LOCK_TIMEOUT_SECONDS = 10.0
# os.replace can fail on Windows for a moment while another program (a virus
# scanner, a file indexer, a reader of the file) has the file open.
REPLACE_ATTEMPTS = 5
REPLACE_PAUSE_SECONDS = 0.1

if sys.platform == "win32":
    import msvcrt

    def lock_file(handle: BinaryIO) -> None:
        """Wait for, and take, the lock on an open file. Raises OSError after LOCK_TIMEOUT_SECONDS.

        Polls with short pauses instead of using LK_LOCK, which retries only
        once a second: with a few processes taking turns, a waiter could miss
        ten turns in a row and fail although each holds the lock for a moment.
        """
        deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
        pause = 0.001
        while True:
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                if time.monotonic() >= deadline:
                    raise
            time.sleep(pause)
            pause = min(pause * 2, 0.05)

    def unlock_file(handle: BinaryIO) -> None:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def lock_file(handle: BinaryIO) -> None:
        """Wait for, and take, the lock on an open file."""
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)

    def unlock_file(handle: BinaryIO) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def locked(path: str | Path) -> Iterator[None]:
    """Hold the lock on the file at `path` (created if missing) for the duration of a `with` block.

    For a separate lock file next to the data it protects. The data file can
    then be replaced atomically (os.replace) while the lock is held, which is
    not possible with a lock on the data file itself.
    """
    with open(path, "ab") as handle:
        lock_file(handle)
        try:
            yield
        finally:
            unlock_file(handle)


def replace_file(path: str | Path, data: bytes, keep_mode: bool = False) -> None:
    """Replace the file at `path` with `data` in one step. Raises OSError.

    The data goes to a new temporary file beside it, with a name of its own
    (two writers never share one), flushed to disk, then moved into place
    with os.replace: a crash leaves the old file or the new one, never half
    of one. The move is tried again for a moment when Windows refuses it
    (PermissionError). If anything fails, the temporary file is removed.
    The new file can be read by its owner only (0600 on POSIX), unless
    keep_mode copies the permissions of the file it replaces.
    """
    path = Path(path)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if keep_mode:
            try:
                shutil.copymode(path, temporary)
            except OSError:  # no file to copy them from yet
                pass
        for attempt in range(REPLACE_ATTEMPTS):
            try:
                os.replace(temporary, path)
                return
            except PermissionError:
                if attempt == REPLACE_ATTEMPTS - 1:
                    raise
                time.sleep(REPLACE_PAUSE_SECONDS)
    finally:
        if os.path.exists(temporary):
            try:
                os.chmod(temporary, stat.S_IWRITE)
                os.remove(temporary)
            except OSError:
                pass
