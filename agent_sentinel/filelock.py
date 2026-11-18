"""Operating-system file locks, for files that several processes write.

Two things need them: the audit log, which several proxies may share, and the
session state of flow rules (session.py), which every hook process reads and
updates. Each lock covers one byte at the start of the file, whatever the
file's length, so a lock file may be empty.
"""

from __future__ import annotations

import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator

# How long to wait for a lock on Windows before giving up with OSError.
LOCK_TIMEOUT_SECONDS = 10.0

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
