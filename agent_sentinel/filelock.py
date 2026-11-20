"""Operating-system file locks, for files that several processes write, and replacing a file in one step.

Two things need the locks: the audit log, which several proxies may share,
and the session state of flow rules (session.py), which every hook process
reads and updates. Each lock covers one byte at the start of the file,
whatever the file's length, so a lock file may be empty.

`replace_file` is how every file agent-sentinel rewrites is written (pins,
session state, rate-limit counts, client configurations).

`make_private_folder` is how every folder agent-sentinel creates is made:
readable by its owner only (mode 0700 on POSIX), the missing folders above
it too.
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
# The folders agent-sentinel creates are its owner's only; and how many missing ones above it are created at most.
PRIVATE_FOLDER_MODE = 0o700
MAX_FOLDERS_CREATED = 64


def make_private_folder(folder: str | Path) -> list[Path]:
    """Create a folder, and each missing folder above it, readable by its owner only. Returns those created.

    Mode 0700 on POSIX, whatever the umask leaves (it only takes bits away).
    Path.mkdir(parents=True) would give the folders above it the default mode
    instead. A folder that exists is left as it is. Raises OSError.
    """
    missing: list[Path] = []
    current = Path(folder)
    while not current.is_dir() and current.parent != current and len(missing) < MAX_FOLDERS_CREATED:
        missing.append(current)
        current = current.parent
    created = []
    for path in reversed(missing):
        try:
            path.mkdir(mode=PRIVATE_FOLDER_MODE)
        except FileExistsError:
            if not path.is_dir():
                raise
            continue
        created.append(path)
    return created

if sys.platform == "win32":
    import msvcrt

    def lock_file(handle: BinaryIO, timeout: float | None = None) -> None:
        """Wait for, and take, the lock on an open file. Raises OSError after `timeout` seconds
        (LOCK_TIMEOUT_SECONDS when None).

        Polls with short pauses instead of using LK_LOCK, which retries only
        once a second: with a few processes taking turns, a waiter could miss
        ten turns in a row and fail although each holds the lock for a moment.
        """
        deadline = time.monotonic() + (LOCK_TIMEOUT_SECONDS if timeout is None else timeout)
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

    def lock_file(handle: BinaryIO, timeout: float | None = None) -> None:
        """Wait for, and take, the lock on an open file.

        timeout: None waits as long as it takes; a number of seconds polls,
        and raises OSError (TimeoutError) when the lock is not had by then.
        """
        if timeout is None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            return
        deadline = time.monotonic() + timeout
        pause = 0.001
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"the lock was not free within {timeout:g} seconds") from None
            time.sleep(pause)
            pause = min(pause * 2, 0.05)

    def unlock_file(handle: BinaryIO) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def locked(path: str | Path, timeout: float | None = None) -> Iterator[None]:
    """Hold the lock on the file at `path` (created if missing) for the duration of a `with` block.

    For a separate lock file next to the data it protects. The data file can
    then be replaced atomically (os.replace) while the lock is held, which is
    not possible with a lock on the data file itself.

    timeout: how long to wait for the lock before OSError; None keeps each
    system's default (LOCK_TIMEOUT_SECONDS on Windows, no limit elsewhere).
    """
    with open(path, "ab") as handle:
        lock_file(handle, timeout)
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
