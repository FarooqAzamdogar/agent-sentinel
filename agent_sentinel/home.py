"""The folder where agent-sentinel keeps one user's files: the policy, the audit log and the tool pins.

    ~/.agent-sentinel                     on macOS and Linux ($HOME/.agent-sentinel)
    %USERPROFILE%\\.agent-sentinel         on Windows (not %APPDATA%: see below)
    $AGENT_SENTINEL_HOME                  when that variable is set (an absolute path)

    <home>/policy.json      written by `init`
    <home>/audit.jsonl      the audit log that `wrap` gives every wrapped server
    <home>/pins/            one tool pins file per wrapped server
    <home>/hook-state/      the Claude Code hook's session state: flow marks and rate-limit counts

Why not %APPDATA% on Windows: Claude Desktop installed from the Microsoft
Store (an MSIX package) sees a private copy of AppData. Files that a proxy
started by it writes there land in the package's own folder, where `report`
run from an ordinary terminal cannot find them. The user profile folder is
not redirected that way.

Nothing here is found implicitly. The proxy never looks in this folder by
itself: `wrap` writes the full path of every file into each wrapped entry,
and every command that writes here prints the full path it used.
"""

from __future__ import annotations

import ntpath
import os
import sys
from collections.abc import Mapping
from pathlib import Path

from .cli_common import CommandError

ENV_VAR = "AGENT_SENTINEL_HOME"
FOLDER_NAME = ".agent-sentinel"
POLICY_FILE = "policy.json"
AUDIT_FILE = "audit.jsonl"
PINS_FOLDER = "pins"
HOOK_STATE_FOLDER = "hook-state"


class HomeError(CommandError):
    """The home folder cannot be worked out. Commands print the message and exit with code 2."""


def is_absolute(path: str, platform: str | None = None) -> bool:
    """True for a full path. On Windows that needs a drive or a network share: "\\\\folder" depends on the drive."""
    platform = platform or sys.platform
    if platform == "win32":
        drive, rest = ntpath.splitdrive(path)
        return bool(drive) and rest.startswith(("\\", "/"))
    return path.startswith("/")


def user_folder(environ: Mapping[str, str] | None = None, platform: str | None = None) -> Path | None:
    """The user's own folder: %USERPROFILE% on Windows, $HOME elsewhere. None if the environment does not say.

    Read from the environment given (os.environ by default), so that tests
    and commands can point everything at a temporary folder.
    """
    environ = os.environ if environ is None else environ
    platform = platform or sys.platform
    if platform == "win32":
        candidates = [environ.get("USERPROFILE", "")]
        if environ.get("HOMEDRIVE") and environ.get("HOMEPATH"):
            candidates.append(environ["HOMEDRIVE"] + environ["HOMEPATH"])
    else:
        candidates = [environ.get("HOME", "")]
    for candidate in candidates:
        if candidate and is_absolute(candidate, platform):
            return Path(candidate)
    return None


def home_folder(environ: Mapping[str, str] | None = None, platform: str | None = None) -> Path:
    """The agent-sentinel home folder (see the module docstring). Raises HomeError if it cannot be worked out.

    AGENT_SENTINEL_HOME must be an absolute path: a relative one would mean a
    different folder for every program that starts in a different place,
    which is the very problem this folder exists to avoid. "~" is not
    expanded, because a client application that sets the variable would not
    expand it either.
    """
    environ = os.environ if environ is None else environ
    platform = platform or sys.platform
    chosen = environ.get(ENV_VAR, "")
    if chosen:
        if not is_absolute(chosen, platform):
            raise HomeError(
                f"{ENV_VAR} must be a full path, such as {_example_path(platform)}; got {chosen!r}"
            )
        return Path(os.path.normpath(chosen))
    folder = user_folder(environ, platform)
    if folder is None:
        variable = "USERPROFILE" if platform == "win32" else "HOME"
        raise HomeError(f"cannot tell where your home folder is: {variable} is not set. Set {ENV_VAR} to a full path")
    return folder / FOLDER_NAME


def _example_path(platform: str) -> str:
    return r"C:\Users\me\.agent-sentinel" if platform == "win32" else "/home/me/.agent-sentinel"


def policy_file(home: Path) -> Path:
    return home / POLICY_FILE


def audit_file(home: Path) -> Path:
    return home / AUDIT_FILE


def pins_folder(home: Path) -> Path:
    return home / PINS_FOLDER


def hook_state_folder(home: Path) -> Path:
    return home / HOOK_STATE_FOLDER


def make_folders(home: Path) -> list[Path]:
    """Create the home folder and its pins folder if they are missing; return the folders that were created."""
    created = []
    for folder in (home, pins_folder(home)):
        if not folder.is_dir():
            try:
                folder.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise HomeError(f"cannot create the folder {folder}: {exc.strerror or exc}") from exc
            created.append(folder)
    return created
