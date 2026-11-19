"""Reading an MCP client's configuration file, and changing server entries in it without disturbing the rest.

Editing another application's configuration is the riskiest thing
agent-sentinel does, so this module refuses whatever it is not sure of:

  * only plain JSON is read: a file with comments or trailing commas (JSONC),
    a repeated key, NaN, or an absurdly long number is refused, never "fixed";
  * a change replaces only the text of the entries that change. Everything
    else in the file, unknown keys, their order, spacing and line endings, is
    kept byte for byte. The edited text is read back and must equal the
    intended document, or nothing is written;
  * a file that changed after it was read is not written;
  * before writing, the original bytes are copied to a new, timestamped
    backup file, which is never overwritten and only its owner can read:
    beside the file, or in the agent-sentinel home folder when the file is
    part of a project under version control (see backup_folder);
  * the new file is written to a temporary file in the same folder and moved
    into place in one step (os.replace), so a crash leaves the old file or
    the new one, never half of one;
  * a link is not edited: the replacement would cut it.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime
from json.decoder import scanstring
from pathlib import Path
from typing import Any

from . import home, jsonutil
from .filelock import replace_file
from .cli_common import CommandError, strict_json
from .textutil import printable

# Client configurations are small. A larger file is refused rather than read.
MAX_CONFIG_BYTES = 4 * 1024 * 1024
# Backups of files in a project under version control go to <home>/backups (see backup_folder).
BACKUPS_FOLDER = "backups"
BACKUPS_IGNORE_FILE = ".gitignore"
_IGNORE_EVERYTHING = "# Backups of client configurations, with the tokens they hold: never commit them.\n*\n"
_WORK_TREE_MARKERS = (".git", ".hg", ".svn", ".jj")
_NO_IGNORE_FILE_MARKERS = frozenset((".hg", ".svn"))  # version control that reads no .gitignore
MAX_FOLDER_DEPTH = 64  # how many folders up a version-control marker is looked for
_WHITESPACE = " \t\n\r"


class ConfigError(CommandError):
    """A configuration file that cannot be read, or changed, safely. Printed; the command exits with code 2."""


@dataclass
class ConfigFile:
    """A configuration file as it was read."""

    path: Path
    raw: bytes  # the exact bytes, to detect a change before writing and to back up
    text: str  # decoded, without a byte order mark
    bom: bool
    document: dict[str, Any]

    @property
    def newline(self) -> str:
        return "\r\n" if "\r\n" in self.text else "\n"


def read_config(path: Path, for_writing: bool = False) -> ConfigFile:
    """Read and parse a configuration file strictly. Raises ConfigError with a message a person can act on."""
    if for_writing and path.is_symlink():
        raise ConfigError(f"{path} is a link; agent-sentinel edits only a plain file. "
                          "Give --config the file it points to")
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError as exc:
        raise ConfigError(f"there is no file at {path}") from exc
    except IsADirectoryError as exc:
        raise ConfigError(f"{path} is a folder, not a configuration file") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(f"{path} is larger than {MAX_CONFIG_BYTES} bytes, which no client configuration is")
    bom = raw.startswith(b"\xef\xbb\xbf")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        hint = " (it is saved as UTF-16)" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else ""
        raise ConfigError(f"{path} is not UTF-8 text{hint}") from exc
    try:
        document = jsonutil.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ConfigError(
            f"{_json_error(path, exc)}\n"
            "agent-sentinel reads only plain JSON: no comments, no trailing commas, no repeated keys"
        ) from exc
    if not isinstance(document, dict):
        raise ConfigError(f"{path} does not hold a JSON object ({{ ... }}) at the top")
    return ConfigFile(path, raw, text, bom, document)


def _json_error(path: Path, error: Exception) -> str:
    """Why the file is not strict JSON, and where, without quoting the text of any value.

    A client configuration often holds tokens in its "env" entries, and the
    text near a mistake could be one of them (a password with a backslash in
    it is an invalid escape): the line and column say enough. Only a
    repeated key is named.
    """
    if isinstance(error, json.JSONDecodeError):
        where = f"{path}:{error.lineno}:{error.colno}: not valid JSON"
        if error.msg.startswith("Invalid \\escape"):  # without the character Python's own reader may add
            return (f"{where}: Invalid \\escape\n"
                    "In JSON a backslash inside text must be doubled: write \\\\ for each \\.")
        return f"{where}: {error.msg}"
    if isinstance(error, jsonutil.RepeatedKeyError):
        return f"{path}: {error}"
    return f"{path}: not valid JSON ({printable(error, limit=100)})"  # absurd nesting, a huge number, NaN


# ---- where things are in the text ---------------------------------------------------------------

@dataclass(frozen=True)
class _Member:
    key: str
    key_start: int  # index of the key's opening quote
    value_start: int
    value_end: int  # one past the value's last character


def _skip_whitespace(text: str, index: int) -> int:
    while index < len(text) and text[index] in _WHITESPACE:
        index += 1
    return index


def _members(text: str, start: int) -> list[_Member]:
    """The members of the JSON object whose "{" is at `start`, with where each one is in the text.

    The text has already been parsed strictly, so this walks valid JSON only;
    the standard decoder finds where each value ends.
    """
    if text[start] != "{":
        raise ValueError("not an object")
    decoder = json.JSONDecoder()
    found: list[_Member] = []
    index = _skip_whitespace(text, start + 1)
    if text[index] == "}":
        return found
    while True:
        if text[index] != '"':
            raise ValueError("expected a key")
        key_start = index
        key, index = scanstring(text, index + 1)
        index = _skip_whitespace(text, index)
        if text[index] != ":":
            raise ValueError("expected ':'")
        value_start = _skip_whitespace(text, index + 1)
        _, value_end = decoder.raw_decode(text, value_start)
        found.append(_Member(key, key_start, value_start, value_end))
        index = _skip_whitespace(text, value_end)
        if text[index] == ",":
            index = _skip_whitespace(text, index + 1)
        elif text[index] == "}":
            return found
        else:
            raise ValueError("expected ',' or '}'")


def _indent_unit(text: str) -> str:
    """The file's own indentation step (two spaces when it cannot be told), for the entries written into it."""
    for line in text.splitlines():
        stripped = line.lstrip(" \t")
        if stripped and len(stripped) < len(line):
            lead = line[: len(line) - len(stripped)]
            return "\t" if lead.startswith("\t") else " " * min(len(lead), 8)
    return "  "


def _entry_text(value: Any, old: Any, config: ConfigFile, member: _Member) -> str:
    """One entry written as JSON in the style of the one it replaces, to take its place in the text.

    When both are objects and only some of their values changed (what wrap
    and unwrap do to "command" and "args"), only those values are written
    anew: every other member of the entry, an unknown key's numbers and
    layout included, stays byte for byte. Otherwise the whole entry is
    written: an entry that was on one line stays on one line, and any other
    is indented like the file, one item per line.
    """
    in_place = _changed_members_text(value, old, config, member)
    if in_place is not None:
        return in_place
    lead = _lead(config.text, member.key_start)
    compact = (
        bool(lead.strip())  # the key is not at the start of its line: the file is written compactly
        or "\n" not in config.text[member.value_start:member.value_end]
    )
    return _json_text(value, config, lead, compact)


def _changed_members_text(value: Any, old: Any, config: ConfigFile, member: _Member) -> str | None:
    """The entry's own text with only its changed values replaced, or None when that is not possible.

    Possible when the entry keeps the same keys in the same order; None when
    a key is added or removed (wrap adds "args" to an entry that had none),
    or the entry is not an object.
    """
    if not isinstance(value, dict) or not isinstance(old, dict) or list(value) != list(old):
        return None
    try:
        parts = _members(config.text, member.value_start)
    except (ValueError, IndexError, RecursionError):
        return None
    if [part.key for part in parts] != list(old):
        return None
    pieces, position = [], member.value_start
    for part in parts:
        if _same_json(value[part.key], old[part.key]):
            continue
        lead = _lead(config.text, part.key_start)
        compact = bool(lead.strip()) or "\n" not in config.text[part.value_start:part.value_end]
        pieces += [config.text[position:part.value_start], _json_text(value[part.key], config, lead, compact)]
        position = part.value_end
    pieces.append(config.text[position:member.value_end])
    return "".join(pieces)


def _same_json(one: Any, other: Any) -> bool:
    """Whether two values are written the same as JSON (1 and True, or 1 and 1.0, are not the same)."""
    return json.dumps(one) == json.dumps(other)


def _lead(text: str, key_start: int) -> str:
    """What comes before a key on its line: its indentation, or other text when the file is written compactly."""
    return text[text.rfind("\n", 0, key_start) + 1:key_start]


def _json_text(value: Any, config: ConfigFile, lead: str, compact: bool) -> str:
    """A value written as JSON: on one line, or indented like the file below a key that has `lead` before it."""

    def written(ascii_only: bool) -> str:
        if compact:
            return json.dumps(value, ensure_ascii=ascii_only)
        return json.dumps(value, indent=_indent_unit(config.text), ensure_ascii=ascii_only).replace("\n", "\n" + lead)

    text = written(ascii_only=False)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:  # a lone surrogate from a JSON escape: keep it escaped
        text = written(ascii_only=True)
    return text.replace("\n", config.newline) if config.newline != "\n" else text


def edited_text(config: ConfigFile, servers_key: str, entries: dict[str, Any]) -> str:
    """The file's text with the entries named in `entries` (under `servers_key`) replaced, and nothing else changed.

    Raises ConfigError if the result does not read back as exactly the
    intended document (a safety net: it should never happen).
    """
    try:
        top = _members(config.text, _skip_whitespace(config.text, 0))
        servers = next(member for member in top if member.key == servers_key)
        spans = {member.key: member for member in _members(config.text, servers.value_start)}
    except (ValueError, IndexError, StopIteration, RecursionError) as exc:
        raise ConfigError(f"{config.path}: could not find the entries to change ({exc}); nothing was written") from exc
    pieces = []
    position = 0
    for member in sorted((spans[name] for name in entries), key=lambda member: member.value_start):
        old = config.document[servers_key][member.key]
        pieces += [config.text[position:member.value_start], _entry_text(entries[member.key], old, config, member)]
        position = member.value_end
    pieces.append(config.text[position:])
    text = "".join(pieces)

    expected = dict(config.document)
    expected[servers_key] = {name: entries.get(name, value) for name, value in config.document[servers_key].items()}
    try:
        if strict_json(text, str(config.path)) != expected:
            raise ValueError("it differs")
    except (CommandError, ValueError) as exc:
        raise ConfigError(
            f"{config.path}: the edited file would not read back as intended; nothing was written"
        ) from exc
    return text


def with_top_level_value(config: ConfigFile, key: str, value: Any) -> str:
    """The file's text with the top-level `key` set to `value`: its value replaced, or the key added at the end.

    For a settings file that gets a whole section (Claude Code's "hooks").
    The new value is indented like the file (on one line in a file written
    on one line). Everything else is kept byte for byte, and the result must
    read back as exactly the intended document, or ConfigError.
    """
    text = config.text
    try:
        start = _skip_whitespace(text, 0)
        members = _members(text, start)
    except (ValueError, IndexError, RecursionError) as exc:
        raise ConfigError(f"{config.path}: could not find where to write {key!r} ({exc}); nothing was written") from exc
    existing = next((member for member in members if member.key == key), None)
    if existing is not None:
        lead = _lead(text, existing.key_start)
        written = _json_text(value, config, lead, compact=bool(lead.strip()))
        edited = text[:existing.value_start] + written + text[existing.value_end:]
    elif members:
        last = members[-1]
        lead = _lead(text, last.key_start)
        compact = bool(lead.strip())
        separator = ", " if compact else "," + config.newline + lead
        added = separator + json.dumps(key) + ": " + _json_text(value, config, lead, compact)
        edited = text[:last.value_end] + added + text[last.value_end:]
    else:  # an empty object: "{}"
        unit = _indent_unit(text)
        close = text.index("}", start)
        added = config.newline + unit + json.dumps(key) + ": " + _json_text(value, config, unit, False) + config.newline
        edited = text[:start + 1] + added + text[close:]

    expected = {**config.document, key: value}
    try:
        if strict_json(edited, str(config.path)) != expected:
            raise ValueError("it differs")
    except (CommandError, ValueError) as exc:
        raise ConfigError(
            f"{config.path}: the edited file would not read back as intended; nothing was written"
        ) from exc
    return edited


def create_config(path: Path, text: str) -> None:
    """Write a new configuration file. Refuses if one appeared meanwhile: it is never overwritten."""
    try:
        with open(path, "x", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise ConfigError(f"{path} appeared while agent-sentinel was working; nothing was written. "
                          "Run the command again") from exc
    except OSError as exc:
        raise ConfigError(f"cannot write {path}: {exc.strerror or exc}") from exc


# ---- writing ----------------------------------------------------------------------------------------

def write_config(config: ConfigFile, text: str, now: datetime | None = None) -> Path:
    """Back up the file, then replace it atomically with `text`. Returns the backup's path.

    Refuses if the file changed since it was read: the change would be lost.
    """
    try:
        with open(config.path, "rb") as handle:
            current = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ConfigError(f"cannot read {config.path} again before writing it: {exc.strerror or exc}") from exc
    if current != config.raw:
        raise ConfigError(f"{config.path} changed while agent-sentinel was working on it; nothing was written. "
                          "Run the command again")
    data = (b"\xef\xbb\xbf" if config.bom else b"") + text.encode("utf-8")
    backup = _backup(config, now or datetime.now())
    _replace(config.path, data)
    return backup


def in_work_tree(path: Path) -> bool:
    """Whether a folder above `path` holds .git, .hg, .svn or .jj: the file is in a project under version control."""
    return bool(_work_tree_markers(path))


def _work_tree_markers(path: Path) -> set[str]:
    """The version-control markers (.git, .hg, .svn, .jj) found in the folders above `path`."""
    found = set()
    for folder in list(path.parents)[:MAX_FOLDER_DEPTH]:
        found.update(marker for marker in _WORK_TREE_MARKERS if os.path.lexists(folder / marker))
    return found


def backup_folder(path: Path) -> tuple[Path, str]:
    """Where the backup of `path` goes, and how its name starts.

    Beside the file, as <file>.agent-sentinel-<time>.bak, unless the file is
    in a project under version control. A project's .mcp.json or
    .claude/settings.local.json often holds tokens and is ignored by name
    (.gitignore), but a backup beside it is not, and `git add -A` would
    commit it. So those backups go to the agent-sentinel home folder,
    <home>/backups/<file>.<8 hex of its full path>.agent-sentinel-<time>.bak.

    The home folder can be in a work tree too (a home folder kept in git for
    its dotfiles). So the backups folder gets a .gitignore that ignores
    everything in it, which git and jj read. Mercurial and Subversion read
    no such file, so a home folder in one of their work trees is refused.
    """
    if not in_work_tree(path):
        return path.parent, f"{path.name}.agent-sentinel-"
    folder = home.home_folder() / BACKUPS_FOLDER
    if _work_tree_markers(folder / BACKUPS_IGNORE_FILE) & _NO_IGNORE_FILE_MARKERS:
        raise ConfigError(f"the agent-sentinel home folder {folder.parent} is inside a Mercurial or Subversion work "
                          f"tree, where the backup of {path.name} (and the tokens in it) could be committed. Set "
                          f"{home.ENV_VAR} to a folder outside it; nothing was changed")
    try:
        folder.mkdir(parents=True, exist_ok=True)
        _ignore_everything(folder)
    except OSError as exc:
        raise ConfigError(f"cannot prepare the folder {folder} for the backup: {exc.strerror or exc}; "
                          "nothing was changed") from exc
    code = hashlib.sha256(os.path.normcase(str(path)).encode("utf-8", "surrogatepass")).hexdigest()[:8]
    return folder, f"{path.name}.{code}.agent-sentinel-"


def _ignore_everything(folder: Path) -> None:
    """Write a .gitignore that ignores every file in `folder`, unless the folder already has one."""
    try:
        with open(folder / BACKUPS_IGNORE_FILE, "x", encoding="utf-8", newline="\n") as handle:
            handle.write(_IGNORE_EVERYTHING)
    except FileExistsError:
        pass


def _backup(config: ConfigFile, now: datetime) -> Path:
    """Copy the original bytes to a new backup file (see backup_folder). Never overwrites: a clash gets -2, -3, ...

    The backup holds every token the original does, so only its owner may
    read it (0600 on POSIX), whatever the permissions of a new file would be.
    """
    folder, start = backup_folder(config.path)
    stamp = now.strftime("%Y%m%d-%H%M%S")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    for number in range(1, 100):
        suffix = "" if number == 1 else f"-{number}"
        backup = folder / f"{start}{stamp}{suffix}.bak"
        try:
            with os.fdopen(os.open(backup, flags, 0o600), "wb") as handle:
                handle.write(config.raw)
                handle.flush()
                os.fsync(handle.fileno())
            return backup
        except FileExistsError:
            continue
        except OSError as exc:
            raise ConfigError(
                f"cannot write a backup of {config.path} in {folder}: {exc.strerror or exc}; nothing was changed"
            ) from exc
    raise ConfigError(f"too many backups of {config.path} with the same time; nothing was changed")


def _replace(path: Path, data: bytes) -> None:
    """Replace the file in one step (filelock.replace_file), keeping its permissions."""
    try:
        replace_file(path, data, keep_mode=True)
    except OSError as exc:
        raise ConfigError(f"cannot write {path}: {exc.strerror or exc}; the file was not changed") from exc
