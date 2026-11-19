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
    backup file beside it, which is never overwritten;
  * the new file is written to a temporary file in the same folder and moved
    into place in one step (os.replace), so a crash leaves the old file or
    the new one, never half of one;
  * a link is not edited: the replacement would cut it.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from json.decoder import scanstring
from pathlib import Path
from typing import Any

from .cli_common import CommandError, strict_json
from .leaks import redact

# Client configurations are small. A larger file is refused rather than read.
MAX_CONFIG_BYTES = 4 * 1024 * 1024
# os.replace can fail on Windows for a moment while another program (a virus
# scanner, a file indexer, the client itself) has the file open.
_REPLACE_ATTEMPTS = 5
_REPLACE_PAUSE_SECONDS = 0.1
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
        document = strict_json(text, str(path))
    except CommandError as exc:
        raise ConfigError(
            f"{_without_excerpt(str(exc))}\n"
            "agent-sentinel reads only plain JSON: no comments, no trailing commas, no repeated keys"
        ) from exc
    if not isinstance(document, dict):
        raise ConfigError(f"{path} does not hold a JSON object ({{ ... }}) at the top")
    return ConfigFile(path, raw, text, bom, document)


def _without_excerpt(message: str) -> str:
    """A JSON error message without the quoted line and its caret (indented lines), secrets blanked out.

    A client configuration often holds tokens in its "env" entries, and the
    quoted line could be one of them: the line and column say enough.
    """
    return redact("\n".join(line for line in message.splitlines() if not line.startswith("    ")))


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


def _entry_text(value: Any, config: ConfigFile, member: _Member) -> str:
    """One entry written as JSON in the style of the one it replaces, to take its place in the text.

    An entry that was on one line stays on one line (so wrapping and then
    unwrapping gives back the same text); otherwise it is indented like the
    file, one item per line.
    """
    line_start = config.text.rfind("\n", 0, member.key_start) + 1
    lead = config.text[line_start:member.key_start]
    compact = (
        bool(lead.strip())  # the key is not at the start of its line: the file is written compactly
        or "\n" not in config.text[member.value_start:member.value_end]
    )

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
        pieces += [config.text[position:member.value_start], _entry_text(entries[member.key], config, member)]
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


def _backup(config: ConfigFile, now: datetime) -> Path:
    """Copy the original bytes to <file>.agent-sentinel-<time>.bak. Never overwrites: a clash gets -2, -3, ..."""
    stamp = now.strftime("%Y%m%d-%H%M%S")
    for number in range(1, 100):
        suffix = "" if number == 1 else f"-{number}"
        backup = config.path.with_name(f"{config.path.name}.agent-sentinel-{stamp}{suffix}.bak")
        try:
            with open(backup, "xb") as handle:
                handle.write(config.raw)
                handle.flush()
                os.fsync(handle.fileno())
            return backup
        except FileExistsError:
            continue
        except OSError as exc:
            raise ConfigError(
                f"cannot write a backup beside {config.path}: {exc.strerror or exc}; nothing was changed"
            ) from exc
    raise ConfigError(f"too many backups of {config.path} with the same time; nothing was changed")


def _replace(path: Path, data: bytes) -> None:
    """Write `data` to a temporary file beside `path`, then move it into place in one step."""
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            shutil.copymode(path, temporary)  # keep the file's permissions (POSIX)
        except OSError:
            pass
        for attempt in range(_REPLACE_ATTEMPTS):
            try:
                os.replace(temporary, path)
                return
            except PermissionError:
                if attempt == _REPLACE_ATTEMPTS - 1:
                    raise
                time.sleep(_REPLACE_PAUSE_SECONDS)
    except OSError as exc:
        raise ConfigError(f"cannot write {path}: {exc.strerror or exc}; the file was not changed") from exc
    finally:
        if os.path.exists(temporary):
            try:
                os.chmod(temporary, stat.S_IWRITE)
                os.remove(temporary)
            except OSError:
                pass
