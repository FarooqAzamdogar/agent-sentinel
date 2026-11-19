"""Helpers shared by the commands of the `agent-sentinel` command line.

Each command lives in a module of its own, named cli_<command>.py, with the
same parts, which __main__.py puts together:

    HELP                   one line for the list of commands
    DESCRIPTION, EPILOG    optional: the text above and below the command's --help
    add_arguments(parser)  the command's options, on an argparse parser
    run(args) -> int       does the work and returns the exit code

Exit codes are shared too: 0 for "allowed / nothing found / all passed", 1 for
"blocked / found / a test failed", 2 for an error in the input, and, for
`check`, 3 for "a person would be asked".

Everything a command prints that it did not write itself (the text of a file,
a tool name from an audit log, a value from a policy or the command line)
goes through `printable`, because it may carry terminal escape codes.
"""

from __future__ import annotations

import argparse
import codecs
import json
import os
import re
import sys
import textwrap
from pathlib import Path
from typing import Any

from .policy import Policy, PolicyError
from .policy_errors import file_error_message, json_error_message, quoted
from .textutil import printable

EXIT_OK = 0
EXIT_FAIL = 1  # blocked, found, or a test failed
EXIT_ERROR = 2
EXIT_ASK = 3

# The largest file a command reads whole (a file to scan, a case file, a result).
# The proxy drops messages larger than this by default, so nothing larger reaches an agent through it.
MAX_INPUT_BYTES = 16 * 1024 * 1024

# Python 3.11 and later refuse to read an integer of more digits than this
# (reading one is slow: the work grows with the square of its length). The
# same limit is applied on 3.10, so that a file reads the same everywhere.
MAX_INT_DIGITS = 4300

# Byte order marks, longest first: the UTF-32-LE mark begins with the UTF-16-LE one.
_BYTE_ORDER_MARKS = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)

# The end of the text an agent is shown for a block: " (ref 7f3a9c21)".
_REF_SUFFIX = re.compile(r" \(ref [0-9a-f]{8}\)\Z")


class CommandError(Exception):
    """A problem with what the command was given. main() prints it and exits with code 2."""


# ---- reporting problems ------------------------------------------------------------

def print_error(message: str) -> None:
    """Print a message to stderr, line by line, each line made printable."""
    for line in str(message).splitlines() or [""]:
        print(f"agent-sentinel: {printable(line, limit=1000)}", file=sys.stderr)


def load_policy(path: str) -> Policy | None:
    """Load a policy file, or print why it cannot be loaded and return None.

    The same words as `validate`: "Invalid policy: ..." then, for a JSON
    error, the line of the file with a caret under the mistake.
    """
    try:
        return Policy.from_file(path)
    except (OSError, PolicyError) as exc:
        message = file_error_message(path, exc) if isinstance(exc, OSError) else str(exc)
        lines = message.splitlines() or [""]
        print(f"Invalid policy: {printable(lines[0], limit=1000)}", file=sys.stderr)
        for line in lines[1:]:
            print(printable(line, limit=1000), file=sys.stderr)
        return None


# ---- reading input -------------------------------------------------------------------

def read_input(path: str, limit: int = MAX_INPUT_BYTES) -> bytes:
    """The bytes of a file, or of stdin for "-". At most `limit` bytes: a larger input is an error.

    Cutting a file short would check only part of it and say nothing about
    the rest, so a larger file is refused instead.
    """
    if path == "-":
        data = sys.stdin.buffer.read(limit + 1)
    else:
        if os.path.isdir(path):
            raise CommandError(f"{path} is a folder; give the files in it one by one")
        try:
            with open(path, "rb") as handle:
                data = handle.read(limit + 1)
        except OSError as exc:
            raise CommandError(f"cannot read {path}: {exc.strerror or type(exc).__name__}") from exc
    if len(data) > limit:
        what = "stdin" if path == "-" else path
        raise CommandError(f"{what} is larger than {limit} bytes, so it was not read")
    return data


def readings(data: bytes) -> list[str]:
    """The ways a file's bytes may be read as text. All of them are scanned.

    Always as UTF-8, which is what most programs assume. Also as the encoding
    a byte order mark announces, and as UTF-16 when the NUL bytes suggest it:
    a UTF-16 file has a NUL beside every letter. Guessing ONE encoding would
    be a way to hide text: two bytes that look like a UTF-16 mark in front of
    ordinary UTF-8 would make the scanner read noise where another program
    reads the words.
    """
    found = [data.decode("utf-8", errors="replace")]
    for mark, encoding in _BYTE_ORDER_MARKS:
        if data.startswith(mark):
            found.append(data.decode(encoding, errors="replace"))
    sample = data[:2000]
    if len(sample) >= 4 and sample.count(0) >= len(sample) // 4:
        found.append(data.decode("utf-16-le", errors="replace"))
        found.append(data.decode("utf-16-be", errors="replace"))
    return list(dict.fromkeys(found))


def bounded_int(text: str) -> int:
    """json's parse_int: an integer, unless it has more digits than MAX_INT_DIGITS (then ValueError)."""
    if len(text) > MAX_INT_DIGITS + 1:  # +1 for a minus sign
        raise ValueError(f"a number with more than {MAX_INT_DIGITS} digits")
    return int(text)


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


class _RepeatedKey(ValueError):
    pass


def _no_repeated_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _RepeatedKey(f"the key {quoted(key, limit=60)} appears twice in one object")
        result[key] = value
    return result


def strict_json(text: str, label: str) -> Any:
    """Parse JSON the way policies are parsed: a repeated key is an error, and errors show where.

    Also refused: NaN and Infinity (Python accepts them, JSON does not) and
    integers longer than MAX_INT_DIGITS. Raises CommandError. A JSON syntax
    error names the line and column, shows the line with a caret, and adds a
    hint for the common mistakes.
    """
    try:
        return json.loads(
            text, object_pairs_hook=_no_repeated_keys, parse_int=bounded_int, parse_constant=_no_constants
        )
    except json.JSONDecodeError as exc:
        raise CommandError(json_error_message(label, exc)) from exc
    except _RepeatedKey as exc:
        raise CommandError(f"{label}: {exc}") from exc
    except (ValueError, RecursionError) as exc:  # absurd nesting, a huge number, NaN
        raise CommandError(f"{label}: not valid JSON ({printable(exc, limit=100)})") from exc


def decode_utf8(data: bytes, label: str) -> str:
    """Text of a UTF-8 file (a byte order mark is allowed), or a CommandError that says what is wrong."""
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            raise CommandError(f"{label}: the file is saved as UTF-16; save it as UTF-8") from exc
        raise CommandError(f"{label}: not valid UTF-8 text (at byte {exc.start}); save the file as UTF-8") from exc


# ---- showing things --------------------------------------------------------------------

def shown_path(path: str | Path) -> str:
    """A path as a person would type it on a command line: printable, and in double quotes if it has a space."""
    text = printable(str(path), limit=500)
    return f'"{text}"' if " " in text else text


def shown_value(value: Any, limit: int = 80) -> str:
    """One argument value, as JSON writes it, shortened and made printable."""
    try:
        spelled = json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError, RecursionError):
        spelled = repr(value)
    return printable(spelled, limit=limit)


def shown_args(args: Any, most: int = 8, limit: int = 80) -> str:
    """Arguments as `name="value", other=5`, with at most `most` of them and each value shortened."""
    if not isinstance(args, dict):
        return shown_value(args, limit)
    parts = [f"{printable(name, limit=60)}={shown_value(value, limit)}" for name, value in list(args.items())[:most]]
    if len(args) > most:
        parts.append(f"... (+{len(args) - most} more)")
    return ", ".join(parts)


def shown_call(tool: Any, args: Any) -> str:
    """A call as `tool(name="value", ...)`, every part printable."""
    return f"{printable(tool, limit=80)}({shown_args(args)})"


def without_ref(text: str) -> str:
    """A block's public text without the random reference at its end."""
    return _REF_SUFFIX.sub("", text)


def print_field(label: str, text: str, indent: int = 2, width: int = 110) -> None:
    """Print `label: text`, with long text wrapped under itself. `text` must already be printable.

    Long words (a pattern, a path) are never broken, so they can be copied whole.
    An empty label continues the field above it.
    """
    lead = " " * indent + f"{label + ':' if label else '':13}"
    print(textwrap.fill(
        text, width=width, initial_indent=lead, subsequent_indent=" " * len(lead),
        break_long_words=False, break_on_hyphens=False,
    ) or lead.rstrip())


def non_negative_int(text: str) -> int:
    """An argparse type: a whole number of 0 or more."""
    try:
        value = int(text) if len(text) <= 18 else -1
    except ValueError:
        raise argparse.ArgumentTypeError(f"must be a whole number, got {quoted(text, limit=40)}") from None
    if value < 0:
        raise argparse.ArgumentTypeError("must be a whole number from 0 to 999999999999999999")
    return value


def positive_int(text: str) -> int:
    """An argparse type: a whole number of 1 or more."""
    value = non_negative_int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return value
