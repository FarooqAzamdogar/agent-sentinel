"""Error messages that help the author of a policy fix it.

Loading a policy is strict, and stays exactly as strict with these helpers:
they only explain. A suggestion is never applied for the author. "alow" is
still refused, with a note that "allow" was probably meant.

Everything here is about the operator's own file, but it is still passed
through `printable` before it is shown, because a policy can be copied from
anywhere.
"""

from __future__ import annotations

import difflib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

from .textutil import printable


class PolicyError(ValueError):
    """The policy is malformed."""


# Words people write for an action, and the action they mean. Used only for
# a "did you mean" hint, and only when the meant word is one of the choices.
_SYNONYMS = {
    "deny": "block", "denied": "block", "reject": "block", "rejected": "block", "refuse": "block",
    "refused": "block", "forbid": "block", "forbidden": "block", "disallow": "block", "disallowed": "block",
    "blocked": "block", "drop": "block",
    "permit": "allow", "permitted": "allow", "allowed": "allow", "accept": "allow", "accepted": "allow",
    "pass": "allow", "enable": "allow", "enabled": "allow",
    "confirm": "ask", "prompt": "ask", "approve": "ask", "approval": "ask", "review": "ask", "asked": "ask",
}

# A word longer than this gets no suggestion: difflib's work grows with its length.
_LONGEST_WORD_COMPARED = 100
# One error names at most this many unknown keys; the rest are counted.
_UNKNOWN_KEYS_NAMED = 5

# How much of a long line of JSON is shown around the place of an error.
_CONTEXT_BEFORE = 60
_CONTEXT_AFTER = 30

# From a backslash to the end of the word it starts: "\.ssh" in "pattern": "\.ssh|id_rsa".
_WORD_AFTER_BACKSLASH = re.compile(r'\\[^"\s|,()\[\]{}]{0,20}')


# ---- naming values in messages ----------------------------------------------

def quoted(value: Any, limit: int = 60) -> str:
    """A value as it should appear in a message: text in single quotes, anything else as JSON writes it."""
    if isinstance(value, str):
        return f"'{printable(value, limit=limit)}'"
    try:
        spelled = json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError, RecursionError):
        spelled = repr(value)
    return printable(spelled, limit=limit)


def listed(words: Iterable[str]) -> str:
    """'a', 'b' or 'c'."""
    shown = [quoted(word) for word in words]
    if len(shown) < 2:
        return "".join(shown)
    return f"{', '.join(shown[:-1])} or {shown[-1]}"


def type_name(value: Any) -> str:
    """What a JSON value is, in the words a policy author uses."""
    if isinstance(value, bool):
        return "true or false"
    if value is None:
        return "null"
    if isinstance(value, dict):
        return "an object"
    if isinstance(value, (list, tuple)):
        return "a list"
    if isinstance(value, str):
        return "text"
    if isinstance(value, (int, float)):
        return "a number"
    return f"a value of type {type(value).__name__}"


# ---- suggestions --------------------------------------------------------------

def did_you_mean(word: Any, choices: Iterable[str]) -> str | None:
    """The choice the author most probably meant by `word`, or None.

    In order: the same word in another case or with spaces around it, a
    common synonym ("deny" for "block"), then the closest spelling.
    """
    if not isinstance(word, str) or len(word) > _LONGEST_WORD_COMPARED:
        return None
    choices = list(choices)
    folded = word.strip().lower()
    for choice in choices:
        if folded == choice.lower():
            return choice
    synonym = _SYNONYMS.get(folded)
    if synonym in choices:
        return synonym
    close = difflib.get_close_matches(folded, choices, n=1, cutoff=0.6)
    return close[0] if close else None


def unknown_keys_message(where: str, unknown: list[str], allowed: Iterable[str]) -> str:
    """Name each unknown key, with the key that was probably meant."""
    allowed = list(allowed)
    sentences = []
    for key in unknown[:_UNKNOWN_KEYS_NAMED]:
        hint = did_you_mean(key, allowed)
        sentences.append(f"unknown key {quoted(key)} in {where}" + (f"; did you mean {quoted(hint)}?" if hint else "."))
    if len(unknown) > _UNKNOWN_KEYS_NAMED:
        sentences.append(f"And {len(unknown) - _UNKNOWN_KEYS_NAMED} more unknown key(s).")
    sentences.append(f"Allowed keys: {', '.join(allowed)}")
    return " ".join(sentences)


def choice_message(where: str, value: Any, choices: Iterable[str]) -> str:
    """Say that `value` is not one of `choices`, and what was probably meant."""
    choices = list(choices)
    message = f"{where} must be {listed(choices)}, got {quoted(value)}"
    if not isinstance(value, str):
        return f"{message}, which is {type_name(value)}; write the word in double quotes"
    hint = did_you_mean(value, choices)
    if hint is None:
        return message
    if value.strip().lower() == hint and value != hint:
        return f"{message}; these words are written in lowercase, without spaces: {quoted(hint)}"
    return f"{message}; did you mean {quoted(hint)}?"


# ---- errors in the file itself ----------------------------------------------

def json_error_message(label: str, error: json.JSONDecodeError) -> str:
    """Report a JSON syntax error with its line and column, the line itself, a caret, and a hint.

        policy.json:2:42: not valid JSON: Invalid \\escape
              "deny_args": [{"arg": "*", "pattern": "\\.ssh"}]
                                                     ^
        In JSON a backslash must be doubled. For the regular expression \\.ssh write "\\\\.ssh".
    """
    lines = [f"{label}:{error.lineno}:{error.colno}: not valid JSON: {error.msg}"]
    source_lines = error.doc.split("\n")
    if 0 < error.lineno <= len(source_lines):
        excerpt, caret = _excerpt(source_lines[error.lineno - 1].rstrip("\r"), error.colno - 1)
        lines += [f"    {excerpt}", f"    {caret}"]
    hint = _json_hint(error)
    if hint:
        lines.append(hint)
    return "\n".join(lines)


def _excerpt(line: str, column: int) -> tuple[str, str]:
    """The part of `line` around `column`, made printable, and a caret line pointing at that column."""
    start = max(0, column - _CONTEXT_BEFORE)
    end = min(len(line), column + _CONTEXT_AFTER)
    before = "..." if start > 0 else ""
    after = "..." if end < len(line) else ""
    # The caret is placed by the printed width of what comes before it, so an
    # escaped tab or control character does not push it out of line.
    lead = before + printable(line[start:column], limit=_CONTEXT_BEFORE + _CONTEXT_AFTER)
    shown = before + printable(line[start:end], limit=_CONTEXT_BEFORE + _CONTEXT_AFTER) + after
    return shown, " " * len(lead) + "^"


def _json_hint(error: json.JSONDecodeError) -> str | None:
    """A sentence on how to fix the most common JSON mistakes in a policy, or None."""
    doc, pos, message = error.doc, error.pos, error.msg
    here = doc[pos:pos + 2]
    if message.startswith("Invalid \\escape") and here.startswith("\\"):
        # The author's own text from the backslash to the end of the word, written both ways.
        word = _WORD_AFTER_BACKSLASH.match(doc, pos)
        written = word.group() if word else here
        return (
            f"In JSON a backslash must be doubled. For the regular expression {printable(written, limit=30)} "
            f"write \"{printable(written.replace(chr(92), chr(92) * 2), limit=60)}\"."
        )
    if "trailing comma" in message or (here[:1] in ("}", "]") and doc[:pos].rstrip().endswith(",")):
        return "JSON allows no comma after the last item of a list or object: remove that comma."
    if here[:1] == "'":
        return "JSON needs double quotes (\") around text and key names, not single quotes."
    if here in ("//", "/*") or here[:1] == "#":
        return "JSON has no comments: remove the comment."
    if message.startswith("Invalid control character"):
        return "A line break or tab inside text must be written as \\n or \\t."
    return None


def unicode_error_message(label: str, error: UnicodeDecodeError) -> str:
    """A file that is not UTF-8 text, with a note when it looks like UTF-16 (which some Windows editors save)."""
    data = error.object if isinstance(error.object, (bytes, bytearray)) else b""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return f"{label}: the file is saved as UTF-16; save it as UTF-8"
    return f"{label}: not valid UTF-8 text (at byte {error.start}); save the file as UTF-8"


def file_error_message(path: str | Path, error: OSError) -> str:
    """Why a policy file could not be read, with its full path and the folder a relative path starts from."""
    absolute = os.path.abspath(path)
    try:
        here = os.getcwd()
    except OSError:
        here = "unknown"
    if isinstance(error, FileNotFoundError):
        return f"there is no policy file at {absolute} (the current folder is {here})"
    reason = error.strerror or type(error).__name__
    return f"cannot read the policy file {absolute}: {reason} (the current folder is {here})"
