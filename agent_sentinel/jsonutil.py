"""Strict JSON reading, shared by the library and the commands.

Python's json module reads more than JSON allows, and each extra is a way for
a file or a message to mean something other than what a person reading it
sees, or to make reading it slow:

  * NaN and Infinity are read as numbers (JSON has no such words);
  * 1e999 is read as infinity, which cannot be written back as JSON;
  * of two equal keys in one object, the last is kept without a word, so a
    second "run_shell": "allow" further down a file replaces the first;
  * an integer of any length is read, and the work grows with the square
    of its length (Python 3.11 and later refuse past 4300 digits; 3.10 does not).

The hooks here refuse all of them by raising ValueError, which each caller
turns into its own kind of error (a PolicyError, a CommandError, a
malformed hook event, a state file read as damaged).
"""

from __future__ import annotations

import json
import math
from typing import Any

from .policy_errors import json_error_message, quoted
from .textutil import printable

# Python 3.11 and later refuse to read an integer of more digits than this. The
# same limit is applied on 3.10, so that a file reads the same everywhere.
MAX_INT_DIGITS = 4300


class RepeatedKeyError(ValueError):
    """A key that appears twice in one JSON object (`key`)."""

    def __init__(self, key: str) -> None:
        super().__init__(f"the key {quoted(key, limit=60)} appears twice in one object")
        self.key = key


def bounded_int(text: str) -> int:
    """json's parse_int: an integer, unless it has more digits than MAX_INT_DIGITS (then ValueError).

    The digits are counted here, before int() sees them, so that the answer
    does not depend on the interpreter's own limit (none before 3.10.7, or
    when it is turned off).
    """
    if len(text) - text.startswith("-") > MAX_INT_DIGITS:
        raise ValueError(f"a number with more than {MAX_INT_DIGITS} digits")
    return int(text)


def finite_float(text: str) -> float:
    """json's parse_float: a number, unless it is too large for one (1e999 would become infinity)."""
    value = float(text)
    if not math.isfinite(value):
        raise ValueError(f"{text[:20]} is too large for a number")
    return value


def no_constant(name: str) -> Any:
    """json's parse_constant: NaN, Infinity and -Infinity are not JSON."""
    raise ValueError(f"{name} is not valid JSON")


def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """json's object_pairs_hook: one object, or RepeatedKeyError for a key that appears twice in it."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RepeatedKeyError(key)
        result[key] = value
    return result


def loads(text: str | bytes) -> Any:
    """Parse strict JSON with every hook above. Raises ValueError (or RecursionError for absurd nesting)."""
    return json.loads(text, object_pairs_hook=unique_keys, parse_int=bounded_int, parse_float=finite_float,
                      parse_constant=no_constant)


def strict_loads(text: str, label: str) -> Any:
    """Parse strict JSON, or raise ValueError with a message for a person that starts with `label`.

    A syntax error names the line and column, shows the line with a caret,
    and adds a hint for the common mistakes (policy_errors.json_error_message).
    """
    try:
        return loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(json_error_message(label, exc)) from exc
    except RepeatedKeyError as exc:
        raise ValueError(f"{label}: {exc}") from exc
    except (ValueError, RecursionError) as exc:  # absurd nesting, a huge number, NaN
        raise ValueError(f"{label}: not valid JSON ({printable(exc, limit=100)})") from exc
