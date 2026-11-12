"""Small text helpers shared by the other modules."""

from __future__ import annotations

import json
from typing import Any


def texts_in(value: Any, *, keys: bool = True, scalars: bool = False) -> list[str]:
    """Collect the text inside a JSON-like value, however deeply nested.

    keys:    also collect dictionary keys (an attacker can hide text there).
    scalars: also collect numbers, booleans and null, written as JSON.

    Iterative on purpose: untrusted input can be nested deeply enough to
    exhaust Python's recursion limit.
    """
    found: list[str] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            found.append(item)
        elif isinstance(item, dict):
            # Reversed so that text comes out in document order.
            for key, child in reversed(list(item.items())):
                stack.append(child)
                if keys:
                    stack.append(key)
        elif isinstance(item, (list, tuple)):
            stack.extend(reversed(item))
        elif scalars:
            found.append(json.dumps(item, default=str))
    return found


def printable(text: Any, limit: int = 300) -> str:
    """Make untrusted text safe to print on a terminal.

    Control characters (including the escape sequences that can recolor,
    hide or rewrite terminal output) and invisible characters are shown as
    escapes such as ``\\x1b``. Long text is cut at `limit` characters.
    """
    text = str(text)
    if len(text) > limit:
        text = text[:limit] + "..."
    return "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in text)
