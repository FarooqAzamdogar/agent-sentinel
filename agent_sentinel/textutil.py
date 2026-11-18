"""Small text helpers shared by the other modules.

`texts_in` and `text_views` collect the text inside a nested value so that it
can be matched against a policy or scanned for injection. `printable` makes
untrusted text safe to show on a terminal.
"""

from __future__ import annotations

import dataclasses
import json
import unicodedata
from collections import deque
from collections.abc import Iterator, Mapping, Sequence
from typing import Any


class UnscannableError(TypeError):
    """A value holds something whose text cannot be collected, so the value cannot be checked."""


# Where a text sits inside a value is called its group: a small number that
# stands for the path to it ("content/*/text"). Dictionary keys get no path.
_ROOT = 0
_KEY = -1
# Stands for every position in a list, so that all members of a list share one path.
_ANY_POSITION = object()


def texts_in(value: Any, *, keys: bool = True, scalars: bool = False, strict: bool = False) -> list[str]:
    """Collect the text inside a JSON-like value, however deeply nested, in document order.

    keys:    also collect dictionary keys (an attacker can hide text there).
    scalars: also collect numbers, booleans and null, written as JSON.
    strict:  raise UnscannableError for a value that cannot be walked (see below)
             instead of leaving it out.

    Beyond JSON, bytes are read as UTF-8, and sets, deques, any mapping, any
    sequence and dataclass instances are walked. Generators, iterators, files
    and other objects are never read: iterating would use them up, and their
    repr() hides what they hold. Without `strict` they are skipped (or written
    with str() when `scalars` is set), which is only safe where the value came
    from JSON and cannot contain them.
    """
    return [text for _, text in _walk(value, keys=keys, scalars=scalars, strict=strict)]


def text_views(value: Any, *, strict: bool = False) -> list[str]:
    """The texts a scanner should read to see everything a JSON-like value says, without duplicates.

    The first view is every key and string joined by newlines. That alone
    misses a phrase split over the items of a list, because the keys of each
    item land between the halves:

        {"content": [{"type": "text", "text": "Do not"}, {"type": "text", "text": "tell the user"}]}

    So each set of two or more strings that sit at the same path, counting all
    positions of a list as one ("content/*/text"), is also given as one view,
    joined by spaces. Blank views are left out. `strict` is as in `texts_in`.
    """
    everything: list[str] = []
    siblings: dict[int, list[str]] = {}
    for group, text in _walk(value, keys=True, scalars=False, strict=strict):
        everything.append(text)
        if group != _KEY:
            siblings.setdefault(group, []).append(text)
    views = ["\n".join(everything)]
    views += [" ".join(texts) for texts in siblings.values() if len(texts) > 1]
    return list(dict.fromkeys(view for view in views if view.strip()))


def _walk(value: Any, *, keys: bool, scalars: bool, strict: bool) -> Iterator[tuple[int, str]]:
    """Yield (group, text) for every text in `value`, in document order.

    Iterative on purpose: untrusted input can be nested deeply enough to
    exhaust Python's recursion limit. For the same reason a path is a number
    looked up in `paths`, not a tuple that grows with the depth.
    """
    paths: dict[tuple[int, Any], int] = {}
    # Containers already walked, by id(). A container that holds itself would
    # otherwise never end. Keeping the object as the value keeps it alive, so
    # that its id cannot be handed to a different object during the walk.
    walked: dict[int, Any] = {}
    stack: list[tuple[Any, int]] = [(value, _ROOT)]
    while stack:
        item, group = stack.pop()
        if isinstance(item, str):
            yield group, item
        elif isinstance(item, (bytes, bytearray, memoryview)):
            yield group, bytes(item).decode("utf-8", errors="replace")
        elif item is None or isinstance(item, (bool, int, float)):
            if scalars:
                yield group, json.dumps(item)
        else:
            members = _members(item)
            if members is None:
                if strict:
                    raise UnscannableError(f"a value of type {type(item).__name__} cannot be scanned")
                if scalars:
                    yield group, json.dumps(item, default=str)
            elif id(item) not in walked:
                walked[id(item)] = item
                named, listed = members
                # Pushed in reverse so that text comes out in document order.
                if listed:
                    inside = paths.setdefault((group, _ANY_POSITION), len(paths) + 1)
                    stack.extend([(child, inside) for child in reversed(listed)])
                for key, child in reversed(named):
                    stack.append((child, paths.setdefault((group, key), len(paths) + 1)))
                    if keys:
                        stack.append((key, _KEY))


def _members(item: Any) -> tuple[list[tuple[Any, Any]], list[Any]] | None:
    """What a container holds, as (named children, listed children); None if `item` is not a container.

    Each kind is checked separately because a value can be more than one at
    once (a dataclass that subclasses list), and every part of it must be read.
    """
    named: list[tuple[Any, Any]] = []
    listed: list[Any] = []
    is_container = False
    if isinstance(item, Mapping):
        named.extend(item.items())
        is_container = True
    if dataclasses.is_dataclass(item) and not isinstance(item, type):
        named.extend((field.name, getattr(item, field.name, None)) for field in dataclasses.fields(item))
        is_container = True
    if isinstance(item, (Sequence, set, frozenset, deque)):
        listed.extend(item)
        is_container = True
    return (named, listed) if is_container else None


# Code points that str.isprintable() accepts although they draw nothing:
# variation selectors, the grapheme joiner, Hangul and Khmer fillers,
# Mongolian separators and the blank Braille pattern.
_BLANK = frozenset([
    0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, *range(0x180B, 0x1810), 0x2800, 0x3164,
    *range(0xFE00, 0xFE10), 0xFFA0, *range(0xE0100, 0xE01F0),
])
# Accented, Arabic and Indic text puts one or two marks on a letter. More than
# that is a "zalgo" stack that spills over the lines above and below.
_MARKS_SHOWN_IN_A_ROW = 2


def printable(text: Any, limit: int = 300) -> str:
    """Make untrusted text safe to print on a terminal.

    Control characters (including the escape sequences that can recolor,
    hide or rewrite terminal output), invisible characters and long stacks of
    combining marks are shown as escapes such as ``\\x1b``. Long text is cut
    at `limit` characters.
    """
    text = str(text)
    if len(text) > limit:
        text = text[:limit] + "..."
    shown: list[str] = []
    marks_in_a_row = 0
    for ch in text:
        is_mark = unicodedata.category(ch) in ("Mn", "Me") or unicodedata.combining(ch) != 0
        marks_in_a_row = marks_in_a_row + 1 if is_mark else 0
        if ch.isprintable() and ord(ch) not in _BLANK and marks_in_a_row <= _MARKS_SHOWN_IN_A_ROW:
            shown.append(ch)
        else:
            shown.append(ch.encode("unicode_escape").decode("ascii"))
    return "".join(shown)
