"""Small text helpers shared by the other modules.

`texts_in` and `text_views` collect the text inside a nested value so that it
can be matched against a policy or scanned for injection. `printable` makes
untrusted text safe to show on a terminal.
"""

from __future__ import annotations

import array
import dataclasses
import json
import unicodedata
from collections import UserString, deque
from collections.abc import Iterator, Mapping, Sequence
from typing import Any


class UnscannableError(TypeError):
    """A value holds something whose text cannot be collected, so the value cannot be checked."""


# Put between two fields of a structured value in the view that lists every key
# and string (see `text_views`). The detector treats it as the end of a
# sentence. A visible symbol on purpose: it must survive normalization.
FIELD_BREAK = "␞"

# How many containers (lists, objects) one walk may open. JSON of a few
# megabytes stays far below this. It stops a value built in code out of shared
# parts, which can describe more containers than it has bytes.
MAX_CONTAINERS = 2_000_000

# Where a text sits inside a value is called its group: a small number that
# stands for the path to it ("content/*/text"). Dictionary keys get no path.
_ROOT = 0
_KEY = -1
# Stands for every position in a list, so that all members of a list share one path.
_ANY_POSITION = object()
# Marks, on the walk's stack, the point where everything inside a container has been read.
_LEAVE = object()


def texts_in(value: Any, *, keys: bool = True, scalars: bool = False, strict: bool = False) -> list[str]:
    """Collect the text inside a JSON-like value, however deeply nested, in document order.

    keys:    also collect dictionary keys (an attacker can hide text there).
    scalars: also collect numbers, booleans and null, written as JSON.
    strict:  raise UnscannableError for a value that cannot be walked (see below)
             instead of leaving it out.

    Beyond JSON, bytes are read as UTF-8, and sets, deques, mappings, lists,
    tuples and other sequences, and dataclass instances are walked.
    Generators, iterators, files, ranges and other objects are never read:
    iterating would use them up or never end, and their repr() hides what they
    hold. Without `strict` they are skipped (or written with str() when
    `scalars` is set), which is only safe where the value came from JSON and
    cannot contain them.

    Raises UnscannableError, strict or not, for a value with more than
    MAX_CONTAINERS nested parts.
    """
    return [text for _, text in _walk(value, keys=keys, scalars=scalars, strict=strict)]


def text_views(value: Any, *, strict: bool = False) -> list[str]:
    """The texts a scanner should read to see everything a JSON-like value says, without duplicates.

    A model does not read a structured value the way it is stored, so one
    reading is not enough:

      1. Every key and string, one per line, with FIELD_BREAK between fields.
         This is the reading that sees a phrase written across a key and its
         value ({"Do not": "tell the user"}). The break keeps field NAMES from
         reading as one sentence: {"email": ..., "token": ..., "url": ...} is
         an ordinary record, not an order to email a token to a URL.
      2. Every string that is not a key, joined by spaces: a phrase written
         across the values of two fields ({"title": "Do not", "body": "tell
         the user"}).
      3. For each set of two or more strings at the same path, counting all
         positions of a list as one ("content/*/text"): joined by spaces, and
         joined by nothing. These see a phrase, or a single word, split over
         the items of a list, where reading 1 has the items' keys in between.

    Blank views are left out. `strict` is as in `texts_in`.
    """
    everything: list[str] = []
    values: list[str] = []
    siblings: dict[int, list[str]] = {}
    for group, text in _walk(value, keys=True, scalars=False, strict=strict):
        if group == _KEY:
            if everything:
                everything.append(FIELD_BREAK)
        else:
            values.append(text)
            siblings.setdefault(group, []).append(text)
        everything.append(text)

    views = ["\n".join(everything)]
    if len(values) > 1:
        views.append(" ".join(values))
    for texts in siblings.values():
        if len(texts) > 1:
            views += [" ".join(texts), "".join(texts)]
    return list(dict.fromkeys(view for view in views if view.strip()))


def _walk(value: Any, *, keys: bool, scalars: bool, strict: bool) -> Iterator[tuple[int, str]]:
    """Yield (group, text) for every text in `value`, in document order.

    Iterative on purpose: untrusted input can be nested deeply enough to
    exhaust Python's recursion limit. For the same reason a path is a number
    looked up in `paths`, not a tuple that grows with the depth.
    """
    paths: dict[tuple[int, Any], int] = {}
    # The containers the walk is inside of right now, by id(). One that holds
    # itself is not entered a second time. One that merely appears twice is
    # read twice, as its JSON would be.
    inside: set[int] = set()
    opened = 0
    stack: list[tuple[Any, Any]] = [(value, _ROOT)]
    while stack:
        item, group = stack.pop()
        if group is _LEAVE:
            inside.discard(item)
        elif isinstance(item, str):
            yield group, item
        elif isinstance(item, UserString):
            yield group, str(item)
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
            elif id(item) not in inside:
                opened += 1
                if opened > MAX_CONTAINERS:
                    raise UnscannableError("the value has too many nested parts to scan")
                inside.add(id(item))
                stack.append((id(item), _LEAVE))  # reached once everything pushed below has been read
                named, listed = members
                # Pushed in reverse so that text comes out in document order.
                if listed:
                    position = paths.setdefault((group, _ANY_POSITION), len(paths) + 1)
                    stack.extend([(child, position) for child in reversed(listed)])
                for key, child in reversed(named):
                    stack.append((child, paths.setdefault((group, key), len(paths) + 1)))
                    if keys:
                        stack.append((key, _KEY))


def _members(item: Any) -> tuple[list[tuple[Any, Any]], list[Any]] | None:
    """What a container holds, as (named children, listed children); None if `item` is not a container.

    Each kind is checked separately because a value can be more than one at
    once (a dataclass that subclasses list), and every part of it must be read.
    A range and an array are not treated as containers: a range can stand for
    billions of numbers, and an array of characters is text in a form the
    scanner would read one letter at a time.
    """
    if isinstance(item, (range, array.array)):
        return None
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
    at `limit` characters, and says how much was cut: someone approving a
    call must be able to tell that there is more than they were shown.
    """
    text = str(text)
    cut = len(text) - limit
    shown: list[str] = []
    marks_in_a_row = 0
    for ch in text[:limit] if cut > 0 else text:
        is_mark = unicodedata.category(ch) in ("Mn", "Me") or unicodedata.combining(ch) != 0
        marks_in_a_row = marks_in_a_row + 1 if is_mark else 0
        if ch.isprintable() and ord(ch) not in _BLANK and marks_in_a_row <= _MARKS_SHOWN_IN_A_ROW:
            shown.append(ch)
        else:
            shown.append(ch.encode("unicode_escape").decode("ascii"))
    if cut > 0:
        shown.append(f"... (+{cut} more characters)")
    return "".join(shown)
