"""Small text helpers shared by the other modules.

`texts_in` and `text_views` collect the text inside a nested value so that it
can be matched against a policy or scanned for injection. `printable` makes
untrusted text safe to show on a terminal.

Also here, because the detector and the secret guard both need them:

  * `normalised_arguments`, the JSON-shaped copy of a call's arguments that
    every check reads, and `numbers_in`, the numbers of a value as JSON writes them;
  * `TERMINAL_ESCAPE` and the Unicode tag-character helpers (`decode_tags`,
    `smuggled_text`), the decoder of the other invisible carriers
    (`decode_invisible`), and `clean_for_forwarding`, which removes escapes,
    tags and other hiding characters from text that is passed on to a client;
  * `folded_text`, one spelling of a text with compatibility forms folded and
    format characters removed;
  * `tool_parameters` and `media_blocks`, which pick parts out of MCP
    messages for the detector;
  * `EncodedRuns`, the bounded decoder of base64 and hex runs (`DecodedRun`).
"""

from __future__ import annotations

import array
import base64
import binascii
import dataclasses
import datetime
import decimal
import enum
import itertools
import json
import os
import re
import sys
import unicodedata
import uuid
from collections import UserString, deque
from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import Any, NamedTuple


class UnscannableError(TypeError):
    """A value holds something whose text cannot be collected, so the value cannot be checked."""


# Put between two fields of a structured value in the view that lists every key
# and string (see `text_views`). The detector treats it as the end of a
# sentence. A visible symbol on purpose: it must survive normalization. Only
# text_views may write one: the same character in the text itself would end a
# sentence where a model reads none, so it is made a space first
# (`without_field_breaks`).
FIELD_BREAK = "␞"


def without_field_breaks(text: str) -> str:
    """`text` with each FIELD_BREAK in it made a space: what the detector reads of untrusted text.

    For a text scanned on its own (not through text_views, which does this
    itself), so that an attacker cannot end a sentence for the detector by
    writing the character between the words of one order.
    """
    return text.replace(FIELD_BREAK, " ") if FIELD_BREAK in text else text

# How many containers (lists, objects) one walk may open. JSON of a few
# megabytes stays far below this. It stops a value built in code out of shared
# parts, which can describe more containers than it has bytes.
MAX_CONTAINERS = 2_000_000

# Where a text sits inside a value is called its group: a small number that
# stands for the path to it ("content/*/text"). Dictionary keys get no path,
# and neither does the data of a rendered image or audio block (see text_views).
_ROOT = 0
_KEY = -1
_MEDIA = -2
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
    `scalars` is set, without quotes, so that a pattern anchored at the start
    of a value still reads it), which is only safe where the value came from
    JSON and cannot contain them: a call's arguments are first made JSON
    (`normalised_arguments`).

    Raises UnscannableError, strict or not, for a value with more than
    MAX_CONTAINERS nested parts.
    """
    return [text for _, text in _walk(value, keys=keys, scalars=scalars, strict=strict)]


def text_views(value: Any, *, strict: bool = False, media: list[str] | None = None) -> list[str]:
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

    Blank views are left out. `strict` is as in `texts_in`. A FIELD_BREAK in
    the value's own text becomes a space, so every one in a view is a real break.

    media: when a list is given, the "data" of each image and audio content
    block that sits where a client renders content (`media_blocks`) is put
    there instead of into the views. A client shows that data as a picture or
    a sound, never as text, so it takes part in no phrase; the caller scans
    it on its own, without decoding it. Image-shaped objects anywhere else
    (_meta, structuredContent) stay in the views like any other text.
    """
    everything: list[str] = []
    values: list[str] = []
    siblings: dict[int, list[str]] = {}
    blocks = media_blocks(value) if media is not None else frozenset()
    for group, text in _walk(value, keys=True, scalars=False, strict=strict, media=blocks):
        if group == _MEDIA:
            assert media is not None
            media.append(text)
            continue
        text = without_field_breaks(text)
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
            texts = _without_long_repeats(texts)
            views += [" ".join(texts), "".join(texts)]
    return list(dict.fromkeys(view for view in views if view.strip()))


# The longest rule the detector has is a chain of three steps, so a phrase
# pieced together from copies of ONE string needs at most three of them.
_REPEATS_KEPT = 3


def _without_long_repeats(texts: list[str]) -> list[str]:
    """Drop all but the first few of each run of identical strings.

    Every item of a long list tends to carry the same values ("type": "text"
    a thousand times). Joining them all says nothing a few copies do not, and
    scanning the result costs time in proportion to its length.
    """
    kept: list[str] = []
    run = 0
    for text in texts:
        run = run + 1 if kept and text == kept[-1] else 1
        if run <= _REPEATS_KEPT:
            kept.append(text)
    return kept


def _walk(
    value: Any, *, keys: bool, scalars: bool, strict: bool, media: frozenset[int] | set[int] = frozenset()
) -> Iterator[tuple[int, str]]:
    """Yield (group, text) for every text in `value`, in document order.

    Iterative on purpose: untrusted input can be nested deeply enough to
    exhaust Python's recursion limit. For the same reason a path is a number
    looked up in `paths`, not a tuple that grows with the depth.

    media: the id() of content blocks (`media_blocks`) whose "data" string is
    yielded with the group _MEDIA instead of its path.
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
                yield group, number_text(item) if type(item) in (int, float) else json.dumps(item)
        else:
            members = _members(item)
            if members is None:
                if strict:
                    raise UnscannableError(f"a value of type {type(item).__name__} cannot be scanned")
                if scalars:
                    # str(), not json.dumps(default=str): its quotes would keep "^/etc/" from matching.
                    yield group, str(item)
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
                rendered = id(item) in media
                for key, child in reversed(named):
                    if rendered and key == "data" and type(child) is str:
                        stack.append((child, _MEDIA))
                    else:
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


# --------------------------------------------------------------------------
# The arguments of a call, as JSON
# --------------------------------------------------------------------------

# How deeply the arguments of one call may be nested. Far deeper than any
# real call: the audit log writes the arguments with json.dumps, which
# recurses, and a value that holds itself must end somewhere.
MAX_ARGUMENT_DEPTH = 256
# How many parts (objects, arrays, strings, numbers...) the arguments of one
# call may have in all. A message of 16 MB of JSON has fewer.
MAX_ARGUMENT_PARTS = 4_000_000
# An integer longer than this many bits (about 4,200 digits) is refused: Python
# will not write a longer one as text, and JSON read by this package has none.
_MAX_INT_BITS = 14_000
# Values that are written as their str(): what a library would send for them.
_WRITTEN_AS_TEXT = (uuid.UUID, datetime.datetime, datetime.date, datetime.time, decimal.Decimal)
_ARRAYS = (list, tuple, set, frozenset, deque)


def normalised_arguments(value: Any) -> Any:
    """A copy of a call's arguments as JSON-shaped data: what every check of the call reads.

    The tool still gets the original objects; this copy is what the secret
    guard, the policy, the audit log and an approver see. Each part becomes:

      * text, numbers, true, false and null: themselves (a subclass of str,
        int or float becomes the plain type); bytes stay bytes (read as UTF-8);
      * an Enum: its value, made JSON in turn;
      * a path (os.PathLike): os.fspath() of it;
      * an object with model_dump (a pydantic model): model_dump(mode="json");
      * a dataclass instance: an object of its fields, as dataclasses.asdict gives;
      * a UUID, a datetime, date or time, a Decimal: its str();
      * a mapping: an object (keys become text as JSON writes them; two keys
        that become the same text are refused); a list, tuple, set,
        frozenset or deque: an array;
      * a pydantic secret (get_secret_value): its value, so that the check
        reads what the tool will; another pydantic value (an HttpUrl): what
        pydantic writes for it in JSON.

    Raises UnscannableError for anything else (a generator, a file, an object
    of unknown kind), for a value nested more than MAX_ARGUMENT_DEPTH deep or
    with more than MAX_ARGUMENT_PARTS parts, and for an integer too long to
    write: the call is then refused, never checked with parts left out.
    Iterative, so a deep value cannot exhaust Python's recursion limit.
    """
    holder: list[Any] = [None]
    stack: list[tuple[Any, Any, Any, int]] = [(value, holder, 0, 0)]
    inside: set[int] = set()  # the containers being copied right now: one that holds itself is refused
    parts = 0
    while stack:
        item, parent, key, depth = stack.pop()
        if parent is _LEAVE:
            inside.discard(item)
            continue
        parts += 1
        if parts > MAX_ARGUMENT_PARTS:
            raise UnscannableError("the arguments have too many parts to check")
        if depth > MAX_ARGUMENT_DEPTH:
            raise UnscannableError("the arguments are nested too deeply to check")
        if type(item) in _JSON_LEAVES:
            parent[key] = _checked_number(item) if type(item) is int else item
            continue
        converted = _CONTAINER if type(item) in (dict, list, tuple) else _converted(item)
        if converted is _CONTAINER:
            parts += _copy_container(item, parent, key, depth, stack, inside)
            if parts > MAX_ARGUMENT_PARTS:
                raise UnscannableError("the arguments have too many parts to check")
        elif type(converted) is _Leaf:
            parent[key] = converted.value
        else:
            stack.append((converted, parent, key, depth + 1))  # read again: a value may become another
    return holder[0]


# The parts that are JSON as they are, copied without a look further (an int is checked for its length).
_JSON_LEAVES = frozenset([str, bool, int, float, type(None)])


class _Leaf(NamedTuple):
    """What a part became, final: text, bytes or a number."""

    value: Any


_CONTAINER = object()  # `_converted`: the part is a container, to be copied member by member


def _checked_number(number: int | float) -> int | float:
    if type(number) is int and number.bit_length() > _MAX_INT_BITS:
        raise UnscannableError("an argument holds a number too long to check")
    return number


def number_text(number: int | float) -> str:
    """A number as JSON writes it ("12", "1.5", "-3e+20"), for the texts a check reads."""
    _checked_number(number)
    return json.dumps(number)


def _converted(item: Any) -> Any:
    """What a part that is not plain JSON becomes: a _Leaf, _CONTAINER, or another value to read again.

    Raises UnscannableError for a part of a kind that cannot be made JSON.
    """
    if isinstance(item, enum.Enum):  # before str and int: an Enum can be either as well
        return item.value
    if isinstance(item, str):
        return _Leaf(str.__str__(item))
    if isinstance(item, bool):
        return _Leaf(bool(item))
    if isinstance(item, int):
        return _Leaf(_checked_number(int.__int__(item)))
    if isinstance(item, float):
        return _Leaf(float.__float__(item))
    if isinstance(item, UserString):
        return _Leaf(str(item))
    if isinstance(item, (bytes, bytearray, memoryview)):
        try:
            return _Leaf(bytes(item))
        except (TypeError, ValueError) as exc:  # a released memoryview
            raise UnscannableError("an argument holds bytes that cannot be read") from exc
    if isinstance(item, type):
        raise UnscannableError(f"an argument is a class ({item.__name__}), which cannot be checked")
    if isinstance(item, os.PathLike):
        return _called(os.fspath, item)
    if callable(getattr(item, "model_dump", None)):
        return _called(lambda model: model.model_dump(mode="json"), item)
    if isinstance(item, (Mapping, *_ARRAYS)) or dataclasses.is_dataclass(item):
        if dataclasses.is_dataclass(item) and isinstance(item, (Mapping, *_ARRAYS)):
            raise UnscannableError(f"an argument of type {type(item).__name__} is two kinds of value at once")
        return _CONTAINER
    if isinstance(item, _WRITTEN_AS_TEXT):
        return _Leaf(str(item))
    if callable(getattr(item, "get_secret_value", None)):
        return _called(lambda secret: secret.get_secret_value(), item)
    pydantic_core = sys.modules.get("pydantic_core")
    if pydantic_core is not None and type(item).__module__.split(".")[0] in ("pydantic", "pydantic_core"):
        return _called(pydantic_core.to_jsonable_python, item)
    raise UnscannableError(f"an argument of type {type(item).__name__} cannot be checked")


def _called(function: Any, item: Any) -> Any:
    """function(item), with any error it raises turned into UnscannableError."""
    try:
        return function(item)
    except Exception as exc:  # the object's own code failed: what it holds cannot be known
        raise UnscannableError(f"an argument of type {type(item).__name__} could not be read") from exc


def _copy_container(
    item: Any, parent: Any, key: Any, depth: int, stack: list[tuple[Any, Any, Any, int]], inside: set[int]
) -> int:
    """Put a copy of a container in its place: its plain members copied now, the others put on the stack.

    Returns how many members it has, for the count of parts.
    """
    if id(item) in inside:
        raise UnscannableError("the arguments contain themselves, which JSON cannot hold")
    inside.add(id(item))
    stack.append((id(item), _LEAVE, None, depth))
    later: list[tuple[Any, Any, Any, int]] = []
    if type(item) is dict or isinstance(item, Mapping) or dataclasses.is_dataclass(item):
        if isinstance(item, Mapping):
            pairs: Iterable[tuple[Any, Any]] = item.items()
        else:
            pairs = [(field.name, getattr(item, field.name, None)) for field in dataclasses.fields(item)]
        copy: dict[str, Any] = {}
        parent[key] = copy
        for name, child in pairs:
            written = name if type(name) is str else _key_text(name)
            if written in copy:
                raise UnscannableError("two keys of one argument are the same once written as JSON")
            if type(child) in _JSON_LEAVES:
                copy[written] = _checked_number(child) if type(child) is int else child
            else:
                copy[written] = None  # holds the place, so that the order of keys is kept
                later.append((child, copy, written, depth + 1))
        members = len(copy)
    else:
        listed = item if isinstance(item, (list, tuple)) else list(item)  # a set or a deque: in its own order
        items: list[Any] = [None] * len(listed)
        parent[key] = items
        for index, child in enumerate(listed):
            if type(child) in _JSON_LEAVES:
                items[index] = _checked_number(child) if type(child) is int else child
            else:
                later.append((child, items, index, depth + 1))
        members = len(listed)
    later.reverse()  # taken from the stack in order
    stack.extend(later)
    return members


def _key_text(key: Any) -> str:
    """A key as JSON writes it: text stays text, 1 becomes "1", True "true", None "null"."""
    for _ in range(8):  # an Enum whose value is another Enum, and so on, ends somewhere
        if type(key) is str:
            return key
        if key is None or type(key) is bool:
            return json.dumps(key)
        if type(key) in (int, float):
            return number_text(key)
        converted = _converted(key)
        if converted is _CONTAINER:
            raise UnscannableError(f"an argument has a key of type {type(key).__name__}, which JSON cannot hold")
        key = converted.value if type(converted) is _Leaf else converted
        if isinstance(key, bytes):
            return key.decode("utf-8", errors="replace")
    raise UnscannableError("an argument has a key that cannot be written as JSON")


def numbers_in(value: Any) -> list[str]:
    """The integers and floats in a JSON-like value (never true or false), each as JSON writes it.

    For the secret guard: a known value or canary sent as a number. Walks what
    `texts_in` walks, iteratively; raises UnscannableError for a value with more
    than MAX_CONTAINERS nested parts.
    """
    found: list[str] = []
    waiting: list[Any] = [value]
    opened = 0
    while waiting:
        item = waiting.pop()
        if isinstance(item, (int, float)) and not isinstance(item, bool):
            found.append(number_text(item))
        elif item is None or isinstance(item, (bool, str, bytes, bytearray, memoryview, UserString)):
            continue
        else:
            members = _members(item)
            if members is None:
                continue
            opened += 1
            if opened > MAX_CONTAINERS:
                raise UnscannableError("the value has too many nested parts to scan")
            named, listed = members
            waiting.extend(child for _, child in named)
            waiting.extend(listed)
    return found


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


# --------------------------------------------------------------------------
# Percent-encoding
# --------------------------------------------------------------------------

# A run of percent escapes, decoded as one piece of UTF-8.
_PERCENT_RUN = re.compile(r"(?:%[0-9A-Fa-f]{2})+")


def percent_decoded(text: str) -> str:
    """One round of percent-decoding: what urllib.parse.unquote(text, errors="replace") returns, in linear time.

    unquote splits the text at every change between ASCII and other
    characters and decodes each ASCII piece in Python, which is several times
    slower when the two alternate ("aéaéaé..."). Only the runs of escapes need
    decoding, and the result is the same: a character between two escapes
    ends any UTF-8 sequence the first one started, so each run decodes on its own.
    """
    if "%" not in text:
        return text
    return _PERCENT_RUN.sub(lambda run: bytes.fromhex(run.group().replace("%", "")).decode("utf-8", "replace"), text)


# --------------------------------------------------------------------------
# Terminal escapes and Unicode tag characters
# --------------------------------------------------------------------------

# Terminal escape sequences: CSI (colours, cursor moves: ESC [ ... letter) and
# OSC (window titles, OSC 8 hyperlinks: ESC ] ... BEL or ESC \). Every part is
# bounded, so a hostile text cannot make one attempt read far ahead. A longer
# sequence is not matched; removing the ESC character then leaves it as
# harmless visible text.
TERMINAL_ESCAPE = re.compile(r"\x1b\[[0-?]{0,64}[ -/]{0,8}[@-~]|\x1b\][^\x07\x1b]{0,512}(?:\x07|\x1b\\)")

# Unicode tag characters (U+E0000 to U+E007F) draw nothing, and U+E0020 to
# U+E007E copy printable ASCII one to one. A sentence written in them is
# invisible to a person but read by a model ("ASCII smuggling"). Their one
# everyday use is a subdivision flag such as England's: a black flag, a few tag
# letters or digits, and the cancel tag U+E007F. Valid flags have at most six.
TAG_CHARACTERS = re.compile("[\U000e0000-\U000e007f]")
_FLAG_SEQUENCE = "\U0001f3f4[\U000e0030-\U000e0039\U000e0061-\U000e007a]{1,6}\U000e007f"
_FLAG_SEQUENCE_RE = re.compile(_FLAG_SEQUENCE)
# A flag, or a run of tag characters that is not one. Tried at each position
# in that order, so the tags of a flag are never read as a hidden run.
_FLAG_OR_TAGS = re.compile(f"(?P<flag>{_FLAG_SEQUENCE})|[\U000e0000-\U000e007f]+")
# What each tag character stands for: U+E0020..U+E007E become ASCII, the
# others (the language tag, the cancel tag, unassigned ones) become nothing.
_TAG_TO_ASCII = {
    code: (chr(code - 0xE0000) if 0xE0020 <= code <= 0xE007E else None) for code in range(0xE0000, 0xE0080)
}


def _tags_spelled(run: str) -> str:
    """The ASCII a run of tag characters spells."""
    return run.translate(_TAG_TO_ASCII)


def decode_tags(text: str) -> str:
    """`text` with each run of tag characters outside a flag replaced by the ASCII it spells.

    Flags are left as they are. This is how a model reads the text: the hidden
    words appear where they were put.
    """
    return _FLAG_OR_TAGS.sub(lambda match: match.group() if match.group("flag") else _tags_spelled(match.group()), text)


def smuggled_text(text: str) -> str:
    """Everything the tag characters outside flags spell in `text`, joined, without the visible text."""
    return "".join(_tags_spelled(match.group()) for match in _FLAG_OR_TAGS.finditer(text) if not match.group("flag"))


def without_flags(text: str) -> str:
    """`text` with each subdivision flag reduced to its black flag, so its tag characters are not counted."""
    return _FLAG_SEQUENCE_RE.sub("\U0001f3f4", text) if "\U0001f3f4" in text else text


# --------------------------------------------------------------------------
# Other invisible carriers: variation selectors and invisible bits
# --------------------------------------------------------------------------

# Variation selectors draw nothing. One after an emoji or a CJK ideograph picks
# how it is drawn; a run of them can carry a byte each ("emoji smuggling"):
# U+FE00..U+FE0F stand for the bytes 0..15, U+E0100..U+E01EF for 16..255.
_SELECTORS = "︀-️\U000e0100-\U000e01ef"
_SELECTOR_RUN = re.compile(f"[{_SELECTORS}]{{2,}}")
# Pairs of invisible characters that can be read as the bits 0 and 1 ("Sneaky
# Bits" writes 0 as U+2062 and 1 as U+2064). Eight bits make a character, so a
# run shorter than 64 cannot spell the 8 characters that count as hidden text.
_BIT_PAIRS = (("⁢", "⁤"), ("​", "‌"), ("‌", "‍"), ("⁠", "﻿"))
HIDDEN_TEXT_CHARS = 8
_BIT_RUNS = tuple(re.compile(f"[{zero}{one}]{{{8 * HIDDEN_TEXT_CHARS},}}") for zero, one in _BIT_PAIRS)
# Two carrier characters in a row: a text without them has nothing to decode (one search, not five).
_TWO_CARRIERS = re.compile(f"[{_SELECTORS}⁠⁢⁤​-‍﻿]{{2}}")
# How much of one text these decoders read: characters of carrier runs, and runs.
_MAX_CARRIER_CHARS = 128 * 1024
_MAX_CARRIER_RUNS = 32


class Unhidden(NamedTuple):
    """What `decode_invisible` found."""

    view: str  # the text with each carrier run replaced by what it spells, as a model may read it
    hidden: str  # what the runs spell, joined by spaces


def decode_invisible(text: str) -> Unhidden | None:
    """Read the variation-selector runs and invisible bit runs in `text`; None when none of them spells text.

    A run of two or more variation selectors is read one byte per selector,
    and a run of 64 or more characters of one invisible pair one bit per
    character, the first character of the pair as 0 (or, if that is not text,
    as 1). What a run spells counts only if it is UTF-8 and mostly printable,
    as for base64. At most _MAX_CARRIER_RUNS runs and _MAX_CARRIER_CHARS
    characters are read, so hostile text stays quick; a payload past them is
    not decoded (it is still an invisible_characters finding).
    """
    if _TWO_CARRIERS.search(text) is None:
        return None
    candidates: list[tuple[int, int, str]] = []
    for match in itertools.islice(_SELECTOR_RUN.finditer(text), _MAX_CARRIER_RUNS):
        candidates.append((match.start(), match.end(), ""))
    for (zero, one), pattern in zip(_BIT_PAIRS, _BIT_RUNS):
        for match in itertools.islice(pattern.finditer(text), _MAX_CARRIER_RUNS):
            candidates.append((match.start(), match.end(), zero + one))
    candidates.sort()
    found: list[tuple[int, int, str]] = []
    chars_left = _MAX_CARRIER_CHARS
    for start, end, pair in candidates[:_MAX_CARRIER_RUNS]:
        if chars_left <= 0:
            break
        if found and start < found[-1][1]:
            continue  # inside a run already read (U+200C belongs to two pairs)
        end = min(end, start + chars_left)
        chars_left -= end - start
        run = text[start:end]
        spelled = _bits_spelled(run, pair) if pair else _selectors_spelled(run)
        if spelled:
            found.append((start, end, spelled))
    if not found:
        return None
    pieces: list[str] = []
    position = 0
    for start, end, spelled in found:
        pieces += [text[position:start], spelled]
        position = end
    pieces.append(text[position:])
    return Unhidden("".join(pieces), " ".join(spelled for _, _, spelled in found))


def _selectors_spelled(run: str) -> str | None:
    """The text a run of variation selectors spells, one byte each; None if it is not text."""
    raw = bytes(ord(ch) - 0xFE00 if ch <= "️" else ord(ch) - 0xE0100 + 16 for ch in run)
    return _as_text(raw, truncated=False)


def _bits_spelled(run: str, pair: str) -> str | None:
    """The text a run of two invisible characters spells as bits, eight to a byte, first bit highest."""
    usable = len(run) // 8 * 8
    for zero, one in (pair, pair[::-1]):
        bits = run[:usable].translate({ord(zero): "0", ord(one): "1"})
        text = _as_text(int(bits, 2).to_bytes(usable // 8, "big"), truncated=False)
        if text is not None:
            return text
    return None


# --------------------------------------------------------------------------
# Cleaning text that is passed on
# --------------------------------------------------------------------------

# Removed by clean_for_forwarding, besides escape sequences and tags: the C0
# controls except tab, line feed and carriage return; DEL; the C1 controls
# (U+009B and U+009D start a terminal escape on their own); the
# bidirectional embedding, override and isolate controls, which reorder how
# text is drawn ("Trojan Source"); and the invisible mathematical operators
# U+2061 to U+2064, which carry hidden bits ("Sneaky Bits"). The everyday
# direction marks (U+200E, U+200F, U+061C) and joiners are kept: Arabic,
# Hebrew, Persian and emoji need them.
_CONTROLS_AND_BIDI = {
    code: None
    for code in [
        *range(0x00, 0x09), 0x0B, 0x0C, *range(0x0E, 0x20), *range(0x7F, 0xA0),
        *range(0x202A, 0x202F), *range(0x2061, 0x2065), *range(0x2066, 0x206A),
    ]
}
# Variation selectors that clean_for_forwarding reduces: a run of two or more,
# and any one of U+E0100..U+E01EF (the ideographic ones).
_SELECTORS_TO_REDUCE = re.compile(f"[{_SELECTORS}]{{2,}}|[\U000e0100-\U000e01ef]")
# CJK ideographs: the characters an ideographic variation selector belongs after.
_CJK_IDEOGRAPHS = ((0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xF900, 0xFAFF), (0x20000, 0x323AF))
# A carriage return that does not end a line moves the cursor back to the
# start of it, so text written after it is drawn over text written before. It
# becomes a line break, which shows both parts and, like the detector (which
# reads it as a space), keeps the words on either side apart.
_LONE_CARRIAGE_RETURN = re.compile(r"\r(?!\n)")


def clean_for_forwarding(text: str) -> str:
    """`text` without what can hide or disguise content from the person who reads it.

    Removed:
      * terminal escape sequences, whole: colours, cursor moves, window titles
        and OSC 8 hyperlinks (the link's visible text stays, its hidden target goes);
      * the other control characters, except tab and line feed (a carriage
        return stays before a line feed, and becomes a line feed elsewhere);
      * Unicode tag characters, except inside a subdivision flag such as England's;
      * the bidirectional embedding, override and isolate controls;
      * the invisible operators U+2061 to U+2064;
      * all but the first of a run of variation selectors, and that one too
        unless it is U+FE00..U+FE0F after a character, or an ideographic
        variation selector after a CJK ideograph. An emoji keeps its one
        VS15 or VS16, and a name written with an ideographic variant keeps it.

    Ordinary text, including Arabic, Hebrew, CJK and emoji, is unchanged. Removing a
    character joins the text on either side of it. The detector's matching
    views remove the same characters, but scan the cleaned text as well as
    the original before passing the cleaned one on: what is forwarded must be
    what was checked.
    """
    if "\x1b" in text:
        text = TERMINAL_ESCAPE.sub("", text)
    text = text.translate(_CONTROLS_AND_BIDI)
    if "\r" in text:
        text = _LONE_CARRIAGE_RETURN.sub("\n", text)
    if TAG_CHARACTERS.search(text):
        text = _FLAG_OR_TAGS.sub(lambda match: match.group() if match.group("flag") else "", text)
    if _SELECTORS_TO_REDUCE.search(text):
        text = _SELECTORS_TO_REDUCE.sub(_one_selector_at_most, text)
    return text


def _one_selector_at_most(match: re.Match[str]) -> str:
    """What is kept of a run of variation selectors: its first one, where it may belong, or nothing."""
    first = match.group()[0]
    start = match.start()
    base = match.string[start - 1] if start else ""
    if not base or base.isspace() or "︀" <= base <= "️" or "\U000e0100" <= base <= "\U000e01ef":
        return ""
    if first <= "️":
        return first
    code = ord(base)
    return first if any(low <= code <= high for low, high in _CJK_IDEOGRAPHS) else ""


# --------------------------------------------------------------------------
# Folding for exact values
# --------------------------------------------------------------------------


class _WithoutFormat(dict):  # type: ignore[type-arg]
    """A str.translate table that removes format characters (category Cf), filled in as characters are met."""

    def __missing__(self, code: int) -> int | None:
        kept = None if unicodedata.category(chr(code)) == "Cf" else code
        self[code] = kept
        return kept


_WITHOUT_FORMAT = _WithoutFormat()
# Characters normalized in one call, and how many times longer a slice may get
# (see detector._decompose for why long texts are normalized in slices).
_FOLD_SLICE = 256
_MAX_FOLD_EXPANSION = 4


def folded_text(text: str) -> str:
    """`text` without format characters (zero-width spaces and joiners, tags, bidi controls), in NFKC form.

    NFKC turns compatibility forms into plain ones: full-width letters,
    ligatures, circled and superscript digits. For comparing exact values,
    which a hijacked agent can spell that way at no cost. ASCII text is
    returned as it is. Normalized in slices, never cut between a character
    and the marks that combine with it, and a slice that would grow more than
    _MAX_FOLD_EXPANSION times has its expanding characters made spaces, so
    hostile text stays quick and short.
    """
    if text.isascii():
        return text
    text = text.translate(_WITHOUT_FORMAT)
    pieces: list[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + _FOLD_SLICE)
        reach = min(len(text), end + 32)
        while end < reach and unicodedata.combining(text[end]):
            end += 1
        piece = text[start:end]
        folded = unicodedata.normalize("NFKC", piece)
        if len(folded) > _MAX_FOLD_EXPANSION * len(piece):
            piece = "".join(
                " " if len(unicodedata.normalize("NFKC", ch)) > _MAX_FOLD_EXPANSION else ch for ch in piece
            )
            folded = unicodedata.normalize("NFKC", piece)
        pieces.append(folded)
        start = end
    return "".join(pieces)


def clean_value_for_forwarding(value: Any) -> Any:
    """A copy of a JSON value with `clean_for_forwarding` applied to every string and every key.

    For values as json.loads returns them: objects, arrays, strings, numbers,
    true, false and null (a tuple becomes a list). Two keys that are the same
    once cleaned become one, and the later value wins, as in JSON.

    Iterative, because the value can be nested deeply. Raises UnscannableError
    for a value with more than MAX_CONTAINERS objects and arrays.
    """
    holder: list[Any] = [None]
    stack: list[tuple[Any, Any, Any]] = [(value, holder, 0)]
    opened = 0
    while stack:
        item, parent, key = stack.pop()
        if isinstance(item, str):
            parent[key] = clean_for_forwarding(item)
        elif isinstance(item, (dict, list, tuple)):
            opened += 1
            if opened > MAX_CONTAINERS:
                raise UnscannableError("the value has too many nested parts to clean")
            if isinstance(item, dict):
                children: dict[Any, Any] = {}
                for name, child in item.items():
                    children[clean_for_forwarding(name) if isinstance(name, str) else name] = child
                copy = dict.fromkeys(children)  # holds the places, so that the order of keys is kept
                parent[key] = copy
                stack.extend((child, copy, name) for name, child in children.items())
            else:
                items: list[Any] = [None] * len(item)
                parent[key] = items
                stack.extend((child, items, index) for index, child in enumerate(item))
        else:
            parent[key] = item
    return holder[0]


# --------------------------------------------------------------------------
# Parts of MCP messages the detector reads separately
# --------------------------------------------------------------------------

# How many parameters, and how many schemas in all, `tool_parameters` reads
# from one tool. Real tools have a few dozen; the rest of the schema is still
# scanned as text with the whole tool.
MAX_PARAMETERS = 1_000
_MAX_SCHEMAS = 5_000
# Where a JSON schema (2020-12, and the older drafts) keeps the schemas of its parts.
_NESTED_SCHEMA_KEYS = (
    "items", "additionalProperties", "not", "if", "then", "else", "contains", "propertyNames",
    "unevaluatedProperties", "unevaluatedItems", "contentSchema",
)
_SCHEMA_LIST_KEYS = ("anyOf", "oneOf", "allOf", "prefixItems")
_SCHEMA_MAP_KEYS = ("properties", "$defs", "definitions", "patternProperties", "dependentSchemas")


def tool_parameters(tool: Any) -> dict[str, str]:
    """The input parameters of an MCP tool definition: each name, with the title and description given for it.

    Read from the tool's "inputSchema", including the parameters of nested
    objects, of array items, of anyOf/oneOf/allOf alternatives and of every
    other place a 2020-12 schema keeps a subschema (if/then/else, contains,
    propertyNames, dependentSchemas, unevaluated*, contentSchema). A name used
    twice gets both texts. Anything that is not shaped like a schema is
    skipped: this picks parts out for a closer look, and the whole tool is
    scanned anyway. At most MAX_PARAMETERS parameters are returned, from at
    most _MAX_SCHEMAS schemas.
    """
    parameters: dict[str, str] = {}
    schema = tool.get("inputSchema") if isinstance(tool, dict) else None
    waiting: list[Any] = [schema]
    visited = 0
    while waiting and visited < _MAX_SCHEMAS and len(parameters) < MAX_PARAMETERS:
        schema = waiting.pop()
        visited += 1
        if not isinstance(schema, dict):
            continue
        for key in _SCHEMA_MAP_KEYS:
            members = schema.get(key)
            if not isinstance(members, dict):
                continue
            for name, member in members.items():
                if key == "properties" and isinstance(name, str) and len(parameters) < MAX_PARAMETERS:
                    described = _schema_text(member)
                    parameters[name] = f"{parameters[name]} {described}".strip() if name in parameters else described
                if len(waiting) < _MAX_SCHEMAS:
                    waiting.append(member)
                elif len(parameters) >= MAX_PARAMETERS:
                    break  # nothing more can be taken from this map
        for key in _NESTED_SCHEMA_KEYS:
            member = schema.get(key)
            if isinstance(member, list):  # "items" as a list of schemas, as the older drafts write it
                waiting.extend(member[:_MAX_SCHEMAS])
            elif isinstance(member, dict):
                waiting.append(member)
        for key in _SCHEMA_LIST_KEYS:
            members = schema.get(key)
            if isinstance(members, list):
                waiting.extend(members[:_MAX_SCHEMAS])
    return parameters


def _schema_text(schema: Any) -> str:
    """The title and description a schema gives, joined."""
    if not isinstance(schema, dict):
        return ""
    return " ".join(text for text in (schema.get("title"), schema.get("description")) if isinstance(text, str))


# The content blocks whose "data" holds encoded media, not text for the model.
_MEDIA_TYPES = ("image", "audio")
# The members through which a client reaches the content blocks it renders: a
# result's "content", and the "content" of each of the "messages" of a prompt
# or a sampling request (under "params" or "result" when a whole request or
# reply is read). Nothing under "_meta" or "structuredContent" is rendered.
_RENDERED_PATH = ("content", "messages", "params", "result")


def media_blocks(value: Any) -> frozenset[int]:
    """The id() of each image and audio content block in a JSON-like value that a client renders as media.

    A block counts where a client renders content: the value itself or an
    item of it (a tool's output given as blocks), and what is reached through
    "content", "messages", "params" and "result" only, ending in "content" or
    one of its items. An image-shaped object anywhere else (_meta,
    structuredContent, a field of the server's own) is not one: it would be
    shown as text, if at all. Only the exact "data" member of these blocks is
    read as media (see text_views); a copy of the same text elsewhere is not.
    The walk is iterative and reads at most MAX_CONTAINERS objects and arrays.
    """
    found: set[int] = set()
    waiting: list[tuple[Any, bool]] = [(value, True)]  # (part, whether a client renders it as a block)
    opened = 0
    while waiting and opened < MAX_CONTAINERS:
        item, rendered = waiting.pop()
        if isinstance(item, dict):
            opened += 1
            if rendered and item.get("type") in _MEDIA_TYPES and isinstance(item.get("data"), str):
                found.add(id(item))
            waiting.extend((item[key], key == "content") for key in _RENDERED_PATH if key in item)
        elif isinstance(item, (list, tuple)):
            opened += 1
            waiting.extend((child, rendered) for child in item)
    return frozenset(found)


# --------------------------------------------------------------------------
# Base64 and hex runs
# --------------------------------------------------------------------------

MIN_BASE64_CHARS = 32  # 24 bytes: shorter runs are ids and hashes far more often than text
MIN_HEX_CHARS = 48  # 24 bytes: a SHA-1 (40) or a short id is not decoded
_HEX_DIGITS = re.compile(r"[0-9A-Fa-f]+")
_UPPER = re.compile(r"[A-Z]")
_LOWER = re.compile(r"[a-z]")
# Share of the decoded characters that must be printable (or tab, newline,
# return) for a run to be read as text. Random bytes almost never pass.
_PRINTABLE_SHARE = 0.85
# How a run is told apart from binary data without decoding all of it: the
# first _SAMPLE_BYTES bytes after up to _MAX_SKIPPED_BYTES leading ones must be
# text. A run is never skipped for how it starts: three NUL bytes make "AAAA",
# the start of an MP4, and a file's magic bytes cost an attacker nothing.
_SAMPLE_BYTES = 256
_MAX_SKIPPED_BYTES = 16
# How many bytes of a binary run are returned as Latin-1 when they are asked
# for (the secret guard: a token inside binary data).
MAX_BINARY_BYTES = 4 * 1024


class DecodedRun(NamedTuple):
    """A run of base64 or hex that decoded to text (or, when asked for, to binary data)."""

    kind: str  # "base64" or "hex"
    text: str  # what it decoded to; for binary data, the first bytes read as Latin-1
    run: str  # the run as it stood in the text
    binary: bool = False  # True: `text` is binary data read as Latin-1, not text


class EncodedRuns:
    """Decodes base64 and hex runs found in text, one level deep, within fixed limits.

    One instance serves one check: the limits are shared by every text it is
    given, and a run met again (in another view of the same value) is not
    decoded again. A run counts as decoded text only if it is valid UTF-8 and
    at least 85% printable once up to 16 leading bytes (a file's magic bytes,
    a few NULs) are passed over; whether it is, is decided on its first
    256 bytes, so a long binary run costs little. Every run that looks
    encoded costs an attempt, binary or not.

    The limits make the work bounded on hostile input, and they can be used to
    hide a payload: runs placed before it use up the attempts or the bytes, and
    a payload encoded twice, split over runs, or written with separators
    ("48 65 6c", "\\x48") is not decoded. Runs shorter than the minimum
    lengths are not decoded either. Which runs are pictures is the caller's
    business: give the decoder only the text it should read (text_views' media).

    max_attempts:  runs decoded (or tried) in all.
    max_kept:      runs returned in all.
    max_bytes:     decoded bytes in all.
    max_run_bytes: decoded bytes of one run; a longer run is decoded only in its first part.
    min_base64_chars, min_hex_chars: the shortest run of each kind that is decoded.
    binary:        also return each run that is binary data, its first
                   MAX_BINARY_BYTES bytes read as Latin-1 (DecodedRun.binary),
                   for a caller that looks for tokens inside binary data.
    """

    def __init__(
        self,
        *,
        max_attempts: int = 64,
        max_kept: int = 16,
        max_bytes: int = 64 * 1024,
        max_run_bytes: int = 16 * 1024,
        min_base64_chars: int = MIN_BASE64_CHARS,
        min_hex_chars: int = MIN_HEX_CHARS,
        binary: bool = False,
    ) -> None:
        self.attempts_left = max_attempts
        self.kept_left = max_kept
        self.bytes_left = max_bytes
        self._max_run_bytes = max_run_bytes
        self._min_base64_chars = min_base64_chars
        self._min_hex_chars = min_hex_chars
        self._binary = binary
        # A run that may be base64 (either alphabet) or hex: hex digits are
        # base64 letters too, and `_kind` tells them apart. A run may go on over
        # several lines, as `base64` wraps its output. Hex is also looked for on
        # its own, because a letter or "/" before it ("example/6768...") makes
        # the longer run base64-shaped.
        shortest = min(min_base64_chars, min_hex_chars)
        self._run_pattern = re.compile(rf"[A-Za-z0-9+/_-]{{{shortest},}}(?:\r?\n[A-Za-z0-9+/_-]+)*={{0,2}}")
        self._hex_pattern = re.compile(rf"[0-9A-Fa-f]{{{min_hex_chars},}}")
        self._seen: set[str] = set()

    def decoded(self, text: str) -> list[DecodedRun]:
        """Each new run in `text` that decodes to text: base64-shaped runs first, then hex ones."""
        found: list[DecodedRun] = []
        for match in itertools.chain(self._run_pattern.finditer(text), self._hex_pattern.finditer(text)):
            if self.attempts_left <= 0 or self.kept_left <= 0 or self.bytes_left <= 0:
                break
            run = match.group()
            if run in self._seen:
                continue
            self._seen.add(run)
            compact = "".join(run.split()) if "\n" in run else run
            results = [self._attempt(compact, run)]
            if (results[0] is None or results[0].binary) and "/" in compact:
                # In a URL the path before a run is part of it ("example/Z2hw..."): try what follows the last "/".
                tail = compact.rpartition("/")[2]
                if tail not in self._seen:
                    self._seen.add(tail)
                    results.append(self._attempt(tail, tail))
            for result in results:
                if result is not None and self.kept_left > 0:
                    self.kept_left -= 1
                    found.append(result)
        return found

    def _attempt(self, compact: str, run: str) -> DecodedRun | None:
        """Decode one candidate, if it looks encoded and the limits allow; None if it is not text."""
        if self.attempts_left <= 0 or self.bytes_left <= 0:
            return None
        kind = self._kind(compact)
        if kind is None:
            return None
        self.attempts_left -= 1
        return self._decode(compact, kind, run)

    def _kind(self, run: str) -> str | None:
        """How to decode `run`, or None if it does not look like encoded text at all (which costs no attempt)."""
        bare = run.rstrip("=")
        if len(bare) >= self._min_hex_chars and len(bare) % 2 == 0 and _HEX_DIGITS.fullmatch(bare):
            return "hex"
        if len(run) < self._min_base64_chars:
            return None
        # Base64 of text has capitals and small letters, and rarely a "/": a
        # run without both, or full of slashes, is a word, a path or an id.
        if not (_UPPER.search(run) and _LOWER.search(run)) or run.count("/") * 16 > len(run):
            return None
        if ("+" in run or "/" in run) and ("-" in run or "_" in run):
            return None  # both alphabets at once: not base64
        return "base64"

    def _decode(self, compact: str, kind: str, run: str) -> DecodedRun | None:
        """Decode a run: first a sample, to tell text from binary data, then as much as the limits allow."""
        limit = min(self._max_run_bytes, self.bytes_left)
        bare = compact.rstrip("=")
        sample, sample_cut = _raw_bytes(bare, kind, min(limit, _SAMPLE_BYTES + _MAX_SKIPPED_BYTES))
        if sample is None:
            return None  # not valid base64 or hex
        whole = sample_cut >= len(bare)  # the sample is the whole run
        start = _start_of_text(sample, truncated=not whole)
        if start is None:  # binary data
            raw = sample
            if self._binary and not whole:
                raw = _raw_bytes(bare, kind, min(limit, MAX_BINARY_BYTES))[0] or sample
            self.bytes_left -= len(raw)
            return DecodedRun(kind, raw.decode("latin-1"), run, binary=True) if self._binary else None
        raw, cut = (sample, sample_cut) if whole else _raw_bytes(bare, kind, limit)
        if raw is None:
            return None
        self.bytes_left -= len(raw)
        text = _as_text(raw[start:], truncated=cut < len(bare))
        return None if text is None else DecodedRun(kind, text, run)


def _raw_bytes(bare: str, kind: str, limit: int) -> tuple[bytes | None, int]:
    """The first `limit` bytes (or fewer: whole groups only) a run decodes to, and how many of its characters
    that took; (None, 0) if the run is not valid base64 or hex."""
    try:
        if kind == "hex":
            cut = min(len(bare), 2 * limit)
            return bytes.fromhex(bare[:cut]), cut
        cut = min(len(bare), limit // 3 * 4)
        chunk = bare[:cut]
        if len(chunk) % 4 == 1:
            chunk = chunk[:-1]  # one character cannot end a run of base64
        chunk += "=" * (-len(chunk) % 4)
        altchars = b"-_" if ("-" in chunk or "_" in chunk) else None
        return base64.b64decode(chunk, altchars=altchars, validate=True), cut
    except (ValueError, binascii.Error):
        return None, 0


def _start_of_text(sample: bytes, truncated: bool) -> int | None:
    """Where text starts in the first bytes of a run: 0 to _MAX_SKIPPED_BYTES, or None if it is binary data."""
    for start in range(min(_MAX_SKIPPED_BYTES, max(0, len(sample) - 1)) + 1):
        if _as_text(sample[start:start + _SAMPLE_BYTES], truncated or start + _SAMPLE_BYTES < len(sample)):
            return start
    return None


def _as_text(raw: bytes, truncated: bool) -> str | None:
    """`raw` as text, if it is UTF-8 and mostly printable; otherwise None."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        # A run decoded only in part can end inside a character.
        if not truncated or error.start < len(raw) - 3:
            return None
        text = raw[: error.start].decode("utf-8")
    if not text:
        return None
    printable_count = sum(1 for ch in text if ch.isprintable() or ch in "\t\n\r")
    return text if printable_count >= _PRINTABLE_SHARE * len(text) else None
