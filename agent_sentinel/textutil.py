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
    the characters that draw nothing removed (`INVISIBLE_OUTSIDE_FORMAT`);
  * `tool_parameters` and `media_blocks`, which pick parts out of MCP
    messages for the detector;
  * `EncodedRuns`, the bounded decoder of base64 and hex runs (`DecodedRun`).
"""

from __future__ import annotations

import array
import base64
import binascii
import bisect
import dataclasses
import datetime
import decimal
import enum
import heapq
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


def keys_and_strings(value: Any) -> tuple[list[str], list[str]]:
    """(texts_in(value), texts_in(value, keys=False)) in one walk: every key and string, and the strings alone."""
    everything: list[str] = []
    strings: list[str] = []
    for group, text in _walk(value, keys=True, scalars=False, strict=False):
        everything.append(text)
        if group != _KEY:
            strings.append(text)
    return everything, strings


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
        elif type(item) in _PLAIN_NUMBERS:  # first, by exact type: arguments can hold millions of numbers
            if scalars:
                yield group, number_text(item)
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


_PLAIN_NUMBERS = frozenset([int, float])


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
# call may have in all. Real calls have far fewer; arguments with more (a
# message of 16 MB of one-digit numbers holds 8 million) are refused, not
# checked for seconds on end.
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
      * an object with model_dump (a pydantic model): model_dump(mode="json"),
        with the fields it leaves out or a serializer rewrites read as the
        model holds them (`_model_copy`);
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
    with more than MAX_ARGUMENT_PARTS parts, for an integer too long to
    write, and for an object whose own code raises while it is read (its
    model_dump, items(), iteration, a property): the call is then refused,
    never checked with parts left out.
    Iterative, so a deep value cannot exhaust Python's recursion limit.

    A value that is JSON already (only dict with text keys, list, str, int,
    float, bool and None, of exactly those types, within the bounds) is
    returned as it is, not copied: arguments that came from JSON are checked
    at the cost of one look at each part.
    """
    if _is_plain_json(value):
        return value
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
        try:
            converted = _CONTAINER if type(item) in (dict, list, tuple) else _converted(item)
            if converted is _CONTAINER:
                parts += _copy_container(item, parent, key, depth, stack, inside)
        except UnscannableError:
            raise
        except Exception as exc:  # the object's own code failed (its items(), iteration, a property)
            raise UnscannableError(f"an argument of type {type(item).__name__} could not be read") from exc
        if converted is _CONTAINER:
            if parts > MAX_ARGUMENT_PARTS:
                raise UnscannableError("the arguments have too many parts to check")
        elif type(converted) is _Leaf:
            parent[key] = converted.value
        else:
            stack.append((converted, parent, key, depth + 1))  # read again: a value may become another
    return holder[0]


# The parts that are JSON as they are, copied without a look further (an int is checked for its length).
_JSON_LEAVES = frozenset([str, bool, int, float, type(None)])
_JSON_TEXT_AND_FLAGS = frozenset([str, bool, float, type(None)])  # the leaves that need no check at all


def _is_plain_json(value: Any) -> bool:
    """Whether `value` is JSON as it is, so that normalised_arguments may return it uncopied.

    Every container a dict with text keys or a list, every other part a str,
    int, float, bool or None, of exactly those types; and the bounds hold:
    nesting depth (no part, container or not, inside more than
    MAX_ARGUMENT_DEPTH containers, as in the copying walk), parts (counted
    as the copying walk counts them) and the length of each integer. A value
    that holds itself goes too deep, or has too many parts, before this
    ends: the copying walk then refuses it.
    """
    kind = type(value)
    if kind is not dict and kind is not list:
        return kind in _JSON_TEXT_AND_FLAGS or (kind is int and value.bit_length() <= _MAX_INT_BITS)
    leaves = _JSON_TEXT_AND_FLAGS
    stack: list[tuple[Any, int]] = [(value, 0)]
    parts = 0
    while stack:
        item, depth = stack.pop()
        if depth >= MAX_ARGUMENT_DEPTH and (depth > MAX_ARGUMENT_DEPTH or item):
            return False  # a part deeper than MAX_ARGUMENT_DEPTH: this one, or its members
        parts += 1 + len(item)
        if parts > MAX_ARGUMENT_PARTS:
            return False
        if type(item) is dict:
            for key in item:
                if type(key) is not str:
                    return False
            members: Iterable[Any] = item.values()
        else:
            members = item
        for member in members:
            kind = type(member)
            if kind in leaves:
                continue
            if kind is int:
                if member.bit_length() > _MAX_INT_BITS:
                    return False
            elif kind is dict or kind is list:
                stack.append((member, depth + 1))
            else:
                return False
    return True


class _Leaf(NamedTuple):
    """What a part became, final: text, bytes or a number."""

    value: Any


_CONTAINER = object()  # `_converted`: the part is a container, to be copied member by member


def _checked_number(number: int | float) -> int | float:
    if type(number) is int and number.bit_length() > _MAX_INT_BITS:
        raise UnscannableError("an argument holds a number too long to check")
    return number


def number_text(number: int | float) -> str:
    """A number as JSON writes it ("12", "1.5", "-3e+20", "NaN"), for the texts a check reads.

    What json.dumps writes, without its cost per call: int and float's own
    repr, except for the three floats JSON spells its own way.
    """
    if isinstance(number, int):
        if number.bit_length() > _MAX_INT_BITS:
            raise UnscannableError("an argument holds a number too long to check")
        return int.__repr__(number)
    if number != number:
        return "NaN"
    if number in (_INFINITY, -_INFINITY):
        return "Infinity" if number > 0 else "-Infinity"
    return float.__repr__(number)


_INFINITY = float("inf")


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
        return _called(_model_copy, item)
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


def _model_copy(model: Any) -> Any:
    """A pydantic model as the checks read it: model_dump(mode="json"), and what the tool reads that it hides.

    The tool reads the model's attributes, and model_dump leaves out a field
    with exclude=True and writes a field with a serializer as the serializer
    says. Each such field is read as the model holds it, and so is each
    private attribute that holds text, bytes or a number (PrivateAttr). A
    pydantic secret among them is read as model_dump writes one, masked. A
    value of a kind that cannot be checked is left out, as model_dump left
    it out. A model whose own serializer writes it as no object is read as
    it writes itself.
    """
    dumped = model.model_dump(mode="json")
    fields = getattr(type(model), "model_fields", None)
    if type(dumped) is not dict or not isinstance(fields, Mapping):
        return dumped
    hidden = {name for name in fields if name not in dumped} | _serialised_fields(type(model), fields)
    for name in sorted(hidden):
        held = getattr(model, name, None)
        if held is None or held == "":
            continue  # nothing in it to check
        if callable(getattr(held, "get_secret_value", None)):
            dumped[name] = _MASKED
            continue
        try:
            dumped[name] = normalised_arguments(held)
        except UnscannableError:
            continue
    private = getattr(model, "__pydantic_private__", None)
    if isinstance(private, dict):
        for name, held in private.items():
            if isinstance(name, str) and name not in dumped and type(held) in (str, bytes, int, float) and held:
                dumped[name] = normalised_arguments(held)
    return dumped


_MASKED = "**********"  # how pydantic writes a secret (SecretStr, SecretBytes) as JSON


def _serialised_fields(model_type: Any, fields: Mapping[str, Any]) -> set[str]:
    """The names of the fields of a pydantic model that a serializer writes (all of them for a model_serializer)."""
    decorators = getattr(model_type, "__pydantic_decorators__", None)
    if getattr(decorators, "model_serializers", None):
        return set(fields)
    names: set[str] = set()
    for decorator in dict(getattr(decorators, "field_serializers", None) or {}).values():
        covered = getattr(getattr(decorator, "info", None), "fields", ())
        names.update(fields if "*" in covered else (name for name in covered if name in fields))
    for name, field in fields.items():
        if any(type(part).__name__ in ("PlainSerializer", "WrapSerializer") for part in getattr(field, "metadata", ())):
            names.add(name)
    return names


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
    if members and depth >= MAX_ARGUMENT_DEPTH:
        # Its members are deeper than MAX_ARGUMENT_DEPTH: refused here even when
        # they are plain JSON and copied above, as _is_plain_json refuses them.
        raise UnscannableError("the arguments are nested too deeply to check")
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
        if type(item) in _PLAIN_NUMBERS or (isinstance(item, (int, float)) and not isinstance(item, bool)):
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

# Terminal escape sequences: CSI (colours, cursor moves: ESC [ ... letter, or
# the one-character CSI U+009B) and OSC (window titles, OSC 8 hyperlinks: ESC ]
# or U+009D ... BEL, ESC \ or U+009C). The parameters of a CSI have no length
# bound, as a terminal reads any number of them ("ESC[000...0m" with a hundred
# zeros is a colour): they cannot hold the characters that start or end a
# sequence, so no character is read by more than a few attempts. An OSC is
# bounded, so that one attempt cannot read far ahead; a longer one is not
# matched, and removing the ESC character then leaves it as visible text.
TERMINAL_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]{0,8}[@-~]|\x1b\][^\x07\x1b\x9c]{0,512}(?:\x07|\x1b\\|\x9c)")
# The same sequences started by the one-character CSI and OSC. A pattern of its
# own, used only on text that has one: a pattern that starts with ESC alone is
# searched for far more quickly than one that starts with any of three.
C1_TERMINAL_ESCAPE = re.compile(r"\x9b[0-?]*[ -/]{0,8}[@-~]|\x9d[^\x07\x1b\x9c]{0,512}(?:\x07|\x1b\\|\x9c)")

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

# Characters that draw nothing although Unicode files them under letters,
# marks or unassigned rather than as format characters (Cf): the grapheme
# joiner, Hangul and Khmer fillers, Mongolian separators, variation selectors,
# and the reserved "ignorable" code points, which include the whole block of
# tag characters. The detector deletes them from its matching views too.
INVISIBLE_OUTSIDE_FORMAT = frozenset([
    0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, *range(0x180B, 0x1810), 0x2065, 0x3164, 0xFFA0,
    *range(0xFE00, 0xFE10), *range(0xFFF0, 0xFFF9), *range(0xE0000, 0xE1000),
])
# The format characters (Cf) that draw nothing: all of them (Unicode 15.1)
# except the few with a glyph of their own (Arabic number signs and the like).
_FORMAT_THAT_DRAWS_NOTHING = frozenset([
    0x00AD, 0x061C, 0x180E, *range(0x200B, 0x2010), *range(0x202A, 0x202F), *range(0x2060, 0x2065),
    *range(0x2066, 0x2070), 0xFEFF, *range(0xFFF9, 0xFFFC), *range(0x13430, 0x13440), *range(0x1BCA0, 0x1BCA4),
    *range(0x1D173, 0x1D17B), 0xE0001, *range(0xE0020, 0xE0080),
])
# What may stand between the characters of one carrier run: what draws
# nothing, and spaces and line breaks. Splitting a run with them changes
# nothing a reader sees, so it must not change what the run spells, nor
# whether clean_for_forwarding removes it.
_BETWEEN_CARRIERS = _FORMAT_THAT_DRAWS_NOTHING | INVISIBLE_OUTSIDE_FORMAT | frozenset(map(ord, " \t\r\n"))


def _class_of(codes: Iterable[int]) -> str:
    """The inside of a regular expression character class that matches exactly the code points `codes`."""
    ordered = sorted(set(codes))
    parts: list[str] = []
    index = 0
    while index < len(ordered):
        low = high = ordered[index]
        while index + 1 < len(ordered) and ordered[index + 1] == high + 1:
            index += 1
            high = ordered[index]
        parts.append(re.escape(chr(low)) if low == high else f"{re.escape(chr(low))}-{re.escape(chr(high))}")
        index += 1
    return "".join(parts)


def _run_of(carriers: Iterable[int], least: int) -> re.Pattern[str]:
    """A run of at least `least` of the characters `carriers`, with only _BETWEEN_CARRIERS between them.

    Linear: the characters between two carriers cannot be carriers, so each
    character of a run is read by one attempt only.
    """
    own = frozenset(carriers)
    body, between = _class_of(own), _class_of(_BETWEEN_CARRIERS - own)
    return re.compile(f"[{body}](?:[{between}]*[{body}]){{{least - 1},}}")


# Variation selectors draw nothing. One after an emoji or a CJK ideograph picks
# how it is drawn; a run of them can carry a byte each ("emoji smuggling"):
# U+FE00..U+FE0F stand for the bytes 0..15, U+E0100..U+E01EF for 16..255.
_SELECTOR_CODES = frozenset([*range(0xFE00, 0xFE10), *range(0xE0100, 0xE01F0)])
_SELECTORS = _class_of(_SELECTOR_CODES)
# Pairs of invisible characters that can be read as the bits 0 and 1 ("Sneaky
# Bits" writes 0 as U+2062 and 1 as U+2064).
_BIT_PAIRS = ("\u2062\u2064", "\u200b\u200c", "\u200c\u200d", "\u2060\ufeff")
HIDDEN_TEXT_CHARS = 8


class _Alphabet(NamedTuple):
    """One way of hiding text in invisible characters, and how a run of it is found."""

    pair: str  # the characters read as 0 and 1; "" for variation selectors, read as bytes
    # Each group of carriers: two selectors or more; for bits, one carrier or
    # more (a run long enough to read alone has eight, one character).
    run: re.Pattern[str]
    others: re.Pattern[str]  # the characters of a run that are not carriers


def _alphabet(pair: str) -> _Alphabet:
    codes = frozenset(map(ord, pair)) if pair else _SELECTOR_CODES
    return _Alphabet(pair, _run_of(codes, 1 if pair else 2), re.compile(f"[^{_class_of(codes)}]+"))


_ALPHABETS = (_alphabet(""), *(_alphabet(pair) for pair in _BIT_PAIRS))
_ANY_CARRIER = re.compile(f"[{_SELECTORS}{_class_of(map(ord, ''.join(_BIT_PAIRS)))}]")
# How much of one text these decoders read: characters of carrier runs (and
# what stands between their carriers), runs of each alphabet, and groups of
# bits too short to read alone (one to seven between two visible characters).
_MAX_CARRIER_CHARS = 128 * 1024
_MAX_CARRIER_RUNS = 256
_MAX_BIT_GROUPS = 8 * 1024
# Bits scattered in groups of one to seven are read joined across the visible
# text only when there are this many of one pair (a payload of
# _MIN_SCATTERED_CHARS characters), and both of its characters occur: ordinary
# text uses one of them alone (Persian ZWNJ), which reads as no text at all.
# Of them, the first _MAX_SCATTERED_BITS are read (4 KiB of hidden text).
# A payload gathered from across a text needs more characters than one that
# stands in a run: text that uses both characters of a pair (Persian words
# next to emoji joined by ZWJ) spells random bytes, and eight random bytes
# are printable once in a few hundred texts, sixteen about never.
_MIN_SCATTERED_CHARS = 16
_MIN_SCATTERED_BITS = 8 * _MIN_SCATTERED_CHARS
_MAX_SCATTERED_BITS = 8 * 4096


class Unhidden(NamedTuple):
    """What `decode_invisible` found."""

    view: str  # the text with each carrier run replaced by what it spells, as a model may read it
    hidden: str  # what the runs spell, joined by spaces


def decode_invisible(text: str) -> Unhidden | None:
    """Read the variation-selector runs and invisible bit runs in `text`; None when none of them spells text.

    A run of two or more variation selectors is read one byte per selector,
    and a run of eight or more characters of one invisible pair one bit per
    character, the first character of the pair as 0 (or, if that is not text,
    as 1). Characters that draw nothing, spaces and line breaks may stand
    between the characters of a run (_BETWEEN_CARRIERS); they are skipped.
    What a run spells counts only if it is mostly printable UTF-8, or starts
    with enough of it, as for base64.

    A run that spells HIDDEN_TEXT_CHARS characters or more is read on its
    own. The other runs of one alphabet are read as one: their characters
    joined, in order, as one run; or, if that is not text, what each of them
    spells, joined. So a payload cut into short runs, with visible text
    between them, is still read whole. In the view, the first of them stands
    for what they spell together, and the others are left out.

    At most _MAX_CARRIER_RUNS runs of each alphabet and _MAX_CARRIER_CHARS
    characters are read, so hostile text stays quick; a payload past them is
    not decoded (it is still an invisible_characters finding).
    """
    first = _ANY_CARRIER.search(text)
    if first is None or _ANY_CARRIER.search(text, first.end()) is None:
        return None
    chars_left = [_MAX_CARRIER_CHARS]
    found: list[tuple[list[tuple[int, int]], str]] = []  # (the spans of the runs, what they spell)
    for alphabet in _ALPHABETS:
        found += _spelled_runs(text, alphabet, chars_left)
    found.sort(key=lambda item: item[0][0])
    taken: list[tuple[int, int, str]] = []  # (start, end, what replaces the span in the view), in order
    hidden: list[str] = []
    for spans, spelled in found:
        # A span read by two alphabets (U+200C belongs to two pairs) counts for the first that spelled text.
        if any(_overlaps(taken, start, end) for start, end in spans):
            continue
        # The spans are in order: merged in one pass (scattered bits can have thousands).
        taken = list(heapq.merge(taken, [(start, end, spelled if index == 0 else "")
                                         for index, (start, end) in enumerate(spans)]))
        hidden.append(spelled)
    if not hidden:
        return None
    pieces: list[str] = []
    position = 0
    for start, end, spelled in taken:
        # Kept apart from a word it touches ("Nice" + hidden "Ignore ..."), so that each is read as a word.
        before = " " if spelled and start and text[start - 1].isalnum() and spelled[0].isalnum() else ""
        after = " " if spelled and end < len(text) and text[end].isalnum() and spelled[-1].isalnum() else ""
        pieces += [text[position:start], before, spelled, after]
        position = end
    pieces.append(text[position:])
    return Unhidden("".join(pieces), " ".join(hidden))


def _overlaps(taken: list[tuple[int, int, str]], start: int, end: int) -> bool:
    """Whether the span from `start` to `end` overlaps one of `taken`, which are in order and do not overlap."""
    index = bisect.bisect_left(taken, (end,))  # the spans that start before `end`
    return index > 0 and taken[index - 1][1] > start


def _spelled_runs(text: str, alphabet: _Alphabet, chars_left: list[int]) -> list[tuple[list[tuple[int, int]], str]]:
    """What the runs of one alphabet in `text` spell: (the spans of the runs, the text), for each that spells text.

    A run long enough to read alone (two selectors, eight bits) that spells
    HIDDEN_TEXT_CHARS characters is one finding. The other runs are read
    joined (see `_joined_reading`); for bits, so are the groups of one to
    seven carriers between visible characters, when there are enough of them.

    chars_left: [characters of runs that may still be read], shared by every alphabet.
    """
    found: list[tuple[list[tuple[int, int]], str]] = []
    rest: list[tuple[int, int, str, str | None]] = []  # runs too short to count alone: span, carriers, spelled
    short: list[tuple[int, int, str]] = []  # groups of fewer than eight bits, in order with `rest`: span, carriers
    runs = groups = 0
    for match in alphabet.run.finditer(text):
        if chars_left[0] <= 0 or runs >= _MAX_CARRIER_RUNS or groups >= _MAX_BIT_GROUPS:
            break
        groups += 1
        start, end = match.start(), min(match.end(), match.start() + chars_left[0])
        chars_left[0] -= end - start
        carriers = alphabet.others.sub("", text[start:end])
        if alphabet.pair and len(carriers) < 8:
            short.append((start, end, carriers))
            continue
        runs += 1
        spelled = _carriers_spelled(carriers, alphabet.pair)
        if spelled is not None and len(spelled) >= HIDDEN_TEXT_CHARS:
            found.append(([(start, end)], spelled))
        else:
            rest.append((start, end, carriers, spelled))
    joined = _joined_reading(rest, short, alphabet.pair)
    if joined is not None:
        found.append(joined)
    return found


def _joined_reading(
    rest: list[tuple[int, int, str, str | None]], short: list[tuple[int, int, str]], pair: str
) -> tuple[list[tuple[int, int]], str] | None:
    """What the runs too short to read alone spell together: (their spans, the text), or None.

    The runs (`rest`) are read as one, their carriers joined in order, or,
    if that is not text, what each of them spells, joined. Bits scattered in
    groups of one to seven (`short`, as "word" + four bits + " word" + four
    bits ...) are read with them, all the carriers in order (`_scattered_text`).
    That reading, of every carrier, wins when it is a payload and has no
    larger share of unprintable characters than the other.
    """
    reading: tuple[list[tuple[int, int]], str] | None = None
    if rest:
        together = _carriers_spelled("".join(carriers for _, _, carriers, _ in rest), pair)
        if together is not None:
            reading = ([(start, end) for start, end, _, _ in rest], together)
        else:
            texts = [(start, end, spelled) for start, end, _, spelled in rest if spelled]
            if texts:
                reading = ([(start, end) for start, end, _ in texts], "".join(spelled for _, _, spelled in texts))
    if not short:
        return reading
    groups = sorted([(start, end, carriers) for start, end, carriers, _ in rest] + short)
    scattered = _scattered_text("".join(carriers for _, _, carriers in groups), pair)
    if scattered is None:
        return reading
    if reading is not None and len(reading[1]) >= HIDDEN_TEXT_CHARS:
        if _unprintable(reading[1]) < _unprintable(scattered):
            return reading
    return [(start, end) for start, end, _ in groups], scattered


# Bits scattered over a text spell a payload only if it reads as more than
# one character over and over: two characters of a pair that take turns
# regularly (a word joiner here, a byte order mark there) spell "UUUU".
_MIN_DISTINCT_CHARS = 5


def _scattered_text(carriers: str, pair: str) -> str | None:
    """What the carriers of one pair, gathered from across a text, spell; None unless it is a payload.

    That needs _MIN_SCATTERED_BITS carriers or more, both characters of the
    pair, and, in the first _MAX_SCATTERED_BITS, text with
    _MIN_DISTINCT_CHARS different characters that reads as written text
    somewhere (`_reads_as_written_text`): the joiners of ordinary text, read
    as bits, pass for "mostly printable" now and then, but not for that.
    """
    if len(carriers) < _MIN_SCATTERED_BITS or pair[0] not in carriers or pair[1] not in carriers:
        return None
    spelled = _bits_spelled(carriers[:_MAX_SCATTERED_BITS], pair)
    if spelled is None or len(set(spelled)) < _MIN_DISTINCT_CHARS or not _reads_as_written_text(spelled):
        return None
    return spelled


def _reads_as_written_text(text: str) -> bool:
    """Whether `text` has _MIN_SCATTERED_CHARS characters in a row that are all printable, at least half of them
    letters or spaces: a sentence or a command, not bytes that happen to be printable."""
    position = 0
    unprintable = [
        match.start() for match in _NOT_PLAIN_ASCII.finditer(text)
        if match.group() == _REPLACEMENT or not match.group().isprintable()
    ]
    for at in (*unprintable, len(text)):
        if at - position >= _MIN_SCATTERED_CHARS:
            if 2 * len(_LETTERS_AND_SPACES.findall(text, position, at)) >= at - position:
                return True
        position = at + 1
    return False


def _unprintable(text: str) -> float:
    """The share of the characters of `text` that are not printable (U+FFFD among them)."""
    return sum(1 for ch in _NOT_PLAIN_ASCII.findall(text) if ch == _REPLACEMENT or not ch.isprintable()) / len(text)


def _carriers_spelled(carriers: str, pair: str) -> str | None:
    """The text a run's carrier characters spell (selectors if `pair` is "", else bits); None if it is not text."""
    return _bits_spelled(carriers, pair) if pair else _selectors_spelled(carriers)


def _selectors_spelled(run: str) -> str | None:
    """The text a run of variation selectors spells, one byte each; None if it is not text."""
    raw = bytes(ord(ch) - 0xFE00 if ch <= "️" else ord(ch) - 0xE0100 + 16 for ch in run)
    return _as_text(raw, truncated=False)


def _bits_spelled(run: str, pair: str) -> str | None:
    """The text a run of two invisible characters spells as bits, eight to a byte, first bit highest.

    Read from its first character, or, if that is not clean text, from one
    of the next seven, either way round: a stray carrier in front must not
    hide what follows. Of the readings that are text, the cleanest wins:
    text throughout before pieces of text (see `_text_of`), then the fewest
    unprintable characters, then the most letters and spaces (a reading one
    bit off can pass for text, but reads as symbols).
    """
    best: tuple[tuple[bool, int, int], str] | None = None
    for skipped in range(8):
        usable = (len(run) - skipped) // 8 * 8
        if not usable:
            break
        for zero, one in (pair, pair[::-1]):
            bits = run[skipped:skipped + usable].translate({ord(zero): "0", ord(one): "1"})
            found = _text_of(int(bits, 2).to_bytes(usable // 8, "big"), truncated=False)
            if found is None:
                continue
            text, whole = found
            unprintable = sum(1 for ch in _NOT_PLAIN_ASCII.findall(text) if ch == _REPLACEMENT or not ch.isprintable())
            if whole and not unprintable and not skipped:
                return text  # clean text from the first character on: the usual case
            score = (not whole, unprintable, -len(_LETTERS_AND_SPACES.findall(text)))
            if best is None or score < best[0]:
                best = (score, text)
    return None if best is None else best[1]


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
# A run of eight or more zero-width spaces, joiners, word joiners or byte
# order marks: no text needs one (each has its use alone, between visible
# characters), and eight of them are a byte of hidden bits. Other characters
# that draw nothing, spaces and line breaks may stand between them, as in a
# run the decoder reads (_BETWEEN_CARRIERS). Removed whole.
_ZERO_WIDTH_RUN = _run_of(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), 8)
# Bits scattered one to seven at a time between visible characters: a pair
# whose characters, read in order across the whole text, spell text is
# removed whole (`_without_scattered_bits`). U+2062/U+2064 go anyway.
_ZERO_WIDTH_CHARS = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")
_ZERO_WIDTH_PAIRS = tuple(
    (pair, re.compile(f"[^{pair}]+"), {ord(ch): None for ch in pair}) for pair in _BIT_PAIRS if "\u2062" not in pair
)
# Variation selectors that clean_for_forwarding reduces: every run of them,
# one or more long (a single one is kept only where it belongs).
_SELECTORS_TO_REDUCE = re.compile(f"[{_SELECTORS}]+")
# CJK ideographs: the characters an ideographic variation selector belongs after.
_CJK_IDEOGRAPHS = ((0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xF900, 0xFAFF), (0x20000, 0x323AF))
# U+FE0E (text style) and U+FE0F (emoji style) belong after a character that
# can be drawn as an emoji: a symbol (So, Sm), a pictograph from U+1F000 on,
# the keycap bases, and the few emoji filed as punctuation or a letter.
_TEXT_OR_EMOJI_STYLE = "\ufe0e\ufe0f"
_EMOJI_BASES_ELSEWHERE = frozenset("#*0123456789\u203c\u2049\u2139\u3030\u303d")
# U+FE00..U+FE0D pick a standardized variant (Unicode's StandardizedVariants):
# of a mathematical symbol (category Sm), always with U+FE00, and of a CJK
# ideograph, with U+FE00..U+FE02 (its compatibility forms). No emoji or other
# symbol has one, so a selector after each emoji, which could carry four
# hidden bits, is not kept.
_EMOJI_SYMBOLS = ("So", "Sm")
_MATH_VARIANT = "\ufe00"
_CJK_VARIANTS = "\ufe00\ufe01\ufe02"
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
      * the invisible operators U+2061 to U+2064, and runs of eight or more
        zero-width spaces, joiners, word joiners and byte order marks, also
        when other characters that draw nothing, or spaces, stand between
        them (_ZERO_WIDTH_RUN); and every character of one of the pairs that
        carry bits (U+200B/U+200C, U+200C/U+200D, U+2060/U+FEFF) when those
        characters, read in order across the whole text, spell text: bits
        scattered a few at a time between visible characters;
      * all but the first of a run of variation selectors, and that one too
        unless it belongs after the character before it: VS15 or VS16 after
        a character that can be drawn as an emoji, U+FE00 after a
        mathematical symbol, U+FE00..U+FE02 or an ideographic variation
        selector after a CJK ideograph. An emoji keeps its one VS15 or VS16,
        and a name written with an ideographic variant keeps it; any other
        selector after a letter, an emoji or a symbol goes (one after each
        could carry four hidden bits).

    Ordinary text, including Arabic, Hebrew, CJK and emoji, is unchanged. Removing a
    character joins the text on either side of it. The detector's matching
    views remove the same characters, but scan the cleaned text as well as
    the original before passing the cleaned one on: what is forwarded must be
    what was checked.
    """
    if "\x1b" in text:
        text = TERMINAL_ESCAPE.sub("", text)
    if "\x9b" in text or "\x9d" in text:
        text = C1_TERMINAL_ESCAPE.sub("", text)
    text = text.translate(_CONTROLS_AND_BIDI)
    if "\r" in text:
        text = _LONE_CARRIAGE_RETURN.sub("\n", text)
    if TAG_CHARACTERS.search(text):
        text = _FLAG_OR_TAGS.sub(lambda match: match.group() if match.group("flag") else "", text)
    text = _without_scattered_bits(text)
    if _ZERO_WIDTH_RUN.search(text):
        text = _ZERO_WIDTH_RUN.sub("", text)
    if _SELECTORS_TO_REDUCE.search(text):
        text = _SELECTORS_TO_REDUCE.sub(_one_selector_at_most, text)
    return text


def _without_scattered_bits(text: str) -> str:
    """`text` without the characters of each zero-width pair that, read in order across it, spell text.

    Only for a text with _MIN_SCATTERED_BITS zero-width characters or more,
    and a pair with that many and both of its characters (ordinary text uses
    one of them alone, which spells nothing). As decode_invisible reads such
    bits (`_scattered_text`).
    """
    counted = itertools.islice(_ZERO_WIDTH_CHARS.finditer(text), _MIN_SCATTERED_BITS)
    if sum(1 for _ in counted) < _MIN_SCATTERED_BITS:
        return text
    for pair, others, removed in _ZERO_WIDTH_PAIRS:
        if pair[0] in text and pair[1] in text and _scattered_text(others.sub("", text), pair) is not None:
            text = text.translate(removed)
    return text


def _one_selector_at_most(match: re.Match[str]) -> str:
    """What is kept of a run of variation selectors: its first one, if it belongs after the character before it."""
    first = match.group()[0]
    start = match.start()
    if not start:
        return ""
    base = match.string[start - 1]
    code = ord(base)
    cjk = any(low <= code <= high for low, high in _CJK_IDEOGRAPHS)
    if first in _TEXT_OR_EMOJI_STYLE:
        emoji = code >= 0x1F000 or base in _EMOJI_BASES_ELSEWHERE or unicodedata.category(base) in _EMOJI_SYMBOLS
        return first if emoji else ""
    if first <= "\ufe0d":  # U+FE00..U+FE0D
        if cjk:
            return first if first in _CJK_VARIANTS else ""
        return first if first == _MATH_VARIANT and unicodedata.category(base) == "Sm" else ""
    return first if cjk else ""  # an ideographic variation selector


# --------------------------------------------------------------------------
# Folding for exact values
# --------------------------------------------------------------------------


class _WithoutInvisible(dict):  # type: ignore[type-arg]
    """A str.translate table that removes the characters that draw nothing, filled in as characters are met.

    Those are the format characters (category Cf) and INVISIBLE_OUTSIDE_FORMAT.
    """

    def __missing__(self, code: int) -> int | None:
        kept = None if code in INVISIBLE_OUTSIDE_FORMAT or unicodedata.category(chr(code)) == "Cf" else code
        self[code] = kept
        return kept


# The table every text shares, which remembers the characters it has met. A
# text that could take it past _MAX_REMEMBERED characters gets a table of its
# own instead, which goes with it: one hostile text holding every character
# of Unicode would otherwise leave a table of tens of megabytes behind.
_WITHOUT_INVISIBLE = _WithoutInvisible()
_MAX_REMEMBERED = 16_384


def _without_invisible(text: str) -> str:
    """`text` without the characters that draw nothing (see _WithoutInvisible)."""
    shared = len(_WITHOUT_INVISIBLE) + len(text) <= _MAX_REMEMBERED
    return text.translate(_WITHOUT_INVISIBLE if shared else _WithoutInvisible())


# Characters normalized in one call, and how many times longer a slice may get
# (see detector._decompose for why long texts are normalized in slices).
_FOLD_SLICE = 256
_MAX_FOLD_EXPANSION = 4


def folded_text(text: str) -> str:
    """`text` without the characters that draw nothing, in NFKC form.

    Removed: format characters (zero-width spaces and joiners, tags, bidi
    controls), variation selectors, the grapheme joiner, fillers
    (INVISIBLE_OUTSIDE_FORMAT). NFKC turns compatibility forms into plain
    ones: full-width letters, ligatures, circled and superscript digits. For comparing exact values,
    which a hijacked agent can spell that way at no cost. ASCII text is
    returned as it is. Normalized in slices, never cut between a character
    and the marks that combine with it, and a slice that would grow more than
    _MAX_FOLD_EXPANSION times has its expanding characters made spaces, so
    hostile text stays quick and short. (A slice with one of the characters
    of _MAY_EXPAND is measured by its characters each folded alone, which
    can be a little longer than the slice folded whole.)
    """
    if text.isascii():
        return text
    text = _without_invisible(text)
    pieces: list[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + _FOLD_SLICE)
        reach = min(len(text), end + 32)
        while end < reach and unicodedata.combining(text[end]):
            end += 1
        piece = text[start:end]
        # Normalising a slice full of characters that expand is itself slow (on Windows above all), so a
        # slice that holds any of those that expand most is first measured without normalising it.
        if _MAY_EXPAND.search(piece) is not None and _folded_length(piece) > _MAX_FOLD_EXPANSION * len(piece):
            piece = _without_expanding(piece)
        folded = unicodedata.normalize("NFKC", piece)
        if len(folded) > _MAX_FOLD_EXPANSION * len(piece):  # a character that expands, not among those
            folded = unicodedata.normalize("NFKC", _without_expanding(piece))
        pieces.append(folded)
        start = end
    return "".join(pieces)


# Where the characters are that NFKC writes as more than _MAX_FOLD_EXPANSION characters: squared Katakana
# words and units (U+3307 ... U+33AF) and two Arabic ligatures (U+FDFA, U+FDFB, which become 18 and 8).
_MAY_EXPAND = re.compile("[㌀-㏿ﷺﷻ]")


def _folded_length(piece: str) -> int:
    """How long `piece` is with each character in its own NFKC form (composing marks only shortens it)."""
    return sum(piece.count(ch) * len(unicodedata.normalize("NFKC", ch)) for ch in set(piece))


def _without_expanding(piece: str) -> str:
    """`piece` with a space for each character NFKC writes as more than _MAX_FOLD_EXPANSION characters.

    One translate, with a table of the characters of the piece: not a
    normalisation per character.
    """
    expanding = {
        ord(ch): " " for ch in set(piece) if len(unicodedata.normalize("NFKC", ch)) > _MAX_FOLD_EXPANSION
    }
    return piece.translate(expanding)


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


def media_blocks(value: Any) -> frozenset[int]:
    """The id() of each image and audio content block in a JSON-like value that a client renders as media.

    Only the places where MCP puts the content a client renders count, and
    each only in the kind of value that has it:

      * an item of the "content" array of a tool's result (an object with a
        "content" array and no "messages");
      * the "content" of one of the "messages" of a prompt or a sampling
        request (an object with a "messages" array and no "content"): a
        single block, or an item of an array of blocks;
      * an item of the value itself, when it is an array (a tool's output
        given as its blocks).

    A whole JSON-RPC message may be read too: then the "params" of a request
    or notification (an object with a "method") or the "result" of a reply
    (one with "jsonrpc" and no "method") is read as above, and nothing else
    of it. An object with both "content" and "messages" is neither kind, so
    none of its blocks counts; nor does an extra "result", "params" or
    "messages" member of a tool's result. An image-shaped object anywhere
    else (_meta, structuredContent, a block nested in a block, an array in an
    array, the value itself) is not one: it would be shown as text, if at
    all. Only the exact "data" member of these blocks is read as media (see
    text_views); a copy of the same text elsewhere is not. At most
    MAX_CONTAINERS blocks are looked at.
    """
    blocks: list[Iterable[Any]] = [value] if isinstance(value, list) else []
    holder = _content_holder(value)
    if holder is not None:
        content, messages = holder.get("content"), holder.get("messages")
        if isinstance(content, list) and "messages" not in holder:
            blocks.append(content)
        elif isinstance(messages, list) and "content" not in holder:
            for message in itertools.islice(messages, MAX_CONTAINERS):
                inner = message.get("content") if isinstance(message, dict) else None
                blocks.append(inner if isinstance(inner, list) else [inner])
    found: set[int] = set()
    for block in itertools.islice(itertools.chain.from_iterable(blocks), MAX_CONTAINERS):
        if isinstance(block, dict) and block.get("type") in _MEDIA_TYPES and isinstance(block.get("data"), str):
            found.add(id(block))
    return frozenset(found)


def _content_holder(value: Any) -> dict[str, Any] | None:
    """The object of `value` that holds rendered content blocks: a request's params, a reply's result, or itself."""
    if not isinstance(value, dict):
        return None
    if isinstance(value.get("method"), str):  # a request or notification, or an entry of an input_required result
        params = value.get("params")
        return params if isinstance(params, dict) else None
    if "jsonrpc" in value:  # a whole reply
        result = value.get("result")
        return result if isinstance(result, dict) else None
    return value


# --------------------------------------------------------------------------
# Base64 and hex runs
# --------------------------------------------------------------------------

MIN_BASE64_CHARS = 32  # 24 bytes: shorter runs are ids and hashes far more often than text
MIN_HEX_CHARS = 48  # 24 bytes: a SHA-1 (40) or a short id is not decoded
_HEX_DIGITS = re.compile(r"[0-9A-Fa-f]+")
_UPPER = re.compile(r"[A-Z]")
_LOWER = re.compile(r"[a-z]")
_SLASHES = re.compile(r"/+")
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
# Base64 cut into pieces, read joined up (besides each piece that is long
# enough, on its own: two values next to each other are not one).
# Pieces: runs of _MIN_PIECE_CHARS characters or more (as the run pattern
# finds them) with a line break and its indent, a space or two, or a
# written-out "\n" between them (_PIECE_BREAK); after a line break the last
# piece may be shorter (_LAST_PIECE). Shorter pieces are the words of
# ordinary text. They are grouped as the runs are found, so the text is
# read once.
# _SHORT_LINES: three or more whole lines of 8 to 15 characters, as base64
# wrapped at a short width, and a shorter last line. It starts with the line
# break before the block (or the start of the text), which lets the regex
# engine jump from one line break to the next.
_BASE64_CHARS = "A-Za-z0-9+/_-"
# How long a piece is: wrapped base64 has lines of 64 or 76 characters, and a
# longer run is a value of its own, not a piece of one.
_MIN_PIECE_CHARS = 16
_MAX_PIECE_CHARS = 256
# What stands between two pieces. A written-out "\n" puts an "n" in front of the next piece ("\r" the
# character between the two backslashes), which the run that follows starts with.
_PIECE_BREAK = re.compile(r"\r?\n[ \t]{0,8}|[ \t]{1,2}")
_WRITTEN_OUT_BREAK = ("\\", "\\r\\")
_LAST_PIECE = re.compile(rf"\r?\n[ \t]{{0,8}}[{_BASE64_CHARS}]{{1,15}}(?![{_BASE64_CHARS}])={{0,2}}")
_LINES = (
    rf"(?P<block>[{_BASE64_CHARS}]{{8,15}}(?:\r?\n[{_BASE64_CHARS}]{{8,15}}){{2,}}"
    rf"(?:\r?\n[{_BASE64_CHARS}]{{1,7}}(?![{_BASE64_CHARS}]))?={{0,2}})"
)
_SHORT_LINES = re.compile(r"\n" + _LINES)
_SHORT_LINES_FIRST = re.compile(_LINES)


_MAX_BLOCKS = 256  # blocks of pieces gathered from one text: more than the attempts of any decoder
# How long a block of pieces gets: far more than the bytes of one run that are decoded (max_run_bytes). A
# longer one is read as blocks of this length.
_MAX_BLOCK_CHARS = 32 * 1024


_COMMON_BREAKS = frozenset({" ", "\n", "\r\n", "\t", "  "})


def _breaks_pieces(text: str, end: int, start: int) -> bool:
    """Whether what stands between a piece that ends at `end` and a run that starts at `start` is a break."""
    if start - end > 10:
        return False
    gap = text[end:start]
    if gap in _COMMON_BREAKS:
        return True
    if gap in _WRITTEN_OUT_BREAK:
        return text.startswith("n", start)
    return _PIECE_BREAK.fullmatch(gap) is not None


def _block_of(text: str, start: int, end: int) -> tuple[int, int]:
    """Where a block of pieces from `start` to `end` stands in `text`, with a shorter last piece on the next line."""
    last = _LAST_PIECE.match(text, end)
    return start, last.end() if last else end


def _joined_up(run: str) -> str:
    """A run without what stands between its pieces: line breaks, spaces, written-out line breaks.

    The run itself when it is in one piece.
    """
    if "\\" in run:
        run = run.replace("\\r\\n", "").replace("\\n", "")
    if "\n" in run or " " in run or "\t" in run or "\r" in run:
        return "".join(run.split())
    return run


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
    decoded again. A run counts as decoded text if it is at least 85%
    printable UTF-8 (a byte that is not UTF-8 counts as unprintable) once up
    to 16 leading bytes (a file's magic bytes, a few NULs) are passed over;
    whether it is, is decided on its first 256 bytes. Padding at its start
    (one group repeated, as NUL bytes are "AAAA...") is passed over too. A
    run that is not text from its start is read for pieces of text (16
    characters or more, see `_text_of`) in its first _SCAN_BYTES bytes:
    text after a binary header, between blocks of binary data, or followed
    by binary data. The pieces are joined by U+FFFD. Such a run costs its
    sample and the text found of the bytes, so a long binary run costs
    little. Every run that looks encoded costs an attempt, binary or not.

    Base64 cut into pieces (lines, spaces, written-out line breaks between
    them: `_runs`, `_SHORT_LINES`) is also read joined up. A run full of "/"
    is tried out of a count of its own and kept only if it is text (a path is
    no text). A run that is not text as it stands is also read from its second
    character on (base64: also its third and fourth; hex: one digit in front),
    at no further attempt; an odd number of hex digits is read without its last.

    The limits make the work bounded on hostile input, and they can be used to
    hide a payload: runs placed before it use up the attempts or the bytes, and
    a payload encoded twice, split over runs, or hex written with separators
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
                   for a caller that looks for tokens inside binary data. A run
                   of text followed by binary data is returned that way too.
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
        self.attempts_left = self._max_attempts = max_attempts
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
        # Runs as short as a piece are found (`_runs`), and only those of the
        # shortest length decoded are tried on their own. Each match is a whole
        # run: one that is long enough matches from its first character on.
        self._shortest = shortest = min(min_base64_chars, min_hex_chars)
        self._run_pattern = re.compile(
            rf"[{_BASE64_CHARS}]{{{min(shortest, _MIN_PIECE_CHARS)},}}(?:\r?\n[{_BASE64_CHARS}]+)*={{0,2}}"
        )
        self._hex_pattern = re.compile(rf"[0-9A-Fa-f]{{{min_hex_chars},}}")
        self._seen: set[str] = set()
        # Runs full of "/" are paths far more often than base64. They are tried all the same (see
        # `_attempt`), but out of a count of their own: a listing of files must not use up the attempts.
        self._path_attempts_left = max_attempts

    def decoded(self, text: str, *, read_before: str | None = None) -> list[DecodedRun]:
        """Each new run in `text` that decodes to text: base64-shaped runs first, then hex ones, then base64
        cut into pieces (see `_runs`) and in short lines (`_SHORT_LINES`).

        read_before: a text this decoder was given before, of which `text`
        is another spelling (the same without invisible characters, say). A
        run that stands in it as it does here was read there and is passed
        over, and at most `max_attempts` runs that this decoder has not met
        are looked at: only what the other spelling brings together is new.
        """
        found: list[DecodedRun] = []
        unmet_left = self._max_attempts
        for run in self._runs(text):
            if self.attempts_left <= 0 or self.kept_left <= 0 or self.bytes_left <= 0:
                break
            if run in self._seen:
                continue
            if read_before is not None:
                if unmet_left <= 0:
                    break
                unmet_left -= 1
                # Only its start can be decoded (max_run_bytes): a long run is not copied and read whole.
                run = run[: 2 * self._max_run_bytes + 4]
                if run in read_before or run in self._seen:
                    continue
            self._seen.add(run)
            compact = _joined_up(run)
            if compact is not run:
                if compact in self._seen:
                    continue  # the same run with other breaks between its pieces
                self._seen.add(compact)
            attempts = self.attempts_left + self._path_attempts_left
            first = self._attempt(compact, run)
            tried = self.attempts_left + self._path_attempts_left < attempts
            results = [first]
            if "/" in compact and (_not_clean_text(first) or _partly_text(first)):
                # In a URL the path before a run is part of it ("example/Z2hw..."): try what follows the last "/".
                tail = compact.rpartition("/")[2]
                if tail not in self._seen:
                    self._seen.add(tail)
                    results.append(self._attempt(tail, tail))
            if len(results) == 2:
                results = _with_the_part_after_a_slash(*results)
            if tried and not _is_text(first):
                # Not text as it stands. A character or two written in front of a run shifts every
                # byte of it: read from one of its next characters, it may be text from there on.
                # Read as well, not instead: binary data as it stands may hold a token (the guard).
                # Only a run that was tried: one past the limits is not read at all.
                results.append(self._shifted(compact, run))
            for result in results:
                if result is not None and self.kept_left > 0:
                    self.kept_left -= 1
                    found.append(result)
        return found

    def _runs(self, text: str) -> Iterator[str]:
        """The candidates in `text`, as they stand in it: runs, hex runs, then blocks of pieces and short lines.

        The blocks of pieces are gathered from the runs as they are found
        (at most _MAX_BLOCKS of them), and come after the hex runs.
        """
        blocks: list[tuple[int, int]] = []
        shortest = self._shortest
        first = last = -1  # where the block of pieces being gathered starts and ends
        pieces = 0
        for match in self._run_pattern.finditer(text):
            start, end = match.span()
            if end - start >= shortest:
                yield match.group()
            if not _MIN_PIECE_CHARS <= end - start <= _MAX_PIECE_CHARS or len(blocks) >= _MAX_BLOCKS:
                continue
            if pieces and end - first <= _MAX_BLOCK_CHARS and (
                text[last:start] in _COMMON_BREAKS or _breaks_pieces(text, last, start)
            ):
                last, pieces = end, pieces + 1
                continue
            if pieces > 1:
                blocks.append(_block_of(text, first, last))
            first, last, pieces = start, end, 1
        if pieces > 1 and len(blocks) < _MAX_BLOCKS:
            blocks.append(_block_of(text, first, last))
        for match in self._hex_pattern.finditer(text):
            yield match.group()
        for start, end in blocks:
            yield text[start:end]
        if "\n" in text:
            first = _SHORT_LINES_FIRST.match(text)
            if first is not None:
                yield first.group("block")
            for match in _SHORT_LINES.finditer(text):
                yield match.group("block")

    def _attempt(self, compact: str, run: str) -> DecodedRun | None:
        """Decode one candidate, if it looks encoded and the limits allow; None if it is not text."""
        if self.attempts_left <= 0 or self.bytes_left <= 0:
            return None
        kind = self._kind(compact)
        if kind is None:
            return None
        # A run full of path separators is a path, unless it decodes to text: "?" at the right places
        # of a text is written "/", and a payload must not escape decoding by holding many of them. A
        # run of slashes counts once: it is how bytes 0xFF are written ("////").
        path = kind == "base64" and len(_SLASHES.findall(compact)) * 16 > len(compact)
        if path:
            if self._path_attempts_left <= 0:
                return None
            self._path_attempts_left -= 1
        else:
            self.attempts_left -= 1
        return self._decode(compact, kind, run, path)

    def _kind(self, run: str) -> str | None:
        """How to decode `run`, or None if it does not look like encoded text at all (which costs no attempt)."""
        bare = run.rstrip("=")
        if len(bare) >= self._min_hex_chars and _HEX_DIGITS.fullmatch(bare):
            return "hex"  # with an odd number of digits too: one more digit must not switch decoding off
        if len(run) < self._min_base64_chars:
            return None
        # Base64 of text has capitals and small letters: a run without both is a word or an id.
        if not (_UPPER.search(run) and _LOWER.search(run)):
            return None
        if ("+" in run or "/" in run) and ("-" in run or "_" in run):
            return None  # both alphabets at once: not base64
        return "base64"

    def _shifted(self, compact: str, run: str) -> DecodedRun | None:
        """A run that is not text as it stands, read from its second character on (base64: also its third
        or fourth), if it is text from there; else None. See `_realigned`. It costs no further attempt."""
        kind = self._kind(compact)
        if kind is None or self.bytes_left <= 0:
            return None
        limit = min(self._max_run_bytes, self.bytes_left)
        realigned = _realigned(compact.rstrip("="), kind, limit)
        if realigned is None:
            return None
        bare, sample, sample_cut, whole, found = realigned
        raw, cut = (sample, sample_cut) if whole else _raw_bytes(bare, kind, limit)
        found_text = None if raw is None else _text_of(raw[found[0]:], truncated=cut < len(bare))
        if raw is None or found_text is None or not found_text[1]:
            return None  # text at its start only: the run as it stands is read for pieces of text already
        self.bytes_left -= len(raw)
        return DecodedRun(kind, found_text[0], run)

    def _decode(self, compact: str, kind: str, run: str, path: bool = False) -> DecodedRun | None:
        """Decode a run: first a sample, to tell text from binary data, then as much as the limits allow.

        path: the run is full of "/" (see `_attempt`): it is returned only if text is found in it.
        """
        limit = min(self._max_run_bytes, self.bytes_left)
        bare = _whole_groups(_without_padding(compact.rstrip("="), kind), kind)
        sample, sample_cut = _raw_bytes(bare, kind, min(limit, _SAMPLE_BYTES + _MAX_SKIPPED_BYTES))
        if sample is None:
            return None  # not valid base64 or hex
        whole = sample_cut >= len(bare)  # the sample is the whole run
        found = _start_of_text(sample, truncated=not whole)
        if found is not None and found[1]:
            # Text from its first bytes on, as far as the sample goes: decoded as far as the limits allow.
            raw, cut = (sample, sample_cut) if whole else _raw_bytes(bare, kind, limit)
            if raw is None:
                return None
            found_text = _text_of(raw[found[0]:], truncated=cut < len(bare))
            charged = len(raw)
        else:
            # Binary data, or text followed by binary data: text may stand further in (after a long binary
            # header, or between two blocks of binary data). Its first _SCAN_BYTES bytes are read for it.
            raw, cut = (sample, sample_cut) if whole else _raw_bytes(bare, kind, min(limit, _SCAN_BYTES))
            if raw is None:
                return None
            found_text = _text_of(raw, truncated=cut < len(bare))
            # Charged for the sample and the text found: a binary run must not use up the bytes of the runs after it.
            charged = len(sample) + (len(found_text[0]) if found_text else 0)
        if found_text is None and path:
            self.bytes_left -= charged
            return None  # a path after all
        if found_text is None or (not found_text[1] and self._binary):
            # Binary data, or text and binary data: the guard reads it all as Latin-1, so nothing in it is missed.
            return self._binary_run(bare, kind, run, raw, cut >= len(bare), limit, charged)
        self.bytes_left -= charged
        return DecodedRun(kind, found_text[0], run)

    def _binary_run(
        self, bare: str, kind: str, run: str, raw: bytes, whole: bool, limit: int, charged: int
    ) -> DecodedRun | None:
        """A run of binary data: its first MAX_BINARY_BYTES bytes as Latin-1 if they are asked for, else None.

        charged: what the run costs of the bytes when they are not asked for.
        """
        if not self._binary:
            self.bytes_left -= charged
            return None
        if not whole and len(raw) < min(limit, MAX_BINARY_BYTES):
            raw = _raw_bytes(bare, kind, min(limit, MAX_BINARY_BYTES))[0] or raw
        self.bytes_left -= len(raw)
        return DecodedRun(kind, raw[:MAX_BINARY_BYTES].decode("latin-1"), run, binary=True)


def _is_text(found: DecodedRun | None) -> bool:
    """Whether a run was decoded, to text."""
    return found is not None and not found.binary


def _partly_text(found: DecodedRun | None) -> bool:
    """Whether a run decoded to text with binary data in it (pieces of text joined by U+FFFD, or a stray byte)."""
    return found is not None and not found.binary and _REPLACEMENT in found.text


def _without_padding(bare: str, kind: str) -> str:
    """A run without its leading padding: one group (3 bytes of base64, 1 of hex) repeated, if it is not text.

    NUL bytes are "AAAA..." in base64: text behind any number of them is
    read, without decoding them. The group is passed over whole, so what
    follows is decoded as it would have been. What follows must be long
    enough to hold _MIN_TEXT_CHARS bytes: padding with a character or two
    after it is binary data, as before.
    """
    size = 2 if kind == "hex" else 4
    group = bare[:size]
    if len(group) < size or not bare.startswith(group, size):
        return bare
    raw, _ = _raw_bytes(group, kind, 3)
    if raw is None or _PLAIN_TEXT_BYTES.fullmatch(raw):
        return bare  # not valid, or text that repeats ("YWFhYWFh" is "aaaaaa")
    repeated = re.match(f"(?:{re.escape(group)})+", bare)
    rest = bare[repeated.end():] if repeated else bare
    shortest = 2 * _MIN_TEXT_CHARS if kind == "hex" else (_MIN_TEXT_CHARS * 4 + 2) // 3
    return rest if len(rest) >= shortest else bare


_A_WORD = re.compile(r"[^\W\d_]{3}")  # three letters in a row
_BOUNDARY_CHARS = 8  # how much of the text before a tail is looked at for bytes that are no text


def _with_the_part_after_a_slash(first: DecodedRun | None, from_tail: DecodedRun | None) -> list[DecodedRun | None]:
    """What is kept of a run and of the part after its last "/", each as decoded (None: not text).

    Both, unless one says nothing the other does not: a tail whose text
    stands inside the run's adds nothing. When the run's text ends with the
    tail's, what stands before it in the run decides.

      * No words (a URL's path read as base64): the tail alone, the same
        text without those bytes in front of it. Unless they end in a letter
        or digit and hold no control character: then they may be the start
        of a word that a stray byte cut ("Ig", a byte, "nore all ..."), and
        both are kept.
      * Words: the run, which has all of the text; the tail is its end, cut
        where a "/" happened to stand. With the tail when bytes that are no
        text stand right before it in the run, so that its first word is
        read clean as well.
    """
    if first is None or first.binary or from_tail is None or from_tail.binary:
        return [first, from_tail]
    if not first.text.endswith(from_tail.text):
        return [first] if from_tail.text in first.text else [first, from_tail]
    before = first.text[: len(first.text) - len(from_tail.text)]
    if _A_WORD.search(before) is None:
        cuts_a_word = before.rstrip(_REPLACEMENT)[-1:].isalnum() and all(ch.isprintable() for ch in before)
        return [first, from_tail] if cuts_a_word else [from_tail]
    near = before[-_BOUNDARY_CHARS:]
    return [first, from_tail] if any(ch == _REPLACEMENT or not ch.isprintable() for ch in near) else [first]


def _whole_groups(bare: str, kind: str) -> str:
    """A run without the last digit of an odd number of hex digits: one digit cannot be a byte."""
    return bare[:-1] if kind == "hex" and len(bare) % 2 else bare


def _realigned(
    bare: str, kind: str, limit: int
) -> tuple[str, bytes, int, bool, tuple[int, bool]] | None:
    """A run read from its second character on (base64: also its third or fourth), if it is text from there.

    One to three characters in front of base64 text, or one digit in front of
    hex, shift every byte of the run, and none of it reads as text any more.
    Each shift is judged on a sample, as the run itself is, and counts only
    if the sample is text throughout from its first byte, _MIN_TEXT_CHARS
    characters or more: binary data read four ways must not pass for text
    more often, and one look at each shift keeps a binary run cheap. Returns
    the shifted run and what `_decode` knows of it (its sample, how many
    characters that took, whether that is all of it, where its text starts).
    """
    sample_chars = 2 * _SAMPLE_BYTES + 4  # characters enough for a sample of either kind
    for skipped in range(1, 2 if kind == "hex" else 4):
        # The sample is read from the start of the shifted run only: the run itself may be long.
        head = bare[skipped : skipped + sample_chars]
        sample, cut = _raw_bytes(_whole_groups(head, kind), kind, min(limit, _SAMPLE_BYTES))
        if sample is None or len(sample) < _MIN_TEXT_CHARS:
            continue
        shifted_chars = len(bare) - skipped
        whole = cut >= (shifted_chars - shifted_chars % 2 if kind == "hex" else shifted_chars)
        found = _text_of(sample, truncated=not whole)
        if found is not None and found[1]:
            return _whole_groups(bare[skipped:], kind), sample, cut, whole, (0, True)
    return None


def _not_clean_text(found: DecodedRun | None) -> bool:
    """Whether a decoded run is not plain text from its first characters on: nothing, binary data, or text with
    an unprintable character among its first ones, as when the path before a run in a URL is decoded with it."""
    if found is None or found.binary:
        return True
    start = found.text[:_MIN_TEXT_CHARS]
    return any(ch == _REPLACEMENT or not ch.isprintable() for ch in _NOT_PLAIN_ASCII.findall(start))


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


def _start_of_text(sample: bytes, truncated: bool) -> tuple[int, bool] | None:
    """Where text starts in the first bytes of a run (0 to _MAX_SKIPPED_BYTES), and whether all of the sample
    after it is text; None if it holds no text. All text after a few skipped bytes is preferred to pieces."""
    pieces = None
    for start in range(min(_MAX_SKIPPED_BYTES, max(0, len(sample) - 1)) + 1):
        found = _text_of(sample[start:start + _SAMPLE_BYTES], truncated or start + _SAMPLE_BYTES < len(sample))
        if found is not None and found[1]:
            return start, True
        if found is not None and pieces is None:
            pieces = (start, False)
    return pieces


# Characters that may not be printable: all but printable ASCII, tab, line feed and carriage return.
_NOT_PLAIN_ASCII = re.compile(r"[^\t\n\r -~]")
_LETTERS_AND_SPACES = re.compile(r"[^\W\d_]| ")
_PLAIN_TEXT_BYTES = re.compile(rb"[\t\n\r -~]+")
# What bytes that are not UTF-8 become ("\xff" is one).
_REPLACEMENT = "\ufffd"
# Text and binary data in one run: a piece of text counts if it has this many
# characters or more, at most _MAX_UNPRINTABLE_AT_START of its first ones
# unprintable; after binary data, this many more (see `_start_of_a_piece`).
_MIN_TEXT_CHARS = 16
_MIN_LATER_TEXT_CHARS = 32
_MAX_UNPRINTABLE_AT_START = int((1 - _PRINTABLE_SHARE) * _MIN_TEXT_CHARS)
# How many bytes of a run that is not text from its start are read for pieces of text, and how many pieces.
_SCAN_BYTES = 4 * 1024
_MAX_TEXT_PIECES = 64


def _as_text(raw: bytes, truncated: bool) -> str | None:
    """`raw` as text, if it is mostly printable UTF-8 or has pieces of text in it; otherwise None (see `_text_of`)."""
    found = _text_of(raw, truncated)
    return None if found is None else found[0]


def _text_of(raw: bytes, truncated: bool) -> tuple[str, bool] | None:
    """(text, whole): `raw` read as UTF-8, if at least 85% of it is printable (whole is then True); else the
    pieces of text in it, joined by U+FFFD (whole is then False); None if it holds no text.

    A byte that is not UTF-8 is read as U+FFFD and counts as unprintable: one
    stray byte, before, inside or after a payload, costs an attacker nothing
    and must not make the whole run binary data. For the same reason binary
    data before, between or after pieces of text does not hide them: a piece
    is a stretch of _MIN_TEXT_CHARS characters or more that starts with
    mostly printable ones and is, as a whole, at least 85% printable (so it
    may take in some of the binary data after it). At most _MAX_TEXT_PIECES
    pieces. truncated: the run was decoded only in part, so it may end inside
    a character, which is then left out.
    """
    text = raw.decode("utf-8", errors="replace")
    if truncated and text.endswith(_REPLACEMENT):
        text = text[:-1]
    if not text:
        return None
    unprintable = [
        match.start() for match in _NOT_PLAIN_ASCII.finditer(text)
        if match.group() == _REPLACEMENT or not match.group().isprintable()
    ]
    if len(text) - len(unprintable) >= _PRINTABLE_SHARE * len(text):
        return text, True
    pieces: list[str] = []
    position = 0
    while len(pieces) < _MAX_TEXT_PIECES:
        start = _start_of_a_piece(unprintable, position, len(text))
        if start is None:
            break
        end = _end_of_a_piece(unprintable, start, len(text))
        pieces.append(text[start:end])
        position = end
    return (_REPLACEMENT.join(pieces), False) if pieces else None


def _start_of_a_piece(unprintable: list[int], position: int, length: int) -> int | None:
    """Where the first piece of text at or after `position` starts: a printable character, followed by enough
    printable ones (see `_text_of`); None if there is none. `unprintable`: the positions of the unprintable ones.

    Near the start of the data (a file's magic bytes before it), _MIN_TEXT_CHARS characters with at most
    _MAX_UNPRINTABLE_AT_START unprintable make a piece; further in, after binary data, _MIN_LATER_TEXT_CHARS:
    random bytes hold a short printable stretch now and then (one 4 KiB block in three holds 16), a long one
    almost never.
    """
    index = bisect.bisect_left(unprintable, position)
    start = position  # a piece starts at `position`, or right after an unprintable character
    while True:
        size = _MIN_TEXT_CHARS if start <= _MAX_SKIPPED_BYTES else _MIN_LATER_TEXT_CHARS
        if start + size > length:
            return None
        if index < len(unprintable) and unprintable[index] == start:
            start, index = start + 1, index + 1  # an unprintable character itself
            continue
        within = bisect.bisect_left(unprintable, start + size, index) - index
        if within <= _MAX_UNPRINTABLE_AT_START:
            return start
        start, index = unprintable[index] + 1, index + 1


# Reading a piece of text stops once it holds this many unprintable characters more than 15% of it: what
# follows is binary data (text after it is the next piece).
_UNPRINTABLE_EXCESS = 32


def _end_of_a_piece(unprintable: list[int], start: int, length: int) -> int:
    """Where the piece of text that starts at `start` ends: as far on as it stays at least 85% printable."""
    first = bisect.bisect_left(unprintable, start)
    if (length - start) - (len(unprintable) - first) >= _PRINTABLE_SHARE * (length - start):
        return length
    # The text before the n-th unprintable character after `start` holds n of them: the longest that is mostly
    # printable ends at one of them.
    end = start + _MIN_TEXT_CHARS
    for count in range(len(unprintable) - first):
        at = unprintable[first + count]
        if (at - start) - count >= _PRINTABLE_SHARE * (at - start):
            end = max(end, at)
        elif count > (1 - _PRINTABLE_SHARE) * (at - start) + _UNPRINTABLE_EXCESS:
            break
    return end
