"""Small text helpers shared by the other modules.

`texts_in` and `text_views` collect the text inside a nested value so that it
can be matched against a policy or scanned for injection. `printable` makes
untrusted text safe to show on a terminal.

Also here, because the detector and the secret guard both need them:

  * `TERMINAL_ESCAPE` and the Unicode tag-character helpers (`decode_tags`,
    `smuggled_text`), and `clean_for_forwarding`, which removes escapes, tags
    and other hiding characters from text that is passed on to a client;
  * `tool_parameters` and `media_payloads`, which pick parts out of MCP
    messages for the detector;
  * `EncodedRuns`, the bounded decoder of base64 and hex runs (`DecodedRun`).
"""

from __future__ import annotations

import array
import base64
import binascii
import dataclasses
import itertools
import json
import re
import unicodedata
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

    Blank views are left out. `strict` is as in `texts_in`. A FIELD_BREAK in
    the value's own text becomes a space, so every one in a view is a real break.
    """
    everything: list[str] = []
    values: list[str] = []
    siblings: dict[int, list[str]] = {}
    for group, text in _walk(value, keys=True, scalars=False, strict=strict):
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
# Cleaning text that is passed on
# --------------------------------------------------------------------------

# Removed by clean_for_forwarding, besides escape sequences and tags: the C0
# controls except tab, line feed and carriage return; DEL; the C1 controls
# (U+009B and U+009D start a terminal escape on their own); and the
# bidirectional embedding, override and isolate controls, which reorder how
# text is drawn ("Trojan Source"). The everyday direction marks (U+200E,
# U+200F, U+061C) and joiners are kept: Arabic, Hebrew, Persian and emoji need them.
_CONTROLS_AND_BIDI = {
    code: None
    for code in [
        *range(0x00, 0x09), 0x0B, 0x0C, *range(0x0E, 0x20), *range(0x7F, 0xA0),
        *range(0x202A, 0x202F), *range(0x2066, 0x206A),
    ]
}
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
      * the bidirectional embedding, override and isolate controls.

    Ordinary text, including Arabic, Hebrew and emoji, is unchanged. Removing a
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
    return text


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
# Where a JSON schema keeps the schemas of its parts.
_NESTED_SCHEMA_KEYS = ("items", "additionalProperties", "not")
_SCHEMA_LIST_KEYS = ("anyOf", "oneOf", "allOf", "prefixItems")
_SCHEMA_MAP_KEYS = ("properties", "$defs", "definitions", "patternProperties")


def tool_parameters(tool: Any) -> dict[str, str]:
    """The input parameters of an MCP tool definition: each name, with the title and description given for it.

    Read from the tool's "inputSchema", including the parameters of nested
    objects, of array items and of anyOf/oneOf/allOf alternatives. A name used
    twice gets both texts. Anything that is not shaped like a schema is
    skipped: this picks parts out for a closer look, and the whole tool is
    scanned anyway. At most MAX_PARAMETERS parameters are returned.
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
        waiting.extend(schema.get(key) for key in _NESTED_SCHEMA_KEYS)
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


def media_payloads(value: Any) -> frozenset[str]:
    """The base64 "data" of every image and audio content block in a JSON-like value.

    The detector skips these when it decodes base64: a picture is not text, and
    decoding it would use up the decoding budget before the text that matters.
    The walk is iterative and reads at most MAX_CONTAINERS objects and arrays.
    """
    found: set[str] = set()
    waiting: list[Any] = [value]
    opened = 0
    while waiting and opened < MAX_CONTAINERS:
        item = waiting.pop()
        if isinstance(item, dict):
            opened += 1
            if item.get("type") in _MEDIA_TYPES and isinstance(item.get("data"), str):
                found.add(item["data"])
            waiting.extend(item.values())
        elif isinstance(item, (list, tuple)):
            opened += 1
            waiting.extend(item)
    return frozenset(found)


# --------------------------------------------------------------------------
# Base64 and hex runs
# --------------------------------------------------------------------------

MIN_BASE64_CHARS = 32  # 24 bytes: shorter runs are ids and hashes far more often than text
MIN_HEX_CHARS = 48  # 24 bytes: a SHA-1 (40) or a short id is not decoded
_HEX_DIGITS = re.compile(r"[0-9A-Fa-f]+")
_UPPER = re.compile(r"[A-Z]")
_LOWER = re.compile(r"[a-z]")
# Base64 of these file types starts with a fixed prefix. They are binary, so
# they cannot decode to text; skipping them saves the budget.
_BINARY_PREFIXES = (
    "iVBORw0KGgo",  # PNG
    "/9j/",  # JPEG
    "R0lGOD",  # GIF
    "UklGR",  # RIFF: WAV, WebP, AVI
    "SUQz",  # MP3 with an ID3 tag
    "T2dnU",  # Ogg
    "ZkxhQ",  # FLAC
    "AAAA",  # MP4, MOV and other ISO media files
    "JVBERi0",  # PDF
    "UEsDB",  # ZIP, DOCX, XLSX
    "H4sI",  # gzip
)
# A data: URI of a picture, a sound or a video; its base64 is skipped as well.
_MEDIA_DATA_URI = re.compile(r"data:(image|audio|video)/[a-z0-9.+-]{1,40};base64,$")
# Share of the decoded characters that must be printable (or tab, newline,
# return) for a run to be read as text. Random bytes almost never pass.
_PRINTABLE_SHARE = 0.85


class DecodedRun(NamedTuple):
    """A run of base64 or hex that decoded to text."""

    kind: str  # "base64" or "hex"
    text: str  # what it decoded to
    run: str  # the run as it stood in the text


class EncodedRuns:
    """Decodes base64 and hex runs found in text, one level deep, within fixed limits.

    One instance serves one check: the limits are shared by every text it is
    given, and a run met again (in another view of the same value) is not
    decoded again. A run counts as decoded text only if it is valid UTF-8 and
    at least 85% printable.

    The limits make the work bounded on hostile input, and they can be used to
    hide a payload: runs placed before it use up the attempts or the bytes, and
    a payload encoded twice, split over runs, or written with separators
    ("48 65 6c", "\\x48") is not decoded. Runs shorter than the minimum
    lengths are not decoded either.

    max_attempts:  runs decoded (or tried) in all.
    max_kept:      runs returned as text in all.
    max_bytes:     decoded bytes in all.
    max_run_bytes: decoded bytes of one run; a longer run is decoded only in its first part.
    min_base64_chars, min_hex_chars: the shortest run of each kind that is decoded.
    skip:          exact runs not to decode (the "data" of image and audio content).
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
        skip: Iterable[str] = (),
    ) -> None:
        self.attempts_left = max_attempts
        self.kept_left = max_kept
        self.bytes_left = max_bytes
        self._max_run_bytes = max_run_bytes
        self._min_base64_chars = min_base64_chars
        self._min_hex_chars = min_hex_chars
        # A run that may be base64 (either alphabet) or hex: hex digits are
        # base64 letters too, and `_kind` tells them apart. A run may go on over
        # several lines, as `base64` wraps its output. Hex is also looked for on
        # its own, because a letter or "/" before it ("example/6768...") makes
        # the longer run base64-shaped.
        shortest = min(min_base64_chars, min_hex_chars)
        self._run_pattern = re.compile(rf"[A-Za-z0-9+/_-]{{{shortest},}}(?:\r?\n[A-Za-z0-9+/_-]+)*={{0,2}}")
        self._hex_pattern = re.compile(rf"[0-9A-Fa-f]{{{min_hex_chars},}}")
        self._skip = frozenset(skip)
        self._seen: set[str] = set()

    def decoded(self, text: str) -> list[DecodedRun]:
        """Each new run in `text` that decodes to text: base64-shaped runs first, then hex ones."""
        found: list[DecodedRun] = []
        for match in itertools.chain(self._run_pattern.finditer(text), self._hex_pattern.finditer(text)):
            if self.attempts_left <= 0 or self.kept_left <= 0 or self.bytes_left <= 0:
                break
            run = match.group()
            if run in self._seen or run in self._skip or self._is_media(text, match.start()):
                continue
            self._seen.add(run)
            compact = "".join(run.split()) if "\n" in run else run
            result = self._attempt(compact, run)
            if result is None and "/" in compact:
                # In a URL the path before a run is part of it ("example/Z2hw..."): try what follows the last "/".
                tail = compact.rpartition("/")[2]
                if tail not in self._seen:
                    self._seen.add(tail)
                    result = self._attempt(tail, tail)
            if result is not None:
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
        decoded = self._decode(compact, kind)
        return None if decoded is None else DecodedRun(kind, decoded, run)

    @staticmethod
    def _is_media(text: str, start: int) -> bool:
        return start >= 7 and text.endswith("base64,", 0, start) and bool(
            _MEDIA_DATA_URI.search(text, max(0, start - 64), start)
        )

    def _kind(self, run: str) -> str | None:
        """How to decode `run`, or None if it does not look like encoded text at all (which costs no attempt)."""
        bare = run.rstrip("=")
        if len(bare) >= self._min_hex_chars and len(bare) % 2 == 0 and _HEX_DIGITS.fullmatch(bare):
            return "hex"
        if len(run) < self._min_base64_chars or run.startswith(_BINARY_PREFIXES):
            return None
        # Base64 of text has capitals and small letters, and rarely a "/": a
        # run without both, or full of slashes, is a word, a path or an id.
        if not (_UPPER.search(run) and _LOWER.search(run)) or run.count("/") * 16 > len(run):
            return None
        if ("+" in run or "/" in run) and ("-" in run or "_" in run):
            return None  # both alphabets at once: not base64
        return "base64"

    def _decode(self, run: str, kind: str) -> str | None:
        limit = min(self._max_run_bytes, self.bytes_left)
        bare = run.rstrip("=")
        try:
            if kind == "hex":
                cut = min(len(bare), 2 * limit)
                raw = bytes.fromhex(bare[:cut])
            else:
                cut = min(len(bare), limit // 3 * 4)
                chunk = bare[:cut]
                if len(chunk) % 4 == 1:
                    chunk = chunk[:-1]  # one character cannot end a run of base64
                chunk += "=" * (-len(chunk) % 4)
                altchars = b"-_" if ("-" in chunk or "_" in chunk) else None
                raw = base64.b64decode(chunk, altchars=altchars, validate=True)
        except (ValueError, binascii.Error):
            return None
        self.bytes_left -= len(raw)
        return _as_text(raw, truncated=cut < len(bare))


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
