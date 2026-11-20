"""The tail scan (DET-5): the end of the content last delivered, read together with the start of the next.

The detector reads one message at a time. An injection cut in two, its
first half at the end of one tool result and its second half at the start of
the next, reaches the model whole, since it reads the two one after the
other, but neither half matches on its own. So the session keeps the end of
the text last delivered on a channel (the "tail", at most session.TAIL_CHARS
characters), and the next content on that channel is also read as
tail + " " + the start of its text, as one more text.

Neither end can be pushed away with something the model does not read:

  * The text is what a client shows the model (reading_text): the text items
    of a tool result, never its images, _meta or structuredContent (unless it
    has no text), and no member names, types or MIME types.
  * Characters that draw nothing (spaces, invisible and control characters,
    combining marks) count as one where they come in a run: the detector
    reads such a run as one space too. The tail is the last TAIL_CHARS
    characters of the text so compacted; the start read with it holds
    HEAD_DRAWN_CHARS characters that draw something.

A finding of the joined text is reported only for a match that ends in the
new text (read_with_tail): the new text's own findings are reported for it
anyway, and a match inside the tail was reported for the content it came
from.

Not covered: a client that shows the model structuredContent while the
content items hold other text; a split between a notification and a result
(each channel has its own tail); content that is withheld (it is not kept,
so the piece after it is read with the text before it).
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from .detector import Finding, scan
from .session import TAIL_CHARS
from .textutil import MAX_CONTAINERS, texts_in

# How much of the start of the next text is read with the tail: this many characters that draw
# something (far more than any chain rule reaches), with their runs of blanks counted as one.
HEAD_DRAWN_CHARS = 2_048
JOINED = "[joined] "  # the start of the excerpt of a finding the tail scan made

# The members of an MCP reply that hold what a client shows the model: a tool result's (and a prompt
# message's) "content", the "contents" of resources/read, the "messages" of prompts/get.
_SHOWN_MEMBERS = ("content", "contents", "messages")
_MEDIA_TYPES = ("image", "audio")
_SHOWN_OF_A_LINK = ("name", "uri")  # a resource_link content item

# What a character is in a "shape" (see _Shapes): one that draws something, or one that draws nothing.
_DRAWN, _BLANK = "x", " "
_BLANK_CATEGORIES = frozenset({"Cc", "Cf", "Mn", "Me"})  # control and format characters, combining marks
# Characters that draw nothing although Unicode files them elsewhere: the Hangul fillers, the braille
# blank, and code points reserved as ignorable (those after the tag characters, in plane 14, among them).
_BLANK_ELSEWHERE = frozenset([0x115F, 0x1160, 0x2065, 0x2800, 0x3164, 0xFFA0, *range(0xFFF0, 0xFFF9),
                              *range(0xE0080, 0xE1000)])
_TAG_CHARACTERS = range(0xE0000, 0xE0080)
_BLANK_RUN = re.compile(" {2,}")  # in a shape: two or more characters in a row that draw nothing
_SPACE = re.compile(r"\s")


def _draws_nothing(char: str) -> bool:
    """Whether a character shows nothing of its own: a space, an invisible or control character, a combining mark.

    Tag characters are the exception: a model reads the text written in them.
    """
    code = ord(char)
    if code in _TAG_CHARACTERS:
        return False
    return char.isspace() or code in _BLANK_ELSEWHERE or unicodedata.category(char) in _BLANK_CATEGORIES


class _Shapes(dict[int, str]):
    """A str.translate table that writes each character as _BLANK if it draws nothing, else as _DRAWN.

    A text's shape has its length, so a position in one is the same in the
    other. Filled in as characters are met, as the detector's tables are
    (detector._Table): at most one entry per code point, ever.
    """

    def __missing__(self, code: int) -> str:
        shape = _BLANK if _draws_nothing(chr(code)) else _DRAWN
        self[code] = shape
        return shape


_SHAPES = _Shapes()


# ---- what the model reads -------------------------------------------------------------------

def reading_text(content: Any, *, reply: bool) -> str:
    """The text of `content` as a client shows it to the model, in order: what the tail scan reads.

    reply: `content` is a reply (a tool result, resources/read, prompts/get,
    an error), not a message the server sends on its own (pass its params).

      * a content item: the text of a text item or of an embedded resource;
        nothing of an image or audio item; the name and uri of a resource link;
      * a resource's contents: its text, never its blob;
      * in a reply, an object with "content", "contents" or "messages": only
        those (not its structuredContent, isError or description). If the
        whole reply has no text, its structuredContent instead;
      * anything else (an error, a notification, the output of a Claude Code
        tool, a library result): every string that is not a key, except
        under "_meta".
    """
    if isinstance(content, str):
        return content
    texts = _shown_texts(content, reply)
    if reply and isinstance(content, dict) and not "".join(texts).strip():
        texts = _shown_texts(content.get("structuredContent"), reply)
    return " ".join(texts)


def _shown_texts(value: Any, reply: bool) -> list[str]:
    """The strings of `value` that reading_text reads, in document order. Iterative, and each container once."""
    texts: list[str] = []
    waiting: list[Any] = [value]
    entered: set[int] = set()
    while waiting:
        item = waiting.pop()
        if isinstance(item, str):
            texts.append(item)
        elif isinstance(item, (dict, list, tuple)):
            if id(item) in entered or len(entered) >= MAX_CONTAINERS:
                continue  # a container that holds itself; past the bound text_views already refused the content
            entered.add(id(item))
            waiting.extend(reversed(_shown_members(item, reply) if isinstance(item, dict) else item))
        else:
            texts.extend(texts_in(item, keys=False))  # bytes, a dataclass, a set ...
    return texts


def _shown_members(item: dict[Any, Any], reply: bool) -> list[Any]:
    """What a client shows the model of one object: see reading_text."""
    kind = item.get("type")
    if isinstance(kind, str):
        if kind in _MEDIA_TYPES:
            return []
        if kind == "text" and isinstance(item.get("text"), str):
            return [item["text"]]
        if kind == "resource" and isinstance(item.get("resource"), dict):
            return [item["resource"].get("text")]
        if kind == "resource_link":
            return [item.get(name) for name in _SHOWN_OF_A_LINK]
    if "uri" in item and ("text" in item or "blob" in item):
        return [item.get("text")]
    if reply:
        shown = [item[name] for name in _SHOWN_MEMBERS if isinstance(item.get(name), (dict, list))]
        if shown:
            return shown
    return [value for name, value in item.items() if name != "_meta"]


# ---- the ends of a text ---------------------------------------------------------------------

def start_of(text: str, drawn: int = HEAD_DRAWN_CHARS) -> str:
    """The start of `text` that holds `drawn` characters that draw something, compacted (see _compacted)."""
    return _first(*_piece(text, drawn, from_end=False), drawn)


def end_of(text: str, drawn: int = TAIL_CHARS) -> str:
    """The end of `text` that holds `drawn` characters that draw something, compacted (see _compacted)."""
    return _last(*_piece(text, drawn, from_end=True), drawn)


def _ends(text: str) -> tuple[str, str]:
    """start_of(text) and end_of(text); a text read whole for its start (mostly blanks) is not read again."""
    piece, shape = _piece(text, HEAD_DRAWN_CHARS, from_end=False)
    start = _first(piece, shape, HEAD_DRAWN_CHARS)
    if piece is not text:
        piece, shape = _piece(text, TAIL_CHARS, from_end=True)
    return start, _last(piece, shape, TAIL_CHARS)


def _first(piece: str, shape: str, drawn: int) -> str:
    """The start of `piece` up to its `drawn`th character that draws something, compacted."""
    end = 0
    for _ in range(drawn):
        found = shape.find(_DRAWN, end)
        if found < 0:
            break
        end = found + 1
    return _compacted(piece[:end], shape[:end])


def _last(piece: str, shape: str, drawn: int) -> str:
    """The end of `piece` from its `drawn`th character from the end that draws something, compacted."""
    start = len(shape)
    for _ in range(drawn):
        found = shape.rfind(_DRAWN, 0, start)
        if found < 0:
            break
        start = found
    return _compacted(piece[start:], shape[start:])


def _piece(text: str, drawn: int, from_end: bool) -> tuple[str, str]:
    """A start (or end) of `text` that holds `drawn` characters that draw something, or all of it; with its shape.

    It grows four times at each step, so a text padded with blanks is read
    once or so, never character by character in Python.
    """
    size = drawn * 4
    while True:
        if size >= len(text):
            return text, text.translate(_SHAPES)
        piece = text[-size:] if from_end else text[:size]
        shape = piece.translate(_SHAPES)
        if len(shape) - shape.count(_BLANK) >= drawn:
            return piece, shape
        size *= 4


def _compacted(text: str, shape: str) -> str:
    """`text` with each run of characters that draw nothing written as one character.

    That is the run's first space if it has one, so that the words on each
    side stay apart, or else its first character, so that a word an invisible
    character splits reads as the detector reads it (whole, and in two).
    """
    pieces: list[str] = []
    at = 0
    for run in _BLANK_RUN.finditer(shape):
        start, end = run.span()
        space = _SPACE.search(text, start, end)
        pieces += [text[at:start], space.group() if space else text[start]]
        at = end
    pieces.append(text[at:])
    return "".join(pieces)


# ---- the scan -------------------------------------------------------------------------------

def read_with_tail(tail: str, text: str, known: list[Finding]) -> tuple[list[Finding], str]:
    """The tail scan of `text`, whose own findings are `known`, after the kept `tail`.

    Returns the findings of matches that start in the tail and end in the
    text (_joined_findings), and the tail to keep once the text is delivered
    (_next_tail).
    """
    if not tail.strip():
        return [], end_of(text)[-TAIL_CHARS:]
    start, end = _ends(text)
    return _joined_findings(tail, start, known), _next_tail(tail, end)


def _next_tail(tail: str, end: str) -> str:
    """The tail to keep once a text that ends with `end` (end_of) is delivered after `tail`: at most TAIL_CHARS."""
    if tail and len(end) < TAIL_CHARS:
        end = end_of(tail + " " + end)  # short texts roll into one tail
    return end[-TAIL_CHARS:]


def _joined_findings(tail: str, head: str, known: list[Finding]) -> list[Finding]:
    """The findings of a match that starts in `tail` and ends in `head` (start_of the new text), read as one text.

    `known` are the findings of the new text itself: a rule it matches is
    reported for it already. For a rule the tail matches on its own
    (reported with the content it came from), the joined text is read again
    from just after the tail's own match (_after_own_match), so that only
    another match, one that ends in the new text, counts. Excerpts start
    with JOINED.
    """
    if not head.strip():
        return []
    have = {finding.rule for finding in known}
    joined = [finding for finding in scan(tail + " " + head) if finding.rule not in have]
    if not joined:
        return []
    alone = {finding.rule for finding in scan(tail)}
    found = [finding for finding in joined if finding.rule not in alone]
    for rule in sorted({finding.rule for finding in joined} & alone):
        rest = _after_own_match(tail, rule)
        found += [finding for finding in scan(rest + " " + head) if finding.rule == rule]
    return [Finding(finding.rule, finding.severity, JOINED + finding.excerpt) for finding in found]


def _after_own_match(tail: str, rule: str) -> str:
    """The longest end of `tail` that `rule` does not match on its own: what follows the start of its last match.

    Found by halving: about ten scans of at most TAIL_CHARS characters.
    """
    matched, clean = 0, len(tail)  # tail[matched:] matches the rule; tail[clean:] does not
    while clean - matched > 1:
        middle = (matched + clean) // 2
        if any(finding.rule == rule for finding in scan(tail[middle:])):
            matched = middle
        else:
            clean = middle
    return tail[clean:]
