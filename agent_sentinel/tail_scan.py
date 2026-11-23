"""The tail scan (DET-5): the end of the content last delivered, read together with the start of the next.

The detector reads one message at a time. An injection cut in two, its
first half at the end of one tool result and its second half at the start of
the next, reaches the model whole, since it reads the two one after the
other, but neither half matches on its own. So the session keeps the end of
the text last delivered on a channel (the "tail"), and the next content on
that channel is also read with it, as one more text.

What is read
------------
The text is what a client shows the model (reading_text): the text items of
a tool result, never its images, _meta or structuredContent (unless it has
no text), and no member names, types or MIME types.

The detector does not match a text as it arrived but in several matching
views (detector.VIEW_KINDS): normalised, with invisible characters deleted
or read as spaces, decoded (terminal escapes, percent-encoding and HTML
character references undone, "_" and a written-out \\n read as spaces), with
and without HTML tags and comments, with the punctuation inside words taken
out ("ig**no**re"), with tag characters spelled out. What
one view drops is padding an attacker can put between two halves: an HTML
comment is gone from the view without tags, but it is text in the others.
So a tail is kept for each kind of view: the last TAIL_CHARS characters of
that view of the text. The next text is read in each kind with that kind's
tail: the first HEAD_CHARS characters of its own view of the same kind. Two
halves are then seen whenever the detector would see them in one message,
in any of those views (the decoded base64 and hex runs and the text that
invisible carriers spell aside: the detector reads each of those on its
own, and reports hidden text of any length that matters by itself).

The joined text is scanned with the names of the call's parameters the
caller gave for the content (read_with_tail's parameter_names), so that an
order to put a credential file into one of them is as severe split in two
as it is whole.

How the two are put together (_readings)
----------------------------------------
A view drops the blanks at its ends, so each end keeps one space where its
text had a blank there (in that kind of view: a zero-width space is a blank
where invisible characters read as spaces, and nothing where they are
deleted). Where the boundary has a blank, the two are read as they are.
Where it has none, they are read twice: joined, as one message would read
them ("instruc" + "tions": a server that cuts its output by size cuts words
in two), and with a space between ("previous" + "instructions": two words
written apart). Short texts roll into one tail the same way; where two of
them meet with no blank, the tail holds SEAM, and is read with every seam
joined and with every seam a space. A tail of mixed seams (a word cut in
two at one, two words written apart at another) is read only in those two
ways.

The views are made the detector's way (detector.view_sources, views_of), but
only of the ends of a text, so that a long result costs little more than one
more reading: the steps that reach far (decoding, HTML tags, tag characters)
run on the whole text, and only a start and an end are normalised. Before
that, each run of characters that draw nothing in any view is shortened to
one of them (compacted), so that padding of any length is read once, in C,
by str.translate.

A finding of a joined text is reported only for a match that ends in the
new text (read_with_tail): the new text's own findings are reported for it
anyway, and a match inside the tail was reported for the content it came
from. Excerpts start with JOINED.

The tail is text at rest
------------------------
A tail is kept as text: in memory for a proxy or a library Firewall, in the
session file in hook mode. So the end it is cut from is first given to
`redact` (the firewall passes its secret guard's), with SECRET_REACH more
characters than are kept, so that a secret the cut goes through starts
outside the tail. A tail rolled from short texts is given to `redact` again,
with its seams joined, for a secret the pieces make together. The firewall
keeps no tail of content refused for a secret.

Not covered: a client that shows the model structuredContent while the
content items hold other text; a split between a notification and a result
(each channel has its own tail); content that is withheld (it is not kept,
so the piece after it is read with the text before it); results that reach
the model in another order than they were delivered in (the tail is read
when content is checked and kept when it is delivered: parallel calls whose
replies come back in the other order, or hook processes that run at once,
where the last to write keeps its tail).
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable, Sequence

from .detector import VIEW_KINDS, Finding, reads_as, scan_views, view_of, view_sources, views_of
from .session import TAIL_CHARS
from .textutil import MAX_CONTAINERS, texts_in

# How much of the start of the next text is read with the tail: this many characters of each view, far more
# than any chain rule reaches.
HEAD_CHARS = 2_048
# How many more characters (of each view) of the end of a text are given to `redact` than are kept: a secret
# the cut at the start of the tail goes through starts at least this far before the tail, unless it is longer.
SECRET_REACH = 4_096
JOINED = "[joined] "  # the start of the excerpt of a finding the tail scan made
Tail = tuple[str, ...]  # a channel's tail: the end of each kind of view, in VIEW_KINDS order
# In a tail rolled from short texts: where two of them met with no blank between them. No view holds it (a
# view deletes or spaces every control character), so it is never text that arrived.
SEAM = "\x00"
# A letter put next to an end of a piece, and how much of the piece it is read with: whether the view keeps
# a space between them tells whether the piece has a blank at that end (_blank_at). Runs of blanks are one
# character by then (compacted), and "_" or a written-out "\n" two at most.
_PROBE = "a"
_PROBE_CHARS = 16

# The members of an MCP reply that hold what a client shows the model: a tool result's (and a prompt
# message's) "content", the "contents" of resources/read, the "messages" of prompts/get.
_SHOWN_MEMBERS = ("content", "contents", "messages")
_MEDIA_TYPES = ("image", "audio")
_SHOWN_OF_A_LINK = ("name", "uri")  # a resource_link content item

# What a character is in a "shape" (see _Shapes): it draws something in some view (_DRAWN), or it draws
# nothing in any. Then it reads as a space in every view (_SPACE: a space, a diaeresis "¨"); as nothing
# where invisible characters are deleted and as a space where they are spaced (_INVISIBLE: a zero-width
# space, a tag character); or as nothing in all of them (_NOTHING: a combining mark).
_DRAWN, _SPACE, _INVISIBLE, _NOTHING = "x", " ", ".", "~"
_BLANK_RUN = re.compile("[ .~]{2,}")  # in a shape: two or more characters in a row that draw nothing


class _Shapes(dict[int, str]):
    """A str.translate table that writes each character as its shape (see above).

    A text's shape has its length, so a position in one is the same in the
    other. Filled in as characters are met, as the detector's tables are
    (detector._Table): at most one entry per code point, ever.
    """

    def __missing__(self, code: int) -> str:
        shape = _shape_of(chr(code))
        self[code] = shape
        return shape


def _shape_of(char: str) -> str:
    deleted, spaced = reads_as(char)
    if spaced.strip():
        return _DRAWN
    if any(part.isspace() for part in deleted):
        return _SPACE
    return _INVISIBLE if spaced else _NOTHING


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

def compacted(text: str) -> str:
    """`text` with each run of characters that draw nothing in any view written as one of them.

    The one kept reads as the run does in every view: a character that
    reads as a space, if the run has one, so that the words on each side
    stay apart; else an invisible character, so that a word the run splits
    reads whole where those are deleted and in two where they are spaced;
    else (combining marks only) the first.
    """
    shape = text.translate(_SHAPES)
    pieces: list[str] = []
    at = 0
    for run in _BLANK_RUN.finditer(shape):
        start, end = run.span()
        keep = shape.find(_SPACE, start, end)
        if keep < 0:
            keep = shape.find(_INVISIBLE, start, end)
        pieces += [text[at:start], text[keep if keep >= 0 else start]]
        at = end
    pieces.append(text[at:])
    return "".join(pieces)


def start_of(text: str, kind: str = VIEW_KINDS[0]) -> str:
    """The first HEAD_CHARS characters of the view of kind `kind` of `text`: what is read after a tail.

    It starts with a space when the text starts with a blank in that kind of view.
    """
    return _Ends(text).start(kind)


def end_of(text: str, kind: str = VIEW_KINDS[0]) -> str:
    """The last TAIL_CHARS characters of the view of kind `kind` of `text`: what is kept as its tail.

    It ends with a space when the text ends with a blank in that kind of
    view (and starts with one when the whole text is kept and starts with one).
    """
    return _Ends(text).end(kind)[0]


_Views = dict[str, tuple[str, str]]  # kind -> (the compacted piece of its source, the view of that piece)


class _Ends:
    """The start and the end of each kind of view of one text, each made when it is first wanted.

    Kinds read from the same source (detector.view_sources) share the pieces
    of it that are normalised, and the start and the end share a view that
    took the whole source (a text that is mostly padding).
    """

    def __init__(self, text: str, redact: Callable[[str], str] | None = None) -> None:
        self._sources = view_sources(text)
        self._redact = redact
        self._kinds_of: dict[int, list[str]] = {}
        for kind in VIEW_KINDS:
            self._kinds_of.setdefault(id(self._sources[kind]), []).append(kind)
        self._grown: dict[tuple[int, bool], _Views] = {}
        self._whole: dict[int, _Views] = {}

    def start(self, kind: str) -> str:
        """The start of the view of this kind, with a space first if the text starts with a blank in it."""
        piece, view = self._views(kind, from_end=False)[kind]
        if not view:
            return ""
        return (" " if _blank_at(piece, kind, at_end=False) else "") + view[:HEAD_CHARS]

    def end(self, kind: str) -> tuple[str, bool]:
        """(The end of the view of this kind, with a space for a blank at either end of it; whether it is all of it).

        A space at the start only when it is all of it: the start of a cut end
        is no boundary.
        """
        piece, view = self._views(kind, from_end=True)[kind]
        if not view:
            return "", True
        whole = len(view) < TAIL_CHARS  # shorter than wanted: the piece is the whole source (_grown)
        lead = " " if whole and _blank_at(piece, kind, at_end=False) else ""
        return lead + view[-TAIL_CHARS:] + (" " if _blank_at(piece, kind, at_end=True) else ""), whole

    def _views(self, kind: str, from_end: bool) -> _Views:
        source = self._sources[kind]
        key = (id(source), from_end)
        if key not in self._grown:
            kinds = self._kinds_of[id(source)]
            wanted = TAIL_CHARS + (SECRET_REACH if self._redact else 0) if from_end else HEAD_CHARS
            views = _grown(source, kinds, wanted, from_end, self._whole.setdefault(id(source), {}))
            if from_end and self._redact is not None:
                views = _redacted(views, self._redact)
            self._grown[key] = views
        return self._grown[key]


def _grown(source: str, kinds: Sequence[str], wanted: int, from_end: bool, whole: _Views) -> _Views:
    """For each kind: a start (or end) of `source`, compacted, whose view has `wanted` characters; or all of it.

    The piece grows four times at each step, and only what it gains is
    compacted, so padding of any length is read once, and never character by
    character in Python. `whole` holds the views of the whole source, made
    for the other end: they are used, and those made here are added.
    """
    found = {kind: whole[kind] for kind in kinds if kind in whole}
    size, done, piece = wanted * 4, 0, ""
    while len(found) < len(kinds):
        size = min(size, len(source))
        if from_end:
            piece = compacted(source[len(source) - size : len(source) - done]) + piece
        else:
            piece += compacted(source[done:size])
        done = size
        everything = done == len(source)
        for kind, view in views_of(piece, [kind for kind in kinds if kind not in found]).items():
            if everything or len(view) >= wanted:
                found[kind] = (piece, view)
                if everything:
                    whole[kind] = (piece, view)
        size *= 4
    return found


def _redacted(views: _Views, redact: Callable[[str], str]) -> _Views:
    """The views of each piece once `redact` has replaced its secrets (made again only where it replaced any)."""
    pieces: dict[int, tuple[str, list[str]]] = {}
    for kind, (piece, _) in views.items():
        pieces.setdefault(id(piece), (piece, []))[1].append(kind)
    redacted = dict(views)
    for piece, kinds in pieces.values():
        kept = redact(piece)
        if kept != piece:
            redacted.update({kind: (kept, view) for kind, view in views_of(kept, kinds).items()})
    return redacted


def _blank_at(piece: str, kind: str, at_end: bool) -> bool:
    """Whether `piece` (compacted) has a blank at its start (or end) in the view of kind `kind`.

    A blank is what that view reads as a space and drops at its ends: a
    space, a zero-width space where invisible characters are spaced, "_"
    where it is read as a space ... Told by reading the piece's edge next to
    a letter: the view keeps a space between them, or not.
    """
    if at_end:
        return view_of(kind, piece[-_PROBE_CHARS:] + _PROBE).endswith(" " + _PROBE)
    return view_of(kind, _PROBE + piece[:_PROBE_CHARS]).startswith(_PROBE + " ")


# ---- the scan -------------------------------------------------------------------------------

def read_with_tail(
    tail: Sequence[str], text: str, known: list[Finding], redact: Callable[[str], str] | None = None,
    parameter_names: Iterable[str] = (),
) -> tuple[list[Finding], Tail]:
    """The tail scan of `text`, whose own findings are `known`, after the kept `tail` (a Tail, or () for none).

    Returns the findings of matches that start in the tail and end in the
    text (_joined_findings), in any kind of view and either reading of the
    boundary (_readings), and the tail to keep once the text is delivered
    (_next_tail). `redact` replaces the secrets in the end that the new tail
    is cut from (see the module docstring). `parameter_names` are the names
    the text's own scan was given (detector.scan_views): the joined text is
    read with them too.
    """
    names = _names(parameter_names)
    ends = _Ends(text, redact)
    before = [entry if isinstance(entry, str) else "" for entry in tuple(tail)[: len(VIEW_KINDS)]]
    before += [""] * (len(VIEW_KINDS) - len(before))
    found: list[Finding] = []
    read: set[tuple[str, str]] = set()
    after: list[str] = []
    for kind, kept in zip(VIEW_KINDS, before):
        if kept.strip():
            for pair in _readings(kept, ends.start(kind)):
                if pair not in read:  # most texts read the same in several kinds of view
                    read.add(pair)
                    found += _joined_findings(*pair, known, names)
        after.append(_next_tail(kept, *ends.end(kind), redact))
    return found, tuple(after)


def _readings(tail: str, head: str) -> list[tuple[str, str]]:
    """The ways a kept tail and the start of the new text (_Ends.start) are read together: (left, right) pairs.

    Where the boundary has a blank (a space at the end of the tail or the
    start of the head), as they are. Else joined (a word cut in two) and
    with a space between (two words written apart). The seams of a rolled
    tail are read all joined and all spaced.
    """
    if not head.strip():
        return []
    lefts = dict.fromkeys((tail.replace(SEAM, ""), tail.replace(SEAM, " ")))
    gaps = ("",) if tail.endswith(" ") or head.startswith(" ") else ("", " ")
    return [(left, gap + head) for left in lefts for gap in gaps]


def _next_tail(tail: str, end: str, whole: bool, redact: Callable[[str], str] | None = None) -> str:
    """The tail of one kind to keep once a text is delivered after `tail`; `end`, `whole`: _Ends.end of the text.

    A text with nothing to read keeps the tail as it was. A short text (all
    of it is in `end`) rolls into the tail: with SEAM between them when the
    boundary has no blank. A secret that `redact` finds once the seams are
    joined (the pieces make it together) is replaced; that tail is then read
    joined only.
    """
    if not end.strip():
        return tail
    if not tail or not whole:
        return end[-TAIL_CHARS:]
    rolled = tail + ("" if tail.endswith(" ") or end.startswith(" ") else SEAM) + end
    if redact is not None and SEAM in rolled:
        joined = rolled.replace(SEAM, "")
        kept = redact(joined)
        if kept != joined:
            rolled = kept
    return rolled[-TAIL_CHARS:]


def _names(parameter_names: Iterable[str]) -> tuple[str, ...]:
    """The parameter names as a tuple, read once: the joined texts are scanned several times with them."""
    if isinstance(parameter_names, (str, bytes)):
        raise TypeError("parameter_names must be a collection of names, not one text")
    return tuple(name for name in parameter_names if isinstance(name, str))


def _scan(text: str, names: tuple[str, ...]) -> list[Finding]:
    """The detector's findings in one text of view ends, read as a result with these parameter names."""
    return scan_views([text], parameter_names=names)


def _joined_findings(tail: str, head: str, known: list[Finding], names: tuple[str, ...] = ()) -> list[Finding]:
    """The findings of a match that starts in `tail` and ends in `head`, read as one text: `tail + head`.

    (A pair from _readings: `head` starts with the space between them, if any.)
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
    joined = [finding for finding in _scan(tail + head, names) if finding.rule not in have]
    if not joined:
        return []
    alone = {finding.rule for finding in _scan(tail, names)}
    found = [finding for finding in joined if finding.rule not in alone]
    for rule in sorted({finding.rule for finding in joined} & alone):
        rest = _after_own_match(tail, rule, names)
        found += [finding for finding in _scan(rest + head, names) if finding.rule == rule]
    return [Finding(finding.rule, finding.severity, JOINED + finding.excerpt) for finding in found]


def _after_own_match(tail: str, rule: str, names: tuple[str, ...] = ()) -> str:
    """The longest end of `tail` that `rule` does not match on its own: what follows the start of its last match.

    Found by halving: about ten scans of at most TAIL_CHARS characters.
    """
    matched, clean = 0, len(tail)  # tail[matched:] matches the rule; tail[clean:] does not
    while clean - matched > 1:
        middle = (matched + clean) // 2
        if any(finding.rule == rule for finding in _scan(tail[middle:], names)):
            matched = middle
        else:
            clean = middle
    return tail[clean:]
