"""Heuristic detection of prompt injection in text an agent reads.

These are pattern rules, not a trained classifier. They catch common,
unsophisticated injections. They miss paraphrased or translated text and
any encoding not listed below, and they can flag harmless text. Treat a
clean scan as "nothing obvious found", not as "safe".

What the rules read
-------------------
One sentence can be written in many ways that read the same, so the rules do
not match the text as it arrived. `_normalize` builds a *matching view*:

  * compatibility forms such as full-width letters are folded to plain ones,
    and accents and other combining marks are dropped;
  * invisible characters are removed, so they cannot split a trigger word;
  * Cyrillic and Greek letters that look like Latin letters become Latin;
  * typographic apostrophes become "'";
  * every run of whitespace becomes one space.

None of that removes anything a reader can see. Undoing an encoding does:
it takes characters away, and taking the wrong ones away would hide a phrase
instead of revealing it ("\\never tell the user" must not lose its "n"). So
those steps go into a second, *decoded* view, and a rule may match in either:

  * percent-encoding and HTML character references are decoded, HTML tags
    and terminal escape sequences are removed (`_decode`);
  * "_" and the written-out escapes \\n, \\t and \\r become a space
    (`_unglue`), because snake_case, _markdown emphasis_ and JSON kept inside
    a string otherwise glue a trigger word to its neighbour.

The chain rules are matched against both views in lowercase; the decoded view
is skipped when it is the same as the plain one. `scan_views` merges the
findings for several texts that describe one value, such as the views
`textutil.text_views` makes of a tool result.

How a rule works
----------------
Most rules are a *chain* of steps: a first pattern, then further patterns that
must each start within a few characters of the previous one. For example
"ignore" ... "previous" ... "instructions". Chains are matched by hand
(see `_match_chain`) instead of with one big regular expression, because the
scanned text is attacker-controlled and a single regular expression with
several ".{0,40}" gaps can be driven into very slow backtracking.

Staying fast on hostile input
-----------------------------
Every pattern reads a text in one pass: its quantifiers are bounded, or cannot
overlap, or run over single spaces only. Normalization works in
short slices (see `_decompose`) and cannot make a text more than a few times
longer. Each rule runs its patterns over a view once; after that the chain matcher
looks matches up in an index (see `_Occurrences`) and rarely has to search
again. It counts its work and gives up at `_SCAN_BUDGET`: the text is then
reported as a high `unscannable_content` finding, never passed as clean.

Adding a rule
-------------
Add a `_rule(...)` entry to `_RULES` and a test to tests/test_detector.py,
including a harmless sentence that must NOT match and a repetitive input in
HostileInputIsScannedQuickly. Keep "high" rules narrow: by default high
findings block content. Write patterns for the views they are matched in:
lowercase, single spaces, plain apostrophes. A rule's first pattern is
written without a leading "\\b" (see `_first_matches`).
"""

from __future__ import annotations

import bisect
import html
import re
import unicodedata
import urllib.parse
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from .textutil import FIELD_BREAK

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    excerpt: str


class _Unscannable(Exception):
    """The text cannot be checked. `scan` reports this as a high finding, so the text is not passed as clean."""


# --------------------------------------------------------------------------
# Normalization: from the text as it arrived to the matching view
# --------------------------------------------------------------------------

# Format characters (category Cf) that are drawn: Arabic, Syriac and Kaithi
# signs written before a number or a verse. Removing them would damage
# ordinary Arabic text and report it as hidden text.
_VISIBLE_FORMAT = frozenset([*range(0x0600, 0x0606), 0x06DD, 0x070F, 0x0890, 0x0891, 0x08E2, 0x110BD, 0x110CD])
# Characters that draw nothing although Unicode files them under letters,
# marks or unassigned: the grapheme joiner, Hangul and Khmer fillers,
# Mongolian separators, variation selectors, and the reserved "ignorable"
# code points, which include the whole block of tag characters.
_INVISIBLE_ELSEWHERE = frozenset([
    0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, *range(0x180B, 0x1810), 0x2065, 0x3164, 0xFFA0,
    *range(0xFE00, 0xFE10), *range(0xFFF0, 0xFFF9), *range(0xE0000, 0xE1000),
])
# Invisible characters with everyday uses: the soft hyphen, the joiners and
# direction marks of emoji, Arabic, Urdu and Persian, the byte order mark and
# the emoji variation selectors. Control characters count too: mojibake and
# terminal output are full of them. On their own these are a low finding.
_EVERYDAY_INVISIBLE = frozenset([0x00AD, 0x061C, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF, *range(0xFE00, 0xFE10)])

# Letters of other alphabets that are drawn like a Latin letter, by Unicode
# name. "{}" stands for both SMALL and CAPITAL.
_LOOKALIKE_NAMES = {
    "CYRILLIC {} LETTER A": "a",
    "CYRILLIC {} LETTER VE": "b",
    "CYRILLIC {} LETTER ES": "c",
    "CYRILLIC {} LETTER IE": "e",
    "CYRILLIC {} LETTER EN": "h",
    "CYRILLIC {} LETTER BYELORUSSIAN-UKRAINIAN I": "i",
    "CYRILLIC {} LETTER JE": "j",
    "CYRILLIC {} LETTER KA": "k",
    "CYRILLIC {} LETTER EM": "m",
    "CYRILLIC {} LETTER O": "o",
    "CYRILLIC {} LETTER ER": "p",
    "CYRILLIC {} LETTER DZE": "s",
    "CYRILLIC {} LETTER TE": "t",
    "CYRILLIC {} LETTER HA": "x",
    "CYRILLIC {} LETTER U": "y",
    "GREEK {} LETTER ALPHA": "a",
    "GREEK {} LETTER EPSILON": "e",
    "GREEK {} LETTER IOTA": "i",
    "GREEK {} LETTER KAPPA": "k",
    "GREEK {} LETTER OMICRON": "o",
    "GREEK {} LETTER RHO": "p",
    "GREEK {} LETTER TAU": "t",
    "GREEK {} LETTER CHI": "x",
    "GREEK SMALL LETTER NU": "v",
    "GREEK SMALL LETTER UPSILON": "u",
    "GREEK CAPITAL LETTER BETA": "b",
    "GREEK CAPITAL LETTER ETA": "h",
    "GREEK CAPITAL LETTER MU": "m",
    "GREEK CAPITAL LETTER NU": "n",
    "GREEK CAPITAL LETTER UPSILON": "y",
    "GREEK CAPITAL LETTER ZETA": "z",
    "LATIN SMALL LETTER DOTLESS I": "i",
}
# What a visible character becomes in the matching view, if not itself: the
# look-alikes, and the typographic apostrophes U+2018, U+2019 and U+02BC.
_FOLDED: dict[int, str] = {
    ord(unicodedata.lookup(name.format(case))): latin
    for name, latin in _LOOKALIKE_NAMES.items()
    for case in ("SMALL", "CAPITAL")
}
_FOLDED.update({0x2018: "'", 0x2019: "'", 0x02BC: "'"})

# The acute accent, used as an apostrophe, has to be folded before
# decomposition, which would turn it into a space and a combining mark.
_ACUTE_ACCENT = "\N{ACUTE ACCENT}"
# Characters normalized in one call, and how many times longer the result may
# be. See `_decompose`.
_SLICE = 256
_MAX_EXPANSION = 3


class _Table(dict[int, "int | str | None"]):
    """A `str.translate` table that is filled in as characters are met.

    Classifying all of Unicode up front takes about a second, and a text uses
    only a few hundred different characters. So a character is classified the
    first time any table meets it (see `_classify`), once per process; every
    later use is a plain dictionary look-up inside `str.translate`.
    """

    def __missing__(self, code: int) -> int | str | None:
        _classify(code)
        return self[code]


_WITHOUT_INVISIBLE = _Table()  # deletes every invisible character
_WITHOUT_HIDDEN_TEXT = _Table()  # deletes the invisible characters that have no everyday use
# Makes the matching view of single characters: deletes invisible characters
# and combining marks, folds look-alikes and apostrophes.
_FOLD = _Table()
# As _FOLD, but control characters and the fillers that draw a blank become a space instead of nothing.
_FOLD_SPACED = _Table()
_BLANK_FILLERS = frozenset([0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x180E])


def _classify(code: int) -> None:
    """Give the character `code` its entry in each of the three tables above."""
    ch = chr(code)
    category = unicodedata.category(ch)
    # Whitespace is never invisible in this sense: it separates words.
    invisible = (
        code in _INVISIBLE_ELSEWHERE
        or (category == "Cf" and code not in _VISIBLE_FORMAT)
        or (category == "Cc" and not ch.isspace())
    )
    everyday = category == "Cc" or code in _EVERYDAY_INVISIBLE
    _WITHOUT_INVISIBLE[code] = None if invisible else code
    _WITHOUT_HIDDEN_TEXT[code] = None if invisible and not everyday else code
    _FOLD[code] = None if invisible or category in ("Mn", "Me") else _FOLDED.get(code, code)
    spaced = code in _BLANK_FILLERS or (category == "Cc" and invisible)
    _FOLD_SPACED[code] = " " if spaced else _FOLD[code]


def _decompose(text: str) -> str:
    """Split every character into its plain parts (Unicode form NFKD): "ｉ" to "i", "ï" to "i" and a mark.

    Done in slices because on one long string CPython's normalizer is
    quadratic: for a run of combining marks in the wrong order and, on
    Windows, for characters that expand. Slicing does not change what the
    rules see. Each character decomposes on its own, and what can differ at a
    slice edge is the order of combining marks, which `_FOLD` then deletes.
    """
    pieces = []
    for start in range(0, len(text), _SLICE):
        piece = text[start : start + _SLICE]
        decomposed = unicodedata.normalize("NFKD", piece)
        if len(decomposed) > _MAX_EXPANSION * len(piece):
            decomposed = unicodedata.normalize("NFKD", _without_expanding(piece))
        pieces.append(decomposed)
    return "".join(pieces)


def _without_expanding(piece: str) -> str:
    """Replace by a space each character that decomposes into more than `_MAX_EXPANSION` characters.

    A few do: U+FDFA becomes 18. Only a slice that is full of them gets here,
    which no real text is, and none of them is part of a Latin word. Without
    this a hostile text could make its matching view many times longer than itself.
    """
    expanding = [ch for ch in set(piece) if len(unicodedata.normalize("NFKD", ch)) > _MAX_EXPANSION]
    return piece.translate({ord(ch): unicodedata.normalize("NFKD", ch)[:_MAX_EXPANSION] for ch in expanding})


def _normalize(text: str, table: "_Table | None" = None) -> str:
    """Build the matching view of `text`. Nothing a reader can see is removed, only folded to its plain form."""
    if not text.isascii():  # plain ASCII has nothing to decompose
        text = _decompose(text.replace(_ACUTE_ACCENT, "'"))
    return " ".join(text.translate(_FOLD if table is None else table).split())


# --------------------------------------------------------------------------
# The decoded view
# --------------------------------------------------------------------------

# Terminal escape sequences: CSI (colors, cursor moves) and OSC (window title,
# hyperlinks). They are removed whole, because removing only the ESC character
# leaves "[31m" glued to the next word.
_ANSI_RE = re.compile(r"\x1b\[[0-?]{0,64}[ -/]{0,8}[@-~]|\x1b\][^\x07\x1b]{0,512}(?:\x07|\x1b\\)")
# html.unescape() reads the digits of "&#...;" with int(), which is slow, or
# raises, once there are thousands of them. No real reference has more than seven.
_ENDLESS_REFERENCE_RE = re.compile(r"&#[0-9]{8}")
_LEADING_ZEROS_RE = re.compile(r"&#0+(?=[0-9])")
# A tag or a comment. Removing it joins the text on both sides, as a browser
# does: "Ig<b></b>nore" reads "Ignore". No length bound is needed: the class
# excludes "<", so no character is read by two attempts.
_TAG_RE = re.compile(r"<[^<>]*>")
# What glues a word to its neighbour without being part of either: the
# underscore, and a newline, tab or return written out as in a JSON string.
_GLUE = ("_", "\\n", "\\t", "\\r")


def _decode(text: str) -> str:
    """Undo, once, the encodings a terminal, a web page or a URL puts on text, which a model reads through.

    Terminal escape sequences, percent-encoding, HTML character references
    and JSON-escaped slashes only: base64, hex and the like are not decoded.
    Each step is a single pass in this order and none is repeated, so text
    that needs the same step twice is not fully decoded. HTML tags are removed
    by the caller, as a separate view.
    """
    if "\x1b" in text:
        text = _ANSI_RE.sub("", text)
    if "\\/" in text:
        text = text.replace("\\/", "/")  # "http:\/\/host", as JSON kept inside a string writes it
    if "%" in text:
        # Same result as urllib.parse.unquote(), which is slow when ASCII and
        # other characters alternate; on bytes the cost depends only on the "%" signs.
        text = urllib.parse.unquote_to_bytes(text.encode("utf-8", "replace")).decode("utf-8", "replace")
    if "&" in text:
        try:
            text = html.unescape(_ENDLESS_REFERENCE_RE.sub(" ", _LEADING_ZEROS_RE.sub("&#", text)))
        except ValueError as error:  # no input is known to get here; if one does, do not call the text clean
            raise _Unscannable("HTML character references could not be decoded") from error
    return text


def _unglue(view: str) -> str:
    """Put a space where a matching view has an underscore or a written-out \\n, \\t or \\r."""
    unglued = view
    for glue in _GLUE:
        unglued = unglued.replace(glue, " ")
    return view if unglued == view else " ".join(unglued.split())


def _matching_views(text: str) -> Iterator[str]:
    """The views of `text` the chain rules are matched in: plain, then decoded if that is different."""
    plain = _normalize(text)
    yield plain
    seen = {plain}
    decoded = _decode(text)
    candidates = [_unglue(plain if decoded == text else _normalize(decoded))]
    if "<" in decoded:
        candidates.append(_unglue(_normalize(_TAG_RE.sub("", decoded))))
    if len(text.translate(_WITHOUT_INVISIBLE)) != len(text):
        candidates.append(_normalize(text, _FOLD_SPACED))
        candidates.append(_unglue(_normalize(decoded, _FOLD_SPACED)))
    for view in candidates:
        if view not in seen:
            seen.add(view)
            yield view


# --------------------------------------------------------------------------
# Chain rules
# --------------------------------------------------------------------------
# The patterns below are matched against lowercased matching views, so they
# are written for them: lowercase, single spaces, "'" apostrophes.

@dataclass(frozen=True)
class _Step:
    pattern: re.Pattern[str]
    max_gap: int  # how many characters after the previous step this one may start


@dataclass(frozen=True)
class _Rule:
    name: str
    severity: str
    steps: tuple[_Step, ...]
    one_sentence: bool  # every step must start in the sentence that holds the first one
    unless_after: re.Pattern[str] | None  # the rule does not apply when this matches right before the first step


def _rule(
    name: str, severity: str, first: str, *then: tuple[int, str], one_sentence: bool = False, unless_after: str = ""
) -> _Rule:
    """Build a rule: a first pattern, then (max_gap, pattern) pairs.

    The first pattern has no leading "\\b": `_first_matches` already refuses a
    match that starts inside a word. Later patterns need their own.
    """
    steps = [_Step(re.compile(first), 0)]
    steps += [_Step(re.compile(pattern), gap) for gap, pattern in then]
    return _Rule(name, severity, tuple(steps), one_sentence, re.compile(unless_after) if unless_after else None)


_OVERRIDE = r"(ignore|disregard|forget|override)\b"
_WHAT_CAME_BEFORE = r"\b(previous|prior|above|earlier|all|your|system)\b"
_SEND = r"(send|forward|post|upload|email|exfiltrate|transmit|leak)\b"
# "Never email your password to ..." is advice, not an order to leak it.
_NEGATION = r"(\bnever|\bnot|\bcannot|n't|\bdont) $"
_NEGATION_REACH = 10  # characters before the verb that are looked at; longer than any negation above
_SECRET = (
    r"(\b(api[_ -]?keys?|passwords?|credentials?|secrets?|(access |auth |session )?tokens?|ssh keys?|private keys?"
    r"|(chat|conversation)[ _./-]?history)\b|\.env\b)"
)
# An email address is recognized from its "@domain.tld" part. Matching the
# name before the "@" as well ("[\w.+-]+@") is slow on long runs of letters.
# 63 characters is the longest label the DNS allows.
_DESTINATION = r"(https?://|\bwww\.|(?<=[\w.+-])@[\w-]{1,63}\.\w)"

_RULES: tuple[_Rule, ...] = (
    _rule(
        "instruction_override", "high",
        _OVERRIDE, (40, _WHAT_CAME_BEFORE), (40, r"\b(instructions?|prompts?)\b"),
    ),
    _rule(
        # The same with a vaguer last word, which is common in harmless text
        # ("later entries override all previous rules"), so it only warns.
        "instruction_override_weak", "medium",
        _OVERRIDE, (40, _WHAT_CAME_BEFORE), (40, r"\b(rules|guidelines|directions)\b"),
    ),
    _rule(
        "hide_from_user", "high",
        r"(do not|don'?t|never|without)\s+(ever\s+)?"
        r"(tell(ing)?|inform(ing)?|mention(ing)?|reveal(ing)?|alert(ing)?|notify(ing)?)\b",
        (30, r"\b(user|human|operator)\b"),
    ),
    _rule(
        # Kept to one sentence: a login page ("Email / Password / Forgot
        # password? https://...") has all three words but orders nothing.
        "exfiltration_to_destination", "high",
        _SEND, (60, _SECRET), (60, _DESTINATION),
        one_sentence=True, unless_after=_NEGATION,
    ),
    _rule(
        # Asking for secrets without naming a destination is often harmless
        # ("send your password reset request to support"), so it only warns.
        "secret_request", "medium",
        _SEND, (60, _SECRET),
    ),
    _rule(
        "role_hijack", "medium",
        r"(you are now\b|from now on,? you\b|new (system )?(instructions?|prompt):"
        r"|< ?/? ?system ?>|\[system\])",
    ),
    _rule(
        "tool_command", "medium",
        r"(call|invoke|use|run|execute)\b",
        (20, r"\b(tool|function|command|shell|terminal)\b"),
        (60, r"\b(immediately|now|silently|without asking|before (responding|answering))\b"),
    ),
)

# A rule that adds nothing once the rule it maps to has matched.
_SUPERSEDED_BY = {
    "instruction_override_weak": "instruction_override",
    "secret_request": "exfiltration_to_destination",
}

# Where a sentence ends in a matching view (which has single spaces only).
# Matched against the view BEFORE it is lowercased: a capital after the full stop is the evidence.
_SENTENCE_END_RE = re.compile(
    FIELD_BREAK + "|"  # between two fields of a structured value: see textutil.text_views
    r"[.!?](?<!\b[A-Za-z]\.)(?<!\.\.\.)"
    r"(?i:(?<!\betc\.)(?<!\bmr\.)(?<!\bdr\.)(?<!\bms\.)(?<!\bst\.)(?<!\bvs\.)(?<!\bno\.)(?<!\bmrs\.)(?<!\bapprox\.))"
    r" (?:(?![a-z0-9])|(?=(?i:https?://|www\.)))"
)

# A windowed search (see `_Occurrences.ends_of_matches`) reads this many
# characters past the last place a match may start, and the end of the window
# acts as the end of the text. So this must stay longer than the longest text
# a step after the first can match (the destination, 66 characters): a shorter
# window would cut a real match short, or let "\b" match in the middle of a
# word that the window cuts in two.
_STEP_SLACK = 120

# How much chain matching one scan() may do. Trying a match as the next step
# of a chain costs one, and so does a windowed search. Ordinary documents use
# a few dozen; only text that repeats the words of a rule tens of thousands
# of times gets here.
_SCAN_BUDGET = 100_000


class _Budget:
    """Counts down the chain matching that one scan() may still do."""

    def __init__(self) -> None:
        self.left = _SCAN_BUDGET

    def spend(self) -> None:
        self.left -= 1
        if self.left < 0:
            raise _Unscannable("scan budget exceeded")


def _is_word(ch: str) -> bool:
    """What the regular expression "\\w" matches."""
    return ch.isalnum() or ch == "_"


def _first_matches(pattern: re.Pattern[str], text: str) -> Iterator[re.Match[str]]:
    """Matches of a rule's first pattern, without those that start in the middle of a word.

    This is what a "\\b" in front of the pattern would do. It is done here
    because this pass over the whole text is most of the cost of a scan: a
    pattern that begins with letters lets the regex engine jump from one
    candidate to the next, where a leading "\\b" makes it stop at every
    character and is about ten times slower.
    """
    pos = 0
    while (match := pattern.search(text, pos)) is not None:
        start = match.start()
        if start and _is_word(text[start - 1]) and _is_word(text[start]):
            pos = start + 1  # not match.end(): a real match may begin inside this one
        else:
            yield match
            pos = match.end()


class _Occurrences:
    """Where one step's pattern occurs in a text, found in a single pass.

    The matcher looks matches up here instead of searching the text again
    after each match of the step before. Without that, hostile text that
    repeats a rule's first words thousands of times is read thousands of times.
    """

    def __init__(self, step: _Step, text: str) -> None:
        self.max_gap = step.max_gap
        self._pattern = step.pattern
        self._text = text
        spans = [match.span() for match in step.pattern.finditer(text)]
        self._starts = [start for start, _ in spans]
        self._ends = [end for _, end in spans]  # sorted, because matches do not overlap

    def __bool__(self) -> bool:
        return bool(self._starts)

    def ends_of_matches(self, pos: int, latest_start: int, budget: _Budget) -> Iterator[int]:
        """Yield where each match that starts in [pos, latest_start] ends, nearest first.

        These must be the matches a search that begins at `pos` would find.
        From a `pos` outside every occurrence, that is the occurrences that
        follow. From a `pos` inside one, a search can find matches the single
        pass skipped ("www." inside the address "a@x-www.example"), so only
        then is the text searched again, in a window.
        """
        index = bisect.bisect_right(self._ends, pos)  # the first occurrence that ends after pos
        if index < len(self._starts) and self._starts[index] < pos:
            budget.spend()
            window_end = min(len(self._text), latest_start + _STEP_SLACK)
            for match in self._pattern.finditer(self._text, pos, window_end):
                if match.start() > latest_start:
                    return
                budget.spend()
                yield match.end()
            return
        while index < len(self._starts) and self._starts[index] <= latest_start:
            budget.spend()
            yield self._ends[index]
            index += 1


def _match_chain(rule: _Rule, text: str, budget: _Budget, cased: str = "") -> tuple[int, int] | None:
    """Return the (start, end) of the first place `rule` matches, or None."""
    first_pattern = rule.steps[0].pattern
    if next(_first_matches(first_pattern, text), None) is None:
        return None
    occurrences = []
    for step in rule.steps[1:]:
        occurrences.append(_Occurrences(step, text))
        if not occurrences[-1]:
            return None  # this step occurs nowhere in the text, so the rule cannot match
    sentence_ends = [match.start() for match in _SENTENCE_END_RE.finditer(cased or text)] if rule.one_sentence else []
    for first in _first_matches(first_pattern, text):
        budget.spend()
        if rule.unless_after and rule.unless_after.search(text, max(0, first.start() - _NEGATION_REACH), first.start()):
            continue
        next_end = bisect.bisect_left(sentence_ends, first.end())
        limit = sentence_ends[next_end] if next_end < len(sentence_ends) else len(text)
        end = _match_rest(tuple(occurrences), first.end(), limit, budget)
        if end is not None:
            return first.start(), end
    return None


def _match_rest(occurrences: tuple[_Occurrences, ...], pos: int, limit: int, budget: _Budget) -> int | None:
    """Match the remaining steps from `pos`, none starting after `limit`; return where the last one ends."""
    if not occurrences:
        return pos
    step = occurrences[0]
    for end in step.ends_of_matches(pos, min(pos + step.max_gap, limit), budget):
        chain_end = _match_rest(occurrences[1:], end, limit, budget)
        if chain_end is not None:
            return chain_end
    return None


def _match_rules(view: str, budget: _Budget, found: dict[str, Finding]) -> None:
    """Add to `found` a finding for each chain rule that matches `view` and is not settled already."""
    # Lowercasing never changes the length of a matching view (the one
    # character it would lengthen, U+0130, does not survive `_decompose`), so
    # positions found in `lowered` can be used to quote from `view`.
    lowered = view.lower()
    for rule in _RULES:
        # A rule has one severity, so a match in an earlier view cannot be improved on.
        if rule.name in found or _SUPERSEDED_BY.get(rule.name) in found:
            continue
        span = _match_chain(rule, lowered, budget, view)
        if span:
            found[rule.name] = Finding(rule.name, rule.severity, _excerpt(view, *span))


# --------------------------------------------------------------------------
# Rules that are not chains (matched on the text as it arrived)
# --------------------------------------------------------------------------

# An image whose URL carries a query string: a common way to leak data,
# because the client fetches the URL without asking. Markdown first, with a
# plain or an <angle-bracket> destination; then HTML. Every part has a length
# bound so hostile input cannot slow the match down. In a plain markdown
# destination a "]" also counts as a hit: without that, a run of unfinished
# images would be read again from each "![", 500 characters at a time.
_IMAGE_EXFIL_RES = (
    re.compile(
        r"!\[[^\]\[]{0,300}\]\(\s{0,5}"
        r"(?:<(?:https?:)?//[^<>\n?#]{1,500}\?|(?:https?:)?//[^)\s?#\]]{1,500}[?\]])",
        re.IGNORECASE,
    ),
    re.compile(
        r"<img\b[^<>]{0,300}?\bsrc\s{0,5}=\s{0,5}[\"']?(?:https?:)?//[^<>\s\"'?#]{1,500}\?",
        re.IGNORECASE,
    ),
)


def _image_finding(text: str) -> Finding | None:
    for pattern in _IMAGE_EXFIL_RES:
        match = pattern.search(text)
        if match:
            return Finding("markdown_image_exfiltration", "medium", _excerpt(text, *match.span()))
    return None


def _invisible_finding(text: str) -> Finding | None:
    # Counted by how much shorter the text gets without them: that runs inside
    # str.translate, where a loop over the characters would be slow.
    count = len(text) - len(text.translate(_WITHOUT_INVISIBLE))
    if not count:
        return None
    hidden_text = len(text.translate(_WITHOUT_HIDDEN_TEXT)) < len(text)
    return Finding("invisible_characters", "medium" if hidden_text else "low", f"{count} invisible character(s)")


def _excerpt(text: str, start: int, end: int, pad: int = 30) -> str:
    return text[max(0, start - pad) : min(len(text), end + pad)].strip()


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def scan(text: str, budget: "_Budget | None" = None) -> list[Finding]:
    """Return the injection findings in `text`, at most one per rule."""
    if not text:
        return []
    found: dict[str, Finding] = {}
    for finding in (_invisible_finding(text), _image_finding(text)):
        if finding:
            found[finding.rule] = finding
    budget = budget or _Budget()
    try:
        for view in _matching_views(text):
            _match_rules(view, budget, found)
    except _Unscannable as problem:
        found["unscannable_content"] = Finding("unscannable_content", "high", str(problem))
    return _without_superseded(found)


def scan_views(texts: Iterable[str]) -> list[Finding]:
    """Scan several texts that describe one value; return at most one finding per rule.

    For a rule found in more than one text, the highest severity wins, and
    among equals the first. See `textutil.text_views` for why one value is
    read as several texts.
    """
    strongest: dict[str, Finding] = {}
    budget = _Budget()
    for text in texts:
        if "unscannable_content" in strongest:
            break
        for finding in scan(text, budget):
            known = strongest.get(finding.rule)
            if known is None or SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[known.severity]:
                strongest[finding.rule] = finding
    return _without_superseded(strongest)


def _without_superseded(found: dict[str, Finding]) -> list[Finding]:
    """The findings, minus any whose stronger rule matched too (possibly in another view)."""
    return [finding for finding in found.values() if _SUPERSEDED_BY.get(finding.rule) not in found]


def max_severity(findings: list[Finding]) -> str | None:
    """The highest severity among `findings`, or None if there are none."""
    if not findings:
        return None
    return max((f.severity for f in findings), key=SEVERITY_ORDER.__getitem__)
