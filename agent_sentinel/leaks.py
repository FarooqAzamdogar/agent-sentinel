"""Recognise secrets that should not leave in a tool call, or sit in a log.

The injection detector looks at text coming IN from tools. This module looks at
what goes OUT: a hijacked agent that has read a private key or an API token
will try to pass it to a tool (an HTTP request, an e-mail, a search query).

Only formats with a fixed, recognisable shape are listed, so that a match is
very likely a real credential. This is not a general "high entropy string"
detector: those flag ordinary identifiers and hashes.

Two uses, with different needs:

  * `find_secrets` decides whether a tool call is refused. A false alarm blocks
    an honest call, so it wants evidence: a key header must be followed by key
    material, and the vaguest token shape must look random.
  * `redact` and `redact_value` clean what goes into the audit log. There a
    false alarm costs nothing, so they remove more.

Adding a pattern: anchor it on a literal prefix and give it explicit length
bounds. Do not use "\\b": an underscore, or the "n" of a written-out "\\n",
counts as a word character and would hide a token that follows it. A prefix
that occurs nowhere else needs no guard in front; a common one takes
`_NOT_AFTER`.
"""

from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import unquote

_NOT_AFTER = r"(?<![A-Za-z0-9])"  # the token does not continue a longer word
_NOT_BEFORE = r"(?![A-Za-z0-9])"


def _looks_random(token: str) -> bool:
    """True for text with a digit and a capital letter in it, as generated keys have."""
    return any(ch.isdigit() for ch in token) and any(ch.isupper() for ch in token)


# (kind, pattern, extra test or None). The kind is shown in logs and reasons;
# it never contains the secret. A prefix that occurs nowhere else ("ghp_",
# "xoxb-") is matched wherever it stands, even glued to other text. Where the
# body has a fixed length, _NOT_BEFORE keeps a longer run of letters from matching.
_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str], Callable[[str], bool] | None], ...] = (
    # Not the key that AWS prints in its own documentation.
    ("AWS access key", re.compile(_NOT_AFTER + r"(?:AKIA|ASIA)(?![0-9A-Z]{9}EXAMPLE)[0-9A-Z]{16}" + _NOT_BEFORE), None),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255}"), None),
    ("Slack token", re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,255}"), None),
    ("Google API key", re.compile(_NOT_AFTER + r"AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"), None),
    ("Stripe live key", re.compile(r"[sr]k_live_[A-Za-z0-9]{20,255}"), None),
    ("API key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,255}"), None),
    # "sk-" alone also starts product slugs and CSS classes ("sk-hynix-platinum-..."),
    # so this vaguer form must stand on its own and look random.
    ("API key", re.compile(_NOT_AFTER + r"sk-(?:proj-)?[A-Za-z0-9_-]{32,255}"), _looks_random),
)

_PRIVATE_KEY = "private key"
_PEM_BEGIN = re.compile(r"-----BEGIN (?:[A-Z0-9]{1,20} ){0,4}PRIVATE KEY(?: BLOCK)?-----")
_PEM_END = "-----END"
_PEM_MAX_BODY = 100_000  # longer than a large PGP key block; bounds the search for the END line
# What follows a real key header: base64. Text that merely mentions the header does not have it.
_KEY_MATERIAL = re.compile(r"[A-Za-z0-9+/]{24}")
_KEY_MATERIAL_REACH = 300

_DECODE_ROUNDS = 3
_PERCENT_ESCAPE = re.compile("%[0-9A-Fa-f]{2}")


def find_secrets(text: str) -> list[str]:
    """Return the kinds of secret found in `text`, each kind once.

    Percent-decoded spellings are read too: in a URL the character before a
    token is often "%20" or "%3D", which would otherwise glue it to a word.
    """
    kinds: list[str] = []
    for spelling in _spellings(text):
        for kind in _kinds_in(spelling):
            if kind not in kinds:
                kinds.append(kind)
    return kinds


def _spellings(text: str) -> list[str]:
    spellings = [text]
    for _ in range(_DECODE_ROUNDS):
        if not _PERCENT_ESCAPE.search(spellings[-1]):
            break
        spellings.append(unquote(spellings[-1], errors="replace"))
    return spellings


def _kinds_in(text: str) -> list[str]:
    kinds = [_PRIVATE_KEY] if _holds_a_private_key(text) else []
    for kind, pattern, accept in _TOKEN_PATTERNS:
        if accept is None:
            found = pattern.search(text) is not None
        else:
            found = any(accept(match.group()) for match in pattern.finditer(text))
        if found:
            kinds.append(kind)
    return kinds


def _holds_a_private_key(text: str) -> bool:
    for begin in _PEM_BEGIN.finditer(text):
        if _KEY_MATERIAL.search(text, begin.end(), begin.end() + _KEY_MATERIAL_REACH):
            return True
    return False


def redact(text: str) -> str:
    """Replace every secret in `text` with a marker such as ``[redacted GitHub token]``."""
    text = _redact_private_keys(text)
    for kind, pattern, accept in _TOKEN_PATTERNS:
        marker = f"[redacted {kind}]"
        if accept is None:
            text = pattern.sub(marker, text)
        else:
            text = pattern.sub(lambda match: marker if accept(match.group()) else match.group(), text)
    return text


def redact_value(value: Any) -> Any:
    """A copy of a JSON-like value with the secrets in its strings and keys replaced.

    Applied to the values themselves, before they are written as JSON. Working
    on the JSON text instead would be wrong twice over: an escape such as
    "\\n" puts a letter in front of a token and hides it from the patterns, and
    a replacement that eats part of an escape leaves a line that is not JSON.

    Iterative, because the value can be nested deeply.
    """
    holder: list[Any] = [None]
    stack: list[tuple[Any, Any, Any]] = [(value, holder, 0)]
    while stack:
        item, parent, key = stack.pop()
        if isinstance(item, str):
            parent[key] = redact(item)
        elif isinstance(item, dict):
            copy: dict[Any, Any] = {}
            parent[key] = copy
            for name, child in item.items():
                name = redact(name) if isinstance(name, str) else name
                copy[name] = None  # holds the place, so that the order of keys is kept
                stack.append((child, copy, name))
        elif isinstance(item, (list, tuple)):
            items: list[Any] = [None] * len(item)
            parent[key] = items
            stack.extend((child, items, index) for index, child in enumerate(item))
        else:
            parent[key] = item
    return holder[0]


def _redact_private_keys(text: str) -> str:
    """Replace each PEM private key, from its BEGIN line to its END line.

    Done by hand instead of with one regular expression: a pattern with an
    open-ended body is slow on text that repeats the BEGIN line many times.
    If no END line is in reach (a key that was cut off, or a very long block)
    everything in reach is removed: better to lose some log text than to keep
    key material.
    """
    pieces: list[str] = []
    pos = 0
    for begin in _PEM_BEGIN.finditer(text):
        if begin.start() < pos:
            continue  # inside a key that was already replaced
        limit = min(len(text), begin.end() + _PEM_MAX_BODY)
        end = text.find(_PEM_END, begin.end(), limit)
        stop = limit
        if end != -1:
            closing = text.find("-----", end + len(_PEM_END), min(limit, end + 80))
            stop = closing + 5 if closing != -1 else end + len(_PEM_END)
        pieces += [text[pos : begin.start()], f"[redacted {_PRIVATE_KEY}]"]
        pos = stop
    pieces.append(text[pos:])
    return "".join(pieces)
