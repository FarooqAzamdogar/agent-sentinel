"""Whether a URI may have come from a URI template (RFC 6570), to refuse reads under a quarantined resource template.

A server lists resource templates such as "notes://{id}"; a client fills
one in and reads "notes://42". When the proxy quarantines a template (its
description was flagged, or it changed after it was pinned), a read of any
URI the template could have produced is refused.

The match errs on the side of matching, since a match only refuses a read:

* every expression ({id}, {+path}, {#frag}, {/seg}, {?q,r}, {.ext}, {;p},
  {&x}, with any modifiers) stands for any text, empty included. Its real
  expansion is a part of that (an operator's "?" or "/" is part of the
  expansion and may be left out when its variables are undefined), so no
  URI the template can produce is missed;
* letters are compared without regard to case, and the URI is compared as
  it is and once percent-decoded, since a server may read either spelling
  the same way;
* a server may also read a URI the same way when it is written with other
  slashes after the scheme or with a "localhost" authority ("file:/x",
  "file:///x" and "file://localhost/x" name one file, RFC 8089), or with
  white space around it. So when the template starts with a scheme, the URI
  and the template are compared a second time with white space trimmed and
  the start "scheme:" + slashes + "localhost" written as "scheme:" alone.
  That second comparison only adds matches, so it never loses one of the
  first;
* a template the proxy cannot read (an unclosed or empty "{...}", a stray
  "}", more than MAX_EXPRESSIONS expressions, more than MAX_TEMPLATE_CHARS
  characters) matches every URI, and so does a URI longer than MAX_URI_CHARS.

Matching is plain string search for each literal part in turn, leftmost
first (as policy._glob_matches does for "*" in tool names), which never
backtracks: the time is bounded by the lengths of the URI and the template.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .policy import _glob_matches
from .textutil import percent_decoded

MAX_TEMPLATE_CHARS = 2048
MAX_EXPRESSIONS = 32
MAX_URI_CHARS = 8192

# A template the matcher cannot read: it matches every URI.
EVERYTHING = None

# The start of a URI, folded: its scheme, then the slashes and a "localhost" authority some spellings leave out.
_SCHEME_START = re.compile(r"([a-z][a-z0-9+.\-]*):/*(?:localhost(?=/|$))?/*")


@dataclass(frozen=True)
class Spellings:
    """The ways a URI is compared (see `spellings`); None in place of it means "matches every template"."""

    exact: tuple[str, ...]  # as it is and percent-decoded, folded
    loose: tuple[str, ...]  # the same, trimmed, with the start written as "scheme:" (_loosened)


def literal_parts(template: str) -> tuple[str, ...] | None:
    """The literal text of a template between its expressions, folded for comparison; None (EVERYTHING) when unreadable.

    "notes://{id}/x{?q}" gives ("notes://", "/x", "").
    """
    if not isinstance(template, str) or len(template) > MAX_TEMPLATE_CHARS:
        return EVERYTHING
    parts: list[str] = []
    start = 0
    position = 0
    while position < len(template):
        character = template[position]
        if character == "}":
            return EVERYTHING
        if character != "{":
            position += 1
            continue
        end = template.find("}", position + 1)
        if end < 0 or end == position + 1 or "{" in template[position + 1:end]:
            return EVERYTHING
        parts.append(template[start:position])
        if len(parts) > MAX_EXPRESSIONS:
            return EVERYTHING
        position = start = end + 1
    parts.append(template[start:])
    return tuple(_folded(part) for part in parts)


def spellings(uri: str) -> Spellings | None:
    """The spellings `may_match` compares a URI in; None when it is too long or not text (it then matches every one).

    Work it out once to compare one URI with many templates.
    """
    if not isinstance(uri, str) or len(uri) > MAX_URI_CHARS:
        return None
    exact = tuple(dict.fromkeys((uri.casefold(), _folded(uri))))
    return Spellings(exact, tuple(dict.fromkeys(_loosened(spelling.strip()) for spelling in exact)))


def may_match(parts: tuple[str, ...] | None, uri: str | Spellings | None) -> bool:
    """Whether `uri` may have been produced from a template with these literal parts (see the module docstring).

    `uri` is the URI, or what `spellings` gave for it.
    """
    found = uri if isinstance(uri, Spellings) or uri is None else spellings(uri)
    if parts is EVERYTHING or found is None:
        return True
    if any(_glob_matches(parts, spelling) for spelling in found.exact):
        return True
    loose = _loose_parts(parts)
    return loose is not None and any(_glob_matches(loose, spelling) for spelling in found.loose)


def _loose_parts(parts: tuple[str, ...]) -> tuple[str, ...] | None:
    """The literal parts, trimmed at both ends and with the start loosened; None if they do not start with a scheme."""
    first = parts[0].lstrip()
    if _SCHEME_START.match(first) is None:
        return None
    loose = [_loosened(first), *parts[1:]]
    loose[-1] = loose[-1].rstrip()
    return tuple(loose)


def _loosened(text: str) -> str:
    """Folded text with its start "scheme:" + slashes + "localhost" written as "scheme:" ("file:///x" -> "file:x")."""
    start = _SCHEME_START.match(text)
    return text if start is None else f"{start.group(1)}:{text[start.end():]}"


def _folded(text: str) -> str:
    """Text as it is compared: percent-decoded once, and without regard to case."""
    return percent_decoded(text).casefold()
