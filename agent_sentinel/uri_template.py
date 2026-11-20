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
* a template the proxy cannot read (an unclosed or empty "{...}", a stray
  "}", more than MAX_EXPRESSIONS expressions, more than MAX_TEMPLATE_CHARS
  characters) matches every URI, and so does a URI longer than MAX_URI_CHARS.

Matching is plain string search for each literal part in turn, leftmost
first (as policy._glob_matches does for "*" in tool names), which never
backtracks: the time is bounded by the lengths of the URI and the template.
"""

from __future__ import annotations

from .policy import _glob_matches
from .textutil import percent_decoded

MAX_TEMPLATE_CHARS = 2048
MAX_EXPRESSIONS = 32
MAX_URI_CHARS = 8192

# A template the matcher cannot read: it matches every URI.
EVERYTHING = None


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


def may_match(parts: tuple[str, ...] | None, uri: str) -> bool:
    """Whether `uri` may have been produced from a template with these literal parts (see the module docstring)."""
    if parts is EVERYTHING or not isinstance(uri, str) or len(uri) > MAX_URI_CHARS:
        return True
    if _glob_matches(parts, uri.casefold()):
        return True
    return "%" in uri and _glob_matches(parts, _folded(uri))


def _folded(text: str) -> str:
    """Text as it is compared: percent-decoded once, and without regard to case."""
    return percent_decoded(text).casefold()
