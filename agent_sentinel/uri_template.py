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
* the URI may go on after the template's last literal text: a server that
  parses the URI reads "file:///docs/a.md#top", "...a.md?raw" and
  "notes://items/42/view/" as the resource without that tail (and Windows
  opens "a.md." and "a.md::$DATA" as a.md). So "file:///docs/{name}.md"
  also matches "file:///docs/a.md.bak": only the start and the order of
  the literal parts count;
* letters are compared without regard to case, and the URI is compared as
  it is and once percent-decoded, since a server may read either spelling
  the same way;
* the URI parsers that servers use (WHATWG URL in Node and in pydantic,
  Python's urllib) drop a tab or a line break anywhere in a URI and the
  control characters and spaces around it, and read a backslash as a
  slash. So the URI and the template are compared a second time with
  every control character, all white space and the zero-width characters
  removed and each backslash written as a slash (_plain);
* a server may also read a URI the same way when it is written with other
  slashes after the scheme or with a "localhost" authority ("file:/x",
  "file:///x" and "file://localhost/x" name one file, RFC 8089), with
  userinfo before the host ("https://me@host/"), with the scheme's default
  port ("https://host:443/") or with a dot after the host
  ("https://host./"). So when the template starts with a scheme, the URI
  and the template are compared a third time, made plain as for the second
  and with the start written as "scheme:" and the host alone (_loosened).
  The second and third comparisons only add matches: what the first finds
  is never lost;
* a template the proxy cannot read (an unclosed or empty "{...}", a stray
  "}", more than MAX_EXPRESSIONS expressions, more than MAX_TEMPLATE_CHARS
  characters) matches every URI, and so does a URI longer than MAX_URI_CHARS.

Not told apart, and so not matched: dot segments ("a/../b"), a host written
as an IP address or in another Unicode form, and percent-encoding applied
twice.

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
# What a URI parser drops or a server may trim: control characters, white space of any kind, and the
# characters that take no room (a byte order mark, which JavaScript's trim() removes, the soft hyphen and
# the zero-width ones, which IDNA drops from a host, and the marks of writing direction).
_DROPPED = re.compile(r"[\x00-\x20\x7f-\x9f\s\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e"
                      r"\u2060-\u2064\u2066-\u206f\ufeff]+")
# The port a parser leaves out of the address it works with, by scheme.
_DEFAULT_PORTS = {"http": "80", "https": "443", "ws": "80", "wss": "443", "ftp": "21"}


@dataclass(frozen=True)
class Spellings:
    """The ways a URI is compared (see `spellings`); None in place of it means "matches every template"."""

    exact: tuple[str, ...]  # as it is and percent-decoded, folded
    plain: tuple[str, ...]  # the same, without control characters and white space, backslashes as slashes (_plain)
    loose: tuple[str, ...]  # the plain ones, with the start written as "scheme:" and the host alone (_loosened)


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
    plain = tuple(dict.fromkeys(_plain(spelling) for spelling in exact))
    return Spellings(exact, plain, tuple(dict.fromkeys(_loosened(spelling) for spelling in plain)))


def may_match(parts: tuple[str, ...] | None, uri: str | Spellings | None) -> bool:
    """Whether `uri` may have been produced from a template with these literal parts (see the module docstring).

    `uri` is the URI, or what `spellings` gave for it.
    """
    found = uri if isinstance(uri, Spellings) or uri is None else spellings(uri)
    if parts is EVERYTHING or found is None:
        return True
    if any(_glob_matches(_open_ended(parts), spelling) for spelling in found.exact):
        return True
    plain = tuple(_plain(part) for part in parts)
    if any(_glob_matches(_open_ended(plain), spelling) for spelling in found.plain):
        return True
    loose = _loose_parts(plain)
    return loose is not None and any(_glob_matches(_open_ended(loose), spelling) for spelling in found.loose)


def _open_ended(parts: tuple[str, ...]) -> tuple[str, ...]:
    """The literal parts with any text allowed after the last: a URI may go on after it (a fragment, a query, "/")."""
    return parts if parts[-1] == "" else (*parts, "")


def _loose_parts(parts: tuple[str, ...]) -> tuple[str, ...] | None:
    """The plain literal parts with the start loosened; None if they do not start with a scheme."""
    if _SCHEME_START.match(parts[0]) is None:
        return None
    return (_loosened(parts[0]), *parts[1:])


def _plain(text: str) -> str:
    """Folded text without control, white space and zero-width characters, and with each backslash written as a slash.

    Done to the URI and to the template alike, which keeps every match: the
    same characters go from both.
    """
    return _DROPPED.sub("", text).replace("\\", "/")


def _loosened(text: str) -> str:
    """Plain text with its start "scheme:" + slashes + "localhost" written as "scheme:" ("file:///x" -> "file:x"),
    and the piece that follows, up to the first "/", "?" or "#", without userinfo, without the scheme's default
    port (or an empty one) and without dots at its end ("https://me@host.:443/x" -> "https:host/x").

    That piece is the host when the text has one. A template's literal text
    that stops inside it is cut the same way, which leaves less of it to
    compare: it then matches more, never less.
    """
    start = _SCHEME_START.match(text)
    if start is None:
        return text
    scheme, rest = start.group(1), text[start.end():]
    stop = next((position for position, character in enumerate(rest) if character in "/?#"), len(rest))
    host = rest[:stop].rpartition("@")[2]
    name, colon, port = host.rpartition(":")
    if colon and port in ("", _DEFAULT_PORTS.get(scheme)):
        host = name
    return f"{scheme}:{host.rstrip('.')}{rest[stop:]}"


def _folded(text: str) -> str:
    """Text as it is compared: percent-decoded once, and without regard to case."""
    return percent_decoded(text).casefold()
