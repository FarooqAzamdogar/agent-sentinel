"""Recognise secrets that should not leave in a tool call, or sit in a log.

The injection detector looks at text coming IN from tools. This module looks at
what goes OUT: a hijacked agent that has read a private key or an API token
will try to pass it to a tool (an HTTP request, an e-mail, a search query).

Only formats with a fixed, recognisable shape are listed, so that a match is
very likely a real credential. This is not a general "high entropy string"
detector: those flag ordinary identifiers and hashes.

Adding a pattern: it must be anchored on a literal prefix, have explicit length
bounds, and must not be able to match a double quote (`redact` is applied to
JSON text and must never swallow the end of a JSON string).
"""

from __future__ import annotations

import re

# (kind, pattern). The kind is shown in logs and reasons; it never contains the secret.
_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{50,255}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,255}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,255}\b")),
    ("API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,255}\b|\bsk-(?:proj-)?[A-Za-z0-9_-]{32,255}\b")),
)

_PRIVATE_KEY = "private key"
_PEM_BEGIN = re.compile(r"-----BEGIN (?:[A-Z0-9]{1,20} ){0,4}PRIVATE KEY(?: BLOCK)?-----")
_PEM_END = "-----END"
_PEM_MAX_BODY = 16_000  # longer than any real key; bounds the search for the END line


def find_secrets(text: str) -> list[str]:
    """Return the kinds of secret found in `text`, each kind once."""
    kinds = [_PRIVATE_KEY] if _PEM_BEGIN.search(text) else []
    kinds += [kind for kind, pattern in _TOKEN_PATTERNS if pattern.search(text)]
    return kinds


def redact(text: str) -> str:
    """Replace every secret in `text` with a marker such as ``[redacted GitHub token]``."""
    text = _redact_private_keys(text)
    for kind, pattern in _TOKEN_PATTERNS:
        text = pattern.sub(f"[redacted {kind}]", text)
    return text


def _redact_private_keys(text: str) -> str:
    """Replace each PEM private key, from its BEGIN line to its END line.

    Done by hand instead of with one regular expression: a pattern with an
    open-ended body is slow on text that repeats the BEGIN line many times.
    A key with no END line in reach loses its BEGIN line only.
    """
    pieces: list[str] = []
    pos = 0
    for begin in _PEM_BEGIN.finditer(text):
        if begin.start() < pos:
            continue  # inside a key that was already replaced
        # Never look past a double quote: in JSON text that is the end of the string.
        limit = text.find('"', begin.end(), begin.end() + _PEM_MAX_BODY)
        limit = begin.end() + _PEM_MAX_BODY if limit == -1 else limit
        end = text.find(_PEM_END, begin.end(), limit)
        stop = begin.end()
        if end != -1:
            closing = text.find("-----", end + len(_PEM_END), min(limit, end + 80))
            stop = closing + 5 if closing != -1 else end + len(_PEM_END)
        pieces += [text[pos : begin.start()], f"[redacted {_PRIVATE_KEY}]"]
        pos = stop
    pieces.append(text[pos:])
    return "".join(pieces)
