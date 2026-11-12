"""Heuristic detection of prompt injection in text an agent reads.

These are pattern rules, not a trained classifier. They catch common,
unsophisticated injections and will miss paraphrased, translated, encoded or
otherwise obfuscated ones, and they can flag harmless text. Treat a clean scan
as "nothing obvious found", not as "safe".
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    excerpt: str


_FLAGS = re.IGNORECASE | re.DOTALL

_SECRETS = (
    r"(\bapi[_ -]?keys?\b|\bpasswords?\b|\bcredentials?\b|\bsecrets?\b|\b(access |auth |session )?tokens?\b"
    r"|\bssh keys?\b|\.env\b|\bprivate keys?\b|\bchat history\b|\bconversation\b)"
)
_SEND = r"\b(send|forward|post|upload|email|exfiltrate|transmit|leak)\b"
_DESTINATION = r"(https?://|\bwww\.|\b[\w.+-]+@[\w-]+\.[\w.-]+)"

# (rule name, severity, pattern). Patterns run on normalized text (see scan).
# High-severity rules are kept narrow, because by default they block content.
_RULES: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "instruction_override",
        "high",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b.{0,40}"
            r"\b(previous|prior|above|earlier|all|your|system)\b.{0,40}"
            r"\b(instructions?|prompts?|rules|guidelines|directions)\b",
            _FLAGS,
        ),
    ),
    (
        "hide_from_user",
        "high",
        re.compile(
            r"\b(do not|don't|never|without)\s+(ever\s+)?"
            r"(tell(ing)?|inform(ing)?|mention(ing)?|reveal(ing)?|alert(ing)?|notify(ing)?)\b.{0,30}"
            r"\b(user|human|operator)\b",
            _FLAGS,
        ),
    ),
    (
        "exfiltration_to_destination",
        "high",
        re.compile(_SEND + r".{0,60}" + _SECRETS + r".{0,60}" + _DESTINATION, _FLAGS),
    ),
    (
        # Asking for secrets without naming a destination is often harmless
        # ("send your password reset request to support"), so it only warns.
        "secret_request",
        "medium",
        re.compile(_SEND + r".{0,60}" + _SECRETS, _FLAGS),
    ),
    (
        "role_hijack",
        "medium",
        re.compile(
            r"(\byou are now\b|\bfrom now on,? you\b|\bnew (system )?(instructions?|prompt):"
            r"|<\s*/?\s*system\s*>|\[system\])",
            _FLAGS,
        ),
    ),
    (
        "tool_command",
        "medium",
        re.compile(
            r"\b(call|invoke|use|run|execute)\b.{0,20}"
            r"\b(tool|function|command|shell|terminal)\b.{0,60}"
            r"\b(immediately|now|silently|without asking|before (responding|answering))\b",
            _FLAGS,
        ),
    ),
]

# A finding for the first rule makes the second one redundant.
_SUPERSEDES = {"exfiltration_to_destination": "secret_request"}

# Characters that render as nothing but can carry hidden instructions.
_INVISIBLE = re.compile("[­​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")

# A markdown image whose URL carries query data: a common way to leak data out.
_MARKDOWN_EXFIL = re.compile(r"!\[[^\]]*\]\(https?://[^)\s]*[?&][^)\s=]*=", re.IGNORECASE)


def _excerpt(text: str, start: int, end: int, pad: int = 30) -> str:
    return text[max(0, start - pad) : min(len(text), end + pad)].strip()


def scan(text: str) -> list[Finding]:
    """Return the injection findings in `text`, at most one per rule."""
    if not text:
        return []
    findings: list[Finding] = []

    invisible = _INVISIBLE.findall(text)
    if invisible:
        findings.append(Finding("invisible_characters", "medium", f"{len(invisible)} invisible character(s)"))

    match = _MARKDOWN_EXFIL.search(text)
    if match:
        findings.append(Finding("markdown_image_exfiltration", "medium", _excerpt(text, *match.span())))

    # Normalize so that look-alike forms cannot hide trigger words: remove
    # invisible characters, fold compatibility forms (full-width letters,
    # ligatures) to plain ones, and collapse whitespace.
    normalized = unicodedata.normalize("NFKC", _INVISIBLE.sub("", text))
    normalized = " ".join(normalized.split())
    found: set[str] = set()
    for rule, severity, pattern in _RULES:
        if any(_SUPERSEDES.get(other) == rule for other in found):
            continue
        match = pattern.search(normalized)
        if match:
            found.add(rule)
            findings.append(Finding(rule, severity, _excerpt(normalized, *match.span())))
    return findings


def max_severity(findings: list[Finding]) -> str | None:
    if not findings:
        return None
    return max((f.severity for f in findings), key=SEVERITY_ORDER.__getitem__)
