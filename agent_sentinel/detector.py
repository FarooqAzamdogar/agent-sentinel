"""Heuristic detection of prompt injection in text an agent reads.

These are pattern rules, not a trained classifier. They catch common,
unsophisticated injections. They miss paraphrased, translated, encoded or
look-alike-letter variants, and they can flag harmless text. Treat a clean
scan as "nothing obvious found", not as "safe".

How a rule works
----------------
Most rules are a *chain* of steps: a first pattern, then further patterns that
must each start within a few characters of the previous one. For example
"ignore" ... "previous" ... "instructions". Chains are matched by hand
(see `_match_chain`) instead of with one big regular expression, because the
scanned text is attacker-controlled and a single regular expression with
several ".{0,40}" gaps can be driven into very slow backtracking.

Adding a rule
-------------
Add a `_rule(...)` entry to `_RULES` and a test to tests/test_detector.py,
including a harmless sentence that must NOT match. Keep "high" rules narrow:
by default high findings block content.
"""

from __future__ import annotations

import bisect
import re
import unicodedata
from dataclasses import dataclass

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    excerpt: str


# --------------------------------------------------------------------------
# Chain rules
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class _Step:
    pattern: re.Pattern[str]
    max_gap: int  # how many characters after the previous step this one may start


@dataclass(frozen=True)
class _Rule:
    name: str
    severity: str
    steps: tuple[_Step, ...]


def _rule(name: str, severity: str, first: str, *then: tuple[int, str]) -> _Rule:
    """Build a rule: a first pattern, then (max_gap, pattern) pairs."""
    steps = [_Step(re.compile(first, re.IGNORECASE), 0)]
    steps += [_Step(re.compile(pattern, re.IGNORECASE), gap) for gap, pattern in then]
    return _Rule(name, severity, tuple(steps))


_SEND = r"\b(send|forward|post|upload|email|exfiltrate|transmit|leak)\b"
_SECRET = (
    r"(\bapi[_ -]?keys?\b|\bpasswords?\b|\bcredentials?\b|\bsecrets?\b|\b(access |auth |session )?tokens?\b"
    r"|\bssh keys?\b|\.env\b|\bprivate keys?\b|\bchat history\b|\bconversation\b)"
)
# An email address is recognized from its "@domain.tld" part. Matching the
# name before the "@" as well ("[\w.+-]+@") is slow on long runs of letters.
_DESTINATION = r"(https?://|\bwww\.|(?<=[\w.+-])@[\w-]{1,255}\.\w)"

_RULES: tuple[_Rule, ...] = (
    _rule(
        "instruction_override", "high",
        r"\b(ignore|disregard|forget|override)\b",
        (40, r"\b(previous|prior|above|earlier|all|your|system)\b"),
        (40, r"\b(instructions?|prompts?|rules|guidelines|directions)\b"),
    ),
    _rule(
        "hide_from_user", "high",
        r"\b(do not|don't|never|without)\s+(ever\s+)?"
        r"(tell(ing)?|inform(ing)?|mention(ing)?|reveal(ing)?|alert(ing)?|notify(ing)?)\b",
        (30, r"\b(user|human|operator)\b"),
    ),
    _rule(
        "exfiltration_to_destination", "high",
        _SEND, (60, _SECRET), (60, _DESTINATION),
    ),
    _rule(
        # Asking for secrets without naming a destination is often harmless
        # ("send your password reset request to support"), so it only warns.
        "secret_request", "medium",
        _SEND, (60, _SECRET),
    ),
    _rule(
        "role_hijack", "medium",
        r"(\byou are now\b|\bfrom now on,? you\b|\bnew (system )?(instructions?|prompt):"
        r"|< ?/? ?system ?>|\[system\])",
    ),
    _rule(
        "tool_command", "medium",
        r"\b(call|invoke|use|run|execute)\b",
        (20, r"\b(tool|function|command|shell|terminal)\b"),
        (60, r"\b(immediately|now|silently|without asking|before (responding|answering))\b"),
    ),
)

# When the first rule matches, the second adds nothing.
_SUPERSEDES = {"exfiltration_to_destination": "secret_request"}

# Extra characters read past a step's gap so that a match starting inside the
# gap is not cut short. Must be longer than any single step can match.
_STEP_SLACK = 120


class _Occurrences:
    """Where one step's pattern occurs in a text, for quick "is one near here?" checks.

    Found in a single pass over the text. Without this index, hostile text
    that repeats a rule's first word thousands of times would make the scanner
    search the area after every repetition.
    """

    def __init__(self, pattern: re.Pattern[str], text: str) -> None:
        spans = [match.span() for match in pattern.finditer(text)]
        self.starts = [start for start, _ in spans]
        self.ends = [end for _, end in spans]  # sorted, because matches do not overlap

    def __bool__(self) -> bool:
        return bool(self.starts)

    def may_start_between(self, pos: int, latest_start: int) -> bool:
        """Could a match start in [pos, latest_start]?

        Any such match overlaps an occurrence that ends after `pos`, so it is
        enough to look at the first occurrence that does. "Yes" still needs
        confirming with a real search; "no" is certain.
        """
        index = bisect.bisect_right(self.ends, pos)
        return index < len(self.starts) and self.starts[index] <= latest_start


def _match_chain(rule: _Rule, text: str) -> tuple[int, int] | None:
    """Return the (start, end) of the first place `rule` matches, or None."""
    later_steps = rule.steps[1:]
    occurrences = []
    for step in later_steps:
        occurrences.append(_Occurrences(step.pattern, text))
        if not occurrences[-1]:
            return None  # this step occurs nowhere in the text, so the rule cannot match
    for first in rule.steps[0].pattern.finditer(text):
        end = _match_rest(later_steps, tuple(occurrences), text, first.end())
        if end is not None:
            return first.start(), end
    return None


def _match_rest(
    steps: tuple[_Step, ...], occurrences: tuple[_Occurrences, ...], text: str, pos: int
) -> int | None:
    """Match the remaining steps starting at `pos`; return where they end."""
    if not steps:
        return pos
    step = steps[0]
    latest_start = pos + step.max_gap
    if not occurrences[0].may_start_between(pos, latest_start):
        return None
    for match in step.pattern.finditer(text, pos, min(len(text), latest_start + _STEP_SLACK)):
        if match.start() > latest_start:
            break
        end = _match_rest(steps[1:], occurrences[1:], text, match.end())
        if end is not None:
            return end
    return None


# --------------------------------------------------------------------------
# Rules that are not chains
# --------------------------------------------------------------------------

# Characters that render as nothing. The first group has no common innocent
# use in plain text and is a known way to hide instructions.
_HIDDEN_TEXT = "​⁠-⁤‪-‮⁦-⁩\U000e0000-\U000e007f"
# The second group is normal in emoji and in scripts such as Arabic, Urdu and
# Persian (joiners, direction marks), so on its own it is only a low finding.
_JOINERS = "­‌-‏﻿"
_HIDDEN_TEXT_RE = re.compile(f"[{_HIDDEN_TEXT}]")
_INVISIBLE_RE = re.compile(f"[{_HIDDEN_TEXT}{_JOINERS}]")

# A markdown image whose URL carries query data: a common way to leak data.
# Every part has a length bound so hostile input cannot slow the match down.
_MARKDOWN_EXFIL_RE = re.compile(
    r"!\[[^\]\[]{0,300}\]\(\s{0,5}https?://[^)\s?#]{1,500}\?[^)\s=]{0,200}=", re.IGNORECASE
)


def _invisible_finding(text: str) -> Finding | None:
    count = len(_INVISIBLE_RE.findall(text))
    if not count:
        return None
    severity = "medium" if _HIDDEN_TEXT_RE.search(text) else "low"
    return Finding("invisible_characters", severity, f"{count} invisible character(s)")


def _excerpt(text: str, start: int, end: int, pad: int = 30) -> str:
    return text[max(0, start - pad) : min(len(text), end + pad)].strip()


def _normalize(text: str) -> str:
    """Undo cheap disguises before matching.

    Removes invisible characters (so they cannot split a trigger word), folds
    compatibility forms such as full-width letters to plain ones, and
    collapses all whitespace to single spaces.
    """
    text = unicodedata.normalize("NFKC", _INVISIBLE_RE.sub("", text))
    return " ".join(text.split())


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def scan(text: str) -> list[Finding]:
    """Return the injection findings in `text`, at most one per rule."""
    if not text:
        return []
    findings: list[Finding] = []

    invisible = _invisible_finding(text)
    if invisible:
        findings.append(invisible)

    match = _MARKDOWN_EXFIL_RE.search(text)
    if match:
        findings.append(Finding("markdown_image_exfiltration", "medium", _excerpt(text, *match.span())))

    normalized = _normalize(text)
    matched: set[str] = set()
    for rule in _RULES:
        if any(_SUPERSEDES.get(name) == rule.name for name in matched):
            continue
        span = _match_chain(rule, normalized)
        if span:
            matched.add(rule.name)
            findings.append(Finding(rule.name, rule.severity, _excerpt(normalized, *span)))
    return findings


def max_severity(findings: list[Finding]) -> str | None:
    """The highest severity among `findings`, or None if there are none."""
    if not findings:
        return None
    return max((f.severity for f in findings), key=SEVERITY_ORDER.__getitem__)
