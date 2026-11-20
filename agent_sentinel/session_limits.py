"""What a session counts while it lasts: session limits, approval memory, and what an approval question shows.

Session limits
--------------
Rate limits (max_calls_per_minute) stop a burst. A slow or sharded leak stays
under them, so a policy can also limit a whole session:

    limits.max_calls_per_session         calls in one session, for all tools together
    tools.<name>.max_calls_per_session   calls to the tools that rule matches (a wildcard rule shares one count)
    limits.max_distinct, tools.<name>.max_distinct
                                         [{"arg": "to", "max": 5}]: different values of one argument
    limits.max_sink_bytes_per_session    bytes of arguments, written as JSON, sent to tools labelled "sink"
    limits.max_identical_calls           how often one call (the same tool, the same arguments) may be made

A call is counted when it is decided, after the policy, the flow rules and
the rate limits let it through or send it to a person, and only if no limit
is full: the call that a limit refuses is not counted, and an ask that a
person then refuses stays counted. The counts live in the session store (in
memory for one proxy or Firewall, in the session file in hook mode); state
that cannot be read refuses the call (fail closed).

Values are compared after NFKC, case folding and trimming, and each entry of
a list is a value of its own. Values and calls are kept as hashes (SHA-256,
cut to 128 bits), never as text. Every count has a bound (session.py); past
it the call is refused, except that max_identical_calls forgets the calls
made longest ago once it counts MAX_IDENTICAL_KEYS different ones.

Approval memory (POL-9)
-----------------------
A person who refuses the same call again and again may in the end approve
it, out of fatigue or by mistake. So an ask a person refused (or let time
out) is remembered by its tool and a hash of its arguments: the same call is
then refused without asking for approvals.refusal_window_seconds (600), and
after approvals.max_refusals_per_tool (3) refusals of one tool within that
time, every ask for that tool is refused until the oldest of them is that
old. Such a refusal is recorded with approval "refused (repeat)". A call that
differs by one character is a new call: the pause per tool is what stops
variations. Approval memory never approves anything; when the session state
cannot be read, the person is asked as before. A new session forgets it.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from typing import Any, Iterable

from .matchers import PathMatcher, destination, read_email_domain, read_url
from .policy import (
    ANY_ARG,
    IDENTICAL_CALLS_LIMIT,
    SESSION_CALLS_LIMIT,
    SINK_BYTES_LIMIT,
    ArgRule,
    Policy,
)
from .session import MAX_IDENTICAL_KEYS, MAX_REFUSALS, SINK, SessionState
from .textutil import printable, texts_in

# The kinds of session limit.
CALLS = "calls"
DISTINCT = "distinct"
SINK_BYTES = "sink_bytes"
IDENTICAL = "identical"

# What an approval question lists of the call's destinations, and how much it reads to find them.
MAX_DESTINATIONS = 10
MAX_STRINGS_READ = 200
MAX_DESTINATION_CHARS = 160


@dataclass(frozen=True)
class SessionLimit:
    """One session limit that applies to a call: its rule id, its kind, the number, and the argument (max_distinct)."""

    rule: str
    kind: str
    limit: int
    arg: str = ""

    def reason(self) -> str:
        """Why a call was refused by this limit, for the audit log."""
        if self.kind == CALLS:
            what = f"{self.limit} call(s) were already made"
        elif self.kind == DISTINCT:
            what = f"the call would make more than {self.limit} different value(s) of argument '{self.arg}'"
        elif self.kind == SINK_BYTES:
            what = f"the call would send more than {self.limit} byte(s) of arguments to tools labelled 'sink'"
        else:
            what = f"this same call was already made {self.limit} time(s)"
        return f"session limit {self.rule} reached: {what} in this session"


def limits_for(policy: Policy, tool: str, labels: Iterable[str]) -> list[SessionLimit]:
    """The session limits that apply to a call of `tool`, whose flow labels are `labels`.

    Every tool rule that matches counts, an exact name and wildcards alike, as for rate limits.
    """
    found: list[SessionLimit] = []
    if policy.max_calls_per_session is not None:
        found.append(SessionLimit(SESSION_CALLS_LIMIT, CALLS, policy.max_calls_per_session))
    found.extend(
        SessionLimit(f"limits.max_distinct[{index}]", DISTINCT, entry.max, entry.arg)
        for index, entry in enumerate(policy.max_distinct)
    )
    if policy.max_sink_bytes_per_session is not None and SINK in frozenset(labels):
        found.append(SessionLimit(SINK_BYTES_LIMIT, SINK_BYTES, policy.max_sink_bytes_per_session))
    if policy.max_identical_calls is not None:
        found.append(SessionLimit(IDENTICAL_CALLS_LIMIT, IDENTICAL, policy.max_identical_calls))
    if isinstance(tool, str):
        for rule in policy.tools:
            if not rule.matches(tool):
                continue
            if rule.max_calls_per_session is not None:
                rule_id = f"tools.{rule.name}.max_calls_per_session"
                found.append(SessionLimit(rule_id, CALLS, rule.max_calls_per_session))
            found.extend(
                SessionLimit(f"tools.{rule.name}.max_distinct[{index}]", DISTINCT, entry.max, entry.arg)
                for index, entry in enumerate(rule.max_distinct)
            )
    return found


def charge(state: SessionState, limits: list[SessionLimit], tool: str, args: dict[str, Any]) -> SessionLimit | None:
    """Count the call in every limit, unless one is full: then return that limit and change nothing.

    `state` is changed in place (the store gives a copy and keeps it only if
    it stays within the bounds of session.py).
    """
    counts: dict[str, int] = {}
    sets: dict[str, list[str]] = {}
    identical = None
    for limit in limits:
        bucket = _digest("limit\x00" + limit.rule)
        if limit.kind in (CALLS, SINK_BYTES):
            amount = 1 if limit.kind == CALLS else _size(args)
            total = counts.get(bucket, state.counts.get(bucket, 0)) + amount
            if total > limit.limit:
                return limit
            counts[bucket] = total
        elif limit.kind == DISTINCT:
            if limit.arg not in args:
                continue
            seen = sets.get(bucket, state.distinct.get(bucket, []))
            fresh = [value for value in value_digests(args[limit.arg], limit.limit + 1) if value not in seen]
            if len(seen) + len(fresh) > limit.limit:
                return limit
            if fresh:
                sets[bucket] = [*seen, *fresh]
        elif limit.kind == IDENTICAL:
            key = call_digest(tool, args)
            if state.identical.get(key, 0) >= limit.limit:
                return limit
            identical = key
    state.counts.update(counts)
    state.distinct.update(sets)
    if identical is not None:
        state.identical[identical] = state.identical.pop(identical, 0) + 1  # now the most recent
        while len(state.identical) > MAX_IDENTICAL_KEYS:
            del state.identical[next(iter(state.identical))]  # forget the call made longest ago
    return None


# ---- hashes ---------------------------------------------------------------------------

def canonical_json(value: Any) -> str:
    """A value written as JSON in one fixed way: keys sorted, no spaces; anything else is named by its type."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=_unwritable)


def _unwritable(value: Any) -> str:
    return f"<{type(value).__name__}>"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()[:32]


def _size(args: dict[str, Any]) -> int:
    return len(canonical_json(args).encode("utf-8", errors="surrogatepass"))


def call_digest(tool: str, args: dict[str, Any]) -> str:
    """The hash that stands for one call: the tool's name and its arguments as canonical JSON."""
    return _digest("call\x00" + str(tool) + "\x00" + canonical_json(args))


def tool_digest(tool: str) -> str:
    return _digest("tool\x00" + str(tool))


def value_digests(value: Any, most: int) -> list[str]:
    """The hashes of an argument's values: each entry of a list, or the value itself; at most `most` of them.

    A value is compared as text: a string as it is, anything else as
    canonical JSON; then NFKC, case folding and trimming.
    """
    entries = list(value[:most]) if isinstance(value, (list, tuple)) else [value]
    found: dict[str, None] = {}
    for entry in entries:
        text = entry if isinstance(entry, str) else canonical_json(entry)
        found[_digest("value\x00" + unicodedata.normalize("NFKC", text).casefold().strip())] = None
    return list(found)


# ---- approval memory ------------------------------------------------------------------

def repeat_refusal(
    state: SessionState, tool: str, args: dict[str, Any], now: float, window: int, most_per_tool: int
) -> str | None:
    """Why this ask is refused without asking (approval memory), or None to ask the person."""
    if window <= 0:
        return None
    recent = _recent(state.refusals, now, window)
    call = call_digest(tool, args)
    same = [when for _, digest, when in recent if digest == call]
    if same:
        ago = max(0, int(now - max(same)))
        return (
            f"a person refused this same call {ago} second(s) ago, so it is refused without asking for "
            f"{window} seconds (approvals.refusal_window_seconds)"
        )
    if most_per_tool > 0:
        who = tool_digest(tool)
        count = sum(1 for digest, _, _ in recent if digest == who)
        if count >= most_per_tool:
            return (
                f"a person refused {count} asks for this tool in the last {window} seconds, so its asks are "
                "refused without asking for now (approvals.max_refusals_per_tool)"
            )
    return None


def remember_refusal(state: SessionState, tool: str, args: dict[str, Any], now: float, window: int) -> None:
    """Remember that a person refused this call now. Refusals older than the window are dropped."""
    if window <= 0:
        return
    kept = _recent(state.refusals, now, window)
    kept.append([tool_digest(tool), call_digest(tool, args), round(max(now, 0.0), 3)])
    state.refusals[:] = kept[-MAX_REFUSALS:]


def _recent(entries: list[list[Any]], now: float, window: int) -> list[list[Any]]:
    """The refusals made within the window. One from the future (the clock went back) counts as made now."""
    kept = []
    for tool, call, when in entries:
        when = min(when, now)
        if when > now - window:
            kept.append([tool, call, when])
    return kept


# ---- what an approval question shows -----------------------------------------------------

def destinations(policy: Policy, tool: str, args: dict[str, Any]) -> tuple[str, ...]:
    """Where the call would send data, as the url, email and path matchers read its arguments.

    Every string in the arguments that reads as a URL or an e-mail address,
    and every value of an argument that a path rule of this tool (or a
    policy-wide one) judges, made absolute. At most MAX_DESTINATIONS, each
    printable and short: "https://evil.example (argument 'url')".
    """
    paths = _path_matchers(policy, tool)
    found: dict[str, None] = {}
    read = 0
    for name, value in args.items():
        for text in texts_in(value, keys=False):
            if read >= MAX_STRINGS_READ or len(found) >= MAX_DESTINATIONS:
                break
            read += 1
            for where in _readings(text, name, paths):
                found.setdefault(f"{where} (argument {printable(repr(str(name)), limit=60)})", None)
    return tuple(printable(entry, limit=MAX_DESTINATION_CHARS) for entry in list(found)[:MAX_DESTINATIONS])


def _readings(text: str, name: str, paths: list[tuple[str, PathMatcher]]) -> list[str]:
    readings = []
    if "://" in text:
        url = read_url(text)
        if url is not None:
            readings.append(f"{url.scheme}://{url.host}")
    if "@" in text:
        domain = read_email_domain(text)
        if domain is not None:
            readings.append(f"e-mail domain {domain}")
    for arg, matcher in paths:
        if arg in (name, ANY_ARG):
            path = destination(matcher, text)
            if path is not None:
                readings.append(path)
                break
    return readings


def _path_matchers(policy: Policy, tool: str) -> list[tuple[str, PathMatcher]]:
    entries: list[ArgRule] = list(policy.deny_args)
    for rule in policy.tools:
        if isinstance(tool, str) and rule.matches(tool):
            entries += [*rule.deny_args, *rule.allow_args]
    for flow in policy.flows:
        entries += list(flow.unless_args)
    return [(entry.arg, entry.matcher) for entry in entries if isinstance(entry.matcher, PathMatcher)]
