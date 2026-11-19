"""`agent-sentinel suggest AUDIT_LOG --policy POLICY`: draft an allowlist from a monitor-mode log.

    agent-sentinel proxy --policy policy.json --audit audit.jsonl --monitor -- <server>   (use the agent a while)
    agent-sentinel suggest audit.jsonl --policy policy.json
    agent-sentinel suggest audit.jsonl --policy policy.json --out policy.new.json

Monitor mode logs every call the policy would block. This command takes the
calls that were blocked ONLY because no tool rule matched (rule "default"),
and proposes an exact rule for each such tool, as a diff against the policy.
It writes a file only with --out, and never the policy file itself.

What it will not do, by design:

  * loosen a block that has a reason: a deny rule, an allow rule, a tool rule
    that says block, the secret guard, the injection detector, quarantine, a
    flow rule, a rate limit, or an "ask" that a person refused or that nobody
    could be asked about (the record's "approval"). Those are listed for
    review by hand. With a default of "ask" nothing is proposed at all: any
    rule for a tool without one would take the person out of the loop;
  * propose a wildcard, or invent an argument rule. Tool names come from the
    log, where the agent or the server chose them, so only plain names
    (letters, digits, "_", ".", "-"; at most 128) become rules, written exactly.
    "delete_*" in a log is a name, and must never turn into a wildcard;
  * propose a tool whose description was flagged or changed, or whose results
    were blocked for prompt injection. Those are listed too.

Each proposed rule has max_calls_per_minute set to twice the busiest minute
seen in the log (at least MIN_LIMIT), unless --no-limits is given.
"""

from __future__ import annotations

import argparse
import copy
import difflib
import json
import os
import re
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from . import auditlog, fix_hints
from .auditlog import field_text, record_time, text_of
from .cli_common import (
    EXIT_ERROR,
    EXIT_OK,
    CommandError,
    decode_utf8,
    load_policy,
    read_input,
    shown_path,
    strict_json,
)
from .policy import Policy, PolicyError
from .policy_errors import type_name
from .textutil import printable

HELP = "draft exact-name rules from a monitor-mode log, as a diff (writes only with --out)"
DESCRIPTION = (
    "Turn the calls a monitor-mode log shows as blocked only by the policy's default into exact-name tool "
    "rules, shown as a diff against the policy. Blocks that have a reason are never loosened: they are listed "
    "for review by hand."
)
EPILOG = """\
examples:
  agent-sentinel suggest audit.jsonl --policy policy.json
  agent-sentinel suggest audit.jsonl --policy policy.json --as ask --out policy.new.json
"""

# A name that may become an exact rule: what the MCP specification recommends for tool names.
_PLAIN_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
# Names the proxy checks as tools, but which stand for a whole family of requests.
_BROAD_NAMES = {
    "resources/read": "it stands for reading ANY resource: write a rule with allow_args on 'uri' by hand",
    "prompts/get": "it stands for getting ANY prompt: write a rule with allow_args on 'name' by hand",
}
MIN_LIMIT = 10
WINDOW_SECONDS = 60
# Bounds for a log that a hostile server filled with names.
MAX_TOOLS = 1000
MAX_KEPT_NAME_CHARS = 256
MAX_ARG_NAMES = 20
MAX_ARG_NAME_CHARS = 100
MAX_PEAK = 100_000  # calls in one minute; the window holds at most this many times
SHOWN_ARG_NAMES = 8
SHOWN_HELD = 20
# Records of these events that were blocked make their tool one to review by hand.
_FLAGGING_EVENTS = {
    "tool_description": "its description was flagged",
    "tool_changed": "its definition changed after it was first seen",
    "result": "a result was blocked",
    "tool_error": "an error it raised was blocked",
}


@dataclass
class _Seen:
    """What the log shows about one tool that only the default blocked."""

    calls: int = 0
    arguments: dict[str, set[str]] = field(default_factory=dict)  # name -> kinds of value seen
    recent: deque = field(default_factory=deque)  # times in the last WINDOW_SECONDS, for the peak
    peak: int = 0

    def add(self, record: dict[str, Any]) -> None:
        self.calls += 1
        args = record.get("args")
        if isinstance(args, dict):
            for name, value in args.items():
                # The agent chose the names: keep few, and short ones.
                name = name if len(name) <= MAX_ARG_NAME_CHARS else name[:MAX_ARG_NAME_CHARS] + "..."
                if name in self.arguments or len(self.arguments) < MAX_ARG_NAMES:
                    self.arguments.setdefault(name, set()).add(type_name(value))
        when = record_time(record)
        if when is not None:
            self._count_minute(when)

    def _count_minute(self, when: datetime) -> None:
        # A sliding window over the log's order, which is the order of time (give or take
        # a record from another process written in the same second).
        stamp = when.timestamp()
        while self.recent and self.recent[0] <= stamp - WINDOW_SECONDS:
            self.recent.popleft()
        if len(self.recent) < MAX_PEAK:
            self.recent.append(stamp)
        self.peak = max(self.peak, len(self.recent))


@dataclass
class _Log:
    unreadable: int = 0
    calls_blocked: int = 0
    by_default: dict[str, _Seen] = field(default_factory=dict)
    too_many_tools: int = 0
    unnamed: int = 0  # blocked by the default, with a tool name that is not text
    held: Counter = field(default_factory=Counter)  # rule id -> blocks
    held_tools: dict[str, set[str]] = field(default_factory=dict)
    flagged: dict[str, str] = field(default_factory=dict)  # tool -> why


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("audit", help="the audit log, best one written in monitor mode (proxy --monitor)")
    parser.add_argument("--policy", required=True, metavar="POLICY", help="the policy the log was written with")
    parser.add_argument("--out", metavar="FILE",
                        help="write the suggested policy to this new file (it must not exist yet)")
    parser.add_argument("--as", dest="action", choices=("allow", "ask"), default="allow",
                        help="the action of each proposed rule (default allow)")
    parser.add_argument("--server", action="append", default=[], metavar="NAME",
                        help="only the calls of this server (proxy --name), for a log several servers share")
    parser.add_argument("--no-limits", action="store_true", help="do not propose max_calls_per_minute")


def run(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    if policy is None:
        return EXIT_ERROR
    if args.out is not None:
        _check_out(args.out, args.policy)
    raw, policy = _raw_policy(args.policy)
    log = read_log(args.audit, tuple(args.server))

    if log.unreadable:
        print(f"WARNING: {log.unreadable} line(s) of the log could not be read and are not counted.")
    print(f"{log.calls_blocked} blocked call(s) in the log; {sum(s.calls for s in log.by_default.values())} "
          f"of them blocked only by the default, to {len(log.by_default)} tool(s).")
    proposed, left_out = choose(log, policy)
    if policy.default == "allow":
        proposed = []
        print('\nThe policy\'s default is "allow" now, so these tools need no rule to be called.')
    elif policy.default == "ask" and proposed:
        proposed = []
        print('\nThe policy\'s default is "ask": a call without a rule goes to a person, and suggest never turns that '
              'into "allow". Write a rule by hand for a tool that needs no review.')
    _print_proposed(proposed, log)
    _print_left_out(left_out, log.unnamed)
    _print_held(log)
    if not proposed:
        print("\nNothing to suggest.")
        return EXIT_OK

    suggested = with_rules(raw, proposed, log, args.action, limits=not args.no_limits)
    try:
        Policy.from_dict(copy.deepcopy(suggested))
    except PolicyError as exc:  # never expected: what is added is plain names and actions
        raise CommandError(f"the suggested policy would not load ({exc}); nothing was written") from exc
    _print_diff(raw, suggested, args.policy)
    if args.out is None:
        print("\nNothing was written. To write the suggested policy to a new file, add --out FILE.")
        return EXIT_OK
    _write(args.out, suggested)
    print(f"\nWrote the suggested policy to {shown_path(os.path.abspath(args.out))}.")
    print(f"Review it, then try it: agent-sentinel validate {shown_path(args.out)}")
    return EXIT_OK


# ---- reading the log ------------------------------------------------------------------------

def read_log(path: str, servers: tuple[str, ...] = ()) -> _Log:
    """Sort the blocked calls of the log: blocked only by the default, or blocked for a reason."""
    log = _Log()
    for record in auditlog.iter_records(path):
        if record is None:
            log.unreadable += 1
            continue
        if servers and text_of(record, "server") not in servers:
            continue
        if not auditlog.is_block(record):
            continue
        event, tool = record.get("event"), text_of(record, "tool")
        if tool is not None and len(tool) > MAX_KEPT_NAME_CHARS:
            # Kept short; such a name can never be proposed (see _PLAIN_NAME), only listed.
            tool = tool[:MAX_KEPT_NAME_CHARS] + "..."
        if event in _FLAGGING_EVENTS and tool is not None and len(log.flagged) < MAX_TOOLS:
            log.flagged.setdefault(tool, _FLAGGING_EVENTS[event])
        if event != "call":
            continue
        log.calls_blocked += 1
        if fix_hints.classify(record.get("rule")).kind != "default" or "approval" in record:
            _add_held(log, record)
        elif tool is None:
            log.unnamed += 1
        else:
            _add_default_block(log, tool, record)
    return log


def _add_default_block(log: _Log, tool: str, record: dict[str, Any]) -> None:
    seen = log.by_default.get(tool)
    if seen is None:
        if len(log.by_default) >= MAX_TOOLS:
            log.too_many_tools += 1
            return
        seen = log.by_default[tool] = _Seen()
    seen.add(record)


def _add_held(log: _Log, record: dict[str, Any]) -> None:
    rule = field_text(record, "rule", 200) if "rule" in record else "(no rule named)"
    if "approval" in record:  # an "ask": the person asked said no, or nobody could be asked
        rule += f" (ask, {field_text(record, 'approval', 20)})"
    if rule not in log.held and len(log.held) >= MAX_TOOLS:
        rule = "(other rules)"
    log.held[rule] += 1
    tools = log.held_tools.setdefault(rule, set())
    if len(tools) < 3:
        tools.add(field_text(record, "tool", 60))


# ---- deciding ---------------------------------------------------------------------------------

def choose(log: _Log, policy: Policy) -> tuple[list[str], list[tuple[str, str]]]:
    """(tools to propose a rule for, [(tool, why it is left out)]), each sorted by name."""
    proposed, left_out = [], []
    for tool in sorted(log.by_default):
        why = why_left_out(tool, policy, log.flagged)
        if why is None:
            proposed.append(tool)
        else:
            left_out.append((tool, why))
    return proposed, left_out


def why_left_out(tool: str, policy: Policy, flagged: dict[str, str]) -> str | None:
    """Why `tool` must not get a proposed rule, or None if it may."""
    if tool in _BROAD_NAMES:
        return _BROAD_NAMES[tool]
    if "*" in tool:
        return "the name has a '*', which in a policy would be a wildcard"
    if not _PLAIN_NAME.fullmatch(tool):
        return ("the name has characters other than letters, digits, '_', '.' and '-' (or is longer than 128); "
                "if it is right, write its rule by hand")
    if tool in flagged:
        return f"{flagged[tool]}: review the tool before allowing it"
    matching = [rule.name for rule in policy.tools if rule.matches(tool)]
    if matching:
        return f"the policy has a rule for it now ({', '.join(printable(name, limit=60) for name in matching[:3])})"
    return None


def limit_for(seen: _Seen) -> int:
    """The proposed max_calls_per_minute: twice the busiest minute seen, and at least MIN_LIMIT."""
    return max(MIN_LIMIT, 2 * seen.peak)


def with_rules(raw: dict[str, Any], tools: list[str], log: _Log, action: str, limits: bool) -> dict[str, Any]:
    """A copy of the policy's JSON with an exact rule added to "tools" for each tool."""
    suggested = copy.deepcopy(raw)
    rules = suggested.setdefault("tools", {})
    for tool in tools:
        if limits:
            rules[tool] = {"action": action, "max_calls_per_minute": limit_for(log.by_default[tool])}
        else:
            rules[tool] = action
    return suggested


# ---- the policy file --------------------------------------------------------------------------

def _raw_policy(path: str) -> tuple[dict[str, Any], Policy]:
    """The policy file's JSON, in its own order, and the policy loaded from exactly that JSON.

    Called after load_policy reported any mistake in the file. Loading again
    from the same text makes sure the proposed rules are judged against the
    file that the suggestion is a diff of, even if it changed in between.
    """
    raw = strict_json(decode_utf8(read_input(path), path), path)
    try:
        return raw, Policy.from_dict(copy.deepcopy(raw))
    except PolicyError as exc:
        raise CommandError(f"{path} changed while it was read; run the command again ({exc})") from exc


def _check_out(out: str, policy_path: str) -> None:
    """--out must be a new file, and never the policy itself."""
    if os.path.normcase(os.path.abspath(out)) == os.path.normcase(os.path.abspath(policy_path)):
        raise CommandError("--out must be a new file: suggest never changes the policy file itself")
    if os.path.lexists(out):
        raise CommandError(f"{os.path.abspath(out)} already exists; give --out a new file name")


def _layout(policy: dict[str, Any]) -> str:
    return json.dumps(policy, indent=2, ensure_ascii=False) + "\n"


def _write(out: str, suggested: dict[str, Any]) -> None:
    try:
        with open(out, "x", encoding="utf-8") as handle:  # "x": never replaces a file that appeared meanwhile
            handle.write(_layout(suggested))
    except FileExistsError as exc:
        raise CommandError(f"{os.path.abspath(out)} already exists; give --out a new file name") from exc


# ---- output -------------------------------------------------------------------------------------

def _print_proposed(tools: list[str], log: _Log) -> None:
    if not tools:
        return
    print("\nProposed: an exact rule for each tool that only the default blocked (names as the log has them):")
    for tool in tools:
        seen = log.by_default[tool]
        named = [
            f"{printable(name, limit=40)} ({' or '.join(sorted(kinds))})" for name, kinds in seen.arguments.items()
        ]
        if len(named) > SHOWN_ARG_NAMES:
            named[SHOWN_ARG_NAMES:] = [f"... (+{len(named) - SHOWN_ARG_NAMES} more)"]
        arguments = ", ".join(named) or "none logged"
        busiest = f"; busiest minute {seen.peak} call(s)" if seen.peak else ""
        print(f"  {tool:30} {seen.calls} call(s){busiest}; arguments: {arguments}")
    if log.too_many_tools:
        print(f"  ... and {log.too_many_tools} call(s) to more tools than are tracked ({MAX_TOOLS})")


def _print_held(log: _Log) -> None:
    if not log.held:
        return
    print("\nBlocked for a reason: suggest never loosens these. Review them by hand (agent-sentinel explain):")
    for rule, count in log.held.most_common(SHOWN_HELD):
        tools = ", ".join(sorted(log.held_tools.get(rule, ())))
        print(f"  {count:>6}  {rule}  ({tools})")
    if len(log.held) > SHOWN_HELD:
        print(f"  ... and {len(log.held) - SHOWN_HELD} more rule(s)")


def _print_left_out(left_out: list[tuple[str, str]], unnamed: int) -> None:
    if not left_out and not unnamed:
        return
    print("\nLeft out of the suggestion:")
    for tool, why in left_out:
        # Escaped to ASCII, so that a look-alike letter (a Cyrillic "a" in "read_file") shows why it was left out.
        shown = tool.encode("ascii", errors="backslashreplace").decode("ascii")
        print(f"  '{printable(shown, limit=80)}': {why}")
    if unnamed:
        print(f"  {unnamed} call(s) whose tool name in the log is not text")


def _print_diff(raw: dict[str, Any], suggested: dict[str, Any], policy_path: str) -> None:
    print("\nSuggested change (the policy written in one standard layout, before and after):")
    name = printable(policy_path, limit=200)
    for line in difflib.unified_diff(
        _layout(raw).splitlines(), _layout(suggested).splitlines(),
        fromfile=f"{name} (now)", tofile=f"{name} (suggested)", lineterm="", n=2,
    ):
        print(printable(line, limit=1000))
