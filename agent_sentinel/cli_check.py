"""`agent-sentinel check POLICY TOOL [name=value ...]`: try one call against a policy, without running anything.

    agent-sentinel check policy.json read_file path=notes/todo.txt
    agent-sentinel check policy.json send_email to=eve@evil.example --show-rules
    agent-sentinel check policy.json search count:=5 --args '{"tags": ["a", "b"]}'
    agent-sentinel check policy.json send_email to=bob@example.com --marks untrusted
    agent-sentinel check policy.json fetch_page url=https://example.com --result page.html
    agent-sentinel check policy.json send_email to=eve@evil.example --history history.json

The call goes through the same checks as a real one, in the same order: the
secret guard, the policy (deny rules, tool rules, the default, and the flow
rules for the marks given with --marks), approval memory, the rate limits
and the session limits. Nothing is logged and nobody is asked: a call that
needs approval is reported as "ask". The answer names the rule that decided,
what the agent would be told, and, for a refusal, what the operator could
change.

--history FILE plays earlier calls and results of the session first (a JSON
list; see parse_history), so that flow marks, session limits, approval
memory and the tail scan of --result can be tried:

    [{"call": "fetch_page", "args": {"url": "https://example.com"}, "seconds_ago": 90},
     {"result": "fetch_page", "content": "the page's text, or any JSON value", "seconds_ago": 90},
     {"call": "send_email", "args": {"to": "eve@evil.example"}, "answer": "refuse", "seconds_ago": 30}]

A call that needs approval is answered as "answer" says ("approve", the
default, or "refuse", as a person would). A result is checked like a real
one and, if it passes, delivered: it sets its marks and is kept for the
tail scan. A result step may carry "args", the arguments of the call it
answers (see parse_history). "seconds_ago" (default 0) dates a step for
approval memory and the rate limits; steps go oldest first, so a step's
seconds_ago is never more than that of the step before it.

Exit codes: 0 allow, 1 block, 3 ask, 2 an error in the input. With --result,
a result that would be withheld counts as a block. The result is checked as
the proxy checks a reply (Firewall.check_result): with the policy's
secrets.in_results "redact", a result holding a secret passes with the
secret replaced, and the answer says which kinds were replaced.

Arguments: `name=value` passes the value as text, exactly as typed.
`name:=JSON` passes a JSON value: a number (`count:=5`), true or false, a
list or an object. --args takes all arguments as one JSON object. A name
given twice is an error.
"""

from __future__ import annotations

import argparse
import math
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from . import fix_hints, session_limits
from .cli_common import (
    EXIT_ASK,
    EXIT_ERROR,
    EXIT_FAIL,
    EXIT_OK,
    CommandError,
    decode_utf8,
    load_policy,
    print_field,
    read_input,
    shown_call,
    shown_path,
    strict_json,
    without_ref,
)
from .firewall import APPROVAL_UNAVAILABLE, SERVER_NAME, WAITING_FOR_APPROVAL, Decision, Firewall, agent_text
from .policy import Policy, limit_rule
from .session import SINK, MemorySessionStore, is_label
from .policy_errors import quoted, type_name, unknown_keys_message
from .textutil import printable

HELP = "try a call against a policy: which rule decides, and what the agent would be told"
DESCRIPTION = (
    "Try one tool call against a policy without running anything: the secret guard, the policy and its "
    "flow rules, approval memory, the rate limits and the session limits, as for a real call. Nothing is "
    "logged and nobody is asked."
)
EPILOG = """\
arguments:
  name=value      the value as text, exactly as typed
  name:=JSON      a JSON value: count:=5, flag:=true, tags:='["a","b"]'
  --args JSON     all arguments as one JSON object

exit codes:
  0  allow    1  block    3  ask (a person would have to approve)    2  error in the input
  With --result, a result that would be withheld counts as a block.

examples:
  agent-sentinel check policy.json read_file path=notes/todo.txt
  agent-sentinel check policy.json send_email to=eve@evil.example --show-rules
  agent-sentinel check policy.json send_email to=bob@example.com --marks untrusted
  agent-sentinel check policy.json fetch_page url=https://example.com --result page.html
  agent-sentinel check policy.json send_email to=eve@evil.example --history history.json

history file (JSON): earlier calls and results of the session, oldest first
  [{"call": "fetch_page", "args": {"url": "https://example.com"}, "seconds_ago": 90},
   {"result": "fetch_page", "content": "the text the tool returned (or any JSON value)", "seconds_ago": 90},
   {"result": "Bash", "args": {"command": "cat notes.txt"}, "content": "what the command printed", "seconds_ago": 60},
   {"call": "send_email", "args": {"to": "eve@evil.example"}, "answer": "refuse", "seconds_ago": 30}]
  "answer"       what a person said to a call the policy asks about: "approve" (the default) or "refuse"
  "args"         of a result step (optional): the arguments of the call it answers, so that a command
                 section's labels_by_class marks the session by what the command did, and the result is
                 read with the names of those arguments
  "seconds_ago"  when the step happened (default 0), for approval memory and the rate limits; never more
                 than in the step before it, since the steps go oldest first
"""

# What a session mark is called in the reason of a flow block, for a mark given on the command line.
_MARKS_CAUSE = "--marks"
# The most marks one check takes. A policy uses a handful of labels.
MAX_MARKS = 50
# History: the most steps one history holds, how long ago a step may be, and the most lines printed of it.
MAX_HISTORY_STEPS = 1_000
MAX_SECONDS_AGO = 10**7
SHOWN_HISTORY_STEPS = 50
HISTORY_ANSWERS = ("approve", "refuse")
_CALL_STEP_KEYS = ("call", "args", "answer", "seconds_ago")
_RESULT_STEP_KEYS = ("result", "content", "args", "seconds_ago")
MAX_STEP_TOOL_CHARS = 512


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("policy", help="the policy JSON file")
    parser.add_argument("tool", help="the tool name, as the agent would call it (resources/read for a resource)")
    parser.add_argument("arguments", nargs="*", metavar="name=value", help="the call's arguments (see below)")
    parser.add_argument("--args", metavar="JSON", help="the call's arguments as one JSON object")
    parser.add_argument("--proxy", action="store_true",
                        help="answer as a proxy with no way to ask a person (no --approve-with): ask becomes block")
    parser.add_argument("--marks", metavar="LABELS",
                        help="flow marks the session already has, comma-separated (untrusted,private): "
                             "checks the call as if the agent had read such content earlier")
    parser.add_argument("--show-rules", action="store_true",
                        help="list every rule that applies to this tool, and which one decides")
    parser.add_argument("--result", metavar="FILE",
                        help="also scan this file as the tool's result (JSON or text; '-' for stdin)")
    parser.add_argument("--history", metavar="FILE",
                        help="play these earlier calls and results of the session first (a JSON list; see below)")
    parser.add_argument("--server", metavar="NAME",
                        help="answer as a proxy started with --name NAME: the policy's server_labels for that "
                             "server mark the session from the start")


def take_extra_arguments(args: argparse.Namespace, extras: list[str]) -> bool:
    """Accept name=value arguments written after an option. Anything that looks like an option is refused."""
    if any(extra.startswith("-") for extra in extras):
        return False
    args.arguments.extend(extras)
    return True


def run(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    if policy is None:
        return EXIT_ERROR
    if not args.tool:
        raise CommandError("the tool name is empty")
    arguments = call_arguments(args.arguments, args.args)
    marks = parse_marks(args.marks)
    result = _read_result(args.result) if args.result is not None else None
    history = _read_history(args.history) if args.history is not None else []
    check_server_name(args.server, "--server")

    store = MemorySessionStore()
    if marks:
        store.add(marks, _MARKS_CAUSE)
    firewall = Firewall(policy, session_store=store, server_name=args.server)  # no audit log, no approver
    # The marks of server_labels come from a proxy only: one with --proxy, or named with --server.
    proxied = args.proxy or args.server is not None
    if proxied:
        deliver_server_marks(firewall)
    played = replay_history(firewall, history, as_proxy=args.proxy, server_marks=proxied)
    # A proxy with no way to ask refuses an ask at once, before the rate and session limits count it.
    decision = firewall.check_call(args.tool, arguments, defer_ask=not args.proxy)
    outcome = outcome_of(decision, as_proxy=args.proxy)

    if played:
        _print_history(played)
    print(shown_call(args.tool, arguments))
    _print_decision(policy, args.tool, arguments, decision, outcome, as_proxy=args.proxy)
    _print_session_note(policy, marks, bool(history), proxied, policy.server_marks(args.server) if proxied else ())
    if args.show_rules:
        _print_rules(policy, firewall, args.tool, arguments, decision)

    result_blocked = False
    if result is not None:
        content, how = result
        scanned = firewall.check_result(args.tool, content, call_id=decision.call_id).decision
        result_blocked = not scanned.allowed
        _print_result(firewall, args.tool, scanned, f"{shown_path(args.result)}, read as {how}", outcome)

    if outcome == "block" or result_blocked:
        return EXIT_FAIL
    return EXIT_ASK if outcome == "ask" else EXIT_OK


# ---- reading what was typed ---------------------------------------------------------

def call_arguments(pairs: list[str], args_json: str | None) -> dict[str, Any]:
    """The call's arguments, from --args JSON and name=value / name:=JSON pairs. CommandError if they are wrong."""
    arguments: dict[str, Any] = {}
    if args_json is not None:
        value = strict_json(args_json, "--args")
        if not isinstance(value, dict):
            raise CommandError('--args must be a JSON object, such as \'{"path": "notes.txt"}\'')
        arguments.update(value)
    for pair in pairs:
        name, value = _one_argument(pair)
        if name in arguments:
            raise CommandError(f"the argument {quoted(name, limit=60)} is given twice")
        arguments[name] = value
    return arguments


def _one_argument(pair: str) -> tuple[str, Any]:
    """(name, value) from "name=value" (the value as text) or "name:=JSON" (the value as JSON reads it)."""
    equals = pair.find("=")
    if equals < 0:
        raise CommandError(
            f"write each argument as name=value, or name:=JSON for a number, true or false, a list or an "
            f"object; got {quoted(pair, limit=60)}"
        )
    is_json = equals > 0 and pair[equals - 1] == ":"
    name = pair[: equals - 1] if is_json else pair[:equals]
    if not name:
        raise CommandError(f"an argument has no name: {quoted(pair, limit=60)}")
    text = pair[equals + 1:]
    if not is_json:
        return name, text
    return name, strict_json(text, f"the value of {printable(name, limit=60)}")


def parse_marks(text: str | None) -> list[str]:
    """The labels of --marks ("untrusted,private"). CommandError for a word that is not a label, or "sink"."""
    if text is None:
        return []
    marks = [part.strip() for part in text.split(",") if part.strip()]
    if not marks:
        raise CommandError("--marks needs at least one label, such as --marks untrusted")
    if len(marks) > MAX_MARKS:
        raise CommandError(f"--marks takes at most {MAX_MARKS} labels")
    for mark in marks:
        check_mark(mark, "--marks")
    return list(dict.fromkeys(marks))


def check_mark(mark: Any, where: str) -> None:
    """Raise CommandError if `mark` cannot be a session mark."""
    if mark == SINK:
        raise CommandError(f"{where}: 'sink' describes a tool, not content, so it is never a mark")
    if not is_label(mark):
        raise CommandError(
            f"{where}: {quoted(mark, limit=60)} is not a label (a lowercase word of letters, digits, '_' and "
            "'-', starting with a letter, at most 40 characters)"
        )


def _read_result(path: str) -> tuple[Any, str]:
    """The content of --result: a JSON object or list as such (as the proxy scans a reply), else the text."""
    text = decode_utf8(read_input(path), path if path != "-" else "stdin")
    try:
        value = strict_json(text, "result")
    except CommandError:
        return text, "text"
    return (value, "JSON") if isinstance(value, (dict, list)) else (text, "text")


# ---- --history: earlier calls and results of the session -------------------------------------

@dataclass(frozen=True)
class HistoryStep:
    """One step of a history: an earlier call ("call") or a result delivered to the agent ("result")."""

    kind: str
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    answer: str = "approve"  # a call that needs approval: what the person answers
    content: Any = None  # a result: the text, or a JSON value
    call_args: dict[str, Any] | None = None  # a result: the arguments of the call it answers, when given
    seconds_ago: float = 0.0


def _read_history(path: str) -> list[HistoryStep]:
    label = "stdin" if path == "-" else printable(path, limit=300)
    data = strict_json(decode_utf8(read_input(path), label), label)
    try:
        return parse_history(data, "the history")
    except CommandError as exc:
        raise CommandError(f"{label}: {exc}") from exc


def parse_history(data: Any, where: str, most: int = MAX_HISTORY_STEPS) -> list[HistoryStep]:
    """Read a history: a list of steps, oldest first. CommandError, naming the step, for any mistake.

    {"call": TOOL, "args": {...}, "answer": "approve" | "refuse", "seconds_ago": N}
        an earlier call; "answer" is used when the policy says ask (default "approve").
    {"result": TOOL, "content": TEXT or JSON, "args": {...}, "seconds_ago": N}
        a result of TOOL that reached the agent (if the policy lets it through).
        "args" (optional) are the arguments of the call it answers: a command
        section's labels_by_class then marks the session by what the command
        did, and the result is read with the names of those arguments.
    "seconds_ago" (default 0) dates the step, for approval memory and the
    rate limits (both count in seconds). Steps go oldest first: a step's
    seconds_ago is never more than the one before it.
    """
    if not isinstance(data, list):
        raise CommandError(f"{where} must be a list of steps ([ ... ]), got {type_name(data)}")
    if len(data) > most:
        raise CommandError(f"{where} has {len(data)} steps; at most {most} are read")
    steps = [_history_step(entry, f"{where}[{index}]") for index, entry in enumerate(data)]
    for index in range(1, len(steps)):
        before, step = steps[index - 1].seconds_ago, steps[index].seconds_ago
        if step > before:
            raise CommandError(
                f"{where}[{index}].seconds_ago is {step:g}, more than the {before:g} of the step before it: "
                "steps go oldest first"
            )
    return steps


def _history_step(entry: Any, where: str) -> HistoryStep:
    if not isinstance(entry, dict):
        raise CommandError(f"{where} must be an object, got {type_name(entry)}")
    kinds = [kind for kind in ("call", "result") if kind in entry]
    if len(kinds) != 1:
        raise CommandError(f'{where} must have exactly one of "call" (an earlier call) or "result" (a result)')
    kind = kinds[0]
    keys = _CALL_STEP_KEYS if kind == "call" else _RESULT_STEP_KEYS
    unknown = [str(key) for key in entry if key not in keys]
    if unknown:
        raise CommandError(unknown_keys_message(where, unknown, keys))
    tool = entry[kind]
    if not isinstance(tool, str) or not 0 < len(tool) <= MAX_STEP_TOOL_CHARS:
        raise CommandError(f"{where}.{kind} must be a tool name (text of 1 to {MAX_STEP_TOOL_CHARS} characters)")
    seconds_ago = entry.get("seconds_ago", 0)
    if isinstance(seconds_ago, bool) or not isinstance(seconds_ago, (int, float)) or not (
        math.isfinite(seconds_ago) and 0 <= seconds_ago <= MAX_SECONDS_AGO
    ):
        raise CommandError(
            f"{where}.seconds_ago must be a number from 0 to {MAX_SECONDS_AGO}, got {quoted(seconds_ago)}"
        )
    if kind == "result":
        if "content" not in entry:
            raise CommandError(f'{where} needs "content": the text or JSON value the tool returned')
        call_args = entry.get("args")
        if call_args is not None and not isinstance(call_args, dict):
            raise CommandError(f"{where}.args must be an object of arguments, got {type_name(call_args)}")
        return HistoryStep(kind, tool, content=entry["content"], call_args=call_args, seconds_ago=float(seconds_ago))
    args = entry.get("args", {})
    if not isinstance(args, dict):
        raise CommandError(f"{where}.args must be an object of arguments, got {type_name(args)}")
    answer = entry.get("answer", "approve")
    if answer not in HISTORY_ANSWERS:
        raise CommandError(f'{where}.answer must be "approve" or "refuse", got {quoted(answer)}')
    return HistoryStep(kind, tool, args=args, answer=answer, seconds_ago=float(seconds_ago))


def check_server_name(server: Any, where: str) -> None:
    """Raise CommandError unless `server` is None or a name `proxy --name` takes (firewall.SERVER_NAME)."""
    if server is not None and (not isinstance(server, str) or not SERVER_NAME.fullmatch(server)):
        raise CommandError(f"{where} must be a server name as proxy --name takes it: 1 to 64 letters, digits, '_', "
                           f"'-' or '.', got {quoted(server, limit=60)}")


def deliver_server_marks(firewall: Firewall) -> None:
    """Set the marks the policy's server_labels give the firewall's server, as a proxy does before any call:
    every reply of the server sets them, and its reply to initialize comes first."""
    firewall.mark_delivered("initialize", frozenset(), channel="reply to initialize", server_marks=True)


def replay_history(
    firewall: Firewall, steps: list[HistoryStep], as_proxy: bool = False, server_marks: bool = False
) -> list[str]:
    """Play the steps against the firewall, in order, as they happened; one line per step, for printing.

    A call is checked (and counted) like a real one; one that needs approval
    is answered by a person as the step says, or, `as_proxy` (a proxy with no
    way to ask), refused at once and not counted, as that proxy refuses it.
    A result is checked like a real one and, if it passes, delivered (its
    marks, its tail; with `server_marks`, those of server_labels too, as a
    proxy delivers everything its server sends). Each step happens
    `seconds_ago` before now on the firewall's clocks: the one approval memory
    reads, and the one the rate limits count calls in (so calls an hour apart
    do not count as made in the same minute). Afterwards it is now again.
    """
    now, ticks = time.time(), time.monotonic()
    lines = []
    try:
        for step in steps:
            firewall._clock = lambda at=now - step.seconds_ago: at
            firewall._rate_clock = lambda at=ticks - step.seconds_ago: at
            lines.append(_played(firewall, step, as_proxy, server_marks))
    finally:
        firewall._clock, firewall._rate_clock = time.time, None
    return lines


def _played(firewall: Firewall, step: HistoryStep, as_proxy: bool = False, server_marks: bool = False) -> str:
    when = f" ({step.seconds_ago:g} s ago)" if step.seconds_ago else ""
    if step.kind == "call":
        decision = firewall.check_call(step.tool, step.args, defer_ask=not as_proxy)
        if decision.pending:
            approved = step.answer == "approve"
            decision = firewall.finish_approval(decision, approved, "the history", asked=True)
            what = ("ask, approved" if decision.allowed else
                    "ask, refused by the person" if not approved else "ask, approved, then blocked")
        else:
            what = "allow" if decision.allowed else "block"
            if decision.approval:
                what += f", {decision.approval}"
        rule = f" ({printable(decision.rule, limit=120)})" if decision.rule else ""
        return f"call {shown_call(step.tool, step.args)}{when} -> {what}{rule}"
    names = [name for name in step.call_args or () if isinstance(name, str)]
    checked = firewall.check_result(step.tool, step.content, parameter_names=names)
    decision = checked.decision
    if not decision.allowed:
        return f"result of {printable(step.tool, limit=80)}{when} -> withheld ({printable(decision.rule, limit=120)})"
    firewall.mark_delivered(step.tool, args=step.call_args, decision=decision, server_marks=server_marks)
    marks = sorted(firewall.session_marks().labels)
    shown = f"; the session's marks: {', '.join(marks)}" if marks else ""
    return f"result of {printable(step.tool, limit=80)}{when} -> delivered{shown}"


def _print_history(lines: list[str]) -> None:
    print(f"History ({len(lines)} step(s), played first):")
    for line in lines[:SHOWN_HISTORY_STEPS]:
        print(f"  {line}")
    if len(lines) > SHOWN_HISTORY_STEPS:
        print(f"  ... and {len(lines) - SHOWN_HISTORY_STEPS} more")
    print()


# ---- the answer -----------------------------------------------------------------------

def outcome_of(decision: Decision, as_proxy: bool) -> str:
    """"allow", "ask" or "block". As a proxy with no approver, a call that needs approval is refused."""
    if decision.allowed:
        return "allow"
    if decision.pending:
        return "block" if as_proxy else "ask"
    return "block"


def _rule_text(decision: Decision) -> str:
    rule = printable(decision.rule, limit=200) if decision.rule else "(none)"
    if decision.matched_arg is not None:
        rule += f", argument '{printable(decision.matched_arg, limit=80)}'"
    return rule


def _print_decision(
    policy: Policy, tool: str, arguments: dict[str, Any], decision: Decision, outcome: str, as_proxy: bool
) -> None:
    verdict = outcome.upper()
    if as_proxy and decision.approval == APPROVAL_UNAVAILABLE:
        verdict += " (the rule says ask, and a proxy with no way to ask a person refuses it)"
    print_field("verdict", verdict)
    print_field("rule", _rule_text(decision))
    described = policy.describe_rule(decision.rule) if decision.rule else None
    if described:
        print_field("the rule", printable(described, limit=1000))
    # A pending decision's reason ends with "; waiting for approval": true in the proxy, not here.
    print_field("reason", printable(decision.reason.removesuffix(WAITING_FOR_APPROVAL), limit=1000))
    if outcome == "ask":
        print_field("then", (
            "a person must approve the call. The library asks the Firewall's approver; the proxy asks only when "
            "it has a way to (--approve-with), and refuses the call otherwise (see --proxy)."
        ))
        return
    if outcome == "block":
        print_field("agent sees", f"{_agent_sees(decision.public_reason)} (ref <random>)")
        hint = fix_hints.fix_hint(
            decision.rule, tool=tool, matched_arg=decision.matched_arg, args=arguments, policy=policy
        )
        print_field("to allow", hint)


def _print_session_note(
    policy: Policy, marks: list[str], has_history: bool = False, proxied: bool = False,
    server_marks: Iterable[str] = (),
) -> None:
    """Notes on the session the call was checked in. `proxied`: checked as a proxy (--proxy or --server), whose
    server gave the session `server_marks` (server_labels)."""
    server_marks = sorted(server_marks)
    if marks and not policy.flows:
        print("Note: the policy has no flow rules, so --marks changes nothing.")
    elif policy.flows and not marks and not has_history and not server_marks:
        print("Note: checked as the first call of a session. Flow rules apply once the agent has read content; "
              "try --marks untrusted (or the labels your flow rules name), or --history.")
    if policy.flows and server_marks:
        print(f"Note: the session has the marks server_labels gives this proxy's server from its first reply on: "
              f"{', '.join(server_marks)}.")
    elif policy.flows and policy.server_labels and not proxied:
        print("Note: the policy's server_labels mark the session in a proxy, by the name it runs under (--name); "
              "checked without one, they set no mark: try --server NAME.")


def _print_result(firewall: Firewall, tool: str, scanned: Decision, source: str, call_outcome: str) -> None:
    policy = firewall.policy
    print(f"\nResult ({source}):")
    if not scanned.allowed:
        print_field("verdict", "BLOCK (withheld from the agent)")
    elif scanned.redacted:
        print_field("verdict", f"PASS, with what looks like a secret replaced ({', '.join(scanned.redacted)})")
    else:
        print_field("verdict", "PASS")
    if scanned.rule:
        print_field("rule", printable(scanned.rule, limit=200))
    print_field("reason", printable(scanned.reason, limit=1000))
    for number, finding in enumerate(scanned.findings):
        excerpt = printable(firewall.shown_excerpt(finding.excerpt), limit=200)
        print_field("findings" if number == 0 else "", f"[{finding.severity.upper():6}] {finding.rule}: {excerpt}")
    if scanned.notice:
        print_field("agent sees", f"first: {without_ref(scanned.notice)} (ref <random>)")
    if scanned.marks and policy.flows:
        marks = ", ".join(sorted(scanned.marks))
        print_field("marks", f"once delivered, the session gets: {marks} (injection.mark_at)")
    if not scanned.allowed:
        print_field("agent sees", f"{_agent_sees(scanned.public_reason)} (ref <random>)")
        print_field("to allow", fix_hints.fix_hint(scanned.rule, tool=tool, policy=policy))
    if call_outcome == "block":
        print("Note: the call itself is blocked, so no result would come back.")


# ---- --show-rules ---------------------------------------------------------------------

def _print_rules(policy: Policy, firewall: Firewall, tool: str, arguments: dict[str, Any], decision: Decision) -> None:
    """Every part of the policy that applies to a call of `tool`, and which one decided this call.

    For the operator: it names rules and patterns.
    """
    print(f"\nWhat applies to '{printable(tool, limit=80)}' (checked in this order):")
    if policy.secrets_in_arguments == "block":
        print("  secrets  the secret guard: a call carrying what looks like a key or token is refused")
    else:
        print("  secrets  the secret guard is off (secrets.in_arguments is allow)")
    for index, deny in enumerate(policy.deny_args):
        print(f"  deny_args[{index}]  policy-wide, for every tool: {printable(deny.describe(), limit=300)}")
    _print_tool_rules(policy, tool)
    # A command section's labels_by_class adds labels by what this call's command does.
    labels = firewall.tool_labels(tool) | policy.command_labels(tool, arguments)
    for index, flow in enumerate(policy.flows):
        if flow.then in labels:
            applies = "applies to this tool"
        else:
            applies = f"does not apply: the tool is not labelled '{flow.then}'"
        print(f"  flows[{index}]  {printable(flow.describe(), limit=600)} ({applies})")
        for number, entry in enumerate(flow.unless_args):
            print(f"    flows[{index}].unless_args[{number}]  {printable(entry.describe(), limit=300)}")
    for bucket, per_minute in policy.call_limits(tool):
        print(f"  {printable(limit_rule(bucket), limit=200)}  at most {per_minute} call(s) per minute")
    for limit in session_limits.limits_for(policy, tool, labels):
        described = policy.describe_rule(limit.rule) or limit.rule
        print(f"  {printable(limit.rule, limit=200)}  {printable(described, limit=300)}")
    if labels:
        print(f"  flow labels: {', '.join(sorted(labels))}")
    if policy.flows and policy.classify_by_annotations:
        print("  (a server's MCP tool annotations can add flow labels when the proxy runs; check cannot see them)")
    if policy.hide_blocked_tools and policy.tool_level_action(tool) == "block":
        print("  hide_blocked_tools: the proxy leaves this tool out of the tool list it shows the agent")
    print(f"Decided by: {_rule_text(decision)}")


def _print_tool_rules(policy: Policy, tool: str) -> None:
    """The tool rules whose name matches `tool`, and their argument rules, in the policy's terms.

    How the policy chooses among them (policy._deciding_rules): an exact name
    wins outright; otherwise every matching wildcard is checked and the
    strictest answer wins. This only describes that; the decision itself
    comes from the Firewall.
    """
    matching =[rule for rule in policy.tools if rule.matches(tool)]
    exact = next((rule for rule in matching if not rule.is_glob), None)
    if not matching:
        print(f"  default  no tool rule matches, so the default decides: {policy.default}")
        return
    for rule in matching:
        name = printable(rule.name, limit=120)
        if not rule.is_glob:
            role = "exact rule: decides (an exact rule beats every wildcard)"
        elif exact is not None:
            role = ("wildcard: the exact rule decides, so only its deny rules and command checks apply "
                    "(and its labels and rate limit)")
        else:
            role = "wildcard: checked; when several match, the strictest answer wins"
        print(f"  tools.{name}  action {rule.action}; {role}")
        for index, deny in enumerate(rule.deny_args):
            print(f"    tools.{name}.deny_args[{index}]  {printable(deny.describe(), limit=300)}")
        if rule.command is not None:
            print(f"    tools.{name}.command  {printable(rule.command.describe(), limit=400)}")
        if rule.is_glob and exact is not None:
            continue
        for index, allow in enumerate(rule.allow_args):
            print(f"    tools.{name}.allow_args[{index}]  {printable(allow.describe(), limit=300)}")
        if rule.other_args == "block":
            print(f"    tools.{name}.other_args  an argument that no allow rule names is refused")


def _agent_sees(public_reason: str) -> str:
    """What the agent reads for a block (the proxy's, the hook's and guard's words), without the random ref."""
    return printable(agent_text(without_ref(public_reason)), limit=500)
