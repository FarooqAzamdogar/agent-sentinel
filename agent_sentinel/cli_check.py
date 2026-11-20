"""`agent-sentinel check POLICY TOOL [name=value ...]`: try one call against a policy, without running anything.

    agent-sentinel check policy.json read_file path=notes/todo.txt
    agent-sentinel check policy.json send_email to=eve@evil.example --show-rules
    agent-sentinel check policy.json search count:=5 --args '{"tags": ["a", "b"]}'
    agent-sentinel check policy.json send_email to=bob@example.com --marks untrusted
    agent-sentinel check policy.json fetch_page url=https://example.com --result page.html

The call goes through the same checks as a real one, in the same order: the
secret guard, the policy (deny rules, tool rules, the default, and the flow
rules for the marks given with --marks), and the rate limits. Nothing is
logged and nobody is asked: a call that needs approval is reported as "ask".
The answer names the rule that decided, what the agent would be told, and,
for a refusal, what the operator could change.

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
from typing import Any

from . import fix_hints
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
from .firewall import WAITING_FOR_APPROVAL, Decision, Firewall, agent_text
from .policy import Policy, limit_rule
from .session import SINK, MemorySessionStore, is_label
from .policy_errors import quoted
from .textutil import printable

HELP = "try a call against a policy: which rule decides, and what the agent would be told"
DESCRIPTION = (
    "Try one tool call against a policy without running anything: the secret guard, the policy and its "
    "flow rules, and the rate limits, as for a real call. Nothing is logged and nobody is asked."
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
"""

# What a session mark is called in the reason of a flow block, for a mark given on the command line.
_MARKS_CAUSE = "--marks"
# The most marks one check takes. A policy uses a handful of labels.
MAX_MARKS = 50


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

    store = MemorySessionStore()
    if marks:
        store.add(marks, _MARKS_CAUSE)
    firewall = Firewall(policy, session_store=store)  # no audit log, no approver
    decision = firewall.check_call(args.tool, arguments, defer_ask=True)
    outcome = outcome_of(decision, as_proxy=args.proxy)

    print(shown_call(args.tool, arguments))
    _print_decision(policy, args.tool, arguments, decision, outcome, as_proxy=args.proxy)
    _print_session_note(policy, marks)
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
    if decision.pending and as_proxy:
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


def _print_session_note(policy: Policy, marks: list[str]) -> None:
    if marks and not policy.flows:
        print("Note: the policy has no flow rules, so --marks changes nothing.")
    elif policy.flows and not marks:
        print("Note: checked as the first call of a session. Flow rules apply once the agent has read content; "
              "try --marks untrusted (or the labels your flow rules name).")


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
        print(f"  flows[{index}]  {flow.describe()} ({applies})")
    for bucket, per_minute in policy.call_limits(tool):
        print(f"  {printable(limit_rule(bucket), limit=200)}  at most {per_minute} call(s) per minute")
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
