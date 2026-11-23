"""What an operator can do about a block: one hint for each kind of rule.

`explain` shows the hint for one audit record ("To allow: ..."), `report` for
each of the most common reasons ("How to fix: ..."), and `check` for a call
that it tried. The hints name rules and settings, so they are for the operator
only, never for the agent.

A rule id comes from an audit record, and an audit log is a plain file that
anyone with access can edit, so `classify` accepts any value and never
raises; an id it does not know is reported as such. Every part of a hint that
comes from the record (a tool name, an argument name, a rule name) is made
printable here, so a hint can be printed as it is.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .elicitation import RULE_FORM as RULE_ELICITATION_FORM, RULE_URL as RULE_ELICITATION_URL
from .policy import (
    IDENTICAL_CALLS_LIMIT,
    SESSION_CALLS_LIMIT,
    SINK_BYTES_LIMIT,
    RULE_AUDIT,
    RULE_CALL_TIMEOUT,
    RULE_CALLER,
    RULE_DEFAULT,
    RULE_HOOK_CONFIG_CHANGES,
    RULE_HOOK_FAILED,
    RULE_INCLUDE_CONTEXT,
    RULE_INDEX,
    RULE_INJECTION,
    RULE_MALFORMED,
    RULE_QUARANTINE,
    RULE_SCHEMA_ARGUMENTS,
    RULE_SCHEMA_REMOTE_REFS,
    RULE_SCHEMA_RESULT,
    RULE_SECRETS,
    RULE_SECRETS_CANARIES,
    RULE_SECRETS_IN_RESULTS,
    RULE_SECRETS_KNOWN_VALUES,
    RULE_SESSION,
    RULE_UNSCANNABLE,
    Policy,
)
from .textutil import printable

# A rule id longer than this is not one the firewall writes (tool names in the log are at most 200 characters).
MAX_RULE_ID_CHARS = 600

# A position as rule ids write it (policy.RULE_INDEX): "[3]", no leading zeros, at most nine digits.
_INDEX = RULE_INDEX
_TOOL_PART = re.compile(
    rf"tools\.(.+)\.(deny_args{_INDEX}|allow_args{_INDEX}|other_args|max_calls_per_minute|max_calls_per_session"
    rf"|max_distinct{_INDEX})"
)
# A tool rule's command section: tools.Bash.command.network, tools.Bash.command.unreadable.
_TOOL_COMMAND = re.compile(r"tools\.(.+)\.command\.([a-z_]{1,20})")

# The fixed rule ids (policy.RULE_*) and the kind of hint each gets.
_FIXED_KINDS = {
    RULE_DEFAULT: "default",
    "limits.max_calls_per_minute": "limit_global",
    SESSION_CALLS_LIMIT: "session_limit",
    SINK_BYTES_LIMIT: "session_limit",
    IDENTICAL_CALLS_LIMIT: "session_limit",
    RULE_SECRETS: "secrets",
    RULE_SECRETS_IN_RESULTS: "secrets_results",
    RULE_SECRETS_CANARIES: "canary",
    RULE_SECRETS_KNOWN_VALUES: "known_value",
    RULE_INJECTION: "injection",
    RULE_UNSCANNABLE: "unscannable",
    RULE_MALFORMED: "malformed",
    RULE_QUARANTINE: "quarantine",
    RULE_SESSION: "session",
    RULE_CALLER: "caller",
    RULE_HOOK_FAILED: "hook_failed",
    RULE_HOOK_CONFIG_CHANGES: "config_change",
    RULE_ELICITATION_URL: "elicitation",
    RULE_ELICITATION_FORM: "elicitation",
    RULE_AUDIT: "audit_required",
    RULE_SCHEMA_ARGUMENTS: "schema_arguments",
    RULE_SCHEMA_RESULT: "schema_result",
    RULE_SCHEMA_REMOTE_REFS: "schema_remote_refs",
    RULE_INCLUDE_CONTEXT: "include_context",
    RULE_CALL_TIMEOUT: "call_timeout",
}
_INDEXED_KINDS = (
    (re.compile(rf"deny_args{_INDEX}"), "deny_global"),
    (re.compile(rf"flows{_INDEX}"), "flow"),
    (re.compile(rf"flows{_INDEX}\.(unless_args{_INDEX}|other_args)"), "flow_exception"),
    (re.compile(rf"limits\.max_distinct{_INDEX}"), "session_limit"),
    (re.compile(rf"secrets\.patterns{_INDEX}"), "secret_pattern"),
)
_PART_KINDS = {"other_args": "other_args", "max_calls_per_minute": "limit_tool",
               "max_calls_per_session": "session_limit"}

# Kinds whose block protects against an attack rather than reflecting a gap in the
# policy. `suggest` never proposes to loosen them; `report` says so next to them.
PROTECTIVE_KINDS = frozenset({
    "deny_global", "deny_tool", "secrets", "secrets_results", "canary", "known_value", "secret_pattern",
    "injection", "unscannable", "malformed", "quarantine", "session", "flow", "flow_exception", "hook_failed",
    "command", "config_change", "elicitation", "audit_required",
    "schema_arguments", "schema_result", "schema_remote_refs", "include_context",
})


@dataclass(frozen=True)
class RuleId:
    """What a rule id names. `kind` is one of the keys used below; `tool_rule` names the tool rule,
    `name` a server_requests or client_requests rule, `text` is the id itself (made printable)."""

    kind: str
    text: str = ""
    tool_rule: str | None = None
    name: str | None = None


def classify(rule: Any) -> RuleId:
    """Read a rule id from an audit record. Never raises: anything unexpected is kind "none" or "unknown"."""
    if not isinstance(rule, str) or not rule:
        return RuleId("none")
    text = printable(rule, limit=200)
    if len(rule) > MAX_RULE_ID_CHARS:
        return RuleId("unknown", text)
    if rule in _FIXED_KINDS:
        return RuleId(_FIXED_KINDS[rule], text)
    for pattern, kind in _INDEXED_KINDS:
        if pattern.fullmatch(rule):
            return RuleId(kind, text)
    for section, kind in (("server_requests.", "server_request"), ("client_requests.", "client_request")):
        if rule.startswith(section) and len(rule) > len(section):
            return RuleId(kind, text, name=rule[len(section):])
    command = _TOOL_COMMAND.fullmatch(rule)
    if command:
        return RuleId("command", text, tool_rule=command.group(1), name=command.group(2))
    part = _TOOL_PART.fullmatch(rule)
    if part:
        tool_rule, which = part.group(1), part.group(2)
        kind = _PART_KINDS.get(which)
        if kind is None:
            kind = ("deny_tool" if which.startswith("deny_args") else
                    "session_limit" if which.startswith("max_distinct") else "allow_tool")
        return RuleId(kind, text, tool_rule=tool_rule)
    if rule.startswith("tools.") and len(rule) > len("tools."):
        return RuleId("tool", text, tool_rule=rule[len("tools."):])
    return RuleId("unknown", text)


def _name(text: Any) -> str:
    return f"'{printable(text, limit=80)}'"


def _json_name(text: Any) -> str:
    """A tool name as it would be written in a policy file: in double quotes, with JSON escapes."""
    return printable(json.dumps(str(text), ensure_ascii=False), limit=100)


def fix_hint(
    rule: Any,
    *,
    tool: Any = None,
    matched_arg: Any = None,
    args: Any = None,
    policy: Policy | None = None,
    approval: Any = None,
) -> str:
    """One or two sentences on what the operator can do about a block decided by `rule`.

    tool:        the tool that was called, if known (from the record)
    matched_arg: the argument the rule matched, if known
    args:        the call's arguments, if they were logged; tells "missing" from "not accepted"
    policy:      the current policy, if known; lets the hint say what a tool rule's action is
    approval:    the record's "approval": the rule said ask, and the call was "refused" by the
                 person asked, or nobody could be asked ("unavailable")
    """
    rule_id = classify(rule)
    if approval == "refused (repeat)":
        return (
            "The policy sends this call to a person, and it was refused without asking: a person refused this "
            "same call a short while ago, or refused several calls of this tool (approvals.refusal_window_seconds, "
            "approvals.max_refusals_per_tool). That stops a hijacked agent from asking until someone gives in. "
            "If a refusal was a mistake, start a new session (restart the client or the proxy), or wait."
        )
    if approval == "refused":
        return (
            "The policy sends this call to a person, and it was refused there: the person said no, or did not "
            "answer in time. That is the policy working as meant; change the rule only if such calls need no review."
        )
    if approval == "unavailable":
        return (
            "The policy sends this call to a person, and nobody could be asked; the reason says why. The proxy "
            "needs an approver that can ask (--approve-with), and refuses when it fails or too many calls wait; "
            "the Claude Code hook refuses in a permission mode that shows no prompt, such as bypassPermissions, "
            "and for a call a mode runs without one (SubagentHandback in auto mode). "
            "Make sure someone can be asked rather than allowing the call."
        )
    argument = f" in argument {_name(matched_arg)}" if isinstance(matched_arg, str) else ""
    kind = rule_id.kind

    if kind == "default":
        return _default_hint(tool)
    if kind == "tool":
        return _tool_rule_hint(rule_id.tool_rule or "", tool, policy)
    if kind == "deny_global":
        return (
            f"The policy-wide deny rule {rule_id.text} matched{argument}. It applies to every tool, and no tool "
            "rule can lift it. If the value is harmless, narrow that rule or move it into the deny_args of the "
            "tools it is meant for; if not, the block is doing its job."
        )
    if kind == "deny_tool":
        return (
            f"A deny rule of the tool rule {_name(rule_id.tool_rule)} matched{argument}. If the value is harmless, "
            "narrow that rule; if not, the block is doing its job."
        )
    if kind == "allow_tool":
        return _allow_rule_hint(rule_id.tool_rule or "", matched_arg, args)
    if kind == "other_args":
        which = _name(matched_arg) if isinstance(matched_arg, str) else "the argument"
        return (
            f"Argument {which} is not named in the allow_args of the tool rule {_name(rule_id.tool_rule)}, whose "
            'other_args is "block". Add an allow_args entry for it ("optional": true if it may be left out).'
        )
    if kind in ("limit_global", "limit_tool"):
        which = (
            "the limit for all tools together (limits.max_calls_per_minute)" if kind == "limit_global"
            else f"the rate limit of the tool rule {_name(rule_id.tool_rule)} (max_calls_per_minute)"
        )
        return (
            f"The call reached {which}. Raise it if this pace is normal for the agent. Each proxy, and each "
            "Firewall, counts its calls on its own; the Claude Code hook counts them per Claude Code session."
        )
    if kind in ("server_request", "client_request"):
        section = "server_requests" if kind == "server_request" else "client_requests"
        sender = "server" if kind == "server_request" else "client"
        return (
            f"The {section} rule {_name(rule_id.name)} refuses this message from the {sender}. Set it to "
            f'"allow" if the {sender} needs it.'
        )
    if kind == "flow":
        return _flow_hint(rule_id.text, rule, policy)
    if kind == "command":
        return _command_hint(rule_id)
    if kind == "flow_exception":
        return _flow_exception_hint(rule_id.text, rule, matched_arg, policy)
    if kind == "session_limit":
        whose = f"the tool rule {_name(rule_id.tool_rule)}" if rule_id.tool_rule else "the policy's limits"
        return (
            f"The call reached the session limit {rule_id.text} of {whose}. It counts for as long as the session "
            "lasts (a proxy's process; a Claude Code session), so a slow or piecemeal leak cannot stay under a "
            "rate limit. Raise it if such a session is normal; a new session starts the count again."
        )
    return _FIXED_HINTS.get(kind, _FIXED_HINTS["unknown"])


def _command_hint(rule_id: RuleId) -> str:
    rule = _name(rule_id.tool_rule)
    if rule_id.name == "unreadable":
        return (
            f"The command section of the tool rule {rule} could not read the command with certainty (an unclosed "
            "quote, a heredoc, a program chosen at run time, a very long or deeply nested command). Write the "
            'command more plainly; "unreadable": "ask" in that section sends such commands to a person instead.'
        )
    return (
        f"The command section of the tool rule {rule} found a command in the class {_name(rule_id.name)}. If it is "
        "harmless, move the class from deny_classes to ask_classes, or (for network and install only) add the "
        'program to allow_programs, such as "git push"; if not, the block is doing its job.'
    )


def _default_hint(tool: Any) -> str:
    drafts = "`agent-sentinel suggest` drafts such rules from a monitor-mode log."
    if not isinstance(tool, str):
        return (
            'No tool rule matched, so the default decided. Add an exact rule to "tools" for each tool the agent '
            f"should use. {drafts}"
        )
    return (
        f"No tool rule matches {_name(tool)}, so the default decided. If the agent should use this tool, add an "
        f'exact rule for it to "tools", such as {_json_name(tool)}: "allow" (or "ask", to have a person approve '
        f"each call). {drafts}"
    )


def _tool_rule_hint(rule_name: str, tool: Any, policy: Policy | None) -> str:
    is_wildcard = "*" in rule_name
    exact_rule = f'{_json_name(tool)}: "ask"' if isinstance(tool, str) else 'an exact rule such as "tool_name": "ask"'
    action = None
    if policy is not None:
        action = next((rule.action for rule in policy.tools if rule.name == rule_name), "missing")
    if action == "missing":
        return (
            f"The policy has no tool rule {_name(rule_name)} now; the record comes from an earlier version of it, "
            "or from another policy."
        )
    if action == "allow":
        return (
            f"The tool rule {_name(rule_name)} allows the tool now: the record comes from an earlier version of "
            "the policy, or a person refused the call when asked."
        )
    if action == "ask":
        return (
            f"The tool rule {_name(rule_name)} says ask, and no person approved the call. The proxy needs an "
            "approver to ask (--approve-with); without one an ask is refused. The Claude Code hook asks in Claude "
            'Code\'s own prompt, but refuses in bypassPermissions mode. Change the action to "allow" only if these '
            "calls need no review."
        )
    if action == "block":
        if is_wildcard:
            return (
                f"The wildcard rule {_name(rule_name)} blocks it. An exact rule beats every wildcard: add "
                f'{exact_rule} (or "allow") to "tools" if this one tool should be usable.'
            )
        return (
            f'The tool rule {_name(rule_name)} blocks this tool. Change its action to "ask" or "allow" if the agent '
            "should use it."
        )
    wildcard_note = f"; or add an exact rule such as {exact_rule}, which beats every wildcard" if is_wildcard else ""
    return (
        f"The tool rule {_name(rule_name)} decided: it says block, or it says ask and no person approved the call. "
        f"Change its action{wildcard_note}."
    )


def _allow_rule_hint(rule_name: str, matched_arg: Any, args: Any) -> str:
    which = _name(matched_arg) if isinstance(matched_arg, str) else "an argument"
    rule = _name(rule_name)
    if isinstance(args, dict) and isinstance(matched_arg, str) and matched_arg not in args:
        return (
            f'The tool rule {rule} requires argument {which}, and the call left it out. Mark that allow_args entry '
            '"optional": true if the argument may be left out.'
        )
    missing = "" if isinstance(args, dict) else ' (or it was left out: then mark the entry "optional": true)'
    return (
        f"The value of argument {which} is not one that the tool rule {rule} accepts{missing}. An allow rule must "
        "accept the WHOLE value: widen it if this value should pass, and try it first with `agent-sentinel check`."
    )


def _flow_hint(text: str, rule: Any, policy: Policy | None) -> str:
    described = policy.describe_rule(rule) if policy is not None else None
    what = f" ({printable(described, limit=300)})" if described else ""
    return (
        f"Flow rule {text}{what}: once the agent has read content with the rule's 'after' labels, calls to tools "
        "with its 'then' label are refused, which stops data from leaving after an injection. It holds until a "
        "new session starts (restart the client or the proxy). If a tool should not count, change its labels or "
        "the flow rule."
    )


def _flow_exception_hint(text: str, rule: Any, matched_arg: Any, policy: Policy | None) -> str:
    entry = None
    if policy is not None and isinstance(rule, str) and ".unless_args[" in rule:
        flow_index, entry_index = re.findall(r"\[(\d+)\]", rule)[:2]
        flows = policy.flows
        flow = flows[int(flow_index)] if int(flow_index) < len(flows) else None
        if flow is not None and int(entry_index) < len(flow.unless_args):
            entry = flow.unless_args[int(entry_index)].describe()
    what = f" ({printable(entry, limit=200)})" if entry else ""
    argument = f" argument {_name(matched_arg)}" if isinstance(matched_arg, str) else " an argument"
    return (
        f"A flow rule applied because{argument} did not meet its exception {text}{what}. The flow narrows a sink "
        "after the agent has read such content: only calls that meet its unless_args go through. If the value is "
        "a safe destination, widen that unless_args entry (try it with `agent-sentinel check --history`); if "
        "not, the block is doing its job."
    )


_FIXED_HINTS = {
    "secrets": (
        "The call carried what looks like a key or token, so it was not made. That is what the guard is for: keep "
        'credentials out of what the agent sends. If it is a false alarm, "secrets": {"in_arguments": "allow"} '
        "turns the guard off for every call, which is not recommended."
    ),
    "secrets_results": (
        "A tool result held what looks like a key or token (secrets.in_results). Keep credentials out of what "
        'tools return to the agent; "off" turns this check off for every result.'
    ),
    "canary": (
        "The call carried one of the policy's canary strings: text from a file the canary was planted in was on "
        "its way out. Find out what read that file; do not loosen this."
    ),
    "known_value": (
        "The call carried the value of an environment variable named in secrets.known_values_from_env. Find out "
        "how the agent got it; do not loosen this."
    ),
    "secret_pattern": (
        "The call carried text in one of the policy's custom secret formats (secrets.patterns). If it is not a "
        "secret, make that format narrower."
    ),
    "injection": (
        "The content had a prompt-injection finding at or above injection.block_severity, so it was withheld. "
        "Read the findings. If it is a false alarm, raising block_severity loosens this for all content, which is "
        "not recommended: the rules are patterns and cannot tell intent."
    ),
    "unscannable": "The content had a type that cannot be checked, so it was refused. No policy setting changes this.",
    "malformed": (
        "The call or message had a shape that cannot be checked (or used a reserved name), so it was refused. No "
        "policy setting changes this; look at the client or the server."
    ),
    "quarantine": (
        "The tool was removed from the tool list: its description was flagged, its definition changed after it "
        "was first seen (pinned), or the list could not be checked. Look at what the server sends. If a changed "
        "tool is legitimate, review it, then remove its entry from the pins file so that it is pinned again."
    ),
    "session": (
        "The session state of the flow rules could not be recorded, so the result was withheld. Check that the "
        "state folder is writable."
    ),
    "caller": "The program that uses the firewall blocked this itself (Firewall.block). Look at that program.",
    "include_context": (
        "The server asked the client's model for an answer written with context included (a sampling request "
        "whose includeContext is not 'none'), and that answer would have gone back to the server. The proxy "
        "refuses such requests whatever the policy says; a server that needs sampling can ask without it."
    ),
    "call_timeout": (
        "The server did not answer the call within limits.call_timeout_seconds, so the client was answered with an "
        "error and the server was asked to cancel the call. Raise the limit if this tool is slow by nature."
    ),
    "hook_failed": (
        "The Claude Code hook could not finish its checks, so it refused (the reason says why: often a policy "
        "that does not load, or a state folder that cannot be written). Fix that cause; no policy rule changes "
        "this."
    ),
    "config_change": (
        "A Claude Code settings file or skill changed during the session, and hook.config_changes is \"block\", so "
        "the running session did not apply it; the file itself stays changed, and the next session reads it. If "
        "you made the change, start a new session; if not, find out what wrote the file and undo it. "
        '"audit" records such changes without refusing them.'
    ),
    "elicitation": (
        "An MCP server asked the user for something an elicitation may not ask: an address that is not a public "
        "https one, or a password, key or card number in a form. The request was declined. Look at the server; no "
        "policy setting allows this."
    ),
    "audit_required": (
        "The audit record could not be written, and the proxy or hook runs with --audit-required, which refuses "
        "what it cannot record. Make the audit log writable again (disk space, permissions, its folder); no policy "
        "rule changes this."
    ),
    "schema_arguments": (
        "The call's arguments did not match the input schema the server declared for the tool, or named an "
        "argument it does not declare (schema_checks.arguments, schema_checks.undeclared_args). A well-behaved "
        "agent follows the schema; if the server's schema is sloppy, set \"schema_checks\": {\"arguments\": "
        "\"warn\"} in that tool's rule."
    ),
    "schema_result": (
        "The server's result did not match the output schema it declared for the tool (schema_checks.results). "
        "Look at the server; if its schema is sloppy, set \"schema_checks\": {\"results\": \"warn\"} in that "
        "tool's rule."
    ),
    "schema_remote_refs": (
        "The tool's schema refers to something outside itself (a $ref, $id or $schema naming a web address or a "
        "file), which a client could fetch unchecked, so the tool was quarantined (schema_checks.remote_refs). "
        "Look at the server's schema; \"warn\" only reports such tools."
    ),
    "none": (
        "This record names no rule: it was written by agent-sentinel before 0.5, or edited. Its reason says what "
        "happened."
    ),
    "unknown": (
        "This is not a rule id agent-sentinel knows: the log may come from another version, or have been edited."
    ),
}
