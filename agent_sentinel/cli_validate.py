"""`agent-sentinel validate POLICY`: check that a policy file is well formed, and summarise it.

Loading is strict (see policy.py), so this prints either the first mistake,
with where it is and what was probably meant, or a summary of the policy and
any warnings: settings that are valid but probably not what the author meant.
A valid policy ends with a pointer to `check`, which tries calls against it.
"""

from __future__ import annotations

import argparse

from .cli_common import EXIT_ERROR, EXIT_OK, load_policy, shown_path
from .policy import (
    DEFAULT_MAX_REFUSALS_PER_TOOL,
    DEFAULT_REFUSAL_WINDOW_SECONDS,
    SCHEMA_CHECK_CHOICES,
    ArgRule,
    Policy,
    SchemaChecks,
)
from .textutil import printable

HELP = "check a policy file"
DESCRIPTION = "Check that a policy file is well formed, print a summary of it, and warn about likely mistakes."


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("policy", help="the policy JSON file")


def run(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    if policy is None:
        return EXIT_ERROR
    print(f"Policy is valid. Default action: {policy.default}. Blocks injection findings at: {policy.block_severity}.")
    print(f"Secrets in tool arguments: {policy.secrets_in_arguments}.", end=" ")
    print(f"Policy-wide deny rules: {len(policy.deny_args)}{_asking(policy.deny_args)}.", end=" ")
    limit = policy.max_calls_per_minute
    print(f"Limit for all tools: {f'{limit} call(s) per minute' if limit else 'none'}.")
    for rule in policy.tools:
        notes = []
        if rule.deny_args:
            notes.append(f"{len(rule.deny_args)} deny rule(s){_asking(rule.deny_args)}")
        if rule.allow_args:
            notes.append(f"{len(rule.allow_args)} allow rule(s)")
        if rule.other_args == "block":
            notes.append("other arguments blocked")
        if rule.max_calls_per_minute:
            notes.append(f"{rule.max_calls_per_minute} call(s) per minute")
        if rule.labels:
            notes.append(f"labels {', '.join(rule.labels)}")
        if rule.command is not None:
            notes.append(f"{rule.command.shell} command checks")
        if rule.schema_checks is not None and _schema_settings(rule.schema_checks):
            notes.append(f"schema checks: {_schema_settings(rule.schema_checks)}")
        print(f"  {printable(rule.name):24} {rule.action:6} {', '.join(notes)}")
        if rule.command is not None:  # which classes it refuses or asks about, as check --show-rules lists it
            described = printable(rule.command.describe(), limit=400)
            print(f"    tools.{printable(rule.name, limit=120)}.command  {described}")
    _print_new_settings(policy)
    for warning in policy.warnings():
        print(f"Warning: {printable(warning)}")
    print(f"Next: try a call against it: agent-sentinel check {shown_path(args.policy)} TOOL [name=value ...]")
    return EXIT_OK


def _print_new_settings(policy: Policy) -> None:
    """The settings added in 0.5, each only when the policy uses it, so older policies print as before.

    Canary strings and the values of known secrets are never printed: an agent
    that reads this output (in a log, a chat) could strip them from what it sends.
    """
    extra = []
    if policy.secrets_in_results != "off":
        extra.append(f"Secrets in tool results: {policy.secrets_in_results}.")
    if policy.secrets_patterns:
        extra.append(f"Custom secret formats: {', '.join(printable(p.name) for p in policy.secrets_patterns)}.")
    if policy.secrets_known_values_from_env:
        ignoring = policy.secrets_known_values_ignore_case
        case = f" (matched ignoring case: {', '.join(ignoring)})" if ignoring else ""
        extra.append(f"Values never sent, from the environment: {', '.join(policy.secrets_known_values_from_env)}"
                     f"{case}.")
    if policy.secrets_canaries:
        extra.append(f"Canaries: {len(policy.secrets_canaries)}.")
    if policy.call_timeout_seconds is not None:
        extra.append(f"The proxy cancels a call the server has not answered within {policy.call_timeout_seconds:g} "
                     "seconds.")
    if extra:
        print(" ".join(extra))
    if policy.server_requests:
        rules = ", ".join(f"{printable(rule.name)} {rule.action}" for rule in policy.server_requests)
        print(f"Server requests: {rules}.")
    if policy.flows:
        print("Flow rules:")
        for index, flow in enumerate(policy.flows):
            print(f"  flows[{index}]  {flow.describe()}")
        if policy.classify_by_annotations:
            print("  MCP tool annotations add labels: openWorldHint -> untrusted, sink; destructiveHint -> sink.")
    if not policy.classify_by_annotations:
        print("MCP tool annotations add no flow labels (classify_by_annotations is false).")
    if policy.client_requests is not None:
        rules = ", ".join(f"{printable(rule.name)} {rule.action}" for rule in policy.client_requests) or "none"
        print(f"Client requests: {rules}.")
    if policy.checks_prompts:
        print("prompts/get is checked like a tool call named 'prompts/get'.")
    if policy.hide_blocked_tools:
        hidden = [printable(rule.name) for rule in policy.tools if policy.tool_level_action(rule.name) == "block"]
        if policy.default == "block":
            hidden.append("every tool without a rule")
        print(f"Hidden from the tool list (blocked outright): {', '.join(hidden) or 'none'}.")
    hook = []
    if policy.hook.config_changes == "block":
        hook.append("changes to Claude Code's settings during a session are refused")
    if policy.hook.treat_auto_as_non_prompting:
        hook.append("an 'ask' in auto mode is refused")
    if hook:
        print(f"Claude Code hook: {'; '.join(hook)}.")
    _print_session_settings(policy)


def _print_session_settings(policy: Policy) -> None:
    """The settings added in 0.6, each only when the policy sets it (approval memory: when it differs from the
    default, which is on)."""
    extra = []
    if policy.warn_severity is not None:
        extra.append(f"Notice for findings at or above: {policy.warn_severity}.")
    if policy.mark_at is not None:
        extra.append(f"Findings at or above {policy.mark_at} mark the session '{policy.injection_mark}'.")
    if policy.require_labels:
        extra.append("Every rule that allows or asks must say its flow labels (require_labels).")
    approvals = _approval_memory(policy)
    if approvals:
        extra.append(approvals)
    if _schema_settings(policy.schema_checks):
        extra.append(f"Schema checks (the proxy), unless a tool rule says otherwise: "
                     f"{_schema_settings(policy.schema_checks)}.")
    if extra:
        print(" ".join(extra))
    for rule in policy.server_labels:
        print(f"  server_labels.{printable(rule.name, limit=80)}  marks {', '.join(rule.labels)}")
    limits = [rule_id for rule_id in ("limits.max_calls_per_session", "limits.max_sink_bytes_per_session",
                                      "limits.max_identical_calls") if policy.describe_rule(rule_id)]
    limits += [f"limits.max_distinct[{index}]" for index in range(len(policy.max_distinct))]
    for rule in policy.tools:
        if rule.max_calls_per_session is not None:
            limits.append(f"tools.{rule.name}.max_calls_per_session")
        limits += [f"tools.{rule.name}.max_distinct[{index}]" for index in range(len(rule.max_distinct))]
    if limits:
        print("Session limits:")
        for rule_id in limits:
            print(f"  {printable(rule_id, limit=200)}  {printable(policy.describe_rule(rule_id) or '', limit=300)}")


def _asking(entries: tuple[ArgRule, ...]) -> str:
    """How many of these deny entries send a call to a person instead of refusing it: " (2 of them ask)", or ""."""
    asks = sum(1 for entry in entries if entry.action == "ask")
    return f" ({asks} of them ask)" if asks else ""


def _schema_settings(checks: SchemaChecks) -> str:
    """The schema_checks settings a section sets, such as "arguments enforce, remote_refs quarantine"."""
    given = [(key, getattr(checks, key)) for key in SCHEMA_CHECK_CHOICES]
    return ", ".join(f"{key} {value}" for key, value in given if value is not None)


def _approval_memory(policy: Policy) -> str:
    """What the approvals section changes in approval memory; empty when it keeps the defaults."""
    window, most = policy.refusal_window_seconds, policy.max_refusals_per_tool
    if (window, most) == (DEFAULT_REFUSAL_WINDOW_SECONDS, DEFAULT_MAX_REFUSALS_PER_TOOL):
        return ""
    if window == 0:
        return "Approval memory: off (approvals.refusal_window_seconds is 0)."
    pause = (f"after {most} refusal(s) of one tool within that time, its asks are refused too" if most
             else "the asks of a tool are never paused (approvals.max_refusals_per_tool is 0)")
    return f"Approval memory: a call a person refused is refused without asking for {window} seconds; {pause}."
