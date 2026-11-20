"""`agent-sentinel validate POLICY`: check that a policy file is well formed, and summarise it.

Loading is strict (see policy.py), so this prints either the first mistake,
with where it is and what was probably meant, or a summary of the policy and
any warnings: settings that are valid but probably not what the author meant.
A valid policy ends with a pointer to `check`, which tries calls against it.
"""

from __future__ import annotations

import argparse

from .cli_common import EXIT_ERROR, EXIT_OK, load_policy, shown_path
from .policy import Policy
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
    print(f"Policy-wide deny rules: {len(policy.deny_args)}.", end=" ")
    limit = policy.max_calls_per_minute
    print(f"Limit for all tools: {f'{limit} call(s) per minute' if limit else 'none'}.")
    for rule in policy.tools:
        notes = []
        if rule.deny_args:
            notes.append(f"{len(rule.deny_args)} deny rule(s)")
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
        print(f"  {printable(rule.name):24} {rule.action:6} {', '.join(notes)}")
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
        extra.append(f"Values never sent, from the environment: {', '.join(policy.secrets_known_values_from_env)}.")
    if policy.secrets_canaries:
        extra.append(f"Canaries: {len(policy.secrets_canaries)}.")
    if extra:
        print(" ".join(extra))
    if policy.flows:
        print("Flow rules:")
        for index, flow in enumerate(policy.flows):
            print(f"  flows[{index}]  {flow.describe()}")
        if policy.classify_by_annotations:
            print("  MCP tool annotations add labels: openWorldHint -> untrusted, sink; destructiveHint -> sink.")
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
