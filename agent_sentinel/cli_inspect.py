"""`agent-sentinel inspect [--policy POLICY] -- <server command>`: what a server offers, and what would reach the agent.

    agent-sentinel inspect -- npx -y @modelcontextprotocol/server-filesystem C:/work
    agent-sentinel inspect --policy policy.json -- python my_server.py

Starts the server, runs the MCP handshake and tools/list through a real
proxy (server_probe.py), stops the server, and lists every tool: whether the
proxy would let it through, why not, what the server claims about it (its
MCP annotations, marked unverified), and with --policy how that policy
would treat a call to it. Nothing is called and nothing is written.

Exit codes: 0 nothing was removed; 1 the proxy removed a tool, the server's
instructions or the whole list; 2 the server could not be started or did
not answer.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from typing import Any

from . import server_probe
from .cli_common import EXIT_ERROR, EXIT_FAIL, EXIT_OK, CommandError, load_policy, shown_command, shown_path
from .policy import Policy
from .server_probe import ListedTool, ProbeResult
from .session import labels_from_annotations
from .textutil import printable

HELP = "start an MCP server, list its tools, and show what the proxy (and a policy) would do with each"
DESCRIPTION = (
    "Start an MCP server, run the handshake and tools/list through the proxy, stop it, and list every tool: "
    "whether it would reach the agent, what the server claims about it, and with --policy how that policy "
    "treats a call to it. No tool is called and nothing is written."
)
EPILOG = """\
examples:
  agent-sentinel inspect -- npx -y @modelcontextprotocol/server-filesystem C:/work
  agent-sentinel inspect --policy policy.json -- python my_server.py

exit codes: 0 nothing removed, 1 the proxy removed something, 2 the server could not be inspected
"""
USAGE = "agent-sentinel inspect [--policy POLICY] [--timeout SECONDS] [--format {text,json}] -- SERVER_COMMAND ..."
# The command line has a server command after "--" (see __main__.py).
TAKES_SERVER_COMMAND = True

UNVERIFIED = (
    "MCP annotations are the server's own claims: nothing checks them, and a server can call any tool read-only."
)


@dataclass
class PolicyView:
    """How a policy treats a call to one tool, before any argument is looked at."""

    action: str
    rules: list[str]  # the rule ids that decide: "tools.read_file", "tools.delete_*", or "default"
    hidden: bool  # hide_blocked_tools would keep it out of the agent's list
    argument_rules: bool  # a deciding rule also judges arguments
    labels: list[str] = field(default_factory=list)  # flow labels, when the policy has flow rules


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy", metavar="POLICY", help="also show how this policy treats a call to each tool")
    parser.add_argument("--timeout", type=timeout_seconds, default=server_probe.DEFAULT_TIMEOUT_SECONDS,
                        metavar="SECONDS",
                        help="give up if the server has not answered by then "
                             f"(default {server_probe.DEFAULT_TIMEOUT_SECONDS:g})")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="output format (default text)")


def timeout_seconds(text: str) -> float:
    """An argparse type: seconds, from 1 to 600."""
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"must be a number of seconds, got {printable(text, limit=40)!r}") from None
    if not 1 <= value <= 600:
        raise argparse.ArgumentTypeError("must be from 1 to 600 seconds")
    return value


def run(args: argparse.Namespace) -> int:
    command = args.server_command
    if not command:
        raise CommandError(
            "give the MCP server command after '--', for example:\n"
            "  agent-sentinel inspect -- npx -y @modelcontextprotocol/server-filesystem /path/to/folder"
        )
    policy = None
    if args.policy is not None:
        policy = load_policy(args.policy)
        if policy is None:
            return EXIT_ERROR
    result = server_probe.probe(command, policy, args.timeout)
    if args.format == "json":
        print(json.dumps(as_json(result, policy), indent=2, ensure_ascii=True))
    else:
        print_result(result, policy, args.policy)
    return EXIT_FAIL if result.found_problems else EXIT_OK


# ---- what a policy says about a tool ------------------------------------------------------

def policy_view(policy: Policy, tool: ListedTool) -> PolicyView:
    """How `policy` treats a call to `tool`: the same choice of rules as Policy.evaluate, without arguments."""
    action = policy.tool_level_action(tool.name)
    exact = [rule for rule in policy.tools if not rule.is_glob and rule.name == tool.name]
    deciding = exact or [rule for rule in policy.tools if rule.is_glob and rule.matches(tool.name)]
    rules = [f"tools.{rule.name}" for rule in deciding if rule.action == action] or ["default"]
    labels: set[str] = set()
    if policy.flows:
        labels |= policy.tool_labels(tool.name)
        if policy.classify_by_annotations:
            labels |= labels_from_annotations(tool.hints)
    return PolicyView(
        action=action,
        rules=rules,
        hidden=policy.hide_blocked_tools and action == "block",
        argument_rules=any(rule.deny_args or rule.allow_args or rule.other_args == "block" for rule in deciding),
        labels=sorted(labels),
    )


def _describe_view(view: PolicyView) -> str:
    parts = [f"{view.action:5}  {printable(', '.join(view.rules), limit=80)}"]
    if view.argument_rules and view.action != "block":
        parts.append("argument rules apply")
    if view.hidden:
        parts.append("hidden from the agent")
    if view.labels:
        parts.append(f"labels {', '.join(view.labels)}")
    return "; ".join(parts)


# ---- text output -----------------------------------------------------------------------------

def print_result(result: ProbeResult, policy: Policy | None, policy_path: str | None) -> None:
    server = printable(result.server_name or "(no name)", limit=80)
    if result.server_version:
        server += f" {printable(result.server_version, limit=40)}"
    print(f"Server: {server}, MCP {printable(result.protocol_version or '(no version)', limit=40)}")
    print(f"Started with: {shown_command(result.command)}")
    print(f"Capabilities: {', '.join(printable(name, limit=40) for name in result.capabilities) or 'none'}")
    print(f"Instructions: {_instructions(result)}")
    if result.list_error:
        print(f"Tool list: {printable(result.list_error, limit=300)}")
    print(f"\n{_counts(result, policy)}.")
    if result.malformed_entries:
        print(f"{result.malformed_entries} entry(ies) of the list are not a tool with a usable name; "
              "the proxy drops them.")
    if result.truncated:
        print(f"Only the first {len(result.tools)} tool(s) were looked at "
              f"(at most {server_probe.MAX_PAGES} pages and {server_probe.MAX_TOOLS} tools).")
    _print_table(result.tools, policy)
    _print_footer(result, policy, policy_path)


def _counts(result: ProbeResult, policy: Policy | None) -> str:
    """"4 tool(s) listed; 1 removed by the proxy; 1 hidden by the policy; 2 would reach the agent"."""
    passed = [tool for tool in result.tools if tool.reaches_agent]
    hidden = [tool for tool in passed if policy is not None and policy_view(policy, tool).hidden]
    parts = [f"{len(result.tools)} tool(s) listed"]
    if len(passed) < len(result.tools):
        parts.append(f"{len(result.tools) - len(passed)} removed by the proxy")
    if hidden:
        parts.append(f"{len(hidden)} hidden by the policy (hide_blocked_tools)")
    parts.append(f"{len(passed) - len(hidden)} would reach the agent")
    return "; ".join(parts)


def _instructions(result: ProbeResult) -> str:
    if result.instructions == "none":
        return "none"
    if result.instructions == "kept":
        return "kept (they reach the model, often in its system prompt)"
    return f"REMOVED by the proxy: {printable(result.instructions_reason or 'flagged', limit=200)}"


def _print_table(tools: list[ListedTool], policy: Policy | None) -> None:
    if not tools:
        return
    width = min(32, max(len(printable(tool.name, limit=32)) for tool in tools))
    print(f"\n  {'TOOL':{width}}  {'POLICY' if policy is not None else 'PROXY'}")
    for tool in tools:
        name = printable(tool.name, limit=32)
        if not tool.reaches_agent:
            status = f"REMOVED: {printable(tool.removed_because or 'removed by the proxy', limit=200)}"
        elif policy is not None:
            status = _describe_view(policy_view(policy, tool))
        else:
            status = "reaches the agent"
        says = tool.says()
        claim = f"  [server says: {', '.join(says)} (unverified)]" if says else ""
        print(f"  {name:{width}}  {status}{claim}")


def _print_footer(result: ProbeResult, policy: Policy | None, policy_path: str | None) -> None:
    notes = []
    if any(tool.says() for tool in result.tools):
        notes.append(UNVERIFIED)
    if policy is not None:
        asked = [tool for tool in result.tools if tool.reaches_agent and policy_view(policy, tool).action == "ask"]
        if asked:
            notes.append("'ask': the proxy refuses these calls unless it is started with an approver (--approve-with).")
        notes.append("Argument rules, flow rules, rate limits and the secret guard are applied to each call as it is "
                     "made: try one with agent-sentinel check.")
    # What the proxy said besides the removals the table already shows (already printable).
    messages = [line for line in result.proxy_messages if "from the tools list:" not in line]
    if messages:
        notes.append("The proxy reported:")
        notes.extend(f"  {line}" for line in messages[:20])
    command = shown_command(result.command)
    if policy is None:
        notes.append(f"Draft a policy from this list: agent-sentinel init -- {command}")
        notes.append(f"See how a policy treats each tool: agent-sentinel inspect --policy POLICY -- {command}")
    else:
        notes.append(f"Try a call: agent-sentinel check {shown_path(policy_path or 'POLICY')} TOOL [name=value ...]")
    print()
    for note in notes:
        print(note)


# ---- JSON output -----------------------------------------------------------------------------

def as_json(result: ProbeResult, policy: Policy | None) -> dict[str, Any]:
    """The result as plain data. Every text from the server is made printable first."""
    tools = []
    for tool in result.tools:
        entry: dict[str, Any] = {
            "name": printable(tool.name, limit=256),
            "reaches_agent": tool.reaches_agent,
            "removed_because": printable(tool.removed_because, limit=300) if tool.removed_because else None,
            "server_says": dict(tool.hints),
        }
        if policy is not None and tool.reaches_agent:
            view = policy_view(policy, tool)
            entry["policy"] = {
                "action": view.action, "rules": [printable(rule, limit=300) for rule in view.rules],
                "hidden": view.hidden, "argument_rules": view.argument_rules, "labels": view.labels,
            }
        tools.append(entry)
    return {
        "command": [printable(part, limit=300) for part in result.command],
        "server": {
            "name": printable(result.server_name, limit=200) if result.server_name is not None else None,
            "version": printable(result.server_version, limit=200) if result.server_version is not None else None,
        },
        "protocol_version": printable(result.protocol_version, limit=64) if result.protocol_version else None,
        "capabilities": [printable(name, limit=40) for name in result.capabilities],
        "instructions": result.instructions,
        "instructions_reason": printable(result.instructions_reason, limit=300) if result.instructions_reason else None,
        "tool_list_error": printable(result.list_error, limit=300) if result.list_error else None,
        "tools": tools,
        "malformed_entries": result.malformed_entries,
        "truncated": result.truncated,
        "server_says_is_unverified": True,
    }
