"""Command line for agent-sentinel.

    agent-sentinel proxy --policy policy.json -- <mcp server command...>
    agent-sentinel scan [FILE]          scan text (or stdin) for prompt injection
    agent-sentinel validate POLICY      check that a policy file is well formed
    agent-sentinel report AUDIT_LOG     summarize an audit log

Everything printed here may contain untrusted text (file contents, tool names
from an audit log), so it goes through `printable` first.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from . import __version__, mcp_proxy
from .detector import scan
from .policy import Policy, PolicyError
from .textutil import printable


def _scan(args: argparse.Namespace) -> int:
    if args.file in (None, "-"):
        data = sys.stdin.buffer.read()
    else:
        data = Path(args.file).read_bytes()
    findings = scan(data.decode("utf-8", errors="replace"))
    if not findings:
        print("No injection patterns found. (Pattern rules only: this is not proof the text is safe.)")
        return 0
    for finding in findings:
        print(f"[{finding.severity.upper():6}] {finding.rule}: {printable(finding.excerpt)}")
    return 1


def _validate(args: argparse.Namespace) -> int:
    try:
        policy = Policy.from_file(args.policy)
    except (OSError, PolicyError) as exc:
        print(f"Invalid policy: {exc}", file=sys.stderr)
        return 2
    print(f"Policy is valid. Default action: {policy.default}. Blocks injection findings at: {policy.block_severity}.")
    for rule in policy.tools:
        extra = []
        if rule.deny_args:
            extra.append(f"{len(rule.deny_args)} deny rule(s)")
        if rule.allow_args:
            extra.append(f"{len(rule.allow_args)} allow rule(s)")
        print(f"  {rule.name:24} {rule.action:6} {', '.join(extra)}")
    if policy.default == "allow":
        print("Warning: default is 'allow', so any tool without a rule can run.")
    return 0


def _report(args: argparse.Namespace) -> int:
    records = []
    unreadable = 0
    with Path(args.audit).open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError:
                record = None
            if isinstance(record, dict):
                records.append(record)
            else:
                unreadable += 1
    if not records:
        print("The audit log has no records.")
        return 0

    def field(record: dict, name: str) -> str:
        return printable(record.get(name, "?"), limit=200)

    counts: Counter[tuple[str, str]] = Counter((printable(r.get("tool", "?"), limit=40), r.get("action")) for r in records)
    print(f"{len(records)} records from {field(records[0], 'time')} to {field(records[-1], 'time')}\n")
    print(f"{'tool':40} {'allowed':>8} {'blocked':>8}")
    for tool in sorted({tool for tool, _ in counts}):
        print(f"{tool:40} {counts[(tool, 'allow')]:>8} {counts[(tool, 'block')]:>8}")

    blocked = [r for r in records if r.get("action") == "block"]
    if blocked:
        print(f"\nLast {min(len(blocked), args.last)} blocked:")
        for record in blocked[-args.last:]:
            print(f"  {field(record, 'time')}  {field(record, 'event')}  {field(record, 'tool')}: {field(record, 'reason')}")
    if unreadable:
        print(f"\n{unreadable} line(s) could not be read and were skipped.")
    return 0


def _make_output_safe() -> None:
    """Never crash on a character the console cannot show (common on Windows)."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")


def main(argv: list[str] | None = None) -> int:
    _make_output_safe()
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["proxy"]:  # the proxy parses its own arguments, including the '--' part
        return mcp_proxy.main(argv[1:])

    parser = argparse.ArgumentParser(prog="agent-sentinel", description="A firewall for AI agent tool calls.")
    parser.add_argument("--version", action="version", version=f"agent-sentinel {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("proxy", help="run an MCP server behind the firewall (see: proxy --help)")

    scan_cmd = commands.add_parser("scan", help="scan a text file (or stdin) for prompt injection")
    scan_cmd.add_argument("file", nargs="?", help="file to scan; omit or use '-' for stdin")
    scan_cmd.set_defaults(func=_scan)

    validate_cmd = commands.add_parser("validate", help="check a policy file")
    validate_cmd.add_argument("policy")
    validate_cmd.set_defaults(func=_validate)

    report_cmd = commands.add_parser("report", help="summarize an audit log")
    report_cmd.add_argument("audit")
    report_cmd.add_argument("--last", type=int, default=10, help="how many recent blocks to list (default 10)")
    report_cmd.set_defaults(func=_report)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except OSError as exc:
        print(f"agent-sentinel: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
