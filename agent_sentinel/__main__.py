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
import codecs
import json
import sys
from collections import Counter
from pathlib import Path

from . import __version__, mcp_proxy
from .detector import scan_views
from .policy import Policy, PolicyError
from .policy_errors import file_error_message
from .textutil import printable

# Byte order marks, longest first: the UTF-32-LE mark begins with the UTF-16-LE one.
_BYTE_ORDER_MARKS = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


def _readings(data: bytes) -> list[str]:
    """The ways a file's bytes may be read as text. All of them are scanned.

    Always as UTF-8, which is what most programs assume. Also as the encoding
    a byte order mark announces, and as UTF-16 when the NUL bytes suggest it:
    a UTF-16 file has a NUL beside every letter. Guessing ONE encoding would
    be a way to hide text: two bytes that look like a UTF-16 mark in front of
    ordinary UTF-8 would make the scanner read noise where another program
    reads the words.
    """
    readings = [data.decode("utf-8", errors="replace")]
    for mark, encoding in _BYTE_ORDER_MARKS:
        if data.startswith(mark):
            readings.append(data.decode(encoding, errors="replace"))
    sample = data[:2000]
    if len(sample) >= 4 and sample.count(0) >= len(sample) // 4:
        readings.append(data.decode("utf-16-le", errors="replace"))
        readings.append(data.decode("utf-16-be", errors="replace"))
    return list(dict.fromkeys(readings))


def _scan(args: argparse.Namespace) -> int:
    data = sys.stdin.buffer.read() if args.file in (None, "-") else Path(args.file).read_bytes()
    findings = scan_views(_readings(data))
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
        message = file_error_message(args.policy, exc) if isinstance(exc, OSError) else str(exc)
        # Line by line: a JSON error shows the line of the file with a caret under the mistake.
        lines = message.splitlines() or [""]
        print(f"Invalid policy: {printable(lines[0], limit=1000)}", file=sys.stderr)
        for line in lines[1:]:
            print(printable(line, limit=1000), file=sys.stderr)
        return 2
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
        print(f"  {printable(rule.name):24} {rule.action:6} {', '.join(notes)}")
    for warning in policy.warnings():
        print(f"Warning: {printable(warning)}")
    return 0


_ACTIONS = ("allow", "block", "would_block")


def _read_audit(path: str) -> tuple[list[dict], int]:
    records, unreadable = [], 0
    with Path(path).open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except (ValueError, RecursionError):  # not JSON, or nested absurdly deep
                record = None
            if isinstance(record, dict):
                records.append(record)
            else:
                unreadable += 1
    return records, unreadable


def _report(args: argparse.Namespace) -> int:
    records, unreadable = _read_audit(args.audit)
    # Said first and plainly: a line that cannot be read may be a record someone wanted hidden.
    if unreadable:
        print(f"WARNING: {unreadable} line(s) of the log could not be read and are not counted below.")
    if not records:
        print("The audit log has no readable records.")
        return 0

    def field(record: dict, name: str, limit: int = 200) -> str:
        return printable(record.get(name, "?"), limit=limit)

    def action(record: dict) -> str:
        value = record.get("action")
        return value if value in _ACTIONS else "other"  # anything unexpected still gets counted

    def table(title: str, records: list[dict], key: str, first_column: str) -> None:
        counts = Counter((field(r, key, 40), action(r)) for r in records)
        print(f"\n{title:40} {first_column:>8} {'blocked':>8} {'would block':>12} {'other':>6}")
        for name in sorted({name for name, _ in counts}):
            row = [counts[(name, a)] for a in (*_ACTIONS, "other")]
            print(f"{name:40} {row[0]:>8} {row[1]:>8} {row[2]:>12} {row[3]:>6}")

    print(f"{len(records)} records from {field(records[0], 'time')} to {field(records[-1], 'time')}")

    # Only "call" records are tool calls. Scan records are labelled by text the
    # server chose, so mixing them in would let a server invent "allowed" rows.
    calls = [r for r in records if r.get("event") == "call"]
    if calls:
        table("Tool calls", calls, "tool", "allowed")
    checks = [r for r in records if r.get("event") != "call"]
    if checks:
        table("Content checks, by kind", checks, "event", "passed")

    blocked = [r for r in records if action(r) in ("block", "would_block")]
    shown = blocked[-args.last :] if args.last > 0 else []
    if shown:
        print(f"\nLast {len(shown)} blocked:")
        for record in shown:
            print(f"  {field(record, 'time')}  {field(record, 'event')}  {field(record, 'tool')}: {field(record, 'reason')}")
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
        mcp_proxy.exit_process(mcp_proxy.main(argv[1:]))  # does not return: see exit_process for why

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
    if not hasattr(args, "func"):  # "proxy" reached here because something came before it, such as "--"
        parser.error("write 'proxy' first: agent-sentinel proxy --policy FILE -- COMMAND")
    try:
        return args.func(args)
    except OSError as exc:
        print(f"agent-sentinel: {printable(exc)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
