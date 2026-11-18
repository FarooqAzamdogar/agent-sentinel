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
from .detector import scan
from .policy import Policy, PolicyError
from .textutil import printable

# Byte order marks, longest first: the UTF-32-LE mark begins with the UTF-16-LE one.
_BYTE_ORDER_MARKS = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


def _decode(data: bytes) -> str:
    """Decode a file for scanning.

    Files are UTF-8 unless they say otherwise. A UTF-16 file read as UTF-8 has
    a NUL between every letter and would scan as clean, so honour byte order
    marks and recognise unmarked UTF-16 by its NUL bytes.
    """
    for mark, encoding in _BYTE_ORDER_MARKS:
        if data.startswith(mark):
            return data.decode(encoding, errors="replace")
    sample = data[:2000]
    if len(sample) >= 4 and sample.count(0) >= len(sample) // 4:
        even_nuls = sample[0::2].count(0)
        odd_nuls = sample[1::2].count(0)
        return data.decode("utf-16-be" if even_nuls > odd_nuls else "utf-16-le", errors="replace")
    return data.decode("utf-8", errors="replace")


def _scan(args: argparse.Namespace) -> int:
    data = sys.stdin.buffer.read() if args.file in (None, "-") else Path(args.file).read_bytes()
    findings = scan(_decode(data))
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
        print(f"Invalid policy: {printable(exc)}", file=sys.stderr)
        return 2
    print(f"Policy is valid. Default action: {policy.default}. Blocks injection findings at: {policy.block_severity}.")
    print(f"Secrets in tool arguments: {policy.secrets_in_arguments}.", end=" ")
    print(f"Policy-wide deny rules: {len(policy.deny_args)}.", end=" ")
    print(f"Limit for all tools: {policy.max_calls_per_minute or 'none'} call(s) per minute.")
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


def _read_audit(path: str) -> tuple[list[dict], int]:
    records, unreadable = [], 0
    with Path(path).open(encoding="utf-8", errors="replace") as handle:
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
    return records, unreadable


def _report(args: argparse.Namespace) -> int:
    records, unreadable = _read_audit(args.audit)
    if not records:
        print("The audit log has no records.")
        return 0

    def field(record: dict, name: str, limit: int = 200) -> str:
        return printable(record.get(name, "?"), limit=limit)

    print(f"{len(records)} records from {field(records[0], 'time')} to {field(records[-1], 'time')}")

    # Only "call" records are tool calls. Scan records are labelled by text the
    # server chose, so mixing them in would let a server invent "allowed" rows.
    calls = [r for r in records if r.get("event") == "call"]
    if calls:
        counts = Counter((field(r, "tool", 40), r.get("action")) for r in calls)
        print(f"\n{'Tool calls':40} {'allowed':>8} {'blocked':>8} {'would block':>12}")
        for tool in sorted({tool for tool, _ in counts}):
            row = (counts[(tool, "allow")], counts[(tool, "block")], counts[(tool, "would_block")])
            print(f"{tool:40} {row[0]:>8} {row[1]:>8} {row[2]:>12}")

    scans = [r for r in records if r.get("event") != "call"]
    if scans:
        counts = Counter((field(r, "event", 40), r.get("action")) for r in scans)
        print(f"\n{'Content checks, by kind':40} {'passed':>8} {'blocked':>8} {'would block':>12}")
        for event in sorted({event for event, _ in counts}):
            row = (counts[(event, "allow")], counts[(event, "block")], counts[(event, "would_block")])
            print(f"{event:40} {row[0]:>8} {row[1]:>8} {row[2]:>12}")

    blocked = [r for r in records if r.get("action") in ("block", "would_block")]
    shown = blocked[-args.last :] if args.last > 0 else []
    if shown:
        print(f"\nLast {len(shown)} blocked:")
        for record in shown:
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
        print(f"agent-sentinel: {printable(exc)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
