"""`agent-sentinel report AUDIT_LOG`: summarize an audit log.

    agent-sentinel report audit.jsonl
    agent-sentinel report audit.jsonl --tool 'read_*' --since 2h --show-args
    agent-sentinel report audit.jsonl --by server --format json
    agent-sentinel report audit.jsonl --follow

The summary has a table of tool calls (by tool, or by server), a table of the
content checks (results, tool descriptions, ...), the most common reasons for
blocks with a hint on how to fix each, and the last blocks. Filters choose
which records count. --follow instead watches the log and prints one line
for each new block, until Ctrl+C.

The log is read line by line with a size limit (see auditlog.py), and every
field from it is passed through `printable` before it is shown, in the JSON
output too: the log holds text chosen by the agent and by the server.
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Callable

from . import auditlog, fix_hints
from .auditlog import BLOCK_ACTIONS, RECORD_ACTIONS, RecordFilter, field_text, text_of
from .cli_common import EXIT_OK, CommandError, non_negative_int, print_field, shown_args
from .textutil import printable

HELP = "summarize an audit log (filters, top reasons with fixes, --follow, --format json)"
DESCRIPTION = (
    "Summarize an audit log: tool calls, content checks, the most common reasons for blocks with how to fix "
    "each, and the last blocks. --follow watches the log for new blocks instead."
)
EPILOG = """\
times for --since and --until:
  30m, 2h, 7d, 1w (that long ago), or a date or time such as 2026-11-18 or 2026-11-18T14:30 (local time)

examples:
  agent-sentinel report audit.jsonl --tool 'read_*' --since 2h --show-args
  agent-sentinel report audit.jsonl --by server --action block --format json
  agent-sentinel report audit.jsonl --follow
"""

# The columns of the tables, as before 0.5. "ask" (a call waiting for approval, new in 0.5)
# gets a column of its own only when the log has such records, so older reports read the same.
_COLUMNS = ("allow", "block", "would_block")
TOP_REASONS = 5
# A log can name any number of tools (a server chooses the names). Past this many rows,
# a table counts the rest together, so that a hostile log cannot print millions of rows.
MAX_TABLE_ROWS = 1000
OTHER_NAMES = "(other names)"
MAX_FOLLOW_LINE_CHARS = 500
# A tool or argument name longer than this is not kept for a hint (the proxy's own limit is 256).
MAX_NAME_CHARS = 256


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("audit", help="the audit log (JSON lines)")
    parser.add_argument("--last", type=non_negative_int, default=10,
                        help="how many recent blocks to list (default 10); 0 shows the counts only, "
                             "without blocks or reasons")
    choose = parser.add_argument_group("which records count")
    choose.add_argument("--tool", metavar="GLOB", help="only these tools; '*' stands for anything ('read_*')")
    choose.add_argument("--server", action="append", default=[], metavar="NAME",
                        help="only records of this server (proxy --name); repeat for several")
    choose.add_argument("--action", action="append", default=[], choices=RECORD_ACTIONS,
                        help="only records with this action; repeat for several")
    choose.add_argument("--event", action="append", default=[], metavar="EVENT",
                        help="only records of this kind: call, result, tool_description, ...; repeat for several")
    choose.add_argument("--since", metavar="WHEN", help="only records from this time on")
    choose.add_argument("--until", metavar="WHEN", help="only records up to this time")
    show = parser.add_argument_group("what is shown")
    show.add_argument("--by", choices=("tool", "server"), default="tool", help="group the calls table (default tool)")
    show.add_argument("--show-args", action="store_true", help="also show the arguments of the blocked calls")
    show.add_argument("--format", choices=("text", "json"), default="text", help="output format (default text)")
    show.add_argument("--follow", action="store_true",
                      help="watch the log and print a line for each new block (or each new record with --action)")


def run(args: argparse.Namespace) -> int:
    chosen = record_filter(args)
    if args.follow:
        return follow(args.audit, chosen, args.show_args, args.format, stop=lambda: False, sleep=time.sleep)
    summary = summarize(args.audit, chosen, args.by, args.last)
    if args.format == "json":
        print(json.dumps(_as_json(summary, args.show_args), ensure_ascii=True, indent=2))
    else:
        print_summary(summary, args.show_args)
    return EXIT_OK


def record_filter(args: argparse.Namespace) -> RecordFilter:
    """The filter the options describe. CommandError for a time that cannot be read."""
    try:
        since = auditlog.parse_when(args.since) if args.since else None
        until = auditlog.parse_when(args.until, end_of_day=True) if args.until else None
    except ValueError as exc:
        raise CommandError(str(exc)) from exc
    return RecordFilter(
        tool=args.tool, servers=tuple(args.server), actions=tuple(args.action), events=tuple(args.event),
        since=since, until=until,
    )


# ---- reading the log into a summary -----------------------------------------------------

class _Table:
    """Counts of records by (name, action), with at most MAX_TABLE_ROWS names."""

    def __init__(self) -> None:
        self.counts: Counter[tuple[str, str]] = Counter()
        self.names: set[str] = set()

    def add(self, name: str, action: str) -> None:
        if name not in self.names and len(self.names) >= MAX_TABLE_ROWS:
            name = OTHER_NAMES
        self.names.add(name)
        self.counts[(name, action)] += 1


class _OneOrSeveral:
    """Whether every record of a group names the same text (a tool, an argument), and which.

    Keeps one short text, so memory stays small whatever the log holds.
    """

    def __init__(self) -> None:
        self.value: str | None = None
        self.several = False

    def add(self, value: Any) -> None:
        if not isinstance(value, str) or len(value) > MAX_NAME_CHARS:
            self.several = True
        elif self.value is None:
            self.value = value
        elif value != self.value:
            self.several = True

    @property
    def only(self) -> str | None:
        """The one text every record had, or None."""
        return None if self.several else self.value


@dataclass
class _Reason:
    """The blocks that share one rule (or, in an older log, one reason)."""

    rule: str | None
    count: int = 0
    reasons: Counter[str] = field(default_factory=Counter)
    tools: _OneOrSeveral = field(default_factory=_OneOrSeveral)
    args: _OneOrSeveral = field(default_factory=_OneOrSeveral)  # the argument a rule matched


@dataclass
class Summary:
    path: str
    filter: RecordFilter
    by: str
    total: int = 0  # readable records in the log
    unreadable: int = 0
    matching: int = 0
    first: dict[str, Any] | None = None
    last: dict[str, Any] | None = None
    calls: _Table = field(default_factory=_Table)
    checks: _Table = field(default_factory=_Table)
    has_ask: bool = False
    reasons: dict[str, _Reason] = field(default_factory=dict)
    blocked: deque = field(default_factory=deque)


def summarize(path: str, chosen: RecordFilter, by: str, last: int) -> Summary:
    """Read the log once and count what the report shows. Memory stays bounded whatever the log holds."""
    summary = Summary(path, chosen, by, blocked=deque(maxlen=last))
    for record in auditlog.iter_records(path):
        if record is None:
            summary.unreadable += 1
            continue
        summary.total += 1
        if chosen.matches(record):
            _count(summary, record)
    return summary


def _action(record: dict[str, Any]) -> str:
    value = record.get("action")
    # Anything unexpected is still counted, as "other".
    return value if isinstance(value, str) and value in RECORD_ACTIONS else "other"


def _count(summary: Summary, record: dict[str, Any]) -> None:
    summary.matching += 1
    if summary.first is None:
        summary.first = record
    summary.last = record
    action = _action(record)
    summary.has_ask = summary.has_ask or action == "ask"
    # Only "call" records are tool calls. Scan records are labelled by text the
    # server chose, so mixing them in would let a server invent "allowed" rows.
    if record.get("event") == "call":
        missing = "(no server)" if summary.by == "server" else "?"
        summary.calls.add(field_text(record, summary.by, 40, missing=missing), action)
    else:
        summary.checks.add(field_text(record, "event", 40), action)
    if action in BLOCK_ACTIONS:
        _count_reason(summary.reasons, record)
        if summary.blocked.maxlen:
            summary.blocked.append(record)


def _count_reason(reasons: dict[str, _Reason], record: dict[str, Any]) -> None:
    """Count a block under its rule; a record that names no rule (or an absurd one) under its reason."""
    rule = text_of(record, "rule")
    if rule is not None and len(rule) > fix_hints.MAX_RULE_ID_CHARS:
        rule = None
    key = f"rule {rule}" if rule is not None else f"reason {field_text(record, 'reason', 200)}"
    if key not in reasons:
        if len(reasons) >= MAX_TABLE_ROWS:
            key, rule = OTHER_NAMES, None
        reasons.setdefault(key, _Reason(rule))
    entry = reasons[key]
    entry.count += 1
    if len(entry.reasons) < MAX_TABLE_ROWS:
        entry.reasons[field_text(record, "reason", 200)] += 1
    entry.tools.add(record.get("tool"))
    entry.args.add(record.get("matched_arg"))


def _top_reasons(summary: Summary) -> list[tuple[_Reason, str, str]]:
    """The most common reasons for blocks: (entry, the reason most often given, how to fix it).

    None with --last 0, which asks for the counts only (and has meant "no reasons shown" since 0.4).
    """
    if not summary.blocked.maxlen:
        return []
    found = []
    for entry in sorted(summary.reasons.values(), key=lambda entry: -entry.count)[:TOP_REASONS]:
        reason = entry.reasons.most_common(1)[0][0] if entry.reasons else "?"
        hint = fix_hints.fix_hint(entry.rule, tool=entry.tools.only, matched_arg=entry.args.only)
        found.append((entry, reason, hint))
    return found


# ---- text output ------------------------------------------------------------------------

def print_summary(summary: Summary, show_args: bool) -> None:
    """The text report: counts, the most common reasons for blocks with fixes, and the last blocks."""
    # Said first and plainly: a line that cannot be read may be a record someone wanted hidden.
    if summary.unreadable:
        print(f"WARNING: {summary.unreadable} line(s) of the log could not be read and are not counted below.")
    if not summary.total:
        print("The audit log has no readable records.")
        return
    if summary.filter.active:
        print(f"Filter: {summary.filter.describe()}")
        if not summary.matching:
            print(f"None of the {summary.total} records matches the filter.")
            return
    first = field_text(summary.first or {}, "time")
    last = field_text(summary.last or {}, "time")
    of_total = f" (of {summary.total} in the log)" if summary.filter.active else ""
    print(f"{summary.matching} records{of_total} from {first} to {last}")

    columns = _COLUMNS + (("ask",) if summary.has_ask else ())
    if summary.calls.counts:
        title = "Tool calls" if summary.by == "tool" else "Tool calls, by server"
        _print_table(title, summary.calls, "allowed", columns)
    if summary.checks.counts:
        _print_table("Content checks, by kind", summary.checks, "passed", columns)

    top = _top_reasons(summary)
    if top:
        print("\nTop reasons for blocks:")
        for entry, reason, hint in top:
            rule = f"{fix_hints.classify(entry.rule).text}: " if entry.rule else ""
            print(f"  {entry.count:>6}  {rule}{reason}")
            print_field("How to fix", hint, indent=10)

    if summary.blocked:
        print(f"\nLast {len(summary.blocked)} blocked:")
        for record in summary.blocked:
            print(f"  {_block_line(record)}")
            if show_args and "args" in record:
                print(f"      args: {_args_text(record)}")


def _print_table(title: str, table: _Table, first_column: str, columns: tuple[str, ...]) -> None:
    header = f"\n{title:40} {first_column:>8} {'blocked':>8} {'would block':>12}"
    if "ask" in columns:
        header += f" {'asked':>6}"
    print(header + f" {'other':>6}")
    for name in sorted(table.names):
        row = [table.counts[(name, action)] for action in (*columns, "other")]
        line = f"{name:40} {row[0]:>8} {row[1]:>8} {row[2]:>12}"
        if "ask" in columns:
            line += f" {row[3]:>6}"
        print(line + f" {row[-1]:>6}")


def _block_line(record: dict[str, Any]) -> str:
    """One block as `time  event  tool: reason  [rule; ref; server]`, every part printable."""
    line = (
        f"{field_text(record, 'time')}  {field_text(record, 'event')}  {field_text(record, 'tool')}: "
        f"{field_text(record, 'reason')}"
    )
    if record.get("action") == "would_block":
        line += " (would block: monitor mode let it through)"
    details = [field_text(record, "rule", 200)] if "rule" in record else []
    if "ref" in record:
        details.append(f"ref {field_text(record, 'ref', 20)}")
    if "server" in record:
        details.append(f"server {field_text(record, 'server', 64)}")
    return line + (f"  [{'; '.join(details)}]" if details else "")


def _args_text(record: dict[str, Any]) -> str:
    """A record's arguments, each value shortened (they can be anything an agent sent)."""
    return shown_args(record.get("args"), most=8, limit=80)


# ---- JSON output -------------------------------------------------------------------------

def _as_json(summary: Summary, show_args: bool) -> dict[str, Any]:
    columns = _COLUMNS + ("ask", "other")

    def table(counts: _Table) -> dict[str, dict[str, int]]:
        return {name: {action: counts.counts[(name, action)] for action in columns} for name in sorted(counts.names)}

    chosen = summary.filter
    blocked = []
    for record in summary.blocked:
        entry = {name: field_text(record, name, 500, missing="") for name in (
            "time", "server", "session", "event", "tool", "call_id", "action", "rule", "matched_arg", "ref", "reason",
        ) if name in record}
        if show_args and "args" in record:
            entry["args"] = _args_text(record)
        blocked.append(entry)
    return {
        "log": printable(summary.path, limit=500),
        "records": summary.total,
        "unreadable_lines": summary.unreadable,
        "matching_records": summary.matching,
        "filter": {
            "tool": chosen.tool, "servers": list(chosen.servers), "actions": list(chosen.actions),
            "events": list(chosen.events),
            "since": chosen.since.isoformat(timespec="seconds") if chosen.since else None,
            "until": chosen.until.isoformat(timespec="seconds") if chosen.until else None,
        },
        "from": field_text(summary.first, "time", 64) if summary.first is not None else None,
        "to": field_text(summary.last, "time", 64) if summary.last is not None else None,
        "calls_by": summary.by,
        "calls": table(summary.calls),
        "content_checks": table(summary.checks),
        "top_reasons": [
            {"rule": printable(entry.rule, limit=200) if entry.rule else None, "reason": reason,
             "count": entry.count, "how_to_fix": hint}
            for entry, reason, hint in _top_reasons(summary)
        ],
        "blocked": blocked,
    }


# ---- --follow ------------------------------------------------------------------------------

def follow(
    path: str, chosen: RecordFilter, show_args: bool, output: str,
    *, stop: Callable[[], bool], sleep: Callable[[float], None],
) -> int:
    """Print a line for each block added to the log from now on (each record with --action), until Ctrl+C."""
    print(f"Watching {printable(path, limit=500)} for new "
          f"{'records' if chosen.actions else 'blocks'}. Press Ctrl+C to stop.", flush=True)
    try:
        for record in auditlog.follow_records(path, stop=stop, sleep=sleep):
            if record is None:
                print("WARNING: a line of the log could not be read.", flush=True)
                continue
            if not chosen.matches(record) or (not chosen.actions and not auditlog.is_block(record)):
                continue
            print(_follow_line(record, show_args, output), flush=True)
    except KeyboardInterrupt:
        pass
    return EXIT_OK


def _follow_line(record: dict[str, Any], show_args: bool, output: str) -> str:
    """One record as one line: `20:46:26  BLOCK  call  read_file  [deny_args[0]]  ref 7f3a9c21`, or as JSON."""
    if output == "json":
        entry = {name: field_text(record, name, 300, missing="") for name in (
            "time", "server", "event", "tool", "action", "rule", "matched_arg", "ref", "reason",
        ) if name in record}
        if show_args and "args" in record:
            entry["args"] = _args_text(record)
        return json.dumps(entry, ensure_ascii=True)
    action = field_text(record, "action", 20).upper()
    parts = [auditlog.clock_time(record), action, field_text(record, "event", 40), field_text(record, "tool", 80)]
    if show_args and "args" in record:
        parts.append(_args_text(record))
    if "rule" in record:
        parts.append(f"[{field_text(record, 'rule', 120)}]")
    if "ref" in record:
        parts.append(f"ref {field_text(record, 'ref', 20)}")
    if "server" in record:
        parts.append(f"server {field_text(record, 'server', 64)}")
    line = "  ".join(parts)
    return line if len(line) <= MAX_FOLLOW_LINE_CHARS else line[:MAX_FOLLOW_LINE_CHARS] + "..."
