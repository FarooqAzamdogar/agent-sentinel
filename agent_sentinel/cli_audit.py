"""`agent-sentinel audit verify FILE [FILE ...] [--key-file K]`: check an audit log's hash chain.

    agent-sentinel audit verify audit.jsonl
    agent-sentinel audit verify audit.jsonl --key-file ~/.agent-sentinel/audit.key
    agent-sentinel audit verify audit.jsonl.1 audit.jsonl.2 audit.jsonl     (rotated files, oldest first)

Every record the firewall writes carries seq, prev and hash, and with a key a
MAC (see audit_chain.py). This command reads the log line by line (bounded,
as `report` does) and says whether the chain is intact. If it is not, it
names the first record that was changed, inserted, moved or is missing, then
counts the other problems and the MAC mismatches.

What it cannot see: without --key-file, someone who could write the file can
have worked out every hash again; and records cut from the END of the log
leave no trace. The last seq and hash it prints are what to keep elsewhere to
catch that later.
"""

from __future__ import annotations

import argparse
import os

from .audit_chain import BROKEN, EMPTY, INTACT, MAX_PROBLEMS_KEPT, AuditKeyError, ChainReport, check_files, read_key_file
from .cli_common import EXIT_FAIL, EXIT_OK, CommandError, full_path, shown_path
from .textutil import printable

HELP = "check an audit log's hash chain and MACs (audit verify FILE [--key-file K])"
DESCRIPTION = (
    "Check that an audit log is as it was written: every record links to the one before it (seq, prev, hash) "
    "and, with --key-file, carries the right MAC."
)
EPILOG = """\
examples:
  agent-sentinel audit verify audit.jsonl
  agent-sentinel audit verify audit.jsonl --key-file ~/.agent-sentinel/audit.key
  agent-sentinel audit verify audit.jsonl.1 audit.jsonl.2 audit.jsonl   (rotated files, oldest first)

exit codes:
  0  intact (or empty)    1  broken, or not chained at all    2  a usage error, or a file that cannot be read

Without --key-file, the chain detects naive edits only: anyone who can write the log can work out every hash
again. Records cut from the end of the log are not detected: keep the last seq and hash somewhere else.
"""
# How many problems are listed after the first.
SHOWN_PROBLEMS = 10


def add_arguments(parser: argparse.ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="audit_command", required=True, metavar="{verify}")
    verify = commands.add_parser(
        "verify", help="check the hash chain (and with --key-file the MACs) of one log, or of rotated files in order",
        description=DESCRIPTION, epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verify.add_argument("files", nargs="+", metavar="FILE",
                        help="the audit log; for a rotated log, every file oldest first (FILE.1 FILE.2 ... FILE)")
    verify.add_argument("--key-file", metavar="K",
                        help="the audit key file the log was written with (proxy or hook --audit-key-file): "
                             "check every record's MAC too")


def run(args: argparse.Namespace) -> int:
    key = None
    if args.key_file is not None:
        try:
            key = read_key_file(full_path(args.key_file))
        except AuditKeyError as exc:
            raise CommandError(f"cannot use the key file {shown_path(args.key_file)}: {exc}") from exc
    paths = [full_path(path) for path in args.files]
    for path in paths:
        if os.path.isdir(path):
            raise CommandError(f"{shown_path(path)} is a folder, not an audit log")
    try:
        report = check_files(paths, key)
    except OSError as exc:
        raise CommandError(f"cannot read {shown_path(exc.filename or '')}: {exc.strerror or type(exc).__name__}"
                           ) from exc
    print_report(report, [printable(path, limit=300) for path in args.files])
    return EXIT_OK if report.state in (INTACT, EMPTY) else EXIT_FAIL


def print_report(report: ChainReport, names: list[str]) -> None:
    """What the check found, in a few lines; the verdict (INTACT, BROKEN, ...) starts its own line."""
    shown = ", ".join(names)
    if report.state == EMPTY:
        print(f"{shown}: empty. Nothing to check (records cut from the end cannot be detected).")
        return
    span = f"seq {report.first_seq} to {report.last_seq}" if report.chained else "none chained"
    print(f"Checked {shown}: {report.lines} line(s), {report.chained} chained record(s) ({span}).")
    if report.unchained_prefix:
        print(f"  The first {report.unchained_prefix} line(s) have no chain fields: agent-sentinel 0.5 or earlier "
              "wrote them, so they cannot be checked.")
    print(f"  MACs: {_mac_state(report)}")
    for note in report.notes:
        print(f"  Note: {note}")
    if report.state == INTACT:
        print("INTACT: every record is as it was written and follows the one before it.")
    elif report.state == BROKEN:
        print(f"BROKEN: {report.problems[0]}")
        others = report.problems[1:1 + SHOWN_PROBLEMS]
        if report.problem_count > 1:
            print(f"  {report.problem_count - 1} more problem(s):")
            for problem in others:
                print(f"    {problem}")
            hidden = report.problem_count - 1 - len(others)
            if hidden > 0:
                kept = "" if report.problem_count <= MAX_PROBLEMS_KEPT else f"; the first {MAX_PROBLEMS_KEPT} are kept"
                print(f"    ... and {hidden} more{kept}")
        if report.key_given:
            print(f"  MAC mismatches: {report.mac_mismatches}")
    else:
        print("NOT VERIFIABLE: no record of the log has chain fields (agent-sentinel 0.5 or earlier, or another "
              "program, wrote it).")
    if report.last_seq is not None and report.last_hash is not None:
        print(f"Last record: seq {report.last_seq}, hash {report.last_hash}. Records cut from the end of the log "
              "cannot be detected: keep these two values somewhere the agent cannot write, and compare later.")


def _mac_state(report: ChainReport) -> str:
    if report.key_given:
        if report.mac_mismatches:
            return f"checked with the key: {report.mac_mismatches} record(s) do not match"
        return "checked with the key: every chained record's MAC matches"
    if report.macs_present:
        return "not checked: the records carry MACs; give --key-file to check them"
    return "none: the log was written without a key, so the chain detects naive edits only"
