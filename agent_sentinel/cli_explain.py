"""`agent-sentinel explain AUDIT_LOG`: why calls were blocked, and what would allow them.

    agent-sentinel explain audit.jsonl --ref 7f3a9c21
    agent-sentinel explain audit.jsonl --last 5 --policy policy.json

The agent is told only a short sentence and a reference, "(ref 7f3a9c21)",
which the user can paste here. The audit record with that reference names
the rule that decided; this command shows it with the call, the reason, and
a "to allow" hint for that kind of rule. With --policy it also describes the
rule as the policy has it now and checks the logged call against that policy
again, to show whether a change already allows it.

A reference is 32 random bits, so in a very long log two records can share
one: every record with it is shown. A call that waited for approval and was
refused has two records with the same reference (the "ask" and the answer).

Exit codes: 0 something was explained, 1 nothing matched, 2 an error.
"""

from __future__ import annotations

import argparse
import re
from collections import deque
from typing import Any

from . import auditlog, fix_hints
from .auditlog import field_text, text_of
from .cli_common import (
    EXIT_ERROR,
    EXIT_FAIL,
    EXIT_OK,
    CommandError,
    load_policy,
    positive_int,
    print_field,
    shown_args,
)
from .firewall import shown_excerpt
from .policy import Policy
from .policy_errors import quoted
from .textutil import printable

HELP = "explain blocks from an audit log (by --ref, or the last few), with how to allow them"
DESCRIPTION = (
    "Explain why calls were blocked, from the audit log: the rule that decided, the reason, and what the "
    "operator could change to allow the call. Give the reference the agent was shown, or let it explain the "
    "last blocks."
)
EPILOG = """\
examples:
  agent-sentinel explain audit.jsonl --ref 7f3a9c21
  agent-sentinel explain audit.jsonl --last 5 --policy policy.json

exit codes:
  0  something was explained    1  no record matched    2  an error
"""

DEFAULT_LAST = 3
# A reference is random, so a few records can share one; more than this is a log someone filled on purpose.
MAX_REF_MATCHES = 20
MAX_FINDINGS_SHOWN = 10
_REF = re.compile(r"\(?\s*(?:ref\s+)?([0-9a-f]{8})\s*\)?")

# Kinds of rule whose answer depends only on the policy and the call's arguments, so the
# logged call can be checked again. Not flows (they depend on the session), not rate
# limits (on the time), not the secret guard (secrets are redacted in the log).
_POLICY_KINDS = frozenset({"default", "tool", "deny_global", "deny_tool", "allow_tool", "other_args", "command"})

_HEADINGS = {
    "block": "BLOCKED",
    "would_block": "WOULD BE BLOCKED (monitor mode let it through)",
    "ask": "WAITING FOR APPROVAL",
}
# The answer to an "ask" that did not let the call through, by the record's "approval". Without one,
# a person approved the call and a flow rule blocked it as the session had changed while it waited.
_REFUSED_HEADINGS = {
    "refused": "REFUSED when a person was asked",
    "unavailable": "REFUSED: nobody could be asked",
}
_BLOCKED_AFTER_APPROVAL = "BLOCKED after it was approved"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("audit", help="the audit log (JSON lines)")
    parser.add_argument("--policy", metavar="POLICY",
                        help="the policy as it is now: describe each rule and check each logged call against it again")
    which = parser.add_mutually_exclusive_group()
    which.add_argument("--ref", help="the reference from the refusal, such as 7f3a9c21 (or '(ref 7f3a9c21)')")
    which.add_argument("--last", type=positive_int, metavar="N",
                       help=f"explain the last N blocks (the default, with N={DEFAULT_LAST})")


def run(args: argparse.Namespace) -> int:
    policy = None
    if args.policy is not None:
        policy = load_policy(args.policy)
        if policy is None:
            return EXIT_ERROR
    ref = parse_ref(args.ref) if args.ref is not None else None
    records, unreadable, more = find_records(args.audit, ref, args.last or DEFAULT_LAST)
    if unreadable:
        print(f"WARNING: {unreadable} line(s) of the log could not be read; a record there cannot be explained.")
    if not records:
        print(f"No record in the log has ref {ref}." if ref else "The log has no blocked calls.")
        return EXIT_FAIL
    if ref is not None and len(records) > 1:
        shown = f"; the first {len(records)} are shown" if more else ""
        print(f"{len(records) + more} records have ref {ref}{shown}.")
    for number, record in enumerate(records):
        if number:
            print()
        explain_record(record, policy)
    return EXIT_OK


def parse_ref(text: str) -> str:
    """The reference in what the user typed or pasted ("7f3a9c21", "(ref 7f3a9c21)"). CommandError otherwise."""
    found = _REF.fullmatch(text.strip().lower())
    if found is None:
        raise CommandError(
            f"{quoted(text, limit=60)} is not a reference: it is 8 characters from 0-9 and a-f, "
            "as in '(ref 7f3a9c21)'"
        )
    return found.group(1)


def find_records(path: str, ref: str | None, last: int) -> tuple[list[dict[str, Any]], int, int]:
    """(the records to explain, unreadable lines, how many more matched than are returned)."""
    unreadable = more = 0
    if ref is not None:
        matches: list[dict[str, Any]] = []
        for record in auditlog.iter_records(path):
            if record is None:
                unreadable += 1
            elif record.get("ref") == ref:
                if len(matches) < MAX_REF_MATCHES:
                    matches.append(record)
                else:
                    more += 1
        return matches, unreadable, more
    blocks: deque[dict[str, Any]] = deque(maxlen=last)
    for record in auditlog.iter_records(path):
        if record is None:
            unreadable += 1
        elif auditlog.is_block(record):
            blocks.append(record)
    return list(blocks), unreadable, 0


# ---- one record -------------------------------------------------------------------------------

def explain_record(record: dict[str, Any], policy: Policy | None) -> None:
    """Print what one audit record says, the rule behind it, and how to allow the call."""
    action = text_of(record, "action") or "?"
    approval = text_of(record, "approval")
    heading = _HEADINGS.get(action, printable(action, limit=20).upper())
    if record.get("event") == "approval":
        heading = "APPROVED" if action == "allow" else _REFUSED_HEADINGS.get(approval or "", _BLOCKED_AFTER_APPROVAL)
    ref = f"ref {field_text(record, 'ref', 20)}  " if "ref" in record else ""
    print(f"{ref}{field_text(record, 'time', 40)}  {heading}  {field_text(record, 'event', 40)} "
          f"{field_text(record, 'tool', 120)}")

    origin = [f"{name} {field_text(record, name, 64)}" for name in ("server", "session", "call_id") if name in record]
    if origin:
        print_field("from", ", ".join(origin))
    if "args" in record:
        args = record["args"]
        shown = shown_args(args, most=12, limit=120) if isinstance(args, dict) else field_text(record, "args")
        print_field("arguments", shown)
    rule = record.get("rule")
    decided = field_text(record, "rule", 200) if "rule" in record else "(not named: a log written before 0.5)"
    if isinstance(record.get("matched_arg"), str):
        decided += f", argument '{field_text(record, 'matched_arg', 80)}'"
    print_field("decided by", decided)
    if policy is not None and isinstance(rule, str):
        # An id far longer than any the firewall writes comes from an edited log: not worth looking up.
        described = policy.describe_rule(rule) if len(rule) <= fix_hints.MAX_RULE_ID_CHARS else None
        if described is None:
            described = "this policy has no such rule now (it was changed, or it is another policy)"
        print_field("rule now", printable(described, limit=1000))
    print_field("reason", field_text(record, "reason", 1000))
    _print_findings(record)
    if policy is not None:
        _print_policy_now(record, policy)
    # Not for an "ask" record: the call was still waiting; the answer has a record of its own.
    if action in ("block", "would_block"):
        hint = fix_hints.fix_hint(
            rule, tool=text_of(record, "tool"), matched_arg=text_of(record, "matched_arg"),
            args=record.get("args"), policy=policy, approval=approval,
        )
        print_field("to allow", hint)


def _print_findings(record: dict[str, Any]) -> None:
    findings = record.get("findings")
    if not isinstance(findings, list):
        return
    readable = [finding for finding in findings[:MAX_FINDINGS_SHOWN] if isinstance(finding, dict)]
    for number, finding in enumerate(readable):
        severity = printable(finding.get("severity", "?"), limit=10).upper()
        excerpt = printable(shown_excerpt(str(finding.get("excerpt", ""))), limit=200)
        rule = printable(finding.get("rule", "?"), limit=60)
        print_field("findings" if number == 0 else "", f"[{severity:6}] {rule}: {excerpt}")
    if len(findings) > MAX_FINDINGS_SHOWN:
        print_field("", f"... and {len(findings) - MAX_FINDINGS_SHOWN} more")


def _print_policy_now(record: dict[str, Any], policy: Policy) -> None:
    """Check the logged call against the policy as it is now, when the answer depends only on the policy."""
    tool, args = text_of(record, "tool"), record.get("args")
    kind = fix_hints.classify(record.get("rule")).kind
    if record.get("event") != "call" or tool is None or kind not in _POLICY_KINDS:
        return
    if not isinstance(args, dict):
        print_field("policy now", "cannot check the call again: its arguments were not logged")
        return
    verdict = policy.evaluate(tool, args)
    rule = f" ({printable(verdict.rule, limit=200)})" if verdict.rule else ""
    print_field("policy now", f"{verdict.action.upper()}{rule}, for the arguments as logged")
    from_command = policy.command_labels(tool, args)
    if from_command:
        # labels_by_class: what the logged command does adds flow labels to this call.
        labels = ", ".join(sorted(policy.tool_labels(tool) | from_command))
        print_field("flow labels", f"{labels} (from what its command does: {', '.join(sorted(from_command))})")
