"""`agent-sentinel scan`: look for prompt injection in text files, and say whether a policy would block them.

    agent-sentinel scan page.txt
    agent-sentinel scan --policy policy.json a.txt b.txt
    cat page.txt | agent-sentinel scan --fail-on medium --format json

Each file is read in every encoding it could be meant in (see
cli_common.readings) and scanned with the same detector the firewall uses.
The output ends with a verdict: would the text be blocked, at the threshold
of the policy (--policy), at a severity given on the command line
(--fail-on), or at the default threshold ("high")?

--as says what the text is: a tool's "result" (the default), a tool's
"description", or a server's "instructions". The last two are read with the
stricter rules for what a server says about itself (detector.METADATA), as
the proxy reads a tools/list reply or an initialize reply: use them to look
at a server's tools before it is installed.

Exit codes. Without --policy or --fail-on they are as before 0.5: 1 when
anything is found, at any severity. With either option, 1 only when a finding
reaches the threshold, so the command can gate a CI job. 2 when a file cannot
be read or the options are wrong; the other files are still scanned.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field

from .cli_common import EXIT_ERROR, EXIT_FAIL, EXIT_OK, CommandError, load_policy, read_input, readings
from .detector import METADATA, RESULT, SEVERITY_ORDER, Finding, scan_views
from .leaks import redact
from .policy import Policy
from .textutil import printable

HELP = "scan text files (or stdin) for prompt injection"
DESCRIPTION = (
    "Scan text for prompt injection with the firewall's detector, and say whether a policy would block it. "
    "The detector is pattern rules: a clean scan is not proof that the text is safe."
)
EPILOG = """\
exit codes:
  0  nothing found (with --policy or --fail-on: nothing at or above the threshold)
  1  something found (with --policy or --fail-on: a finding at or above the threshold)
  2  a file could not be read, or the options are wrong

examples:
  agent-sentinel scan page.txt
  agent-sentinel scan --policy policy.json notes.md page.html
  agent-sentinel scan --as description tool-description.txt
  cat page.txt | agent-sentinel scan --fail-on medium --format json
"""

# --as: what the text is, and the detector's profile for it (as the firewall picks it for each scan_result event).
PROFILES = {"result": RESULT, "description": METADATA, "instructions": METADATA}
# More files than this in one command is almost certainly a mistake (a glob gone wrong).
MAX_FILES = 1_000
# The threshold the firewall uses when a policy does not set one.
DEFAULT_THRESHOLD = Policy().block_severity
_CLEAN = "No injection patterns found. (Pattern rules only: this is not proof the text is safe.)"


@dataclass
class _Scanned:
    name: str  # as given on the command line, or "stdin"
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


@dataclass(frozen=True)
class _Threshold:
    severity: str | None  # None: the policy blocks no content
    source: str  # "policy", "fail-on" or "default"
    label: str  # for the verdict line


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("files", nargs="*", metavar="FILE", help="files to scan; none, or '-', reads stdin")
    threshold = parser.add_mutually_exclusive_group()
    threshold.add_argument("--policy", metavar="POLICY",
                           help="judge the findings with this policy's injection.block_severity")
    threshold.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), metavar="SEVERITY",
                           help="exit with 1 only for a finding of this severity or higher (low, medium, high)")
    parser.add_argument("--as", dest="read_as", choices=tuple(PROFILES), default="result",
                        help="what the text is: a tool's result (the default), a tool's description, or a server's "
                             "instructions (these two are read with the stricter rules for what a server says "
                             "about itself)")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="output format (default text)")


def run(args: argparse.Namespace) -> int:
    names = list(args.files) or ["-"]
    if names.count("-") > 1:
        raise CommandError("stdin ('-') can be read only once")
    if len(names) > MAX_FILES:
        raise CommandError(f"at most {MAX_FILES} files can be scanned at once, got {len(names)}")
    threshold = _threshold(args)
    if threshold is None:
        return EXIT_ERROR
    scanned = [_scan_one(name, PROFILES[args.read_as]) for name in names]
    blocked = [item for item in scanned if _reaches(item.findings, threshold.severity)]
    if args.format == "json":
        _print_json(scanned, blocked, threshold)
    else:
        _print_text(scanned, blocked, threshold)

    if any(item.error for item in scanned):
        return EXIT_ERROR
    if threshold.source == "default":  # as before 0.5: any finding at all
        return EXIT_FAIL if any(item.findings for item in scanned) else EXIT_OK
    return EXIT_FAIL if blocked else EXIT_OK


def _threshold(args: argparse.Namespace) -> _Threshold | None:
    """Where the blocking severity comes from; None (after printing why) if the policy cannot be loaded."""
    if args.policy is not None:
        policy = load_policy(args.policy)
        if policy is None:
            return None
        severity = policy.block_severity
        label = f"block_severity={severity}" if severity else "this policy blocks no content (block_severity null)"
        return _Threshold(severity, "policy", label)
    if args.fail_on is not None:
        return _Threshold(args.fail_on, "fail-on", f"--fail-on {args.fail_on}")
    return _Threshold(DEFAULT_THRESHOLD, "default", f"the default block_severity={DEFAULT_THRESHOLD}")


def _scan_one(name: str, profile: str = RESULT) -> _Scanned:
    shown = "stdin" if name == "-" else name
    try:
        data = read_input(name)
    except CommandError as exc:
        return _Scanned(shown, error=str(exc))
    return _Scanned(shown, findings=scan_views(readings(data), profile=profile))


def _reaches(findings: list[Finding], severity: str | None) -> bool:
    if severity is None:
        return False
    return any(SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[severity] for finding in findings)


def _excerpt(finding: Finding) -> str:
    # Excerpts end up in CI logs and terminals: secrets are redacted, control codes escaped.
    return printable(redact(finding.excerpt), limit=200)


def _print_text(scanned: list[_Scanned], blocked: list[_Scanned], threshold: _Threshold) -> None:
    single = len(scanned) == 1
    for item in scanned:
        if item.error:
            print(f"agent-sentinel: {printable(item.error, limit=500)}", file=sys.stderr)
            continue
        if not single:
            print(f"{printable(item.name, limit=200)}:" + ("" if item.findings else " no injection patterns found"))
        elif not item.findings:
            print(_CLEAN)
        for finding in item.findings:
            indent = "" if single else "  "
            print(f"{indent}[{finding.severity.upper():6}] {finding.rule}: {_excerpt(finding)}")
    print(_verdict(scanned, blocked, threshold))


def _verdict(scanned: list[_Scanned], blocked: list[_Scanned], threshold: _Threshold) -> str:
    """The last line of the text output: would the firewall block this, and why."""
    findings = [finding for item in scanned for finding in item.findings]
    errors = sum(1 for item in scanned if item.error)
    unread = f"; {errors} file(s) could not be read" if errors else ""
    if blocked:
        counted = sum(1 for finding in findings if _reaches([finding], threshold.severity))
        where = f" in {len(blocked)} of {len(scanned)} inputs" if len(scanned) > 1 else ""
        return f"Verdict: would be BLOCKED ({threshold.label}; {counted} finding(s) at or above it{where}){unread}"
    if findings:
        return f"Verdict: would pass ({threshold.label}); {len(findings)} finding(s) below it, only logged{unread}"
    return f"Verdict: would pass ({threshold.label}); nothing found{unread}"


def _print_json(scanned: list[_Scanned], blocked: list[_Scanned], threshold: _Threshold) -> None:
    files = []
    for item in scanned:
        files.append({
            "file": printable(item.name, limit=500),
            "findings": [
                {"rule": f.rule, "severity": f.severity, "excerpt": _excerpt(f)} for f in item.findings
            ],
            "blocked": _reaches(item.findings, threshold.severity),
            "error": printable(item.error, limit=500) if item.error else None,
        })
    output = {
        "verdict": "blocked" if blocked else "passed",
        "threshold": threshold.severity,
        "threshold_from": threshold.source,
        "files": files,
    }
    # ASCII only: valid JSON whatever the console's encoding, and no raw control characters.
    print(json.dumps(output, ensure_ascii=True, indent=2))
