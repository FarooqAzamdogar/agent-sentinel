"""The firewall: checks tool calls against a policy, scans text, logs both.

This is the core that everything else calls. It has two questions to answer:

    check_call(tool, args)   may the agent make this call?        (policy)
    scan_result(tool, text)  may the agent read this text?        (detector)

Both return a `Decision` and write one line to the audit log.
"""

from __future__ import annotations

import json
import sys
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .detector import SEVERITY_ORDER, Finding, max_severity, scan
from .policy import Policy
from .textutil import texts_in

# Called for "ask" rules: (tool, args, reason) -> True to approve.
Approver = Callable[[str, dict[str, Any], str], bool]


class BlockedError(Exception):
    """Raised by Firewall.run when a call or its result is blocked."""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    findings: list[Finding] = field(default_factory=list)


class Firewall:
    def __init__(
        self,
        policy: Policy,
        audit_path: str | Path | None = None,
        approver: Approver | None = None,
        log_args: bool = True,
    ) -> None:
        self.policy = policy
        self.audit_path = Path(audit_path) if audit_path else None
        self.approver = approver
        self.log_args = log_args
        self._audit_lock = threading.Lock()
        self._audit_failed = False

    # ---- decisions ----------------------------------------------------------

    def check_call(self, tool: str, args: dict[str, Any] | None = None) -> Decision:
        """Decide whether the agent may call `tool` with `args`."""
        args = args or {}
        if not isinstance(args, dict):
            return self.block(tool, "tool arguments must be an object")

        verdict = self.policy.evaluate(tool, args)
        if verdict.action == "allow":
            decision = Decision(True, verdict.reason)
        elif verdict.action == "ask":
            decision = self._ask_human(tool, args, verdict.reason)
        else:
            decision = Decision(False, verdict.reason)
        self._audit("call", tool, decision, args=args)
        return decision

    def scan_result(self, tool: str, text: str, event: str = "result", log_clean: bool = True) -> Decision:
        """Scan text before the agent reads it.

        event:     labels the audit record, e.g. "result" or "tool_description".
        log_clean: set False to log only when something was found (useful for
                   high-volume traffic such as progress notifications).
        """
        findings = scan(text)
        worst = max_severity(findings)
        threshold = self.policy.block_severity
        rules = ", ".join(f.rule for f in findings)
        if worst is None:
            decision = Decision(True, "no injection patterns found")
        elif threshold is not None and SEVERITY_ORDER[worst] >= SEVERITY_ORDER[threshold]:
            decision = Decision(False, f"possible prompt injection ({rules})", findings)
        else:
            decision = Decision(True, f"suspicious content below blocking threshold ({rules})", findings)
        if findings or log_clean:
            self._audit(event, tool, decision)
        return decision

    def block(self, tool: str, reason: str, event: str = "call") -> Decision:
        """Record and return a block that did not come from the policy."""
        decision = Decision(False, reason)
        self._audit(event, tool, decision)
        return decision

    def run(self, tool: str, args: dict[str, Any], fn: Callable[..., Any]) -> Any:
        """Check the call, run `fn(**args)`, scan its result, and return it."""
        decision = self.check_call(tool, args)
        if not decision.allowed:
            raise BlockedError(decision.reason)
        result = fn(**args)
        decision = self.scan_result(tool, "\n".join(texts_in(result)))
        if not decision.allowed:
            raise BlockedError(decision.reason)
        return result

    # ---- internals ----------------------------------------------------------

    def _ask_human(self, tool: str, args: dict[str, Any], reason: str) -> Decision:
        if self.approver is None:
            return Decision(False, f"{reason}; approval required but no approver is configured")
        try:
            approved = self.approver(tool, args, reason)
        except Exception as exc:  # a broken approver must not approve anything
            return Decision(False, f"{reason}; the approver failed ({type(exc).__name__})")
        if approved:
            return Decision(True, f"{reason}; approved by a human")
        return Decision(False, f"{reason}; rejected by a human")

    def _audit(self, event: str, tool: str, decision: Decision, args: dict[str, Any] | None = None) -> None:
        if self.audit_path is None:
            return
        record: dict[str, Any] = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event,
            "tool": tool,
            "action": "allow" if decision.allowed else "block",
            "reason": decision.reason,
        }
        if args is not None and self.log_args:
            record["args"] = args
        if decision.findings:
            record["findings"] = [asdict(f) for f in decision.findings]
        line = json.dumps(record, ensure_ascii=False, default=str)
        try:
            # backslashreplace: JSON text can hold characters that UTF-8 cannot
            # encode (lone surrogates); those must not make logging fail.
            with self._audit_lock, self.audit_path.open("a", encoding="utf-8", errors="backslashreplace") as handle:
                handle.write(line + "\n")
        except OSError as exc:
            # A broken log must not stop the firewall from enforcing decisions.
            if not self._audit_failed:
                self._audit_failed = True
                print(f"agent-sentinel: cannot write audit log {self.audit_path}: {exc}", file=sys.stderr)
