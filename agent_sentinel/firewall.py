"""The firewall: checks tool calls against a policy, scans text, logs both.

This is the core that everything else calls. It answers two questions:

    check_call(tool, args)   may the agent make this call?        (policy, secrets, rate limits)
    scan_result(tool, text)  may the agent read this text?        (detector)

Both return a `Decision` and write one line to the audit log.

A Decision carries two texts. `reason` is the full detail and goes to the audit
log and the human approver. `public_reason` is what may be shown to the agent:
it never says which rule or pattern refused the call, because a hijacked agent
would use that to find a way round the policy.
"""

from __future__ import annotations

import inspect
import json
import sys
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterable

from .detector import SEVERITY_ORDER, Finding, max_severity, scan_views
from .leaks import find_secrets, redact
from .policy import Policy, Verdict
from .textutil import UnscannableError, text_views, texts_in

# Called for "ask" rules: (tool, args, reason) -> True to approve. It must
# return exactly True to approve; anything else is a refusal. `tool` and `args`
# are chosen by the agent: pass them through `printable` before showing them.
Approver = Callable[[str, dict[str, Any], str], bool]

RATE_WINDOW_SECONDS = 60

_INJECTION_REFUSAL = "possible prompt injection; the content was withheld"
_SECRET_REFUSAL = "the arguments contain what looks like a secret, so the call was not made"
_RATE_REFUSAL = "too many calls in a short time; try again later"
_UNSCANNABLE_REFUSAL = "the result has a type that cannot be checked"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str  # full detail: for the audit log and the operator
    findings: list[Finding] = field(default_factory=list)
    public_reason: str = ""  # safe to show to the agent; defaults to `reason`

    def __post_init__(self) -> None:
        if not self.public_reason:
            object.__setattr__(self, "public_reason", self.reason)

    def __bool__(self) -> bool:
        # So that `if firewall.check_call(...):` means what it looks like.
        return self.allowed


class BlockedError(Exception):
    """Raised by Firewall.run when a call or its result is blocked.

    str(error) is the public reason, safe to hand to the agent. The full
    Decision, with the detailed reason, is in `error.decision`.
    """

    def __init__(self, decision: Decision | str) -> None:
        if isinstance(decision, str):
            decision = Decision(False, decision)
        super().__init__(decision.public_reason)
        self.decision = decision


class _RateLimiter:
    """Counts calls per bucket over a sliding window. Thread-safe."""

    def __init__(self) -> None:
        self._calls: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def over_limit(self, limits: list[tuple[str, int]], now: float) -> str | None:
        """Record one call in every bucket, unless one is full; then return that bucket."""
        with self._lock:
            for bucket, limit in limits:
                calls = self._calls.setdefault(bucket, deque())
                while calls and calls[0] <= now - RATE_WINDOW_SECONDS:
                    calls.popleft()
                if len(calls) >= limit:
                    return bucket
            for bucket, _ in limits:
                self._calls[bucket].append(now)
        return None


class Firewall:
    def __init__(
        self,
        policy: Policy,
        audit_path: str | Path | None = None,
        approver: Approver | None = None,
        log_args: bool = True,
        monitor: bool = False,
    ) -> None:
        """
        monitor: record what WOULD be blocked (audit action "would_block") but
                 allow it. For tuning a new policy; it protects nothing.
        """
        self.policy = policy
        self.audit_path = Path(audit_path) if audit_path else None
        self.approver = approver
        self.log_args = log_args
        self.monitor = monitor
        self._limiter = _RateLimiter()
        self._audit_lock = threading.Lock()
        self._audit_failed = False

    # ---- decisions ----------------------------------------------------------

    def check_call(self, tool: str, args: dict[str, Any] | None = None) -> Decision:
        """Decide whether the agent may call `tool` with `args`."""
        if args is None:
            args = {}
        if not isinstance(args, dict):
            return self.block(tool, "tool arguments must be an object")
        return self._finish("call", tool, self._decide_call(tool, args), args=args)

    def scan_result(
        self, tool: str, text: str | Iterable[str], event: str = "result", log_clean: bool = True
    ) -> Decision:
        """Scan text before the agent reads it.

        text:      one text, or several views of the same content (see
                   `textutil.text_views`); a finding in any view counts.
        event:     labels the audit record, e.g. "result" or "tool_description".
        log_clean: set False to log only when something was found (useful for
                   high-volume traffic such as progress notifications).
        """
        findings = scan_views([text] if isinstance(text, str) else text)
        worst = max_severity(findings)
        threshold = self.policy.block_severity
        rules = ", ".join(f.rule for f in findings)
        if worst is None:
            decision = Decision(True, "no injection patterns found")
        elif threshold is not None and SEVERITY_ORDER[worst] >= SEVERITY_ORDER[threshold]:
            decision = Decision(False, f"possible prompt injection ({rules})", findings, _INJECTION_REFUSAL)
        else:
            decision = Decision(True, f"suspicious content below blocking threshold ({rules})", findings)
        return self._finish(event, tool, decision, log=bool(findings) or log_clean)

    def block(self, tool: str, reason: str, event: str = "call", public_reason: str = "") -> Decision:
        """Record and return a block that did not come from the policy or the detector."""
        return self._finish(event, tool, Decision(False, reason, public_reason=public_reason))

    def run(self, tool: str, args: dict[str, Any], fn: Callable[..., Any]) -> Any:
        """Check the call, run `fn(**args)`, scan its result, and return it.

        Raises BlockedError if the call, the result, or the text of an error
        raised by the tool is blocked. For an `async def` tool use `run_async`.
        """
        self._require_allowed(self.check_call(tool, args))
        try:
            result = fn(**args)
        except Exception as exc:
            self._scan_tool_error(tool, exc)
            raise
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):
                result.close()  # it will never be awaited; avoid a runtime warning
            self._require_allowed(self.block(tool, "the tool returned an awaitable; use run_async", event="result"))
        return self._checked_result(tool, result)

    async def run_async(self, tool: str, args: dict[str, Any], fn: Callable[..., Awaitable[Any]]) -> Any:
        """Like `run`, for a tool that is an `async def` function."""
        self._require_allowed(self.check_call(tool, args))
        try:
            result = await fn(**args)
        except Exception as exc:
            self._scan_tool_error(tool, exc)
            raise
        return self._checked_result(tool, result)

    # ---- internals: calls ---------------------------------------------------

    def _decide_call(self, tool: str, args: dict[str, Any]) -> Decision:
        verdict = self.policy.evaluate(tool, args)
        if verdict.action == "block":
            return Decision(False, verdict.reason, public_reason=verdict.public)

        if self.policy.secrets_in_arguments == "block":
            secrets = find_secrets("\n".join(texts_in(args, keys=True)))
            if secrets:
                reason = f"arguments contain what looks like a secret ({', '.join(secrets)})"
                return Decision(False, reason, public_reason=_SECRET_REFUSAL)

        bucket = self._limiter.over_limit(self.policy.call_limits(tool), time.monotonic())
        if bucket is not None:
            return Decision(False, f"rate limit reached for '{bucket}'", public_reason=_RATE_REFUSAL)

        if verdict.action == "ask":
            return self._ask_human(tool, args, verdict)
        return Decision(True, verdict.reason)

    def _ask_human(self, tool: str, args: dict[str, Any], verdict: Verdict) -> Decision:
        def refused(why: str) -> Decision:
            return Decision(False, f"{verdict.reason}; {why}", public_reason=verdict.public)

        if self.approver is None:
            return refused("approval required but no approver is configured")
        try:
            answer = self.approver(tool, args, verdict.reason)
        except Exception as exc:  # a broken approver must not approve anything
            return refused(f"the approver failed ({type(exc).__name__})")
        if inspect.iscoroutine(answer):
            answer.close()
            return refused("the approver is async, which is not supported, so nobody was asked")
        if answer is True:  # exactly True: a truthy "no" or an un-awaited coroutine must not approve
            return Decision(True, f"{verdict.reason}; approved by a human")
        if answer is False:
            return refused("rejected by a human")
        return refused("the approver did not return True or False")

    # ---- internals: results -------------------------------------------------

    def _checked_result(self, tool: str, result: Any) -> Any:
        try:
            views = text_views(result, strict=True)
        except UnscannableError as exc:
            # Fail closed: a result that cannot be read cannot be called clean.
            self._require_allowed(self.block(tool, str(exc), event="result", public_reason=_UNSCANNABLE_REFUSAL))
            return result  # only reached in monitor mode
        self._require_allowed(self.scan_result(tool, views))
        return result

    def _scan_tool_error(self, tool: str, exc: Exception) -> None:
        """An error message from a tool is attacker-controlled text too."""
        decision = self.scan_result(tool, str(exc), event="tool_error", log_clean=False)
        if not decision.allowed:
            raise BlockedError(decision) from None  # do not carry the text along as __cause__

    @staticmethod
    def _require_allowed(decision: Decision) -> None:
        if not decision.allowed:
            raise BlockedError(decision)

    # ---- internals: audit ---------------------------------------------------

    def _finish(
        self, event: str, tool: str, decision: Decision, args: dict[str, Any] | None = None, log: bool = True
    ) -> Decision:
        """Write the audit record and apply monitor mode."""
        if self.monitor and not decision.allowed:
            self._audit(event, tool, "would_block", decision, args)
            return Decision(True, f"monitor mode, would block: {decision.reason}", decision.findings)
        if log:
            self._audit(event, tool, "allow" if decision.allowed else "block", decision, args)
        return decision

    def _audit(self, event: str, tool: str, action: str, decision: Decision, args: dict[str, Any] | None) -> None:
        if self.audit_path is None:
            return
        record: dict[str, Any] = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event,
            "tool": tool,
            "action": action,
            "reason": decision.reason,
        }
        if args is not None and self.log_args:
            record["args"] = args
        if decision.findings:
            record["findings"] = [asdict(f) for f in decision.findings]
        line = _log_safe(redact(json.dumps(record, ensure_ascii=False, default=str)))
        try:
            with self._audit_lock, self.audit_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError as exc:
            # A broken log must not stop the firewall from enforcing decisions.
            if not self._audit_failed:
                self._audit_failed = True
                print(f"agent-sentinel: cannot write audit log {self.audit_path}: {exc}", file=sys.stderr)


def _log_safe(json_line: str) -> str:
    """Escape every character that is not plainly printable in a line of JSON.

    json.dumps escapes the ASCII control characters only. That leaves DEL, the
    C1 controls (one of them starts a terminal escape sequence), bidi overrides
    and the Unicode line separators, any of which can mislead someone reading
    the log with `cat` or split one record in two. Such characters only occur
    inside JSON strings, so a \\uXXXX escape is always valid there. Ordinary
    non-English text stays readable.
    """
    if json_line.isascii() and json_line.isprintable():
        return json_line

    def escape(ch: str) -> str:
        code = ord(ch)
        if code < 0x10000:
            return f"\\u{code:04x}"
        code -= 0x10000
        return f"\\u{0xD800 + (code >> 10):04x}\\u{0xDC00 + (code & 0x3FF):04x}"

    return "".join(ch if ch.isprintable() else escape(ch) for ch in json_line)
