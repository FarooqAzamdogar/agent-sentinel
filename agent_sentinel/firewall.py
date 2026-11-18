"""The firewall: checks tool calls against a policy, scans text, logs both.

This is the core that everything else calls. It answers two questions:

    check_call(tool, args)   may the agent make this call?        (secrets, policy, rate limits)
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
import os
import re
import sys
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, BinaryIO, Callable, Iterable

from .detector import SEVERITY_ORDER, Finding, max_severity, scan_views
from .leaks import find_secrets, redact, redact_value
from .policy import Policy, Verdict
from .textutil import UnscannableError, printable, text_views, texts_in

# Called for "ask" rules: (tool, args, reason) -> True to approve. It must
# return exactly True to approve; anything else is a refusal. `tool` and `args`
# are chosen by the agent: pass them through `printable` before showing them,
# and show every argument, not only the first few.
Approver = Callable[[str, dict[str, Any], str], bool]

RATE_WINDOW_SECONDS = 60
# Arguments longer than this, written as JSON, are left out of the audit log.
# Without a bound an agent could fill the disk with refused calls.
MAX_LOGGED_ARGS_CHARS = 100_000
# How many linked errors (causes, notes, group members) of a tool error are read.
MAX_ERROR_PARTS = 50

# A long unbroken run of letters and digits in an excerpt. An excerpt is cut
# out of the text around a match, and the cut can go through the middle of a
# token, leaving most of it in a form the redaction no longer recognises.
_LONG_RUN = re.compile(r"[A-Za-z0-9_+/=-]{20,}")

_INJECTION_REFUSAL = "possible prompt injection; the content was withheld"
_SECRET_REFUSAL = "the call contains what looks like a secret, so it was not made"
_RATE_REFUSAL = "too many calls in a short time; try again later"
_UNSCANNABLE_REFUSAL = "the content has a type that cannot be checked"


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
        monitor: record what the policy and the detector WOULD block (audit
                 action "would_block") but allow it. For tuning a new policy;
                 it protects nothing. Calls and results that cannot be checked
                 at all are still refused.
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
        if not isinstance(tool, str) or not isinstance(args, dict):
            return self.refuse(printable(tool, limit=80), "the tool name must be text and the arguments an object")
        return self._finish("call", tool, self._decide_call(tool, args), args=args)

    def scan_result(
        self, tool: str, content: Any, event: str = "result", log_clean: bool = True
    ) -> Decision:
        """Scan what a tool returned before the agent reads it.

        content:   a text, or whatever value a tool returned: bytes, a list, a
                   dict, nested as deep as it likes. A value is read through
                   `textutil.text_views`, so a phrase split over two items of
                   a list, or over two fields, is still seen as one.
        event:     labels the audit record, e.g. "result" or "tool_description".
        log_clean: set False to log only when something was found (useful for
                   high-volume traffic such as progress notifications).
        """
        if isinstance(content, str):
            views = [content]
        else:
            try:
                views = text_views(content, strict=True)
            except UnscannableError as exc:
                # Fail closed: content that cannot be read cannot be called clean.
                return self.refuse(tool, str(exc), event=event, public_reason=_UNSCANNABLE_REFUSAL)

        findings = scan_views(views)
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
        """Record and return a block that monitor mode may lift, like a block by the policy."""
        return self._finish(event, tool, Decision(False, reason, public_reason=public_reason))

    def refuse(self, tool: str, reason: str, event: str = "call", public_reason: str = "") -> Decision:
        """Record and return a block that always holds, even in monitor mode.

        For what cannot be checked at all: a malformed call, a result of an
        unreadable type. Monitor mode is for trying out a policy, and must not
        let these through.
        """
        decision = Decision(False, reason, public_reason=public_reason)
        self._audit(event, tool, "block", decision, None)
        return decision

    def run(self, tool: str, args: dict[str, Any] | None, fn: Callable[..., Any]) -> Any:
        """Check the call, run `fn(**args)`, scan its result, and return it.

        Raises BlockedError if the call, the result, or the text of an error
        raised by the tool is blocked. For an `async def` tool use `run_async`.
        """
        args = {} if args is None else args
        self._require_allowed(self.check_call(tool, args))
        blocked = None
        try:
            result = fn(**args)
        except Exception as exc:
            blocked = self._blocked_tool_error(tool, exc)
            if blocked is None:
                raise
        if blocked is not None:
            # Raised here, outside the handler, so that the tool's error and its
            # text do not travel along as the new error's __context__.
            raise BlockedError(blocked)
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):
                result.close()  # it will never be awaited; avoid a runtime warning
            self._require_allowed(self.refuse(tool, "the tool returned an awaitable; use run_async", event="result"))
        return self._checked_result(tool, result)

    async def run_async(self, tool: str, args: dict[str, Any] | None, fn: Callable[..., Any]) -> Any:
        """Like `run`, for a tool that is an `async def` function (a plain function works too)."""
        args = {} if args is None else args
        self._require_allowed(self.check_call(tool, args))
        blocked = None
        try:
            result = fn(**args)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:
            blocked = self._blocked_tool_error(tool, exc)
            if blocked is None:
                raise
        if blocked is not None:
            raise BlockedError(blocked)
        return self._checked_result(tool, result)

    # ---- internals: calls ---------------------------------------------------

    def _decide_call(self, tool: str, args: dict[str, Any]) -> Decision:
        # The secret guard runs first, so that its answer does not depend on the
        # policy. If it ran after, "looks like a secret" would tell a probing
        # agent that the policy would have let the call through.
        if self.policy.secrets_in_arguments == "block":
            secrets = find_secrets("\n".join([tool, *texts_in(args, keys=True)]))
            if secrets:
                reason = f"the call contains what looks like a secret ({', '.join(secrets)})"
                return Decision(False, reason, public_reason=_SECRET_REFUSAL)

        verdict = self.policy.evaluate(tool, args)
        if verdict.action not in ("allow", "ask"):
            # Any other word means block, including one this code does not know.
            return Decision(False, verdict.reason, public_reason=verdict.public)
        if verdict.action == "ask" and self.approver is None:
            # Refused before the rate limit is touched: otherwise the switch to
            # "too many calls" would reveal which tools are waiting for approval.
            return self._refused_ask(verdict, "approval required but no approver is configured")

        bucket = self._limiter.over_limit(self.policy.call_limits(tool), time.monotonic())
        if bucket is not None:
            return Decision(False, f"rate limit reached for '{bucket}'", public_reason=_RATE_REFUSAL)

        if verdict.action == "ask":
            return self._ask_human(tool, args, verdict)
        return Decision(True, verdict.reason)

    @staticmethod
    def _refused_ask(verdict: Verdict, why: str) -> Decision:
        return Decision(False, f"{verdict.reason}; {why}", public_reason=verdict.public)

    def _ask_human(self, tool: str, args: dict[str, Any], verdict: Verdict) -> Decision:
        assert self.approver is not None
        try:
            answer = self.approver(tool, args, verdict.reason)
        except Exception as exc:  # a broken approver must not approve anything
            return self._refused_ask(verdict, f"the approver failed ({type(exc).__name__})")
        if inspect.iscoroutine(answer):
            answer.close()
            return self._refused_ask(verdict, "the approver is async, which is not supported, so nobody was asked")
        if answer is True:  # exactly True: a truthy "no" or an un-awaited coroutine must not approve
            return Decision(True, f"{verdict.reason}; approved by a human")
        if answer is False:
            return self._refused_ask(verdict, "rejected by a human")
        return self._refused_ask(verdict, "the approver did not return True or False")

    # ---- internals: results -------------------------------------------------

    def _checked_result(self, tool: str, result: Any) -> Any:
        self._require_allowed(self.scan_result(tool, result))
        return result

    def _blocked_tool_error(self, tool: str, exc: BaseException) -> Decision | None:
        """Scan the text of an error a tool raised; return the block, or None to let the error through.

        An error message is attacker-controlled text too (a web server's error
        page, a file name), and agent loops commonly hand it back to the model.
        """
        decision = self.scan_result(tool, _error_texts(exc), event="tool_error", log_clean=False)
        return None if decision.allowed else decision

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
            record["findings"] = [dict(asdict(f), excerpt=_LONG_RUN.sub("[...]", f.excerpt)) for f in decision.findings]
        try:
            _append_line(self.audit_path, _audit_line(record))
        except OSError as exc:
            # A broken log must not stop the firewall from enforcing decisions.
            if not self._audit_failed:
                self._audit_failed = True
                print(f"agent-sentinel: cannot write audit log {self.audit_path}: {exc}", file=sys.stderr)


def _error_texts(exc: BaseException) -> list[str]:
    """Every text an error carries: its message, arguments and notes, and those of the errors linked to it.

    Linked errors are the members of an exception group (what asyncio's
    TaskGroup raises) and the `raise ... from ...` chain. Any of them can end
    up in a traceback that is shown to the model.
    """
    texts: list[str] = []
    seen: set[int] = set()
    waiting: list[BaseException] = [exc]
    while waiting and len(seen) < MAX_ERROR_PARTS:
        error = waiting.pop()
        if id(error) in seen:
            continue
        seen.add(id(error))
        texts.append(str(error))
        texts.extend(texts_in(list(error.args)))
        # What the error object carries besides its message: the captured output
        # of a failed command, the body of an HTTP error, its notes.
        texts.extend(texts_in(getattr(error, "__dict__", {}), keys=False))
        linked = [*getattr(error, "exceptions", ()), error.__cause__, error.__context__]
        waiting.extend(link for link in linked if isinstance(link, BaseException))
    return [text for text in dict.fromkeys(texts) if text.strip()]


def _audit_line(record: dict[str, Any]) -> str:
    """One audit record as a line of JSON: secrets redacted, oversized arguments left out, safe to display."""
    record = redact_value(record)  # before json.dumps: see leaks.redact_value for why
    args = record.get("args")
    if args is not None:
        size = len(json.dumps(args, ensure_ascii=False, default=str))
        if size > MAX_LOGGED_ARGS_CHARS:
            record["args"] = f"[{size} characters of arguments not logged]"
    return _log_safe(json.dumps(record, ensure_ascii=False, default=lambda value: redact(str(value))))


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


def _append_line(path: Path, line: str) -> None:
    """Append one line to a file that other processes may be appending to as well.

    Two proxies given the same --audit file would otherwise overwrite each
    other's records: on Windows an append is "seek to the end, then write",
    and another process can write in between. An operating-system lock around
    the append makes it one step.
    """
    data = (line + "\n").encode("utf-8", errors="backslashreplace")
    with open(path, "ab") as handle:
        _lock_file(handle)
        try:
            handle.seek(0, os.SEEK_END)
            handle.write(data)
            handle.flush()
        finally:
            _unlock_file(handle)


if sys.platform == "win32":
    import msvcrt

    def _lock_file(handle: BinaryIO) -> None:
        handle.seek(0)  # the lock covers one byte at the start, whatever the file's length
        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)  # waits up to about ten seconds

    def _unlock_file(handle: BinaryIO) -> None:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock_file(handle: BinaryIO) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)

    def _unlock_file(handle: BinaryIO) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
