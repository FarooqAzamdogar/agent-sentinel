"""The firewall: checks tool calls against a policy, scans text, logs both.

This is the core that everything else calls. It answers two questions:

    check_call(tool, args)     may the agent make this call?      (secrets, policy, rate limits)
    scan_result(tool, text)    may the agent read this text?      (detector; secrets in results)

Both return a `Decision` and write one line to the audit log. What a server
says about itself (tool descriptions, list entries, its instructions) is
scanned with stricter rules than tool results: see METADATA_EVENTS.

With the policy's `secrets.in_results` set to "redact", a result may be
passed on with its secrets replaced. Only `check_result` can hand back that
copy, so a caller that forwards results should use it: it returns the
Decision together with the content to pass on. `scan_result` refuses a
result that would need redacting, rather than let it through unchanged.

A Decision carries two texts. `reason` is the full detail and goes to the audit
log and the human approver. `public_reason` is what may be shown to the agent:
it never says which rule or pattern refused the call, because a hijacked agent
would use that to find a way round the policy.

Every block also gets a `ref`, eight random hex characters. It ends the text
the agent sees ("... (ref 7f3a9c21)") and is written to the audit record, so
a person who sees a refusal in a chat can find the record that explains it.
Being random, it tells the agent nothing. The record also names the rule that
decided (`rule`, see policy.py) and the argument it matched (`matched_arg`).

Every record says where it comes from: "session" (a random id per Firewall,
or one the caller gives), "server" (when the Firewall was given a server
name), and, for the records of one call, a shared "call_id": the call, its
approval, its result.

Flow rules look at what the agent has read earlier in the session (see
session.py). The firewall holds the session's marks in a store, and a
result's marks are set by `mark_delivered`, only once the result is about to
reach the agent. `run` does this itself; a program that calls `check_call`
and `scan_result` on its own must call `mark_delivered` too.

An "ask" can also be answered later: `check_call(..., defer_ask=True)` returns
a pending Decision instead of calling the approver, and `finish_approval`
turns the human's answer into the final Decision.
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
from secrets import token_hex
from typing import Any, Awaitable, Callable, Iterable, Mapping

from .detector import METADATA, RESULT, SEVERITY_ORDER, Finding, max_severity, scan_views
from .filelock import lock_file as _lock_file, unlock_file as _unlock_file
from .leaks import (
    CANARY,
    CUSTOM,
    KNOWN_VALUE,
    CannotRedact,
    CustomFormat,
    Found,
    SecretGuard,
    known_values_from_environment,
)
from .policy import (
    PERMITTED,
    RULE_CALLER,
    RULE_INJECTION,
    RULE_MALFORMED,
    RULE_SECRETS,
    RULE_SECRETS_CANARIES,
    RULE_SECRETS_IN_RESULTS,
    RULE_SECRETS_KNOWN_VALUES,
    RULE_SESSION,
    RULE_UNSCANNABLE,
    SECRET_CHARSETS,
    Policy,
    Verdict,
    limit_rule,
)
from .session import (
    MAX_SESSION_ID_CHARS,
    SINK,
    MemorySessionStore,
    SessionMarks,
    SessionStateError,
    SessionStore,
    labels_from_annotations,
)
from .textutil import UnscannableError, media_payloads, printable, text_views, texts_in, tool_parameters

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
# Calls waiting for finish_approval. A caller that never finishes them cannot grow
# memory without bound: the oldest is forgotten (and refused if it is finished later).
MAX_PENDING_APPROVALS = 1_000
# Tools whose MCP annotations are remembered. Past this, every unknown tool counts as untrusted and a sink.
MAX_ANNOTATED_TOOLS = 10_000
# A server name, as `proxy --name` accepts it: it is written into every audit record.
SERVER_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
MAX_CALL_ID_CHARS = 256
# The scan_result events whose content is a server describing itself: a tool
# definition, an entry of another list (prompts, resources), the instructions
# it gives at initialize. They are read with the detector's "metadata" rules,
# which know how tool descriptions are poisoned (see detector.py, "Profiles").
METADATA_EVENTS = frozenset({"tool_description", "list_item", "server_instructions"})
# The scan_result events that secrets.in_results applies to: what a call
# returned, or the error it raised (the proxy checks every reply to a request
# as a "result"). Not what a server says about itself, and not a request the
# server sends (the policy's server_requests section decides those).
RESULT_EVENTS = frozenset({"result", "tool_error"})
# The arguments of a call are also read joined end to end, so that a token
# split over two arguments is seen whole. The joined text is cut at this
# length: past it, a split token is not seen.
MAX_JOINED_ARGUMENT_CHARS = 100_000

# A long unbroken run of letters and digits in an excerpt. An excerpt is cut
# out of the text around a match, and the cut can go through the middle of a
# token, leaving most of it in a form the redaction no longer recognises.
_LONG_RUN = re.compile(r"[A-Za-z0-9_+/=-]{20,}")

_INJECTION_REFUSAL = "possible prompt injection; the content was withheld"
_SECRET_REFUSAL = "the call contains what looks like a secret, so it was not made"
_RATE_REFUSAL = "too many calls in a short time; try again later"
_UNSCANNABLE_REFUSAL = "the content has a type that cannot be checked"
_SECRET_RESULT_REFUSAL = "the content holds what looks like a secret, so it was withheld"
# Says nothing about flows or sessions: the agent must not learn that its history is tracked.
_WITHHELD_REFUSAL = "the content could not be checked, so it was withheld"


def new_ref() -> str:
    """A fresh block reference: eight random lowercase hex characters."""
    return token_hex(4)


def new_call_id() -> str:
    """A fresh call id: sixteen random lowercase hex characters, shared by the audit records of one call."""
    return token_hex(8)


def with_ref(text: str, ref: str) -> str:
    """The text an agent is shown for a block: the public reason, then the reference."""
    suffix = f" (ref {ref})"
    return text if text.endswith(suffix) else text + suffix


@dataclass(frozen=True)
class Decision:
    """The answer to one check.

    For a block, `public_reason` ends with " (ref <ref>)", and `ref` is set
    to a new random reference unless one is given. For an allowed decision
    `public_reason` defaults to the neutral PERMITTED, which names no rule.
    `rule` and `matched_arg` are for the audit log and the operator only.

    `call_id` links the audit records of one call (check_call sets it; pass it
    to scan_result for the call's result). `pending` is True only for the
    answer of `check_call(..., defer_ask=True)` to a call that needs a human:
    it is not allowed (so `bool(decision)` is False), and `finish_approval`
    gives the final answer. `redacted` names the kinds of secret that
    `check_result` replaced in a result (never the secrets themselves).
    """

    allowed: bool
    reason: str  # full detail: for the audit log and the operator
    findings: list[Finding] = field(default_factory=list)
    public_reason: str = ""  # safe to show to the agent; a block defaults to `reason`
    rule: str | None = None  # which rule decided (see policy.py for the names)
    matched_arg: str | None = None  # the argument a rule about one argument matched
    ref: str | None = None  # blocks only: the reference shared by the agent's text and the audit record
    call_id: str | None = None  # shared by the audit records of one call
    pending: bool = False  # waiting for a human: see Firewall.check_call(defer_ask=True) and finish_approval
    redacted: tuple[str, ...] = ()  # kinds of secret replaced in a result, e.g. ("GitHub token",)

    def __post_init__(self) -> None:
        if self.pending and self.allowed:
            raise ValueError("a pending decision is never allowed")
        public = self.public_reason or (self.reason if not self.allowed else PERMITTED)
        if not self.allowed:
            ref = self.ref or new_ref()
            object.__setattr__(self, "ref", ref)
            public = with_ref(public, ref)
        object.__setattr__(self, "public_reason", public)

    def __bool__(self) -> bool:
        # So that `if firewall.check_call(...):` means what it looks like.
        return self.allowed


@dataclass(frozen=True)
class CheckedResult:
    """The answer of `Firewall.check_result`: the Decision, and the content that may be passed on.

    content: when decision.allowed, exactly what was checked and may reach the
             agent: the content that was given, or a copy with its secrets
             replaced (decision.redacted names their kinds). None when the
             content is refused: there is nothing to pass on then.
    """

    decision: Decision
    content: Any = None

    def __bool__(self) -> bool:
        return self.decision.allowed


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
        server_name: str | None = None,
        session_id: str | None = None,
        session_store: SessionStore | None = None,
        rate_limiter: Any = None,
    ) -> None:
        """
        monitor:       record what the policy and the detector WOULD block (audit
                       action "would_block") but allow it. For tuning a new policy;
                       it protects nothing. Calls and results that cannot be checked
                       at all are still refused.
        server_name:   written as "server" into every audit record, so several
                       proxies can share one log. Letters, digits, "_", "-" and ".",
                       at most 64 (what `proxy --name` accepts); ValueError otherwise.
        session_id:    written as "session" into every audit record. Default: a new
                       random id, so each Firewall is its own session. Hook mode
                       passes the client's session id. Text of 1 to 256 characters.
        session_store: where the marks of flow rules are kept (see session.py).
                       Default: a new MemorySessionStore, so the session lasts as
                       long as this Firewall. Hook mode passes a FileSessionStore.
        rate_limiter:  where calls are counted for the rate limits. Default: in
                       memory, for this Firewall alone. Hook mode, where every
                       call is checked by a new process, passes one that keeps
                       the counts in a file (hook_state.FileRateLimiter). It needs
                       one method, over_limit(limits, now) -> the name of a full
                       bucket, or None after counting the call in every bucket.
        """
        if server_name is not None and (not isinstance(server_name, str) or not SERVER_NAME.fullmatch(server_name)):
            raise ValueError("server_name must be 1 to 64 letters, digits, '_', '-' or '.'")
        if session_id is not None and (
            not isinstance(session_id, str) or not 0 < len(session_id) <= MAX_SESSION_ID_CHARS
        ):
            raise ValueError(f"session_id must be text of 1 to {MAX_SESSION_ID_CHARS} characters")
        self.policy = policy
        self.audit_path = Path(audit_path) if audit_path else None
        self.approver = approver
        self.log_args = log_args
        self.monitor = monitor
        self.server_name = server_name
        self.session_id = session_id if session_id is not None else token_hex(8)
        self.session_store: SessionStore = session_store if session_store is not None else MemorySessionStore()
        self._limiter = rate_limiter if rate_limiter is not None else _RateLimiter()
        self._audit_lock = threading.Lock()
        self._audit_failed = False
        # Guards the two collections below; each check takes it only briefly.
        self._state_lock = threading.Lock()
        # Labels learned from MCP tool annotations: tool name -> labels. Only ever grows.
        self._annotation_labels: dict[str, frozenset[str]] = {}
        self._annotations_overflowed = False
        # Calls waiting for finish_approval: call id -> (the pending decision, the tool, its reason).
        self._pending_approvals: dict[str, tuple[Decision, str, str]] = {}
        # The secret guard for the policy's secret settings: (settings it was built
        # for, the guard, warnings about secrets.known_values_from_env). Built now,
        # so that the values of those variables are read when the firewall starts;
        # rebuilt if the settings change. One tuple, so that a thread never sees a
        # guard with another guard's warnings.
        self._secret_environment: Mapping[str, str] | None = None  # None: os.environ
        self._guard_state: tuple[tuple[Any, ...], SecretGuard, list[str]] | None = None
        self._secret_guard()

    # ---- decisions ----------------------------------------------------------

    def check_call(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        *,
        defer_ask: bool = False,
        call_id: str | None = None,
    ) -> Decision:
        """Decide whether the agent may call `tool` with `args`.

        In order: the secret guard, the policy (rules, then flow rules), the
        rate limits, then, for an "ask", the approver.

        defer_ask: for a caller that asks the human itself, later (the proxy,
                   a hook). A call that needs approval then gets a pending
                   Decision (allowed False, pending True, with a ref) once the
                   secret guard, the policy and the rate limits have passed it,
                   and the approver is NOT called. Show the human
                   `decision.reason` and every argument (through `printable`),
                   then call `finish_approval`. Without defer_ask, nothing
                   changes. In monitor mode defer_ask is ignored: nothing waits.
        call_id:   the id that links this call's audit records, when the caller
                   has one (a hook gets the client's tool_use_id). Default: a new
                   random id. Either way it is in `decision.call_id`; pass it to
                   scan_result for the call's result.
        """
        call_id = _checked_call_id(call_id)
        if args is None:
            args = {}
        if not isinstance(tool, str) or not isinstance(args, dict):
            return self.refuse(
                printable(tool, limit=80), "the tool name must be text and the arguments an object",
                rule=RULE_MALFORMED, call_id=call_id,
            )
        decision = self._decide_call(tool, args, defer_ask and not self.monitor, call_id)
        if decision.pending:
            self._remember_pending(decision, tool)
            self._audit("call", tool, "ask", decision, args)
            return decision
        return self._finish("call", tool, decision, args=args)

    def finish_approval(self, decision: Decision, approved: bool, approver: str) -> Decision:
        """Turn a human's answer to a pending call into the final Decision, and log it.

        decision: the pending Decision that check_call(..., defer_ask=True) returned.
        approved: the answer. Only exactly True approves; anything else refuses.
        approver: who or what answered, for the audit log, e.g. "dialog",
                  "elicitation" or "timeout". Shortened and made printable.

        An approved call is allowed (rule: the rule that said ask). A refused one
        is blocked and keeps the pending decision's ref, so the agent's text and
        both audit records carry the same reference. Each pending decision can
        be finished once: a second answer, or one for a decision this Firewall
        did not issue or has forgotten (more than MAX_PENDING_APPROVALS were
        waiting), is a refusal. Before approving, the flow rules are checked
        again: if what the agent read while the call waited means a flow rule
        now blocks it, the call is refused. Rate limits are not counted again.
        The audit record has event "approval". Monitor mode never lifts this
        answer: it lifts what the policy would block, not a human's "no" or an
        answer that matches no waiting call (and in monitor mode nothing waits).
        """
        if not isinstance(decision, Decision) or not decision.pending:
            raise ValueError("finish_approval takes a pending Decision from check_call(..., defer_ask=True)")
        who = printable(str(approver), limit=100)
        with self._state_lock:
            entry = self._pending_approvals.get(decision.call_id or "")
            if entry is not None and entry[0] is decision:
                del self._pending_approvals[decision.call_id or ""]
            else:
                entry = None
        tool = entry[1] if entry is not None else "?"
        base = entry[2] if entry is not None else decision.reason
        if entry is None:
            reason = f"{base}; an answer from {who} came for a call that is not waiting"
            final = self._refused_approval(decision, reason)
        elif approved is not True:
            what = "refused" if approved is False else "not answered with True or False"
            final = self._refused_approval(decision, f"{base}; {what} by {who}")
        else:
            final = self._approved_unless_a_flow_blocks(decision, tool, base, who)
        self._audit("approval", tool, "allow" if final.allowed else "block", final, None)
        return final

    def scan_result(
        self,
        tool: str,
        content: Any,
        event: str = "result",
        log_clean: bool = True,
        *,
        call_id: str | None = None,
        foreign_tools: Iterable[str] = (),
    ) -> Decision:
        """Scan what a tool returned before the agent reads it.

        content:   a text, or whatever value a tool returned: bytes, a list, a
                   dict, nested as deep as it likes. A value is read through
                   `textutil.text_views`, so a phrase split over two items of
                   a list, or over two fields, is still seen as one.
        event:     labels the audit record, e.g. "result" or "tool_description".
                   The events in METADATA_EVENTS ("tool_description",
                   "list_item", "server_instructions") are what a server says
                   about itself, and are read with the detector's stricter
                   "metadata" rules; for "tool_description" each parameter of
                   the tool is also read on its own.
        log_clean: set False to log only when something was found (useful for
                   high-volume traffic such as progress notifications).
        call_id:   the call this is the result of (decision.call_id from
                   check_call), so that both records share it.
        foreign_tools: for the metadata events only: names of tools that belong
                   to OTHER servers (see `foreign_tool_names`). A description
                   that gives orders about one of them is reported as tool
                   shadowing. Never pass the scanned server's own tool names.

        The base64 "data" of image and audio content is not decoded by the
        detector (it is still scanned as text). A clean result does not set
        flow marks: call `mark_delivered` once it is certain the result
        reaches the agent.

        Secrets (the policy's secrets.in_results, for the RESULT_EVENTS
        "result" and "tool_error"): with "block", a result holding what looks
        like a secret is refused. With "redact", scan_result cannot hand back
        a redacted copy, so it refuses every result that `check_result` would
        change (a JWT included); use `check_result` to pass results on with
        their secrets replaced. With "block", a JWT is never a reason to
        refuse, and canaries are not looked for in results.
        """
        checked = self._checked_content(tool, content, event, log_clean, call_id, foreign_tools, can_replace=False)
        return checked.decision

    def check_result(
        self,
        tool: str,
        content: Any,
        event: str = "result",
        log_clean: bool = True,
        *,
        call_id: str | None = None,
        foreign_tools: Iterable[str] = (),
    ) -> CheckedResult:
        """Like `scan_result`, and also return the content that may be passed on: for a caller that forwards it.

        With the policy's secrets.in_results "redact", the secrets in a result
        are replaced first (see leaks.SecretGuard.redact_result), and the copy
        is what the detector scans and what `CheckedResult.content` holds.
        Pass on exactly that, never the original. Without a secret, or with any
        other setting, the content is the one given (the same object), and the
        answer is the one scan_result would give.

        Results that are not text are redacted where they are text, dict,
        list or tuple (exactly those types; numbers, booleans and None are
        kept). A result is refused (decision not allowed, content None) when
        it holds a secret that cannot be replaced: one split over several
        strings, or one inside a part of another type (bytes, a set, a
        dataclass, a subclass of str or dict, ...), which cannot be rebuilt
        without it. A part of another type with no secret in it is passed on
        as it is. The audit record lists the kinds replaced under "redacted",
        never the secrets; decision.redacted holds the same.
        """
        return self._checked_content(tool, content, event, log_clean, call_id, foreign_tools, can_replace=True)

    def secret_warnings(self) -> list[str]:
        """Why some secrets.known_values_from_env values are not guarded: for the operator, at startup.

        A variable that is not set in the environment the values are read from
        (see set_secret_environment), or whose value is shorter than
        leaks.MIN_VALUE_CHARS (8) or longer than leaks.MAX_VALUE_CHARS. The
        texts name variables, never values. Empty when all are guarded.
        """
        self._secret_guard()
        assert self._guard_state is not None
        return list(self._guard_state[2])

    def set_secret_environment(self, environ: Mapping[str, str] | None) -> None:
        """Read the values of secrets.known_values_from_env from `environ` instead of os.environ.

        For a caller that starts the tool's server with an environment of its
        own (the proxy with --clean-env or --env-file): the values to guard
        are the ones the server holds. The mapping is copied now; None goes
        back to os.environ. Entries that are not text are ignored.
        """
        if environ is not None and not isinstance(environ, Mapping):
            raise TypeError("environ must be a mapping of variable names to values, or None")
        self._secret_environment = None if environ is None else {
            name: value for name, value in environ.items() if isinstance(name, str) and isinstance(value, str)
        }
        self._guard_state = None  # rebuilt now, from the new values
        self._secret_guard()

    def block(
        self, tool: str, reason: str, event: str = "call", public_reason: str = "", rule: str = RULE_CALLER,
        call_id: str | None = None,
    ) -> Decision:
        """Record and return a block that monitor mode may lift, like a block by the policy.

        rule:    the rule id for the audit log, such as "server_requests.sampling/createMessage".
                 The default, "caller", says the program that called block() decided.
        call_id: links the record to a call; a "call" record gets a new one when none is given.
        """
        call_id = _call_id_for(event, call_id)
        return self._finish(
            event, tool, Decision(False, reason, public_reason=public_reason, rule=rule, call_id=call_id)
        )

    def note(self, tool: str, reason: str, event: str, call_id: str | None = None) -> None:
        """Record something the operator should know about that blocks nothing: audit action "note".

        For example a tool kept although its name breaks the MCP naming rules,
        or a tool the proxy hid from the tool list. Nothing reaches the agent.
        """
        self._audit(event, tool, "note", Decision(True, reason, call_id=call_id), None)

    def refuse(
        self, tool: str, reason: str, event: str = "call", public_reason: str = "", rule: str = RULE_MALFORMED,
        call_id: str | None = None,
    ) -> Decision:
        """Record and return a block that always holds, even in monitor mode.

        For what cannot be checked at all: a malformed call, a result of an
        unreadable type, a tool that cannot be vouched for. Monitor mode is for
        trying out a policy, and must not let these through.

        rule:    the rule id for the audit log: "malformed" (the default),
                 "unscannable", "quarantine" or "session".
        call_id: links the record to a call; a "call" record gets a new one when none is given.
        """
        call_id = _call_id_for(event, call_id)
        decision = Decision(False, reason, public_reason=public_reason, rule=rule, call_id=call_id)
        self._audit(event, tool, "block", decision, None)
        return decision

    def withhold(self, tool: str, error: SessionStateError, call_id: str | None = None) -> Decision:
        """Record and return the refusal of a result whose flow marks could not be recorded.

        For a caller of `mark_delivered` that got SessionStateError: send the
        agent this decision's public_reason instead of the result. Rule
        "session"; a block that monitor mode does not lift. The agent's text
        says only that the content could not be checked.
        """
        return self.refuse(
            tool, f"the result was withheld: {error}", event="result", public_reason=_WITHHELD_REFUSAL,
            rule=RULE_SESSION, call_id=call_id,
        )

    def run(self, tool: str, args: dict[str, Any] | None, fn: Callable[..., Any]) -> Any:
        """Check the call, run `fn(**args)`, scan its result, and return it.

        Raises BlockedError if the call, the result, or the text of an error
        raised by the tool is blocked. A result (or an error) that is returned
        to the caller sets the session's flow marks first. For an `async def`
        tool use `run_async`.

        With the policy's secrets.in_results "redact", what is returned is the
        checked copy with its secrets replaced (see check_result), not the
        tool's own object. An error whose text holds a secret is blocked under
        "redact" as under "block": an exception cannot be rebuilt without it.
        """
        args = {} if args is None else args
        decision = self.check_call(tool, args)
        self._require_allowed(decision)
        call_id = decision.call_id
        blocked = None
        try:
            result = fn(**args)
        except Exception as exc:
            blocked = self._blocked_tool_error(tool, exc, call_id)
            if blocked is None:
                # The error's text reaches the caller, and through it, often, the agent.
                blocked = self._deliver(tool, call_id)
            if blocked is None:
                raise
        if blocked is not None:
            # Raised here, outside the handler, so that the tool's error and its
            # text do not travel along as the new error's __context__.
            raise BlockedError(blocked)
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):
                result.close()  # it will never be awaited; avoid a runtime warning
            reason = "the tool returned an awaitable; use run_async"
            self._require_allowed(self.refuse(tool, reason, event="result", rule=RULE_UNSCANNABLE, call_id=call_id))
        return self._checked_result(tool, result, call_id)

    async def run_async(self, tool: str, args: dict[str, Any] | None, fn: Callable[..., Any]) -> Any:
        """Like `run`, for a tool that is an `async def` function (a plain function works too)."""
        args = {} if args is None else args
        decision = self.check_call(tool, args)
        self._require_allowed(decision)
        call_id = decision.call_id
        blocked = None
        try:
            result = fn(**args)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:
            blocked = self._blocked_tool_error(tool, exc, call_id)
            if blocked is None:
                blocked = self._deliver(tool, call_id)
            if blocked is None:
                raise
        if blocked is not None:
            raise BlockedError(blocked)
        return self._checked_result(tool, result, call_id)

    def foreign_tool_names(self, own_tools: Iterable[str] = ()) -> frozenset[str]:
        """The tool names the policy writes out in full, minus `own_tools`: for scan_result's `foreign_tools`.

        A policy that covers several servers names their sensitive tools
        ("send_email"); a description from this server that gives orders about
        one of them is tool shadowing. Pass the names in the server's own tool
        list as `own_tools`: its tools refer to each other all the time.
        Wildcard rules ("delete_*") and method names ("resources/read",
        "prompts/get") are left out. Add the names of other servers' tools
        (from their pins) when the caller knows them.
        """
        if isinstance(own_tools, (str, bytes)):
            raise TypeError("own_tools must be a collection of tool names, not one text")
        own = {name for name in own_tools if isinstance(name, str)}
        named = (rule.name for rule in self.policy.tools if not rule.is_glob and "/" not in rule.name)
        return frozenset(name for name in named if name not in own)

    # ---- flow labels and session marks ----------------------------------------

    def tool_labels(self, tool: str) -> frozenset[str]:
        """Every flow label `tool` has: those the policy gives it, plus those its MCP annotations implied.

        Annotation labels count only when the policy's classify_by_annotations
        is on (the default). When more tools were annotated than can be
        remembered, a tool whose annotations were not kept counts as both
        untrusted and a sink.
        """
        labels = self.policy.tool_labels(tool)
        if self.policy.classify_by_annotations and isinstance(tool, str):
            with self._state_lock:
                learned = self._annotation_labels.get(tool)
                if learned is None and self._annotations_overflowed:
                    learned = labels_from_annotations({"openWorldHint": True})
            labels |= learned or frozenset()
        return labels

    def marks_for(self, tool: str) -> frozenset[str]:
        """The marks a delivered result of `tool` gives the session: its labels except "sink"."""
        return frozenset(label for label in self.tool_labels(tool) if label != SINK)

    def mark_delivered(self, tool: str, marks: Iterable[str] | None = None) -> None:
        """Record that a result of `tool` is reaching the agent: the session gains its marks.

        Call it when it is certain the result will be delivered (it passed
        scan_result and nothing else will withhold it), and BEFORE delivering
        it. A result that is refused or withheld must not be marked.

        marks: the labels to mark, if the caller worked them out earlier with
               `marks_for` (the proxy does, when the call is let through, so
               it need not keep the tool name). Default: marks_for(tool).
        tool:  only names the cause in the audit reason of a later flow block;
               any text (the proxy passes a resource's URI), shortened when kept.

        Does nothing when the policy has no flow rules. Raises
        SessionStateError when the marks cannot be recorded (a file store that
        cannot be written): then the result must be withheld.
        """
        if not self.policy.flows:
            return
        wanted = self.marks_for(tool) if marks is None else frozenset(marks)
        if wanted:
            self.session_store.add(wanted, tool)

    def session_marks(self) -> SessionMarks:
        """The session's marks now. Never raises: a store that fails counts as every mark set."""
        try:
            return self.session_store.read()
        except Exception as exc:  # a broken store must not make the flow rules pass
            return SessionMarks.untrusted(f"the session store failed ({type(exc).__name__})")

    def learn_annotations(self, tool: str, annotations: Any) -> None:
        """Remember the flow labels an MCP tool's annotations imply (see session.labels_from_annotations).

        The proxy calls this for each tool of a tools/list reply that it lets
        through. Labels only add up: annotations that later drop a hint do not
        remove a label learned earlier.
        """
        if not isinstance(tool, str):
            return
        labels = labels_from_annotations(annotations)
        if not labels:
            return
        with self._state_lock:
            known = self._annotation_labels.get(tool)
            if known is not None:
                self._annotation_labels[tool] = known | labels
            elif len(self._annotation_labels) < MAX_ANNOTATED_TOOLS:
                self._annotation_labels[tool] = labels
            else:
                self._annotations_overflowed = True

    # ---- internals: calls ---------------------------------------------------

    def _decide_call(self, tool: str, args: dict[str, Any], defer_ask: bool, call_id: str) -> Decision:
        # The secret guard runs first, so that its answer does not depend on the
        # policy. If it ran after, "looks like a secret" would tell a probing
        # agent that the policy would have let the call through.
        secrets = self._secrets_in_call(tool, args)
        if secrets:
            reason = f"the call contains what looks like a secret ({_kinds(secrets)})"
            return Decision(False, reason, public_reason=_SECRET_REFUSAL, rule=_secret_rule(secrets), call_id=call_id)

        verdict = self._verdict(tool, args)
        if verdict.action not in ("allow", "ask"):
            # Any other word means block, including one this code does not know.
            return Decision(
                False, verdict.reason, public_reason=verdict.public, rule=verdict.rule,
                matched_arg=verdict.matched_arg, call_id=call_id,
            )
        if verdict.action == "ask" and self.approver is None and not defer_ask:
            # Refused before the rate limit is touched: otherwise the switch to
            # "too many calls" would reveal which tools are waiting for approval.
            return self._refused_ask(verdict, "approval required but no approver is configured", call_id)

        bucket = self._limiter.over_limit(self.policy.call_limits(tool), time.monotonic())
        if bucket is not None:
            reason = f"rate limit reached for '{bucket}'"
            return Decision(False, reason, public_reason=_RATE_REFUSAL, rule=limit_rule(bucket), call_id=call_id)

        if verdict.action == "ask":
            if defer_ask:
                return Decision(
                    False, f"{verdict.reason}; waiting for approval", public_reason=verdict.public,
                    rule=verdict.rule, matched_arg=verdict.matched_arg, call_id=call_id, pending=True,
                )
            return self._ask_human(tool, args, verdict, call_id)
        return Decision(True, verdict.reason, rule=verdict.rule, call_id=call_id)

    def _secret_guard(self) -> SecretGuard:
        """The secret guard for the policy's secret settings, rebuilt when they have changed.

        Building it reads the values of secrets.known_values_from_env, from
        this process's environment (which a server it starts inherits) unless
        set_secret_environment gave another.
        """
        policy = self.policy
        settings = (policy.secrets_patterns, policy.secrets_known_values_from_env, policy.secrets_canaries)
        state = self._guard_state
        if state is not None and state[0] == settings:
            return state[1]
        environ = os.environ if self._secret_environment is None else self._secret_environment
        values, warnings = known_values_from_environment(policy.secrets_known_values_from_env, environ)
        custom = [
            CustomFormat(pattern.name, pattern.prefix, SECRET_CHARSETS[pattern.charset], pattern.min_len,
                         pattern.max_len)
            for pattern in policy.secrets_patterns
        ]
        guard = SecretGuard(custom, values, policy.secrets_canaries)
        self._guard_state = (settings, guard, warnings)
        return guard

    def _secrets_in_call(self, tool: str, args: dict[str, Any]) -> list[Found]:
        """The secrets in a call's tool name and arguments.

        Formats (built-in and custom) are looked for only when the policy's
        secrets.in_arguments is "block". Known values and canaries are always
        looked for: the operator listed them by name, and they never belong in a call.
        """
        guard = self._secret_guard()
        formats = self.policy.secrets_in_arguments == "block"
        if not formats and not guard.has_values:
            return []
        return guard.find_in_texts(_call_spellings(tool, args), formats=formats)

    def _verdict(self, tool: str, args: dict[str, Any]) -> Verdict:
        """The policy's verdict, with the flow rules applied when the policy has any."""
        if not self.policy.flows:
            return self.policy.evaluate(tool, args)
        return self.policy.evaluate(tool, args, marks=self.session_marks(), extra_labels=self.tool_labels(tool))

    @staticmethod
    def _refused_ask(verdict: Verdict, why: str, call_id: str | None) -> Decision:
        # The rule is the one that said "ask": that is what the operator would change.
        return Decision(
            False, f"{verdict.reason}; {why}", public_reason=verdict.public, rule=verdict.rule, call_id=call_id
        )

    def _ask_human(self, tool: str, args: dict[str, Any], verdict: Verdict, call_id: str) -> Decision:
        assert self.approver is not None
        try:
            answer = self.approver(tool, args, verdict.reason)
        except Exception as exc:  # a broken approver must not approve anything
            return self._refused_ask(verdict, f"the approver failed ({type(exc).__name__})", call_id)
        if inspect.iscoroutine(answer):
            answer.close()
            return self._refused_ask(
                verdict, "the approver is async, which is not supported, so nobody was asked", call_id
            )
        if answer is True:  # exactly True: a truthy "no" or an un-awaited coroutine must not approve
            return Decision(True, f"{verdict.reason}; approved by a human", rule=verdict.rule, call_id=call_id)
        if answer is False:
            return self._refused_ask(verdict, "rejected by a human", call_id)
        return self._refused_ask(verdict, "the approver did not return True or False", call_id)

    # ---- internals: deferred approval -------------------------------------------

    def _remember_pending(self, decision: Decision, tool: str) -> None:
        base = decision.reason[: -len("; waiting for approval")]
        with self._state_lock:
            self._pending_approvals[decision.call_id or ""] = (decision, tool, base)
            while len(self._pending_approvals) > MAX_PENDING_APPROVALS:
                # Forget the oldest: finishing it later refuses it, which is the safe side.
                del self._pending_approvals[next(iter(self._pending_approvals))]

    @staticmethod
    def _refused_approval(pending: Decision, reason: str) -> Decision:
        return Decision(
            False, reason, public_reason=pending.public_reason, rule=pending.rule, matched_arg=pending.matched_arg,
            ref=pending.ref, call_id=pending.call_id,
        )

    def _approved_unless_a_flow_blocks(self, pending: Decision, tool: str, base: str, who: str) -> Decision:
        """Approve, unless a flow rule blocks the call now (the agent may have read more while it waited)."""
        if self.policy.flows:
            flow = self.policy.flow_verdict(tool, self.session_marks(), self.tool_labels(tool))
            if flow is not None and flow.action == "block":
                reason = f"{flow.reason} (approved by {who}, but the session changed while the call waited)"
                return Decision(
                    False, reason, public_reason=pending.public_reason, rule=flow.rule, ref=pending.ref,
                    call_id=pending.call_id,
                )
        return Decision(True, f"{base}; approved by {who}", rule=pending.rule, call_id=pending.call_id)

    # ---- internals: results -------------------------------------------------

    def _checked_content(
        self,
        tool: str,
        content: Any,
        event: str,
        log_clean: bool,
        call_id: str | None,
        foreign_tools: Iterable[str],
        can_replace: bool,
    ) -> CheckedResult:
        """scan_result and check_result: the secret step (for results), then the detector, then one audit record.

        can_replace: whether the caller passes on the content this returns. If
        not, a result that would need redacting is refused instead.
        """
        if isinstance(content, str):
            views = [content]
        else:
            try:
                views = text_views(content, strict=True)
            except UnscannableError as exc:
                # Fail closed: content that cannot be read cannot be called clean.
                refusal = self.refuse(
                    tool, str(exc), event=event, public_reason=_UNSCANNABLE_REFUSAL, rule=RULE_UNSCANNABLE,
                    call_id=call_id,
                )
                return CheckedResult(refusal)

        redacted: tuple[str, ...] = ()
        secret_problem = None
        if event in RESULT_EVENTS and self.policy.secrets_in_results != "off":
            content, views, redacted, secret_problem = self._secrets_in_result(content, views, can_replace)

        # The detector reads what will be passed on: after redaction, the copy.
        metadata = event in METADATA_EVENTS
        findings = scan_views(
            views,
            profile=METADATA if metadata else RESULT,
            parameters=tool_parameters(content) if event == "tool_description" else None,
            foreign_tools=foreign_tools if metadata else (),
            skip_decoding=() if isinstance(content, str) else media_payloads(content),
        )
        decision = self._result_decision(findings, redacted, secret_problem, call_id)
        logged = bool(findings) or bool(redacted) or secret_problem is not None or log_clean
        decision = self._finish(event, tool, decision, log=logged)
        return CheckedResult(decision, content if decision.allowed else None)

    def _secrets_in_result(
        self, content: Any, views: list[str], can_replace: bool
    ) -> tuple[Any, list[str], tuple[str, ...], str | None]:
        """Apply secrets.in_results: (content, its views, kinds replaced, why it must be refused or None).

        The content and views returned are what the detector reads next and
        what is passed on if nothing refuses it: the redacted copy, or the
        content as given. Canaries are not looked for: a canary must stay in
        the private text it marks, so that it is caught if that text is sent
        out in a call. A JWT is redacted but never a reason to refuse.
        """
        guard = self._secret_guard()
        if self.policy.secrets_in_results == "block":
            found = guard.find_in_texts(views, canaries=False)
            if found:
                return content, views, (), f"the result holds what looks like a secret ({_kinds(found)})"
            return content, views, (), None

        # "redact". Most results hold no secret: one pass over the views says so,
        # before any string is copied.
        if not guard.find_in_texts(views, canaries=False, redaction_only=True):
            return content, views, (), None
        try:
            copy, kinds = guard.redact_result(content)
            if not kinds:
                copy_views = views
            elif isinstance(copy, str):
                copy_views = [copy]
            else:
                copy_views = text_views(copy, strict=True)
        except (CannotRedact, UnscannableError) as exc:
            return content, views, (), f"the result holds what looks like a secret that cannot be redacted: {exc}"
        # Redaction works string by string. What it could not replace (a secret
        # split over several strings, or one past the decoding limits of a
        # single string) is still there, and the result is refused.
        left = guard.find_in_texts(copy_views, canaries=False)
        if not can_replace and (kinds or left):
            # scan_result: its caller passes on the content it holds, which cannot be changed from here.
            every_kind = ", ".join(dict.fromkeys([*kinds, *(item.kind for item in left)]))
            reason = (
                f"the result holds what looks like a secret ({every_kind}); secrets.in_results is 'redact', "
                "but this caller cannot pass on a redacted copy (Firewall.check_result can)"
            )
            return content, views, (), reason
        if left:
            why = (
                f"what looks like a secret ({_kinds(left)}) is still there after redaction: it is split over "
                "several strings, or encoded where it cannot be replaced"
            )
            return copy, copy_views, kinds, why
        return copy, copy_views, kinds, None

    def _result_decision(
        self, findings: list[Finding], redacted: tuple[str, ...], secret_problem: str | None, call_id: str | None
    ) -> Decision:
        """The Decision on a result, from the detector's findings and the secret step."""
        worst = max_severity(findings)
        threshold = self.policy.block_severity
        rules = ", ".join(f.rule for f in findings)
        if secret_problem is not None:
            reason = secret_problem + (f"; the detector also found: {rules}" if findings else "")
            return Decision(
                False, reason, findings, _SECRET_RESULT_REFUSAL, rule=RULE_SECRETS_IN_RESULTS, call_id=call_id,
                redacted=redacted,
            )
        if worst is not None and threshold is not None and SEVERITY_ORDER[worst] >= SEVERITY_ORDER[threshold]:
            reason = f"possible prompt injection ({rules})"
            return Decision(
                False, reason, findings, _INJECTION_REFUSAL, rule=RULE_INJECTION, call_id=call_id, redacted=redacted
            )
        if worst is None:
            reason = "no injection patterns found"
        else:
            reason = f"suspicious content below blocking threshold ({rules})"
        if not redacted:
            return Decision(True, reason, findings, call_id=call_id)
        reason = f"replaced what looks like a secret ({', '.join(redacted)}); {reason}"
        return Decision(True, reason, findings, rule=RULE_SECRETS_IN_RESULTS, call_id=call_id, redacted=redacted)

    def _checked_result(self, tool: str, result: Any, call_id: str | None) -> Any:
        """The result `run` returns: checked (and, with secrets.in_results "redact", redacted), and marked delivered."""
        checked = self.check_result(tool, result, call_id=call_id)
        self._require_allowed(checked.decision)
        refused = self._deliver(tool, call_id)
        if refused is not None:
            raise BlockedError(refused)
        return checked.content

    def _deliver(self, tool: str, call_id: str | None) -> Decision | None:
        """Set the marks of a result that is about to be returned; a refusal if they cannot be recorded."""
        try:
            self.mark_delivered(tool)
        except SessionStateError as exc:
            return self.withhold(tool, exc, call_id=call_id)
        return None

    def _blocked_tool_error(self, tool: str, exc: BaseException, call_id: str | None = None) -> Decision | None:
        """Scan the text of an error a tool raised; return the block, or None to let the error through.

        An error message is attacker-controlled text too (a web server's error
        page, a file name), and agent loops commonly hand it back to the model.
        """
        decision = self.scan_result(tool, _error_texts(exc), event="tool_error", log_clean=False, call_id=call_id)
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
            reason = f"monitor mode, would block: {decision.reason}"
            return Decision(
                True, reason, decision.findings, rule=decision.rule, matched_arg=decision.matched_arg,
                call_id=decision.call_id, redacted=decision.redacted,
            )
        if log:
            self._audit(event, tool, "allow" if decision.allowed else "block", decision, args)
        return decision

    def _audit(self, event: str, tool: str, action: str, decision: Decision, args: dict[str, Any] | None) -> None:
        if self.audit_path is None:
            return
        record: dict[str, Any] = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        # Where the record comes from: several proxies (and hook processes) can share one log.
        if self.server_name is not None:
            record["server"] = self.server_name
        record["session"] = self.session_id
        record.update(event=event, tool=tool)
        if decision.call_id is not None:
            record["call_id"] = decision.call_id
        record["action"] = action
        # Which rule decided, the argument it matched, and the reference the agent was given.
        for name in ("rule", "matched_arg", "ref"):
            value = getattr(decision, name)
            if value is not None:
                record[name] = value
        record["reason"] = decision.reason
        if decision.redacted:
            record["redacted"] = list(decision.redacted)
        if args is not None and self.log_args:
            record["args"] = args
        if decision.findings:
            record["findings"] = [dict(asdict(f), excerpt=_LONG_RUN.sub("[...]", f.excerpt)) for f in decision.findings]
        try:
            _append_line(self.audit_path, _audit_line(record, self._secret_guard()))
        except OSError as exc:
            # A broken log must not stop the firewall from enforcing decisions.
            if not self._audit_failed:
                self._audit_failed = True
                print(f"agent-sentinel: cannot write audit log {self.audit_path}: {exc}", file=sys.stderr)


def _checked_call_id(call_id: Any) -> str:
    """The call id to use: the caller's, if it gave a valid one, or a new one."""
    if call_id is None:
        return new_call_id()
    if not isinstance(call_id, str) or not 0 < len(call_id) <= MAX_CALL_ID_CHARS:
        raise ValueError(f"call_id must be text of 1 to {MAX_CALL_ID_CHARS} characters")
    return call_id


def _call_id_for(event: str, call_id: str | None) -> str | None:
    """Every "call" record has a call id; other records only when the caller gives one."""
    if call_id is not None:
        return _checked_call_id(call_id)
    return new_call_id() if event == "call" else None


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


def _call_spellings(tool: str, args: dict[str, Any]) -> list[str]:
    """The texts of a call that the secret guard reads.

    1. The tool name, keys and strings, one per line.
    2. The strings joined end to end with nothing between them, and the keys
       and strings joined the same way: a token split over several arguments
       (in order), or over a key and its value, is seen whole.
    3. Each two neighbouring strings joined, one pair per line. In (2) the
       start of a split token is glued to the end of the argument before it,
       and the formats that must not continue a longer word (an AWS key,
       "sk-...") would not be seen there; a pair starts on a line of its own.

    Each joined text is cut at MAX_JOINED_ARGUMENT_CHARS: past that, a split
    token is not seen. The one-per-line text is not cut (it is what the guard
    has always read).
    """
    everything = texts_in(args, keys=True)
    strings = texts_in(args, keys=False)
    spellings = ["\n".join([tool, *everything])]
    if len(strings) > 1:
        spellings.append(_joined(strings, MAX_JOINED_ARGUMENT_CHARS))
        pairs = (strings[index] + strings[index + 1] for index in range(len(strings) - 1))
        spellings.append(_joined(pairs, MAX_JOINED_ARGUMENT_CHARS, separator="\n"))
    if len(everything) > len(strings):
        spellings.append(_joined(everything, MAX_JOINED_ARGUMENT_CHARS))
    return list(dict.fromkeys(spellings))


def _joined(texts: Iterable[str], limit: int, separator: str = "") -> str:
    """The texts joined with `separator` between them, cut at `limit` characters (read no further)."""
    pieces: list[str] = []
    room = limit
    for text in texts:
        if pieces and separator:
            pieces.append(separator)
            room -= len(separator)
        if room <= 0:
            break
        pieces.append(text[:room])
        room -= len(pieces[-1])
    return "".join(pieces)


def _kinds(found: list[Found]) -> str:
    """The kinds of secret found, for a reason in the audit log."""
    return ", ".join(item.kind for item in found)


def _secret_rule(found: list[Found]) -> str:
    """The rule id of a call refused for secrets: the most specific part of the guard that found one.

    A canary first (it can only be there if private text is leaving), then
    a known value, then a custom format, then the built-in formats ("secrets").
    """
    sources = {item.source for item in found}
    if CANARY in sources:
        return RULE_SECRETS_CANARIES
    if KNOWN_VALUE in sources:
        return RULE_SECRETS_KNOWN_VALUES
    for item in found:
        if item.source == CUSTOM:
            return f"secrets.patterns[{item.index}]"
    return RULE_SECRETS


def _audit_line(record: dict[str, Any], guard: SecretGuard) -> str:
    """One audit record as a line of JSON: secrets redacted, oversized arguments left out, safe to display.

    `guard` knows the policy's custom formats, known values and canaries, so
    those are redacted as well as the built-in formats.
    """
    record = guard.redact_value(record)  # before json.dumps: see SecretGuard.redact_value for why
    args = record.get("args")
    if args is not None:
        size = len(json.dumps(args, ensure_ascii=False, default=str))
        if size > MAX_LOGGED_ARGS_CHARS:
            record["args"] = f"[{size} characters of arguments not logged]"
    return _log_safe(json.dumps(record, ensure_ascii=False, default=lambda value: guard.redact(str(value))))


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

