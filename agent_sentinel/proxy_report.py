"""What the proxy tells the person who reads its stderr.

An MCP client keeps each server's stderr in a log (Claude Desktop writes
mcp-server-NAME.log, Cursor shows Output > MCP Logs), and that is where a
person looks when a tool "does not work". So the proxy writes there:

* when it starts, a summary: its version, the server's name, the policy it
  loaded and what that policy says, where the audit log and the pins are,
  the server command, how calls that need approval are asked about, and
  warnings about settings that are probably not what was meant
  (startup_lines);
* one line for every message it blocks, naming the rule that decided and the
  reference the agent was shown (block_line), so a refusal seen in a chat
  can be found in the log;
* with --verbose, one line for every call it lets through.

Nothing here reaches the agent. Lines about traffic are limited (LineBudget):
a peer that provokes a flood of blocks cannot flood the log. What the server
writes to its own stderr is passed on with a budget of its own (also with
--quiet), so a server that writes a flood cannot bury the proxy's lines.
Everything that came from a peer, a file or the command line is passed
through `printable` before it is printed (mcp_proxy._warn does that for
every line).

Levels (proxy --quiet and --verbose):

    QUIET    errors only (the proxy cannot start, a check failed inside the
             proxy, a file cannot be written), and the monitor-mode notice
    NORMAL   also the startup summary, warnings, one line per block, and what
             was removed from lists (the default)
    VERBOSE  also one line per call that was let through
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from .firewall import WOULD_BLOCK_PREFIX
from .leaks import redact
from .policy import ACTIONS, SAMPLING_CREATE, Policy, known_value_warnings
from .textutil import printable

QUIET = "quiet"
NORMAL = "normal"
VERBOSE = "verbose"

# At most this many lines about traffic in each window of this many seconds.
LINES_PER_WINDOW = 20
WINDOW_SECONDS = 10.0
# The lines the server writes to its own stderr, which have a budget of their own
# (see the module docstring). Enough for the traceback of a server that fails to start.
SERVER_LINES_PER_WINDOW = 60
SERVER_WINDOW_SECONDS = 60.0
# The policy's own warnings (Policy.warnings, as `validate` prints them) shown at startup.
MAX_POLICY_WARNINGS_SHOWN = 10


# ---- one line per decision ------------------------------------------------------

def block_line(what: str, decision: Any) -> str:
    """The line for a block: what was blocked, why, and, in brackets, the rule and the reference.

        blocked tools/call 'delete_file': rule 'delete_*' says block [rule tools.delete_*, ref 1c0e44d2]

    The reference is the one the agent's text ends with, so a person who sees
    a refusal in a chat can find this line and the audit record.
    """
    return f"{what}: {printable(decision.reason, limit=300)} {rule_and_ref(decision)}"


def rule_and_ref(decision: Any) -> str:
    """The end of every line about a block: [rule tools.delete_*, ref 1c0e44d2]."""
    return f"[rule {printable(decision.rule or '?', limit=100)}, ref {decision.ref}]"


def allowed_line(what: str, decision: Any) -> str:
    """The line for a call that was let through (shown with --verbose), or that monitor mode let through."""
    rule = printable(decision.rule or "?", limit=100)
    if getattr(decision, "would_block", False):
        reason = printable(decision.reason.removeprefix(WOULD_BLOCK_PREFIX), limit=300)
        return f"would block {what} (monitor mode lets it through): {reason} [rule {rule}]"
    return f"allowed {what} [rule {rule}]"


# ---- the startup summary --------------------------------------------------------------

@dataclass(frozen=True)
class Startup:
    """What the proxy was started with, for the summary it prints."""

    version: str
    name: str | None
    policy_path: str
    policy: Policy
    audit_path: str | None
    pins_path: str | None
    pins_enabled: bool
    server_command: Sequence[str]
    # Each --approve-with backend: (how it is described, why it cannot ask on this machine or None).
    approvers: Sequence[tuple[str, str | None]] = ()
    approval_timeout: int = 120
    approval_timeout_given: bool = False
    monitor: bool = False
    # Firewall.secret_warnings, for the values of secrets.known_values_from_env as the server's
    # environment holds them. When given, they replace the policy's own guess (known_value_warnings),
    # which can only look at the proxy's environment.
    secret_warnings: Sequence[str] | None = None
    # proxy --session-group, and the file the group's marks are kept in (None when it was not joined).
    session_group: str | None = None
    session_file: str | None = None


def startup_lines(start: Startup) -> list[str]:
    """The summary the proxy prints when it starts: one line per setting, then the warnings."""
    policy = start.policy
    lines = [f"proxy starting (agent-sentinel {start.version})"]
    if start.name:
        lines.append(f"  name      {start.name}")
    else:
        lines.append("  name      none (--name NAME labels this server's lines and audit records)")
    lines.append(f"  policy    {os.path.abspath(start.policy_path)}: {policy_summary(policy)}")
    lines.append(f"  audit     {os.path.abspath(start.audit_path)}" if start.audit_path else "  audit     none")
    if not start.pins_enabled:
        lines.append("  pins      off (--no-pins): a tool whose definition changes is not quarantined")
    elif start.pins_path:
        lines.append(f"  pins      {os.path.abspath(start.pins_path)}")
    else:
        lines.append("  pins      in memory: definitions are compared with those first seen since the proxy started")
    lines.append(f"  server    {shown_server_command(start.server_command)}")
    if start.approvers:
        backends = ", else ".join(description for description, _ in start.approvers)
        lines.append(f"  approval  {backends}; no answer within {start.approval_timeout} s refuses the call")
    if start.session_group and start.session_file:
        lines.append(f"  session   group '{start.session_group}': flow marks shared with the other proxies of this "
                     f"client run, in {start.session_file}")
    elif start.session_group:
        lines.append(f"  session   group '{start.session_group}' not joined: the policy has no flow rules, so there "
                     "are no marks to share")
    hidden = hidden_tools(policy)
    if hidden and not start.monitor:
        lines.append(f"  hidden    left out of the tool list, as the policy blocks them outright: {', '.join(hidden)}")
    return lines + [f"warning: {text}" for text in startup_warnings(start)]


def startup_warnings(start: Startup) -> list[str]:
    """Settings that are valid but probably not what was meant, in the order a person should read them."""
    policy = start.policy
    found = []
    if not start.audit_path:
        found.append("no --audit file, so blocked calls are reported here but recorded nowhere")
    for flag, path in (("--policy", start.policy_path), ("--audit", start.audit_path), ("--pins", start.pins_path)):
        if path and not os.path.isabs(path):
            found.append(
                f"the {flag} path '{printable(path, limit=200)}' is relative, so it depends on the folder the client "
                f"starts the proxy in (now {_current_folder()}); give the full path"
            )
    if start.audit_path and not os.path.isdir(os.path.dirname(os.path.abspath(start.audit_path))):
        found.append("the folder of the --audit file does not exist, so no record can be written")
    asks = asks_in(policy)
    if asks and not start.monitor and not start.approvers:
        found.append(
            f"the policy says \"ask\" for {', '.join(asks)}, and no --approve-with is given, so these calls are refused"
        )
    for description, unavailable in start.approvers:
        if unavailable:
            found.append(f"--approve-with {description} cannot ask on this machine: {unavailable}")
    if start.approval_timeout_given and not start.approvers:
        found.append("--approval-timeout has no effect without --approve-with")
    if policy.block_severity is None:
        found.append("injection.block_severity is null: text with injection findings is logged, never blocked")
    if policy.secrets_in_arguments == "allow":
        found.append("secrets.in_arguments is \"allow\": calls that carry keys or tokens are not refused")
    if policy.flows and policy.server_request_action(SAMPLING_CREATE) != "block":
        found.append(
            "the policy has flow rules, but server_requests does not block sampling/createMessage: the server can ask "
            "the client's model to write text and get it back, which flow rules see only as a call to a sink once "
            "a \"block\" flow's marks are set. Add \"sampling/createMessage\": \"block\" to server_requests"
        )
    policy_warnings = policy.warnings()
    if start.secret_warnings is not None:
        guessed = set(known_value_warnings(policy))
        policy_warnings = [text for text in policy_warnings if text not in guessed]
        found.extend(f"secrets.known_values_from_env: {printable(text, limit=300)}" for text in start.secret_warnings)
    found.extend(printable(text, limit=500) for text in policy_warnings[:MAX_POLICY_WARNINGS_SHOWN])
    if len(policy_warnings) > MAX_POLICY_WARNINGS_SHOWN:
        found.append(f"{len(policy_warnings) - MAX_POLICY_WARNINGS_SHOWN} more warning(s) about the policy; "
                     "`agent-sentinel validate` lists them all")
    return found


def policy_summary(policy: Policy) -> str:
    """What a policy says, in one line: "default block, 7 tool rules (4 allow, 1 ask, 2 block), ..."."""
    parts = [f"default {policy.default}"]
    if policy.tools:
        counts = Counter(rule.action for rule in policy.tools)
        by_action = ", ".join(f"{counts[action]} {action}" for action in ACTIONS if counts[action])
        parts.append(f"{len(policy.tools)} tool rule(s) ({by_action})")
    else:
        parts.append("no tool rules")
    if policy.deny_args:
        parts.append(f"{len(policy.deny_args)} policy-wide deny rule(s)")
    if policy.flows:
        parts.append(f"{len(policy.flows)} flow rule(s)")
    if policy.max_calls_per_minute:
        parts.append(f"at most {policy.max_calls_per_minute} calls a minute")
    if policy.call_timeout_seconds is not None:
        parts.append(f"calls time out after {policy.call_timeout_seconds:g} s")
    if policy.block_severity is not None:
        parts.append(f"injections blocked from {policy.block_severity}")
    return ", ".join(parts)


def asks_in(policy: Policy) -> list[str]:
    """What the policy sends to a person: the "ask" rules by name, the default, and flow rules."""
    asks = [printable(rule.name, limit=80) for rule in policy.tools if rule.action == "ask"]
    if policy.default == "ask":
        asks.append("every tool without a rule")
    asks.extend(f"flows[{index}]" for index, flow in enumerate(policy.flows) if flow.action == "ask")
    return asks


def hidden_tools(policy: Policy) -> list[str]:
    """The tools hide_blocked_tools leaves out of the tool list, by rule (as `validate` lists them)."""
    if not policy.hide_blocked_tools:
        return []
    hidden = [printable(rule.name, limit=80) for rule in policy.tools if policy.tool_level_action(rule.name) == "block"]
    if policy.default == "block":
        hidden.append("every tool without a rule")
    return hidden


def shell_line(words: Sequence[str], platform: str | None = None) -> str:
    """Words as one command line for this system's shell, quoted where a word needs it. Not made printable."""
    if (platform or sys.platform) == "win32":
        return subprocess.list2cmdline(list(words))
    return shlex.join(words)


def shown_server_command(argv: Sequence[str]) -> str:
    """The server command as a person would type it, with anything that looks like a key or token redacted.

    A token passed on the command line would otherwise be copied into the
    client's log.
    """
    return printable(redact(shell_line(argv)), limit=1000)


def missing_policy_hint(path: str) -> str | None:
    """Advice for a policy file that was not found, when its path is relative; None otherwise."""
    if os.path.isabs(path):
        return None
    from . import home  # here, not at the top: home imports cli_common, which imports this module

    try:  # where `init` writes the policy: the home folder, which AGENT_SENTINEL_HOME may move
        example = str(home.policy_file(home.home_folder()))
    except home.HomeError:
        example = "/full/path/to/policy.json"
    return (
        "MCP clients start servers in a folder of their own choosing, often not the one you expect, "
        f"so give the policy's full path, for example --policy {example}"
    )


def _current_folder() -> str:
    try:
        return os.getcwd()
    except OSError:
        return "unknown"


# ---- a limit on lines about traffic ------------------------------------------------------------

class LineBudget:
    """At most `limit` lines in each window of `window` seconds; lines past that are counted, not printed.

    The first line left out in a window is replaced by a notice that lines
    are being left out. The first line of a later window, or flush() when the
    proxy stops, is preceded by one line that says how many were left out.
    Nothing waits on a timer, so no thread prints at an unexpected moment.

    write: prints one line: (text, length limit for printable).
    where: where the lines left out can be found, for the notices; by
           default the audit log, or how to keep one (has_audit).
    """

    def __init__(
        self,
        write: Callable[[str, int], None],
        has_audit: bool,
        limit: int = LINES_PER_WINDOW,
        window: float = WINDOW_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        where: str | None = None,
    ) -> None:
        self._write = write
        if where is None:
            where = "the audit log has every block" if has_audit else "start the proxy with --audit FILE to keep them"
        self._where = where
        self._limit = limit
        self._window = window
        self._clock = clock
        self._lock = threading.Lock()
        self._window_started: float | None = None
        self._shown = 0
        self._left_out = 0

    def line(self, text: str, limit: int = 300) -> None:
        with self._lock:
            now = self._clock()
            if self._window_started is None or now - self._window_started >= self._window:
                self._say_how_many_were_left_out()
                self._window_started, self._shown = now, 0
            if self._shown < self._limit:
                self._shown += 1
                self._write(text, limit)
                return
            if self._left_out == 0:
                self._write(f"more than {self._limit} lines in {self._window:g} seconds: the next ones are left out "
                            f"for the rest of that time; {self._where}", 300)
            self._left_out += 1

    def flush(self) -> None:
        """Say how many lines were left out, if any (the proxy calls this when it stops)."""
        with self._lock:
            self._say_how_many_were_left_out()

    def _say_how_many_were_left_out(self) -> None:
        if self._left_out:
            self._write(f"left out {self._left_out} line(s) here to keep this log readable; {self._where}", 300)
            self._left_out = 0
