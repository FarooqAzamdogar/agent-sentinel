"""Start an MCP server, ask it for its tools through the real proxy, and stop it again.

`inspect` and `init -- <server command>` use this. The server is started the
way the proxy starts it (the same checks on the command: never from the
current folder, no batch-file arguments that cmd.exe would change), and
spoken to as a client would: initialize, notifications/initialized, then
tools/list page by page. Never tools/call: nothing the server offers is run.

Every message passes through a real `Proxy` with the policy given, so "would
reach the agent" here means exactly what the proxy would let through: a tool
whose description holds an injection is removed here as it would be there.
The server's own reply is kept beside the proxy's, so that removed tools can
be listed too, with the reason from the firewall's audit record (written to a
temporary folder that is deleted afterwards).

Everything the server sends is untrusted: tool names, descriptions,
annotations, its error messages and its stderr. Callers print all of it
through `printable`, and treat annotations as the server's claims, never as
facts: a server can call any tool "read-only".

Bounds: one overall timeout, at most MAX_PAGES pages and MAX_TOOLS tools, the
proxy's message size limit, and the last MAX_STDERR_LINES lines of stderr.
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__, auditlog, mcp_proxy
from .cli_common import CommandError
from .firewall import Firewall
from .policy import Policy
from .textutil import printable

DEFAULT_TIMEOUT_SECONDS = 15.0
# The protocol revision asked for. Widely supported; a server that prefers another answers with its own.
PROTOCOL_VERSION = "2025-06-18"
MAX_PAGES = 20
MAX_TOOLS = 1000
MAX_CURSOR_CHARS = 1024
MAX_DESCRIPTION_CHARS = 2000
MAX_STDERR_LINES = 20
MAX_STDERR_LINE_BYTES = 2000
# What the server may leave unread of what the proxy writes to it before it counts as gone.
MAX_UNREAD_BYTES = 1024 * 1024
MAX_CAPABILITIES = 20
MAX_INFO_CHARS = 200
# The MCP annotations that say what a tool does. Kept only when they are true or false.
HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
_HINT_WORDS = {
    "readOnlyHint": "read-only", "destructiveHint": "destructive",
    "idempotentHint": "idempotent", "openWorldHint": "open world",
}
# The events and actions of the audit records that say why the proxy removed something.
_REMOVAL_EVENTS = ("tool_description", "tool_changed")
_PROXY_PREFIX = "Blocked by agent-sentinel:"


class ProbeError(CommandError):
    """The server could not be started or did not answer as an MCP server. Printed, exit code 2."""


@dataclass
class ListedTool:
    """One tool from the server's list. Everything in it came from the server."""

    name: str
    reaches_agent: bool  # the proxy let it through to the client
    removed_because: str | None = None
    hints: dict[str, bool] = field(default_factory=dict)  # the server's annotations: claims, not facts
    description: str = ""  # shortened to MAX_DESCRIPTION_CHARS

    def says(self) -> list[str]:
        """The annotations that are true, in words: "read-only", "destructive", ..."""
        return [_HINT_WORDS[hint] for hint in HINTS if self.hints.get(hint) is True]

    @property
    def claims_read_only(self) -> bool:
        """The server says the tool only reads (and does not also call it destructive)."""
        return self.hints.get("readOnlyHint") is True and self.hints.get("destructiveHint") is not True


@dataclass
class ProbeResult:
    command: list[str]
    server_name: str | None = None
    server_version: str | None = None
    protocol_version: str | None = None
    capabilities: list[str] = field(default_factory=list)
    instructions: str = "none"  # "none", "kept" or "removed"
    instructions_reason: str | None = None
    tools: list[ListedTool] = field(default_factory=list)
    malformed_entries: int = 0  # list entries that are not a tool with a usable name
    truncated: bool = False  # more pages or tools than were looked at
    list_error: str | None = None  # the tool list could not be read: why
    list_refused_by_proxy: bool = False
    proxy_messages: list[str] = field(default_factory=list)

    @property
    def removed(self) -> list[ListedTool]:
        return [tool for tool in self.tools if not tool.reaches_agent]

    @property
    def found_problems(self) -> bool:
        """Something was removed or refused: what `inspect` reports with exit code 1."""
        return bool(self.removed) or self.instructions == "removed" or self.list_refused_by_proxy


def probe(command: list[str], policy: Policy | None = None, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> ProbeResult:
    """Start the server, list its tools through a proxy with this policy (a block-all one if None), stop it.

    The policy's hide_blocked_tools is turned off for the run, so that the
    list shows every tool the scan keeps; callers say which ones the policy
    would hide. Raises ProbeError when the server cannot be started, stops
    early, or does not answer in time.
    """
    if not command:
        raise ProbeError("give the MCP server command after '--'")
    scan_policy = dataclasses.replace(policy, hide_blocked_tools=False) if policy is not None else Policy()
    folder = Path(tempfile.mkdtemp(prefix="agent-sentinel-probe-"))
    audit_path = folder / "audit.jsonl"
    messages = io.StringIO()
    try:
        # The proxy reports to stderr; those lines are collected and shown with the result.
        with contextlib.redirect_stderr(messages):
            session = _ServerSession(command, scan_policy, audit_path, timeout)
            try:
                result = _talk(session, command)
            finally:
                session.close()
        result.proxy_messages = [line for line in messages.getvalue().splitlines() if line.strip()][:50]
        _add_reasons(result, audit_path)
        return result
    finally:
        shutil.rmtree(folder, ignore_errors=True)


# ---- the conversation ---------------------------------------------------------------

def _talk(session: _ServerSession, command: list[str]) -> ProbeResult:
    raw_init, reply = session.request("initialize", {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "agent-sentinel", "version": __version__},
    })
    init = _result_of(reply, "initialize")
    session.notify("notifications/initialized")
    result = ProbeResult(command=list(command))
    _read_server_info(result, raw_init, init)

    seen_cursors: set[str] = set()
    cursor: str | None = None
    for _ in range(MAX_PAGES):
        raw, reply = session.request("tools/list", {} if cursor is None else {"cursor": cursor})
        if not isinstance(reply.get("result"), dict):
            _read_list_error(result, raw, reply)
            return result
        _add_page(result, raw, reply["result"])
        cursor = reply["result"].get("nextCursor")
        if not isinstance(cursor, str) or not 0 < len(cursor) <= MAX_CURSOR_CHARS or cursor in seen_cursors:
            return result
        if len(result.tools) >= MAX_TOOLS:
            result.truncated = True
            return result
        seen_cursors.add(cursor)
    result.truncated = True  # the server still had pages after MAX_PAGES
    return result


def _result_of(reply: dict[str, Any], method: str) -> dict[str, Any]:
    """The result of a reply, or a ProbeError that says what came instead."""
    result = reply.get("result")
    if isinstance(result, dict):
        return result
    raise ProbeError(f"the server did not accept {method}: {_error_text(reply)}")


def _error_text(reply: dict[str, Any]) -> str:
    error = reply.get("error")
    message = error.get("message") if isinstance(error, dict) else None
    return printable(message, limit=300) if isinstance(message, str) else "it sent no usable result"


def _bounded_text(value: Any, limit: int = MAX_INFO_CHARS) -> str | None:
    return value[:limit] if isinstance(value, str) else None


def _read_server_info(result: ProbeResult, raw: Any, init: dict[str, Any]) -> None:
    """Name, version, protocol revision and capabilities, as the proxy delivered them."""
    info = init.get("serverInfo")
    if isinstance(info, dict):
        result.server_name = _bounded_text(info.get("name"))
        result.server_version = _bounded_text(info.get("version"))
    result.protocol_version = _bounded_text(init.get("protocolVersion"), 64)
    capabilities = init.get("capabilities")
    if isinstance(capabilities, dict):
        result.capabilities = [str(name)[:40] for name in list(capabilities)[:MAX_CAPABILITIES]]
    if isinstance(raw, dict) and isinstance(raw.get("instructions"), str) and raw["instructions"].strip():
        result.instructions = "kept" if isinstance(init.get("instructions"), str) else "removed"


def _read_list_error(result: ProbeResult, raw: Any, reply: dict[str, Any]) -> None:
    """The tool list came back as an error: the server's own, or the proxy's refusal of the whole list."""
    text = _error_text(reply)
    result.list_refused_by_proxy = text.startswith(_PROXY_PREFIX)
    if not result.list_refused_by_proxy:
        result.list_error = f"the server answered tools/list with an error: {text}"
        return
    result.list_error = f"the proxy refused the whole tool list: {text}"
    # The tools the server did list never reach the agent: show them, each with that reason.
    if isinstance(raw, dict):
        _add_page(result, raw, {"tools": []}, reason=result.list_error)


def _add_page(result: ProbeResult, raw: Any, delivered: dict[str, Any], reason: str | None = None) -> None:
    """Add one page of tools: every tool the server listed, and whether the proxy let it through."""
    delivered_tools = delivered.get("tools")
    delivered_names = {
        tool.get("name") for tool in delivered_tools if isinstance(tool, dict) and isinstance(tool.get("name"), str)
    } if isinstance(delivered_tools, list) else set()
    entries = raw.get("tools") if isinstance(raw, dict) else None
    if not isinstance(entries, list):  # the server's own reply was not kept; the proxy's is all there is
        entries = delivered_tools if isinstance(delivered_tools, list) else []
    known = {tool.name for tool in result.tools}
    for entry in entries:
        name = entry.get("name") if isinstance(entry, dict) else None
        if not isinstance(name, str) or not 0 < len(name) <= mcp_proxy.MAX_NAME_CHARS:
            result.malformed_entries += 1
            continue
        if name in known:
            continue
        if len(result.tools) >= MAX_TOOLS:
            result.truncated = True
            return
        known.add(name)
        description = entry.get("description")
        result.tools.append(ListedTool(
            name=name,
            reaches_agent=name in delivered_names,
            removed_because=reason,
            hints=_hints(entry.get("annotations")),
            description=description[:MAX_DESCRIPTION_CHARS] if isinstance(description, str) else "",
        ))


def _hints(annotations: Any) -> dict[str, bool]:
    if not isinstance(annotations, dict):
        return {}
    return {hint: annotations[hint] for hint in HINTS if isinstance(annotations.get(hint), bool)}


def _add_reasons(result: ProbeResult, audit_path: Path) -> None:
    """Fill in why each removed tool (and removed instructions) were removed, from the audit records."""
    reasons: dict[str, str] = {}
    if audit_path.exists():
        for record in auditlog.iter_records(str(audit_path)):
            if record is None or not auditlog.is_block(record):
                continue
            tool, reason = auditlog.text_of(record, "tool"), auditlog.text_of(record, "reason")
            if tool is None or reason is None:
                continue
            if record.get("event") in _REMOVAL_EVENTS:
                reasons.setdefault(tool, reason)
            elif record.get("event") == "server_instructions" and result.instructions_reason is None:
                result.instructions_reason = reason
    for tool in result.tools:
        if not tool.reaches_agent and tool.removed_because is None:
            # The proxy logs a tool under its name, shortened the way _label shortens it.
            tool.removed_because = reasons.get(mcp_proxy._label(tool.name), "removed by the proxy")


# ---- the server process ---------------------------------------------------------------

class _ClientEnd:
    """The client's end of the proxy: collects the replies the proxy writes toward the client.

    Only replies are kept (the proxy delivers a reply only to a request that
    was sent, so there are as many as requests). What the server sends of its
    own accord, notifications and requests, is dropped here: a server that
    floods them must not fill memory while the probe waits.
    """

    def __init__(self) -> None:
        self.messages: queue.Queue[Any] = queue.Queue()

    def write(self, data: bytes) -> int:
        for line in data.splitlines():
            if not line.strip():
                continue
            try:
                message = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if isinstance(message, dict) and "id" in message and "method" not in message:
                self.messages.put(message)
        return len(data)

    def flush(self) -> None:
        pass


class _ServerInput:
    """The server's end of the proxy: what the proxy writes to the server, passed on by a thread of its own.

    The proxy writes to the server while holding a lock, from this program's
    thread (requests) and from the thread that reads the server (its answers
    to requests it refuses). A server that stops reading its input would
    block such a write for good, and with it the lock, the timeout and the
    clean-up. So a write only queues the bytes; this object's thread does the
    blocking write, and when the server is killed, its write fails and it ends.
    A server that leaves more than MAX_UNREAD_BYTES unread is treated as gone.
    """

    def __init__(self, stream: Any) -> None:
        self._stream = stream
        self._chunks: queue.Queue[bytes | None] = queue.Queue()
        self._lock = threading.Lock()
        self._unread = 0
        self._broken = False
        self._closed = False
        self._thread = threading.Thread(target=self._pass_on, daemon=True)
        self._thread.start()

    def write(self, data: bytes) -> int:
        with self._lock:
            if self._broken or self._closed:
                raise OSError("the server's input is closed")
            if self._unread + len(data) > MAX_UNREAD_BYTES:
                self._broken = True
                raise OSError("the server does not read its input")
            self._unread += len(data)
        self._chunks.put(bytes(data))
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        """Close the server's input once everything queued was written (as a client that quits)."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._chunks.put(None)

    def _pass_on(self) -> None:
        while True:
            chunk = self._chunks.get()
            if chunk is None:
                break
            try:
                self._stream.write(chunk)
                self._stream.flush()
            except (OSError, ValueError):
                with self._lock:
                    self._broken = True
                break
            with self._lock:
                self._unread -= len(chunk)
        try:
            self._stream.close()
        except (OSError, ValueError):
            pass

    def join(self, timeout: float) -> None:
        self._thread.join(timeout)

    @property
    def broken(self) -> bool:
        """The server stopped reading (too much left unread), or its input could not be written."""
        with self._lock:
            return self._broken


def _executable(command: list[str]) -> str:
    """The server program, found and checked the way the proxy does it, or a ProbeError in the proxy's words."""
    executable = mcp_proxy._resolve_executable(command[0])
    if executable is None:
        raise ProbeError(
            f"cannot find the server command '{command[0]}' on PATH. The current folder is not searched; "
            f"to run a file from it, write the path, for example .{os.sep}{command[0]}"
        )
    unsafe = mcp_proxy._unsafe_for_batch_file(executable, command[1:])
    if unsafe:
        raise ProbeError(
            f"cannot pass {unsafe[0]!r} to the batch file {executable}: cmd.exe would change it. "
            "Start the program behind the batch file directly, for example with node or python"
        )
    return executable


class _ServerSession:
    """The server process, with a Proxy between it and this program."""

    def __init__(self, command: list[str], policy: Policy, audit_path: Path, timeout: float) -> None:
        executable = _executable(command)
        # As the proxy does: whatever the server starts must not pick up a program from the current folder.
        environment = dict(os.environ, NoDefaultCurrentDirectoryInExePath="1")
        try:
            self.process = subprocess.Popen(
                [executable, *command[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment,
            )
        except OSError as exc:
            raise ProbeError(f"cannot start the server: {exc.strerror or exc}") from exc
        self.timeout = timeout
        self.deadline = time.monotonic() + timeout
        self._client = _ClientEnd()
        self._input = _ServerInput(self.process.stdin)
        self.proxy = mcp_proxy.Proxy(Firewall(policy, audit_path=audit_path, log_args=False),
                                     client_out=self._client, server_in=self._input)
        self._lock = threading.Lock()
        self._next_id = 0
        self._wanted: set[int] = set()  # ids of requests sent, whose raw replies are kept
        self._raw: dict[int, Any] = {}
        self._stderr: deque[str] = deque(maxlen=MAX_STDERR_LINES)
        self._output_closed = threading.Event()
        self._readers = [
            threading.Thread(target=self._read_output, daemon=True),
            threading.Thread(target=self._read_stderr, daemon=True),
        ]
        for reader in self._readers:
            reader.start()

    # ---- what the server sends

    def _read_output(self) -> None:
        """Hand each line to the proxy, as its server pump would, keeping the raw replies to our requests."""
        assert self.process.stdout is not None
        stream, limit = self.process.stdout, mcp_proxy.DEFAULT_MAX_MESSAGE_BYTES
        try:
            while True:
                line = stream.readline(limit + 1)
                if not line:
                    return
                if len(line) > limit and not line.endswith(b"\n"):
                    _skip_rest_of_line(stream)  # the proxy drops such a message too
                    continue
                self._keep_raw(line)
                self.proxy.handle_server_line(line)
        except (OSError, ValueError):
            return
        finally:
            self._output_closed.set()

    def _keep_raw(self, line: bytes) -> None:
        try:
            message = json.loads(line)
        except (ValueError, RecursionError):
            return
        if not isinstance(message, dict) or "result" not in message:
            return
        msg_id = message.get("id")
        if isinstance(msg_id, int) and not isinstance(msg_id, bool):
            with self._lock:
                if msg_id in self._wanted:
                    self._raw[msg_id] = message["result"]

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        try:
            for line in iter(lambda: self.process.stderr.readline(MAX_STDERR_LINE_BYTES), b""):
                text = line.decode("utf-8", errors="replace").rstrip("\r\n")
                if text.strip():
                    self._stderr.append(text)
        except (OSError, ValueError):
            return

    # ---- what this program sends

    def request(self, method: str, params: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
        """Send a request through the proxy; return (the server's raw result or None, the reply the client got)."""
        with self._lock:
            self._next_id += 1
            msg_id = self._next_id
            self._wanted.add(msg_id)
        self._send({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params}, method)
        reply = self._wait_for(msg_id, method)
        with self._lock:
            self._wanted.discard(msg_id)
            return self._raw.pop(msg_id, None), reply

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method}, method)

    def _send(self, message: dict[str, Any], method: str) -> None:
        try:
            self.proxy.handle_client_line(json.dumps(message).encode("utf-8") + b"\n")
        except (OSError, ValueError) as exc:  # the server has closed its input
            raise ProbeError(self._stopped(method)) from exc

    def _wait_for(self, msg_id: int, method: str) -> dict[str, Any]:
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeError(
                    f"the server did not answer {method} within {self.timeout:g} seconds (see --timeout)"
                    + self._last_words()
                )
            try:
                message = self._client.messages.get(timeout=min(0.1, remaining))
            except queue.Empty:
                if self._output_closed.is_set() and self._client.messages.empty():
                    raise ProbeError(self._stopped(method)) from None
                continue
            if isinstance(message, dict) and message.get("id") == msg_id and (
                "result" in message or "error" in message
            ):
                return message
            # Anything else (a notification, a request from the server) is not what we wait for.

    def _stopped(self, method: str) -> str:
        if self._input.broken and self.process.poll() is None:
            return f"the server stopped reading its input before it answered {method}" + self._last_words()
        try:
            code = self.process.wait(timeout=2)
            how = f" (exit code {code})"
        except subprocess.TimeoutExpired:
            how = ""
        self._readers[1].join(timeout=1)  # its last words
        return f"the server stopped before it answered {method}{how}" + self._last_words()

    def _last_words(self) -> str:
        lines = list(self._stderr)[-5:]
        if not lines:
            return ""
        return "; its last lines on stderr:\n" + "\n".join(f"  {printable(line, limit=300)}" for line in lines)

    def close(self) -> None:
        """Close the server's input, as a client does when it quits, and make sure the process is gone."""
        self._input.close()
        mcp_proxy._stop(self.process, time.monotonic() + 2)
        self._input.join(timeout=2)
        for reader in self._readers:
            reader.join(timeout=2)
        # Closed only once its reader has finished: closing a pipe that a thread is still reading
        # (a grandchild of the server can hold it open) would wait for that read.
        for reader, stream in zip(self._readers, (self.process.stdout, self.process.stderr)):
            if stream is not None and not reader.is_alive():
                try:
                    stream.close()
                except OSError:
                    pass


def _skip_rest_of_line(stream: Any) -> None:
    while True:
        chunk = stream.readline(65536)
        if not chunk or chunk.endswith(b"\n"):
            return
