"""Run an MCP server behind the firewall.

    agent-sentinel proxy --policy policy.json -- <server command...>

The proxy speaks MCP's stdio transport: one JSON-RPC message per line. It sits
between the client (the agent's host application) and the real server.

    client  --->  [ inspect client message ]  --->  server
    client  <---  [ inspect server message ]  <---  server

Trust model
-----------
* The server is untrusted. Any text it sends may reach the model, so every
  message from it is scanned, whatever its type, and replies are rebuilt from
  the parts that were checked.
* The agent is not fully trusted either: it may have been hijacked by text it
  read earlier. So the actions it requests ("tools/call", "resources/read",
  "resources/subscribe") must pass the policy.

Fail closed
-----------
A message the proxy cannot parse, cannot match to a request, or fails to check
is dropped or answered with an error. It is never forwarded unchecked. Messages
are re-serialized, so each side receives exactly what the proxy inspected.

Code layout
-----------
`Proxy.handle_client_line` and `Proxy.handle_server_line` are the two entry
points. Each parses a line, asks an `_inspect_*` method what to do, and sends
the resulting `_Outcome`. The `_inspect_*` methods decide and never write to a
stream, which keeps them easy to test.

Rules with action "ask" are blocked here, because a stdio proxy has no
terminal to ask a human on.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable

from .firewall import Decision, Firewall
from .policy import Policy, PolicyError
from .textutil import printable, text_views

# How long a tool call waits for an in-flight tools/list reply to be checked.
TOOL_LIST_WAIT_SECONDS = 15
# How long the server gets to finish after the client disconnects.
SHUTDOWN_GRACE_SECONDS = 5

# Resource limits. Each bounds something a hostile peer could otherwise grow forever.
DEFAULT_MAX_MESSAGE_BYTES = 16 * 1024 * 1024
MAX_PENDING_REQUESTS = 10_000  # client requests waiting for a reply
MAX_SERVER_REQUESTS = 1_000  # server requests waiting for the client's reply
MAX_QUARANTINED_TOOLS = 10_000
MAX_PINNED_TOOLS = 10_000
MAX_LABEL_CHARS = 200

# Resource reads are checked by the policy under this name, with one
# argument, "uri". A policy rule for it looks like a rule for a tool.
RESOURCE_READ = "resources/read"
_RESOURCE_METHODS = (RESOURCE_READ, "resources/subscribe")

# List methods and the result field that holds their items. Items are scanned
# one by one, so a single poisoned entry does not take the whole list down.
_LIST_ITEMS_KEY = {
    "tools/list": "tools",
    "prompts/list": "prompts",
    "resources/list": "resources",
    "resources/templates/list": "resourceTemplates",
}

JsonObject = dict[str, Any]


@dataclass(frozen=True)
class _PendingRequest:
    """A client request that was forwarded and is waiting for its reply."""

    method: str
    label: str  # the name used in the audit log: tool name, resource URI or method


@dataclass(frozen=True)
class _Outcome:
    """What to do with an inspected message. Either side may be None."""

    to_server: Any = None
    to_client: Any = None


_DROP = _Outcome()


# ---- small helpers ----------------------------------------------------------

def _warn(message: str) -> None:
    # Warnings can include names chosen by the server, so make them terminal-safe.
    print(f"agent-sentinel: {printable(message)}", file=sys.stderr, flush=True)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def _finite_float(text: str) -> float:
    # "1e999" is valid JSON but becomes infinity, which cannot be written back as JSON.
    value = float(text)
    if not math.isfinite(value):
        raise ValueError(f"{text[:20]} is too large for a number")
    return value


def _parse(line: bytes) -> Any:
    """Parse one line of strict JSON (Python would otherwise accept NaN and Infinity)."""
    return json.loads(line, parse_constant=_reject_constant, parse_float=_finite_float)


def _valid_id(value: Any) -> bool:
    """MCP request ids are strings or integers (bool is an int in Python, so exclude it)."""
    return isinstance(value, (str, int)) and not isinstance(value, bool)


def _label(text: str) -> str:
    """A bounded name for the audit log; the text may be chosen by the peer."""
    return text if len(text) <= MAX_LABEL_CHARS else text[:MAX_LABEL_CHARS] + "..."


def _tool_error(msg_id: Any, reason: str) -> JsonObject:
    """A tools/call result telling the agent that the call was blocked."""
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "content": [{"type": "text", "text": f"Blocked by agent-sentinel: {reason}"}],
            "isError": True,
        },
    }


def _rpc_error(msg_id: Any, reason: str, code: int = -32000) -> JsonObject:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": f"Blocked by agent-sentinel: {reason}"}}


# ---- tool pinning -----------------------------------------------------------

class ToolPins:
    """Remembers what each tool looked like when it was first seen.

    A server can show a harmless tool until the user trusts it and then change
    its description or schema (a "rug pull"). Each tool definition is reduced
    to a fingerprint the first time it is listed; a later listing with a
    different fingerprint is reported as "changed".

    With a file, the fingerprints survive restarts (trust on first use). Use
    one file per server. To accept a legitimate update, delete the tool's
    entry, or the file.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else None
        self._fingerprints: dict[str, str] = {}
        self._unsaved = False
        if self._path is not None and self._path.exists():
            self._load()

    def _load(self) -> None:
        assert self._path is not None
        data = json.loads(self._path.read_text(encoding="utf-8"))
        tools = data.get("tools") if isinstance(data, dict) else None
        if not isinstance(tools, dict) or not all(isinstance(v, str) for v in tools.values()):
            raise ValueError(f"{self._path}: not a tool pins file")
        self._fingerprints = dict(tools)

    @staticmethod
    def fingerprint(tool: JsonObject) -> str:
        canonical = json.dumps(tool, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode("ascii")).hexdigest()

    def check(self, name: str, tool: JsonObject) -> str:
        """Return "same", "changed", "new" (and remember it) or "full"."""
        fingerprint = self.fingerprint(tool)
        known = self._fingerprints.get(name)
        if known is not None:
            return "same" if known == fingerprint else "changed"
        if len(self._fingerprints) >= MAX_PINNED_TOOLS:
            return "full"
        self._fingerprints[name] = fingerprint
        self._unsaved = True
        return "new"

    def save(self) -> None:
        """Write new fingerprints to the file, if there is one. Never raises."""
        if self._path is None or not self._unsaved:
            return
        temporary = self._path.with_name(self._path.name + ".tmp")
        try:
            temporary.write_text(json.dumps({"version": 1, "tools": self._fingerprints}, indent=1), encoding="utf-8")
            os.replace(temporary, self._path)  # atomic: a crash cannot leave half a file
            self._unsaved = False
        except OSError as exc:
            _warn(f"cannot save tool pins to {self._path}: {exc}")


# ---- the proxy --------------------------------------------------------------

class Proxy:
    def __init__(
        self,
        firewall: Firewall,
        client_out: BinaryIO,
        server_in: BinaryIO,
        pins: ToolPins | None = None,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    ) -> None:
        self._firewall = firewall
        self._client_out = client_out
        self._server_in = server_in
        self._pins = pins if pins is not None else ToolPins()
        self._max_message_bytes = max_message_bytes
        self._client_write_lock = threading.Lock()
        self._server_write_lock = threading.Lock()

        # `_state` guards the collections below. It is a Condition so that
        # tool calls can wait for tool lists to finish being checked.
        self._state = threading.Condition()
        self._pending: dict[str | int, _PendingRequest] = {}
        self._server_requests: set[str | int] = set()  # ids of server requests the client has yet to answer
        self._quarantined_tools: set[str] = set()
        self._quarantine_overflowed = False
        self._tools_unverified = False  # set while the latest tools/list reply was malformed
        self._tool_lists_in_flight: set[str | int] = set()

    # ---- entry points -------------------------------------------------------

    def pump_client_to_server(self, client_in: BinaryIO) -> None:
        """Relay client messages until the client or the server goes away."""
        self._pump(client_in, self.handle_client_line, "client")

    def pump_server_to_client(self, server_out: BinaryIO) -> None:
        """Relay server messages until the server or the client goes away."""
        self._pump(server_out, self.handle_server_line, "server")

    def _pump(self, stream: BinaryIO, handle_line: Callable[[bytes], None], side: str) -> None:
        limit = self._max_message_bytes
        while True:
            try:
                # A bounded read: a peer that never sends a newline cannot fill memory.
                line = stream.readline(limit + 1)
                if not line:
                    return
                if len(line) > limit and not line.endswith(b"\n"):
                    self._discard_rest_of_line(stream)
                    self._dropped(f"a {side} message larger than {limit} bytes")
                elif line.strip():
                    handle_line(line)
            except (OSError, ValueError):  # a pipe was closed under us
                return

    @staticmethod
    def _discard_rest_of_line(stream: BinaryIO) -> None:
        while True:
            chunk = stream.readline(65536)
            if not chunk or chunk.endswith(b"\n"):
                return

    def handle_client_line(self, line: bytes) -> None:
        try:
            message = _parse(line)
        except (ValueError, RecursionError):
            self._dropped("a client message that is not valid JSON")
            return
        try:
            outcome = self._inspect_client_message(message)
        except Exception as exc:  # a bug in a check must not let the message through
            _warn(f"refused a client message after an internal error: {exc!r}")
            outcome = self._internal_error_outcome(message)
        self._send(outcome)

    def handle_server_line(self, line: bytes) -> None:
        try:
            message = _parse(line)
        except (ValueError, RecursionError):
            self._dropped("a server message that is not valid JSON")
            return
        try:
            outcome = self._inspect_server_message(message)
        except Exception as exc:
            _warn(f"dropped a server message after an internal error: {exc!r}")
            outcome = _DROP
        self._send(outcome)

    # ---- refusing -----------------------------------------------------------

    def _dropped(self, what: str) -> _Outcome:
        """Record and report a message that is being dropped for its shape."""
        self._firewall.block("?", f"dropped {what}", event="dropped")
        _warn(f"dropped {what}")
        return _DROP

    def _refusal(self, label: str, reason: str) -> Decision:
        """A block for a structural reason. Unlike a policy block, monitor mode does not lift it."""
        self._firewall.block(label, reason)
        return Decision(False, reason)

    # ---- client -> server ---------------------------------------------------

    def _inspect_client_message(self, message: Any) -> _Outcome:
        if isinstance(message, list):
            return self._refuse_batch(message)
        if not isinstance(message, dict):
            return self._dropped("a client message that is not a JSON object")
        if "id" in message and not _valid_id(message["id"]):
            return self._dropped("a client message with an invalid id")

        method = message.get("method")
        if method is None:
            return self._check_client_reply(message)
        if not isinstance(method, str) or not method:
            return self._dropped("a client message with an invalid method")

        if method == "tools/call":
            return self._check_tool_call(message)
        if method in _RESOURCE_METHODS:
            return self._check_resource_request(message)
        if method == "notifications/cancelled":
            self._forget_cancelled_request(message)
        return self._forward_request(message, label=method)

    def _refuse_batch(self, batch: list[Any]) -> _Outcome:
        # MCP no longer uses JSON-RPC batches. Refusing them keeps every
        # request on the single, checked path above.
        self._firewall.block("?", "dropped a batched client message", event="dropped")
        replies = [
            _rpc_error(item["id"], "batched requests are not supported", code=-32600)
            for item in batch
            if isinstance(item, dict) and _valid_id(item.get("id"))
        ]
        return _Outcome(to_client=replies or None)

    def _check_client_reply(self, message: JsonObject) -> _Outcome:
        """No method: this must be the client's answer to a request the server made."""
        msg_id = message.get("id")
        is_reply = ("result" in message) != ("error" in message)
        with self._state:
            expected = is_reply and _valid_id(msg_id) and msg_id in self._server_requests
            if expected:
                self._server_requests.discard(msg_id)
        if not expected:
            return self._dropped("a client message that answers no request from the server")
        return _Outcome(to_server=message)

    def _check_tool_call(self, message: JsonObject) -> _Outcome:
        params = message.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        arguments = params.get("arguments") if isinstance(params, dict) else None

        if not isinstance(name, str) or not name:
            decision = self._refusal("?", "malformed tools/call request: missing tool name")
        elif arguments is not None and not isinstance(arguments, dict):
            decision = self._refusal(_label(name), "malformed tools/call request: arguments must be an object")
        elif name in _RESOURCE_METHODS:
            # Resource reads share the policy's namespace; a tool must not borrow their rule.
            decision = self._refusal(_label(name), "this tool name is reserved")
        elif not self._wait_for_tool_lists():
            decision = self._refusal(_label(name), "timed out waiting for the tool list to be checked")
        elif self._is_quarantined(name):
            decision = self._refusal(_label(name), "this tool was removed from the tool list and cannot be called")
        else:
            decision = self._firewall.check_call(name, arguments or {})
        return self._forward_or_refuse(message, decision, label=_label(str(name)), refusal=_tool_error)

    def _check_resource_request(self, message: JsonObject) -> _Outcome:
        """resources/read and resources/subscribe both ask the server to open a URI."""
        params = message.get("params")
        uri = params.get("uri") if isinstance(params, dict) else None
        if not isinstance(uri, str) or not uri:
            decision = self._refusal(RESOURCE_READ, f"malformed {message['method']} request: missing uri")
        else:
            decision = self._firewall.check_call(RESOURCE_READ, {"uri": uri})
        return self._forward_or_refuse(message, decision, label=_label(str(uri)), refusal=_rpc_error)

    def _forward_or_refuse(
        self, message: JsonObject, decision: Decision, label: str, refusal: Callable[[Any, str], JsonObject]
    ) -> _Outcome:
        if decision.allowed:
            return self._forward_request(message, label, refusal)
        if "id" in message:
            return _Outcome(to_client=refusal(message["id"], decision.public_reason))
        return _DROP

    def _forward_request(
        self, message: JsonObject, label: str, refusal: Callable[[Any, str], JsonObject] = _rpc_error
    ) -> _Outcome:
        """Forward a client message, remembering a request so its reply can be matched and scanned."""
        if "id" not in message:
            return _Outcome(to_server=message)  # a notification: no reply will come
        with self._state:
            # If the client reuses an id that is still in flight, the newer
            # request wins. That is safe because every reply is scanned.
            is_new = message["id"] not in self._pending
            if is_new and len(self._pending) >= MAX_PENDING_REQUESTS:
                reason = "too many requests are waiting for a reply"
                return _Outcome(to_client=refusal(message["id"], reason))
            self._pending[message["id"]] = _PendingRequest(message["method"], label)
            if message["method"] == "tools/list":
                self._tool_lists_in_flight.add(message["id"])
        return _Outcome(to_server=message)

    def _forget_cancelled_request(self, message: JsonObject) -> None:
        params = message.get("params")
        request_id = params.get("requestId") if isinstance(params, dict) else None
        if not _valid_id(request_id):
            return
        with self._state:
            self._pending.pop(request_id, None)
            self._tool_lists_in_flight.discard(request_id)
            self._state.notify_all()

    def _wait_for_tool_lists(self) -> bool:
        """Wait until no tools/list reply is being checked.

        Without this, a call could reach a tool in the short time before the
        list that would quarantine it has been processed. The wait holds up
        the client-to-server direction, which is the price of keeping calls
        in order; it ends as soon as the server answers.
        """
        with self._state:
            if self._state.wait_for(lambda: not self._tool_lists_in_flight, timeout=TOOL_LIST_WAIT_SECONDS):
                return True
            # The server never answered. Stop waiting for those lists so that
            # later calls are not delayed too; a late reply is still filtered.
            self._tool_lists_in_flight.clear()
            return False

    def _is_quarantined(self, tool: str) -> bool:
        with self._state:
            # No tool can be vouched for if more were quarantined than can be
            # remembered, or if the last tool list could not be checked at all.
            return self._quarantine_overflowed or self._tools_unverified or tool in self._quarantined_tools

    def _set_tools_unverified(self, unverified: bool) -> None:
        with self._state:
            if unverified and not self._tools_unverified:
                _warn("the tool list could not be checked; tool calls are refused until a valid list arrives")
            self._tools_unverified = unverified

    def _quarantine(self, tool: str) -> None:
        with self._state:
            if len(self._quarantined_tools) < MAX_QUARANTINED_TOOLS:
                self._quarantined_tools.add(tool)
            elif not self._quarantine_overflowed:
                self._quarantine_overflowed = True
                _warn("too many quarantined tools to track; all tool calls are now refused")

    def _internal_error_outcome(self, message: Any) -> _Outcome:
        """Tell the client its request failed, so it is not left waiting."""
        if isinstance(message, dict) and isinstance(message.get("method"), str) and _valid_id(message.get("id")):
            return _Outcome(to_client=_rpc_error(message["id"], "internal error while checking the request"))
        return _DROP

    # ---- server -> client ---------------------------------------------------

    def _inspect_server_message(self, message: Any) -> _Outcome:
        if not isinstance(message, dict):
            return self._dropped("a server message that is not a JSON object")
        if "method" in message:
            return self._check_server_request(message)
        return self._check_server_reply(message)

    def _check_server_request(self, message: JsonObject) -> _Outcome:
        """Check a request or notification that the server sends to the client.

        These can carry text toward the model (a sampling request is a prompt
        the server wants the client's model to answer). The policy may refuse
        a method outright; everything that is let through is scanned.
        """
        method, msg_id = message["method"], message.get("id")
        is_request = "id" in message
        well_formed = (
            isinstance(method, str) and method
            and "result" not in message and "error" not in message  # otherwise it is a reply in disguise
            and (not is_request or _valid_id(msg_id))
        )
        if not well_formed:
            return self._dropped("a server message that is neither a valid request nor a reply")

        label = _label(f"server:{method}")  # prefixed so it cannot pass for a tool name in the log
        if self._firewall.policy.server_request_action(method) == "block":
            decision = self._firewall.block(label, "the policy does not permit this server request", "server_request")
        else:
            decision = self._firewall.scan_result(label, text_views(message), event="server_request", log_clean=False)
        if decision.allowed and is_request and not self._expect_client_reply(msg_id):
            decision = Decision(False, "too many server requests are waiting for a reply")

        if decision.allowed:
            return _Outcome(to_client=message)
        _warn(f"refused a '{method}' message from the server: {decision.reason}")
        if is_request:
            # Answer so the server is not left waiting, without saying which check it failed.
            return _Outcome(to_server=_rpc_error(msg_id, "request refused"))
        return _DROP

    def _expect_client_reply(self, msg_id: str | int) -> bool:
        with self._state:
            if len(self._server_requests) >= MAX_SERVER_REQUESTS and msg_id not in self._server_requests:
                return False
            self._server_requests.add(msg_id)
            return True

    def _check_server_reply(self, message: JsonObject) -> _Outcome:
        msg_id = message.get("id")
        with self._state:
            pending = self._pending.pop(msg_id, None) if _valid_id(msg_id) else None
        if pending is None:
            # A reply to a request we did not forward could not be attributed
            # to a method, so there is no safe way to deliver it.
            return self._dropped("a server reply that matches no forwarded request")
        try:
            return _Outcome(to_client=self._checked_reply(message, pending))
        except Exception as exc:
            _warn(f"blocked a server reply after an internal error: {exc!r}")
            return _Outcome(to_client=_rpc_error(msg_id, "internal error while checking the reply"))
        finally:
            # Quarantine decisions were recorded inside _checked_reply, so
            # calls waiting on this tool list may now proceed.
            with self._state:
                self._tool_lists_in_flight.discard(msg_id)
                self._state.notify_all()

    def _checked_reply(self, message: JsonObject, pending: _PendingRequest) -> JsonObject:
        """Return the reply to deliver: rebuilt from checked parts, or an error.

        The server's own envelope is never forwarded: only "result" or "error"
        is taken from it, so text in any other member cannot ride along.
        """
        msg_id = message["id"]
        if ("result" in message) == ("error" in message):
            return self._malformed_reply(pending, msg_id, "a reply must have exactly one of result and error")
        if "error" in message:
            return self._deliver_or_block(pending, msg_id, "error", message["error"], scan=message["error"])

        result = message["result"]
        to_scan = result
        items_key = _LIST_ITEMS_KEY.get(pending.method)
        if items_key is not None:
            is_tool_list = items_key == "tools"
            if not isinstance(result, dict) or not isinstance(result.get(items_key, []), list):
                if is_tool_list:
                    # Its tools could not be checked, so none of them can be vouched for.
                    self._set_tools_unverified(True)
                return self._malformed_reply(pending, msg_id, "a list reply must hold a list")
            if items_key in result:
                result[items_key] = self._clean_items(result[items_key], items_key)
                if is_tool_list:
                    self._set_tools_unverified(False)
                # The items were just checked one by one; what is left is checked below.
                to_scan = {key: value for key, value in result.items() if key != items_key}
        elif pending.method == "initialize" and isinstance(result, dict):
            self._strip_poisoned_instructions(result)
        return self._deliver_or_block(pending, msg_id, "result", result, scan=to_scan, log_clean=items_key is None)

    def _malformed_reply(self, pending: _PendingRequest, msg_id: Any, reason: str) -> JsonObject:
        self._firewall.block(pending.label, f"malformed reply: {reason}", event="result")
        _warn(f"blocked a malformed reply to {pending.method}: {reason}")
        return _rpc_error(msg_id, "the server sent a malformed reply")

    def _deliver_or_block(
        self, pending: _PendingRequest, msg_id: Any, member: str, value: Any, scan: Any, log_clean: bool = True
    ) -> JsonObject:
        decision = self._firewall.scan_result(pending.label, text_views(scan), log_clean=log_clean)
        if decision.allowed:
            return {"jsonrpc": "2.0", "id": msg_id, member: value}
        if pending.method == "tools/call":
            return _tool_error(msg_id, decision.public_reason)
        return _rpc_error(msg_id, decision.public_reason)

    def _strip_poisoned_instructions(self, result: JsonObject) -> None:
        """Remove the server's `instructions` if they look like an injection.

        Clients commonly place these instructions in the model's system
        prompt, which makes them the most direct injection route a server has.
        Removing the field keeps the connection usable.
        """
        instructions = result.get("instructions")
        if not isinstance(instructions, str):
            return
        decision = self._firewall.scan_result("initialize", instructions, event="server_instructions")
        if not decision.allowed:
            del result["instructions"]
            _warn(f"removed the server's instructions: {decision.reason}")

    def _clean_items(self, items: list[Any], items_key: str) -> list[Any]:
        """Return the list entries (tools, prompts, resources) that are safe to show."""
        kept = []
        for item in items:
            name = item.get("name") if isinstance(item, dict) else None
            label = _label(name) if isinstance(name, str) and name else "?"
            problem = self._problem_with_item(item, label, is_tool=items_key == "tools")
            if problem is None:
                kept.append(item)
            else:
                _warn(f"removed '{label}' from the {items_key} list: {problem}")
        if items_key == "tools":
            self._pins.save()
        return kept

    def _problem_with_item(self, item: Any, label: str, is_tool: bool) -> str | None:
        """Why a list entry must be removed, or None if it may stay."""
        if not isinstance(item, dict) or (is_tool and label == "?"):
            return "it is not a well-formed entry"
        if is_tool and self._is_quarantined(item["name"]):
            return "it was quarantined earlier"  # even if it looks clean now

        event = "tool_description" if is_tool else "list_item"
        decision = self._firewall.scan_result(label, text_views(item), event=event, log_clean=False)
        if decision.allowed and is_tool:
            decision = self._check_pin(item, label)
        if decision.allowed:
            return None
        if is_tool:
            # Remember the name: the agent may already know it from an
            # earlier list, and the server may list it again looking clean.
            self._quarantine(item["name"])
        return decision.reason

    def _check_pin(self, tool: JsonObject, label: str) -> Decision:
        status = self._pins.check(tool["name"], tool)
        if status == "changed":
            reason = "its definition changed after it was first seen"
            return self._firewall.block(label, f"tool quarantined: {reason}", event="tool_changed")
        if status == "full":
            return Decision(False, "too many tools to keep track of")
        return Decision(True, "tool definition is unchanged or new")

    # ---- sending ------------------------------------------------------------

    def _send(self, outcome: _Outcome) -> None:
        if outcome.to_server is not None:
            self._write(self._server_in, self._server_write_lock, outcome.to_server)
        if outcome.to_client is not None:
            self._write(self._client_out, self._client_write_lock, outcome.to_client)

    @staticmethod
    def _write(stream: BinaryIO, lock: threading.Lock, message: Any) -> None:
        data = json.dumps(message).encode("utf-8") + b"\n"
        with lock:
            stream.write(data)
            stream.flush()


# ---- starting and stopping the server ---------------------------------------

def _resolve_executable(name: str) -> str | None:
    """Find the server command on PATH, never in the current directory.

    The proxy usually runs in a project folder, where a hijacked agent with a
    file-writing tool (or a cloned repository) could plant "npx.cmd". Windows
    would normally run that file in preference to the real one on PATH. A
    command written with a folder, such as ".\\server.exe", is used as given:
    that is an explicit choice by the operator.
    """
    if os.path.dirname(name):
        return name
    here = os.path.normcase(os.path.abspath(os.getcwd()))
    folders = [
        folder for folder in os.environ.get("PATH", "").split(os.pathsep)
        if folder and os.path.normcase(os.path.abspath(folder)) != here
    ]
    endings = [""]
    if sys.platform == "win32":
        endings = [e for e in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(os.pathsep) if e]
        if any(name.lower().endswith(e.lower()) for e in endings):
            endings = [""]
    for folder in folders:
        for ending in endings:
            candidate = os.path.join(folder, name + ending)
            if os.path.isfile(candidate) and (sys.platform == "win32" or os.access(candidate, os.X_OK)):
                return candidate
    return None


def _relay_stderr(stream: BinaryIO) -> None:
    """Print what the server writes to stderr, made safe and clearly labelled.

    Left alone, the server would write straight to the operator's terminal:
    escape codes, or lines dressed up as messages from this proxy.
    """
    while True:
        try:
            chunk = stream.readline(8192)  # bounded, in case there is never a newline
        except (OSError, ValueError):
            return
        if not chunk:
            return
        text = chunk.decode("utf-8", errors="replace").rstrip("\r\n")
        if text:
            _warn(f"server stderr: {text}")


def _stop(server: subprocess.Popen) -> int:
    """Make sure the server process is gone and return its exit code."""
    if server.poll() is None:
        if sys.platform == "win32":
            # terminate() would leave grandchildren running (e.g. the node
            # process behind an npx.cmd launcher); /T ends the whole tree.
            taskkill = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "taskkill.exe")
            subprocess.run([taskkill, "/PID", str(server.pid), "/T", "/F"], capture_output=True, check=False)
        else:
            server.terminate()
    try:
        return server.wait(timeout=SHUTDOWN_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        server.kill()
        return server.wait()


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-sentinel proxy", description="Run an MCP server behind the firewall.")
    parser.add_argument("--policy", required=True, help="path to the policy JSON file")
    parser.add_argument("--audit", default=None, help="path of the audit log (JSON lines)")
    parser.add_argument("--no-log-args", action="store_true", help="leave tool arguments out of the audit log")
    parser.add_argument("--pins", default=None, metavar="FILE",
                        help="remember tool definitions in FILE and quarantine a tool that changes later")
    parser.add_argument("--monitor", action="store_true",
                        help="log what the policy and the scanner would block, but block nothing (for tuning a policy)")
    parser.add_argument("--max-message-bytes", type=_positive_int, default=DEFAULT_MAX_MESSAGE_BYTES,
                        help=f"drop any message larger than this (default {DEFAULT_MAX_MESSAGE_BYTES})")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- followed by the MCP server command")
    args = parser.parse_args(argv)
    if hasattr(sys.stderr, "reconfigure"):  # warnings must never crash on an odd character
        sys.stderr.reconfigure(errors="backslashreplace")

    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("give the MCP server command after '--'")
    try:
        policy = Policy.from_file(args.policy)
    except (OSError, PolicyError) as exc:
        _warn(f"cannot load policy: {exc}")
        return 2
    try:
        pins = ToolPins(args.pins)
    except (OSError, ValueError) as exc:  # unreadable, not JSON, or not a pins file
        _warn(f"cannot load tool pins: {exc}")
        return 2

    executable = _resolve_executable(command[0])
    if executable is None:
        _warn(f"cannot find the server command '{command[0]}' on PATH. The current folder is not searched; "
              f"to run a file from it, write the path, for example .{os.sep}{command[0]}")
        return 2
    # Keep Windows from looking in the current folder when it starts the process.
    os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"
    try:
        server = subprocess.Popen(
            [executable, *command[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    except OSError as exc:
        _warn(f"cannot start server: {exc}")
        return 2
    assert server.stdin is not None and server.stdout is not None and server.stderr is not None
    if args.monitor:
        _warn("monitor mode: nothing is being blocked by the policy or the scanner")

    firewall = Firewall(policy, audit_path=args.audit, log_args=not args.no_log_args, monitor=args.monitor)
    proxy = Proxy(firewall, sys.stdout.buffer, server.stdin, pins=pins, max_message_bytes=args.max_message_bytes)

    # Run one relay per direction. When either side closes, shut down.
    one_side_closed = threading.Event()

    def relay(pump: Callable[[BinaryIO], None], stream: BinaryIO) -> None:
        try:
            pump(stream)
        finally:
            one_side_closed.set()

    client_relay = threading.Thread(target=relay, args=(proxy.pump_client_to_server, sys.stdin.buffer), daemon=True)
    server_relay = threading.Thread(target=relay, args=(proxy.pump_server_to_client, server.stdout), daemon=True)
    # The stderr relay is never joined: a grandchild of the server can hold that pipe open.
    threading.Thread(target=_relay_stderr, args=(server.stderr,), daemon=True).start()
    client_relay.start()
    server_relay.start()
    one_side_closed.wait()

    try:
        server.stdin.close()  # tell the server there is no more input
    except OSError:
        pass
    server_relay.join(timeout=SHUTDOWN_GRACE_SECONDS)  # let it finish answering
    return _stop(server)


if __name__ == "__main__":
    sys.exit(main())
