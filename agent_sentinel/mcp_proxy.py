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

Protocol revisions
------------------
The proxy knows the revisions in mcp_protocol.SUPPORTED_VERSIONS, from
2024-11-05 to 2026-07-28 (see mcp_protocol.py for the two eras). A revision
it does not know could add message kinds that would pass unpoliced, so:

* an `initialize` asking for a version the proxy does not know is sent on
  asking for the newest legacy version it knows, and an initialize reply
  that names a version the proxy does not know is refused;
* a request naming an unknown version in params._meta (2026-07-28 style) is
  answered by the proxy with UnsupportedProtocolVersionError, so the client
  retries with a version the proxy knows;
* a server/discover reply lists only the versions the proxy knows;
* a result whose resultType the proxy does not know is refused.

What the 2026-07-28 revision adds is checked like its older equivalent:

* a server asks the client for input inside its reply to tools/call,
  prompts/get or resources/read ("input_required"). Each thing it asks for
  must pass `server_requests`, as a request of its own would, and is
  scanned; one refused entry refuses the whole reply;
* the client's answers (`inputResponses` in the retried request) pass the
  secret guard, as its answers to legacy server requests do;
* subscriptions/listen needs, for every resource URI it names, the
  permission to read that URI, as resources/subscribe does;
* the instructions in a server/discover reply are checked like those in an
  initialize reply;
* once the client has shown that it speaks 2026-07-28, a request from the
  server is refused: on stdio a modern server must not send requests;
* a result the proxy builds itself for a 2026-07-28 request says
  "resultType": "complete";
* tasks are not supported: the tasks capability and extension are removed
  from what each side tells the other, a task result is refused, and
  tasks/* requests are answered "method not found".

The capabilities the client declares are minimised on their way to the
server: a capability whose server request the policy blocks (sampling,
elicitation, roots) is removed, so a well-behaved server does not ask. Only
the copy sent to the server is changed.

What the client sends back to the server (its answers to server requests,
and the inputResponses of a retried request) passes the secret guard, and
an answer is rebuilt from its `result` or `error` before it is forwarded.

Flow rules
----------
One proxy process is one session. When a tools/call or resources/read result
is delivered, the session gains the marks of that tool (Firewall.marks_for,
worked out when the call was let through), so a later call can be refused by
a flow rule. Marks are set just before the reply is sent, and only for a
reply that is sent; a reply that is blocked sets none. The labels implied by
each listed tool's MCP annotations are passed to the firewall as well.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable

from . import mcp_protocol as protocol
from .firewall import Decision, Firewall
from .leaks import find_secrets
from .mcp_protocol import ShapeError
from .policy import RULE_MALFORMED, RULE_QUARANTINE, RULE_SECRETS, Policy, PolicyError
from .policy_errors import file_error_message
from .session import SessionStateError
from .textutil import UnscannableError, printable, texts_in

# How long a tool call waits for an in-flight tools/list reply to be checked.
TOOL_LIST_WAIT_SECONDS = 15
# After either side closes, how long the server has in all to finish answering
# and exit before it is stopped. Kept short: a host application that closes
# our input typically waits only a couple of seconds before killing us, and a
# proxy that is killed first leaves its server running.
SHUTDOWN_GRACE_SECONDS = 1.5

# Resource limits. Each bounds something a hostile peer could otherwise grow forever.
DEFAULT_MAX_MESSAGE_BYTES = 16 * 1024 * 1024
MAX_PENDING_REQUESTS = 10_000  # client requests waiting for a reply
MAX_SERVER_REQUESTS = 1_000  # server requests waiting for the client's reply
MAX_QUARANTINED_TOOLS = 10_000
MAX_PINNED_TOOLS = 10_000
MAX_LABEL_CHARS = 200
MAX_NAME_CHARS = 256  # tool names and request ids the proxy has to remember

# Resource reads are checked by the policy under this name, with one
# argument, "uri". A policy rule for it looks like a rule for a tool.
RESOURCE_READ = "resources/read"
_RESOURCE_METHODS = (RESOURCE_READ, "resources/subscribe")

# The members of a tool definition that reach the model, and so are pinned.
_PINNED_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")

# List methods and the result field that holds their items. Items are scanned
# one by one, so a single poisoned entry does not take the whole list down.
_LIST_ITEMS_KEY = {
    "tools/list": "tools",
    "prompts/list": "prompts",
    "resources/list": "resources",
    "resources/templates/list": "resourceTemplates",
}

JsonObject = dict[str, Any]

# What the agent is told. Like every refusal, it names no rule.
_SECRET_REFUSAL = "the request contains what looks like a secret, so it was not sent"
_INPUT_REFUSAL = "the server asked for input that is not permitted"
_MALFORMED_REQUEST = "the request is malformed"
_MALFORMED_REPLY = "the server sent a malformed reply"
_UNSUPPORTED_REQUEST = "this request is not supported"
_UNSUPPORTED_REPLY = "the server sent a reply this proxy cannot check"
_UNSUPPORTED_VERSION = "the server chose a protocol version this proxy does not support"
# What a refused server is told: nothing about why.
_SERVER_REFUSAL = "request refused"

# The protocol era of the session (see mcp_protocol.py), once the client has shown it.
_LEGACY = "legacy"
_MODERN = "modern"


@dataclass(frozen=True)
class _PendingRequest:
    """A client request that was forwarded and is waiting for its reply."""

    method: str
    label: str  # the name used in the audit log: tool name, resource URI or method
    # Flow marks to set when the reply is delivered (tools/call and resources/read only).
    marks: frozenset[str] = frozenset()
    call_id: str | None = None  # the firewall's id for this call, so the result's record shares it
    # The request named a 2026-07-28 protocol version, so a result the proxy builds for it needs a resultType.
    modern: bool = False


@dataclass(frozen=True)
class _Outcome:
    """What to do with an inspected message. Either side may be None."""

    to_server: Any = None
    to_client: Any = None


_DROP = _Outcome()


# ---- small helpers ----------------------------------------------------------

def _warn(message: str, limit: int = 300) -> None:
    # Warnings can include names chosen by the server, so make them terminal-safe.
    print(f"agent-sentinel: {printable(message, limit=limit)}", file=sys.stderr, flush=True)


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
    """MCP request ids are strings or integers (bool is an int in Python, so exclude it).

    Ids are remembered until answered, so a very long one is refused too.
    """
    if isinstance(value, str):
        return len(value) <= MAX_NAME_CHARS
    return isinstance(value, int) and not isinstance(value, bool)


def _is_name(value: Any) -> bool:
    """A usable tool, prompt or resource name. The proxy remembers names, so they have a length limit."""
    return isinstance(value, str) and 0 < len(value) <= MAX_NAME_CHARS


def _label(text: str) -> str:
    """A bounded name for the audit log; the text may be chosen by the peer."""
    return text if len(text) <= MAX_LABEL_CHARS else text[:MAX_LABEL_CHARS] + "..."


def _tool_error(msg_id: Any, reason: str, modern: bool = False) -> JsonObject:
    """A tools/call result telling the agent that the call was blocked.

    modern: the request named a 2026-07-28 protocol version, where every
            result must say what kind of result it is.
    """
    result: JsonObject = {
        "content": [{"type": "text", "text": f"Blocked by agent-sentinel: {reason}"}],
        "isError": True,
    }
    if modern:
        result["resultType"] = protocol.RESULT_COMPLETE
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _rpc_error(msg_id: Any, reason: str, code: int = -32000) -> JsonObject:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": f"Blocked by agent-sentinel: {reason}"}}


def _refusal_reply(method: str, msg_id: Any, reason: str, modern: bool) -> JsonObject:
    """The answer to a refused request: a tool error for a tool call, so the agent reads it; else a JSON-RPC error."""
    if method == "tools/call":
        return _tool_error(msg_id, reason, modern)
    return _rpc_error(msg_id, reason)


def _is_modern_request(message: JsonObject) -> bool:
    """Whether a client request names a 2026-07-28 protocol version (one the proxy knows)."""
    try:
        return protocol.requested_version(message) in protocol.MODERN_VERSIONS
    except ShapeError:
        return False


def _request_label(message: JsonObject) -> str:
    """The name a client request has in the audit log: the tool's name for a tool call, otherwise the method.

    The same names check_call is given, so all records of a tool are found under one name.
    """
    params = message.get("params")
    name = params.get("name") if isinstance(params, dict) else None
    if message["method"] == "tools/call" and isinstance(name, str) and name:
        return _label(name)
    return _label(message["method"])


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

    def __init__(self, path: str | Path | None = None, enabled: bool = True) -> None:
        self._enabled = enabled
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
        """A digest of the parts of a tool definition that a model reads.

        Other members, such as "_meta", are left out: servers put counters and
        timestamps there, and a tool that "changed" on every listing would be
        quarantined for nothing.
        """
        pinned = {name: tool[name] for name in _PINNED_FIELDS if name in tool}
        canonical = json.dumps(pinned, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode("ascii")).hexdigest()

    def check(self, name: str, tool: JsonObject) -> str:
        """Return "same", "changed", "new" (and remember it) or "full"."""
        if not self._enabled:
            return "same"
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
        # Server requests the client has yet to answer, id -> method, oldest first (a dict keeps insertion order).
        self._server_requests: dict[str | int, str] = {}
        # The protocol era of the session: None until it is known, "legacy" once the client
        # sends initialize (for good: a dual-era client falls back to it), "modern" once a
        # client request names a 2026-07-28 version or a server/discover result arrives.
        # In a modern session the server may not send requests (see _check_server_request).
        self._era: str | None = None
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
        self._firewall.refuse("?", f"dropped {what}", event="dropped", rule=RULE_MALFORMED)
        _warn(f"dropped {what}")
        return _DROP

    def _refusal(self, label: str, reason: str, rule: str = RULE_MALFORMED) -> Decision:
        """A block for a structural reason. Unlike a policy block, monitor mode does not lift it."""
        return self._firewall.refuse(label, reason, rule=rule)

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

        # What every request must pass first: the protocol revision's rules, then
        # the secret guard on the answers it carries back to the server (if any).
        refused = self._check_protocol(message) or self._check_input_responses(message)
        if refused is not None:
            return refused
        if method == "tools/call":
            return self._check_tool_call(message)
        if method in _RESOURCE_METHODS:
            return self._check_resource_request(message)
        if method == protocol.SUBSCRIPTIONS_LISTEN:
            return self._check_subscriptions(message)
        if method.startswith(protocol.TASKS_METHOD_PREFIX):
            return self._refuse_task_request(message)
        if method == "notifications/cancelled":
            self._forget_cancelled_request(message)
        return self._forward_request(message, label=_label(method))

    def _refuse_batch(self, batch: list[Any]) -> _Outcome:
        # MCP no longer uses JSON-RPC batches. Refusing them keeps every
        # request on the single, checked path above.
        decision = self._firewall.refuse(
            "?", "dropped a batched client message", event="dropped",
            public_reason="batched requests are not supported", rule=RULE_MALFORMED,
        )
        replies = [
            _rpc_error(item["id"], decision.public_reason, code=-32600)
            for item in batch
            if isinstance(item, dict) and _valid_id(item.get("id"))
        ]
        return _Outcome(to_client=replies or None)

    # ---- client -> server: answers to the server's requests -----------------------

    def _check_client_reply(self, message: JsonObject) -> _Outcome:
        """No method: this must be the client's answer to a request the server made.

        The answer is written by the client's model or its user (a sampling
        result is text a possibly hijacked model wrote), so it passes the
        secret guard like a tool call's arguments, `error.data` included. It
        is rebuilt from its `result` or `error`, so nothing else in the message
        reaches the server. A refused answer is replaced by an error that tells
        the server nothing.
        """
        msg_id = message.get("id")
        is_reply = ("result" in message) != ("error" in message)
        with self._state:
            method = self._server_requests.pop(msg_id, None) if is_reply and _valid_id(msg_id) else None
        if method is None:
            return self._dropped("a client message that answers no request from the server")

        label = _label(f"server:{method}")  # the label the server's request was logged under
        member = "result" if "result" in message else "error"
        try:
            value = protocol.client_reply_value(member, message[member])
            secrets = self._secrets_in(value)
        except (ShapeError, UnscannableError) as exc:
            self._firewall.refuse(label, f"malformed client reply: {exc}", event="client_reply", rule=RULE_MALFORMED)
            _warn(f"refused the client's answer to a '{method}' request: {exc}")
            return _Outcome(to_server=_rpc_error(msg_id, _SERVER_REFUSAL))
        if secrets:
            reason = f"the client's answer contains what looks like a secret ({', '.join(secrets)})"
            decision = self._firewall.block(label, reason, event="client_reply", rule=RULE_SECRETS)
            if not decision.allowed:
                _warn(f"refused the client's answer to a '{method}' request: {reason}")
                return _Outcome(to_server=_rpc_error(msg_id, _SERVER_REFUSAL))
        return _Outcome(to_server={"jsonrpc": "2.0", "id": msg_id, member: value})

    def _check_input_responses(self, message: JsonObject) -> _Outcome | None:
        """Pass the answers a retried request carries through the secret guard; None when it may go on.

        A 2026-07-28 client answers an input_required reply by sending its
        request again with `inputResponses`: a sampling result is text the
        model wrote, an elicitation result what the user typed. They are
        checked like a tool call's arguments, before the policy looks at the
        request, so that this answer does not depend on the policy. Their
        shape was checked by _check_protocol. `requestState` is the server's
        own state echoed back: it is never scanned or logged.
        """
        params = message.get("params")
        responses = params.get("inputResponses") if isinstance(params, dict) else None
        if not responses:
            return None
        try:
            secrets = self._secrets_in(responses)
        except UnscannableError as exc:
            return self._refuse_malformed_request(message, str(exc))
        if not secrets:
            return None
        reason = f"the answers sent with the request contain what looks like a secret ({', '.join(secrets)})"
        decision = self._firewall.block(
            _request_label(message), reason, public_reason=_SECRET_REFUSAL, rule=RULE_SECRETS
        )
        return None if decision.allowed else self._refused(message, decision)  # allowed: monitor mode

    def _secrets_in(self, value: Any) -> list[str]:
        """The kinds of secret in what the client sends the server besides a call's arguments.

        The same guard check_call applies to arguments (keys included), under
        the same setting: with secrets.in_arguments "allow", nothing is looked for.
        """
        if self._firewall.policy.secrets_in_arguments != "block":
            return []
        return find_secrets("\n".join(texts_in(value, keys=True)))

    # ---- client -> server: the protocol revision ------------------------------

    def _check_protocol(self, message: JsonObject) -> _Outcome | None:
        """Apply the protocol revision's rules to a client message; None when it may go on.

        * A request naming a version in params._meta that the proxy does not
          know is answered with UnsupportedProtocolVersionError, as a 2026-07-28
          server would answer it, so the client retries with a version the
          proxy knows.
        * initialize must name a protocol version, and one the proxy cannot
          pass on is replaced by the newest legacy version it knows.
        * The client's capabilities are minimised in the copy sent to the server.
        * The shape of what a retried request carries back to the server
          (inputResponses, requestState) is checked.
        * The session's era is noted (see `_era`).
        """
        method = message["method"]
        params = message.get("params")
        try:
            version = protocol.requested_version(message)
            if version is not None and version not in protocol.SUPPORTED_VERSIONS:
                return self._unsupported_version(message, version)
            if method == protocol.INITIALIZE:
                self._prepare_initialize(message)
            self._minimise_request_capabilities(message)
            if isinstance(params, dict):
                protocol.check_retry_params(params)
        except ShapeError as exc:
            return self._refuse_malformed_request(message, str(exc))
        self._note_era(method, version)
        return None

    def _note_era(self, method: str, version: str | None) -> None:
        with self._state:
            if method == protocol.INITIALIZE:
                self._era = _LEGACY  # the client chose the handshake, so the server may make requests
            elif version in protocol.MODERN_VERSIONS and self._era is None:
                self._era = _MODERN

    def _prepare_initialize(self, message: JsonObject) -> None:
        """Check a legacy initialize request, and make it ask for a protocol version this proxy knows.

        The server answers with a version of its choice, and the proxy accepts
        only a legacy version it knows (see _check_handshake_reply). Passing on
        an unknown version would invite the server to answer with it, and the
        session would then have to be refused.
        """
        params = message.get("params")
        if not isinstance(params, dict):
            raise ShapeError("params must be an object")
        version = params.get("protocolVersion")
        if not isinstance(version, str):
            raise ShapeError("protocolVersion must be text")
        if version not in protocol.LEGACY_VERSIONS:
            _warn(f"the client asked for MCP protocol version '{printable(version, limit=40)}' in initialize, "
                  f"which this proxy cannot pass on; asking the server for {protocol.NEWEST_LEGACY_VERSION} instead")
            params["protocolVersion"] = protocol.NEWEST_LEGACY_VERSION
        if "capabilities" in params:
            params["capabilities"] = protocol.minimised_capabilities(params["capabilities"], self._blocked_requests())

    def _minimise_request_capabilities(self, message: JsonObject) -> None:
        """Minimise the capabilities a 2026-07-28 request declares in params._meta (requested_version checked _meta)."""
        params = message.get("params")
        meta = params.get("_meta") if isinstance(params, dict) else None
        key = protocol.CLIENT_CAPABILITIES_KEY
        if isinstance(meta, dict) and key in meta:
            meta[key] = protocol.minimised_capabilities(meta[key], self._blocked_requests())

    def _blocked_requests(self) -> frozenset[str]:
        """The server requests the policy blocks, of those a client capability offers (sampling, elicitation, roots).

        Their capabilities are removed from what the server is told, so that a
        well-behaved server does not ask for what would be refused. In monitor
        mode nothing is removed: the requests would be let through anyway.
        """
        if self._firewall.monitor:
            return frozenset()
        policy = self._firewall.policy
        return frozenset(
            method for method in protocol.CAPABILITY_METHODS.values() if policy.server_request_action(method) == "block"
        )

    def _unsupported_version(self, message: JsonObject, version: str) -> _Outcome:
        """Answer a request naming a protocol version the proxy does not know, as a 2026-07-28 server would."""
        method = message["method"]
        reason = f"the request names MCP protocol version '{printable(version, limit=40)}', unknown to this proxy"
        self._firewall.refuse(_label(method), reason, event="client_request", rule=RULE_MALFORMED)
        _warn(f"refused a '{method}' request: {reason}")
        if "id" not in message:
            return _DROP
        return _Outcome(to_client=protocol.unsupported_version_error(message["id"], version))

    def _refuse_malformed_request(self, message: JsonObject, problem: str) -> _Outcome:
        """Refuse a client request whose shape the proxy cannot check, with "invalid params", as a server would."""
        method = message["method"]
        decision = self._firewall.refuse(
            _label(method), f"malformed {method} request: {problem}", event="client_request",
            public_reason=_MALFORMED_REQUEST, rule=RULE_MALFORMED,
        )
        _warn(f"refused a malformed '{method}' request: {problem}")
        if "id" not in message:
            return _DROP
        return _Outcome(to_client=_rpc_error(message["id"], decision.public_reason, code=protocol.INVALID_PARAMS))

    def _refuse_task_request(self, message: JsonObject) -> _Outcome:
        """Refuse a tasks/* request: a task's result could not be tied back to its tool, so tasks are not supported."""
        method = message["method"]
        reason = "tasks are not supported by the proxy"
        decision = self._firewall.refuse(
            _label(method), reason, event="client_request", public_reason=_UNSUPPORTED_REQUEST, rule=RULE_MALFORMED,
        )
        _warn(f"refused a '{method}' request: {reason}")
        if "id" not in message:
            return _DROP
        return _Outcome(to_client=_rpc_error(message["id"], decision.public_reason, code=protocol.METHOD_NOT_FOUND))

    def _refused(self, message: JsonObject, decision: Decision) -> _Outcome:
        """Answer a refused client request with the decision's public reason (a notification gets no answer)."""
        if "id" not in message:
            return _DROP
        reply = _refusal_reply(message["method"], message["id"], decision.public_reason, _is_modern_request(message))
        return _Outcome(to_client=reply)

    # ---- client -> server: requests the policy decides ---------------------------

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
        elif "task" in params:
            # A 2025-11-25 task-augmented call: its result would arrive through tasks/*, which is refused.
            decision = self._refusal(_label(name), "task-augmented tool calls are not supported by the proxy")
        elif not self._wait_for_tool_lists():
            decision = self._refusal(_label(name), "timed out waiting for the tool list to be checked", RULE_QUARANTINE)
        elif self._is_quarantined(name):
            reason = "this tool was removed from the tool list and cannot be called"
            decision = self._refusal(_label(name), reason, RULE_QUARANTINE)
        else:
            decision = self._firewall.check_call(name, arguments or {})
        marks = self._firewall.marks_for(name) if decision.allowed else frozenset()
        return self._forward_or_refuse(message, decision, label=_label(str(name)), marks=marks)

    def _check_resource_request(self, message: JsonObject) -> _Outcome:
        """resources/read and resources/subscribe both ask the server to open a URI."""
        params = message.get("params")
        uri = params.get("uri") if isinstance(params, dict) else None
        if not isinstance(uri, str) or not uri:
            decision = self._refusal(RESOURCE_READ, f"malformed {message['method']} request: missing uri")
        else:
            decision = self._firewall.check_call(RESOURCE_READ, {"uri": uri})
        # Only a read returns content; a subscription's updates arrive as reads of their own.
        reads = decision.allowed and message["method"] == RESOURCE_READ
        marks = self._firewall.marks_for(RESOURCE_READ) if reads else frozenset()
        return self._forward_or_refuse(message, decision, label=_label(str(uri)), marks=marks)

    def _check_subscriptions(self, message: JsonObject) -> _Outcome:
        """subscriptions/listen (2026-07-28) replaces resources/subscribe, so it needs the same permission.

        Each resource URI it subscribes to is checked as a read of that URI,
        and one refusal refuses the whole request. The list-changed filters
        ask only for notifications, which are scanned when they come.
        """
        try:
            uris = protocol.subscribed_uris(message.get("params"))
        except ShapeError as exc:
            return self._refuse_malformed_request(message, str(exc))
        for uri in uris:
            decision = self._firewall.check_call(RESOURCE_READ, {"uri": uri})
            if not decision.allowed:
                return self._refused(message, decision)
        return self._forward_request(message, label=protocol.SUBSCRIPTIONS_LISTEN)

    def _forward_or_refuse(
        self, message: JsonObject, decision: Decision, label: str, marks: frozenset[str] = frozenset(),
    ) -> _Outcome:
        if decision.allowed:
            return self._forward_request(message, label, marks=marks, call_id=decision.call_id)
        return self._refused(message, decision)

    def _forward_request(
        self, message: JsonObject, label: str, marks: frozenset[str] = frozenset(), call_id: str | None = None,
    ) -> _Outcome:
        """Forward a client message, remembering a request so its reply can be matched and scanned."""
        if "id" not in message:
            return _Outcome(to_server=message)  # a notification: no reply will come
        modern = _is_modern_request(message)
        with self._state:
            # If the client reuses an id that is still in flight, the newer
            # request wins. The reply is scanned either way; honest clients do not reuse ids.
            is_new = message["id"] not in self._pending
            if is_new and len(self._pending) >= MAX_PENDING_REQUESTS:
                reason = "too many requests are waiting for a reply"
                return _Outcome(to_client=_refusal_reply(message["method"], message["id"], reason, modern))
            self._pending[message["id"]] = _PendingRequest(message["method"], label, marks, call_id, modern)
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

    def _was_quarantined(self, tool: str) -> bool:
        """Whether this tool itself was quarantined (for filtering a list; calls use _is_quarantined)."""
        with self._state:
            return self._quarantine_overflowed or tool in self._quarantined_tools

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
        the server wants the client's model to answer). A request the protocol
        does not allow here is refused; the policy may refuse a method
        outright; everything that is let through is scanned.
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
        problem = self._server_request_problem(method) if is_request else None
        if problem is not None:
            # Not a policy decision, so monitor mode does not lift it.
            self._firewall.refuse(label, problem, event="server_request", rule=RULE_MALFORMED)
            _warn(f"refused a '{method}' request from the server: {problem}")
            return _Outcome(to_server=_rpc_error(msg_id, _SERVER_REFUSAL, code=protocol.METHOD_NOT_FOUND))

        verdict = self._firewall.policy.server_request_verdict(method)
        if verdict.action == "block":
            rule = verdict.rule or RULE_MALFORMED
            decision = self._firewall.block(label, verdict.reason, "server_request", rule=rule)
        else:
            decision = self._firewall.scan_result(label, message, event="server_request", log_clean=False)
        if decision.allowed:
            if is_request:
                self._expect_client_reply(msg_id, method)
            elif method == "notifications/cancelled":
                self._forget_cancelled_server_request(message)
            return _Outcome(to_client=message)
        _warn(f"refused a '{method}' message from the server: {decision.reason}")
        if is_request:
            # Answer so the server is not left waiting, without saying which check it failed.
            return _Outcome(to_server=_rpc_error(msg_id, _SERVER_REFUSAL))
        return _DROP

    def _server_request_problem(self, method: str) -> str | None:
        """Why the protocol does not let the server send this request, or None (then the policy decides)."""
        with self._state:
            modern = self._era == _MODERN
        if modern:
            # A 2026-07-28 server asks for input inside its replies (see _checked_input_required).
            return "protocol violation: a server speaking MCP 2026-07-28 must not send requests on stdio"
        if method.startswith(protocol.TASKS_METHOD_PREFIX):
            return "tasks are not supported by the proxy"
        return None

    def _expect_client_reply(self, msg_id: str | int, method: str) -> None:
        with self._state:
            self._server_requests.pop(msg_id, None)
            self._server_requests[msg_id] = method  # the answer is logged under the request's method
            if len(self._server_requests) > MAX_SERVER_REQUESTS:
                # Forget the oldest one: its answer, if it ever comes, is dropped.
                # Refusing new requests instead would let abandoned ones block the server for good.
                del self._server_requests[next(iter(self._server_requests))]

    def _forget_cancelled_server_request(self, message: JsonObject) -> None:
        params = message.get("params")
        request_id = params.get("requestId") if isinstance(params, dict) else None
        if _valid_id(request_id):
            with self._state:
                self._server_requests.pop(request_id, None)

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
        is taken from it, so text in any other member cannot ride along. A
        result must be of a kind the proxy knows (its resultType): a complete
        result, or, for the requests that allow one, an input_required result.
        """
        msg_id = message["id"]
        if ("result" in message) == ("error" in message):
            return self._malformed_reply(pending, msg_id, "a reply must have exactly one of result and error")
        if "error" in message:
            return self._deliver_or_block(pending, msg_id, "error", message["error"], scan=message["error"])

        result = message["result"]
        try:
            kind = protocol.result_type(result)
        except ShapeError as exc:
            return self._malformed_reply(pending, msg_id, str(exc))
        if kind == protocol.RESULT_INPUT_REQUIRED:
            return self._checked_input_required(pending, msg_id, result)
        if kind == protocol.RESULT_TASK or (pending.method == "tools/call" and protocol.is_legacy_task(result)):
            return self._unsupported_reply(pending, msg_id, "the result is a task, and tasks are not supported")
        if kind != protocol.RESULT_COMPLETE:
            return self._unsupported_reply(pending, msg_id, f"unknown resultType '{printable(kind, limit=40)}'")
        if isinstance(result, dict) and "inputRequests" in result:
            # A client should ignore them here, but one that acted on them would bypass server_requests.
            return self._malformed_reply(pending, msg_id, "only an input_required result can carry inputRequests")

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
                # The entries were checked one by one. What is left is scanned as a
                # whole below, because a phrase can be split over two entries.
        elif pending.method in (protocol.INITIALIZE, protocol.SERVER_DISCOVER):
            refusal = self._check_handshake_reply(pending, msg_id, result)
            if refusal is not None:
                return refusal
        return self._deliver_or_block(pending, msg_id, "result", result, scan=result, log_clean=items_key is None)

    def _checked_input_required(self, pending: _PendingRequest, msg_id: Any, result: Any) -> JsonObject:
        """Check an input_required result: a 2026-07-28 server asking the client for input inside its reply.

        Each thing it asks for is what a legacy server would have sent as a
        request of its own, so each must pass `server_requests` and is scanned
        on its own, under the same label ("server:<method>"). One refused
        entry refuses the whole reply: delivering part of it would change what
        the server asked. The rebuilt result is then scanned whole, like any result.
        """
        if pending.method not in protocol.INPUT_METHODS:
            return self._malformed_reply(pending, msg_id, f"an input_required result cannot answer {pending.method}")
        if not pending.modern:
            reason = "an input_required result answers a request that names no 2026-07-28 protocol version"
            return self._malformed_reply(pending, msg_id, reason)
        try:
            entries = protocol.input_requests(result)
        except ShapeError as exc:
            return self._malformed_reply(pending, msg_id, str(exc))
        for entry in entries.values():
            decision = self._check_input_request(entry, pending)
            if not decision.allowed:
                return _refusal_reply(pending.method, msg_id, decision.public_reason, pending.modern)
        return self._deliver_or_block(pending, msg_id, "result", result, scan=result)

    def _check_input_request(self, entry: JsonObject, pending: _PendingRequest) -> Decision:
        """The policy's answer for one entry of an input_required result, then the scan of it."""
        method = entry["method"]
        label = _label(f"server:{method}")
        verdict = self._firewall.policy.server_request_verdict(method)
        if verdict.action == "block":
            decision = self._firewall.block(
                label, verdict.reason, event="server_request", public_reason=_INPUT_REFUSAL,
                rule=verdict.rule or RULE_MALFORMED, call_id=pending.call_id,
            )
        else:
            decision = self._firewall.scan_result(
                label, entry, event="server_request", log_clean=False, call_id=pending.call_id
            )
        if not decision.allowed:
            _warn(f"refused a reply to {pending.method} that asks the client for '{method}': {decision.reason}")
        return decision

    def _check_handshake_reply(self, pending: _PendingRequest, msg_id: Any, result: Any) -> JsonObject | None:
        """Check what a server says about itself in reply to initialize or server/discover; a refusal, or None.

        * The protocol version must be one the proxy knows: initialize's
          `protocolVersion` a legacy version; server/discover's
          `supportedVersions` is cut down to the versions the proxy knows, and
          must keep at least one.
        * Tasks are removed from the server's capabilities, so that the client
          does not start one.
        * Instructions that look like an injection are removed.
        A server/discover result also makes the session a 2026-07-28 one,
        unless the client has chosen initialize.
        """
        problem = None
        try:
            if not isinstance(result, dict):
                raise ShapeError(f"the result of {pending.method} must be an object")
            if pending.method == protocol.INITIALIZE:
                version = result.get("protocolVersion")
                if not isinstance(version, str):
                    raise ShapeError("an initialize result must name its protocolVersion")
                if version not in protocol.LEGACY_VERSIONS:
                    shown = printable(version, limit=40)
                    problem = f"the server chose MCP protocol version '{shown}', which this proxy does not know"
            else:
                versions = protocol.known_versions(result.get("supportedVersions"))
                if not versions:
                    problem = "the server supports no MCP protocol version this proxy knows"
                result["supportedVersions"] = versions
            if "capabilities" in result:
                result["capabilities"] = protocol.minimised_capabilities(result["capabilities"])
        except ShapeError as exc:
            return self._malformed_reply(pending, msg_id, str(exc))
        if problem is not None:
            return self._unsupported_reply(pending, msg_id, problem, _UNSUPPORTED_VERSION, code=protocol.INVALID_PARAMS)
        self._strip_poisoned_instructions(result, source=pending.method)
        if pending.method == protocol.SERVER_DISCOVER:
            with self._state:
                if self._era is None:
                    self._era = _MODERN
        return None

    def _malformed_reply(self, pending: _PendingRequest, msg_id: Any, reason: str) -> JsonObject:
        decision = self._firewall.refuse(
            pending.label, f"malformed reply: {reason}", event="result",
            public_reason=_MALFORMED_REPLY, rule=RULE_MALFORMED, call_id=pending.call_id,
        )
        _warn(f"blocked a malformed reply to {pending.method}: {reason}")
        return _rpc_error(msg_id, decision.public_reason)

    def _unsupported_reply(
        self, pending: _PendingRequest, msg_id: Any, reason: str, public_reason: str = _UNSUPPORTED_REPLY,
        code: int = -32000,
    ) -> JsonObject:
        """Refuse a reply the proxy was not built to check: a kind of result or a protocol version it does not know."""
        decision = self._firewall.refuse(
            pending.label, f"unsupported reply: {reason}", event="result",
            public_reason=public_reason, rule=RULE_MALFORMED, call_id=pending.call_id,
        )
        _warn(f"blocked a reply to {pending.method}: {reason}")
        return _rpc_error(msg_id, decision.public_reason, code=code)

    def _deliver_or_block(
        self, pending: _PendingRequest, msg_id: Any, member: str, value: Any, scan: Any, log_clean: bool = True
    ) -> JsonObject:
        decision = self._firewall.scan_result(pending.label, scan, log_clean=log_clean, call_id=pending.call_id)
        if decision.allowed:
            decision = self._mark_delivered(pending)
        if decision.allowed:
            return {"jsonrpc": "2.0", "id": msg_id, member: value}
        return _refusal_reply(pending.method, msg_id, decision.public_reason, pending.modern)

    def _mark_delivered(self, pending: _PendingRequest) -> Decision:
        """Set the flow marks of a reply that is about to be delivered; a refusal if they cannot be recorded.

        An error reply sets them too: its text reaches the agent like a result.
        """
        try:
            self._firewall.mark_delivered(pending.label, pending.marks)
        except SessionStateError as exc:
            _warn(f"withheld a reply to {pending.method}: {exc}")
            return self._firewall.withhold(pending.label, exc, call_id=pending.call_id)
        return Decision(True, "delivered", call_id=pending.call_id)

    def _strip_poisoned_instructions(self, result: JsonObject, source: str) -> None:
        """Remove the server's `instructions` (from initialize or server/discover) if they look like an injection.

        Clients commonly place these instructions in the model's system
        prompt, which makes them the most direct injection route a server has.
        Removing the field keeps the connection usable.
        """
        instructions = result.get("instructions")
        if not isinstance(instructions, str):
            return
        decision = self._firewall.scan_result(source, instructions, event="server_instructions")
        if not decision.allowed:
            del result["instructions"]
            _warn(f"removed the server's instructions: {decision.reason}")

    def _clean_items(self, items: list[Any], items_key: str) -> list[Any]:
        """Return the list entries (tools, prompts, resources) that are safe to show."""
        kept = []
        for item in items:
            name = item.get("name") if isinstance(item, dict) else None
            label = _label(name) if _is_name(name) else "?"
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
        if is_tool and self._was_quarantined(item["name"]):
            return "it was quarantined earlier"  # even if it looks clean now

        event = "tool_description" if is_tool else "list_item"
        decision = self._firewall.scan_result(label, item, event=event, log_clean=False)
        if decision.allowed and is_tool:
            decision = self._check_pin(item, label)
        if decision.allowed:
            if is_tool:
                # Annotations are pinned with the rest of the tool, and they can only add flow labels.
                self._firewall.learn_annotations(item["name"], item.get("annotations"))
            return None
        if is_tool:
            # Remember the name: the agent may already know it from an
            # earlier list, and the server may list it again looking clean.
            self._quarantine(item["name"])
        return decision.reason

    def _check_pin(self, tool: JsonObject, label: str) -> Decision:
        status = self._pins.check(tool["name"], tool)
        if status == "changed":
            reason = (
                "its definition changed after it was first seen. If the change is expected, restart the proxy; "
                "with --pins, first delete this tool's entry from the pins file"
            )
            reason = f"tool quarantined: {reason}"
            return self._firewall.block(label, reason, event="tool_changed", rule=RULE_QUARANTINE)
        if status == "full":
            return Decision(False, "too many tools to keep track of", rule=RULE_QUARANTINE)
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
    here = os.getcwd()
    # A relative PATH entry ("node_modules\\.bin") points into the current
    # folder too, and the same folder can be spelled in more than one way.
    folders = [
        folder for folder in os.environ.get("PATH", "").split(os.pathsep)
        if os.path.isabs(folder) and not _same_folder(folder, here)
    ]
    endings = [""]
    if sys.platform == "win32":
        endings = [e for e in os.environ.get("PATHEXT", "").split(os.pathsep) if e] or _DEFAULT_PATHEXT
        if any(name.lower().endswith(e.lower()) for e in endings):
            endings = [""]
    for folder in folders:
        for ending in endings:
            candidate = os.path.join(folder, name + ending)
            if os.path.isfile(candidate) and (sys.platform == "win32" or os.access(candidate, os.X_OK)):
                return candidate
    return None


_DEFAULT_PATHEXT = [".COM", ".EXE", ".BAT", ".CMD"]
# Characters that cmd.exe gives a meaning of its own, even inside an argument.
_CMD_SPECIAL = set('&|<>^%!"\n\r')


def _same_folder(one: str, other: str) -> bool:
    try:
        return os.path.samefile(one, other)  # sees through short names, links and letter case
    except OSError:  # one of them does not exist
        return os.path.normcase(os.path.abspath(one)) == os.path.normcase(os.path.abspath(other))


def _unsafe_for_batch_file(executable: str, arguments: list[str]) -> list[str]:
    """The arguments that a .cmd or .bat launcher would not receive as written.

    Windows runs such a file through cmd.exe, which reads "&", "%NAME%" and
    "^" in an argument as its own syntax: a URL "…?a=1&b=2" would be cut at
    the "&" and "b=2" run as a command. Better to refuse than to start the
    server with something other than what the operator wrote.
    """
    if sys.platform != "win32" or not executable.lower().endswith((".bat", ".cmd")):
        return []
    return [argument for argument in arguments if _CMD_SPECIAL & set(argument)]


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
            _warn(f"server stderr: {text}", limit=len(text) + 20)  # the whole line: reads are already bounded


def _stop(server: subprocess.Popen, deadline: float) -> int:
    """Make sure the server process is gone and return its exit code.

    The server has until `deadline` to exit by itself: one that has closed its
    output may still be writing its state to disk.
    """
    try:
        return server.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        pass
    if server.poll() is None:
        if sys.platform == "win32":
            # terminate() would leave grandchildren running (e.g. the node
            # process behind an npx.cmd launcher); /T ends the whole tree.
            taskkill = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "taskkill.exe")
            subprocess.run([taskkill, "/PID", str(server.pid), "/T", "/F"], capture_output=True, check=False)
        else:
            server.terminate()
    try:
        return server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        return server.wait()


def exit_process(code: int) -> None:
    """End the process now, with this exit code.

    A normal exit would wait on the thread that is still blocked reading our
    standard input (the client has not closed it), and Python aborts with a
    "Fatal Python error" and a meaningless exit code when it cannot.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (OSError, ValueError):
            pass
    os._exit(code)


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
    parser.add_argument("--no-pins", action="store_true",
                        help="do not quarantine a tool whose definition changes (for servers that change them often)")
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
        message = file_error_message(args.policy, exc) if isinstance(exc, OSError) else str(exc)
        # One line at a time: a JSON error shows the line of the file with a caret under it.
        for number, line in enumerate(message.splitlines()):
            _warn(f"cannot load policy: {line}" if number == 0 else line, limit=500)
        return 2
    try:
        pins = ToolPins(args.pins, enabled=not args.no_pins)
    except (OSError, ValueError) as exc:  # unreadable, not JSON, or not a pins file
        _warn(f"cannot load tool pins: {exc}")
        return 2

    executable = _resolve_executable(command[0])
    if executable is None:
        _warn(f"cannot find the server command '{command[0]}' on PATH. The current folder is not searched; "
              f"to run a file from it, write the path, for example .{os.sep}{command[0]}")
        return 2
    unsafe = _unsafe_for_batch_file(executable, command[1:])
    if unsafe:
        _warn(f"cannot pass {unsafe[0]!r} to the batch file {executable}: cmd.exe would change it. "
              "Start the program behind the batch file directly, for example with node or python")
        return 2
    # Keeps cmd.exe, and whatever the server starts, from running a file in the
    # current folder in place of a command of the same name on PATH.
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

    # Asked to stop (SIGTERM, or Ctrl+Break on Windows): shut down as if a side had closed,
    # so that the server is stopped too instead of being left running.
    for signal_name in ("SIGTERM", "SIGBREAK"):
        if hasattr(signal, signal_name):
            try:
                signal.signal(getattr(signal, signal_name), lambda *_: one_side_closed.set())
            except (ValueError, OSError):  # not the main thread, or not supported here
                pass

    client_relay = threading.Thread(target=relay, args=(proxy.pump_client_to_server, sys.stdin.buffer), daemon=True)
    server_relay = threading.Thread(target=relay, args=(proxy.pump_server_to_client, server.stdout), daemon=True)
    # The stderr relay is never joined: a grandchild of the server can hold that pipe open.
    threading.Thread(target=_relay_stderr, args=(server.stderr,), daemon=True).start()
    client_relay.start()
    server_relay.start()
    while not one_side_closed.wait(0.25):  # in short waits, so that a signal handler gets to run
        pass

    deadline = time.monotonic() + SHUTDOWN_GRACE_SECONDS
    try:
        server.stdin.close()  # tell the server there is no more input
    except OSError:
        pass
    server_relay.join(timeout=SHUTDOWN_GRACE_SECONDS)  # let it finish answering
    return _stop(server, deadline)


if __name__ == "__main__":
    exit_process(main())
