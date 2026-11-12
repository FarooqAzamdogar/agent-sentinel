"""Run an MCP server behind the firewall.

    agent-sentinel proxy --policy policy.json -- <server command...>

The proxy speaks MCP's stdio transport: one JSON-RPC message per line. It sits
between the client (the agent's host application) and the real server.

    client  --->  [ inspect client message ]  --->  server
    client  <---  [ inspect server message ]  <---  server

Trust model
-----------
* The server is untrusted. Any text it sends may reach the model, so every
  message from it is scanned, whatever its type.
* The agent is not fully trusted either: it may have been hijacked by text it
  read earlier. So the actions it requests ("tools/call", "resources/read")
  must pass the policy.

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
import json
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass
from typing import Any, BinaryIO, Callable

from .firewall import Decision, Firewall
from .policy import Policy, PolicyError
from .textutil import printable, texts_in

# How long a tool call waits for an in-flight tools/list reply to be checked.
TOOL_LIST_WAIT_SECONDS = 15
# How long the server gets to finish after the client disconnects.
SHUTDOWN_GRACE_SECONDS = 5

# Resource reads are checked by the policy under this name, with one
# argument, "uri". A policy rule for it looks like a rule for a tool.
RESOURCE_READ = "resources/read"

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


def _parse(line: bytes) -> Any:
    """Parse one line of strict JSON (Python would otherwise accept NaN and Infinity)."""
    return json.loads(line, parse_constant=_reject_constant)


def _valid_id(value: Any) -> bool:
    """MCP request ids are strings or integers (bool is an int in Python, so exclude it)."""
    return isinstance(value, (str, int)) and not isinstance(value, bool)


def _text_of(value: Any) -> str:
    return "\n".join(texts_in(value))


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


# ---- the proxy --------------------------------------------------------------

class Proxy:
    def __init__(self, firewall: Firewall, client_out: BinaryIO, server_in: BinaryIO) -> None:
        self._firewall = firewall
        self._client_out = client_out
        self._server_in = server_in
        self._client_write_lock = threading.Lock()
        self._server_write_lock = threading.Lock()

        # `_state` guards the three collections below. It is a Condition so
        # that tool calls can wait for tool lists to finish being checked.
        self._state = threading.Condition()
        self._pending: dict[str | int, _PendingRequest] = {}
        self._quarantined_tools: set[str] = set()
        self._tool_lists_in_flight: set[str | int] = set()

    # ---- entry points -------------------------------------------------------

    def pump_client_to_server(self, client_in: BinaryIO) -> None:
        """Relay client messages until the client or the server goes away."""
        self._pump(client_in, self.handle_client_line)

    def pump_server_to_client(self, server_out: BinaryIO) -> None:
        """Relay server messages until the server or the client goes away."""
        self._pump(server_out, self.handle_server_line)

    @staticmethod
    def _pump(stream: BinaryIO, handle_line: Callable[[bytes], None]) -> None:
        for line in stream:
            if not line.strip():
                continue
            try:
                handle_line(line)
            except (OSError, ValueError):  # a pipe was closed under us
                return

    def handle_client_line(self, line: bytes) -> None:
        try:
            message = _parse(line)
        except (ValueError, RecursionError):
            _warn("dropped a client message that is not valid JSON")
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
            _warn("dropped a server message that is not valid JSON")
            return
        try:
            outcome = self._inspect_server_message(message)
        except Exception as exc:
            _warn(f"dropped a server message after an internal error: {exc!r}")
            outcome = _DROP
        self._send(outcome)

    # ---- client -> server ---------------------------------------------------

    def _inspect_client_message(self, message: Any) -> _Outcome:
        if isinstance(message, list):
            return self._refuse_batch(message)
        if not isinstance(message, dict):
            _warn("dropped a client message that is not a JSON object")
            return _DROP
        if "id" in message and not _valid_id(message["id"]):
            _warn("dropped a client message with an invalid id")
            return _DROP

        method = message.get("method")
        if method is None:
            # No method: this is the client's answer to a request the server made.
            if "result" in message or "error" in message:
                return _Outcome(to_server=message)
            _warn("dropped a client message that is neither a request nor a reply")
            return _DROP
        if not isinstance(method, str):
            _warn("dropped a client message with an invalid method")
            return _DROP

        if method == "tools/call":
            return self._check_tool_call(message)
        if method == RESOURCE_READ:
            return self._check_resource_read(message)
        if method == "notifications/cancelled":
            self._forget_cancelled_request(message)
        self._remember(message, label=method)
        return _Outcome(to_server=message)

    def _refuse_batch(self, batch: list[Any]) -> _Outcome:
        # MCP no longer uses JSON-RPC batches. Refusing them keeps every
        # request on the single, checked path above.
        replies = [
            _rpc_error(item["id"], "batched requests are not supported", code=-32600)
            for item in batch
            if isinstance(item, dict) and _valid_id(item.get("id"))
        ]
        return _Outcome(to_client=replies or None)

    def _check_tool_call(self, message: JsonObject) -> _Outcome:
        params = message.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        arguments = params.get("arguments") if isinstance(params, dict) else None

        if not isinstance(name, str) or not name:
            decision = self._firewall.block("?", "malformed tools/call request: missing tool name")
        elif arguments is not None and not isinstance(arguments, dict):
            decision = self._firewall.block(name, "malformed tools/call request: arguments must be an object")
        elif not self._wait_for_tool_lists():
            decision = self._firewall.block(name, "timed out waiting for the tool list to be checked")
        elif self._is_quarantined(name):
            decision = self._firewall.block(name, "tool was removed because its description looks poisoned")
        else:
            decision = self._firewall.check_call(name, arguments or {})
        return self._forward_or_refuse(message, decision, label=str(name), refusal=_tool_error)

    def _check_resource_read(self, message: JsonObject) -> _Outcome:
        params = message.get("params")
        uri = params.get("uri") if isinstance(params, dict) else None
        if not isinstance(uri, str) or not uri:
            decision = self._firewall.block(RESOURCE_READ, "malformed resources/read request: missing uri")
        else:
            decision = self._firewall.check_call(RESOURCE_READ, {"uri": uri})
        return self._forward_or_refuse(message, decision, label=str(uri), refusal=_rpc_error)

    def _forward_or_refuse(
        self, message: JsonObject, decision: Decision, label: str, refusal: Callable[[Any, str], JsonObject]
    ) -> _Outcome:
        if decision.allowed:
            self._remember(message, label)
            return _Outcome(to_server=message)
        if "id" in message:
            return _Outcome(to_client=refusal(message["id"], decision.reason))
        return _DROP

    def _remember(self, message: JsonObject, label: str) -> None:
        """Record a forwarded request so that its reply can be matched and scanned."""
        if "id" not in message:
            return  # a notification: no reply will come
        with self._state:
            # If the client reuses an id that is still in flight, the newer
            # request wins. That is safe because every reply is scanned.
            self._pending[message["id"]] = _PendingRequest(message["method"], label)
            if message["method"] == "tools/list":
                self._tool_lists_in_flight.add(message["id"])

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
        list that would quarantine it has been processed.
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
            return tool in self._quarantined_tools

    def _internal_error_outcome(self, message: Any) -> _Outcome:
        """Tell the client its request failed, so it is not left waiting."""
        if isinstance(message, dict) and isinstance(message.get("method"), str) and _valid_id(message.get("id")):
            return _Outcome(to_client=_rpc_error(message["id"], "internal error while checking the request"))
        return _DROP

    # ---- server -> client ---------------------------------------------------

    def _inspect_server_message(self, message: Any) -> _Outcome:
        if not isinstance(message, dict):
            _warn("dropped a server message that is not a JSON object")
            return _DROP
        if "method" in message:
            return self._check_server_request(message)
        return self._check_server_reply(message)

    def _check_server_request(self, message: JsonObject) -> _Outcome:
        """Scan a request or notification that the server sends to the client.

        These can carry text toward the model (a sampling request is a prompt
        the server wants the client's model to answer), so they are scanned.
        """
        method = message["method"] if isinstance(message["method"], str) else "?"
        decision = self._firewall.scan_result(method, _text_of(message), event="server_request", log_clean=False)
        if decision.allowed:
            return _Outcome(to_client=message)
        _warn(f"dropped a '{method}' message from the server: {decision.reason}")
        if _valid_id(message.get("id")):  # a request: answer it so the server is not left waiting
            return _Outcome(to_server=_rpc_error(message["id"], decision.reason))
        return _DROP

    def _check_server_reply(self, message: JsonObject) -> _Outcome:
        msg_id = message.get("id")
        with self._state:
            pending = self._pending.pop(msg_id, None) if _valid_id(msg_id) else None
        if pending is None:
            # A reply to a request we did not forward could not be attributed
            # to a method, so there is no safe way to deliver it.
            _warn("dropped a server reply that matches no forwarded request")
            return _DROP
        try:
            return _Outcome(to_client=self._scan_reply(message, pending))
        except Exception as exc:
            _warn(f"blocked a server reply after an internal error: {exc!r}")
            return _Outcome(to_client=_rpc_error(msg_id, "internal error while checking the reply"))
        finally:
            # Quarantine decisions were recorded inside _scan_reply, so calls
            # waiting on this tool list may now proceed.
            with self._state:
                self._tool_lists_in_flight.discard(msg_id)
                self._state.notify_all()

    def _scan_reply(self, message: JsonObject, pending: _PendingRequest) -> JsonObject:
        """Return the reply to deliver: the original, a cleaned copy, or an error."""
        if "result" not in message:
            # An error reply can carry attacker-controlled text too.
            return self._deliver_or_block(message, pending, content=message.get("error"))

        result = message["result"]
        content = result
        if isinstance(result, dict):
            if pending.method == "initialize":
                self._strip_poisoned_instructions(result)
            items_key = _LIST_ITEMS_KEY.get(pending.method)
            if items_key:
                self._drop_poisoned_items(result, items_key)
                # The items were just scanned one by one; scan what is left.
                content = {key: value for key, value in result.items() if key != items_key}
        return self._deliver_or_block(message, pending, content, log_clean=pending.method not in _LIST_ITEMS_KEY)

    def _deliver_or_block(
        self, message: JsonObject, pending: _PendingRequest, content: Any, log_clean: bool = True
    ) -> JsonObject:
        decision = self._firewall.scan_result(pending.label, _text_of(content), log_clean=log_clean)
        if decision.allowed:
            return message
        if pending.method == "tools/call":
            return _tool_error(message["id"], decision.reason)
        return _rpc_error(message["id"], decision.reason)

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

    def _drop_poisoned_items(self, result: JsonObject, items_key: str) -> None:
        """Remove list entries (tools, prompts, resources) that look poisoned."""
        items = result.get(items_key)
        if not isinstance(items, list):
            return
        event = "tool_description" if items_key == "tools" else "list_item"
        kept = []
        for item in items:
            name = item.get("name") if isinstance(item, dict) else None
            label = name if isinstance(name, str) else "?"
            decision = self._firewall.scan_result(label, _text_of(item), event=event, log_clean=False)
            if decision.allowed:
                kept.append(item)
                continue
            if items_key == "tools":
                # Remember the name: the agent may already know it from an
                # earlier list, and the server may list it again looking clean.
                with self._state:
                    self._quarantined_tools.add(label)
            _warn(f"removed '{label}' from the {items_key} list: {decision.reason}")
        result[items_key] = kept

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


# ---- command line -----------------------------------------------------------

def _stop(server: subprocess.Popen) -> int:
    """Make sure the server process is gone and return its exit code."""
    if server.poll() is None:
        if sys.platform == "win32":
            # terminate() would leave grandchildren running (e.g. the node
            # process behind an npx.cmd launcher); /T ends the whole tree.
            subprocess.run(["taskkill", "/PID", str(server.pid), "/T", "/F"], capture_output=True, check=False)
        else:
            server.terminate()
    try:
        return server.wait(timeout=SHUTDOWN_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        server.kill()
        return server.wait()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-sentinel proxy", description="Run an MCP server behind the firewall.")
    parser.add_argument("--policy", required=True, help="path to the policy JSON file")
    parser.add_argument("--audit", default=None, help="path of the audit log (JSON lines)")
    parser.add_argument("--no-log-args", action="store_true", help="leave tool arguments out of the audit log")
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

    executable = shutil.which(command[0]) or command[0]  # resolves .cmd launchers on Windows
    try:
        server = subprocess.Popen([executable, *command[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    except OSError as exc:
        _warn(f"cannot start server: {exc}")
        return 2
    assert server.stdin is not None and server.stdout is not None

    firewall = Firewall(policy, audit_path=args.audit, log_args=not args.no_log_args)
    proxy = Proxy(firewall, client_out=sys.stdout.buffer, server_in=server.stdin)

    # Run one relay per direction. When either side closes, shut down.
    one_side_closed = threading.Event()

    def relay(pump: Callable[[BinaryIO], None], stream: BinaryIO) -> None:
        try:
            pump(stream)
        finally:
            one_side_closed.set()

    client_relay = threading.Thread(target=relay, args=(proxy.pump_client_to_server, sys.stdin.buffer), daemon=True)
    server_relay = threading.Thread(target=relay, args=(proxy.pump_server_to_client, server.stdout), daemon=True)
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
