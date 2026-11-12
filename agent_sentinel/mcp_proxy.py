"""Run an MCP server behind the firewall.

    python -m agent_sentinel proxy --policy policy.json -- <server command...>

The proxy speaks MCP's stdio transport (one JSON-RPC message per line). It sits
between the client (the agent) and the real server:

  * a "tools/call" request is checked against the policy; a blocked call is
    answered by the proxy and never reaches the server;
  * the result of an allowed call is scanned for prompt injection before the
    client sees it; a blocked result is replaced with an error;
  * tool descriptions in "tools/list" are scanned; a tool whose description
    looks poisoned is removed from the list and calls to it are blocked;
  * results of "resources/read" and "prompts/get" are scanned the same way.

The proxy fails closed: anything it cannot parse or does not understand well
enough to check is dropped, never forwarded. Messages are re-serialized, so
the server sees exactly what the proxy checked.

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
from typing import Any, BinaryIO

from .firewall import Firewall, strings_in
from .policy import Policy, PolicyError

LIST_WAIT_SECONDS = 15

_SCANNED_METHODS = ("tools/call", "tools/list", "resources/read", "prompts/get")


def _warn(message: str) -> None:
    print(f"agent-sentinel: {message}", file=sys.stderr, flush=True)


def _valid_id(value: Any) -> bool:
    return isinstance(value, (str, int, float)) and not isinstance(value, bool)


def _blocked_result(msg_id: Any, reason: str) -> dict[str, Any]:
    """A tools/call reply that tells the agent the call was blocked."""
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "content": [{"type": "text", "text": f"Blocked by agent-sentinel: {reason}"}],
            "isError": True,
        },
    }


def _error(msg_id: Any, reason: str, code: int = -32000) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": f"Blocked by agent-sentinel: {reason}"}}


class Proxy:
    def __init__(self, firewall: Firewall, client_in: BinaryIO, client_out: BinaryIO, server: subprocess.Popen) -> None:
        self.firewall = firewall
        self.client_in = client_in
        self.client_out = client_out
        self.server = server
        self._pending: dict[Any, tuple[str, str]] = {}  # request id -> (method, tool or label)
        self._quarantined: set[str] = set()  # tools removed from tools/list
        self._lock = threading.Lock()
        # Tool calls wait while a tools/list reply is being checked, so a call
        # cannot slip through to a tool that is about to be quarantined.
        self._lists_pending = 0
        self._lists_done = threading.Condition(self._lock)

    # ---- client -> server -------------------------------------------------

    def client_to_server(self) -> None:
        assert self.server.stdin is not None
        for line in self.client_in:
            if not line.strip():
                continue
            try:
                forward = self._handle_request_line(line)
            except Exception as exc:  # fail closed: never forward on a bug
                _warn(f"dropped a client message after an internal error: {exc!r}")
                continue
            if forward is None:
                continue
            try:
                self.server.stdin.write(json.dumps(forward).encode("utf-8") + b"\n")
                self.server.stdin.flush()
            except OSError:
                break
        try:
            self.server.stdin.close()
        except OSError:
            pass

    def _handle_request_line(self, line: bytes) -> dict[str, Any] | None:
        """Return the message to forward to the server, or None to drop it."""
        try:
            message = json.loads(line)
        except ValueError:
            _warn("dropped a client message that is not valid JSON")
            return None
        if isinstance(message, list):
            # MCP no longer uses JSON-RPC batches; refusing them keeps every
            # request on the checked path.
            replies = [_error(m["id"], "batched requests are not supported", -32600)
                       for m in message if isinstance(m, dict) and _valid_id(m.get("id"))]
            if replies:
                self._send_client(replies)
            return None
        if not isinstance(message, dict):
            _warn("dropped a client message that is not a JSON object")
            return None
        if "id" in message and not _valid_id(message["id"]):
            _warn("dropped a client message with an invalid id")
            return None

        method = message.get("method")
        if method == "tools/call":
            return self._check_tool_call(message)
        if method in _SCANNED_METHODS and "id" in message:
            params = message.get("params") if isinstance(message.get("params"), dict) else {}
            label = str(params.get("uri") or params.get("name") or method)
            with self._lock:
                self._pending[message["id"]] = (method, label)
                if method == "tools/list":
                    self._lists_pending += 1
        return message

    def _check_tool_call(self, message: dict[str, Any]) -> dict[str, Any] | None:
        params = message.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        arguments = params.get("arguments") if isinstance(params, dict) else None
        with self._lists_done:
            lists_checked = self._lists_done.wait_for(lambda: self._lists_pending == 0, timeout=LIST_WAIT_SECONDS)
        if not lists_checked:
            decision = self.firewall.block(str(name), "timed out waiting for the tool list to be checked")
        elif not isinstance(name, str) or not name:
            decision = self.firewall.block("?", "malformed tools/call request: missing tool name")
        elif arguments is not None and not isinstance(arguments, dict):
            decision = self.firewall.block(name, "malformed tools/call request: arguments must be an object")
        elif name in self._quarantined:
            decision = self.firewall.block(name, "tool was removed because its description looks poisoned")
        else:
            decision = self.firewall.check_call(name, arguments or {})

        if not decision.allowed:
            if "id" in message:
                self._send_client(_blocked_result(message["id"], decision.reason))
            return None
        if "id" in message:
            with self._lock:
                self._pending[message["id"]] = ("tools/call", name)
        return message

    # ---- server -> client -------------------------------------------------

    def server_to_client(self) -> None:
        assert self.server.stdout is not None
        for line in self.server.stdout:
            if not line.strip():
                continue
            try:
                reply = self._handle_response_line(line)
            except Exception as exc:  # fail closed
                _warn(f"dropped a server message after an internal error: {exc!r}")
                continue
            if reply is not None:
                self._send_client(reply)

    def _handle_response_line(self, line: bytes) -> dict[str, Any] | None:
        try:
            message = json.loads(line)
        except ValueError:
            _warn("dropped a server message that is not valid JSON")
            return None
        if not isinstance(message, dict):
            _warn("dropped a server message that is not a JSON object")
            return None
        if "method" in message or "id" not in message or not _valid_id(message["id"]):
            return message  # a request or notification from the server: not scanned

        with self._lock:
            method, label = self._pending.pop(message["id"], (None, ""))
        if method is None:
            return message
        try:
            return self._scan_response(message, method, label)
        finally:
            if method == "tools/list":
                with self._lists_done:
                    self._lists_pending -= 1
                    self._lists_done.notify_all()

    def _scan_response(self, message: dict[str, Any], method: str, label: str) -> dict[str, Any]:
        if "result" not in message:
            # An error reply can carry attacker-controlled text too.
            decision = self.firewall.scan_result(label, "\n".join(strings_in(message.get("error"))))
            return message if decision.allowed else _error(message["id"], decision.reason)
        if method == "tools/list":
            return self._filter_tool_list(message)

        decision = self.firewall.scan_result(label, "\n".join(strings_in(message["result"])))
        if decision.allowed:
            return message
        if method == "tools/call":
            return _blocked_result(message["id"], decision.reason)
        return _error(message["id"], decision.reason)

    def _filter_tool_list(self, message: dict[str, Any]) -> dict[str, Any]:
        result = message["result"]
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            return message
        kept = []
        for tool in tools:
            name = str(tool.get("name", "?")) if isinstance(tool, dict) else "?"
            decision = self.firewall.scan_result(name, "\n".join(strings_in(tool)), event="tool_description")
            if decision.allowed:
                kept.append(tool)
            else:
                with self._lock:
                    self._quarantined.add(name)
                _warn(f"removed tool '{name}' from the tool list: {decision.reason}")
        result["tools"] = kept
        return message

    def _send_client(self, message: Any) -> None:
        data = json.dumps(message).encode("utf-8") + b"\n"
        with self._lock:
            self.client_out.write(data)
            self.client_out.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-sentinel proxy", description="Run an MCP server behind the firewall.")
    parser.add_argument("--policy", required=True, help="path to the policy JSON file")
    parser.add_argument("--audit", default=None, help="path of the audit log (JSON lines)")
    parser.add_argument("--no-log-args", action="store_true", help="leave tool arguments out of the audit log")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- followed by the MCP server command")
    args = parser.parse_args(argv)

    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("give the MCP server command after '--'")
    try:
        policy = Policy.from_file(args.policy)
    except (OSError, PolicyError) as exc:
        _warn(f"cannot load policy: {exc}")
        return 2

    executable = shutil.which(command[0]) or command[0]  # resolves .cmd shims on Windows
    try:
        server = subprocess.Popen([executable, *command[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    except OSError as exc:
        _warn(f"cannot start server: {exc}")
        return 2

    firewall = Firewall(policy, audit_path=args.audit, log_args=not args.no_log_args)
    proxy = Proxy(firewall, sys.stdin.buffer, sys.stdout.buffer, server)
    threading.Thread(target=proxy.client_to_server, daemon=True).start()
    proxy.server_to_client()  # returns when the server closes its output
    return server.wait()


if __name__ == "__main__":
    sys.exit(main())
