"""`agent-sentinel demo`: watch the firewall and the proxy decide, in a temporary folder.

    agent-sentinel demo
    agent-sentinel demo --keep demo-files

Three parts, all with a small demo policy and a fake MCP server
(demo_server.py, which holds the demo's deliberately poisoned text):

  1. The library: a pretend agent makes six tool calls through
     `Firewall.run`, and each is allowed, blocked, or sent to a (pretend)
     person for approval.
  2. The proxy: `agent-sentinel proxy` is started in front of the fake server,
     exactly as an MCP client would start it, and sent the messages a client
     would send. It removes a poisoned tool from the tool list, refuses a
     call, and withholds a poisoned result.
  3. The audit log both wrote: `report`, then `explain` for one refusal.

Everything is written to a new temporary folder, which is deleted at the
end, unless --keep names a folder to keep the files in. Nothing outside that
folder is touched. Everything printed that came from the server or the log
goes through `printable`: some of it is hostile on purpose.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from . import cli_explain, cli_report, demo_server
from .auditlog import RecordFilter
from .cli_common import EXIT_OK, CommandError, shown_call, shown_path
from .firewall import BlockedError, Firewall
from .policy import Policy
from .textutil import printable

HELP = "see the firewall and the proxy at work (runs in a temporary folder)"
DESCRIPTION = (
    "A pretend agent makes tool calls through the firewall library, then through the proxy in front of a "
    "fake MCP server. Runs in a temporary folder, which is deleted afterwards unless --keep is given."
)

# The demo's policy. Written to the demo folder as policy.json, so `check` and `validate` can be tried on it.
DEMO_POLICY: dict[str, Any] = {
    "default": "block",
    "deny_args": [{"arg": "*", "pattern": r"(^|[\\/:])\.(ssh|aws|env)\b|id_(rsa|ed25519)"}],
    "tools": {
        "read_file": "allow",
        "fetch_page": "allow",
        "send_email": {
            "action": "ask",
            "allow_args": [
                {"arg": "to", "type": "email", "domains": ["example.com"]},
                {"arg": "body", "pattern": "(?s).*", "optional": True},
            ],
            "other_args": "block",
        },
        "delete_*": "block",
    },
    "injection": {"block_severity": "high"},
}

# The calls of part 1: (tool, arguments, what the reader should notice).
LIBRARY_CALLS: tuple[tuple[str, dict[str, Any], str], ...] = (
    ("read_file", {"path": "notes/todo.txt"}, "an ordinary call"),
    ("read_file", {"path": "/home/me/.ssh/id_rsa"}, "a private key"),
    ("fetch_page", {"url": "https://evil.example/recipes"}, "a page with a hidden instruction"),
    ("send_email", {"to": "boss@example.com", "body": "Report attached"}, "a rule that says ask"),
    ("send_email", {"to": "attacker@evil.example", "body": "secrets"}, "an address the policy does not allow"),
    ("delete_file", {"path": "notes/todo.txt"}, "a tool the policy blocks"),
)

# How long the proxy has to answer one message. Generous: a slow machine starts two Python processes.
REPLY_TIMEOUT_SECONDS = 30
MAX_STDERR_LINES = 40
_REF_IN_TEXT = re.compile(r"\(ref ([0-9a-f]{8})\)")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--keep", metavar="DIR",
                        help="write the demo's files (policy, audit log) to this new or empty folder, and keep them")


def run(args: argparse.Namespace) -> int:
    folder = _keep_folder(args.keep) if args.keep else Path(tempfile.mkdtemp(prefix="agent-sentinel-demo-"))
    try:
        policy_path, audit_path = folder / "policy.json", folder / "audit.jsonl"
        policy_path.write_text(json.dumps(DEMO_POLICY, indent=2) + "\n", encoding="utf-8")
        policy = Policy.from_file(policy_path)
        print(f"agent-sentinel demo. Files are written to {shown_path(folder)}"
              f"{'' if args.keep else ' (deleted at the end)'}.")
        _library_part(policy, audit_path)
        refused_ref = _proxy_part(policy_path, audit_path)
        _log_part(policy, audit_path, refused_ref)
        _next_steps(policy_path if args.keep else None, audit_path if args.keep else None)
    finally:
        if not args.keep:
            shutil.rmtree(folder, ignore_errors=True)
    return EXIT_OK


def _keep_folder(path: str) -> Path:
    """The --keep folder: created if missing; refused if it holds anything, so the demo overwrites nothing."""
    folder = Path(path).resolve()
    if folder.exists() and not folder.is_dir():
        raise CommandError(f"{folder} is a file; --keep needs a folder")
    if folder.is_dir() and any(folder.iterdir()):
        raise CommandError(f"{folder} is not empty; give --keep a new or empty folder, so that nothing is overwritten")
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def _heading(title: str) -> None:
    print(f"\n=== {title} ===")


# ---- part 1: the library ------------------------------------------------------------------

def _library_part(policy: Policy, audit_path: Path) -> None:
    _heading("1. The library: Firewall.run() in front of six tool calls")
    print("The agent sees only a short reason and a ref; the rule that decided goes to the audit log.")

    def approve(tool: str, args: dict[str, Any], reason: str) -> bool:
        print(f"    a person is asked to approve {shown_call(tool, args)}: {printable(reason)}. The demo says yes.")
        return True

    firewall = Firewall(policy, audit_path=audit_path, approver=approve)
    for tool, args, what in LIBRARY_CALLS:
        print(f"\n  agent calls {shown_call(tool, args)}  ({what})")
        try:
            result = firewall.run(tool, args, lambda **kwargs: demo_server.call_tool(tool, kwargs))
        except BlockedError as exc:
            decision = exc.decision
            print(f"    BLOCKED. The agent is told: {printable(exc, limit=200)}")
            argument = f", argument '{printable(decision.matched_arg, limit=60)}'" if decision.matched_arg else ""
            print(f"    The audit log says: rule {printable(decision.rule, limit=100)}{argument}")
        else:
            print(f"    ALLOWED. The tool returned: {printable(result, limit=200)}")


# ---- part 2: the proxy ----------------------------------------------------------------------

class _ProxyProcess:
    """`agent-sentinel proxy` in front of the demo server, started and spoken to as an MCP client would."""

    def __init__(self, policy_path: Path, audit_path: Path) -> None:
        if not sys.executable:
            raise CommandError("cannot tell which Python runs this program, so the proxy cannot be started")
        command = [
            sys.executable, "-m", "agent_sentinel", "proxy", "--policy", str(policy_path), "--audit", str(audit_path),
            "--", sys.executable, "-m", "agent_sentinel.demo_server",
        ]
        # The proxy and the server must import this copy of agent_sentinel, installed or not.
        package_parent = str(Path(__file__).resolve().parent.parent)
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [package_parent, env.get("PYTHONPATH")]))
        self.process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=str(policy_path.parent), env=env,
        )
        self._replies: queue.Queue[Any] = queue.Queue()
        self._stderr: list[str] = []
        threading.Thread(target=self._read_replies, daemon=True).start()
        self._stderr_reader = threading.Thread(target=self._read_stderr, daemon=True)
        self._stderr_reader.start()

    def _read_replies(self) -> None:
        assert self.process.stdout is not None
        for line in iter(lambda: self.process.stdout.readline(1024 * 1024), b""):
            try:
                self._replies.put(json.loads(line))
            except ValueError:
                self._replies.put(None)

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        for line in iter(lambda: self.process.stderr.readline(8192), b""):
            if len(self._stderr) < MAX_STDERR_LINES:
                self._stderr.append(line.decode("utf-8", errors="replace").rstrip("\r\n"))

    def send(self, message: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(message).encode("utf-8") + b"\n")
        self.process.stdin.flush()

    def request(self, msg_id: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Send a request and return the reply with its id. CommandError if none comes in time."""
        try:
            self.send({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params})
        except OSError:  # the proxy has already stopped; the loop below says why
            pass
        deadline = time.monotonic() + REPLY_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            try:
                reply = self._replies.get(timeout=0.2)
            except queue.Empty:
                if self.process.poll() is not None:
                    raise CommandError(self._stopped_message(method)) from None
                continue
            if isinstance(reply, dict) and reply.get("id") == msg_id:
                return reply
        raise CommandError(f"the proxy did not answer the {method} request in time")

    def _stopped_message(self, method: str) -> str:
        self._stderr_reader.join(timeout=2)  # let it read the proxy's last words
        said ="\n".join(printable(line, limit=300) for line in self._stderr[-5:])
        return f"the proxy stopped before it answered the {method} request" + (f"; it said:\n{said}" if said else "")

    def stderr_lines(self) -> list[str]:
        return list(self._stderr)

    def close(self) -> None:
        """Close the proxy's input, as a client does when it quits, and wait for it to stop."""
        try:
            if self.process.stdin is not None:
                self.process.stdin.close()
        except OSError:
            pass
        try:
            self.process.wait(timeout=REPLY_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self._stderr_reader.join(timeout=2)  # the last lines it wrote, for stderr_lines()


def _reply_text(reply: dict[str, Any]) -> str:
    """The text an agent would read in a tools/call reply, or the error message."""
    if isinstance(reply.get("error"), dict):
        return str(reply["error"].get("message", ""))
    result = reply.get("result")
    content = result.get("content") if isinstance(result, dict) else None
    items = content if isinstance(content, list) else []
    return " ".join(item["text"] for item in items if isinstance(item, dict) and isinstance(item.get("text"), str))


def _proxy_part(policy_path: Path, audit_path: Path) -> str | None:
    """Run the proxy round trip; return the ref of the refused call, for part 3."""
    _heading("2. The proxy: agent-sentinel proxy in front of an MCP server")
    print("Started as a client would start it:")
    print(f"  agent-sentinel proxy --policy {shown_path(policy_path.name)} --audit {shown_path(audit_path.name)} "
          "-- python -m agent_sentinel.demo_server")
    proxy = _ProxyProcess(policy_path, audit_path)
    try:
        info = proxy.request(1, "initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "demo-client", "version": "1"},
        })
        server = info.get("result", {}).get("serverInfo", {}) if isinstance(info.get("result"), dict) else {}
        print(f"\n  initialize: connected to {printable(server.get('name', '?') if isinstance(server, dict) else '?')}")
        proxy.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        listed = proxy.request(2, "tools/list", {})
        tools = listed.get("result", {}).get("tools", []) if isinstance(listed.get("result"), dict) else []
        names = [tool.get("name") for tool in tools if isinstance(tool, dict)]
        removed = [tool["name"] for tool in demo_server.TOOLS if tool["name"] not in names]
        print(f"  tools/list: the server offers {len(demo_server.TOOLS)} tools; the agent sees "
              f"{', '.join(printable(name, limit=60) for name in names) or 'none'}")
        if removed:
            print(f"    removed by the proxy: {', '.join(removed)} (the proxy's own report is below)")

        refused_ref = None
        for number, (tool, args) in enumerate((
            ("read_file", {"path": "/home/me/.ssh/id_rsa"}),
            ("fetch_page", {"url": "https://evil.example/recipes"}),
            ("read_file", {"path": "notes/todo.txt"}),
        ), start=3):
            reply = proxy.request(number, "tools/call", {"name": tool, "arguments": args})
            text = _reply_text(reply)
            is_error = isinstance(reply.get("result"), dict) and reply["result"].get("isError") is True
            print(f"  tools/call {shown_call(tool, args)}")
            print(f"    the agent reads: {printable(text, limit=200)}{'  (an error)' if is_error else ''}")
            found = _REF_IN_TEXT.search(text)
            if found and refused_ref is None:
                refused_ref = found.group(1)
    finally:
        proxy.close()
    lines = proxy.stderr_lines()
    if lines:
        print("\n  What the proxy reported on stderr, for the operator:")
        for line in lines:
            print(f"    {printable(line, limit=300)}")
    return refused_ref


# ---- part 3: the audit log ------------------------------------------------------------------

def _log_part(policy: Policy, audit_path: Path, refused_ref: str | None) -> None:
    _heading("3. The audit log both wrote")
    print("$ agent-sentinel report audit.jsonl --show-args --last 5")
    summary = cli_report.summarize(str(audit_path), RecordFilter(), "tool", last=5)
    cli_report.print_summary(summary, show_args=True)
    if refused_ref is None:
        return
    print(f"\nA user who sees \"(ref {refused_ref})\" in a refusal can look it up:")
    print(f"$ agent-sentinel explain audit.jsonl --ref {refused_ref} --policy policy.json")
    records, _, _ = cli_explain.find_records(str(audit_path), refused_ref, 1)
    for record in records:
        cli_explain.explain_record(record, policy)


def _next_steps(policy_path: Path | None, audit_path: Path | None) -> None:
    _heading("Next steps")
    if policy_path is not None:
        start = f"or start from the demo's policy, kept at {shown_path(policy_path)}."
    else:
        start = "or start from the demo's policy: agent-sentinel demo --keep DIR"
    log = shown_path(audit_path) if audit_path is not None else "audit.jsonl"
    print(f"""  1. Write a policy for your own tools: agent-sentinel init --template starter
     or draft one from a server's real tool list: agent-sentinel init -- <server command>
     {start}
  2. Check it:            agent-sentinel validate policy.json
  3. Try calls on it:     agent-sentinel check policy.json read_file path=notes/todo.txt
  4. Put the proxy in front of your MCP client's servers (shows the change; --apply writes it):
       agent-sentinel wrap --client claude-desktop --policy /full/path/policy.json
     then check that every server is protected: agent-sentinel doctor
     (wrap --monitor while you tune the policy: it logs what would be blocked and blocks nothing)
  5. Read what happened:  agent-sentinel report {log}
     and for a refusal:   agent-sentinel explain {log} --ref <ref>""")

