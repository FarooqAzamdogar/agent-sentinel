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

What a reply forwards
---------------------
A reply's result or error passes Firewall.check_result: the scanner, and the
policy's secrets.in_results, which with "redact" forwards a copy with the
secrets replaced. A reply, a list entry and the server's instructions are
forwarded cleaned of what can hide text from the person who reads it:
terminal escape sequences, control characters, Unicode tag characters and
bidi overrides (textutil.clean_value_for_forwarding). The text as the server
sent it is scanned first (hidden tag text is read there), and a copy that
cleaning changed is scanned again; pins are taken of what the server sent.
Requests and notifications from the server are forwarded as they were sent,
once checked: cleaning could change a method or a field the client answers by.

Code layout
-----------
`Proxy.handle_client_line` and `Proxy.handle_server_line` are the two entry
points. Each parses a line, asks an `_inspect_*` method what to do, and sends
the resulting `_Outcome`. The `_inspect_*` methods decide and never write to a
stream, which keeps them easy to test.

Approvals
---------
A call the policy says "ask" for is refused, unless the proxy was given a
way to ask a person (proxy --approve-with: a dialog on this machine, the
operator's own program, or a form the MCP client shows; see approvers.py).
Then the call is held: the firewall has already passed it through the secret
guard, the policy and the rate limits (check_call with defer_ask), and a
worker thread asks, so the client's other messages keep flowing meanwhile.
Only an explicit yes lets it through; no answer before --approval-timeout,
an error or anything else refuses it. Before a held call is sent on, the
proxy checks again that the tool was not quarantined while it waited, and
the firewall checks the flow rules again (finish_approval). One question is
asked at a time, and at most MAX_WAITING_APPROVALS calls wait.

The agent cannot answer for the person: a dialog and a program answer on
this machine, and the client's answer to the proxy's own elicitation is
matched by a random id that is never sent to the server, and never
forwarded to it.

What the operator sees
----------------------
On stderr, which MCP clients keep in their log of the server (see
proxy_report.py): a summary at startup, one line for each block with the
rule that decided and the reference the agent was shown, and, with
--verbose, one line for each call let through. Lines about traffic are
limited (20 in 10 seconds, proxy_report.LineBudget), so a peer cannot flood
the log. --quiet leaves only errors. What the server writes to its stderr is
passed on, labelled "server stderr:", with a limit of its own (60 lines a
minute), with or without --quiet.

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
and the inputResponses of a retried request) passes the same secret guard as
a call's arguments (Firewall.find_secrets: the formats, the policy's own
formats, known values and canaries), and an answer is rebuilt from its
`result` or `error` before it is forwarded.

Lists, pins and names
---------------------
The entries of a tools/list, prompts/list, resources/list or
resources/templates/list reply are checked one by one (_clean_items):

* icons that are not safe for the client to fetch are dropped (the entry
  stays; mcp_protocol.clean_icons), here and in the server's own serverInfo;
* tool and prompt names must follow the MCP naming rules (proxy --tool-names
  strict, warn or off) and must not look like another name of the same
  server ("read_fіle" beside "read_file"); a name listed twice with two
  different definitions is refused; an entry whose name (or URI) has
  characters the proxy does not forward is refused in every mode;
* each entry is scanned (a tool's description also with the tool names the
  policy gives other servers, to catch shadowing), and tools, prompts and
  resource templates are compared with their pins (pins.py), as are the
  server's instructions.

A tool, prompt or template that fails is removed from the list and
quarantined for as long as the proxy runs: it is left out of later lists, a
tool cannot be called, a prompt cannot be fetched, and no URI the template
may produce can be read or subscribed to (uri_template.py). Changed
instructions are removed from the reply. With a pins file, a changed
definition is kept beside it for `agent-sentinel pins diff` and `pins
accept`. Then, if the policy says hide_blocked_tools, the tools it blocks
outright are hidden from the list (never in monitor mode); a call to a
hidden tool is still checked and refused.

A list that comes in pages (nextCursor) is scanned across the boundary of
two pages as well (_checked_page_boundary): the end of the page before is
read with the start of the next.

With --pin-server the server itself is pinned too (pins.py, "The server
itself"): how it is launched, before it starts, and the serverInfo of its
handshake. A server that differs from its pin is not started, or its
handshake is refused (--on-server-change refuse, the default); with
--on-server-change quarantine it runs quarantined (quarantine_server): every
tool, prompt, resource and resource template is left out of its lists; its
instructions are removed and never pinned; tool calls, prompts, resource
reads, subscriptions (subscriptions/listen too), completions and any other
request but the handshake, ping, the lists and logging/setLevel are
refused; every request it sends the client (sampling, elicitation, roots;
not ping) is refused, and every notification it sends but
notifications/cancelled is dropped. Monitor mode logs the change only.

Requests other than tool calls
------------------------------
The policy's client_requests section may refuse any other method the client
sends (Policy.client_request_verdict), with "method not found". Once the
policy opts in (Policy.checks_prompts), prompts/get is checked like a call of
a tool named "prompts/get", with arguments {"name", "arguments"}.
completion/complete passes the secret guard, since it carries what the user
is typing.

Elicitation
-----------
An elicitation is checked for what it asks the user (elicitation.py): a URL
it sends the user to must be a public https address, and on the operator's
list if there is one (--elicitation-host); a form may not ask for a password,
key or card number. This applies to elicitation/create requests, to the
entries of input_required results and to URLElicitationRequiredError replies.

Flow rules
----------
One proxy process is one session, unless it is given --session-group: then
the proxies of one run of the MCP client that name the same group share one
session, kept in a file (session.GroupSessionStore; the run is found by
client_run.py), and what one server delivered counts for the calls of the
others. When a tools/call or resources/read result is delivered, the session
gains the marks of that tool (Firewall.marks_for, worked out when the call
was let through), so a later call can be refused by a flow rule. Marks are
set just before the reply is sent, and only for a reply that is sent; a
reply that is blocked sets none.

The labels implied by each listed tool's MCP annotations are passed to the
firewall as well, and at startup those of the pinned tools. While the policy
has flow rules and classify_by_annotations is on, a tool that neither a
checked tools/list nor a pin has shown counts as untrusted and a sink.

A sampling request from the server (sampling/createMessage, or an
input_required entry asking for one) is refused when it asks for
includeContext other than "none", and, once the session holds every mark of
a "block" flow whose "then" is "sink", as a call to a sink would be.

Call timeout
------------
With limits.call_timeout_seconds, a tools/call, resources/read or
prompts/get the server does not answer in time is answered with a JSON-RPC
error (the neutral reason and a ref), cancelled at the server with
notifications/cancelled, and recorded with event "timeout". The server's
late reply is dropped, and the request's id stays in use until it comes.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import heapq
import itertools
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from secrets import token_hex
from typing import Any, BinaryIO, Callable, Iterable, Mapping, Sequence

from . import __version__, client_run, elicitation, home, proxy_report, uri_template
from . import mcp_protocol as protocol
from . import server_env
from .approvers import (
    APPROVAL_ID_PREFIX,
    ELICITATION_VERSIONS,
    Answer,
    ApprovalBackend,
    ApprovalRequest,
    ElicitationApprover,
    NotShowable,
    check_showable,
    declares_form_elicitation,
    parse_backend,
)
from .firewall import (
    SERVER_NAME,
    WAITING_FOR_APPROVAL,
    CheckedResult,
    Decision,
    Firewall,
    agent_text,
    secret_rule,
)
from .jsonutil import finite_float, no_constant
from .launch import launch_identity
from .leaks import Found
from .mcp_protocol import ShapeError
from .pins import CHANGED, FULL, KIND_WORDS, NEW, PINNED_LISTS, ToolPins, definition_of, fingerprint, server_info_value
from .policy import (
    PROMPTS_GET,
    RULE_CALL_TIMEOUT,
    RULE_INCLUDE_CONTEXT,
    RULE_MALFORMED,
    RULE_QUARANTINE,
    RULE_SECRETS_IN_RESULTS,
    RULE_UNSCANNABLE,
    SAMPLING_CREATE,
    Policy,
    PolicyError,
)
from .policy_errors import file_error_message, type_name
from .session import (
    GROUP_NAME_RULE, JOINED, NEW_RUN, REPLACED, GroupJoin, GroupSessionStore, SessionStateError, group_name,
)
from .detector import METADATA, SEVERITY_ORDER, max_severity, scan_views
from .textutil import (
    MAX_CONTAINERS, UnscannableError, clean_for_forwarding, clean_value_for_forwarding, printable, text_views,
)

# How long a tool call waits for an in-flight tools/list reply to be checked.
TOOL_LIST_WAIT_SECONDS = 15
# After either side closes, how long the server has in all to finish answering
# and exit before it is stopped. Kept short: a host application that closes
# our input typically waits only a couple of seconds before killing us, and a
# proxy that is killed first leaves its server running.
SHUTDOWN_GRACE_SECONDS = 1.5

# Resource limits. Each bounds something a hostile peer could otherwise grow forever.
DEFAULT_MAX_MESSAGE_BYTES = 16 * 1024 * 1024
MAX_MAX_MESSAGE_BYTES = 1024 * 1024 * 1024  # the most --max-message-bytes may be: 1 GiB
MAX_PENDING_REQUESTS = 10_000  # client requests waiting for a reply
MAX_SERVER_REQUESTS = 1_000  # server requests waiting for the client's reply
MAX_QUARANTINED = 10_000  # tools, prompts and resource templates together
MAX_KNOWN_NAMES = 10_000  # names of one kind remembered to catch look-alikes
MAX_REPORTED = 10_000  # things reported once on stderr (see _first_report)
MAX_LABEL_CHARS = 200
MAX_NAME_CHARS = 256  # tool names and request ids the proxy has to remember
MAX_WAITING_APPROVALS = 16  # calls held for a person's answer; more are refused at once
MAX_QUARANTINED_TEMPLATES = 1_000  # the uriTemplates of quarantined resource templates; past it, no read is let through

# Pagination (_checked_page_boundary): while a list's cursor chain is open, the text nearest the end
# of the page before is scanned with the text nearest the start of the next page, this many bytes of
# each (see _boundary_view).
PAGE_BOUNDARY_BYTES = 4096
# The text members kept at a boundary, on each side: the five a model reads first, then others (nested
# ones too, such as "inputSchema/properties/q/description"), the first found nearest the boundary.
MAX_BOUNDARY_MEMBERS = 16
MAX_BOUNDARY_PATH_CHARS = 128  # a member's path ("annotations/title") is cut to its last this many characters
_MEMBER_OVERHEAD = 6  # what a kept value costs besides its path and its text: quotes, colon, comma, as in JSON
_REPEATS_KEPT = 3  # as in textutil.text_views: a run of one text says nothing more after a few copies
# Ends of pages kept at once, per list, by the cursor of the page after: the one used least recently goes first.
MAX_OPEN_CURSORS = 8

# limits.call_timeout_seconds applies to these requests: the ones the policy decides like a call.
_TIMED_METHODS = ("tools/call", "resources/read", PROMPTS_GET)
TIMEOUT_ERROR_CODE = -32001  # what MCP's SDKs answer a request that timed out with

# proxy --approval-timeout: how long a held call waits for an answer, in seconds.
DEFAULT_APPROVAL_TIMEOUT = 120
MAX_APPROVAL_TIMEOUT = 3600

# Resource reads are checked by the policy under this name, with one
# argument, "uri". A policy rule for it looks like a rule for a tool.
RESOURCE_READ = "resources/read"
_RESOURCE_METHODS = (RESOURCE_READ, "resources/subscribe")
# Names a tool may not have: the policy checks these requests under them, and a tool must not borrow their rules.
_RESERVED_TOOL_NAMES = (*_RESOURCE_METHODS, PROMPTS_GET)
# The client requests the policy decides. Each must have an id: sent as a notification, it is refused.
_POLICY_METHODS = ("tools/call", *_RESERVED_TOOL_NAMES, protocol.SUBSCRIPTIONS_LISTEN)
COMPLETION_COMPLETE = "completion/complete"
# Where 2026-07-28 puts the server's serverInfo (in the _meta of a server/discover result).
_SERVER_INFO_KEY = "io.modelcontextprotocol/serverInfo"

# List methods and the result field that holds their items. Items are scanned
# one by one, so a single poisoned entry does not take the whole list down.
_LIST_ITEMS_KEY = {
    "tools/list": "tools",
    "prompts/list": "prompts",
    "resources/list": "resources",
    "resources/templates/list": "resourceTemplates",
}
# What a client may still ask of a server quarantined for differing from its pin (Proxy.quarantine_server): the
# handshake, ping, the lists (every entry is removed) and the log level. The other requests are refused.
_ASKED_OF_A_QUARANTINED_SERVER = frozenset({
    protocol.INITIALIZE, protocol.SERVER_DISCOVER, "ping", *_LIST_ITEMS_KEY, "logging/setLevel",
})
# What such a server may still tell the client: that it cancelled a request of its own. Its other
# notifications (log messages, progress, list changes, resource updates) are dropped.
_TOLD_BY_A_QUARANTINED_SERVER = frozenset({"notifications/cancelled"})
# One entry of each list, as audit events name it ("tool_changed", "prompt_lookalike", ...).
_ENTRY_NAME = {"tools": "tool", "prompts": "prompt", "resources": "resource", "resourceTemplates": "resource_template"}
# The lists whose names are what the client calls or fetches by: they follow the
# MCP naming rules and are checked for look-alikes.
_NAMED_LISTS = ("tools", "prompts")
# The members of a list entry that the client sends back to ask for it (a tool's name, a resource's
# URI). What the proxy forwards is cleaned of hidden characters, so an entry whose member would change
# is removed: the client could not ask for it as the server knows it.
_ASKED_FOR_BY = {"tools": ("name",), "prompts": ("name",), "resources": ("uri",),
                 "resourceTemplates": ("name", "uriTemplate")}

# proxy --tool-names: what happens to a tool or prompt whose name breaks the MCP naming rules.
TOOL_NAMES_STRICT = "strict"  # removed and quarantined
TOOL_NAMES_WARN = "warn"  # kept, and reported on stderr and in the audit log (the default)
TOOL_NAMES_OFF = "off"  # neither the naming rules nor look-alikes are checked
TOOL_NAME_MODES = (TOOL_NAMES_STRICT, TOOL_NAMES_WARN, TOOL_NAMES_OFF)

# proxy --on-server-change, with --pin-server: what happens when the server differs from its pin (pins.py).
SERVER_CHANGE_REFUSE = "refuse"  # the proxy does not start (a changed launch) or refuses the handshake (serverInfo)
SERVER_CHANGE_QUARANTINE = "quarantine"  # it starts, with every tool, prompt and resource template quarantined
SERVER_CHANGE_MODES = (SERVER_CHANGE_REFUSE, SERVER_CHANGE_QUARANTINE)

JsonObject = dict[str, Any]
# What the boundary scan keeps of one entry of a list (_boundary_view): (member path, text) pairs, in the entry's order.
_KeptEntry = tuple[tuple[str, str], ...]

# A name the proxy may put into a command line it suggests to the operator (pins diff NAME). The name
# comes from the server, and Windows quoting (list2cmdline) does not stop cmd.exe reading "&" or
# PowerShell reading "$(...)" in it. Any other name is left out of the command, which then lists every
# change; the line that reports the quarantine names the entry anyway.
_SHELL_SAFE_NAME = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_.-]{0,127}")

# What the agent is told. Like every refusal, it names no rule.
_SECRET_REFUSAL = "the request contains what looks like a secret, so it was not sent"
_INPUT_REFUSAL = "the server asked for input that is not permitted"
_MALFORMED_REQUEST = "the request is malformed"
_MALFORMED_REPLY = "the server sent a malformed reply"
_UNSUPPORTED_REQUEST = "this request is not supported"
_UNSUPPORTED_REPLY = "the server sent a reply this proxy cannot check"
_UNSUPPORTED_VERSION = "the server chose a protocol version this proxy does not support"
_UNCHECKED_CONTENT = "the content could not be checked, so it was withheld"
_TIMEOUT_REFUSAL = "the server did not answer in time, so the request was cancelled"
_TIMED_OUT_ID_REFUSAL = "the id of this request belongs to a request that timed out; send it with another id"
_TEMPLATE_REFUSAL = "this resource cannot be read: its template was removed from the template list"
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
    # A list request that continues a cursor chain: a digest of its cursor (see _checked_page_boundary).
    cursor: str | None = None
    # limits.call_timeout_seconds: when, on time.monotonic(), the call is answered with an error if the
    # server has not answered it. Once that happened, `timed_out` is set and the server's reply is dropped.
    deadline: float | None = None
    timed_out: bool = False


@dataclass(frozen=True)
class _PageTail:
    """The end of a page of a list whose next page has not been checked yet (see _checked_page_boundary).

    Side by side, for each entry with text in the boundary view (_boundary_view), in page order:
    """

    texts: tuple[_KeptEntry, ...]  # the text kept of it, PAGE_BOUNDARY_BYTES in all
    names: tuple[str, ...]  # its name, to quarantine (tools, prompts, resource templates); "" if it has none
    templates: tuple[str, ...]  # its uriTemplate (resource templates); "" if it has none


@dataclass(frozen=True)
class _Outcome:
    """What to do with an inspected message. Either side may be None."""

    to_server: Any = None
    to_client: Any = None


_DROP = _Outcome()
# The answer for a held call the client cancelled; compared by identity (_ask_someone).
_CANCELLED = Answer(False, "the client cancelled the request")


@dataclass
class _WaitingCall:
    """A client request held until a person approves it, or the time for an answer runs out.

    The worker thread that asks (Proxy._approval_worker) is the only one that
    sends anything for it. `answered` is set when an answer arrives or the
    client cancels the request; `answer` and `cancelled` say which. Both are
    changed under Proxy._state.
    """

    message: JsonObject
    pending: Decision  # from check_call(..., defer_ask=True)
    request: ApprovalRequest
    label: str  # the audit label, as for a forwarded request
    description: str  # "tools/call 'send_email'", for stderr
    deadline: float  # on time.monotonic(): no answer by then refuses the call
    answered: threading.Event = field(default_factory=threading.Event)
    answer: Answer | None = None
    cancelled: bool = False


# ---- small helpers ----------------------------------------------------------

# How each line the proxy writes to stderr begins: "agent-sentinel", or, with
# --name, "agent-sentinel[NAME]", so that the log of a client that runs
# several proxies says which one wrote each line.
_stderr_label = "agent-sentinel"


def _warn(message: str, limit: int = 300) -> None:
    # Warnings can include names chosen by the server, so make them terminal-safe.
    print(f"{_stderr_label}: {printable(message, limit=limit)}", file=sys.stderr, flush=True)


def _name_stderr(name: str) -> None:
    """Put the server's name (proxy --name, already checked against SERVER_NAME) in every stderr line."""
    global _stderr_label
    _stderr_label = f"agent-sentinel[{name}]"


def _parse(line: bytes) -> Any:
    """Parse one line of JSON, refusing NaN, Infinity and 1e999 (jsonutil), which cannot be written back as JSON.

    A repeated key is not refused here: the proxy forwards what it parsed and
    checked, written anew, never the original bytes, so the server sees the
    same single value the proxy checked.
    """
    return json.loads(line, parse_constant=no_constant, parse_float=finite_float)


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


def _kinds(found: list[Found]) -> str:
    """The kinds of secret the guard found, for a reason in the audit log: "GitHub token, value of DB_PASSWORD"."""
    return ", ".join(item.kind for item in found)


def _tool_error(msg_id: Any, reason: str, modern: bool = False) -> JsonObject:
    """A tools/call result telling the agent that the call was blocked.

    modern: the request named a 2026-07-28 protocol version, where every
            result must say what kind of result it is.
    """
    result: JsonObject = {
        "content": [{"type": "text", "text": agent_text(reason)}],
        "isError": True,
    }
    if modern:
        result["resultType"] = protocol.RESULT_COMPLETE
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _rpc_error(msg_id: Any, reason: str, code: int = -32000) -> JsonObject:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": agent_text(reason)}}


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


# The parameter that says what a request is about, for the lines the operator reads.
_SUBJECT_PARAM = {"tools/call": "name", "resources/read": "uri", "resources/subscribe": "uri", PROMPTS_GET: "name"}


def _request_description(message: JsonObject) -> str:
    """A client request as the operator reads it on stderr: "tools/call 'delete_file'", or just the method."""
    method = message["method"]
    params = message.get("params")
    key = _SUBJECT_PARAM.get(method)
    subject = params.get(key) if key and isinstance(params, dict) else None
    if isinstance(subject, str) and subject:
        return f"{method} '{printable(subject, limit=MAX_LABEL_CHARS)}'"
    return printable(method, limit=MAX_LABEL_CHARS)


def _reply_description(pending: _PendingRequest) -> str:
    """The reply to a request, as the operator reads it: "the reply to tools/call 'fetch_page'"."""
    if pending.label != pending.method:
        return f"the reply to {pending.method} '{printable(pending.label, limit=MAX_LABEL_CHARS)}'"
    return f"the reply to {pending.method}"


def _digest(text: str) -> str:
    """A short fixed-length stand-in for a text the proxy must recognise later, such as a cursor."""
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:32]


def _cursor_digest(message: JsonObject) -> str | None:
    """The digest of the cursor a list request continues from, or None for the first page.

    Every string is a cursor, "" too, as every string nextCursor starts a
    chain (_remember_page_end). A list reply whose nextCursor is not a
    string is refused, so a cursor of another type was never handed out by
    the server through this proxy.
    """
    params = message.get("params")
    cursor = params.get("cursor") if isinstance(params, dict) else None
    return _digest(cursor) if isinstance(cursor, str) else None


# The members of a list entry a model reads first: the boundary scan always looks for them.
_BOUNDARY_MEMBERS = ("description", "title", "name", "uriTemplate", "uri")


def _boundary_view(
    entries: Sequence[Any], from_end: bool, wanted: Iterable[str] = (),
) -> list[tuple[int, _KeptEntry]]:
    """The text nearest one end of a page of a list, PAGE_BOUNDARY_BYTES in all, for _checked_page_boundary.

    A list is scanned whole (textutil.text_views), and one of the ways it is
    read joins the texts at one path ("description", "annotations/title",
    "inputSchema/properties/q/description", "arguments/*/description": a
    member, nested or not, with list positions as "*") over the entries that
    have it, skipping the entries that do not. So for each member this keeps
    the values of the entries nearest that end (the end of the page when
    from_end, else its start) that have text in it, as many as fit the
    member's share. The budget is shared fairly: a member that needs less than
    an equal share leaves the rest to the others, so a long description cannot
    crowd out a title. A kept value costs its path, its text and
    _MEMBER_OVERHEAD bytes; the last value kept of a member is cut, keeping
    the part nearest the boundary. The five members of _BOUNDARY_MEMBERS and
    the `wanted` ones (the members the other side of the boundary kept) are
    always looked for, and besides them the first others found nearest the
    boundary, MAX_BOUNDARY_MEMBERS - 5 of them. As in text_views, a run of the
    same text is kept at most _REPEATS_KEPT times.

    `entries` are list entries, or what this kept of entries before (a
    _KeptEntry, read as it is). Returns (index into `entries`, the (member,
    kept text) pairs) for each entry with text kept, in page order, its texts
    in the entry's own order.
    """
    found = _boundary_values(entries, from_end, wanted)
    shares = _fair_shares({key: sum(_value_cost(key, value) for _, _, value in values)
                           for key, values in found.items()}, PAGE_BOUNDARY_BYTES)
    kept: dict[int, list[tuple[int, str, str]]] = {}
    for key, values in found.items():
        room = shares[key]
        fixed = _value_cost(key, "")
        for index, position, value in values:
            piece = _cut_to_bytes(value, room - fixed, keep_end=from_end) if room > fixed else ""
            if not piece:
                break
            kept.setdefault(index, []).append((position, key, piece))
            room -= _value_cost(key, piece)
    return [(index, tuple((key, piece) for _, key, piece in sorted(kept[index]))) for index in sorted(kept)]


def _boundary_values(
    entries: Sequence[Any], from_end: bool, wanted: Iterable[str] = (),
) -> dict[str, list[tuple[int, int, str]]]:
    """For each member, the (index, position, value) of the entries nearest one end that have text in it, nearest first.

    `position` is the value's place among the texts of its entry
    (_entry_texts). A member is followed until its values would cost
    PAGE_BOUNDARY_BYTES, which no share can exceed. The walk reads every entry
    otherwise (entries without a member must not hide the next one that has
    it), unless every member is full and no other can be added.
    """
    found: dict[str, list[tuple[int, int, str]]] = {key: [] for key in (*_BOUNDARY_MEMBERS, *wanted)}
    cost = dict.fromkeys(found, 0)
    others = 0  # members found that were not looked for from the start
    full = 0  # members whose values cost PAGE_BOUNDARY_BYTES already
    room_for_others = MAX_BOUNDARY_MEMBERS - len(_BOUNDARY_MEMBERS)
    for index in range(len(entries) - 1, -1, -1) if from_end else range(len(entries)):
        entry = entries[index]
        texts = entry if isinstance(entry, tuple) else _entry_texts(entry) if isinstance(entry, dict) else ()
        positions = range(len(texts) - 1, -1, -1) if from_end else range(len(texts))
        for position in positions:
            key, value = texts[position]
            if not value or value.isspace():
                continue
            if key not in found:
                if others >= room_for_others:
                    continue
                found[key], cost[key] = [], 0
                others += 1
            values = found[key]
            if cost[key] >= PAGE_BOUNDARY_BYTES:
                continue
            if len(values) >= _REPEATS_KEPT and all(text == value for _, _, text in values[-_REPEATS_KEPT:]):
                continue
            values.append((index, position, value))
            cost[key] += _value_cost(key, value)
            full += cost[key] >= PAGE_BOUNDARY_BYTES
        if full == len(found) and others >= room_for_others:
            break  # nothing further can be kept
    return {key: values for key, values in found.items() if values}


def _entry_texts(entry: Mapping[str, Any]) -> _KeptEntry:
    """The (member path, text) of every text value in a list entry, in document order.

    A path is the keys down to the value joined by "/", with "*" for a
    position in a list, as textutil.text_views groups texts:
    "inputSchema/properties/q/description", "arguments/*/name". A path longer
    than MAX_BOUNDARY_PATH_CHARS is cut to its end (two paths that are then
    the same are read as one, which only joins more). Text at any depth is
    read, as the whole-list scan reads it: the walk is iterative, so its cost
    is linear in the entry, and like text_views it raises UnscannableError
    past MAX_CONTAINERS objects and arrays (an entry that large was already
    refused by its own scan).
    """
    texts: list[tuple[str, str]] = []
    stack: list[tuple[Any, str]] = [(entry, "")]
    opened = 0
    while stack:
        value, path = stack.pop()
        if isinstance(value, str):
            if path:
                texts.append((path, value))
            continue
        opened += 1
        if opened > MAX_CONTAINERS:
            raise UnscannableError("the list entry has too many nested parts to read")
        # Pushed in reverse, so that they come out in document order; numbers and the like are left out.
        if isinstance(value, dict):
            stack.extend([(child, _member_path(path, key)) for key, child in reversed(value.items())
                          if isinstance(key, str) and isinstance(child, _TEXT_HOLDERS)])
        elif isinstance(value, list):
            inner = _member_path(path, "*")
            stack.extend([(child, inner) for child in reversed(value) if isinstance(child, _TEXT_HOLDERS)])
    return tuple(texts)


_TEXT_HOLDERS = (str, dict, list)  # what _entry_texts reads: JSON's text, objects and arrays


def _member_path(path: str, step: str) -> str:
    """`path` one step further down, cut to its last MAX_BOUNDARY_PATH_CHARS characters (see _entry_texts)."""
    joined = f"{path}/{step}" if path else step
    return joined[-MAX_BOUNDARY_PATH_CHARS:] if len(joined) > MAX_BOUNDARY_PATH_CHARS else joined


def _scannable(kept: Iterable[_KeptEntry]) -> list[list[dict[str, str]]]:
    """Kept entries in the shape the scan reads: texts of one member share one path, in document order."""
    return [[{key: text} for key, text in entry] for entry in kept]


def _value_cost(key: str, value: str) -> int:
    """What one kept value of a member costs in the boundary view's budget, in bytes."""
    return len(key.encode("utf-8", "surrogatepass")) + len(value.encode("utf-8", "surrogatepass")) + _MEMBER_OVERHEAD


def _fair_shares(needs: Mapping[str, int], room: int) -> dict[str, int]:
    """Split `room` among the members: each gets what it needs, up to an equal part of what the others leave."""
    shares: dict[str, int] = {}
    left = len(needs)
    for key in sorted(needs, key=needs.__getitem__):
        shares[key] = min(needs[key], room // left)
        room -= shares[key]
        left -= 1
    return shares


def _fewest(refused: Callable[[int], bool], total: int) -> int:
    """The smallest count from 1 to `total` that `refused` holds for, taking it to hold for `total`.

    A binary search, so at most about log2(total) scans: adding text to a
    scan rarely takes a finding away. If it ever does, the count found is
    still one that is refused.
    """
    low, high = 0, total
    while high - low > 1:
        middle = (low + high) // 2
        if refused(middle):
            high = middle
        else:
            low = middle
    return high


def _cut_to_bytes(text: str, size: int, keep_end: bool) -> str:
    """At most `size` bytes of `text` written as UTF-8: its end when keep_end, else its start."""
    data = text.encode("utf-8", "surrogatepass")
    if len(data) <= size:
        return text
    return (data[-size:] if keep_end else data[:size]).decode("utf-8", "ignore")


# ---- names that look alike ----------------------------------------------------

class _NameRegistry:
    """The names one server has given its tools (or its prompts), to catch a new name that looks like a known one.

    Two names look alike when they have the same mcp_protocol.name_skeleton:
    "read_fіle" (with a Cyrillic і) or "read_fiIe" beside "read_file". A
    wildcard rule such as "read_*" matches both, and a person reading the list
    cannot tell them apart. The name seen first keeps its skeleton: a pinned
    name, then one listed earlier, then, within one list, the first that
    follows the naming rules (so a server cannot push the real name out by
    listing the fake one first). Names are only ever added.
    """

    def __init__(self, known: Iterable[str]) -> None:
        self._lock = threading.Lock()
        self._first: dict[str, str] = {}  # skeleton -> the name that has it
        for name in known:
            if len(self._first) < MAX_KNOWN_NAMES:
                self._first.setdefault(protocol.name_skeleton(name), name)

    def lookalikes(self, names: Iterable[str], follows_rules: Callable[[str], bool]) -> dict[str, str]:
        """Register the names of one list; return {name: why it is refused} for those that cannot keep their name."""
        groups: dict[str, list[str]] = {}
        for name in dict.fromkeys(names):
            groups.setdefault(protocol.name_skeleton(name), []).append(name)
        refused: dict[str, str] = {}
        with self._lock:
            for skeleton, group in groups.items():
                first = self._first.get(skeleton)
                if first is None:
                    if len(self._first) >= MAX_KNOWN_NAMES:
                        # It cannot be remembered, so a later look-alike could not be caught.
                        refused.update(dict.fromkeys(group, "too many names to keep track of"))
                        continue
                    first = next((name for name in group if follows_rules(name)), group[0])
                    self._first[skeleton] = first
                for name in group:
                    if name != first:
                        refused[name] = f"its name looks like that of '{printable(first, limit=80)}'"
        return refused


# ---- the proxy --------------------------------------------------------------

class Proxy:
    def __init__(
        self,
        firewall: Firewall,
        client_out: BinaryIO,
        server_in: BinaryIO,
        pins: ToolPins | None = None,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        tool_names: str = TOOL_NAMES_WARN,
        elicitation_hosts: Sequence[str] = (),
        approvers: Sequence[ApprovalBackend] = (),
        approval_timeout: float = DEFAULT_APPROVAL_TIMEOUT,
        report: str = proxy_report.NORMAL,
        pin_server: bool = False,
        on_server_change: str = SERVER_CHANGE_REFUSE,
    ) -> None:
        """
        pins:              the pins of this server (pins.ToolPins); default: kept in memory only.
        pin_server:        compare the serverInfo of each handshake with the server's pin (proxy --pin-server).
        on_server_change:  when it differs: SERVER_CHANGE_REFUSE refuses the handshake, SERVER_CHANGE_QUARANTINE
                           lets it through; either way every tool, prompt and template is quarantined.
        tool_names:        what to do with a tool or prompt whose name breaks the MCP naming
                           rules: TOOL_NAMES_STRICT, TOOL_NAMES_WARN (the default) or TOOL_NAMES_OFF.
        elicitation_hosts: the hosts a URL-mode elicitation may send the user to (proxy
                           --elicitation-host); empty: any public https address. PolicyError
                           for an entry that cannot be used.
        approvers:         who is asked about a call the policy says "ask" for (proxy
                           --approve-with; approvers.py), in order: the first that can ask at
                           the time of the call is used. Empty: such calls are refused.
        approval_timeout:  seconds a held call waits for an answer before it is refused.
        report:            how much the proxy writes to stderr: proxy_report.QUIET, NORMAL or VERBOSE.
        """
        if tool_names not in TOOL_NAME_MODES:
            raise ValueError(f"tool_names must be one of {', '.join(TOOL_NAME_MODES)}")
        if report not in (proxy_report.QUIET, proxy_report.NORMAL, proxy_report.VERBOSE):
            raise ValueError("report must be proxy_report.QUIET, NORMAL or VERBOSE")
        if not 0 < approval_timeout <= MAX_APPROVAL_TIMEOUT:
            raise ValueError(f"approval_timeout must be more than 0 and at most {MAX_APPROVAL_TIMEOUT} seconds")
        if type(max_message_bytes) is not int or not 1 <= max_message_bytes <= MAX_MAX_MESSAGE_BYTES:
            raise ValueError(f"max_message_bytes must be a whole number from 1 to {MAX_MAX_MESSAGE_BYTES}")
        if on_server_change not in SERVER_CHANGE_MODES:
            raise ValueError(f"on_server_change must be one of {', '.join(SERVER_CHANGE_MODES)}")
        self._pin_server = pin_server
        self._on_server_change = on_server_change
        # Why the whole server is quarantined (its pin changed: quarantine_server), or None. Guarded by `_state`.
        self._server_quarantine: str | None = None
        self._firewall = firewall
        self._client_out = client_out
        self._server_in = server_in
        self._pins = pins if pins is not None else ToolPins()
        self._max_message_bytes = max_message_bytes
        self._tool_names = tool_names
        self._elicitation_hosts = elicitation.allowed_hosts(elicitation_hosts)
        self._client_write_lock = threading.Lock()
        self._server_write_lock = threading.Lock()
        # The names each named list has used, to catch look-alikes; pinned names come first.
        self._names = {kind: _NameRegistry(self._pins.names(kind)) for kind in _NAMED_LISTS}
        # Every tool name this server has listed (at most MAX_KNOWN_NAMES), so that a description that
        # names one of the server's own tools is not taken for shadowing (_foreign_tools). Guarded by `_state`.
        self._listed_tools: set[str] = set()

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
        # Entries removed from their list for good, by list: such a tool cannot be called, nor such a prompt fetched.
        self._quarantined: dict[str, set[str]] = {kind: set() for kind in PINNED_LISTS}
        self._quarantine_overflowed = False
        # The uriTemplates of quarantined resource templates, with their literal parts (uri_template.py): a URI
        # one of them may produce cannot be read or subscribed to. Past MAX_QUARANTINED_TEMPLATES, none can.
        self._quarantined_templates: dict[str, tuple[str, ...] | None] = {}
        self._templates_overflowed = False
        # The end of each page that gave a nextCursor, by list and by a digest of that cursor, least recently
        # used first (at most MAX_OPEN_CURSORS per list).
        self._page_tails: dict[str, dict[str, _PageTail]] = {kind: {} for kind in _LIST_ITEMS_KEY.values()}
        # limits.call_timeout_seconds: (deadline, order, request id) of forwarded calls, soonest first, and the
        # thread that answers those whose time runs out (_watch_deadlines), while there are any.
        self._deadlines: list[tuple[float, int, Any]] = []
        self._deadline_order = itertools.count()
        self._watching_deadlines = False
        self._deadline_wake = threading.Event()
        self._tools_unverified = False  # set while the latest tools/list reply was malformed
        self._tool_lists_in_flight: set[str | int] = set()
        # What was already reported on stderr: a client that lists its tools often gets each line once.
        self._reported: set[tuple[str, ...]] = set()

        # Approvals (see "Approvals" above). The approvers themselves never change.
        self._approvers = tuple(approvers)
        self._approval_timeout = approval_timeout
        # Calls held for an answer, by the firewall's call id; the proxy's own questions to
        # the client (elicitation), by their request id. Both guarded by `_state`.
        self._waiting: dict[str, _WaitingCall] = {}
        self._questions: dict[str, _WaitingCall] = {}
        # One question at a time: a person facing several at once could answer the wrong one.
        self._approval_turn = threading.Lock()
        # What the client said in initialize, and the version the server chose: whether
        # the client can be asked through an elicitation form. Guarded by `_state`.
        self._client_shows_forms = False
        self._negotiated_version: str | None = None

        # What the operator reads on stderr (proxy_report.py). `_warn` is looked up when a
        # line is written, so that output redirected or silenced around a call is respected.
        self._report_level = report
        self._lines = proxy_report.LineBudget(
            lambda text, limit: _warn(text, limit=limit), has_audit=firewall.audit_path is not None
        )
        self._seed_annotation_labels()

    def _seed_annotation_labels(self) -> None:
        """Give the firewall the flow labels of the pinned tools' annotations, and presume the rest unknown.

        Annotation labels (classify_by_annotations) are otherwise learned only
        from a tool list this process checked, and a client may call a tool
        without listing tools first (it cached the list in an earlier process,
        or knows the name). A pinned tool keeps the labels of its pinned
        annotations; a tool neither pinned nor listed counts as untrusted and
        a sink while the policy has flow rules (Firewall.presume_unlisted_tools).
        """
        for name, definition in self._pins.definitions("tools").items():
            self._firewall.learn_annotations(name, definition.get("annotations"))
        self._firewall.presume_unlisted_tools(exempt=_RESERVED_TOOL_NAMES)

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
        decision = self._firewall.refuse("?", f"dropped {what}", event="dropped", rule=RULE_MALFORMED)
        self._report(f"dropped {what} {proxy_report.rule_and_ref(decision)}")
        return _DROP

    def _refusal(
        self, label: str, reason: str, rule: str = RULE_MALFORMED, public_reason: str = "", call_id: str | None = None,
    ) -> Decision:
        """A block for a structural reason. Unlike a policy block, monitor mode does not lift it."""
        return self._firewall.refuse(label, reason, public_reason=public_reason, rule=rule, call_id=call_id)

    # ---- what the operator reads on stderr ----------------------------------------

    def _report(self, text: str, limit: int = 300) -> None:
        """A line about traffic, for the operator: not with --quiet, and within the line budget."""
        if self._report_level != proxy_report.QUIET:
            self._lines.line(text, limit)

    def _report_block(self, what: str, decision: Decision) -> None:
        """One line for a block: what, why, the rule and the reference the agent was shown."""
        self._report(proxy_report.block_line(what, decision), limit=1000)

    def _report_allowed(self, what: str, decision: Decision) -> None:
        """A line for a call that was let through: with --verbose, or when monitor mode lifted a block."""
        lifted = decision.would_block
        if lifted or self._report_level == proxy_report.VERBOSE:
            self._report(proxy_report.allowed_line(what, decision), limit=1000)

    def close_report(self) -> None:
        """Say how many lines the line budget left out, if any. The proxy calls this when it stops."""
        if self._report_level != proxy_report.QUIET:
            self._lines.flush()

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
        if method in _POLICY_METHODS and "id" not in message:
            # These are requests: a notification cannot ask for them, and one could not be
            # held for approval, cancelled or answered like a request.
            return self._refuse_malformed_request(message, "it has no id")
        if "id" in message and self._id_in_flight(message["id"]):
            # A reply is matched to its request by id, and checked as the reply to that kind
            # of request: under a reused id, a tool list could pass as a tool's result and
            # skip the list's checks (pins, quarantine, hiding), or a result could set the
            # flow marks of another tool. MCP forbids reusing an id; the request is dropped,
            # unanswered, because any answer under that id would be taken for the first one's.
            # The first one of a request that timed out was answered already, so this one is.
            if self._id_timed_out(message["id"]):
                return self._refuse_timed_out_id(message)
            return self._dropped("a client request that reuses the id of a request still waiting for its reply")

        # What every request must pass first: the protocol revision's rules, then the
        # secret guard on what it carries to the server besides a call's arguments
        # (answers to the server, what the user is typing), then the policy's
        # client_requests. The secret guard comes before the policy, so that its
        # answer does not tell a probing agent what the policy would have said.
        refused = (
            self._check_protocol(message)
            or self._check_input_responses(message)
            or self._check_completion(message)
            or self._check_client_request(message)
        )
        if refused is not None:
            return refused
        if method == "tools/call":
            return self._check_tool_call(message)
        if method in _RESOURCE_METHODS:
            return self._check_resource_request(message)
        if method == PROMPTS_GET:
            return self._check_prompt_request(message)
        if method == protocol.SUBSCRIPTIONS_LISTEN:
            return self._check_subscriptions(message)
        if method.startswith(protocol.TASKS_METHOD_PREFIX):
            return self._refuse_task_request(message)
        if method == "notifications/cancelled" and self._forget_cancelled_request(message):
            return _DROP  # it cancelled a call held for approval, which the server never saw
        refused = self._refused_by_server_quarantine(message)
        if refused is not None:
            return refused
        return self._forward_request(message, label=_label(method))

    def _refused_by_server_quarantine(self, message: JsonObject) -> _Outcome | None:
        """Refuse a request a quarantined server (quarantine_server) may not answer; None when it may go on.

        Such a server serves nothing: the client may still open the session,
        ping it and list (every entry is removed), and set its log level. Any
        other request, completion/complete for one, would bring the server's
        answer to the client. Notifications get no answer, so they pass.
        """
        quarantined = self._whole_server_quarantined()
        if quarantined is None or "id" not in message or message["method"] in _ASKED_OF_A_QUARANTINED_SERVER:
            return None
        method = message["method"]
        reason = f"the whole server is quarantined: {quarantined}"
        return self._refused(message, self._firewall.refuse(_label(method), reason, event="client_request",
                                                            rule=RULE_QUARANTINE))

    def _refuse_batch(self, batch: list[Any]) -> _Outcome:
        # MCP no longer uses JSON-RPC batches. Refusing them keeps every
        # request on the single, checked path above.
        decision = self._firewall.refuse(
            "?", "dropped a batched client message", event="dropped",
            public_reason="batched requests are not supported", rule=RULE_MALFORMED,
        )
        self._report(f"refused a batch of {len(batch)} client messages {proxy_report.rule_and_ref(decision)}")
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

        An answer to one of the proxy's own approval questions is taken first,
        by its id, and never reaches the server (_approval_answer).
        """
        msg_id = message.get("id")
        if isinstance(msg_id, str) and msg_id.startswith(APPROVAL_ID_PREFIX):
            return self._approval_answer(message)
        is_reply = ("result" in message) != ("error" in message)
        with self._state:
            method = self._server_requests.pop(msg_id, None) if is_reply and _valid_id(msg_id) else None
        if method is None:
            return self._dropped("a client message that answers no request from the server")

        label = _label(f"server:{method}")  # the label the server's request was logged under
        member = "result" if "result" in message else "error"
        what = f"refused the client's answer to a '{printable(method, limit=100)}' request"
        try:
            value = protocol.client_reply_value(member, message[member])
            secrets = self._secrets_in(value)
        except (ShapeError, UnscannableError) as exc:
            decision = self._firewall.refuse(
                label, f"malformed client reply: {exc}", event="client_reply", rule=RULE_MALFORMED
            )
            self._report(f"{what}: {exc} {proxy_report.rule_and_ref(decision)}")
            return _Outcome(to_server=_rpc_error(msg_id, _SERVER_REFUSAL))
        if secrets:
            reason = f"the client's answer contains what looks like a secret ({_kinds(secrets)})"
            decision = self._firewall.block(label, reason, event="client_reply", rule=secret_rule(secrets))
            if not decision.allowed:
                self._report_block(what, decision)
                return _Outcome(to_server=_rpc_error(msg_id, _SERVER_REFUSAL))
        return _Outcome(to_server={"jsonrpc": "2.0", "id": msg_id, member: value})

    def _approval_answer(self, message: JsonObject) -> _Outcome:
        """The client's answer to one of the proxy's own approval questions (an elicitation form).

        It is matched by the question's random id, which only the client was
        ever sent; a server request may not use an id that begins the same way
        (_server_request_problem). The answer goes to the call that waits for
        it and nowhere else: nothing is sent to the server.
        """
        with self._state:
            waiting = self._questions.pop(message["id"], None)
        if waiting is None:
            self._report("ignored an answer to an approval question that is no longer waiting")
            return _DROP
        if ("result" in message) != ("error" in message):
            answer = ElicitationApprover.answer(message)
        else:
            answer = Answer(False, "an answer that is neither a result nor an error", asked=False)
        self._take_answer(waiting, answer)
        return _DROP

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
        reason = f"the answers sent with the request contain what looks like a secret ({_kinds(secrets)})"
        decision = self._firewall.block(
            _request_label(message), reason, public_reason=_SECRET_REFUSAL, rule=secret_rule(secrets)
        )
        return None if decision.allowed else self._refused(message, decision)  # allowed: monitor mode

    def _check_completion(self, message: JsonObject) -> _Outcome | None:
        """Pass a completion/complete request through the secret guard; None when it may go on.

        A client asks for completions while the user types an argument of a
        prompt or a resource template: `argument.value` is that half-typed
        text and `context.arguments` what was typed before. A key pasted there
        would reach the server as it is typed, so the request is checked like
        a call's arguments.
        """
        if message["method"] != COMPLETION_COMPLETE:
            return None
        try:
            secrets = self._secrets_in(message.get("params"))
        except UnscannableError as exc:
            return self._refuse_malformed_request(message, str(exc))
        if not secrets:
            return None
        reason = f"the completion request contains what looks like a secret ({_kinds(secrets)})"
        decision = self._firewall.block(
            COMPLETION_COMPLETE, reason, event="client_request", public_reason=_SECRET_REFUSAL,
            rule=secret_rule(secrets),
        )
        return None if decision.allowed else self._refused(message, decision)  # allowed: monitor mode

    def _check_client_request(self, message: JsonObject) -> _Outcome | None:
        """Apply the policy's client_requests section to the request's method; None when it may go on.

        A refused request is answered "method not found", as a server that
        does not offer the method would answer, so the client carries on
        without it; a notification is dropped. tools/call and the resource
        requests are always allowed here: the tools rules decide them, call by call.
        """
        method = message["method"]
        verdict = self._firewall.policy.client_request_verdict(method)
        if verdict.action != "block":
            return None
        decision = self._firewall.block(
            _label(method), verdict.reason, event="client_request", public_reason=verdict.public,
            rule=verdict.rule or RULE_MALFORMED,
        )
        if decision.allowed:  # monitor mode
            return None
        self._report_block(f"blocked {_request_description(message)}", decision)
        if "id" not in message:
            return _DROP
        return _Outcome(to_client=_rpc_error(message["id"], decision.public_reason, code=protocol.METHOD_NOT_FOUND))

    def _secrets_in(self, value: Any) -> list[Found]:
        """The secrets in what the client sends the server besides a call's arguments.

        The firewall's own guard, exactly as check_call applies it to a call's
        arguments (Firewall.find_secrets): the built-in and custom formats,
        unless secrets.in_arguments is "allow", and the known values and
        canaries always. Raises UnscannableError for a value nested too deeply to read.
        """
        return self._firewall.find_secrets(value)

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

        Whether the client can show an elicitation form is noted from its own
        capabilities, before they are minimised for the server: the proxy may
        ask the client's user to approve a call even when the server may not
        send elicitations (C31 changes only the server's copy).
        """
        params = message.get("params")
        if not isinstance(params, dict):
            raise ShapeError("params must be an object")
        version = params.get("protocolVersion")
        if not isinstance(version, str):
            raise ShapeError("protocolVersion must be text")
        if version not in protocol.LEGACY_VERSIONS:
            self._report(
                f"the client asked for MCP protocol version '{printable(version, limit=40)}' in initialize, "
                f"which this proxy cannot pass on; asking the server for {protocol.NEWEST_LEGACY_VERSION} instead"
            )
            params["protocolVersion"] = protocol.NEWEST_LEGACY_VERSION
        shows_forms = declares_form_elicitation(params.get("capabilities"))
        if "capabilities" in params:
            params["capabilities"] = protocol.minimised_capabilities(params["capabilities"], self._blocked_requests())
        with self._state:
            self._client_shows_forms = shows_forms

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
        decision = self._firewall.refuse(_label(method), reason, event="client_request", rule=RULE_MALFORMED)
        self._report_block(f"refused a '{printable(method, limit=100)}' request", decision)
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
        self._report(f"refused a malformed '{method}' request: {problem} {proxy_report.rule_and_ref(decision)}")
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
        self._report_block(f"refused a '{printable(method, limit=100)}' request", decision)
        if "id" not in message:
            return _DROP
        return _Outcome(to_client=_rpc_error(message["id"], decision.public_reason, code=protocol.METHOD_NOT_FOUND))

    def _refused(self, message: JsonObject, decision: Decision) -> _Outcome:
        """Report a refused client request, and answer it with the decision's public reason.

        A notification gets no answer.
        """
        self._report_block(f"blocked {_request_description(message)}", decision)
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
        elif name in _RESERVED_TOOL_NAMES:
            # Resource reads and prompts share the policy's namespace; a tool must not borrow their rules.
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
            return self._check_policy(message, name, arguments or {}, label=_label(name))
        return self._forward_or_refuse(message, decision, label=_label(str(name)))

    def _check_resource_request(self, message: JsonObject) -> _Outcome:
        """resources/read and resources/subscribe both ask the server to open a URI.

        Any URI of a server quarantined for differing from its pin, and a URI
        that a quarantined resource template may produce, is refused first
        (_quarantined_read), as a call to a quarantined tool is.
        """
        params = message.get("params")
        uri = params.get("uri") if isinstance(params, dict) else None
        if not isinstance(uri, str) or not uri:
            decision = self._refusal(RESOURCE_READ, f"malformed {message['method']} request: missing uri")
            return self._forward_or_refuse(message, decision, label=RESOURCE_READ)
        refusal = self._quarantined_read(uri)
        if refusal is not None:
            return self._forward_or_refuse(message, refusal, label=_label(uri))
        return self._check_policy(message, RESOURCE_READ, {"uri": uri}, label=_label(uri))

    def _quarantined_read(self, uri: str, call_id: str | None = None) -> Decision | None:
        """The refusal of a read of `uri` for a quarantine, or None: first a server that differs from its pin
        (--pin-server: it serves nothing), then a quarantined resource template that may produce the URI."""
        quarantined = self._whole_server_quarantined()
        if quarantined is not None:
            return self._refusal(_label(uri), f"the whole server is quarantined: {quarantined}", RULE_QUARANTINE,
                                 call_id=call_id)
        return self._template_refusal(uri, call_id)

    def _template_refusal(self, uri: str, call_id: str | None = None) -> Decision | None:
        """The refusal of a read of `uri` when a quarantined resource template may produce it, or None."""
        why = self._quarantined_template_of(uri)
        if why is None:
            return None
        return self._refusal(_label(uri), why, RULE_QUARANTINE, public_reason=_TEMPLATE_REFUSAL, call_id=call_id)

    def _quarantined_template_of(self, uri: str) -> str | None:
        """Why `uri` may come from a quarantined resource template (uri_template.may_match), or None.

        Past MAX_QUARANTINED_TEMPLATES no template can be ruled out, so every URI is refused.
        """
        with self._state:
            if self._templates_overflowed:
                return "too many resource templates were quarantined to keep track of, so no resource can be read"
            templates = list(self._quarantined_templates.items())
        spellings = uri_template.spellings(uri) if templates else None
        for template, parts in templates:
            if uri_template.may_match(parts, spellings):
                return f"the URI may come from the quarantined resource template '{printable(template, limit=120)}'"
        return None

    def _check_prompt_request(self, message: JsonObject) -> _Outcome:
        """prompts/get: fetch a prompt by name, with arguments that fill it in.

        A prompt removed from the prompt list (flagged, changed, or with a
        name that is not allowed) cannot be fetched. Once the policy opts in
        (Policy.checks_prompts), the request is checked like a call of a tool
        named "prompts/get" with the arguments {"name", "arguments"}: deny
        rules, the secret guard, the tools rules, rate limits and flow rules.
        Otherwise it is forwarded as before 0.5, and its reply is scanned.
        """
        params = message.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        arguments = params.get("arguments") if isinstance(params, dict) else None
        if not _is_name(name) or (arguments is not None and not isinstance(arguments, dict)):
            return self._refuse_malformed_request(message, "it needs a prompt name, and arguments as an object")
        if self._was_quarantined("prompts", name):
            decision = self._refused_prompt(name)
        elif self._firewall.policy.checks_prompts:
            return self._check_policy(message, PROMPTS_GET, {"name": name, "arguments": arguments or {}}, PROMPTS_GET)
        else:
            return self._forward_request(message, label=PROMPTS_GET)
        return self._forward_or_refuse(message, decision, label=PROMPTS_GET)

    def _refused_prompt(self, name: str, call_id: str | None = None) -> Decision:
        """The refusal of a prompts/get for a prompt that was removed from the prompt list."""
        return self._firewall.refuse(
            PROMPTS_GET, f"the prompt '{printable(name, limit=80)}' was removed from the prompt list",
            public_reason="this prompt was removed from the prompt list and cannot be used", rule=RULE_QUARANTINE,
            call_id=call_id,
        )

    def _check_subscriptions(self, message: JsonObject) -> _Outcome:
        """subscriptions/listen (2026-07-28) replaces resources/subscribe, so it needs the same permission.

        Each resource URI it subscribes to is checked as a read of that URI,
        and one refusal refuses the whole request. The list-changed filters
        ask only for notifications, which are scanned when they come. A
        quarantined server (quarantine_server) is listened to for nothing.
        """
        try:
            uris = protocol.subscribed_uris(message.get("params"))
        except ShapeError as exc:
            return self._refuse_malformed_request(message, str(exc))
        quarantined = self._whole_server_quarantined()
        if quarantined is not None:  # a server that differs from its pin serves nothing (--pin-server)
            reason = f"the whole server is quarantined: {quarantined}"
            return self._refused(message, self._refusal(protocol.SUBSCRIPTIONS_LISTEN, reason, RULE_QUARANTINE))
        for uri in uris:
            decision = self._template_refusal(uri)  # a Decision is false when it refuses: compare with None
            if decision is None:
                decision = self._firewall.check_call(RESOURCE_READ, {"uri": uri})
            if not decision.allowed:
                return self._refused(message, decision)
        return self._forward_request(message, label=protocol.SUBSCRIPTIONS_LISTEN)

    def _check_policy(self, message: JsonObject, tool: str, arguments: JsonObject, label: str) -> _Outcome:
        """Ask the firewall about a request the policy decides, then forward it, refuse it, or hold it for approval.

        `tool` and `arguments` are what the policy sees: the tool's name and
        arguments, or "resources/read" with {"uri"}, or "prompts/get" with
        {"name", "arguments"}. With approvers, an "ask" comes back pending and
        the request is held (_hold_for_approval); without, the firewall refuses it.
        """
        decision = self._firewall.check_call(tool, arguments, defer_ask=bool(self._approvers))
        if decision.pending:
            return self._hold_for_approval(message, decision, tool, arguments, label)
        return self._forward_or_refuse(message, decision, label)

    def _forward_or_refuse(self, message: JsonObject, decision: Decision, label: str) -> _Outcome:
        """Forward a request the checks allowed (setting what it needs for its reply), or refuse it."""
        if not decision.allowed:
            return self._refused(message, decision)
        self._report_allowed(_request_description(message), decision)
        return self._forward_request(message, label, marks=self._marks_of(message), call_id=decision.call_id)

    def _marks_of(self, message: JsonObject) -> frozenset[str]:
        """The flow marks the reply to an allowed request gives the session once it is delivered.

        A tool's result, a resource read and a prompt bring content into the
        conversation. A subscription brings nothing itself: its updates arrive
        as reads of their own.
        """
        method = message["method"]
        if method == "tools/call":
            return self._firewall.marks_for(message["params"]["name"])
        if method in (RESOURCE_READ, PROMPTS_GET):
            return self._firewall.marks_for(method)
        return frozenset()

    # ---- client -> server: calls held for a person's approval --------------------------

    def _hold_for_approval(
        self, message: JsonObject, pending: Decision, tool: str, arguments: JsonObject, label: str,
    ) -> _Outcome:
        """Hold a request the policy says "ask" for; a worker thread asks, and sends the outcome later.

        Nothing is sent now. The client is not kept waiting on its other
        messages: they are handled while the person decides.
        """
        # The person is told why the policy asks; that the call is waiting, they can see.
        reason = pending.reason.removesuffix(WAITING_FOR_APPROVAL)
        request = ApprovalRequest(tool, arguments, reason, pending.ref or "", self._firewall.server_name,
                                  method=message["method"])
        waiting = _WaitingCall(
            message, pending, request, label, _request_description(message),
            deadline=time.monotonic() + self._approval_timeout,
        )
        with self._state:
            room = len(self._waiting) < MAX_WAITING_APPROVALS
            if room:
                self._waiting[pending.call_id or ""] = waiting
        if not room:
            who = f"the proxy ({MAX_WAITING_APPROVALS} calls were already waiting)"
            return self._refused(message, self._firewall.finish_approval(pending, False, who, asked=False))
        self._report(f"waiting for approval: {waiting.description} {proxy_report.rule_and_ref(pending)}", limit=1000)
        threading.Thread(target=self._approval_worker, args=(waiting,), name="agent-sentinel approval",
                         daemon=True).start()
        return _DROP

    def _approval_worker(self, waiting: _WaitingCall) -> None:
        """Ask about one held call, then send the outcome: the request to the server, or a refusal to the client.

        Fails closed: an error anywhere refuses the call. A call the client
        cancelled meanwhile gets no answer at all. The call counts as waiting
        until its outcome has been sent.
        """
        try:
            try:
                answer, who = self._ask_someone(waiting)
                approved = answer.approved is True
                final = self._firewall.finish_approval(
                    waiting.pending, approved, f"{who} ({answer.detail})", asked=answer.asked
                )
                outcome = self._released(waiting, final)
            except Exception as exc:  # a bug must not let the call through
                _warn(f"refused a call that waited for approval, after an internal error: {exc!r}")
                final = self._firewall.finish_approval(
                    waiting.pending, False, "the proxy, after an internal error", asked=False
                )
                outcome = self._refused(waiting.message, final)
            if not waiting.cancelled:
                self._send(outcome)
        except (OSError, ValueError):  # the client or the server has gone; the proxy is stopping
            pass
        finally:
            with self._state:
                self._waiting.pop(waiting.pending.call_id or "", None)

    def waiting_for_approval(self) -> int:
        """How many calls are held for a person's answer now (until each one's outcome has been sent)."""
        with self._state:
            return len(self._waiting)

    def _ask_someone(self, waiting: _WaitingCall) -> tuple[Answer, str]:
        """Ask the first approver that can ask now; return the answer and who gave it, for the audit log.

        One question at a time: a person facing several questions at once
        could answer the wrong one. A call whose turn does not come before its
        deadline is refused like one nobody answered.
        """
        try:
            check_showable(waiting.request.arguments)
        except NotShowable as exc:
            return Answer(False, str(exc), asked=False), "the proxy"
        approver, why_nobody = self._choose_approver()
        if approver is None:
            if self._first_report("nobody to ask", why_nobody):
                self._report(f"a call needs approval, but nobody can be asked: {why_nobody}", limit=1000)
            return Answer(False, why_nobody, asked=False), "nobody"
        if not self._approval_turn.acquire(timeout=max(0.0, waiting.deadline - time.monotonic())):
            return Answer(False, "no answer in time: other calls were being asked about"), approver.name
        try:
            if waiting.cancelled:
                answer = self._await_answer(waiting)
            elif isinstance(approver, ElicitationApprover):
                answer = self._ask_client(waiting)
            else:
                answer = self._ask_on_this_machine(approver, waiting)
        finally:
            self._approval_turn.release()
        # Nobody refused a call the client withdrew: the record names the client, not the approver.
        return answer, ("the client" if answer is _CANCELLED else approver.name)

    def _choose_approver(self) -> tuple[ApprovalBackend | None, str]:
        """The first approver that can ask now, or None and why none can."""
        reasons = []
        for approver in self._approvers:
            why = self._why_cannot_ask(approver)
            if why is None:
                return approver, ""
            reasons.append(f"{approver.name}: {why}")
        return None, "; ".join(reasons)

    def _why_cannot_ask(self, approver: ApprovalBackend) -> str | None:
        """Why this approver cannot ask about a call now, or None.

        An elicitation needs a session opened with initialize (a 2026-07-28
        server, which the proxy stands in for, may not send requests on stdio),
        a protocol version that has elicitation, and a client that declared it
        can show a form.
        """
        if not isinstance(approver, ElicitationApprover):
            return approver.unavailable()
        with self._state:
            era, shows_forms, version = self._era, self._client_shows_forms, self._negotiated_version
        if era != _LEGACY or version is None:
            return "the session was not opened with initialize"
        if version not in ELICITATION_VERSIONS:
            return f"MCP protocol version {version} has no elicitation"
        if not shows_forms:
            return "the client did not declare that it can show an elicitation form"
        return None

    def _ask_on_this_machine(self, approver: ApprovalBackend, waiting: _WaitingCall) -> Answer:
        """Ask through a dialog or the operator's program, in a thread of its own.

        The answer is awaited only until the deadline, so a dialog or program
        that ignores its timeout cannot hold the call past it.
        """
        timeout = waiting.deadline - time.monotonic()
        if timeout <= 0 or waiting.cancelled:
            return self._await_answer(waiting)

        def ask() -> None:
            try:
                answer = approver.ask(waiting.request, timeout)
            except Exception as exc:  # a broken approver refuses
                answer = Answer(False, f"it failed: {printable(exc, limit=100)}", asked=False)
            self._take_answer(waiting, answer)

        threading.Thread(target=ask, name="agent-sentinel approver", daemon=True).start()
        return self._await_answer(waiting)

    def _ask_client(self, waiting: _WaitingCall) -> Answer:
        """Ask the client's user with an elicitation form; the answer arrives through _approval_answer.

        If no answer comes in time, the question is withdrawn with
        notifications/cancelled, so the form does not stay open.
        """
        request_id = APPROVAL_ID_PREFIX + token_hex(16)
        with self._state:
            version = self._negotiated_version or ""
            self._questions[request_id] = waiting
        timeout = max(1.0, waiting.deadline - time.monotonic())
        self._send(_Outcome(to_client=ElicitationApprover.question(request_id, waiting.request, timeout, version)))
        answer = self._await_answer(waiting)
        with self._state:
            unanswered = self._questions.pop(request_id, None) is not None
        if unanswered:
            withdrawn = {"requestId": request_id, "reason": "the call was refused before an answer came"}
            self._send(_Outcome(to_client={"jsonrpc": "2.0", "method": "notifications/cancelled", "params": withdrawn}))
        return answer

    def _take_answer(self, waiting: _WaitingCall, answer: Answer) -> None:
        """Record the first answer for a held call; a later one (after the timeout) is ignored."""
        with self._state:
            if waiting.answer is None:
                waiting.answer = answer
        waiting.answered.set()

    def _await_answer(self, waiting: _WaitingCall) -> Answer:
        """Wait until the call is answered or cancelled, or its deadline passes, and return the answer."""
        waiting.answered.wait(max(0.0, waiting.deadline - time.monotonic()))
        with self._state:
            if waiting.cancelled:
                return _CANCELLED
            if waiting.answer is None:  # from now on a late answer changes nothing
                waiting.answer = Answer(False, f"no answer within {self._approval_timeout:g} seconds")
            return waiting.answer

    def _released(self, waiting: _WaitingCall, final: Decision) -> _Outcome:
        """What to send once a held call has its final decision.

        An approved call is checked once more for what may have changed while
        it waited: a tool list that removed the tool, or the prompt (the
        firewall already checked the flow rules again). Then it is forwarded
        like any allowed request.
        """
        message = waiting.message
        if waiting.cancelled:
            return _DROP
        if not final.allowed:
            return self._refused(message, final)
        refusal = self._removed_while_waiting(message, waiting.label, final.call_id)
        if refusal is not None:
            return self._refused(message, refusal)
        self._report(f"approved {waiting.description} {proxy_report.rule_and_ref(waiting.pending)}: {final.reason}",
                     limit=1000)
        return self._forward_request(message, waiting.label, marks=self._marks_of(message), call_id=final.call_id)

    def _removed_while_waiting(self, message: JsonObject, label: str, call_id: str | None) -> Decision | None:
        """The refusal of an approved call whose tool, prompt, resource template or whole server (--pin-server)
        was quarantined while it waited."""
        method, params = message["method"], message["params"]
        if method in _RESOURCE_METHODS:
            return self._quarantined_read(params["uri"], call_id)
        if method == "tools/call":
            if not self._wait_for_tool_lists():
                reason = "timed out waiting for the tool list to be checked"
                return self._refusal(label, reason, RULE_QUARANTINE, call_id=call_id)
            if self._is_quarantined(params["name"]):
                return self._refusal(
                    label, "the tool was removed from the tool list while the call waited for approval",
                    RULE_QUARANTINE, public_reason="this tool was removed from the tool list and cannot be called",
                    call_id=call_id,
                )
        elif method == PROMPTS_GET and self._was_quarantined("prompts", params["name"]):
            return self._refused_prompt(params["name"], call_id)
        return None

    def _forward_request(
        self, message: JsonObject, label: str, marks: frozenset[str] = frozenset(), call_id: str | None = None,
    ) -> _Outcome:
        """Forward a client message, remembering a request so its reply can be matched and scanned."""
        if "id" not in message:
            return _Outcome(to_server=message)  # a notification: no reply will come
        modern = _is_modern_request(message)
        method = message["method"]
        cursor = _cursor_digest(message) if method in _LIST_ITEMS_KEY else None
        timeout = self._firewall.policy.call_timeout_seconds
        deadline = time.monotonic() + timeout if timeout is not None and method in _TIMED_METHODS else None
        with self._state:
            # A request that reuses an id still in flight never gets here (_id_in_flight).
            full = message["id"] not in self._pending and len(self._pending) >= MAX_PENDING_REQUESTS
            if not full:
                self._pending[message["id"]] = _PendingRequest(
                    method, label, marks, call_id, modern, cursor=cursor, deadline=deadline
                )
                if method == "tools/list":
                    self._tool_lists_in_flight.add(message["id"])
                if deadline is not None:
                    self._watch_deadline(message["id"], deadline)
        if full:
            event = "call" if message["method"] == "tools/call" else "client_request"
            refusal = self._firewall.refuse(
                label, "too many requests are waiting for a reply", event=event, rule=RULE_MALFORMED, call_id=call_id
            )
            return self._refused(message, refusal)
        return _Outcome(to_server=message)

    def _id_in_flight(self, msg_id: Any) -> bool:
        """Whether a request of the client's with this id still waits: forwarded and unanswered, or held for approval.

        An id is free again once its reply came, or once the client cancelled it.
        """
        with self._state:
            return msg_id in self._pending or any(
                waiting.message.get("id") == msg_id and not waiting.cancelled for waiting in self._waiting.values()
            )

    def _id_timed_out(self, msg_id: Any) -> bool:
        """Whether this id belongs to a forwarded request that timed out and whose late reply has not come."""
        with self._state:
            pending = self._pending.get(msg_id)
            return pending is not None and pending.timed_out

    def _refuse_timed_out_id(self, message: JsonObject) -> _Outcome:
        """Answer a request that reuses the id of one that timed out, with an error, without forwarding it.

        The client was told the first request timed out, so the id looks free
        to it; but the server may still answer the first, and that late reply
        would be taken for this one's. The id is free again once it came.
        """
        method = message["method"]
        decision = self._firewall.refuse(
            _label(method), f"{method} reuses the id of a request that timed out, whose late reply may still come",
            event="client_request", public_reason=_TIMED_OUT_ID_REFUSAL, rule=RULE_MALFORMED,
        )
        self._report(f"refused a '{method}' request that reuses the id of a request that timed out "
                     f"{proxy_report.rule_and_ref(decision)}")
        return _Outcome(to_client=_rpc_error(message["id"], decision.public_reason, code=protocol.INVALID_REQUEST))

    def _forget_cancelled_request(self, message: JsonObject) -> bool:
        """Forget a request the client cancelled. True when it was only held for approval, never forwarded.

        A held call that is cancelled is refused (its question, if one is
        showing, is left to time out) and no answer is sent for it. A call
        that timed out stays remembered: its id is not free until the server's
        late reply came (see _time_out).
        """
        params = message.get("params")
        request_id = params.get("requestId") if isinstance(params, dict) else None
        if not _valid_id(request_id):
            return False
        with self._state:
            waiting_reply = self._pending.get(request_id)
            forwarded = waiting_reply is not None
            if forwarded and not waiting_reply.timed_out:
                del self._pending[request_id]
            self._tool_lists_in_flight.discard(request_id)
            self._state.notify_all()
            held = [waiting for waiting in self._waiting.values() if waiting.message.get("id") == request_id]
            for waiting in held:
                waiting.cancelled = True
                waiting.answered.set()
        return bool(held) and not forwarded

    # ---- limits.call_timeout_seconds ----------------------------------------------------

    def _watch_deadline(self, msg_id: Any, deadline: float) -> None:
        """Have a forwarded call answered when its deadline passes. Called with `_state` held.

        One thread (_watch_deadlines) waits for the soonest deadline; it is
        started when the first call is timed and ends when none is left. The
        heap keeps an entry for a call answered in time until its deadline
        passes; it is rebuilt from the waiting calls if it grows past twice
        MAX_PENDING_REQUESTS.
        """
        heapq.heappush(self._deadlines, (deadline, next(self._deadline_order), msg_id))
        if len(self._deadlines) > 2 * MAX_PENDING_REQUESTS:
            self._deadlines = [(pending.deadline, next(self._deadline_order), key)
                               for key, pending in self._pending.items()
                               if pending.deadline is not None and not pending.timed_out]
            heapq.heapify(self._deadlines)
        if self._watching_deadlines:
            self._deadline_wake.set()  # the new deadline may be the soonest
            return
        self._watching_deadlines = True
        threading.Thread(target=self._watch_deadlines, name="agent-sentinel call timeout", daemon=True).start()

    def _watch_deadlines(self) -> None:
        """Answer each forwarded call whose time ran out (_time_out); return when no call is timed any more."""
        while True:
            with self._state:
                self._deadline_wake.clear()  # a deadline added from now on wakes the wait below
                now = time.monotonic()
                expired = self._take_expired(now)
                if not expired and not self._deadlines:
                    self._watching_deadlines = False
                    return
                wait = self._deadlines[0][0] - now if self._deadlines else 0.0
            for msg_id, pending in expired:
                self._time_out(msg_id, pending)
            if not expired:
                self._deadline_wake.wait(min(max(wait, 0.001), 1.0))

    def _take_expired(self, now: float) -> list[tuple[Any, _PendingRequest]]:
        """The forwarded calls whose deadline has passed, each marked as timed out. Called with `_state` held.

        A timed-out call stays among the requests waiting for a reply, so that
        its id is not taken by a new request while the server may still
        answer it (a late reply would be taken for the new request's), and so
        that it counts against MAX_PENDING_REQUESTS. In monitor mode the call
        is only recorded, and goes on waiting.
        """
        expired = []
        while self._deadlines and self._deadlines[0][0] <= now:
            _, _, msg_id = heapq.heappop(self._deadlines)
            pending = self._pending.get(msg_id)
            if pending is None or pending.timed_out or pending.deadline is None or pending.deadline > now:
                continue  # answered in time, or the id now belongs to a later request
            changed = {"deadline": None} if self._firewall.monitor else {"timed_out": True}
            self._pending[msg_id] = dataclasses.replace(pending, **changed)
            expired.append((msg_id, pending))
        return expired

    def _time_out(self, msg_id: Any, pending: _PendingRequest) -> None:
        """Answer a call the server did not answer in time with an error, and cancel it at the server.

        The record has event "timeout" and rule limits.call_timeout_seconds.
        The reply the server may still send is dropped (_check_server_reply).
        Monitor mode records what would have happened, and the call goes on waiting.
        """
        try:
            seconds = self._firewall.policy.call_timeout_seconds or 0
            reason = f"the server did not answer within {seconds:g} seconds, so the call was cancelled"
            decision = self._firewall.block(
                pending.label, reason, event="timeout", public_reason=_TIMEOUT_REFUSAL, rule=RULE_CALL_TIMEOUT,
                call_id=pending.call_id,
            )
            what = f"timed out waiting for {_reply_description(pending)}"
            if decision.allowed:  # monitor mode
                self._report_allowed(what, decision)
                return
            self._report_block(what, decision)
            cancel = {"jsonrpc": "2.0", "method": "notifications/cancelled",
                      "params": {"requestId": msg_id, "reason": "the request timed out"}}
            self._send(_Outcome(to_server=cancel,
                                to_client=_rpc_error(msg_id, decision.public_reason, code=TIMEOUT_ERROR_CODE)))
        except (OSError, ValueError):  # the client or the server has gone; the proxy is stopping
            pass
        except Exception as exc:  # a bug here must not stop the thread that times out the other calls
            _warn(f"could not answer a call that timed out, after an internal error: {exc!r}")

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
        """Whether a call to this tool must be refused because the tool cannot be vouched for."""
        with self._state:
            # No tool can be vouched for if more were quarantined than can be remembered, if the last tool
            # list could not be checked at all, or if the server is no longer the one that was pinned.
            return (self._quarantine_overflowed or self._tools_unverified or self._server_quarantine is not None
                    or tool in self._quarantined["tools"])

    def _was_quarantined(self, kind: str, name: str) -> bool:
        """Whether this entry of a list (tools, prompts, resourceTemplates) was itself quarantined."""
        with self._state:
            return self._quarantine_overflowed or self._server_quarantine is not None or name in self._quarantined[kind]

    def quarantine_server(self, reason: str) -> None:
        """Quarantine the whole server, for as long as the proxy runs (see "Lists, pins and names").

        For a server that differs from its pin (proxy --pin-server): every
        entry of its lists is left out, its instructions are removed (and not
        pinned), calls, prompts, resource reads and subscriptions are refused,
        and so is every other client request but the handshake, ping, the
        lists and logging/setLevel (_refused_by_server_quarantine); every
        request the server sends the client but ping is refused, and every
        notification but notifications/cancelled is dropped.
        """
        with self._state:
            if self._server_quarantine is None:
                self._server_quarantine = reason

    def _whole_server_quarantined(self) -> str | None:
        """Why the whole server is quarantined (quarantine_server), or None."""
        with self._state:
            return self._server_quarantine

    def _set_tools_unverified(self, unverified: bool) -> None:
        with self._state:
            if unverified and not self._tools_unverified:
                self._report("the tool list could not be checked; tool calls are refused until a valid list arrives")
            self._tools_unverified = unverified

    def _quarantine(self, kind: str, name: str, templates: Iterable[str] = ()) -> None:
        """Quarantine an entry by name; for a resource template, also the uriTemplates it is known by (templates)."""
        with self._state:
            for template in templates:
                if template in self._quarantined_templates or self._templates_overflowed:
                    continue
                if len(self._quarantined_templates) < MAX_QUARANTINED_TEMPLATES:
                    self._quarantined_templates[template] = uri_template.literal_parts(template)
                else:
                    self._templates_overflowed = True
                    self._report("too many quarantined resource templates to track; every resource read is now "
                                 "refused")
            if sum(len(names) for names in self._quarantined.values()) < MAX_QUARANTINED:
                self._quarantined[kind].add(name)
            elif not self._quarantine_overflowed:
                self._quarantine_overflowed = True
                self._report("too many quarantined entries to track; all tool calls and prompts are now refused")

    def _first_report(self, *key: str) -> bool:
        """True the first time `key` comes up, so that a line about it is printed once, not at every listing.

        Past MAX_REPORTED keys every line is printed again: noisy, but nothing is hidden.
        """
        with self._state:
            if key in self._reported:
                return False
            if len(self._reported) < MAX_REPORTED:
                self._reported.add(key)
            return True

    def _internal_error_outcome(self, message: Any) -> _Outcome:
        """Tell the client its request failed, so it is not left waiting."""
        if isinstance(message, dict) and isinstance(message.get("method"), str) and _valid_id(message.get("id")):
            text = self._internal_error_text(_label(message["method"]), "client_request", "the request")
            return _Outcome(to_client=_rpc_error(message["id"], text))
        return _DROP

    def _internal_error_text(self, label: str, event: str, what: str) -> str:
        """Record a refusal after an internal error; return what the agent is told, with the record's ref.

        The error itself is already on stderr. If even the record cannot be
        written, the agent is told the same without a ref.
        """
        public = f"internal error while checking {what}"
        try:
            return self._firewall.refuse(
                label, f"refused after an internal error while checking {what}", event=event, public_reason=public,
                rule=RULE_MALFORMED,
            ).public_reason
        except Exception:  # the record is a courtesy; the refusal stands without it
            return public

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
        problem = self._server_request_problem(method, msg_id) if is_request else None
        if problem is not None:
            # Not a policy decision, so monitor mode does not lift it.
            refusal = self._firewall.refuse(label, problem, event="server_request", rule=RULE_MALFORMED)
            self._report_block(f"refused a '{printable(method, limit=100)}' request from the server", refusal)
            return _Outcome(to_server=_rpc_error(msg_id, _SERVER_REFUSAL, code=protocol.METHOD_NOT_FOUND))
        allowed = ("ping",) if is_request else _TOLD_BY_A_QUARANTINED_SERVER
        quarantined = self._whole_server_quarantined() if method not in allowed else None
        if quarantined is not None:  # a server that differs from its pin tells the client nothing (--pin-server)
            refusal = self._firewall.refuse(label, f"the whole server is quarantined: {quarantined}",
                                            event="server_request", rule=RULE_QUARANTINE)
            kind = "request" if is_request else "notification"
            self._report_block(f"refused a '{printable(method, limit=100)}' {kind} from the quarantined server",
                               refusal)
            return _Outcome(to_server=_rpc_error(msg_id, _SERVER_REFUSAL)) if is_request else _DROP

        verdict = self._firewall.policy.server_request_verdict(method)
        decision = None
        if verdict.action == "block":
            rule = verdict.rule or RULE_MALFORMED
            decision = self._firewall.block(label, verdict.reason, "server_request", rule=rule)
        elif method == elicitation.ELICITATION_CREATE:
            decision = self._elicitation_refusal(label, message.get("params"))
        elif method == SAMPLING_CREATE:
            decision = self._sampling_refusal(label, message.get("params"))
        if decision is None:
            decision = self._firewall.scan_result(label, message, event="server_request", log_clean=False)
        if decision.allowed:
            if is_request:
                self._expect_client_reply(msg_id, method)
            elif method == "notifications/cancelled":
                self._forget_cancelled_server_request(message)
            return _Outcome(to_client=message)
        self._report_block(f"refused a '{printable(method, limit=100)}' message from the server", decision)
        if is_request:
            # Answer so the server is not left waiting, without saying which check it failed.
            return _Outcome(to_server=_rpc_error(msg_id, _SERVER_REFUSAL))
        return _DROP

    def _server_request_problem(self, method: str, msg_id: str | int) -> str | None:
        """Why the protocol does not let the server send this request, or None (then the policy decides).

        An id that begins like the ids of the proxy's own approval questions is
        refused, so that the client's answer to a server request can never be
        taken for an answer to an approval question.
        """
        if isinstance(msg_id, str) and msg_id.startswith(APPROVAL_ID_PREFIX):
            return "the request uses an id reserved for the proxy's own requests"
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
        if pending.timed_out:
            # The client was told the call timed out, and the server was told to cancel it.
            return self._dropped(f"a late server reply to {pending.method} '{pending.label}', which had timed out")
        try:
            return _Outcome(to_client=self._checked_reply(message, pending))
        except Exception as exc:
            _warn(f"blocked a server reply after an internal error: {exc!r}")
            text = self._internal_error_text(pending.label, "result", "the reply")
            return _Outcome(to_client=_rpc_error(msg_id, text))
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
            refusal = self._url_elicitation_refusal(pending, msg_id, message["error"])
            if refusal is not None:
                return refusal
            return self._deliver_or_block(pending, msg_id, "error", message["error"])

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
            if result.get("nextCursor") is not None and not isinstance(result["nextCursor"], str):
                # MCP's cursors are strings, and the boundary scan follows a chain by the string the client echoes.
                return self._malformed_reply(pending, msg_id, "the nextCursor of a list reply must be a string")
            if items_key in result:
                result[items_key] = self._clean_items(result[items_key], items_key)
                result[items_key] = self._checked_page_boundary(pending, items_key, result[items_key])
                if is_tool_list:
                    self._set_tools_unverified(False)
                # The entries were checked one by one. What is left is scanned as a
                # whole below, because a phrase can be split over two entries.
        elif pending.method in (protocol.INITIALIZE, protocol.SERVER_DISCOVER):
            refusal = self._check_handshake_reply(pending, msg_id, result)
            if refusal is not None:
                return refusal
        delivered = self._deliver_or_block(pending, msg_id, "result", result, log_clean=items_key is None)
        if items_key is not None:
            self._remember_page_end(pending, items_key, delivered)
        return delivered

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
        return self._deliver_or_block(pending, msg_id, "result", result)

    def _check_input_request(self, entry: JsonObject, pending: _PendingRequest) -> Decision:
        """The policy's answer for one entry of an input_required result, then what an elicitation asks, then a scan."""
        method = entry["method"]
        label = _label(f"server:{method}")
        verdict = self._firewall.policy.server_request_verdict(method)
        decision = None
        if verdict.action == "block":
            decision = self._firewall.block(
                label, verdict.reason, event="server_request", public_reason=_INPUT_REFUSAL,
                rule=verdict.rule or RULE_MALFORMED, call_id=pending.call_id,
            )
        elif method == elicitation.ELICITATION_CREATE:
            decision = self._elicitation_refusal(label, entry.get("params"), pending.call_id)
        elif method == SAMPLING_CREATE:
            decision = self._sampling_refusal(label, entry.get("params"), pending.call_id)
        if decision is None:
            decision = self._firewall.scan_result(
                label, entry, event="server_request", log_clean=False, call_id=pending.call_id
            )
        if not decision.allowed:
            self._report_block(
                f"refused a reply to {pending.method} that asks the client for '{printable(method, limit=100)}'",
                decision,
            )
        return decision

    def _elicitation_refusal(self, label: str, params: Any, call_id: str | None = None) -> Decision | None:
        """Check what an elicitation asks the user (elicitation.review_request); the refusal, or None to go on.

        A refusal for what is asked (an address that may not be opened, a form
        that asks for a password) is a block that monitor mode lifts; one for a
        shape that cannot be checked always holds. Fields that only sometimes
        mean a secret are reported to the operator and let through.
        """
        try:
            review = elicitation.review_request(params, self._elicitation_hosts)
        except ShapeError as exc:
            return self._firewall.refuse(
                label, f"malformed elicitation: {exc}", event="server_request", public_reason=_INPUT_REFUSAL,
                rule=RULE_MALFORMED, call_id=call_id,
            )
        for field in review.unclear:
            reason = f"the elicitation asks for {field}, which may be a secret"
            self._firewall.note(label, reason, event="server_request", call_id=call_id)
            self._report(reason)
        if review.refusal is None:
            return None
        decision = self._firewall.block(
            label, review.refusal, event="server_request", public_reason=_INPUT_REFUSAL, rule=review.rule,
            call_id=call_id,
        )
        return None if decision.allowed else decision

    def _sampling_refusal(self, label: str, params: Any, call_id: str | None = None) -> Decision | None:
        """Check a sampling request the policy lets through; the refusal, or None to go on (then it is scanned).

        The client's answer to sampling/createMessage is text its model wrote,
        and it goes to the server, so:

        * a request whose includeContext is present and not "none" is refused:
          it asks the client to put the conversation (or what other servers
          sent) into what the model reads, so the answer could carry it out.
          The value is deprecated in MCP 2026-07-28;
        * once the session holds every "after" mark of a "block" flow whose
          "then" is "sink", the request is refused as a call to a sink would
          be (Policy.sampling_flow_verdict). The marks are read again here.

        Both are blocks that monitor mode lifts.
        """
        if isinstance(params, dict) and "includeContext" in params and params["includeContext"] != "none":
            asked = params["includeContext"]
            shown = f"'{printable(asked, limit=40)}'" if isinstance(asked, str) else type_name(asked)
            reason = (f"the sampling request asks for includeContext {shown}: the client's model would answer from "
                      "the conversation, and the answer would go to the server")
            decision = self._firewall.block(label, reason, event="server_request", public_reason=_INPUT_REFUSAL,
                                            rule=RULE_INCLUDE_CONTEXT, call_id=call_id)
            if not decision.allowed:
                return decision
        policy = self._firewall.policy
        if not policy.flows:
            return None
        flow = policy.sampling_flow_verdict(self._firewall.session_marks())
        if flow is None:
            return None
        decision = self._firewall.block(label, flow.reason, event="server_request", public_reason=_INPUT_REFUSAL,
                                        rule=flow.rule or RULE_MALFORMED, call_id=call_id)
        return None if decision.allowed else decision

    def _url_elicitation_refusal(self, pending: _PendingRequest, msg_id: Any, error: Any) -> JsonObject | None:
        """The refusal of an error reply that sends the user to an address that may not be opened, or None.

        Only a URLElicitationRequiredError (-32042) does: its data lists URL-mode
        elicitations the client is to show before it retries the request.
        """
        try:
            review = elicitation.review_url_required_error(error, self._elicitation_hosts)
        except ShapeError as exc:
            return self._malformed_reply(pending, msg_id, str(exc))
        if review.refusal is None:
            return None
        decision = self._firewall.block(
            pending.label, review.refusal, event="result", public_reason=_INPUT_REFUSAL, rule=review.rule,
            call_id=pending.call_id,
        )
        if decision.allowed:  # monitor mode
            return None
        self._report_block(f"refused a reply to {pending.method}", decision)
        return _refusal_reply(pending.method, msg_id, decision.public_reason, pending.modern)

    def _check_handshake_reply(self, pending: _PendingRequest, msg_id: Any, result: Any) -> JsonObject | None:
        """Check what a server says about itself in reply to initialize or server/discover; a refusal, or None.

        * The protocol version must be one the proxy knows: initialize's
          `protocolVersion` a legacy version; server/discover's
          `supportedVersions` is cut down to the versions the proxy knows, and
          must keep at least one.
        * Tasks are removed from the server's capabilities, so that the client
          does not start one.
        * Unsafe icons are removed from the serverInfo.
        * Instructions that look like an injection, or that changed since they
          were pinned, are removed.
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
        meta = result.get("_meta")
        if self._pin_server:
            refusal = self._check_server_info(pending, msg_id, result)
            if refusal is not None:
                return refusal
        for server_info in (result.get("serverInfo"), meta.get(_SERVER_INFO_KEY) if isinstance(meta, dict) else None):
            if isinstance(server_info, dict) and "icons" in server_info:
                self._clean_icons_of(server_info, f"the server, in its reply to {pending.method}")
        self._check_instructions(result, source=pending.method)
        with self._state:
            if pending.method == protocol.INITIALIZE:
                # The version both sides now speak: it decides whether the client can be asked in a form.
                self._negotiated_version = result["protocolVersion"]
            elif pending.method == protocol.SERVER_DISCOVER and self._era is None:
                self._era = _MODERN
        return None

    def _check_server_info(self, pending: _PendingRequest, msg_id: Any, result: JsonObject) -> JsonObject | None:
        """With --pin-server: compare the serverInfo of a handshake reply with the server's pin; a refusal, or None.

        The first serverInfo is pinned (pins.ToolPins.check_server_info). One
        that differs quarantines the whole server (quarantine_server), and
        with --on-server-change refuse (the default) the reply is refused
        too. In monitor mode the change is logged and nothing happens.
        """
        meta = result.get("_meta")
        server_info = result.get("serverInfo")
        if not isinstance(server_info, dict) and isinstance(meta, dict):
            server_info = meta.get(_SERVER_INFO_KEY)
        server_info = server_info if isinstance(server_info, dict) else {}
        status, changed = self._pins.check_server_info({"name": server_info_value(server_info.get("name")),
                                                        "version": server_info_value(server_info.get("version"))})
        self._save_pins()
        if status != CHANGED:
            return None
        what = f"its serverInfo ({', '.join(changed)}) changed since it was pinned"
        reason = f"the server is quarantined: {what}. {server_change_advice(self._pins.path)}"
        decision = self._firewall.block(pending.label, reason, event="server_changed", rule=RULE_QUARANTINE,
                                        call_id=pending.call_id)
        if decision.allowed:  # monitor mode: logged as what would have been blocked
            return None
        self.quarantine_server(what)
        self._report_block("quarantined every tool, prompt and resource template of the server", decision)
        if self._on_server_change == SERVER_CHANGE_QUARANTINE:
            return None
        return _rpc_error(msg_id, decision.public_reason)

    def _malformed_reply(self, pending: _PendingRequest, msg_id: Any, reason: str) -> JsonObject:
        decision = self._firewall.refuse(
            pending.label, f"malformed reply: {reason}", event="result",
            public_reason=_MALFORMED_REPLY, rule=RULE_MALFORMED, call_id=pending.call_id,
        )
        self._report(f"blocked a malformed reply to {pending.method}: {reason} {proxy_report.rule_and_ref(decision)}")
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
        self._report(f"blocked a reply to {pending.method}: {reason} {proxy_report.rule_and_ref(decision)}")
        return _rpc_error(msg_id, decision.public_reason, code=code)

    def _deliver_or_block(
        self, pending: _PendingRequest, msg_id: Any, member: str, value: Any, log_clean: bool = True
    ) -> JsonObject:
        """The reply to deliver for the `result` or `error` the server sent: built from what was checked, or a refusal.

        The value passes Firewall.check_result: the scanner, and the policy's
        secrets.in_results, which with "redact" gives a copy with the secrets
        replaced. It is then cleaned of hidden characters (_checked_for_forwarding).
        The reply holds that checked copy, never `value` itself. The flow
        marks of the request are set just before the reply is returned.
        """
        checked = self._checked_for_forwarding(pending.label, value, "result", log_clean, pending.call_id)
        decision = checked.decision
        if not decision.allowed:
            self._report_block(f"blocked {_reply_description(pending)}", decision)
        else:
            if decision.redacted:
                self._report(f"replaced what looks like a secret ({', '.join(decision.redacted)}) in "
                             f"{_reply_description(pending)} [rule {RULE_SECRETS_IN_RESULTS}]")
            decision = self._mark_delivered(pending)  # reports a reply it withholds
        if decision.allowed:
            return {"jsonrpc": "2.0", "id": msg_id, member: checked.content}
        return _refusal_reply(pending.method, msg_id, decision.public_reason, pending.modern)

    def _checked_for_forwarding(
        self, label: str, value: Any, event: str, log_clean: bool, call_id: str | None = None,
        foreign_tools: Iterable[str] = (),
    ) -> CheckedResult:
        """Check something the server sent (Firewall.check_result), and return the copy that may be forwarded.

        The copy is cleaned of what can hide or disguise text from the person
        who reads it: terminal escape sequences, control characters, Unicode
        tag characters and bidi overrides (textutil.clean_value_for_forwarding).
        The value is checked as the server sent it first, because hidden tag
        text is read there, and an injection written in it is refused. If
        cleaning changed anything, the cleaned copy is checked as well, since
        removing a character joins the text on either side of it: what is
        forwarded is always what was checked. (Pins are taken earlier, of
        what the server sent.)
        """
        checked = self._firewall.check_result(
            label, value, event=event, log_clean=log_clean, call_id=call_id, foreign_tools=foreign_tools
        )
        if not checked.decision.allowed:
            return checked
        try:
            cleaned = clean_value_for_forwarding(checked.content)
        except UnscannableError as exc:
            refusal = self._firewall.refuse(
                label, f"the content could not be cleaned for forwarding: {exc}", event=event,
                public_reason=_UNCHECKED_CONTENT, rule=RULE_UNSCANNABLE, call_id=call_id,
            )
            return CheckedResult(refusal)
        if cleaned == checked.content:
            return checked
        again = self._firewall.check_result(
            label, cleaned, event=event, log_clean=False, call_id=call_id, foreign_tools=foreign_tools
        )
        if not again.decision.allowed or not checked.decision.redacted:
            return again
        # Both checks replaced secrets, or only the first: the reply should name every kind replaced.
        kinds = tuple(dict.fromkeys([*checked.decision.redacted, *again.decision.redacted]))
        return CheckedResult(dataclasses.replace(again.decision, redacted=kinds), again.content)

    def _mark_delivered(self, pending: _PendingRequest) -> Decision:
        """Set the flow marks of a reply that is about to be delivered; a refusal if they cannot be recorded.

        An error reply sets them too: its text reaches the agent like a result.
        """
        try:
            self._firewall.mark_delivered(pending.label, pending.marks)
        except SessionStateError as exc:
            decision = self._firewall.withhold(pending.label, exc, call_id=pending.call_id)
            self._report_block(f"withheld a reply to {pending.method}", decision)
            return decision
        return Decision(True, "delivered", call_id=pending.call_id)

    def _check_instructions(self, result: JsonObject, source: str) -> None:
        """Remove the server's `instructions` (from initialize or server/discover) if they look like an injection,
        or if they changed since they were pinned.

        Clients commonly place these instructions in the model's system
        prompt, which makes them the most direct injection route a server has.
        Removing the field keeps the connection usable. Instructions that stay
        are forwarded cleaned of hidden characters (_checked_for_forwarding);
        the pin is taken of the text as the server sent it.

        Instructions are text. Anything else (a list, an object) is removed
        without being forwarded: the stricter checks and the pin are made for
        text, and a lenient client might still show the model what is inside.
        A null is removed too; it says nothing.

        A server that differs from its pin (quarantine_server) cannot be
        vouched for, so its instructions are removed whatever they say, and
        are never pinned: they would steer the model, and become the baseline
        its later instructions are compared with.
        """
        if "instructions" not in result:
            return
        instructions = result["instructions"]
        if instructions is None:
            del result["instructions"]
            return
        quarantined = self._whole_server_quarantined()
        if quarantined is not None:
            del result["instructions"]
            decision = self._firewall.refuse(source, f"the whole server is quarantined: {quarantined}",
                                             event="server_instructions", rule=RULE_QUARANTINE)
            self._report_block("removed the instructions of the quarantined server", decision)
            return
        if not isinstance(instructions, str):
            del result["instructions"]
            reason = f"the server's instructions are not text but {type_name(instructions)}"
            decision = self._firewall.refuse(source, reason, event="server_instructions", rule=RULE_MALFORMED)
            self._report_block("removed the server's instructions", decision)
            return
        # No foreign tool names: the server's own tools are not known yet, and its
        # instructions name them ("call get_me first").
        checked = self._checked_for_forwarding(source, instructions, "server_instructions", log_clean=True)
        decision = checked.decision
        if decision.allowed:
            decision = self._check_instructions_pin(source, instructions)
        if decision.allowed:
            result["instructions"] = checked.content
        else:
            del result["instructions"]
            self._report_block("removed the server's instructions", decision)

    def _check_instructions_pin(self, source: str, instructions: str) -> Decision:
        status = self._pins.check_instructions(instructions)
        self._save_pins()
        if status == CHANGED:
            reason = f"they changed after they were first seen. {self._how_to_accept('instructions')}"
            return self._firewall.block(source, reason, event="instructions_changed", rule=RULE_QUARANTINE)
        return Decision(True, "the instructions are unchanged or new")

    def _how_to_accept(self, kind: str, name: str | None = None) -> str:
        """What the operator can do about a pinned definition that changed: the end of a quarantine reason.

        With a pins file, the proxy keeps the new definition beside it (see
        pins.py, "Changes waiting"), so the change can be looked at and
        accepted with the pins command. Either way the entry stays removed
        until the proxy restarts. The server's name for the entry goes into
        the command only when no shell can read anything into it (_SHELL_SAFE_NAME).
        """
        if self._pins.path is None:
            return "If the change is expected, restart the proxy"
        command = ["agent-sentinel", "pins", "diff", "--pins", str(self._pins.path)]
        if kind != "tools":
            command += ["--kind", KIND_WORDS[kind]]
        if name is not None and _SHELL_SAFE_NAME.fullmatch(name):
            command.append(name)
        return (f"If the change is expected, review it with: {proxy_report.shell_line(command)}; "
                "then pins accept, and restart the proxy")

    def _clean_items(self, items: list[Any], items_key: str) -> list[Any]:
        """Return the entries of a list (tools, prompts, resources, resourceTemplates) that are safe to show.

        1. Unsafe icons are dropped from every entry; the entry stays.
        2. Names that collide are found for the list as a whole (_name_collisions).
        3. Each entry is checked on its own (_problem_with_item).
        4. Tools the policy blocks outright are hidden, now that every tool
           has been scanned and pinned (_without_blocked_tools).
        """
        for item in items:
            if isinstance(item, dict) and "icons" in item:
                name = item.get("name")
                self._clean_icons_of(item, f"'{_label(name) if _is_name(name) else '?'}' in the {items_key} list")
        collisions, repeats = self._name_collisions(items, items_key)
        foreign = self._foreign_tools(items) if items_key == "tools" else frozenset()
        kept = []
        for position, item in enumerate(items):
            if position in repeats:
                continue  # the very same entry listed again: forwarded once
            name = item.get("name") if isinstance(item, dict) else None
            label = _label(name) if _is_name(name) else "?"
            collision = collisions.get(name) if label != "?" else None
            problem, forwarded = self._problem_with_item(item, label, items_key, collision, foreign)
            if problem is None:
                kept.append(forwarded)
            else:
                self._report(f"removed '{label}' from the {items_key} list: {problem}", limit=1000)
        if items_key in PINNED_LISTS:
            self._save_pins()
        if items_key == "tools":
            kept = self._without_blocked_tools(kept)
        return kept

    def _foreign_tools(self, tools: list[Any]) -> frozenset[str]:
        """The names of other servers' tools, for the shadowing check of this list's descriptions.

        A description that gives orders about another server's tool ("when
        send_email is called, bcc ...") is tool shadowing. The proxy sees one
        server, so it takes the tool names the policy writes out in full
        (Firewall.foreign_tool_names), less every name this server has
        listed in this process, lists now, or has pinned: its own tools refer
        to each other all the time.
        """
        listed = {tool["name"] for tool in tools if isinstance(tool, dict) and _is_name(tool.get("name"))}
        with self._state:
            for name in listed - self._listed_tools:
                if len(self._listed_tools) >= MAX_KNOWN_NAMES:
                    break
                self._listed_tools.add(name)
            own = listed | self._listed_tools
        return self._firewall.foreign_tool_names(own | set(self._pins.names("tools")))

    def _clean_icons_of(self, item: JsonObject, whose: str) -> None:
        """Drop the icons of an entry (or of the server) that are not safe to forward (mcp_protocol.clean_icons).

        whose: the entry, for the stderr line ("'search_web' in the tools list"); each is reported once.
        """
        kept, dropped = protocol.clean_icons(item["icons"])
        if kept:
            item["icons"] = kept
        else:
            del item["icons"]
        if dropped and self._first_report("icons", whose):
            self._report(f"dropped {len(dropped)} icon(s) of {whose}: {dropped[0]}")

    def _name_collisions(self, items: list[Any], kind: str) -> tuple[dict[str, tuple[str, str, bool]], set[int]]:
        """Find the names of a list that collide: {name: (reason, audit event, whether monitor mode may lift it)},
        and the positions of entries that repeat an earlier one exactly, to be dropped.

        * A name listed twice with two different definitions (tools, prompts,
          templates): the client could use either, so both are refused, and
          monitor mode does not lift that.
        * A name that looks like another name of the server (tools and
          prompts, unless --tool-names off): see _NameRegistry.
        """
        if kind not in PINNED_LISTS:
            return {}, set()
        definitions: dict[str, str] = {}
        collisions: dict[str, tuple[str, str, bool]] = {}
        repeats: set[int] = set()
        entry = _ENTRY_NAME[kind]
        for position, item in enumerate(items):
            name = item.get("name") if isinstance(item, dict) else None
            if not _is_name(name):
                continue
            definition = fingerprint(definition_of(kind, item))
            if name not in definitions:
                definitions[name] = definition
            elif definitions[name] == definition:
                repeats.add(position)
            else:
                collisions[name] = ("the list has two different entries with this name", f"{entry}_name", False)
        if kind in _NAMED_LISTS and self._tool_names != TOOL_NAMES_OFF:
            def follows_rules(name: str) -> bool:
                return protocol.tool_name_problem(name) is None

            # With strict, a name that breaks the rules is removed anyway, so it must not claim a skeleton.
            names = [name for name in definitions if name not in collisions
                     and (self._tool_names != TOOL_NAMES_STRICT or follows_rules(name))]
            for name, reason in self._names[kind].lookalikes(names, follows_rules).items():
                collisions[name] = (reason, f"{entry}_lookalike", True)
        return collisions, repeats

    def _problem_with_item(
        self, item: Any, label: str, kind: str, collision: tuple[str, str, bool] | None = None,
        foreign_tools: Iterable[str] = (),
    ) -> tuple[str | None, Any]:
        """Why a list entry must be removed (None if it may stay), and the entry to forward in its place.

        In order: its shape, an earlier quarantine, its name (collision from
        _name_collisions, characters that cannot be forwarded, the naming
        rules), the scanner (a tool's description with the names of other
        servers' tools, `foreign_tools`, to catch shadowing), its pin. The
        entry forwarded is the copy cleaned of hidden characters, checked too
        (_checked_for_forwarding); the pin is taken of the entry as the server
        sent it. A tool, prompt or template that is removed is quarantined.
        """
        pinned = kind in PINNED_LISTS
        if not isinstance(item, dict) or (pinned and label == "?"):
            return "it is not a well-formed entry", None
        with self._state:
            server_quarantine = self._server_quarantine
        if server_quarantine is not None:  # resources too: none of them can be read
            return f"the whole server is quarantined: {server_quarantine}", None
        if pinned and self._was_quarantined(kind, item["name"]):
            # Even if it looks clean now. A template's uriTemplate as listed now is refused too.
            self._quarantine(kind, item["name"], self._template_texts(kind, item))
            return "it was quarantined earlier", None

        decision = self._check_name(item, label, kind, collision)
        forwarded = None
        if decision.allowed:
            event = "tool_description" if kind == "tools" else "list_item"
            checked = self._checked_for_forwarding(label, item, event, log_clean=False, foreign_tools=foreign_tools)
            decision, forwarded = checked.decision, checked.content
        if decision.allowed and pinned:
            decision = self._check_pin(kind, item, label)
        if decision.allowed:
            if kind == "tools":
                # Annotations are pinned with the rest of the tool, and they can only add flow labels.
                self._firewall.learn_annotations(item["name"], item.get("annotations"))
            return None, forwarded
        if pinned:
            # Remember the name: the agent may already know it from an
            # earlier list, and the server may list it again looking clean.
            # A resource template's URIs cannot be read either (_template_refusal).
            self._quarantine(kind, item["name"], self._template_texts(kind, item))
        return decision.reason, None

    def _template_texts(self, kind: str, item: Any) -> list[str]:
        """The uriTemplates a resource template is known by: as listed now, and as pinned (as first seen)."""
        if kind != "resourceTemplates" or not isinstance(item, dict):
            return []
        found = [item.get("uriTemplate")]
        if _is_name(item.get("name")):
            pinned = self._pins.definition(kind, item["name"])
            found.append(pinned.get("uriTemplate") if pinned is not None else None)
        return list(dict.fromkeys(text for text in found if isinstance(text, str)))

    def _check_name(self, item: JsonObject, label: str, kind: str, collision: tuple[str, str, bool] | None) -> Decision:
        """The verdict on an entry's name: a collision, then hidden characters, then the MCP naming rules.

        An entry whose name (or URI) would change when it is cleaned for
        forwarding is refused in every mode: the client would ask for it by a
        name the server does not know, or by the name of another entry. A
        name outside the MCP naming rules (tools and prompts) is refused with
        --tool-names strict; with warn it is kept and reported, once, on
        stderr and in the audit log.
        """
        if collision is not None:
            reason, event, may_lift = collision
            if may_lift:
                return self._firewall.block(label, reason, event=event, rule=RULE_QUARANTINE)
            return self._firewall.refuse(label, reason, event=event, rule=RULE_QUARANTINE)
        hiding = [member for member in _ASKED_FOR_BY[kind]
                  if isinstance(item.get(member), str) and clean_for_forwarding(item[member]) != item[member]]
        if hiding:
            reason = (f"its {hiding[0]} has characters the proxy does not forward (controls, escapes, tag or bidi "
                      "characters), so the client could not ask for it as the server knows it")
            return self._firewall.refuse(label, reason, event=f"{_ENTRY_NAME[kind]}_name", rule=RULE_MALFORMED)
        if kind not in _NAMED_LISTS or self._tool_names == TOOL_NAMES_OFF:
            return Decision(True, "the name is not checked")
        problem = protocol.tool_name_problem(item["name"])
        if problem is None:
            return Decision(True, "the name follows the MCP naming rules")
        reason = f"its name breaks the MCP naming rules: {problem}"
        event = f"{_ENTRY_NAME[kind]}_name"
        if self._tool_names == TOOL_NAMES_STRICT:
            return self._firewall.block(label, reason, event=event, rule=RULE_QUARANTINE)
        if self._first_report("name", kind, item["name"]):
            self._firewall.note(label, f"{reason} (kept: --tool-names warn)", event=event)
            self._report(f"the name of '{label}' in the {kind} list breaks the MCP naming rules: {problem}; "
                         "it is kept (--tool-names strict would remove it)")
        return Decision(True, reason)

    def _check_pin(self, kind: str, item: JsonObject, label: str) -> Decision:
        status = self._pins.check_item(kind, item["name"], item)
        if status == CHANGED:
            what = _ENTRY_NAME[kind].replace("_", " ")
            reason = (
                f"{what} quarantined: its definition changed after it was first seen. "
                f"{self._how_to_accept(kind, item['name'])}"
            )
            return self._firewall.block(label, reason, event=f"{_ENTRY_NAME[kind]}_changed", rule=RULE_QUARANTINE)
        if status == FULL:
            # Logged like every other removal, with a ref, so that `explain` and `report` can say why.
            return self._firewall.refuse(label, f"too many {kind} to keep track of",
                                         event=f"{_ENTRY_NAME[kind]}_pins_full", rule=RULE_QUARANTINE)
        return Decision(True, "the definition is unchanged or new")

    def _save_pins(self) -> None:
        try:
            self._pins.save()
        except OSError as exc:
            _warn(f"cannot save the pins file: {exc}")

    def _without_blocked_tools(self, tools: list[JsonObject]) -> list[JsonObject]:
        """Hide the tools the policy blocks outright (the policy's hide_blocked_tools).

        Done after every tool was scanned and pinned, so hiding changes
        nothing about those checks. It keeps a blocked tool's description out
        of the model's context and saves the agent calls that would be
        refused; it is not enforcement: a call to a hidden tool is still
        checked, and refused. A tool that needs approval ("ask") stays
        visible, and nothing is hidden in monitor mode, which must show what
        happens without changing it. Each hidden name is reported once.
        """
        policy = self._firewall.policy
        if not policy.hide_blocked_tools or self._firewall.monitor:
            return tools
        shown, newly_hidden = [], []
        for tool in tools:
            if policy.tool_level_action(tool["name"]) != "block":
                shown.append(tool)
            elif self._first_report("hidden", tool["name"]):
                newly_hidden.append(_label(tool["name"]))
        for name in newly_hidden:
            self._firewall.note(name, "hidden from the tool list: the policy blocks every call to it", "tool_hidden")
        if newly_hidden:
            hidden = ", ".join(newly_hidden)
            self._report(f"hid {len(newly_hidden)} tool(s) that the policy blocks from the tool list: {hidden}",
                         limit=2000)
        return shown

    # ---- lists in pages ---------------------------------------------------------------

    def _checked_page_boundary(self, pending: _PendingRequest, items_key: str, entries: list[Any]) -> list[Any]:
        """The entries of a page of a list to forward, once the boundary with the page before was scanned.

        A list reply is scanned whole because a phrase can be split over two
        entries; the client joins the pages of a list into one, so a phrase
        can also be split over the end of one page and the start of the next.
        When the request's cursor is the nextCursor of a page whose end is
        kept, the text nearest the end of that page before
        (_remember_page_end) is scanned with the text nearest the start
        of this page (_boundary_view: for each member, nested ones included,
        the nearest entries that have text in it, PAGE_BOUNDARY_BYTES of each
        side; this side always looks for the members the end kept) with the
        metadata rules. If that is refused, the fewest entries of this page's
        side that are refused with that end are removed, and they and the
        fewest entries of the end of the page before that take part are
        quarantined (tools, prompts, resource templates: they cannot be used,
        and are left out of later lists). The page before was already
        forwarded: its entries stay in the client's list.
        """
        if pending.cursor is None or not entries:
            return entries
        with self._state:
            tails = self._page_tails[items_key]
            tail = tails.pop(pending.cursor, None)
            if tail is not None:
                tails[pending.cursor] = tail  # just used: forgotten last
        if tail is None or not tail.texts:
            return entries
        ended_with = dict.fromkeys(key for entry in reversed(tail.texts) for key, _ in reversed(entry))
        head = _boundary_view(entries, from_end=False, wanted=ended_with)
        start = [text for _, text in head]
        if not start:
            return entries
        decision = self._firewall.scan_result(
            pending.label, {items_key: _scannable([*tail.texts, *start])}, event="list_item", log_clean=False,
            call_id=pending.call_id,
        )
        if decision.allowed:
            return entries
        removed, ended = self._boundary_entries(items_key, tail.texts, start)
        if items_key in PINNED_LISTS:
            for position in ended:
                name = tail.names[position]
                if name:
                    listed = {"name": name, "uriTemplate": tail.templates[position] or None}
                    self._quarantine(items_key, name, self._template_texts(items_key, listed))
            for position in removed:
                entry = entries[head[position][0]]
                if _is_name(entry.get("name")):
                    self._quarantine(items_key, entry["name"], self._template_texts(items_key, entry))
        count = len(removed)
        self._report_block(
            f"removed {count} entr{'y' if count == 1 else 'ies'} near the start of a page of the {items_key} list: "
            "read with the end of the page before (already forwarded), they were refused; both are quarantined",
            decision,
        )
        dropped = {head[position][0] for position in removed}
        return [entry for index, entry in enumerate(entries) if index not in dropped]

    def _boundary_entries(
        self, items_key: str, end: Sequence[_KeptEntry], start: Sequence[_KeptEntry],
    ) -> tuple[list[int], list[int]]:
        """Which entries of a refused boundary to remove (positions in `start`) and to quarantine (in `end`).

        On each side, the fewest entries nearest the boundary that are refused
        with the other side (_fewest: a binary search). If the farthest of
        those is refused with the other side on its own, it alone is taken:
        the entries in between, which a phrase may be padded with, are left
        out. Each scan is unrecorded and of 2 * PAGE_BOUNDARY_BYTES at most,
        about 2 * log2(entries) + 2 of them in all.
        """
        taken = _fewest(lambda count: self._boundary_refused(items_key, end, start[:count]), len(start))
        removed = list(range(taken))
        if taken > 1 and self._boundary_refused(items_key, end, [start[taken - 1]]):
            removed = [taken - 1]
        chosen = [start[position] for position in removed]
        reach = _fewest(lambda count: self._boundary_refused(items_key, end[len(end) - count:], chosen), len(end))
        ended = list(range(len(end) - reach, len(end)))
        if reach > 1 and self._boundary_refused(items_key, [end[len(end) - reach]], chosen):
            ended = [len(end) - reach]
        return removed, ended

    def _boundary_refused(self, items_key: str, end: Sequence[_KeptEntry], start: Sequence[_KeptEntry]) -> bool:
        """Whether the end of one page read with the start of the next has a finding at the blocking severity.

        Not recorded: it only narrows down which entries a recorded refusal
        (_checked_page_boundary) is about.
        """
        threshold = self._firewall.policy.block_severity
        if threshold is None:
            return False
        views = text_views({items_key: _scannable([*end, *start])}, strict=True)
        worst = max_severity(scan_views(views, profile=METADATA))
        return worst is not None and SEVERITY_ORDER[worst] >= SEVERITY_ORDER[threshold]

    def _remember_page_end(self, pending: _PendingRequest, items_key: str, delivered: JsonObject) -> None:
        """Keep the end of a page that was delivered with a nextCursor, for the next page's boundary scan.

        What is kept is the text the client was sent (the delivered reply):
        _boundary_view of the page, read from its end. The end of the page
        before is read on after it, so a member this page has too little text
        in is filled from the pages before. Every string nextCursor, "" too,
        is followed (_cursor_digest); _checked_reply refuses any other.

        The end of a page is kept when its next page arrives, too: a client
        may ask for that page again (a retry, after a refused page, or two
        requests at once), and each answer is scanned with the same end. At
        most MAX_OPEN_CURSORS ends per list are kept; the one used least
        recently is forgotten first.
        """
        result = delivered.get("result")
        entries = result.get(items_key) if isinstance(result, dict) else None
        next_cursor = result.get("nextCursor") if isinstance(result, dict) else None
        with self._state:
            before = self._page_tails[items_key].get(pending.cursor) if pending.cursor is not None else None
        if not isinstance(entries, list) or not isinstance(next_cursor, str):
            return
        # Side by side: what to read of each entry, its name and its uriTemplate ("" when it has none).
        texts: list[Any] = list(before.texts) if before is not None else []
        names = list(before.names) if before is not None else []
        templates = list(before.templates) if before is not None else []
        for entry in entries:
            if isinstance(entry, dict):
                texts.append(entry)
                names.append(entry["name"] if _is_name(entry.get("name")) else "")
                template = entry.get("uriTemplate") if items_key == "resourceTemplates" else None
                # One too long to read matches every URI (uri_template), cut or not: it is kept bounded.
                templates.append(template[:uri_template.MAX_TEMPLATE_CHARS + 1] if isinstance(template, str) else "")
        kept = _boundary_view(texts, from_end=True)
        tail = _PageTail(tuple(text for _, text in kept), tuple(names[index] for index, _ in kept),
                         tuple(templates[index] for index, _ in kept))
        with self._state:
            tails = self._page_tails[items_key]
            key = _digest(next_cursor)
            tails.pop(key, None)  # stored again as the newest
            tails[key] = tail
            while len(tails) > MAX_OPEN_CURSORS:
                del tails[next(iter(tails))]

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


def server_stderr_budget() -> proxy_report.LineBudget:
    """The line budget for what the server writes to its stderr: its own, apart from the proxy's lines."""
    return proxy_report.LineBudget(
        lambda text, limit: _warn(text, limit=limit), has_audit=False,
        limit=proxy_report.SERVER_LINES_PER_WINDOW, window=proxy_report.SERVER_WINDOW_SECONDS,
        where="the server wrote them to its stderr: run the server by itself to see them all",
    )


def _relay_stderr(stream: BinaryIO, budget: proxy_report.LineBudget) -> None:
    """Print what the server writes to stderr, made safe, clearly labelled and within `budget`.

    Left alone, the server would write straight to the operator's terminal:
    escape codes, or lines dressed up as messages from this proxy. The budget
    is not the one the proxy's own lines use: a server that writes thousands
    of lines must not crowd out, or bury, the lines that report its blocks.
    """
    try:
        while True:
            try:
                chunk = stream.readline(8192)  # bounded, in case there is never a newline
            except (OSError, ValueError):
                return
            if not chunk:
                return
            text = chunk.decode("utf-8", errors="replace").rstrip("\r\n")
            if text:
                budget.line(f"server stderr: {text}", limit=len(text) + 20)  # the whole line: reads are bounded
    finally:
        budget.flush()  # how many lines were left out, if any


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


def _message_bytes(text: str) -> int:
    """--max-message-bytes: a whole number of bytes, 1 to MAX_MAX_MESSAGE_BYTES."""
    try:
        value = int(text) if len(text) <= 12 else 0
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number of bytes") from None
    if not 1 <= value <= MAX_MAX_MESSAGE_BYTES:
        raise argparse.ArgumentTypeError(f"must be 1 to {MAX_MAX_MESSAGE_BYTES} bytes")
    return value


def _file_path(text: str) -> str:
    """A file named by an option, with a leading "~" read as the home folder.

    MCP clients start the proxy without a shell, so nothing else expands it:
    "~/policy.json" would name a folder called "~" in the client's own folder.
    """
    return os.path.expanduser(text)


def _server_name(text: str) -> str:
    if not SERVER_NAME.fullmatch(text):
        raise argparse.ArgumentTypeError("must be 1 to 64 letters, digits, '_', '-' or '.'")
    return text


def _session_group(text: str) -> str:
    """--session-group: it names a file in <home>/sessions, so the characters of a server name only, in lower case."""
    group = group_name(text)
    if group is None:
        raise argparse.ArgumentTypeError(f"must be {GROUP_NAME_RULE}")
    return group


def _pass_env_name(text: str) -> str:
    try:
        return server_env.check_pass_name(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _approver(text: str) -> ApprovalBackend:
    """One --approve-with value (approvers.parse_backend). A program is looked up as the server command is."""
    try:
        return parse_backend(text, _resolve_executable)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _approval_timeout(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number of seconds") from None
    if not 1 <= value <= MAX_APPROVAL_TIMEOUT:
        raise argparse.ArgumentTypeError(f"must be 1 to {MAX_APPROVAL_TIMEOUT} seconds")
    return value


def _say_nothing(message: str, limit: int = 300) -> None:
    """What `_warn` becomes for notices under --quiet."""


def _argument_parser() -> argparse.ArgumentParser:
    # allow_abbrev=False: "--mon" is not --monitor, and "--polic weak.json" is not another --policy. A config
    # file is read by people and by `doctor`, and both must see the options the proxy really uses.
    parser = argparse.ArgumentParser(prog="agent-sentinel proxy", description="Run an MCP server behind the firewall.",
                                     allow_abbrev=False)
    # File paths: a leading "~" is the home folder (_file_path), as a shell would read it.
    parser.add_argument("--policy", type=_file_path, required=True, help="path to the policy JSON file")
    parser.add_argument("--audit", type=_file_path, default=None, help="path of the audit log (JSON lines)")
    parser.add_argument("--no-log-args", action="store_true", help="leave tool arguments out of the audit log")
    parser.add_argument("--name", type=_server_name, default=None, metavar="NAME",
                        help="a short name for the server (letters, digits, '_', '-', '.'; at most 64), written into "
                             "every audit record and at the start of every line the proxy prints")
    parser.add_argument("--session-group", type=_session_group, default=None, metavar="NAME",
                        help="share flow marks with the other proxies of the same client run that name this group "
                             "(kept in <home>/sessions/NAME.json, NAME in lower case; needs --name). wrap gives "
                             "every server of one client the same group")
    parser.add_argument("--pins", type=_file_path, default=None, metavar="FILE",
                        help="remember tool, prompt and template definitions in FILE, and quarantine one that "
                             "changes later")
    parser.add_argument("--no-pins", action="store_true",
                        help="do not quarantine a tool whose definition changes (for servers that change them often)")
    parser.add_argument("--monitor", action="store_true",
                        help="log what the policy and the scanner would block, but block nothing (for tuning a policy)")
    parser.add_argument("--max-message-bytes", type=_message_bytes, default=DEFAULT_MAX_MESSAGE_BYTES, metavar="BYTES",
                        help=f"drop any message larger than this (default {DEFAULT_MAX_MESSAGE_BYTES}, "
                             f"at most {MAX_MAX_MESSAGE_BYTES})")
    parser.add_argument("--tool-names", choices=TOOL_NAME_MODES, default=TOOL_NAMES_WARN,
                        help="a tool or prompt whose name breaks the MCP naming rules is removed (strict), "
                             "reported (warn, the default) or let be (off)")
    parser.add_argument("--elicitation-host", action="append", default=[], metavar="HOST",
                        help="a host a URL-mode elicitation may send the user to; repeat it for more, "
                             "'*.example.com' for subdomains (default: any public https address)")
    parser.add_argument("--clean-env", action="store_true",
                        help="start the server with a minimal environment (PATH, system and temporary folders, "
                             "home folder, ...) instead of every variable the proxy has")
    parser.add_argument("--pass-env", type=_pass_env_name, action="append", default=[], metavar="NAME",
                        help="also give the server this variable with --clean-env; repeat it for more, "
                             "NAME* for every variable starting with NAME")
    parser.add_argument("--env-file", type=_file_path, default=None, metavar="FILE",
                        help="add the NAME=VALUE lines of FILE to the server's environment (values are never printed)")
    parser.add_argument("--approve-with", type=_approver, action="append", default=[], metavar="BACKEND",
                        help="ask a person about calls the policy says \"ask\" for: dialog (a window on this machine), "
                             "elicitation (a form in the MCP client, if it declares it can show one) or "
                             "command:PROGRAM (it reads the request as JSON and approves by printing 'approve'); "
                             "repeat it to give a fallback. Without it, such calls are refused")
    parser.add_argument("--approval-timeout", type=_approval_timeout, default=None, metavar="SECONDS",
                        help=f"refuse a call nobody answered within this time (default {DEFAULT_APPROVAL_TIMEOUT}, "
                             f"at most {MAX_APPROVAL_TIMEOUT})")
    parser.add_argument("--pin-server", action="store_true",
                        help="also pin the server itself in the --pins file: how it is launched (the program, a "
                             "runner's package version, the SHA-256 of a local script) and the name and version it "
                             "reports. A server that differs is refused, see --on-server-change")
    parser.add_argument("--on-server-change", choices=SERVER_CHANGE_MODES, default=None,
                        help="with --pin-server, a server that differs from its pin: refuse (the default) does not "
                             "start it, or refuses its handshake; quarantine starts it with every tool quarantined")
    loudness = parser.add_mutually_exclusive_group()
    loudness.add_argument("--quiet", action="store_true",
                          help="print only errors (the server's own stderr is still passed on)")
    loudness.add_argument("--verbose", action="store_true", help="also print a line for every call let through")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- followed by the MCP server command")
    return parser


def _env_file_values(args: argparse.Namespace) -> dict[str, str] | None:
    """The variables of --env-file (none without it); None, after saying why, if the file cannot be used."""
    try:
        return server_env.read_env_file(args.env_file) if args.env_file else {}
    except (OSError, server_env.EnvFileError) as exc:
        _warn(f"cannot use the env file: {exc}", limit=500)
        return None


def _guarded_values(
    names: Sequence[str], environment: Mapping[str, str], windows: bool = sys.platform == "win32",
) -> dict[str, str]:
    """The values secrets.known_values_from_env guards, for Firewall.set_secret_environment.

    A variable's value as the server is given it (its environment, the env
    file included), or else the proxy's own: a value the agent could send
    out through this server's tools is a secret whether the server holds it
    or not. Names compare without regard to case on Windows, as the system does.
    """
    values: dict[str, str] = {}
    for name in names:
        value = environment.get(name)
        if value is None and windows:
            value = next((found for key, found in environment.items() if key.upper() == name.upper()), None)
        if value is None:
            value = os.environ.get(name)
        if value is not None:
            values[name] = value
    return values


def _report_server_environment(
    args: argparse.Namespace, environment: Mapping[str, str], added: Mapping[str, str], say: Callable[..., None],
) -> None:
    """Report on the environment the server is started with.

    Names are reported, never values: the --pass-env names the proxy does not
    have, what --clean-env passes, and the variables that look like secrets
    and that no --pass-env or env file named. `say` prints those notices
    (nothing under --quiet).
    """
    if args.clean_env:
        for name in server_env.missing_names(os.environ, args.pass_env):
            say(f"--pass-env {name}: the proxy has no such variable, so the server does not get it")
        named = server_env.named_variables(environment, args.pass_env, added)
        say(f"--clean-env: the server gets a minimal environment, plus {', '.join(named) or 'nothing else'}",
            limit=2000)
    secret_looking = server_env.unnamed_secrets(environment, args.pass_env, added)
    if secret_looking:
        say(f"the server gets {len(secret_looking)} environment variable(s) whose names look like secrets: "
            f"{', '.join(secret_looking)}. If it does not need them, start the proxy with --clean-env; "
            "name each one it needs with --pass-env NAME", limit=2000)


@dataclass(frozen=True)
class _JoinedGroup:
    """A session group this proxy joined at startup (--session-group), for the startup lines and the audit log."""

    store: GroupSessionStore
    joined: GroupJoin
    run: client_run.ClientRun


def _join_session_group(group: str, name: str) -> _JoinedGroup | None:
    """Join the session group's file in <home>/sessions (session.GroupSessionStore); None, after saying why, if not."""
    try:
        folder = home.sessions_folder(home.home_folder())
    except home.HomeError as exc:
        _warn(f"cannot use --session-group: {exc}", limit=500)
        return None
    run = client_run.find_client_run()
    store = GroupSessionStore(folder, group, run.id, name, run_started=run.started)
    try:
        joined = store.join()
    except SessionStateError as exc:
        _warn(f"cannot use --session-group: {exc}", limit=500)
        return None
    return _JoinedGroup(store, joined, run)


def _report_session_group(group: _JoinedGroup, firewall: Firewall, say: Callable[..., None]) -> None:
    """Say (and record, as a note) how the proxy joined its session group; a file it cannot use is always reported."""
    joined, store, run = group.joined, group.store, group.run
    members = ", ".join(joined.members)
    client = f"{printable(run.program, limit=60)} {run.id}" if run.id != client_run.UNKNOWN else "unknown"
    others = (f" (the file holds the sessions of {joined.others} other client run(s) too, each of its own)"
              if joined.others else "")
    if joined.status == NEW_RUN:
        text = f"began the flow session of client run {client}{others}"
        if joined.replaced:
            text += (f"; the session of the client run begun first (its members: {', '.join(joined.replaced)}) "
                     "was removed to make room")
    elif joined.status == JOINED:
        text = f"joined the flow session of client run {client}, with {members}{others}"
    elif joined.status == REPLACED:
        before = f" (its members: {', '.join(joined.replaced)})" if joined.replaced else ""
        text = f"began the flow session of client run {client}, replacing the file: {joined.detail}{before}"
    else:
        text = f"{joined.detail}. Delete {store.path} while the client is not running to start afresh"
    firewall.note(f"session_group:{store.group}", text, event="session_group")
    line = f"session group '{store.group}': {text}"
    if joined.status not in (NEW_RUN, JOINED, REPLACED):
        _warn(line, limit=1000)
    else:
        say(line, limit=1000)
    if run.id == client_run.UNKNOWN:
        _warn(f"session group '{store.group}': the client process could not be told apart, so the group's flow "
              "marks carry over from one run of the client to the next (stricter than needed, never laxer)", limit=500)


def _report_policy_error(path: str, error: Exception) -> None:
    """Say why the policy cannot be loaded, line by line, with advice for a relative path that was not found.

    A JSON error shows the line of the file with a caret under the mistake.
    The most common first failure is a relative --policy path: MCP clients
    start servers in a folder of their own choosing, so the file is not where
    the operator expected.
    """
    message = file_error_message(path, error) if isinstance(error, OSError) else str(error)
    for number, line in enumerate(message.splitlines()):
        _warn(f"cannot load policy: {line}" if number == 0 else line, limit=500)
    hint = proxy_report.missing_policy_hint(path) if isinstance(error, FileNotFoundError) else None
    if hint:
        _warn(hint, limit=500)


def server_change_advice(pins_path: Any) -> str:
    """What the operator can do about a server that differs from its pin (proxy --pin-server)."""
    command = ["agent-sentinel", "pins", "diff", "--server", "--pins", str(pins_path)]
    return (f"If the change is expected, review it with: {proxy_report.shell_line(command)}; then pins accept "
            "--server, and restart the proxy")


def _check_server_launch(pins: ToolPins, firewall: Firewall, executable: str, command: list[str],
                         label: str, say: Callable[..., None]) -> str | None:
    """With --pin-server: compare how the server is about to be launched with its pin (pins.py).

    The first launch is pinned. Returns what changed when it differs and
    the change is not lifted by monitor mode (the caller then refuses to
    start, or quarantines the server), else None.
    """
    status, changed = pins.check_server_launch(launch_identity(executable, command))
    try:
        pins.save()
    except OSError as exc:
        _warn(f"cannot save the pins file: {exc}")
    if status == NEW:
        say("--pin-server: pinned how the server is launched; it is compared at every later start")
    if status != CHANGED:
        return None
    what = f"its launch ({', '.join(changed)}) changed since it was pinned"
    decision = firewall.block(label, f"the server differs from its pin: {what}. {server_change_advice(pins.path)}",
                              event="server_changed", rule=RULE_QUARANTINE)
    if decision.allowed:  # monitor mode
        say(f"monitor mode: the server differs from its pin ({what}); it starts as usual")
        return None
    _warn(f"the server differs from its pin: {what}. {server_change_advice(pins.path)} "
          f"{proxy_report.rule_and_ref(decision)}", limit=2000)
    return what


def main(argv: list[str] | None = None) -> int:
    parser = _argument_parser()
    args = parser.parse_args(argv)
    if hasattr(sys.stderr, "reconfigure"):  # warnings must never crash on an odd character
        sys.stderr.reconfigure(errors="backslashreplace")
    if args.name is not None:
        _name_stderr(args.name)

    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("give the MCP server command after '--'")
    if args.pin_server and (args.pins is None or args.no_pins):
        parser.error("--pin-server pins the server in the pins file: give --pins FILE, without --no-pins")
    if args.on_server_change is not None and not args.pin_server:
        parser.error("--on-server-change says what happens to a server that differs from its pin: it needs "
                     "--pin-server")
    on_server_change = args.on_server_change or SERVER_CHANGE_REFUSE
    backends = [approver.describe() for approver in args.approve_with]
    for backend in backends:
        if backends.count(backend) > 1:
            parser.error(f"--approve-with {backend} is given twice")
    if args.session_group is not None and args.name is None:
        parser.error("--session-group needs --name: each mark the group shares names the server it came from")
    report = proxy_report.QUIET if args.quiet else proxy_report.VERBOSE if args.verbose else proxy_report.NORMAL
    say = _say_nothing if args.quiet else _warn  # notices; errors always go through _warn
    try:
        policy = Policy.from_file(args.policy)
    except (OSError, PolicyError) as exc:
        _report_policy_error(args.policy, exc)
        return 2
    try:
        pins = ToolPins(args.pins, enabled=not args.no_pins)
    except (OSError, ValueError) as exc:  # unreadable, not JSON, or not a pins file
        _warn(f"cannot load the pins file: {exc}", limit=500)
        return 2
    try:
        elicitation.allowed_hosts(args.elicitation_host)
    except PolicyError as exc:
        _warn(f"cannot use {exc}", limit=500)
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
    added = _env_file_values(args)
    if added is None:
        return 2
    environment = server_env.server_environment(os.environ, args.clean_env, args.pass_env, added)
    # A session group shares the flow marks; without flow rules there are none to share.
    group = None
    if args.session_group is not None and policy.flows:
        group = _join_session_group(args.session_group, args.name)
        if group is None:
            return 2
    firewall = Firewall(
        policy, audit_path=args.audit, log_args=not args.no_log_args, monitor=args.monitor, server_name=args.name,
        session_store=group.store if group is not None else None,
    )
    # secrets.known_values_from_env guards the values the server is given (--clean-env, --pass-env, --env-file).
    firewall.set_secret_environment(_guarded_values(policy.secrets_known_values_from_env, environment))

    approval_timeout = args.approval_timeout or DEFAULT_APPROVAL_TIMEOUT
    start = proxy_report.Startup(
        version=__version__, name=args.name, policy_path=args.policy, policy=policy, audit_path=args.audit,
        pins_path=args.pins, pins_enabled=not args.no_pins, server_command=[executable, *command[1:]],
        approvers=[(approver.describe(), approver.unavailable()) for approver in args.approve_with],
        approval_timeout=approval_timeout, approval_timeout_given=args.approval_timeout is not None,
        monitor=args.monitor, secret_warnings=firewall.secret_warnings(),
        session_group=args.session_group, session_file=str(group.store.path) if group is not None else None,
    )
    for line in proxy_report.startup_lines(start):
        say(line, limit=1500)
    if group is not None:
        _report_session_group(group, firewall, say)
    _report_server_environment(args, environment, added, say)
    server_changed = None
    if args.pin_server:
        server_changed = _check_server_launch(pins, firewall, executable, command, args.name or "server", say)
        if server_changed is not None and on_server_change == SERVER_CHANGE_REFUSE:
            _warn("refusing to start the server (--on-server-change refuse)")
            return 2
    try:
        server = subprocess.Popen(
            [executable, *command[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment,
        )
    except OSError as exc:
        _warn(f"cannot start server: {exc}")
        return 2
    assert server.stdin is not None and server.stdout is not None and server.stderr is not None
    if args.monitor:
        # Printed even under --quiet: the proxy is protecting nothing.
        _warn("monitor mode: nothing is being blocked by the policy or the scanner")

    proxy = Proxy(
        firewall, sys.stdout.buffer, server.stdin, pins=pins, max_message_bytes=args.max_message_bytes,
        tool_names=args.tool_names, elicitation_hosts=args.elicitation_host, approvers=args.approve_with,
        approval_timeout=approval_timeout, report=report, pin_server=args.pin_server,
        on_server_change=on_server_change,
    )
    if server_changed is not None:
        _warn("every tool, prompt and resource template of the server is quarantined (--on-server-change quarantine)")
        proxy.quarantine_server(server_changed)

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
    server_lines = server_stderr_budget()
    threading.Thread(target=_relay_stderr, args=(server.stderr, server_lines), daemon=True).start()
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
    proxy.close_report()  # how many lines about traffic were left out, if any
    exit_code = _stop(server, deadline)
    server_lines.flush()  # and how many of the server's stderr lines, if its relay has not said so yet
    return exit_code


if __name__ == "__main__":
    exit_process(main())
