"""What the proxy knows about MCP message shapes, across the protocol's revisions.

MCP has two eras (see "Versioning and Compatibility" in the 2026-07-28 revision):

* Legacy revisions, 2024-11-05 to 2025-11-25, open a session with an
  `initialize` handshake. The server may send the client requests of its own
  (sampling, elicitation, roots) at any time.
* The modern revision, 2026-07-28, has no handshake. Every request names its
  protocol version and the client's capabilities in `params._meta`, every
  result says what kind of result it is in `resultType`, and a server that
  needs something from the client asks for it inside its reply: an
  "input_required" result holding `inputRequests` (a "multi round-trip
  request", MRTR). The client then sends the request again with its
  `inputResponses`. On stdio a modern server must never send a request of its own.

The functions here are pure and know nothing about the policy. Each looks at
one message, or one part of one, and either returns what the proxy may
forward or raises ShapeError with a reason for the operator. mcp_proxy.py
decides what to do about it. Every limit below bounds something that a
hostile peer controls.
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Any

from .textutil import printable

JsonObject = dict[str, Any]

# ---- protocol versions ----------------------------------------------------------

# The revisions this proxy was built for. A revision it does not know may add
# message kinds that would pass through unpoliced, so they are not let through.
LEGACY_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
MODERN_VERSIONS = ("2026-07-28",)
SUPPORTED_VERSIONS = LEGACY_VERSIONS + MODERN_VERSIONS
# What an `initialize` asking for a version it cannot have is changed to.
NEWEST_LEGACY_VERSION = LEGACY_VERSIONS[-1]

# The `_meta` keys a 2026-07-28 request carries.
PROTOCOL_VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
CLIENT_CAPABILITIES_KEY = "io.modelcontextprotocol/clientCapabilities"

# ---- methods ------------------------------------------------------------------------

INITIALIZE = "initialize"  # legacy: opens the session
SERVER_DISCOVER = "server/discover"  # 2026-07-28: what the server supports
SUBSCRIPTIONS_LISTEN = "subscriptions/listen"  # 2026-07-28: replaces resources/subscribe
# Methods of the tasks feature (tasks/get, tasks/result, tasks/update, tasks/cancel, tasks/list).
TASKS_METHOD_PREFIX = "tasks/"

# ---- JSON-RPC error codes ---------------------------------------------------------

METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
UNSUPPORTED_PROTOCOL_VERSION = -32022  # defined by 2026-07-28; clients retry with a listed version

# ---- results ----------------------------------------------------------------------

RESULT_COMPLETE = "complete"
RESULT_INPUT_REQUIRED = "input_required"
# Defined by the tasks extension. Tasks are not supported by the proxy: a task's
# result arrives later, through other methods, where it cannot be tied to its tool.
RESULT_TASK = "task"

# The client requests whose reply may ask for input (MRTR), and what it may ask for.
INPUT_METHODS = ("tools/call", "prompts/get", "resources/read")
INPUT_REQUEST_METHODS = ("elicitation/create", "sampling/createMessage", "roots/list")

# ---- capabilities -----------------------------------------------------------------

# A client capability, and the server request it lets the server make.
CAPABILITY_METHODS = {
    "sampling": "sampling/createMessage",
    "elicitation": "elicitation/create",
    "roots": "roots/list",
}
# Tasks: a capability of their own in 2025-11-25, an extension in 2026-07-28.
TASKS_CAPABILITY = "tasks"
TASKS_EXTENSION = "io.modelcontextprotocol/tasks"

# ---- subscriptions/listen -----------------------------------------------------------

SUBSCRIPTION_FLAGS = ("toolsListChanged", "promptsListChanged", "resourcesListChanged")
RESOURCE_SUBSCRIPTIONS = "resourceSubscriptions"

# ---- limits -------------------------------------------------------------------------

MAX_KEY_CHARS = 256  # keys of inputRequests and inputResponses: the same limit as names and ids
MAX_INPUT_ENTRIES = 32  # entries in one inputRequests or inputResponses map
MAX_REQUEST_STATE_CHARS = 64 * 1024  # the server's opaque state, echoed back by the client
MAX_SUBSCRIBED_URIS = 256  # resource URIs in one subscriptions/listen request
MAX_SUPPORTED_VERSIONS = 64  # entries in a server/discover reply's supportedVersions
MAX_VERSION_CHARS = 64  # a protocol version as the proxy echoes it back in an error


class ShapeError(ValueError):
    """A message, or part of one, whose shape the proxy cannot check. The text is for the operator."""


def _shown(value: Any, limit: int = 60) -> str:
    """Peer-chosen text, shortened and made safe for a reason that reaches stderr and the audit log."""
    return printable(value, limit=limit)


def _is_key(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_KEY_CHARS


# ---- reading a client request ---------------------------------------------------------

def requested_version(message: JsonObject) -> str | None:
    """The protocol version a request names in params._meta, or None if it names none (legacy).

    Raises ShapeError when `_meta` is not an object or the version is not text.
    """
    params = message.get("params")
    if not isinstance(params, dict) or "_meta" not in params:
        return None
    meta = params["_meta"]
    if not isinstance(meta, dict):
        raise ShapeError("params._meta must be an object")
    if PROTOCOL_VERSION_KEY not in meta:
        return None
    version = meta[PROTOCOL_VERSION_KEY]
    if not isinstance(version, str):
        raise ShapeError("the protocol version in params._meta must be text")
    return version


def unsupported_version_error(msg_id: Any, requested: str) -> JsonObject:
    """The UnsupportedProtocolVersionError a 2026-07-28 server sends for a version it does not support.

    The code, message and data are those the specification defines, so that
    a client recognises the error and retries with a listed version.
    """
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {
            "code": UNSUPPORTED_PROTOCOL_VERSION,
            "message": "Unsupported protocol version",
            "data": {"supported": list(MODERN_VERSIONS), "requested": requested[:MAX_VERSION_CHARS]},
        },
    }


def minimised_capabilities(capabilities: Any, blocked_methods: Collection[str] = ()) -> JsonObject:
    """A copy of a capabilities object without what the other side must not be offered.

    Removed: a client capability whose server request is in `blocked_methods`
    (sampling for "sampling/createMessage", and so on), and tasks, both the
    2025-11-25 capability and the 2026-07-28 extension. Used for the client's
    capabilities on their way to the server, and, with no blocked methods, for
    the server's capabilities on their way to the client, so that neither
    side starts a task the proxy would refuse. The given object is not changed.
    """
    if not isinstance(capabilities, dict):
        raise ShapeError("capabilities must be an object")
    kept: JsonObject = {}
    for name, value in capabilities.items():
        blocked = name in CAPABILITY_METHODS and CAPABILITY_METHODS[name] in blocked_methods
        if name != TASKS_CAPABILITY and not blocked:
            kept[name] = value
    if "extensions" in kept:
        extensions = kept["extensions"]
        if not isinstance(extensions, dict):
            raise ShapeError("capabilities.extensions must be an object")
        kept["extensions"] = {name: value for name, value in extensions.items() if name != TASKS_EXTENSION}
    return kept


def check_retry_params(params: JsonObject) -> None:
    """Check the parts of a request that answer an earlier input_required reply.

    inputResponses must map at most MAX_INPUT_ENTRIES names to objects (the
    client's answers); requestState must be text of at most
    MAX_REQUEST_STATE_CHARS. What the answers say is checked by the caller.
    """
    if "inputResponses" in params:
        responses = params["inputResponses"]
        if not isinstance(responses, dict):
            raise ShapeError("inputResponses must be an object")
        if len(responses) > MAX_INPUT_ENTRIES:
            raise ShapeError(f"inputResponses has {len(responses)} entries; at most {MAX_INPUT_ENTRIES} are accepted")
        for key, answer in responses.items():
            if not _is_key(key):
                raise ShapeError(f"an inputResponses key must be text of 1 to {MAX_KEY_CHARS} characters")
            if not isinstance(answer, dict):
                raise ShapeError(f"inputResponses['{_shown(key)}'] must be an object")
    if "requestState" in params:
        _check_request_state(params["requestState"])


def _check_request_state(state: Any) -> None:
    # Opaque to the client, which must echo it unchanged: only its type and size are checked.
    if not isinstance(state, str):
        raise ShapeError("requestState must be text")
    if len(state) > MAX_REQUEST_STATE_CHARS:
        raise ShapeError(f"requestState has {len(state)} characters; at most {MAX_REQUEST_STATE_CHARS} are accepted")


def subscribed_uris(params: Any) -> list[str]:
    """The resource URIs a subscriptions/listen request subscribes to, each once.

    The request's `notifications` object may hold only the filters the
    2026-07-28 revision defines: the three list-changed flags (true or false)
    and `resourceSubscriptions`, a list of at most MAX_SUBSCRIBED_URIS URIs.
    Anything else is refused, because the proxy cannot tell what it would let
    the server send.
    """
    if not isinstance(params, dict):
        raise ShapeError("params must be an object")
    notifications = params.get("notifications")
    if not isinstance(notifications, dict):
        raise ShapeError("params.notifications must be an object")
    for name, value in notifications.items():
        if name in SUBSCRIPTION_FLAGS:
            if not isinstance(value, bool):
                raise ShapeError(f"notifications.{name} must be true or false")
        elif name != RESOURCE_SUBSCRIPTIONS:
            raise ShapeError(f"unknown subscription type '{_shown(name)}'")
    uris = notifications.get(RESOURCE_SUBSCRIPTIONS, [])
    if not isinstance(uris, list):
        raise ShapeError(f"notifications.{RESOURCE_SUBSCRIPTIONS} must be a list")
    if len(uris) > MAX_SUBSCRIBED_URIS:
        raise ShapeError(f"{len(uris)} resource subscriptions; at most {MAX_SUBSCRIBED_URIS} are accepted")
    if not all(isinstance(uri, str) and uri for uri in uris):
        raise ShapeError("each resource subscription must be a URI")
    return list(dict.fromkeys(uris))


def client_reply_value(member: str, value: Any) -> Any:
    """The `result` or `error` of the client's answer to a server request, rebuilt from what the protocol defines.

    A result must be an object. An error keeps only `code` (an integer),
    `message` (text) and `data`, so that nothing else rides along to the server.
    """
    if member == "result":
        if not isinstance(value, dict):
            raise ShapeError("result must be an object")
        return value
    code = value.get("code") if isinstance(value, dict) else None
    if not isinstance(code, int) or isinstance(code, bool) or not isinstance(value.get("message"), str):
        raise ShapeError("error must be an object with an integer code and a text message")
    rebuilt = {"code": code, "message": value["message"]}
    if "data" in value:
        rebuilt["data"] = value["data"]
    return rebuilt


# ---- reading a server reply ----------------------------------------------------------

def result_type(result: Any) -> str:
    """What kind of result this is. An absent resultType means "complete", as in every legacy reply."""
    if not isinstance(result, dict) or "resultType" not in result:
        return RESULT_COMPLETE
    kind = result["resultType"]
    if not isinstance(kind, str):
        raise ShapeError("resultType must be text")
    return kind


def is_legacy_task(result: Any) -> bool:
    """Whether a tools/call result is a 2025-11-25 task handle ({"task": {...}}) instead of the tool's result.

    A tool's result always has `content`; a task handle has none.
    """
    return (
        isinstance(result, dict)
        and "resultType" not in result
        and "content" not in result
        and isinstance(result.get("task"), dict)
    )


def input_requests(result: JsonObject) -> dict[str, JsonObject]:
    """Check an input_required result and return its input requests, rebuilt.

    `inputRequests` must map at most MAX_INPUT_ENTRIES names to requests for
    elicitation, sampling or the client's roots, each {"method", "params"};
    `requestState` must be text of at most MAX_REQUEST_STATE_CHARS. The result
    must have at least one of them. Each entry is rebuilt from its method and
    params, and the result is changed to hold the rebuilt map, so that nothing
    else in an entry rides along. An empty dict means the result asks for no
    input (it carries only requestState).
    """
    if "inputRequests" not in result and "requestState" not in result:
        raise ShapeError("an input_required result must have inputRequests or requestState")
    if "requestState" in result:
        _check_request_state(result["requestState"])
    if "inputRequests" not in result:
        return {}
    requests = result["inputRequests"]
    if not isinstance(requests, dict):
        raise ShapeError("inputRequests must be an object")
    if len(requests) > MAX_INPUT_ENTRIES:
        raise ShapeError(f"inputRequests has {len(requests)} entries; at most {MAX_INPUT_ENTRIES} are accepted")
    rebuilt: dict[str, JsonObject] = {}
    for key, entry in requests.items():
        if not _is_key(key):
            raise ShapeError(f"an inputRequests key must be text of 1 to {MAX_KEY_CHARS} characters")
        method = entry.get("method") if isinstance(entry, dict) else None
        if not isinstance(method, str) or method not in INPUT_REQUEST_METHODS:
            raise ShapeError(f"inputRequests['{_shown(key)}'] is not a request for elicitation, sampling or roots")
        rebuilt[key] = {"method": method}
        if "params" in entry:
            if not isinstance(entry["params"], dict):
                raise ShapeError(f"inputRequests['{_shown(key)}'].params must be an object")
            rebuilt[key]["params"] = entry["params"]
    result["inputRequests"] = rebuilt
    return rebuilt


def known_versions(versions: Any) -> list[str]:
    """The versions in a server/discover reply's supportedVersions that this proxy knows, in the server's order."""
    if not isinstance(versions, list) or not all(isinstance(version, str) for version in versions):
        raise ShapeError("supportedVersions must be a list of versions")
    if len(versions) > MAX_SUPPORTED_VERSIONS:
        raise ShapeError(f"supportedVersions has {len(versions)} entries; at most {MAX_SUPPORTED_VERSIONS} are allowed")
    return [version for version in dict.fromkeys(versions) if version in SUPPORTED_VERSIONS]
