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

Besides the eras, this module holds the rules the specification sets for
parts of a message that both eras share: icons (2025-11-25) and tool names
(SEP-986), with a way to tell when two names look alike.

The functions here are pure and know nothing about the policy. Each looks at
one message, or one part of one, and either returns what the proxy may
forward or raises ShapeError with a reason for the operator. mcp_proxy.py
decides what to do about it. Every limit below bounds something that a
hostile peer controls.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Collection
from typing import Any

from .matchers import read_url
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


# ---- addresses a client is asked to open ---------------------------------------------

# Top-level names that only ever mean a private network or this machine. A
# host under one of them is never a public web site, whatever DNS says.
_LOCAL_SUFFIXES = ("localhost", "local", "internal", "arpa", "lan", "home", "corp", "intranet", "private")
_LOCAL_NAMES = ("metadata.goog",)  # Google's cloud metadata service, which has no local-only suffix


def public_https_problem(url: str) -> str | None:
    """Why `url` is not a plain https address of a public web site, or None if it is one.

    The client opens such an address on the user's machine (an icon it
    fetches, a sign-in page it shows), so it must be a URL that every parser
    reads the same way (matchers.read_url: no user name, backslash, space,
    "%" or non-ASCII letter in the host, no xn-- label), use https, and name a
    host that is neither an IP address nor a local name (no dot at all, or
    under one of _LOCAL_SUFFIXES). There is no DNS lookup.
    """
    if url[:8].lower() != "https://":
        return "is not an https address"
    found = read_url(url)
    if found is None:
        return "cannot be read with certainty (a user name, a space, a backslash or an odd host)"
    if found.is_address:
        return "names an IP address instead of a host name"
    if "." not in found.host or found.host.rsplit(".", 1)[-1] in _LOCAL_SUFFIXES or found.host in _LOCAL_NAMES:
        return "names a host on a local network"
    return None


# ---- icons (2025-11-25) ------------------------------------------------------------------

MAX_ICONS = 32  # icons of one item; more than this and none are kept
MAX_ICON_CHARS = 100 * 1024  # the src of one icon (an inline image is as long as its data)
MAX_ICON_SIZES = 16
ICON_THEMES = ("light", "dark")
# Kinds of image an icon may be. SVG is left out on purpose: an SVG file can
# carry script, and the specification asks clients to treat it with caution.
ICON_MIME_TYPES = ("image/png", "image/jpeg", "image/jpg", "image/webp")
# An image carried inside the URL itself. The class has no overlap with what
# follows it, so matching stays linear however long the data is.
_DATA_IMAGE = re.compile(r"data:image/(?:png|jpe?g|webp);base64,[A-Za-z0-9+/]*={0,2}", re.IGNORECASE)
_ICON_SIZE = re.compile(r"[0-9]{1,5}[xX][0-9]{1,5}|any")


def clean_icons(icons: Any) -> tuple[list[JsonObject], list[str]]:
    """The icons of a tool, prompt, resource, template or server that are safe to forward, and what was dropped.

    The specification says a client MUST refuse icons with unsafe schemes
    (javascript:, file:, ...); not every client does, and an icon is fetched
    by the user's machine as soon as a list is shown, which makes a remote one
    a tracking pixel. So an icon is kept only when its `src` is a public https
    address (public_https_problem) or an inline PNG, JPEG or WebP image
    (data:image/...;base64,...) of at most MAX_ICON_CHARS. Its `mimeType`, if
    given, must name one of those image types; `sizes` and `theme` must have
    their defined shapes. Each kept icon is rebuilt from those four members.

    Returns (kept icons, one reason per dropped icon). Only icons are dropped,
    never the item that has them.
    """
    if not isinstance(icons, list):
        return [], ["icons is not a list"]
    if len(icons) > MAX_ICONS:
        return [], [f"there are {len(icons)} icons; at most {MAX_ICONS} are accepted"]
    kept: list[JsonObject] = []
    dropped: list[str] = []
    for icon in icons:
        problem = _icon_problem(icon)
        if problem is None:
            kept.append({key: icon[key] for key in ("src", "mimeType", "sizes", "theme") if key in icon})
        else:
            dropped.append(problem)
    return kept, dropped


def _icon_problem(icon: Any) -> str | None:
    src = icon.get("src") if isinstance(icon, dict) else None
    if not isinstance(src, str):
        return "an icon is not an object with a text src"
    if len(src) > MAX_ICON_CHARS:
        return f"an icon's src is longer than {MAX_ICON_CHARS} characters"
    if src[:5].lower() == "data:":
        if not _DATA_IMAGE.fullmatch(src):
            return "an inline icon is not a base64 PNG, JPEG or WebP image"
    else:
        problem = public_https_problem(src)
        if problem is not None:
            return f"an icon's address {problem}: {_shown(src)}"
    if "mimeType" in icon and icon["mimeType"] not in ICON_MIME_TYPES:
        return f"an icon has the type '{_shown(icon['mimeType'], 40)}', which is not a PNG, JPEG or WebP image"
    sizes = icon.get("sizes", [])
    if not isinstance(sizes, list) or len(sizes) > MAX_ICON_SIZES or not all(
        isinstance(size, str) and _ICON_SIZE.fullmatch(size) for size in sizes
    ):
        return "an icon's sizes are not a short list such as [\"48x48\"]"
    if "theme" in icon and icon["theme"] not in ICON_THEMES:
        return "an icon's theme is neither \"light\" nor \"dark\""
    return None


# ---- tool names (SEP-986) and names that look alike ---------------------------------------

MAX_TOOL_NAME_CHARS = 128
# What the specification says a tool name SHOULD be: ASCII letters, digits, "_", "-" and ".".
_TOOL_NAME = re.compile(r"[A-Za-z0-9_.-]+")


def tool_name_problem(name: str) -> str | None:
    """Why a tool (or prompt) name breaks the MCP naming rules, or None if it keeps them.

    A name outside the rules is easy to misread in a client's list: a space,
    an invisible character, or a letter of another alphabet that looks Latin.
    """
    if not 0 < len(name) <= MAX_TOOL_NAME_CHARS:
        return f"it is not 1 to {MAX_TOOL_NAME_CHARS} characters long"
    if not _TOOL_NAME.fullmatch(name):
        return "it has characters other than ASCII letters, digits, '_', '-' and '.'"
    return None


# Letters of other alphabets drawn like a Latin letter, by Unicode name: the
# letters the detector folds as well. "{}" stands for both SMALL and CAPITAL.
_LOOKALIKE_LETTERS = {
    "CYRILLIC {} LETTER A": "a", "CYRILLIC {} LETTER VE": "b", "CYRILLIC {} LETTER ES": "c",
    "CYRILLIC {} LETTER IE": "e", "CYRILLIC {} LETTER EN": "h", "CYRILLIC {} LETTER BYELORUSSIAN-UKRAINIAN I": "i",
    "CYRILLIC {} LETTER JE": "j", "CYRILLIC {} LETTER KA": "k", "CYRILLIC {} LETTER EM": "m",
    "CYRILLIC {} LETTER O": "o", "CYRILLIC {} LETTER ER": "p", "CYRILLIC {} LETTER DZE": "s",
    "CYRILLIC {} LETTER TE": "t", "CYRILLIC {} LETTER HA": "x", "CYRILLIC {} LETTER U": "y",
    "GREEK {} LETTER ALPHA": "a", "GREEK {} LETTER EPSILON": "e", "GREEK {} LETTER IOTA": "i",
    "GREEK {} LETTER KAPPA": "k", "GREEK {} LETTER OMICRON": "o", "GREEK {} LETTER RHO": "p",
    "GREEK {} LETTER TAU": "t", "GREEK {} LETTER CHI": "x",
}
_LOOKALIKES = {
    ord(unicodedata.lookup(name.format(case))): latin
    for name, latin in _LOOKALIKE_LETTERS.items()
    for case in ("SMALL", "CAPITAL")
}
_LOOKALIKES.update({
    ord(unicodedata.lookup(name)): latin
    for name, latin in {
        "GREEK SMALL LETTER NU": "v", "GREEK SMALL LETTER UPSILON": "u", "GREEK CAPITAL LETTER BETA": "b",
        "GREEK CAPITAL LETTER ETA": "h", "GREEK CAPITAL LETTER MU": "m", "GREEK CAPITAL LETTER NU": "n",
        "GREEK CAPITAL LETTER UPSILON": "y", "GREEK CAPITAL LETTER ZETA": "z", "LATIN SMALL LETTER DOTLESS I": "i",
    }.items()
})
# ASCII characters that many fonts draw alike, once letters are lowercase:
# capital I, small l, digit 1 and "|"; letter o and digit 0.
_ASCII_LOOKALIKES = str.maketrans({"i": "l", "1": "l", "|": "l", "0": "o"})
# Characters decomposed in one call. On one long string CPython's normaliser
# takes quadratic time for a long run of combining marks, which it sorts one by
# one, so text is decomposed in slices, as the detector does. A slice edge can
# only separate a mark from its letter, and marks are deleted anyway.
_SLICE = 256


def fold_lookalikes(text: str) -> str:
    """Text reduced to the plain lowercase letters a reader sees.

    Compatibility forms become plain ones (full-width letters, ligatures),
    accents and other combining marks are removed, invisible characters are
    deleted, Cyrillic and Greek letters drawn like Latin ones become those
    letters, and case is folded. Linear in the length of the text; the result
    can be longer than the text (a ligature becomes several letters).
    """
    decomposed = "".join(
        unicodedata.normalize("NFKD", text[start:start + _SLICE]) for start in range(0, len(text), _SLICE)
    )
    visible = "".join(ch for ch in decomposed if unicodedata.category(ch) not in ("Mn", "Me", "Cf", "Cc"))
    return visible.translate(_LOOKALIKES).casefold()


def name_skeleton(name: str) -> str:
    """What a name looks like on screen: two names with the same skeleton are easy to mistake for each other.

    fold_lookalikes, then "i", "l", "1" and "|" are one character, and so are
    "o" and "0". "read_fіle" (Cyrillic і), "read_fiIe", "Read_File" and
    "read_file" all have the skeleton "read_flle". Only for comparing; never shown.
    """
    return fold_lookalikes(name).translate(_ASCII_LOOKALIKES)
