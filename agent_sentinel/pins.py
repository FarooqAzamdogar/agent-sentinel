"""Pins: what each tool, prompt and resource template looked like when it was first seen.

A server can show a harmless definition until the user trusts it and then
change it (a "rug pull"). The proxy pins each definition the first time it is
listed (trust on first use); a later listing whose fingerprint differs is
"changed", and the proxy removes that entry and refuses to use it for as long
as it runs. The server's instructions are pinned the same way.

What is pinned is what a model or a person reads. `_meta` is left out: servers
put counters and timestamps there, and an entry that "changed" on every
listing would be removed for nothing.

    tools              name, title, description, inputSchema, outputSchema, annotations, icons, execution
    prompts            name, title, description, arguments, icons
    resourceTemplates  name, title, description, uriTemplate, mimeType, annotations, icons
    instructions       the text of the server's instructions (initialize or server/discover)

A member is pinned only if the entry has it (so `execution` only for a tool
that has one). Icons are pinned as the proxy forwards them, after unsafe ones
were dropped (mcp_protocol.clean_icons).

The pins file, version 2
------------------------
With a file, pins survive restarts. It is JSON, written whole and atomically:

    {
      "version": 2,
      "tools": {
        "read_file": {
          "sha256": "<64 lowercase hex: the fingerprint of the definition>",
          "first_seen": "2026-11-19T12:00:00Z",
          "definition": {"name": "read_file", "description": "Read a file", "inputSchema": {...}}
        },
        "old_tool": {"sha256_v1": "<64 lowercase hex>"}
      },
      "prompts": {"summarize": {"sha256": "...", "first_seen": "...", "definition": {...}}},
      "resourceTemplates": {"notes": {"sha256": "...", "first_seen": "...", "definition": {...}}},
      "instructions": {"sha256": "...", "first_seen": "...", "definition": {"instructions": "Use read_file ..."}}
    }

* Each section maps a name (1 to 256 characters) to one pin; "instructions"
  is a single pin, absent until the server has sent instructions.
* "definition" holds exactly the pinned members of the entry, as the server
  sent them. It is left out when it is larger than MAX_DEFINITION_CHARS, or
  when the stored definitions already add up to MAX_STORED_DEFINITION_CHARS;
  the fingerprint is always kept. For instructions it is {"instructions": text}.
* The fingerprint is the SHA-256 of the definition written as canonical JSON
  (keys sorted, no spaces, ASCII only; see `fingerprint`). The loader checks
  that a stored definition has the fingerprint stored with it, so a person
  shown a definition is shown what is compared.
* "sha256_v1" (tools only, and alone in its pin) is a tool pinned by a
  version 1 file and not listed since the upgrade. Its fingerprint covers the
  members version 1 pinned (TOOL_FIELDS_V1), and its definition is unknown.
* "first_seen" is when the definition was pinned, in UTC. For a tool carried
  over from version 1 it is when the version 2 pin replaced the old one.

Version 1 files, {"version": 1, "tools": {"read_file": "<64 hex>"}}, are
still read. The first time such a tool is listed, its fingerprint over the
version 1 members is compared with the stored one. Only if they match is the
tool pinned anew with every version 2 member; otherwise it changed, and it is
removed like any changed tool. So the upgrade gives a changed tool no free
pass. The file is written back as version 2.

The loader is strict: an unknown version, section or member, a repeated key,
a malformed fingerprint or a definition that does not match its fingerprint
is an error. Keep a pins file where the agent's tools cannot write: anything
that can edit it can make a changed definition look pinned.

Changes waiting
---------------
When a pinned entry changes, the proxy keeps the definition it was sent in a
second file beside the pins file, "<pins file>.pending" (pending_path), in
the same format and under the same limits. (A new definition the scanner
removes never gets as far as its pin, so it is not kept: accepting it would
not let it through.) Nothing reads the file automatically: it is for the
operator, who looks at the change with `agent-sentinel pins diff` and, on a
terminal, accepts it with `agent-sentinel pins accept` (cli_pins.py), which
scans it again. The changed entry stays removed until the proxy restarts.

A running proxy writes the pins file whole when it pins something new. It
writes the file as it is on disk plus what it pinned since its last write,
so a pin that `pins accept` or `pins forget` changed meanwhile is not put back.

The server itself (proxy --pin-server, opt-in)
----------------------------------------------
A server's code can change behind tool definitions that stay the same. With
--pin-server the proxy also pins the server, in an optional "server"
section of the same file:

    "server": {
      "first_seen": "2026-11-20T12:00:00Z",
      "launch": {"executable": "C:\\\\nodejs\\\\npx.cmd", "package": "npx mcp-remote@0.1.16",
                 "script": null, "script_sha256": null},
      "info": {"name": "mcp-remote", "version": "0.1.16"}
    }

* "launch" (launch.LAUNCH_FIELDS) is taken before the server starts: the
  program found for the command, the package a runner (npx, uvx, ...) runs
  as written, and the local script it starts with that file's SHA-256 (or
  the program file itself, when it is no interpreter). Each may be null.
* "info" is the name and version of the serverInfo the server sends in its
  handshake; absent until it has answered once. A value longer than
  MAX_SERVER_INFO_CHARS is kept as "sha256:<64 hex>" of it.

A launch that differs from its pin makes the proxy refuse to start (or, with
--on-server-change quarantine, start with every tool, prompt and template
quarantined); serverInfo that differs refuses the handshake (or quarantines).
The new identity waits in the pending file's "server" section for `pins
diff --server` and `pins accept --server`. An agent-sentinel older than 0.6
refuses a pins file with this section (it does not know it), which fails closed.

One format for both uses
------------------------
The "server" section is an optional part of version 2: the version number
stays 2, a file without the section reads as before, and a version 1 file
(which has neither definitions nor a server pin) is written back as version
2, with the section once --pin-server pins the server.

The proxy also reads the stored tool definitions at startup (definitions):
the annotations of each pinned tool give it its flow labels before any list
has shown it, and the pinned uriTemplate of a quarantined resource template
is refused as well as the one listed now. A tool whose definition was not
kept (too large, or carried over from version 1) seeds no labels. A server
quarantined for differing from its own pin still seeds them, from the
definitions pinned while it was trusted, but none of its tools can be
called, so they decide nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import jsonutil
from .filelock import replace_file
from .textutil import printable

PINS_VERSION = 2

# What version 1 (agent-sentinel 0.4) pinned of a tool.
TOOL_FIELDS_V1 = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
# What is pinned of an entry of each list, by the result member that holds the list.
PINNED_FIELDS = {
    "tools": TOOL_FIELDS_V1 + ("icons", "execution"),
    "prompts": ("name", "title", "description", "arguments", "icons"),
    "resourceTemplates": ("name", "title", "description", "uriTemplate", "mimeType", "annotations", "icons"),
}
PINNED_LISTS = tuple(PINNED_FIELDS)
INSTRUCTIONS = "instructions"
SERVER = "server"
# What the "server" section pins (see "The server itself"), and how long one value may be.
LAUNCH_FIELDS = ("executable", "package", "script", "script_sha256")
INFO_FIELDS = ("name", "version")
MAX_SERVER_VALUE_CHARS = 4096
MAX_SERVER_INFO_CHARS = 256
# How the pins command names each section (agent-sentinel pins ... --kind WORD).
KIND_WORDS = {"tools": "tool", "prompts": "prompt", "resourceTemplates": "template", INSTRUCTIONS: INSTRUCTIONS}

# Limits. Pinned text comes from the server, so everything kept is bounded.
MAX_PINS_PER_LIST = 10_000
MAX_NAME_CHARS = 256
MAX_DEFINITION_CHARS = 64 * 1024  # one stored definition, as canonical JSON
MAX_STORED_DEFINITION_CHARS = 8 * 1024 * 1024  # all stored definitions together
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_FIRST_SEEN_CHARS = 64

# What `check` answers.
SAME = "same"
CHANGED = "changed"
NEW = "new"  # first seen, and now pinned
FULL = "full"  # first seen, but too many are pinned to remember another

_SHA256 = re.compile(r"[0-9a-f]{64}")
_PIN_KEYS = ("sha256", "sha256_v1", "first_seen", "definition")


class PinsFileError(ValueError):
    """A pins file that cannot be used. The message names the file and the problem, never pinned text."""


@dataclass(frozen=True)
class Pin:
    """One pin: an entry of a section of the pins file (see the module docstring).

    sha256:     the fingerprint of the definition; None only for a pin carried over from version 1.
    sha256_v1:  for that carried-over pin: the fingerprint over TOOL_FIELDS_V1.
    first_seen: when it was pinned, as "2026-11-19T12:00:00Z".
    definition: the pinned members, when small enough to keep.
    """

    sha256: str | None = None
    sha256_v1: str | None = None
    first_seen: str | None = None
    definition: dict[str, Any] | None = None


@dataclass(frozen=True)
class ServerPin:
    """The server itself, pinned with proxy --pin-server (see "The server itself").

    launch:     LAUNCH_FIELDS -> value or None.
    info:       INFO_FIELDS -> value or None, once the server has answered a handshake; None before.
    first_seen: when it was pinned.
    """

    launch: dict[str, str | None]
    info: dict[str, str | None] | None = None
    first_seen: str | None = None


def server_info_value(value: Any) -> str | None:
    """A serverInfo name or version as the pin keeps it: text as it is, a long one as its SHA-256, else None."""
    if not isinstance(value, str):
        return None
    if len(value) <= MAX_SERVER_INFO_CHARS:
        return value
    return "sha256:" + hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def server_changes(pinned: dict[str, str | None] | None, seen: dict[str, str | None] | None) -> list[str]:
    """The fields of a launch or an info that differ; paths are compared as the system compares them."""
    if pinned is None or seen is None:
        return [] if pinned is seen else ["(all)"]
    changed = []
    for name in sorted(set(pinned) | set(seen)):
        old, new = pinned.get(name), seen.get(name)
        if name in ("executable", "script") and isinstance(old, str) and isinstance(new, str):
            old, new = os.path.normcase(old), os.path.normcase(new)
        if old != new:
            changed.append(name)
    return changed


@dataclass
class PinsFile:
    """What a pins file holds: one section per list (PINNED_LISTS), each name -> Pin, and the instructions' pin.

    `server`: the server's own pin (proxy --pin-server), or None.
    """

    lists: dict[str, dict[str, Pin]] = field(default_factory=lambda: {kind: {} for kind in PINNED_LISTS})
    instructions: Pin | None = None
    version: int = PINS_VERSION  # the version the file had when it was read
    server: ServerPin | None = None


# ---- fingerprints -----------------------------------------------------------------------

def definition_of(kind: str, item: dict[str, Any]) -> dict[str, Any]:
    """The members of a list entry that are pinned (PINNED_FIELDS[kind]), those it has."""
    return {name: item[name] for name in PINNED_FIELDS[kind] if name in item}


def canonical_json(definition: dict[str, Any]) -> str:
    """A definition as the one text its fingerprint is taken of: keys sorted, no spaces, ASCII only."""
    return json.dumps(definition, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fingerprint(definition: dict[str, Any]) -> str:
    """The SHA-256, in lowercase hex, of a definition's canonical JSON."""
    return hashlib.sha256(canonical_json(definition).encode("ascii")).hexdigest()


def v1_fingerprint(tool: dict[str, Any]) -> str:
    """A tool's fingerprint as version 1 took it: over TOOL_FIELDS_V1 only."""
    return fingerprint({name: tool[name] for name in TOOL_FIELDS_V1 if name in tool})


# ---- reading and writing the file --------------------------------------------------------

def read_pins_file(path: str | Path) -> PinsFile:
    """Read a pins file of version 1 or 2. Raises PinsFileError (or OSError if it cannot be read)."""
    path = Path(path)
    if path.stat().st_size > MAX_FILE_BYTES:
        raise PinsFileError(f"{path}: the pins file is larger than {MAX_FILE_BYTES} bytes")
    try:
        text = path.read_bytes().decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PinsFileError(f"{path}: the pins file is not UTF-8 text") from exc
    try:
        data = jsonutil.loads(text)
    except (ValueError, RecursionError) as exc:
        raise PinsFileError(f"{path}: the pins file is not valid JSON ({exc})") from exc
    try:
        return _pins_from(data)
    except PinsFileError as exc:
        raise PinsFileError(f"{path}: {exc}") from exc


def write_pins_file(path: str | Path, pins: PinsFile) -> None:
    """Write a pins file as version 2, atomically: a crash cannot leave half a file. Raises OSError."""
    text = json.dumps(pins_document(pins), indent=1, ensure_ascii=True)  # ASCII: safe to look at in a terminal
    replace_file(path, (text + "\n").encode("ascii"))


def pins_document(pins: PinsFile) -> dict[str, Any]:
    """The JSON form of a PinsFile, version 2."""
    document: dict[str, Any] = {"version": PINS_VERSION}
    for kind in PINNED_LISTS:
        document[kind] = {name: _pin_document(pin) for name, pin in pins.lists[kind].items()}
    if pins.instructions is not None:
        document[INSTRUCTIONS] = _pin_document(pins.instructions)
    if pins.server is not None:
        document[SERVER] = _server_document(pins.server)
    return document


def _server_document(pin: ServerPin) -> dict[str, Any]:
    document: dict[str, Any] = {}
    if pin.first_seen is not None:
        document["first_seen"] = pin.first_seen
    document["launch"] = {name: pin.launch.get(name) for name in LAUNCH_FIELDS}
    if pin.info is not None:
        document["info"] = {name: pin.info.get(name) for name in INFO_FIELDS}
    return document


def _pin_document(pin: Pin) -> dict[str, Any]:
    if pin.sha256_v1 is not None:
        return {"sha256_v1": pin.sha256_v1}
    document: dict[str, Any] = {"sha256": pin.sha256}
    if pin.first_seen is not None:
        document["first_seen"] = pin.first_seen
    if pin.definition is not None:
        document["definition"] = pin.definition
    return document


def _pins_from(data: Any) -> PinsFile:
    if not isinstance(data, dict) or "version" not in data:
        raise PinsFileError("not a pins file: expected a JSON object with a \"version\"")
    version = data["version"]
    if type(version) is int and version == 1:  # type(), not isinstance(): true and 1.0 are not versions
        return _pins_from_version_1(data)
    if type(version) is int and version == PINS_VERSION:
        return _pins_from_version_2(data)
    raise PinsFileError(f"pins file version {printable(version, limit=20)} is not one this agent-sentinel reads "
                        f"(it reads 1 and {PINS_VERSION})")


def _pins_from_version_1(data: dict[str, Any]) -> PinsFile:
    """{"version": 1, "tools": {name: fingerprint}}: every tool becomes a pin carried over from version 1."""
    _expect_keys(data, ("version", "tools"), "a version 1 pins file")
    tools = _section(data.get("tools", {}), "tools")
    pins = PinsFile(version=1)
    for name, sha in tools.items():
        if not isinstance(sha, str) or not _SHA256.fullmatch(sha):
            raise PinsFileError(f"tools '{printable(name, limit=80)}': a fingerprint must be 64 lowercase hex digits")
        pins.lists["tools"][name] = Pin(sha256_v1=sha)
    return pins


def _pins_from_version_2(data: dict[str, Any]) -> PinsFile:
    _expect_keys(data, ("version", *PINNED_LISTS, INSTRUCTIONS, SERVER), "a pins file")
    pins = PinsFile(version=PINS_VERSION)
    for kind in PINNED_LISTS:
        for name, entry in _section(data.get(kind, {}), kind).items():
            pins.lists[kind][name] = _pin_from(entry, kind, name)
    if INSTRUCTIONS in data:
        pins.instructions = _pin_from(data[INSTRUCTIONS], INSTRUCTIONS, None)
    if SERVER in data:
        pins.server = _server_pin_from(data[SERVER])
    return pins


def _server_pin_from(entry: Any) -> ServerPin:
    """Read the "server" section: every member known, every value text of bounded length or null."""
    if not isinstance(entry, dict):
        raise PinsFileError("\"server\" must be an object")
    _expect_keys(entry, ("first_seen", "launch", "info"), "\"server\"")
    first_seen = entry.get("first_seen")
    if first_seen is not None and (not isinstance(first_seen, str) or len(first_seen) > MAX_FIRST_SEEN_CHARS):
        raise PinsFileError("\"server\": \"first_seen\" must be a time written as text")
    if "launch" not in entry:
        raise PinsFileError("\"server\" needs a \"launch\"")
    launch = _server_values(entry["launch"], LAUNCH_FIELDS, "server.launch", MAX_SERVER_VALUE_CHARS)
    sha = launch.get("script_sha256")
    if sha is not None and not _SHA256.fullmatch(sha):
        raise PinsFileError("\"server.launch\": \"script_sha256\" must be 64 lowercase hex digits or null")
    info = None
    if "info" in entry:
        info = _server_values(entry["info"], INFO_FIELDS, "server.info", len("sha256:") + 64)
    return ServerPin(launch=launch, info=info, first_seen=first_seen)


def _server_values(value: Any, fields: tuple[str, ...], where: str, longest: int) -> dict[str, str | None]:
    if not isinstance(value, dict):
        raise PinsFileError(f"\"{where}\" must be an object")
    _expect_keys(value, fields, f"\"{where}\"")
    found: dict[str, str | None] = {}
    for name in fields:
        item = value.get(name)
        if item is not None and (not isinstance(item, str) or len(item) > longest):
            raise PinsFileError(f"\"{where}\": \"{name}\" must be text of at most {longest} characters, or null")
        found[name] = item
    return found


def _section(value: Any, kind: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PinsFileError(f"\"{kind}\" must be an object of names")
    if len(value) > MAX_PINS_PER_LIST:
        raise PinsFileError(f"\"{kind}\" has {len(value)} entries; at most {MAX_PINS_PER_LIST} are read")
    for name in value:
        if not 0 < len(name) <= MAX_NAME_CHARS:
            raise PinsFileError(f"a name in \"{kind}\" is not 1 to {MAX_NAME_CHARS} characters long")
    return value


def _pin_from(entry: Any, kind: str, name: str | None) -> Pin:
    """Read one pin, checking that its stored definition (if any) belongs to it and has its fingerprint."""
    where = kind if name is None else f"{kind} '{printable(name, limit=80)}'"
    if not isinstance(entry, dict):
        raise PinsFileError(f"{where}: a pin must be an object")
    _expect_keys(entry, _PIN_KEYS, where)
    if "sha256_v1" in entry:
        if kind != "tools" or len(entry) != 1:
            raise PinsFileError(f"{where}: \"sha256_v1\" is only used alone, for a tool pinned by a version 1 file")
        return Pin(sha256_v1=_hex(entry["sha256_v1"], where))
    if "sha256" not in entry:
        raise PinsFileError(f"{where}: a pin needs a \"sha256\"")
    sha = _hex(entry["sha256"], where)
    first_seen = entry.get("first_seen")
    if first_seen is not None and (not isinstance(first_seen, str) or len(first_seen) > MAX_FIRST_SEEN_CHARS):
        raise PinsFileError(f"{where}: \"first_seen\" must be a time written as text")
    definition = entry.get("definition")
    if definition is not None:
        _check_definition(definition, kind, name, where)
        if fingerprint(definition) != sha:
            raise PinsFileError(f"{where}: the stored definition does not match its sha256; "
                                "the file was edited by hand or damaged")
    return Pin(sha256=sha, first_seen=first_seen, definition=definition)


def _check_definition(definition: Any, kind: str, name: str | None, where: str) -> None:
    if kind == INSTRUCTIONS:
        if not isinstance(definition, dict) or set(definition) != {INSTRUCTIONS} or not isinstance(
            definition[INSTRUCTIONS], str
        ):
            raise PinsFileError(f"{where}: the definition must be {{\"instructions\": <text>}}")
        return
    if not isinstance(definition, dict):
        raise PinsFileError(f"{where}: the definition must be an object")
    _expect_keys(definition, PINNED_FIELDS[kind], f"{where}: the definition")
    if definition.get("name") != name:
        raise PinsFileError(f"{where}: the definition has another name")


def _hex(value: Any, where: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise PinsFileError(f"{where}: a fingerprint must be 64 lowercase hex digits")
    return value


def _expect_keys(value: dict[str, Any], allowed: tuple[str, ...], where: str) -> None:
    unknown = [key for key in value if key not in allowed]
    if unknown:
        raise PinsFileError(
            f"{where} has the unknown key '{printable(unknown[0], limit=80)}' (allowed: {', '.join(allowed)})"
        )


def pending_path(path: str | Path) -> Path:
    """Where the changed definitions of a pins file wait for the operator: "<pins file>.pending"."""
    path = Path(path)
    return path.with_name(path.name + ".pending")


def now() -> str:
    """The time now, as a pin's first_seen: "2026-11-19T12:00:00Z" (UTC)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_pin(definition: dict[str, Any], stored_chars: int = 0) -> Pin:
    """A pin of a definition seen now; the definition is kept only within the limits.

    stored_chars: how much the file already stores in definitions
    (MAX_STORED_DEFINITION_CHARS bounds the total). The stored definition is
    a copy read back from the canonical text, so it is exactly what was fingerprinted.
    """
    text = canonical_json(definition)
    keep = len(text) <= MAX_DEFINITION_CHARS and stored_chars + len(text) <= MAX_STORED_DEFINITION_CHARS
    return Pin(sha256=fingerprint(definition), first_seen=now(), definition=json.loads(text) if keep else None)


def stored_chars(pins: PinsFile) -> int:
    """How many characters of definitions a PinsFile stores (for MAX_STORED_DEFINITION_CHARS)."""
    every = [pin for section in pins.lists.values() for pin in section.values()]
    every += [pins.instructions] if pins.instructions is not None else []
    return sum(len(canonical_json(pin.definition)) for pin in every if pin.definition is not None)


# ---- the pins of one running proxy ----------------------------------------------------------

class ToolPins:
    """The pins of one server: in memory, and in a pins file when there is one. Thread-safe.

    Despite the name (kept from 0.4), it pins prompts, resource templates and
    the server's instructions as well as tools. Use one file per server. A
    changed entry stays removed while the proxy runs; its new definition
    waits in the pending file (see "Changes waiting") for `agent-sentinel
    pins accept`, after which the proxy is restarted.
    """

    def __init__(self, path: str | Path | None = None, enabled: bool = True) -> None:
        """path: the pins file, read now if it exists (PinsFileError if it cannot be used); None to keep pins in memory.
        enabled: False pins nothing: every check answers SAME.
        """
        self._enabled = enabled
        self._path = Path(path) if path else None
        self._lock = threading.Lock()
        self._pins = PinsFile()
        if self._path is not None and self._path.exists():
            self._pins = read_pins_file(self._path)
        self._stored_chars = stored_chars(self._pins)
        self._unsaved = False
        # What this process pinned itself since it last wrote the file (section, name; INSTRUCTIONS, None for
        # the instructions): only these are written over what is on disk (see save).
        self._added: set[tuple[str, str | None]] = set()
        # The changed definitions seen by this process, for the pending file (see "Changes waiting").
        self._pending = PinsFile()
        self._pending_chars = 0
        self._pending_unsaved = False
        # The server's own pin (see "The server itself"): whether this process made or completed it, and whether
        # the launch it saw differs from the pin (its serverInfo is then never written into the pin).
        self._server_added = False
        self._server_launch_changed = False

    @property
    def path(self) -> Path | None:
        """The pins file, or None when pins are kept in memory only."""
        return self._path

    @staticmethod
    def fingerprint(tool: dict[str, Any]) -> str:
        """The fingerprint of a tool definition (its PINNED_FIELDS["tools"] members)."""
        return fingerprint(definition_of("tools", tool))

    def check(self, name: str, tool: dict[str, Any]) -> str:
        """check_item for a tool."""
        return self.check_item("tools", name, tool)

    def check_item(self, kind: str, name: str, item: dict[str, Any]) -> str:
        """Compare an entry of a list (PINNED_LISTS) with its pin: SAME, CHANGED, NEW (now pinned) or FULL.

        An entry pinned by a version 1 file is compared over the members that
        version pinned; if they match, it is pinned anew with every member.
        """
        if not self._enabled:
            return SAME
        definition = definition_of(kind, item)
        sha = fingerprint(definition)
        with self._lock:
            pins = self._pins.lists[kind]
            pin = pins.get(name)
            if pin is None:
                if len(pins) >= MAX_PINS_PER_LIST:
                    return FULL
                pins[name] = self._new_pin(definition, kind, name)
                return NEW
            if pin.sha256_v1 is not None:
                if pin.sha256_v1 != v1_fingerprint(item):
                    self._note_pending(kind, name, definition, sha)
                    return CHANGED
                # The members version 1 did not pin are trusted now.
                pins[name] = self._new_pin(definition, kind, name)
                return SAME
            if pin.sha256 == sha:
                return SAME
            self._note_pending(kind, name, definition, sha)
            return CHANGED

    def check_instructions(self, text: str) -> str:
        """Compare the server's instructions with their pin: SAME, CHANGED or NEW (now pinned)."""
        if not self._enabled:
            return SAME
        definition = {INSTRUCTIONS: text}
        sha = fingerprint(definition)
        with self._lock:
            if self._pins.instructions is None:
                self._pins.instructions = self._new_pin(definition, INSTRUCTIONS, None)
                return NEW
            if self._pins.instructions.sha256 == sha:
                return SAME
            self._note_pending(INSTRUCTIONS, None, definition, sha)
            return CHANGED

    def names(self, kind: str) -> list[str]:
        """The pinned names of one list, in the order they were pinned."""
        with self._lock:
            return list(self._pins.lists[kind])

    def definitions(self, kind: str) -> dict[str, dict[str, Any]]:
        """The pinned definitions of one list that are kept, by name (a pin too large to keep, or carried
        over from version 1, has none). With pins off (enabled=False), nothing: nothing is compared either.

        The proxy reads the tools' annotations from them at startup, and the
        uriTemplate of a resource template it quarantines.
        """
        if not self._enabled:
            return {}
        with self._lock:
            return {name: pin.definition for name, pin in self._pins.lists[kind].items() if pin.definition is not None}

    def definition(self, kind: str, name: str) -> dict[str, Any] | None:
        """The pinned definition of one entry, if one is kept (see definitions); None otherwise."""
        if not self._enabled:
            return None
        with self._lock:
            pin = self._pins.lists[kind].get(name)
            return pin.definition if pin is not None else None

    @property
    def server_pin(self) -> ServerPin | None:
        """The server's own pin (proxy --pin-server), or None."""
        with self._lock:
            return self._pins.server

    def check_server_launch(self, launch: dict[str, str | None]) -> tuple[str, list[str]]:
        """Compare how the server is launched (launch.launch_identity) with its pin.

        (NEW, []) pins it, (SAME, []), or (CHANGED, the fields that differ):
        the launch seen then waits in the pending file for `pins accept --server`.
        """
        if not self._enabled:
            return SAME, []
        with self._lock:
            pin = self._pins.server
            if pin is None:
                self._pins.server = ServerPin(launch=dict(launch), first_seen=now())
                self._server_added = self._unsaved = True
                return NEW, []
            changed = server_changes(pin.launch, launch)
            if not changed:
                return SAME, []
            self._server_launch_changed = True
            self._note_server_pending(launch=launch)
            return CHANGED, changed

    def check_server_info(self, info: dict[str, str | None]) -> tuple[str, list[str]]:
        """Compare the serverInfo of a handshake ({"name", "version"}, see server_info_value) with the pin.

        (NEW, []) when none was pinned yet (it is now, unless the launch
        differed from its pin), (SAME, []), or (CHANGED, the fields): the
        identity seen then waits in the pending file.
        """
        if not self._enabled:
            return SAME, []
        with self._lock:
            pin = self._pins.server
            if self._server_launch_changed:
                self._note_server_pending(info=info)  # with the launch seen, for `pins accept --server`
            if pin is None or pin.info is None:
                if self._server_launch_changed:
                    return SAME, []  # the server is held back for its launch already; nothing new is trusted
                launch = pin.launch if pin is not None else {name: None for name in LAUNCH_FIELDS}
                self._pins.server = ServerPin(launch=dict(launch), info=dict(info),
                                              first_seen=pin.first_seen if pin is not None else now())
                self._server_added = self._unsaved = True
                return NEW, []
            changed = server_changes(pin.info, info)
            if not changed:
                return SAME, []
            self._note_server_pending(info=info)
            return CHANGED, changed

    def _note_server_pending(self, launch: dict[str, str | None] | None = None,
                             info: dict[str, str | None] | None = None) -> None:
        """Keep the server identity seen for the pending file: the pin with what differed put in. Lock held.

        After a changed launch, the pinned serverInfo is not carried over: a
        new launch (a new version) is expected to say something new, and once
        accepted the proxy pins what it says at its next start.
        """
        if self._path is None:
            return
        pinned = self._pins.server
        waiting = self._pending.server or ServerPin(
            launch=dict(pinned.launch) if pinned is not None else {name: None for name in LAUNCH_FIELDS},
            info=dict(pinned.info) if pinned is not None and pinned.info is not None
            and not self._server_launch_changed else None)
        self._pending.server = ServerPin(launch=dict(launch) if launch is not None else waiting.launch,
                                         info=dict(info) if info is not None else waiting.info, first_seen=now())
        self._pending_unsaved = True

    def save(self) -> None:
        """Write the pins file and the pending file, if there is a file and anything changed. Raises OSError.

        The pins file is written as it is on disk now, plus the pins this
        process made since it last wrote the file: a pin the operator
        accepted or forgot meanwhile (agent-sentinel pins accept / forget) is
        kept as they left it, even one this process made earlier. A pins file
        that has become unreadable is written from memory.
        """
        if self._path is None:
            return
        with self._lock:
            if self._unsaved:
                write_pins_file(self._path, self._merged_with_disk())
                self._unsaved = False
                # Written: from now on the file on disk is the operator's to change. A pin missing from it
                # later was forgotten on purpose, and must not be put back by the next save.
                self._added.clear()
                self._server_added = False
            if self._pending_unsaved:
                write_pins_file(pending_path(self._path), self._pending_merged_with_disk())
                self._pending_unsaved = False

    def _new_pin(self, definition: dict[str, Any], kind: str, name: str | None) -> Pin:
        """A pin for a definition seen now, which this process made. Called with the lock held."""
        pin = new_pin(definition, self._stored_chars)
        if pin.definition is not None:
            self._stored_chars += len(canonical_json(pin.definition))
        self._unsaved = True
        self._added.add((kind, name))
        return pin

    def _note_pending(self, kind: str, name: str | None, definition: dict[str, Any], sha: str) -> None:
        """Keep a changed definition for the pending file (only with a pins file). Called with the lock held."""
        if self._path is None:
            return
        waiting = self._pending.instructions if kind == INSTRUCTIONS else self._pending.lists[kind].get(name or "")
        if waiting is not None and waiting.sha256 == sha:
            return  # the same change, seen again
        if kind != INSTRUCTIONS and waiting is None and len(self._pending.lists[kind]) >= MAX_PINS_PER_LIST:
            return
        pin = new_pin(definition, self._pending_chars)
        if pin.definition is not None:
            self._pending_chars += len(canonical_json(pin.definition))
        if kind == INSTRUCTIONS:
            self._pending.instructions = pin
        else:
            self._pending.lists[kind][name or ""] = pin
        self._pending_unsaved = True

    def _merged_with_disk(self) -> PinsFile:
        """The pins file as it is on disk, with the pins this process made put in. Called with the lock held.

        A pin this process made replaces the one on disk only where the disk
        has none, or has one carried over from version 1 that this process
        upgraded. Without a readable file on disk, the pins in memory.
        """
        try:
            merged = read_pins_file(self._path) if self._path is not None and self._path.exists() else None
        except (OSError, ValueError):
            merged = None
        if merged is None:
            return self._pins
        for kind, name in sorted(self._added, key=lambda key: (key[0], key[1] or "")):
            ours = self._pins.instructions if kind == INSTRUCTIONS else self._pins.lists[kind].get(name or "")
            theirs = merged.instructions if kind == INSTRUCTIONS else merged.lists[kind].get(name or "")
            if ours is None or (theirs is not None and theirs.sha256_v1 is None):
                continue
            if kind == INSTRUCTIONS:
                merged.instructions = ours
            elif len(merged.lists[kind]) < MAX_PINS_PER_LIST or theirs is not None:
                merged.lists[kind][name or ""] = ours
        ours_server, theirs_server = self._pins.server, merged.server
        # The server pin this process made, or completed with its serverInfo, goes in where the disk has none,
        # or has the same launch without an info yet; one the operator accepted meanwhile is kept.
        if self._server_added and ours_server is not None and (theirs_server is None or (
                theirs_server.info is None and not server_changes(theirs_server.launch, ours_server.launch))):
            merged.server = ours_server
        return merged

    def _pending_merged_with_disk(self) -> PinsFile:
        """The pending file on disk with this process's changes put in; it starts afresh if it cannot be read."""
        assert self._path is not None
        try:
            merged = read_pins_file(pending_path(self._path))
        except (OSError, ValueError):
            merged = PinsFile()
        for kind in PINNED_LISTS:
            for name, pin in self._pending.lists[kind].items():
                if name in merged.lists[kind] or len(merged.lists[kind]) < MAX_PINS_PER_LIST:
                    merged.lists[kind][name] = pin
        if self._pending.instructions is not None:
            merged.instructions = self._pending.instructions
        if self._pending.server is not None:
            merged.server = self._pending.server
        return merged
