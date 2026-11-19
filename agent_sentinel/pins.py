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
writes the file as it is on disk plus what it pinned itself, so a pin that
`pins accept` or `pins forget` changed meanwhile is not put back.
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


@dataclass
class PinsFile:
    """What a pins file holds: one section per list (PINNED_LISTS), each name -> Pin, and the instructions' pin."""

    lists: dict[str, dict[str, Pin]] = field(default_factory=lambda: {kind: {} for kind in PINNED_LISTS})
    instructions: Pin | None = None
    version: int = PINS_VERSION  # the version the file had when it was read


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
        data = json.loads(text, object_pairs_hook=_no_repeated_keys, parse_constant=_no_constant)
    except (ValueError, RecursionError) as exc:
        raise PinsFileError(f"{path}: the pins file is not valid JSON ({exc})") from exc
    try:
        return _pins_from(data)
    except PinsFileError as exc:
        raise PinsFileError(f"{path}: {exc}") from exc


def write_pins_file(path: str | Path, pins: PinsFile) -> None:
    """Write a pins file as version 2, atomically: a crash cannot leave half a file. Raises OSError."""
    path = Path(path)
    text = json.dumps(pins_document(pins), indent=1, ensure_ascii=True)  # ASCII: safe to look at in a terminal
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text + "\n", encoding="utf-8")
    os.replace(temporary, path)


def pins_document(pins: PinsFile) -> dict[str, Any]:
    """The JSON form of a PinsFile, version 2."""
    document: dict[str, Any] = {"version": PINS_VERSION}
    for kind in PINNED_LISTS:
        document[kind] = {name: _pin_document(pin) for name, pin in pins.lists[kind].items()}
    if pins.instructions is not None:
        document[INSTRUCTIONS] = _pin_document(pins.instructions)
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


def _no_repeated_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    found: dict[str, Any] = {}
    for key, value in pairs:
        if key in found:
            raise ValueError(f"the key '{printable(key, limit=80)}' appears twice in one object")
        found[key] = value
    return found


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


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
    _expect_keys(data, ("version", *PINNED_LISTS, INSTRUCTIONS), "a pins file")
    pins = PinsFile(version=PINS_VERSION)
    for kind in PINNED_LISTS:
        for name, entry in _section(data.get(kind, {}), kind).items():
            pins.lists[kind][name] = _pin_from(entry, kind, name)
    if INSTRUCTIONS in data:
        pins.instructions = _pin_from(data[INSTRUCTIONS], INSTRUCTIONS, None)
    return pins


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
        # What this process pinned itself (section, name; INSTRUCTIONS, None for the instructions): only
        # these are written over what is on disk (see save).
        self._added: set[tuple[str, str | None]] = set()
        # The changed definitions seen by this process, for the pending file (see "Changes waiting").
        self._pending = PinsFile()
        self._pending_chars = 0
        self._pending_unsaved = False

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

    def save(self) -> None:
        """Write the pins file and the pending file, if there is a file and anything changed. Raises OSError.

        The pins file is written as it is on disk now, plus the pins this
        process made itself: a pin the operator accepted or forgot meanwhile
        (agent-sentinel pins accept / forget) is kept as they left it. A
        pins file that has become unreadable is written from memory.
        """
        if self._path is None:
            return
        with self._lock:
            if self._unsaved:
                write_pins_file(self._path, self._merged_with_disk())
                self._unsaved = False
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
        return merged
