"""`doctor --save-baseline FILE` and `doctor --baseline FILE`: notice what was added to the configurations, or changed.

Malware and worms add MCP servers and hooks to client configurations
(SANDWORM_MODE), and an approved configuration can change later without a
prompt (MCPoison). doctor --save-baseline records what the configurations
hold now; doctor --baseline compares with that record and fails (exit 1)
on anything added, changed or removed, and says which by name only.

What is recorded, each as an HMAC-SHA256 under a random key kept in the file:

    every MCP configuration doctor checks: each member of each server entry
        ("command", "args", "type", "url", "cwd", ...), with "env" and "headers"
        reduced to their sorted NAMES: a new token value changes nothing,
        a new variable does
    Claude Code's settings files (claude_settings: the user's, and the
    project's in the current folder):
        "hooks", one item per event (every matcher and command of it)
        "env", one item per variable (its value: ANTHROPIC_BASE_URL and the like)
        enableAllProjectMcpServers, disableAllHooks, enabledMcpjsonServers

A value is never written to the file and never printed. The key makes a
weak value (a short password in "env") costly to guess from the file, but
not impossible: keep the baseline where only you can read it (it is written
0600 on POSIX). Run doctor --baseline from the folder the baseline was saved
in, with the same --config files: a project's configuration is found there.

The file:

    {"agent_sentinel_baseline": 1, "saved": "2026-11-20T12:00:00Z", "key": "<64 hex>",
     "items": [{"where": ["config", "C:/work/app/.mcp.json", "server", "files", "args"], "hmac": "<64 hex>"}, ...]}
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import jsonutil
from .cli_common import CommandError
from .filelock import replace_file
from .textutil import printable

BASELINE_VERSION = 1
MAX_BASELINE_BYTES = 16 * 1024 * 1024
MAX_ITEMS = 100_000
MAX_WHERE_PARTS = 6
MAX_NAME_CHARS = 4096
# The members of a Claude Code settings file that are recorded whole (besides "hooks" and "env").
SETTINGS_KEYS = ("enableAllProjectMcpServers", "disableAllHooks", "enabledMcpjsonServers")
# Server members recorded by name only.
NAMES_ONLY = ("env", "headers")
_HEX64 = frozenset("0123456789abcdef")

Where = tuple[str, ...]


@dataclass
class Baseline:
    key: bytes
    items: dict[Where, str] = field(default_factory=dict)
    saved: str = ""


def new_key() -> bytes:
    return secrets.token_bytes(32)


def _digest(key: bytes, value: Any) -> str:
    """The HMAC of a value written as canonical JSON (keys sorted, ASCII only)."""
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError, RecursionError):
        text = repr(value)
    return hmac.new(key, text.encode("ascii", "backslashreplace"), hashlib.sha256).hexdigest()


def config_items(key: bytes, path: str, servers: Any) -> dict[Where, str]:
    """The items of one MCP configuration: each member of each server entry (env and headers by name only)."""
    items: dict[Where, str] = {}
    if not isinstance(servers, dict):
        items[("config", path, "servers")] = _digest(key, servers)
        return items
    for name, entry in servers.items():
        where = ("config", path, "server", str(name))
        if not isinstance(entry, dict):
            items[(*where, "(entry)")] = _digest(key, entry)
            continue
        for member, value in entry.items():
            if member in NAMES_ONLY and isinstance(value, dict):
                value = sorted(str(variable) for variable in value)
            items[(*where, str(member))] = _digest(key, value)
    return items


def settings_items(key: bytes, path: str, document: dict[str, Any] | None, error: str | None) -> dict[Where, str]:
    """The items of one Claude Code settings file (see the module docstring)."""
    if document is None:
        return {("settings", path, "(cannot be read)"): _digest(key, error or "")}
    items: dict[Where, str] = {("settings", path, "(file)"): _digest(key, "present")}
    hooks = document.get("hooks")
    if isinstance(hooks, dict):
        for event, groups in hooks.items():
            items[("settings", path, "hooks", str(event))] = _digest(key, groups)
    elif hooks is not None:
        items[("settings", path, "hooks")] = _digest(key, hooks)
    env = document.get("env")
    if isinstance(env, dict):
        for name, value in env.items():
            items[("settings", path, "env", str(name))] = _digest(key, value)
    elif env is not None:
        items[("settings", path, "env")] = _digest(key, env)
    for name in SETTINGS_KEYS:
        if name in document:
            items[("settings", path, name)] = _digest(key, document[name])
    return items


# ---- the file ------------------------------------------------------------------------------------

def save(path: Path, baseline: Baseline) -> None:
    """Write the baseline atomically, readable by its owner only. Raises CommandError."""
    if len(baseline.items) > MAX_ITEMS:
        raise CommandError(f"the configurations hold more than {MAX_ITEMS} items, more than a baseline keeps")
    document = {
        "agent_sentinel_baseline": BASELINE_VERSION,
        "saved": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "key": baseline.key.hex(),
        "items": [{"where": list(where), "hmac": digest} for where, digest in sorted(baseline.items.items())],
    }
    if not path.parent.is_dir():
        raise CommandError(f"the folder {path.parent} does not exist; create it first, or give another file")
    try:
        replace_file(path, (json.dumps(document, indent=1, ensure_ascii=True) + "\n").encode("ascii"))
    except OSError as exc:
        raise CommandError(f"cannot write the baseline {path}: {exc.strerror or exc}") from exc


def load(path: Path) -> Baseline:
    """Read a baseline strictly. CommandError when it cannot be read or is not one."""
    try:
        if os.path.getsize(path) > MAX_BASELINE_BYTES:
            raise CommandError(f"{path} is larger than {MAX_BASELINE_BYTES} bytes, which no baseline is")
        data = jsonutil.loads(path.read_bytes().decode("utf-8-sig"))
    except FileNotFoundError:
        raise CommandError(f"there is no baseline at {path}; save one with doctor --save-baseline FILE") from None
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise CommandError(f"cannot read the baseline {path}: {printable(exc, limit=200)}") from None
    problem = _problem(data)
    if problem:
        raise CommandError(f"{path} is not a baseline doctor can use: {problem}")
    items = {tuple(item["where"]): item["hmac"] for item in data["items"]}
    return Baseline(bytes.fromhex(data["key"]), items, data["saved"])


def _problem(data: Any) -> str | None:
    if not isinstance(data, dict) or set(data) != {"agent_sentinel_baseline", "saved", "key", "items"}:
        return "expected an object with agent_sentinel_baseline, saved, key and items"
    if data["agent_sentinel_baseline"] != BASELINE_VERSION or type(data["agent_sentinel_baseline"]) is not int:
        return f"its version is not {BASELINE_VERSION}"
    if not isinstance(data["saved"], str) or len(data["saved"]) > 64:
        return "\"saved\" is not a time"
    if not _hex64(data["key"]):
        return "\"key\" is not 64 hex digits"
    items = data["items"]
    if not isinstance(items, list) or len(items) > MAX_ITEMS:
        return f"\"items\" is not a list of at most {MAX_ITEMS}"
    for item in items:
        if not isinstance(item, dict) or set(item) != {"where", "hmac"} or not _hex64(item["hmac"]):
            return "an item is not {\"where\": [...], \"hmac\": <64 hex>}"
        where = item["where"]
        if (not isinstance(where, list) or not 2 <= len(where) <= MAX_WHERE_PARTS
                or not all(isinstance(part, str) and len(part) <= MAX_NAME_CHARS for part in where)):
            return "an item's \"where\" is not a short list of names"
    return None


def _hex64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX64


# ---- comparing -------------------------------------------------------------------------------------

def changes(old: dict[Where, str], new: dict[Where, str]) -> list[tuple[str, Where]]:
    """("added" | "changed" | "removed", where) for each item that differs, in a stable order."""
    found = [("added" if where not in old else "changed", where)
             for where, digest in new.items() if old.get(where) != digest]
    found += [("removed", where) for where in old if where not in new]
    return sorted(found, key=lambda change: (change[1], change[0]))


def described(found: list[tuple[str, Where]]) -> list[str]:
    """One printable line per server or setting that differs, naming what differs and never a value.

    The members of one server are said together: "changed server 'files' in C:/x/.mcp.json: args, env".
    """
    by_server: dict[tuple[str, Where], list[str]] = {}
    lines = []
    for change, where in found:
        if where[0] == "config" and len(where) == 5:
            by_server.setdefault((change, where[:4]), []).append(where[4])
        else:
            lines.append(_setting_line(change, where))
    for (change, where), members in by_server.items():
        _, path, _, name = where
        target = "to" if change == "added" else "from" if change == "removed" else "in"
        lines.append(f"{change} server '{printable(name, limit=80)}' {target} {printable(path, limit=300)}: "
                     + ", ".join(printable(member, limit=60) for member in members[:20])
                     + (" ..." if len(members) > 20 else ""))
    return sorted(lines)


def _setting_line(change: str, where: Where) -> str:
    kind, path, *names = where
    what = " ".join(printable(name, limit=80) for name in names) or "(file)"
    target = "to" if change == "added" else "from" if change == "removed" else "in"
    return f"{change} {what} {target} {printable(path, limit=300)}" + (" (servers)" if kind == "config" else "")
