"""The MCP clients agent-sentinel knows: where their configurations are, and how to print an entry for the others.

Editable (plain JSON, so `wrap` can change them):

    claude-desktop  claude_desktop_config.json, "mcpServers"
                    Windows:  %APPDATA%\\Claude\\  and, for the Microsoft Store (MSIX) app,
                              %LOCALAPPDATA%\\Packages\\Claude_*\\LocalCache\\Roaming\\Claude\\
                    macOS:    ~/Library/Application Support/Claude/
                    Linux:    ~/.config/Claude/
    cursor          ~/.cursor/mcp.json (user), .cursor/mcp.json (project), "mcpServers"
    vscode          .vscode/mcp.json (project), "servers"
    claude-code     .mcp.json (project), "mcpServers"
    windsurf        ~/.config/devin/mcp_config.json (%APPDATA%\\devin\\ on Windows), "mcpServers";
                    ~/.codeium/windsurf/mcp_config.json is read only for discovery

Snippet only (a format agent-sentinel does not edit, or app state): Claude
Code's user scope (`claude mcp add`), Codex (TOML), Cline, Antigravity,
and "other" for any client that takes a command and its arguments.

Everything is worked out from the environment and the folder given, never
cached, so that tests (and cautious users) can point it all at a temporary
folder by setting HOME / USERPROFILE / APPDATA / LOCALAPPDATA / XDG_CONFIG_HOME.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import home
from .cli_common import CommandError, shell_line

MAX_EXTENSIONS_LISTED = 100


@dataclass(frozen=True)
class Client:
    name: str
    label: str
    servers_key: str  # where the configuration keeps its servers
    editable: bool  # `wrap` may change its configuration file
    restart: str  # what to do so that the client starts the wrapped servers
    note: str = ""  # for snippet-only clients: where the entry goes


CLIENTS: dict[str, Client] = {client.name: client for client in (
    Client("claude-desktop", "Claude Desktop", "mcpServers", True,
           "Quit Claude Desktop completely (also from the system tray or menu bar) and start it again. "
           "Proxy messages appear in Claude's log folder, in mcp-server-<name>.log."),
    Client("cursor", "Cursor", "mcpServers", True,
           "Restart Cursor, or turn each server off and on in its MCP settings. "
           "Proxy messages appear in the Output panel (MCP Logs)."),
    Client("vscode", "VS Code", "servers", True,
           "Restart each server (command palette: MCP: List Servers). Proxy messages appear in its output."),
    Client("claude-code", "Claude Code", "mcpServers", True,
           "Start a new Claude Code session in this project (approve the changed servers if asked); /mcp shows them."),
    Client("windsurf", "Windsurf", "mcpServers", True,
           "Refresh the MCP servers in Windsurf's settings, or restart Windsurf."),
    Client("cline", "Cline", "mcpServers", False, "Cline restarts a server when its settings change.",
           "Open Cline's MCP settings (Configure MCP Servers) and put the entry under \"mcpServers\"."),
    Client("antigravity", "Antigravity", "mcpServers", False, "Restart the Antigravity CLI.",
           "Put the entry under \"mcpServers\" in ~/.gemini/config/mcp_config.json "
           "(or .agents/mcp_config.json in a project)."),
    Client("codex", "Codex", "mcp_servers", False, "Start a new Codex session.",
           "Codex keeps its servers in ~/.codex/config.toml, which agent-sentinel does not edit."),
    Client("other", "another client", "mcpServers", False, "Restart the client.",
           "Give your client this command and these arguments, in the format it documents."),
)}


@dataclass(frozen=True)
class Location:
    """Where one client keeps one configuration."""

    client: str
    scope: str  # "user" or "project"
    path: Path
    note: str = ""  # said when it is listed, for example how the file is used


def _user_folder(environ: Mapping[str, str], platform: str) -> Path | None:
    return home.user_folder(environ, platform)


def _config_home(environ: Mapping[str, str], user: Path | None) -> Path | None:
    """$XDG_CONFIG_HOME, else ~/.config (Linux and the other non-Windows systems)."""
    chosen = environ.get("XDG_CONFIG_HOME", "")
    if chosen and chosen.startswith("/"):
        return Path(chosen)
    return user / ".config" if user is not None else None


def desktop_locations(environ: Mapping[str, str], platform: str) -> list[Location]:
    """Claude Desktop's configuration files that exist (or the usual one, if none does)."""
    user = _user_folder(environ, platform)
    name = "claude_desktop_config.json"
    if platform == "win32":
        found = []
        appdata = environ.get("APPDATA", "")
        if appdata and home.is_absolute(appdata, platform):
            found.append(Location("claude-desktop", "user", Path(appdata) / "Claude" / name))
        local = environ.get("LOCALAPPDATA", "")
        if local and home.is_absolute(local, platform):
            packages = Path(local) / "Packages"
            try:
                folders = sorted(packages.glob("Claude_*"))[:10] if packages.is_dir() else []
            except OSError:
                folders = []
            for folder in folders:
                found.append(Location(
                    "claude-desktop", "user", folder / "LocalCache" / "Roaming" / "Claude" / name,
                    "the copy the Microsoft Store (MSIX) app reads",
                ))
        return found
    if platform == "darwin":
        if user is None:
            return []
        return [Location("claude-desktop", "user", user / "Library" / "Application Support" / "Claude" / name)]
    config_home = _config_home(environ, user)
    return [Location("claude-desktop", "user", config_home / "Claude" / name)] if config_home else []


def windsurf_locations(environ: Mapping[str, str], platform: str) -> list[Location]:
    user = _user_folder(environ, platform)
    found = []
    if platform == "win32":
        appdata = environ.get("APPDATA", "")
        if appdata and home.is_absolute(appdata, platform):
            found.append(Location("windsurf", "user", Path(appdata) / "devin" / "mcp_config.json"))
    else:
        config_home = _config_home(environ, user)
        if config_home is not None:
            found.append(Location("windsurf", "user", config_home / "devin" / "mcp_config.json"))
    if user is not None:
        found.append(Location("windsurf", "user", user / ".codeium" / "windsurf" / "mcp_config.json",
                              "older location, read only for discovery: Windsurf uses the devin file"))
    return found


def all_locations(environ: Mapping[str, str] | None = None, cwd: str | Path | None = None,
                  platform: str | None = None) -> list[Location]:
    """Every configuration location agent-sentinel knows, for this user and the project in `cwd`."""
    environ = os.environ if environ is None else environ
    platform = platform or sys.platform
    project = Path(cwd if cwd is not None else os.getcwd())
    user = _user_folder(environ, platform)
    found = desktop_locations(environ, platform)
    if user is not None:
        found.append(Location("cursor", "user", user / ".cursor" / "mcp.json"))
    found.append(Location("cursor", "project", project / ".cursor" / "mcp.json"))
    found.append(Location("vscode", "project", project / ".vscode" / "mcp.json"))
    found.append(Location("claude-code", "project", project / ".mcp.json"))
    found.extend(windsurf_locations(environ, platform))
    return _each_file_once(found)


def _each_file_once(locations: list[Location]) -> list[Location]:
    """The locations without repeats: in the home folder, the project's .cursor/mcp.json is the user's.

    Listed twice, one file would be checked twice, and its servers would
    seem to share their pins files with themselves.
    """
    seen: set[str] = set()
    unique = []
    for location in locations:
        key = os.path.normcase(os.path.abspath(location.path))
        if key not in seen:
            seen.add(key)
            unique.append(location)
    return unique


def target_for(client: str, project: bool, environ: Mapping[str, str] | None = None,
               cwd: str | Path | None = None, platform: str | None = None) -> Location:
    """The configuration `wrap --client NAME` changes when no --config is given. CommandError when unclear."""
    environ = os.environ if environ is None else environ
    platform = platform or sys.platform
    info = CLIENTS[client]
    if not info.editable:
        raise CommandError(snippet_only_message(client))
    locations = [location for location in all_locations(environ, cwd, platform) if location.client == client]
    if client in ("vscode", "claude-code"):
        project = True  # they have no user-level file that agent-sentinel edits
    scoped = [location for location in locations if location.scope == ("project" if project else "user")]
    if not scoped:
        raise CommandError(f"agent-sentinel does not know a {'project' if project else 'user'} configuration "
                           f"for {info.label}; give the file with --config")
    if client == "claude-desktop":
        return _desktop_target(scoped)
    if client == "windsurf":
        return _windsurf_target(scoped)
    location = scoped[0]
    if not location.path.is_file():
        raise CommandError(f"there is no {info.label} configuration at {location.path}, so there is nothing to wrap"
                           + ("" if project or client != "cursor"
                              else " (for a project's .cursor/mcp.json, add --project)"))
    return location


def _desktop_target(locations: list[Location]) -> Location:
    """The one Claude Desktop file that exists. With two (the usual one and an MSIX copy), refuse: guessing
    wrong would change a file the app ignores, and the servers would stay unprotected."""
    existing = [location for location in locations if location.path.is_file()]
    if not existing:
        where = "\n".join(f"  {location.path}" for location in locations) or "  (no folder is known)"
        raise CommandError(f"Claude Desktop's configuration was not found. Looked at:\n{where}\n"
                           "Open Claude Desktop's Settings > Developer > Edit Config once to create it, "
                           "or give the file with --config")
    if len(existing) > 1:
        where = "\n".join(f"  {location.path}" + (f"  ({location.note})" if location.note else "")
                          for location in existing)
        raise CommandError(
            "Claude Desktop has more than one configuration file here:\n" + where + "\n"
            "The app installed from the Microsoft Store reads the copy under Packages; the one under AppData is "
            "what Settings > Developer > Edit Config opens. Choose the one your app uses with --config"
        )
    return existing[0]


def _windsurf_target(locations: list[Location]) -> Location:
    current, *older = locations
    if current.path.is_file():
        return current
    if any(location.path.is_file() for location in older):
        raise CommandError(
            f"Windsurf reads its servers from {current.path}, which does not exist yet; the older "
            f"{older[0].path} is only read for discovery, so wrapping it would change nothing. Open Windsurf's MCP "
            "settings once so that it writes its own file, or give a file with --config"
        )
    raise CommandError(f"there is no Windsurf configuration at {current.path}, so there is nothing to wrap")


def client_for_file(path: Path) -> str | None:
    """The client a configuration file belongs to, guessed from its name and folder (for doctor --config)."""
    name, parent = path.name.lower(), path.parent.name.lower()
    if name == "claude_desktop_config.json":
        return "claude-desktop"
    if name == "mcp.json" and parent == ".cursor":
        return "cursor"
    if name == "mcp.json" and parent == ".vscode":
        return "vscode"
    if name == ".mcp.json":
        return "claude-code"
    if name == "mcp_config.json" and parent in ("devin", "windsurf"):
        return "windsurf"
    return None


def scope_of(path: Path, environ: Mapping[str, str] | None = None, platform: str | None = None) -> str:
    """"project" for a configuration of a project folder (.mcp.json, .vscode/, a project's .cursor/), else "user"."""
    name, parent = path.name.lower(), path.parent.name.lower()
    if name == ".mcp.json" or parent == ".vscode":
        return "project"
    if parent == ".cursor":
        user = home.user_folder(os.environ if environ is None else environ, platform or sys.platform)
        same = user is not None and os.path.normcase(str(path.parent.parent)) == os.path.normcase(str(user))
        return "user" if same else "project"
    return "user"


def project_folder(path: Path) -> Path:
    """The project a project configuration belongs to: the folder that holds .mcp.json, .vscode/ or .cursor/."""
    return path.parent.parent if path.parent.name.lower() in (".vscode", ".cursor") else path.parent


def inside_folder(path: str | Path, folder: str | Path) -> bool:
    """Whether `path` is `folder` or inside it, compared by components (no file is looked at)."""
    inside = os.path.normcase(os.path.normpath(str(folder)))
    try:
        return os.path.commonpath([os.path.normcase(os.path.normpath(str(path))), inside]) == inside
    except ValueError:  # different drives, or one path relative
        return False


def files_inside_project(config: Path, files: dict[str, str | None]) -> list[str]:
    """For a project's configuration: which of the named files (what -> path) are inside that project.

    The agent's own tools can often write there, and an agent that can
    change the policy, the pins or the log can switch the protection off or
    hide what it did.
    """
    if scope_of(config) != "project":
        return []
    project = project_folder(config)
    return [what for what, path in files.items() if path and inside_folder(path, project)]


def is_app_state(path: Path) -> bool:
    """Claude Code's ~/.claude.json: the app's own state, which is never edited (use `claude mcp add --scope user`)."""
    return path.name.lower() == ".claude.json"


def snippet_only_message(client: str) -> str:
    info = CLIENTS[client]
    return (f"agent-sentinel does not edit {info.label}'s configuration. {info.note} To print an entry to paste:\n"
            f"  agent-sentinel wrap --client {client} --policy POLICY --name NAME -- <server command>")


def desktop_extensions(config_path: Path) -> list[str]:
    """The Desktop Extensions installed beside a Claude Desktop configuration (folder names; at most 100).

    Claude Desktop starts extensions itself; they are not entries in the
    configuration, so they cannot be wrapped.
    """
    folder = config_path.parent / "Claude Extensions"
    try:
        names = sorted(entry.name for entry in folder.iterdir() if entry.is_dir())
    except OSError:
        return []
    return names[:MAX_EXTENSIONS_LISTED]


# ---- entries to paste ---------------------------------------------------------------------------

def _toml_text(text: str) -> str:
    """A TOML basic string: JSON's escapes, except that TOML also wants DEL escaped."""
    return json.dumps(text, ensure_ascii=False).replace("\x7f", "\\u007f")


def snippet(client: str, name: str, entry: dict[str, Any], platform: str | None = None) -> str:
    """What to paste into the client's configuration (or run) to add one wrapped server."""
    info = CLIENTS[client]
    words = [entry["command"], *entry["args"]]
    if client == "codex":
        # A JSON string is a TOML basic string, as long as letters outside ASCII are written as
        # themselves (JSON's "😀" pairs are not TOML).
        toml_key = name if all(ch.isascii() and (ch.isalnum() or ch in "_-") for ch in name) else _toml_text(name)
        return "\n".join([
            "Run:",
            "  " + shell_line(["codex", "mcp", "add", name, "--", *words], platform),
            "or add to ~/.codex/config.toml:",
            f"  [mcp_servers.{toml_key}]",
            f"  command = {_toml_text(entry['command'])}",
            f"  args = [{', '.join(_toml_text(argument) for argument in entry['args'])}]",
        ])
    if client == "other":
        return "\n".join(["Command:", f"  {entry['command']}", "Arguments:",
                          *(f"  {argument}" for argument in entry["args"]),
                          "As one line:", "  " + shell_line(words, platform)])
    block = json.dumps({info.servers_key: {name: entry}}, indent=2)
    lines = [f"Put this entry under \"{info.servers_key}\" in the configuration:", block]
    if client == "claude-code":
        # "claude mcp add" takes the command as plain words, which no shell mangles (JSON in an argument
        # loses its quotes in Windows PowerShell 5).
        lines += ["For Claude Code's user scope (every project), run instead:",
                  "  " + shell_line(["claude", "mcp", "add", "--scope", "user", name, "--", *words], platform)]
    return "\n".join(lines)
