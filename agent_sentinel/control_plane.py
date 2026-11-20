"""Can the agent reach agent-sentinel's own files? The control-plane checks of `doctor`. Read-only.

The control plane is what decides whether agent-sentinel protects anything:
the policies, the pins files and the changes waiting beside them, the audit
logs, the Claude Code hook's state folder, the proxies' env files and
approver programs, and the home folder that holds most of them. An agent
that can write one of them can switch the protection off or hide what it did:
rewrite the policy, mark a changed tool as pinned, make an approver say yes.

doctor looks for four ways in. None of them opens a file; the permissions are
read with stat.

* server_reaches: a server given a folder that holds one of them (a
  filesystem server started on the home folder can write the policy).
* roots_holding: an allow_args "type": "path" root of a policy that holds one.
* writable_by: a policy that lets a write call name one of them. It is a dry
  run of Policy.evaluate (the policy-wide deny_args, the tool rules and the
  default, without flows) for Write, Edit, MultiEdit and NotebookEdit (Claude
  Code's tools) and write_file, edit_file and move_file (the reference
  filesystem server's); a call the policy would allow outright is reported.
* permission_lines: on POSIX, one that other users can read or change, or
  that another user owns; on Windows, an AGENT_SENTINEL_HOME outside the
  user profile, which does not get the profile's private permissions.

Every check is bounded: at most MAX_CONTROL_FILES files, MAX_DRY_RUNS policy
evaluations, MAX_PATH_ARGUMENTS arguments of one server.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import clients, config_file, home, jsonutil, launch
from .config_file import ConfigError, read_config
from .matchers import PathMatcher
from .policy import Policy
from .textutil import printable

# The write calls a policy is dry-run with, and the arguments that name the file.
WRITE_CALLS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Write", ("file_path",)), ("Edit", ("file_path",)), ("MultiEdit", ("file_path",)),
    ("NotebookEdit", ("notebook_path",)), ("write_file", ("path",)), ("edit_file", ("path",)),
    ("move_file", ("source", "destination")),
)
MAX_CONTROL_FILES = 1000
MAX_DRY_RUNS = 20_000
MAX_PATH_ARGUMENTS = 1000
MAX_SHOWN = 5  # files named in one line; the rest are counted
MAX_FOLDER_DEPTH = 128
MAX_HOOK_COMMAND_CHARS = 16 * 1024  # of a hook's "command" text that is split into words
# Claude Code's settings files, relative to the user's folder and to the project (the current folder).
USER_SETTINGS = (Path(".claude") / "settings.json",)
PROJECT_SETTINGS = (Path(".claude") / "settings.json", Path(".claude") / "settings.local.json")
# Claude Code's own state file in the user's folder (claude_state), and how large it may be.
CLAUDE_STATE = Path(".claude.json")
MAX_CLAUDE_STATE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class ControlFile:
    """One file (or folder) of the control plane: what it is, its full path, and whose it is."""

    what: str  # "policy", "pins file", "changes waiting beside the pins file", "audit log", ...
    path: str  # full, as written
    whose: str = ""  # "claude-desktop: files", "the Claude Code hook", "agent-sentinel home folder"
    folder: bool = False

    def shown(self) -> str:
        return f"the {self.what} {printable(self.path, limit=300)}" + (f" ({self.whose})" if self.whose else "")


def path_key(path: str) -> str:
    """A path as the system compares it: normalised, and without case on Windows."""
    return os.path.normcase(os.path.normpath(path))


def unique(files: Iterable[ControlFile]) -> tuple[list[ControlFile], bool]:
    """The files without repeats (by path), at most MAX_CONTROL_FILES; and whether some were left out."""
    seen: dict[str, ControlFile] = {}
    over = False
    for found in files:
        if not found.path or not home.is_absolute(found.path):
            continue
        key = path_key(found.path)
        if key in seen:
            continue
        if len(seen) >= MAX_CONTROL_FILES:
            over = True
            break
        seen[key] = found
    return list(seen.values()), over


# ---- servers that are given a folder holding one ------------------------------------------------

class FolderIndex:
    """Each folder above a control file, and the files below it: "which of them is inside this folder?" at once."""

    def __init__(self, files: list[ControlFile]) -> None:
        self._below: dict[str, list[ControlFile]] = {}
        for found in files:
            key = path_key(found.path)
            for _ in range(MAX_FOLDER_DEPTH):
                self._below.setdefault(key, []).append(found)
                parent = os.path.dirname(key)
                if parent == key:
                    break
                key = parent

    def inside(self, folder: str) -> list[ControlFile]:
        """The control files that are `folder` or inside it."""
        return self._below.get(path_key(folder), [])


def _path_arguments(args: list[str]) -> list[str]:
    """The arguments of a server command that are full paths (or the value of an option such as --root=PATH)."""
    found = []
    for arg in args[:MAX_PATH_ARGUMENTS]:
        value = arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
        value = os.path.expanduser(value.strip()) if value.startswith("~") else value.strip()
        if value and home.is_absolute(value):
            found.append(value)
    return found


def server_reaches(server_args: list[str], index: FolderIndex) -> list[str]:
    """What doctor says when a server's path arguments are folders that hold control files (empty when none)."""
    lines = []
    for value in _path_arguments(server_args):
        held = index.inside(value)
        if not held:
            continue
        names = ", ".join(found.shown() for found in held[:MAX_SHOWN])
        more = f" and {len(held) - MAX_SHOWN} more" if len(held) > MAX_SHOWN else ""
        lines.append(f"the server is given the folder {printable(value, limit=300)}, which holds {names}{more}: if "
                     "the server can write there, the agent can change them through it, and so switch the "
                     "protection off. Give it a narrower folder, or make sure its policy denies them (see Control "
                     "plane)")
        if len(lines) >= MAX_SHOWN:
            break
    return lines


# ---- what a policy lets the agent write -------------------------------------------------------------

class Budget:
    """How many policy evaluations the checks may still make (MAX_DRY_RUNS); `exceeded` once one was refused."""

    def __init__(self, limit: int | None = None) -> None:
        self.left = MAX_DRY_RUNS if limit is None else limit
        self.exceeded = False

    def take(self) -> bool:
        if self.left <= 0:
            self.exceeded = True
            return False
        self.left -= 1
        return True


def _target(found: ControlFile) -> str:
    """The path a write call would name: the file itself, or a file inside a folder."""
    return os.path.join(found.path, "x.json") if found.folder else found.path


def writable_by(policy: Policy, path: str, budget: Budget | None = None) -> list[str]:
    """The write calls (WRITE_CALLS) that `policy` would allow outright with `path` as the file they name."""
    allowed = []
    for tool, arguments in WRITE_CALLS:
        if budget is not None and not budget.take():
            break
        try:
            verdict = policy.evaluate(tool, {name: path for name in arguments})
        except (ValueError, TypeError, RecursionError):  # cannot tell: say so as if it were allowed
            allowed.append(f"{tool} (could not be checked)")
            continue
        if verdict.action == "allow":
            allowed.append(tool)
    return allowed


def writable_warning(policy: Policy, path: str | Path, what: str) -> str | None:
    """For wrap and hook install: why the policy should deny the file they just edited, or None when it does.

    An agent that may write a client's configuration or Claude Code's
    settings can take agent-sentinel out of it, for this and every later session.
    """
    tools = writable_by(policy, str(path))
    if not tools:
        return None
    rule = json.dumps({"arg": "*", "type": "path", "roots": [str(path)]})
    return (f"the policy would let the agent write {what} {printable(str(path), limit=300)} ({', '.join(tools)} "
            "allowed): a hijacked agent could take agent-sentinel out of it, for this session and every later one. "
            f"Deny it in the policy's deny_args, for example {printable(rule, limit=400)}")


def policy_writes(policy: Policy, files: list[ControlFile], budget: Budget) -> list[tuple[ControlFile, list[str]]]:
    """The control files a policy lets the agent write, with the calls that would be allowed."""
    found = []
    for control in files:
        tools = writable_by(policy, _target(control), budget)
        if tools:
            found.append((control, tools))
        if budget.exceeded:
            break
    return found


def _calls(tools: list[str]) -> str:
    """The write calls allowed, or "every write call" when that is all of WRITE_CALLS."""
    return "every write call" if len(tools) == len(WRITE_CALLS) and all(
        tool == call[0] for tool, call in zip(tools, WRITE_CALLS)) else ", ".join(tools)


def roots_holding(policy: Policy, files: list[ControlFile], budget: Budget) -> list[tuple[str, str, list[ControlFile]]]:
    """(rule, argument, files) for each allow_args path entry whose roots hold control files."""
    found = []
    for rule in policy.tools:
        for entry in rule.allow_args:
            if not isinstance(entry.matcher, PathMatcher):
                continue
            held = []
            for control in files:
                if not budget.take():
                    break
                try:
                    if entry.matcher.accepts(_target(control)):
                        held.append(control)
                except (ValueError, TypeError, RecursionError):
                    continue
            if held:
                found.append((rule.name, entry.arg, held))
    return found


def policy_lines(label: str, policy: Policy, files: list[ControlFile], budget: Budget) -> list[str]:
    """What doctor says about one policy and the control files: writes it allows, and roots that hold them."""
    lines = []
    writes = policy_writes(policy, files, budget)
    if writes:
        named = "; ".join(f"{control.shown()}: {_calls(tools)}" for control, tools in writes[:MAX_SHOWN])
        more = f"; and {len(writes) - MAX_SHOWN} more" if len(writes) > MAX_SHOWN else ""
        lines.append(f"the policy {printable(label, limit=300)} would let the agent write agent-sentinel's own files "
                     f"({named}{more}), and so switch the protection off. Deny them in deny_args (the templates "
                     "deny any argument that names .agent-sentinel), or keep them where the policy denies")
    for rule, argument, held in roots_holding(policy, files, budget):
        named = ", ".join(control.shown() for control in held[:MAX_SHOWN])
        more = f" and {len(held) - MAX_SHOWN} more" if len(held) > MAX_SHOWN else ""
        lines.append(f"the policy {printable(label, limit=300)}: tools.{printable(rule, limit=80)} allows argument "
                     f"{printable(argument, limit=80)!r} inside a root that holds {named}{more}. Narrow the root, "
                     "or deny those files in deny_args")
    return lines


# ---- permissions -------------------------------------------------------------------------------------

def permission_problem(mode: int, owned: bool, program: bool = False, by_root: bool = False) -> str | None:
    """Why other users can get at a file or folder with this mode, or None (POSIX).

    `program`: an approver program, which others may read and run, but not
    change. `by_root`: owned by the administrator (uid 0), who can change
    anything anyway: only what other users can change matters then (a
    system-wide policy or program must be readable by everyone).
    """
    if not owned and not by_root:
        return "is owned by another user, who can change it"
    if mode & 0o022:
        return "can be changed by other users"
    if not program and not by_root and mode & 0o044:
        return "can be read by other users"
    return None


def permission_lines(files: list[ControlFile], stat_of: Callable[[str], Any] = os.stat,
                     posix: bool = os.name == "posix", uid: int | None = None) -> list[str]:
    """POSIX: each existing control file or folder that other users can read or change, or that another user owns.

    One that root owns is trusted, as long as no other user can change it.
    """
    if not posix:
        return []
    if uid is None:
        uid = os.getuid() if hasattr(os, "getuid") else -1
    lines = []
    for control in files:
        try:
            found = stat_of(control.path)
        except (OSError, ValueError):
            continue  # not there (yet): nothing to say about its permissions
        folder = stat.S_ISDIR(found.st_mode)
        owned, by_root = found.st_uid == uid, found.st_uid == 0
        problem = permission_problem(found.st_mode, owned, program=control.what == "approver program",
                                     by_root=by_root)
        if problem is None:
            continue
        mode = f"(mode {stat.S_IMODE(found.st_mode):o})"
        shown_path = printable(control.path, limit=300)
        fix = "chmod 755" if control.what == "approver program" else ("chmod 700" if folder else "chmod 600")
        if by_root and not owned:
            lines.append(f"{control.shown()} {problem} {mode}. Let only root change it: sudo chmod go-w {shown_path}")
        elif not owned:
            lines.append(f"{control.shown()} {problem} {mode}. Use one of your own instead, and make it yours alone "
                         f"({fix})")
        else:
            lines.append(f"{control.shown()} {problem} {mode}. Make it yours alone: {fix} {shown_path}")
    return lines


def windows_home_lines(environ: Mapping[str, str] | None = None, platform: str | None = None) -> list[str]:
    """Windows: an AGENT_SENTINEL_HOME outside the user profile does not get the profile's private permissions."""
    environ = os.environ if environ is None else environ
    platform = platform or sys.platform
    chosen = environ.get(home.ENV_VAR, "")
    if platform != "win32" or not chosen or not home.is_absolute(chosen, platform):
        return []
    profile = home.user_folder(environ, platform)
    if profile is not None and clients.inside_folder(chosen, profile):
        return []
    return [f"{home.ENV_VAR} is {printable(chosen, limit=300)}, outside your user profile: a folder there takes the "
            "permissions of the folder above it (often any signed-in user may change it), not the profile's private "
            "ones. Keep it in your profile, or let only your account in (icacls)"]


# ---- the files themselves --------------------------------------------------------------------------------

def home_files(folder: Path) -> list[ControlFile]:
    """The control files of the agent-sentinel home folder (whether they exist or not)."""
    whose = "agent-sentinel home folder"
    return [
        ControlFile("home folder", str(folder), whose, folder=True),
        ControlFile("policy", str(home.policy_file(folder)), whose),
        ControlFile("pins folder", str(home.pins_folder(folder)), whose, folder=True),
        ControlFile("hook state folder", str(home.hook_state_folder(folder)), whose, folder=True),
        ControlFile("backups folder", str(folder / config_file.BACKUPS_FOLDER), whose, folder=True),
    ]


@dataclass
class SettingsFile:
    """One Claude Code settings file: its document, or why it cannot be read."""

    path: Path
    scope: str  # "user" or "project"
    document: dict[str, Any] | None = None
    error: str | None = None


def claude_settings(environ: Mapping[str, str] | None = None, cwd: str | Path | None = None) -> list[SettingsFile]:
    """Claude Code's settings files that exist: the user's (~/.claude/settings.json) and the project's (in `cwd`)."""
    environ = os.environ if environ is None else environ
    user = home.user_folder(environ)
    project = Path(cwd if cwd is not None else os.getcwd())
    candidates = [(user / name, "user") for name in USER_SETTINGS] if user is not None else []
    candidates += [(project / name, "project") for name in PROJECT_SETTINGS]
    found, seen = [], set()
    for path, scope in candidates:
        key = path_key(str(path))
        if key in seen or not path.is_file():
            continue
        seen.add(key)
        try:
            document = read_config(path).document
        except ConfigError as exc:
            found.append(SettingsFile(path, scope, error=printable(str(exc).splitlines()[0], limit=300)))
            continue
        found.append(SettingsFile(path, scope, document if isinstance(document, dict) else None,
                                  None if isinstance(document, dict) else "not a JSON object"))
    return found


def claude_state(environ: Mapping[str, str] | None = None) -> SettingsFile | None:
    """Claude Code's own state file, ~/.claude.json, read only (None when there is none).

    It holds the servers `claude mcp add` writes for the user ("mcpServers")
    and for each project (projects[PATH].mcpServers), and the switches that
    let a project's .mcp.json servers in. It can be large (it keeps per-project
    history), so it may be up to MAX_CLAUDE_STATE_BYTES.
    """
    user = home.user_folder(os.environ if environ is None else environ)
    if user is None:
        return None
    path = user / CLAUDE_STATE
    if not path.is_file():
        return None
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_CLAUDE_STATE_BYTES + 1)
        if len(raw) > MAX_CLAUDE_STATE_BYTES:
            return SettingsFile(path, "user", error=f"it is larger than {MAX_CLAUDE_STATE_BYTES} bytes")
        document = jsonutil.loads(raw.decode("utf-8-sig"))
    except OSError as exc:
        return SettingsFile(path, "user", error=printable(exc.strerror or exc, limit=300))
    except UnicodeDecodeError:
        return SettingsFile(path, "user", error="it is not UTF-8 text")
    except (ValueError, RecursionError):  # what it says may quote the file, which can hold tokens
        return SettingsFile(path, "user", error="it is not strict JSON")
    if not isinstance(document, dict):
        return SettingsFile(path, "user", error="not a JSON object")
    return SettingsFile(path, "user", document)


def hook_paths(settings: list[SettingsFile]) -> list[tuple[str, str]]:
    """(what, path) of each --policy, --audit and --state-dir that agent-sentinel's Claude Code hooks are given."""
    from .cli_hook import is_our_handler  # here: cli_hook imports what imports cli_doctor, which imports this module

    options = {"--policy": "hook policy", "--audit": "hook audit log", "--state-dir": "hook state folder"}
    found = []
    for settings_file in settings:
        hooks = (settings_file.document or {}).get("hooks")
        for groups in (hooks.values() if isinstance(hooks, dict) else ()):
            for group in (groups if isinstance(groups, list) else ()):
                handlers = group.get("hooks") if isinstance(group, dict) else None
                for handler in (handlers if isinstance(handlers, list) else ()):
                    if not is_our_handler(handler):
                        continue
                    words = _handler_words(handler)
                    for index, word in enumerate(words):
                        name, equals, value = word.partition("=")  # --policy PATH, or --policy=PATH
                        if name not in options:
                            continue
                        path = value if equals else (words[index + 1] if index + 1 < len(words) else "")
                        if path:
                            found.append((options[name], os.path.expanduser(path)))
                    if len(found) > MAX_CONTROL_FILES:
                        return found
    return found


def _handler_words(handler: dict[str, Any]) -> list[str]:
    """A hook handler's words: its "args" (as hook install writes it), or its "command" text split into words."""
    args = handler.get("args")
    if isinstance(args, list):
        return [word for word in args if isinstance(word, str)]
    return launch.shell_words(handler["command"][:MAX_HOOK_COMMAND_CHARS])
