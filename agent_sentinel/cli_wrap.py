"""`agent-sentinel wrap`: put the proxy in front of the servers in an MCP client's configuration.

    agent-sentinel wrap --client claude-desktop --policy policy.json            show what would change
    agent-sentinel wrap --client claude-desktop --policy policy.json --apply    change it (after a backup)
    agent-sentinel wrap --client codex --policy policy.json --name files -- npx -y some-server
                                                                                 print an entry to paste

Without a server command, wrap edits a client's configuration file (the
clients that keep plain JSON: see clients.py). Each stdio server entry gets
the proxy in front of it (see wrapping.py), with absolute --policy, --audit,
--pins (one file per server) and --name, and a --pass-env for each name in
its "env" (and --contain, with wrap --contain: see containment.py). Remote
servers, entries already wrapped, and Claude Desktop
Extensions are listed and left alone: none of them can be wrapped. One
thing is offered for an entry that is wrapped already: when it has no
--session-group (0.5.0 wrote none), wrap shows the option as a change to
that entry, and --apply adds it (wrapping.add_session_group). In a
project's configuration (cli_doctor.config_scope), a Python that imports
agent_sentinel only without -I (a pip --user install) is not written in:
the client starts it in the project, which could hold an agent_sentinel
folder of its own (wrapping.launcher_problem).

By default nothing is written: wrap prints what it would change, entry by
entry, as a diff in which env values are never shown. --apply writes, after
copying the file to a timestamped backup beside it, and replaces the file in
one step (config_file.py). The rest of the file is kept byte for byte.

With a server command after "--", nothing is edited: wrap prints the entry
to paste, or the command to run, for that client. That is the way for
clients whose configuration agent-sentinel does not edit (Codex, Cline,
Antigravity, Claude Code's user scope, and any other).

`unwrap` (cli_unwrap.py) takes the proxy out again.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__, clients, control_plane, home, mcp_proxy
from .cli_common import (
    EXIT_ERROR,
    EXIT_OK,
    INSTALL_COMMAND,
    CommandError,
    full_path,
    load_policy,
    shown_command,
    shown_path,
)
from .cli_doctor import config_scope, launch_lines, project_of
from .clients import CLIENTS
from .config_file import ConfigFile, edited_text, read_config, write_config
from .launch import without_address_credentials
from .leaks import redact_value
from .policy import Policy
from .textutil import printable
from .wrapping import (
    ProxySettings,
    PythonCheck,
    WrapError,
    add_session_group,
    check_python,
    command_line,
    kind_of,
    launcher_problem,
    pins_file,
    proxy_command_of,
    server_label,
    wrap_entry,
)

HELP = "put the proxy in front of each server in a client's configuration (shows a diff; writes with --apply)"
DESCRIPTION = (
    "Put the proxy in front of every stdio server in an MCP client's configuration. Prints what would change; "
    "--apply writes it, after a backup. With a server command after '--', prints an entry to paste instead."
)
EPILOG = """\
clients:
  claude-desktop, cursor (add --project for .cursor/mcp.json), vscode (.vscode/mcp.json),
  claude-code (.mcp.json), windsurf: their configuration is edited.
  cline, antigravity, codex, other: an entry to paste is printed (give the server command after --).

examples:
  agent-sentinel wrap --client claude-desktop --policy C:/Users/me/.agent-sentinel/policy.json
  agent-sentinel wrap --client claude-desktop --policy C:/Users/me/.agent-sentinel/policy.json --apply
  agent-sentinel wrap --client codex --policy policy.json --name files -- npx -y some-mcp-server@1.2.3
"""
USAGE = """agent-sentinel wrap --client NAME [--config FILE | --project] --policy POLICY [--audit FILE]
                           [--pins-dir DIR] [--server NAME ...] [--monitor] [--contain]
                           [--session-group NAME | --no-session-group] [--apply]
       agent-sentinel wrap --client NAME --policy POLICY --name NAME [--audit FILE] [--pins-dir DIR]
                           [--monitor] [--contain] [--session-group NAME | --no-session-group]
                           -- SERVER_COMMAND ..."""
TAKES_SERVER_COMMAND = True
HIDDEN = "<value not shown>"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--client", required=True, choices=tuple(CLIENTS), help="the MCP client")
    add_config_arguments(parser)
    parser.add_argument("--policy", required=True, metavar="POLICY", help="the policy every wrapped server uses")
    parser.add_argument("--audit", metavar="FILE",
                        help="the audit log (default: audit.jsonl in the agent-sentinel home folder)")
    parser.add_argument("--pins-dir", metavar="DIR",
                        help="the folder for the pins files, one per server (default: pins in the home folder)")
    parser.add_argument("--server", action="append", default=[], metavar="NAME",
                        help="wrap only this server (repeat for more; default: every one)")
    parser.add_argument("--monitor", action="store_true",
                        help="start the proxies in monitor mode: log what would be blocked, block nothing")
    parser.add_argument("--contain", action="store_true",
                        help="start the proxies with --contain: each server, and the processes it starts, end with "
                             "its proxy (cleanup, not isolation: it still runs as you and can read your files)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--session-group", type=mcp_proxy._session_group, metavar="NAME",
                       help="the proxies' --session-group, the same for every server, so that the flow rules see "
                            "what each server of this client delivered (default: the client's name)")
    group.add_argument("--no-session-group", action="store_true",
                       help="give the proxies no session group: each server's flow marks stay its own")
    parser.add_argument("--name", metavar="NAME", help="with a server command after '--': the server's name")
    parser.add_argument("--apply", action="store_true",
                        help="write the change (after a backup); without it, only show it")


def add_config_arguments(parser: argparse.ArgumentParser) -> None:
    """The options that choose the configuration file (wrap and unwrap share them)."""
    parser.add_argument("--config", metavar="FILE", help="the configuration file (default: the client's usual one)")
    parser.add_argument("--project", action="store_true",
                        help="cursor: the project's .cursor/mcp.json in this folder, not the user's ~/.cursor/mcp.json")


def run(args: argparse.Namespace) -> int:
    if args.server_command is not None:
        return _print_snippet(args)
    if args.name is not None:
        raise CommandError("--name is for printing an entry: give the server command after '--'")
    config = open_config(args.client, args.config, args.project)
    servers = servers_of(config, args.client)
    names = selected(servers, args.server)
    loaded = _policy(args.policy)
    if loaded is None:
        return EXIT_ERROR
    python = this_python()
    settings = _settings(args, loaded[0], python)
    plan = plan_wrap(config, args.client, servers, names, settings)
    _print_header(config, args.client, settings, *loaded, shares=_shares_the_group(plan, settings))
    exposed = control_plane.writable_warning(loaded[1], config.path, "this configuration file")
    if exposed:
        print(f"Warning: {exposed}")
    print_plan(plan)
    if args.client == "claude-desktop":
        _print_extensions(config.path)
    changes = {step.name: step.new for step in plan if step.new is not None}
    if not changes:
        print("\nNothing to wrap.")
        return EXIT_OK
    _warn_about_python(settings.python, python)
    print_diffs(plan, "wrapped")
    if not args.apply:
        print("\nNothing was changed. To make this change, run the same command with --apply.")
        return EXIT_OK
    for folder in make_folders(settings):
        print(f"Created the folder {shown_path(folder)}")
    backup = apply_changes(config, args.client, changes)
    print(f"\nBackup of the original: {shown_path(backup)}")
    grouped = sum(1 for step in plan if step.new is not None and step.done is not None)
    print(f"Wrote {shown_path(config.path)}: {len(changes) - grouped} server(s) wrapped"
          + (f", {grouped} given the session group" if grouped else "") + ".")
    print(f"Next: {CLIENTS[args.client].restart}")
    print("Check the result: agent-sentinel doctor"
          + (f" --config {shown_path(config.path)}" if args.config else ""))
    print(f"To undo: agent-sentinel unwrap --client {args.client}"
          + (f" --config {shown_path(config.path)}" if args.config else "")
          + (" --project" if args.project else "") + " --apply   (or copy the backup back)")
    return EXIT_OK


# ---- the configuration file -------------------------------------------------------------------

def open_config(client: str, config: str | None, project: bool) -> ConfigFile:
    """Read the configuration to change: --config, or the client's usual file."""
    if client not in CLIENTS or not CLIENTS[client].editable:
        raise CommandError(clients.snippet_only_message(client))
    if config is not None:
        path = Path(full_path(config))
    else:
        path = clients.target_for(client, project).path
    if clients.is_app_state(path):
        raise CommandError(
            f"{path} is Claude Code's own state file, which agent-sentinel never edits. For Claude Code's user "
            "scope, print a command to run instead:\n"
            "  agent-sentinel wrap --client claude-code --policy POLICY --name NAME -- <server command>"
        )
    return read_config(path, for_writing=True)


def servers_of(config: ConfigFile, client: str) -> dict[str, Any]:
    key = CLIENTS[client].servers_key
    servers = config.document.get(key)
    if servers is None:
        raise CommandError(f"{config.path} has no \"{key}\" section, so there is nothing to change")
    if not isinstance(servers, dict):
        raise CommandError(f"in {config.path}, \"{key}\" is not an object ({{ ... }}); fix it by hand first")
    return servers


def selected(servers: dict[str, Any], wanted: list[str]) -> set[str]:
    """The entries to work on: those named with --server, or all."""
    if not wanted:
        return set(servers)
    missing = [name for name in wanted if name not in servers]
    if missing:
        known = ", ".join(printable(name, limit=60) for name in servers) or "none"
        raise CommandError(f"no server named {printable(missing[0], limit=60)!r} in this file; it has: {known}")
    return set(wanted)


def apply_changes(config: ConfigFile, client: str, changes: dict[str, Any]) -> Path:
    """Write the changed entries into the file (after a backup); return the backup's path."""
    text = edited_text(config, CLIENTS[client].servers_key, changes)
    return write_config(config, text)


# ---- deciding ------------------------------------------------------------------------------------

@dataclass
class Step:
    """What happens to one entry."""

    name: str
    old: Any
    new: dict[str, Any] | None  # None: left as it is
    says: str  # one line for the user
    done: str | None = None  # what the diff calls the new entry, when it is not the command's usual word


def _policy(path: str) -> tuple[str, Policy] | None:
    """The policy's full path and the policy, or None (after saying why) if it does not load."""
    policy_path = full_path(path)
    policy = load_policy(policy_path)
    return None if policy is None else (policy_path, policy)


def this_python() -> PythonCheck:
    """How the wrapped entries can start the Python that runs this command (it is started to find out)."""
    if not sys.executable:
        raise CommandError("cannot tell which Python runs agent-sentinel, so the wrapped entries could not start it")
    return check_python(os.path.abspath(sys.executable))


def _settings(args: argparse.Namespace, policy_path: str, python: PythonCheck) -> ProxySettings:
    """The paths every wrapped entry gets, all absolute."""
    folder = None if (args.audit and args.pins_dir) else home.home_folder()
    return ProxySettings(
        python=os.path.abspath(sys.executable),
        policy=policy_path,
        audit=full_path(args.audit) if args.audit else str(home.audit_file(folder)),
        pins_folder=full_path(args.pins_dir) if args.pins_dir else str(home.pins_folder(folder)),
        monitor=args.monitor,
        isolated=python.isolated,
        contain=args.contain,
        session_group=None if args.no_session_group else (args.session_group or args.client),
    )


def make_folders(settings: ProxySettings) -> list[Path]:
    """Create the audit log's folder and the pins folder (owner-only) if they are missing; return those created."""
    created = []
    for folder in (Path(settings.audit).parent, Path(settings.pins_folder)):
        if not folder.is_dir():
            try:
                home.make_private_folder(folder)
            except OSError as exc:
                raise CommandError(
                    f"cannot create the folder {folder}: {exc.strerror or exc}; nothing was changed"
                ) from exc
            created.append(folder)
    return created


def plan_wrap(config: ConfigFile, client: str, servers: dict[str, Any], names: set[str],
              settings: ProxySettings) -> list[Step]:
    """Decide, entry by entry, what wrap does. Nothing is changed here."""
    taken: set[str] = set()
    for entry in servers.values():  # the names wrapped entries already use
        found = proxy_command_of(entry)
        if found is not None and found.value("--name"):
            taken.add(found.value("--name").lower())
    # A project's configuration: an entry doctor would call broken there (a Python without -I) is not written.
    project = project_of(config.path) if config_scope(config.path) == "project" else None
    plan = []
    for name, entry in servers.items():
        if name in names:
            plan.append(_wrap_step(config, client, name, entry, settings, taken, project))
    return plan


def _wrap_step(config: ConfigFile, client: str, name: str, entry: Any, settings: ProxySettings,
               taken: set[str], project: Path | None = None) -> Step:
    kind = kind_of(entry)
    if kind == "remote":
        return Step(name, entry, None,
                    "skipped: a remote server; the proxy speaks stdio only, so it stays NOT protected")
    if kind == "broken":
        return Step(name, entry, None, "skipped: the entry has no usable \"command\" and \"args\"")
    if proxy_command_of(entry) is not None:
        return _wrapped_already_step(name, entry, settings)
    words = command_line(entry)
    assert words is not None
    shown = shown_command([without_address_credentials(word) for word in words], limit=120)
    executable = mcp_proxy._resolve_executable(words[0])
    if executable is not None:
        unsafe = mcp_proxy._unsafe_for_batch_file(executable, words[1:])
        if unsafe:
            return Step(name, entry, None, (
                f"skipped: the proxy would refuse to pass {printable(unsafe[0], limit=60)!r} to the batch file "
                f"{printable(executable, limit=120)} (cmd.exe would change it). Start the program behind it "
                "directly, for example with node, then wrap again"
            ))
    label = server_label(name, taken)
    try:
        new = wrap_entry(entry, settings, label, pins_file(settings, client, label, str(config.path)))
    except WrapError as exc:
        return Step(name, entry, None, f"skipped: {exc}")
    problem = launcher_problem(proxy_command_of(new), project)
    if problem:
        return Step(name, entry, None, f"skipped: the program that would start the proxy, "
                                       f"{printable(settings.python, limit=120)}, {problem}")
    says = f"will be wrapped, as --name {label}: {shown}"
    if executable is None:
        says += (f"\n      (note: '{printable(words[0], limit=60)}' is not on this terminal's PATH; the proxy looks "
                 "for it on the PATH the client gives it, never in the current folder)")
    says += "".join(f"\n      {line}" for line in launch_warnings(words))
    return Step(name, entry, new, says)


def _wrapped_already_step(name: str, entry: Any, settings: ProxySettings) -> Step:
    """An entry that is wrapped already. It is left alone, except that one without a session group (as
    versions before 0.6 wrapped) is given this run's group: that one option is the whole change."""
    group = proxy_command_of(entry).value("--session-group")
    if settings.session_group is None:
        return Step(name, entry, None, "skipped: already wrapped")
    if group is not None:
        other = "" if group.lower() == settings.session_group.lower() else (
            f", in session group '{printable(group, limit=64)}' (not '{settings.session_group}': it does not "
            "share flow marks with the servers of that group)")
        return Step(name, entry, None, "skipped: already wrapped" + other)
    try:
        new = add_session_group(entry, settings.session_group, settings.python)
    except WrapError as exc:
        return Step(name, entry, None, f"skipped: already wrapped, without a session group, so its flow marks "
                                       f"stay its own: {exc}")
    return Step(name, entry, new, f"already wrapped, without a session group (as versions before 0.6 wrapped): "
                                  f"--session-group {settings.session_group} will be added; nothing else of the "
                                  "entry changes", done="given the session group")


def _shares_the_group(plan: list[Step], settings: ProxySettings) -> bool:
    """Whether any entry is, or would be, in this run's session group."""
    if settings.session_group is None:
        return False
    for step in plan:
        found = proxy_command_of(step.new if step.new is not None else step.old)
        group = found.value("--session-group") if found is not None else None
        if group is not None and group.lower() == settings.session_group.lower():
            return True
    return False


def launch_warnings(words: list[str]) -> list[str]:
    """doctor's launch checks of a server command, as warnings: wrap protects a server, not how it starts."""
    return [("WARNING (doctor fails this): " if line.level == "fail" else "warning: ") + line.text
            for line in launch_lines(words)]


# ---- showing ---------------------------------------------------------------------------------------

def _print_header(config: ConfigFile, client: str, settings: ProxySettings, policy_path: str, policy: Policy,
                  shares: bool = True) -> None:
    print(f"{CLIENTS[client].label} configuration: {shown_path(config.path)}")
    warnings = policy.warnings()
    note = f"; {len(warnings)} warning(s): agent-sentinel validate {shown_path(policy_path)}" if warnings else ""
    print(f"Policy: {shown_path(policy_path)} (default {policy.default}, {len(policy.tools)} tool rule(s){note})")
    if policy.may_ask():
        print("  Its 'ask' rules are refused by the proxy unless it is started with an approver (--approve-with).")
    print(f"Each wrapped server logs to {shown_path(settings.audit)}")
    print(f"and keeps its tool pins in its own file in {shown_path(settings.pins_folder)}")
    if settings.session_group is not None and shares:  # only when an entry is, or would be, in the group
        print(f"The servers share their flow marks as session group '{settings.session_group}' "
              "(--no-session-group keeps each server's own)")
    exposed = clients.files_inside_project(
        config.path, {"policy": policy_path, "audit log": settings.audit, "pins folder": settings.pins_folder})
    if exposed:
        print(f"Warning: the {', the '.join(exposed)} would be inside the project folder, where the agent's own tools "
              "may be able to change them (and so switch the protection off). Keep them in the agent-sentinel home "
              "folder.")
    if settings.monitor:
        print("Monitor mode: the proxies will log what they would block, and block NOTHING.")
    if settings.contain:
        print("Contained: each server, and the processes it starts, end with its proxy (--contain; cleanup, "
              "not isolation).")


def print_plan(plan: list[Step]) -> None:
    print()
    width = min(30, max([len(printable(step.name, limit=30)) for step in plan] or [4]))
    for step in plan:
        print(f"  {printable(step.name, limit=30):{width}}  {step.says}")


def _print_extensions(config_path: Path) -> None:
    extensions = clients.desktop_extensions(config_path)
    if extensions:
        print(f"\n  Desktop Extensions ({len(extensions)}): not wrappable, so NOT protected. Claude Desktop starts "
              "them itself; to protect one, turn it off and add its server as an entry instead:")
        print("    " + ", ".join(printable(name, limit=60) for name in extensions))


def shown_entry(entry: Any) -> str:
    """An entry as JSON for a person to read: env and header values hidden, recognisable secrets redacted."""
    if isinstance(entry, dict):
        entry = {
            key: ({name: HIDDEN for name in value} if key in ("env", "headers") and isinstance(value, dict) else value)
            for key, value in entry.items()
        }
        for key in ("command", "args", "url", "serverUrl"):  # a password written into an address
            if isinstance(entry.get(key), str):
                entry[key] = without_address_credentials(entry[key])
            elif isinstance(entry.get(key), list):
                entry[key] = [without_address_credentials(word) if isinstance(word, str) else word
                              for word in entry[key]]
    return json.dumps(redact_value(entry), indent=2, ensure_ascii=False)


def print_diffs(plan: list[Step], done: str) -> None:
    """The change to each entry as a unified diff (env values never shown). The rest of the file is not touched."""
    print("\nThe change (only these entries change; the rest of the file is kept as it is):")
    for step in plan:
        if step.new is None:
            continue
        name = printable(step.name, limit=60)
        for line in difflib.unified_diff(shown_entry(step.old).splitlines(), shown_entry(step.new).splitlines(),
                                         fromfile=f"{name} (now)", tofile=f"{name} ({step.done or done})",
                                         lineterm="", n=2):
            print(printable(line, limit=1000))


def _warn_about_python(python: str, check: PythonCheck) -> None:
    """Say so if the Python the entries start cannot run this agent-sentinel the safe way, or at all."""
    shown = printable(python, limit=200)
    if check.version is None:
        print(f"\nWarning: {shown} cannot import agent_sentinel when started from another folder, so the wrapped "
              f"servers would not start. Install the package for that Python ({INSTALL_COMMAND}, run with that "
              "Python; see Install in the README) before you restart the client.")
        return
    if not check.isolated:
        print(f"\nWarning: {shown} finds agent_sentinel only in your own site-packages (pip install --user), which "
              "Python's isolated mode (-I) leaves out. So the entries start it without -I, and a folder named "
              "agent_sentinel in the folder the client starts a server in would run instead of the proxy. "
              "Install the package for all users or in a virtual environment, then wrap again.")
    if check.version != __version__:
        print(f"\nWarning: {shown} has agent-sentinel {printable(check.version, limit=20)} installed, not "
              f"{__version__} (this command); the wrapped entries need {__version__}'s proxy options.")


# ---- an entry to paste ---------------------------------------------------------------------------

def _print_snippet(args: argparse.Namespace) -> int:
    command = args.server_command
    if not command:
        raise CommandError("give the server command after '--'")
    for option, given in (("--config", args.config), ("--project", args.project), ("--apply", args.apply),
                          ("--server", args.server)):
        if given:
            raise CommandError(f"{option} is for editing a configuration; with a server command after '--', wrap "
                               "only prints an entry to paste")
    if not args.name:
        raise CommandError("give the server a name with --name, for example --name files")
    loaded = _policy(args.policy)
    if loaded is None:
        return EXIT_ERROR
    python = this_python()
    settings = _settings(args, loaded[0], python)
    label = server_label(args.name, set())
    entry: dict[str, Any] = {"command": command[0], "args": command[1:]}
    if args.client == "vscode":
        entry = {"type": "stdio", **entry}
    # Named after the server command too, so that two entries printed for two servers given the same name
    # never share a pins file.
    pins = pins_file(settings, args.client, label, "\0".join(command))
    try:
        wrapped = wrap_entry(entry, settings, label, pins)
    except WrapError as exc:
        raise CommandError(f"cannot print an entry for this command: {exc}") from exc
    info = CLIENTS[args.client]
    print(f"{info.label}: the server '{printable(args.name, limit=60)}' with the proxy in front of it."
          + (f" {info.note}" if info.note else ""))
    for line in clients.snippet(args.client, args.name, wrapped).splitlines():
        print(printable(line, limit=5000))
    print("If the server needs environment variables, keep them in the entry's env as before.")
    for warning in launch_warnings(command):
        print(warning[0].upper() + warning[1:])
    for folder in make_folders(settings):
        print(f"Created the folder {shown_path(folder)}")
    _warn_about_python(settings.python, python)
    print(f"Then: {info.restart}")
    return EXIT_OK
