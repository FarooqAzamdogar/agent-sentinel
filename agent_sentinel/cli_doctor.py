"""`agent-sentinel doctor`: one read-only check of every MCP client configuration. "Am I actually protected?"

    agent-sentinel doctor
    agent-sentinel doctor --config .mcp.json --config .vscode/mcp.json --format json

For each configuration file (those `clients` finds, or the ones given with
--config), each server is one of:

    protected     the proxy is in front of it, and it would start
    unprotected   it starts the server directly, or the proxy runs in monitor mode (which blocks nothing)
    remote        a URL: the proxy speaks stdio only, so it cannot be protected
    broken        wrapped, but the proxy would not start or would not find what it needs:
                  no policy, a relative or missing policy, a policy that does not load,
                  an unreadable pins file, an env file it cannot use, a command that is
                  not found, an argument a .cmd launcher cannot take, an option value
                  the proxy refuses (checked by the proxy's own functions, such as
                  --max-message-bytes over 1 GiB); or wrapped, but something else may
                  start as the proxy: a launcher written as a relative path, a Python
                  option such as -X pycache_prefix (wrapping.launcher_problem), or a
                  variable of the entry's "env" (PYTHONPATH for a Python without -I,
                  UV_INDEX_URL for uvx, USERPROFILE for any: wrapping.env_redirects);
                  in a project's configuration, also a Python started without -I,
                  and on Windows a launcher written without a folder when the project
                  folder holds a program of that name

A project's configuration is one kept in a project and shared through its
repository: .mcp.json, .vscode/mcp.json, a project's .cursor/mcp.json, and
any other --config file inside a folder under version control (config_scope).
The client is likely started in that project (project_of).

and these are checked too: every policy loads, with its warnings; the audit
and pins folders can be written; no two servers share a pins file; npx and
uvx packages are pinned to a version; and which env names look like secrets
written in the file (names only: a value is never printed). A leading "~" in
--policy, --audit, --pins, --env-file and an --approve-with command: is the
home folder, as the proxy reads it.

How each server is launched (launch_lines, with launch.py): a package of
advisories.py that is malware fails, one with a known vulnerability warns,
so does one a letter away from a popular MCP package's name; and so does a
risky command: inline code (sh -c, cmd /c, powershell -EncodedCommand,
node -e, python -c), shell operators in arguments, sudo, a download piped to
a runner, a package from a git repository, a container with --privileged,
the host's root or home folder mounted, host namespaces or no image digest,
and an argument that names a credential file, a whole drive or the whole
home folder. The full command is then printed, never cut short. A package is
found behind a wrapper too (cmd /c npx ..., env, sh -c "npx ...", npm exec,
pnpm dlx, yarn dlx: launch.commands_run).

The control plane (control_plane.py): whether a server, a policy's
allow_args root or a policy's write rules let the agent reach
agent-sentinel's own files (policies, pins, audit logs, the hook's state,
env files, approver programs); and on POSIX whether other users can read or
change them. In a project's configuration, an approver program or an env
file inside the project folder is broken (the agent's own tools could
rewrite them).

--save-baseline FILE records what the configurations, Claude Code's
settings and the servers of its ~/.claude.json hold; --baseline FILE fails
on anything added, changed or removed since (doctor_baseline.py). Saving
the baseline is the only thing doctor writes.

Nothing is changed and no server is started. A configuration may come from
someone else (a project's checked-in .mcp.json), so doctor never runs a
program it names: whether a Python can import agent_sentinel is tried only
for the Python that runs doctor itself. Files it names (policy, pins, env
file) are read only when they are ordinary files of at most
MAX_CHECKED_FILE_BYTES, and a path on another machine (\\\\server\\share on
Windows) is never touched: merely looking at one makes Windows sign in to
that machine with the user's credentials. Neither is a device path
(\\\\?\\..., \\\\.\\..., \\??\\...), which can name another machine too
(_never_opened). Everything read from a configuration or a policy is
printed through `printable`.

Exit codes: 0 every stdio server is protected; 1 a server is not protected
or is broken, a configuration cannot be read, a policy does not load, or
something differs from the --baseline; 2 a --config file does not exist, or
the --baseline cannot be read.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import __version__, clients, config_file, control_plane, doctor_baseline, elicitation, home, launch, mcp_proxy
from . import server_env
from .approvers import COMMAND_PREFIX
from .cli_common import EXIT_FAIL, EXIT_OK, CommandError, full_path, shell_line, shown_command, shown_path
from .clients import CLIENTS
from .config_file import ConfigError, read_config
from .control_plane import ControlFile
from .firewall import SERVER_NAME
from .launch import unpinned_package  # noqa: F401  (doctor's own check, kept under its old name too)
from .leaks import find_secrets, redact
from .pins import pending_path
from .policy import Policy, PolicyError
from .policy_errors import file_error_message
from .server_env import looks_secret  # the proxy's own test, so that doctor and the proxy agree
from .textutil import printable
from .wrapping import (
    FLAG_OPTIONS,
    VALUE_OPTIONS,
    ProxyCommand,
    command_line,
    env_redirects,
    installed_version,
    kind_of,
    launcher_problem,
    mentions_proxy,
    python_letters,
    read_proxy_command,
    shortened_option,
)

HELP = "check, without changing anything, that every server in your MCP client configurations is protected"
DESCRIPTION = (
    "Check every MCP client configuration (or the files given with --config): is each server protected, would "
    "the proxy start, do the policies load, can the logs and pins be written, are packages pinned. Read-only."
)
EPILOG = """\
exit codes: 0 every stdio server is protected; 1 something is not protected, broken, or unreadable; 2 a --config
file does not exist

A configuration may come from someone else (a project's .mcp.json), so doctor never starts a program it names
(only the Python running doctor is asked which agent-sentinel it has) and never opens a path on another machine
(\\\\server\\share) or a device path (\\\\?\\, \\\\.\\, \\??\\): on Windows, merely looking at one sends your
sign-in to that machine.

examples:
  agent-sentinel doctor
  agent-sentinel doctor --config .mcp.json --format json
  agent-sentinel doctor --save-baseline ~/.agent-sentinel/baseline.json      later: --baseline FILE
"""

STATUSES = ("protected", "unprotected", "remote", "broken")
MAX_POLICY_WARNINGS_SHOWN = 20
# The largest policy or pins file doctor reads (both are small; a configuration could name anything).
MAX_CHECKED_FILE_BYTES = 16 * 1024 * 1024
# The agent-sentinel version this Python runs, isolated (-I) or not (see _check_launcher), for one run.
_versions: dict[tuple[str, bool], str | None] = {}


@dataclass
class Line:
    """One line of the checklist: "ok", "warn", "fail" or "info", and what it says (already printable)."""

    level: str
    text: str


@dataclass
class ServerReport:
    name: str
    status: str
    lines: list[Line] = field(default_factory=list)
    policy: str | None = None  # full path, when the entry names one
    pins: str | None = None
    audit: str | None = None
    # For the control-plane checks (not printed): the server command, and the env file and approver programs.
    command: list[str] = field(default_factory=list)
    env_file: str | None = None
    approvers: list[str] = field(default_factory=list)


@dataclass
class ConfigReport:
    client: str | None
    path: Path
    scope: str = "user"
    note: str = ""
    error: str | None = None
    servers: list[ServerReport] = field(default_factory=list)
    extensions: list[str] = field(default_factory=list)
    entries: Any = None  # the servers as the file holds them, for --save-baseline and --baseline (never printed)


@dataclass
class PolicyReport:
    path: str
    loads: bool
    summary: str
    warnings: list[str] = field(default_factory=list)
    policy: Policy | None = None  # the loaded policy, for the control-plane checks


@dataclass
class Extras:
    """What doctor checks beyond each server: the control plane, and the baseline."""

    control_plane: list[Line] = field(default_factory=list)
    baseline_file: str | None = None  # --baseline
    drift: list[str] = field(default_factory=list)  # what differs from it (names only)
    saved_baseline: str | None = None  # --save-baseline
    baseline_warnings: list[str] = field(default_factory=list)  # what the baseline could not read


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", action="append", default=[], metavar="FILE",
                        help="check this configuration file (repeat for more; default: every one `clients` finds)")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="output format (default text)")
    baseline = parser.add_mutually_exclusive_group()
    baseline.add_argument("--save-baseline", metavar="FILE",
                          help="record what the configurations and Claude Code's settings and ~/.claude.json hold "
                               "now (servers, hooks, env overrides, permissions), to compare with later; the only "
                               "file doctor writes")
    baseline.add_argument("--baseline", metavar="FILE",
                          help="fail on any server, hook or setting added, changed or removed since --save-baseline "
                               "wrote FILE (names are shown, never values)")


def run(args: argparse.Namespace) -> int:
    _versions.clear()
    saved = doctor_baseline.load(Path(full_path(args.baseline))) if args.baseline else None
    reports = [check_config(*where) for where in _configs(args.config)]
    policies = check_policies(reports)
    for report in reports:
        for server in report.servers:
            _add_policy_result(server, policies)
    shared = shared_pins(reports)
    settings = control_plane.claude_settings()
    extras = Extras(control_plane=check_control_plane(reports, policies, settings))
    state = control_plane.claude_state() if saved is not None or args.save_baseline else None
    if state is not None and state.error:
        extras.baseline_warnings.append(f"Claude Code's {shown_path(state.path)} cannot be read ({state.error}), so "
                                        "the servers it holds are not compared")
    if saved is not None:
        extras.baseline_file = full_path(args.baseline)
        current = baseline_items(reports, settings, saved.key, state)
        extras.drift = doctor_baseline.described(doctor_baseline.changes(saved.items, current))
    if args.save_baseline:
        target = Path(full_path(args.save_baseline))
        key = doctor_baseline.new_key()
        doctor_baseline.save(target, doctor_baseline.Baseline(key, baseline_items(reports, settings, key, state)))
        extras.saved_baseline = str(target)
    code = EXIT_FAIL if extras.drift else exit_code(reports, policies)
    if args.format == "json":
        print(json.dumps(as_json(reports, policies, shared, code, extras), indent=2, ensure_ascii=True))
    else:
        print_report(reports, policies, shared, code, extras)
    return code


def _configs(given: list[str]) -> list[tuple[Path, str | None, str, str]]:
    """(path, client, scope, note) of each configuration to check."""
    if given:
        found = []
        for path_text in given:
            path = Path(full_path(path_text))
            if not path.exists():
                raise CommandError(f"there is no file at {path}")
            found.append((path, clients.client_for_file(path), config_scope(path), ""))
        return found
    return [(location.path, location.client, location.scope, location.note)
            for location in clients.all_locations() if location.path.is_file()]


def config_scope(path: Path) -> str:
    """"project" or "user" for a configuration file given by its path (doctor --config, wrap --config).

    clients.scope_of knows the project files by name (.mcp.json,
    .vscode/mcp.json, a project's .cursor/mcp.json). Any other file of no
    known client is a project's too when it is inside a folder under version
    control: the repository shares it, and decides what is in the folder a
    client given it is started in. So is one on another machine, which is
    not looked into (_never_opened). A known user file (Claude Desktop's,
    the user's Cursor or Windsurf file, Claude Code's ~/.claude.json) stays
    the user's, even in a home folder kept under version control.
    """
    scope = clients.scope_of(path)
    if scope == "user" and clients.client_for_file(path) is None and not clients.is_app_state(path) and (
            _never_opened(str(path)) or _work_tree_top(path) is not None):
        return "project"
    return scope


def project_of(path: Path) -> Path:
    """The folder a client of a project configuration is likely started in: its project's root.

    The folder that holds .mcp.json, .vscode/ or .cursor/; for any other
    file, the top of its work tree (else the file's own folder).
    """
    if clients.scope_of(path) == "project":
        return clients.project_folder(path)
    return _work_tree_top(path) or path.parent


def _work_tree_top(path: Path) -> Path | None:
    """The nearest folder above `path` that holds .git, .hg, .svn or .jj (as config_file looks), or None.

    Nothing on another machine is looked at.
    """
    if _never_opened(str(path)):
        return None
    for folder in list(path.parents)[:config_file.MAX_FOLDER_DEPTH]:
        if any(os.path.lexists(folder / marker) for marker in config_file._WORK_TREE_MARKERS):
            return folder
    return None


# ---- one configuration ----------------------------------------------------------------------------

def check_config(path: Path, client: str | None, scope: str, note: str) -> ConfigReport:
    report = ConfigReport(client, path, scope, note)
    try:
        config = read_config(path)
    except ConfigError as exc:
        report.error = printable(str(exc).splitlines()[0], limit=300)
        return report
    key = CLIENTS[client].servers_key if client in CLIENTS else _guess_key(config.document)
    servers = config.document.get(key, {})
    report.entries = servers
    if not isinstance(servers, dict):
        report.error = f"\"{key}\" is not an object"
        return report
    project = project_of(path) if scope == "project" else None
    for name, entry in servers.items():
        report.servers.append(check_server(name, entry, client, project))
    if client == "claude-desktop":
        report.extensions = clients.desktop_extensions(path)
    return report


def _guess_key(document: dict[str, Any]) -> str:
    return "servers" if "servers" in document and "mcpServers" not in document else "mcpServers"


def check_server(name: str, entry: Any, client: str | None, project: Path | None) -> ServerReport:
    """The status of one entry and what is wrong or worth knowing about it."""
    shown_name = printable(name, limit=60)
    kind = kind_of(entry)
    if kind == "remote":
        report = ServerReport(shown_name, "remote", [Line(
            "warn", "NOT protected: a remote server (a URL); the proxy speaks stdio only, so it cannot be protected")])
        report.lines += _secret_lines(entry)
        return report
    if kind == "broken":
        return ServerReport(shown_name, "broken", [Line("fail", "the entry has no usable \"command\" and \"args\"")])
    words = command_line(entry)
    assert words is not None
    proxy = read_proxy_command(words)
    if proxy is None and mentions_proxy(words):
        report = ServerReport(shown_name, "broken", [Line(
            "fail", f"NOT protected: {_shown(words)} starts the proxy only after other words, or from a package that "
                    "is not agent-sentinel at a version (a URL or a path); either may run something else, unchecked. "
                    "Make the entry start the server directly, then run wrap")])
        report.lines += _secret_lines(entry)
        return report
    if proxy is None:
        fix = f"agent-sentinel wrap --client {client} --policy POLICY" if client else "agent-sentinel wrap"
        report = ServerReport(shown_name, "unprotected", [
            Line("fail", f"NOT protected: starts {_shown(words)} directly. To fix: {fix}")], command=words)
        report.lines += launch_lines(words) + _secret_lines(entry)
        return report
    report = ServerReport(shown_name, "protected", command=proxy.server)
    _check_wrapped(report, proxy, entry, project)
    report.lines += launch_lines(proxy.server) + _secret_lines(entry)
    if any(line.level == "fail" for line in report.lines):
        report.status = "broken"
    elif proxy.has("--monitor"):
        report.status = "unprotected"
        report.lines.insert(0, Line("fail", f"NOT protected: monitor mode (--monitor) logs what the proxy would block "
                                            f"and blocks nothing: {_shown(proxy.server)}. Unwrap, then wrap again "
                                            "without --monitor"))
    else:
        report.lines.insert(0, Line("ok", f"protected: {_shown(proxy.server)}"))
    return report


def _shown(words: list[str]) -> str:
    return shown_command(words, limit=120)


def _check_wrapped(report: ServerReport, proxy: ProxyCommand, entry: dict[str, Any], project: Path | None) -> None:
    lines = report.lines
    _check_launcher(lines, proxy, project)
    for option, _ in proxy.options:
        if option in VALUE_OPTIONS or option in FLAG_OPTIONS:
            continue
        shortens = shortened_option(option)
        if shortens:
            lines.append(Line("fail", f"the proxy option {printable(option, limit=60)!r} is a shortened "
                                      f"{' or '.join(shortens)}: this proxy refuses it, and another version would take "
                                      "it for the whole option. Write the option in full"))
        else:
            lines.append(Line("warn", f"the proxy option {printable(option, limit=60)!r} is not one this version "
                                      "knows; the proxy may refuse to start"))
    if len(proxy.values("--policy")) > 1:
        lines.append(Line("fail", "--policy is given more than once: the proxy uses the last one, which is easy to "
                                  "miss when reading the entry. Keep one"))
    _check_values(lines, proxy)
    report.policy = _policy_path(lines, proxy.value("--policy"))
    report.pins = _pins_path(lines, proxy)
    report.audit = _audit_path(lines, proxy.value("--audit"))
    _check_env_file(lines, proxy.value("--env-file"))
    report.env_file = _local_path(proxy.value("--env-file"))
    report.approvers = _approver_programs(proxy)
    _check_name(lines, proxy.values("--name"))
    _check_server_command(lines, proxy.server)
    _check_passed_env(lines, proxy, entry)
    _check_env_redirects(lines, proxy, entry)
    if project is not None:
        _check_inside_project(report, project)


def _check_inside_project(report: ServerReport, project: Path) -> None:
    """A project's configuration: what of the proxy's own files the project folder holds (DET-9).

    The agent's own tools can often write the project. A policy, pins file
    or audit log there is a warning; an approver program (it alone can turn
    every 'ask' into a yes) or an env file (it gives the server variables
    such as NODE_OPTIONS) there is broken.
    """
    for what, path in (("policy", report.policy), ("pins file", report.pins), ("audit log", report.audit)):
        if path and inside_project(path, project):
            report.lines.append(Line("warn", f"the {what} is inside the project folder, where the agent's own tools "
                                             "may be able to change it; keep it in the agent-sentinel home folder"))
    for what, path in [("env file", report.env_file), *(("approver program", program) for program in report.approvers)]:
        if path and inside_project(path, project):
            report.lines.append(Line("fail", f"the {what} {printable(path, limit=300)} is inside the project folder, "
                                             "where the agent's own tools may be able to rewrite it"
                                             + (" to approve every call" if what == "approver program" else "")
                                             + "; keep it in the agent-sentinel home folder (or another folder the "
                                               "agent cannot write)"))


def inside_project(path: str, project: Path) -> bool:
    """Whether a file is inside the project folder: as written, or as the system resolves both paths.

    The second catches another spelling of the same place: a Windows short
    (8.3) name such as C:\\Users\\JOHNSM~1, a link or a junction. Nothing on
    another machine is looked at (_never_opened).
    """
    if clients.inside_folder(path, project):
        return True
    if _never_opened(path) or _never_opened(str(project)):
        return False
    try:
        return clients.inside_folder(os.path.realpath(path), os.path.realpath(project))
    except (OSError, ValueError):
        return False


def _local_path(path: str | None) -> str | None:
    """A full path on this machine from a proxy option ("~" expanded), or None (none, relative, or never opened)."""
    if not path:
        return None
    path = _option_path(path)
    return os.path.normpath(path) if home.is_absolute(path) and not _never_opened(path) else None


def _approver_programs(proxy: ProxyCommand) -> list[str]:
    """The program of each --approve-with command:, as the proxy finds it (a name on PATH, or a full path)."""
    found = []
    for value in proxy.values("--approve-with"):
        if not value.startswith(COMMAND_PREFIX):
            continue
        program = _option_path(value[len(COMMAND_PREFIX):])
        if not program or _approver_not_looked_up(program):
            continue
        located = program if home.is_absolute(program) else mcp_proxy._resolve_executable(program)
        if located:
            found.append(os.path.normpath(os.path.abspath(located)))
    return found


def _check_launcher(lines: list[Line], proxy: ProxyCommand, project: Path | None) -> None:
    """The program that starts the proxy exists, and a Python started with -m agent_sentinel can import it.

    `project`: the project folder of a project's configuration, None for a user's own (launcher_problem).
    """
    starter = proxy.launcher[0]
    refused = _never_opened(starter)
    if refused:
        lines.append(Line("fail", f"the program that starts the proxy, {printable(starter, limit=200)}, {refused} "
                                  "(see agent-sentinel doctor --help)"))
        return
    problem = launcher_problem(proxy, project)  # a relative path is not looked for: doctor's folder is not the client's
    if problem:
        lines.append(Line("fail", f"the program that starts the proxy, {printable(starter, limit=200)}, {problem}"))
        return
    if not (os.path.isfile(starter) if home.is_absolute(starter) else mcp_proxy._resolve_executable(starter)):
        lines.append(Line("fail", f"the program that starts the proxy, {printable(starter, limit=200)}, was not found"))
        return
    module = proxy.python_module()  # whatever harmless options come before -m
    if module is None:
        return
    python, isolated = module
    if proxy.imports_from_its_folder():  # a user's own configuration: a project's has failed above
        lines.append(Line("warn", "Python is started without -I, so a folder named agent_sentinel in the folder the "
                                  "client starts the server in would run instead of the proxy. To fix: unwrap, then "
                                  "wrap again"))
    if not _is_this_python(python):
        return  # never run a program a configuration names: it could be anything
    if "P" in python_letters(proxy.launcher) and sys.version_info < (3, 11):
        lines.append(Line("fail", f"{printable(python, limit=200)} is Python {sys.version.split()[0]}, which does not "
                                  "know -P (Python 3.11 and later), so the proxy will not start. Use -I instead"))
        return
    if (python, isolated) not in _versions:  # one check per Python, however many servers it starts
        _versions[python, isolated] = installed_version(python, isolated)
    version = _versions[python, isolated]
    if version is None:
        how = "with -I " if isolated else ""
        lines.append(Line("fail", f"{printable(python, limit=200)} started {how}cannot import agent_sentinel, so the "
                                  "proxy will not start; install the package for that Python"
                                  + (" (for all users or in a virtual environment: -I leaves out a --user install)"
                                     if isolated else "")))
    elif version != __version__:
        lines.append(Line("warn", f"{printable(python, limit=200)} runs agent-sentinel "
                                  f"{printable(version, limit=20)}, not {__version__}; options this version wrote "
                                  "may be unknown to it"))


def _is_this_python(program: str) -> bool:
    """Whether `program` is the Python running doctor (the only program doctor starts)."""
    if not home.is_absolute(program) or _never_opened(program) or not sys.executable:
        return False
    try:
        return os.path.samefile(program, sys.executable)
    except OSError:
        return False


def _never_opened(path: str) -> str | None:
    """Why doctor must not look at `path` at all, or None. A Windows matter.

    Windows answers any look at a network path (\\\\server\\share\\..., also
    //server/share), even "does it exist?", by signing in to that server with
    the user's credentials. A checked-in configuration must not be able to
    make doctor do that. A device or NT path (\\\\?\\..., \\\\.\\..., \\??\\...)
    can name another machine as well (\\??\\UNC\\server\\share\\...), and
    Python before 3.13 takes \\??\\... for a full path, so these are refused
    too, without a look.
    """
    if sys.platform != "win32" or path[:1] not in ("\\", "/"):
        return None
    if path[1:2] == "?" or (path[1:2] in ("\\", "/") and path[2:3] in ("?", ".")):
        return ("is a device path (\\\\?\\, \\\\.\\ or \\??\\); doctor does not open those, as they can name "
                "another machine")
    if path[1:2] in ("\\", "/"):
        return "is on another machine; doctor does not open network paths"
    return None


def _option_path(path: str) -> str:
    """A file path from a proxy option, read as the proxy reads it: a leading "~" is the home folder."""
    return os.path.expanduser(path)


def _too_big(path: str) -> bool:
    try:
        return os.path.getsize(path) > MAX_CHECKED_FILE_BYTES
    except OSError:
        return True


def _policy_path(lines: list[Line], policy: str | None) -> str | None:
    if policy is None:
        lines.append(Line("fail", "no --policy, so the proxy will not start"))
        return None
    written, policy = policy, _option_path(policy)
    refused = _never_opened(policy)
    if refused:
        lines.append(Line("fail", f"the policy {printable(policy, limit=200)} {refused}, so it cannot tell whether "
                                  "the proxy will start. Keep the policy on this machine"))
        return None
    if not home.is_absolute(policy):
        lines.append(Line("fail", f"the policy path {printable(written, limit=200)!r} is relative: the client starts "
                                  "the proxy in a folder of its own choosing. Write the full path"))
        return None
    if not os.path.isfile(policy):
        lines.append(Line("fail", f"there is no policy file at {printable(policy, limit=200)}"))
        return None
    if _too_big(policy):
        lines.append(Line("fail", f"the policy {printable(policy, limit=200)} is larger than {MAX_CHECKED_FILE_BYTES} "
                                  "bytes, which no policy is"))
        return None
    return os.path.normpath(policy)


def _pins_path(lines: list[Line], proxy: ProxyCommand) -> str | None:
    if proxy.has("--no-pins"):
        lines.append(Line("warn", "--no-pins: a tool whose definition changes is not quarantined"))
        return None
    pins = proxy.value("--pins")
    if pins is None:
        lines.append(Line("warn", "no --pins: tool definitions are remembered only while the proxy runs"))
        return None
    written, pins = pins, _option_path(pins)
    refused = _never_opened(pins)
    if refused:
        lines.append(Line("warn", f"the pins file {printable(pins, limit=200)} {refused}, so it was not checked"))
        return os.path.normpath(pins)
    if not home.is_absolute(pins):
        lines.append(Line("warn", f"the pins path {printable(written, limit=200)!r} is relative to whatever folder "
                                  "the client starts the proxy in. Write the full path"))
        return None
    if os.path.exists(pins) and (not os.path.isfile(pins) or _too_big(pins)):
        lines.append(Line("fail", f"the pins path {printable(pins, limit=200)} is not an ordinary pins file "
                                  f"(a folder, a device, or over {MAX_CHECKED_FILE_BYTES} bytes)"))
    elif os.path.exists(pins):
        try:
            mcp_proxy.ToolPins(pins)
        except (OSError, ValueError, RecursionError) as exc:
            lines.append(Line("fail", f"the pins file cannot be read, so the proxy will not start: "
                                      f"{printable(exc, limit=200)}"))
    _check_writable(lines, pins, "pins file", "tool pins are not saved")
    return os.path.normpath(pins)


def _audit_path(lines: list[Line], audit: str | None) -> str | None:
    if audit is None:
        lines.append(Line("warn", "no --audit: the proxy's decisions are not logged"))
        return None
    written, audit = audit, _option_path(audit)
    refused = _never_opened(audit)
    if refused:
        lines.append(Line("warn", f"the audit log {printable(audit, limit=200)} {refused}, so it was not checked"))
        return os.path.normpath(audit)
    if not home.is_absolute(audit):
        lines.append(Line("warn", f"the audit path {printable(written, limit=200)!r} is relative to whatever folder "
                                  "the client starts the proxy in. Write the full path"))
        return None
    _check_writable(lines, audit, "audit log", "decisions are not logged")
    return os.path.normpath(audit)


def _check_env_file(lines: list[Line], env_file: str | None) -> None:
    """The proxy reads --env-file before it starts the server, and does not start when it cannot use it.

    Read with the proxy's own reader, when it is an ordinary file; its errors
    give a line number, never a value. An empty value means no env file to
    the proxy too.
    """
    if not env_file:
        return
    path = _option_path(env_file)
    refused = _never_opened(path)
    if refused:
        lines.append(Line("fail", f"the env file {printable(path, limit=200)} {refused}, so it cannot tell whether "
                                  "the proxy will start. Keep the env file on this machine"))
        return
    if not home.is_absolute(path):
        lines.append(Line("fail", f"the env file path {printable(env_file, limit=200)!r} is relative: the client "
                                  "starts the proxy in a folder of its own choosing. Write the full path"))
        return
    if not os.path.isfile(path):
        lines.append(Line("fail", f"there is no env file at {printable(path, limit=200)}, so the proxy will not "
                                  "start"))
        return
    try:
        server_env.read_env_file(path)  # at most MAX_ENV_FILE_BYTES
    except (OSError, server_env.EnvFileError) as exc:
        lines.append(Line("fail", f"the proxy cannot use the env file, so it will not start: "
                                  f"{printable(exc, limit=300)}"))


def _check_writable(lines: list[Line], path: str, what: str, consequence: str) -> None:
    folder = os.path.dirname(path)
    if not os.path.isdir(folder):
        lines.append(Line("warn", f"the {what}'s folder {printable(folder, limit=200)} does not exist, "
                                  f"so {consequence}"))
    elif not os.access(folder, os.W_OK) or (os.path.exists(path) and not os.access(path, os.W_OK)):
        lines.append(Line("warn", f"the {what} {printable(path, limit=200)} cannot be written, so {consequence}"))


def _check_name(lines: list[Line], names: list[str]) -> None:
    if not names:
        lines.append(Line("warn", "no --name: the audit log cannot tell this server's records from others'"))
    for name in names:
        if not SERVER_NAME.fullmatch(name):
            lines.append(Line("fail", f"the proxy refuses the --name {printable(name, limit=80)!r} (letters, digits, "
                                      "'-', '_' and '.' only, at most 64)"))


def _check_values(lines: list[Line], proxy: ProxyCommand) -> None:
    """The option values the proxy refuses to start with, found by the proxy's own checks (--name: _check_name)."""
    approvers = []
    for option, value in proxy.options:
        if value is None or option not in _VALUE_CHECKS:
            continue
        if option == "--approve-with" and value.startswith(COMMAND_PREFIX):
            program = _option_path(value[len(COMMAND_PREFIX):])
            refused = _approver_not_looked_up(program)
            if refused:
                lines.append(Line("fail", f"the approver {printable(value, limit=120)!r} {refused}"))
                continue
            value = COMMAND_PREFIX + program
        try:
            checked = _VALUE_CHECKS[option](value)
        except argparse.ArgumentTypeError as exc:
            lines.append(Line("fail", f"the proxy refuses {option} {printable(value, limit=80)!r} "
                                      f"({printable(exc, limit=200)}), so it will not start"))
            continue
        if option == "--approve-with":
            approvers.append(checked.describe())
    for repeated in sorted({described for described in approvers if approvers.count(described) > 1}):
        lines.append(Line("fail", f"--approve-with {printable(repeated, limit=120)} is given twice, so the proxy "
                                  "will not start"))
    try:
        elicitation.allowed_hosts(proxy.values("--elicitation-host"))
    except PolicyError as exc:
        lines.append(Line("fail", f"the proxy will not start: it cannot use {printable(exc, limit=200)}"))
    if proxy.has("--quiet") and proxy.has("--verbose"):
        lines.append(Line("fail", "--quiet and --verbose are both given, and the proxy takes only one of them, so it "
                                  "will not start"))
    if proxy.has("--pin-server") and (proxy.value("--pins") is None or proxy.has("--no-pins")):
        lines.append(Line("fail", "--pin-server pins the server in the pins file, so the proxy will not start without "
                                  "--pins FILE, or with --no-pins"))
    if proxy.values("--on-server-change") and not proxy.has("--pin-server"):
        lines.append(Line("fail", "--on-server-change needs --pin-server, so the proxy will not start"))


def _approver_not_looked_up(program: str) -> str | None:
    """Why the program of an --approve-with command: is not looked for, or None when the proxy's check may run.

    The proxy's check looks at the file. Only a name looked up on PATH, or a
    full path on this machine, gets that far; anything else could make
    Windows open a network path (see _never_opened).
    """
    refused = _never_opened(program)
    if refused:
        return f"{refused}, so it cannot tell whether the proxy will start"
    if os.path.dirname(program) and not home.is_absolute(program):
        return (f"names {printable(program, limit=120)!r}, which is a relative path (a full path on Windows starts "
                "with a drive); doctor does not look for it. Write the program's full path")
    return None


def _tool_names(value: str) -> str:
    if value not in mcp_proxy.TOOL_NAME_MODES:
        raise argparse.ArgumentTypeError(f"choose from {', '.join(mcp_proxy.TOOL_NAME_MODES)}")
    return value


def _server_change(value: str) -> str:
    if value not in mcp_proxy.SERVER_CHANGE_MODES:
        raise argparse.ArgumentTypeError(f"choose from {', '.join(mcp_proxy.SERVER_CHANGE_MODES)}")
    return value


# The proxy's own check of an option's value: the types and choices of its argument parser. A value for which
# one raises ArgumentTypeError is one the proxy refuses to start with.
_VALUE_CHECKS: dict[str, Callable[[str], Any]] = {
    "--max-message-bytes": mcp_proxy._message_bytes,
    "--approval-timeout": mcp_proxy._approval_timeout,
    "--approve-with": mcp_proxy._approver,
    "--pass-env": mcp_proxy._pass_env_name,
    "--tool-names": _tool_names,
    "--on-server-change": _server_change,
}


def _check_server_command(lines: list[Line], server: list[str]) -> None:
    if not server:
        lines.append(Line("fail", "no server command after '--', so the proxy will not start"))
        return
    executable = mcp_proxy._resolve_executable(server[0])
    if executable is None:
        lines.append(Line("fail", f"the server command {printable(server[0], limit=120)!r} is not on this terminal's "
                                  "PATH (the proxy never looks in the current folder); write its full path"))
        return
    unsafe = mcp_proxy._unsafe_for_batch_file(executable, server[1:])
    if unsafe:
        lines.append(Line("fail", f"the proxy will refuse to pass {printable(unsafe[0], limit=60)!r} to the batch file "
                                  f"{printable(executable, limit=120)} (cmd.exe would change it); start the program "
                                  "behind it directly"))


def _check_passed_env(lines: list[Line], proxy: ProxyCommand, entry: dict[str, Any]) -> None:
    """With --clean-env, a variable of the entry's env that is not passed on never reaches the server."""
    env = entry.get("env")
    if not proxy.has("--clean-env") or not isinstance(env, dict):
        return
    passed = set(proxy.values("--pass-env"))
    missing = [name for name in env if name not in passed]
    if missing:
        lines.append(Line("warn", "--clean-env without --pass-env for "
                                  + ", ".join(printable(name, limit=60) for name in missing[:10])
                                  + ": the server will not get those variables"))


def _check_env_redirects(lines: list[Line], proxy: ProxyCommand, entry: dict[str, Any]) -> None:
    """Variables of the entry's env that can make something else start as the proxy (wrapping.env_redirects)."""
    named: dict[str, list[str]] = {}
    for name, changes in env_redirects(entry, proxy):
        named.setdefault(changes, []).append(name)
    for changes, names in named.items():
        shown = ", ".join(printable(name, limit=60) for name in names[:10]) + (" ..." if len(names) > 10 else "")
        lines.append(Line("fail", f"the entry's \"env\" sets {shown}; with that, {changes}, so what starts may not be "
                                  "the proxy this entry describes. Take it out of \"env\" (an --env-file gives a "
                                  "variable to the server alone)"))


# ---- how a server is launched, and secrets ---------------------------------------------------------------

def launch_lines(words: list[str]) -> list[Line]:
    """doctor's launch checks of a server command (launch.py; wrap, clients and inspect say the same).

    A package of advisories.py: malware fails, a known vulnerability warns;
    a name a letter away from a popular MCP package warns; a package without
    an exact version warns; and so does a risky command, with the full
    command printed (secrets redacted, never cut short).
    """
    if not words:
        return []
    lines = []
    # Each package a runner fetches, behind wrappers too: cmd /c npx ..., env ..., sh -c "npx ...", npm exec.
    for ref in launch.runner_packages(words):
        lines += [Line(level, text) for level, text in launch.advisory_findings(ref)]
        squatted = launch.typosquat_of(ref)
        if squatted:
            lines.append(Line("warn", f"the package {printable(ref.spec, limit=120)!r} is named one letter away from "
                                      f"the popular {squatted!r}: a typosquat runs someone else's code under a "
                                      "name you meant to trust. Check that it is the package you mean"))
        found = launch.unpinned_spec(ref)
        if found is not None:
            package, pinned = found
            lines.append(Line("warn", f"the package {printable(package, limit=80)!r} is not pinned to an exact "
                                      "version: a new release would run without review. Pin it, for example "
                                      f"{printable(pinned, limit=80)}"))
    risks = launch.launch_risks(words)
    if risks:
        lines.append(Line("warn", f"the launch command {'; '.join(risks)}. The full command: {full_command(words)}"))
    return lines


def full_command(words: list[str]) -> str:
    """A command as one line to print in full: quoted, printable, recognisable secrets redacted, never cut short.

    Quick on a hostile, megabytes-long command too: words are quoted, and
    runs of plain ASCII text made printable, a piece at a time instead of
    letter by letter (the result is the same as shell_line and printable give).
    """
    line = " ".join(_windows_word(word) for word in words) if sys.platform == "win32" else shell_line(words)
    text = redact(line)
    pieces, start = [], 0
    for run in _PLAIN_TEXT.finditer(text):  # printable() leaves plain ASCII as it is
        if run.start() > start:
            pieces.append(printable(text[start:run.start()], limit=run.start() - start))
        pieces.append(run.group())
        start = run.end()
    if start < len(text):
        pieces.append(printable(text[start:], limit=len(text) - start))
    return "".join(pieces)


_PLAIN_TEXT = re.compile(r"[ -~]+")


def _windows_word(word: str) -> str:
    """One word as subprocess.list2cmdline quotes it (shell_line on Windows), a piece at a time.

    Backslashes before a quote are doubled and the quote escaped; a word
    with a space or a tab (or none at all) is quoted, its trailing
    backslashes doubled.
    """
    parts = word.split('"')
    pieces = []
    for part in parts[:-1]:
        kept = part.rstrip("\\")
        pieces.append(kept + "\\" * (2 * (len(part) - len(kept))) + '\\"')
    last = parts[-1]
    if word and " " not in word and "\t" not in word:
        return "".join(pieces) + last
    kept = last.rstrip("\\")
    return '"' + "".join(pieces) + kept + "\\" * (2 * (len(last) - len(kept))) + '"'


def _secret_lines(entry: Any) -> list[Line]:
    """Env (and header) names that look like secrets, and arguments that hold one. Never a value."""
    if not isinstance(entry, dict):
        return []
    lines = []
    for key in ("env", "headers"):
        values = entry.get(key)
        if not isinstance(values, dict):
            continue
        named = [name for name in values if looks_secret(str(name))
                 or (isinstance(values[name], str) and find_secrets(values[name]))]
        if named:
            shown = ", ".join(printable(name, limit=60) for name in named[:10])
            lines.append(Line("warn", f"{key} holds {shown} in plain text in this file (values not shown); anything "
                                      "that can read the file can read them"))
    args = entry.get("args")
    if isinstance(args, list):
        kinds = sorted({kind for arg in args if isinstance(arg, str) for kind in find_secrets(arg)})
        if kinds:
            lines.append(Line("warn", f"an argument holds what looks like a {', '.join(kinds)}: it shows in process "
                                      "lists and in this file. Pass it in env instead"))
    return lines


# ---- policies, pins, the whole ---------------------------------------------------------------------------

def check_policies(reports: list[ConfigReport]) -> dict[str, PolicyReport]:
    """Load each policy the wrapped entries name, once."""
    found: dict[str, PolicyReport] = {}
    for report in reports:
        for server in report.servers:
            if server.policy and os.path.normcase(server.policy) not in found:
                found[os.path.normcase(server.policy)] = _load(server.policy)
    return found


def _load(path: str) -> PolicyReport:
    try:
        policy = Policy.from_file(path)
    except (OSError, PolicyError) as exc:
        message = file_error_message(path, exc) if isinstance(exc, OSError) else str(exc)
        return PolicyReport(path, False, printable(message.splitlines()[0] if message else "", limit=300))
    asks = sum(rule.action == "ask" for rule in policy.tools)
    summary = f"loads: default {policy.default}, {len(policy.tools)} tool rule(s)"
    if asks:
        summary += f", {asks} 'ask' rule(s), refused by the proxy unless it has an approver (--approve-with)"
    if policy.default == "allow":
        summary += "; default allow: every tool without a rule can be called"
    return PolicyReport(path, True, summary, [printable(text, limit=300) for text in policy.warnings()], policy)


def _add_policy_result(server: ServerReport, policies: dict[str, PolicyReport]) -> None:
    loaded = policies.get(os.path.normcase(server.policy)) if server.policy else None
    if loaded is not None and not loaded.loads:
        server.lines.append(Line("fail", "the policy does not load, so the proxy will not start (see Policies below)"))
        server.status = "broken"
        server.lines = [line for line in server.lines if line.level != "ok"]


def shared_pins(reports: list[ConfigReport]) -> list[tuple[str, list[str]]]:
    """Pins files that more than one server uses: (path, ["client: server", ...])."""
    users: dict[str, list[str]] = {}
    paths: dict[str, str] = {}
    for report in reports:
        for server in report.servers:
            if server.pins:
                key = os.path.normcase(server.pins)
                paths.setdefault(key, server.pins)
                users.setdefault(key, []).append(f"{report.client or report.path.name}: {server.name}")
    return [(paths[key], names) for key, names in users.items() if len(names) > 1]


def counts(reports: list[ConfigReport]) -> Counter:
    return Counter(server.status for report in reports for server in report.servers)


# ---- the control plane, and the baseline -----------------------------------------------------------------

def control_files(reports: list[ConfigReport], hooks: list[tuple[str, str]]) -> list[ControlFile]:
    """agent-sentinel's own files: each wrapped server's, the Claude Code hooks', and the home folder's."""
    found: list[ControlFile] = []
    for report in reports:
        for server in report.servers:
            whose = f"{report.client or report.path.name}: {server.name}"
            pins = [("pins file", server.pins), ("changes waiting beside the pins file",
                                                 str(pending_path(server.pins)) if server.pins else None)]
            for what, path in [("policy", server.policy), *pins, ("audit log", server.audit),
                               ("env file", server.env_file),
                               *(("approver program", program) for program in server.approvers)]:
                if path and not _never_opened(path):
                    found.append(ControlFile(what, path, whose))
    for what, path in hooks:
        if not _never_opened(path):
            found.append(ControlFile(what, path, "the Claude Code hook", folder=what == "hook state folder"))
    try:
        found += control_plane.home_files(home.home_folder())
    except home.HomeError:
        pass
    return found


def check_control_plane(reports: list[ConfigReport], policies: dict[str, PolicyReport],
                        settings: list[control_plane.SettingsFile]) -> list[Line]:
    """Whether servers, policies or other users can reach agent-sentinel's own files (control_plane.py).

    Lines about one server go into its report; the rest are returned.
    """
    hooks = control_plane.hook_paths(settings)
    files, too_many = control_plane.unique(control_files(reports, hooks))
    index = control_plane.FolderIndex(files)
    for report in reports:
        for server in report.servers:
            server.lines += [Line("warn", text) for text in control_plane.server_reaches(server.command[1:], index)]
    lines: list[Line] = []
    budget = control_plane.Budget()
    loaded = [(policy.path, policy.policy) for policy in policies.values() if policy.policy is not None]
    for what, path in hooks:
        if what == "hook policy" and os.path.normcase(os.path.normpath(path)) not in policies:
            loaded += _hook_policy(path, lines)
    for label, policy in dict(loaded).items():
        lines += [Line("warn", text) for text in control_plane.policy_lines(label, policy, files, budget)]
    # The audit log's own permissions are the audit log's business (auditlog/firewall), not reported here.
    lines += [Line("warn", text) for text in control_plane.permission_lines(
        [found for found in files if found.what not in ("audit log", "hook audit log")])]
    lines += [Line("warn", text) for text in control_plane.windows_home_lines()]
    if too_many or budget.exceeded:
        lines.append(Line("warn", "there are more of agent-sentinel's own files and policies than doctor checks in one "
                                  f"run ({control_plane.MAX_CONTROL_FILES} files, {control_plane.MAX_DRY_RUNS} "
                                  "policy checks): not every one was checked"))
    for settings_file in settings:
        if settings_file.error:
            lines.append(Line("warn", f"Claude Code's settings {shown_path(settings_file.path)} cannot be read, so "
                                      f"its hooks were not checked: {settings_file.error}"))
    return lines


def _hook_policy(path: str, lines: list[Line]) -> list[tuple[str, Policy]]:
    """The policy a Claude Code hook of agent-sentinel names, loaded for the control-plane checks."""
    if _never_opened(path) or not home.is_absolute(path) or not os.path.isfile(path) or _too_big(path):
        lines.append(Line("warn", f"the Claude Code hook's policy {printable(path, limit=300)} is not a policy file "
                                  "on this machine that doctor reads, so the hook blocks every call"))
        return []
    loaded = _load(path)
    if loaded.policy is None:
        lines.append(Line("warn", f"the Claude Code hook's policy does not load, so the hook blocks every call: "
                                  f"{loaded.summary}"))
        return []
    return [(path, loaded.policy)]


def baseline_items(reports: list[ConfigReport], settings: list[control_plane.SettingsFile], key: bytes,
                   state: control_plane.SettingsFile | None = None) -> dict[doctor_baseline.Where, str]:
    """What --save-baseline records and --baseline compares: every configuration's servers, Claude Code's
    settings, and the servers and switches of its ~/.claude.json (`state`, control_plane.claude_state)."""
    items: dict[doctor_baseline.Where, str] = {}
    if state is not None:
        items.update(doctor_baseline.claude_state_items(key, str(state.path), state.document, state.error))
    for report in reports:
        if report.error and report.entries is None:
            items[("config", str(report.path), "(cannot be read)")] = "0" * 64
            continue
        items.update(doctor_baseline.config_items(key, str(report.path), report.entries))
    for settings_file in settings:
        items.update(doctor_baseline.settings_items(key, str(settings_file.path), settings_file.document,
                                                    settings_file.error))
    return items


def exit_code(reports: list[ConfigReport], policies: dict[str, PolicyReport]) -> int:
    found = counts(reports)
    failed = (found["unprotected"] or found["broken"] or any(report.error for report in reports)
              or any(not policy.loads for policy in policies.values()))
    return EXIT_FAIL if failed else EXIT_OK


# ---- output ------------------------------------------------------------------------------------------------

def _mark(level: str) -> str:
    return f"[{level}]".ljust(7)


def print_report(reports: list[ConfigReport], policies: dict[str, PolicyReport],
                 shared: list[tuple[str, list[str]]], code: int, extras: Extras | None = None) -> None:
    print("agent-sentinel doctor: a read-only check; nothing is changed and no server is started.")
    print(f"{_mark('info')}agent-sentinel {__version__}, Python {sys.version.split()[0]}: {shown_path(sys.executable)}")
    try:
        folder = home.home_folder()
        print(f"{_mark('info')}home folder: {shown_path(folder)}" + ("" if folder.is_dir() else " (not created yet)"))
    except home.HomeError as exc:
        print(f"{_mark('warn')}{printable(exc, limit=300)}")
    if not reports:
        print("\nNo MCP client configuration was found. Check a file with: agent-sentinel doctor --config FILE")
    for report in reports:
        _print_config(report)
    if policies:
        print("\nPolicies:")
        for policy in policies.values():
            print(f"  {_mark('ok' if policy.loads else 'fail')}{shown_path(policy.path)} {policy.summary}")
            for warning in policy.warnings[:MAX_POLICY_WARNINGS_SHOWN]:
                print(f"  {_mark('warn')}  {warning}")
            if len(policy.warnings) > MAX_POLICY_WARNINGS_SHOWN:
                more = len(policy.warnings) - MAX_POLICY_WARNINGS_SHOWN
                print(f"  {'':7}  ... and {more} more: agent-sentinel validate")
    for path, names in shared:
        print(f"\n{_mark('warn')}{len(names)} servers share the pins file {shown_path(path)}: "
              f"{', '.join(names)}. Give each server its own (wrap does)")
    if extras is not None:
        _print_extras(extras)
    found = counts(reports)
    extensions = sum(len(report.extensions) for report in reports)
    print(f"\nSummary: {found['protected']} protected, {found['unprotected']} NOT protected, {found['remote']} remote "
          f"(cannot be protected), {found['broken']} broken"
          + (f"; {extensions} Desktop Extension(s), which cannot be wrapped" if extensions else "") + ".")
    if code:
        print("Exit code 1: see the [fail] lines.")


def _print_extras(extras: Extras) -> None:
    """The control plane, and what differs from the --baseline (or where --save-baseline wrote it)."""
    if extras.control_plane:
        print("\nControl plane (agent-sentinel's own files: policies, pins, audit logs, hook state, approvers):")
        for line in extras.control_plane:
            print(f"  {_mark(line.level)}{line.text}")
    if extras.baseline_file is not None:
        print(f"\nBaseline {shown_path(extras.baseline_file)}:")
        if not extras.drift:
            print(f"  {_mark('ok')}nothing was added, changed or removed since it was saved")
        for text in extras.drift:
            print(f"  {_mark('fail')}{text}")
        if extras.drift:
            print(f"  {'':7}If you made these changes, save a new baseline: agent-sentinel doctor --save-baseline FILE")
    if extras.saved_baseline is not None:
        print(f"\n{_mark('info')}Saved the baseline to {shown_path(extras.saved_baseline)}; compare with it later: "
              f"agent-sentinel doctor --baseline {shown_path(extras.saved_baseline)}")
    for text in extras.baseline_warnings:
        print(f"  {_mark('warn')}{text}")


def _print_config(report: ConfigReport) -> None:
    label = CLIENTS[report.client].label if report.client in CLIENTS else "Configuration"
    scope = " (project)" if report.scope == "project" else ""
    print(f"\n{label}{scope}: {shown_path(report.path)}" + (f"  ({report.note})" if report.note else ""))
    if report.error:
        print(f"  {_mark('fail')}cannot be read: {report.error}")
        return
    if not report.servers:
        print(f"  {_mark('info')}no servers")
    width = min(24, max([len(server.name) for server in report.servers] or [4]))
    for server in report.servers:
        for line in server.lines:
            print(f"  {_mark(line.level)}{server.name:{width}}  {line.text}")
    if report.extensions:
        print(f"  {_mark('warn')}{len(report.extensions)} Desktop Extension(s), which cannot be wrapped, so NOT "
              f"protected: {', '.join(printable(name, limit=40) for name in report.extensions[:10])}"
              + (" ..." if len(report.extensions) > 10 else ""))


def as_json(reports: list[ConfigReport], policies: dict[str, PolicyReport],
            shared: list[tuple[str, list[str]]], code: int, extras: Extras | None = None) -> dict[str, Any]:
    """The report as plain data; every text from a file is already printable."""
    extras = extras or Extras()
    return {
        "version": __version__,
        "python": printable(sys.executable, limit=500),
        "configs": [{
            "client": report.client,
            "path": printable(report.path, limit=500),
            "scope": report.scope,
            "error": report.error,
            "servers": [{
                "name": server.name,
                "status": server.status,
                "policy": printable(server.policy, limit=500) if server.policy else None,
                "pins": printable(server.pins, limit=500) if server.pins else None,
                "audit": printable(server.audit, limit=500) if server.audit else None,
                "findings": [{"level": line.level, "text": line.text} for line in server.lines],
            } for server in report.servers],
            "desktop_extensions": [printable(name, limit=100) for name in report.extensions],
        } for report in reports],
        "policies": [{"path": printable(policy.path, limit=500), "loads": policy.loads, "summary": policy.summary,
                      "warnings": policy.warnings} for policy in policies.values()],
        "shared_pins": [{"path": printable(path, limit=500), "servers": names} for path, names in shared],
        "control_plane": [{"level": line.level, "text": line.text} for line in extras.control_plane],
        "baseline": None if extras.baseline_file is None else {
            "file": printable(extras.baseline_file, limit=500), "changes": extras.drift},
        "saved_baseline": printable(extras.saved_baseline, limit=500) if extras.saved_baseline else None,
        "baseline_warnings": extras.baseline_warnings,
        "summary": {status: counts(reports)[status] for status in STATUSES},
        "exit_code": code,
    }
