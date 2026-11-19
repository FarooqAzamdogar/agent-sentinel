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
                  an unreadable pins file, a command that is not found, an argument a
                  .cmd launcher cannot take

and these are checked too: every policy loads, with its warnings; the audit
and pins folders can be written; no two servers share a pins file; npx and
uvx packages are pinned to a version; and which env names look like secrets
written in the file (names only: a value is never printed).

Nothing is changed and no server is started. A configuration may come from
someone else (a project's checked-in .mcp.json), so doctor never runs a
program it names: whether a Python can import agent_sentinel is tried only
for the Python that runs doctor itself. Files it names (policy, pins) are
read only when they are ordinary files of at most MAX_CHECKED_FILE_BYTES,
and a path on another machine (\\\\server\\share on Windows) is never
touched: merely looking at one makes Windows sign in to that machine with
the user's credentials. Everything read from a configuration or a policy is
printed through `printable`.

Exit codes: 0 every stdio server is protected; 1 a server is not protected
or is broken, a configuration cannot be read, or a policy does not load;
2 a --config file does not exist.
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
from typing import Any

from . import __version__, clients, home, mcp_proxy
from .cli_common import EXIT_FAIL, EXIT_OK, CommandError, shown_command, shown_path
from .clients import CLIENTS
from .config_file import ConfigError, read_config
from .firewall import SERVER_NAME
from .leaks import find_secrets
from .policy import Policy, PolicyError
from .policy_errors import file_error_message
from .server_env import looks_secret  # the proxy's own test, so that doctor and the proxy agree
from .textutil import printable
from .wrapping import (
    FLAG_OPTIONS,
    VALUE_OPTIONS,
    ProxyCommand,
    command_line,
    installed_version,
    kind_of,
    mentions_proxy,
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
(\\\\server\\share): on Windows, merely looking at one sends your sign-in to that machine.

examples:
  agent-sentinel doctor
  agent-sentinel doctor --config .mcp.json --format json
"""

STATUSES = ("protected", "unprotected", "remote", "broken")
_EXACT_VERSION = re.compile(r"v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?")
# Where a PyPI package's name ends in a requirement such as "pkg>=1.0" or "pkg[extra]".
_PYPI_NAME_END = re.compile(r"[=<>~!@ \[]")
_NPX_VALUE_OPTIONS = frozenset({"-p", "--package", "-c", "--call", "--cache", "--registry", "--userconfig", "-w",
                                "--workspace", "--node-options"})
_UVX_VALUE_OPTIONS = frozenset({
    "--from", "--with", "--with-editable", "--with-requirements", "-p", "--python", "--index", "--index-url",
    "--extra-index-url", "--default-index", "--find-links", "-f", "--constraint", "-c", "--override",
    "--python-preference", "--refresh-package", "--reinstall-package", "--upgrade-package", "--cache-dir",
    "--directory", "--project", "--config-file", "--env-file", "--index-strategy", "--keyring-provider",
    "--resolution", "--prerelease", "--exclude-newer", "--link-mode", "--compile-bytecode",
})
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


@dataclass
class ConfigReport:
    client: str | None
    path: Path
    scope: str = "user"
    note: str = ""
    error: str | None = None
    servers: list[ServerReport] = field(default_factory=list)
    extensions: list[str] = field(default_factory=list)


@dataclass
class PolicyReport:
    path: str
    loads: bool
    summary: str
    warnings: list[str] = field(default_factory=list)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", action="append", default=[], metavar="FILE",
                        help="check this configuration file (repeat for more; default: every one `clients` finds)")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="output format (default text)")


def run(args: argparse.Namespace) -> int:
    _versions.clear()
    reports = [check_config(*where) for where in _configs(args.config)]
    policies = check_policies(reports)
    for report in reports:
        for server in report.servers:
            _add_policy_result(server, policies)
    shared = shared_pins(reports)
    code = exit_code(reports, policies)
    if args.format == "json":
        print(json.dumps(as_json(reports, policies, shared, code), indent=2, ensure_ascii=True))
    else:
        print_report(reports, policies, shared, code)
    return code


def _configs(given: list[str]) -> list[tuple[Path, str | None, str, str]]:
    """(path, client, scope, note) of each configuration to check."""
    if given:
        found = []
        for path_text in given:
            path = Path(os.path.abspath(path_text))
            if not path.exists():
                raise CommandError(f"there is no file at {path}")
            found.append((path, clients.client_for_file(path), clients.scope_of(path), ""))
        return found
    return [(location.path, location.client, location.scope, location.note)
            for location in clients.all_locations() if location.path.is_file()]


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
    if not isinstance(servers, dict):
        report.error = f"\"{key}\" is not an object"
        return report
    project = clients.project_folder(path)
    for name, entry in servers.items():
        report.servers.append(check_server(name, entry, client, project if scope == "project" else None))
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
            "fail", f"NOT protected: {_shown(words)} starts the proxy only after other words, which may run something "
                    "else first, unchecked. Make the entry start the server directly, then run wrap")])
        report.lines += _secret_lines(entry)
        return report
    if proxy is None:
        fix = f"agent-sentinel wrap --client {client} --policy POLICY" if client else "agent-sentinel wrap"
        report = ServerReport(shown_name, "unprotected", [
            Line("fail", f"NOT protected: starts {_shown(words)} directly. To fix: {fix}")])
        report.lines += _package_lines(words) + _secret_lines(entry)
        return report
    report = ServerReport(shown_name, "protected")
    _check_wrapped(report, proxy, entry, project)
    report.lines += _package_lines(proxy.server) + _secret_lines(entry)
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
    _check_launcher(lines, proxy)
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
    report.policy = _policy_path(lines, proxy.value("--policy"))
    report.pins = _pins_path(lines, proxy)
    report.audit = _audit_path(lines, proxy.value("--audit"))
    _check_name(lines, proxy.value("--name"))
    _check_server_command(lines, proxy.server)
    _check_passed_env(lines, proxy, entry)
    if project is not None:
        for what, path in (("policy", report.policy), ("pins file", report.pins), ("audit log", report.audit)):
            if path and clients.inside_folder(path, project):
                lines.append(Line("warn", f"the {what} is inside the project folder, where the agent's own tools may "
                                          "be able to change it; keep it in the agent-sentinel home folder"))


def _check_launcher(lines: list[Line], proxy: ProxyCommand) -> None:
    """The program that starts the proxy exists, and a Python started with -m agent_sentinel can import it."""
    starter = proxy.launcher[0]
    if _on_another_machine(starter):
        lines.append(Line("fail", f"the program that starts the proxy, {printable(starter, limit=200)}, is on another "
                                  "machine; doctor does not open network paths (see agent-sentinel doctor --help)"))
        return
    if not (os.path.isfile(starter) if home.is_absolute(starter) else mcp_proxy._resolve_executable(starter)):
        lines.append(Line("fail", f"the program that starts the proxy, {printable(starter, limit=200)}, was not found"))
        return
    module = proxy.python_module()
    if module is None:
        return
    python, isolated = module
    if not isolated:
        lines.append(Line("warn", "Python is started without -I, so a folder named agent_sentinel in the folder the "
                                  "client starts the server in would run instead of the proxy. To fix: unwrap, then "
                                  "wrap again"))
    if not _is_this_python(python):
        return  # never run a program a configuration names: it could be anything
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
    if not home.is_absolute(program) or _on_another_machine(program) or not sys.executable:
        return False
    try:
        return os.path.samefile(program, sys.executable)
    except OSError:
        return False


def _on_another_machine(path: str) -> bool:
    """A Windows network path (\\\\server\\share\\..., also //server/share and \\\\?\\UNC\\...), never opened.

    Windows answers any look at such a path, even "does it exist?", by
    signing in to that server with the user's credentials. A checked-in
    configuration must not be able to make doctor do that. Device paths
    (\\\\.\\, \\\\?\\) start the same way and are refused with them.
    """
    return sys.platform == "win32" and path[:1] in ("\\", "/") and path[1:2] in ("\\", "/")


def _too_big(path: str) -> bool:
    try:
        return os.path.getsize(path) > MAX_CHECKED_FILE_BYTES
    except OSError:
        return True


def _policy_path(lines: list[Line], policy: str | None) -> str | None:
    if policy is None:
        lines.append(Line("fail", "no --policy, so the proxy will not start"))
        return None
    if not home.is_absolute(policy):
        lines.append(Line("fail", f"the policy path {printable(policy, limit=200)!r} is relative: the client starts "
                                  "the proxy in a folder of its own choosing. Write the full path"))
        return None
    if _on_another_machine(policy):
        lines.append(Line("fail", f"the policy {printable(policy, limit=200)} is on another machine; doctor does not "
                                  "open network paths, so it cannot tell whether the proxy will start. Keep the "
                                  "policy on this machine"))
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
    if not home.is_absolute(pins):
        lines.append(Line("warn", f"the pins path {printable(pins, limit=200)!r} is relative to whatever folder the "
                                  "client starts the proxy in. Write the full path"))
        return None
    if _on_another_machine(pins):
        lines.append(Line("warn", f"the pins file {printable(pins, limit=200)} is on another machine; doctor does "
                                  "not open network paths, so it was not checked"))
        return os.path.normpath(pins)
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
    if not home.is_absolute(audit):
        lines.append(Line("warn", f"the audit path {printable(audit, limit=200)!r} is relative to whatever folder the "
                                  "client starts the proxy in. Write the full path"))
        return None
    if _on_another_machine(audit):
        lines.append(Line("warn", f"the audit log {printable(audit, limit=200)} is on another machine; doctor does "
                                  "not open network paths, so it was not checked"))
    else:
        _check_writable(lines, audit, "audit log", "decisions are not logged")
    return os.path.normpath(audit)


def _check_writable(lines: list[Line], path: str, what: str, consequence: str) -> None:
    folder = os.path.dirname(path)
    if not os.path.isdir(folder):
        lines.append(Line("warn", f"the {what}'s folder {printable(folder, limit=200)} does not exist, "
                                  f"so {consequence}"))
    elif not os.access(folder, os.W_OK) or (os.path.exists(path) and not os.access(path, os.W_OK)):
        lines.append(Line("warn", f"the {what} {printable(path, limit=200)} cannot be written, so {consequence}"))


def _check_name(lines: list[Line], name: str | None) -> None:
    if name is None:
        lines.append(Line("warn", "no --name: the audit log cannot tell this server's records from others'"))
    elif not SERVER_NAME.fullmatch(name):
        lines.append(Line("fail", f"the proxy refuses the --name {printable(name, limit=80)!r} (letters, digits, "
                                  "'-', '_' and '.' only, at most 64)"))


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


# ---- packages and secrets ------------------------------------------------------------------------------

def unpinned_package(words: list[str]) -> tuple[str, str] | None:
    """(package, how to pin it) when an npx or uvx command runs a package without an exact version; else None."""
    program = os.path.basename(words[0].replace("\\", "/")).lower()
    for ending in (".cmd", ".exe", ".bat", ".ps1"):
        if program.endswith(ending):
            program = program[: -len(ending)]
    if program == "npx":
        spec = _first_package(words[1:], _NPX_VALUE_OPTIONS, ("-p", "--package"))
        return (spec, f"{_npm_name(spec)}@1.2.3") if spec and _npm_unpinned(spec) else None
    if program == "uvx" or (program == "uv" and words[1:3] == ["tool", "run"]):
        rest = words[1:] if program == "uvx" else words[3:]
        spec = _first_package(rest, _UVX_VALUE_OPTIONS, ("--from",))
        if not spec or not _pypi_unpinned(spec):
            return None
        return spec, _PYPI_NAME_END.split(spec, maxsplit=1)[0] + "==1.2.3"
    return None


def _first_package(args: list[str], value_options: frozenset[str], package_options: tuple[str, ...]) -> str | None:
    """The package a runner runs: the value of --package/--from, or else the first word that is not an option."""
    index = 0
    while index < len(args):
        word = args[index]
        name, equals, value = word.partition("=")
        if name in package_options:
            return value if equals else (args[index + 1] if index + 1 < len(args) else None)
        if word == "--":
            return args[index + 1] if index + 1 < len(args) else None
        if equals and name in value_options:
            pass
        elif word in value_options:
            index += 1
        elif not word.startswith("-"):
            return word
        index += 1
    return None


def _npm_name(spec: str) -> str:
    at = spec.find("@", 1)
    return spec if at == -1 else spec[:at]


def _npm_unpinned(spec: str) -> bool:
    if spec.startswith((".", "/", "~")) or ":" in spec or ("/" in spec and not spec.startswith("@")):
        return False  # a path, a URL or a git reference: not a registry package
    at = spec.find("@", 1)
    return at == -1 or not _EXACT_VERSION.fullmatch(spec[at + 1:])


def _pypi_unpinned(spec: str) -> bool:
    if spec.startswith((".", "/", "~")) or "://" in spec or spec.startswith("git+"):
        return False
    if "==" in spec:
        return not _EXACT_VERSION.fullmatch(spec.split("==", 1)[1].strip())
    if "@" in spec:  # uv's "package@1.2.3"
        return not _EXACT_VERSION.fullmatch(spec.split("@", 1)[1].strip())
    return True


def _package_lines(words: list[str]) -> list[Line]:
    if not words:
        return []
    found = unpinned_package(words)
    if found is None:
        return []
    package, pinned = found
    return [Line("warn", f"the package {printable(package, limit=80)!r} is not pinned to an exact version: a new "
                         f"release would run without review. Pin it, for example {printable(pinned, limit=80)}")]


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
    return PolicyReport(path, True, summary, [printable(text, limit=300) for text in policy.warnings()])


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


def exit_code(reports: list[ConfigReport], policies: dict[str, PolicyReport]) -> int:
    found = counts(reports)
    failed = (found["unprotected"] or found["broken"] or any(report.error for report in reports)
              or any(not policy.loads for policy in policies.values()))
    return EXIT_FAIL if failed else EXIT_OK


# ---- output ------------------------------------------------------------------------------------------------

def _mark(level: str) -> str:
    return f"[{level}]".ljust(7)


def print_report(reports: list[ConfigReport], policies: dict[str, PolicyReport],
                 shared: list[tuple[str, list[str]]], code: int) -> None:
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
    found = counts(reports)
    extensions = sum(len(report.extensions) for report in reports)
    print(f"\nSummary: {found['protected']} protected, {found['unprotected']} NOT protected, {found['remote']} remote "
          f"(cannot be protected), {found['broken']} broken"
          + (f"; {extensions} Desktop Extension(s), which cannot be wrapped" if extensions else "") + ".")
    if code:
        print("Exit code 1: see the [fail] lines.")


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
            shared: list[tuple[str, list[str]]], code: int) -> dict[str, Any]:
    """The report as plain data; every text from a file is already printable."""
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
        "summary": {status: counts(reports)[status] for status in STATUSES},
        "exit_code": code,
    }
