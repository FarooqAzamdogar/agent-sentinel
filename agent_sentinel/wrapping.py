"""One server entry of a client configuration: what kind it is, and putting the proxy in front of it or taking it out.

A stdio entry starts a program:

    "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:/work"],
              "env": {"DEBUG": "1"}}

Wrapped, the same entry starts the proxy, which starts the program:

    "files": {"command": "C:/Python313/python.exe",
              "args": ["-I", "-m", "agent_sentinel", "proxy", "--policy", "C:/Users/me/.agent-sentinel/policy.json",
                       "--audit", "C:/Users/me/.agent-sentinel/audit.jsonl",
                       "--pins", "C:/Users/me/.agent-sentinel/pins/claude-desktop-files-3fa29c1b.json",
                       "--name", "files", "--pass-env", "DEBUG",
                       "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "C:/work"],
              "env": {"DEBUG": "1"}}

Every other key of the entry, known or not, stays where it was. Unwrapping
rebuilds "command" and "args" from what follows the "--", so no record of the
original needs to be kept anywhere else (the backup `wrap` makes covers an
exact restore). Every path is absolute: the client starts the proxy in a
folder of its own choosing.

Why "-I" (isolated mode): `python -m` imports from the current folder first,
and clients start servers in folders they choose, often the project the
agent works on. A folder named agent_sentinel there would run instead of the
proxy. -I leaves the current folder (and PYTHON* variables) out. It also
leaves out the user's own site-packages, so a `pip install --user` copy is
not found with it: then `wrap` writes the entry without -I and says why.

Each name in the entry's "env" becomes a --pass-env, so that the server
still gets its tokens when the proxy is started with --clean-env.

Remote entries ("url", "serverUrl", or a type such as "http") cannot be
wrapped: the proxy speaks stdio only.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any

# The proxy options that take a value, and those that do not (the command-line
# contract between the proxy and the commands that write or read wrapped entries).
VALUE_OPTIONS = frozenset({
    "--policy", "--audit", "--pins", "--name", "--pass-env", "--env-file", "--approve-with",
    "--approval-timeout", "--max-message-bytes", "--tool-names", "--elicitation-host",
})
FLAG_OPTIONS = frozenset({"--no-log-args", "--no-pins", "--monitor", "--clean-env", "--quiet", "--verbose"})
# What starts the proxy: "python -I -m agent_sentinel proxy", "agent-sentinel proxy", "uvx agent-sentinel@0.5 proxy".
_LAUNCHER = re.compile(r"agent[-_]sentinel(\.exe|\.cmd|\.bat)?([=@].*)?", re.IGNORECASE)
_LAUNCHER_REACH = 8  # how far into the command the launcher is looked for
# How a Python is told to run agent-sentinel: isolated (see the module docstring) or not.
ISOLATED_MODULE = ["-I", "-m", "agent_sentinel"]
PLAIN_MODULE = ["-m", "agent_sentinel"]
# Remote entries: these keys, or one of these types.
REMOTE_KEYS = ("url", "serverUrl")
REMOTE_TYPES = frozenset({"http", "sse", "streamable-http", "streamablehttp", "ws", "websocket"})
# What --name allows (firewall.SERVER_NAME), and what a variable name may be.
_NAME_CHARACTER = re.compile(r"[^A-Za-z0-9_.-]")
MAX_NAME_CHARS = 64
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")


class WrapError(ValueError):
    """An entry that cannot be wrapped or unwrapped, and why (said to the user, the entry is left alone)."""


# ---- what kind of entry ------------------------------------------------------------------

def kind_of(entry: Any) -> str:
    """"remote", "stdio", or "broken" (not an object, or no usable command)."""
    if not isinstance(entry, dict):
        return "broken"
    entry_type = entry.get("type")
    if any(key in entry for key in REMOTE_KEYS) or (
        isinstance(entry_type, str) and entry_type.lower() in REMOTE_TYPES
    ):
        return "remote"
    return "stdio" if command_line(entry) is not None else "broken"


def command_line(entry: Any) -> list[str] | None:
    """[command, *args] of a stdio entry, or None if they are missing or not text."""
    if not isinstance(entry, dict):
        return None
    command, args = entry.get("command"), entry.get("args", [])
    if not isinstance(command, str) or not command.strip():
        return None
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        return None
    return [command, *args]


@dataclass
class ProxyCommand:
    """A wrapped entry read back: the proxy's options, and the server command after "--"."""

    launcher: list[str]  # the words that start the proxy, up to and including "proxy"
    options: list[tuple[str, str | None]] = field(default_factory=list)  # (option, value or None), in order
    server: list[str] = field(default_factory=list)  # empty when there is no "--" or nothing after it

    def value(self, option: str) -> str | None:
        """The last value given for an option (as argparse would keep it), or None."""
        values = self.values(option)
        return values[-1] if values else None

    def values(self, option: str) -> list[str]:
        return [value for name, value in self.options if name == option and value is not None]

    def has(self, flag: str) -> bool:
        return any(name == flag for name, _ in self.options)

    def python_module(self) -> tuple[str, bool] | None:
        """(the Python, whether it runs isolated) when the launcher is `PYTHON [-I] -m agent_sentinel proxy`.

        None for any other launcher (an agent-sentinel script, uvx, a shell).
        """
        middle = self.launcher[1:-1]
        if middle == ISOLATED_MODULE:
            return self.launcher[0], True
        if middle == PLAIN_MODULE:
            return self.launcher[0], False
        return None


def read_proxy_command(words: list[str]) -> ProxyCommand | None:
    """The proxy part of a command line, or None if the command does not start the proxy.

    Lenient on purpose, because `doctor` reads entries written by hand and by
    newer versions: an option it does not know is kept as a flag. The
    server command is everything after the first "--" that is not the value
    of an option.
    """
    at = None
    for index in range(min(len(words) - 1, _LAUNCHER_REACH)):
        word = os.path.basename(words[index].replace("\\", "/"))
        if words[index + 1] == "proxy" and _LAUNCHER.fullmatch(word):
            at = index + 2
            break
    if at is None:
        return None
    found = ProxyCommand(launcher=words[:at])
    index = at
    while index < len(words):
        word = words[index]
        if word == "--":
            found.server = words[index + 1:]
            return found
        name, equals, value = word.partition("=")
        if equals and name in VALUE_OPTIONS:
            found.options.append((name, value))
        elif word in VALUE_OPTIONS and index + 1 < len(words):
            found.options.append((word, words[index + 1]))
            index += 1
        else:
            found.options.append((word, None))
        index += 1
    return found


def proxy_command_of(entry: Any) -> ProxyCommand | None:
    """The proxy part of an entry's command, or None if it is not wrapped (or not a stdio entry)."""
    words = command_line(entry)
    return read_proxy_command(words) if words is not None else None


# ---- wrapping ------------------------------------------------------------------------------

@dataclass(frozen=True)
class ProxySettings:
    """What wrap writes into each entry. Every path is absolute."""

    python: str
    policy: str
    audit: str
    pins_folder: str
    monitor: bool = False
    isolated: bool = True  # start Python with -I (see the module docstring)


def server_label(name: str, taken: set[str]) -> str:
    """A --name for the entry `name`: letters, digits, "-", "_" and "." only, at most 64, not one already taken."""
    base = _NAME_CHARACTER.sub("-", name)[:MAX_NAME_CHARS].strip("-") or "server"
    label, number = base, 1
    while label.lower() in taken:
        number += 1
        suffix = f"-{number}"
        label = base[: MAX_NAME_CHARS - len(suffix)] + suffix
    taken.add(label.lower())
    return label


def pins_file(settings: ProxySettings, client: str, label: str, source: str) -> str:
    """One pins file per server: <pins folder>/<client>-<name>-<8 hex>.json.

    `source` says where the entry comes from: the configuration file's full
    path, or for a printed entry its server command. The code tells apart two
    configurations that name a server the same (two projects with a "files"
    server), so they never share a pins file.
    """
    where = os.path.normcase(source).encode("utf-8", "surrogatepass")
    code = hashlib.sha256(where).hexdigest()[:8]
    return os.path.join(settings.pins_folder, f"{client}-{label}-{code}.json")


def passed_variables(entry: dict[str, Any]) -> list[str]:
    """The names in the entry's "env", which become --pass-env. WrapError for a name that is not a variable name."""
    env = entry.get("env", {})
    if env is None:
        return []
    if not isinstance(env, dict):
        raise WrapError("its \"env\" is not an object")
    names = []
    for name in env:
        if not ENV_NAME.fullmatch(name):
            raise WrapError(f"its \"env\" has a key that is not a plain variable name: {name[:60]!r}")
        names.append(name)
    return names


def wrap_entry(entry: dict[str, Any], settings: ProxySettings, label: str, pins: str) -> dict[str, Any]:
    """A copy of a stdio entry that starts the proxy in front of the same command.

    The other keys keep their place; "args" is added after "command" when the
    entry had none. WrapError if the entry cannot be wrapped.
    """
    words = command_line(entry)
    if words is None:
        raise WrapError("it has no usable \"command\" (text) and \"args\" (a list of text)")
    if read_proxy_command(words) is not None:
        raise WrapError("it is already wrapped")
    module = ISOLATED_MODULE if settings.isolated else PLAIN_MODULE
    proxy_args = [*module, "proxy", "--policy", settings.policy, "--audit", settings.audit,
                  "--pins", pins, "--name", label]
    for name in passed_variables(entry):
        proxy_args += ["--pass-env", name]
    if settings.monitor:
        proxy_args.append("--monitor")
    proxy_args += ["--", *words]
    return _with_command(entry, settings.python, proxy_args)


def unwrap_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """A copy of a wrapped entry that starts the server command directly again. WrapError if it is not wrapped."""
    found = proxy_command_of(entry)
    if found is None:
        raise WrapError("it is not wrapped")
    if not found.server:
        raise WrapError("it starts the proxy without a server command after '--'; fix it by hand")
    return _with_command(entry, found.server[0], found.server[1:])


def _with_command(entry: dict[str, Any], command: str, args: list[str]) -> dict[str, Any]:
    rebuilt: dict[str, Any] = {}
    for key, value in entry.items():
        if key == "command":
            rebuilt["command"] = command
            if "args" not in entry and args:
                rebuilt["args"] = list(args)
        elif key == "args":
            if args:
                rebuilt["args"] = list(args)
        else:
            rebuilt[key] = value
    return rebuilt


def installed_version(python: str, isolated: bool = True) -> str | None:
    """The agent-sentinel version that `python [-I] -m agent_sentinel` would run, or None if it cannot import it.

    Run from the temporary folder, as a client would start it: not from this
    folder, where a copy of the source could be imported that the client
    never sees. Without -I, -E still leaves out PYTHON* variables, which the
    client's environment may not have.
    """
    flag = "-I" if isolated else "-E"
    try:
        found = subprocess.run(
            [python, flag, "-c", "import agent_sentinel, sys; sys.stdout.write(str(agent_sentinel.__version__))"],
            capture_output=True, timeout=30, cwd=tempfile.gettempdir(),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if found.returncode != 0:
        return None
    return found.stdout.decode("ascii", errors="replace").strip()[:40] or None


@dataclass(frozen=True)
class PythonCheck:
    """How the wrapped entries should start this Python, and the agent-sentinel version it then runs."""

    isolated: bool
    version: str | None  # None: it cannot import agent_sentinel at all


def check_python(python: str) -> PythonCheck:
    """Try `python -I` first; fall back to plain -m only when that alone imports agent_sentinel (a --user install)."""
    version = installed_version(python, isolated=True)
    if version is not None:
        return PythonCheck(True, version)
    version = installed_version(python, isolated=False)
    if version is not None:
        return PythonCheck(False, version)
    return PythonCheck(True, None)
