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
exact restore). One thing cannot be told apart that way: an entry written
with "args": [] and one without "args" wrap the same, and both come back
without "args" (they mean the same to a client). Every path is absolute: the
client starts the proxy in a folder of its own choosing.

Why "-I" (isolated mode): `python -m` imports from the current folder first,
and clients start servers in folders they choose, often the project the
agent works on. A folder named agent_sentinel there would run instead of the
proxy. -I leaves the current folder (and PYTHON* variables) out. It also
leaves out the user's own site-packages, so a `pip install --user` copy is
not found with it: then `wrap` writes the entry without -I and says why.

Each name in the entry's "env" becomes a --pass-env, so that the server
still gets its tokens when the proxy is started with --clean-env. The client
gives "env" to whatever it starts, so the proxy's launcher gets it too. A
variable there that changes what the launcher runs (PYTHONPATH for a Python
without -I, UV_INDEX_URL for uvx, __PYVENV_LAUNCHER__ for any Python) or
where the proxy finds "~" (USERPROFILE, HOME) makes the entry broken, and
wrap does not write such an entry (env_redirects). A launcher written as a
relative path, or a Python option that can change what it imports, makes
the entry broken too (launcher_problem).

Remote entries ("url", "serverUrl", or a type such as "http") cannot be
wrapped: the proxy speaks stdio only.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from . import home
from .textutil import printable

# The proxy options that take a value, and those that do not (the command-line
# contract between the proxy and the commands that write or read wrapped entries).
VALUE_OPTIONS = frozenset({
    "--policy", "--audit", "--pins", "--name", "--pass-env", "--env-file", "--approve-with",
    "--approval-timeout", "--max-message-bytes", "--tool-names", "--elicitation-host",
})
FLAG_OPTIONS = frozenset({"--no-log-args", "--no-pins", "--monitor", "--clean-env", "--quiet", "--verbose"})
# The shapes of command that start the proxy (read_proxy_command), each followed by "proxy":
#   agent-sentinel                        the script (agent-sentinel.exe, .cmd, .bat)
#   PYTHON [-I] -m agent_sentinel         a Python, with only harmless options of its own before -m
#   uvx / uv tool run / pipx run PACKAGE  a package runner, PACKAGE being agent-sentinel[@VERSION|==VERSION|@latest]
SCRIPT = re.compile(r"agent[-_]sentinel(\.exe|\.cmd|\.bat)?", re.IGNORECASE)
# A PEP 440 version, in a strict form: 1!0.5.0rc1.post2.dev3+local.4, every part but the release optional.
# uv reads "NAME@X" as a version only when X is one; anything else ("0.5.0-evil", "1.zip") becomes a
# requirement "NAME @ X", and X a path relative to the folder the client starts it in. Each number is at
# most 18 digits, so that uv's 64-bit numbers hold it.
_VERSION = r"(?i:([0-9]{1,18}!)?[0-9]{1,18}(\.[0-9]{1,18})*((a|b|rc)[0-9]{1,18})?(\.post[0-9]{1,18})?" \
           r"(\.dev[0-9]{1,18})?(\+[a-z0-9]+(\.[a-z0-9]+)*)?)"
# Only a version may follow the package's name. Anything else is a requirement that installs other code under
# that name: "agent-sentinel@git+https://...", "agent-sentinel @ file:///...", extras, markers. "latest" is
# lowercase only: uv knows no other spelling, and would read "@LATEST" as a folder named LATEST.
PACKAGE = re.compile(r"(?i:agent[-_]sentinel)(@latest|(@|==)" + _VERSION + r")?")
# A runner's package word is matched against PACKAGE only when it is at most this long: the name, "==" and a
# version of up to 64 characters, far longer than any real one. A longer word is not agent-sentinel at a version.
MAX_PACKAGE_CHARS = len("agent-sentinel==") + 64
# Any word that names agent-sentinel, whatever follows the name (mentions_proxy).
_NAMED = re.compile(r"agent[-_]sentinel([^A-Za-z0-9_-].*)?", re.IGNORECASE | re.DOTALL)
# The file name of a Python, with .exe or not: python3.13, python3.13t (free-threaded), pythonw, python_d and
# python3.12d or python3.12-dbg (debug builds), python3.12-intel64 (macOS), pypy3.10, graalpy, and the py launcher.
_PYTHON = re.compile(r"((python|pypy|graalpy)[0-9.]*t?w?(d|_d|-dbg)?(-intel64)?|pyw?)(\.exe)?", re.IGNORECASE)
# Options a Python may get before "-m agent_sentinel" that cannot make it run anything else
# (not -c, not another -m, not a script): -I, -E, -s, -S, -B, -u, -O, -q, -b; -X and -W
# with their value; the Windows py launcher's version, such as -3.12.
_PYTHON_FLAGS = re.compile(r"-[IEsSBuOqb]+|-[0-9][0-9.]*(-(32|64))?")
_PYTHON_VALUE_FLAGS = frozenset({"-X", "-W"})
# The only -X values that leave what a Python imports and runs as it was (launcher_problem). Others need not:
# "-X pycache_prefix=folder" makes even "python -I" run bytecode found in that folder, which may be relative to
# the client's; "-X frozen_modules=off" and "-X presite=module" change what is imported. A -W value is harmless
# unless its category has a dot: "-W ignore::module.Warning" imports that module when Python starts.
_HARMLESS_X_VALUES = frozenset({"utf8", "utf8=0", "utf8=1"})
_RUNNERS = (["uvx"], ["uv", "tool", "run"], ["pipx", "run"])
_RUNNER_PACKAGE_OPTIONS = frozenset({"--from", "--spec"})  # uvx --from agent-sentinel==0.5.0 agent-sentinel
_LAUNCHER_REACH = 8  # how far into the command a mention of the proxy is looked for (mentions_proxy)
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
# Variables of an entry's "env" that change what starts as the proxy (env_redirects). The client starts the
# launcher with them, so they act on it, not only on the server behind it. Which ones count depends on the
# launcher; each set comes with what it changes, as doctor says it.
#   Every launcher ends in a Python, which takes its own program file from __PYVENV_LAUNCHER__ even with -I:
#   told that it is x/Scripts/python.exe, it imports from x/Lib/site-packages when x holds a pyvenv.cfg.
#   PYTHONEXECUTABLE does the same on macOS, and counts here with or without -I, to be safe.
_EVERY_PYTHON = (frozenset({"__PYVENV_LAUNCHER__", "PYTHONEXECUTABLE"}), (),
                 "Python takes its own program file from it, even with -I, and imports from the site-packages "
                 "beside that file")
#   A launcher written without a folder is looked up on PATH.
_LOOKED_UP = (frozenset({"PATH"}), (),
              "the client looks up the program that starts the proxy, written without a folder, on that PATH")
#   The Windows py launcher chooses its Python by these.
_PY_LAUNCHER = (frozenset({"VIRTUAL_ENV", "PY_PYTHON", "PY_PYTHON2", "PY_PYTHON3"}), ("PYLAUNCHER_",),
                "the py launcher may start another Python")
#   A Python started without -I or -E imports from what these name (the agent-sentinel script and the
#   package runners start one that way).
_PYTHON_IMPORTS = (frozenset({"PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE", "PYTHONPLATLIBDIR",
                              "PYTHONPYCACHEPREFIX"}), (),
                   "a Python started without -I imports from the folders it names")
#   A Python started without -I, -s or -S finds the user's own site-packages from these, and runs the
#   .pth files there.
_USER_SITE = (frozenset({"APPDATA", "HOME", "USERPROFILE"}), (),
              "a Python started without -I finds the user's own site-packages, and runs their .pth files, "
              "in another folder")
#   uvx, uv tool run and pipx run choose by these where they get agent-sentinel from, which Python they
#   install it for, and which saved copy they reuse: uv reads UV_*, pipx PIPX_* and the pip it runs PIP_*,
#   each its configuration, cache and tools from the user's folders, and its downloads trust what the
#   certificate variables name. Any variable of theirs counts, apart from a few that change none of that.
#   On Windows uv reads its system configuration from %SYSTEMDRIVE%\ProgramData\uv\uv.toml.
_RUNNER = (frozenset({"PATH", "VIRTUAL_ENV", "CONDA_PREFIX", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
                      "PROGRAMDATA", "SYSTEMDRIVE", "XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "XDG_CACHE_HOME",
                      "XDG_DATA_HOME", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"}),
           ("UV_", "PIP_", "PIPX_"),
           "the package runner may get agent-sentinel from another index or folder, or run it with another "
           "Python or a saved copy")
_RUNNER_HARMLESS = frozenset({
    "UV_NO_CONFIG", "UV_NO_CACHE", "UV_OFFLINE", "UV_NO_PROGRESS", "UV_HTTP_TIMEOUT", "UV_REQUEST_TIMEOUT",
    "UV_CONCURRENT_DOWNLOADS", "UV_CONCURRENT_BUILDS", "UV_CONCURRENT_INSTALLS", "UV_LINK_MODE",
    "UV_COMPILE_BYTECODE", "UV_NATIVE_TLS",
    "PIP_DISABLE_PIP_VERSION_CHECK", "PIP_NO_CACHE_DIR", "PIP_QUIET", "PIP_VERBOSE", "PIP_NO_COLOR",
    "PIP_PROGRESS_BAR", "PIP_TIMEOUT", "PIP_RETRIES", "PIP_NO_INPUT", "PIP_ROOT_USER_ACTION",
    "PIPX_USE_EMOJI",
})
#   Whatever the launcher, the proxy reads "~" in --policy and its other file options, and in the policy's paths,
#   as the home folder these name. AGENT_SENTINEL_HOME counts only when it is not a full path (env_redirects): then
#   the proxy's home folder is in whatever folder the client starts it in.
_HOME = (frozenset({"HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", home.ENV_VAR}), (),
         "the proxy takes its home folder, and \"~\" in its options and in the policy's paths, from another place")
_PY_LAUNCHER_NAME = re.compile(r"pyw?(\.exe)?", re.IGNORECASE)
_FLAG_LETTERS = re.compile(r"-[IEsSBuOqb]+")


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


def _program(word: str) -> str:
    """The file name of a program, whichever slash its path uses: "C:\\py\\python.exe" -> "python.exe"."""
    return os.path.basename(word.replace("\\", "/"))


def _launcher_length(words: list[str]) -> int | None:
    """How many words start the proxy, "proxy" included, when the command has one of the known shapes; else None.

    Only these shapes count: whatever runs before the proxy in any other
    command (`cmd /c evil.py & agent-sentinel proxy ...`, `node x.js
    agent-sentinel proxy ...`) is not checked by anything, so such a command
    must never be taken for a protected one.
    """
    if not words:
        return None
    at = None
    program = _program(words[0])
    if SCRIPT.fullmatch(program):
        at = 1
    elif _PYTHON.fullmatch(program):
        at = _after_python_options(words)
    else:
        name = program.lower()
        name = name[:-len(".exe")] if name.endswith(".exe") else name
        for runner in _RUNNERS:
            if [name, *words[1:len(runner)]] == runner:
                at = _after_runner_options(words, len(runner))
                break
    if at is None or words[at:at + 1] != ["proxy"]:
        return None
    return at + 1


def _after_python_options(words: list[str]) -> int | None:
    """Where "proxy" must be after `PYTHON [harmless options] -m agent_sentinel`; None for any other Python command."""
    index = 1
    while index < len(words) and words[index] != "-m":
        if words[index] in _PYTHON_VALUE_FLAGS:
            index += 2
        elif _PYTHON_FLAGS.fullmatch(words[index]):
            index += 1
        else:
            return None
    return index + 2 if words[index + 1:index + 2] == ["agent_sentinel"] else None


def _after_runner_options(words: list[str], index: int) -> int | None:
    """Where "proxy" must be after `uvx [--from PACKAGE] PACKAGE`; None when the runner runs anything else."""
    if words[index:index + 1] and words[index] in _RUNNER_PACKAGE_OPTIONS:
        if not _is_package(words[index + 1] if index + 1 < len(words) else ""):
            return None
        index += 2
    return index + 1 if index < len(words) and _is_package(words[index]) else None


def _is_package(word: str) -> bool:
    """Whether a runner's word is agent-sentinel at a version (PACKAGE); a word over MAX_PACKAGE_CHARS never is."""
    return len(word) <= MAX_PACKAGE_CHARS and PACKAGE.fullmatch(word) is not None


def mentions_proxy(words: list[str]) -> bool:
    """Whether "agent-sentinel proxy" appears near the start of a command that read_proxy_command does not accept.

    Such a command may run something else first, or install something else
    under the name agent-sentinel ("uvx agent-sentinel@git+https://...
    proxy"), so it is not protected; doctor says why instead of calling it a
    plain unprotected server.
    """
    if read_proxy_command(words) is not None:
        return False
    return any(words[index + 1] == "proxy"
               and (_NAMED.fullmatch(words[index]) or _NAMED.fullmatch(_program(words[index])))
               for index in range(min(len(words) - 1, _LAUNCHER_REACH)))


def read_proxy_command(words: list[str]) -> ProxyCommand | None:
    """The proxy part of a command line, or None if the command does not start the proxy in a known shape.

    The launcher must have one of the shapes _launcher_length accepts. The
    options are read leniently, because `doctor` reads entries written by
    hand and by newer versions: an option it does not know is kept as a flag
    (see shortened_option). The server command is everything after the first
    "--" that is not the value of an option.
    """
    at = _launcher_length(words)
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


def shortened_option(word: str) -> list[str]:
    """The proxy options that `word` is a shortened form of ("--mon" -> ["--monitor"]); empty for any other word.

    argparse takes a shortened option for the whole one unless told not to.
    This proxy refuses them (allow_abbrev=False), but a proxy of another
    version may not, and an entry with "--mon" or "--polic weak.json" would
    then run in monitor mode, or with another policy than the one it seems to
    name.
    """
    name = word.partition("=")[0]
    if not name.startswith("--") or len(name) < 3 or name in VALUE_OPTIONS or name in FLAG_OPTIONS:
        return []
    return sorted(option for option in VALUE_OPTIONS | FLAG_OPTIONS if option.startswith(name))


def env_redirects(entry: Any, proxy: ProxyCommand,
                  environ: Mapping[str, str] | None = None) -> list[tuple[str, str]]:
    """(name, what it changes) for each variable of the entry's "env" that can change what starts as the proxy.

    A configuration need not touch the command to run other code under the
    name agent-sentinel: "PYTHONPATH": "evil" or "UV_INDEX_URL": "https://..."
    does it with the command left as it was. Which variables count depends on
    the launcher (see _EVERY_PYTHON and the sets after it); names are compared
    in capitals, as Windows does. A variable set to the value it has in
    `environ` (this terminal's, by default) changes nothing the user did not
    choose, so it does not count: people copy APPDATA into "env" so that a
    client that leaves it out can start npx.
    """
    env = entry.get("env") if isinstance(entry, dict) else None
    if not isinstance(env, dict):
        return []
    environ = os.environ if environ is None else environ
    sets = _redirecting_sets(proxy.launcher)
    found = []
    for name, value in env.items():
        upper = str(name).upper()
        if upper == home.ENV_VAR and isinstance(value, str) and home.is_absolute(value):
            continue  # a full path is the same folder wherever the client starts the proxy
        for names, prefixes, changes in sets:
            if upper in names or (upper.startswith(prefixes) and upper not in _RUNNER_HARMLESS):
                break
        else:
            continue
        own = environ.get(str(name))
        if isinstance(value, str) and own is not None and os.path.normcase(value) == os.path.normcase(own):
            continue
        found.append((str(name), changes))
    return found


def _redirecting_sets(launcher: list[str]) -> list[tuple[frozenset[str], tuple[str, ...], str]]:
    """The sets of variables that change what this launcher starts (see env_redirects)."""
    program = _program(launcher[0])
    sets = [_EVERY_PYTHON]
    if program == launcher[0]:
        sets.append(_LOOKED_UP)
    letters = set()
    if _PYTHON.fullmatch(program):
        if _PY_LAUNCHER_NAME.fullmatch(program):
            sets.append(_PY_LAUNCHER)
        index = 1
        while index < len(launcher) and launcher[index] != "-m":  # the Python's own options (see _PYTHON_FLAGS)
            if _FLAG_LETTERS.fullmatch(launcher[index]):
                letters.update(launcher[index][1:])
            index += 2 if launcher[index] in _PYTHON_VALUE_FLAGS else 1
    elif not SCRIPT.fullmatch(program):
        sets.append(_RUNNER)
    if not letters & {"I", "E"}:
        sets.append(_PYTHON_IMPORTS)
    if not letters & {"I", "s", "S"}:
        sets.append(_USER_SITE)
    sets.append(_HOME)
    return sets


def launcher_problem(proxy: ProxyCommand) -> str | None:
    """Why the program that starts the proxy may run something else than the entry says, or None. As doctor says it.

    Clients start "command" without a shell, so a path with a folder that is
    not a full path ("tools/python.exe", ".venv\\Scripts\\agent-sentinel.exe",
    and "~/py/python.exe", since only a shell reads "~" as the home folder)
    runs whatever is at that place under the folder the client starts in,
    often the project. A bare name is looked up on PATH; a full path is what
    it says. A Python's own -X and -W options can make it import other code
    (_HARMLESS_X_VALUES).
    """
    starter = proxy.launcher[0]
    if _program(starter) != starter and not home.is_absolute(starter):
        return ("is a relative path: the client starts it without a shell, so it runs whatever is at that path "
                "relative to its working folder (often the project), and \"~\" is not the home folder there. "
                "Write its full path")
    if not _PYTHON.fullmatch(_program(starter)):
        return None
    index = 1
    while index < len(proxy.launcher) and proxy.launcher[index] != "-m":  # the Python's own options
        flag = proxy.launcher[index]
        if flag not in _PYTHON_VALUE_FLAGS:
            index += 1
            continue
        value = proxy.launcher[index + 1] if index + 1 < len(proxy.launcher) else ""
        if not _harmless_python_option(flag, value):
            return (f"is started with {flag} {printable(value, limit=80)!r}, which can make Python import or run "
                    "other code (of -X only utf8 is taken, and a -W category must not name a module). Take the "
                    "option out")
        index += 2
    return None


def _harmless_python_option(flag: str, value: str) -> bool:
    """Whether a Python's own `-X value` or `-W value` leaves what it imports and runs as it was."""
    if flag == "-X":
        return value in _HARMLESS_X_VALUES
    fields = value.split(":")  # -W action:message:category:module:lineno
    category = fields[2] if len(fields) > 2 else ""
    return len(fields) <= 5 and "." not in category


def status_of(entry: Any) -> str:
    """"protected", "unprotected", "remote" or "broken", from the entry alone (no file is looked at).

    What `clients` counts; doctor checks the same and more (does the policy
    load, does the program exist). Monitor mode blocks nothing, so it is not
    protected. A proxy option written shortened, or --policy given twice,
    is broken: the proxy refuses the first, and a reader of the entry would
    take the wrong --policy for the one that counts. So is an entry whose
    launcher may run something else (launcher_problem), or whose "env" can
    change what starts as the proxy (env_redirects).
    """
    kind = kind_of(entry)
    if kind != "stdio":
        return kind
    words = command_line(entry) or []
    proxy = read_proxy_command(words)
    if proxy is None:
        return "broken" if mentions_proxy(words) else "unprotected"
    if any(shortened_option(option) for option, _ in proxy.options) or len(proxy.values("--policy")) > 1:
        return "broken"
    if launcher_problem(proxy) or env_redirects(entry, proxy):
        return "broken"
    return "unprotected" if proxy.has("--monitor") else "protected"


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
    entry had none. WrapError if the entry cannot be wrapped, or if the new
    entry would not read back as wrapped (doctor would call it broken, and
    wrap and unwrap would not know it).
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
    new = _with_command(entry, settings.python, proxy_args)
    found = proxy_command_of(new)
    if found is None or found.server != words or found.python_module() != (settings.python, settings.isolated):
        raise WrapError(f"the Python {printable(_program(settings.python), limit=60)!r} does not have a name "
                        "agent-sentinel reads back as a Python (python, pypy or graalpy, with or without a version), "
                        "so the wrapped entry would not be known as wrapped. Run wrap with a Python of such a name")
    redirects = env_redirects(new, found)
    if redirects:
        names = ", ".join(printable(name, limit=60) for name, _ in redirects[:10])
        raise WrapError(f"its \"env\" sets {names}; with that, {redirects[0][1]}, so the wrapped entry would not be "
                        "protected. Take such variables out of \"env\" first (the proxy's --env-file can give them "
                        "to the server alone)")
    return new


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
