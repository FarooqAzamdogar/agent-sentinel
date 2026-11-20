"""What a server's launch command runs, and what is risky about it. Functions of the command's words.

    commands_run       the commands a launch runs, looked at behind wrappers: cmd /c X,
                       env NAME=VALUE X, sh -c "X && Y", powershell -Command X (or
                       -EncodedCommand), sudo X, wsl X, exec X
    runner_packages    the packages runners (npx, bunx, pnpm dlx, yarn dlx, npm exec, uvx,
                       uv tool run, pipx run) fetch and run, behind such wrappers too
    runner_package     the first of them
    unpinned_package   such a package run without an exact version
    advisory_findings  a package of advisories.py: malware (fail) or a known vulnerability (warn)
    typosquat_of       a package one edit away from a popular MCP package's name
    launch_risks       what is risky in the command itself: inline code (sh -c, powershell
                       -EncodedCommand, node -e, python -c), shell operators in arguments, sudo,
                       a download piped to a runner, a package from a git repository, a container
                       with host privileges or mounts or without an image digest, and arguments
                       that name credential files, a whole drive or the whole home folder
    launch_identity    what proxy --pin-server pins of a launch (pins.py): the program, the runners'
                       packages as written, and the SHA-256 of the local script it starts

doctor (cli_doctor.launch_lines), clients, wrap and inspect report these;
none of them starts a program or touches the network. launch_identity reads
one local file, the script, which the proxy is about to start anyway.

Everything is bounded: MAX_WORDS_LINTED words of a command, MAX_LINTED_CHARS
characters of its text scanned by patterns (a longer command is reported as
such), MAX_WRAPPERS wrappers in a row and MAX_COMMANDS commands behind them.

Everything returned that holds text from a configuration is already
printable (textutil.printable).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import posixpath
import re
import shlex
from dataclasses import dataclass

from . import advisories, home
from .advisories import NPM, PYPI
from .templates import CREDENTIAL_PATTERN
from .textutil import printable

# How many words of one command are looked at, how many options after an interpreter (no real one has more),
# how many characters of its text the patterns read, and how many risks are reported for it.
MAX_WORDS_LINTED = 4096
MAX_OPTIONS_SCANNED = 64
MAX_LINTED_CHARS = 64 * 1024
MAX_RISKS = 12
# No program's path (and no path doctor compares) is longer than this; a longer word names neither.
MAX_PATH_CHARS = 4096

# ---- the program a word names -----------------------------------------------------------------

_ENDINGS = (".exe", ".cmd", ".bat", ".ps1", ".com")


def program_name(word: str) -> str:
    """The name of a program, lowercase, without its folder or a Windows ending: "C:\\x\\NPX.CMD" -> "npx"."""
    if len(word) > MAX_PATH_CHARS:
        return ""
    name = word.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():  # "C:npx": a drive's current folder
        name = name[2:]
    for ending in _ENDINGS:
        if name.endswith(ending):
            return name[: -len(ending)]
    return name


# The file name of a Python (as wrapping._PYTHON reads it), without an ending.
_PYTHON = re.compile(r"(python|pypy|graalpy)[0-9.]*t?w?(d|_d|-dbg)?(-intel64)?|pyw?")
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "mksh", "fish", "csh", "tcsh", "ash", "busybox"})
_POWERSHELL = frozenset({"powershell", "pwsh", "powershell_ise"})
_NODE = frozenset({"node", "nodejs", "bun"})
_ELEVATE = frozenset({"sudo", "doas", "runas", "pkexec", "gsudo"})
_CONTAINER = frozenset({"docker", "podman", "nerdctl"})

# ---- the commands behind a wrapper ------------------------------------------------------------

MAX_WRAPPERS = 4  # wrappers in a row that are looked behind: cmd /c env bash -c "exec npx ..."
MAX_LOOKED_BEHIND = 16  # wrappers looked behind in one launch, in all
MAX_COMMANDS = 16  # commands one launch is taken to run, at most
MAX_COMMAND_STRING_CHARS = 8192  # of a command string (sh -c "..."); the rest of it is not looked at
_OPERATOR_WORDS = frozenset({"&&", "||", ";", "|", "&"})
_OPERATORS_IN_TEXT = re.compile(r"&&|\|\||[;&|\r\n]")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_SPACE = re.compile(r"\s")
_ENV_VALUE_OPTIONS = frozenset({"-u", "--unset", "-C", "--chdir"})
_ELEVATE_VALUE_OPTIONS = frozenset({"-u", "--user", "-g", "--group", "-C", "--close-from", "-D", "--chdir", "-p",
                                    "--prompt", "-R", "--chroot", "-T", "--command-timeout", "-U", "--other-user",
                                    "-r", "--role", "-t", "--type"})
_GSUDO_VALUE_OPTIONS = frozenset({"-i", "--integrity", "-u", "--user"})
_WSL_VALUE_OPTIONS = frozenset({"-d", "--distribution", "-u", "--user", "--cd", "--distribution-id", "--shell-type"})


def commands_run(words: list[str]) -> list[list[str]]:
    """The commands a launch runs: [words] itself, or what wrappers in front of it run.

    `cmd /c "npx -y x"`, `env A=1 npx -y x`, `bash -c "cd /srv && exec npx -y x"`,
    `powershell -Command npx -y x` (or -EncodedCommand), `sudo npx -y x`,
    `wsl npx -y x`: each gives the npx command (and `cd /srv` for the third). A
    command string is split at shell operators and into words roughly as a
    shell would. At most MAX_COMMANDS commands, MAX_WRAPPERS wrappers deep.
    """
    found: list[list[str]] = []
    queue: list[tuple[list[str], int]] = [(words[:MAX_WORDS_LINTED], 0)]
    looked = 0
    while queue and len(found) < MAX_COMMANDS:
        command, depth = queue.pop(0)
        if depth:
            command = _without_assignments(command)
        if not command:
            continue
        inner = _behind(command) if depth < MAX_WRAPPERS and looked < MAX_LOOKED_BEHIND else None
        if inner is None:
            found.append(command)
            continue
        looked += 1
        queue.extend((each, depth + 1) for each in inner[:MAX_COMMANDS])
    return found


def _without_assignments(words: list[str]) -> list[str]:
    """A shell command without the NAME=VALUE words in front of its program."""
    index = 0
    while index < len(words) and index < MAX_OPTIONS_SCANNED and _ASSIGNMENT.match(words[index]):
        index += 1
    return words[index:]


def _behind(words: list[str]) -> list[list[str]] | None:
    """The commands a wrapper runs (empty when it runs none); None when `words` is no wrapper known here."""
    program = program_name(words[0])
    args = words[1:]
    if program == "cmd":
        return _behind_cmd(args)
    if program == "env":
        return _behind_env(args)
    if program in _SHELLS and program != "busybox":
        return _behind_shell(args)
    if program in _POWERSHELL:
        return _behind_powershell(program, args)
    if program in _ELEVATE:
        return _behind_elevation(program, args)
    if program == "wsl":
        return _behind_wsl(args)
    if program == "exec":
        index = _after_options(args, frozenset({"-a"}))
        return [args[index:]] if index < len(args) else []
    if program in ("call", "nohup"):
        return [args] if args else []
    return None


def _behind_cmd(args: list[str]) -> list[list[str]] | None:
    """cmd /c (or /k, /r) and what follows it, which cmd reads as one command line."""
    index = _option_index(args[:MAX_OPTIONS_SCANNED], _is_cmd_run, prefixes=("/",))
    if index is None:
        return None  # an interactive cmd
    rest = ([args[index][2:]] if len(args[index]) > 2 else []) + args[index + 1:]
    return _split_text(_joined(rest))


def _behind_env(args: list[str]) -> list[list[str]]:
    """env [options] [NAME=VALUE ...] COMMAND; env -S "COMMAND ..." splits the string into words."""
    index = 0
    while index < min(len(args), MAX_OPTIONS_SCANNED):
        word = args[index]
        name, equals, value = word.partition("=")
        if word == "--":
            index += 1
            break
        if name == "--split-string" or (word.startswith("-S") and not word.startswith("--")):
            if equals and name == "--split-string":
                text, after = value, index + 1
            elif len(word) > 2 and not name == "--split-string":
                text, after = word[2:], index + 1
            else:
                text, after = (args[index + 1] if index + 1 < len(args) else ""), index + 2
            command = shell_words(text[:MAX_COMMAND_STRING_CHARS]) + args[after:]
            return [command] if command else []
        if word.startswith("-"):
            index += 2 if word in _ENV_VALUE_OPTIONS else 1
        elif _ASSIGNMENT.match(word):
            index += 1
        else:
            break
    return [args[index:]] if index < len(args) else []


def _behind_shell(args: list[str]) -> list[list[str]] | None:
    """sh -c "COMMAND" (any -c cluster, after options such as -o errexit): the commands in the string."""
    options = args[:MAX_OPTIONS_SCANNED]
    index = _option_index(options, _is_c_cluster, prefixes=("-", "+"), takes_value=_shell_takes_value)
    if index is None:
        return None  # a script file, or an interactive shell
    after = index + 1
    while after < len(options) and options[after].startswith(("-", "+")) and options[after] not in ("-", "--"):
        after += 2 if _shell_takes_value(options[after]) else 1
    if after < len(args) and args[after] == "--":
        after += 1
    return _split_text(args[after]) if after < len(args) else []


def _behind_powershell(program: str, args: list[str]) -> list[list[str]] | None:
    """powershell -Command ... (or -EncodedCommand BASE64, or Windows PowerShell's plain first argument)."""
    found = _powershell_command(program, args[:MAX_OPTIONS_SCANNED])
    if found is None:
        return None
    index, kind = found
    if kind == "encoded":
        text = _decoded_powershell(args[index + 1]) if index + 1 < len(args) else None
        return _split_text(text) if text else []
    return _split_text(_joined(args[index if kind == "plain" else index + 1:]))


def _behind_elevation(program: str, args: list[str]) -> list[list[str]]:
    """sudo, doas, pkexec, gsudo: the command after their options; runas: its command string."""
    if program == "runas":
        index = 0
        while index < min(len(args), MAX_OPTIONS_SCANNED) and args[index].startswith("/"):
            index += 1
        return _split_text(args[index]) if index < len(args) else []
    index = _after_options(args, _GSUDO_VALUE_OPTIONS if program == "gsudo" else _ELEVATE_VALUE_OPTIONS)
    return [args[index:]] if index < len(args) else []


def _behind_wsl(args: list[str]) -> list[list[str]]:
    """wsl [options] COMMAND (run by the Linux shell), or wsl -e COMMAND (run directly)."""
    index = 0
    while index < min(len(args), MAX_OPTIONS_SCANNED):
        word = args[index]
        if word in ("-e", "--exec"):
            return [args[index + 1:]] if index + 1 < len(args) else []
        if word == "--":
            index += 1
            break
        if not word.startswith("-"):
            break
        index += 2 if word in _WSL_VALUE_OPTIONS else 1
    return _split_text(_joined(args[index:])) if index < len(args) else []


def _after_options(args: list[str], value_options: frozenset[str]) -> int:
    """Where a wrapper's own options end: the index of its first other word (after "--", if it has one)."""
    index = 0
    while index < len(args):
        if index >= MAX_OPTIONS_SCANNED:
            return len(args)
        word = args[index]
        if word == "--":
            return index + 1
        if not word.startswith("-") or word == "-":
            return index
        index += 2 if word in value_options else 1
    return index


def _joined(words: list[str]) -> str:
    """Words as one command line again (at most MAX_COMMAND_STRING_CHARS), for a wrapper that hands them to a shell.

    One word is the command line itself (cmd /c "npx -y x"); of several, a
    word with a space was one argument (cmd /c "C:\\Program Files\\x.cmd" -y).
    """
    if len(words) == 1:
        return words[0][:MAX_COMMAND_STRING_CHARS]
    pieces, length = [], 0
    for word in words:
        if length > MAX_COMMAND_STRING_CHARS:
            break
        word = word[:MAX_COMMAND_STRING_CHARS]
        piece = f'"{word}"' if (not word or _SPACE.search(word)) and '"' not in word else word
        pieces.append(piece)
        length += len(piece) + 1
    return " ".join(pieces)


def _split_text(text: str) -> list[list[str]]:
    """The commands of a command string: split at shell operators, each into words (roughly as a shell would)."""
    commands = []
    for part in _OPERATORS_IN_TEXT.split(text[:MAX_COMMAND_STRING_CHARS], maxsplit=MAX_COMMANDS):
        words = shell_words(part)
        if words:
            commands.append(words)
    return commands[:MAX_COMMANDS]


def shell_words(text: str) -> list[str]:
    """One command's words, its quotes taken away; a text with backslashes keeps them (Windows paths)."""
    lexer = shlex.shlex(text, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    if "\\" in text:
        lexer.escape = ""
    try:
        return list(lexer)
    except ValueError:  # an unclosed quote
        return text.split()


def _decoded_powershell(value: str) -> str | None:
    """The command an -EncodedCommand value holds (base64 of UTF-16LE text), or None."""
    if len(value) > MAX_COMMAND_STRING_CHARS * 3:
        value = value[: MAX_COMMAND_STRING_CHARS * 3 // 4 * 4]
    try:
        return base64.b64decode(value, validate=True).decode("utf-16-le", "replace")
    except (binascii.Error, ValueError):
        return None


# ---- packages a runner fetches ----------------------------------------------------------------

_EXACT_VERSION = re.compile(r"v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?")
# Where a PyPI package's name ends in a requirement such as "pkg>=1.0" or "pkg[extra]".
_PYPI_NAME_END = re.compile(r"[=<>~!@ \[;]")
_NPX_VALUE_OPTIONS = frozenset({"-p", "--package", "-c", "--call", "--cache", "--registry", "--userconfig", "-w",
                                "--workspace", "--node-options"})
_UVX_VALUE_OPTIONS = frozenset({
    "--from", "--with", "--with-editable", "--with-requirements", "-p", "--python", "--index", "--index-url",
    "--extra-index-url", "--default-index", "--find-links", "-f", "--constraint", "-c", "--override",
    "--python-preference", "--refresh-package", "--reinstall-package", "--upgrade-package", "--cache-dir",
    "--directory", "--project", "--config-file", "--env-file", "--index-strategy", "--keyring-provider",
    "--resolution", "--prerelease", "--exclude-newer", "--link-mode", "--compile-bytecode",
})
# uv's own options and those of `uv run` that take a value (for the script `uv run` starts).
_UV_VALUE_OPTIONS = _UVX_VALUE_OPTIONS | frozenset({
    "--color", "--allow-insecure-host", "--package", "--extra", "--no-extra", "--group", "--only-group", "--no-group",
})
_PIPX_VALUE_OPTIONS = frozenset({"--spec", "--python", "--index-url", "-i", "--pip-args", "--suffix"})
_GIT_SOURCES = ("git+", "git:", "github:", "gitlab:", "bitbucket:", "gist:")


@dataclass(frozen=True)
class PackageRef:
    """The package a runner fetches: as written (`spec`), its registry name and its exact version, if any."""

    runner: str  # "npx", "bunx", "npm exec", "pnpm dlx", "yarn dlx", "uvx", "uv tool run", "pipx run"
    ecosystem: str  # advisories.NPM or advisories.PYPI
    spec: str  # as written: "mcp-remote@0.1.16", "mcp-server-git==2026.1.14"
    name: str  # npm: lowercase; PyPI: normalised (PEP 503); "" when it is no registry package
    version: str | None  # the exact version the spec pins, if it pins one
    source: str  # "registry", "git", "url" or "path"

    @property
    def written(self) -> str:
        """The runner and the spec, as one text: "npx mcp-remote@0.1.16"."""
        return f"{self.runner} {self.spec}"


def runner_packages(words: list[str]) -> list[PackageRef]:
    """The packages the runners of a launch fetch and run (commands_run: behind wrappers too); each once."""
    found: list[PackageRef] = []
    for command in commands_run(words):
        ref = _direct_package(command)
        if ref is not None and ref not in found:
            found.append(ref)
    return found


def runner_package(words: list[str]) -> PackageRef | None:
    """The first package a runner of this launch runs (runner_packages); None when no runner runs one."""
    found = runner_packages(words)
    return found[0] if found else None


def _runner_of(words: list[str]) -> tuple[str, str, int] | None:
    """(runner, ecosystem, where its own arguments start) when `words` start a package runner; else None."""
    program = program_name(words[0])
    second = words[1:2]
    if program in ("npx", "bunx"):
        return program, NPM, 1
    if program == "pnpx":
        return "pnpm dlx", NPM, 1
    if program == "bun" and second == ["x"]:
        return "bunx", NPM, 2
    if program == "npm" and second in (["exec"], ["x"]):
        return "npm exec", NPM, 2
    if program in ("pnpm", "yarn") and second == ["dlx"]:
        return f"{program} dlx", NPM, 2
    if program == "uvx":
        return "uvx", PYPI, 1
    if program == "uv" and words[1:3] == ["tool", "run"]:
        return "uv tool run", PYPI, 3
    if program == "pipx" and second == ["run"]:
        return "pipx run", PYPI, 2
    return None


def _direct_package(words: list[str]) -> PackageRef | None:
    """The package of a runner that is the command's own program (not behind a wrapper)."""
    found = _runner_of(words) if words else None
    if found is None:
        return None
    runner, ecosystem, start = found
    if ecosystem == NPM:
        spec = _first_package(words[start:], _NPX_VALUE_OPTIONS, ("-p", "--package"))
        return _npm_ref(runner, spec) if spec else None
    if runner == "pipx run":
        spec = _first_package(words[start:], _PIPX_VALUE_OPTIONS, ("--spec",))
    else:
        spec = _first_package(words[start:], _UVX_VALUE_OPTIONS, ("--from",))
    return _pypi_ref(runner, spec) if spec else None


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


def _first_plain_index(args: list[str], value_options: frozenset[str]) -> int | None:
    """The index of a runner's first word that is not an option (the package, or with -p the program it runs)."""
    index = 0
    while index < len(args):
        word = args[index]
        if word == "--":
            return index + 1 if index + 1 < len(args) else None
        if not word.startswith("-"):
            return index
        index += 2 if "=" not in word and word in value_options else 1
    return None


def _npm_ref(runner: str, spec: str) -> PackageRef:
    """What an npm spec names. An alias ("npm:real@1.0.0", "alias@npm:real@1.0.0") names the real package."""
    written, lowered = spec, spec.lower()
    if lowered.startswith("npm:"):
        spec = spec[4:]
    else:
        at = spec.find("@", 1)
        if at != -1 and lowered[at + 1:].startswith("npm:"):
            spec = spec[at + 5:]
    lowered = spec.lower()
    if lowered.startswith(_GIT_SOURCES) or ("/" in spec and not spec.startswith("@") and ":" not in spec
                                            and not spec.startswith((".", "/", "~"))):
        return PackageRef(runner, NPM, written, "", None, "git")  # "user/repo" is a GitHub repository to npm
    if lowered.startswith(("http:", "https:")):
        return PackageRef(runner, NPM, written, "", None, "url")
    if spec.startswith((".", "/", "~")) or ":" in spec or "\\" in spec:
        return PackageRef(runner, NPM, written, "", None, "path")
    at = spec.find("@", 1)
    name = (spec if at == -1 else spec[:at]).lower()
    version = spec[at + 1:] if at != -1 and _EXACT_VERSION.fullmatch(spec[at + 1:]) else None
    return PackageRef(runner, NPM, written, name, version, "registry")


def _pypi_ref(runner: str, spec: str) -> PackageRef:
    lowered = spec.lower()
    if lowered.startswith("git+") or " @ git+" in lowered or "@git+" in lowered:
        return PackageRef(runner, PYPI, spec, "", None, "git")
    if "://" in spec:
        return PackageRef(runner, PYPI, spec, "", None, "url")
    if spec.startswith((".", "/", "~")) or "\\" in spec:
        return PackageRef(runner, PYPI, spec, "", None, "path")
    name = pypi_name(_PYPI_NAME_END.split(spec, maxsplit=1)[0])
    version = None
    if "==" in spec and _EXACT_VERSION.fullmatch(spec.split("==", 1)[1].strip()):
        version = spec.split("==", 1)[1].strip()
    elif "==" not in spec and "@" in spec and _EXACT_VERSION.fullmatch(spec.split("@", 1)[1].strip()):
        version = spec.split("@", 1)[1].strip()  # uv's "package@1.2.3"
    return PackageRef(runner, PYPI, spec, name, version, "registry")


def pypi_name(name: str) -> str:
    """A PyPI name as the index compares it (PEP 503): lowercase, each run of "-", "_" and "." one "-"."""
    return re.sub(r"[-_.]+", "-", name).lower()


def unpinned_package(words: list[str]) -> tuple[str, str] | None:
    """(package, how to pin it) for the first registry package of the launch run without an exact version."""
    for ref in runner_packages(words):
        found = unpinned_spec(ref)
        if found is not None:
            return found
    return None


def unpinned_spec(ref: PackageRef) -> tuple[str, str] | None:
    """(package, how to pin it) when a registry package is run without an exact version; else None."""
    if ref.source != "registry" or ref.version is not None:
        return None
    if ref.ecosystem == NPM:
        at = ref.spec.find("@", 1)
        return ref.spec, f"{ref.spec if at == -1 else ref.spec[:at]}@1.2.3"
    return ref.spec, _PYPI_NAME_END.split(ref.spec, maxsplit=1)[0] + "==1.2.3"


# ---- advisories and typosquats ----------------------------------------------------------------

_VERSION_PARTS = re.compile(r"v?([0-9]{1,18}(?:\.[0-9]{1,18}){0,7})(.*)", re.DOTALL)
_NOT_A_PRE_RELEASE = ("+", ".post", "-post", "post")


def _version_key(text: str, length: int) -> tuple[tuple[int, ...], int] | None:
    """A version as something to compare: its numbers (padded to `length`), then 0 for a pre-release, else 1."""
    found = _VERSION_PARTS.fullmatch(text.strip())
    if found is None:
        return None
    numbers = tuple(int(part) for part in found.group(1).split("."))
    rest = found.group(2)
    pre_release = bool(rest) and not rest.lower().startswith(_NOT_A_PRE_RELEASE)
    return numbers + (0,) * (length - len(numbers)), 0 if pre_release else 1


def version_before(version: str, bound: str) -> bool | None:
    """Whether `version` comes before `bound` (1.0.15 before 1.0.16, 1.0.16-rc.1 too); None when it cannot be read."""
    length = 8
    ours, theirs = _version_key(version, length), _version_key(bound, length)
    if ours is None or theirs is None:
        return None
    return ours < theirs


def _same_package(ref: PackageRef, advisory: advisories.Advisory) -> bool:
    wanted = advisory.name.lower() if advisory.ecosystem == NPM else pypi_name(advisory.name)
    return ref.source == "registry" and ref.ecosystem == advisory.ecosystem and ref.name == wanted


def advisory_findings(ref: PackageRef) -> list[tuple[str, str]]:
    """("fail" or "warn", what to say) for each advisory of advisories.py that concerns this package."""
    found = []
    shown = printable(ref.written, limit=200)
    for advisory in advisories.MALICIOUS:
        if not _same_package(ref, advisory):
            continue
        before = version_before(ref.version, advisory.first_bad) if ref.version else None
        if before:
            found.append(("warn", f"{shown}: {advisory.summary} ({advisory.ids}; {advisory.source}). This version "
                                  "is older than the malicious ones, but comes from the same place: remove it"))
        else:
            how = "is a malicious version" if ref.version else "does not pin an exact version, so it may fetch one"
            found.append(("fail", f"{shown} {how}: {advisory.summary} ({advisory.ids}; {advisory.source}). "
                                  "Remove this server, and treat what it could reach as exposed"))
    for advisory in advisories.VULNERABLE:
        if _same_package(ref, advisory) and ref.version and version_before(ref.version, advisory.fixed or ""):
            found.append(("warn", f"{shown} has a known vulnerability, fixed in {advisory.fixed}: {advisory.summary} "
                                  f"({advisory.ids}; {advisory.source}). Update it to {advisory.fixed} or later"))
    return found


def within_one_edit(one: str, other: str) -> bool:
    """Whether two different texts are one edit apart: a letter added, left out or changed, or two adjacent swapped."""
    if one == other or abs(len(one) - len(other)) > 1:
        return False
    if len(one) == len(other):
        differ = [index for index in range(len(one)) if one[index] != other[index]]
        if len(differ) == 1:
            return True
        return (len(differ) == 2 and differ[1] == differ[0] + 1
                and one[differ[0]] == other[differ[1]] and one[differ[1]] == other[differ[0]])
    shorter, longer = (one, other) if len(one) < len(other) else (other, one)
    index = 0
    while index < len(shorter) and shorter[index] == longer[index]:
        index += 1
    return shorter[index:] == longer[index + 1:]


def typosquat_of(ref: PackageRef) -> str | None:
    """The popular package (advisories.POPULAR) whose name this one imitates, one edit away; None otherwise."""
    if ref.source != "registry" or len(ref.name) < advisories.MIN_TYPOSQUAT_CHARS:
        return None
    popular = advisories.POPULAR.get(ref.ecosystem, ())
    if ref.name in popular or ref.name in advisories.LOOKALIKES_OK.get(ref.ecosystem, frozenset()):
        return None
    return next((name for name in popular if within_one_edit(ref.name, name)), None)


# ---- what is risky in the command itself --------------------------------------------------------

_SHELL_OPERATORS = ("&&", "||", ";", "|")
_ELEVATE_IN_TEXT = re.compile(r"(?:^|[\s;&|(`'\"])(sudo|doas|runas|pkexec|gsudo)(?:\.exe)?(?:\s|$)", re.IGNORECASE)
_DOWNLOADER = re.compile(r"\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|"
                         r"start-bitstransfer|certutil|bitsadmin)\b", re.IGNORECASE)
_RUNNER_AT_START = re.compile(r"\s*(?:sudo\s+)?(sh|bash|zsh|dash|ksh|fish|python[0-9.]*|py|node|perl|ruby|php|iex|"
                              r"invoke-expression|pwsh|powershell|cmd)\b", re.IGNORECASE)
_EVALUATOR = re.compile(r"\b(iex|invoke-expression)\b", re.IGNORECASE)
_SUBSHELL_DOWNLOAD = re.compile(r"(?:\$\(|<\(|`)\s*(curl|wget)\b", re.IGNORECASE)
_CREDENTIAL = re.compile(CREDENTIAL_PATTERN, re.IGNORECASE)
_DRIVE_ROOT = re.compile(r"[A-Za-z]:[\\/]?|[\\/]{1,2}|\\\\\?\\[A-Za-z]:\\?")
_DRIVE = re.compile(r"[A-Za-z]:")
# A word that names the home folder, at the start of a path: "~", "$HOME", "%USERPROFILE%", ...
_HOME_PREFIX = re.compile(r"(~|\$home|\$\{home\}|%userprofile%|%homepath%|\$env:userprofile)(?=[\\/]|\Z)",
                          re.IGNORECASE)
# The options of `docker run` (and podman's) that take a value, so that the image is found after them.
_CONTAINER_VALUE_OPTIONS = frozenset({
    "-v", "--volume", "-e", "--env", "--env-file", "-p", "--publish", "--name", "--network", "--net", "--mount",
    "-w", "--workdir", "-u", "--user", "--entrypoint", "--pid", "--ipc", "--uts", "--userns", "--cgroupns", "-l",
    "--label", "--label-file", "--cap-add", "--cap-drop", "--device", "--add-host", "--platform", "--pull",
    "--restart", "-m", "--memory", "--memory-swap", "--cpus", "--cpu-shares", "--cpuset-cpus", "-h", "--hostname",
    "--dns", "--dns-search", "--security-opt", "--tmpfs", "--ulimit", "--log-driver", "--log-opt", "--runtime",
    "--gpus", "--shm-size", "--stop-signal", "--stop-timeout", "--cidfile", "--volumes-from", "--expose", "--link",
    "--health-cmd", "--mac-address", "--ip", "--ip6", "-a", "--attach", "--group-add", "--isolation",
    "--network-alias", "--annotation", "--sysctl", "--device-cgroup-rule", "--storage-opt", "--domainname",
    # and the rarer ones
    "--pids-limit", "--cpu-period", "--cpu-quota", "--cpu-rt-period", "--cpu-rt-runtime", "--cpuset-mems",
    "--cpu-count", "--cpu-percent", "--blkio-weight", "--blkio-weight-device", "--device-read-bps",
    "--device-read-iops", "--device-write-bps", "--device-write-iops", "--io-maxbandwidth", "--io-maxiops",
    "--kernel-memory", "--memory-reservation", "--memory-swappiness", "--oom-score-adj", "--health-interval",
    "--health-retries", "--health-start-period", "--health-start-interval", "--health-timeout", "--cgroup-parent",
    "--dns-option", "--dns-opt", "--link-local-ip", "--detach-keys", "--volume-driver",
    # podman's
    "--pod", "--pod-id-file", "--arch", "--os", "--variant", "--authfile", "--cert-dir", "--creds", "--decryption-key",
    "--secret", "--tz", "--uidmap", "--gidmap", "--umask", "--unsetenv", "--timeout", "--systemd", "--sdnotify",
    "--seccomp-policy", "--requires", "--retry", "--retry-delay", "--personality", "--pidfile", "--preserve-fds",
    "--hosts-file", "--image-volume", "--init-path", "--chrootdirs", "--conmon-pidfile", "--group-entry",
    "--passwd-entry", "--subgidname", "--subuidname", "--rdt-class", "--env-merge", "--cgroups", "--cgroup-conf",
    "--hostuser",
})
# The options of `docker run` that take no value.
_CONTAINER_FLAGS = frozenset({
    "-d", "--detach", "-i", "--interactive", "-t", "--tty", "--rm", "--privileged", "--init", "-P", "--publish-all",
    "--read-only", "--sig-proxy", "--no-healthcheck", "--oom-kill-disable", "-q", "--quiet", "--disable-content-trust",
    "--help", "--use-api-socket", "--replace", "--rootfs", "--env-host", "--http-proxy", "--no-hosts",
    "--read-only-tmpfs", "--rmi", "--tls-verify", "--passwd",
})
# The options of docker, podman and nerdctl themselves (before "run") that take a value.
_CONTAINER_GLOBAL_VALUE_OPTIONS = frozenset({
    "--context", "-c", "-H", "--host", "--config", "-l", "--log-level", "--tlscacert", "--tlscert", "--tlskey",
    "--connection", "--url", "--identity", "--root", "--runroot", "--storage-driver", "--storage-opt",
    "--cgroup-manager", "--events-backend", "--module", "--network-cmd-path", "--network-config-dir", "--runtime",
    "--runtime-flag", "--tmpdir", "--hooks-dir", "--imagestore", "--registries-conf", "--ssh", "--volumepath",
    "--conmon", "--out", "-n", "--namespace", "-a", "--address", "--snapshotter", "--cni-path", "--cni-netconfpath",
    "--data-root", "--host-gateway-ip", "--hosts-dir",
})
_A_NUMBER = re.compile(r"[0-9][0-9.]*[A-Za-z%]{0,3}")


def launch_risks(words: list[str], user_home: str | None = None) -> list[str]:
    """What is risky about a launch command, each as a short printable phrase; empty when nothing is.

    `user_home`: the user's own folder, to recognise an argument that names
    it whole (default: this user's, from the environment).
    """
    words = words[:MAX_WORDS_LINTED]
    if not words:
        return []
    if user_home is None:
        folder = home.user_folder()
        user_home = str(folder) if folder is not None else None
    read, too_long = _read_part(words)
    commands = commands_run(words)
    risks: list[str] = []
    risks += _inline_code(words)
    risks += _shell_operators(words[1:])
    risks += _elevation(read)
    if _piped_download(" ".join(read)):
        risks.append("downloads something and runs it (a download piped to a shell or interpreter)")
    risks += _package_from_git(commands)
    for command in (words, *commands):
        risks += _container_risks(command, user_home)
    risks += _sensitive_arguments(read[1:], user_home)
    if too_long:
        risks.append(f"is longer than {MAX_LINTED_CHARS} characters, more than any real command line, so only its "
                     "start was checked for credential files, raised privileges and downloads")
    return list(dict.fromkeys(risks))[:MAX_RISKS]


def _read_part(words: list[str]) -> tuple[list[str], bool]:
    """The words whose text the patterns read: the first MAX_LINTED_CHARS characters; and whether that is not all."""
    read, left = [], MAX_LINTED_CHARS
    for word in words:
        if len(word) > left:
            read.append(word[:left])
            return read, True
        read.append(word)
        left -= len(word)
    return read, False


def _inline_code(words: list[str]) -> list[str]:
    """Interpreters given code on the command line: sh -c, cmd /c, powershell -Command, node -e, python -c."""
    found = []
    for index, word in enumerate(words):
        program = program_name(word)
        options = words[index + 1:index + 1 + MAX_OPTIONS_SCANNED]
        flag = None
        if program in _SHELLS:
            flag = _first_option(options, _is_c_cluster, prefixes=("-", "+"), takes_value=_shell_takes_value)
        elif program == "cmd":
            flag = _first_option(options, _is_cmd_run, prefixes=("/",))
        elif program in _POWERSHELL:
            command = _powershell_command(program, options)
            flag = options[command[0]] if command is not None else None
        elif program in _NODE:
            flag = _first_option(options, _is_node_eval, values=_NODE_VALUE_OPTIONS)
        elif program == "deno" and options[:1] == ["eval"]:
            flag = "eval"
        elif _PYTHON.fullmatch(program):
            flag = _first_option(options, lambda option: not option.startswith("--") and option[1:].isalpha()
                                 and "c" in option[1:], values=_PYTHON_VALUE_OPTIONS, stops=("-m",))
        if flag is not None:
            found.append(f"runs code written on the command line ({printable(program, limit=40)} "
                         f"{printable(flag, limit=40)})")
    return found


def _is_c_cluster(option: str) -> bool:
    """A shell's -c, alone or in a cluster of letters (-lc, -ec)."""
    return option.startswith("-") and not option.startswith("--") and option[1:].isalpha() and "c" in option[1:]


def _shell_takes_value(option: str) -> bool:
    """A shell option that takes the next word: --rcfile, --init-file, and -o, -O, +o, +O (also ending a cluster)."""
    return option in ("--rcfile", "--init-file") or (
        not option.startswith("--") and len(option) >= 2 and option[1:].isalpha() and option[-1] in "oO")


def _is_cmd_run(option: str) -> bool:
    return option[:2].lower() in ("/c", "/k", "/r")


_NODE_EVAL_CLUSTER = re.compile(r"-[cehipv]*[ep][cehipv]*")


def _is_node_eval(option: str) -> bool:
    """node's -e, --eval, -p, --print, or a cluster of its short options with one of them (-pe)."""
    return option.split("=", 1)[0] in ("-e", "--eval", "-p", "--print") or bool(_NODE_EVAL_CLUSTER.fullmatch(option))


def _option_index(options: list[str], wanted, prefixes: tuple[str, ...] = ("-",), values: tuple[str, ...] = (),
                  stops: tuple[str, ...] = (), takes_value=None) -> int | None:
    """The index of an interpreter's first option that `wanted` accepts, looked for before its first other word.

    `values` (or `takes_value`): the options that take the next word as their
    value; `stops`: options after which the rest belongs to something else (python -m).
    """
    index = 0
    while index < len(options):
        option = options[index]
        if not option.startswith(prefixes) or option in ("-", "--", "+"):
            return None
        if wanted(option):
            return index
        if option in stops:
            return None
        index += 2 if option in values or (takes_value is not None and takes_value(option)) else 1
    return None


def _first_option(options: list[str], wanted, **how) -> str | None:
    """The option _option_index finds, or None."""
    index = _option_index(options, wanted, **how)
    return None if index is None else options[index]


# PowerShell parameters that take a value, and the short names it also takes for them.
_POWERSHELL_VALUE_PARAMETERS = ("executionpolicy", "windowstyle", "version", "inputformat", "outputformat",
                                "psconsolefile", "configurationname", "configurationfile", "workingdirectory",
                                "settingsfile", "custompipename")
_POWERSHELL_VALUE_ALIASES = frozenset({"ep", "ex", "w", "v", "if", "of", "o", "wd"})


def _powershell_command(program: str, options: list[str]) -> tuple[int, str] | None:
    """Where a PowerShell command line gives code: (index, "command", "encoded" or "plain"), or None.

    -Command, -CommandWithArgs (or a shortening PowerShell takes for them:
    -c, -cwa, -co), -EncodedCommand (-e, -ec, -enc, ...). Windows PowerShell
    (powershell.exe) also runs its first plain argument as a command;
    PowerShell 7 (pwsh) runs it as a script file.
    """
    index = 0
    while index < len(options):
        option = options[index]
        if not option.startswith(("-", "/")):
            return (index, "plain") if program != "pwsh" and not option.lower().endswith(".ps1") else None
        name = option.lstrip("-/").lower().split(":", 1)[0]
        if name in ("e", "ec") or (len(name) >= 2 and "encodedcommand".startswith(name)):
            return index, "encoded"
        if name in ("c", "cwa") or (len(name) >= 2 and any(
                full.startswith(name) for full in ("command", "commandwithargs"))):
            return index, "command"
        if name in ("f", "file") or (len(name) >= 2 and "file".startswith(name)):
            return None
        takes_value = name in _POWERSHELL_VALUE_ALIASES or (
            len(name) >= 2 and any(full.startswith(name) for full in _POWERSHELL_VALUE_PARAMETERS))
        index += 2 if takes_value else 1
    return None


def _shell_operators(args: list[str]) -> list[str]:
    for arg in args:
        for operator in _SHELL_OPERATORS:
            if operator in arg:
                return [f"has the shell operator {operator!r} in an argument (a shell would run what follows it)"]
    return []


def _elevation(words: list[str]) -> list[str]:
    for word in words:
        program = program_name(word)
        found = program if program in _ELEVATE else None
        if found is None:
            match = _ELEVATE_IN_TEXT.search(word)
            found = match.group(1).lower() if match else None
        if found is not None:
            return [f"runs with raised privileges ({found})"]
    return []


def _piped_download(text: str) -> bool:
    """Whether a command downloads something and hands it to a runner: curl ... | sh, iex (iwr ...), $(curl ...).

    Split at each "|", so the check stays linear however long the text is.
    """
    parts = text.split("|")
    for left, right in zip(parts, parts[1:]):
        if _DOWNLOADER.search(left) and _RUNNER_AT_START.match(right):
            return True
    return bool((_EVALUATOR.search(text) and _DOWNLOADER.search(text)) or _SUBSHELL_DOWNLOAD.search(text))


def _package_from_git(commands: list[list[str]]) -> list[str]:
    for command in commands:
        ref = _direct_package(command)
        if ref is not None and ref.source in ("git", "url"):
            return [f"runs a package straight from a git repository or a web address, unreviewed and unpinned "
                    f"({printable(ref.written, limit=120)})"]
        if program_name(command[0]) in ("uvx", "uv", "pipx") and any(
                word[:4].lower() == "git+" for word in command[1:]):
            return ["installs a package straight from a git repository (git+...), unreviewed and unpinned"]
    return []


def _container_risks(words: list[str], user_home: str | None) -> list[str]:
    """docker/podman run with --privileged, the host's root or home folder mounted, host namespaces, no image digest."""
    for index, word in enumerate(words):
        if program_name(word) not in _CONTAINER:
            continue
        rest = _after_container_options(words[index + 1:])
        if rest[:1] == ["container"]:
            rest = rest[1:]
        if rest[:1] != ["run"]:
            return []
        return _run_options(rest[1:], user_home)
    return []


def _after_container_options(args: list[str]) -> list[str]:
    """What follows docker's (podman's, nerdctl's) own options: "--context x run ..." -> "run ..."."""
    index = 0
    while index < min(len(args), MAX_OPTIONS_SCANNED) and args[index].startswith("-") and args[index] != "--":
        index += 2 if args[index] in _CONTAINER_GLOBAL_VALUE_OPTIONS else 1
    return args[index:]


def _run_options(args: list[str], user_home: str | None) -> list[str]:
    risks, index, image = [], 0, None
    while index < len(args):
        word = args[index]
        if not word.startswith("-") or word == "--":
            image = args[index + 1] if word == "--" and index + 1 < len(args) else (None if word == "--" else word)
            break
        name, equals, value = word.partition("=")
        if not equals and name in _CONTAINER_VALUE_OPTIONS:
            value = args[index + 1] if index + 1 < len(args) else ""
            index += 1
        elif not equals and name[:2] == "-v" and len(name) > 2:  # -v/:/host
            name, value = "-v", name[2:]
        elif (not equals and name.startswith("--") and name not in _CONTAINER_FLAGS and index + 1 < len(args)
              and _only_a_value(args[index + 1])):
            index += 1  # an option not known here, followed by what can only be its value (no image looks so)
        index += 1
        if name == "--privileged" and value.lower() not in ("false", "0"):
            risks.append("runs a container with --privileged (it has the run of the host)")
        elif name in ("--network", "--net", "--pid", "--ipc", "--uts", "--userns") and value.lower() == "host":
            risks.append(f"shares the host's {name.lstrip('-')} with the container ({name} host)")
        elif name in ("-v", "--volume", "--mount"):
            source = _mount_source(value) if name == "--mount" else _volume_source(value)
            what = _whole_folder(source, user_home) if source else None
            if what:
                risks.append(f"mounts {what} into the container ({printable(name, limit=20)} "
                             f"{printable(value, limit=120)})")
    if image is not None and "@sha256:" not in image.lower():
        risks.append(f"runs the image {printable(image, limit=120)} by a tag, not pinned by digest (@sha256:...): a "
                     "new image can be pushed under the same tag")
    return risks


def _only_a_value(word: str) -> bool:
    """A word that is an option's value and never an image: a number or size, true/false, KEY=VALUE, a path."""
    return (bool(_A_NUMBER.fullmatch(word[:64])) or word.lower() in ("true", "false") or "=" in word
            or word.startswith(("/", "\\", "~", ".")))


def _volume_source(value: str) -> str:
    """The host side of a -v value: "/:/host" -> "/", "C:\\:/host" -> "C:\\"."""
    if re.match(r"[A-Za-z]:[\\/:]", value) or re.fullmatch(r"[A-Za-z]:", value):
        rest = value[2:]
        cut = rest.find(":")
        return value if cut == -1 else value[: 2 + cut]
    return value.split(":", 1)[0]


def _mount_source(value: str) -> str:
    """The host side of a --mount value: "type=bind,source=/,target=/host" -> "/"."""
    for part in value.split(","):
        key, _, found = part.partition("=")
        if key.strip().lower() in ("source", "src"):
            return found.strip()
    return ""


def _whole_folder(value: str, user_home: str | None) -> str | None:
    """"the whole drive" or "the whole home folder" when a path names one of them; None otherwise.

    Spellings that come to the same folder count too: "/.", "C:\\.", "$HOME/", "~/.".
    """
    text = value.strip().strip("\"'")
    if not text or len(text) > MAX_PATH_CHARS:
        return None
    if _is_drive_root(text):
        return "a whole drive (the root folder)"
    prefix = _HOME_PREFIX.match(text)
    if prefix and _goes_nowhere(text[prefix.end():]):
        return "the whole home folder"
    if user_home and (text.startswith("~") or home.is_absolute(text)):
        expanded = os.path.expanduser(text)
        if os.path.normcase(os.path.normpath(expanded)) == os.path.normcase(os.path.normpath(user_home)):
            return "the whole home folder"
    return None


def _is_drive_root(text: str) -> bool:
    """"/", "C:\\", "D:", and what comes to the same: "/.", "C:\\.", "/tmp/..". A share (\\\\server\\x) is none."""
    if _DRIVE_ROOT.fullmatch(text):
        return True
    if _DRIVE.match(text):
        text = text[2:]
        if not text[:1] in ("\\", "/"):
            return False
    slashed = text.replace("\\", "/")
    return slashed.startswith("/") and not slashed.startswith("//") and posixpath.normpath(slashed) == "/"


def _goes_nowhere(tail: str) -> bool:
    """Whether a path's rest after its folder stays in that folder: "", "/", "/.", "\\"."""
    return posixpath.normpath("/" + tail.replace("\\", "/").lstrip("/")) == "/"


def _sensitive_arguments(args: list[str], user_home: str | None) -> list[str]:
    found = []
    for arg in args:
        value = arg.split("=", 1)[1] if arg.startswith("-") and "=" in arg else arg
        if _CREDENTIAL.search(arg):
            found.append(f"names a credential or client configuration file in an argument "
                         f"({printable(arg, limit=120)})")
        whole = _whole_folder(value, user_home)
        if whole:
            found.append(f"gives the server {whole} in an argument ({printable(arg, limit=120)})")
    return found


# ---- what proxy --pin-server pins ----------------------------------------------------------------

LAUNCH_FIELDS = ("executable", "package", "script", "script_sha256")
# The largest script (or program) whose SHA-256 is taken; a larger one is pinned by its path only.
MAX_HASHED_BYTES = 64 * 1024 * 1024
# The longest text of the packages pinned as it is; a longer one is pinned as "sha256:<hex>" of it.
MAX_PINNED_PACKAGE_CHARS = 1024
_SCRIPT_RUNNERS = frozenset({"node", "nodejs", "bun", "deno", "ruby", "perl", "php", "bash", "sh", "zsh", "dash",
                             "ksh", "rscript", "lua", "tsx", "ts-node"})
# Packages that a runner fetches to start a local script: npx -y tsx@4 server.ts.
_SCRIPT_RUNNER_PACKAGES = frozenset({"tsx", "ts-node", "esno", "vite-node", "jiti", "node", "bun", "deno"})
_PYTHON_VALUE_OPTIONS = ("-X", "-W")
# Launchers whose own file says nothing of what runs: package runners (their package is pinned by its spec),
# shells given a command, and container runtimes (an image is pinned by its digest, which doctor checks).
_NOT_PINNED_BY_FILE = frozenset({"npx", "bunx", "pnpx", "uvx", "uv", "pipx", "cmd", "java", *_CONTAINER})
_NODE_VALUE_OPTIONS = ("-r", "--require", "--import", "--loader", "--experimental-loader", "--env-file",
                       "--conditions", "-C", "--title", "--inspect-port")
_SCRIPT_STOPS = ("-e", "--eval", "-p", "--print", "-c")


def launch_target(executable: str, words: list[str], cwd: str | None = None) -> str | None:
    """The local file a launch command runs: the script an interpreter is given, or else the program itself.

    Behind a wrapper (cmd /c node server.js, env, sh -c "exec ..."), the one
    command it runs; None when it runs several. A runner's package (npx,
    uvx) is pinned by its spec, so None for it, unless it runs a local script
    (npx -y tsx@4 server.ts); `uv run server.py` gives the script. None too for
    a Python started with -m or -c, and for inline code. A relative script is
    read against `cwd` (the proxy's current folder), as the interpreter will.
    """
    commands = commands_run(words)
    if len(commands) != 1:
        return None
    command = commands[0]
    found: str | None = executable
    if command != words[:MAX_WORDS_LINTED]:  # behind a wrapper: the wrapper finds the program, not the proxy
        found = command[0] if home.is_absolute(command[0]) else None
    return _target_of(found, command, cwd)


def _target_of(executable: str | None, words: list[str], cwd: str | None) -> str | None:
    program = program_name(words[0])
    args = words[1:MAX_WORDS_LINTED]
    base = cwd
    script: str | None
    if _runner_of(words) is not None:
        script = _runner_script(words)
    elif program == "uv":
        script, base = _uv_run_script(args, cwd)
    elif program in _NOT_PINNED_BY_FILE:
        return None
    elif _PYTHON.fullmatch(program):
        script = _first_plain_word(args, _PYTHON_VALUE_OPTIONS, stops=("-m", "-c"))
    elif program in _SCRIPT_RUNNERS:
        if program in ("deno", "bun") and args[:1] == ["run"]:
            args = args[1:]
        script = _first_plain_word(args, _NODE_VALUE_OPTIONS, stops=_SCRIPT_STOPS)
    elif program in _POWERSHELL:
        script = next((args[index + 1] for index in range(len(args) - 1)
                       if args[index].lstrip("-/").lower() in ("file", "f")), None)
    else:
        return os.path.abspath(executable) if executable else None
    if script is None:
        return None
    return os.path.abspath(os.path.join(base or os.getcwd(), os.path.expanduser(script)))


def _runner_script(words: list[str]) -> str | None:
    """The local script a runner's package starts: npx -y tsx@4 server.ts -> "server.ts"; else None."""
    ref = _direct_package(words)
    runner = _runner_of(words)
    if ref is None or runner is None or ref.source != "registry" or ref.name not in _SCRIPT_RUNNER_PACKAGES:
        return None
    args = words[runner[2]:MAX_WORDS_LINTED]
    index = _first_plain_index(args, _NPX_VALUE_OPTIONS if ref.ecosystem == NPM else _UVX_VALUE_OPTIONS)
    if index is None:
        return None
    rest = args[index + 1:]
    if ref.name in ("deno", "bun") and rest[:1] == ["run"]:
        rest = rest[1:]
    return _first_plain_word(rest, _NODE_VALUE_OPTIONS, stops=_SCRIPT_STOPS)


def _uv_run_script(args: list[str], cwd: str | None) -> tuple[str | None, str | None]:
    """(the script, the folder it is read against) of `uv [options] run [options] SCRIPT.py` (or `... run python S`)."""
    directory = None
    index = 0
    seen_run = False
    while index < len(args):
        word = args[index]
        if word == "--" and seen_run:
            index += 1
            break
        if not word.startswith("-"):
            if seen_run:
                break
            if word != "run":
                return None, None  # another uv command (uv tool run is a runner, see _runner_of)
            seen_run = True
            index += 1
            continue
        if word in ("-m", "--module"):
            return None, None
        name, equals, value = word.partition("=")
        takes_value = not equals and word in _UV_VALUE_OPTIONS
        if name == "--directory":
            directory = value if equals else (args[index + 1] if index + 1 < len(args) else None)
        index += 2 if takes_value else 1
    if not seen_run or index >= len(args):
        return None, None
    base = os.path.join(cwd or os.getcwd(), directory) if directory else cwd
    target = args[index]
    if _PYTHON.fullmatch(program_name(target)):
        return _first_plain_word(args[index + 1:], _PYTHON_VALUE_OPTIONS, stops=("-m", "-c")), base
    if target.lower().endswith((".py", ".pyw")):
        return target, base
    return None, None


def _first_plain_word(args: list[str], value_options: tuple[str, ...], stops: tuple[str, ...]) -> str | None:
    index = 0
    while index < len(args):
        word = args[index]
        if word in stops or word.split("=", 1)[0] in stops:
            return None
        if not word.startswith("-") or word == "-":
            return None if word == "-" else word
        index += 2 if word in value_options else 1
    return None


def file_sha256(path: str) -> str | None:
    """The SHA-256 of an ordinary file of at most MAX_HASHED_BYTES; None when it is not one, or cannot be read."""
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > MAX_HASHED_BYTES:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            read = 0
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                read += len(chunk)
                if read > MAX_HASHED_BYTES:  # it grew while it was read
                    return None
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, ValueError):
        return None


def launch_identity(executable: str, words: list[str], cwd: str | None = None) -> dict[str, str | None]:
    """What --pin-server pins of a launch (LAUNCH_FIELDS): the program found, the runners' packages as
    written (behind wrappers too, joined with "; "), and the local script with its SHA-256 (None for each
    that does not apply)."""
    packages = "; ".join(ref.written for ref in runner_packages(words)) or None
    if packages is not None and len(packages) > MAX_PINNED_PACKAGE_CHARS:
        packages = "sha256:" + hashlib.sha256(packages.encode("utf-8", "surrogatepass")).hexdigest()
    script = launch_target(executable, words, cwd)
    return {
        "executable": os.path.abspath(executable),
        "package": packages,
        "script": script,
        "script_sha256": file_sha256(script) if script else None,
    }
