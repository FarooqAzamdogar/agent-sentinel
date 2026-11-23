"""What a server's launch command runs, and what is risky about it. Functions of the command's words.

    commands_run       the commands a launch runs, looked at behind wrappers: cmd /c X
                       (also cmd /d/s/c X, and cmd's start), env NAME=VALUE X, sh -c
                       "X && Y", powershell -Command X (or -EncodedCommand, iex), sudo X,
                       wsl X, exec X, timeout N X, nice X, corepack X
    runner_packages    the packages runners (npx, bunx, pnpm dlx, yarn dlx, npm exec, uvx,
                       uv tool run, pipx run, deno run npm:, deno x) fetch and run, behind
                       such wrappers too: every npx -p, and the requirements of uvx --with
                       and uv run --with; an npm registry's package file address names its
                       package and version too
    runner_package     the first of them
    unpinned_package   such a package run without an exact version
    advisory_findings  a package of advisories.py: malware (fail) or a known vulnerability (warn)
    typosquat_of       a package one edit away from a popular MCP package's name
    launch_risks       what is risky in the command itself: inline code (sh -c, powershell
                       -EncodedCommand, node -e, python -c), shell operators in arguments, sudo,
                       a download piped to a runner, a package from a git repository, a container
                       with host privileges, the host's root or its container engine's socket
                       mounted, or without an image digest, and arguments
                       that name credential files, a whole drive or the whole home folder
    launch_identity    what proxy --pin-server pins of a launch (pins.py): the program, the runners'
                       packages as written (secrets masked), the SHA-256 of the local script it
                       starts, found past the interpreter's options as that interpreter reads them
                       (_ScriptOptions), and the SHA-256 of the whole command line; every file
                       that may be the script is pinned when an option in front of it is not
                       known here
    masked             a piece of a command with its secrets taken out, as every message here
                       quotes it and as a pin keeps it

doctor (cli_doctor.launch_lines), clients, wrap and inspect report these;
none of them starts a program or touches the network. launch_identity reads
local files only: the script, which the proxy is about to start anyway (for
a folder, the few files an interpreter runs for it).

Everything is bounded: MAX_WORDS_LINTED words of a command, MAX_LINTED_CHARS
characters of its text scanned by patterns, MAX_OPTIONS_SCANNED options in a
row, MAX_WRAPPERS wrappers in a row and MAX_COMMANDS commands behind them. A
command that goes past one of these bounds is reported as such by
launch_risks: only part of it was checked.

Everything returned that holds text from a configuration is already
printable (textutil.printable).
"""

from __future__ import annotations

import base64
import binascii
import contextvars
import hashlib
import json
import os
import posixpath
import re
import shlex
import string
from dataclasses import dataclass, replace

from . import advisories, home
from .advisories import NPM, PYPI
from .leaks import redact
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
# Of one piece of a command quoted in a message, this much is read for secrets before it is cut to fit.
MAX_QUOTED_CHARS = 4096

# ---- secrets in a command, and bounds that end a reading early --------------------------------

MASKED_CREDENTIAL = "[redacted credential]"
# What may stand before the "@" of an address: "user:password", or a token alone.
_USERINFO = re.compile(r"([^\s/?#@\\:]{0,256})(:[^\s/?#@\\]{0,512})?@")
_SCHEME_END = re.compile(r"[A-Za-z][A-Za-z0-9+.-]{0,30}\Z")


def masked(text: str) -> str:
    """A command's text with its secrets taken out, for a message and for a pin.

    The built-in secret formats become their markers (leaks.redact), and so
    does a credential written into an address (without_address_credentials).
    Masking the result again changes nothing.
    """
    return without_address_credentials(redact(text))


def without_address_credentials(text: str) -> str:
    """Text with the credentials written into its addresses replaced by MASKED_CREDENTIAL: the password of
    "https://user:password@host", and the token of "https://TOKEN@host" (the user of "ssh://git@host" is no
    secret, and is kept)."""
    at = text.find("://")
    if at == -1:
        return text
    pieces, start = [], 0
    while at != -1:
        found = _USERINFO.match(text, at + 3)
        if found is not None:
            user, password = found.group(1), found.group(2)
            scheme = _SCHEME_END.search(text, max(start, at - 31), at)
            over_ssh = scheme is not None and scheme.group().lower().endswith("ssh")
            if password:
                pieces += [text[start:found.start(2) + 1], MASKED_CREDENTIAL, "@"]
                start = found.end()
            elif user and not over_ssh:
                pieces += [text[start:found.start(1)], MASKED_CREDENTIAL, "@"]
                start = found.end()
        at = text.find("://", at + 3)
    pieces.append(text[start:])
    return "".join(pieces)


def _quoted(text: str, limit: int) -> str:
    """A piece of a command to quote in a message: its secrets masked, printable, at most `limit` characters."""
    return printable(masked(text[:MAX_QUOTED_CHARS]), limit=limit)


# While launch_risks reads a command, a bound that ends some reading before the command's end notes it here.
_CUTS: contextvars.ContextVar[list[bool] | None] = contextvars.ContextVar("agent_sentinel_launch_cuts", default=None)


def _cut_short() -> None:
    """Note that a bound ended the reading of a command early; launch_risks then says that only part was checked."""
    noted = _CUTS.get()
    if noted is not None and not noted:
        noted.append(True)


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
# Windows starts no program with a longer command line (CreateProcess), so cmd never reads further than this.
MAX_CMD_LINE_CHARS = 32_768
_OPERATOR_WORDS = frozenset({"&&", "||", ";", "|", "&"})
_OPERATORS_IN_TEXT = re.compile(r"&&|\|\||[;&|\r\n]")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_SPACE = re.compile(r"\s")
# cmd reads each "/" and the character after it as a switch; /C, /K or /R gives the command (also "/d/s/c").
_CMD_SWITCH = re.compile(r"/(.)", re.DOTALL)
_ENV_VALUE_OPTIONS = frozenset({"-u", "--unset", "-C", "--chdir", "-a", "--argv0", "-P"})
_ENV_VALUE_LETTERS = "uCaP"  # env's short options that take a value: the rest of their word, else the next word
_ELEVATE_VALUE_OPTIONS = frozenset({"-u", "--user", "-g", "--group", "-C", "--close-from", "-D", "--chdir", "-p",
                                    "--prompt", "-R", "--chroot", "-T", "--command-timeout", "-U", "--other-user",
                                    "-r", "--role", "-t", "--type"})
_GSUDO_VALUE_OPTIONS = frozenset({"-i", "--integrity", "-u", "--user"})
_WSL_VALUE_OPTIONS = frozenset({"-d", "--distribution", "-u", "--user", "--cd", "--distribution-id", "--shell-type"})
_START_VALUE_OPTIONS = frozenset({"/d", "/node", "/affinity"})
# Wrappers that run the rest of their words as one command: (their options that take a value, how many plain
# words they take before the command). timeout takes a duration first; corepack runs a package manager.
_SIMPLE_WRAPPERS: dict[str, tuple[frozenset[str], int]] = {
    "call": (frozenset(), 0),
    "nohup": (frozenset(), 0),
    "setsid": (frozenset(), 0),
    "nice": (frozenset({"-n", "--adjustment"}), 0),
    "stdbuf": (frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}), 0),
    "timeout": (frozenset({"-k", "--kill-after", "-s", "--signal"}), 1),
    "corepack": (frozenset(), 0),
}


def commands_run(words: list[str]) -> list[list[str]]:
    """The commands a launch runs: [words] itself, or what wrappers in front of it run.

    `cmd /c "npx -y x"`, `env A=1 npx -y x`, `bash -c "cd /srv && exec npx -y x"`,
    `powershell -Command npx -y x` (or -EncodedCommand), `sudo npx -y x`,
    `wsl npx -y x`, `timeout 60 npx -y x`: each gives the npx command (and
    `cd /srv` for the third). A command string is split at shell operators
    and into words roughly as a shell would. At most MAX_COMMANDS commands,
    MAX_WRAPPERS wrappers deep.
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
            if (depth >= MAX_WRAPPERS or looked >= MAX_LOOKED_BEHIND) and _is_wrapper(command[0]):
                _cut_short()  # a wrapper that was not looked behind
            found.append(command)
            continue
        looked += 1
        queue.extend((each, depth + 1) for each in inner[:MAX_COMMANDS])
    if queue:
        _cut_short()
    return found


def _is_wrapper(word: str) -> bool:
    """Whether a word names a program that _behind looks behind."""
    program = program_name(word)
    return (program in ("cmd", "env", "wsl", "exec", "start", "iex", "invoke-expression")
            or (program in _SHELLS and program != "busybox") or program in _POWERSHELL or program in _ELEVATE
            or program in _SIMPLE_WRAPPERS)


def _without_assignments(words: list[str]) -> list[str]:
    """A shell command without the NAME=VALUE words in front of its program."""
    index = 0
    while index < len(words) and index < MAX_OPTIONS_SCANNED and _ASSIGNMENT.match(words[index]):
        index += 1
    if MAX_OPTIONS_SCANNED <= index < len(words):
        _cut_short()
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
    if program == "start":
        return _behind_start(args)
    if program in ("iex", "invoke-expression"):  # PowerShell's own `sh -c`
        return _split_text(_joined(args[1:] if args[:1] and args[0].startswith("-") else args))
    if program in _SIMPLE_WRAPPERS:
        value_options, plain_words = _SIMPLE_WRAPPERS[program]
        index = _after_options(args, value_options) + plain_words
        if index >= len(args):
            return []
        if program == "corepack":  # corepack pnpm@9.0.0 dlx ...: the package manager, at a version
            return [[args[index].split("@", 1)[0], *args[index + 1:]]]
        return [args[index:]]
    return None


def _behind_cmd(args: list[str]) -> list[list[str]] | None:
    """cmd /c (or /k, /r) and what follows it, which cmd reads as one command line.

    cmd looks through its whole command line for the switch, so it is found
    after other text too (`cmd foo /c x`) and run together with other
    switches (`cmd /d/s/c x`, `cmd /cx`). A caret is cmd's escape: `n^px` is npx.
    """
    found = _cmd_run_at(args)
    if found is None:
        return None  # an interactive cmd
    index, start = found
    if len(args[index]) - start > MAX_COMMAND_STRING_CHARS:
        _cut_short()
    piece, rest = args[index][start:start + MAX_COMMAND_STRING_CHARS], args[index + 1:]
    if not piece.strip():
        text = _joined(rest)
    elif not rest:
        text = piece
    else:
        text = piece + " " + _quoted_words(rest)
    return _split_text(_without_carets(text))


def _cmd_run_at(args: list[str], switches_only: bool = False) -> tuple[int, int] | None:
    """Where cmd's /C, /K or /R is: (the index of its word, where the command starts in that word); else None.

    As cmd itself does: the first "/" followed by C, K or R anywhere in the
    command line, inside quotes too; the character after any other "/" is
    that switch's ("/t:0a/c" is /c, "//c" is none). `switches_only`: stop at
    the first word that is no switch (for a word "cmd" among other arguments).
    """
    left = MAX_CMD_LINE_CHARS
    for index, word in enumerate(args[:MAX_WORDS_LINTED]):
        if left <= 0 or (switches_only and not word.startswith("/")):
            return None
        for match in _CMD_SWITCH.finditer(word, 0, left):
            if match.group(1) in "cCkKrR":
                return index, match.end()
        left -= len(word) + 1
    return None


def _without_carets(text: str) -> str:
    """A cmd command line with its escapes taken away: outside double quotes, "^" makes the next character plain."""
    if "^" not in text:
        return text
    kept, quoted, index = [], False, 0
    while index < len(text):
        char = text[index]
        if char == "^" and not quoted:
            index += 1
            char = text[index] if index < len(text) else ""
        elif char == '"':
            quoted = not quoted
        kept.append(char)
        index += 1
    return "".join(kept)


def _behind_start(args: list[str]) -> list[list[str]]:
    """cmd's start ["title"] [/options] COMMAND. Its quotes are gone by now, so a first plain word may be the title
    or the program: both readings are given (`start "" npx -y x`, `start /b /wait npx -y x`)."""
    found: list[list[str]] = []
    readings = (1,) if args[:1] == [""] else (0, 1) if args and not args[0].startswith("/") else (0,)
    for skip in readings:
        index = skip
        while index < min(len(args), MAX_OPTIONS_SCANNED) and args[index].startswith("/"):
            index += 2 if args[index].lower() in _START_VALUE_OPTIONS else 1
        if MAX_OPTIONS_SCANNED <= index < len(args):
            _cut_short()
        if index < len(args) and args[index:] not in found:
            found.append(args[index:])
    return found


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
            if len(text) > MAX_COMMAND_STRING_CHARS:
                _cut_short()
            command = shell_words(text[:MAX_COMMAND_STRING_CHARS]) + args[after:]
            return [command] if command else []
        if word.startswith("-"):
            index += 2 if word in _ENV_VALUE_OPTIONS or _env_cluster_takes_next(word) else 1
        elif _ASSIGNMENT.match(word):
            index += 1
        else:
            break
    if MAX_OPTIONS_SCANNED <= index < len(args):
        _cut_short()
    return [args[index:]] if index < len(args) else []


def _env_cluster_takes_next(word: str) -> bool:
    """Whether a cluster of env's short options ends in one that takes the next word: "-iu NAME", "-iC DIR"
    ("-uNAME" carries its value)."""
    return (not word.startswith("--") and len(word) > 2 and word[-1] in _ENV_VALUE_LETTERS
            and not any(letter in _ENV_VALUE_LETTERS for letter in word[1:-1]))


def _behind_shell(args: list[str]) -> list[list[str]] | None:
    """sh -c "COMMAND" (any -c cluster, after options such as -o errexit): the commands in the string."""
    options = args[:MAX_OPTIONS_SCANNED]
    index = _option_index(options, _is_c_cluster, prefixes=("-", "+"), takes_value=_shell_takes_value)
    if index is None:
        return None  # a script file, or an interactive shell
    after = index + 1
    while after < len(options) and options[after].startswith(("-", "+")) and options[after] not in ("-", "--"):
        after += 2 if _shell_takes_value(options[after]) else 1
    if MAX_OPTIONS_SCANNED <= after < len(args):
        _cut_short()
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
        if MAX_OPTIONS_SCANNED <= index < len(args):
            _cut_short()
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
    if MAX_OPTIONS_SCANNED <= index < len(args):
        _cut_short()
    return _split_text(_joined(args[index:])) if index < len(args) else []


def _after_options(args: list[str], value_options: frozenset[str]) -> int:
    """Where a wrapper's own options end: the index of its first other word (after "--", if it has one)."""
    index = 0
    while index < len(args):
        if index >= MAX_OPTIONS_SCANNED:
            _cut_short()
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
        if len(words[0]) > MAX_COMMAND_STRING_CHARS:
            _cut_short()
        return words[0][:MAX_COMMAND_STRING_CHARS]
    return _quoted_words(words)


def _quoted_words(words: list[str]) -> str:
    """Words as one command line, a word with a space quoted (at most about MAX_COMMAND_STRING_CHARS)."""
    pieces, length = [], 0
    for word in words:
        if length > MAX_COMMAND_STRING_CHARS or len(word) > MAX_COMMAND_STRING_CHARS:
            _cut_short()
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
    parts = _OPERATORS_IN_TEXT.split(text[:MAX_COMMAND_STRING_CHARS], maxsplit=MAX_COMMANDS)
    if len(text) > MAX_COMMAND_STRING_CHARS or len(parts) > MAX_COMMANDS:
        _cut_short()
    for part in parts:
        words = shell_words(_ungrouped(part))
        if words:
            commands.append(words)
    return commands[:MAX_COMMANDS]


def _ungrouped(part: str) -> str:
    """One command of a command string without the grouping around it: "{ npx -y x" (of "{ npx -y x; }"),
    "(npx -y x)", PowerShell's "& {npx -y x}" (split at "&" already) and ". {npx -y x}" (dot-sourcing)."""
    text = part.lstrip()
    if text[:2] in (". ", ".\t"):  # sh's `. FILE` and PowerShell's dot-sourcing
        text = text[1:].lstrip()
    opened = text.lstrip("({ \t")
    return opened.rstrip(")} \t") if len(opened) != len(text) else text


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
        _cut_short()
        value = value[: MAX_COMMAND_STRING_CHARS * 3 // 4 * 4]
    try:
        return base64.b64decode(value, validate=True).decode("utf-16-le", "replace")
    except (binascii.Error, ValueError):
        return None


# ---- packages a runner fetches ----------------------------------------------------------------

_EXACT_VERSION = re.compile(r"v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?")
# Where a PyPI package's name ends in a requirement such as "pkg>=1.0" or "pkg[extra]".
_PYPI_NAME_END = re.compile(r"[=<>~!@ \[;]")
_NPX_VALUE_OPTIONS = frozenset({
    "-p", "--package", "-c", "--call", "--cache", "--registry", "--userconfig", "-w", "--workspace", "--node-options",
    # npm's own settings that take a value, which npx and npm exec take too
    "--prefix", "--loglevel", "--tag", "--location", "--script-shell", "--globalconfig", "--otp", "--before",
    "--cafile", "--proxy", "--https-proxy", "--noproxy", "--scope", "--fetch-retries", "--fetch-timeout",
    "--maxsockets", "--local-address", "--user-agent", "--shell",
    # pnpm's, yarn's and bun's
    "--cwd", "--dir", "-C", "--reporter", "--allow-build", "--filter",
})
# What pnpm dlx and yarn dlx read otherwise: their -c is --shell-mode, a flag, and they have no --workspace NAME.
_NOT_DLX_VALUE_OPTIONS = frozenset({"-c", "--call", "-w", "--workspace"})
# The options of these runners that take no value. An option that is in neither list is not known here: the
# word after it may be its value or the package (_runner_words).
_NPX_FLAGS = frozenset({
    "-y", "--yes", "--no", "-q", "--quiet", "-s", "--silent", "-d", "-dd", "-ddd", "--verbose", "--no-install",
    "--ignore-existing", "--prefer-online", "--prefer-offline", "--offline", "--json", "--workspaces", "-ws",
    "--include-workspace-root", "--ignore-scripts", "--foreground-scripts", "--no-audit", "--no-fund",
    "--no-update-notifier", "--no-progress", "--legacy-peer-deps", "--force", "-f", "--global", "-g", "--no-color",
    "--unicode", "--no-unicode", "--bun", "--shell-mode", "-c", "--help", "-h", "--version", "-v",
})
# The programs whose own options may hand a string to a shell (_runner_code_option).
_RUNNER_PROGRAMS = frozenset({"npx", "bunx", "pnpx", "npm", "pnpm", "yarn"})
_UVX_FLAGS = frozenset({
    "-q", "--quiet", "-qq", "-v", "--verbose", "-vv", "-n", "--no-cache", "--offline", "--no-progress",
    "--native-tls", "--no-native-tls", "--system-certs", "--no-config", "--no-python-downloads",
    "--allow-python-downloads", "--managed-python", "--no-managed-python", "--refresh", "-U", "--upgrade",
    "--reinstall", "--force-reinstall", "--no-index", "--no-build", "--no-binary", "--no-build-isolation",
    "--compile-bytecode", "--no-compile-bytecode", "--no-sources", "--no-env-file", "--isolated",
    "--show-resolution", "--lfs", "--no-color", "--preview", "--no-preview", "--no-installer-metadata", "--help",
    "-h", "--version", "-V",
})
_UV_RUN_FLAGS = _UVX_FLAGS | frozenset({
    "--no-sync", "--frozen", "--locked", "--no-project", "--exact", "--inexact", "--no-dev", "--dev", "--only-dev",
    "--all-extras", "--all-groups", "--all-packages", "--no-default-groups", "--script", "-s", "--gui-script",
    "--active", "--no-active", "--no-editable", "--no-install-project", "--no-install-workspace", "-m", "--module",
})
_PIPX_FLAGS = frozenset({"--no-cache", "--pypackages", "--verbose", "-v", "--quiet", "-q", "--system-site-packages",
                         "--path", "--global", "--help", "-h"})
_UVX_VALUE_OPTIONS = frozenset({
    "--from", "--with", "-w", "--with-editable", "--with-requirements", "-p", "--python", "--index", "--index-url",
    "-i", "--extra-index-url", "--default-index", "--find-links", "-f", "--constraint", "--constraints", "-c",
    "--override", "--overrides", "--build-constraint", "--build-constraints", "-b", "--python-preference",
    "--refresh-package", "--reinstall-package", "--upgrade-package", "-P", "--cache-dir", "--directory", "--project",
    "--config-file", "--env-file", "--index-strategy", "--keyring-provider", "--resolution", "--prerelease",
    "--exclude-newer", "--exclude-newer-package", "--link-mode", "-C", "--config-setting", "--config-settings-package",
    "--no-binary-package", "--no-build-package", "--python-platform", "--torch-backend", "--fork-strategy",
    "--with-executables-from", "--color", "--allow-insecure-host",
})
# uv's own options and those of `uv run` that take a value (for the script `uv run` starts).
_UV_VALUE_OPTIONS = _UVX_VALUE_OPTIONS | frozenset({
    "--package", "--extra", "--no-extra", "--group", "--only-group", "--no-group",
})
_PIPX_VALUE_OPTIONS = frozenset({"--spec", "--python", "--index-url", "-i", "--pip-args", "--suffix"})
_GIT_SOURCES = ("git+", "git:", "github:", "gitlab:", "bitbucket:", "gist:")
# A git address in scp's form, which npm takes for a repository: "git@github.com:user/repo.git".
_SCP_ADDRESS = re.compile(r"[A-Za-z0-9._~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+:")
_PACKAGE_OPTIONS = ("-p", "--package")  # npx, npm exec, pnpm dlx, yarn dlx: each one names a package to fetch
_WITH_OPTIONS = ("--with", "-w")  # uvx, uv tool run: requirements installed beside the package
_A_VERSION_NEXT = re.compile(r"\s*[!=<>~]")  # after a comma in "pkg>=1,<2": the version goes on
# The package managers whose subcommand runs a package: (its names, the runner it is, its ecosystem).
# "exe" is npm's own abbreviation of exec (npm 11 still takes it).
_SUBCOMMAND_RUNNERS: dict[str, tuple[tuple[str, ...], str, str]] = {
    "npm": (("exec", "exe", "x"), "npm exec", NPM),
    "pnpm": (("dlx",), "pnpm dlx", NPM),
    "yarn": (("dlx",), "yarn dlx", NPM),
    "bun": (("x",), "bunx", NPM),
    "pipx": (("run",), "pipx run", PYPI),
}


JSR = "jsr"  # the JavaScript registry deno fetches "jsr:@scope/name" from (no advisories.py entries)


@dataclass(frozen=True)
class PackageRef:
    """The package a runner fetches: as written (`spec`), its registry name and its exact version, if any."""

    # "npx", "bunx", "npm exec", "pnpm dlx", "yarn dlx", "uvx", "uv tool run", "uv run", "pipx run", "deno run",
    # "deno x"
    runner: str
    ecosystem: str  # advisories.NPM, advisories.PYPI or JSR
    spec: str  # as written: "mcp-remote@0.1.16", "mcp-server-git==2026.1.14", "npm:postmark-mcp@1.0.16"
    # npm: lowercase; PyPI: normalised (PEP 503); "" when it names no registry package (a registry's own
    # package file address, https://registry.npmjs.org/NAME/-/NAME-VERSION.tgz, names one)
    name: str
    version: str | None  # the exact version the spec pins, if it pins one
    source: str  # "registry", "git", "url" or "path"
    role: str = "run"  # "run": a package the runner runs; "with": a requirement beside it (uvx --with)
    # Whether the word may be something else: an option in front of it is not known here, so it may be that
    # option's value, or an argument of the package that is (_runner_words).
    unsure: bool = False
    # Without an exact version: the highest version the spec can fetch, when the spec bounds it ("<0.1.16",
    # "0.1.15 || 0.1.14", "~=2025.1.0"): (its numbers, whether that version itself can be fetched).
    highest: tuple[tuple[int, ...], bool] | None = None

    @property
    def written(self) -> str:
        """The runner and the spec, as one text: "npx mcp-remote@0.1.16" ("uvx --with x==1.0" for a requirement)."""
        return f"{self.runner} --with {self.spec}" if self.role == "with" else f"{self.runner} {self.spec}"


def runner_packages(words: list[str]) -> list[PackageRef]:
    """The packages the runners of a launch fetch and run (commands_run: behind wrappers too); each once.

    Every package a runner is given counts: each `npx -p`, and the
    requirements of `uvx --with` and `uv run --with` (role "with"). deno
    fetches what `deno run npm:pkg@1.0.0` (or jsr:, or a web address) and
    `deno x pkg` name.
    """
    found: list[PackageRef] = []
    for command in commands_run(words):
        for ref in _direct_packages(command):
            if ref not in found:
                found.append(ref)
    return found


def runner_package(words: list[str]) -> PackageRef | None:
    """The first package a runner of this launch runs (runner_packages); None when no runner runs one."""
    found = runner_packages(words)
    return found[0] if found else None


def _runner_of(words: list[str]) -> tuple[str, str, int] | None:
    """(runner, ecosystem, where its own arguments start) when `words` start a package runner; else None.

    The subcommand is found after the program's own options too:
    `npm --yes exec`, `pnpm --silent dlx`, `uv --quiet tool run`. `uv run`
    runs a command of the project's, and fetches only its --with requirements.
    deno is read by _deno_packages.
    """
    program = program_name(words[0])
    if program in ("npx", "bunx"):
        return program, NPM, 1
    if program == "pnpx":
        return "pnpm dlx", NPM, 1
    if program == "uvx":
        return "uvx", PYPI, 1
    if program in _SUBCOMMAND_RUNNERS:
        names, runner, ecosystem = _SUBCOMMAND_RUNNERS[program]
        at = _subcommand_at(words, 1, names)
        return (runner, ecosystem, at + 1) if at is not None else None
    if program == "uv":
        at = _subcommand_at(words, 1, ("tool", "run"))
        if at is not None and words[at] == "run":
            return "uv run", PYPI, at + 1
        at = _subcommand_at(words, at + 1, ("run", "uvx")) if at is not None else None
        return ("uv tool run", PYPI, at + 1) if at is not None else None
    return None


def _subcommand_at(words: list[str], start: int, names: tuple[str, ...]) -> int | None:
    """Where a program's subcommand is (one of `names`), after the program's own options; None for another one.

    An option's value cannot always be told from a flag here (`npm --prefix
    /x exec`, but `npm --yes exec`), so a plain word right after an option is
    passed over as its possible value.
    """
    index, value_possible = start, False
    while index < min(len(words), start + MAX_OPTIONS_SCANNED):
        word = words[index]
        if word in names:
            return index
        if word == "--":
            return index + 1 if words[index + 1:index + 2] and words[index + 1] in names else None
        if word.startswith("-") and word != "-":
            value_possible = "=" not in word
        elif value_possible:
            value_possible = False
        else:
            return None
        index += 1
    if index < len(words):
        _cut_short()
    return None


def _direct_packages(words: list[str]) -> list[PackageRef]:
    """The packages of a runner that is the command's own program (not behind a wrapper)."""
    if words and program_name(words[0]) == "deno":
        return _deno_packages(words)
    found = _runner_of(words) if words else None
    if found is None:
        return []
    runner, ecosystem, start = found
    args = words[start:MAX_WORDS_LINTED]
    if ecosystem == NPM:
        return [replace(_npm_ref(runner, spec), unsure=unsure)
                for spec, unsure in _runner_specs(args, _npx_value_options(runner), _NPX_FLAGS, _PACKAGE_OPTIONS)]
    if runner == "pipx run":
        return [replace(_pypi_ref(runner, spec), unsure=unsure)
                for spec, unsure in _runner_specs(args, _PIPX_VALUE_OPTIONS, _PIPX_FLAGS, ("--spec",))]
    refs = []
    if runner != "uv run":  # uv run's command is the project's own (its script is pinned, see _uv_run_script)
        refs = [replace(_pypi_ref(runner, spec), unsure=unsure)
                for spec, unsure in _runner_specs(args, _UVX_VALUE_OPTIONS, _UVX_FLAGS, ("--from",))]
    value_options = _UV_VALUE_OPTIONS if runner == "uv run" else _UVX_VALUE_OPTIONS
    flags = _UV_RUN_FLAGS if runner == "uv run" else _UVX_FLAGS
    for value, sure in _option_values(args, value_options, flags, _WITH_OPTIONS):
        refs += [replace(_pypi_ref(runner, spec, role="with"), unsure=not sure) for spec in _requirements(value)]
    return refs


def _npx_value_options(runner: str) -> frozenset[str]:
    """The options that take a value for npx, npm exec and bunx, or as pnpm dlx and yarn dlx read them."""
    return _NPX_VALUE_OPTIONS - _NOT_DLX_VALUE_OPTIONS if runner in ("pnpm dlx", "yarn dlx") else _NPX_VALUE_OPTIONS


def _deno_packages(words: list[str]) -> list[PackageRef]:
    """What deno fetches and runs: `deno run -A npm:pkg@1.0.0` (or `deno serve`, or `deno npm:...` for short;
    also jsr: and a web address), and the package of `deno x pkg` (npm's when it names no registry)."""
    args = words[1:MAX_WORDS_LINTED]
    at = _first_plain_at(args, _DENO_OPTIONS)
    if at is not None and args[at] == "x":
        specs, runner = _script_words(args[at + 1:], _DENO_OPTIONS)[:1], "deno x"
    else:
        specs, runner = _subcommand_scripts("deno", args), "deno run"
    refs = []
    for spec in specs:
        lowered = spec.lower()
        if lowered.startswith(("http:", "https:")):
            refs.append(_npm_ref(runner, spec))  # a web address: run unreviewed (a registry's file names its package)
        elif lowered.startswith("jsr:"):
            refs.append(_jsr_ref(runner, spec))
        elif lowered.startswith("npm:") or runner == "deno x":
            refs.append(replace(_npm_ref(runner, _without_subpath(spec)), spec=spec))
    return refs


def _without_subpath(spec: str) -> str:
    """An npm or JSR spec without the file inside the package deno may name: "npm:preact@10/hooks" -> "npm:preact@10"."""
    prefix = spec[:4] if spec[:4].lower() in ("npm:", "jsr:") else ""
    if not prefix:
        return spec  # no registry named: read as npx reads it ("user/repo" is a repository)
    parts = spec[len(prefix):].split("/")
    kept = 2 if parts[0].startswith("@") else 1
    return prefix + "/".join(parts[:kept])


def _jsr_ref(runner: str, spec: str) -> PackageRef:
    """What a JSR spec names: "jsr:@std/http@1.0.0/file-server" -> @std/http, version 1.0.0."""
    body = _without_subpath(spec)[4:]
    at = body.find("@", 1)
    name = (body if at == -1 else body[:at]).lower()
    version = body[at + 1:] if at != -1 and _EXACT_VERSION.fullmatch(body[at + 1:]) else None
    return PackageRef(runner, JSR, spec, name, version, "registry")


def _runner_words(args: list[str], value_options: frozenset[str], flags: frozenset[str]
                  ) -> tuple[list[tuple[str, str | None, bool]], list[int], bool]:
    """A runner's own options, and where the words are that may be its package:
    ([(option, its value or None, whether it is surely the runner's own)], [index, ...], whether the package
    is in doubt).

    The package is the runner's first word that is no option. An option in
    neither `value_options` nor `flags` is not known here: it may take the
    next word as its value (npx --some-option VALUE pkg) or take none (npx
    --some-flag pkg), which cannot be told from the words. So the plain word
    after such an option is taken and the reading goes on to the next plain
    word: the package is one of the words taken (at most
    MAX_SCRIPT_CANDIDATES), and an option read after the first of them may
    be the package's own.
    """
    options: list[tuple[str, str | None, bool]] = []
    plain: list[int] = []
    index, maybe_value, in_doubt = 0, False, False
    while index < len(args):
        word = args[index]
        if word == "--":
            if index + 1 < len(args):
                plain.append(index + 1)
            break
        if not word.startswith("-"):
            plain.append(index)
            in_doubt = in_doubt or maybe_value
            if not maybe_value or len(plain) >= MAX_SCRIPT_CANDIDATES:
                break
            maybe_value = False
            index += 1
            continue
        name, equals, value = word.partition("=")
        if equals:
            options.append((name, value, not plain))
            maybe_value = False
        elif word in value_options:
            options.append((word, args[index + 1] if index + 1 < len(args) else None, not plain))
            maybe_value = False
            index += 1
        else:
            options.append((word, None, not plain))
            maybe_value = word not in flags and word != "-"
        index += 1
    return options, plain, in_doubt


def _runner_specs(args: list[str], value_options: frozenset[str], flags: frozenset[str],
                  package_options: tuple[str, ...]) -> list[tuple[str, bool]]:
    """The packages a runner runs, each with whether it is unsure (PackageRef.unsure): every value of its
    --package (--from, --spec), or else its first plain word (see _runner_words for the words taken when an
    option in front of it is not known here)."""
    options, plain, in_doubt = _runner_words(args, value_options | frozenset(package_options), flags)
    named = [(value, sure) for name, value, sure in options if name in package_options and value]
    if len(named) > MAX_COMMANDS:
        _cut_short()
    specs = [(value, not sure) for value, sure in named[:MAX_COMMANDS]]
    if not any(sure for _, sure in named):  # no --package for sure: a plain word is the package
        specs += [(args[index], in_doubt) for index in plain]
    return specs


def _option_values(args: list[str], value_options: frozenset[str], flags: frozenset[str],
                   wanted: tuple[str, ...]) -> list[tuple[str, bool]]:
    """Every value given to the `wanted` options among a runner's own options, each with whether the option is
    surely the runner's own (it stands before the first plain word: _runner_words)."""
    options, _, _ = _runner_words(args, value_options | frozenset(wanted), flags)
    found = [(value, sure) for name, value, sure in options if name in wanted and value]
    if len(found) > MAX_COMMANDS:
        _cut_short()
    return found[:MAX_COMMANDS]


def _requirements(value: str) -> list[str]:
    """The requirements of one --with value, as uv splits it: at commas outside brackets that start no version
    ("a,b[x,y]>=1,<2" is "a" and "b[x,y]>=1,<2")."""
    found, depth, start = [], 0, 0
    if len(value) > MAX_COMMAND_STRING_CHARS:
        _cut_short()
    text = value[:MAX_COMMAND_STRING_CHARS]
    for index, char in enumerate(text):
        if char == "[":
            depth += 1
        elif char == "]":
            depth = max(depth - 1, 0)
        elif char == "," and depth == 0 and not _A_VERSION_NEXT.match(text, index + 1):
            found.append(text[start:index].strip())
            start = index + 1
    found.append(text[start:].strip())
    return [requirement for requirement in found if requirement][:MAX_COMMANDS]


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


# ---- the version a spec names, or the highest it allows ------------------------------------------

# A PEP 440 version written in full (no "*", no range): 2025.1, 1.2.3.4, 1.0.0rc1, 2025.1.1.post1, 1.0+local.
_PYPI_EXACT = re.compile(
    r"(?i)v?(?:[0-9]{1,18}!)?[0-9]{1,18}(?:\.[0-9]{1,18}){0,7}"
    r"(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]{0,18})?"
    r"(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]{0,18}|-[0-9]{1,18})?(?:[-_.]?dev[-_.]?[0-9]{0,18})?"
    r"(?:\+[a-z0-9]{1,64}(?:[-_.][a-z0-9]{1,64}){0,16})?")
# The numbers of a version or of part of one, npm's wildcards too: "1.2.3", "v1.2", "1.x", "1.2.*", "1.2.3-rc.1".
_VERSION_NUMBERS = re.compile(r"v?([0-9]{1,18})(?:\.([0-9]{1,18}|[xX*]))?(?:\.([0-9]{1,18}|[xX*]))?(?:[-+].*)?")
_COMPARATOR = re.compile(r"(<=|>=|<|>|=|~>|~|\^)?\s*([^\s<>=~^]\S*)")
MAX_RANGE_CHARS = 256  # of a version range that is read for its highest version


def _numbers(text: str) -> list[int] | None:
    """The leading numbers a version names, up to three, without wildcards: "1.2.x" -> [1, 2]; None if it is none."""
    found = _VERSION_NUMBERS.fullmatch(text)
    if found is None:
        return None
    numbers = []
    for part in found.groups():
        if part is None or part in "xX*":
            break
        numbers.append(int(part))
    return numbers


def _next_after(numbers: list[int], kept: int) -> tuple[tuple[int, ...], bool]:
    """The first version after every one that begins with the first `kept` numbers: ([1, 2, 3], 2) -> 1.3.0, itself
    not allowed."""
    head = numbers[:kept]
    return (*head[:-1], head[-1] + 1, *([0] * (3 - kept))), False


def _comparator_bound(operator: str, version: str) -> tuple[tuple[int, ...], bool] | None:
    """The highest version one npm comparator allows, or None when it sets no upper limit (">=1.0.0", "*", a tag)."""
    numbers = _numbers(version)
    if not numbers or operator in (">", ">="):
        return None
    whole = len(numbers) == 3
    padded = tuple(numbers + [0] * (3 - len(numbers)))
    if operator == "<":
        return padded, False
    if operator in ("~", "~>"):
        return _next_after(numbers, min(len(numbers), 2))
    if operator == "^":  # up to the next change of the first number that is not 0
        kept = next((at + 1 for at, number in enumerate(numbers) if number), len(numbers))
        return _next_after(numbers, kept)
    # "<=", "=" or none: the version itself, or every version that begins with these numbers ("1.2", "1.2.x")
    return (padded, True) if whole else _next_after(numbers, len(numbers))


def _lower(one: tuple[tuple[int, ...], bool], other: tuple[tuple[int, ...], bool]) -> bool:
    """Whether one upper limit is below another (the same numbers: the one that leaves the version itself out)."""
    return (one[0], one[1]) < (other[0], other[1])


def _npm_highest(wanted: str) -> tuple[tuple[int, ...], bool] | None:
    """The highest version an npm range can fetch, or None when it has no upper limit or is not understood.

    "A || B" allows what either does; the comparators of one alternative
    ("<2.0.0 >=1.2.0", "1.0.0 - 1.2.3", "~1.2.3", "^0.1.14", "1.2.x") all hold.
    """
    if not wanted or len(wanted) > MAX_RANGE_CHARS:
        return None
    highest = None
    for alternative in wanted.split("||"):
        low, hyphen, high = alternative.partition(" - ")
        text = "<=" + high.strip() if hyphen else alternative
        limit = None
        for operator, version in _COMPARATOR.findall(text):
            bound = _comparator_bound(operator, version)
            if bound is not None and (limit is None or _lower(bound, limit)):
                limit = bound
        if limit is None:
            return None
        if highest is None or _lower(highest, limit):
            highest = limit
    return highest


def _pypi_highest(specifiers: str) -> tuple[tuple[int, ...], bool] | None:
    """The highest version a PyPI requirement's version part can fetch ("<2025.12", "==2025.1.*", "~=2025.1.0"),
    or None when it has no upper limit or is not understood. Every clause between commas holds."""
    if not specifiers or len(specifiers) > MAX_RANGE_CHARS:
        return None
    limit = None
    for clause in specifiers.split(","):
        found = re.fullmatch(r"\s*(<=|<|===|==|~=)\s*([0-9A-Za-z.*+!_-]+)\s*", clause)
        if found is None:
            continue
        operator, version = found.groups()
        numbers = _numbers(version[:-2] if version.endswith(".*") else version)
        if not numbers:
            continue
        padded = tuple(numbers + [0] * (3 - len(numbers)))
        if operator == "<":
            bound = (padded, False)
        elif operator == "~=":
            bound = _next_after(numbers, max(len(numbers) - 1, 1))
        elif version.endswith(".*"):
            bound = _next_after(numbers, len(numbers))
        else:
            bound = (padded, True)
        if limit is None or _lower(bound, limit):
            limit = bound
    return limit


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
    at = spec.find("@", 1)
    wanted = lowered[at + 1:] if at != -1 else ""  # "name@github:user/repo" names a repository too
    if (lowered.startswith(_GIT_SOURCES) or wanted.startswith(_GIT_SOURCES) or _SCP_ADDRESS.match(spec)
            or ("/" in spec and not spec.startswith("@") and ":" not in spec
                and not spec.startswith((".", "/", "~")))):
        return PackageRef(runner, NPM, written, "", None, "git")  # "user/repo" is a GitHub repository to npm
    if lowered.startswith(("http:", "https:")) or "://" in spec:
        name, version = _tarball_package(spec) or ("", None)
        return PackageRef(runner, NPM, written, name, version, "url")
    if spec.startswith((".", "/", "~")) or ":" in spec or "\\" in spec:
        return PackageRef(runner, NPM, written, "", None, "path")
    name = (spec if at == -1 else spec[:at]).lower()
    wanted = spec[at + 1:].strip() if at != -1 else ""
    exact = wanted[1:].strip() if wanted.startswith("=") else wanted  # "=1.2.3" is npm's own way to say 1.2.3
    version = exact if _EXACT_VERSION.fullmatch(exact) else None
    return PackageRef(runner, NPM, written, name, version, "registry",
                      highest=None if version else _npm_highest(wanted))


def _tarball_package(url: str) -> tuple[str, str | None] | None:
    """(name, version) when an address is an npm registry's file of a package; else None.

    Registries keep them as .../NAME/-/NAME-VERSION.tgz (a scoped
    .../@scope/name/-/name-VERSION.tgz, or @scope%2fname): for example
    https://registry.npmjs.org/postmark-mcp/-/postmark-mcp-1.0.16.tgz. The
    version is None when it is no exact version.
    """
    scheme, found, rest = url[:MAX_PATH_CHARS].partition("://")
    if not found or scheme.lower() not in ("http", "https"):
        return None
    path = rest.partition("/")[2].split("?", 1)[0].split("#", 1)[0]
    folder, found, file = path.partition("/-/")
    if not found or "/" in file or not file.lower().endswith(".tgz"):
        return None
    segments = folder.replace("%2f", "/").replace("%2F", "/").split("/")
    name = "/".join(segments[-2:]) if len(segments) >= 2 and segments[-2].startswith("@") else segments[-1]
    stem = file[:-4]
    if not name or not stem.lower().startswith(segments[-1].lower() + "-"):
        return None
    version = stem[len(segments[-1]) + 1:]
    return name.lower(), version if _EXACT_VERSION.fullmatch(version) else None


def _pypi_ref(runner: str, spec: str, role: str = "run") -> PackageRef:
    lowered = spec.lower()
    if lowered.startswith("git+") or " @ git+" in lowered or "@git+" in lowered:
        return PackageRef(runner, PYPI, spec, "", None, "git", role)
    if "://" in spec:
        return PackageRef(runner, PYPI, spec, "", None, "url", role)
    if spec.startswith((".", "/", "~")) or "\\" in spec:
        return PackageRef(runner, PYPI, spec, "", None, "path", role)
    name = pypi_name(_PYPI_NAME_END.split(spec, maxsplit=1)[0])
    requirement = spec.split(";", 1)[0].strip()  # without an environment marker: 'pkg==1.0; python_version>"3"'
    version = None
    if "==" in requirement:
        pinned = requirement.split("==", 1)[1].lstrip("=").strip()  # "===" pins the very text
        version = pinned if _PYPI_EXACT.fullmatch(pinned) else None
    elif "@" in requirement and _PYPI_EXACT.fullmatch(requirement.split("@", 1)[1].strip()):
        version = requirement.split("@", 1)[1].strip()  # uv's "package@1.2.3"
    highest = None
    if version is None:
        end = re.search(r"[=<>~!]", requirement)
        highest = _pypi_highest(requirement[end.start():]) if end is not None else None
    return PackageRef(runner, PYPI, spec, name, version, "registry", role, highest=highest)


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
    """(package, how to pin it) when a registry package is run without an exact version; else None.

    A requirement installed beside it (uvx --with) is left to the advisories,
    as the package's own dependencies are.
    """
    if ref.source != "registry" or ref.version is not None or ref.role != "run":
        return None
    if ref.ecosystem in (NPM, JSR):
        prefix = ref.spec[:4] if ref.spec[:4].lower() in ("npm:", "jsr:") else ""  # deno's, and npm's alias
        body = _without_subpath(ref.spec)[len(prefix):]
        at = body.find("@", 1)
        return ref.spec, f"{prefix}{body if at == -1 else body[:at]}@1.2.3"
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
    """Whether a package is the advisory's: by its registry name, or as named by a registry's package file address."""
    wanted = advisory.name.lower() if advisory.ecosystem == NPM else pypi_name(advisory.name)
    return ref.source in ("registry", "url") and ref.ecosystem == advisory.ecosystem and ref.name == wanted


def advisory_findings(ref: PackageRef) -> list[tuple[str, str]]:
    """("fail" or "warn", what to say) for each advisory of advisories.py that concerns this package."""
    found = []
    shown = _quoted(ref.written, 200)
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
        if not _same_package(ref, advisory):
            continue
        if ref.version and version_before(ref.version, advisory.fixed or ""):
            found.append(("warn", f"{shown} has a known vulnerability, fixed in {advisory.fixed}: {advisory.summary} "
                                  f"({advisory.ids}; {advisory.source}). Update it to {advisory.fixed} or later"))
        elif not ref.version and ref.highest is not None and _all_before(ref.highest, advisory.fixed or ""):
            found.append(("warn", f"{shown} can only fetch versions before {advisory.fixed}, which have a known "
                                  f"vulnerability: {advisory.summary} ({advisory.ids}; {advisory.source}). Allow "
                                  f"{advisory.fixed} or later"))
    return found


def _all_before(highest: tuple[tuple[int, ...], bool], fixed: str) -> bool:
    """Whether every version up to `highest` (PackageRef.highest) comes before the version `fixed`."""
    key = _version_key(fixed, 8)
    if key is None:
        return False
    numbers, allowed = highest
    padded = tuple(numbers) + (0,) * (8 - len(numbers))
    return padded < key[0] or (padded == key[0] and not allowed)


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
    "--network-alias", "--annotation", "--sysctl", "--device-cgroup-rule", "--storage-opt", "--domainname", "-c",
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
# The one-letter options of `docker run`: those that take a value (the rest of their word, else the next word)
# and those that take none. They can be written together: -it, -iv HOST:/c, -itv/:/host.
_CONTAINER_VALUE_LETTERS = "vepwulmhac"
_CONTAINER_FLAG_LETTERS = "ditPq"
_A_NUMBER = re.compile(r"[0-9][0-9.]*[A-Za-z%]{0,3}")
# A word that is a mount or a path and never an image: "/:/host", "C:\\x:/x", "~/x", "./x", "vol:/data".
_NEVER_AN_IMAGE = re.compile(r"[/\\~.]|[A-Za-z]:[/\\]|[^:]*:[/\\]")
MAX_MOUNTS_CHECKED = 64  # mounts of one container checked for the host's root, home folder or engine socket
# A container engine's socket (or Windows pipe), and the folders that hold one: a container given it can start
# containers of its own on the host, privileged and with the host's root mounted.
_ENGINE_SOCKETS = frozenset({"docker.sock", "podman.sock", "containerd.sock", "docker_engine"})
_ENGINE_SOCKET_FOLDERS = frozenset({"/run", "/var/run", "/run/docker", "/var/run/docker", "/run/podman",
                                    "/var/run/podman", "/run/containerd", "/var/run/containerd"})
_ENGINE_CONTROL = "it can control the host's containers, which in effect is root on the host"


def launch_risks(words: list[str], user_home: str | None = None) -> list[str]:
    """What is risky about a launch command, each as a short printable phrase; empty when nothing is.

    `user_home`: the user's own folder, to recognise an argument that names
    it whole (default: this user's, from the environment).
    """
    more_words = len(words) > MAX_WORDS_LINTED
    words = words[:MAX_WORDS_LINTED]
    if not words:
        return []
    if user_home is None:
        folder = home.user_folder()
        user_home = str(folder) if folder is not None else None
    read, too_long = _read_part(words)
    cuts: list[bool] = []
    noting = _CUTS.set(cuts)
    try:
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
    finally:
        _CUTS.reset(noting)
    if more_words or cuts:  # first, so that it is never among the risks left out
        risks.insert(0, "is longer than this check reads (more than "
                        f"{MAX_WORDS_LINTED} words, {MAX_OPTIONS_SCANNED} options in a row, {MAX_COMMANDS} commands, "
                        f"{MAX_WRAPPERS} wrappers in a row or {MAX_COMMAND_STRING_CHARS} characters of a command "
                        "string), so only part of it was checked: read the rest yourself")
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
    """Interpreters given code on the command line: sh -c, cmd /c, powershell -Command, node -e, python -c.

    cmd as the program is read as cmd reads its command line (`cmd foo /c x`,
    `cmd /d/s/c x`); a word "cmd" among the arguments only with switches
    right after it, at most MAX_LOOKED_BEHIND times.
    """
    found = []
    cmd_scans = 0
    for index, word in enumerate(words):
        program = program_name(word)
        options = words[index + 1:index + 1 + MAX_OPTIONS_SCANNED]
        flag = None
        if program in _SHELLS:
            flag = _first_option(options, _is_c_cluster, prefixes=("-", "+"), takes_value=_shell_takes_value)
        elif program == "cmd" and cmd_scans < MAX_LOOKED_BEHIND:
            cmd_scans += 1
            run_at = _cmd_run_at(words[index + 1:], switches_only=index > 0)
            flag = words[index + 1 + run_at[0]] if run_at is not None else None
        elif program in _POWERSHELL:
            command = _powershell_command(program, options)
            flag = options[command[0]] if command is not None else None
        elif program in _NODE:
            flag = _first_option(options, _is_node_eval, values=_NODE_VALUE_OPTIONS)
            if flag is None and program == "bun":  # bun run -e CODE
                at = _first_plain_at(options, _BUN_OPTIONS)
                if at is not None and options[at] == "run":
                    flag = _code_option(options[at + 1:], _BUN_OPTIONS, "ep", frozenset({"--eval", "--print"}))
        elif program == "deno":
            at = _first_plain_at(options, _DENO_OPTIONS)  # deno -q eval CODE
            flag = "eval" if at is not None and options[at] == "eval" else None
        elif _PYTHON.fullmatch(program):
            flag = _code_option(options, _PYTHON_OPTIONS, "c")
        elif program in _RUNNER_PROGRAMS:
            flag = _runner_code_option(words[index:index + 1 + MAX_OPTIONS_SCANNED])
        else:
            if program == "cmd":
                _cut_short()  # more words named cmd than are read
            known = _CODE_OPTIONS.get(program) or _CODE_OPTIONS.get(program.rstrip("0123456789."))  # php8.3
            flag = _code_option(options, *known) if known is not None else None
        if flag is not None:
            found.append(f"runs code written on the command line ({printable(program, limit=40)} "
                         f"{_quoted(flag, 40)})")
    return found


def _code_option(options: list[str], spec: _ScriptOptions, letters: str,
                 names: frozenset[str] = frozenset()) -> str | None:
    """The option that hands an interpreter code on the command line, or None when a script, a module or
    nothing of the kind comes first.

    The options are read as the interpreter reads them (_read_option): a
    letter of a cluster counts ("-Ic"), a letter inside another option's
    value does not ("-Wonce", "-Xtracemalloc"). `letters` and `names` are the
    short and the long options that take code, among those after which no
    script runs.
    """
    index, maybe_value = 0, False
    while index < len(options):
        word = options[index]
        if word == "--":
            return None
        if not _is_option(word, spec):
            if not maybe_value:
                return None
            maybe_value = False  # perhaps the value of an option not known here
            index += 1
            continue
        kind, taken, _ = _read_option(word, None, spec)
        if kind == _STOP:
            if word.startswith("--"):
                return word if word.partition("=")[0] in names else None
            stopped_at = next(letter for letter in word[1:] if letter in spec.short_stops)
            return word if stopped_at in letters else None
        if kind == _SCRIPT:
            return None
        maybe_value = kind == _UNKNOWN
        index += taken
    if len(options) >= MAX_OPTIONS_SCANNED:
        _cut_short()
    return None


def _runner_code_option(words: list[str]) -> str | None:
    """The option that makes a package runner hand a string to a shell: npx -c "...", npm exec --call "...",
    pnpm dlx --shell-mode (-c); None for a runner without one, or a command that is no runner."""
    runner = _runner_of(words)
    if runner is None or runner[1] != NPM:
        return None
    options, _, _ = _runner_words(words[runner[2]:], _npx_value_options(runner[0]), _NPX_FLAGS)
    return next((name for name, _, sure in options if sure and name in ("-c", "--call", "--shell-mode")), None)


def _is_c_cluster(option: str) -> bool:
    """A shell's -c, alone or in a cluster of letters (-lc, -ec)."""
    return option.startswith("-") and not option.startswith("--") and option[1:].isalpha() and "c" in option[1:]


def _shell_takes_value(option: str) -> bool:
    """A shell option that takes the next word: --rcfile, --init-file, and -o, -O, +o, +O (also ending a cluster)."""
    return option in ("--rcfile", "--init-file") or (
        not option.startswith("--") and len(option) >= 2 and option[1:].isalpha() and option[-1] in "oO")


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
    if len(options) >= MAX_OPTIONS_SCANNED:
        _cut_short()
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
        # "-ExecutionPolicy:Bypass" carries what follows the colon: the next word is read for itself
        # (Windows PowerShell does not take the form as a parameter at all, and runs the rest as a command).
        index += 2 if takes_value and ":" not in option else 1
    if len(options) >= MAX_OPTIONS_SCANNED:
        _cut_short()
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
        ref = next((ref for ref in _direct_packages(command) if ref.source in ("git", "url")
                    and (not ref.unsure or _names_an_address(ref.spec))), None)
        if ref is not None and ref.unsure:  # the word may be the value of an option in front of it
            return [f"may run a package straight from a git repository or a web address, unreviewed and unpinned "
                    f"({_quoted(ref.written, 120)}: an option before it is not one this check knows, so this word "
                    "is that option's value or the package)"]
        if ref is not None:
            return [f"runs a package straight from a git repository or a web address, unreviewed and unpinned "
                    f"({_quoted(ref.written, 120)})"]
        if program_name(command[0]) == "uv":  # uv run https://host/server.py downloads the script and runs it
            target = _uv_run_target(command[1:MAX_WORDS_LINTED])[0]
            if target is not None and target.lower().startswith(("http://", "https://")):
                return [f"downloads a script from a web address and runs it, unreviewed and unpinned "
                        f"(uv run {_quoted(target, 120)})"]
        if program_name(command[0]) in ("uvx", "uv", "pipx") and any(
                word[:4].lower() == "git+" for word in command[1:]):
            return ["installs a package straight from a git repository (git+...), unreviewed and unpinned"]
    return []


def _names_an_address(spec: str) -> bool:
    """Whether a spec says outright that it is a repository or a web address (not merely "word/word", which
    npm reads as a GitHub repository but which may as well be a folder given to an option)."""
    lowered = spec.lower()
    return lowered.startswith(_GIT_SOURCES) or "://" in spec or "git+" in lowered or bool(_SCP_ADDRESS.match(spec))


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
    if MAX_OPTIONS_SCANNED <= index < len(args):
        _cut_short()
    return args[index:]


def _run_options(args: list[str], user_home: str | None) -> list[str]:
    risks, index, image, mounts = [], 0, None, 0
    while index < len(args):
        word = args[index]
        if word == "--":
            image = args[index + 1] if index + 1 < len(args) else None
            break
        if not word.startswith("-"):
            if not _NEVER_AN_IMAGE.match(word):
                image = word
                break
            # No image is written so: it is the value of an option not known here. Read as a mount, in case.
            name, value = "-v", word
            index += 1
        else:
            name, equals, value = word.partition("=")
            clustered = _short_options(word) if not word.startswith("--") and len(word) > 2 else None
            if clustered is not None:  # -it, -iv HOST:/c, -v/:/host: the last letter read is the option
                name, value = clustered
                if value is None and name[1] in _CONTAINER_VALUE_LETTERS:
                    value = args[index + 1] if index + 1 < len(args) else ""
                    index += 1
                elif value == "" and index + 1 < len(args) and _only_a_value(args[index + 1]):
                    index += 1  # a letter not known here, followed by what can only be its value
                value = value or ""
            elif not equals and name in _CONTAINER_VALUE_OPTIONS:
                value = args[index + 1] if index + 1 < len(args) else ""
                index += 1
            elif (not equals and name not in _CONTAINER_FLAGS and index + 1 < len(args)
                  and _only_a_value(args[index + 1])):
                index += 1  # an option not known here, followed by what can only be its value (no image looks so)
            index += 1
        if name == "--privileged" and value.lower() not in ("false", "0"):
            risks.append("runs a container with --privileged (it has the run of the host)")
        elif name in ("--network", "--net", "--pid", "--ipc", "--uts", "--userns") and value.lower() == "host":
            risks.append(f"shares the host's {name.lstrip('-')} with the container ({name} host)")
        elif name == "--use-api-socket" and value.lower() not in ("false", "0"):
            risks.append(f"gives the container the Docker engine's socket (--use-api-socket): {_ENGINE_CONTROL}")
        elif name in ("-v", "--volume", "--mount"):
            mounts += 1
            if mounts > MAX_MOUNTS_CHECKED:
                continue
            source = _mount_source(value) if name == "--mount" else _volume_source(value)
            what = _whole_folder(source, user_home) if source else None
            shown = f"({printable(name, limit=20)} {_quoted(value, 120)})"
            if what:
                risks.append(f"mounts {what} into the container {shown}")
            elif source and _engine_socket(source):
                risks.append(f"mounts the container engine's socket into the container {shown}: {_ENGINE_CONTROL}")
    if mounts > MAX_MOUNTS_CHECKED:
        risks.append(f"mounts {mounts} folders or files into the container, more than any real one needs, so only the "
                     f"first {MAX_MOUNTS_CHECKED} were checked")
    if image is not None and "@sha256:" not in image.lower():
        risks.append(f"runs the image {_quoted(image, 120)} by a tag, not pinned by digest (@sha256:...): a "
                     "new image can be pushed under the same tag")
    return risks


def _short_options(word: str) -> tuple[str, str | None]:
    """A word of one-letter options of `docker run`, read as docker reads it: (the last option read, its value
    if the word carries it, else None).

    "-it" -> ("-t", None); "-iv" -> ("-v", None), which takes the next word;
    "-v/:/host" and "-itv=/:/host" -> ("-v", "/:/host"). A letter not known
    here ends the reading: ("-" + letter, "").
    """
    for position, letter in enumerate(word[1:1 + MAX_CLUSTER_LETTERS], start=1):
        if letter in _CONTAINER_VALUE_LETTERS:
            rest = word[position + 1:]
            return "-" + letter, (rest[1:] if rest.startswith("=") else rest) or None
        if letter not in _CONTAINER_FLAG_LETTERS:
            return "-" + letter, ""
    return "-" + word[-1], None


def _only_a_value(word: str) -> bool:
    """A word that is an option's value and never an image: a number or size, true/false, KEY=VALUE. (A path
    is none either, but it is not passed over: _run_options reads it as a mount, in case it is one.)"""
    return bool(_A_NUMBER.fullmatch(word[:64])) or word.lower() in ("true", "false") or (
        "=" in word and not _NEVER_AN_IMAGE.match(word))


def _volume_source(value: str) -> str:
    """The host side of a -v value: "/:/host" -> "/", "C:\\:/host" -> "C:\\"."""
    if re.match(r"[A-Za-z]:[\\/:]", value) or re.fullmatch(r"[A-Za-z]:", value):
        rest = value[2:]
        cut = rest.find(":")
        return value if cut == -1 else value[: 2 + cut]
    return value.split(":", 1)[0]


def _engine_socket(source: str) -> bool:
    """Whether a mount's host side is a container engine's socket, Windows pipe or the folder that holds one:
    /var/run/docker.sock, podman.sock, containerd.sock, //./pipe/docker_engine, /var/run, /run/podman."""
    text = source.strip().strip("\"'").replace("\\", "/").lower()
    if not text or len(text) > MAX_PATH_CHARS:
        return False
    normal = posixpath.normpath(text)
    return normal.rstrip("/").rsplit("/", 1)[-1] in _ENGINE_SOCKETS or normal in _ENGINE_SOCKET_FOLDERS


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
                         f"({_quoted(arg, 120)})")
        whole = _whole_folder(value, user_home)
        if whole:
            found.append(f"gives the server {whole} in an argument ({_quoted(arg, 120)})")
    return found


# ---- what proxy --pin-server pins ----------------------------------------------------------------

LAUNCH_FIELDS = ("executable", "package", "script", "script_sha256", "command_sha256")
# The largest script (or program) whose SHA-256 is taken; a larger one is pinned by its path only.
MAX_HASHED_BYTES = 64 * 1024 * 1024
# What an interpreter runs when its script is a folder, or a name without its ending: `python DIR` runs
# DIR/__main__.py, `node DIR` the "main" of DIR/package.json or DIR/index.js, `node dist/index` dist/index.js.
# Every one of these files that exists is hashed (_files_run), so no interpreter's own rules are guessed.
_FOLDER_SCRIPTS = ("__main__.py", "package.json", "index.js", "index.mjs", "index.cjs", "index.ts", "index.mts",
                   "index.cts", "index.tsx", "index.jsx", "index.json", "index.node")
_SCRIPT_ENDINGS = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx", ".json", ".node")
MAX_PACKAGE_JSON_BYTES = 1024 * 1024  # of a package.json read for its "main"
# The longest text of the packages pinned as it is; a longer one is pinned as "sha256:<hex>" of it.
MAX_PINNED_PACKAGE_CHARS = 1024
# Packages that a runner fetches to start a local script: npx -y tsx@4 server.ts.
_SCRIPT_RUNNER_PACKAGES = frozenset({"tsx", "ts-node", "esno", "vite-node", "jiti", "node", "bun", "deno"})
# Launchers whose own file says nothing of what runs: package runners (their package is pinned by its spec),
# shells given a command, and container runtimes (an image is pinned by its digest, which doctor checks).
_NOT_PINNED_BY_FILE = frozenset({"npx", "bunx", "pnpx", "uvx", "uv", "pipx", "cmd", "java", *_CONTAINER})
# The most words taken for one launch's script, when options in front of it are not known here (each is pinned).
MAX_SCRIPT_CANDIDATES = 4
# The most letters of one cluster of short options read (-euxo); no real one has more.
MAX_CLUSTER_LETTERS = 32
# A word that names something by a scheme (npm:, jsr:, https:, node:), not a local file; "C:" is a drive.
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]+:")


@dataclass(frozen=True)
class _ScriptOptions:
    """How an interpreter reads the options in front of its script: getopt's way, with long options.

    values:          long options that take the next word as their value (unless written --name=value);
    flags:           long options that take none, and every one that begins with one of `flag_prefixes`;
    short_values:    letters that take a value: the rest of their word, else the next word (-I lib, -Ilib);
    short_attached:  letters whose value, if any, is the rest of their word only (perl -Mstrict, ruby -x);
    short_flags:     letters that take none (a cluster such as -uB is read a letter at a time);
    stops, short_stops:   options after which no script file runs (code on the command line, a module);
    script, short_script: options whose value is the script itself (php -f FILE);
    plus:            whether a word that begins with "+" is an option too (a shell's +o NAME).
    An option that is none of these is not known here (see _script_words).
    """

    values: frozenset[str] = frozenset()
    flags: frozenset[str] = frozenset()
    flag_prefixes: tuple[str, ...] = ()
    short_values: str = ""
    short_attached: str = ""
    short_flags: str = ""
    stops: frozenset[str] = frozenset()
    short_stops: str = ""
    script: frozenset[str] = frozenset()
    short_script: str = ""
    plus: bool = False


def _more(base: _ScriptOptions, values: tuple[str, ...] = (), flags: tuple[str, ...] = ()) -> _ScriptOptions:
    """An interpreter's options with a few of its own added (tsx is node with options of its own)."""
    return replace(base, values=base.values | frozenset(values), flags=base.flags | frozenset(flags))


_PYTHON_OPTIONS = _ScriptOptions(
    values=frozenset({"--check-hash-based-pycs"}),
    flags=frozenset({"--help", "--version", "--help-env", "--help-xoptions", "--help-all"}),
    short_values="XW", short_flags="bBdEhiIOPqRsSuvVx?", short_stops="cm",
)
_NODE_OPTIONS = _ScriptOptions(
    values=frozenset({
        "--require", "--import", "--loader", "--experimental-loader", "--env-file", "--env-file-if-exists",
        "--conditions", "--title", "--inspect-port", "--debug-port", "--input-type", "--watch-path",
        "--watch-kill-signal", "--experimental-default-type", "--experimental-config-file",
        "--experimental-sea-config", "--experimental-policy", "--policy-integrity",
        "--experimental-specifier-resolution", "--es-module-specifier-resolution", "--disable-warning",
        "--disable-proto", "--redirect-warnings", "--unhandled-rejections", "--dns-result-order", "--icu-data-dir",
        "--openssl-config", "--tls-cipher-list", "--tls-keylog", "--use-largepages", "--localstorage-file",
        "--max-http-header-size", "--secure-heap", "--secure-heap-min", "--heapsnapshot-signal",
        "--heapsnapshot-near-heap-limit", "--diagnostic-dir", "--report-dir", "--report-directory",
        "--report-filename", "--report-signal", "--cpu-prof-dir", "--cpu-prof-name", "--cpu-prof-interval",
        "--heap-prof-dir", "--heap-prof-name", "--heap-prof-interval", "--trace-event-categories",
        "--trace-event-file-pattern", "--trace-require-module", "--snapshot-blob", "--build-snapshot-config",
        "--allow-fs-read", "--allow-fs-write", "--security-revert", "--inspect-publish-uid", "--stack-size",
        "--stack-trace-limit", "--max-old-space-size", "--max-semi-space-size", "--v8-pool-size",
        "--network-family-autoselection-attempt-timeout", "--test-name-pattern", "--test-skip-pattern",
        "--test-reporter", "--test-reporter-destination", "--test-concurrency", "--test-timeout", "--test-shard",
        "--test-isolation", "--test-coverage-include", "--test-coverage-exclude", "--test-coverage-branches",
        "--test-coverage-functions", "--test-coverage-lines", "--test-global-setup",
    }),
    flags=frozenset({
        "--watch", "--check", "--interactive", "--test", "--permission", "--jitless", "--preserve-symlinks",
        "--preserve-symlinks-main", "--abort-on-uncaught-exception", "--frozen-intrinsics", "--insecure-http-parser",
        "--zero-fill-buffers", "--pending-deprecation", "--throw-deprecation", "--enable-source-maps", "--prof",
        "--prof-process", "--cpu-prof", "--heap-prof", "--entry-url", "--build-snapshot", "--strip-types",
        "--node-memory-debug", "--async-context-frame", "--help", "--version", "--v8-options", "--completion-bash",
    }),
    flag_prefixes=("--no-", "--experimental-", "--trace-", "--harmony", "--allow-", "--use-", "--tls-m",
                   "--openssl-", "--force-", "--expose", "--enable-", "--disable-", "--report-", "--test-",
                   "--watch-", "--inspect"),
    short_values="rC", short_flags="chiv", short_stops="ep", stops=frozenset({"--eval", "--print", "--run"}),
)
_TSX_OPTIONS = _more(_NODE_OPTIONS, values=("--tsconfig", "--include", "--exclude", "--ignore"),
                     flags=("--no-cache", "--clear-screen"))
_TS_NODE_OPTIONS = _ScriptOptions(
    values=frozenset({"--project", "--require", "--compiler", "--compiler-options", "--ignore", "--ignore-diagnostics",
                      "--cwd", "--dir", "--scope-dir", "--transpiler"}),
    flags=frozenset({"--transpile-only", "--type-check", "--compiler-host", "--files", "--pretty", "--skip-project",
                     "--skip-ignore", "--prefer-ts-exts", "--log-error", "--esm", "--swc", "--emit", "--scope",
                     "--show-config", "--interactive", "--version", "--help", "--cwd-mode", "--script-mode"}),
    short_values="rPCOID", short_flags="THivh", short_stops="ep", stops=frozenset({"--eval", "--print"}),
)
_VITE_NODE_OPTIONS = _ScriptOptions(
    values=frozenset({"--root", "--config", "--mode", "--options"}),
    flags=frozenset({"--watch", "--script", "--help", "--version"}),
    short_values="rcm", short_flags="wvh",
)
# deno's options take an optional value only as --name=value (--allow-read=/srv, -R=/srv), so most are flags.
_DENO_OPTIONS = _ScriptOptions(
    values=frozenset({"--config", "--import-map", "--cert", "--location", "--seed", "--log-level", "--ext",
                      "--preload", "--require", "--conditions"}),
    flags=frozenset({"--quiet", "--cached-only", "--check", "--reload", "--lock", "--env-file", "--node-modules-dir",
                     "--vendor", "--frozen", "--unsafely-ignore-certificate-errors", "--v8-flags", "--hmr",
                     "--permission-set", "--enable-testing-features-do-not-use", "--strace-ops", "--help"}),
    flag_prefixes=("--allow-", "--deny-", "--no-", "--unstable", "--inspect", "--watch"),
    short_values="cL", short_flags="AqrRWNESIPh",
)
_BUN_OPTIONS = _ScriptOptions(
    values=frozenset({"--cwd", "--config", "--env-file", "--preload", "--require", "--import", "--tsconfig-override",
                      "--define", "--loader", "--main-fields", "--extension-order", "--jsx-factory", "--jsx-fragment",
                      "--jsx-import-source", "--jsx-runtime", "--conditions", "--port", "--install", "--filter",
                      "--elide-lines", "--shell", "--title", "--unhandled-rejections", "--console-depth",
                      "--fetch-preconnect", "--max-http-header-size", "--dns-result-order", "--user-agent"}),
    flags=frozenset({"--bun", "--silent", "--watch", "--hot", "--smol", "--if-present", "--prefer-offline",
                     "--prefer-latest", "--expose-gc", "--zero-fill-buffers", "--redis-preconnect", "--sql-preconnect",
                     "--throw-deprecation", "--verbose", "--version", "--help", "--revision", "--workspaces",
                     "--parallel", "--sequential", "--use-system-ca", "--use-openssl-ca"}),
    flag_prefixes=("--no-", "--inspect", "--experimental-"),
    short_values="crdlF", short_flags="bhiv", short_stops="ep", stops=frozenset({"--eval", "--print"}),
)
_RUBY_OPTIONS = _ScriptOptions(
    values=frozenset({"--disable", "--enable", "--encoding", "--external-encoding", "--internal-encoding"}),
    flags=frozenset({"--version", "--verbose", "--copyright", "--help", "--yjit", "--rjit", "--jit", "--debug"}),
    flag_prefixes=("--disable-", "--enable-", "--yjit-", "--rjit-", "--jit-", "--dump", "--backtrace-limit",
                   "--crash-report", "--parser"),
    short_values="ICEXr", short_attached="0FKTWix", short_flags="acdhlnpsSvwyU", short_stops="e",
)
_PERL_OPTIONS = _ScriptOptions(
    flags=frozenset({"--help", "--version"}),
    short_values="I", short_attached="0CdDFilmMxV", short_flags="acnpsStTuUvwWXh", short_stops="eE",
)
_PHP_OPTIONS = _ScriptOptions(
    values=frozenset({"--php-ini", "--define", "--zend-extension"}),
    flags=frozenset({"--interactive", "--no-php-ini", "--no-chdir", "--info", "--modules", "--version", "--help",
                     "--syntax-check", "--syntax-highlight", "--strip", "--hide-args", "--ini"}),
    stops=frozenset({"--run", "--process-begin", "--process-code", "--process-end", "--rf", "--rc", "--re", "--rz",
                     "--ri"}),
    script=frozenset({"--file", "--process-file"}),
    short_values="cdzSt", short_flags="aCehHilmnqsvw", short_stops="rBRE", short_script="fF",
)
_LUA_OPTIONS = _ScriptOptions(short_values="l", short_flags="ivEW", short_stops="e")
_RSCRIPT_OPTIONS = _ScriptOptions(flag_prefixes=("--",), short_stops="e")  # Rscript's own are --name or --name=value
_SHELL_OPTIONS = _ScriptOptions(
    values=frozenset({"--rcfile", "--init-file"}),
    flags=frozenset({"--login", "--noediting", "--noprofile", "--norc", "--posix", "--restricted", "--verbose",
                     "--version", "--help", "--debugger", "--dump-strings", "--dump-po-strings", "--pretty-print"}),
    short_values="oO", short_flags="".join(sorted(set(string.ascii_letters) - set("oOcs"))), short_stops="cs",
    plus=True,
)
_INTERPRETERS: dict[str, _ScriptOptions] = {
    "node": _NODE_OPTIONS, "nodejs": _NODE_OPTIONS, "jiti": _NODE_OPTIONS, "tsx": _TSX_OPTIONS,
    "esno": _TSX_OPTIONS, "ts-node": _TS_NODE_OPTIONS, "vite-node": _VITE_NODE_OPTIONS, "deno": _DENO_OPTIONS,
    "bun": _BUN_OPTIONS, "ruby": _RUBY_OPTIONS, "perl": _PERL_OPTIONS, "php": _PHP_OPTIONS, "lua": _LUA_OPTIONS,
    "rscript": _RSCRIPT_OPTIONS, **{shell: _SHELL_OPTIONS for shell in _SHELLS if shell != "busybox"},
}
# deno's and bun's commands other than the ones that run a script; any other first word is a script to run
# (`deno server.ts`, `bun server.ts`).
_DENO_COMMANDS = frozenset({
    "add", "approve-scripts", "audit", "bench", "bundle", "check", "clean", "compile", "completions", "coverage",
    "deploy", "doc", "eval", "fmt", "help", "info", "init", "install", "jupyter", "lint", "lsp", "outdated",
    "publish", "remove", "repl", "sandbox", "task", "test", "types", "uninstall", "update", "upgrade", "vendor", "x",
})
_BUN_COMMANDS = frozenset({
    "a", "add", "audit", "build", "c", "completions", "create", "discord", "exec", "help", "i", "info", "init",
    "install", "link", "outdated", "patch", "patch-commit", "pm", "publish", "remove", "repl", "rm", "test",
    "unlink", "update", "upgrade", "why", "x",
})
# For _inline_code, which looks for node -e past the options that take a value.
_NODE_VALUE_OPTIONS = (*sorted(_NODE_OPTIONS.values), "-r", "-C")
_OSASCRIPT_OPTIONS = _ScriptOptions(short_values="ls", short_flags="i", short_stops="e")
# The other interpreters that take code on the command line (_code_option): how their options are read, the
# one-letter options that take code, and the long ones.
_CODE_OPTIONS: dict[str, tuple[_ScriptOptions, str, frozenset[str]]] = {
    "perl": (_PERL_OPTIONS, "eE", frozenset()),
    "ruby": (_RUBY_OPTIONS, "e", frozenset()),
    "php": (_PHP_OPTIONS, "rBRE", frozenset({"--run", "--process-begin", "--process-code", "--process-end"})),
    "lua": (_LUA_OPTIONS, "e", frozenset()),
    "luajit": (_LUA_OPTIONS, "e", frozenset()),
    "rscript": (_RSCRIPT_OPTIONS, "e", frozenset()),
    "osascript": (_OSASCRIPT_OPTIONS, "e", frozenset()),
}

# What an option is to an interpreter (_read_option).
_KNOWN, _UNKNOWN, _STOP, _SCRIPT = "known", "unknown", "stop", "script"


def _read_option(word: str, following: str | None, spec: _ScriptOptions) -> tuple[str, int, str | None]:
    """What an option word is to an interpreter: (what, how many words it takes, the script for _SCRIPT).

    _KNOWN: an option known here; _UNKNOWN: one not known here, taken to be
    one word (whether it takes the next is not known); _STOP: no script
    file runs; _SCRIPT: the option gives the script (`following`, or the
    value written in the word).
    """
    if word.startswith("--"):
        name, equals, value = word.partition("=")
        if name in spec.stops:
            return _STOP, 1, None
        if name in spec.script:
            return (_SCRIPT, 1, value) if equals else (_SCRIPT, 2, following)
        if equals:
            return _KNOWN, 1, None  # it carries its value
        if name in spec.values:
            return _KNOWN, 2, None
        if name in spec.flags or name.startswith(spec.flag_prefixes):
            return _KNOWN, 1, None
        return _UNKNOWN, 1, None
    for position, letter in enumerate(word[1:1 + MAX_CLUSTER_LETTERS], start=1):
        more = position + 1 < len(word)  # the word goes on after this letter
        if letter in spec.short_stops:
            return _STOP, 1, None
        if letter in spec.short_script:
            return (_SCRIPT, 1, word[position + 1:]) if more else (_SCRIPT, 2, following)
        if letter in spec.short_values:
            return _KNOWN, (1 if more else 2), None
        if letter in spec.short_attached or word[position + 1:position + 2] == "=":
            return _KNOWN, 1, None  # the rest of the word is its value (deno's -R=/srv too)
        if letter not in spec.short_flags:
            return _UNKNOWN, 1, None
    return (_KNOWN if len(word) <= 1 + MAX_CLUSTER_LETTERS else _UNKNOWN), 1, None


def _is_option(word: str, spec: _ScriptOptions) -> bool:
    return len(word) > 1 and (word[0] == "-" or (spec.plus and word[0] == "+"))


def _script_words(args: list[str], spec: _ScriptOptions) -> list[str]:
    """The words that may be the script an interpreter runs, read past its options (_ScriptOptions); [] for none.

    One word when every option in front of it is known here. A plain word
    right after an option not known here may be that option's value or the
    script, so it is taken and the words after it are read on, to the next
    plain word: each word taken is pinned, and the script is one of them
    (at most MAX_SCRIPT_CANDIDATES). No more is taken once it is clear that
    no script file runs: code on the command line, a module, standard input.
    """
    found: list[str] = []
    index, maybe_value = 0, False
    while index < min(len(args), MAX_OPTIONS_SCANNED) and len(found) < MAX_SCRIPT_CANDIDATES:
        word = args[index]
        if word == "--":
            return found + args[index + 1:index + 2]
        if not _is_option(word, spec):
            if word == "-":  # standard input
                return found
            found.append(word)
            if not maybe_value:
                return found
            maybe_value = False
            index += 1
            continue
        kind, taken, script = _read_option(word, args[index + 1] if index + 1 < len(args) else None, spec)
        if kind == _STOP:
            return found
        if kind == _SCRIPT:
            return found + ([script] if script else [])
        maybe_value = kind == _UNKNOWN
        index += taken
    if MAX_OPTIONS_SCANNED <= index < len(args):
        _cut_short()
    return found


def _first_plain_at(args: list[str], spec: _ScriptOptions) -> int | None:
    """Where the first word that is no option is (an option not known here taken to take none); None if none is."""
    index = 0
    while index < min(len(args), MAX_OPTIONS_SCANNED):
        word = args[index]
        if word == "--":
            return index + 1 if index + 1 < len(args) else None
        if not _is_option(word, spec):
            return index
        kind, taken, _ = _read_option(word, None, spec)
        if kind in (_STOP, _SCRIPT):
            return None
        index += taken
    if MAX_OPTIONS_SCANNED <= index < len(args):
        _cut_short()
    return None


def _interpreter_scripts(program: str, args: list[str]) -> list[str] | None:
    """The words that may be an interpreter's script (_script_words); None when `program` is no interpreter known here."""
    if _PYTHON.fullmatch(program):
        return _script_words(args, _PYTHON_OPTIONS)
    if program not in _INTERPRETERS:
        program = program.rstrip("0123456789.")  # php8.3, lua5.4, ruby3.3
    spec = _INTERPRETERS.get(program)
    if spec is None:
        return None
    if program in ("deno", "bun"):
        return _subcommand_scripts(program, args)
    if program in ("tsx", "esno") and args[:1] == ["watch"]:
        args = args[1:]
    return _script_words(args, spec)


def _subcommand_scripts(program: str, args: list[str]) -> list[str]:
    """`deno [run|serve] ... SCRIPT` and `bun [run] ... SCRIPT`: the words that may be the script; [] for another
    command of theirs."""
    spec = _INTERPRETERS[program]
    at = _first_plain_at(args, spec)
    if at is None:
        return []
    if args[at] in (("run", "serve") if program == "deno" else ("run",)):
        return _script_words(args[at + 1:], spec)
    if args[at] in (_DENO_COMMANDS if program == "deno" else _BUN_COMMANDS):
        return []
    return _script_words(args, spec)


def launch_targets(executable: str, words: list[str], cwd: str | None = None) -> list[str]:
    """The local files a launch command runs: the script an interpreter is given, or else the program itself.

    Behind a wrapper (cmd /c node server.js, env, sh -c "exec ..."), the one
    command it runs; none when it runs several. A runner's package (npx,
    uvx, deno's npm:) is pinned by its spec, so none for it, unless it runs
    a local script (npx -y tsx@4 server.ts); `uv run server.py` gives the
    script. None for a Python started with -m or -c, nor for inline code. A
    relative script is read against `cwd` (the proxy's current folder), as
    the interpreter will. One file, or several when an option in front of
    the script is not known here (_script_words).
    """
    commands = commands_run(words)
    if len(commands) != 1:
        return []
    command = commands[0]
    found: str | None = executable
    if command != words[:MAX_WORDS_LINTED]:  # behind a wrapper: the wrapper finds the program, not the proxy
        found = command[0] if home.is_absolute(command[0]) else None
    return _targets_of(found, command, cwd)


def _targets_of(executable: str | None, words: list[str], cwd: str | None) -> list[str]:
    program = program_name(words[0])
    args = words[1:MAX_WORDS_LINTED]
    base = cwd
    runner = _runner_of(words)
    scripts: list[str] | None
    if runner is not None and runner[0] != "uv run":
        scripts = _runner_script(words)
    elif program == "uv":
        scripts, base = _uv_run_script(args, cwd)
    elif program in _NOT_PINNED_BY_FILE:
        return []
    elif program in _POWERSHELL:
        given = next((args[index + 1] for index in range(len(args) - 1)
                      if args[index].lstrip("-/").lower() in ("file", "f")), None)
        scripts = [given] if given else []
    else:
        scripts = _interpreter_scripts(program, args)
        if scripts is None:
            return [os.path.abspath(executable)] if executable else []
    paths: list[str] = []
    for script in scripts:
        if script and not _SCHEME.match(script):  # npm:pkg, https://...: deno's package, pinned by its spec
            path = os.path.abspath(os.path.join(base or os.getcwd(), os.path.expanduser(script)))
            if path not in paths:
                paths.append(path)
    return paths


def _runner_script(words: list[str]) -> list[str]:
    """The words that may be the local script a runner's package starts: npx -y tsx@4 server.ts -> ["server.ts"]."""
    refs = _direct_packages(words)
    ref = refs[0] if refs else None
    runner = _runner_of(words)
    if ref is None or runner is None or ref.source != "registry" or ref.name not in _SCRIPT_RUNNER_PACKAGES:
        return []
    args = words[runner[2]:MAX_WORDS_LINTED]
    index = _first_plain_index(args, _NPX_VALUE_OPTIONS if ref.ecosystem == NPM else _UVX_VALUE_OPTIONS)
    if index is None:
        return []
    return _interpreter_scripts(ref.name, args[index + 1:]) or []


def _uv_run_target(args: list[str]) -> tuple[str | None, list[str], str | None]:
    """(what `uv [options] run [options] TARGET ...` runs, the words after it, uv's --directory); a target of
    None for another uv command, for a module (-m) or when nothing is named."""
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
                return None, [], None  # another uv command (uv tool run is a runner, see _runner_of)
            seen_run = True
            index += 1
            continue
        if word in ("-m", "--module"):
            return None, [], None
        name, equals, value = word.partition("=")
        takes_value = not equals and word in _UV_VALUE_OPTIONS
        if name == "--directory":
            directory = value if equals else (args[index + 1] if index + 1 < len(args) else None)
        index += 2 if takes_value else 1
    if not seen_run or index >= len(args):
        return None, [], None
    return args[index], args[index + 1:], directory


def _uv_run_script(args: list[str], cwd: str | None) -> tuple[list[str], str | None]:
    """(the script, the folder it is read against) of `uv [options] run [options] SCRIPT.py` (or `... run python S`)."""
    target, rest, directory = _uv_run_target(args)
    if target is None:
        return [], None
    base = os.path.join(cwd or os.getcwd(), directory) if directory else cwd
    if _PYTHON.fullmatch(program_name(target)):
        return _script_words(rest, _PYTHON_OPTIONS), base
    if target.lower().endswith((".py", ".pyw")):
        return [target], base
    return [], None


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
    written (behind wrappers too, joined with "; "), the local script with its SHA-256 (None for each
    that does not apply), and the SHA-256 of the whole command line (command_sha256).

    A secret in a package's address is masked (masked): the pin still tells
    a changed address, and holds no token. When several files may be the
    script (an option in front of it is not known here: _script_words),
    "script" holds their paths joined with "; " and "script_sha256" the
    SHA-256 of their own SHA-256s, so that a change to any of them is seen.
    A script that is a folder, or a name without its ending, is hashed as
    the files an interpreter runs for it (_files_run). "script_sha256" is
    None when nothing could be hashed: unhashed_code says so in words.
    """
    packages = "; ".join(_pinned_package(ref.written) for ref in runner_packages(words)) or None
    if packages is not None and len(packages) > MAX_PINNED_PACKAGE_CHARS:
        packages = "sha256:" + hashlib.sha256(packages.encode("utf-8", "surrogatepass")).hexdigest()
    script, script_sha256 = _pinned_scripts(launch_targets(executable, words, cwd))
    program = os.path.abspath(executable)
    if len(program) > MAX_PATH_CHARS:  # longer than a pins file keeps
        program = "sha256:" + hashlib.sha256(program.encode("utf-8", "surrogatepass")).hexdigest()
    return {
        "executable": program,
        "package": packages,
        "script": script,
        "script_sha256": script_sha256,
        "command_sha256": command_sha256(executable, words),
    }


def _pinned_package(written: str) -> str:
    """A runner's package as a pin keeps it: as written with its secrets masked, or the SHA-256 of a text too
    long to be a real one (never the text itself, which may hold a secret)."""
    if len(written) <= MAX_QUOTED_CHARS:
        return masked(written)
    return "sha256:" + hashlib.sha256(written.encode("utf-8", "surrogatepass")).hexdigest()


def command_sha256(executable: str, words: list[str]) -> str:
    """The SHA-256 that stands for a whole launch command in a server's pin.

    Taken of the program found and of every argument as written, so that
    any change of the launch is a change: another module after -m, another
    image, a registry option, a second script. Secrets are masked first
    (masked), so that a new token is no change of the launch. That is done
    for the first MAX_LINTED_CHARS characters of the arguments, more than a
    real command line has; what lies beyond is hashed as it is written.
    """
    digest = hashlib.sha256()
    left = MAX_LINTED_CHARS
    for word in (os.path.normcase(os.path.abspath(executable)), *words[1:]):
        if len(word) <= left:
            left -= len(word)
            word = masked(word)
        else:
            left = 0
        digest.update(word.encode("utf-8", "surrogatepass") + b"\0")
    return digest.hexdigest()


def unhashed_code(launch: dict[str, str | None]) -> str | None:
    """What to tell the operator when a server's pin (LAUNCH_FIELDS) holds the SHA-256 of none of the server's
    code; None when it holds one, or pins a runner's package by its spec."""
    if launch.get("script_sha256"):
        return None
    script = launch.get("script")
    if script:
        return (f"the script {printable(script, limit=300)} could not be hashed (it is missing, a folder with no "
                f"file an interpreter runs, unreadable, or larger than {MAX_HASHED_BYTES} bytes), so only its path "
                "is pinned: a change to the server's code will not be seen")
    if launch.get("package"):
        return None
    return ("this launch names no local script (it runs a module, a container image, a command string or a "
            "program that another program finds), so only the program and the command line are pinned: a change "
            "to the server's code will not be seen unless it changes the command line (an image's digest does, "
            "a module's files or an image behind a tag do not)")


def _package_main(path: str) -> str | None:
    """The "main" of a package.json (at most MAX_PACKAGE_JSON_BYTES), or None when it has none that can be read."""
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > MAX_PACKAGE_JSON_BYTES:
            return None
        with open(path, "rb") as handle:
            document = json.loads(handle.read(MAX_PACKAGE_JSON_BYTES).decode("utf-8-sig"))
    except (OSError, ValueError, RecursionError):
        return None
    main = document.get("main") if isinstance(document, dict) else None
    return main if isinstance(main, str) and 0 < len(main) <= MAX_PATH_CHARS and "\0" not in main else None


def _files_run(path: str) -> list[str]:
    """The ordinary files an interpreter may run for a script path: the file itself; for a folder, its
    __main__.py, its package.json with the "main" that names, and its index file; for a name that is no file,
    the name with a script's ending (`node dist/index` runs dist/index.js). Empty when there is none."""
    try:
        if os.path.isfile(path):
            return [path]
        if os.path.isdir(path):
            candidates = [os.path.join(path, name) for name in _FOLDER_SCRIPTS]
            main = _package_main(os.path.join(path, "package.json"))
            if main is not None:
                target = os.path.join(path, main)
                candidates += [target, *(target + ending for ending in _SCRIPT_ENDINGS),
                               os.path.join(target, "index.js")]
        else:
            candidates = [path + ending for ending in _SCRIPT_ENDINGS]
        return list(dict.fromkeys(each for each in candidates if os.path.isfile(each)))
    except (OSError, ValueError):
        return []


def _script_sha256(path: str) -> str | None:
    """The SHA-256 pinned for one script path: the file's own, or for a folder or a name without its ending
    the SHA-256 of the SHA-256s of the files run for it (_files_run); None when none of them could be hashed."""
    files = _files_run(path)
    if files == [path]:
        return file_sha256(path)
    digests = [(file_sha256(each), each[len(path):]) for each in files]
    if not any(digest for digest, _ in digests):
        return None
    combined = hashlib.sha256()
    for digest, name in digests:
        combined.update(f"{digest or '-'} {name}\n".encode("utf-8", "surrogatepass"))
    return combined.hexdigest()


def _pinned_scripts(paths: list[str]) -> tuple[str | None, str | None]:
    """The "script" and "script_sha256" pinned of the files that may be the script (see launch_identity)."""
    if not paths:
        return None, None
    digest: str | None
    if len(paths) == 1:
        script, digest = paths[0], _script_sha256(paths[0])
    else:
        script = "; ".join(paths)
        digests = [_script_sha256(path) for path in paths]
        combined = hashlib.sha256()
        for path, each in zip(paths, digests):
            combined.update(f"{each or '-'} {path}\n".encode("utf-8", "surrogatepass"))
        digest = combined.hexdigest() if any(digests) else None
    if len(script) > MAX_PATH_CHARS:  # longer than a pins file keeps: pinned by its SHA-256
        script = "sha256:" + hashlib.sha256(script.encode("utf-8", "surrogatepass")).hexdigest()
    return script, digest
