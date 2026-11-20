"""Argument matchers: the ways a policy rule can judge the value of one argument.

An entry of deny_args or allow_args names an argument and holds exactly one
matcher:

    pattern      a regular expression, matched case-insensitively
    contains     a piece of text (deny_args only), case-insensitive
    one_of       a list of exact values, case-sensitive
    starts_with  a literal beginning, case-insensitive
    ends_with    a literal ending, case-insensitive
    no_options   true: the value must not start with "-" (so it cannot be read as a command-line option)
    type         "path" with "roots", "url" with "hosts" (and "schemes", and the limits
                 max_label_length, max_path_segment_chars, max_query_chars), "email" with
                 "domains", or "command" with "classes" (and "shell"; see commands.py)

Each matcher answers the question of the list it is in:

    found_in(text)   deny_args: is this text a match? The policy asks it for
                     every text inside the argument, nested values and object
                     keys included, and for their percent-decoded spellings
                     (except the url and path matchers, which read escapes
                     themselves).
    accepts(text)    allow_args: is this the whole of an acceptable value? The
                     policy asks it for the value, or for each entry of a flat list.

A typed matcher (path, url, email) reads the value the way a program would.
When it cannot read a value with certainty (an ambiguous URL, a Windows short
name, a network path), it answers "found" in deny_args and "not accepted" in
allow_args: either way the call is refused. All checks are on the text only.
Nothing here touches the file system or the network, except that on Windows a
home folder spelled with short names (HOME=C:\\Users\\ALEXAN~1) is asked for
its long name once (_long_home_name).
"""

from __future__ import annotations

import ipaddress
import ntpath
import os
import posixpath
import re
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

from . import commands
from .policy_errors import PolicyError, did_you_mean, listed, quoted, type_name
from .textutil import percent_decoded

# The keys that choose a matcher. An entry has exactly one of them.
MATCHER_KEYS = ("pattern", "contains", "one_of", "starts_with", "ends_with", "no_options", "type")
TYPES = ("path", "url", "email", "command")
# The url matcher's limits on the parts of a URL that can carry data (all optional).
URL_LIMITS = ("max_label_length", "max_path_segment_chars", "max_query_chars")
# What each type needs, and what it may have besides.
_TYPE_REQUIRED = {"path": "roots", "url": "hosts", "email": "domains", "command": "classes"}
_TYPE_OPTIONAL = {"path": (), "url": ("schemes", *URL_LIMITS), "email": (), "command": ("shell",)}
TYPE_SETTINGS = ("roots", "hosts", "schemes", "domains", *URL_LIMITS, "classes", "shell")
# Every key an entry of deny_args or allow_args may have. Keys that suit only
# one side are accepted here and refused with a specific message by `build`
# (or, for "optional" and "action", by the policy loader).
ENTRY_KEYS = ("arg", *MATCHER_KEYS, *TYPE_SETTINGS, "optional", "action")

# ---- percent-decoding ----------------------------------------------------------

# A server decodes a percent-encoded value once. Three rounds leave room for
# values that were encoded again on the way; a value that needs more is refused.
DECODE_ROUNDS = 3

# What percent-decoding would change. Looking for it first means a text with no
# escapes in it ("100% done", or megabytes of bare "%") is not copied.
_PERCENT_ESCAPE = re.compile("%[0-9A-Fa-f]{2}")


def decoded_spellings(text: str) -> Iterator[str | None]:
    """Yield the text as written, then each round of percent-decoding it; finally None if it is still encoded.

    "file:///home/me/%2Essh/id_rsa" names the same file as the plain spelling
    to anything that treats the value as a URI, so a check must see both.
    The number of rounds is fixed, so a value encoded a thousand times over
    cannot buy a thousand rounds of work. A value that still holds an escape
    after the last round could not be checked, and the caller treats the None
    as "refuse": nothing ordinary is encoded that many times.

    Compatibility folding (NFKC) is left out on purpose: file systems do not
    apply it, and it is slow on long runs of combining marks.
    """
    yield text
    for _ in range(DECODE_ROUNDS):
        if not _PERCENT_ESCAPE.search(text):
            return
        text = percent_decoded(text)
        yield text
    if _PERCENT_ESCAPE.search(text):
        yield None


# ---- the matchers --------------------------------------------------------------

# Characters that Python's case-insensitive matching treats as "i", "s" and "k":
# dotted capital I, dotless i, long s and the Kelvin sign. A pattern for
# "acme-inc.com" would otherwise accept "acme-ınc.com", a different domain
# that anyone can register.
_CASE_LOOKALIKES = dict.fromkeys((0x0130, 0x0131, 0x017F, 0x212A), "\ufffd")


def _matches_whole_value(pattern: re.Pattern[str], text: str) -> bool:
    """True if the pattern matches the whole text, also with case look-alikes made unmatchable."""
    return bool(pattern.fullmatch(text)) and bool(pattern.fullmatch(text.translate(_CASE_LOOKALIKES)))


class Matcher:
    """One way of judging an argument's value. See the module docstring for the two questions."""

    key = ""  # the policy key that chose this matcher, such as "pattern"
    # True: in allow_args only text is acceptable, never a number or true/false.
    text_only = False
    # True: in deny_args the policy also asks found_in about each percent-decoded
    # spelling of a text (see decoded_spellings), and refuses a text still encoded
    # after the last round. A matcher that reads escapes itself turns this off.
    deny_checks_decoded = True

    def found_in(self, text: str) -> bool:
        raise NotImplementedError

    def accepts(self, text: str) -> bool:
        raise NotImplementedError

    def describe(self) -> str:
        """What the matcher checks, for the operator (validate, explain). Never shown to the agent."""
        raise NotImplementedError


@dataclass(frozen=True)
class PatternMatcher(Matcher):
    """A regular expression: found anywhere (deny), or matching the whole value (allow)."""

    pattern: re.Pattern[str]
    key = "pattern"

    def found_in(self, text: str) -> bool:
        return bool(self.pattern.search(text))

    def accepts(self, text: str) -> bool:
        # The value is matched as written, not percent-decoded: an allow pattern
        # that lists "%" on purpose ("docs/[\w%./-]+") must keep accepting
        # "docs/my%20notes.txt". An author whose tool decodes its arguments
        # should leave "%" out of the pattern.
        return _matches_whole_value(self.pattern, text)

    def describe(self) -> str:
        return f"pattern {quoted(self.pattern.pattern, limit=200)}"


# A ".." path segment, which climbs out of the folder a value starts with.
_DOT_DOT_SEGMENT = re.compile(r"(^|[\\/])\.\.([\\/]|$)")


@dataclass(frozen=True)
class LiteralMatcher(Matcher):
    """contains, starts_with or ends_with: a literal text, compared case-insensitively like a pattern.

    Each compiles to an escaped regular expression, so the case look-alike
    defence and the handling of lists stay exactly as for patterns.
    """

    kind: str  # "contains", "starts_with" or "ends_with"
    literal: str
    _found: re.Pattern[str] = field(init=False, repr=False, compare=False)
    _whole: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        escaped = re.escape(self.literal)
        found, whole = {
            "contains": (escaped, f"(?s:.*){escaped}(?s:.*)"),
            "starts_with": (rf"\A{escaped}", f"{escaped}(?s:.*)"),
            "ends_with": (rf"{escaped}\Z", f"(?s:.*){escaped}"),
        }[self.kind]
        object.__setattr__(self, "_found", re.compile(found, re.IGNORECASE))
        object.__setattr__(self, "_whole", re.compile(whole, re.IGNORECASE))

    @property
    def key(self) -> str:  # type: ignore[override]
        return self.kind

    def found_in(self, text: str) -> bool:
        return bool(self._found.search(text))

    def accepts(self, text: str) -> bool:
        if not _matches_whole_value(self._whole, text):
            return False
        if self.kind == "starts_with":
            # "docs/" then "../../etc/passwd" starts with "docs/" as text but is
            # not inside docs. starts_with is text matching, so it cannot vouch
            # for such a value in any spelling; "type": "path" checks containment.
            for spelling in decoded_spellings(text):
                if spelling is None or _DOT_DOT_SEGMENT.search(spelling):
                    return False
        return True

    def describe(self) -> str:
        return f"{self.kind.replace('_', ' ')} {quoted(self.literal, limit=200)}"


@dataclass(frozen=True)
class OneOfMatcher(Matcher):
    """A list of exact values. Case-sensitive, unlike patterns: "Main" is not "main"."""

    values: frozenset[str]
    key = "one_of"

    def found_in(self, text: str) -> bool:
        return text in self.values

    def accepts(self, text: str) -> bool:
        return text in self.values

    def describe(self) -> str:
        return f"one of {', '.join(quoted(value) for value in sorted(self.values))}"


@dataclass(frozen=True)
class NoOptionsMatcher(Matcher):
    """The value must not start with "-", where a program would read it as an option ("--output=...")."""

    key = "no_options"

    def found_in(self, text: str) -> bool:
        # Leading spaces are skipped: a program that trims its arguments sees the dash.
        return text.lstrip().startswith("-")

    def accepts(self, text: str) -> bool:
        return not self.found_in(text)

    def describe(self) -> str:
        return "no value that starts with '-'"


# ---- paths ----------------------------------------------------------------------

# Longer values are refused rather than read: no ordinary path is this long.
MAX_PATH_CHARS = 4096
# A component of a Windows short (8.3) name, such as "PROGRA~1" or "ID_ED2~1".
# Windows opens the long name it stands for, which text rules cannot see.
_SHORT_NAME = re.compile(r"~[0-9]")
# Names Windows opens as devices, in any folder and with any extension.
_DEVICE_NAMES = frozenset(
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"]
    + [f"{device}{suffix}" for device in ("COM", "LPT") for suffix in "0123456789\u00b9\u00b2\u00b3"]
)
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_WINDOWS_DRIVE_URI_PATH = re.compile(r"/[A-Za-z]:")

# Folders that every system has under a second name, with no link the agent
# made: through them a value reaches a root without naming it. Windows keeps
# junctions for programs written for XP, in every profile (C:\Users\Default
# is copied for each new user), in ProgramData and in Documents. Each is (the
# alias, what it leads to), in lowercase as deny_args compares. A name used
# for more than one junction ("Application Data", "Start Menu", "Templates")
# is read each way; a reading that names no real folder can only add blocks.
_WINDOWS_ALIASES = (
    # The drive and C:\Users.
    ("\\documents and settings\\", "\\users\\"),
    ("\\users\\all users\\", "\\programdata\\"),
    ("\\users\\default user\\", "\\users\\default\\"),
    # A profile.
    ("\\application data\\", "\\appdata\\roaming\\"),
    ("\\cookies\\", "\\appdata\\local\\microsoft\\windows\\inetcookies\\"),
    ("\\local settings\\", "\\appdata\\local\\"),
    ("\\my documents\\", "\\documents\\"),
    ("\\nethood\\", "\\appdata\\roaming\\microsoft\\windows\\network shortcuts\\"),
    ("\\printhood\\", "\\appdata\\roaming\\microsoft\\windows\\printer shortcuts\\"),
    ("\\recent\\", "\\appdata\\roaming\\microsoft\\windows\\recent\\"),
    ("\\sendto\\", "\\appdata\\roaming\\microsoft\\windows\\sendto\\"),
    ("\\start menu\\", "\\appdata\\roaming\\microsoft\\windows\\start menu\\"),
    ("\\templates\\", "\\appdata\\roaming\\microsoft\\windows\\templates\\"),
    # Documents, a profile's or Public's.
    ("\\documents\\my music\\", "\\music\\"),
    ("\\documents\\my pictures\\", "\\pictures\\"),
    ("\\documents\\my videos\\", "\\videos\\"),
    # AppData\Local and ProgramData, where "Application Data" leads to the folder that holds it.
    ("\\application data\\", "\\"),
    ("\\appdata\\local\\history\\", "\\appdata\\local\\microsoft\\windows\\history\\"),
    ("\\appdata\\local\\temporary internet files\\", "\\appdata\\local\\microsoft\\windows\\inetcache\\"),
    ("\\microsoft\\windows\\temporary internet files\\", "\\microsoft\\windows\\inetcache\\"),
    ("\\programdata\\desktop\\", "\\users\\public\\desktop\\"),
    ("\\programdata\\documents\\", "\\users\\public\\documents\\"),
    ("\\programdata\\start menu\\", "\\programdata\\microsoft\\windows\\start menu\\"),
    ("\\programdata\\templates\\", "\\programdata\\microsoft\\windows\\templates\\"),
)
# The real Start Menu, Recent, SendTo and Templates folders are in a
# Microsoft\Windows folder: a name there is the folder itself, not an alias
# (and reading it as one would never end, as the target holds the name again).
# Each is (the alias, a pattern for it outside Microsoft\Windows, the target).
# The pattern looks back from the end of the alias, so that it starts with the
# alias's own text, which the regex engine searches for quickly.
_WINDOWS_ALIAS_PATTERNS = tuple(
    (alias, re.compile(re.escape(alias) + "(?<!" + re.escape("\\microsoft\\windows" + alias) + ")"), target)
    for alias, target in _WINDOWS_ALIASES
)
# How many alias readings one value may have, and how many characters its
# readings may have in all (each reading is searched for every alias). Every
# spelling of the value and both readings of "~/" count against the same
# budget. A real path has a few readings of a few hundred characters at most
# (24 readings for the longest chain of real junctions); a value that needs
# more is denied rather than read in part.
_MAX_ALIAS_READINGS = 32
_MAX_ALIAS_CHARS = 16 * 1024
# On Linux, /proc/<process>/root, cwd, fd ... lead into another process's view of
# the files (/dev/fd is /proc/self/fd), where a root can be reached by any name.
# A path through them cannot be read with certainty.
_PROC_LINKS = re.compile(r"(?:^|/)(?:proc/[^/]+(?:/task/[^/]+)?/(?:root|cwd|fd|fdinfo|map_files|exe)|dev/fd)(?:/|$)")
# On macOS, /etc, /tmp and /var are links into /private.
_MACOS_PRIVATE = ("etc", "tmp", "var")
# Spellings that a shell, os.path.expandvars or a Windows program replaces before it
# opens the file: $NAME, ${...} and $(...), and %NAME% (cmd). A lone "$" is not one.
_SHELL_VARIABLE = re.compile(r"\$[A-Za-z_{(]")
# "%" then a name then "%", looked for at every "%" (the lookahead lets them overlap).
_PERCENT_VARIABLE = re.compile(r"%(?=([A-Za-z_][^%\\/\"<>|*?\r\n]{0,63})%)")
# cmd's batch parameters: %~dp0, %~f1, %*, and %0 to %9 when no hex digit follows (%2e is a percent escape).
_BATCH_PARAMETER = re.compile(r"%~|%[0-9*](?![0-9A-Fa-f])")
# cmd's delayed expansion: !NAME!.
_DELAYED_VARIABLE = re.compile(r"!(?=[A-Za-z_][^!\\/\"<>|*?\r\n]{0,63}!)")
# Two hex digits between "%" signs are a percent escape ("caf%C3%A9"), not a variable.
_HEX_PAIR = re.compile(r"[0-9A-Fa-f]{2}")
# MSYS2, Git Bash and Cygwin spellings of a Windows drive: "/c/Users", "/cygdrive/c", "/mnt/c".
# On Windows such a path is never meant as written: those tools turn it into C:\Users.
_MSYS_DRIVE = re.compile(r"/(cygdrive(/|$)|mnt/[A-Za-z](/|$)|[A-Za-z](/|$))")


def _names_a_variable(path: str) -> bool:
    """True if the path holds $NAME, ${...}, $(...), %NAME%, %~dp0, %1 or !NAME!, which some tools expand."""
    if _SHELL_VARIABLE.search(path) or _BATCH_PARAMETER.search(path) or _DELAYED_VARIABLE.search(path):
        return True
    return any(not _HEX_PAIR.fullmatch(found.group(1)) for found in _PERCENT_VARIABLE.finditer(path))


class _Unreadable(Exception):
    """A path that cannot be read with certainty. The message says why, for an error about a root."""


class _AliasBudget:
    """The alias readings of one value searched so far, against _MAX_ALIAS_READINGS and _MAX_ALIAS_CHARS.

    One budget serves all of a value's readings, so a value with several
    spellings, or one starting with "~/", cannot buy a fresh budget for each.
    """

    def __init__(self) -> None:
        self.readings = 0
        self.chars = 0

    def spend(self, reading: str) -> None:
        """Count one more reading to search, or raise _Unreadable past the budget."""
        self.readings += 1
        self.chars += len(reading)
        if self.readings > _MAX_ALIAS_READINGS:
            raise _Unreadable("it goes through more of the system's folder aliases than are followed")
        if self.chars > _MAX_ALIAS_CHARS:
            raise _Unreadable("it is too long to read through all of the system's folder aliases")


def _home_folder() -> str:
    return _long_home_name(os.path.expanduser("~"))


# The long forms of home folders spelled with short names, once found.
_LONG_HOME_NAMES: dict[str, str] = {}


def _long_home_name(path: str) -> str:
    """On Windows, the long form of a home folder spelled with short (8.3) names; otherwise the path itself.

    HOME or USERPROFILE can be set to "C:\\Users\\ALEXAN~1". The home folder is
    chosen by the person running agent-sentinel, not by the agent, so here (and
    only here) the system is asked for its long name (GetLongPathNameW, which
    follows no link), and "~/.ssh" stays a usable root. A value an agent sends
    is never read this way: its short names are refused. When the system cannot
    say (no such folder), the path is kept, and a root under it is refused as before.
    """
    if os.name != "nt" or not _SHORT_NAME.search(path) or len(path) > MAX_PATH_CHARS:
        return path
    known = _LONG_HOME_NAMES.get(path)
    if known is not None:
        return known
    try:
        import ctypes

        get_long_path_name = ctypes.WinDLL("kernel32").GetLongPathNameW
        get_long_path_name.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
        get_long_path_name.restype = ctypes.c_uint32
        buffer = ctypes.create_unicode_buffer(MAX_PATH_CHARS + 1)
        length = get_long_path_name(path, buffer, len(buffer))
    except (AttributeError, OSError, ValueError):
        return path
    if not 0 < length < len(buffer) or _SHORT_NAME.search(buffer.value):
        return path
    if len(_LONG_HOME_NAMES) < 8:
        _LONG_HOME_NAMES[path] = buffer.value
    return buffer.value


@dataclass(frozen=True)
class PathMatcher(Matcher):
    """"type": "path": the value, read as a path, is inside one of the roots.

    Lexical only: the path is made absolute and normalised as text ("a/../b"
    becomes "b"), then compared with each root component by component, never
    as a plain prefix ("C:/work/app2" is not inside "C:/work/app"). Symbolic
    links and junctions are not followed, so a link inside a root can still
    lead out of it, and a link elsewhere into it. deny_args does know the
    second names the system itself gives some folders (_WINDOWS_ALIASES, such
    as "C:\\Documents and Settings" for "C:\\Users" and "~\\Start Menu" for
    the Start Menu in AppData; "/private/etc" on macOS).

    A value is refused (allow_args) or denied (deny_args) when it cannot be
    read with certainty: a Windows short name ("SSH~1"), an alternate data
    stream ("a.txt:secret"), a "\\\\?\\" or "\\\\.\\" path, a network (UNC) path, a
    device name (CON, NUL, COM1...), a name ending in a dot or a space,
    wildcards, control characters, "~user", a path through /proc/<process>/root,
    cwd or fd or through /dev/fd, or more than MAX_PATH_CHARS characters. So is
    one that names an environment variable ($HOME, ${HOME}, $(cmd), %USERPROFILE%;
    a tool that expands it opens another file), and on Windows an MSYS or Cygwin
    spelling of a drive ("/c/Users", "/cygdrive/c", "/mnt/c").
    deny_args also denies a value with more alias readings than _MAX_ALIAS_READINGS,
    or with readings longer than _MAX_ALIAS_CHARS characters in all, counted
    over all of its spellings and readings together.

    Readings. A value starting with "~/" is read as the home folder, as most
    tools read it; deny_args also checks it as a folder named "~". A "file:"
    URI is read as the path it names. In allow_args, the value and each of its
    percent-decoded spellings must be inside a root, because a tool may decode
    it; deny_args denies the value if any of its spellings is in a root.

    Case. On Windows, ASCII letters compare without case (as the file system
    does); other letters must match exactly. Elsewhere, case matters in
    allow_args. deny_args ignores case everywhere, which can only add blocks.
    """

    roots: tuple[str, ...]  # canonical, as made by `for_roots`
    # For tests: the path rules of another system, and fixed folders. Defaults are this machine's.
    flavour: ModuleType = field(default=os.path, repr=False)
    current_folder: Callable[[], str] = field(default=os.getcwd, repr=False, compare=False)
    home_folder: Callable[[], str] = field(default=_home_folder, repr=False, compare=False)
    key = "type"
    text_only = True
    # found_in reads the percent-decoded spellings itself, so that they all
    # spend from one alias budget (see _AliasBudget).
    deny_checks_decoded = False

    @classmethod
    def for_roots(
        cls,
        entries: Any,
        where: str = "roots",
        flavour: ModuleType = os.path,
        current_folder: Callable[[], str] = os.getcwd,
        home_folder: Callable[[], str] = _home_folder,
    ) -> "PathMatcher":
        """Check the "roots" of a policy entry and make the matcher.

        A root is an absolute path, or a path starting with "~/" (the home
        folder of whoever loads the policy). It must pass the same checks as a
        value, and is made canonical once, here.
        """
        checker = cls((), flavour=flavour, current_folder=current_folder, home_folder=home_folder)
        roots = []
        for entry in _text_list(entries, f"{where}: 'roots'"):
            expanded = home_folder() + entry[1:] if checker._starts_with_home(entry) else entry
            if flavour is ntpath:
                is_absolute = bool(re.match(r"[A-Za-z]:[\\/]", expanded)) or expanded.startswith(("\\\\", "//"))
            else:
                is_absolute = expanded.startswith("/")
            if not is_absolute:
                raise PolicyError(f"{where}: the root {quoted(entry)} must be an absolute path, or start with ~/")
            try:
                roots.append(checker._absolute(expanded, expand_home=False))
            except _Unreadable as exc:
                raise PolicyError(f"{where}: the root {quoted(entry)} cannot be used: {exc}") from None
        return cls(tuple(roots), flavour=flavour, current_folder=current_folder, home_folder=home_folder)

    @property
    def _windows(self) -> bool:
        return self.flavour is ntpath

    # ---- the two questions ----------------------------------------------------

    def accepts(self, text: str) -> bool:
        try:
            readings = [self._absolute(reading, expand_home=True)
                        for spelling in decoded_spellings(text) for reading in self._paths_in(spelling)]
        except _Unreadable:
            return False
        roots = [self._allow_key(root) for root in self.roots]
        return all(any(self._inside(self._allow_key(path), root) for root in roots) for path in readings)

    def found_in(self, text: str) -> bool:
        budget = _AliasBudget()  # one for the whole value: every spelling and reading spends from it
        try:
            readings = [self._absolute(reading, expand_home=expand)
                        for spelling in decoded_spellings(text)
                        for reading in self._paths_in(spelling)
                        for expand in ((True, False) if self._starts_with_home(reading) else (False,))]
            names = [name for path in readings for name in self._other_names(path.casefold(), budget)]
        except _Unreadable:
            return True
        roots = [root.casefold() for root in self.roots]
        return any(self._inside(name, root) for name in names for root in roots)

    def describe(self) -> str:
        return f"a path inside {', '.join(quoted(root, limit=200) for root in self.roots)}"

    # ---- reading a value --------------------------------------------------------

    def _paths_in(self, spelling: str | None) -> list[str]:
        """The path a spelling stands for: itself, or the path of a "file:" URI."""
        if spelling is None:
            raise _Unreadable("it is still percent-encoded after several rounds of decoding")
        if spelling[:5].lower() != "file:":
            return [spelling]
        try:
            parts = urlsplit(spelling)
        except ValueError as exc:
            raise _Unreadable("it is not a valid file URI") from exc
        if parts.netloc.lower() not in ("", "localhost"):
            raise _Unreadable("it is a file URI on another computer")
        if "?" in spelling or "#" in spelling or not parts.path:
            raise _Unreadable("it is a file URI with a query or fragment, or no path")
        path = parts.path
        if self._windows and _WINDOWS_DRIVE_URI_PATH.match(path):
            path = path[1:]  # file:///C:/x names C:/x
        return [path]

    def _starts_with_home(self, path: str) -> bool:
        separators = "/\\" if self._windows else "/"
        return path == "~" or (path.startswith("~") and path[1] in separators)

    def _absolute(self, path: str, expand_home: bool) -> str:
        """The absolute, normalised form of a path, or _Unreadable."""
        if len(path) <= MAX_PATH_CHARS and _names_a_variable(path):
            # A tool that expands it opens another file than the text names ("%USERPROFILE%\\.ssh").
            raise _Unreadable("it names an environment variable ($NAME, ${...}, $(...) or %NAME%), which a tool "
                              "may expand")
        if self._windows and _MSYS_DRIVE.match(path):
            raise _Unreadable("on Windows, /c/..., /cygdrive/... and /mnt/c/... are MSYS or Cygwin spellings of a "
                              "drive")
        if path.startswith("~"):
            if not self._starts_with_home(path):
                raise _Unreadable("'~name' can mean another user's home folder")
            if expand_home:
                path = self.home_folder() + path[1:]
        if len(path) > MAX_PATH_CHARS:
            raise _Unreadable(f"it is longer than {MAX_PATH_CHARS} characters")
        if any(ch < " " or ch == "\x7f" for ch in path):
            raise _Unreadable("it holds a control character")
        return self._absolute_windows(path) if self._windows else self._absolute_posix(path)

    def _here(self) -> str:
        try:
            return self.current_folder()
        except OSError as exc:  # the current folder was deleted
            raise _Unreadable("the current folder is unknown") from exc

    def _absolute_windows(self, path: str) -> str:
        path = path.replace("/", "\\")
        self._refuse_device_paths(path)
        drive, rest = ntpath.splitdrive(path)
        if drive and not rest.startswith("\\"):
            # "C:name" means "name" in drive C's own current folder, which this process cannot know.
            raise _Unreadable("a drive-relative path such as C:name")
        if not drive:
            path = ntpath.join(self._here(), path)  # also gives "\name" the current drive
            self._refuse_device_paths(path)  # the current folder itself may be a network path
        drive, rest = ntpath.splitdrive(path)
        if not re.fullmatch("[A-Za-z]:", drive) or not rest.startswith("\\"):
            raise _Unreadable("it does not start with a drive letter")
        if ":" in rest:
            raise _Unreadable("an alternate data stream (a ':' after the drive)")
        if any(ch in rest for ch in '*?"<>|'):
            raise _Unreadable("wildcards or characters Windows does not allow in names")
        # Checked before ".." is resolved: Windows drops trailing dots and
        # spaces from a name, so ".. " climbs a folder although the text says otherwise.
        for name in rest.split("\\"):
            if name in ("", ".", ".."):
                continue
            if name[-1] in ". ":
                raise _Unreadable(f"the name {quoted(name)} ends in a dot or a space")
            if _SHORT_NAME.search(name):
                raise _Unreadable(f"the name {quoted(name)} looks like a short (8.3) name")
            if name.split(".")[0].rstrip(" ").upper() in _DEVICE_NAMES:
                raise _Unreadable(f"the name {quoted(name)} is a device")
        return ntpath.normpath(path)

    @staticmethod
    def _refuse_device_paths(path: str) -> None:
        """Refuse network (UNC) paths and the \\\\?\\, \\\\.\\ and \\??\\ prefixes, which skip Windows' own checks."""
        if path.startswith("\\\\") or path.startswith("\\??\\"):
            raise _Unreadable("a network (UNC) path, or a \\\\?\\, \\\\.\\ or \\??\\ device path")

    def _absolute_posix(self, path: str) -> str:
        if "\\" in path:
            # A file name may hold a backslash here, but a tool written for
            # Windows, or a shell, would read it as a separator.
            raise _Unreadable("it holds a backslash")
        if "*" in path or "?" in path:
            raise _Unreadable("it holds wildcards")
        if not path.startswith("/"):
            path = posixpath.join(self._here(), path)
        # Looked for before and after ".." is resolved: the system resolves a ".." after following the
        # link, so "/proc/self/cwd/.." is the parent of the current folder, not "/proc/self".
        if _PROC_LINKS.search(path) or _PROC_LINKS.search(posixpath.normpath(path)):
            raise _Unreadable("it goes through /proc/<process>/root, cwd or fd, or /dev/fd, which lead elsewhere")
        path = posixpath.normpath(path)
        if path.startswith("//"):  # two leading slashes may name a network path
            raise _Unreadable("it starts with two slashes")
        return path

    # ---- comparing --------------------------------------------------------------

    def _other_names(self, path: str, budget: _AliasBudget) -> list[str]:
        """`path` (absolute, lowercase), and what it names under the system's own aliases (_WINDOWS_ALIASES, /private).

        For deny_args: "C:\\Documents and Settings\\me\\.ssh" is "C:\\Users\\me\\.ssh",
        and on macOS "/private/etc" is "/etc". Extra readings can only add blocks.
        The work is bounded: each reading searched is spent from `budget`, the
        value's own, and past it the value is _Unreadable.
        """
        if not self._windows:
            parts = path.split("/")
            if len(parts) > 2 and parts[1] == "private" and parts[2] in _MACOS_PRIVATE:
                return [path, "/" + "/".join(parts[2:])]
            if len(parts) > 1 and parts[1] in _MACOS_PRIVATE:
                return [path, "/private" + path]
            return [path]
        names = [path]
        seen = {path}
        for name in names:  # grows as it goes: an alias reached through another is read too
            budget.spend(name)
            padded = name + "\\"
            for alias, pattern, target in _WINDOWS_ALIAS_PATTERNS:
                if alias not in padded:
                    continue
                changed = pattern.sub(lambda _: target, padded)
                if changed == padded:  # the name is only there as the real folder, in Microsoft\Windows
                    continue
                other = ntpath.normpath(changed)
                if other not in seen:
                    names.append(other)
                    seen.add(other)
        return names

    def _allow_key(self, path: str) -> str:
        return path.translate(_ASCII_LOWER) if self._windows else path

    def _inside(self, path: str, root: str) -> bool:
        """True if `path` is `root` or below it, compared component by component."""
        try:
            return self.flavour.commonpath([path, root]) == root
        except ValueError:  # another drive, or one absolute and one not
            return False


# ---- hosts: urls and e-mail addresses -------------------------------------------

MAX_URL_CHARS = 8192
MAX_EMAIL_CHARS = 254
_DNS_LABEL = re.compile(r"[a-z0-9_-]{1,63}")
# Host names that always mean this machine or a cloud metadata service. The
# url matcher never accepts them, whatever the hosts list says.
_LOCAL_NAMES = ("localhost", "metadata", "metadata.google.internal", "metadata.goog", "instance-data")
_SCHEMES_WITHOUT_HOST = ("mailto", "file", "data", "javascript", "about", "blob", "tel", "sms", "urn")
_SCHEME = re.compile(r"[a-z][a-z0-9+.-]{0,31}")
# A conservative local part: what real mailboxes use. Quoted local parts and
# the old routing characters ("%", "!") are refused.
_LOCAL_PART = re.compile(r"[A-Za-z0-9_+'-]+(\.[A-Za-z0-9_+'-]+)*")
_AUTHORITY = re.compile(r"(?P<host>\[[0-9A-Fa-f:.]+\]|[^:\[\]]+)(?::(?P<port>[0-9]{1,5}))?")

Address = ipaddress.IPv4Address | ipaddress.IPv6Address


def _is_dns_name(host: str) -> bool:
    """A lowercase ASCII host name with valid labels and no "xn--" (punycode) label."""
    if not host or len(host) > 253:
        return False
    return all(_DNS_LABEL.fullmatch(label) and not label.startswith("xn--") for label in host.split("."))


def _ends_in_a_number(host: str) -> bool:
    """True for a host a browser reads as an IPv4 address: its last label is a decimal or 0x number."""
    last = host.rsplit(".", 1)[-1]
    return last.isdigit() or (last[:2] in ("0x", "0X") and all(c in "0123456789abcdefABCDEF" for c in last[2:]))


_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")


def _embedded_ipv4(address: Address) -> list[ipaddress.IPv4Address]:
    """The IPv4 addresses an IPv6 address carries inside it (mapped, 6to4, Teredo, NAT64): the same destination."""
    if not isinstance(address, ipaddress.IPv6Address):
        return []
    inner = [address.ipv4_mapped, address.sixtofour, address.teredo[1] if address.teredo else None]
    if address in _NAT64:
        inner.append(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
    return [found for found in inner if found is not None]


def _is_public(address: Address) -> bool:
    """False for private, loopback, link-local, shared, reserved, multicast and unspecified addresses.

    This covers the cloud metadata addresses (169.254.169.254, fd00:ec2::254,
    100.100.100.200) and IPv6 forms that carry an IPv4 address inside.
    """
    if any(not _is_public(inner) for inner in _embedded_ipv4(address)):
        return False
    return address.is_global and not address.is_multicast and not address.is_reserved


def _is_local_name(host: str) -> bool:
    return host in _LOCAL_NAMES or host.endswith(".localhost")


@dataclass(frozen=True)
class _Host:
    """One entry of "hosts" or "domains": an exact name, all subdomains of a name, or an exact IP address."""

    name: str
    subdomains: bool = False
    is_address: bool = False

    def matches(self, host: str, is_address: bool) -> bool:
        if self.is_address or is_address:
            return self.is_address and is_address and host == self.name
        if self.subdomains:
            return host.endswith("." + self.name)
        return host == self.name

    def __str__(self) -> str:
        return f"*.{self.name}" if self.subdomains else self.name


def _read_address(text: str) -> Address | None:
    """An IP address written in its standard form, or None."""
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
        try:
            return ipaddress.IPv6Address(text)
        except ValueError:
            return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _host_entries(value: Any, where: str, setting: str, allow_addresses: bool, allow_side: bool) -> tuple[_Host, ...]:
    """Read a "hosts" or "domains" list.

    "example.com" is that host only. ".example.com" or "*.example.com" is
    every subdomain of it, not example.com itself: list both to have both.
    """
    entries = _text_list(value, f"{where}: '{setting}'")
    hosts = []
    for entry in entries:
        text = entry.lower()
        subdomains = text.startswith((".", "*."))
        if subdomains:
            text = text[2:] if text.startswith("*.") else text[1:]
        problem = None
        address = _read_address(text) if allow_addresses else None
        if "*" in text:
            problem = "a '*' may only start an entry, as in \"*.example.com\"; list the hosts themselves"
        elif address is not None:
            if subdomains:
                problem = "an IP address has no subdomains"
            elif allow_side and not _is_public(address):
                problem = "private, loopback, link-local and metadata addresses are never allowed"
            else:
                hosts.append(_Host(str(address), is_address=True))
                continue
        elif any(ch in text for ch in "/:@?#[]"):
            problem = "write a host name only, without a scheme, port or path"
        elif not text.isascii():
            problem = "names with non-ASCII letters are not supported; their xn-- form is refused too"
        elif not _is_dns_name(text):
            problem = "it is not a valid host name (or it has an xn-- label, which is refused)"
        elif _ends_in_a_number(text):
            problem = "it is not a valid IP address" if allow_addresses else "IP addresses are not supported here"
        elif allow_side and allow_addresses and _is_local_name(text):
            problem = "localhost and cloud metadata names are never allowed"
        if problem:
            raise PolicyError(f"{where}: the {setting} entry {quoted(entry)} cannot be used: {problem}")
        hosts.append(_Host(text, subdomains=subdomains))
    return tuple(hosts)


@dataclass(frozen=True)
class _ReadUrl:
    scheme: str
    host: str  # a lowercase name, or an IP address in its standard form
    is_address: bool
    # deny_args only: the IPv4 address an IPv6 host carries, which reaches the same machine.
    also_known_as: tuple[str, ...] = ()


def _url_to_address(scheme: str, text: str) -> _ReadUrl | None:
    address = _read_address(text)
    if address is None:
        return None
    return _ReadUrl(scheme, str(address), True, tuple(str(inner) for inner in _embedded_ipv4(address)))


def read_url(text: str) -> _ReadUrl | None:
    """The scheme and host of a URL, or None if the URL cannot be read with certainty.

    Refused: anything with spaces, control characters or a backslash (parsers
    disagree about where a host ends after a backslash), no "//host" part,
    user information ("user@host"), a "%" or a non-ASCII letter in the host,
    a bad port, and an IP address in any form but the standard one
    ("2852039166" and "0251.0376.0251.0376" are both 169.254.169.254 to a browser).
    """
    if not text or len(text) > MAX_URL_CHARS or any(ch <= " " or ch in "\x7f\\" for ch in text):
        return None
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    netloc = parts.netloc
    if not netloc or not netloc.isascii() or "@" in netloc or "%" in netloc:
        return None
    authority = _AUTHORITY.fullmatch(netloc)
    if authority is None:
        return None
    port = authority.group("port")
    if port is not None and not 0 < int(port) < 65536:
        return None
    host = authority.group("host").lower()
    if host.startswith("["):
        return _url_to_address(parts.scheme, host)
    if host.endswith("."):
        host = host[:-1]  # "example.com." is the same host written as a full name
    if _ends_in_a_number(host):
        return _url_to_address(parts.scheme, host)
    return _ReadUrl(parts.scheme, host, False) if _is_dns_name(host) else None


@dataclass(frozen=True)
class UrlMatcher(Matcher):
    """"type": "url": a URL whose scheme is allowed and whose host is listed.

    In allow_args the scheme must be in "schemes" (default only "https"), and
    localhost, cloud metadata names and private addresses are never accepted.
    In deny_args a URL is denied when its host is listed, whatever its
    scheme, or when it cannot be read. There is no DNS lookup: a listed name
    that resolves to a private address is not caught.

    Limits (each optional) keep the parts of a URL that can carry data short,
    so a fetch tool's request cannot hold much: max_label_length (each label
    of the host), max_path_segment_chars (each part of the path between "/"),
    max_query_chars (the query and the fragment together). They count the
    characters as written, escapes included. A URL over a limit is not
    accepted in allow_args and is denied in deny_args.
    """

    hosts: tuple[_Host, ...]
    schemes: tuple[str, ...] = ("https",)
    max_label_length: int | None = None
    max_path_segment_chars: int | None = None
    max_query_chars: int | None = None
    key = "type"
    text_only = True
    # deny_args reads the URL as written, not its percent-decoded spellings. A
    # URL that can be read has no escape in its scheme or host (read_url refuses
    # a "%" there), so decoding cannot change which host it names; it could only
    # turn an ordinary "%20" in the path or query into a space that read_url
    # refuses, which would deny every such URL. A URL that cannot be read is denied.
    deny_checks_decoded = False

    def accepts(self, text: str) -> bool:
        url = read_url(text)
        if url is None or url.scheme not in self.schemes or not self._within_limits(text):
            return False
        if url.is_address and not _is_public(ipaddress.ip_address(url.host)):
            return False
        if not url.is_address and _is_local_name(url.host):
            return False
        return any(host.matches(url.host, url.is_address) for host in self.hosts)

    def found_in(self, text: str) -> bool:
        url = read_url(text)
        if url is None or not self._within_limits(text):
            return True
        names = [(url.host, url.is_address), *((inner, True) for inner in url.also_known_as)]
        return any(host.matches(name, is_address) for host in self.hosts for name, is_address in names)

    def _within_limits(self, text: str) -> bool:
        """True if no part of the URL (one that read_url can read) is longer than its limit."""
        if self.max_label_length is None and self.max_path_segment_chars is None and self.max_query_chars is None:
            return True
        parts = urlsplit(text)
        host = (parts.hostname or "").rstrip(".")
        if self.max_label_length is not None and any(len(label) > self.max_label_length
                                                     for label in host.split(".")):
            return False
        if self.max_path_segment_chars is not None and any(len(segment) > self.max_path_segment_chars
                                                           for segment in parts.path.split("/")):
            return False
        return self.max_query_chars is None or len(parts.query) + len(parts.fragment) <= self.max_query_chars

    def describe(self) -> str:
        limits = [f"{name} {value}" for name, value in (("labels at most", self.max_label_length),
                                                         ("path segments at most", self.max_path_segment_chars),
                                                         ("query at most", self.max_query_chars))
                  if value is not None]
        shown = f" ({', '.join(limits)} characters)" if limits else ""
        return f"a {'/'.join(self.schemes)} URL to {', '.join(str(host) for host in self.hosts)}{shown}"


@dataclass(frozen=True)
class CommandMatcher(Matcher):
    """"type": "command": a shell command line that falls into one of `classes` (commands.py).

    In deny_args the value is denied when its command is in one of the
    classes or cannot be read; in allow_args it is accepted only when it can
    be read and is in none of them. For the Claude Code hook's Bash tool, a
    tool rule's "command" section does more (ask, allow_programs, labels).
    """

    classes: frozenset[str]
    shell: str = "bash"
    key = "type"
    text_only = True
    deny_checks_decoded = False  # a command is read as the shell reads it, not percent-decoded

    def found_in(self, text: str) -> bool:
        reading = commands.read_command(text, self.shell)
        return reading.unreadable is not None or bool(reading.kinds() & self.classes)

    def accepts(self, text: str) -> bool:
        return not self.found_in(text)

    def describe(self) -> str:
        kinds = ", ".join(kind for kind in commands.CLASSES if kind in self.classes)
        return f"a {self.shell} command in the class(es) {kinds}, or one that cannot be read"


def read_email_domain(text: str) -> str | None:
    """The domain of a single, plain e-mail address, or None.

    Only "local@domain" is read: a display name ("Bob <bob@example.com>"), a
    list of addresses, a quoted local part or an IP address as the domain is refused.
    """
    if not text or len(text) > MAX_EMAIL_CHARS or not text.isascii() or text.count("@") != 1:
        return None
    local, domain = text.split("@")
    if len(local) > 64 or not _LOCAL_PART.fullmatch(local):
        return None
    domain = domain.lower()
    if _ends_in_a_number(domain) or not _is_dns_name(domain):
        return None
    return domain


@dataclass(frozen=True)
class EmailMatcher(Matcher):
    """"type": "email": a single address whose domain is listed."""

    domains: tuple[_Host, ...]
    key = "type"
    text_only = True

    def accepts(self, text: str) -> bool:
        domain = read_email_domain(text)
        return domain is not None and any(entry.matches(domain, False) for entry in self.domains)

    def found_in(self, text: str) -> bool:
        domain = read_email_domain(text)
        return domain is None or any(entry.matches(domain, False) for entry in self.domains)

    def describe(self) -> str:
        return f"an e-mail address at {', '.join(str(domain) for domain in self.domains)}"


# ---- reading an entry of the policy ---------------------------------------------

def build(spec: dict[str, Any], where: str, deny: bool, any_arg: bool) -> Matcher:
    """Make the matcher that one deny_args (deny=True) or allow_args entry asks for.

    `spec` has already been checked for unknown keys. `any_arg` is True for
    "arg": "*", which reads every text of every argument.
    """
    present = [key for key in MATCHER_KEYS if key in spec]
    if not present:
        if any(key in spec for key in TYPE_SETTINGS):
            raise PolicyError(f"{where} has type settings but no \"type\"; add \"type\": {listed(TYPES)}")
        raise PolicyError(f"{where} needs a matcher: one of {listed(MATCHER_KEYS)}")
    if len(present) > 1:
        raise PolicyError(
            f"{where} has both {quoted(present[0])} and {quoted(present[1])}, but an entry takes exactly one "
            "matcher. To check one argument in two ways, write two entries for it"
        )
    key = present[0]
    if key != "type":
        stray = [setting for setting in TYPE_SETTINGS if setting in spec]
        if stray:
            raise PolicyError(f"{where}: {quoted(stray[0])} goes with \"type\", not with {quoted(key)}")
    value = spec[key]
    if key == "pattern":
        return _pattern(value, where)
    if key == "contains":
        if not deny:
            raise PolicyError(
                f"{where}: 'contains' is only used in deny_args. In allow_args the whole value must be "
                "acceptable; use 'one_of', 'starts_with', 'ends_with', 'pattern' or a 'type'"
            )
        return LiteralMatcher("contains", _literal(value, where, key))
    if key in ("starts_with", "ends_with"):
        return LiteralMatcher(key, _literal(value, where, key))
    if key == "one_of":
        return OneOfMatcher(frozenset(_text_list(value, f"{where}: 'one_of'", allow_empty_text=True)))
    if key == "no_options":
        if value is not True:
            raise PolicyError(
                f"{where}: 'no_options' must be true (to drop the check, remove the key), got {quoted(value)}"
            )
        return NoOptionsMatcher()
    return _typed(spec, where, deny, any_arg)


def _typed(spec: dict[str, Any], where: str, deny: bool, any_arg: bool) -> Matcher:
    kind = spec["type"]
    if not isinstance(kind, str) or kind not in TYPES:
        hint = did_you_mean(kind, TYPES)
        raise PolicyError(f"{where}: 'type' must be {listed(TYPES)}, got {quoted(kind)}"
                          + (f"; did you mean {quoted(hint)}?" if hint else ""))
    if any_arg:
        raise PolicyError(
            f"{where}: a \"type\" matcher needs a named argument. With \"arg\": \"*\" it would read every "
            f"value of every argument as a {kind}"
        )
    for setting in TYPE_SETTINGS:
        if setting in spec and setting != _TYPE_REQUIRED[kind] and setting not in _TYPE_OPTIONAL[kind]:
            owner = next(name for name in TYPES if setting == _TYPE_REQUIRED[name] or setting in _TYPE_OPTIONAL[name])
            raise PolicyError(f"{where}: {quoted(setting)} goes with \"type\": {quoted(owner)}, not {quoted(kind)}")
    required = _TYPE_REQUIRED[kind]
    if required not in spec:
        raise PolicyError(f"{where}: \"type\": {quoted(kind)} needs {quoted(required)}")
    if kind == "path":
        return PathMatcher.for_roots(spec["roots"], where)
    if kind == "email":
        domains = _host_entries(spec["domains"], where, "domains", allow_addresses=False, allow_side=not deny)
        return EmailMatcher(domains)
    if kind == "command":
        return CommandMatcher(command_classes(spec["classes"], f"{where}: 'classes'"),
                              command_shell(spec.get("shell", "bash"), f"{where}: 'shell'"))
    if "schemes" in spec and deny:
        raise PolicyError(
            f"{where}: 'schemes' is only used in allow_args; deny_args denies a listed host whatever its scheme"
        )
    hosts = _host_entries(spec["hosts"], where, "hosts", allow_addresses=True, allow_side=not deny)
    limits = {name: _url_limit(spec[name], f"{where}: {quoted(name)}", 63 if name == "max_label_length"
                               else MAX_URL_CHARS)
              for name in URL_LIMITS if name in spec}
    return UrlMatcher(hosts, _schemes(spec.get("schemes", ["https"]), where), **limits)


def _url_limit(value: Any, what: str, most: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= most:
        raise PolicyError(f"{what} must be a whole number from 1 to {most}, got {quoted(value)}")
    return value


def command_classes(value: Any, what: str, allow_empty: bool = False) -> frozenset[str]:
    """A list of command classes (commands.CLASSES), each named once."""
    if not isinstance(value, list) or (not value and not allow_empty):
        raise PolicyError(f"{what} must be a list of command classes ({', '.join(commands.CLASSES)}), "
                          f"got {quoted(value)}")
    seen: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or entry not in commands.CLASSES:
            hint = did_you_mean(entry, commands.CLASSES)
            raise PolicyError(f"{what}: {quoted(entry)} is not a command class; the classes are "
                              f"{listed(commands.CLASSES)}" + (f"; did you mean {quoted(hint)}?" if hint else ""))
        if entry in seen:
            raise PolicyError(f"{what}: {quoted(entry)} is listed twice")
        seen.append(entry)
    return frozenset(seen)


def command_shell(value: Any, what: str) -> str:
    if not isinstance(value, str) or value not in commands.SHELLS:
        hint = did_you_mean(value, commands.SHELLS)
        raise PolicyError(f"{what} must be {listed(commands.SHELLS)}, got {quoted(value)}"
                          + (f"; did you mean {quoted(hint)}?" if hint else ""))
    return value


def _pattern(value: Any, where: str) -> PatternMatcher:
    if not isinstance(value, str):
        raise PolicyError(f"{where}: 'pattern' must be text, got {type_name(value)}")
    try:
        # Patterns are not stripped or checked for edge spaces: "rm -rf " is a legitimate pattern.
        return PatternMatcher(re.compile(value, re.IGNORECASE))
    except re.error as exc:
        raise PolicyError(f"{where}: bad pattern {quoted(value)} ({exc})") from exc


def _literal(value: Any, where: str, key: str) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyError(f"{where}: {quoted(key)} must be text that is not empty, got {quoted(value)}")
    return value


def _text_list(value: Any, what: str, allow_empty_text: bool = False) -> list[str]:
    """A list of one or more texts; numbers are refused with a hint, because values are compared as text."""
    if not isinstance(value, list) or not value:
        raise PolicyError(f"{what} must be a list with at least one entry, got {quoted(value)}")
    for entry in value:
        if not isinstance(entry, str):
            raise PolicyError(
                f"{what}: each entry must be text in double quotes (write 5 as \"5\"), got {quoted(entry)}"
            )
        if not allow_empty_text and (not entry or entry != entry.strip()):
            raise PolicyError(f"{what}: entry {quoted(entry)} must not be empty or have spaces around it")
    return value


def _schemes(value: Any, where: str) -> tuple[str, ...]:
    schemes = []
    for entry in _text_list(value, f"{where}: 'schemes'"):
        scheme = entry.lower().rstrip(":/")
        if not _SCHEME.fullmatch(scheme):
            raise PolicyError(f"{where}: the scheme {quoted(entry)} is not a URL scheme such as \"https\"")
        if scheme in _SCHEMES_WITHOUT_HOST:
            raise PolicyError(
                f"{where}: the scheme {quoted(entry)} has no host for the url matcher to check; "
                "for e-mail addresses use \"type\": \"email\", for files \"type\": \"path\""
            )
        schemes.append(scheme)
    return tuple(dict.fromkeys(schemes))
