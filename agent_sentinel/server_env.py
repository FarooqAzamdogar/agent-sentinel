"""The environment variables the MCP server is started with (proxy --clean-env, --pass-env, --env-file).

By default the server inherits every environment variable the proxy has, as
any program does. A server, or an agent that has taken over one of its tools
(a shell, a file reader that can open /proc/<pid>/environ), can read them all:
cloud keys, tokens, passwords. So:

* --clean-env starts the server with only what the operating system needs to
  start a program (MINIMAL_WINDOWS or MINIMAL_POSIX), plus
* --pass-env NAME for each variable the server needs (NAME may end in "*" to
  pass every variable whose name starts with what comes before it), and
* --env-file FILE, whose NAME=VALUE lines are added to the server's
  environment (see read_env_file), with or without --clean-env.

MCP clients built on the official SDKs already start a stdio server (here,
the proxy) with a short list of variables plus those configured for it, so
--clean-env matters most when the proxy is started from a shell, a script or
CI, or by a client that passes on its whole environment.

Whatever the mode, the proxy warns at startup about the variables the server
gets whose names look like secrets (looks_secret) and that no --pass-env or
--env-file named. Names are printed; values never are, not in warnings and
not in error messages.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable, Mapping

# What a program needs to start and run normally, and nothing that is usually secret.
MINIMAL_WINDOWS = (
    "ALLUSERSPROFILE", "APPDATA", "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)", "COMMONPROGRAMW6432",
    "COMPUTERNAME", "COMSPEC",
    "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "NUMBER_OF_PROCESSORS", "OS", "PATH", "PATHEXT",
    "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
    "PROGRAMW6432", "PUBLIC", "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP", "USERDOMAIN", "USERNAME",
    "USERPROFILE", "WINDIR",
)
MINIMAL_POSIX = ("HOME", "LANG", "LANGUAGE", "LC_*", "LOGNAME", "PATH", "SHELL", "TERM", "TMPDIR", "TZ", "USER")

# Keeps cmd.exe, and whatever the server starts, from running a file in the
# current folder in place of a command of the same name on PATH (Windows).
NO_CURRENT_FOLDER_LOOKUP = ("NoDefaultCurrentDirectoryInExePath", "1")

MAX_ENV_FILE_BYTES = 1024 * 1024
MAX_ENV_FILE_ENTRIES = 1000
MAX_VALUE_CHARS = 32767  # what Windows allows for one variable

# A variable name as an env file or --pass-env writes it. --pass-env may end it in "*".
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,255}")
_PASS_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,255}\*?")

# Words that, as a whole part of a variable's name, say that its value is a secret (or,
# for SSH_AUTH_SOCK, a way to use one): GITHUB_TOKEN, OPENAI_API_KEY, DB_PASSWORD,
# AWS_SECRET_ACCESS_KEY, GITHUB_PAT, SENTRY_DSN.
_SECRET_WORDS = frozenset((
    "TOKEN", "TOKENS", "SECRET", "SECRETS", "CREDENTIAL", "CREDENTIALS", "KEY", "KEYS", "APIKEY", "PAT", "AUTH",
    "COOKIE", "DSN",
))
# These mean a secret even inside a longer word, as in PGPASSWORD. (PWD does not: on
# POSIX it is the current folder, so MYSQL_PWD is not recognised.)
_SECRET_INSIDE_WORDS = ("PASSWORD", "PASSWD", "PASSPHRASE")
_NAME_PARTS = re.compile(r"[A-Z][a-z0-9]+|[A-Z0-9]+(?![a-z])|[a-z0-9]+")


class EnvFileError(ValueError):
    """An env file that cannot be used. The message says where, and never shows a value."""


def check_pass_name(text: str) -> str:
    """A --pass-env argument: a variable name, or a name prefix ending in "*". Raises ValueError otherwise."""
    if not _PASS_NAME.fullmatch(text):
        if text.strip() == "*":
            raise ValueError("'*' would pass every variable; leave out --clean-env instead")
        raise ValueError("write a variable name (letters, digits and _, not starting with a digit), "
                         "optionally ending in * to pass every variable that starts with it")
    return text


def read_env_file(path: str | Path) -> dict[str, str]:
    """Read NAME=VALUE lines. Raises EnvFileError (or OSError if the file cannot be read).

    * Blank lines and lines whose first non-space character is "#" are skipped.
    * NAME is letters, digits and "_", not starting with a digit, with nothing
      around it. Each name may be set once.
    * VALUE is everything after the first "=", as written; a value wrapped in a
      matching pair of double or single quotes loses them. Nothing else is
      interpreted: no escapes, no "${...}", no "export" in front.
    * The file is UTF-8, at most MAX_ENV_FILE_BYTES; a value has no NUL
      character and at most MAX_VALUE_CHARS characters.
    Errors give the line number, never the line, since it may hold a secret.
    """
    path = Path(path)
    if path.stat().st_size > MAX_ENV_FILE_BYTES:
        raise EnvFileError(f"{path}: the env file is larger than {MAX_ENV_FILE_BYTES} bytes")
    try:
        text = path.read_bytes().decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise EnvFileError(f"{path}: the env file is not UTF-8 text") from exc
    values: dict[str, str] = {}
    first_line: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, equals, value = line.partition("=")
        where = f"{path}, line {number}"
        if not equals:
            raise EnvFileError(f"{where}: expected NAME=VALUE")
        if not _NAME.fullmatch(name):
            raise EnvFileError(f"{where}: the text before '=' is not a variable name (letters, digits and _, "
                               "not starting with a digit, with no spaces or 'export' around it)")
        if name in first_line:
            raise EnvFileError(f"{where}: {name} is already set on line {first_line[name]}")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if "\x00" in value or len(value) > MAX_VALUE_CHARS:
            raise EnvFileError(f"{where}: the value of {name} has a NUL character or is too long")
        if len(values) >= MAX_ENV_FILE_ENTRIES:
            raise EnvFileError(f"{where}: an env file may set at most {MAX_ENV_FILE_ENTRIES} variables")
        values[name] = value
        first_line[name] = number
    return values


def server_environment(
    inherited: Mapping[str, str],
    clean: bool,
    pass_names: Iterable[str] = (),
    added: Mapping[str, str] | None = None,
    windows: bool = sys.platform == "win32",
) -> dict[str, str]:
    """The environment to start the server with.

    inherited:  the proxy's own environment (os.environ).
    clean:      True for --clean-env: keep only the minimal variables and those pass_names name.
    pass_names: --pass-env names or "PREFIX*" patterns; without `clean` they change nothing.
    added:      the variables of an env file; they win over inherited ones of the same name.
    windows:    names are compared ignoring case, as Windows does.
    """
    if clean:
        wanted = [*(MINIMAL_WINDOWS if windows else MINIMAL_POSIX), *pass_names]
        environment = {name: value for name, value in inherited.items() if _named(name, wanted, windows)}
    else:
        environment = dict(inherited)
    for name, value in (added or {}).items():
        _put(environment, name, value, windows)
    if windows:
        _put(environment, *NO_CURRENT_FOLDER_LOOKUP, windows)
    return environment


def missing_names(inherited: Mapping[str, str], pass_names: Iterable[str], windows: bool = sys.platform == "win32"
                  ) -> list[str]:
    """The --pass-env names (not patterns) that the proxy's own environment does not have."""
    return [
        name for name in pass_names
        if not name.endswith("*") and not any(_named(have, [name], windows) for have in inherited)
    ]


def looks_secret(name: str) -> bool:
    """Whether a variable's name says that its value is a secret: one of its words is TOKEN, KEY, AUTH, ...,
    or it has PASSWORD, PASSWD or PASSPHRASE anywhere in it.

    Names are split into words at "_" and where lower case turns to upper
    case, so GITHUB_TOKEN, githubToken, OPENAI_API_KEY and PGPASSWORD look
    secret; KEYBOARD_LAYOUT, TOKENIZERS_PARALLELISM, GIT_AUTHOR_NAME and PATH do not.
    """
    upper = name.upper()
    if any(word in upper for word in _SECRET_INSIDE_WORDS):
        return True
    return any(part.upper() in _SECRET_WORDS for part in _NAME_PARTS.findall(name))


def named_variables(
    environment: Mapping[str, str], pass_names: Iterable[str] = (), added: Iterable[str] = (),
    windows: bool = sys.platform == "win32",
) -> list[str]:
    """The names in `environment` that --pass-env or the env file named, sorted."""
    named = [*pass_names, *added]
    return sorted(name for name in environment if _named(name, named, windows))


def unnamed_secrets(
    environment: Mapping[str, str], pass_names: Iterable[str] = (), added: Iterable[str] = (),
    windows: bool = sys.platform == "win32",
) -> list[str]:
    """The names in `environment` that look secret and were not named by --pass-env or the env file, sorted."""
    named = [*pass_names, *added]
    return sorted(name for name in environment if looks_secret(name) and not _named(name, named, windows))


def _named(name: str, patterns: Iterable[str], windows: bool) -> bool:
    """Whether a variable's name is one of `patterns` (a name, or a prefix ending in "*")."""
    if windows:
        name = name.upper()
    for pattern in patterns:
        if windows:
            pattern = pattern.upper()
        if (pattern.endswith("*") and name.startswith(pattern[:-1])) or name == pattern:
            return True
    return False


def _put(environment: dict[str, str], name: str, value: str, windows: bool) -> None:
    """Set a variable, replacing one whose name differs only in case on Windows (the OS would see two)."""
    if windows:
        for existing in [key for key in environment if key.upper() == name.upper()]:
            del environment[existing]
    environment[name] = value
