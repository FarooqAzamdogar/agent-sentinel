"""Containing the MCP server's process: proxy --contain (phase 1) and --sandbox (phase 2).

The proxy starts the server as the user who runs it. Without containment, a
server the proxy is stopped in front of keeps running if the proxy dies, and
a server may use as much memory and as many processes as it likes.

Phase 1: --contain (standard library only)
------------------------------------------
* Windows: before the server starts, the proxy puts itself into a job
  object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. The server and the
  processes it starts inherit the job, so when the proxy's process ends,
  however it ends (killed included), Windows ends them. A process that
  Windows starts on the server's behalf (through WMI, the Task Scheduler or
  an out-of-process COM server) is not the server's child and is outside
  the job; a server can also keep the job open by duplicating the proxy's
  handle to it. The proxy joins the job itself
  because a process that subprocess starts cannot be started suspended and
  then assigned; nested jobs (Windows 8 and later) let this work when the
  client already runs the proxy in a job of its own. The limits
  (--server-memory-mb, --server-processes, --server-cpu-seconds) are set on a
  second job that holds the server alone, nested in the first, so that they
  do not apply to the proxy. The server is put into it just after it starts:
  what the server starts in those first moments is outside the limits,
  though still inside the first job. No UI restrictions are set: they would
  stop a server from opening a browser to sign in.
* Linux and macOS: the server runs in a session and process group of its own
  (start_new_session), which the proxy ends (killpg) when it stops: whatever
  the server started that is still in the group goes too. It starts with no
  core dumps (RLIMIT_CORE 0) and at most SERVER_OPEN_FILES open files; on
  Linux it is also killed when the proxy dies (PR_SET_PDEATHSIG, through
  ctypes). --server-memory-mb sets RLIMIT_AS, the virtual memory of each
  process (Node and V8 reserve a great deal, so it is never set unless
  asked, and must be generous); --server-cpu-seconds sets RLIMIT_CPU.
  --server-processes is Windows only: RLIMIT_NPROC counts every process of
  the user, not the server's.

Phase 2: --sandbox (implies --contain), with a tool already installed
--------------------------------------------------------------------
* bwrap (Linux, bubblewrap): the server sees the whole file system read-only,
  a private /tmp and /dev, its own process list, and an empty home folder
  (the one $HOME names and the account's own, when they differ), except the
  folders named with --sandbox-allow (read-write) and --sandbox-read
  (read-only). The agent-sentinel home folder is hidden, and so are /run and
  the other places where the host's services listen on unix sockets
  (HIDDEN_SYSTEM_PLACES: the Docker daemon, the system D-Bus, the session's
  ssh agent and keyring), since a socket can be used on a read-only mount.
  It has no network unless --sandbox-network is given. A folder the server
  may write may not hold the proxy's own files (policy, pins, audit log)
  or the agent-sentinel home: the server could change or replace them.
* sandbox-exec (macOS): a generated profile denies reading and writing the
  usual credential places in the home folder and the agent-sentinel home;
  writing the proxy's own files, the files that run later outside the
  sandbox (launch agents, shell startup files, cron and at jobs), and every
  folder on the way to any of these (a renamed folder would take them out
  from under the denials); asking LaunchServices, Apple Events or launchd
  to start a program (that program would not be sandboxed); and the
  network unless --sandbox-network is given. It starts from "allow
  default": everything else stays readable and writable.
* Windows has none: run the server as another user, or in an AppContainer
  (see the notes); --contain still ends it with the proxy.
A tool that is not installed is not downloaded: the proxy refuses to start.

What this does NOT do
---------------------
Phase 1 does not stop a hostile server from reading the user's files (such
as ~/.ssh) or from writing the agent-sentinel home folder (the policy, the
pins, the audit log): the server still runs as the same user. It cleans up
after a server; it does not contain a hostile one, which can have a process
started outside the job (Windows) or leave the process group (setsid). Only
the phase 2 sandboxes reduce that, and sandbox-exec's deny list less than
bwrap.

Fail closed: when containment was asked for and any part of it cannot be set
up, the proxy says why and does not start the server (or stops it at once).
"""

from __future__ import annotations

import ctypes
import os
import posixpath
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

SANDBOXES = ("bwrap", "sandbox-exec")
SANDBOX_EXEC = "/usr/bin/sandbox-exec"  # always this path: never one found on PATH
SERVER_OPEN_FILES = 4096  # RLIMIT_NOFILE under --contain (POSIX); a lower limit is kept
MIN_SERVER_MEMORY_MB, MAX_SERVER_MEMORY_MB = 16, 1024 * 1024
MAX_SERVER_PROCESSES = 10_000
MAX_SERVER_CPU_SECONDS = 10_000_000  # about 115 days
MAX_SANDBOX_PATHS = 64  # --sandbox-allow and --sandbox-read together
SWEEP_SECONDS = 1.0  # how long what is left of the server's process group has to exit before it is killed

# Credential places, relative to the home folder, that a sandboxed server never sees: those of
# templates.CREDENTIAL_PATTERN, and the MCP clients' own configuration (so a server cannot unwrap itself).
CREDENTIAL_PATHS = (
    ".ssh", ".aws", ".azure", ".docker", ".gnupg", ".kube", ".netrc", ".npmrc", ".pypirc", ".pgpass",
    ".git-credentials", ".env", ".config/gh", ".config/gcloud", ".config/github-copilot", ".claude", ".claude.json",
    ".cursor", ".codeium", ".codex", ".vscode", "Library/Keychains", "Library/Application Support/Claude",
    "Library/Application Support/Code/User", "Library/Application Support/Cursor/User",
)

# Places outside the home folder where the host's services listen on unix sockets: the Docker,
# containerd and podman daemons, the system D-Bus, libvirt, databases, the session's own sockets
# (/run/user: the ssh agent, the keyring), LXD. A unix socket can be connected to on a read-only
# mount, and some of these are a way out of any sandbox (docker run -v /:/host), so bwrap covers
# each that exists with an empty tmpfs, and a sandbox folder may not show one again.
HIDDEN_SYSTEM_PLACES = ("/run", "/var/run", "/run/user", "/var/lib/lxd", "/var/snap/lxd/common/lxd")
SESSION_SOCKETS = "/run/user"
RESOLV_CONF = "/etc/resolv.conf"  # often a link into /run (systemd-resolved); shown again with --sandbox-network

# What a server sandboxed by sandbox-exec may not write, relative to the home folder: what runs
# later outside the sandbox (launch agents, shell startup files, git's configuration).
PERSISTENCE_PATHS = (
    "Library/LaunchAgents", ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout", ".bashrc", ".bash_profile",
    ".bash_login", ".profile", ".config/fish", ".gitconfig", ".config/git",
)
SYSTEM_PERSISTENCE_PATHS = ("/usr/lib/cron", "/private/var/at")  # crontab and at jobs (the same folder)
# What starts a program for the caller outside its sandbox (macOS): the services, and their commands.
LAUNCH_SERVICES = ("com.apple.coreservices.launchservicesd", "com.apple.coreservices.appleevents")
LAUNCH_PROGRAMS = ("/usr/bin/open", "/usr/bin/osascript", "/bin/launchctl", "/usr/bin/crontab", "/usr/bin/at",
                   "/usr/bin/batch")

# Windows job objects (winnt.h).
_JOB_EXTENDED_LIMITS = 9  # JobObjectExtendedLimitInformation
_LIMIT_PROCESS_TIME = 0x0002
_LIMIT_ACTIVE_PROCESS = 0x0008
_LIMIT_PROCESS_MEMORY = 0x0100
_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_PROCESS_TERMINATE = 0x0001
_PROCESS_SET_QUOTA = 0x0100
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_PR_SET_PDEATHSIG = 1  # linux/prctl.h


class ContainmentError(Exception):
    """Containment was asked for and cannot be set up; the text says why, for the operator."""


@dataclass(frozen=True)
class Settings:
    """What the proxy's containment options ask for. Paths are full paths ("~" already read as the home folder)."""

    contain: bool = False
    memory_mb: int | None = None
    processes: int | None = None
    cpu_seconds: int | None = None
    sandbox: str | None = None
    allow: tuple[str, ...] = ()  # --sandbox-allow: folders the sandboxed server may read and write
    read: tuple[str, ...] = ()  # --sandbox-read: folders it may read
    network: bool = False  # --sandbox-network

    @property
    def active(self) -> bool:
        """Whether any containment is asked for: --contain, a limit, or a sandbox option (each implies --contain)."""
        return self.contain or self.sandbox is not None or bool(self.allow or self.read or self.network) or any(
            value is not None for value in (self.memory_mb, self.processes, self.cpu_seconds))


# ---- reading the options ------------------------------------------------------------------------

def _whole_number(text: str, low: int, high: int, unit: str) -> int:
    try:
        value = int(text) if len(text) <= 12 else -1
    except ValueError:
        raise ValueError(f"must be a whole number of {unit}") from None
    if not low <= value <= high:
        raise ValueError(f"must be {low} to {high} {unit}")
    return value


def memory_mb(text: str) -> int:
    """--server-memory-mb: ValueError for a value the proxy refuses."""
    return _whole_number(text, MIN_SERVER_MEMORY_MB, MAX_SERVER_MEMORY_MB, "megabytes")


def processes(text: str) -> int:
    """--server-processes."""
    return _whole_number(text, 1, MAX_SERVER_PROCESSES, "processes")


def cpu_seconds(text: str) -> int:
    """--server-cpu-seconds."""
    return _whole_number(text, 1, MAX_SERVER_CPU_SECONDS, "seconds")


# ---- whether it can work here ---------------------------------------------------------------------

def check(settings: Settings, find: Callable[[str], str | None], platform: str = sys.platform,
          user_home: str | Sequence[str] | None = None, control_files: Sequence[str] = ()) -> str | None:
    """Why these settings cannot be used on this machine, or None. Nothing is started or changed.

    For the proxy before it starts, and for doctor. `find` looks a program
    up on PATH (the proxy's own lookup, which never looks in the current
    folder). The order matters for doctor: the platform is looked at before
    any path, so that nothing a configuration names is opened in vain.
    user_home: the home folders a sandbox hides (default: _homes).
    control_files: the proxy's own files (policy, pins, audit log), which no
    folder the server may write may hold.
    """
    if not settings.active:
        return None
    if settings.sandbox is None and (settings.allow or settings.read or settings.network):
        return "--sandbox-allow, --sandbox-read and --sandbox-network need --sandbox"
    if settings.processes is not None and platform != "win32":
        return ("--server-processes is only available on Windows; elsewhere the only process limit counts every "
                "process of the user, not the server's")
    if settings.sandbox is None:
        return None
    if settings.sandbox not in SANDBOXES:
        return f"--sandbox must be one of {', '.join(SANDBOXES)}"
    if platform == "win32":
        return ("--sandbox is not available on Windows: run the server as another user or in an AppContainer "
                "instead (--contain still ends it with the proxy)")
    if settings.sandbox == "bwrap":
        if not platform.startswith("linux"):
            return "--sandbox bwrap needs Linux"
        if find("bwrap") is None:
            return "--sandbox bwrap: bwrap (bubblewrap) is not on PATH; install it, it is never downloaded"
        if len(settings.allow) + len(settings.read) > MAX_SANDBOX_PATHS:
            return f"--sandbox-allow and --sandbox-read may name at most {MAX_SANDBOX_PATHS} folders"
        homes = _homes(user_home)
        if homes is None:
            return "the home folder is / or unknown, so the sandbox could not hide it"
        for option, paths in (("--sandbox-allow", settings.allow), ("--sandbox-read", settings.read)):
            for path in paths:
                problem = _sandbox_path_problem(path, homes)
                if problem:
                    return f"{option} {path}: {problem}"
        return _writable_problem(settings.allow, control_files)
    if platform != "darwin":
        return "--sandbox sandbox-exec needs macOS"
    if not os.path.isfile(SANDBOX_EXEC):
        return f"--sandbox sandbox-exec: {SANDBOX_EXEC} is missing"
    if settings.allow or settings.read:
        return ("--sandbox-allow and --sandbox-read are for --sandbox bwrap; sandbox-exec hides the credential "
                "places and leaves the rest readable")
    return None


def _homes(given: str | Sequence[str] | None = None) -> list[str] | None:
    """The home folders a sandbox hides, as real paths; None when $HOME is / or unknown.

    By default, the one $HOME names and the account's own (from the password
    database) when it differs: a client or launcher may set HOME to another
    folder, and the real one, with ~/.ssh in it, must not show through.
    `given` replaces both (for tests). An account home of / is skipped.
    """
    if given is None:
        names = [os.path.expanduser("~"), _account_home()]
    else:
        names = [given] if isinstance(given, str) else list(given)
    homes: list[str] = []
    for index, name in enumerate(names):
        home = os.path.realpath(name) if name else ""
        if home in ("/", "") or not home.startswith("/"):
            if index == 0:
                return None
            continue
        if home not in homes:
            homes.append(home)
    return homes


def _account_home() -> str | None:
    """The home folder of the account the proxy runs as (POSIX), whatever $HOME says; None when unknown."""
    try:
        import pwd  # POSIX only

        return pwd.getpwuid(os.getuid()).pw_dir or None
    except (ImportError, KeyError, AttributeError, OSError):
        return None


def _within(path: str, folder: str) -> bool:
    """Whether `path` is `folder` or inside it (POSIX paths, already made real)."""
    return path == folder or path.startswith(folder.rstrip("/") + "/")


def _sandbox_path_problem(path: str, homes: Sequence[str]) -> str | None:
    """Why a folder may not be shown to a sandboxed server, or None. Both its spelling and its real path count."""
    if not path.startswith("/"):
        return "is not a full path"
    if any(ord(character) < 32 for character in path):
        return "has a control character"
    real = os.path.realpath(path)
    if not os.path.exists(real):
        return "does not exist"
    for shown in dict.fromkeys((posixpath.normpath(path), real)):
        if any(_within(home, shown) for home in homes):
            return "would show the whole home folder, credentials included"
        for place in HIDDEN_SYSTEM_PLACES:
            if os.path.lexists(place) and _within(os.path.realpath(place), shown):
                return f"would show {place}, where the host's services have their sockets"
        if _within(shown, SESSION_SOCKETS):
            return f"is inside {SESSION_SOCKETS}, where the session's sockets are (the ssh agent, the keyring)"
        for home in homes:
            for credential in CREDENTIAL_PATHS:
                place = posixpath.join(home, credential)
                if _within(shown, place) or (_within(place, shown) and os.path.lexists(place)):
                    return (f"would show {place}, a place where credentials are kept (a server installed there, "
                            "such as an editor extension's or a Claude Code plugin's, cannot be sandboxed)")
    return None


def _credential_program_problem(program: str, homes: Sequence[str],
                                real: Callable[[str], str] = os.path.realpath) -> str | None:
    """Why the server's program cannot run in either sandbox because it lies in a credential place, or None.

    Both sandboxes hide CREDENTIAL_PATHS, which include the MCP clients' own
    folders (~/.claude, ~/.vscode, ~/.cursor ...), where editor extensions
    and Claude Code plugins install their servers. Such a server could not be
    read inside the sandbox, and showing its folder would show the
    credentials beside it, so the proxy says so before it starts anything.
    """
    for one in dict.fromkeys((posixpath.normpath(program), real(program))):
        for home in homes:
            for credential in CREDENTIAL_PATHS:
                place = posixpath.join(home, credential)
                if _within(one, place):
                    return (f"the server's program {one} is inside {place}, a place where credentials are kept, "
                            "which the sandbox never shows; a server installed there cannot be sandboxed (use "
                            "--contain alone, or install the server elsewhere)")
    return None


def _writable_problem(allow: Sequence[str], protected: Iterable[str | None],
                      real: Callable[[str], str] = os.path.realpath) -> str | None:
    """Why a folder the server may write would let it change the proxy's own files, or None.

    A file inside such a folder, whether it exists yet or not, could be
    written, or replaced for the next session by renaming a folder on its
    way: so a folder that holds the policy, the pins, the audit log or the
    agent-sentinel home is refused.
    """
    names = [(name, real(name)) for name in protected if name]
    for folder in allow:
        where = real(folder)
        for name, name_real in names:
            if _within(name_real, where):
                return (f"--sandbox-allow {folder}: it holds {name}, which the server could then change or replace; "
                        "keep the policy, pins, audit log and agent-sentinel home out of the folders the server "
                        "may write")
    return None


def _secret_shown_problem(settings: Settings, secrets: Sequence[str], homes: Sequence[str], agent_home: str | None,
                          exists: Callable[[str], bool] = os.path.exists,
                          real: Callable[[str], str] = os.path.realpath) -> str | None:
    """Why a bwrap sandbox would let the server read a secret file of the proxy's (the audit key), or None.

    secrets: real paths. bwrap shows the whole file system read-only, then
    hides the home folders, /tmp and the system places, shows the --sandbox-read
    and --sandbox-allow folders again, and hides the agent-sentinel home last.
    So a secret is hidden inside the agent-sentinel home, or inside a hidden
    place and no shown folder; anywhere else the server could read it, and
    with the audit key sign records of its own.
    """
    hidden = [*homes, "/tmp", *_system_places(exists, real)]
    shown = [folder for folder, _ in _shown_folders(settings, real)]
    for secret in secrets:
        if agent_home and _within(secret, agent_home):
            continue
        folder = next((one for one in shown if _within(secret, one)), None)
        if folder is not None:
            return (f"the sandbox shows {folder}, which holds the audit key file {secret}: the server could read it "
                    "and sign records of its own; keep the key out of the folders the server may read")
        if not any(_within(secret, place) for place in hidden):
            return (f"the audit key file {secret} is outside the folders the sandbox hides (the home folders, /tmp, "
                    "the agent-sentinel home), so the server could read it; keep the key in the agent-sentinel home")
    return None


def _system_places(exists: Callable[[str], bool] = os.path.exists,
                   real: Callable[[str], str] = os.path.realpath) -> list[str]:
    """The HIDDEN_SYSTEM_PLACES that exist, as real paths, each once and none inside another already listed."""
    found: list[str] = []
    for place in HIDDEN_SYSTEM_PLACES:
        if not exists(place):
            continue
        where = real(place)
        if where != "/" and not any(_within(where, done) for done in found):
            found.append(where)
    return found


def _shown_folders(settings: Settings, real: Callable[[str], str] = os.path.realpath) -> list[tuple[str, str]]:
    """The folders a bwrap sandbox shows, as (path, "--ro-bind" or "--bind"), in the order to mount them.

    Each folder is shown at its own spelling and at its real path, so that a
    program found through a link is there either way. Shorter paths come
    first, so that a folder inside another gets its own access; at one depth
    a writable folder comes last.
    """
    shown: list[tuple[str, str]] = []
    for how, paths in (("--ro-bind", settings.read), ("--bind", settings.allow)):
        for path in paths:
            for one in dict.fromkeys((posixpath.normpath(path), real(path))):
                if (one, how) not in shown:
                    shown.append((one, how))
    return sorted(shown, key=lambda entry: (entry[0].count("/"), entry[1] == "--bind"))


def _hidden_program_problem(program: str, settings: Settings, homes: Sequence[str],
                            exists: Callable[[str], bool] = os.path.exists,
                            real: Callable[[str], str] = os.path.realpath) -> str | None:
    """Why the server's program would not be found inside a bwrap sandbox, or None.

    The sandbox empties the home folders, /tmp and the system places; a
    program in one of them must be in a folder named with --sandbox-read
    or --sandbox-allow, at its spelling and at its real path.
    """
    hidden = [*homes, "/tmp", *_system_places(exists, real)]
    shown = [folder for folder, _ in _shown_folders(settings, real)]
    for one in dict.fromkeys((posixpath.normpath(program), real(program))):
        place = next((folder for folder in hidden if _within(one, folder)), None)
        if place is not None and not any(_within(one, folder) for folder in shown):
            return (f"the server's program {one} is inside {place}, which the sandbox hides; add --sandbox-read "
                    f"{posixpath.dirname(one)}")
    return None


# ---- the sandboxes' own words ---------------------------------------------------------------------

def bwrap_arguments(settings: Settings, home: str | Sequence[str], agent_home: str | None,
                    exists: Callable[[str], bool] = os.path.exists,
                    real: Callable[[str], str] = os.path.realpath) -> list[str]:
    """bubblewrap's options for a sandboxed server (the words between "bwrap" and "--").

    home: the home folder, or the home folders ($HOME's and the account's), as real paths.
    Later mounts cover earlier ones, so the order is: everything read-only,
    then a fresh /dev, /proc, /tmp, an empty /run and the other system
    places where services have their sockets (with --sandbox-network, the
    resolver's file there shown again), the empty home folders, then the
    folders the server may read or write (_shown_folders), then the
    agent-sentinel home hidden again. check and _sandbox_prefix have made
    sure that no folder the server may write holds the proxy's own files.
    """
    homes = [home] if isinstance(home, str) else list(home)
    words = ["--unshare-all", "--die-with-parent", "--new-session",
             "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"]
    if settings.network:
        words.append("--share-net")
    places = _system_places(exists, real)
    for place in places:
        words += ["--tmpfs", place]
    if settings.network:
        resolver = real(RESOLV_CONF)
        if resolver != RESOLV_CONF and exists(resolver) and any(_within(resolver, place) for place in places):
            words += ["--ro-bind", resolver, resolver]  # name lookups need it, and it holds no socket
    for one in sorted(homes, key=lambda path: path.count("/")):
        if exists(one):
            words += ["--tmpfs", one]
    for path, how in _shown_folders(settings, real):
        words += [how, path, path]
    if agent_home and exists(agent_home):
        words += ["--tmpfs", agent_home]
    return words


def sandbox_exec_profile(settings: Settings, home: str | Sequence[str], agent_home: str | None,
                         control_files: Iterable[str] = (), real: Callable[[str], str] = os.path.realpath,
                         secret_files: Iterable[str] = ()) -> str:
    """The sandbox-exec (SBPL) profile for a sandboxed server. ContainmentError for a path it cannot quote.

    home: the home folder, or the home folders ($HOME's and the account's).
    secret_files: files the server may neither read nor write (the audit key
    file), wherever they are.
    Later rules win over earlier ones, so everything is allowed first and the
    denials follow. `real` gives a path's real path: the sandbox matches real
    paths (/tmp is /private/tmp), so both spellings are denied. The denials
    name paths, so a folder on the way to a denied place may not be renamed
    or replaced either (a literal denial of writing it: what is inside stays
    writable where it was).
    """
    homes = [home] if isinstance(home, str) else list(home)
    lines = ["(version 1)", "(allow default)"]
    if not settings.network:
        lines.append("(deny network*)")
    # A program started by LaunchServices (open), Apple Events (osascript) or launchd (launchctl) is not
    # sandboxed: the server may not ask them to start one.
    lines += ["(deny lsopen)", "(deny appleevent-send)", "(deny job-creation)",
              "(deny mach-lookup " + " ".join(f"(global-name {_sbpl_string(name)})" for name in LAUNCH_SERVICES) + ")",
              "(deny process-exec " + " ".join(f"(literal {_sbpl_string(path)})" for path in LAUNCH_PROGRAMS) + ")"]
    hidden = [posixpath.join(one, credential) for one in homes for credential in CREDENTIAL_PATHS]
    if agent_home:
        hidden.append(agent_home)
    hidden += [path for path in secret_files if path]
    unwritable = [posixpath.join(one, path) for one in homes for path in PERSISTENCE_PATHS]
    unwritable += SYSTEM_PERSISTENCE_PATHS
    files = list(control_files)
    for path in _with_real_paths(hidden, real):
        lines.append(f"(deny file-read* file-write* (subpath {_sbpl_string(path)}))")
    for path in _with_real_paths(unwritable, real):
        lines.append(f"(deny file-write* (subpath {_sbpl_string(path)}))")
    for path in _with_real_paths(files, real):
        lines.append(f"(deny file-write* (literal {_sbpl_string(path)}))")
    folders = _ancestors(_with_real_paths([*hidden, *unwritable, *files], real))
    for path in _with_real_paths(folders, real):
        lines.append(f"(deny file-write* (literal {_sbpl_string(path)}))")
    return "\n".join(dict.fromkeys(lines)) + "\n"


def _ancestors(paths: Iterable[str]) -> list[str]:
    """The folders on the way to each path, / left out, each once."""
    found: list[str] = []
    for path in paths:
        folder = posixpath.dirname(path.rstrip("/"))
        while folder not in ("/", "") and folder not in found:
            found.append(folder)
            folder = posixpath.dirname(folder)
    return found


def _with_real_paths(paths: Iterable[str], real: Callable[[str], str]) -> list[str]:
    """Each path, and its real path when that differs."""
    found: list[str] = []
    for path in paths:
        for one in (path, real(path)):
            if one not in found:
                found.append(one)
    return found


def _sbpl_string(path: str) -> str:
    if any(character in path for character in '"\\') or any(ord(character) < 32 for character in path):
        raise ContainmentError(f"cannot write {path!r} into a sandbox profile (a quote, backslash or control "
                               "character)")
    return f'"{path}"'


def describe(settings: Settings, platform: str = sys.platform) -> str:
    """What containment the server gets, in one line, for the proxy's startup lines and for doctor."""
    if not settings.active:
        return "none"
    if platform == "win32":
        parts = ["the server and its child processes end with the proxy (a job object; cleanup, not isolation)"]
    else:
        parts = ["the server's process group ends with the proxy (cleanup, not isolation), no core dumps, "
                 f"at most {SERVER_OPEN_FILES} open files"]
    if settings.memory_mb is not None:
        what = "committed memory" if platform == "win32" else "virtual memory"
        parts.append(f"{what} at most {settings.memory_mb} MB per process")
    if settings.processes is not None:
        parts.append(f"at most {settings.processes} process(es) at once")
    if settings.cpu_seconds is not None:
        parts.append(f"at most {settings.cpu_seconds} s of CPU time per process")
    if settings.sandbox is not None:
        network = "with" if settings.network else "without"
        parts.append(f"sandboxed by {settings.sandbox}, {network} network")
    return "; ".join(parts)


def label(settings: Settings) -> str | None:
    """A short name for what the server gets: "contained", "sandboxed (NAME)", or None (doctor, session_start)."""
    if not settings.active:
        return None
    return f"sandboxed ({settings.sandbox})" if settings.sandbox else "contained"


# ---- setting it up -------------------------------------------------------------------------------------

class Containment:
    """What the proxy does around starting and stopping the server. This one does nothing: no containment.

    The order of use: `command` and `popen_options` for subprocess.Popen,
    `after_start` once the server runs, `sweep` once it has stopped.
    """

    description = "none"

    def command(self, server_command: Sequence[str]) -> list[str]:
        """The command to start: the server's own, or the server's behind a sandbox."""
        return list(server_command)

    def popen_options(self) -> dict[str, Any]:
        """Extra keyword arguments for subprocess.Popen."""
        return {}

    def after_start(self, server: subprocess.Popen) -> None:
        """Finish containing a server that has just started. ContainmentError if that fails (stop the server then)."""

    def sweep(self, server: subprocess.Popen) -> None:
        """End whatever the server started that is still running. Never raises."""


def prepare(settings: Settings, find: Callable[[str], str | None], control_files: Sequence[str] = (),
            server_executable: str | None = None, secret_files: Sequence[str] = ()) -> Containment:
    """Set up containment for a server about to start; ContainmentError when it cannot be (fail closed).

    control_files: the proxy's own files (policy, pins, audit log), which a
                   sandboxed server may not write.
    server_executable: the program the server command starts, which must be
                   visible inside a bwrap sandbox.
    secret_files:  the proxy's files a sandboxed server may not read either
                   (the audit key file, --audit-key-file). --contain alone
                   does not hide them: the server runs as the same user.
    On Windows the proxy joins its job object here, before the server starts.
    """
    if not settings.active:
        return Containment()
    problem = check(settings, find, control_files=control_files)
    if problem is not None:
        raise ContainmentError(problem)
    if sys.platform == "win32":
        return _WindowsJob(settings)
    prefix: list[str] = []
    if settings.sandbox is not None:
        prefix = _sandbox_prefix(settings, find, control_files, server_executable, secret_files)
    return _ProcessGroup(settings, prefix)


def _agent_home() -> str:
    from . import home  # here, not at the top: home imports the command-line helpers

    try:
        return os.path.realpath(str(home.home_folder()))
    except home.HomeError as exc:
        raise ContainmentError(f"cannot tell where the agent-sentinel home folder is, so the sandbox could not hide "
                               f"it: {exc}") from exc


def _sandbox_prefix(settings: Settings, find: Callable[[str], str | None], control_files: Sequence[str],
                    server_executable: str | None, secret_files: Sequence[str] = ()) -> list[str]:
    homes = _homes()
    if homes is None:
        raise ContainmentError("the home folder is / or unknown, so the sandbox could not hide it")
    agent_home = _agent_home()
    files = [os.path.realpath(name) for name in control_files if name]
    secrets = [os.path.realpath(name) for name in secret_files if name]
    if server_executable is not None:
        problem = _credential_program_problem(server_executable, homes)
        if problem is not None:
            raise ContainmentError(problem)
    if settings.sandbox == "sandbox-exec":
        return [SANDBOX_EXEC, "-p", sandbox_exec_profile(settings, homes, agent_home, files, secret_files=secrets)]
    problem = _writable_problem(settings.allow, [*files, agent_home])
    if problem is None:
        problem = _secret_shown_problem(settings, secrets, homes, agent_home)
    if problem is None and server_executable is not None:
        problem = _hidden_program_problem(server_executable, settings, homes)
    if problem is not None:
        raise ContainmentError(problem)
    bwrap = find("bwrap")
    if bwrap is None:
        raise ContainmentError("bwrap (bubblewrap) is not on PATH")
    return [bwrap, *bwrap_arguments(settings, homes, agent_home), "--"]


class _WindowsJob(Containment):
    """--contain on Windows: the proxy in a kill-on-close job object; the limits on a second job, the server's own."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self.description = describe(settings, "win32")
        self._kernel32 = _kernel32()
        # Never closed: the handle closes when the proxy's process ends, and that ends the job's processes.
        self._outer = self._new_job(_LIMIT_KILL_ON_JOB_CLOSE)
        if not self._kernel32.AssignProcessToJobObject(self._outer, self._kernel32.GetCurrentProcess()):
            raise ContainmentError(f"cannot put the proxy into a job object: {_last_error()}")
        if not self._in_job(self._kernel32.GetCurrentProcess(), self._outer):
            raise ContainmentError("the proxy is not in its job object after joining it")
        self._inner: int | None = None

    def _new_job(self, flags: int, memory: int = 0, processes: int = 0, cpu_ticks: int = 0) -> int:
        job = self._kernel32.CreateJobObjectW(None, None)
        if not job:
            raise ContainmentError(f"cannot create a job object: {_last_error()}")
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = flags
        limits.BasicLimitInformation.ActiveProcessLimit = processes
        limits.BasicLimitInformation.PerProcessUserTimeLimit = cpu_ticks
        limits.ProcessMemoryLimit = memory
        if not self._kernel32.SetInformationJobObject(job, _JOB_EXTENDED_LIMITS, ctypes.byref(limits),
                                                      ctypes.sizeof(limits)):
            error = _last_error()
            self._kernel32.CloseHandle(job)
            raise ContainmentError(f"cannot set the limits of a job object: {error}")
        return job

    def _in_job(self, process: int, job: int) -> bool:
        found = ctypes.c_int(0)
        return bool(self._kernel32.IsProcessInJob(process, job, ctypes.byref(found))) and bool(found.value)

    def after_start(self, server: subprocess.Popen) -> None:
        kernel32 = self._kernel32
        access = _PROCESS_SET_QUOTA | _PROCESS_TERMINATE | _PROCESS_QUERY_LIMITED_INFORMATION
        # Popen holds a handle to the server, so its process id cannot be reused meanwhile.
        process = kernel32.OpenProcess(access, False, server.pid)
        if not process:
            raise ContainmentError(f"cannot open the server's process: {_last_error()}")
        try:
            if not self._in_job(process, self._outer):
                raise ContainmentError("the server did not start inside the proxy's job object")
            settings = self._settings
            if settings.memory_mb is None and settings.processes is None and settings.cpu_seconds is None:
                return
            flags = _LIMIT_KILL_ON_JOB_CLOSE
            memory = processes = cpu_ticks = 0
            if settings.memory_mb is not None:
                flags |= _LIMIT_PROCESS_MEMORY
                memory = settings.memory_mb * 1024 * 1024
            if settings.processes is not None:
                flags |= _LIMIT_ACTIVE_PROCESS
                processes = settings.processes
            if settings.cpu_seconds is not None:
                flags |= _LIMIT_PROCESS_TIME
                cpu_ticks = settings.cpu_seconds * 10_000_000  # in units of 100 nanoseconds
            self._inner = self._new_job(flags, memory, processes, cpu_ticks)
            if not kernel32.AssignProcessToJobObject(self._inner, process):
                raise ContainmentError(f"cannot put the server into the job object of its limits: {_last_error()}")
        finally:
            kernel32.CloseHandle(process)

    def sweep(self, server: subprocess.Popen) -> None:
        if self._inner is not None:
            self._kernel32.TerminateJobObject(self._inner, 1)
        # What is left in the proxy's own job ends with the proxy's process.


class _ProcessGroup(Containment):
    """--contain on Linux and macOS: a session and process group of the server's own, resource limits, and
    (Linux) a signal when the proxy dies; with --sandbox, the server started behind bwrap or sandbox-exec."""

    def __init__(self, settings: Settings, prefix: list[str]) -> None:
        import resource  # POSIX only

        self._prefix = prefix
        self.description = describe(settings)
        wanted = [(resource.RLIMIT_CORE, 0), (resource.RLIMIT_NOFILE, SERVER_OPEN_FILES)]
        if settings.memory_mb is not None:
            wanted.append((resource.RLIMIT_AS, settings.memory_mb * 1024 * 1024))
        if settings.cpu_seconds is not None:
            wanted.append((resource.RLIMIT_CPU, settings.cpu_seconds))
        # Worked out here, in the proxy, so that the child only has to set them. A limit the proxy already
        # has that is lower is kept.
        self._limits = []
        for which, value in wanted:
            soft, hard = resource.getrlimit(which)
            new_hard = value if hard == resource.RLIM_INFINITY else min(hard, value)
            new_soft = new_hard if soft == resource.RLIM_INFINITY else min(soft, new_hard)
            self._limits.append((which, (new_soft, new_hard)))
        self._prctl = _linux_prctl() if sys.platform.startswith("linux") else None
        # preexec_fn runs in the child between fork and exec, where only async-signal-safe work is safe if the
        # parent has other threads (a lock one of them held stays locked in the child). The proxy starts its
        # threads only after the server; refuse rather than take that risk if that ever changes.
        if threading.active_count() > 1:
            raise ContainmentError("the proxy has other threads running, so it cannot set the server's limits safely")

    def command(self, server_command: Sequence[str]) -> list[str]:
        return [*self._prefix, *server_command]

    def popen_options(self) -> dict[str, Any]:
        return {"start_new_session": True, "preexec_fn": self._in_child()}

    def _in_child(self) -> Callable[[], None]:
        import resource

        limits, prctl, parent = self._limits, self._prctl, os.getpid()

        def setup() -> None:
            # In the child, before the server's program runs. An exception here makes Popen fail in the proxy.
            for which, values in limits:
                resource.setrlimit(which, values)
            if prctl is not None:
                if prctl(_PR_SET_PDEATHSIG, int(signal.SIGKILL), 0, 0, 0) != 0:
                    raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG) failed")
                if os.getppid() != parent:  # the proxy died before the signal was set up
                    os.kill(os.getpid(), signal.SIGKILL)

        return setup

    def sweep(self, server: subprocess.Popen) -> None:
        group = server.pid  # start_new_session made the server the leader of a group of that number
        try:
            os.killpg(group, signal.SIGTERM)
            deadline = time.monotonic() + SWEEP_SECONDS
            while time.monotonic() < deadline:
                time.sleep(0.05)
                os.killpg(group, 0)  # ProcessLookupError once the group is empty
            os.killpg(group, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def _linux_prctl() -> Callable[..., int]:
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    return prctl


# ---- Windows job objects through ctypes ------------------------------------------------------------------

class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32), ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t), ("PriorityClass", ctypes.c_uint32), ("SchedulingClass", ctypes.c_uint32),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimits), ("IoInfo", _IoCounters), ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _kernel32() -> Any:
    """kernel32 with the signatures used here (a loader of its own, so that no other module's is changed)."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    handle, boolean, dword = ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32
    for name, arguments, result in (
        ("CreateJobObjectW", [ctypes.c_void_p, ctypes.c_wchar_p], handle),
        ("SetInformationJobObject", [handle, ctypes.c_int, ctypes.c_void_p, dword], boolean),
        ("AssignProcessToJobObject", [handle, handle], boolean),
        ("IsProcessInJob", [handle, handle, ctypes.POINTER(ctypes.c_int)], boolean),
        ("TerminateJobObject", [handle, ctypes.c_uint], boolean),
        ("GetCurrentProcess", [], handle),
        ("OpenProcess", [dword, boolean, dword], handle),
        ("CloseHandle", [handle], boolean),
    ):
        function = getattr(kernel32, name)
        function.argtypes = arguments
        function.restype = result
    return kernel32


def _last_error() -> str:
    code = ctypes.get_last_error()  # type: ignore[attr-defined]
    return f"{ctypes.FormatError(code).strip()} (error {code})"  # type: ignore[attr-defined]
