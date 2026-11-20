"""Containing the MCP server's process: proxy --contain (phase 1) and --sandbox (phase 2).

The proxy starts the server as the user who runs it. Without containment, a
server the proxy is stopped in front of keeps running if the proxy dies, and
a server may use as much memory and as many processes as it likes.

Phase 1: --contain (standard library only)
------------------------------------------
* Windows: before the server starts, the proxy puts itself into a job
  object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. The server and everything it
  starts inherit the job, so when the proxy's process ends, however it ends
  (killed included), Windows ends them all. The proxy joins the job itself
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
  a private /tmp and /dev, its own process list, and an empty home folder,
  except the folders named with --sandbox-allow (read-write) and
  --sandbox-read (read-only). The agent-sentinel home folder is hidden, and
  so is /run/user (the session's sockets: the keyring, the ssh agent).
  It has no network unless --sandbox-network is given.
* sandbox-exec (macOS): a generated profile denies reading and writing the
  usual credential places in the home folder and the agent-sentinel home,
  writing the proxy's own files (policy, pins, audit log), and the network
  unless --sandbox-network is given. Everything else stays readable.
* Windows has none: run the server as another user, or in an AppContainer
  (see the notes); --contain still ends it with the proxy.
A tool that is not installed is not downloaded: the proxy refuses to start.

What this does NOT do
---------------------
Phase 1 does not stop a hostile server from reading the user's files (such
as ~/.ssh) or from writing the agent-sentinel home folder (the policy, the
pins, the audit log): the server still runs as the same user. Only the
phase 2 sandboxes reduce that.

Fail closed: when containment was asked for and any part of it cannot be set
up, the proxy says why and does not start the server (or stops it at once).
"""

from __future__ import annotations

import ctypes
import dataclasses
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
          user_home: str | None = None) -> str | None:
    """Why these settings cannot be used on this machine, or None. Nothing is started or changed.

    For the proxy before it starts, and for doctor. `find` looks a program
    up on PATH (the proxy's own lookup, which never looks in the current
    folder). The order matters for doctor: the platform is looked at before
    any path, so that nothing a configuration names is opened in vain.
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
        home = _user_home(user_home)
        if home is None:
            return "the home folder is / or unknown, so the sandbox could not hide it"
        for option, paths in (("--sandbox-allow", settings.allow), ("--sandbox-read", settings.read)):
            for path in paths:
                problem = _sandbox_path_problem(path, home)
                if problem:
                    return f"{option} {path}: {problem}"
        return None
    if platform != "darwin":
        return "--sandbox sandbox-exec needs macOS"
    if not os.path.isfile(SANDBOX_EXEC):
        return f"--sandbox sandbox-exec: {SANDBOX_EXEC} is missing"
    if settings.allow or settings.read:
        return ("--sandbox-allow and --sandbox-read are for --sandbox bwrap; sandbox-exec hides the credential "
                "places and leaves the rest readable")
    return None


def _user_home(given: str | None) -> str | None:
    home = os.path.realpath(given or os.path.expanduser("~"))
    return None if home in ("/", "") or not home.startswith("/") else home


def _within(path: str, folder: str) -> bool:
    """Whether `path` is `folder` or inside it (POSIX paths, already made real)."""
    return path == folder or path.startswith(folder.rstrip("/") + "/")


def _sandbox_path_problem(path: str, home: str) -> str | None:
    """Why a folder may not be shown to a sandboxed server, or None."""
    if not path.startswith("/"):
        return "is not a full path"
    if any(ord(character) < 32 for character in path):
        return "has a control character"
    real = os.path.realpath(path)
    if not os.path.exists(real):
        return "does not exist"
    if _within(home, real):
        return "would show the whole home folder, credentials included"
    for credential in CREDENTIAL_PATHS:
        place = posixpath.join(home, credential)
        if _within(real, place) or (_within(place, real) and os.path.lexists(place)):
            return f"would show {place}, a place where credentials are kept"
    return None


# ---- the sandboxes' own words ---------------------------------------------------------------------

def bwrap_arguments(settings: Settings, home: str, agent_home: str | None, control_files: Iterable[str] = (),
                    exists: Callable[[str], bool] = os.path.exists) -> list[str]:
    """bubblewrap's options for a sandboxed server (the words between "bwrap" and "--").

    Later mounts cover earlier ones, so the order is: everything read-only,
    then a fresh /dev, /proc, /tmp, an empty /run/user and home folder, then
    the folders the server may read or write (shorter paths first, so that a
    folder inside another gets its own access), then the agent-sentinel home
    hidden again, and the proxy's own files read-only again where an allowed
    folder would have made them writable. Every path is used as given: real,
    full paths (see check, and _sandbox_prefix, which makes them real).
    """
    words = ["--unshare-all", "--die-with-parent", "--new-session",
             "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"]
    if settings.network:
        words.append("--share-net")
    if exists("/run/user"):
        words += ["--tmpfs", "/run/user"]
    words += ["--tmpfs", home]
    shown = sorted([(path, "--ro-bind") for path in settings.read] + [(path, "--bind") for path in settings.allow],
                   key=lambda entry: (entry[0].count("/"), entry[1] == "--bind"))
    for path, how in shown:
        words += [how, path, path]
    if agent_home and exists(agent_home):
        words += ["--tmpfs", agent_home]
    writable = [path for path, how in shown if how == "--bind"]
    for name in control_files:
        if (exists(name) and not (agent_home and _within(name, agent_home))
                and any(_within(name, folder) for folder in writable)):
            words += ["--ro-bind", name, name]
    return words


def sandbox_exec_profile(settings: Settings, home: str, agent_home: str | None, control_files: Iterable[str] = (),
                         real: Callable[[str], str] = os.path.realpath) -> str:
    """The sandbox-exec (SBPL) profile for a sandboxed server. ContainmentError for a path it cannot quote.

    Later rules win over earlier ones, so everything is allowed first and the
    denials follow. `real` gives a path's real path: the sandbox matches real
    paths (/tmp is /private/tmp), so both spellings are denied.
    """
    lines = ["(version 1)", "(allow default)"]
    if not settings.network:
        lines.append("(deny network*)")
    hidden = [posixpath.join(home, credential) for credential in CREDENTIAL_PATHS]
    if agent_home:
        hidden.append(agent_home)
    for path in _with_real_paths(hidden, real):
        lines.append(f"(deny file-read* file-write* (subpath {_sbpl_string(path)}))")
    for path in _with_real_paths(control_files, real):
        lines.append(f"(deny file-write* (literal {_sbpl_string(path)}))")
    return "\n".join(lines) + "\n"


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
        parts = ["the server and everything it starts end with the proxy (a job object)"]
    else:
        parts = ["the server's process group ends with the proxy, no core dumps, "
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
            server_executable: str | None = None) -> Containment:
    """Set up containment for a server about to start; ContainmentError when it cannot be (fail closed).

    control_files: the proxy's own files (policy, pins, audit log), which a
                   sandboxed server may not write.
    server_executable: the program the server command starts, which must be
                   visible inside a bwrap sandbox.
    On Windows the proxy joins its job object here, before the server starts.
    """
    if not settings.active:
        return Containment()
    problem = check(settings, find)
    if problem is not None:
        raise ContainmentError(problem)
    if sys.platform == "win32":
        return _WindowsJob(settings)
    prefix: list[str] = []
    if settings.sandbox is not None:
        prefix = _sandbox_prefix(settings, find, control_files, server_executable)
    return _ProcessGroup(settings, prefix)


def _agent_home() -> str:
    from . import home  # here, not at the top: home imports the command-line helpers

    try:
        return os.path.realpath(str(home.home_folder()))
    except home.HomeError as exc:
        raise ContainmentError(f"cannot tell where the agent-sentinel home folder is, so the sandbox could not hide "
                               f"it: {exc}") from exc


def _sandbox_prefix(settings: Settings, find: Callable[[str], str | None], control_files: Sequence[str],
                    server_executable: str | None) -> list[str]:
    user_home = _user_home(None)
    if user_home is None:
        raise ContainmentError("the home folder is / or unknown, so the sandbox could not hide it")
    agent_home = _agent_home()
    files = [os.path.realpath(name) for name in control_files if name]
    settings = dataclasses.replace(settings, allow=tuple(os.path.realpath(path) for path in settings.allow),
                                   read=tuple(os.path.realpath(path) for path in settings.read))
    if settings.sandbox == "sandbox-exec":
        return [SANDBOX_EXEC, "-p", sandbox_exec_profile(settings, user_home, agent_home, files)]
    if server_executable is not None:
        program = os.path.realpath(server_executable)
        shown = [*settings.allow, *settings.read]
        if _within(program, user_home) and not any(_within(program, folder) for folder in shown):
            raise ContainmentError(f"the server's program {program} is inside the home folder, which the sandbox "
                                   f"hides; add --sandbox-read {os.path.dirname(program)}")
    bwrap = find("bwrap")
    if bwrap is None:
        raise ContainmentError("bwrap (bubblewrap) is not on PATH")
    return [bwrap, *bwrap_arguments(settings, user_home, agent_home, files), "--"]


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
