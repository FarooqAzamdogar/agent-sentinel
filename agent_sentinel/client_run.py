"""Which run of the MCP client a proxy belongs to: the client process, and when it started.

The proxies of a session group (proxy --session-group, session.py) share
their flow marks with the other proxies of the same client run, and with no
others. A run is told by the client process: the nearest process above the
proxy that is not a shell or a launcher (cmd.exe, conhost, sh, bash, dash,
zsh, PowerShell, the py launcher, the launcher stub of a Python virtual
environment, the agent-sentinel script, uv, uvx, pipx), together with the
time that process started. Its id is "<pid>@<start time>", so that a process
number the system gives out again later is a new run.

How the start time is found, each with a limit on what it reads and how long it takes:

    Windows   CreateToolhelp32Snapshot (the parent of each process) and GetProcessTimes, through ctypes
    Linux     /proc/<pid>/stat (the parent and the start time, in clock ticks since the system started)
    macOS     ps -o ppid=,lstart=,comm= for each process, with a time limit

When the client cannot be found (a process that cannot be read, a parent
that started after its child, which means its number was reused, or more
than MAX_ANCESTORS launchers), the run is UNKNOWN. Every proxy of the group
then shares one run, whatever client run it belongs to: marks carry over
from one run of the client to the next, which is too strict, never too lax.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

UNKNOWN = "unknown"
# How many processes above the proxy are looked at, at most.
MAX_ANCESTORS = 16
# How long finding the client may take in all, and one `ps` (macOS) at most.
TOTAL_SECONDS = 4.0
PS_SECONDS = 2.0
# Programs that start the proxy for the client, never the client itself (lowercase, without .exe).
LAUNCHERS = frozenset({
    "cmd", "conhost", "sh", "bash", "dash", "zsh", "fish", "ksh", "mksh", "tcsh", "csh", "powershell", "pwsh",
    "py", "pyw", "agent-sentinel", "agent_sentinel", "uv", "uvx", "pipx", "env",
})
_PYTHON = re.compile(r"(python|pypy)[0-9.]*[tw]?(d|_d)?")
_MAX_STAT_BYTES = 4096


@dataclass(frozen=True)
class ClientRun:
    """One run of the MCP client: its id, and what is known about the client process."""

    id: str  # "<pid>@<start time>", or UNKNOWN
    started: float | None = None  # when the client process started, in seconds since the epoch
    program: str = ""  # the client's program name, for the operator


@dataclass(frozen=True)
class _Process:
    parent: int
    name: str  # the program's file name, lowercase, without .exe
    started: float  # seconds since the epoch
    start_key: str  # the start time exactly as the system gives it
    image: str = ""  # the program's full path, where it is known (Windows)


def find_client_run() -> ClientRun:
    """The run of the client this process was started by; ClientRun(UNKNOWN) when it cannot be told. Never raises."""
    deadline = time.monotonic() + TOTAL_SECONDS
    try:
        if sys.platform == "win32":
            reader = _WindowsProcesses()
        elif os.path.isdir("/proc/self"):
            reader = _ProcProcesses()
        else:
            reader = _PsProcesses(deadline)
        return _walk_up(reader, deadline)
    except Exception:  # whatever went wrong, the run is unknown, which is the strict answer
        return ClientRun(UNKNOWN)


def is_launcher(name: str, image: str = "") -> bool:
    """Whether a process of this program name (and full path, if known) only starts the proxy for the client."""
    base = name.lower().lstrip("-")
    base = base[:-4] if base.endswith(".exe") else base
    if base in LAUNCHERS:
        return True
    # A Python virtual environment on Windows starts its python.exe as a stub that starts the real one.
    return bool(image) and _PYTHON.fullmatch(base) is not None and _is_venv_stub(image)


def _is_venv_stub(image: str) -> bool:
    folder = Path(image).parent
    try:
        return folder.name.lower() == "scripts" and (folder.parent / "pyvenv.cfg").is_file()
    except OSError:
        return False


def _walk_up(reader: "_Reader", deadline: float) -> ClientRun:
    """Go up from this process to the first process that is not a launcher."""
    child = reader.process(os.getpid())
    if child is None:
        return ClientRun(UNKNOWN)
    pid = child.parent
    for _ in range(MAX_ANCESTORS):
        if pid <= 1 or pid == 4 or time.monotonic() > deadline:  # 0 and 4: the system on Windows; 1: init
            return ClientRun(UNKNOWN)
        found = reader.process(pid)
        if found is None or found.started > child.started + 1e-6:
            return ClientRun(UNKNOWN)  # gone, unreadable, or a number given out again to a younger process
        if not is_launcher(found.name, found.image):
            return ClientRun(f"{pid}@{found.start_key}", found.started, found.name)
        child, pid = found, found.parent
    return ClientRun(UNKNOWN)


class _Reader:
    def process(self, pid: int) -> _Process | None:
        raise NotImplementedError


# ---- Linux -------------------------------------------------------------------------------------

class _ProcProcesses(_Reader):
    """/proc/<pid>/stat: the parent, the program name and the start time in clock ticks since boot."""

    def __init__(self) -> None:
        self._boot = _boot_time()
        self._ticks = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
        self._boot_id = _read_small("/proc/sys/kernel/random/boot_id").strip()[:36]

    def process(self, pid: int) -> _Process | None:
        try:
            data = _read_small(f"/proc/{pid}/stat")
        except OSError:
            return None
        start, end = data.find("("), data.rfind(")")
        if start < 0 or end < start:
            return None
        fields = data[end + 2:].split()
        if len(fields) < 20:
            return None
        ticks = int(fields[19])
        key = f"{self._boot_id[:8]}-{ticks}" if self._boot_id else str(ticks)
        return _Process(int(fields[1]), data[start + 1:end].lower(), self._boot + ticks / self._ticks, key)


def _read_small(path: str) -> str:
    with open(path, "rb") as handle:
        return handle.read(_MAX_STAT_BYTES).decode("utf-8", "replace")


def _boot_time() -> float:
    for line in _read_small("/proc/stat").splitlines():
        if line.startswith("btime "):
            return float(line.split()[1])
    return 0.0


# ---- macOS and other systems: ps -------------------------------------------------------------------

class _PsProcesses(_Reader):
    """`ps -o ppid=,lstart=,comm= -p PID`, one process at a time, each within PS_SECONDS."""

    def __init__(self, deadline: float) -> None:
        self._deadline = deadline
        self._ps = next((path for path in ("/bin/ps", "/usr/bin/ps") if os.path.isfile(path)), None)

    def process(self, pid: int) -> _Process | None:
        if self._ps is None:
            return None
        timeout = min(PS_SECONDS, self._deadline - time.monotonic())
        if timeout <= 0:
            return None
        try:
            found = subprocess.run([self._ps, "-o", "ppid=,lstart=,comm=", "-p", str(pid)], capture_output=True,
                                   timeout=timeout, env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"})
        except (OSError, subprocess.SubprocessError):
            return None
        words = found.stdout.decode("utf-8", "replace").split()
        if found.returncode != 0 or len(words) < 7:
            return None
        started_text = " ".join(words[1:6])  # "Wed Nov 20 10:00:00 2026"
        try:
            started = time.mktime(time.strptime(started_text, "%a %b %d %H:%M:%S %Y"))
        except (ValueError, OverflowError):
            return None
        name = os.path.basename(" ".join(words[6:])).lower()
        return _Process(int(words[0]), name, started, str(int(started)))


# ---- Windows ---------------------------------------------------------------------------------------

class _WindowsProcesses(_Reader):
    """One snapshot of every process's parent and program name; GetProcessTimes for the start time."""

    _MAX_PROCESSES = 100_000
    _EPOCH_OFFSET = 11_644_473_600  # seconds from 1601-01-01 (Windows file times) to 1970-01-01

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32 = kernel32

        class Entry(ctypes.Structure):
            _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                        ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                        ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
                        ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]

        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
        kernel32.Process32FirstW.restype = wintypes.BOOL
        kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
        kernel32.Process32NextW.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                        ctypes.POINTER(wintypes.DWORD)]
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL

        self._table: dict[int, tuple[int, str]] = {}
        snapshot = kernel32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
        if snapshot is None or snapshot == ctypes.c_void_p(-1).value:
            raise OSError("cannot list the processes")
        try:
            entry = Entry()
            entry.dwSize = ctypes.sizeof(Entry)
            more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while more and len(self._table) < self._MAX_PROCESSES:
                self._table[int(entry.th32ProcessID)] = (int(entry.th32ParentProcessID), entry.szExeFile)
                more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snapshot)

    def process(self, pid: int) -> _Process | None:
        listed = self._table.get(pid)
        if listed is None:
            return None
        times = self._times(pid)
        if times is None:
            return None
        created, image = times
        name = listed[1].lower()
        return _Process(listed[0], name[:-4] if name.endswith(".exe") else name,
                        created / 10_000_000 - self._EPOCH_OFFSET, str(created), image)

    def _times(self, pid: int) -> tuple[int, str] | None:
        """(creation time in 100 ns units since 1601, the program's full path) of a process, or None."""
        ctypes = self._ctypes
        from ctypes import wintypes

        kernel32 = self._kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return None
        try:
            created, ended, kernel, user = (wintypes.FILETIME() for _ in range(4))
            if not kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(ended), ctypes.byref(kernel),
                                            ctypes.byref(user)):
                return None
            buffer = ctypes.create_unicode_buffer(1024)
            size = wintypes.DWORD(len(buffer))
            image = buffer.value if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)) else ""
            return (created.dwHighDateTime << 32) | created.dwLowDateTime, image
        finally:
            kernel32.CloseHandle(handle)
