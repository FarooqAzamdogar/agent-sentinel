"""Ways the proxy asks a person to approve a call that the policy says "ask" for.

    agent-sentinel proxy --policy p.json --approve-with dialog --approve-with command:C:\\tools\\approve.cmd -- ...

A tool rule with action "ask" holds a call until a person approves it. The
proxy cannot ask inside the conversation: the agent reads the conversation,
and an answer typed there could come from the agent itself. So it asks
outside it, through one of these backends (proxy --approve-with, which can be
repeated; for each call the first backend that can ask at that moment is used):

* "dialog": a window on this machine's desktop. On Windows a message box
  (MessageBoxTimeoutW through ctypes, always on top, "Cancel" the default);
  on macOS osascript's `display dialog`; on Linux zenity, when it is installed
  and a display is set. Elsewhere it cannot ask. kdialog is not used: its
  command line cannot make "refuse" the default button, so a stray Enter
  would approve.
* "command:<program>": the operator's own program. It gets the request as one
  line of JSON on its standard input (see ApprovalRequest.as_json) and
  approves only by exiting with code 0 after printing exactly "approve". It is
  started without a shell and without arguments.
* "elicitation": a form the MCP client shows its user (elicitation/create),
  used only when the client declared that it can show one. The proxy sends
  the question and reads the answer itself (mcp_proxy.py); this module builds
  the question and reads the answer.

Whatever the backend, only an explicit yes approves. A timeout, an error, a
window that is closed, or an answer in any other form refuses the call.

What the person is shown: the tool and every argument, quoted as JSON and
passed through `printable`. A long value is cut, with a note that says how
much was left out, so a long body cannot push a "bcc" argument out of sight;
a call with more arguments than fit on a screen is refused instead of asked
about (NotShowable).

The agent must never be able to approve its own call. No backend reads
anything the agent can write: a dialog and a program answer on this machine,
and an elicitation is answered by the client, whose answer the proxy matches
by a random id that is never sent to the server (mcp_proxy refuses server
requests whose id could be confused with one). What the agent wrote is
only ever shown, as quoted and escaped data.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Union

from .textutil import printable

DIALOG = "dialog"
ELICITATION = "elicitation"
COMMAND = "command"
COMMAND_PREFIX = "command:"

# What a person can be asked to read. A call with more arguments is refused, not shown in part.
MAX_SHOWN_ARGUMENTS = 20
MAX_SHOWN_NAME_CHARS = 80
MAX_SHOWN_VALUE_CHARS = 200

# A command approver approves by printing this word on its own (one line end allowed).
APPROVE_OUTPUTS = (b"approve", b"approve\n", b"approve\r\n")
# The version of the JSON a command approver reads, in case it ever changes.
COMMAND_INPUT_VERSION = 1
# How long a dialog program or command may outlive the timeout before it is stopped.
_GRACE_SECONDS = 5

# The ids of the proxy's own elicitation requests begin with this, followed by
# 32 random hex digits. The proxy refuses a server request whose id begins the
# same way, so an answer from the client can never be mistaken for another.
APPROVAL_ID_PREFIX = "agent-sentinel-approval-"
# The protocol revisions that have form elicitation, and the one where a request names its mode.
ELICITATION_VERSIONS = ("2025-06-18", "2025-11-25")
_MODE_VERSIONS = ("2025-11-25",)
APPROVE_FIELD = "approve"

# Windows message box flags and answers (winuser.h). OK/Cancel rather than
# Yes/No: in a Yes/No box the letter "y" presses Yes, so a person typing in the
# chat when the box takes the focus could approve without seeing it. Enter,
# Space and Esc all choose Cancel, the default button.
_MB_OKCANCEL = 0x1
_MB_ICONWARNING = 0x30
_MB_DEFBUTTON2 = 0x100
_MB_SETFOREGROUND = 0x10000
_MB_TOPMOST = 0x40000
_IDOK = 1
_IDCANCEL = 2
_MB_TIMEDOUT = 32000  # what MessageBoxTimeoutW returns when nobody answered in time

_OSASCRIPT = "/usr/bin/osascript"
# Runs osascript's display dialog with the text and title as arguments, never
# as part of the script, so nothing in them can be read as AppleScript.
_OSASCRIPT_LINES = (
    "on run argv",
    'display dialog (item 1 of argv) with title (item 2 of argv) buttons {"Refuse", "Allow"} '
    'default button "Refuse" cancel button "Refuse" with icon caution giving up after ((item 3 of argv) as integer)',
    "end run",
)
_OSASCRIPT_ALLOWED = b"button returned:Allow, gave up:false"

# Runs a program: (argv, standard input, timeout in seconds) -> (exit code, or None after a
# timeout, standard output, standard error). Injected in tests.
Runner = Callable[[list, bytes, float], "tuple[int | None, bytes, bytes]"]


class NotShowable(ValueError):
    """The call cannot be shown to a person in full, so nobody is asked and the call is refused."""


@dataclass(frozen=True)
class ApprovalRequest:
    """One call waiting for a person's answer.

    tool:      what the agent wants to call: a tool's name, or "resources/read" / "prompts/get".
    arguments: its arguments, as the agent wrote them.
    reason:    why the policy asks (operator text: it names the rule). Shown by
               the dialog and given to a command, never put in an elicitation,
               which a client might let the model read.
    ref:       the reference the agent is shown if the call is refused, also in the audit log.
    server:    the server's name (proxy --name), if it has one.
    """

    tool: str
    arguments: dict[str, Any]
    reason: str
    ref: str
    server: str | None = None

    def as_json(self, timeout: float) -> dict[str, Any]:
        """What a command approver reads on its standard input (one line of JSON, ASCII only)."""
        return {
            "version": COMMAND_INPUT_VERSION,
            "server": self.server,
            "tool": self.tool,
            "arguments": self.arguments,
            "reason": self.reason,
            "ref": self.ref,
            "timeout_seconds": _whole_seconds(timeout),
        }


@dataclass(frozen=True)
class Answer:
    """What came back. Only `approved is True` lets the call through; `detail` is for the audit log."""

    approved: bool
    detail: str


def _whole_seconds(timeout: float) -> int:
    return max(1, int(timeout))


def _seconds(timeout: float) -> str:
    """A timeout as a person reads it: "1 second", "120 seconds"."""
    count = _whole_seconds(timeout)
    return "1 second" if count == 1 else f"{count} seconds"


# ---- what the person reads ----------------------------------------------------

def check_showable(arguments: Mapping[str, Any]) -> None:
    """Raise NotShowable when the arguments cannot all be shown to a person."""
    if len(arguments) > MAX_SHOWN_ARGUMENTS:
        raise NotShowable(
            f"the call has {len(arguments)} arguments, more than the {MAX_SHOWN_ARGUMENTS} a person can be shown"
        )
    for value in arguments.values():
        _spelled(value)


def _spelled(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise NotShowable("an argument cannot be written out to be shown") from exc


def argument_lines(arguments: Mapping[str, Any]) -> list[str]:
    """One line per argument: its name and its value, each as JSON, made printable and cut to a readable length.

    Written as JSON so that every value is quoted: a value cannot look like
    the end of one argument and the start of another, and a line break in it
    shows as \\n. Every argument gets its line, however long the one before.
    """
    check_showable(arguments)
    lines = []
    for name, value in arguments.items():
        shown_name = printable(json.dumps(str(name), ensure_ascii=False), limit=MAX_SHOWN_NAME_CHARS)
        lines.append(f"  {shown_name}: {printable(_spelled(value), limit=MAX_SHOWN_VALUE_CHARS)}")
    return lines or ["  (none)"]


def _what_is_called(tool: str) -> str:
    if tool == "resources/read":
        return "read a resource"
    if tool == "prompts/get":
        return "fetch a prompt"
    return f"call the tool {printable(json.dumps(tool, ensure_ascii=False), limit=MAX_SHOWN_NAME_CHARS)}"


def approval_text(request: ApprovalRequest, timeout: float, how_to_answer: str = "", for_client: bool = False) -> str:
    """The question, as the person reads it.

    for_client: the text goes into an elicitation. Then the policy's reason
                is left out (a client might let the model read it), and the
                characters that Markdown or HTML would act on are escaped, so
                that agent text cannot hide part of the question in a client
                that renders the message (an HTML comment, a link that shows
                other text than its address, an entity for an invisible character).
    """
    where = f" on the server '{request.server}'" if request.server else ""
    arguments = "\n".join(argument_lines(request.arguments))
    if for_client:
        arguments = _without_markup(arguments)
    lines = [
        f"The agent wants to {_what_is_called(request.tool)}{where}.",
        "",
        "Arguments, as the agent wrote them (long values are cut):",
        arguments,
        "",
    ]
    if not for_client:
        lines.append(f"Why you are asked: {printable(request.reason, limit=300)}")
    lines.append(
        f"If nobody answers within {_seconds(timeout)}, the call is refused. Reference: {request.ref}"
    )
    if how_to_answer:
        lines.append(how_to_answer)
    return "\n".join(lines)


_MARKUP = {"&": "\\u0026", "<": "\\u003c", ">": "\\u003e", "[": "\\u005b", "]": "\\u005d", "`": "\\u0060"}


def _without_markup(text: str) -> str:
    return "".join(_MARKUP.get(ch, ch) for ch in text)


def _title(request: ApprovalRequest) -> str:
    return f"agent-sentinel[{request.server}]: approve a call?" if request.server else "agent-sentinel: approve a call?"


# ---- running a program ------------------------------------------------------------

def run_program(argv: list, data: bytes, timeout: float) -> tuple[int | None, bytes, bytes]:
    """Run a program without a shell, give it `data` on standard input, and wait at most `timeout` seconds.

    Returns (exit code, standard output, standard error); the exit code is
    None when the program did not finish in time. It is then stopped together
    with whatever it started (a .cmd file's interpreter, a dialog it opened),
    so a window it left open cannot be answered after the call was refused.
    """
    options: dict[str, Any] = {}
    if sys.platform == "win32":
        options["creationflags"] = subprocess.CREATE_NO_WINDOW  # no console window flashing up
    else:
        options["start_new_session"] = True  # its own process group, so all of it can be stopped
    process = subprocess.Popen(
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, **options
    )
    try:
        out, err = process.communicate(data, timeout=timeout)
    except subprocess.TimeoutExpired:
        _stop_tree(process)
        return None, b"", b""
    return process.returncode, out, err


def _stop_tree(process: subprocess.Popen) -> None:
    """Stop a program and everything it started, then collect it."""
    try:
        if sys.platform == "win32":
            taskkill = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "taskkill.exe")
            subprocess.run([taskkill, "/PID", str(process.pid), "/T", "/F"], capture_output=True, check=False)
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    process.kill()
    try:
        process.communicate(timeout=_GRACE_SECONDS)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        pass  # a grandchild may still hold a pipe; the process itself is gone


def _first_line(data: bytes) -> str:
    lines = data.decode("utf-8", errors="replace").strip().splitlines()
    return printable(lines[0], limit=120) if lines else ""


def find_program(name: str, environ: Mapping[str, str] = os.environ) -> str | None:
    """Find a program on PATH, looking only in absolute folders and never in the current one.

    The proxy often runs in a project folder, where an agent with a file tool
    could plant a program of the same name.
    """
    try:
        here = os.path.realpath(os.getcwd())
    except OSError:
        here = None
    for folder in environ.get("PATH", "").split(os.pathsep):
        if not os.path.isabs(folder) or os.path.realpath(folder) == here:
            continue
        candidate = os.path.join(folder, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


# ---- the backends -----------------------------------------------------------------

class DialogApprover:
    """Asks in a window on this machine's desktop (see the module docstring for each system)."""

    name = DIALOG

    def __init__(
        self,
        platform: str = sys.platform,
        environ: Mapping[str, str] = os.environ,
        find: Callable[[str], str | None] | None = None,
        run: Runner | None = None,
        message_box: Callable[[str, str, int], int] | None = None,
    ) -> None:
        """The defaults are the real system; tests pass fakes, so that no test ever opens a window.

        message_box: (text, title, timeout in milliseconds) -> the Windows answer code.
        """
        self._platform = platform
        self._environ = environ
        self._find = find if find is not None else (lambda name: find_program(name, environ))
        self._run = run if run is not None else run_program
        self._message_box = message_box

    def describe(self) -> str:
        return DIALOG

    def unavailable(self) -> str | None:
        """Why no dialog can be shown on this machine, or None when one can."""
        if self._platform == "win32":
            if self._message_box is not None or _user32_loads():
                return None
            return "the Windows dialog library (user32) cannot be loaded"
        if self._platform == "darwin":
            return None if os.path.isfile(_OSASCRIPT) else f"{_OSASCRIPT} was not found"
        if not (self._environ.get("DISPLAY") or self._environ.get("WAYLAND_DISPLAY")):
            return "no display is set (DISPLAY or WAYLAND_DISPLAY), so no window can be shown"
        if self._find("zenity") is None:
            return "zenity was not found on PATH (it shows the dialog on Linux)"
        return None

    def ask(self, request: ApprovalRequest, timeout: float) -> Answer:
        if self._platform == "win32":
            return self._ask_windows(request, timeout)
        if self._platform == "darwin":
            return self._ask_macos(request, timeout)
        return self._ask_zenity(request, timeout)

    def _ask_windows(self, request: ApprovalRequest, timeout: float) -> Answer:
        text = approval_text(request, timeout, "Press OK to allow this call, or Cancel to refuse it.")
        message_box = self._message_box or _windows_message_box
        code = message_box(text, _title(request), max(1, int(timeout * 1000)))
        if code == _IDOK:
            return Answer(True, "OK")
        if code == _IDCANCEL:
            return Answer(False, "Cancel")
        if code == _MB_TIMEDOUT:
            return Answer(False, f"no answer within {_seconds(timeout)}")
        return Answer(False, f"the dialog could not be shown (answer code {code})")

    def _ask_macos(self, request: ApprovalRequest, timeout: float) -> Answer:
        text = approval_text(request, timeout, "Choose Allow to allow this call, or Refuse to refuse it.")
        argv = [_OSASCRIPT]
        for line in _OSASCRIPT_LINES:
            argv += ["-e", line]
        argv += [text, _title(request), str(_whole_seconds(timeout))]
        code, out, err = self._run(argv, b"", timeout + _GRACE_SECONDS)
        if code == 0 and out.strip() == _OSASCRIPT_ALLOWED:
            return Answer(True, "Allow")
        return Answer(False, _program_detail("osascript", code, out, err, timeout))

    def _ask_zenity(self, request: ApprovalRequest, timeout: float) -> Answer:
        zenity = self._find("zenity")
        if zenity is None:
            return Answer(False, "zenity was not found")
        text = approval_text(request, timeout, "Choose Allow to allow this call, or Refuse to refuse it.")
        argv = [
            zenity, "--question", "--title", _title(request),
            # zenity reads backslash escapes in its text: "\n" written by the agent (shown
            # as a backslash and an n) would become a real line break. Doubling every
            # backslash keeps them as written. --no-markup keeps "<b>" and the like as text.
            "--text", text.replace("\\", "\\\\"), "--no-markup",
            "--ok-label", "Allow", "--cancel-label", "Refuse", "--default-cancel",
            "--width", "640", "--timeout", str(_whole_seconds(timeout)),
        ]
        code, out, err = self._run(argv, b"", timeout + _GRACE_SECONDS)
        if code == 0:
            return Answer(True, "Allow")
        return Answer(False, _program_detail("zenity", code, out, err, timeout))


def _program_detail(program: str, code: int | None, out: bytes, err: bytes, timeout: float) -> str:
    if code is None:
        return f"no answer within {_seconds(timeout)}"
    problem = _first_line(err) or _first_line(out)
    return f"{program} exited with code {code}" + (f": {problem}" if problem else "")


def _user32_loads() -> bool:
    try:
        import ctypes

        ctypes.WinDLL("user32")
    except (ImportError, OSError, AttributeError):
        return False
    return True


def _windows_message_box(text: str, title: str, timeout_ms: int) -> int:
    """Show a Windows message box (always on top, Cancel the default) and return the answer code.

    MessageBoxTimeoutW closes the box by itself when time is up. It is not in
    Microsoft's documentation but has been in user32 since Windows XP; if it
    is ever missing, MessageBoxW is used, and the proxy's own timeout still
    refuses the call (the box then stays until it is closed, and its answer
    is ignored).
    """
    import ctypes

    user32 = ctypes.WinDLL("user32")
    flags = _MB_OKCANCEL | _MB_ICONWARNING | _MB_DEFBUTTON2 | _MB_SETFOREGROUND | _MB_TOPMOST
    box = getattr(user32, "MessageBoxTimeoutW", None)
    if box is not None:
        box.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_ushort,
                        ctypes.c_uint32)
        box.restype = ctypes.c_int
        return box(None, text, title, flags, 0, timeout_ms)
    box = user32.MessageBoxW
    box.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint)
    box.restype = ctypes.c_int
    return box(None, text, title, flags)


class CommandApprover:
    """Asks the operator's own program (see the module docstring for what it reads and must print)."""

    name = COMMAND

    def __init__(self, program: str, run: Runner | None = None) -> None:
        self.program = program
        self._run = run if run is not None else run_program

    def describe(self) -> str:
        return f"command {self.program}"

    def unavailable(self) -> str | None:
        return None if os.path.isfile(self.program) else f"the program {self.program} no longer exists"

    def ask(self, request: ApprovalRequest, timeout: float) -> Answer:
        data = json.dumps(request.as_json(timeout), ensure_ascii=True).encode("ascii") + b"\n"
        code, out, err = self._run([self.program], data, timeout)
        if code is None:
            return Answer(False, f"no answer within {_seconds(timeout)}")
        if code != 0:
            return Answer(False, _program_detail("the program", code, b"", err, timeout))
        if out not in APPROVE_OUTPUTS:
            return Answer(False, "the program did not print 'approve'")
        return Answer(True, "the program printed 'approve'")


class ElicitationApprover:
    """Asks through the MCP client with a form (elicitation/create).

    The proxy sends the question and receives the answer, because both go
    through its connection to the client; this class builds the one and reads
    the other. It can ask only in a legacy session (2025-06-18 or 2025-11-25)
    whose client declared form elicitation; the proxy decides that per call.
    """

    name = ELICITATION

    def describe(self) -> str:
        return "elicitation (when the client declares it)"

    def unavailable(self) -> str | None:
        return None  # decided by the proxy, from what the client declared

    @staticmethod
    def question(request_id: str, request: ApprovalRequest, timeout: float, version: str) -> dict[str, Any]:
        """The elicitation/create request asking the client's user to approve the call."""
        schema = {
            "type": "object",
            "properties": {
                APPROVE_FIELD: {
                    "type": "boolean",
                    "title": "Allow this call",
                    "description": "Leave this off, or decline, to refuse the call.",
                    "default": False,
                },
            },
            "required": [APPROVE_FIELD],
        }
        params: dict[str, Any] = {}
        if version in _MODE_VERSIONS:
            params["mode"] = "form"
        params["message"] = approval_text(request, timeout, for_client=True)
        params["requestedSchema"] = schema
        return {"jsonrpc": "2.0", "id": request_id, "method": "elicitation/create", "params": params}

    @staticmethod
    def answer(reply: Mapping[str, Any]) -> Answer:
        """Read the client's reply. Only action "accept" with the field exactly true approves."""
        result = reply.get("result")
        if "error" in reply or not isinstance(result, dict):
            return Answer(False, "the client answered with an error")
        action = result.get("action")
        content = result.get("content")
        if action == "accept" and isinstance(content, dict) and content.get(APPROVE_FIELD) is True:
            return Answer(True, "accepted")
        if action in ("decline", "cancel"):
            return Answer(False, f"{action}d")  # "declined", "cancelled"
        if action == "accept":
            return Answer(False, "accepted without approving")
        return Answer(False, "an answer the proxy cannot read")


Approver = Union[DialogApprover, CommandApprover, ElicitationApprover]


def declares_form_elicitation(capabilities: Any) -> bool:
    """Whether a client's capabilities (from initialize) say it can show an elicitation form.

    `"elicitation": {}` means form mode (2025-06-18, and kept so in 2025-11-25);
    from 2025-11-25 a client may name its modes: {"form": {}, "url": {}}.
    """
    elicitation = capabilities.get("elicitation") if isinstance(capabilities, dict) else None
    if not isinstance(elicitation, dict):
        return False
    return not elicitation or isinstance(elicitation.get("form"), dict)


def parse_backend(text: str, resolve: Callable[[str], str | None]) -> Approver:
    """Read one --approve-with value: "dialog", "elicitation" or "command:<program>".

    resolve: finds a program named without a folder on PATH (never in the
             current folder); mcp_proxy passes the function it uses for the
             server command. Raises ValueError with a message for the operator.

    A command must be a full path, or a name found on PATH: a relative path
    would depend on the folder the client starts the proxy in, and could
    point into a folder the agent can write to.
    """
    if text == DIALOG:
        return DialogApprover()
    if text == ELICITATION:
        return ElicitationApprover()
    if text.startswith(COMMAND_PREFIX):
        program = text[len(COMMAND_PREFIX):]
        if not program:
            raise ValueError("write the program after 'command:', for example command:/usr/local/bin/approve")
        if os.path.dirname(program) and not os.path.isabs(program):
            raise ValueError(f"'{printable(program, limit=200)}' is a relative path; write the program's full path")
        found = resolve(program)
        if found is None or not os.path.isfile(found):
            raise ValueError(f"cannot find the program '{printable(program, limit=200)}'")
        if sys.platform != "win32" and not os.access(found, os.X_OK):
            raise ValueError(f"the program '{printable(found, limit=200)}' is not executable")
        return CommandApprover(os.path.abspath(found))
    raise ValueError(
        f"unknown approver '{printable(text, limit=60)}'; write dialog, elicitation or command:<program>"
    )
