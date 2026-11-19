"""Tests for the ways the proxy asks a person to approve a call (approvers.py).

No test opens a real window: every dialog test passes a fake message box or
a fake program runner. The command approver is also tried with real, tiny
programs written into a temporary folder.
"""

import ctypes
import itertools
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import support  # noqa: F401  (puts the project on the path)
from agent_sentinel import approvers
from agent_sentinel.approvers import (
    APPROVAL_ID_PREFIX,
    Answer,
    ApprovalRequest,
    CommandApprover,
    DialogApprover,
    ElicitationApprover,
    NotShowable,
    approval_text,
    argument_lines,
    declares_form_elicitation,
    parse_backend,
)

EMAIL = {"to": "bob@example.com", "subject": "Lunch", "body": "See you at noon."}


def request(arguments=None, tool="send_email", reason="rule 'send_email' says ask", server=None):
    return ApprovalRequest(tool, dict(EMAIL) if arguments is None else arguments, reason, "7f3a9c21", server)


def unhurried():
    """A clock for a dialog fake: each reading is ten seconds after the one before, so no answer comes too fast."""
    return itertools.count(0, 10).__next__


def hurried(seconds):
    """A clock for a dialog fake whose answer comes `seconds` after the dialog opened."""
    return iter([0.0, seconds]).__next__


class FakeRunner:
    """Stands in for run_program: records what it was asked to run and answers as told."""

    def __init__(self, code=0, out=b"", err=b""):
        self.answer = (code, out, err)
        self.calls = []

    def __call__(self, argv, data, timeout):
        self.calls.append((argv, data, timeout))
        return self.answer


# ---- what the person reads -------------------------------------------------------------------

class WhatThePersonReads(unittest.TestCase):
    def test_every_argument_is_shown_quoted_on_its_own_line(self):
        lines = argument_lines({"to": "bob@example.com", "count": 3, "tags": ["a", "b"]})
        self.assertEqual(lines, ['  "to": "bob@example.com"', '  "count": 3', '  "tags": ["a", "b"]'])

    def test_a_long_value_is_cut_with_a_note_and_cannot_push_a_later_argument_out_of_sight(self):
        lines = argument_lines({"to": "bob@example.com", "body": "x" * 50_000, "bcc": "eve@evil.example"})
        self.assertEqual(len(lines), 3)
        self.assertIn("more characters)", lines[1])
        self.assertLess(len(lines[1]), approvers.MAX_SHOWN_VALUE_CHARS + 60)
        self.assertEqual(lines[2], '  "bcc": "eve@evil.example"')

    def test_a_value_cannot_fake_a_line_of_its_own_or_hide_text(self):
        hostile = 'ok"\n  "bcc": "none"\x1b[2K‮evil​'
        (line,) = argument_lines({"body": hostile})
        self.assertNotIn("\n", line)
        for invisible in ("\x1b", "‮", "​"):
            self.assertNotIn(invisible, line)
        self.assertIn('\\"', line)  # the quote inside the value stays escaped

    def test_an_argument_name_is_quoted_and_escaped_too(self):
        (line,) = argument_lines({'to": "x\nbcc': "y"})
        self.assertTrue(line.startswith('  "to\\": \\"x\\nbcc": '))

    def test_more_arguments_than_a_person_can_be_shown_are_refused_not_cut(self):
        too_many = {f"a{n}": n for n in range(approvers.MAX_SHOWN_ARGUMENTS + 1)}
        with self.assertRaises(NotShowable):
            argument_lines(too_many)
        self.assertEqual(len(argument_lines(dict(list(too_many.items())[:-1]))), approvers.MAX_SHOWN_ARGUMENTS)

    def test_a_value_that_cannot_be_written_out_is_refused(self):
        with self.assertRaises(NotShowable):
            argument_lines({"x": object()})

    def test_a_call_without_arguments_says_so(self):
        self.assertEqual(argument_lines({}), ["  (none)"])

    def test_the_dialog_text_names_the_tool_the_server_the_reason_the_time_and_the_ref(self):
        text = approval_text(request(server="mail"), 120, "Press OK to allow it.")
        for expected in ('call the tool "send_email" on the server \'mail\'', '"to": "bob@example.com"',
                         "rule 'send_email' says ask", "within 120 seconds", "7f3a9c21", "Press OK to allow it."):
            self.assertIn(expected, text)

    def test_resource_reads_and_prompts_are_named_as_such(self):
        self.assertIn("read a resource", approval_text(request({"uri": "file:///a"}, tool="resources/read"), 5))
        self.assertIn("fetch a prompt", approval_text(request({"name": "p"}, tool="prompts/get"), 5))

    def test_the_text_for_the_client_leaves_out_the_policy_and_escapes_markup(self):
        hostile = {"bcc": "[team@example.com](mailto:eve@evil.example) <!-- hidden --> `x` &#x202e;"}
        text = approval_text(request(hostile), 60, for_client=True)
        self.assertNotIn("rule 'send_email'", text)
        for markup in ("[", "]", "<", ">", "`", "&"):
            self.assertNotIn(markup, text.split("Arguments", 1)[1])
        self.assertIn("mailto:eve@evil.example", text)  # still shown, as text

    def test_the_text_for_the_client_escapes_markup_in_the_tool_name_too(self):
        # The server chose the name: an unclosed comment in it would hide the rest of the question.
        text = approval_text(request(tool="notes<!--[x](y)`&"), 60, for_client=True)
        for markup in ("[", "]", "<", ">", "`", "&"):
            self.assertNotIn(markup, text)
        self.assertIn("notes\\u003c!--", text.splitlines()[0])

    def test_what_a_command_reads(self):
        data = request(server="mail").as_json(90.7)
        self.assertEqual(data, {"version": 1, "server": "mail", "method": None, "tool": "send_email",
                                "arguments": EMAIL, "reason": "rule 'send_email' says ask", "ref": "7f3a9c21",
                                "timeout_seconds": 90})

    def test_a_subscription_is_named_as_one_although_the_policy_checks_it_as_a_read(self):
        held = ApprovalRequest("resources/read", {"uri": "file:///notes/a.txt"}, "ask", "7f3a9c21",
                               method="resources/subscribe")
        self.assertIn("The agent wants to subscribe to a resource", approval_text(held, 5))
        self.assertNotIn("read a resource", approval_text(held, 5))
        data = held.as_json(5)
        self.assertEqual((data["method"], data["tool"]), ("resources/subscribe", "resources/read"))


# ---- the dialog --------------------------------------------------------------------------------

class TheWindowsDialog(unittest.TestCase):
    def ask(self, code, clock=None):
        shown = []

        def message_box(text, title, timeout_ms):
            shown.append((text, title, timeout_ms))
            return code

        dialog = DialogApprover(platform="win32", message_box=message_box, clock=clock or unhurried())
        return dialog.ask(request(server="mail"), 30), shown[0]

    def test_only_ok_approves(self):
        self.assertEqual(self.ask(1)[0], Answer(True, "OK"))
        for code, detail in ((2, "Cancel"), (32000, "no answer within 30 seconds"), (0, "could not be shown"),
                             (6, "could not be shown")):  # 6 is IDYES, which this box never offers
            with self.subTest(code=code):
                answer = self.ask(code)[0]
                self.assertFalse(answer.approved)
                self.assertIn(detail, answer.detail)

    def test_a_box_that_could_not_be_shown_asked_nobody(self):
        # The audit log then says nobody could be asked, not that a person said no.
        self.assertEqual([self.ask(code)[0].asked for code in (2, 32000, 0, 6)], [True, True, False, False])

    def test_the_box_shows_the_call_and_closes_itself_at_the_timeout(self):
        _, (text, title, timeout_ms) = self.ask(2)
        self.assertIn('"to": "bob@example.com"', text)
        self.assertIn("Press OK to allow this call, or Cancel to refuse it.", text)
        self.assertEqual(title, "agent-sentinel[mail]: approve a call?")
        self.assertEqual(timeout_ms, 30_000)

    def test_the_real_box_is_ok_cancel_with_cancel_the_default_and_always_on_top(self):
        # The ctypes call itself, with a fake user32: no window is opened.
        calls = []

        def message_box_timeout(*args):
            calls.append(args)
            return 1

        user32 = mock.NonCallableMock(spec=["MessageBoxTimeoutW"])
        user32.MessageBoxTimeoutW = message_box_timeout  # a plain function: ctypes sets argtypes on it
        with mock.patch.object(ctypes, "WinDLL", create=True, return_value=user32):
            self.assertEqual(approvers._windows_message_box("text", "title", 5000), 1)
        (hwnd, text, title, flags, language, timeout_ms), = calls
        self.assertEqual((hwnd, text, title, language, timeout_ms), (None, "text", "title", 0, 5000))
        self.assertEqual(flags & 0xF, 0x1)  # MB_OKCANCEL: no Yes button, whose "y" key a typing person could hit
        self.assertTrue(flags & 0x100)  # MB_DEFBUTTON2: Enter and Space choose Cancel
        self.assertTrue(flags & 0x40000)  # MB_TOPMOST
        self.assertFalse(flags & 0x10000)  # not MB_SETFOREGROUND: it must not grab the keys of a person typing

    def test_an_ok_that_comes_too_soon_after_the_box_opened_is_refused(self):
        # Tab then Enter, typed for the editor, moves the focus to OK and presses it.
        answer, _ = self.ask(1, clock=hurried(0.3))
        self.assertFalse(answer.approved)
        self.assertIn("too soon to have been read", answer.detail)
        self.assertEqual(self.ask(1, clock=hurried(approvers.MIN_SECONDS_TO_APPROVE))[0], Answer(True, "OK"))
        self.assertEqual(self.ask(2, clock=hurried(0.3))[0], Answer(False, "Cancel"))

    def test_without_user32_there_is_no_dialog(self):
        with mock.patch.object(approvers, "_user32_loads", return_value=False):
            self.assertIn("user32", DialogApprover(platform="win32").unavailable())
        with mock.patch.object(approvers, "_user32_loads", return_value=True):
            self.assertIsNone(DialogApprover(platform="win32").unavailable())


class TheMacDialog(unittest.TestCase):
    def test_the_text_is_passed_as_an_argument_never_as_script(self):
        runner = FakeRunner(0, b"button returned:Allow, gave up:false\n")
        dialog = DialogApprover(platform="darwin", run=runner, clock=unhurried())
        hostile = request({"body": '" & do shell script "touch /tmp/x" & "'})
        self.assertTrue(dialog.ask(hostile, 45).approved)
        (argv, data, timeout), = runner.calls
        self.assertEqual(argv[0], "/usr/bin/osascript")
        script = " ".join(argv[1:1 + 2 * len(approvers._OSASCRIPT_LINES)])
        self.assertNotIn("touch", script)
        self.assertIn('default button "Refuse" cancel button "Refuse"', script)
        self.assertIn("do shell script", argv[-3])  # the text, as an argument
        self.assertEqual(argv[-1], "45")
        self.assertGreater(timeout, 45)

    def test_only_the_exact_allow_answer_approves(self):
        for code, out in ((1, b""), (0, b"button returned:Refuse, gave up:false"),
                          (0, b"button returned:, gave up:true"), (0, b"button returned:Allow, gave up:true"),
                          (0, b"button returned:Allow, gave up:false, extra"), (None, b"")):
            with self.subTest(code=code, out=out):
                dialog = DialogApprover(platform="darwin", run=FakeRunner(code, out), clock=unhurried())
                self.assertFalse(dialog.ask(request(), 5).approved)

    def test_an_allow_that_comes_too_soon_is_refused(self):
        runner = FakeRunner(0, b"button returned:Allow, gave up:false\n")
        self.assertFalse(DialogApprover(platform="darwin", run=runner, clock=hurried(0.5)).ask(request(), 45).approved)

    def test_only_refuse_and_the_timeout_count_as_asking(self):
        # "Refuse" is the cancel button: osascript ends with error -128. Any other error: no dialog was shown.
        for code, out, err, asked in ((1, b"", b"execution error: User canceled. (-128)\n", True),
                                      (0, b"button returned:, gave up:true", b"", True), (None, b"", b"", True),
                                      (1, b"", b"execution error: No user interaction allowed. (-1713)\n", False)):
            with self.subTest(code=code, err=err):
                dialog = DialogApprover(platform="darwin", run=FakeRunner(code, out, err), clock=unhurried())
                answer = dialog.ask(request(), 5)
                self.assertEqual((answer.approved, answer.asked), (False, asked))


class TheLinuxDialog(unittest.TestCase):
    DISPLAY = {"DISPLAY": ":0", "PATH": "/usr/bin"}

    def dialog(self, runner=None, environ=DISPLAY, zenity="/usr/bin/zenity", clock=None):
        return DialogApprover(platform="linux", environ=environ, find=lambda name: zenity, run=runner or FakeRunner(),
                              clock=clock or unhurried())

    def test_it_needs_a_display_and_zenity(self):
        self.assertIn("no display", self.dialog(environ={"PATH": "/usr/bin"}).unavailable())
        self.assertIn("zenity", self.dialog(zenity=None).unavailable())
        self.assertIsNone(self.dialog().unavailable())
        self.assertIsNone(self.dialog(environ={"WAYLAND_DISPLAY": "wayland-0"}).unavailable())

    def test_zenity_shows_plain_text_with_refuse_as_the_default(self):
        runner = FakeRunner(0)
        self.assertTrue(self.dialog(runner).ask(request({"body": "a\\nb <b>bold</b>"}), 60).approved)
        (argv, _, _), = runner.calls
        for flag in ("--question", "--no-markup", "--default-cancel"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index("--timeout") + 1], "60")
        text = argv[argv.index("--text") + 1]
        self.assertIn("a\\\\\\\\nb", text)  # the agent's backslash is doubled again, so zenity keeps it as written
        self.assertIn("<b>bold</b>", text)

    def test_only_exit_code_zero_approves(self):
        for code in (1, 5, -1, None):
            with self.subTest(code=code):
                self.assertFalse(self.dialog(FakeRunner(code)).ask(request(), 5).approved)

    def test_only_refuse_and_the_timeout_count_as_asking(self):
        # zenity exits with 1 for Refuse or a closed window and 5 at its timeout; other codes are its errors.
        for code, asked in ((1, True), (5, True), (None, True), (-1, False), (255, False)):
            with self.subTest(code=code):
                self.assertEqual(self.dialog(FakeRunner(code)).ask(request(), 5).asked, asked)
        self.assertFalse(self.dialog(zenity=None).ask(request(), 5).asked)

    def test_an_allow_that_comes_too_soon_is_refused(self):
        # zenity (GTK) moves the focus with Tab too.
        answer = self.dialog(FakeRunner(0), clock=hurried(1.0)).ask(request(), 60)
        self.assertFalse(answer.approved)
        self.assertIn("too soon", answer.detail)


class OtherPlatforms(unittest.TestCase):
    def test_a_platform_without_a_known_dialog_cannot_ask(self):
        self.assertIsNotNone(DialogApprover(platform="haiku", environ={}, find=lambda name: None).unavailable())


# ---- the command --------------------------------------------------------------------------------

class TheCommandWithAFakeRunner(unittest.TestCase):
    def test_the_request_goes_to_standard_input_as_one_line_of_json(self):
        runner = FakeRunner(0, b"approve\n")
        self.assertTrue(CommandApprover("/opt/approve", run=runner).ask(request(), 30).approved)
        (argv, data, timeout), = runner.calls
        self.assertEqual(argv, ["/opt/approve"])  # no arguments, so nothing of the agent's reaches a command line
        self.assertTrue(data.endswith(b"\n") and data.count(b"\n") == 1)
        self.assertTrue(data.isascii())
        self.assertEqual(json.loads(data)["arguments"], EMAIL)
        self.assertEqual(timeout, 30)

    def test_only_exit_code_zero_and_exactly_approve_approve(self):
        for out in (b"approve", b"approve\n", b"approve\r\n"):
            with self.subTest(out=out):
                self.assertTrue(CommandApprover("/x", run=FakeRunner(0, out)).ask(request(), 5).approved)
        for code, out in ((0, b"approve "), (0, b" approve"), (0, b"APPROVE"), (0, b"approved"), (0, b"yes"),
                          (0, b"approve\napprove"), (0, b""), (1, b"approve"), (2, b"approve\n"), (None, b"")):
            with self.subTest(code=code, out=out):
                self.assertFalse(CommandApprover("/x", run=FakeRunner(code, out)).ask(request(), 5).approved)

    def test_a_failing_program_is_described_with_its_first_error_line(self):
        answer = CommandApprover("/x", run=FakeRunner(3, b"", b"no such key\x1b[31m\nmore")).ask(request(), 5)
        self.assertEqual(answer, Answer(False, "the program exited with code 3: no such key\\x1b[31m"))


def write_program(folder, body):
    """A program the command approver can start: a .cmd file on Windows, a script with a #! line elsewhere."""
    script = Path(folder) / "approver_body.py"
    script.write_text(body, encoding="utf-8")
    if sys.platform == "win32":
        program = Path(folder) / "approve.cmd"
        program.write_text(f'@"{sys.executable}" "{script}"\r\n', encoding="ascii")
    else:
        program = Path(folder) / "approve"
        program.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
        program.chmod(program.stat().st_mode | stat.S_IXUSR)
    return str(program)


class TheCommandForReal(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)

    def program(self, body):
        return CommandApprover(write_program(self.folder, body))

    def test_a_program_that_prints_approve_approves_and_reads_the_request(self):
        seen = self.folder / "seen.json"
        approver = self.program(
            "import sys\n"
            f"open({str(seen)!r}, 'w').write(sys.stdin.readline())\n"
            "print('approve')\n"
        )
        self.assertTrue(approver.ask(request(), 30).approved)
        self.assertEqual(json.loads(seen.read_text())["arguments"], EMAIL)

    def test_the_agents_text_cannot_make_the_program_approve(self):
        # A program that echoes what it read: whatever the agent wrote is inside the JSON, never alone on a line.
        approver = self.program("import sys\nsys.stdout.write(sys.stdin.read())\n")
        for value in ("approve", "approve\n", "x\napprove\n", "& echo approve", "\"\napprove"):
            with self.subTest(value=value):
                self.assertFalse(approver.ask(request({"body": value}), 30).approved)

    def test_a_program_that_exits_with_an_error_refuses_even_after_printing_approve(self):
        approver = self.program("import sys\nprint('approve')\nsys.exit(1)\n")
        self.assertEqual(approver.ask(request(), 30), Answer(False, "the program exited with code 1"))

    def test_a_program_that_does_not_answer_in_time_is_stopped_and_refuses(self):
        approver = self.program("import time\ntime.sleep(60)\nprint('approve')\n")
        started = time.monotonic()
        answer = approver.ask(request(), 1)
        self.assertEqual(answer, Answer(False, "no answer within 1 second"))
        self.assertLess(time.monotonic() - started, 20)

    def test_a_program_that_reads_nothing_still_answers(self):
        self.assertTrue(self.program("print('approve')\n").ask(request({"body": "x" * 200_000}), 30).approved)


# ---- the elicitation -----------------------------------------------------------------------------

class TheElicitation(unittest.TestCase):
    def test_the_question_is_a_form_with_one_yes_no_field_that_defaults_to_no(self):
        question = ElicitationApprover.question(APPROVAL_ID_PREFIX + "ab" * 16, request(), 60, "2025-11-25")
        self.assertEqual(question["method"], "elicitation/create")
        params = question["params"]
        self.assertEqual(params["mode"], "form")
        field = params["requestedSchema"]["properties"]["approve"]
        self.assertEqual((field["type"], field["default"]), ("boolean", False))
        self.assertEqual(params["requestedSchema"]["required"], ["approve"])
        self.assertIn('"to": "bob@example.com"', params["message"])
        self.assertNotIn("says ask", params["message"])

    def test_the_mode_is_named_only_where_the_protocol_has_it(self):
        question = ElicitationApprover.question("agent-sentinel-approval-x", request(), 60, "2025-06-18")
        self.assertNotIn("mode", question["params"])

    def test_only_accept_with_approve_exactly_true_approves(self):
        def reply(result=None, error=None):
            message = {"jsonrpc": "2.0", "id": "agent-sentinel-approval-x"}
            if result is not None:
                message["result"] = result
            if error is not None:
                message["error"] = error
            return message

        self.assertTrue(ElicitationApprover.answer(reply({"action": "accept", "content": {"approve": True}})).approved)
        for hostile in (
            reply({"action": "accept", "content": {"approve": "true"}}),
            reply({"action": "accept", "content": {"approve": 1}}),
            reply({"action": "accept", "content": {"approve": [True]}}),
            reply({"action": "accept", "content": {}}),
            reply({"action": "accept"}),
            reply({"action": "accept", "content": [True]}),
            reply({"action": "ACCEPT", "content": {"approve": True}}),
            reply({"action": "decline", "content": {"approve": True}}),
            reply({"action": "cancel"}),
            reply({"content": {"approve": True}}),
            reply([]),
            reply(error={"code": -1, "message": "no"}),
            reply({"action": "accept", "content": {"approve": True}}, error={"code": 1, "message": "x"}),
            {"jsonrpc": "2.0", "id": "x"},
        ):
            with self.subTest(hostile=hostile):
                self.assertFalse(ElicitationApprover.answer(hostile).approved)

    def test_an_error_or_an_unreadable_answer_means_nobody_was_asked(self):
        error = {"jsonrpc": "2.0", "id": "x", "error": {"code": -1, "message": "no form"}}
        unknown = {"jsonrpc": "2.0", "id": "x", "result": {"action": "later"}}
        self.assertEqual([ElicitationApprover.answer(reply).asked for reply in (error, unknown)], [False, False])
        for result in ({"action": "decline"}, {"action": "cancel"},
                       {"action": "accept", "content": {"approve": False}}):
            with self.subTest(result=result):
                self.assertTrue(ElicitationApprover.answer({"jsonrpc": "2.0", "id": "x", "result": result}).asked)

    def test_which_clients_can_show_a_form(self):
        for capabilities, expected in (
            ({"elicitation": {}}, True), ({"elicitation": {"form": {}}}, True),
            ({"elicitation": {"form": {}, "url": {}}}, True), ({"elicitation": {"url": {}}}, False),
            ({"elicitation": {"form": True}}, False), ({"elicitation": True}, False), ({}, False), (None, False),
            ([], False), ({"sampling": {}}, False),
        ):
            with self.subTest(capabilities=capabilities):
                self.assertEqual(declares_form_elicitation(capabilities), expected)


# ---- choosing a backend ---------------------------------------------------------------------------

class ReadingApproveWith(unittest.TestCase):
    def test_the_named_backends(self):
        self.assertIsInstance(parse_backend("dialog", lambda name: None), DialogApprover)
        self.assertIsInstance(parse_backend("elicitation", lambda name: None), ElicitationApprover)

    def test_a_command_is_a_full_path_or_a_name_found_on_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            program = write_program(tmp, "print('approve')\n")
            self.assertEqual(parse_backend(f"command:{program}", lambda name: name).program, program)
            found = parse_backend("command:approve-it", lambda name: program if name == "approve-it" else None)
            self.assertEqual(found.program, program)

    def test_a_command_may_start_with_the_home_folder(self):
        # MCP clients start the proxy without a shell, so "~" is read here.
        with tempfile.TemporaryDirectory() as tmp:
            program = write_program(tmp, "print('approve')\n")
            with mock.patch.dict(os.environ, {"HOME": tmp, "USERPROFILE": tmp}):
                found = parse_backend(f"command:~/{os.path.basename(program)}", lambda name: name)
        self.assertEqual(os.path.normcase(found.program), os.path.normcase(os.path.abspath(program)))

    def test_a_command_that_cannot_be_used_is_refused_clearly(self):
        for text, message in (
            ("command:", "write the program"),
            (f"command:{os.path.join('tools', 'approve')}", "relative path"),
            ("command:no_such_program_xyz", "cannot find"),
            ("command:" + os.path.abspath("no_such_folder_xyz/approve"), "cannot find"),
            ("prompt", "unknown approver"),
            ("Dialog", "unknown approver"),
            ("command:\x1b[2Jx/y", "relative path"),
        ):
            with self.subTest(text=text):
                with self.assertRaises(ValueError) as caught:
                    parse_backend(text, lambda name: None)
                self.assertIn(message, str(caught.exception))
                self.assertNotIn("\x1b", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
