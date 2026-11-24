"""Running `agent-sentinel` commands inside the test process, which is much faster than a new process.

Never use it for `proxy`: the proxy ends the process it runs in (see mcp_proxy.exit_process).
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import support  # noqa: F401  (puts the project folder on sys.path)
from agent_sentinel import home as home_module
from agent_sentinel.__main__ import main

# The fake servers the tests start.
TESTS = Path(__file__).resolve().parent
SCRIPTED_SERVER = TESTS / "scripted_mcp_server.py"
FAKE_SERVER = TESTS.parent / "examples" / "fake_mcp_server.py"


def run_cli(*args, stdin=b""):
    """Run one command; return (exit code, stdout text, stderr text)."""
    out, err = io.StringIO(), io.StringIO()
    saved_stdin = sys.stdin
    sys.stdin = io.TextIOWrapper(io.BytesIO(stdin), encoding="utf-8")
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = main([str(arg) for arg in args])
            except SystemExit as exc:  # argparse refuses the command line
                code = exc.code if isinstance(exc.code, int) else 2
    finally:
        sys.stdin = saved_stdin
    return code, out.getvalue(), err.getvalue()


class TempFolderTest(unittest.TestCase):
    """A test with a temporary folder, `self.folder`, and helpers to write files into it."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, content):
        """Write text (or a value, as JSON) to a file in the folder (made if missing) and return its path."""
        path = self.folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not isinstance(content, (str, bytes)):
            content = json.dumps(content)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def write_log(self, name, records):
        """Write audit records (dicts, or lines of text) as a log and return its path."""
        lines = [record if isinstance(record, str) else json.dumps(record) for record in records]
        return self.write(name, "".join(line + "\n" for line in lines))


class IsolatedHomeTest(TempFolderTest):
    """A test in which every place agent-sentinel could look for a user's files is inside the temporary folder.

    HOME, USERPROFILE, APPDATA, LOCALAPPDATA and XDG_CONFIG_HOME point into it,
    AGENT_SENTINEL_HOME is unset, and the current folder is `self.project`.
    So the commands that find client configurations (clients, wrap, doctor)
    can never read or change the real ones of the person running the tests.
    """

    def setUp(self):
        super().setUp()
        # The full, long form of the path: %TEMP% can be spelled with Windows short (8.3) names,
        # which the path matcher refuses in a policy root.
        self.folder = self.folder.resolve()
        self.user = self.folder / "user"
        self.appdata = self.folder / "appdata"
        self.local_appdata = self.folder / "localappdata"
        self.project = self.folder / "project"
        for folder in (self.user, self.appdata, self.local_appdata, self.project):
            folder.mkdir()
        environment = mock.patch.dict(os.environ, {
            "HOME": str(self.user), "USERPROFILE": str(self.user), "APPDATA": str(self.appdata),
            "LOCALAPPDATA": str(self.local_appdata), "XDG_CONFIG_HOME": str(self.user / ".config"),
        })
        environment.start()
        self.addCleanup(environment.stop)
        for name in ("AGENT_SENTINEL_HOME", "HOMEDRIVE", "HOMEPATH"):
            os.environ.pop(name, None)  # restored by the patch when the test ends
        self._previous_folder = os.getcwd()
        os.chdir(self.project)

    def tearDown(self):
        os.chdir(self._previous_folder)  # before the folder is deleted: Windows cannot delete the current folder
        super().tearDown()

    @property
    def home(self):
        """The agent-sentinel home folder of this test's user."""
        return self.user / ".agent-sentinel"

    def make_home(self, *folders):
        """Create the agent-sentinel home, its pins folder and any others named, as agent-sentinel creates them.

        Owner-only: mode 0700 on POSIX (home.make_private_folder). A fixture
        that made them with Path.mkdir would leave them 0755 under the usual
        umask, which is not what the product does, and `doctor` would then
        report every one of them as readable by other users.
        """
        home_module.make_folders(self.home)
        for folder in folders:
            home_module.make_private_folder(folder)
        return self.home

    def write_private(self, name, content):
        """Write one of agent-sentinel's own files (a policy, a pins file, an audit key) as the product writes it.

        Owner-only: mode 0600 on POSIX (home.PRIVATE_FILE_MODE), which is
        what `init` gives the policy and what the proxy requires of an audit
        key file. On Windows the mode is the read-only flag and means nothing
        to these checks.
        """
        path = self.write(name, content)
        os.chmod(path, home_module.PRIVATE_FILE_MODE)  # 0600 keeps the owner's write permission: rmtree still works
        return path

    def program_on_path(self, name):
        """Make `name` findable as a program on PATH for this test, with a stand-in where the system has none.

        Several checks are written around a server command that starts a
        shell, "cmd /c npx ...", because that is the form a real Windows
        entry takes. What those tests are about is the launch lint, the
        advisories or the containment, not whether the program exists: the
        PATH lookup has tests of its own (test_cli_doctor). So on a system
        with no program of that name, an empty stand-in is written into this
        test's own folder and that folder is put on PATH. The command's words
        stay as they were, so every check reads the same entry everywhere.
        """
        from agent_sentinel import mcp_proxy

        if mcp_proxy._resolve_executable(name) is not None:
            return
        folder = self.folder / "programs"
        folder.mkdir(exist_ok=True)
        # Never with a .bat or .cmd ending: doctor fails an entry that passes such arguments to a batch file.
        stand_in = folder / ((name + ".exe") if sys.platform == "win32" else name)
        stand_in.write_bytes(b"")
        stand_in.chmod(0o755)  # POSIX looks for the execute bit (mcp_proxy._resolve_executable)
        path = mock.patch.dict(os.environ, {"PATH": str(folder) + os.pathsep + os.environ.get("PATH", "")})
        path.start()
        self.addCleanup(path.stop)
        self.assertIsNotNone(mcp_proxy._resolve_executable(name), f"the stand-in for {name} is not on PATH")

    def scenario(self, **scenario):
        """Write a scenario for tests/scripted_mcp_server.py; return the command that starts it."""
        path = self.write(f"scenario-{len(list(self.folder.glob('scenario-*')))}.json", scenario)
        return [sys.executable, str(SCRIPTED_SERVER), str(path)]
