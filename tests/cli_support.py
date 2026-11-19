"""Running `agent-sentinel` commands inside the test process, which is much faster than a new process.

Never use it for `proxy`: the proxy ends the process it runs in (see mcp_proxy.exit_process).
"""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

import support  # noqa: F401  (puts the project folder on sys.path)
from agent_sentinel.__main__ import main


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
        """Write text (or a value, as JSON) to a file in the folder and return its path."""
        path = self.folder / name
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
