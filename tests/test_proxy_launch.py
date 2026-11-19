"""Tests for how the proxy starts: --name, and the server's environment (server_env.py: --clean-env,
--pass-env, --env-file, the warning about variables that look like secrets).

The unit tests pass environments in as dictionaries; the end-to-end tests
start the real proxy with an environment of their own, in front of a tiny
server that reports which variables it got. Nothing reads or changes the
environment of the test run itself.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import EXAMPLE_POLICY_PATH, ROOT
from test_proxy import call, request
from agent_sentinel import server_env
from agent_sentinel.server_env import (
    EnvFileError,
    check_pass_name,
    looks_secret,
    missing_names,
    named_variables,
    read_env_file,
    server_environment,
    unnamed_secrets,
)

SECRET_VALUE = "s3cr3t-value-that-must-never-be-printed"


# ---- the environment ---------------------------------------------------------------------------

class TheServersEnvironment(unittest.TestCase):
    POSIX = {"PATH": "/usr/bin", "HOME": "/home/me", "LANG": "C.UTF-8", "LC_ALL": "C", "AWS_SECRET_ACCESS_KEY": "x",
             "GITHUB_TOKEN": "y", "NODE_OPTIONS": "--x", "NODE_ENV": "production", "EDITOR": "vi"}
    WINDOWS = {"PATH": r"C:\Windows", "SYSTEMROOT": r"C:\Windows", "USERPROFILE": r"C:\Users\me", "TEMP": r"C:\t",
               "GITHUB_TOKEN": "y", "OPENAI_API_KEY": "z"}

    def test_clean_env_keeps_only_the_minimal_variables_and_the_named_ones(self):
        environment = server_environment(self.POSIX, clean=True, pass_names=["GITHUB_TOKEN"], windows=False)
        self.assertEqual(set(environment), {"PATH", "HOME", "LANG", "LC_ALL", "GITHUB_TOKEN"})

    def test_a_name_ending_in_a_star_passes_every_variable_that_starts_with_it(self):
        environment = server_environment(self.POSIX, clean=True, pass_names=["NODE_*"], windows=False)
        self.assertIn("NODE_OPTIONS", environment)
        self.assertIn("NODE_ENV", environment)
        self.assertNotIn("GITHUB_TOKEN", environment)

    def test_on_windows_the_minimal_variables_are_the_windows_ones_and_case_does_not_matter(self):
        environment = server_environment(dict(self.WINDOWS, SystemDrive="C:"), clean=True,
                                         pass_names=["github_token"], windows=True)
        self.assertEqual(set(environment) - {"NoDefaultCurrentDirectoryInExePath"},
                         {"PATH", "SYSTEMROOT", "USERPROFILE", "TEMP", "SystemDrive", "GITHUB_TOKEN"})

    def test_on_windows_the_server_never_looks_up_commands_in_the_current_folder(self):
        for clean in (False, True):
            with self.subTest(clean=clean):
                environment = server_environment({"PATH": "x", "nodefaultcurrentdirectoryinexepath": "0"}, clean,
                                                  windows=True)
                self.assertEqual(environment, {"PATH": "x", "NoDefaultCurrentDirectoryInExePath": "1"})
        self.assertNotIn("NoDefaultCurrentDirectoryInExePath", server_environment({}, False, windows=False))

    def test_without_clean_env_everything_is_inherited_and_pass_env_changes_nothing(self):
        environment = server_environment(self.POSIX, clean=False, pass_names=["NOTHING"], windows=False)
        self.assertEqual(environment, self.POSIX)

    def test_env_file_variables_are_added_and_win_over_inherited_ones(self):
        environment = server_environment(self.POSIX, True, added={"GITHUB_TOKEN": "mine", "EXTRA": "1"}, windows=False)
        self.assertEqual((environment["GITHUB_TOKEN"], environment["EXTRA"]), ("mine", "1"))
        windows = server_environment({"Path": "a"}, False, added={"PATH": "b"}, windows=True)
        self.assertEqual({k: v for k, v in windows.items() if k != "NoDefaultCurrentDirectoryInExePath"}, {"PATH": "b"})

    def test_the_proxys_own_environment_is_never_changed(self):
        inherited = dict(self.POSIX)
        server_environment(inherited, True, added={"EXTRA": "1"}, windows=True)
        self.assertEqual(inherited, self.POSIX)

    def test_pass_env_names_the_proxy_does_not_have_are_found(self):
        self.assertEqual(missing_names(self.POSIX, ["GITHUB_TOKEN", "NOPE", "NODE_*", "MISSING_*"], windows=False),
                         ["NOPE"])
        self.assertEqual(missing_names(self.WINDOWS, ["github_token"], windows=True), [])
        self.assertEqual(missing_names(self.POSIX, ["github_token"], windows=False), ["github_token"])

    def test_named_variables_are_those_pass_env_or_the_env_file_named(self):
        environment = {"PATH": "x", "GITHUB_TOKEN": "y", "NODE_ENV": "z", "FROM_FILE": "w"}
        self.assertEqual(named_variables(environment, ["GITHUB_TOKEN", "NODE_*"], ["FROM_FILE"], windows=False),
                         ["FROM_FILE", "GITHUB_TOKEN", "NODE_ENV"])


class NamesThatLookLikeSecrets(unittest.TestCase):
    def test_names_that_look_like_secrets(self):
        for name in ("GITHUB_TOKEN", "OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "DB_PASSWORD",
                     "PGPASSWORD", "PGPASSWD", "GPG_PASSPHRASE", "GOOGLE_APPLICATION_CREDENTIALS", "GITHUB_PAT",
                     "SENTRY_DSN",
                     "SSH_AUTH_SOCK", "githubToken", "stripeApiKey", "NPM_TOKENS", "SESSION_COOKIE", "APIKEY"):
            with self.subTest(name=name):
                self.assertTrue(looks_secret(name))

    def test_names_that_do_not(self):
        for name in ("PATH", "HOME", "KEYBOARD_LAYOUT", "GIT_AUTHOR_NAME", "MONKEY", "TOKENIZERS_PARALLELISM",
                     "PATHEXT", "SECRETARY", "AUTHOR", "LANG", "PWD", "XDG_SESSION_TYPE", "KEYRING_BACKEND"):
            with self.subTest(name=name):
                self.assertFalse(looks_secret(name))

    def test_secret_looking_names_that_were_named_are_not_reported(self):
        environment = {"GITHUB_TOKEN": "a", "OPENAI_API_KEY": "b", "NPM_TOKEN": "c", "FROM_FILE_KEY": "d", "PATH": "e"}
        self.assertEqual(unnamed_secrets(environment, ["GITHUB_TOKEN", "NPM_*"], ["FROM_FILE_KEY"], windows=False),
                         ["OPENAI_API_KEY"])

    def test_pass_env_names_are_checked(self):
        for good in ("GITHUB_TOKEN", "NODE_*", "_X", "a1"):
            with self.subTest(good=good):
                self.assertEqual(check_pass_name(good), good)
        for bad in ("*", "1ABC", "A B", "A=B", "A*B", "", "x" * 300, "ÄBC"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    check_pass_name(bad)


class EnvFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "server.env"

    def read(self, text):
        self.path.write_bytes(text.encode("utf-8") if isinstance(text, str) else text)
        return read_env_file(self.path)

    def refused(self, text):
        with self.assertRaises(EnvFileError) as caught:
            self.read(text)
        message = str(caught.exception)
        self.assertNotIn(SECRET_VALUE, message)
        self.assertIn(str(self.path), message)
        return message

    def test_an_env_file_is_read(self):
        values = self.read(
            "# the server's settings\n\n  # indented comment\nTOKEN=abc\nEMPTY=\nEQUALS=a=b=c\n"
            "DOUBLE=\"two words\"\nSINGLE='it''s'\nHALF=\"no end\nSPACES=  kept as written  \r\n"
        )
        self.assertEqual(values, {"TOKEN": "abc", "EMPTY": "", "EQUALS": "a=b=c", "DOUBLE": "two words",
                                  "SINGLE": "it''s", "HALF": "\"no end", "SPACES": "  kept as written  "})

    def test_a_byte_order_mark_is_allowed(self):
        self.assertEqual(self.read(b"\xef\xbb\xbfA=1\n"), {"A": "1"})

    def test_a_bad_env_file_is_refused_without_showing_any_value(self):
        for what, text in {
            "a line without =": f"GOOD=1\n{SECRET_VALUE}\n",
            "a name with spaces": f"MY TOKEN={SECRET_VALUE}\n",
            "export in front": f"export TOKEN={SECRET_VALUE}\n",
            "a space before =": f"TOKEN ={SECRET_VALUE}\n",
            "a name starting with a digit": f"1TOKEN={SECRET_VALUE}\n",
            "the value as the name": f"{SECRET_VALUE}=x\n",
            "a name set twice": f"TOKEN={SECRET_VALUE}\nTOKEN=again\n",
            "a NUL in a value": f"TOKEN={SECRET_VALUE}\x00\n",
            "a value that is too long": "TOKEN=" + "x" * (server_env.MAX_VALUE_CHARS + 1) + f"{SECRET_VALUE}\n",
        }.items():
            with self.subTest(what):
                message = self.refused(text)
                self.assertRegex(message, r"line \d+")
        self.assertIn("already set on line 1", self.refused(f"TOKEN={SECRET_VALUE}\nTOKEN=again\n"))

    def test_a_file_that_is_not_utf8_or_too_large_or_too_long_is_refused(self):
        self.refused(b"TOKEN=\xff\xfe\n")
        with mock.patch.object(server_env, "MAX_ENV_FILE_BYTES", 10):
            self.refused(f"TOKEN={SECRET_VALUE}\n")
        with mock.patch.object(server_env, "MAX_ENV_FILE_ENTRIES", 2):
            self.refused("A=1\nB=2\nC=3\n")


# ---- the real proxy ------------------------------------------------------------------------------

# A server that answers every request with the names of its environment variables, and the value of one.
ENV_SERVER = r'''
import json, os, sys
for line in sys.stdin:
    message = json.loads(line)
    if "id" in message:
        result = {"names": sorted(os.environ), "from_file": os.environ.get("FROM_FILE")}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}) + "\n")
        sys.stdout.flush()
'''


class StartingTheProxy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.server = self.folder / "env_server.py"
        self.server.write_text(ENV_SERVER, encoding="utf-8")

    def run_proxy(self, proxy_args, messages=(request(1, "ping"),), server=None, extra_env=None):
        """Start the proxy with a known environment; return (replies by id, stderr, exit code)."""
        environment = dict(os.environ, DEMO_SERVICE_TOKEN=SECRET_VALUE, HARMLESS_SETTING="1", **(extra_env or {}))
        environment.pop("PYTHONPATH", None)
        proc = subprocess.run(
            [sys.executable, "-m", "agent_sentinel", "proxy", "--policy", str(EXAMPLE_POLICY_PATH), *proxy_args,
             "--", sys.executable, str(server or self.server)],
            input="".join(json.dumps(m) + "\n" for m in messages).encode(), capture_output=True, cwd=ROOT,
            timeout=60, env=environment,
        )
        replies = {m["id"]: m for m in map(json.loads, proc.stdout.decode().splitlines())}
        return replies, proc.stderr.decode(errors="replace"), proc.returncode

    def test_the_name_labels_every_stderr_line_and_every_audit_record(self):
        audit = self.folder / "audit.jsonl"
        replies, stderr, code = self.run_proxy(["--name", "files.v2", "--audit", str(audit)],
                                               messages=[call(1, "delete_file", {"path": "x"})])
        self.assertEqual(code, 0, stderr)
        lines = [line for line in stderr.splitlines() if line]
        self.assertTrue(lines)
        self.assertTrue(all(line.startswith("agent-sentinel[files.v2]: ") for line in lines), stderr)
        records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
        self.assertEqual({record["server"] for record in records}, {"files.v2"})

    def test_without_a_name_the_lines_start_as_before(self):
        _, stderr, _ = self.run_proxy([])
        self.assertTrue(stderr.startswith("agent-sentinel: "), stderr)

    def test_a_name_outside_the_allowed_characters_stops_the_proxy(self):
        for name in ("my server", "a/b", "x" * 65, "", "naïve"):
            with self.subTest(name=name):
                _, stderr, code = self.run_proxy(["--name", name])
                self.assertEqual(code, 2)
                self.assertIn("argument --name", stderr)

    def test_the_startup_warning_names_secret_looking_variables_but_never_their_values(self):
        replies, stderr, code = self.run_proxy([])
        self.assertEqual(code, 0, stderr)
        self.assertIn("DEMO_SERVICE_TOKEN", stderr)
        self.assertIn("look like secrets", stderr)
        self.assertNotIn(SECRET_VALUE, stderr)
        self.assertIn("DEMO_SERVICE_TOKEN", replies[1]["result"]["names"])  # without --clean-env it is inherited

    def test_a_variable_named_by_pass_env_is_not_warned_about(self):
        _, stderr, _ = self.run_proxy(["--pass-env", "DEMO_SERVICE_TOKEN"])
        self.assertNotIn("DEMO_SERVICE_TOKEN", stderr)

    def test_clean_env_starts_the_server_with_only_what_it_was_given(self):
        env_file = self.folder / "server.env"
        env_file.write_text(f"FROM_FILE={SECRET_VALUE}\n", encoding="utf-8")
        replies, stderr, code = self.run_proxy(
            ["--clean-env", "--pass-env", "HARMLESS_*", "--pass-env", "NOT_SET_HERE", "--env-file", str(env_file)])
        self.assertEqual(code, 0, stderr)
        names = set(replies[1]["result"]["names"])
        self.assertNotIn("DEMO_SERVICE_TOKEN", names)
        self.assertTrue({"PATH", "HARMLESS_SETTING", "FROM_FILE"} <= {name.upper() for name in names} | names)
        self.assertEqual(replies[1]["result"]["from_file"], SECRET_VALUE)
        self.assertIn("--pass-env NOT_SET_HERE: the proxy has no such variable", stderr)
        self.assertIn("--clean-env: the server gets a minimal environment, plus FROM_FILE, HARMLESS_SETTING", stderr)
        self.assertNotIn("look like secrets", stderr)
        self.assertNotIn(SECRET_VALUE, stderr)

    def test_a_bad_env_file_stops_the_proxy_before_the_server_starts(self):
        env_file = self.folder / "server.env"
        env_file.write_text(f"{SECRET_VALUE}\n", encoding="utf-8")
        marker = self.folder / "started"
        server = self.folder / "marker_server.py"
        server.write_text(f"open({str(marker)!r}, 'w').close()\n", encoding="utf-8")
        _, stderr, code = self.run_proxy(["--env-file", str(env_file)], server=server)
        self.assertEqual(code, 2)
        self.assertIn("cannot use the env file", stderr)
        self.assertNotIn(SECRET_VALUE, stderr)
        self.assertFalse(marker.exists())
        _, stderr, code = self.run_proxy(["--env-file", str(self.folder / "missing.env")])
        self.assertEqual(code, 2)

    def test_a_bad_pass_env_name_or_elicitation_host_stops_the_proxy(self):
        for args, expected in ((["--pass-env", "A=B"], "argument --pass-env"),
                               (["--elicitation-host", "https://auth.example.com/"], "cannot use --elicitation-host"),
                               (["--tool-names", "loose"], "argument --tool-names")):
            with self.subTest(args=args):
                _, stderr, code = self.run_proxy(args)
                self.assertEqual(code, 2)
                self.assertIn(expected, stderr)

    def test_a_damaged_pins_file_stops_the_proxy(self):
        pins = self.folder / "pins.json"
        pins.write_text('{"version": 2, "tools": {"x": {"sha256": "nope"}}}', encoding="utf-8")
        _, stderr, code = self.run_proxy(["--pins", str(pins)])
        self.assertEqual(code, 2)
        self.assertIn("cannot load the pins file", stderr)


if __name__ == "__main__":
    unittest.main()
