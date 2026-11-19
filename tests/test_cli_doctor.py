"""`agent-sentinel doctor` (agent_sentinel/cli_doctor.py), on fixture configurations only.

Every test runs with HOME, USERPROFILE, APPDATA, LOCALAPPDATA and the current
folder inside a temporary folder (IsolatedHomeTest): doctor never reads the
real client configurations of the person running the tests.
"""

import json
import os
import sys
import unittest
from unittest import mock

from cli_support import IsolatedHomeTest, run_cli
from agent_sentinel import __version__, cli_doctor, clients, templates

TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"


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
        status, text = self.reasons({"command": str(self.folder / "missing-python"),
                                     "args": ["-m", "agent_sentinel", "proxy", "--policy", str(self.policy),
                                              "--", "x"]})
        self.assertIn("the program that starts the proxy", text)
        status, text = self.reasons({"command": sys.executable, "args": ["-m", "agent_sentinel", "proxy", "--policy",
                                                                         str(self.policy)]})
        self.assertEqual(status, "broken")
        self.assertIn("no server command after '--'", text)

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
        program = self.write("not-python.exe", "MZ")
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
