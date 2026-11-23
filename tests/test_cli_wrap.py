"""`agent-sentinel clients`, `wrap` and `unwrap` (cli_clients.py, cli_wrap.py, cli_unwrap.py).

Every test runs with HOME, USERPROFILE, APPDATA, LOCALAPPDATA and the current
folder inside a temporary folder (IsolatedHomeTest), so the real client
configurations of the person running the tests are never read or changed.
"""

import json
import os
import sys
import unittest
from unittest import mock

from cli_support import IsolatedHomeTest, run_cli
from agent_sentinel import __version__, clients, templates
from agent_sentinel.cli_common import shown_path
from agent_sentinel.wrapping import PythonCheck

TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
ORIGINAL = {
    "globalShortcut": "Ctrl+Space",
    "mcpServers": {
        "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/work"]},
        "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@2025.4.8"],
                   "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": TOKEN, "LOG_LEVEL": "debug"}},
        "remote-api": {"url": "https://example.com/mcp"},
        "broken": {"args": ["x"]},
    },
    "zUnknownSetting": {"keep": ["me", 1]},
}


class WrapTest(IsolatedHomeTest):
    def setUp(self):
        super().setUp()
        # The Python of the wrapped entries is checked by starting it; here it is said to be fine.
        check = mock.patch("agent_sentinel.cli_wrap.check_python", return_value=PythonCheck(True, __version__))
        self.check_python = check.start()
        self.addCleanup(check.stop)
        self.policy = self.write("policy.json", templates.template("starter"))
        self.config = clients.desktop_locations(os.environ, sys.platform)[0].path

    def place(self, document=ORIGINAL, path=None):
        path = path or self.config
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(json.dumps(document, indent=2).encode("utf-8"))
        return path

    def wrap(self, *args):
        return run_cli("wrap", "--client", "claude-desktop", "--policy", self.policy, *args)

    def backups(self, path=None):
        path = path or self.config
        return sorted(entry for entry in path.parent.iterdir() if entry.name.endswith(".bak"))


class ShowingAndApplying(WrapTest):
    def test_by_default_it_shows_a_diff_and_writes_nothing(self):
        self.place()
        before = self.config.read_bytes()
        code, out, err = self.wrap()
        self.assertEqual(code, 0, err)
        self.assertIn("files", out)
        self.assertRegex(out, r"files\s+will be wrapped, as --name files: "
                              r"npx -y @modelcontextprotocol/server-filesystem")
        self.assertRegex(out, r"remote-api\s+skipped: a remote server")
        self.assertRegex(out, r"broken\s+skipped: the entry has no usable")
        self.assertIn("--- files (now)", out)
        self.assertIn("+++ files (wrapped)", out)
        self.assertIn("Nothing was changed. To make this change, run the same command with --apply.", out)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(self.backups(), [])
        self.assertFalse(self.home.exists())

    def test_env_values_are_never_printed(self):
        self.place()
        for args in ((), ("--apply",)):
            code, out, err = self.wrap(*args)
            self.assertEqual(code, 0, err)
            self.assertNotIn(TOKEN, out + err)
            self.assertNotIn("debug", out + err)
        code, out, err = run_cli("unwrap", "--client", "claude-desktop")
        self.assertNotIn(TOKEN, out + err)

    def test_the_ask_note_counts_asks_from_argument_entries(self):
        # Every rule allows, but a deny_args entry asks: without --approve-with the proxy refuses those calls.
        self.place()
        entry = {"arg": "path", "contains": ".claude", "action": "ask"}
        self.policy.write_text(json.dumps({"tools": {"write_file": {"action": "allow", "deny_args": [entry]}}}),
                               encoding="utf-8")
        code, out, err = self.wrap()
        self.assertEqual(code, 0, err)
        self.assertIn("Its 'ask' rules are refused by the proxy unless it is started with an approver", out)
        self.policy.write_text(json.dumps({"tools": {"write_file": "allow"}}), encoding="utf-8")
        code, out, err = self.wrap()
        self.assertEqual(code, 0, err)
        self.assertNotIn("Its 'ask' rules", out)

    def test_apply_backs_up_then_wraps_every_stdio_server_with_full_paths(self):
        self.place()
        original = self.config.read_bytes()
        code, out, err = self.wrap("--apply")
        self.assertEqual(code, 0, err)
        (backup,) = self.backups()
        self.assertEqual(backup.read_bytes(), original)
        self.assertIn(f"Backup of the original: {shown_path(backup)}", out)
        self.assertIn("2 server(s) wrapped", out)
        document = json.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(list(document), ["globalShortcut", "mcpServers", "zUnknownSetting"])
        self.assertEqual(document["zUnknownSetting"], ORIGINAL["zUnknownSetting"])
        servers = document["mcpServers"]
        self.assertEqual(servers["remote-api"], ORIGINAL["mcpServers"]["remote-api"])
        self.assertEqual(servers["broken"], ORIGINAL["mcpServers"]["broken"])
        files = servers["files"]
        self.assertEqual(files["command"], os.path.abspath(sys.executable))
        args = files["args"]
        # -I: the current folder the client starts the proxy in is not searched for agent_sentinel.
        self.assertEqual(args[:4], ["-I", "-m", "agent_sentinel", "proxy"])
        self.assertEqual(args[args.index("--policy") + 1], str(self.policy))
        self.assertEqual(args[args.index("--audit") + 1], str(self.home / "audit.jsonl"))
        pins = args[args.index("--pins") + 1]
        self.assertTrue(pins.startswith(str(self.home / "pins")))
        self.assertEqual(args[args.index("--name") + 1], "files")
        self.assertEqual(args[args.index("--") + 1:], ORIGINAL["mcpServers"]["files"]["args"][:0] + ["npx", "-y",
                         "@modelcontextprotocol/server-filesystem", "/work"])
        for value in (args[args.index("--policy") + 1], args[args.index("--audit") + 1], pins):
            self.assertTrue(os.path.isabs(value))
        github = servers["github"]
        self.assertEqual(github["env"], ORIGINAL["mcpServers"]["github"]["env"])
        self.assertEqual([github["args"][i + 1] for i, word in enumerate(github["args"]) if word == "--pass-env"],
                         ["GITHUB_PERSONAL_ACCESS_TOKEN", "LOG_LEVEL"])
        self.assertNotEqual(pins, github["args"][github["args"].index("--pins") + 1])  # one pins file per server
        self.assertTrue((self.home / "pins").is_dir())

    def test_wrapping_twice_changes_nothing(self):
        self.place()
        self.assertEqual(self.wrap("--apply")[0], 0)
        wrapped = self.config.read_bytes()
        code, out, _ = self.wrap("--apply")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"files\s+skipped: already wrapped")
        self.assertIn("Nothing to wrap.", out)
        self.assertEqual(self.config.read_bytes(), wrapped)
        self.assertEqual(len(self.backups()), 1)

    def test_a_relative_policy_is_written_as_a_full_path(self):
        self.place()
        relative = os.path.relpath(self.policy)
        code, _, err = run_cli("wrap", "--client", "claude-desktop", "--policy", relative, "--apply")
        self.assertEqual(code, 0, err)
        args = json.loads(self.config.read_text(encoding="utf-8"))["mcpServers"]["files"]["args"]
        self.assertEqual(args[args.index("--policy") + 1], str(self.policy))

    def test_audit_pins_dir_and_monitor_can_be_chosen(self):
        self.place()
        code, out, err = self.wrap("--audit", "logs/a.jsonl", "--pins-dir", "my-pins", "--monitor", "--apply")
        self.assertEqual(code, 0, err)
        self.assertIn("Monitor mode: the proxies will log what they would block, and block NOTHING.", out)
        args = json.loads(self.config.read_text(encoding="utf-8"))["mcpServers"]["files"]["args"]
        self.assertEqual(args[args.index("--audit") + 1], str(self.project / "logs" / "a.jsonl"))
        self.assertTrue(args[args.index("--pins") + 1].startswith(str(self.project / "my-pins")))
        self.assertIn("--monitor", args)
        self.assertTrue((self.project / "logs").is_dir())
        self.assertFalse(self.home.exists())

    def test_only_the_servers_named_are_wrapped(self):
        self.place()
        code, out, err = self.wrap("--server", "github", "--apply")
        self.assertEqual(code, 0, err)
        servers = json.loads(self.config.read_text(encoding="utf-8"))["mcpServers"]
        self.assertEqual(servers["files"], ORIGINAL["mcpServers"]["files"])
        self.assertEqual(servers["github"]["args"][:4], ["-I", "-m", "agent_sentinel", "proxy"])
        code, _, err = self.wrap("--server", "nope")
        self.assertEqual(code, 2)
        self.assertIn("no server named 'nope' in this file; it has: files, github, remote-api, broken", err)

    def test_the_rest_of_the_file_is_kept_byte_for_byte(self):
        text = ('{\n  "a": 1,\n  "mcpServers": {\n    "keep": {"url": "https://x/mcp"},\n'
                '    "w": {"command": "npx", "args": ["pkg"]}\n  },\n  "z": [1,2,3]\n}\n')
        self.config.parent.mkdir(parents=True)
        self.config.write_bytes(text.encode("utf-8"))
        self.assertEqual(self.wrap("--apply")[0], 0)
        written = self.config.read_text(encoding="utf-8")
        self.assertTrue(written.startswith('{\n  "a": 1,\n  "mcpServers": {\n    "keep": {"url": "https://x/mcp"},\n'))
        self.assertTrue(written.endswith('\n  },\n  "z": [1,2,3]\n}\n'))

    def test_the_python_that_would_start_the_proxy_is_checked(self):
        self.place()
        self.check_python.return_value = PythonCheck(True, None)
        code, out, _ = self.wrap()
        self.assertEqual(code, 0)
        self.assertIn("cannot import agent_sentinel when started from another folder", out)
        self.check_python.return_value = PythonCheck(True, "0.0.1")
        _, out, _ = self.wrap()
        self.assertIn("has agent-sentinel 0.0.1 installed", out)

    def test_the_install_advice_names_an_install_that_works(self):
        # agent-sentinel is not on PyPI yet: "pip install agent-sentinel" would fail, or install someone else's
        # package of that name into the Python the client starts.
        self.place()
        self.check_python.return_value = PythonCheck(True, None)
        for args in (("--client", "claude-desktop"), ("--client", "codex", "--name", "files", "--", "npx", "x")):
            with self.subTest(args=args):
                code, out, err = run_cli("wrap", "--policy", self.policy, *args)
                self.assertEqual(code, 0, err)
                self.assertIn("python -m pip install git+https://github.com/FarooqAzamdogar/agent-sentinel.git", out)
                self.assertIn("see Install in the README", out)
                self.assertNotIn("pip install agent-sentinel", out)

    def test_a_leading_tilde_is_the_home_folder(self):
        # Windows PowerShell 5.1 and cmd pass "~" on as it is; it must not become a folder named "~".
        config = self.place(path=self.user / "configs" / "claude.json")
        self.write("user/my-policy.json", templates.template("starter"))
        code, out, err = run_cli("wrap", "--client", "claude-desktop", "--config", "~/configs/claude.json",
                                 "--policy", "~/my-policy.json", "--audit", "~/logs/audit.jsonl",
                                 "--pins-dir", "~/my-pins", "--apply")
        self.assertEqual(code, 0, err)
        args = json.loads(config.read_text(encoding="utf-8"))["mcpServers"]["files"]["args"]
        self.assertEqual(args[args.index("--policy") + 1], str(self.user / "my-policy.json"))
        self.assertEqual(args[args.index("--audit") + 1], str(self.user / "logs" / "audit.jsonl"))
        self.assertTrue(args[args.index("--pins") + 1].startswith(str(self.user / "my-pins") + os.sep))
        self.assertFalse((self.project / "~").exists())
        code, out, err = run_cli("unwrap", "--client", "claude-desktop", "--config", "~/configs/claude.json", "--apply")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(config.read_text(encoding="utf-8")), ORIGINAL)

    def test_a_user_install_is_started_without_isolation_and_the_risk_is_named(self):
        self.place()
        self.check_python.return_value = PythonCheck(False, __version__)
        code, out, err = self.wrap("--apply")
        self.assertEqual(code, 0, err)
        self.assertIn("finds agent_sentinel only in your own site-packages (pip install --user)", out)
        args = json.loads(self.config.read_text(encoding="utf-8"))["mcpServers"]["files"]["args"]
        self.assertEqual(args[:3], ["-m", "agent_sentinel", "proxy"])
        # Still recognised as wrapped, so a second run does not wrap it again.
        self.assertRegex(self.wrap()[1], r"files\s+skipped: already wrapped")


class Refusals(WrapTest):
    def test_a_policy_that_does_not_load_changes_nothing(self):
        self.place()
        before = self.config.read_bytes()
        bad = self.write("bad.json", {"default": "maybe"})
        code, _, err = run_cli("wrap", "--client", "claude-desktop", "--policy", bad, "--apply")
        self.assertEqual(code, 2)
        self.assertIn("Invalid policy:", err)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_a_file_that_is_not_plain_json_is_never_edited(self):
        self.config.parent.mkdir(parents=True)
        self.config.write_bytes(b'{\n  // my servers\n  "mcpServers": {"a": {"command": "npx"}}\n}\n')
        code, _, err = self.wrap("--apply")
        self.assertEqual(code, 2)
        self.assertIn("agent-sentinel reads only plain JSON", err)
        self.assertEqual(self.backups(), [])

    def test_a_json_mistake_is_reported_by_line_without_quoting_the_line(self):
        # A missing comma right after a token: the quoted line would show it.
        self.config.parent.mkdir(parents=True)
        self.config.write_text('{"mcpServers": {"a": {"command": "npx", "env": {"T": "' + TOKEN + '"} "x": 1}}}',
                               encoding="utf-8")
        code, _, err = self.wrap()
        self.assertEqual(code, 2)
        self.assertIn(":1:", err)  # the line (and column) of the mistake
        self.assertIn("not valid JSON", err)
        self.assertNotIn(TOKEN, err)
        self.assertNotIn(TOKEN[:12], err)

    def test_a_backslash_mistake_in_a_secret_is_located_without_quoting_it(self):
        # "\Z" is not a JSON escape. The hint written for policies would quote what follows the backslash.
        secret = "Zx9QpLm77Kw2Rt5Y"
        self.config.parent.mkdir(parents=True)
        self.config.write_text('{"mcpServers": {"db": {"command": "npx", "args": ["db-server@1.0.0"],\n'
                               '  "env": {"DB_PASSWORD": "hunter2\\' + secret + '"}}}}', encoding="utf-8")
        for command in (("wrap", "--client", "claude-desktop", "--policy", self.policy),
                        ("unwrap", "--client", "claude-desktop")):
            with self.subTest(command=command[0]):
                code, out, err = run_cli(*command)
                self.assertEqual(code, 2)
                self.assertIn(":2:", err)
                self.assertIn("a backslash inside text must be doubled", err)
                self.assertNotIn(secret[:6], out + err)
                self.assertNotIn("hunter2", out + err)

    def test_claude_codes_state_file_is_never_edited(self):
        state = self.write("project/.claude.json", {"mcpServers": {"a": {"command": "npx"}}})
        code, _, err = run_cli("wrap", "--client", "claude-code", "--config", state, "--policy", self.policy, "--apply")
        self.assertEqual(code, 2)
        self.assertIn("Claude Code's own state file", err)
        self.assertIn("agent-sentinel wrap --client claude-code --policy POLICY --name NAME --", err)

    def test_a_missing_configuration_is_an_error_not_a_new_file(self):
        code, _, err = self.wrap("--apply")
        self.assertEqual(code, 2)
        self.assertIn("Claude Desktop's configuration was not found", err)
        self.assertFalse(self.config.exists())

    def test_servers_that_are_not_an_object_are_refused(self):
        self.place({"mcpServers": ["a"]})
        code, _, err = self.wrap()
        self.assertEqual(code, 2)
        self.assertIn('"mcpServers" is not an object', err)
        self.place({"other": 1})
        code, _, err = self.wrap()
        self.assertIn('has no "mcpServers" section', err)

    @unittest.skipUnless(sys.platform == "win32", "the Microsoft Store app is a Windows matter")
    def test_two_claude_desktop_files_need_config_to_choose(self):
        self.place()
        store = self.local_appdata / "Packages" / "Claude_abc" / "LocalCache" / "Roaming" / "Claude"
        msix = self.place(path=store / "claude_desktop_config.json")
        code, _, err = self.wrap("--apply")
        self.assertEqual(code, 2)
        self.assertIn("more than one configuration file", err)
        self.assertEqual(self.backups(), [])
        code, _, err = self.wrap("--config", msix, "--apply")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.backups(msix)), 1)
        self.assertEqual(self.backups(), [])

    @unittest.skipUnless(sys.platform == "win32", "batch files are a Windows matter")
    def test_a_server_whose_batch_file_would_mangle_an_argument_is_left_alone(self):
        launcher = self.write("server.cmd", "@echo off\r\n")
        self.place({"mcpServers": {"web": {"command": str(launcher), "args": ["https://x/?a=1&b=2"]}}})
        code, out, _ = self.wrap("--apply")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"web\s+skipped: the proxy would refuse to pass 'https://x/\?a=1&b=2'")
        self.assertIn("Nothing to wrap.", out)

    def test_an_env_key_that_is_not_a_variable_name_leaves_the_entry_alone(self):
        self.place({"mcpServers": {"odd": {"command": "npx", "args": ["x"], "env": {"BAD NAME": "1"}}}})
        code, out, _ = self.wrap()
        self.assertEqual(code, 0)
        self.assertIn("not a plain variable name", out)
        self.assertIn("Nothing to wrap.", out)

    def test_an_env_that_would_change_what_starts_as_the_proxy_leaves_the_entry_alone(self):
        # The client gives "env" to the proxy's Python too; this one would import from another folder, even with -I.
        self.place({"mcpServers": {"odd": {"command": "npx", "args": ["x"],
                                           "env": {"__PYVENV_LAUNCHER__": r"evil\Scripts\python.exe"}}}})
        before = self.config.read_bytes()
        code, out, _ = self.wrap("--apply")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"odd\s+skipped: its \"env\" sets __PYVENV_LAUNCHER__; with that, Python takes its own "
                              r"program file from it")
        self.assertIn("Nothing to wrap.", out)
        self.assertEqual(self.config.read_bytes(), before)

    def test_a_python_without_isolation_is_not_written_into_a_projects_configuration(self):
        # A pip --user install is found only without -I. In a project's file the client starts the proxy in the
        # project, where the repository can put an agent_sentinel folder: doctor would call that entry broken.
        self.check_python.return_value = PythonCheck(False, __version__)
        self.write("repo/.git/HEAD", "ref: refs/heads/main\n")
        mcp = self.write("project/.mcp.json", {"mcpServers": {"a": {"command": "npx", "args": ["x"]}}})
        shared = self.write("repo/configs/servers.json", {"mcpServers": {"a": {"command": "npx", "args": ["x"]}}})
        for args, path in ((["--client", "claude-code"], mcp),
                           (["--client", "claude-desktop", "--config", shared], shared)):
            before = path.read_bytes()
            with self.subTest(path=path):
                code, out, err = run_cli("wrap", *args, "--policy", self.policy, "--apply")
                self.assertEqual(code, 0, err)
                self.assertRegex(out, r"a\s+skipped: the program that would start the proxy, .+, runs -m "
                                      r"agent_sentinel without -I \(or -P, Python 3\.11 and later\) from a "
                                      r"configuration kept in the project")
                self.assertIn("Nothing to wrap.", out)
                self.assertEqual(path.read_bytes(), before)
        # With -I it is written; a user's own file gets the entry without -I (see the --user install test above).
        self.check_python.return_value = PythonCheck(True, __version__)
        self.assertEqual(run_cli("wrap", "--client", "claude-code", "--policy", self.policy, "--apply")[0], 0)
        self.assertEqual(json.loads(mcp.read_text(encoding="utf-8"))["mcpServers"]["a"]["args"][:3],
                         ["-I", "-m", "agent_sentinel"])

    def test_options_that_do_not_go_together(self):
        self.place()
        code, _, err = self.wrap("--name", "x")
        self.assertEqual(code, 2)
        self.assertIn("--name is for printing an entry", err)
        for client in ("codex", "cline", "antigravity", "other"):
            code, _, err = run_cli("wrap", "--client", client, "--policy", self.policy)
            self.assertEqual(code, 2)
            self.assertIn("To print an entry to paste", err)

    def test_hostile_server_names_are_printed_safely(self):
        self.place({"mcpServers": {"evil\x1b[2J\x07": {"command": "npx", "args": ["x\x1b]0;t\x07"]}}})
        code, out, err = self.wrap()
        self.assertEqual(code, 0, err)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        self.assertIn("--name evil--2J:", out)


class Unwrapping(WrapTest):
    def test_unwrap_shows_then_restores_every_wrapped_entry(self):
        original = self.place().read_bytes()
        self.assertEqual(self.wrap("--apply")[0], 0)
        wrapped = self.config.read_bytes()
        code, out, err = run_cli("unwrap", "--client", "claude-desktop")
        self.assertEqual(code, 0, err)
        self.assertRegex(out, r"files\s+will start npx -y @modelcontextprotocol/server-filesystem /work directly again")
        self.assertIn("+++ files (unwrapped)", out)
        self.assertEqual(self.config.read_bytes(), wrapped)
        code, out, err = run_cli("unwrap", "--client", "claude-desktop", "--apply")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.config.read_bytes(), original)  # the very same text, not only the same JSON
        self.assertEqual(len(self.backups()), 2)
        self.assertIn("2 server(s) unwrapped; they are not protected any more.", out)

    def test_nothing_wrapped_means_nothing_to_unwrap(self):
        self.place()
        code, out, _ = run_cli("unwrap", "--client", "claude-desktop", "--apply")
        self.assertEqual(code, 0)
        self.assertIn("No server in it is wrapped.", out)
        self.assertEqual(self.backups(), [])
        code, out, _ = run_cli("unwrap", "--client", "claude-desktop", "--server", "files")
        self.assertRegex(out, r"files\s+skipped: not wrapped")

    def test_a_wrapped_entry_without_a_server_command_is_left_for_a_person(self):
        self.place({"mcpServers": {"half": {"command": "python", "args": ["-m", "agent_sentinel", "proxy", "--policy",
                                                                          "p.json"]}}})
        code, out, _ = run_cli("unwrap", "--client", "claude-desktop", "--apply")
        self.assertEqual(code, 0)
        self.assertIn("without a server command after '--'; fix it by hand", out)
        self.assertEqual(self.backups(), [])

    def test_project_configurations(self):
        vscode = self.write("project/.vscode/mcp.json", {"servers": {"a": {"type": "stdio", "command": "npx",
                                                                           "args": ["pkg"]}}})
        code, _, err = run_cli("wrap", "--client", "vscode", "--policy", self.policy, "--apply")
        self.assertEqual(code, 0, err)
        entry = json.loads(vscode.read_text(encoding="utf-8"))["servers"]["a"]
        self.assertEqual(list(entry), ["type", "command", "args"])
        self.assertEqual(run_cli("unwrap", "--client", "vscode", "--apply")[0], 0)
        self.assertEqual(json.loads(vscode.read_text(encoding="utf-8"))["servers"]["a"],
                         {"type": "stdio", "command": "npx", "args": ["pkg"]})
        cursor = self.write("project/.cursor/mcp.json", {"mcpServers": {"a": {"command": "npx"}}})
        code, out, err = run_cli("wrap", "--client", "cursor", "--project", "--policy", self.policy, "--apply")
        self.assertEqual(code, 0, err)
        self.assertIn("agent_sentinel", cursor.read_text(encoding="utf-8"))
        self.assertNotIn("inside the project folder", out)

    def test_files_the_agent_could_change_are_pointed_out(self):
        self.write("project/.mcp.json", {"mcpServers": {"a": {"command": "npx"}}})
        policy = self.write("project/policy.json", templates.template("readonly"))
        code, out, err = run_cli("wrap", "--client", "claude-code", "--policy", policy, "--audit", "audit.jsonl")
        self.assertEqual(code, 0, err)
        self.assertIn("Warning: the policy, the audit log would be inside the project folder", out)


class EntriesToPaste(WrapTest):
    def test_codex_gets_a_command_to_run(self):
        code, out, err = run_cli("wrap", "--client", "codex", "--policy", self.policy, "--name", "files", "--",
                                 "npx", "-y", "pkg", "--", "--flag")
        self.assertEqual(code, 0, err)
        self.assertIn("codex mcp add files --", out)
        self.assertIn("[mcp_servers.files]", out)
        self.assertIn("Start a new Codex session.", out)
        self.assertTrue((self.home / "pins").is_dir())

    def test_vscode_entries_say_they_are_stdio(self):
        code, out, err = run_cli("wrap", "--client", "vscode", "--policy", self.policy, "--name", "files", "--", "npx")
        self.assertEqual(code, 0, err)
        block = json.loads(out[out.index("{"):out.index("\nIf the server")])
        entry = block["servers"]["files"]
        self.assertEqual(entry["type"], "stdio")
        self.assertEqual(entry["args"][-2:], ["--", "npx"])

    def test_two_servers_printed_under_one_name_get_their_own_pins_files(self):
        def pins_of(*command):
            code, out, err = run_cli("wrap", "--client", "cline", "--policy", self.policy, "--name", "files", "--",
                                     *command)
            self.assertEqual(code, 0, err)
            args = json.loads(out[out.index("{"):out.index("\nIf the server")])["mcpServers"]["files"]["args"]
            return args[args.index("--pins") + 1]

        first, second = pins_of("npx", "server-a"), pins_of("npx", "server-b")
        self.assertNotEqual(first, second)
        self.assertEqual(first, pins_of("npx", "server-a"))
        self.assertTrue(os.path.basename(first).startswith("cline-files-"))

    def test_a_command_that_already_starts_the_proxy_is_not_wrapped_again(self):
        code, _, err = run_cli("wrap", "--client", "codex", "--policy", self.policy, "--name", "f", "--",
                               "agent-sentinel", "proxy", "--policy", "p.json", "--", "npx")
        self.assertEqual(code, 2)
        self.assertIn("cannot print an entry for this command: it is already wrapped", err)

    def test_printing_an_entry_never_edits_anything(self):
        self.place()
        for extra, expected in ((("--apply",), "--apply is for editing"), (("--config", "x.json"), "--config is for"),
                                (("--server", "a"), "--server is for")):
            code, _, err = run_cli("wrap", "--client", "claude-desktop", "--policy", self.policy, "--name", "f",
                                   *extra, "--", "npx")
            self.assertEqual(code, 2)
            self.assertIn(expected, err)
        code, _, err = run_cli("wrap", "--client", "claude-desktop", "--policy", self.policy, "--", "npx")
        self.assertIn("give the server a name with --name", err)
        code, _, err = run_cli("wrap", "--client", "codex", "--policy", self.policy, "--name", "f", "--")
        self.assertIn("give the server command after '--'", err)
        self.assertEqual(self.backups(), [])


class ListingClients(WrapTest):
    def test_found_configurations_are_listed_with_their_counts(self):
        self.place()
        (self.config.parent / "Claude Extensions" / "ant.dir.filesystem").mkdir(parents=True)
        self.write("project/.mcp.json", {"mcpServers": {"x": {"command": "npx"}}})
        self.write("project/.vscode/mcp.json", "{ // comment\n}")
        code, out, err = run_cli("clients")
        self.assertEqual(code, 0, err)
        self.assertIn(shown_path(self.config), out)
        self.assertIn("4 server(s): 2 NOT protected, 1 remote (cannot be protected), 1 broken", out)
        self.assertIn("1 Desktop Extension(s), which cannot be wrapped: ant.dir.filesystem", out)
        self.assertIn("claude-code (project)", out)
        self.assertIn("cannot be read:", out)
        self.assertIn("Also looked for (not found):", out)
        self.assertEqual(self.backups(), [])
        self.assertEqual(self.wrap("--apply")[0], 0)
        _, out, _ = run_cli("clients")
        self.assertIn("4 server(s): 2 protected, 1 remote (cannot be protected), 1 broken", out)

    def test_monitor_mode_and_doubtful_entries_are_not_counted_as_protected(self):
        self.place({"mcpServers": {"plain": {"command": "npx", "args": ["x"]}}})
        self.assertEqual(self.wrap("--monitor", "--apply")[0], 0)
        _, out, _ = run_cli("clients")
        self.assertIn("1 server(s): 1 NOT protected", out)
        self.config.unlink()
        self.place({"mcpServers": {"short": {"command": "agent-sentinel", "args": [
            "proxy", "--policy", str(self.policy), "--mon", "--", "x"]}, "behind": {"command": "cmd.exe", "args": [
                "/c", "evil.py", "&", "agent-sentinel", "proxy", "--policy", str(self.policy), "--", "x"]}}})
        _, out, _ = run_cli("clients")
        self.assertIn("2 server(s): 2 broken", out)
        # Entries whose "env" makes the launcher install or import agent-sentinel from somewhere else.
        self.config.unlink()
        self.place({"mcpServers": {
            "index": {"command": "uvx", "args": ["agent-sentinel==0.5.0", "proxy", "--policy", str(self.policy), "--",
                                                 "x"], "env": {"UV_INDEX_URL": "https://evil.example/simple"}},
            "path": {"command": sys.executable, "args": ["-m", "agent_sentinel", "proxy", "--policy", str(self.policy),
                                                         "--", "x"], "env": {"PYTHONPATH": "evil"}},
            "fine": {"command": sys.executable, "args": ["-I", "-m", "agent_sentinel", "proxy", "--policy",
                                                         str(self.policy), "--", "x"], "env": {"PYTHONPATH": "evil"}}}})
        _, out, _ = run_cli("clients")
        self.assertIn("3 server(s): 1 protected, 2 broken", out)
        # A launcher the client finds relative to its working folder, a Python option that changes what it
        # imports, and a home folder of the entry's own (where the proxy reads "~").
        self.config.unlink()
        proxy = ["proxy", "--policy", str(self.policy), "--", "x"]
        self.place({"mcpServers": {
            "relative": {"command": "tools/python.exe", "args": ["-I", "-m", "agent_sentinel", *proxy]},
            "prefix": {"command": sys.executable, "args": ["-I", "-X", "pycache_prefix=.c", "-m", "agent_sentinel",
                                                           *proxy]},
            "home": {"command": sys.executable, "args": ["-I", "-m", "agent_sentinel", *proxy],
                     "env": {"USERPROFILE": "."}},
            "fine": {"command": sys.executable, "args": ["-I", "-X", "utf8", "-m", "agent_sentinel", *proxy]}}})
        _, out, _ = run_cli("clients")
        self.assertIn("4 server(s): 1 protected, 3 broken", out)

    def test_a_projects_configuration_is_counted_with_its_project_folder(self):
        # The client starts the servers of a project's file in the project, which the repository fills.
        proxy = ["proxy", "--policy", str(self.policy), "--", "x"]
        servers = {
            "plain": {"command": sys.executable, "args": ["-m", "agent_sentinel", *proxy]},
            "options": {"command": sys.executable, "args": ["-B", "-X", "utf8", "-m", "agent_sentinel", *proxy]},
            "isolated": {"command": sys.executable, "args": ["-I", "-X", "utf8", "-m", "agent_sentinel", *proxy]},
            "uvx": {"command": "uvx", "args": ["agent-sentinel@0.5.0", *proxy]}}
        self.write("project/.mcp.json", {"mcpServers": servers})
        self.place({"mcpServers": servers})  # a user's own file: Python without -I is a warning there (doctor)
        _, out, _ = run_cli("clients")
        self.assertIn("4 server(s): 2 protected, 2 broken", out)
        self.assertIn("4 server(s): 4 protected", out)
        if sys.platform == "win32":  # Windows looks in the folder the client starts in before PATH
            self.write("project/uvx.exe", "MZ")
            _, out, _ = run_cli("clients")
            self.assertIn("4 server(s): 1 protected, 3 broken", out)
            self.assertIn("4 server(s): 4 protected", out)

    def test_nothing_found(self):
        code, out, _ = run_cli("clients")
        self.assertEqual(code, 0)
        self.assertIn("No MCP client configuration was found.", out)

    def test_in_the_home_folder_the_users_cursor_file_is_listed_once(self):
        cursor = self.write("user/.cursor/mcp.json", {"mcpServers": {"x": {"command": "npx"}}})
        os.chdir(self.user)
        _, out, _ = run_cli("clients")
        self.assertEqual(out.count(shown_path(cursor)), 1)
        self.assertNotIn("cursor (project)", out)

    @unittest.skipUnless(sys.platform == "win32", "the Microsoft Store app is a Windows matter")
    def test_two_claude_desktop_files_are_pointed_out(self):
        self.place()
        self.place(path=self.local_appdata / "Packages" / "Claude_abc" / "LocalCache" / "Roaming" / "Claude"
                   / "claude_desktop_config.json")
        _, out, _ = run_cli("clients")
        self.assertIn("Claude Desktop has more than one configuration file", out)


class SessionGroups(WrapTest):
    """Every server of one client gets the same --session-group, so that their proxies share flow marks."""

    def groups(self):
        servers = json.loads(self.config.read_text(encoding="utf-8"))["mcpServers"]
        found = {}
        for name in ("files", "github"):
            args = servers[name]["args"]
            found[name] = args[args.index("--session-group") + 1] if "--session-group" in args else None
        return found

    def test_by_default_the_group_is_the_clients_name(self):
        self.place()
        code, out, err = self.wrap("--apply")
        self.assertEqual(code, 0, err)
        self.assertIn("session group 'claude-desktop'", out)
        self.assertEqual(self.groups(), {"files": "claude-desktop", "github": "claude-desktop"})

    def test_a_group_can_be_named_or_left_out(self):
        self.place()
        self.assertEqual(self.wrap("--apply", "--session-group", "work")[0], 0)
        self.assertEqual(self.groups(), {"files": "work", "github": "work"})
        self.place()
        self.assertEqual(self.wrap("--apply", "--session-group", "Work")[0], 0)  # one file whatever the case
        self.assertEqual(self.groups(), {"files": "work", "github": "work"})
        self.place()
        self.assertEqual(self.wrap("--apply", "--no-session-group")[0], 0)
        self.assertEqual(self.groups(), {"files": None, "github": None})

    def test_a_group_that_could_name_another_file_is_refused(self):
        self.place()
        for name in ("../x", "nul"):
            code, _, err = self.wrap("--session-group", name)
            self.assertEqual(code, 2)
            self.assertIn("--session-group", err)
        code, _, err = self.wrap("--session-group", "x", "--no-session-group")
        self.assertEqual(code, 2)

    def test_an_entry_to_paste_gets_the_group_too(self):
        code, out, err = run_cli("wrap", "--client", "vscode", "--policy", self.policy, "--name", "files", "--", "npx")
        self.assertEqual(code, 0, err)
        args = json.loads(out[out.index("{"):out.index("\nIf the server")])["servers"]["files"]["args"]
        self.assertEqual(args[args.index("--session-group") + 1], "vscode")


class EntriesWrappedBeforeSessionGroups(WrapTest):
    """A configuration wrapped by 0.5.0 has no --session-group. wrap says so, and offers the option as a change
    to each such entry; --apply writes it after the usual backup, and nothing else of the entry changes."""

    def wrapped_as_0_5_0_did(self):
        self.place()
        self.assertEqual(self.wrap("--apply", "--no-session-group")[0], 0)  # what 0.5.0 wrote: no group
        for backup in self.backups():
            backup.unlink()
        return self.servers()

    def servers(self):
        return json.loads(self.config.read_text(encoding="utf-8"))["mcpServers"]

    def with_group(self, entry, group="claude-desktop"):
        at = entry["args"].index("--")
        return dict(entry, args=[*entry["args"][:at], "--session-group", group, *entry["args"][at:]])

    def test_the_change_is_shown_and_nothing_is_written_without_apply(self):
        self.wrapped_as_0_5_0_did()
        before = self.config.read_bytes()
        code, out, err = self.wrap()
        self.assertEqual(code, 0, err)
        for name in ("files", "github"):
            self.assertRegex(out, name + r"\s+already wrapped, without a session group \(as versions before 0\.6 "
                                         r"wrapped\): --session-group claude-desktop will be added; nothing else of "
                                         r"the entry changes")
        self.assertIn("+++ files (given the session group)", out)
        self.assertRegex(out, r'\+\s+"--session-group",\n\+\s+"claude-desktop",')
        self.assertNotIn("skipped: already wrapped", out)
        self.assertIn("Nothing was changed. To make this change, run the same command with --apply.", out)
        self.assertNotIn(TOKEN, out + err)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_apply_adds_the_group_to_each_entry_and_touches_nothing_else(self):
        old = self.wrapped_as_0_5_0_did()
        original = self.config.read_bytes()
        code, out, err = self.wrap("--apply")
        self.assertEqual(code, 0, err)
        (backup,) = self.backups()
        self.assertEqual(backup.read_bytes(), original)
        self.assertIn("0 server(s) wrapped, 2 given the session group.", out)
        self.assertIn("The servers share their flow marks as session group 'claude-desktop'", out)
        new = self.servers()
        for name in ("files", "github"):
            self.assertEqual(new[name], self.with_group(old[name]))
            self.assertEqual(list(new[name]), list(old[name]))  # the keys, in their order
        for name in ("remote-api", "broken"):
            self.assertEqual(new[name], old[name])
        document = json.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(document["zUnknownSetting"], ORIGINAL["zUnknownSetting"])
        # the entries read back as wrapped, in the group, and doctor has nothing to say about groups
        code, out, _ = run_cli("doctor", "--config", self.config)
        self.assertNotIn("session-group", out)
        # run again: now there is nothing to do, and wrap says what is true
        code, out, err = self.wrap("--apply")
        self.assertRegex(out, r"files\s+skipped: already wrapped\n")
        self.assertIn("Nothing to wrap.", out)
        self.assertIn("The servers share their flow marks as session group 'claude-desktop'", out)
        self.assertEqual(self.servers(), new)

    def test_unwrap_gives_the_original_entries_back(self):
        self.wrapped_as_0_5_0_did()
        self.assertEqual(self.wrap("--apply")[0], 0)
        self.assertEqual(run_cli("unwrap", "--client", "claude-desktop", "--apply")[0], 0)
        self.assertEqual(self.servers(), ORIGINAL["mcpServers"])

    def test_without_a_group_nothing_is_offered_and_nothing_is_claimed(self):
        old = self.wrapped_as_0_5_0_did()
        code, out, err = self.wrap("--apply", "--no-session-group")
        self.assertEqual(code, 0, err)
        self.assertRegex(out, r"files\s+skipped: already wrapped\n")
        self.assertIn("Nothing to wrap.", out)
        self.assertNotIn("share their flow marks", out)
        self.assertEqual(self.servers(), old)

    def test_a_new_server_is_wrapped_and_the_old_ones_join_its_group(self):
        old = self.wrapped_as_0_5_0_did()
        document = json.loads(self.config.read_text(encoding="utf-8"))
        document["mcpServers"]["notes"] = {"command": "npx", "args": ["-y", "notes-server@1.0.0"]}
        self.place(document)
        code, out, err = self.wrap("--apply", "--session-group", "work")
        self.assertEqual(code, 0, err)
        self.assertIn("1 server(s) wrapped, 2 given the session group.", out)
        new = self.servers()
        self.assertEqual(new["files"], self.with_group(old["files"], "work"))
        self.assertIn("--session-group", new["notes"]["args"])
        # only the servers asked for
        self.place(document)
        code, out, err = self.wrap("--apply", "--server", "files")
        self.assertIn("0 server(s) wrapped, 1 given the session group.", out)
        self.assertEqual(self.servers()["github"], old["github"])

    def test_an_entry_another_python_starts_is_left_alone_and_said_to_be_alone(self):
        old = self.wrapped_as_0_5_0_did()
        document = json.loads(self.config.read_text(encoding="utf-8"))
        other = "C:\\other\\python.exe" if sys.platform == "win32" else "/opt/other/bin/python3"
        for name in ("files", "github"):
            document["mcpServers"][name]["command"] = other  # perhaps an agent-sentinel that knows no groups
        unnamed = document["mcpServers"]["files"]["args"]
        self.place(document)
        code, out, err = self.wrap("--apply")
        self.assertEqual(code, 0, err)
        self.assertRegex(out, r"files\s+skipped: already wrapped, without a session group, so its flow marks stay its "
                              r"own: it does not start the proxy with the Python that runs this command")
        self.assertIn("unwrap it, then wrap again", out)
        self.assertNotIn("share their flow marks", out)  # no entry is, or would be, in the group
        self.assertIn("Nothing to wrap.", out)
        self.assertEqual(self.servers(), document["mcpServers"])
        self.assertEqual(self.backups(), [])
        # an entry without --name cannot be given a group either: the proxy would refuse to start
        document["mcpServers"]["files"]["command"] = old["files"]["command"]
        at = unnamed.index("--name")
        del unnamed[at:at + 2]
        self.place(document)
        code, out, err = self.wrap("--apply")
        self.assertRegex(out, r"files\s+skipped: already wrapped, without a session group, so its flow marks stay its "
                              r"own: it has no --name")

    def test_an_entry_of_another_group_is_named(self):
        self.place()
        self.assertEqual(self.wrap("--apply", "--session-group", "other")[0], 0)
        code, out, err = self.wrap()
        self.assertRegex(out, r"files\s+skipped: already wrapped, in session group 'other' \(not 'claude-desktop'")
        self.assertNotIn("share their flow marks", out)


if __name__ == "__main__":
    unittest.main()
