"""`agent-sentinel hook install claude-code` (agent_sentinel/cli_hook.py).

Every test runs with HOME, USERPROFILE and the current folder inside a
temporary folder (IsolatedHomeTest): the real ~/.claude/settings.json of the
person running the tests is never read or changed.
"""

import json
import os
import sys
from unittest import mock

from cli_support import IsolatedHomeTest, run_cli
from agent_sentinel import __version__, cli_hook
from agent_sentinel.wrapping import PythonCheck

POLICY = {"default": "block", "tools": {"Read": "allow", "Bash": "ask", "mcp__github__*": "allow"}}
EXISTING = {
    "model": "opus",
    "hooks": {
        "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/my-check"}]}],
        "Stop": [{"hooks": [{"type": "command", "command": "notify-send done"}]}],
    },
    "permissions": {"allow": ["Read"]},
}


class InstallTest(IsolatedHomeTest):
    def setUp(self):
        super().setUp()
        # The hooks' Python is checked by starting it; here it is said to be fine.
        check = mock.patch("agent_sentinel.cli_hook.this_python", return_value=PythonCheck(True, __version__))
        self.python_check = check.start()
        self.addCleanup(check.stop)
        self.policy = self.write("policy.json", POLICY)
        self.settings = self.user / ".claude" / "settings.json"

    def install(self, *args):
        return run_cli("hook", "install", "claude-code", "--policy", self.policy, *args)

    def place(self, document=EXISTING, text=None):
        self.settings.parent.mkdir(parents=True, exist_ok=True)
        self.settings.write_bytes((text if text is not None else json.dumps(document, indent=2)).encode("utf-8"))
        return self.settings.read_bytes()

    def backups(self):
        return sorted(path for path in self.settings.parent.iterdir() if path.name.endswith(".bak"))

    def our_handlers(self, document):
        return [handler for groups in document["hooks"].values() for group in groups for handler in group["hooks"]
                if cli_hook.is_our_handler(handler)]


class PrintingTheSnippet(InstallTest):
    def test_without_settings_it_prints_the_hooks_and_writes_nothing(self):
        code, out, err = self.install()
        self.assertEqual(code, 0, err)
        snippet = json.loads(out[out.index("{"):out.index("\nWhich file:")])
        hooks = snippet["hooks"]
        self.assertEqual(set(hooks), {"SessionStart", "PreToolUse", "PostToolUse", "PostToolUseFailure",
                                      "Elicitation", "ElicitationResult", "ConfigChange"})
        self.assertEqual(hooks["PreToolUse"][0]["matcher"], "*")
        self.assertEqual(hooks["PostToolUse"][0]["matcher"],
                         "WebFetch|WebSearch|ReadMcpResourceTool|ListMcpResourcesTool|mcp__.*")
        self.assertEqual(hooks["Elicitation"][0]["matcher"], "*")
        self.assertEqual(hooks["ElicitationResult"][0]["matcher"], "*")
        self.assertEqual(hooks["ConfigChange"][0]["matcher"],
                         "user_settings|project_settings|local_settings|policy_settings|skills")
        handler = hooks["PreToolUse"][0]["hooks"][0]
        self.assertEqual(handler["type"], "command")
        self.assertEqual(handler["command"], os.path.abspath(sys.executable))
        self.assertEqual(handler["args"][:5], ["-I", "-m", "agent_sentinel", "hook", "claude-code"])
        self.assertEqual(handler["onFailure"], "block")
        self.assertEqual(handler["timeout"], 60)
        options = dict(zip(handler["args"][5::2], handler["args"][6::2]))
        self.assertEqual(options, {
            "--policy": str(self.policy),
            "--audit": str(self.home / "audit.jsonl"),
            "--state-dir": str(self.home / "hook-state"),
        })
        self.assertIn("v2.1.295", out)
        self.assertFalse(self.settings.exists())
        self.assertFalse(self.home.exists())

    def test_the_options_reach_the_hooks(self):
        audit, state = self.folder / "logs" / "a.jsonl", self.folder / "st"
        code, out, _ = self.install("--audit", audit, "--state-dir", state, "--no-log-args", "--scan-all-results")
        self.assertEqual(code, 0)
        hooks = json.loads(out[out.index("{"):out.index("\nWhich file:")])["hooks"]
        handler = hooks["PostToolUse"][0]["hooks"][0]
        self.assertEqual(hooks["PostToolUse"][0]["matcher"], "*")
        self.assertEqual(handler["args"][-1], "--no-log-args")
        self.assertIn(str(audit), handler["args"])
        self.assertIn(str(state), handler["args"])

    def test_subagent_reports_are_scanned_only_on_request(self):
        code, out, _ = self.install("--scan-subagent-reports")
        self.assertEqual(code, 0)
        hooks = json.loads(out[out.index("{"):out.index("\nWhich file:")])["hooks"]
        matcher = "WebFetch|WebSearch|ReadMcpResourceTool|ListMcpResourcesTool|mcp__.*|Agent|SubagentHandback"
        self.assertEqual(hooks["PostToolUse"][0]["matcher"], matcher)
        self.assertEqual(hooks["PostToolUseFailure"][0]["matcher"], matcher)
        self.assertIn("MCP resources and subagent reports)", out)
        code, _, err = self.install("--scan-subagent-reports", "--scan-all-results")
        self.assertEqual(code, 2)
        self.assertIn("not allowed with argument", err)

    def test_it_warns_about_tools_whose_output_or_prompt_it_cannot_cover(self):
        self.policy = self.write("policy.json", {"default": "ask", "tools": {"Read": "allow"}})
        _, out, _ = self.install()
        self.assertIn("so is an 'ask' for SubagentHandback in auto mode", out)
        self.assertIn("Monitor, whose streamed events no hook can scan", out)
        self.assertNotIn("hook.config_changes", out)
        self.policy = self.write("policy.json", {"default": "block", "tools": {"Monitor": "block"},
                                                 "hook": {"config_changes": "block",
                                                          "treat_auto_as_non_prompting": True}})
        _, out, _ = self.install()
        self.assertIn("SubagentHandback, ReadMcpResourceTool, ListMcpResourcesTool, Monitor, MultiEdit,", out)
        self.assertIn("ToolSearch, Skill, TaskCreate, TaskUpdate, TaskList, TaskGet, TaskOutput, TaskStop, "
                      "BashOutput, KillShell (it has no rule", out)
        self.assertNotIn("whose streamed events", out)
        self.assertIn("is refused (hook.config_changes)", out)

    def test_it_says_what_the_session_features_of_the_policy_do_in_hook_mode(self):
        # The 0.6 session features: the warn notice, server_labels (proxy only), approval memory (never learns here).
        self.policy = self.write("policy.json", {"default": "ask", "tools": {"Read": "allow"}})
        _, out, _ = self.install()
        self.assertIn("approval memory (approvals) does not apply", out)
        self.assertNotIn("injection.warn_severity", out)
        self.assertNotIn("server_labels", out)
        self.assertIn("session limits, the end of the last output for the tail scan, and the settings snapshot", out)
        self.policy = self.write("policy.json", {"default": "block", "tools": {"Read": "allow"},
                                                 "injection": {"warn_severity": "medium"},
                                                 "server_labels": {"web": ["untrusted"]},
                                                 "flows": [{"after": ["untrusted"], "then": "sink", "action": "block"}]})
        _, out, _ = self.install()
        self.assertIn("at or above medium (injection.warn_severity) reaches Claude with a notice", out)
        self.assertIn("server_labels apply in the proxy only", out)
        self.assertNotIn("approval memory", out)

    def test_a_python_that_finds_the_package_only_in_user_site_packages_runs_it_without_isolation(self):
        self.python_check.return_value = PythonCheck(False, __version__)
        code, out, _ = self.install()
        self.assertEqual(code, 0)
        self.assertIn('"-m",\n', out)
        self.assertNotIn('"-I"', out)
        self.assertIn("Warning:", out)

    def test_the_install_advice_names_an_install_that_works(self):
        self.python_check.return_value = PythonCheck(True, None)
        self.settings.parent.mkdir(parents=True)
        for args in ((), ("--settings", self.settings)):
            with self.subTest(args=args):
                code, out, _ = self.install(*args)
                self.assertEqual(code, 0)
                self.assertIn("python -m pip install git+https://github.com/FarooqAzamdogar/agent-sentinel.git", out)
                self.assertNotIn("pip install agent-sentinel", out)

    def test_a_leading_tilde_is_the_home_folder(self):
        # Windows PowerShell 5.1 and cmd pass "~" on as it is.
        self.write("user/hook-policy.json", POLICY)
        self.settings.parent.mkdir(parents=True)
        code, out, err = run_cli("hook", "install", "claude-code", "--policy", "~/hook-policy.json",
                                 "--audit", "~/logs/audit.jsonl", "--state-dir", "~/state",
                                 "--settings", "~/.claude/settings.json", "--apply")
        self.assertEqual(code, 0, err)
        (handler, *_) = self.our_handlers(json.loads(self.settings.read_text(encoding="utf-8")))
        options = dict(zip(handler["args"][5::2], handler["args"][6::2]))
        self.assertEqual(options, {"--policy": str(self.user / "hook-policy.json"),
                                   "--audit": str(self.user / "logs" / "audit.jsonl"),
                                   "--state-dir": str(self.user / "state")})
        self.assertFalse((self.project / "~").exists())

    def test_it_warns_when_the_policy_blocks_claude_codes_own_tools(self):
        _, out, _ = self.install()
        self.assertIn("the policy blocks Claude Code's own tools Glob, Grep, Edit, Write", out)
        self.assertIn("Its 'ask' rules show Claude Code's own permission prompt", out)

    def test_the_ask_note_counts_asks_from_command_checks(self):
        # Every rule allows, but the Bash command section asks: bypassPermissions still refuses those calls.
        self.policy.write_text(json.dumps({"tools": {"Bash": {"action": "allow",
                                                              "command": {"ask_classes": ["network"]}}}}),
                               encoding="utf-8")
        _, out, _ = self.install()
        self.assertIn("Its 'ask' rules show Claude Code's own permission prompt", out)
        self.policy.write_text(json.dumps({"tools": {"Bash": "allow"}}), encoding="utf-8")
        _, out, _ = self.install()
        self.assertNotIn("Its 'ask' rules", out)

    def test_a_policy_that_does_not_load_stops_it(self):
        self.policy.write_text('{"default": "deny"}', encoding="utf-8")
        code, out, err = self.install()
        self.assertEqual(code, 2)
        self.assertIn("Invalid policy", err)
        self.assertEqual(out, "")

    def test_apply_needs_a_settings_file(self):
        code, _, err = self.install("--apply")
        self.assertEqual(code, 2)
        self.assertIn("--apply needs --settings FILE", err)

    def test_a_path_with_a_placeholder_is_refused(self):
        code, _, err = self.install("--state-dir", self.folder / "${CLAUDE_PROJECT_DIR}")
        self.assertEqual(code, 2)
        self.assertIn("placeholder", err)


class ChangingASettingsFile(InstallTest):
    def test_by_default_it_shows_the_change_and_writes_nothing(self):
        before = self.place()
        code, out, err = self.install("--settings", self.settings)
        self.assertEqual(code, 0, err)
        self.assertIn("--- hooks (now)", out)
        self.assertIn("+++ hooks (with agent-sentinel)", out)
        self.assertIn("Nothing was changed. To make this change, run the same command with --apply.", out)
        self.assertEqual(self.settings.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_apply_adds_the_hooks_after_a_backup_and_keeps_everything_else(self):
        before = self.place()
        code, out, err = self.install("--settings", self.settings, "--apply")
        self.assertEqual(code, 0, err)
        (backup,) = self.backups()
        self.assertEqual(backup.read_bytes(), before)
        document = json.loads(self.settings.read_text(encoding="utf-8"))
        self.assertEqual((document["model"], document["permissions"]), ("opus", {"allow": ["Read"]}))
        self.assertEqual(list(document), ["model", "hooks", "permissions"])
        hooks = document["hooks"]
        self.assertEqual(hooks["Stop"], EXISTING["hooks"]["Stop"])
        self.assertEqual(hooks["PreToolUse"][0], EXISTING["hooks"]["PreToolUse"][0], "the user's own hook stays first")
        self.assertEqual(len(self.our_handlers(document)), 7)
        self.assertTrue((self.home / "hook-state").is_dir())
        self.assertIn("Backup of the original", out)

    def test_installing_twice_changes_nothing_and_another_policy_replaces_the_entries(self):
        self.place()
        self.install("--settings", self.settings, "--apply")
        after_first = self.settings.read_bytes()
        code, out, _ = self.install("--settings", self.settings, "--apply")
        self.assertEqual(code, 0)
        self.assertIn("already in it", out)
        self.assertEqual(self.settings.read_bytes(), after_first)
        other = self.write("other-policy.json", POLICY)
        run_cli("hook", "install", "claude-code", "--policy", other, "--settings", self.settings, "--apply")
        handlers = self.our_handlers(json.loads(self.settings.read_text(encoding="utf-8")))
        self.assertEqual(len(handlers), 7)
        self.assertTrue(all(str(other) in handler["args"] for handler in handlers))

    def test_a_missing_settings_file_is_created_only_with_apply(self):
        self.settings.parent.mkdir(parents=True)
        code, out, _ = self.install("--settings", self.settings)
        self.assertEqual(code, 0)
        self.assertIn("does not exist yet", out)
        self.assertFalse(self.settings.exists())
        code, out, _ = self.install("--settings", self.settings, "--apply")
        self.assertEqual(code, 0)
        self.assertEqual(set(json.loads(self.settings.read_text(encoding="utf-8"))), {"hooks"})
        self.assertIn("Created", out)

    def test_a_settings_file_in_a_missing_folder_is_refused(self):
        code, _, err = self.install("--settings", self.folder / "nowhere" / "settings.json", "--apply")
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)

    def test_line_endings_and_a_compact_file_are_kept(self):
        self.place(text='{"model": "opus", "hooks": {}, "env": {"A": "1"}}\r\n')
        self.install("--settings", self.settings, "--apply")
        text = self.settings.read_bytes().decode("utf-8")
        self.assertTrue(text.startswith('{"model": "opus", "hooks": {"SessionStart": '))
        self.assertTrue(text.endswith(', "env": {"A": "1"}}\r\n'))

    def test_settings_that_cannot_be_read_safely_are_refused(self):
        for name, text, expected in (
            ("comments", '{\n  // mine\n  "hooks": {}\n}', "plain JSON"),
            ("hooks that are not an object", '{"hooks": []}', '"hooks" in the settings file is not an object'),
            ("an event that is not a list", '{"hooks": {"PreToolUse": {}}}', "is not a list"),
        ):
            with self.subTest(name):
                before = self.place(text=text)
                code, _, err = self.install("--settings", self.settings, "--apply")
                self.assertEqual(code, 2)
                self.assertIn(expected, err)
                self.assertEqual(self.settings.read_bytes(), before)

    def test_a_backslash_mistake_in_a_secret_is_located_without_quoting_it(self):
        before = self.place(text='{"env": {"ANTHROPIC_API_KEY": "abc\\Qsecretpart12345"}}')
        code, out, err = self.install("--settings", self.settings, "--apply")
        self.assertEqual(code, 2)
        self.assertIn("not valid JSON: Invalid \\escape", err)
        self.assertNotIn("secretpart", out + err)
        self.assertEqual(self.settings.read_bytes(), before)

    def test_claude_codes_own_state_file_is_never_edited(self):
        state = self.write("user/.claude.json", {"projects": {}})
        code, _, err = self.install("--settings", state, "--apply")
        self.assertEqual(code, 2)
        self.assertIn("never edits", err)

    def test_a_project_settings_file_warns_about_files_inside_the_project(self):
        settings = self.project / ".claude" / "settings.local.json"
        settings.parent.mkdir()
        code, out, _ = run_cli("hook", "install", "claude-code", "--policy", self.write("project/policy.json", POLICY),
                               "--settings", settings, "--state-dir", self.project / "state")
        self.assertEqual(code, 0)
        self.assertIn("Warning: the policy, the state folder would be inside the project folder", out)
        _, out, _ = self.install("--settings", self.settings)
        self.assertNotIn("inside the project folder", out)


class RecognisingOurEntries(InstallTest):
    def test_entries_that_run_the_hook_command_are_ours_and_others_are_not(self):
        ours = (
            {"type": "command", "command": "C:\\py\\python.exe", "args": ["-I", "-m", "agent_sentinel", "hook",
                                                                         "claude-code", "--policy", "p"]},
            {"type": "command", "command": "python -m agent_sentinel hook claude-code --policy p.json"},
            {"type": "command", "command": "C:\\py\\Scripts\\agent-sentinel.exe", "args": ["hook", "claude-code"]},
            {"type": "command", "command": "/usr/bin/agent-sentinel", "args": ["hook", "claude-code"]},
            {"type": "command", "command": "uvx agent-sentinel@0.5.0 hook claude-code --policy p"},
            {"type": "command", "command": "uvx", "args": ["agent-sentinel==0.5.0", "hook", "claude-code"]},
            {"type": "command", "command": "pipx run agent-sentinel hook claude-code"},
            {"type": "command", "command": "python -m agent_sentinel.__main__ hook claude-code"},
        )
        others = (
            {"type": "command", "command": "/usr/local/bin/my-check"},
            {"type": "command", "command": "python", "args": ["hook", "claude-code"]},
            {"type": "command", "command": "agent-sentinel", "args": ["report", "audit.jsonl"]},
            {"type": "http", "url": "https://example.com"},
            "not an entry",
        )
        for handler in ours:
            self.assertTrue(cli_hook.is_our_handler(handler), handler)
        for handler in others:
            self.assertFalse(cli_hook.is_our_handler(handler), handler)

    def test_a_group_shared_with_another_hook_keeps_the_other_hook(self):
        ours = {"type": "command", "command": "python -m agent_sentinel hook claude-code"}
        mine = {"type": "command", "command": "my-check"}
        merged = cli_hook.merged_hooks({"PreToolUse": [{"matcher": "*", "hooks": [ours, mine]}]},
                                       cli_hook.hook_groups(ours))
        self.assertEqual(merged["PreToolUse"][0], {"matcher": "*", "hooks": [mine]})
        self.assertEqual(merged["PreToolUse"][1]["hooks"], [ours])


class WhatInstallSaysAboutClaudeCodesOwnTools(InstallTest):
    def header(self, policy):
        self.policy = self.write("policy.json", policy)
        code, out, err = self.install()
        self.assertEqual(code, 0, err)
        return out.split("Add this to", 1)[0]

    def test_a_policy_written_for_mcp_servers_is_warned_about_every_tool_it_blocks(self):
        header = self.header({"default": "block", "tools": {"mcp__github__*": "allow", "Read": "allow"}})
        (warning,) = [line for line in header.splitlines() if "the policy blocks Claude Code's own tools" in line]
        for tool in ("Bash", "ToolSearch", "Skill", "TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "TaskOutput",
                     "TaskStop", "EnterPlanMode", "ExitPlanMode", "AskUserQuestion", "Monitor"):
            self.assertIn(f" {tool}", warning)
        self.assertNotIn(" Read,", warning)
        (note,) = [line for line in header.splitlines() if "the policy also refuses" in line]
        self.assertIn("EnterWorktree, ExitWorktree, LSP, CronCreate, CronDelete, CronList, SendMessage, ListAgents",
                      note)
        self.assertEqual(set(cli_hook.BUILT_IN_TOOLS) & set(cli_hook.OTHER_BUILT_IN_TOOLS), set())

    def test_the_hook_templates_decide_each_tool_install_knows_and_get_no_warning(self):
        from agent_sentinel import Policy, templates

        for name in ("claude-code", "claude-code-strict"):
            with self.subTest(template=name):
                document = templates.template(name)
                header = self.header(document)
                self.assertNotIn("the policy blocks Claude Code's own tools", header)
                self.assertNotIn("warning(s)", header)
                self.assertIn("Note: the policy also refuses EnterWorktree, ExitWorktree, LSP,", header)
                policy = Policy.from_dict(document)
                for tool in cli_hook.BUILT_IN_TOOLS:
                    self.assertNotEqual(policy.tool_level_action(tool), "block", tool)
                for tool in ("ToolSearch", "TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "TaskStop", "KillShell",
                             "EnterPlanMode", "Skill", "TaskOutput", "BashOutput"):
                    self.assertEqual(policy.tool_level_action(tool), "allow", tool)
                # What brings text in is labelled on purpose; what does neither says so with no labels.
                for tool in ("Skill", "TaskOutput", "BashOutput", "ToolSearch", "Bash", "PowerShell"):
                    self.assertEqual(set(policy.tool_labels(tool)), {"private"}, tool)
                for tool in ("TaskCreate", "TaskStop", "EnterPlanMode"):
                    self.assertEqual(set(policy.tool_labels(tool)), set(), tool)
                for tool in cli_hook.OTHER_BUILT_IN_TOOLS:
                    self.assertEqual(policy.tool_level_action(tool), "block", tool)

    def test_the_monitor_note_does_not_ask_for_labels_that_are_there(self):
        labelled = {"default": "block", "tools": {"Monitor": {"action": "ask", "labels": ["untrusted", "sink"]}}}
        header = self.header(labelled)
        self.assertIn("Note: the policy lets the agent use Monitor, whose streamed events no hook can scan.", header)
        self.assertNotIn("Label it", header)
        for labels in ([], ["untrusted"], ["sink"]):
            header = self.header({"default": "block", "tools": {"Monitor": {"action": "ask", "labels": labels}}})
            self.assertIn('no hook can scan. Label it "untrusted" and "sink" for the flow rules, or block it.', header)
        self.assertNotIn("Monitor, whose", self.header({"default": "block", "tools": {"Read": "allow"}}))

    def test_it_says_what_happens_when_the_policy_file_changes_during_a_session(self):
        header = self.header(POLICY)
        self.assertIn("If the policy file changes during a session, that session's calls are refused until a new "
                      "session starts (hook.policy_changes).", header)
        header = self.header({**POLICY, "hook": {"policy_changes": "audit"}})
        self.assertIn('is only recorded, and applies at once (hook.policy_changes is "audit")', header)


class TheCommandClaudeCodeRuns(InstallTest):
    """`hook claude-code` starts anew for every event, so it loads only what answering one needs."""

    EVENT = {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Read", "tool_use_id": "t",
             "tool_input": {"file_path": "notes.txt"}, "permission_mode": "default"}

    def run_event(self, *words, event=None, code=None):
        """Answer one event in a new Python; return (exit code, stdout, stderr)."""
        import subprocess

        from support import ROOT

        command = [sys.executable, *(("-c", code) if code else ("-m", "agent_sentinel")), "hook", "claude-code",
                   "--policy", str(self.policy), "--state-dir", str(self.folder / "state"), *words]
        environment = {**os.environ, "PYTHONPATH": str(ROOT)}
        done = subprocess.run(command, input=json.dumps(event or self.EVENT).encode("utf-8"), capture_output=True,
                              timeout=120, env=environment)
        return done.returncode, done.stdout.decode("utf-8"), done.stderr.decode("utf-8")

    def test_an_event_does_not_load_the_other_commands(self):
        code = ("import sys\n"
                "from agent_sentinel.__main__ import main\n"
                "status = main(sys.argv[1:])\n"
                "loaded = sorted(name.split('.')[1] for name in sys.modules if name.startswith('agent_sentinel.'))\n"
                "print(' '.join(loaded), file=sys.stderr)\n"
                "sys.exit(status)\n")
        status, out, err = self.run_event(code=code)
        self.assertEqual((status, out), (0, ""), err)
        loaded = set(err.split())
        self.assertLessEqual({"cli_hook", "claude_hooks", "firewall", "policy", "hook_state"}, loaded)
        for module in ("mcp_proxy", "cli_doctor", "cli_wrap", "cli_init", "launch", "containment", "control_plane",
                       "clients", "config_file", "wrapping", "pins", "server_probe"):
            self.assertNotIn(module, loaded)

    def test_it_answers_as_through_the_whole_command_line(self):
        denied = {**self.EVENT, "tool_name": "Write"}
        status, out, err = self.run_event(event=denied)
        self.assertEqual(status, 0, err)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")
        # Words it does not know end with exit code 2, which blocks; so does a missing --policy.
        self.assertEqual(self.run_event("--no-such-option")[0], 2)
        self.assertEqual(run_cli("hook", "claude-code", "--state-dir", self.folder / "state", stdin=b"{}")[0], 2)
        code, out, _ = run_cli("hook", "claude-code", "--help")
        self.assertEqual(code, 0)
        self.assertIn("usage: agent-sentinel hook claude-code", out)
        self.assertIn("--audit-required", out)
