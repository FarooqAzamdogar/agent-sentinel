"""Reading and changing client configuration files (agent_sentinel/config_file.py)."""

import json
import os
import shutil
import subprocess
import unittest
from datetime import datetime
from unittest import mock

from cli_support import TempFolderTest
from agent_sentinel import config_file, filelock, wrapping
from agent_sentinel.config_file import ConfigError, edited_text, read_config, write_config

ORIGINAL = """{
  "globalShortcut": "Ctrl+Space",
  "mcpServers": {
    "files": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:/work"]
    },
    "remote": {"url": "https://example.com/mcp"},
    "notes": {"command": "python", "args": ["notes.py"], "zzz": {"keep": [1, 2.50, true, null]}}
  },
  "unknownLater": {"b": 1, "a": 2}
}
"""
NEW_FILES = {"command": "python", "args": ["-m", "agent_sentinel", "proxy", "--", "npx"]}


class ReadingStrictly(TempFolderTest):
    def test_plain_json_is_read(self):
        config = read_config(self.write("c.json", ORIGINAL.encode("utf-8")))
        self.assertEqual(list(config.document), ["globalShortcut", "mcpServers", "unknownLater"])
        self.assertFalse(config.bom)

    def test_anything_but_plain_json_is_refused_with_a_reason(self):
        for name, text, expected in (
            ("comment", '{\n  // my servers\n  "mcpServers": {}\n}', "not valid JSON"),
            ("trailing comma", '{"mcpServers": {},}', "not valid JSON"),
            ("repeated key", '{"mcpServers": {"a": {}, "a": {}}}', "appears twice"),
            ("NaN", '{"x": NaN}', "not valid JSON"),
            ("huge number", '{"x": ' + "9" * 5000 + "}", "not valid JSON"),
            ("not an object", "[1, 2]", "does not hold a JSON object"),
            ("deep nesting", "[" * 100_000 + "]" * 100_000, "not valid JSON"),
        ):
            with self.subTest(name), self.assertRaises(ConfigError) as caught:
                read_config(self.write("bad.json", text))
            self.assertIn(expected, str(caught.exception))

    def test_a_mistake_inside_text_is_located_but_the_text_is_never_quoted(self):
        # A password with a backslash in it is an invalid escape; the hint for a policy would quote what follows.
        secret = "Zx9QpLm77Kw2Rt5Y"
        for text, expected in (
            ('{\n  "mcpServers": {},\n  "env": {"DB_PASSWORD": "hunter2\\' + secret + '"}\n}', ":3:"),
            ('{"env": {"API_KEY": "abc\\Qsecretpart' + secret + '"}}', ":1:"),
            ('{"env": {"API_KEY": "abc\\u12' + secret + '"}}', ":1:"),
            ('{"env": {"API_KEY": "abc\t' + secret + '"}}', ":1:"),
            ('{"env": {"API_KEY": "abc' + secret, ":1:"),
        ):
            with self.subTest(text=text), self.assertRaises(ConfigError) as caught:
                read_config(self.write("bad.json", text))
            message = str(caught.exception)
            self.assertIn(expected, message)
            self.assertIn("not valid JSON", message)
            for quoted in (secret, secret[:6], "hunter2", "Qsecret", "regular expression"):
                self.assertNotIn(quoted, message)
        with self.assertRaises(ConfigError) as caught:
            read_config(self.write("bad.json", '{"env": {"P": "a\\Zb"}}'))
        self.assertIn("Invalid \\escape\nIn JSON a backslash inside text must be doubled", str(caught.exception))

    def test_jsonc_gets_the_plain_json_explanation(self):
        with self.assertRaises(ConfigError) as caught:
            read_config(self.write("c.json", '{\n  // comment\n  "servers": {}\n}'))
        self.assertIn("agent-sentinel reads only plain JSON: no comments, no trailing commas", str(caught.exception))

    def test_encodings_and_sizes(self):
        with self.assertRaises(ConfigError) as caught:
            read_config(self.write("u16.json", '{"a": 1}'.encode("utf-16")))
        self.assertIn("UTF-16", str(caught.exception))
        with mock.patch.object(config_file, "MAX_CONFIG_BYTES", 10), self.assertRaises(ConfigError) as caught:
            read_config(self.write("big.json", '{"a": "0123456789"}'))
        self.assertIn("larger than 10 bytes", str(caught.exception))
        with self.assertRaises(ConfigError) as caught:
            read_config(self.folder / "missing.json")
        self.assertIn("there is no file at", str(caught.exception))
        with self.assertRaises(ConfigError):
            read_config(self.folder)

    def test_a_link_is_not_edited(self):
        target = self.write("real.json", "{}")
        link = self.folder / "link.json"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("this system does not let the tests make a symbolic link")
        read_config(link)  # reading through it is fine
        with self.assertRaises(ConfigError) as caught:
            read_config(link, for_writing=True)
        self.assertIn("is a link", str(caught.exception))


class EditingInPlace(TempFolderTest):
    def test_only_the_named_entry_changes_and_the_rest_is_kept_byte_for_byte(self):
        config = read_config(self.write("c.json", ORIGINAL.encode("utf-8")))
        text = edited_text(config, "mcpServers", {"files": NEW_FILES})
        start = ORIGINAL.index('"files": ') + len('"files": ')
        end = ORIGINAL.index('    },\n    "remote"') + len("    }")
        self.assertEqual(text[:start], ORIGINAL[:start])
        self.assertEqual(text[text.index(',\n    "remote"'):], ORIGINAL[end:])
        document = json.loads(text)
        self.assertEqual(document["mcpServers"]["files"], NEW_FILES)
        self.assertEqual(list(document), ["globalShortcut", "mcpServers", "unknownLater"])
        self.assertEqual(list(document["mcpServers"]), ["files", "remote", "notes"])
        # Only the changed values are written, each in the layout of the one it replaces.
        self.assertIn('\n    "files": {\n      "command": "python",\n'
                      '      "args": ["-m", "agent_sentinel", "proxy", "--", "npx"]\n    },', text)
        # An entry that gains or loses a key is written whole, indented like the file.
        text = edited_text(config, "mcpServers", {"files": {"command": "python"}, "remote": {"command": "x",
                                                                                           "args": ["a"]}})
        self.assertIn('\n    "files": {\n      "command": "python"\n    },', text)
        self.assertIn('\n    "remote": {"command": "x", "args": ["a"]},', text)

    def test_several_entries_change_in_one_pass(self):
        config = read_config(self.write("c.json", ORIGINAL.encode("utf-8")))
        text = edited_text(config, "mcpServers", {"notes": {"command": "x"}, "files": {"command": "y"}})
        servers = json.loads(text)["mcpServers"]
        self.assertEqual((servers["files"], servers["notes"]), ({"command": "y"}, {"command": "x"}))
        self.assertEqual(servers["remote"], {"url": "https://example.com/mcp"})
        self.assertIn('"remote": {"url": "https://example.com/mcp"},', text)  # untouched, still on one line

    def test_a_compact_file_stays_compact(self):
        compact = '{"mcpServers":{"a":{"command":"npx"},"b":{"command":"uvx"}},"x":1}'
        text = edited_text(read_config(self.write("c.json", compact)), "mcpServers", {"a": {"command": "python"}})
        self.assertEqual(text, '{"mcpServers":{"a":{"command":"python"},"b":{"command":"uvx"}},"x":1}')

    def test_an_entry_written_on_one_line_stays_on_one_line_and_comes_back_the_same(self):
        config = read_config(self.write("c.json", ORIGINAL.encode("utf-8")))
        text = edited_text(config, "mcpServers", {"notes": {"command": "x", "args": ["a", "b"]}})
        self.assertIn('\n    "notes": {"command": "x", "args": ["a", "b"]}\n', text)
        path = self.write("c.json", text.encode("utf-8"))
        back = edited_text(read_config(path), "mcpServers", {"notes": json.loads(ORIGINAL)["mcpServers"]["notes"]})
        self.assertEqual(back, ORIGINAL.replace("2.50", "2.5"))  # JSON writes the number 2.50 as 2.5

    def test_wrap_then_unwrap_gives_back_the_same_bytes_when_only_command_and_args_change(self):
        # Only the values that change are written: an unknown key's numbers (2.50, 1e2) and an
        # "args" list written on one line inside an entry of several lines stay as they were.
        original = ('\ufeff{\r\n  "mcpServers": {\r\n    "caf\u00e9": {\r\n      "command": "python",\r\n'
                    '      "args": ["server.py", "--port", "8080"],\r\n'
                    '      "x-unknown": {"keep": [1, 2.50, 1e2]},\r\n      "env": {\r\n        "A": "1"\r\n'
                    '      }\r\n    },\r\n    "two": {\r\n      "command": "node",\r\n      "args": [\r\n'
                    '        "x.js"\r\n      ]\r\n    }\r\n  }\r\n}\r\n')
        path = self.write("c.json", original.encode("utf-8"))
        settings = wrapping.ProxySettings("C:/py/python.exe", "C:/p.json", "C:/a.jsonl", "C:/pins")
        config = read_config(path)
        servers = config.document["mcpServers"]
        wrapped = {name: wrapping.wrap_entry(entry, settings, name, "PINS") for name, entry in servers.items()}
        write_config(config, edited_text(config, "mcpServers", wrapped))
        text = path.read_bytes().decode("utf-8-sig")
        self.assertIn('"x-unknown": {"keep": [1, 2.50, 1e2]}', text)
        self.assertIn('"args": ["-I", "-m", "agent_sentinel", "proxy"', text)  # one line, as it was
        self.assertIn('"args": [\r\n        "-I",\r\n', text)  # one item per line, as it was
        config = read_config(path)
        unwrapped = {name: wrapping.unwrap_entry(entry) for name, entry in config.document["mcpServers"].items()}
        write_config(config, edited_text(config, "mcpServers", unwrapped))
        self.assertEqual(path.read_bytes(), original.encode("utf-8"))

    def test_windows_line_endings_tabs_and_a_byte_order_mark_are_kept(self):
        original = '{\r\n\t"servers": {\r\n\t\t"a": {\r\n\t\t\t"command": "npx"\r\n\t\t}\r\n\t}\r\n}\r\n'
        path = self.write("c.json", b"\xef\xbb\xbf" + original.encode("utf-8"))
        config = read_config(path)
        self.assertTrue(config.bom)
        text = edited_text(config, "servers", {"a": {"command": "python", "args": ["x"]}})
        self.assertNotIn("\n", text.replace("\r\n", ""))
        self.assertIn('\t\t"a": {\r\n\t\t\t"command": "python",', text)
        write_config(config, text)
        self.assertTrue(path.read_bytes().startswith(b"\xef\xbb\xbf"))

    def test_text_that_is_not_ascii_stays_readable_and_a_lone_surrogate_stays_escaped(self):
        config = read_config(self.write("c.json", '{"mcpServers": {"a": {"command": "npx"}}}'))
        text = edited_text(config, "mcpServers", {"a": {"command": "café"}})
        self.assertIn("café", text)
        text = edited_text(config, "mcpServers", {"a": {"command": "\ud800"}})
        self.assertIn("\\ud800", text)
        text.encode("utf-8")

    def test_keys_written_with_escapes_are_found(self):
        original = '{"mcp\\u0053ervers": {"a\\"b": {"command": "npx"}}}'
        text = edited_text(read_config(self.write("c.json", original)), "mcpServers", {'a"b': {"command": "x"}})
        self.assertEqual(json.loads(text), {"mcpServers": {'a"b': {"command": "x"}}})


class Writing(TempFolderTest):
    def test_the_original_goes_to_a_new_backup_and_the_file_is_replaced(self):
        path = self.write("c.json", ORIGINAL.encode("utf-8"))
        config = read_config(path)
        text = edited_text(config, "mcpServers", {"files": NEW_FILES})
        backup = write_config(config, text, now=datetime(2026, 11, 19, 14, 30, 5))
        self.assertEqual(backup.name, "c.json.agent-sentinel-20261119-143005.bak")
        self.assertEqual(backup.read_bytes(), ORIGINAL.encode("utf-8"))
        self.assertEqual(path.read_bytes(), text.encode("utf-8"))
        self.assertEqual(sorted(entry.name for entry in self.folder.iterdir()), ["c.json", backup.name])

    def test_a_backup_is_never_overwritten(self):
        path = self.write("c.json", ORIGINAL.encode("utf-8"))
        when = datetime(2026, 11, 19, 14, 30, 5)
        first = write_config(read_config(path), ORIGINAL.replace("Ctrl", "Alt"), now=when)
        second = write_config(read_config(path), ORIGINAL, now=when)
        self.assertNotEqual(first, second)
        self.assertEqual(second.name, "c.json.agent-sentinel-20261119-143005-2.bak")
        self.assertEqual(first.read_text(encoding="utf-8"), ORIGINAL)
        self.assertIn("Alt", second.read_text(encoding="utf-8"))

    @unittest.skipUnless(os.name == "posix", "file modes are a POSIX matter")
    def test_a_backup_can_be_read_only_by_its_owner(self):
        path = self.write("c.json", ORIGINAL.encode("utf-8"))
        os.chmod(path, 0o600)
        previous = os.umask(0o022)
        try:
            backup = write_config(read_config(path), ORIGINAL.replace("Ctrl", "Alt"))
        finally:
            os.umask(previous)
        self.assertEqual(os.stat(backup).st_mode & 0o777, 0o600)

    def test_a_file_in_a_project_under_version_control_is_backed_up_outside_it(self):
        # A project's .mcp.json is often in .gitignore because it holds tokens; a backup beside it is not.
        home = self.folder / "sentinel-home"
        for marker, make in ((".git", "mkdir"), (".git", "file"), (".hg", "mkdir")):
            project = self.folder / f"project-{marker}-{make}"
            (project / "sub").mkdir(parents=True)
            if make == "mkdir":
                (project / marker).mkdir()
            else:
                (project / marker).write_text("gitdir: elsewhere\n", encoding="utf-8")
            path = project / "sub" / ".mcp.json"
            path.write_bytes(ORIGINAL.encode("utf-8"))
            with self.subTest(marker=marker, make=make), \
                    mock.patch.dict(os.environ, {"AGENT_SENTINEL_HOME": str(home)}):
                backup = write_config(read_config(path), ORIGINAL.replace("Ctrl", "Alt"),
                                      now=datetime(2026, 11, 19, 14, 30, 5))
                self.assertEqual(backup.parent, home / "backups")
                self.assertRegex(backup.name, r"^\.mcp\.json\.[0-9a-f]{8}\.agent-sentinel-20261119-143005(-\d+)?\.bak$")
                self.assertEqual(backup.read_bytes(), ORIGINAL.encode("utf-8"))
                self.assertEqual(sorted(entry.name for entry in path.parent.iterdir()), [".mcp.json"])
        self.assertFalse(config_file.in_work_tree(self.folder / "c.json"))

    def test_backups_in_a_home_folder_kept_in_git_are_ignored_by_git(self):
        # Dotfiles kept as a git repository in the home folder: ~/.cursor/mcp.json is in it, and so is
        # the agent-sentinel home folder with its backups.
        user = self.folder.resolve() / "user"
        path = user / ".cursor" / "mcp.json"
        path.parent.mkdir(parents=True)
        git = shutil.which("git")
        if git:
            subprocess.run([git, "init", "-q", str(user)], check=True, capture_output=True, timeout=60)
        else:
            (user / ".git").mkdir()
        (user / ".gitignore").write_text(".cursor/mcp.json\n", encoding="utf-8")  # the file itself is ignored
        path.write_bytes(ORIGINAL.encode("utf-8"))
        home = user / ".agent-sentinel"
        with mock.patch.dict(os.environ, {"AGENT_SENTINEL_HOME": str(home)}):
            backup = write_config(read_config(path), ORIGINAL.replace("Ctrl", "Alt"))
            write_config(read_config(path), ORIGINAL)  # a second backup keeps the same .gitignore
        self.assertEqual(backup.parent, home / "backups")
        self.assertEqual((home / "backups" / ".gitignore").read_text(encoding="utf-8").splitlines()[-1], "*")
        if git:
            added = subprocess.run([git, "add", "-A", "--dry-run"], cwd=user, capture_output=True, text=True,
                                   timeout=60, check=True).stdout
            self.assertNotIn(".bak", added)
            self.assertNotIn("backups", added)

    def test_a_home_folder_kept_in_mercurial_or_subversion_gets_no_backup(self):
        # Neither reads a .gitignore, so a backup with tokens there could be committed: refused, nothing changed.
        for marker in (".hg", ".svn"):
            user = self.folder / f"user{marker}"
            (user / marker).mkdir(parents=True)
            path = user / "project" / ".mcp.json"
            (user / "project" / ".git").mkdir(parents=True)
            path.write_bytes(ORIGINAL.encode("utf-8"))
            with self.subTest(marker=marker), \
                    mock.patch.dict(os.environ, {"AGENT_SENTINEL_HOME": str(user / ".agent-sentinel")}), \
                    self.assertRaises(ConfigError) as caught:
                write_config(read_config(path), "{}")
            self.assertIn("Mercurial or Subversion work tree", str(caught.exception))
            self.assertIn("AGENT_SENTINEL_HOME", str(caught.exception))
            self.assertEqual(path.read_bytes(), ORIGINAL.encode("utf-8"))
            self.assertFalse((user / ".agent-sentinel").exists())

    def test_a_file_that_changed_since_it_was_read_is_not_written(self):
        path = self.write("c.json", ORIGINAL.encode("utf-8"))
        config = read_config(path)
        path.write_bytes(ORIGINAL.replace("Ctrl", "Shift").encode("utf-8"))
        with self.assertRaises(ConfigError) as caught:
            write_config(config, edited_text(config, "mcpServers", {"files": NEW_FILES}))
        self.assertIn("changed while agent-sentinel was working on it; nothing was written", str(caught.exception))
        self.assertIn("Shift", path.read_text(encoding="utf-8"))
        self.assertEqual([entry.name for entry in self.folder.iterdir()], ["c.json"])

    def test_a_failed_replace_leaves_the_file_and_no_temporary_file(self):
        path = self.write("c.json", ORIGINAL.encode("utf-8"))
        config = read_config(path)
        with mock.patch.object(config_file.os, "replace", side_effect=PermissionError("in use")), \
                mock.patch.object(filelock.time, "sleep"), self.assertRaises(ConfigError) as caught:
            write_config(config, "{}")
        self.assertIn("the file was not changed", str(caught.exception))
        self.assertEqual(path.read_text(encoding="utf-8"), ORIGINAL)
        self.assertEqual([entry.name for entry in self.folder.iterdir() if entry.suffix == ".tmp"], [])

    def test_a_replace_that_fails_once_is_tried_again(self):
        path = self.write("c.json", ORIGINAL.encode("utf-8"))
        real_replace = os.replace
        attempts = []

        def flaky(source, target):
            attempts.append(target)
            if len(attempts) == 1:
                raise PermissionError("in use for a moment")
            real_replace(source, target)

        with mock.patch.object(config_file.os, "replace", flaky), mock.patch.object(filelock.time, "sleep"):
            write_config(read_config(path), "{}")
        self.assertEqual(path.read_text(encoding="utf-8"), "{}")
        self.assertEqual(len(attempts), 2)


class SettingATopLevelSection(TempFolderTest):
    """with_top_level_value and create_config: what `hook install` uses for a settings file's "hooks"."""

    HOOKS = {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "x", "args": ["a"]}]}]}

    def edited(self, text):
        config = read_config(self.write("settings.json", text.encode("utf-8")))
        result = config_file.with_top_level_value(config, "hooks", self.HOOKS)
        self.assertEqual(json.loads(result), {**config.document, "hooks": self.HOOKS})
        return result

    def test_an_existing_section_is_replaced_and_the_rest_kept_byte_for_byte(self):
        text = '{\n  "model": "opus",\n  "hooks": {"Stop": []},\n  "zzz": [1,   2]\n}\n'
        result = self.edited(text)
        self.assertTrue(result.startswith('{\n  "model": "opus",\n  "hooks": {\n    "PreToolUse": [\n'))
        self.assertTrue(result.endswith('\n  },\n  "zzz": [1,   2]\n}\n'))

    def test_a_missing_section_is_added_at_the_end_in_the_files_style(self):
        result = self.edited('{\r\n\t"model": "opus"\r\n}\r\n')
        self.assertTrue(result.startswith('{\r\n\t"model": "opus",\r\n\t"hooks": {\r\n\t\t"PreToolUse"'))
        self.assertNotIn("\n", result.replace("\r\n", ""))
        self.assertTrue(self.edited('{"a": 1}').startswith('{"a": 1, "hooks": {"PreToolUse": '))

    def test_an_empty_object_gets_the_section(self):
        for text in ("{}", "{ }\n", "﻿{}"):
            with self.subTest(text=text):
                self.assertIn('"hooks": {', self.edited(text))

    def test_a_result_that_would_not_read_back_is_not_returned(self):
        config = read_config(self.write("settings.json", b'{"a": 1}'))
        with mock.patch.object(config_file, "_json_text", return_value="[broken"):
            with self.assertRaisesRegex(ConfigError, "would not read back"):
                config_file.with_top_level_value(config, "hooks", self.HOOKS)

    def test_a_new_file_is_never_written_over_an_existing_one(self):
        path = self.folder / "new.json"
        config_file.create_config(path, "{}\n")
        self.assertEqual(path.read_text(encoding="utf-8"), "{}\n")
        with self.assertRaisesRegex(ConfigError, "appeared"):
            config_file.create_config(path, '{"other": 1}')
        self.assertEqual(path.read_text(encoding="utf-8"), "{}\n")


if __name__ == "__main__":
    unittest.main()
