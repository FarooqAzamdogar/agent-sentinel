"""Reading and changing client configuration files (agent_sentinel/config_file.py)."""

import json
import os
import unittest
from datetime import datetime
from unittest import mock

from cli_support import TempFolderTest
from agent_sentinel import config_file
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
        # The new entry is indented like the file.
        self.assertIn('\n    "files": {\n      "command": "python",\n      "args": [\n        "-m",', text)

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
        self.assertEqual(text, '{"mcpServers":{"a":{"command": "python"},"b":{"command":"uvx"}},"x":1}')

    def test_an_entry_written_on_one_line_stays_on_one_line_and_comes_back_the_same(self):
        config = read_config(self.write("c.json", ORIGINAL.encode("utf-8")))
        text = edited_text(config, "mcpServers", {"notes": {"command": "x", "args": ["a", "b"]}})
        self.assertIn('\n    "notes": {"command": "x", "args": ["a", "b"]}\n', text)
        path = self.write("c.json", text.encode("utf-8"))
        back = edited_text(read_config(path), "mcpServers", {"notes": json.loads(ORIGINAL)["mcpServers"]["notes"]})
        self.assertEqual(back, ORIGINAL.replace("2.50", "2.5"))  # JSON writes the number 2.50 as 2.5

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
                mock.patch.object(config_file.time, "sleep"), self.assertRaises(ConfigError) as caught:
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

        with mock.patch.object(config_file.os, "replace", flaky), mock.patch.object(config_file.time, "sleep"):
            write_config(read_config(path), "{}")
        self.assertEqual(path.read_text(encoding="utf-8"), "{}")
        self.assertEqual(len(attempts), 2)


if __name__ == "__main__":
    unittest.main()
