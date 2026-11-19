"""Where MCP clients keep their configurations, and the entries printed for the others (agent_sentinel/clients.py).

Every test builds its own environment, pointing into a temporary folder, so
nothing here looks at the real configurations of the person running the tests.
"""

import json
import os
import shlex
import sys
import unittest
from pathlib import Path, PureWindowsPath

from cli_support import TempFolderTest
from agent_sentinel import clients
from agent_sentinel.cli_common import CommandError


class Locations(TempFolderTest):
    def setUp(self):
        super().setUp()
        self.folder = self.folder.resolve()
        self.user = self.folder / "user"
        self.project = self.folder / "project"
        # The environment of this system's kind, pointing into the temporary folder.
        if sys.platform == "win32":
            self.env = {"USERPROFILE": str(self.user), "APPDATA": str(self.folder / "roaming"),
                        "LOCALAPPDATA": str(self.folder / "local")}
        else:
            self.env = {"HOME": str(self.user), "XDG_CONFIG_HOME": str(self.folder / "roaming")}

    def target(self, client, project=False):
        return clients.target_for(client, project, self.env, self.project, sys.platform).path

    def desktop_file(self):
        return clients.desktop_locations(self.env, sys.platform)[0].path

    def place(self, path, servers=None, key="mcpServers"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({key: servers or {}}), encoding="utf-8")
        return path

    def locations(self, environ, platform):
        return [(location.client, location.scope, location.path)
                for location in clients.all_locations(environ, self.project, platform)]

    def test_every_known_place_on_windows(self):
        environ = {"USERPROFILE": "C:\\Users\\me", "APPDATA": "C:\\Users\\me\\AppData\\Roaming",
                   "LOCALAPPDATA": "C:\\Users\\me\\AppData\\Local"}
        found = {(client, scope, str(PureWindowsPath(path)))
                 for client, scope, path in self.locations(environ, "win32")}
        project = str(PureWindowsPath(self.project))
        for expected in (
            ("claude-desktop", "user", "C:\\Users\\me\\AppData\\Roaming\\Claude\\claude_desktop_config.json"),
            ("cursor", "user", "C:\\Users\\me\\.cursor\\mcp.json"),
            ("cursor", "project", project + "\\.cursor\\mcp.json"),
            ("vscode", "project", project + "\\.vscode\\mcp.json"),
            ("claude-code", "project", project + "\\.mcp.json"),
            ("windsurf", "user", "C:\\Users\\me\\AppData\\Roaming\\devin\\mcp_config.json"),
            ("windsurf", "user", "C:\\Users\\me\\.codeium\\windsurf\\mcp_config.json"),
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, found)

    @unittest.skipUnless(sys.platform == "win32", "the Microsoft Store app is a Windows matter")
    def test_the_microsoft_store_copy_of_claude_desktop_is_found(self):
        package = self.folder / "local" / "Packages" / "Claude_pzs8sxrjxfjjc"
        msix = self.place(package / "LocalCache" / "Roaming" / "Claude" / "claude_desktop_config.json")
        found = [location for location in clients.desktop_locations(self.env, "win32") if location.path == msix]
        self.assertEqual(len(found), 1)
        self.assertIn("Microsoft Store", found[0].note)

    def test_macos_and_linux_places(self):
        mac = self.locations({"HOME": "/Users/me"}, "darwin")
        self.assertIn(("claude-desktop", "user",
                       Path("/Users/me/Library/Application Support/Claude/claude_desktop_config.json")), mac)
        linux = self.locations({"HOME": "/home/me", "XDG_CONFIG_HOME": "/cfg"}, "linux")
        self.assertIn(("claude-desktop", "user", Path("/cfg/Claude/claude_desktop_config.json")), linux)
        self.assertIn(("windsurf", "user", Path("/cfg/devin/mcp_config.json")), linux)
        linux = self.locations({"HOME": "/home/me"}, "linux")
        self.assertIn(("claude-desktop", "user", Path("/home/me/.config/Claude/claude_desktop_config.json")), linux)

    def test_without_a_home_only_the_project_places_are_known(self):
        found = self.locations({}, "linux")
        self.assertEqual({scope for _, scope, _ in found}, {"project"})

    def test_claude_desktop_with_one_file_is_that_file(self):
        usual = self.place(self.desktop_file())
        self.assertEqual(self.target("claude-desktop"), usual)

    @unittest.skipUnless(sys.platform == "win32", "the Microsoft Store app is a Windows matter")
    def test_claude_desktop_from_the_store_alone_is_its_store_copy(self):
        package = self.folder / "local" / "Packages" / "Claude_abc"
        msix = self.place(package / "LocalCache" / "Roaming" / "Claude" / "claude_desktop_config.json")
        self.assertEqual(self.target("claude-desktop"), msix)

    @unittest.skipUnless(sys.platform == "win32", "the Microsoft Store app is a Windows matter")
    def test_claude_desktop_with_two_files_is_refused_until_one_is_chosen(self):
        usual = self.place(self.folder / "roaming" / "Claude" / "claude_desktop_config.json")
        msix = self.place(self.folder / "local" / "Packages" / "Claude_abc" / "LocalCache" / "Roaming" / "Claude"
                          / "claude_desktop_config.json")
        with self.assertRaises(CommandError) as caught:
            self.target("claude-desktop")
        message = str(caught.exception)
        self.assertIn("more than one configuration file", message)
        self.assertIn(str(usual), message)
        self.assertIn(str(msix), message)
        self.assertIn("--config", message)

    def test_claude_desktop_without_a_file_says_where_it_looked(self):
        with self.assertRaises(CommandError) as caught:
            self.target("claude-desktop")
        self.assertIn("Edit Config", str(caught.exception))
        self.assertIn(str(self.desktop_file()), str(caught.exception))

    def test_windsurf_edits_the_devin_file_and_refuses_the_discovery_only_one(self):
        older = self.place(self.user / ".codeium" / "windsurf" / "mcp_config.json")
        with self.assertRaises(CommandError) as caught:
            self.target("windsurf")
        self.assertIn("only read for discovery", str(caught.exception))
        current = self.place(self.folder / "roaming" / "devin" / "mcp_config.json")
        self.assertEqual(self.target("windsurf"), current)
        self.assertTrue(older.exists())

    def test_cursor_is_the_user_file_unless_project_is_asked_for(self):
        user = self.place(self.user / ".cursor" / "mcp.json")
        project = self.place(self.project / ".cursor" / "mcp.json")
        self.assertEqual(self.target("cursor"), user)
        self.assertEqual(self.target("cursor", project=True), project)
        os.remove(user)
        with self.assertRaises(CommandError) as caught:
            self.target("cursor")
        self.assertIn("add --project", str(caught.exception))

    def test_vscode_and_claude_code_are_project_files(self):
        vscode = self.place(self.project / ".vscode" / "mcp.json", key="servers")
        claude_code = self.place(self.project / ".mcp.json")
        self.assertEqual(self.target("vscode"), vscode)
        self.assertEqual(self.target("claude-code"), claude_code)
        self.assertEqual(clients.CLIENTS["vscode"].servers_key, "servers")

    def test_clients_that_are_not_edited_point_to_the_snippet(self):
        for client in ("codex", "cline", "antigravity", "other"):
            with self.subTest(client=client), self.assertRaises(CommandError) as caught:
                self.target(client)
            self.assertIn(f"agent-sentinel wrap --client {client} --policy POLICY --name NAME -- <server command>",
                          str(caught.exception))

    def test_desktop_extensions_are_listed_by_folder(self):
        config = self.place(self.desktop_file())
        self.assertEqual(clients.desktop_extensions(config), [])
        for name in ("ant.dir.filesystem", "zeta"):
            (config.parent / "Claude Extensions" / name).mkdir(parents=True)
        (config.parent / "Claude Extensions" / "loose-file.txt").write_text("x", encoding="utf-8")
        self.assertEqual(clients.desktop_extensions(config), ["ant.dir.filesystem", "zeta"])


class WhichClientAFileBelongsTo(unittest.TestCase):
    def test_by_name_and_folder(self):
        for path, client, scope in (
            (Path("/x/claude_desktop_config.json"), "claude-desktop", "user"),
            (Path("/work/app/.cursor/mcp.json"), "cursor", "project"),
            (Path("/work/app/.vscode/mcp.json"), "vscode", "project"),
            (Path("/work/app/.mcp.json"), "claude-code", "project"),
            (Path("/home/me/.config/devin/mcp_config.json"), "windsurf", "user"),
            (Path("/x/other.json"), None, "user"),
        ):
            with self.subTest(path=path):
                self.assertEqual(clients.client_for_file(path), client)
                self.assertEqual(clients.scope_of(path, {"HOME": "/home/me"}, "linux"), scope)
        self.assertEqual(clients.scope_of(Path("/home/me/.cursor/mcp.json"), {"HOME": "/home/me"}, "linux"), "user")
        self.assertEqual(clients.project_folder(Path("/work/app/.vscode/mcp.json")), Path("/work/app"))
        self.assertEqual(clients.project_folder(Path("/work/app/.mcp.json")), Path("/work/app"))

    def test_inside_a_folder_is_decided_by_components_not_by_text(self):
        root = os.path.abspath("work")
        self.assertTrue(clients.inside_folder(os.path.join(root, "a", "p.json"), root))
        self.assertTrue(clients.inside_folder(root, root))
        self.assertFalse(clients.inside_folder(root + "-other" + os.sep + "p.json", root))
        self.assertFalse(clients.inside_folder(os.path.join(root, "..", "p.json"), root))
        self.assertFalse(clients.inside_folder("relative.json", root))
        project = Path(root) / ".mcp.json"
        self.assertEqual(clients.files_inside_project(project, {"policy": os.path.join(root, "p.json"), "pins": None,
                                                                "log": os.path.abspath("elsewhere.jsonl")}),
                         ["policy"])
        self.assertEqual(clients.files_inside_project(Path(root) / "claude_desktop_config.json",
                                                      {"policy": os.path.join(root, "p.json")}), [])

    def test_claude_codes_state_file_is_recognised(self):
        self.assertTrue(clients.is_app_state(Path("/home/me/.claude.json")))
        self.assertFalse(clients.is_app_state(Path("/work/.mcp.json")))


class EntriesToPaste(unittest.TestCase):
    ENTRY = {"command": "/usr/bin/python3", "args": ["-m", "agent_sentinel", "proxy", "--policy", "/p q.json",
                                                     "--", "npx", "-y", "pkg"]}

    def test_codex_gets_its_add_command_and_a_toml_table(self):
        text = clients.snippet("codex", "files", self.ENTRY, platform="linux")
        command = text.splitlines()[1].strip()
        self.assertEqual(shlex.split(command), ["codex", "mcp", "add", "files", "--", *[self.ENTRY["command"]],
                                                *self.ENTRY["args"]])
        self.assertIn("[mcp_servers.files]", text)
        self.assertIn('command = "/usr/bin/python3"', text)
        self.assertIn('[mcp_servers."my server"]', clients.snippet("codex", "my server", self.ENTRY, platform="linux"))

    def test_json_clients_get_an_entry_under_their_key(self):
        text = clients.snippet("cline", "files", self.ENTRY)
        block = json.loads(text[text.index("{"):])
        self.assertEqual(block, {"mcpServers": {"files": self.ENTRY}})

    def test_claude_code_also_gets_the_user_scope_command(self):
        text = clients.snippet("claude-code", "files", self.ENTRY, platform="linux")
        line = next(line for line in text.splitlines() if line.strip().startswith("claude mcp add"))
        self.assertEqual(shlex.split(line), ["claude", "mcp", "add", "--scope", "user", "files", "--",
                                             self.ENTRY["command"], *self.ENTRY["args"]])

    def test_other_clients_get_the_command_and_arguments(self):
        text = clients.snippet("other", "files", self.ENTRY, platform="linux")
        self.assertIn("Command:\n  /usr/bin/python3\nArguments:\n  -m\n", text)

    def test_windows_command_lines_are_quoted_for_windows(self):
        line = clients.shell_line([r"C:\Program Files\Python\python.exe", "-m", "x"], platform="win32")
        self.assertEqual(line, r'"C:\Program Files\Python\python.exe" -m x')


if __name__ == "__main__":
    unittest.main()
