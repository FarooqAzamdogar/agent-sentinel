"""The agent-sentinel home folder (agent_sentinel/home.py)."""

import unittest
from pathlib import Path

from cli_support import TempFolderTest
from agent_sentinel import home


class WhereTheHomeFolderIs(unittest.TestCase):
    def test_on_windows_it_is_in_the_user_profile_not_in_appdata(self):
        environ = {"USERPROFILE": r"C:\Users\me", "APPDATA": r"C:\Users\me\AppData\Roaming"}
        self.assertEqual(home.home_folder(environ, "win32"), Path(r"C:\Users\me") / ".agent-sentinel")

    def test_elsewhere_it_is_a_dot_folder_in_home(self):
        self.assertEqual(home.home_folder({"HOME": "/home/me"}, "linux"), Path("/home/me/.agent-sentinel"))
        self.assertEqual(home.home_folder({"HOME": "/Users/me"}, "darwin"), Path("/Users/me/.agent-sentinel"))

    def test_windows_falls_back_to_homedrive_and_homepath(self):
        environ = {"HOMEDRIVE": "D:", "HOMEPATH": r"\Users\me"}
        self.assertEqual(home.home_folder(environ, "win32"), Path(r"D:\Users\me") / ".agent-sentinel")

    def test_agent_sentinel_home_overrides_it(self):
        environ = {"HOME": "/home/me", home.ENV_VAR: "/srv/sentinel/"}
        self.assertEqual(home.home_folder(environ, "linux"), Path("/srv/sentinel"))
        environ = {"USERPROFILE": r"C:\Users\me", home.ENV_VAR: r"D:\sentinel"}
        self.assertEqual(home.home_folder(environ, "win32"), Path(r"D:\sentinel"))

    def test_a_relative_agent_sentinel_home_is_refused(self):
        for value, platform in (("sentinel", "linux"), ("~/sentinel", "linux"), (r"\sentinel", "win32"),
                                ("C:sentinel", "win32"), ("./x", "win32")):
            with self.subTest(value=value), self.assertRaises(home.HomeError) as caught:
                home.home_folder({"HOME": "/home/me", "USERPROFILE": r"C:\Users\me", home.ENV_VAR: value}, platform)
            self.assertIn("AGENT_SENTINEL_HOME must be a full path", str(caught.exception))

    def test_without_a_home_variable_it_says_which_one_to_set(self):
        with self.assertRaises(home.HomeError) as caught:
            home.home_folder({}, "win32")
        self.assertIn("USERPROFILE is not set", str(caught.exception))
        with self.assertRaises(home.HomeError) as caught:
            home.home_folder({"HOME": "relative/home"}, "linux")
        self.assertIn("HOME is not set", str(caught.exception))

    def test_full_paths_on_windows_need_a_drive_or_a_share(self):
        self.assertTrue(home.is_absolute(r"C:\x", "win32"))
        self.assertTrue(home.is_absolute("C:/x", "win32"))
        self.assertTrue(home.is_absolute(r"\\server\share\x", "win32"))
        self.assertFalse(home.is_absolute(r"\x", "win32"))
        self.assertFalse(home.is_absolute("C:x", "win32"))
        self.assertTrue(home.is_absolute("/x", "linux"))
        self.assertFalse(home.is_absolute("x", "linux"))

    def test_the_files_inside_it(self):
        folder = Path("/home/me/.agent-sentinel")
        self.assertEqual(home.policy_file(folder), folder / "policy.json")
        self.assertEqual(home.audit_file(folder), folder / "audit.jsonl")
        self.assertEqual(home.pins_folder(folder), folder / "pins")


class MakingTheFolders(TempFolderTest):
    def test_the_folder_and_its_pins_folder_are_created_and_reported_once(self):
        folder = self.folder / "deep" / ".agent-sentinel"
        self.assertEqual(home.make_folders(folder), [folder, folder / "pins"])
        self.assertTrue((folder / "pins").is_dir())
        self.assertEqual(home.make_folders(folder), [])

    def test_a_file_in_the_way_is_an_error(self):
        blocker = self.write("blocker", "x")
        with self.assertRaises(home.HomeError) as caught:
            home.make_folders(blocker / "home")
        self.assertIn("cannot create the folder", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
