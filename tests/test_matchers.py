"""Tests for the argument matchers (matchers.py) and how a policy loads them.

Path tests run with both Windows and POSIX path rules on every machine: the
matcher takes the path module and the current and home folders as
parameters, so no test depends on where it runs or touches a real folder,
except the few marked as using this machine's own rules.
"""

import ntpath
import os
import posixpath
import tempfile
import time
import unittest
from pathlib import Path

from support import ROOT  # noqa: F401  (puts the package on the path)
from agent_sentinel import Policy, PolicyError
from agent_sentinel.matchers import PathMatcher, read_email_domain, read_url


def rule(entry, deny=False, **rule_options):
    """A policy whose tool "t" has this one argument entry."""
    side = "deny_args" if deny else "allow_args"
    return Policy.from_dict({"tools": {"t": {"action": "allow", side: [entry], **rule_options}}})


def verdict(policy, **args):
    return policy.evaluate("t", args).action


def rejected(test, data, *fragments):
    """Assert that loading `data` fails, with every fragment in the message."""
    with test.assertRaises(PolicyError) as caught:
        Policy.from_dict(data)
    for fragment in fragments:
        test.assertIn(fragment, str(caught.exception))
    return str(caught.exception)


def entry_rejected(test, entry, *fragments, deny=False):
    side = "deny_args" if deny else "allow_args"
    return rejected(test, {"tools": {"t": {"action": "allow", side: [entry]}}}, *fragments)


WINDOWS = {"flavour": ntpath, "current_folder": lambda: r"C:\work\app", "home_folder": lambda: r"C:\Users\me"}
POSIX = {"flavour": posixpath, "current_folder": lambda: "/work/app", "home_folder": lambda: "/home/me"}


# ---- the simple matchers -----------------------------------------------------------

class Contains(unittest.TestCase):
    def test_contains_denies_the_text_anywhere_in_any_case(self):
        policy = rule({"arg": "*", "contains": "id_rsa"}, deny=True)
        self.assertEqual(verdict(policy, path="/home/me/.ssh/ID_RSA.pub"), "block")
        self.assertEqual(verdict(policy, path="a.txt", more={"nested": ["x/id_rsa"]}), "block")
        self.assertEqual(verdict(policy, path="a.txt"), "allow")

    def test_contains_is_literal_text_not_a_pattern(self):
        policy = rule({"arg": "q", "contains": "a.b"}, deny=True)
        self.assertEqual(verdict(policy, q="xa.by"), "block")
        self.assertEqual(verdict(policy, q="axb"), "allow")

    def test_contains_sees_through_percent_encoding(self):
        policy = rule({"arg": "uri", "contains": ".ssh"}, deny=True)
        self.assertEqual(verdict(policy, uri="file:///home/me/%2Essh/x"), "block")

    def test_contains_is_refused_in_allow_args_with_the_reason(self):
        entry_rejected(self, {"arg": "url", "contains": "example.com"}, "only used in deny_args", "whole value")

    def test_contains_needs_text_that_is_not_empty(self):
        for value in ("", 5, ["a"], None, True):
            with self.subTest(value=value):
                entry_rejected(self, {"arg": "q", "contains": value}, "'contains' must be text", deny=True)


class OneOf(unittest.TestCase):
    def test_one_of_accepts_only_the_listed_values_exactly(self):
        policy = rule({"arg": "env", "one_of": ["staging", "prod"]})
        self.assertEqual(verdict(policy, env="prod"), "allow")
        for value in ("Prod", "prod ", "production", "", "prod\n"):
            with self.subTest(value=value):
                self.assertEqual(verdict(policy, env=value), "block")

    def test_every_entry_of_a_list_must_be_listed(self):
        policy = rule({"arg": "env", "one_of": ["staging", "prod"]})
        self.assertEqual(verdict(policy, env=["staging", "prod"]), "allow")
        self.assertEqual(verdict(policy, env=["staging", "dev"]), "block")

    def test_numbers_and_flags_are_compared_as_json_writes_them(self):
        policy = rule({"arg": "n", "one_of": ["1", "2", "true"]})
        self.assertEqual(verdict(policy, n=2), "allow")
        self.assertEqual(verdict(policy, n=True), "allow")
        self.assertEqual(verdict(policy, n=2.5), "block")

    def test_one_of_in_deny_args_denies_an_exact_value_at_any_depth(self):
        policy = rule({"arg": "*", "one_of": ["--force"]}, deny=True)
        self.assertEqual(verdict(policy, flags=["-v", "--force"]), "block")
        self.assertEqual(verdict(policy, flags=["--forced"]), "allow")

    def test_one_of_needs_a_list_of_text(self):
        entry_rejected(self, {"arg": "n", "one_of": [1, 2]}, 'write 5 as "5"')
        for value in ([], "prod", None, {"a": 1}):
            with self.subTest(value=value):
                entry_rejected(self, {"arg": "env", "one_of": value}, "at least one entry")


class StartsWithAndEndsWith(unittest.TestCase):
    def test_starts_with_accepts_a_value_with_that_beginning_in_any_case(self):
        policy = rule({"arg": "path", "starts_with": "docs/"})
        self.assertEqual(verdict(policy, path="docs/a.txt"), "allow")
        self.assertEqual(verdict(policy, path="DOCS/a.txt"), "allow")
        self.assertEqual(verdict(policy, path="src/docs/a.txt"), "block")

    def test_starts_with_refuses_a_dot_dot_segment_in_any_spelling(self):
        policy = rule({"arg": "path", "starts_with": "docs/"})
        for value in ("docs/../../etc/passwd", "docs\\..\\secret", "docs/%2e%2e/secret", "docs/%252e%252e/x",
                      "docs/.."):
            with self.subTest(value=value):
                self.assertEqual(verdict(policy, path=value), "block")
        self.assertEqual(verdict(policy, path="docs/v1..v2.txt"), "allow")  # ".." inside a name is not a segment

    def test_ends_with_accepts_a_value_with_that_ending(self):
        policy = rule({"arg": "file", "ends_with": ".md"})
        self.assertEqual(verdict(policy, file="notes/README.MD"), "allow")
        self.assertEqual(verdict(policy, file="notes.md.exe"), "block")

    def test_case_lookalike_letters_do_not_pass(self):
        policy = rule({"arg": "host", "ends_with": ".acme-inc.com"})
        self.assertEqual(verdict(policy, host="mail.acme-inc.com"), "allow")
        self.assertEqual(verdict(policy, host="mail.acme-\u0131nc.com"), "block")

    def test_in_deny_args_they_deny_a_beginning_or_an_ending(self):
        starts = rule({"arg": "cmd", "starts_with": "rm "}, deny=True)
        ends = rule({"arg": "file", "ends_with": ".pem"}, deny=True)
        self.assertEqual(verdict(starts, cmd="RM -rf /"), "block")
        self.assertEqual(verdict(starts, cmd="echo rm x"), "allow")
        self.assertEqual(verdict(ends, file="keys/server.PEM"), "block")
        self.assertEqual(verdict(ends, file="server.pem.txt"), "allow")

    def test_they_need_text_that_is_not_empty(self):
        for key in ("starts_with", "ends_with"):
            for value in ("", 3, None, ["a"]):
                with self.subTest(key=key, value=value):
                    entry_rejected(self, {"arg": "x", key: value}, f"'{key}' must be text")


class NoOptions(unittest.TestCase):
    def test_a_value_that_starts_with_a_dash_is_refused(self):
        policy = rule({"arg": "target", "no_options": True})
        self.assertEqual(verdict(policy, target="main"), "allow")
        self.assertEqual(verdict(policy, target="feature-x"), "allow")  # a dash later is fine
        for value in ("--output=/home/me/.bashrc", "-x", "  --exec", -5):
            with self.subTest(value=value):
                self.assertEqual(verdict(policy, target=value), "block")

    def test_in_deny_args_it_sees_decoded_and_nested_values(self):
        policy = rule({"arg": "args", "no_options": True}, deny=True)
        self.assertEqual(verdict(policy, args=["file.txt", "--upload-pack=evil"]), "block")
        self.assertEqual(verdict(policy, args="%2D%2Doutput=x"), "block")
        self.assertEqual(verdict(policy, args=["file.txt"]), "allow")

    def test_two_entries_combine_it_with_another_matcher(self):
        policy = rule({"arg": "target", "pattern": r"[\w./=-]+"})
        both = Policy.from_dict({"tools": {"t": {"action": "allow", "allow_args": [
            {"arg": "target", "pattern": r"[\w./=-]+"}, {"arg": "target", "no_options": True},
        ]}}})
        self.assertEqual(verdict(policy, target="--output=x"), "allow")  # the pattern alone lets it through
        self.assertEqual(verdict(both, target="--output=x"), "block")
        self.assertEqual(verdict(both, target="main"), "allow")

    def test_no_options_must_be_true(self):
        for value in (False, "true", 1, None):
            with self.subTest(value=value):
                entry_rejected(self, {"arg": "x", "no_options": value}, "'no_options' must be true")


# ---- paths -------------------------------------------------------------------------

class PathsOnWindows(unittest.TestCase):
    def setUp(self):
        self.matcher = PathMatcher.for_roots([r"C:\work\app", "~/projects"], **WINDOWS)

    def test_paths_inside_a_root_are_accepted(self):
        for value in (r"C:\work\app\a.txt", "C:/work/app/sub/b.txt", "c:\\WORK\\App\\x", r"C:\work\app",
                      "docs/a.txt", r".\docs\a.txt", r"\work\app\x", "~/projects/site/index.html",
                      "file:///C:/work/app/x.txt", "file://localhost/C:/work/app/x.txt", r"C:\work\app\sub\..\y"):
            with self.subTest(value=value):
                self.assertTrue(self.matcher.accepts(value))

    def test_paths_outside_every_root_are_refused(self):
        for value in (r"C:\work\app2\x", r"C:\work", "C:/work/app/../app2/x", "../secret.txt", r"D:\work\app\x",
                      r"C:\Users\me\.ssh\id_rsa", "~/.ssh/id_rsa", "docs/%2e%2e/%2e%2e/x",
                      "docs/%252e%252e/%252e%252e/x"):
            with self.subTest(value=value):
                self.assertFalse(self.matcher.accepts(value))

    def test_windows_tricks_are_refused(self):
        for name, value in [
            ("short 8.3 name", r"C:\work\app\SSH~1\ID_ED2~1"),
            ("alternate data stream", r"C:\work\app\a.txt:hidden"),
            ("data stream type", r"C:\work\app\a.txt::$DATA"),
            ("long-path prefix", "\\\\?\\C:\\work\\app\\x"),
            ("device prefix", "\\\\.\\C:\\work\\app\\x"),
            ("NT object path", "\\??\\C:\\work\\app\\x"),
            ("network path", "\\\\server\\share\\x"),
            ("network path with slashes", "//server/share/x"),
            ("device name", r"C:\work\app\con"),
            ("device name with extension", r"C:\work\app\NUL.txt"),
            ("numbered device", r"C:\work\app\com1.log"),
            ("trailing space climbs", "C:\\work\\app\\.. \\x"),
            ("trailing dot", r"C:\work\app\secret."),
            ("three dots", r"C:\work\app\...\x"),
            ("drive-relative", "C:app\\x"),
            ("wildcard", r"C:\work\app\*.txt"),
            ("file URI on another computer", "file://server/share/x"),
            ("another user's home", "~admin/projects/x"),
            ("control character", "C:\\work\\app\\a\x00.txt"),
        ]:
            with self.subTest(trick=name):
                self.assertFalse(self.matcher.accepts(value))

    def test_a_case_lookalike_letter_is_not_the_letter_it_resembles(self):
        self.assertFalse(self.matcher.accepts("C:\\wor\u212a\\app\\x"))  # Kelvin sign, not K
        self.assertFalse(self.matcher.accepts("C:\\work\\app\u0130\\x"))

    def test_deny_matches_any_reading_ignoring_case(self):
        deny = PathMatcher.for_roots(["~/.ssh"], **WINDOWS)
        for value in ("~/.ssh/id_rsa", r"C:\USERS\ME\.SSH\id_rsa", "C:/Users/me/.ssh", "file:///C:/Users/me/.ssh/x",
                      r"C:\Users\me\x\..\.ssh\config"):
            with self.subTest(value=value):
                self.assertTrue(deny.found_in(value))
        self.assertFalse(deny.found_in(r"C:\work\app\notes.txt"))
        self.assertFalse(deny.found_in(r"C:\Users\me\.sshd\x"))

    def test_deny_denies_what_it_cannot_read(self):
        deny = PathMatcher.for_roots(["~/.ssh"], **WINDOWS)
        for value in (r"C:\Users\me\SSH~1\id_rsa", "\\\\localhost\\c$\\Users\\me\\.ssh", "~root/.ssh", "a" * 5000):
            with self.subTest(value=value[:40]):
                self.assertTrue(deny.found_in(value))

    def test_deny_sees_through_the_folders_windows_names_twice(self):
        # Every Windows has these junctions; reaching a root through them needs no link of the agent's.
        deny = PathMatcher.for_roots(["~/.ssh", r"C:\Users\me\AppData\Roaming\Claude",
                                      r"C:\Users\me\AppData\Local\Secrets", r"C:\ProgramData\Vault"], **WINDOWS)
        for value in (r"C:\Documents and Settings\me\.ssh\id_rsa",
                      r"C:\Users\me\Application Data\Claude\config.json",
                      r"C:\Documents and Settings\me\Application Data\Claude\config.json",
                      r"C:\Users\me\Local Settings\Secrets\x",
                      r"C:\Users\me\AppData\Local\Application Data\Secrets\x",
                      r"C:\Users\All Users\Vault\key",
                      r"C:\ProgramData\Application Data\Vault\key"):
            with self.subTest(value=value):
                self.assertTrue(deny.found_in(value))
        self.assertFalse(deny.found_in(r"C:\Documents and Settings\me\notes.txt"))
        self.assertFalse(deny.found_in(r"C:\Users\me\Application Data\Other\x"))

    def test_deny_sees_through_the_other_junctions_of_a_profile_programdata_and_documents(self):
        # `dir /AL` of C:\Users\Default (copied for every new user), C:\ProgramData and Documents lists these.
        roots = ["~/AppData", "~/Pictures", "~/Music", "C:/Users/Public", "C:/ProgramData/Microsoft"]
        deny = PathMatcher.for_roots(roots, **WINDOWS)
        history = PathMatcher.for_roots([r"C:\Users\me\AppData\Local\Microsoft\Windows\History",
                                         r"C:\Users\me\AppData\Local\Microsoft\Windows\INetCache"], **WINDOWS)
        for value in (r"C:\Users\me\Start Menu\Programs\Startup\evil.cmd", "~/Start Menu/Programs/Startup/evil.cmd",
                      r"C:\Users\me\SendTo\evil.lnk", r"C:\Users\me\Recent\report.lnk",
                      r"C:\Users\me\Templates\Normal.dotm", r"C:\Users\me\NetHood\x", r"C:\Users\me\PrintHood\x",
                      r"C:\Users\me\Cookies\x", r"C:\Documents and Settings\me\Start Menu\Programs\Startup\evil.cmd",
                      r"C:\ProgramData\Start Menu\Programs\StartUp\evil.cmd", r"C:\ProgramData\Templates\x",
                      r"C:\ProgramData\Desktop\evil.lnk", r"C:\ProgramData\Documents\x.txt",
                      r"C:\Users\All Users\Documents\x.txt", r"C:\Users\me\Documents\My Pictures\passport.jpg",
                      r"C:\Users\me\My Documents\My Music\song.mp3"):
            with self.subTest(value=value):
                self.assertTrue(deny.found_in(value))
        for value in (r"C:\Users\me\Local Settings\History\x", r"C:\Users\me\AppData\Local\Temporary Internet Files\x",
                      r"C:\Users\me\AppData\Local\Microsoft\Windows\Temporary Internet Files\x"):
            with self.subTest(value=value):
                self.assertTrue(history.found_in(value))
        # A folder of the same name elsewhere is no junction, and the real folders are not aliases of themselves.
        for value in (r"C:\work\app\templates\index.html", r"C:\work\Microsoft\Windows\Start Menu\Programs\x",
                      r"C:\Users\me\Documents\notes.txt", r"C:\Users\me\Desktop\x"):
            with self.subTest(value=value):
                self.assertFalse(deny.found_in(value))

    def test_deny_denies_a_value_with_more_alias_readings_than_it_follows(self):
        deny = PathMatcher.for_roots(["~/AppData"], **WINDOWS)
        names = ["templates", "recent", "sendto", "cookies", "nethood", "printhood", "start menu"]
        self.assertFalse(deny.found_in("C:\\work\\" + "\\".join(names[:4]) + "\\x"))
        self.assertTrue(deny.found_in("C:\\work\\" + "\\".join(names) + "\\x"))  # denied rather than read in part

    def test_an_unknown_current_folder_refuses_relative_paths(self):
        def gone():
            raise FileNotFoundError("deleted")

        matcher = PathMatcher.for_roots([r"C:\work\app"], flavour=ntpath, current_folder=gone)
        self.assertFalse(matcher.accepts("docs/a.txt"))
        self.assertTrue(matcher.accepts(r"C:\work\app\docs\a.txt"))


class PathsOnPosix(unittest.TestCase):
    def setUp(self):
        self.matcher = PathMatcher.for_roots(["/work/app", "~/projects"], **POSIX)

    def test_paths_inside_a_root_are_accepted(self):
        for value in ("/work/app/a.txt", "docs/a.txt", "./docs/../b.txt", "~/projects/x", "file:///work/app/x",
                      "/work/app", "///work/app/x"):
            with self.subTest(value=value):
                self.assertTrue(self.matcher.accepts(value))

    def test_paths_outside_or_unclear_are_refused(self):
        for value in ("/work/app2/x", "/work/app/../app2", "../x", "/WORK/app/a", "//work/app/x", "docs\\..\\..\\x",
                      "/work/app/*", "~/.ssh/id_rsa", "~other/x", "/etc/passwd", "file://host/work/app/x"):
            with self.subTest(value=value):
                self.assertFalse(self.matcher.accepts(value))

    def test_deny_ignores_case_because_some_file_systems_do(self):
        deny = PathMatcher.for_roots(["~/.ssh"], **POSIX)
        self.assertTrue(deny.found_in("/home/me/.SSH/id_rsa"))
        self.assertTrue(deny.found_in("~/.ssh"))
        self.assertFalse(deny.found_in("/home/me/notes"))

    def test_deny_sees_through_the_folders_the_system_names_twice(self):
        deny = PathMatcher.for_roots(["~/.ssh", "/etc", "/private/var/secrets"], **POSIX)
        for value in ("/proc/self/root/home/me/.ssh/id_rsa", "/proc/self/cwd/../home/me/.ssh/id_rsa",
                      "/proc/1/task/1/root/etc/passwd", "/proc/self/fd/3", "/dev/fd/3", "/x/../proc/self/cwd/..",
                      "/private/etc/passwd", "/var/secrets/key"):
            with self.subTest(value=value):
                self.assertTrue(deny.found_in(value))
        self.assertFalse(deny.found_in("/private/notes/a.txt"))
        self.assertFalse(deny.found_in("/proc/cpuinfo"))

    def test_a_path_through_another_process_is_not_accepted_either(self):
        self.assertFalse(self.matcher.accepts("/proc/self/cwd/a.txt"))
        self.assertFalse(self.matcher.accepts("/proc/self/root/work/app/a.txt"))


class PathsInAPolicy(unittest.TestCase):
    """These use this machine's own path rules, with a real temporary folder as the root."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.realpath(self.tmp.name)
        self.policy = rule({"arg": "path", "type": "path", "roots": [self.root]})

    def test_a_path_in_the_root_is_allowed_and_one_outside_is_blocked(self):
        self.assertEqual(verdict(self.policy, path=os.path.join(self.root, "a.txt")), "allow")
        self.assertEqual(verdict(self.policy, path=os.path.join(self.root, "..", "a.txt")), "block")
        self.assertEqual(verdict(self.policy, path=self.root + "2"), "block")

    def test_only_text_is_a_path(self):
        for value in (5, True, None, {"p": self.root}, [], [self.root, 5]):
            with self.subTest(value=value):
                self.assertEqual(verdict(self.policy, path=value), "block")
        inside = [os.path.join(self.root, "a"), os.path.join(self.root, "b")]
        self.assertEqual(verdict(self.policy, path=inside), "allow")

    def test_a_deny_entry_with_a_path_type(self):
        policy = rule({"arg": "path", "type": "path", "roots": [self.root]}, deny=True)
        self.assertEqual(verdict(policy, path=os.path.join(self.root, "x", "..", "y")), "block")
        self.assertEqual(verdict(policy, path=os.path.join(self.root + "-other", "y")), "allow")

    def test_a_root_that_does_not_exist_is_warned_about(self):
        missing = os.path.join(self.root, "no-such-folder")
        warnings = rule({"arg": "path", "type": "path", "roots": [missing, self.root]}).warnings()
        self.assertEqual(len(warnings), 1)
        self.assertIn("tools.t.allow_args[0]", warnings[0])
        self.assertIn("no-such-folder", warnings[0])
        self.assertEqual(self.policy.warnings(), [])

    def test_roots_must_be_absolute_text_that_can_be_read(self):
        for roots, fragment in [
            (["relative/folder"], "must be an absolute path"),
            ([], "at least one entry"),
            ("C:/work", "at least one entry"),
            ([5], "must be text"),
            ([" /work"], "spaces around it"),
        ]:
            with self.subTest(roots=roots):
                entry_rejected(self, {"arg": "path", "type": "path", "roots": roots}, fragment)

    @unittest.skipUnless(os.name == "nt", "Windows path rules")
    def test_a_root_with_a_windows_trick_is_refused_when_loading(self):
        for root, fragment in [(r"C:\PROGRA~1\app", "short (8.3) name"), (r"\\server\share", "network"),
                               (r"C:\work\con", "device")]:
            with self.subTest(root=root):
                entry_rejected(self, {"arg": "path", "type": "path", "roots": [root]}, fragment)


class HostileValuesAreHandledQuickly(unittest.TestCase):
    VALUES = ["a" * 1_000_000, "\\" * 500_000, "../" * 300_000, "%25" * 300_000, "C:" + "\\a" * 2000,
              "~" * 100_000, "http://" + "a." * 200_000, "@" * 500_000, "[" * 300_000, "1." * 300_000]

    def test_every_typed_matcher_answers_quickly(self):
        matchers = [PathMatcher.for_roots([r"C:\work"], **WINDOWS), PathMatcher.for_roots(["/work"], **POSIX)]
        started = time.perf_counter()
        for value in self.VALUES:
            for matcher in matchers:
                self.assertFalse(matcher.accepts(value))
                matcher.found_in(value)
            self.assertIsNone(read_url(value))
            self.assertIsNone(read_email_domain(value))
        self.assertLess(time.perf_counter() - started, 5)

    def test_a_policy_with_typed_rules_checks_a_huge_call_quickly(self):
        policy = Policy.from_dict({"tools": {"t": {"action": "allow",
            "deny_args": [{"arg": "*", "one_of": ["x"]}, {"arg": "u", "type": "url", "hosts": ["evil.example"]}],
            "allow_args": [{"arg": "u", "type": "url", "hosts": ["example.com"]},
                           {"arg": "m", "type": "email", "domains": ["example.com"], "optional": True}]}}})
        started = time.perf_counter()
        for value in self.VALUES:
            policy.evaluate("t", {"u": value, "m": value})
        self.assertLess(time.perf_counter() - started, 5)


# ---- urls ----------------------------------------------------------------------------

class Urls(unittest.TestCase):
    def setUp(self):
        self.policy = rule({"arg": "url", "type": "url", "hosts": ["example.com", ".example.com", "8.8.8.8"]})

    def check(self, url):
        return verdict(self.policy, url=url)

    def test_a_listed_host_over_https_is_allowed(self):
        for url in ("https://example.com", "https://example.com/a?b=c#d", "https://www.example.com:8443/x",
                    "HTTPS://EXAMPLE.COM/x", "https://example.com./x", "https://8.8.8.8/dns",
                    "https://example.com/اردو"):
            with self.subTest(url=url):
                self.assertEqual(self.check(url), "allow")

    def test_hosts_that_only_contain_a_listed_name_are_blocked(self):
        for url in ("https://evil.net/?.example.com/x", "https://evil.net#.example.com/x",
                    "https://example.com.evil.net/", "https://evilexample.com/", "https://evil.net/https://example.com"):
            with self.subTest(url=url):
                self.assertEqual(self.check(url), "block")

    def test_only_https_unless_more_schemes_are_listed(self):
        self.assertEqual(self.check("http://example.com/"), "block")
        self.assertEqual(self.check("ftp://example.com/"), "block")
        both = rule({"arg": "url", "type": "url", "hosts": ["example.com"], "schemes": ["http", "HTTPS"]})
        self.assertEqual(verdict(both, url="http://example.com/"), "allow")
        self.assertEqual(verdict(both, url="https://example.com/"), "allow")

    def test_text_that_parsers_read_differently_is_blocked(self):
        for url in ("https://evil.net\\@example.com/", "https://evil.net\\.example.com/", "https://user@example.com/",
                    "https://example.com@evil.net/", "https://ex%61mple.com/", "https:// example.com/",
                    "https://example.com /x", "https://exa\tmple.com/", "https:example.com", "//example.com/x",
                    "example.com", "https://example.com:99999/", "https://example.com:+443/", "https://example.com:/",
                    "https://[example.com]/", "https://example..com/"):
            with self.subTest(url=url):
                self.assertEqual(self.check(url), "block")

    def test_numeric_hosts_are_blocked_unless_listed_exactly(self):
        for url in ("https://8.8.4.4/", "https://134744072/", "https://0x08080808/", "https://010.010.010.010/",
                    "https://8.8.8/", "https://[::ffff:8.8.8.8]/", "https://example.123/"):
            with self.subTest(url=url):
                self.assertEqual(self.check(url), "block")

    def test_metadata_names_are_blocked_even_under_a_wildcard(self):
        policy = rule({"arg": "url", "type": "url", "hosts": [".internal", ".google.internal", "example.com"]})
        self.assertEqual(verdict(policy, url="https://metadata.google.internal/computeMetadata/v1/"), "block")
        self.assertEqual(verdict(policy, url="https://db.internal/"), "allow")
        entry_rejected(self, {"arg": "u", "type": "url", "hosts": [".localhost"]}, "never allowed")

    def test_non_ascii_and_punycode_hosts_are_blocked(self):
        for url in ("https://exаmple.com/", "https://xn--exmple-cua.com/", "https://www.xn--80ak6aa92e.example.com/"):
            with self.subTest(url=url):
                self.assertEqual(self.check(url), "block")

    def test_a_label_longer_than_dns_allows_is_blocked(self):
        self.assertEqual(self.check(f"https://{'a' * 63}.example.com/"), "allow")
        self.assertEqual(self.check(f"https://{'a' * 64}.example.com/"), "block")
        self.assertEqual(self.check("https://" + "a." * 130 + "example.com/"), "block")  # over 253 characters

    def test_subdomain_entries_do_not_cover_the_name_itself(self):
        policy = rule({"arg": "url", "type": "url", "hosts": ["*.example.com"]})
        self.assertEqual(verdict(policy, url="https://api.example.com/"), "allow")
        self.assertEqual(verdict(policy, url="https://example.com/"), "block")

    def test_only_text_is_a_url(self):
        for value in (5, None, {"href": "https://example.com"}, ["https://example.com", 5]):
            with self.subTest(value=value):
                self.assertEqual(self.check(value), "block")
        self.assertEqual(self.check(["https://example.com", "https://a.example.com"]), "allow")

    def test_deny_blocks_a_listed_host_with_any_scheme_and_what_it_cannot_read(self):
        policy = rule({"arg": "url", "type": "url", "hosts": ["pastebin.com", "169.254.169.254"]}, deny=True)
        for url in ("https://pastebin.com/raw/x", "ftp://PASTEBIN.com/", "https://pastebin%2Ecom/x",
                    "http://169.254.169.254/latest/meta-data", "http://2852039166/", "pastebin.com/raw/x",
                    "http://[::ffff:169.254.169.254]/", "http://[::ffff:a9fe:a9fe]/", "http://[64:ff9b::a9fe:a9fe]/"):
            with self.subTest(url=url):
                self.assertEqual(verdict(policy, url=url), "block")
        self.assertEqual(verdict(policy, url="https://example.com/"), "allow")

    def test_deny_reads_a_url_as_written_so_an_escape_in_its_path_is_no_reason_to_deny(self):
        # Decoding "%20" gives a space, which read_url refuses: decoding first would deny every such URL.
        policy = rule({"arg": "url", "type": "url", "hosts": ["pastebin.com"]}, deny=True)
        for url in ("https://docs.python.org/search?q=two%20words", "https://example.com/a%0Ab",
                    "https://example.com/a%5Cb", "https://example.com/%25252525252525"):
            with self.subTest(url=url):
                self.assertEqual(verdict(policy, url=url), "allow")
        # An escape in the host, or a URL that only an extra decoding makes readable, is still denied.
        for url in ("https://pastebin%2Ecom/x", "https%3A%2F%2Fpastebin.com/x", "https://example.com%40pastebin.com/",
                    "https://pastebin.com/search?q=two%20words"):
            with self.subTest(url=url):
                self.assertEqual(verdict(policy, url=url), "block")

    def test_private_and_metadata_addresses_cannot_be_allowed(self):
        for host in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "100.100.100.200", "::1",
                     "[fd00:ec2::254]", "::ffff:169.254.169.254", "0.0.0.0", "224.0.0.1", "localhost",
                     "metadata.google.internal"):
            with self.subTest(host=host):
                entry_rejected(self, {"arg": "u", "type": "url", "hosts": [host]}, "never allowed")
        rule({"arg": "u", "type": "url", "hosts": ["127.0.0.1", "localhost"]}, deny=True)  # denying them is fine

    def test_hosts_entries_are_checked(self):
        for host, fragment in [
            ("https://example.com", "host name only"), ("example.com:443", "host name only"),
            ("example.com/path", "host name only"), ("*", "list the hosts"), ("api.*.example.com", "list the hosts"),
            ("exämple.com", "non-ASCII"), ("xn--exmple-cua.com", "not a valid host name"),
            ("a..b", "not a valid host name"),
            ("1.2.3", "not a valid IP address"), ("*.8.8.8.8", "no subdomains"), ("", "must not be empty"),
        ]:
            with self.subTest(host=host):
                entry_rejected(self, {"arg": "u", "type": "url", "hosts": [host]}, fragment)
        entry_rejected(self, {"arg": "u", "type": "url", "hosts": []}, "at least one entry")

    def test_schemes_are_checked(self):
        for schemes, fragment in [(["mailto"], "type\": \"email"), (["file"], "type\": \"path"),
                                  (["ht tp"], "not a URL scheme"), ([], "at least one entry"),
                                  ("https", "at least one entry")]:
            with self.subTest(schemes=schemes):
                entry = {"arg": "u", "type": "url", "hosts": ["example.com"], "schemes": schemes}
                entry_rejected(self, entry, fragment)
        entry = {"arg": "u", "type": "url", "hosts": ["e.com"], "schemes": ["https"]}
        entry_rejected(self, entry, "only used in allow_args", deny=True)


# ---- e-mail addresses ------------------------------------------------------------------

class EmailAddresses(unittest.TestCase):
    def setUp(self):
        self.policy = rule({"arg": "to", "type": "email", "domains": ["example.com", ".corp.example"]})

    def test_an_address_at_a_listed_domain_is_allowed(self):
        for to in ("bob@example.com", "Bob.Smith+news@EXAMPLE.COM", "o'brien@mail.corp.example",
                   ["a@example.com", "b@example.com"]):
            with self.subTest(to=to):
                self.assertEqual(verdict(self.policy, to=to), "allow")

    def test_anything_but_one_plain_address_at_a_listed_domain_is_blocked(self):
        for to in ("bob@evil.example", "bob@example.com.evil.example", "Bob <bob@example.com>",
                   "a@example.com, b@example.com", "a@example.com;b@evil.example", "bob%evil.example@example.com",
                   "evil.example!bob@example.com", '"bob"@example.com', "bob@[93.184.216.34]", "bob@1.2.3.4",
                   "@example.com", "bob@", ".bob@example.com", "bo..b@example.com", "bob@example.com ",
                   "böb@example.com",
                   "bob@corp.example", ["bob@example.com", "x@evil.example"], 5):
            with self.subTest(to=to):
                self.assertEqual(verdict(self.policy, to=to), "block")

    def test_deny_blocks_a_listed_domain_and_what_it_cannot_read(self):
        policy = rule({"arg": "to", "type": "email", "domains": ["evil.example"]}, deny=True)
        for to in ("x@evil.example", "X@EVIL.EXAMPLE", "Bob <x@example.com>", ["a@example.com", "x@evil.example"]):
            with self.subTest(to=to):
                self.assertEqual(verdict(policy, to=to), "block")
        self.assertEqual(verdict(policy, to="a@example.com"), "allow")

    def test_domains_entries_are_checked(self):
        for domain, fragment in [("1.2.3.4", "IP addresses are not supported"), ("exämple.com", "non-ASCII"),
                                 ("@example.com", "host name only"), ("*", "list the hosts")]:
            with self.subTest(domain=domain):
                entry_rejected(self, {"arg": "to", "type": "email", "domains": [domain]}, fragment)


# ---- entries --------------------------------------------------------------------------

class Entries(unittest.TestCase):
    def test_an_entry_needs_exactly_one_matcher(self):
        entry_rejected(self, {"arg": "to"}, "needs a matcher")
        entry_rejected(self, {"arg": "to", "pattern": "a", "one_of": ["a"]}, "exactly one matcher", "two entries")
        entry_rejected(self, {"arg": "to", "no_options": True, "starts_with": "a"}, "exactly one matcher")

    def test_type_settings_go_with_their_type(self):
        entry_rejected(self, {"arg": "p", "roots": ["/x"]}, "no \"type\"")
        entry_rejected(self, {"arg": "p", "pattern": "a", "hosts": ["e.com"]}, "'hosts' goes with \"type\"")
        entry = {"arg": "p", "type": "path", "roots": ["/x"], "hosts": ["e.com"]}
        entry_rejected(self, entry, "'hosts' goes with \"type\": 'url'")
        entry_rejected(self, {"arg": "u", "type": "url", "hosts": ["e.com"], "domains": ["e.com"]}, "'email'")

    def test_each_type_needs_its_setting(self):
        for kind, setting in (("path", "roots"), ("url", "hosts"), ("email", "domains")):
            with self.subTest(type=kind):
                entry_rejected(self, {"arg": "x", "type": kind}, f"needs '{setting}'")

    def test_an_unknown_type_is_refused_with_a_suggestion(self):
        entry_rejected(self, {"arg": "x", "type": "URL", "hosts": ["e.com"]}, "did you mean 'url'?")
        entry_rejected(self, {"arg": "x", "type": 5}, "'type' must be")

    def test_a_typed_matcher_needs_a_named_argument(self):
        rejected(self, {"deny_args": [{"arg": "*", "type": "url", "hosts": ["e.com"]}]}, "needs a named argument")

    def test_a_pattern_must_be_text_and_a_valid_expression(self):
        entry_rejected(self, {"arg": "x", "pattern": 5}, "'pattern' must be text")
        entry_rejected(self, {"arg": "x", "pattern": "("}, "bad pattern")

    def test_optional_is_explained_in_deny_args(self):
        rejected(self, {"deny_args": [{"arg": "a", "pattern": "b", "optional": True}]}, "only used in allow_args")

    def test_an_optional_typed_argument_may_be_left_out(self):
        policy = rule({"arg": "cc", "type": "email", "domains": ["example.com"], "optional": True})
        self.assertEqual(verdict(policy), "allow")
        self.assertEqual(verdict(policy, cc="x@evil.example"), "block")

    def test_entries_describe_what_they_check(self):
        policy = Policy.from_dict({"tools": {"t": {"action": "allow", "allow_args": [
            {"arg": "u", "type": "url", "hosts": ["example.com", ".example.org"]},
            {"arg": "m", "type": "email", "domains": ["example.com"], "optional": True},
            {"arg": "e", "one_of": ["b", "a"]},
            {"arg": "s", "starts_with": "docs/"},
            {"arg": "o", "no_options": True},
        ]}}})
        described = [entry.describe() for entry in policy.tools[0].allow_args]
        self.assertEqual(described, [
            "argument 'u': a https URL to example.com, *.example.org",
            "argument 'm': an e-mail address at example.com, or left out",
            "argument 'e': one of 'a', 'b'",
            "argument 's': starts with 'docs/'",
            "argument 'o': no value that starts with '-'",
        ])


class ThePolicyFileStillLoads(unittest.TestCase):
    def test_a_policy_file_with_every_matcher_loads(self):
        text = """{
          "deny_args": [{"arg": "*", "contains": "id_rsa"}, {"arg": "*", "one_of": ["--force"]}],
          "tools": {
            "fetch": {"action": "allow", "allow_args": [{"arg": "url", "type": "url", "hosts": [".example.com"]}]},
            "mail": {"action": "ask", "allow_args": [
              {"arg": "to", "type": "email", "domains": ["example.com"]},
              {"arg": "body", "pattern": "(?s).*", "optional": true}], "other_args": "block"},
            "git": {"action": "allow", "allow_args": [{"arg": "ref", "no_options": true},
                                                      {"arg": "ref", "starts_with": "feature/"}]},
            "read": {"action": "allow", "deny_args": [{"arg": "path", "ends_with": ".pem"}]}
          }
        }"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(text, encoding="utf-8")
            policy = Policy.from_file(path)
        self.assertEqual(policy.evaluate("git", {"ref": "feature/x"}).action, "allow")
        self.assertEqual(policy.evaluate("git", {"ref": "-feature/x"}).action, "block")
        self.assertEqual(policy.evaluate("fetch", {"url": "https://docs.example.com/a"}).action, "allow")
        self.assertEqual(policy.evaluate("read", {"path": "server.pem"}).action, "block")


if __name__ == "__main__":
    unittest.main()
