"""Containing the server's process: proxy --contain and --sandbox (agent_sentinel/containment.py), wrap and doctor.

The unit tests check what the proxy would do, on any platform. The
end-to-end tests start the real proxy in front of small servers written for
them, and look at the processes: on Windows the job object (an orphaned
grandchild ends with the proxy, and the limits hold), on Linux and macOS the
process group and the resource limits, on Linux the signal at the proxy's
death, and, where bubblewrap works, the sandbox. Every test that starts a
process stops it, and waits have time limits.
"""

import ctypes
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from support import EXAMPLE_POLICY_PATH, ROOT
from test_cli_doctor import DoctorTest
from agent_sentinel import containment, mcp_proxy, wrapping
from agent_sentinel.containment import ContainmentError, Settings, bwrap_arguments, check, sandbox_exec_profile
from agent_sentinel.wrapping import ProxySettings, read_proxy_command, status_of, wrap_entry

POSIX = os.name == "posix"
WINDOWS = sys.platform == "win32"


def found(name):
    return f"/usr/bin/{name}"


def not_found(name):
    return None


# ---- the options and what they ask for --------------------------------------------------------------

class TheOptions(unittest.TestCase):
    def parse(self, *words):
        with mock.patch("sys.stderr"):
            return mcp_proxy._argument_parser().parse_args(["--policy", "p.json", *words, "--", "server"])

    def test_the_proxy_reads_every_containment_option(self):
        args = self.parse("--contain", "--server-memory-mb", "512", "--server-processes", "8",
                          "--server-cpu-seconds", "60", "--sandbox", "bwrap", "--sandbox-allow", "~/work",
                          "--sandbox-read", "/opt/node", "--sandbox-network")
        settings = mcp_proxy._containment_settings(args)
        self.assertEqual(settings, Settings(True, 512, 8, 60, "bwrap", (os.path.expanduser("~/work"),),
                                            ("/opt/node",), True))
        self.assertFalse(mcp_proxy._containment_settings(self.parse()).active)

    def test_values_out_of_range_are_refused(self):
        for words in (("--server-memory-mb", "8"), ("--server-memory-mb", "lots"), ("--server-processes", "0"),
                      ("--server-cpu-seconds", "-1"), ("--server-cpu-seconds", "9" * 20), ("--sandbox", "docker"),
                      ("--contai",)):
            with self.subTest(words=words), self.assertRaises(SystemExit):
                self.parse(*words)

    def test_a_memory_limit_too_small_to_start_anything_is_refused_with_the_least_value(self):
        for text in ("0", "1", str(containment.MIN_SERVER_MEMORY_MB - 1)):
            with self.subTest(text=text), self.assertRaisesRegex(
                    ValueError, f"must be {containment.MIN_SERVER_MEMORY_MB} to .* megabytes; the least is "
                                f"{containment.MIN_SERVER_MEMORY_MB}"):
                containment.memory_mb(text)
        self.assertEqual(containment.memory_mb(str(containment.MIN_SERVER_MEMORY_MB)), containment.MIN_SERVER_MEMORY_MB)
        stderr = io.StringIO()
        with mock.patch("sys.stderr", stderr), self.assertRaises(SystemExit):
            mcp_proxy._argument_parser().parse_args(["--policy", "p.json", "--server-memory-mb", "4", "--", "server"])
        self.assertIn(f"the least is {containment.MIN_SERVER_MEMORY_MB}", stderr.getvalue())

    def test_each_option_implies_contain(self):
        for settings in (Settings(memory_mb=64), Settings(processes=2), Settings(cpu_seconds=5),
                         Settings(sandbox="bwrap"), Settings(allow=("/w",)), Settings(network=True)):
            with self.subTest(settings=settings):
                self.assertTrue(settings.active)
        self.assertFalse(Settings().active)

    def test_wrap_and_doctor_know_the_options(self):
        for option in containment_options():
            with self.subTest(option=option):
                self.assertIn(option, wrapping.VALUE_OPTIONS | wrapping.FLAG_OPTIONS)
                self.assertIn(option, wrapping.CONTAIN_OPTIONS)


def containment_options():
    return ("--contain", "--server-memory-mb", "--server-processes", "--server-cpu-seconds", "--sandbox",
            "--sandbox-allow", "--sandbox-read", "--sandbox-network")


class WhetherItCanWorkHere(unittest.TestCase):
    def test_contain_and_its_limits_work_everywhere_but_the_process_limit_is_windows_only(self):
        for platform in ("win32", "linux", "darwin"):
            with self.subTest(platform=platform):
                self.assertIsNone(check(Settings(contain=True, memory_mb=64, cpu_seconds=5), found, platform))
        self.assertIsNone(check(Settings(processes=4), found, "win32"))
        self.assertIn("only available on Windows", check(Settings(processes=4), found, "linux"))

    def test_each_sandbox_needs_its_platform_and_its_tool(self):
        self.assertIn("not available on Windows", check(Settings(sandbox="bwrap"), found, "win32"))
        self.assertIn("not available on Windows", check(Settings(sandbox="sandbox-exec"), found, "win32"))
        self.assertIn("needs Linux", check(Settings(sandbox="bwrap"), found, "darwin"))
        self.assertIn("needs macOS", check(Settings(sandbox="sandbox-exec"), found, "linux"))
        self.assertIn("not on PATH", check(Settings(sandbox="bwrap"), not_found, "linux"))
        with mock.patch("os.path.isfile", return_value=False):
            self.assertIn("is missing", check(Settings(sandbox="sandbox-exec"), found, "darwin"))
        with mock.patch("os.path.isfile", return_value=True):
            self.assertIsNone(check(Settings(sandbox="sandbox-exec"), found, "darwin"))
            self.assertIn("are for --sandbox bwrap", check(Settings(sandbox="sandbox-exec", read=("/x",)), found,
                                                           "darwin"))

    def test_sandbox_options_need_a_sandbox(self):
        for settings in (Settings(allow=("/w",)), Settings(contain=True, read=("/w",)), Settings(network=True)):
            with self.subTest(settings=settings):
                self.assertIn("need --sandbox", check(settings, found, "linux"))

    @unittest.skipUnless(sys.platform.startswith("linux"), "the folders a bwrap sandbox may show are checked on Linux")
    def test_folders_that_would_show_the_home_folder_or_credentials_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            home = os.path.realpath(folder)
            os.makedirs(os.path.join(home, "work"))
            os.makedirs(os.path.join(home, ".ssh"))
            os.makedirs(os.path.join(home, ".config", "gh"))

            def problem(*allow):
                return check(Settings(sandbox="bwrap", allow=allow), found, "linux", user_home=home)

            self.assertIsNone(problem(os.path.join(home, "work")))
            self.assertIn("whole home folder", problem(home))
            self.assertIn("whole home folder", problem("/"))
            self.assertIn("credentials", problem(os.path.join(home, ".ssh")))
            self.assertIn("credentials", problem(os.path.join(home, ".config")))
            # PB2-5: a plugin's or extension's server lives in the client's own folder, which stays hidden.
            os.makedirs(os.path.join(home, ".claude", "plugins", "p"))
            self.assertIn("cannot be sandboxed", problem(os.path.join(home, ".claude", "plugins", "p")))
            self.assertIn("does not exist", problem(os.path.join(home, "nope")))
            self.assertIn("not a full path", problem("work"))
            # PB-5: a folder may not show the host's sockets again.
            if os.path.isdir("/run"):
                self.assertIn("where the host's services have their sockets", problem("/run"))
            # PB-7: nor hold the proxy's own files, whether they exist yet or not.
            work = os.path.join(home, "work")
            refused = check(Settings(sandbox="bwrap", allow=(work,)), found, "linux", user_home=home,
                            control_files=[os.path.join(work, "logs", "audit.jsonl")])
            self.assertIn("could then change or replace", refused)
            self.assertIsNone(check(Settings(sandbox="bwrap", read=(work,)), found, "linux", user_home=home,
                                    control_files=[os.path.join(work, "policy.json")]))


def same(path):
    return path


def a_linux_host(*present, links=None):
    """exists and real for a Linux host with these paths (and every home folder named below), and these links."""
    links = links or {}

    def real(path):
        for link, target in links.items():
            if containment._within(path, link):
                return target + path[len(link):]
        return path

    def exists(path):
        return path in present or real(path) in present or path.startswith(("/home/", "/srv/"))

    return exists, real


class TheSandboxesWords(unittest.TestCase):
    HOME = "/home/me"

    def test_bwrap_shows_the_file_system_read_only_and_hides_the_home_folder(self):
        settings = Settings(sandbox="bwrap", allow=("/home/me/work",), read=("/home/me/work/docs", "/home/me/.nvm"))
        exists, real = a_linux_host("/run", "/var/run", "/run/user", links={"/var/run": "/run"})
        words = bwrap_arguments(settings, self.HOME, "/home/me/.agent-sentinel", exists=exists, real=real)
        self.assertEqual(words[:12], ["--unshare-all", "--die-with-parent", "--new-session", "--ro-bind", "/", "/",
                                      "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"])
        self.assertNotIn("--share-net", words)
        text = " ".join(words)
        # Later mounts cover earlier ones: /run and the home folder are emptied, then the folders are shown,
        # shorter paths first (so docs inside work stays read-only), then the agent-sentinel home is hidden again.
        order = ["--tmpfs /run ", "--tmpfs /home/me ", "--bind /home/me/work /home/me/work",
                 "--ro-bind /home/me/work/docs /home/me/work/docs", "--tmpfs /home/me/.agent-sentinel"]
        positions = [text.index(part) for part in order]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("--ro-bind /home/me/.nvm /home/me/.nvm", text)
        self.assertNotIn("/var/run", text)  # a link to /run: hidden with it
        self.assertNotIn("/run/user", text)  # inside /run
        self.assertIn("--share-net", bwrap_arguments(Settings(sandbox="bwrap", network=True), self.HOME, None))
        nothing = bwrap_arguments(Settings(sandbox="bwrap"), self.HOME, None, exists=lambda path: False, real=same)
        self.assertNotIn("/run", nothing)

    def test_bwrap_hides_every_place_where_the_hosts_services_have_sockets(self):
        # PB-5: /run/docker.sock, /run/containerd, the system D-Bus, LXD; a socket works on a read-only mount.
        exists, real = a_linux_host("/run", "/var/run", "/var/lib/lxd", "/var/snap/lxd/common/lxd",
                                    "/run/systemd/resolve/stub-resolv.conf",
                                    links={"/etc/resolv.conf": "/run/systemd/resolve/stub-resolv.conf"})
        words = bwrap_arguments(Settings(sandbox="bwrap"), self.HOME, None, exists=exists, real=real)
        hidden = [words[index + 1] for index, word in enumerate(words) if word == "--tmpfs"]
        self.assertEqual(hidden, ["/tmp", "/run", "/var/run", "/var/lib/lxd", "/var/snap/lxd/common/lxd", "/home/me"])
        self.assertNotIn("stub-resolv.conf", " ".join(words))
        # With the network, the resolver's file comes back, alone: name lookups need it, and it is no socket.
        networked = bwrap_arguments(Settings(sandbox="bwrap", network=True), self.HOME, None, exists=exists, real=real)
        text = " ".join(networked)
        resolver = "--ro-bind /run/systemd/resolve/stub-resolv.conf /run/systemd/resolve/stub-resolv.conf"
        self.assertIn(resolver, text)
        self.assertLess(text.index("--tmpfs /run "), text.index(resolver))

    def test_bwrap_hides_the_accounts_own_home_folder_too_and_shows_a_folder_at_both_its_paths(self):
        # PB-9: HOME may name another folder; the real one must not show through the read-only /.
        exists, real = a_linux_host(links={"/home/me/tools": "/srv/tools"})
        words = bwrap_arguments(Settings(sandbox="bwrap", read=("/home/me/tools",)), ["/tmp/x/home", "/home/me"],
                                None, exists=lambda path: True, real=real)
        text = " ".join(words)
        self.assertLess(text.index("--tmpfs /home/me "), text.index("--tmpfs /tmp/x/home"))
        self.assertIn("--ro-bind /home/me/tools /home/me/tools", text)
        self.assertIn("--ro-bind /srv/tools /srv/tools", text)

    def test_the_servers_program_must_be_visible_inside_bwrap(self):
        exists, real = a_linux_host("/run", links={"/run/current-system": "/nix/store/abc-system"})
        homes = ["/home/me"]

        def problem(program, **folders):
            return containment._hidden_program_problem(program, Settings(sandbox="bwrap", **folders), homes,
                                                       exists=exists, real=real)

        self.assertIsNone(problem("/usr/bin/node"))
        self.assertIn("add --sandbox-read /home/me/.nvm/bin", problem("/home/me/.nvm/bin/node"))
        self.assertIsNone(problem("/home/me/.nvm/bin/node", read=("/home/me/.nvm",)))
        self.assertIn("inside /run", problem("/run/current-system/sw/bin/node"))
        self.assertIsNone(problem("/run/current-system/sw/bin/node", read=("/run/current-system/sw/bin",)))
        self.assertIn("inside /tmp", problem("/tmp/server/run"))

    def test_a_server_installed_in_a_credential_place_cannot_be_sandboxed(self):
        # PB2-5: editor extensions and Claude Code plugins install their servers in ~/.vscode, ~/.cursor and
        # ~/.claude, which both sandboxes hide (PROXY-8); the proxy says so before anything starts.
        homes = ["/home/me"]
        for program in ("/home/me/.claude/plugins/p/server", "/home/me/.vscode/extensions/e/bin/srv",
                        "/home/me/.cursor/extensions/e/srv", "/home/me/.ssh/run"):
            with self.subTest(program=program):
                problem = containment._credential_program_problem(program, homes, real=same)
                self.assertIn("a place where credentials are kept", problem)
                self.assertIn("cannot be sandboxed", problem)
        for program in ("/usr/bin/node", "/home/me/.nvm/bin/node", "/home/me/.claudette/srv"):
            with self.subTest(program=program):
                self.assertIsNone(containment._credential_program_problem(program, homes, real=same))
        linked = containment._credential_program_problem("/usr/local/bin/srv", homes,
                                                          real=lambda path: "/home/me/.claude/plugins/p/srv")
        self.assertIn("inside /home/me/.claude,", linked)
        with mock.patch.object(containment, "_homes", return_value=homes), \
                mock.patch.object(containment, "_agent_home", return_value="/home/me/.agent-sentinel"):
            for sandbox in ("bwrap", "sandbox-exec"):
                with self.subTest(sandbox=sandbox), self.assertRaises(ContainmentError) as caught:
                    containment._sandbox_prefix(Settings(sandbox=sandbox), found, [],
                                                "/home/me/.claude/plugins/p/server")
                self.assertIn("cannot be sandboxed", str(caught.exception))

    def test_a_folder_the_server_may_write_may_not_hold_the_proxys_own_files(self):
        # PB-7: whether the file exists yet or not, and the agent-sentinel home too.
        def problem(*protected):
            return containment._writable_problem(("/w",), protected, real=same)

        self.assertIn("/w/sub/audit.jsonl", problem("/w/sub/audit.jsonl"))
        self.assertIn("could then change or replace", problem("/etc/policy.json", "/w/.agent-sentinel"))
        self.assertIsNone(problem("/etc/policy.json", "/home/me/.agent-sentinel", None))
        self.assertIsNone(containment._writable_problem((), ["/w/policy.json"], real=same))

    def test_sandbox_exec_denies_the_credentials_the_agent_sentinel_home_and_the_network(self):
        profile = sandbox_exec_profile(Settings(sandbox="sandbox-exec"), "/Users/me", "/Users/me/.agent-sentinel",
                                       ["/etc/agent/policy.json"], real=lambda path: path.replace("/etc/", "/private/etc/"))
        lines = profile.splitlines()
        self.assertEqual(lines[:3], ["(version 1)", "(allow default)", "(deny network*)"])
        self.assertIn('(deny file-read* file-write* (subpath "/Users/me/.ssh"))', lines)
        self.assertIn('(deny file-read* file-write* (subpath "/Users/me/Library/Application Support/Claude"))', lines)
        self.assertIn('(deny file-read* file-write* (subpath "/Users/me/.agent-sentinel"))', lines)
        self.assertIn('(deny file-write* (literal "/etc/agent/policy.json"))', lines)
        self.assertIn('(deny file-write* (literal "/private/etc/agent/policy.json"))', lines)
        self.assertEqual(len(lines), len(set(lines)))
        with_network = sandbox_exec_profile(Settings(sandbox="sandbox-exec", network=True), "/Users/me", None,
                                            real=lambda path: path)
        self.assertNotIn("network", with_network)
        with self.assertRaises(ContainmentError):
            sandbox_exec_profile(Settings(sandbox="sandbox-exec"), '/Users/a"b', None, real=lambda path: path)

    def test_sandbox_exec_denies_the_ways_to_start_a_program_outside_the_sandbox(self):
        # PB-6: open, osascript and launchctl have launchd start a program that is not sandboxed.
        lines = sandbox_exec_profile(Settings(sandbox="sandbox-exec"), "/Users/me", None, real=same).splitlines()
        for line in ("(deny lsopen)", "(deny appleevent-send)", "(deny job-creation)",
                     '(deny mach-lookup (global-name "com.apple.coreservices.launchservicesd") '
                     '(global-name "com.apple.coreservices.appleevents"))'):
            self.assertIn(line, lines)
        executions = next(line for line in lines if line.startswith("(deny process-exec"))
        for program in ("/usr/bin/open", "/usr/bin/osascript", "/bin/launchctl", "/usr/bin/crontab"):
            self.assertIn(f'(literal "{program}")', executions)
        # What runs later outside the sandbox may not be written: launch agents, shell startup files, cron.
        for path in ("/Users/me/Library/LaunchAgents", "/Users/me/.zshrc", "/Users/me/.gitconfig", "/private/var/at"):
            self.assertIn(f'(deny file-write* (subpath "{path}"))', lines)

    def test_sandbox_exec_keeps_the_folders_on_the_way_to_a_denied_place_from_being_renamed(self):
        # PB-7: renaming ~/.config would take ~/.config/gh out from under its denial; renaming a policy's
        # folder would let a new one take its place.
        lines = sandbox_exec_profile(Settings(sandbox="sandbox-exec"), "/Users/me", "/Users/me/x/.agent-sentinel",
                                     ["/Users/me/proj/policy.json"], real=same).splitlines()
        for folder in ("/Users/me/.config", "/Users/me/Library/Application Support", "/Users/me/Library",
                       "/Users/me/x", "/Users/me/proj", "/Users/me", "/Users"):
            self.assertIn(f'(deny file-write* (literal "{folder}"))', lines)
        self.assertNotIn('(deny file-write* (literal "/"))', lines)

    def test_sandbox_exec_denies_the_credentials_of_both_home_folders(self):
        lines = sandbox_exec_profile(Settings(sandbox="sandbox-exec"), ["/tmp/h", "/Users/me"], None,
                                     real=same).splitlines()
        self.assertIn('(deny file-read* file-write* (subpath "/tmp/h/.ssh"))', lines)
        self.assertIn('(deny file-read* file-write* (subpath "/Users/me/.ssh"))', lines)

    def test_sandbox_exec_hides_the_audit_key_file_wherever_it_is(self):
        # The audit key (--audit-key-file) signs the records: a sandboxed server may neither read nor replace it.
        # The control files stay readable, only their writing is denied.
        lines = sandbox_exec_profile(Settings(sandbox="sandbox-exec"), "/Users/me", None, ["/etc/as/policy.json"],
                                     real=same, secret_files=["/opt/keys/audit.key"]).splitlines()
        self.assertIn('(deny file-read* file-write* (subpath "/opt/keys/audit.key"))', lines)
        self.assertIn('(deny file-write* (literal "/opt/keys"))', lines)
        self.assertIn('(deny file-write* (literal "/etc/as/policy.json"))', lines)
        self.assertNotIn('(deny file-read* file-write* (subpath "/etc/as/policy.json"))', lines)
        self.assertEqual(len(lines), len(set(lines)))

    def test_bwrap_refuses_to_show_the_audit_key_file(self):
        exists, real = a_linux_host("/run")
        homes = ["/home/me"]

        def problem(key, **folders):
            return containment._secret_shown_problem(Settings(sandbox="bwrap", **folders), [key], homes,
                                                     "/srv/as/.agent-sentinel", exists=exists, real=real)

        # Hidden: in the emptied home folder, in /tmp, in the agent-sentinel home (hidden last, even inside a
        # folder the server may read).
        self.assertIsNone(problem("/home/me/.agent-sentinel/audit.key"))
        self.assertIsNone(problem("/home/me/keys/audit.key", read=("/home/me/tools",)))
        self.assertIsNone(problem("/tmp/audit.key"))
        self.assertIsNone(problem("/srv/as/.agent-sentinel/audit.key", read=("/srv/as",)))
        # Shown: inside a folder the server may read or write, or outside every hidden place.
        self.assertIn("the sandbox shows /home/me/proj, which holds the audit key file",
                      problem("/home/me/proj/audit.key", read=("/home/me/proj",)))
        self.assertIn("the sandbox shows /home/me/proj", problem("/home/me/proj/k/audit.key", allow=("/home/me/proj",)))
        self.assertIn("outside the folders the sandbox hides", problem("/etc/as/audit.key"))
        self.assertIsNone(containment._secret_shown_problem(Settings(sandbox="bwrap"), [], homes, None,
                                                            exists=exists, real=real))

    @unittest.skipUnless(sys.platform.startswith("linux"), "real paths of POSIX folders")
    def test_the_sandboxes_are_given_the_audit_key_file(self):
        with mock.patch.object(containment, "_homes", return_value=["/home/me"]), \
                mock.patch.object(containment, "_agent_home", return_value="/home/me/.agent-sentinel"):
            words = containment._sandbox_prefix(Settings(sandbox="sandbox-exec"), found, [], None,
                                                ["/opt/k/audit.key"])
            self.assertIn('(deny file-read* file-write* (subpath "/opt/k/audit.key"))', words[2])
            with self.assertRaises(ContainmentError) as caught:
                containment._sandbox_prefix(Settings(sandbox="bwrap"), found, [], None, ["/opt/k/audit.key"])
            self.assertIn("audit key file", str(caught.exception))

    @unittest.skipUnless(POSIX, "the home folders are POSIX paths")
    def test_the_home_folders_are_homes_and_the_accounts_own(self):
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as other:
            one, other = os.path.realpath(one), os.path.realpath(other)
            with mock.patch.dict(os.environ, {"HOME": one}), \
                    mock.patch.object(containment, "_account_home", return_value=other):
                self.assertEqual(containment._homes(), [one, other])
            with mock.patch.dict(os.environ, {"HOME": one}), \
                    mock.patch.object(containment, "_account_home", return_value="/"):
                self.assertEqual(containment._homes(), [one])
            with mock.patch.dict(os.environ, {"HOME": "/"}):
                self.assertIsNone(containment._homes())

    def test_describe_says_what_the_server_gets(self):
        self.assertIn("job object", containment.describe(Settings(contain=True), "win32"))
        # PB-4: cleanup, not containment of hostile code.
        self.assertIn("cleanup, not isolation", containment.describe(Settings(contain=True), "win32"))
        self.assertIn("cleanup, not isolation", containment.describe(Settings(contain=True), "linux"))
        self.assertNotIn("everything it starts", containment.describe(Settings(contain=True), "win32"))
        with mock.patch("sys.stdout", new_callable=io.StringIO) as shown:
            with self.assertRaises(SystemExit):
                mcp_proxy._argument_parser().parse_args(["--help"])
        self.assertIn("WMI", " ".join(shown.getvalue().split()))
        text = containment.describe(Settings(memory_mb=512, processes=4, cpu_seconds=60), "win32")
        self.assertIn("committed memory at most 512 MB per process", text)
        self.assertIn("at most 4 process(es)", text)
        posix = containment.describe(Settings(sandbox="bwrap"), "linux")
        self.assertIn("process group", posix)
        self.assertIn("sandboxed by bwrap, without network", posix)
        self.assertEqual(containment.describe(Settings(), "linux"), "none")

    def test_the_startup_summary_says_it(self):
        from agent_sentinel import proxy_report
        from support import POLICY
        start = proxy_report.Startup(version="x", name="files", policy_path="p.json", policy=POLICY, audit_path=None,
                                     pins_path=None, pins_enabled=True, server_command=["server"])
        self.assertFalse(any(line.startswith("  contain") for line in proxy_report.startup_lines(start)))
        import dataclasses
        contained = dataclasses.replace(start, containment="the server ends with the proxy")
        self.assertIn("  contain   the server ends with the proxy", proxy_report.startup_lines(contained))


class SettingUpWithoutAnything(unittest.TestCase):
    def test_no_containment_changes_nothing(self):
        contained = containment.prepare(Settings(), found)
        self.assertEqual(contained.command(["server", "x"]), ["server", "x"])
        self.assertEqual(contained.popen_options(), {})

    def test_what_cannot_work_is_refused_before_anything_starts(self):
        refused = Settings(sandbox="bwrap") if WINDOWS else Settings(processes=2)
        with self.assertRaises(ContainmentError):
            containment.prepare(refused, found)

    def test_an_error_nobody_planned_for_is_a_refusal_too(self):
        # ctypes raises OSError or AttributeError when the system lacks a call, or refuses one.
        for error in (OSError(1, "Operation not permitted"), AttributeError("function 'prctl' not found"),
                      ValueError("not allowed to raise maximum limit"), ImportError("No module named 'resource'")):
            with self.subTest(error=error), \
                    mock.patch.object(containment, "_WindowsJob", side_effect=error), \
                    mock.patch.object(containment, "_ProcessGroup", side_effect=error):
                with self.assertRaises(ContainmentError) as raised:
                    containment.prepare(Settings(contain=True), found)
                self.assertIn(f"this system refused a step of the set-up ({type(error).__name__}: ",
                              str(raised.exception))
                self.assertNotIn("\n", str(raised.exception))
        with mock.patch.object(containment, "check", side_effect=ValueError("embedded null byte")):
            with self.assertRaises(ContainmentError):
                containment.prepare(Settings(contain=True), found)


class TheAuditTrailOfContainment(unittest.TestCase):
    """What the proxy's audit records say about containment: session_start, and session_end when it fails.

    The proxy runs in this process up to the point where it would relay
    messages; containment.prepare is replaced, so nothing is contained here.
    """

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        self.audit = self.folder / "audit.jsonl"
        self.key = self.folder / "audit.key"
        self.key.write_bytes(b"k" * 32)
        if POSIX:
            self.key.chmod(0o600)

    def run_proxy(self, *options, prepare):
        stderr = io.StringIO()
        with mock.patch.object(containment, "prepare", prepare), mock.patch("sys.stderr", stderr):
            code = mcp_proxy.main(["--policy", str(EXAMPLE_POLICY_PATH), "--audit", str(self.audit),
                                   "--audit-key-file", str(self.key), *options, "--",
                                   sys.executable, "-c", "import sys; sys.stdin.read()"])
        return code, stderr.getvalue()

    def sessions(self):
        records = [json.loads(line) for line in self.audit.read_text(encoding="utf-8").splitlines()]
        return [record for record in records if record["event"] in ("session_start", "session_end")]

    def verified(self):
        from agent_sentinel import audit_chain
        report = audit_chain.check_files([str(self.audit)], key=self.key.read_bytes())
        return report.state, report.mac_mismatches

    def test_a_containment_that_cannot_be_set_up_is_recorded_and_the_key_file_is_kept_from_the_sandbox(self):
        asked = []

        def refuse(settings, find, control_files=(), server_executable=None, secret_files=(), numbered_files=()):
            asked.append((settings, list(control_files), list(secret_files)))
            raise ContainmentError("bwrap is not here")

        code, err = self.run_proxy("--sandbox", "bwrap", prepare=refuse)
        self.assertEqual(code, 2)
        self.assertIn("cannot contain the server as asked, so it is not started: bwrap is not here", err)
        (settings, control_files, secret_files), = asked
        self.assertEqual(settings.sandbox, "bwrap")
        self.assertIn(str(self.audit), control_files)
        self.assertEqual(secret_files, [str(self.key)])  # the key is a secret: a sandbox may not show it
        start, end = self.sessions()
        self.assertEqual((start["containment"], start["signed"]), ("sandboxed (bwrap)", True))
        self.assertEqual(end["reason"], "the server could not be contained as asked, so it was not started")
        self.assertEqual(self.verified(), ("intact", 0))

    def test_a_server_stopped_because_its_containment_failed_is_recorded_with_its_exit_code(self):
        class FailsAfterStart(containment.Containment):
            def after_start(self, server):
                raise ContainmentError("the limits job could not be applied")

        code, err = self.run_proxy("--contain", "--server-cpu-seconds", "60",
                                   prepare=lambda *args, **kwargs: FailsAfterStart())
        self.assertEqual(code, 2)
        self.assertIn("so it was stopped: the limits job could not be applied", err)
        start, end = self.sessions()
        self.assertEqual(start["containment"], "contained")
        self.assertEqual(end["reason"], "the server could not be contained as asked, so it was stopped")
        self.assertIsInstance(end["server_exit_code"], int)
        self.assertEqual(self.verified(), ("intact", 0))

    def test_a_containment_that_fails_in_an_unplanned_way_is_refused_in_plain_words_and_recorded(self):
        error = AttributeError("function 'prctl' not found")
        with mock.patch.object(containment, "_WindowsJob", side_effect=error), \
                mock.patch.object(containment, "_ProcessGroup", side_effect=error):
            code, err = self.run_proxy("--contain", prepare=containment.prepare)
        self.assertEqual(code, 2)
        self.assertIn("cannot contain the server as asked, so it is not started: this system refused a step of the "
                      "set-up (AttributeError: function 'prctl' not found)", err)
        self.assertNotIn("Traceback", err)
        start, end = self.sessions()
        self.assertEqual(end["reason"], "the server could not be contained as asked, so it was not started")

    def recording(self):
        """A containment that notes what the proxy asks of it, and the server it was given."""
        calls, servers = [], []

        class Recording(containment.Containment):
            def after_start(self, server):
                servers.append(server)
                calls.append("after_start")

            def sweep(self, server):
                calls.append("sweep" if server.poll() is not None else "sweep of a running server")

        return Recording(), calls, servers

    def stop_signals(self):
        return {name: signal.getsignal(getattr(signal, name))
                for name in ("SIGTERM", "SIGINT", "SIGBREAK", "SIGHUP", "SIGQUIT") if hasattr(signal, name)}

    def test_an_error_after_the_server_started_still_stops_it_sweeps_and_records_the_end(self):
        # Nothing between starting the server and the end of main may leave it running: with --contain on
        # Linux and macOS the sweep is the only thing that ends what the server started.
        contained, calls, servers = self.recording()
        before = self.stop_signals()
        with mock.patch.object(mcp_proxy, "Proxy", side_effect=RuntimeError("a bug in the proxy")):
            with self.assertRaisesRegex(RuntimeError, "a bug in the proxy"):
                self.run_proxy("--contain", prepare=lambda *args, **kwargs: contained)
        self.assertEqual(calls, ["after_start", "sweep"])
        self.assertIsNotNone(servers[0].poll())  # stopped, not left behind
        for stream in (servers[0].stdin, servers[0].stdout, servers[0].stderr):
            stream.close()
        start, end = self.sessions()
        self.assertEqual(end["reason"], "the proxy stopped on an error or an interrupt")
        self.assertIsInstance(end["server_exit_code"], int)
        self.assertEqual(self.verified(), ("intact", 0))
        self.assertEqual(self.stop_signals(), before)  # the caller's handlers are back

    def test_an_interrupt_after_the_server_started_does_the_same(self):
        # Ctrl+C where the handler could not be put in place (not the main thread) arrives as KeyboardInterrupt.
        contained, calls, servers = self.recording()
        with mock.patch.object(mcp_proxy, "Proxy", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_proxy("--contain", prepare=lambda *args, **kwargs: contained)
        self.assertEqual(calls, ["after_start", "sweep"])
        self.assertIsNotNone(servers[0].poll())
        for stream in (servers[0].stdin, servers[0].stdout, servers[0].stderr):
            stream.close()
        self.assertEqual([record["event"] for record in self.sessions()], ["session_start", "session_end"])

    def test_the_end_is_recorded_once_when_the_proxy_stops_the_server_itself(self):
        class FailsAfterStart(containment.Containment):
            def after_start(self, server):
                raise ContainmentError("the limits job could not be applied")

        before = self.stop_signals()
        code, _ = self.run_proxy("--contain", prepare=lambda *args, **kwargs: FailsAfterStart())
        self.assertEqual(code, 2)
        self.assertEqual([record["event"] for record in self.sessions()], ["session_start", "session_end"])
        self.assertEqual(self.stop_signals(), before)

    def test_session_start_says_what_containment_was_asked_for(self):
        from agent_sentinel import Firewall
        from support import POLICY
        args = mcp_proxy._argument_parser().parse_args(["--policy", "p.json", "--", "server"])
        for settings, expected in ((Settings(), "none"), (Settings(contain=True), "contained"),
                                   (Settings(memory_mb=64), "contained"),
                                   (Settings(sandbox="sandbox-exec"), "sandboxed (sandbox-exec)")):
            with self.subTest(expected=expected):
                details = mcp_proxy._session_details(Firewall(POLICY), args, ["server"], settings)
                self.assertEqual(details["containment"], expected)
        self.assertIsNone(containment.label(Settings()))


class TheProcessGroupSetup(unittest.TestCase):
    """--contain on Linux and macOS, with a stand-in for the resource module, so that it runs anywhere."""

    def fake_resource(self):
        calls = []
        limits = {"core": (1000, -1), "nofile": (1024, 1_048_576), "as": (-1, -1), "cpu": (-1, 30)}
        module = types.SimpleNamespace(
            RLIMIT_CORE="core", RLIMIT_NOFILE="nofile", RLIMIT_AS="as", RLIMIT_CPU="cpu", RLIM_INFINITY=-1,
            getrlimit=lambda which: limits[which], setrlimit=lambda which, values: calls.append((which, values)),
        )
        return module, calls

    def group(self, settings):
        module, calls = self.fake_resource()
        with mock.patch.dict(sys.modules, {"resource": module}), \
                mock.patch("threading.active_count", return_value=1), \
                mock.patch.object(containment, "_linux_prctl", return_value=None):
            contained = containment._ProcessGroup(settings, [])
            contained._prctl = None
            options = contained.popen_options()
            options["preexec_fn"]()
        return contained, options, dict(calls)

    def test_the_server_gets_a_group_of_its_own_and_its_limits(self):
        contained, options, limits = self.group(Settings(contain=True, memory_mb=256, cpu_seconds=60))
        self.assertTrue(options["start_new_session"])
        self.assertEqual(limits["core"], (0, 0))
        self.assertEqual(limits["nofile"], (1024, containment.SERVER_OPEN_FILES))  # the lower soft limit is kept
        self.assertEqual(limits["as"], (256 * 1024 * 1024, 256 * 1024 * 1024))
        self.assertEqual(limits["cpu"], (30, 30))  # a lower limit the proxy has is kept

    def test_without_a_memory_limit_virtual_memory_is_left_alone(self):
        _, _, limits = self.group(Settings(contain=True))
        self.assertNotIn("as", limits)
        self.assertNotIn("cpu", limits)

    def test_the_memory_limit_is_set_last_so_that_nothing_after_it_needs_memory(self):
        # The child is a copy of the proxy and may already use more than a small limit allows: the call
        # through ctypes, and every other limit, come before it.
        module, _ = self.fake_resource()
        order = []
        module.setrlimit = lambda which, values: order.append(which)

        def prctl(*arguments):
            order.append("prctl")
            return 0

        with mock.patch.dict(sys.modules, {"resource": module}), \
                mock.patch("threading.active_count", return_value=1), \
                mock.patch.object(containment, "_linux_prctl", return_value=prctl), \
                mock.patch.object(signal, "SIGKILL", 9, create=True), \
                mock.patch.object(os, "getppid", os.getpid), \
                mock.patch.object(os, "kill", side_effect=AssertionError("the child would have been killed")):
            contained = containment._ProcessGroup(Settings(contain=True, memory_mb=16, cpu_seconds=60), [])
            contained._prctl = prctl
            contained.popen_options()["preexec_fn"]()
        self.assertEqual(order, ["prctl", "core", "nofile", "cpu", "as"])

    def test_it_refuses_when_threads_are_running(self):
        module, _ = self.fake_resource()
        with mock.patch.dict(sys.modules, {"resource": module}), mock.patch("threading.active_count", return_value=3):
            with self.assertRaises(ContainmentError):
                containment._ProcessGroup(Settings(contain=True), [])

    def test_the_sweep_ends_what_is_left_of_the_group(self):
        contained, _, _ = self.group(Settings(contain=True))
        sent = []

        def killpg(group, signal_number):
            sent.append((group, signal_number))
            if signal_number == 0:
                raise ProcessLookupError

        with mock.patch.object(os, "killpg", killpg, create=True):
            contained.sweep(types.SimpleNamespace(pid=4242))
        self.assertEqual(sent, [(4242, signal.SIGTERM), (4242, 0)])

    def test_a_sandbox_goes_in_front_of_the_server(self):
        module, _ = self.fake_resource()
        with mock.patch.dict(sys.modules, {"resource": module}), mock.patch("threading.active_count", return_value=1):
            contained = containment._ProcessGroup(Settings(sandbox="bwrap"), ["/usr/bin/bwrap", "--x", "--"])
        self.assertEqual(contained.command(["node", "s.js"]), ["/usr/bin/bwrap", "--x", "--", "node", "s.js"])


class TheWindowsLimitsJob(unittest.TestCase):
    """--server-memory-mb and the other limits on Windows, with a stand-in for kernel32, so that it runs anywhere."""

    def job(self, assigned=True, opened=True, in_job=True, error=None):
        closed = []

        def is_in_job(process, job, found):
            found._obj.value = int(in_job)
            return 1

        def assign(job, process):
            if error is not None:
                raise error
            return int(assigned)

        kernel32 = types.SimpleNamespace(
            OpenProcess=lambda access, inherit, pid: 5 if opened else 0, IsProcessInJob=is_in_job,
            CreateJobObjectW=lambda security, name: 7, SetInformationJobObject=lambda *arguments: 1,
            AssignProcessToJobObject=assign, CloseHandle=closed.append, TerminateJobObject=lambda job, code: 1,
        )
        job = object.__new__(containment._WindowsJob)
        job._settings, job._kernel32, job._outer, job._inner = Settings(processes=4), kernel32, 11, None
        return job, closed

    def server(self, exit_code):
        return types.SimpleNamespace(pid=4242, poll=lambda: exit_code)

    def test_a_server_that_cannot_be_put_into_its_job_is_refused_while_it_runs(self):
        with mock.patch.object(containment, "_last_error", return_value="Access is denied. (error 5)"):
            for options, words in (({"assigned": False}, "cannot put the server into the job object of its limits: "
                                                         "Access is denied. (error 5)"),
                                   ({"opened": False}, "cannot open the server's process"),
                                   ({"in_job": False}, "the server did not start inside the proxy's job object")):
                with self.subTest(options=options):
                    job, closed = self.job(**options)
                    with self.assertRaises(ContainmentError) as raised:
                        job.after_start(self.server(None))
                    self.assertIn(words, str(raised.exception))
                    self.assertEqual(closed, [5] if options != {"opened": False} else [])

    def test_a_server_that_has_already_ended_is_not_an_error(self):
        # A command that fails at once: Windows says "Access is denied" for a process that is gone. The proxy
        # goes on, and passes on the server's own output and exit code.
        with mock.patch.object(containment, "_last_error", return_value="Access is denied. (error 5)"):
            for options in ({"assigned": False}, {"opened": False}, {"in_job": False}, {"error": OSError(5, "x")}):
                with self.subTest(options=options):
                    job, _ = self.job(**options)
                    job.after_start(self.server(1))

    def test_an_error_nobody_planned_for_is_a_refusal_in_plain_words(self):
        job, closed = self.job(error=OSError(22, "exception: access violation"))
        with self.assertRaisesRegex(ContainmentError, r"this system refused a step of the set-up \(OSError: "):
            job.after_start(self.server(None))
        self.assertEqual(closed, [5])

    def test_a_running_server_gets_its_job(self):
        job, closed = self.job()
        job.after_start(self.server(None))
        self.assertEqual((job._inner, closed), (7, [5]))

    @unittest.skipUnless(WINDOWS, "job objects are a Windows matter")
    def test_on_windows_the_limits_of_a_server_that_has_already_ended_are_passed_over(self):
        # In a process of its own: setting up containment puts the calling process into a job for good.
        code = (
            "import subprocess, sys\n"
            "from agent_sentinel import containment\n"
            "contained = containment.prepare(containment.Settings(processes=4), lambda name: None)\n"
            "server = subprocess.Popen([sys.executable, '-c', 'raise SystemExit(7)'], **contained.popen_options())\n"
            "server.wait()\n"
            "contained.after_start(server)\n"
            "contained.sweep(server)\n"
            "print('passed over, exit code', server.returncode)\n"
        )
        done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120,
                              env=dict(os.environ, PYTHONPATH=str(ROOT)))
        self.assertEqual((done.returncode, done.stdout.strip()), (0, "passed over, exit code 7"), done.stderr)


class TheStopSignals(unittest.TestCase):
    """Which signals the proxy takes as "stop", with a stand-in for the signal module, so that it runs anywhere."""

    def signals(self, ignored=(), not_from_python=(), fails=(), names=("SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT")):
        handlers = {}
        numbers = {name: number for number, name in enumerate(names, start=1)}

        def get(number):
            name = names[number - 1]
            if number in handlers:
                return handlers[number]
            return "ignore" if name in ignored else None if name in not_from_python else f"default of {name}"

        def set_handler(number, handler):
            if names[number - 1] in fails:
                raise ValueError("signal only works in main thread of the main interpreter")
            handlers[number] = handler

        module = types.SimpleNamespace(SIG_IGN="ignore", SIG_DFL="default", getsignal=get, signal=set_handler,
                                       **numbers)
        return module, handlers, numbers

    def test_every_signal_that_would_end_the_proxy_asks_it_to_stop_instead(self):
        module, handlers, numbers = self.signals()
        with mock.patch.object(mcp_proxy, "signal", module):
            under_way = mcp_proxy._Started()
            under_way.stop_on_signals()
            self.assertEqual(set(handlers), set(numbers.values()))  # Ctrl+C, a hangup and Ctrl+\ as well as SIGTERM
            self.assertFalse(under_way.stop_asked())
            handlers[numbers["SIGHUP"]](numbers["SIGHUP"], None)
            self.assertTrue(under_way.stop_asked())
            under_way.restore_signals()
        self.assertEqual(handlers, {number: f"default of {name}" for name, number in numbers.items()})

    def test_each_of_them_alone_is_enough(self):
        for name in ("SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT"):
            module, handlers, numbers = self.signals()
            with self.subTest(name=name), mock.patch.object(mcp_proxy, "signal", module):
                under_way = mcp_proxy._Started()
                under_way.stop_on_signals()
                handlers[numbers[name]](numbers[name], None)
                self.assertTrue(under_way.stop_asked())

    def test_a_signal_that_was_being_ignored_stays_ignored_except_sigterm(self):
        # nohup, or a background job of a shell without job control: the starter chose that.
        module, handlers, numbers = self.signals(ignored=("SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT"))
        with mock.patch.object(mcp_proxy, "signal", module):
            under_way = mcp_proxy._Started()
            under_way.stop_on_signals()
        self.assertEqual(set(handlers), {numbers["SIGTERM"]})

    def test_signals_this_system_lacks_or_refuses_are_passed_over(self):
        module, handlers, numbers = self.signals(names=("SIGTERM", "SIGBREAK", "SIGINT"), fails=("SIGINT",),
                                                 not_from_python=("SIGBREAK",))
        with mock.patch.object(mcp_proxy, "signal", module):
            under_way = mcp_proxy._Started()
            under_way.stop_on_signals()  # Windows: no SIGHUP, no SIGQUIT
            self.assertEqual(set(handlers), {numbers["SIGTERM"], numbers["SIGBREAK"]})
            kept = handlers[numbers["SIGBREAK"]]
            under_way.restore_signals()
        self.assertEqual(handlers[numbers["SIGTERM"]], "default of SIGTERM")
        self.assertIs(handlers[numbers["SIGBREAK"]], kept)  # set by something other than Python: left as it is

    def test_abandoning_ends_the_server_sweeps_and_records_even_when_a_step_fails(self):
        done = []
        server = types.SimpleNamespace(pid=1)
        contained = types.SimpleNamespace(sweep=lambda given: done.append("sweep"))
        firewall = types.SimpleNamespace(provenance=lambda event, reason, details: done.append((event, details)))
        under_way = mcp_proxy._Started()
        under_way.abandon()  # nothing was started: nothing to do
        under_way.running(server, contained, firewall)
        with mock.patch.object(mcp_proxy, "_stop", side_effect=KeyboardInterrupt):  # a second Ctrl+C
            under_way.abandon()
        self.assertEqual(done, ["sweep", ("session_end", {"server_exit_code": None})])
        under_way.abandon()  # once only
        self.assertEqual(len(done), 2)
        failing = types.SimpleNamespace(sweep=mock.Mock(side_effect=OSError("gone")))
        under_way.running(server, failing, firewall)
        with mock.patch.object(mcp_proxy, "_stop", return_value=3):
            under_way.abandon()
        self.assertEqual(done[-1], ("session_end", {"server_exit_code": 3}))


# ---- wrap and doctor ---------------------------------------------------------------------------------------

class WrapAndDoctor(DoctorTest):
    def test_wrap_writes_contain_and_the_entry_stays_protected(self):
        root = "C:\\sentinel" if WINDOWS else "/sentinel"
        settings = ProxySettings(python=os.path.join(root, "python.exe"), policy=os.path.join(root, "p.json"),
                                 audit=os.path.join(root, "a.jsonl"), pins_folder=os.path.join(root, "pins"),
                                 contain=True)
        new = wrap_entry({"command": "npx", "args": ["-y", "pkg@1.0.0"]}, settings, "files", "PINS")
        self.assertEqual(new["args"][-5:], ["--contain", "--", "npx", "-y", "pkg@1.0.0"])
        self.assertTrue(read_proxy_command([new["command"], *new["args"]]).has("--contain"))
        self.assertEqual(status_of(new), "protected")

    def test_doctor_reports_a_contained_server_and_keeps_it_protected(self):
        path = self.config({"kept": self.wrapped("kept", "--contain", "--server-memory-mb", "512"),
                            "plain": self.wrapped("plain")})
        code, servers, _ = self.statuses(path)
        self.assertEqual(code, 0)
        self.assertEqual(servers["kept"]["status"], "protected")
        self.assertEqual(servers["kept"]["containment"], "contained")
        self.assertIsNone(servers["plain"]["containment"])
        texts = [finding["text"] for finding in servers["kept"]["findings"]]
        self.assertTrue(any(text.startswith("contained: ") and "512 MB" in text for text in texts), texts)
        self.assertFalse(any("not one this version knows" in text for text in texts))

    def test_doctor_calls_an_entry_broken_when_its_containment_cannot_work(self):
        path = self.config({"orphan": self.wrapped("orphan", "--sandbox-network"),
                            "small": self.wrapped("small", "--server-memory-mb", "1")})
        code, servers, _ = self.statuses(path)
        self.assertEqual(code, 1)
        self.assertEqual(servers["orphan"]["status"], "broken")
        self.assertTrue(any("need --sandbox" in finding["text"] for finding in servers["orphan"]["findings"]))
        self.assertEqual(servers["small"]["status"], "broken")
        self.assertTrue(any("--server-memory-mb '1'" in finding["text"] for finding in servers["small"]["findings"]))

    def test_doctor_knows_the_audit_options_beside_the_containment_ones(self):
        # The audit lane's proxy options, checked by the proxy's own parser, and the --audit they need.
        key = self.home / "audit.key"
        path = self.config({
            "both": self.wrapped("both", "--contain", "--audit-key-file", str(key), "--audit-required",
                                 "--audit-max-bytes", "65536"),
            "small": self.wrapped("small", "--audit-max-bytes", "10"),
            "nolog": self.wrapped("nolog", "--audit-required", "--audit-key-file", str(key), audit=""),
        })
        code, servers, _ = self.statuses(path)
        self.assertEqual(code, 1)
        self.assertEqual((servers["both"]["status"], servers["both"]["containment"]), ("protected", "contained"))
        texts = [finding["text"] for finding in servers["both"]["findings"]]
        self.assertFalse(any("not one this version knows" in text for text in texts), texts)
        self.assertEqual(servers["small"]["status"], "broken")
        self.assertTrue(any("--audit-max-bytes '10'" in finding["text"] for finding in servers["small"]["findings"]))
        self.assertEqual(servers["nolog"]["status"], "broken")
        self.assertTrue(any("--audit-key-file, --audit-required without --audit" in finding["text"]
                            for finding in servers["nolog"]["findings"]))

    def test_doctor_warns_of_an_audit_key_file_inside_the_project(self):
        key = self.project / "keys" / "audit.key"
        path = self.write("project/.mcp.json", {"mcpServers": {"s": self.wrapped("s", "--audit-key-file", str(key))}})
        code, out, _ = self.doctor(path)
        self.assertIn("the audit key file is inside the project folder", out)

    def test_the_wrap_command_takes_contain(self):
        from cli_support import run_cli
        from agent_sentinel import __version__
        from agent_sentinel.wrapping import PythonCheck
        with mock.patch("agent_sentinel.cli_wrap.check_python", return_value=PythonCheck(True, __version__)):
            code, out, err = run_cli("wrap", "--client", "codex", "--policy", self.policy, "--name", "files",
                                     "--contain", "--", "npx", "-y", "pkg@1.0.0")
        self.assertEqual(code, 0, err)
        self.assertIn("--contain", out)


# ---- the real proxy ----------------------------------------------------------------------------------------

# A server that starts a grandchild that sleeps (its stdio closed, so that it holds no pipe of the proxy's),
# writes "<its pid> <the grandchild's pid>", then answers every request with what it can see of its limits.
TREE_SERVER = r'''
import json, os, subprocess, sys
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(90)"],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
with open(sys.argv[1], "w") as pids:
    pids.write(f"{os.getpid()} {child.pid}")
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    seen = {}
    if os.name == "posix":
        import resource
        seen = {"core": list(resource.getrlimit(resource.RLIMIT_CORE)),
                "files": list(resource.getrlimit(resource.RLIMIT_NOFILE)),
                "own_group": os.getpgid(0) == os.getpid()}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": seen}) + "\n")
    sys.stdout.flush()
'''

# A server that answers each request by trying what --server-memory-mb and --server-processes refuse.
LIMITS_SERVER = r'''
import json, subprocess, sys
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    result = {}
    try:
        block = bytearray(300 * 1024 * 1024)
        result["memory"] = "allocated"
        del block
    except MemoryError:
        result["memory"] = "refused"
    try:
        child = subprocess.run([sys.executable, "-c", "print('ran')"], capture_output=True, timeout=30)
        result["child"] = child.stdout.decode().strip()
    except OSError:
        result["child"] = "refused"
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}) + "\n")
    sys.stdout.flush()
'''

# A server that writes its pid and then uses the CPU, or sleeps, whatever happens to its input.
STUBBORN_SERVER = r'''
import os, sys, time
with open(sys.argv[1], "w") as pid:
    pid.write(str(os.getpid()))
deadline = time.time() + 60
while time.time() < deadline:
    if sys.argv[2] == "busy":
        sum(range(10000))
    else:
        time.sleep(0.2)
'''

# A server that writes its pid and then sleeps, whatever happens to its input and whatever Ctrl+C or
# Ctrl+Break its console sends: only the proxy ends it.
DEAF_SERVER = r'''
import os, signal, sys, time
for name in ("SIGINT", "SIGBREAK"):
    if hasattr(signal, name):
        signal.signal(getattr(signal, name), signal.SIG_IGN)
with open(sys.argv[1], "w") as pid:
    pid.write(str(os.getpid()))
time.sleep(90)
'''

# A server that answers a request with what it could and could not do inside a sandbox.
SANDBOX_SERVER = r'''
import json, os, sys
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    result = {}
    for name, path in (("credential", os.path.join(os.environ["HOME"], ".ssh", "id_rsa")),
                       ("agent_home", os.path.join(os.environ["AGENT_SENTINEL_HOME"], "policy.json"))):
        try:
            open(path).read()
            result[name] = "read"
        except OSError:
            result[name] = "hidden"
    try:
        with open(os.path.join(sys.argv[1], "written.txt"), "w") as out:
            out.write("x")
        result["allowed"] = "written"
    except OSError:
        result["allowed"] = "refused"
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}) + "\n")
    sys.stdout.flush()
'''


# The proxy's main() in a process of its own, with a containment that notes what is asked of it and, once the
# server runs, does to the main thread what Ctrl+C does. argv: the file for the notes, then the proxy's arguments.
INTERRUPTED_PROXY = r'''
import sys, threading, _thread
from agent_sentinel import containment, mcp_proxy
notes = sys.argv[1]

def note(text):
    with open(notes, "a") as out:
        out.write(text + "\n")

class Recording(containment.Containment):
    def after_start(self, server):
        note("after_start")
        threading.Timer(1.0, _thread.interrupt_main).start()

    def sweep(self, server):
        note("sweep")

containment.prepare = lambda *args, **kwargs: Recording()
try:
    code = mcp_proxy.main(sys.argv[2:])
    note("returned")
except BaseException as error:
    note("raised " + type(error).__name__)
    code = 99
mcp_proxy.exit_process(code)
'''


def default_signals():
    """In a proxy the test starts (POSIX): the stop signals as a terminal's foreground process has them,
    whatever the process that runs the tests inherited."""
    for name in ("SIGINT", "SIGHUP", "SIGQUIT", "SIGTERM"):
        signal.signal(getattr(signal, name), signal.SIG_DFL)


def ignored_hangup():
    """In a proxy the test starts (POSIX): SIGHUP ignored, as nohup leaves it."""
    signal.signal(signal.SIGHUP, signal.SIG_IGN)


def alive(pid):
    """Whether a process is running (a zombie is not), without signalling it."""
    if WINDOWS:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if not handle:
            return False
        try:
            return kernel32.WaitForSingleObject(handle, 0) == 0x102  # WAIT_TIMEOUT: still running
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    status = Path(f"/proc/{pid}/status")
    if status.exists():
        try:
            return "\tZ" not in status.read_text().split("State:", 1)[1].splitlines()[0]
        except (OSError, IndexError):
            return False
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout
    return bool(state.strip()) and "Z" not in state


def kill(pid):
    """Stop a process the test started, if it is still there."""
    if not alive(pid):
        return
    if WINDOWS:
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def wait_until(condition, seconds=10.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.1)
    return condition()


class TheRealProxy(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(self.remove_folder)
        self.environment = dict(os.environ, PYTHONPATH=str(ROOT))
        self.environment.pop("AGENT_SENTINEL_HOME", None)

    def remove_folder(self):
        import shutil
        for _ in range(50):
            shutil.rmtree(self.folder, ignore_errors=True)
            if not self.folder.exists():
                return
            time.sleep(0.1)

    def server(self, name, source):
        path = self.folder / name
        path.write_text(source, encoding="utf-8")
        return path

    def start(self, proxy_args, server, *server_args, environment=None, **popen_options):
        proxy = subprocess.Popen(
            [sys.executable, "-m", "agent_sentinel", "proxy", "--policy", str(EXAMPLE_POLICY_PATH), "--quiet",
             *map(str, proxy_args), "--", sys.executable, str(server), *map(str, server_args)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.folder,
            env=environment or self.environment, **popen_options,
        )
        self.addCleanup(self.stop, proxy)
        return proxy

    @staticmethod
    def stop(proxy):
        if proxy.poll() is None:
            proxy.kill()
        proxy.communicate(timeout=30)

    def pids(self, path):
        self.assertTrue(wait_until(lambda: path.exists() and path.read_text().strip()), "the server never started")
        return [int(word) for word in path.read_text().split()]

    def ask(self, proxy):
        proxy.stdin.write(b'{"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}}\n')
        proxy.stdin.flush()
        return json.loads(proxy.stdout.readline())["result"]

    def test_what_cannot_be_contained_here_is_refused_before_the_server_starts(self):
        marker = self.folder / "started"
        server = self.server("marker.py", f"open({str(marker)!r}, 'w').close()\n")
        refused = ["--sandbox", "bwrap"] if WINDOWS else ["--server-processes", "2"]
        proc = subprocess.run(
            [sys.executable, "-m", "agent_sentinel", "proxy", "--policy", str(EXAMPLE_POLICY_PATH), *refused,
             "--", sys.executable, str(server)], capture_output=True, cwd=self.folder, env=self.environment, timeout=60,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"cannot contain the server as asked, so it is not started", proc.stderr)
        self.assertFalse(marker.exists())

    def test_a_refused_containment_is_in_the_audit_log_between_session_start_and_session_end(self):
        marker = self.folder / "started"
        server = self.server("marker.py", f"open({str(marker)!r}, 'w').close()\n")
        audit = self.folder / "audit.jsonl"
        refused, asked = (["--sandbox", "bwrap"], "sandboxed (bwrap)") if WINDOWS else (["--server-processes", "2"],
                                                                                         "contained")
        proc = subprocess.run(
            [sys.executable, "-m", "agent_sentinel", "proxy", "--policy", str(EXAMPLE_POLICY_PATH), "--audit", str(audit),
             "--audit-required", *refused, "--", sys.executable, str(server)],
            capture_output=True, cwd=self.folder, env=self.environment, timeout=60,
        )
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertFalse(marker.exists())
        records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([record["event"] for record in records], ["chain_start", "session_start", "session_end"])
        self.assertEqual(records[1]["containment"], asked)
        self.assertEqual(records[2]["reason"], "the server could not be contained as asked, so it was not started")

    @unittest.skipUnless(WINDOWS, "job objects are a Windows matter")
    def test_on_windows_an_orphaned_grandchild_ends_with_the_proxy_only_when_contained(self):
        server = self.server("tree.py", TREE_SERVER)
        for contain in (False, True):
            with self.subTest(contain=contain):
                pid_file = self.folder / f"pids-{contain}.txt"
                proxy = self.start(["--contain"] if contain else [], server, pid_file)
                server_pid, grandchild = self.pids(pid_file)
                self.addCleanup(kill, grandchild)
                self.addCleanup(kill, server_pid)
                proxy.kill()  # the hardest way to go: no chance to stop anything
                proxy.wait(timeout=30)
                self.assertTrue(wait_until(lambda: not alive(server_pid)))
                if contain:
                    self.assertTrue(wait_until(lambda: not alive(grandchild)), "the grandchild outlived the proxy")
                else:
                    time.sleep(1)
                    self.assertTrue(alive(grandchild))  # what --contain is for

    @unittest.skipUnless(WINDOWS, "job objects are a Windows matter")
    def test_on_windows_the_memory_and_process_limits_hold_for_the_server_alone(self):
        server = self.server("limits.py", LIMITS_SERVER)
        limited = self.start(["--server-memory-mb", "128", "--server-processes", "1"], server)
        self.assertEqual(self.ask(limited), {"memory": "refused", "child": "refused"})
        roomy = self.start(["--contain", "--server-memory-mb", "2048", "--server-processes", "3"], server)
        self.assertEqual(self.ask(roomy), {"memory": "allocated", "child": "ran"})

    @unittest.skipUnless(WINDOWS, "job objects are a Windows matter")
    def test_on_windows_the_cpu_limit_ends_a_busy_server(self):
        pid_file = self.folder / "pid.txt"
        server = self.server("busy.py", STUBBORN_SERVER)
        started = time.monotonic()
        proxy = self.start(["--server-cpu-seconds", "1"], server, pid_file, "busy")
        (server_pid,) = self.pids(pid_file)
        self.addCleanup(kill, server_pid)
        proxy.wait(timeout=45)  # the server's end closes its output, and the proxy stops
        self.assertLess(time.monotonic() - started, 40)
        self.assertFalse(alive(server_pid))

    @unittest.skipUnless(POSIX, "process groups and resource limits are a POSIX matter")
    def test_on_posix_the_server_has_its_own_group_and_limits_and_the_group_ends_with_the_proxy(self):
        pid_file = self.folder / "pids.txt"
        proxy = self.start(["--contain"], self.server("tree.py", TREE_SERVER), pid_file)
        server_pid, grandchild = self.pids(pid_file)
        self.addCleanup(kill, grandchild)
        self.addCleanup(kill, server_pid)
        seen = self.ask(proxy)
        self.assertEqual(seen["core"], [0, 0])
        self.assertLessEqual(seen["files"][1], containment.SERVER_OPEN_FILES)
        self.assertTrue(seen["own_group"])
        proxy.stdin.close()  # the client goes away: the proxy stops the server, then sweeps its group
        proxy.wait(timeout=30)
        self.assertTrue(wait_until(lambda: not alive(grandchild)), "the grandchild outlived the proxy")

    def test_an_interrupt_stops_the_server_sweeps_and_records_the_end(self):
        # What Ctrl+C does to the proxy's main thread, in a process of its own: the proxy must shut down as
        # it does when a side closes. The server here never ends by itself, whatever happens to its input.
        pid_file, audit, calls = self.folder / "pid.txt", self.folder / "audit.jsonl", self.folder / "calls.txt"
        server = self.server("stubborn.py", STUBBORN_SERVER)
        runner = self.server("runner.py", INTERRUPTED_PROXY)
        done = subprocess.run(
            [sys.executable, str(runner), str(calls), "--policy", str(EXAMPLE_POLICY_PATH), "--quiet", "--audit",
             str(audit), "--contain", "--", sys.executable, str(server), str(pid_file), "sleep"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.folder,
            env=self.environment, timeout=120,
        )
        (server_pid,) = self.pids(pid_file)
        self.addCleanup(kill, server_pid)
        self.assertNotIn(b"Traceback", done.stderr)
        self.assertNotIn(b"KeyboardInterrupt", done.stderr)
        noted = calls.read_text().split()
        self.assertEqual(noted[:2], ["after_start", "sweep"], done.stderr)
        self.assertEqual(noted[2], "returned")  # main came back with the server's exit code
        self.assertTrue(wait_until(lambda: not alive(server_pid)), "the server outlived the proxy")
        records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([record["event"] for record in records][-2:], ["session_start", "session_end"])
        self.assertEqual(records[-1]["reason"], "the proxy stopped")

    @unittest.skipUnless(WINDOWS, "Ctrl+Break is a Windows matter")
    def test_on_windows_ctrl_break_stops_the_server_and_records_the_end(self):
        pid_file, audit = self.folder / "pid.txt", self.folder / "audit.jsonl"
        proxy = self.start(["--contain", "--audit", audit], self.server("deaf.py", DEAF_SERVER), pid_file,
                           creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        (server_pid,) = self.pids(pid_file)
        self.addCleanup(kill, server_pid)
        time.sleep(0.5)  # the server ignores the signal by now, and the proxy is relaying
        try:
            proxy.send_signal(signal.CTRL_BREAK_EVENT)
        except OSError:
            self.skipTest("this process has no console to send Ctrl+Break through")
        proxy.wait(timeout=30)
        self.assertTrue(wait_until(lambda: not alive(server_pid)), "the server outlived the proxy")
        records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
        self.assertEqual((records[-1]["event"], records[-1]["reason"]), ("session_end", "the proxy stopped"))

    @unittest.skipUnless(POSIX, "these signals, and a session of the server's own, are a POSIX matter")
    def test_on_posix_every_signal_that_stops_the_proxy_ends_the_servers_group_too(self):
        # Under --contain the server has a session of its own, so the terminal's Ctrl+C or hangup reaches the
        # proxy alone: the proxy must stop the server and sweep its group itself.
        server = self.server("tree.py", TREE_SERVER)
        for name in ("SIGINT", "SIGHUP", "SIGQUIT", "SIGTERM"):
            with self.subTest(signal=name):
                pid_file, audit = self.folder / f"pids-{name}.txt", self.folder / f"audit-{name}.jsonl"
                proxy = self.start(["--contain", "--audit", audit], server, pid_file, preexec_fn=default_signals)
                server_pid, grandchild = self.pids(pid_file)
                self.addCleanup(kill, grandchild)
                self.addCleanup(kill, server_pid)
                self.assertTrue(self.ask(proxy)["own_group"])  # the proxy is relaying: its handlers are in place
                proxy.send_signal(getattr(signal, name))
                self.assertIsNotNone(proxy.wait(timeout=30))
                self.assertGreaterEqual(proxy.returncode, 0, "the signal ended the proxy before it could clean up")
                self.assertTrue(wait_until(lambda: not alive(server_pid)), "the server outlived the proxy")
                self.assertTrue(wait_until(lambda: not alive(grandchild)), "the grandchild outlived the proxy")
                events = [json.loads(line)["event"] for line in audit.read_text(encoding="utf-8").splitlines()]
                self.assertEqual(events[-1], "session_end")

    @unittest.skipUnless(POSIX, "these signals are a POSIX matter")
    def test_on_posix_a_hangup_that_was_being_ignored_stays_ignored(self):
        # nohup: the proxy must not stop on a signal that whoever started it chose to ignore.
        pid_file = self.folder / "pids.txt"
        proxy = self.start(["--contain"], self.server("tree.py", TREE_SERVER), pid_file, preexec_fn=ignored_hangup)
        server_pid, grandchild = self.pids(pid_file)
        self.addCleanup(kill, grandchild)
        self.addCleanup(kill, server_pid)
        self.assertTrue(self.ask(proxy)["own_group"])
        proxy.send_signal(signal.SIGHUP)
        time.sleep(1.0)
        self.assertIsNone(proxy.poll())
        self.assertTrue(self.ask(proxy)["own_group"])  # still relaying
        proxy.stdin.close()
        proxy.wait(timeout=30)
        self.assertTrue(wait_until(lambda: not alive(grandchild)), "the grandchild outlived the proxy")

    @unittest.skipUnless(sys.platform.startswith("linux"), "PR_SET_PDEATHSIG is a Linux matter")
    def test_on_linux_the_server_dies_with_a_killed_proxy(self):
        pid_file = self.folder / "pid.txt"
        proxy = self.start(["--contain"], self.server("stubborn.py", STUBBORN_SERVER), pid_file, "sleep")
        (server_pid,) = self.pids(pid_file)
        self.addCleanup(kill, server_pid)
        proxy.kill()
        proxy.wait(timeout=30)
        self.assertTrue(wait_until(lambda: not alive(server_pid)), "the server outlived the proxy")

    @unittest.skipUnless(sys.platform.startswith("linux") and mcp_proxy._resolve_executable("bwrap"),
                         "bubblewrap is a Linux tool, and is not installed here")
    def test_on_linux_bwrap_hides_the_home_folder_and_shows_what_is_allowed(self):
        probe = subprocess.run([mcp_proxy._resolve_executable("bwrap"), "--unshare-all", "--die-with-parent",
                                "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "true"], capture_output=True)
        if probe.returncode != 0:
            self.skipTest("bubblewrap cannot make a sandbox here (user namespaces may be off)")
        home = self.folder / "home"
        (home / ".ssh").mkdir(parents=True)
        (home / ".ssh" / "id_rsa").write_text("not a real key")
        agent_home = self.folder / ".agent-sentinel"
        agent_home.mkdir()
        (agent_home / "policy.json").write_text("{}")
        allowed = self.folder / "allowed"
        allowed.mkdir()
        code = self.folder / "code"
        code.mkdir()
        server = code / "sandboxed.py"
        server.write_text(SANDBOX_SERVER, encoding="utf-8")
        environment = dict(self.environment, HOME=str(home), AGENT_SENTINEL_HOME=str(agent_home))
        # The sandbox empties the account's own home folder as well as HOME's: a Python kept there is shown.
        account_home = containment._account_home()
        python = [] if not account_home else [
            ["--sandbox-read", folder] for folder in dict.fromkeys(
                os.path.realpath(folder) for folder in (sys.base_prefix, sys.prefix, os.path.dirname(sys.executable)))
            if containment._within(folder, os.path.realpath(account_home))]
        proxy = self.start(["--sandbox", "bwrap", "--sandbox-allow", allowed, "--sandbox-read", code,
                            *[word for words in python for word in words]], server, allowed, environment=environment)
        self.assertEqual(self.ask(proxy), {"credential": "hidden", "agent_home": "hidden", "allowed": "written"})
        self.assertTrue((allowed / "written.txt").exists())


if __name__ == "__main__":
    unittest.main()
