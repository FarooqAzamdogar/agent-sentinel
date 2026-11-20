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
            self.assertIn("does not exist", problem(os.path.join(home, "nope")))
            self.assertIn("not a full path", problem("work"))


class TheSandboxesWords(unittest.TestCase):
    HOME = "/home/me"

    def test_bwrap_shows_the_file_system_read_only_and_hides_the_home_folder(self):
        settings = Settings(sandbox="bwrap", allow=("/home/me/work",), read=("/home/me/work/docs", "/home/me/.nvm"))
        words = bwrap_arguments(settings, self.HOME, "/home/me/.agent-sentinel",
                                ["/home/me/work/policy.json", "/etc/policy.json", "/home/me/.agent-sentinel/p.json"],
                                exists=lambda path: True)
        self.assertEqual(words[:12], ["--unshare-all", "--die-with-parent", "--new-session", "--ro-bind", "/", "/",
                                      "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"])
        self.assertNotIn("--share-net", words)
        text = " ".join(words)
        # Later mounts cover earlier ones: the home folder is emptied, then the folders are shown, shorter
        # paths first (so docs inside work stays read-only), then the agent-sentinel home is hidden again,
        # and a policy inside a writable folder is made read-only again.
        order = ["--tmpfs /run/user", "--tmpfs /home/me ", "--bind /home/me/work /home/me/work",
                 "--ro-bind /home/me/work/docs /home/me/work/docs", "--tmpfs /home/me/.agent-sentinel",
                 "--ro-bind /home/me/work/policy.json /home/me/work/policy.json"]
        positions = [text.index(part) for part in order]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("--ro-bind /home/me/.nvm /home/me/.nvm", text)
        self.assertNotIn("/etc/policy.json", text)  # read-only already, under the read-only /
        self.assertNotIn("p.json", text)  # hidden with the agent-sentinel home
        self.assertIn("--share-net", bwrap_arguments(Settings(sandbox="bwrap", network=True), self.HOME, None))
        self.assertNotIn("/run/user", bwrap_arguments(Settings(sandbox="bwrap"), self.HOME, None, exists=lambda p: False))

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
        with_network = sandbox_exec_profile(Settings(sandbox="sandbox-exec", network=True), "/Users/me", None,
                                            real=lambda path: path)
        self.assertNotIn("network", with_network)
        with self.assertRaises(ContainmentError):
            sandbox_exec_profile(Settings(sandbox="sandbox-exec"), '/Users/a"b', None, real=lambda path: path)

    def test_describe_says_what_the_server_gets(self):
        self.assertIn("job object", containment.describe(Settings(contain=True), "win32"))
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

    def start(self, proxy_args, server, *server_args, environment=None):
        proxy = subprocess.Popen(
            [sys.executable, "-m", "agent_sentinel", "proxy", "--policy", str(EXAMPLE_POLICY_PATH), "--quiet",
             *proxy_args, "--", sys.executable, str(server), *map(str, server_args)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.folder,
            env=environment or self.environment,
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
        proxy = self.start(["--sandbox", "bwrap", "--sandbox-allow", allowed, "--sandbox-read", code], server,
                           allowed, environment=environment)
        self.assertEqual(self.ask(proxy), {"credential": "hidden", "agent_home": "hidden", "allowed": "written"})
        self.assertTrue((allowed / "written.txt").exists())


if __name__ == "__main__":
    unittest.main()
