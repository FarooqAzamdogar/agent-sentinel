"""One server entry: its kind, wrapping and unwrapping it (agent_sentinel/wrapping.py)."""

import os
import sys
import unittest
from unittest import mock

import support  # noqa: F401
from agent_sentinel import wrapping
from agent_sentinel.wrapping import ProxySettings, WrapError, kind_of, read_proxy_command, unwrap_entry, wrap_entry

ROOT = "C:\\sentinel" if sys.platform == "win32" else "/sentinel"
SETTINGS = ProxySettings(
    python=os.path.join(ROOT, "python.exe"), policy=os.path.join(ROOT, "policy.json"),
    audit=os.path.join(ROOT, "audit.jsonl"), pins_folder=os.path.join(ROOT, "pins"),
)


def wrapped(entry, settings=SETTINGS, label="files", pins="PINS"):
    return wrap_entry(entry, settings, label, pins)


class KindsOfEntry(unittest.TestCase):
    def test_remote_entries(self):
        for entry in ({"url": "https://x/mcp"}, {"serverUrl": "https://x/mcp"}, {"type": "http", "command": "x"},
                      {"type": "SSE"}, {"type": "streamable-http", "url": "u"}):
            with self.subTest(entry=entry):
                self.assertEqual(kind_of(entry), "remote")

    def test_stdio_and_broken_entries(self):
        self.assertEqual(kind_of({"command": "npx", "args": ["-y", "x"]}), "stdio")
        self.assertEqual(kind_of({"type": "stdio", "command": "npx"}), "stdio")
        for entry in ("npx", None, [], {}, {"command": ""}, {"command": 5}, {"command": "npx", "args": "x"},
                      {"command": "npx", "args": ["ok", 5]}, {"command": "npx", "args": [{"a": 1}]}):
            with self.subTest(entry=entry):
                self.assertEqual(kind_of(entry), "broken")


class Wrapping(unittest.TestCase):
    def test_the_proxy_is_put_in_front_with_full_paths_and_every_other_key_kept_in_place(self):
        entry = {"type": "stdio", "command": "npx", "args": ["-y", "pkg"], "env": {"TOKEN": "t", "DEBUG": "1"},
                 "cwd": "/w", "x-unknown": [1]}
        new = wrapped(entry)
        self.assertEqual(list(new), ["type", "command", "args", "env", "cwd", "x-unknown"])
        self.assertEqual(new["command"], SETTINGS.python)
        self.assertEqual(new["args"], [
            "-I", "-m", "agent_sentinel", "proxy", "--policy", SETTINGS.policy, "--audit", SETTINGS.audit,
            "--pins", "PINS", "--name", "files", "--pass-env", "TOKEN", "--pass-env", "DEBUG",
            "--", "npx", "-y", "pkg",
        ])
        self.assertEqual(new["env"], entry["env"])
        self.assertEqual(entry["command"], "npx")  # the original is not changed

    def test_args_are_added_after_the_command_when_there_were_none(self):
        new = wrapped({"command": "server", "env": {}})
        self.assertEqual(list(new), ["command", "args", "env"])
        self.assertEqual(new["args"][-2:], ["--", "server"])

    def test_monitor_mode_is_written_when_asked_for(self):
        settings = ProxySettings(SETTINGS.python, SETTINGS.policy, SETTINGS.audit, SETTINGS.pins_folder, monitor=True)
        self.assertIn("--monitor", wrapped({"command": "x"}, settings)["args"])
        self.assertNotIn("--monitor", wrapped({"command": "x"})["args"])

    def test_python_runs_isolated_unless_the_settings_say_otherwise(self):
        settings = ProxySettings(SETTINGS.python, SETTINGS.policy, SETTINGS.audit, SETTINGS.pins_folder,
                                 isolated=False)
        plain = wrapped({"command": "x"}, settings)
        self.assertEqual(plain["args"][:3], ["-m", "agent_sentinel", "proxy"])
        self.assertEqual(wrapping.proxy_command_of(plain).python_module(), (SETTINGS.python, False))
        self.assertEqual(wrapping.proxy_command_of(wrapped({"command": "x"})).python_module(), (SETTINGS.python, True))
        self.assertIsNone(read_proxy_command(["agent-sentinel", "proxy", "--", "x"]).python_module())
        self.assertIsNone(read_proxy_command(["py", "-X", "utf8", "-m", "agent_sentinel", "proxy"]).python_module())

    def test_the_python_check_prefers_isolation_and_falls_back_only_when_it_must(self):
        def answers(isolated_version, plain_version):
            return lambda python, isolated=True: isolated_version if isolated else plain_version

        with mock.patch.object(wrapping, "installed_version", answers("0.5.0", "0.5.0")):
            self.assertEqual(wrapping.check_python("py"), wrapping.PythonCheck(True, "0.5.0"))
        with mock.patch.object(wrapping, "installed_version", answers(None, "0.5.0")):
            self.assertEqual(wrapping.check_python("py"), wrapping.PythonCheck(False, "0.5.0"))
        with mock.patch.object(wrapping, "installed_version", answers(None, None)):
            self.assertEqual(wrapping.check_python("py"), wrapping.PythonCheck(True, None))

    def test_the_installed_version_is_asked_from_another_folder_and_isolated(self):
        version = wrapping.installed_version(sys.executable, isolated=True)
        # This copy of the source is not what the started Python sees from the temporary folder.
        if version is not None:
            self.assertRegex(version, r"^[0-9][0-9A-Za-z.+-]*$")
        with mock.patch.object(wrapping.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=0, stdout=b"0.5.0\n")
            self.assertEqual(wrapping.installed_version("py", isolated=False), "0.5.0")
        command = run.call_args.args[0]
        self.assertEqual(command[:2], ["py", "-E"])
        self.assertNotEqual(run.call_args.kwargs["cwd"], os.getcwd())

    def test_an_entry_is_never_wrapped_twice(self):
        once = wrapped({"command": "npx", "args": ["x"]})
        with self.assertRaises(WrapError) as caught:
            wrapped(once)
        self.assertIn("already wrapped", str(caught.exception))
        for command, args in (("agent-sentinel", ["proxy", "--policy", "p", "--", "x"]),
                              (r"C:\Python\Scripts\agent-sentinel.exe", ["proxy", "--", "x"]),
                              ("agent-sentinel.cmd", ["proxy", "--", "x"]),
                              ("uvx", ["agent-sentinel@0.5.0", "proxy", "--", "x"]),
                              ("python3", ["-m", "agent_sentinel", "proxy", "--", "x"]),
                              ("python3", ["-I", "-m", "agent_sentinel", "proxy", "--", "x"])):
            with self.subTest(command=command), self.assertRaises(WrapError):
                wrapped({"command": command, "args": args})

    def test_whatever_python_wrap_runs_under_its_entry_reads_back_as_wrapped(self):
        entry = {"command": "npx", "args": ["-y", "srv@1.0.0"]}
        for python in ("/opt/pypy3.10/bin/pypy3.10", r"C:\pypy3.10\pypy3.10.exe", "/opt/pypy/bin/pypy3",
                       "/opt/graalpy/bin/graalpy", r"C:\graalpy\bin\graalpy.exe", "/usr/bin/python3.13d",
                       "/usr/bin/python3.12-dbg", "/Library/Frameworks/Python.framework/Versions/3.12/bin/"
                       "python3.12-intel64", r"C:\Python313\python_d.exe", r"C:\Python313\pythonw_d.exe",
                       "/usr/bin/python3.13td", "/usr/bin/python3.13t", "/usr/bin/python3", r"C:\Python313\python.exe"):
            for isolated in (True, False):
                settings = ProxySettings(python, SETTINGS.policy, SETTINGS.audit, SETTINGS.pins_folder,
                                         isolated=isolated)
                with self.subTest(python=python, isolated=isolated):
                    once = wrapped(entry, settings)
                    self.assertEqual(wrapping.status_of(once), "protected")
                    self.assertEqual(wrapping.proxy_command_of(once).python_module(), (python, isolated))
                    with self.assertRaisesRegex(WrapError, "already wrapped"):
                        wrapped(once, settings)
                    self.assertEqual(unwrap_entry(once), entry)

    def test_wrap_refuses_to_write_an_entry_it_would_not_read_back(self):
        # A Python of a name the reader does not know: the entry would look like a command that runs
        # something else before the proxy, and a second wrap would put a proxy in front of the proxy.
        for python in ("/opt/bin/my-interpreter", r"C:\tools\node.exe", "/usr/bin/agent-sentinel", "/usr/bin/uvx"):
            settings = ProxySettings(python, SETTINGS.policy, SETTINGS.audit, SETTINGS.pins_folder)
            with self.subTest(python=python), self.assertRaises(WrapError) as caught:
                wrapped({"command": "npx", "args": ["x"]}, settings)
            self.assertIn("does not have a name agent-sentinel reads back as a Python", str(caught.exception))

    def test_env_must_hold_plain_variable_names(self):
        for env, expected in (({"A B": "1"}, "not a plain variable name"), (["A"], "is not an object"),
                              ({"--policy": "x"}, "not a plain variable name")):
            with self.subTest(env=env), self.assertRaises(WrapError) as caught:
                wrapped({"command": "x", "env": env})
            self.assertIn(expected, str(caught.exception))
        self.assertNotIn("--pass-env", wrapped({"command": "x", "env": None})["args"])

    def test_an_entry_without_a_usable_command_is_refused(self):
        for entry in ({}, {"command": "x", "args": [1]}):
            with self.subTest(entry=entry), self.assertRaises(WrapError):
                wrapped(entry)


class Unwrapping(unittest.TestCase):
    def test_unwrap_gives_back_the_original_entry(self):
        for entry in ({"command": "npx", "args": ["-y", "pkg", "--", "--flag"], "env": {"A": "1"}, "z": True},
                      {"command": "server"},
                      {"type": "stdio", "command": "uvx", "args": ["--from", "pkg==1.0.0", "pkg"]}):
            with self.subTest(entry=entry):
                self.assertEqual(unwrap_entry(wrapped(entry)), entry)
                self.assertEqual(list(unwrap_entry(wrapped(entry))), list(entry))

    def test_only_a_wrapped_entry_with_a_server_command_is_unwrapped(self):
        with self.assertRaises(WrapError) as caught:
            unwrap_entry({"command": "npx", "args": ["x"]})
        self.assertIn("not wrapped", str(caught.exception))
        with self.assertRaises(WrapError) as caught:
            unwrap_entry({"command": "python", "args": ["-m", "agent_sentinel", "proxy", "--policy", "p"]})
        self.assertIn("without a server command", str(caught.exception))


class ReadingTheProxyCommand(unittest.TestCase):
    def test_options_and_the_server_command_are_read(self):
        found = read_proxy_command(["py", "-m", "agent_sentinel", "proxy", "--policy", "p.json", "--audit=a.jsonl",
                                    "--monitor", "--pass-env", "A", "--pass-env", "B", "--new-flag", "--", "npx",
                                    "--", "--policy"])
        self.assertEqual(found.launcher, ["py", "-m", "agent_sentinel", "proxy"])
        self.assertEqual(found.value("--policy"), "p.json")
        self.assertEqual(found.value("--audit"), "a.jsonl")
        self.assertEqual(found.values("--pass-env"), ["A", "B"])
        self.assertTrue(found.has("--monitor"))
        self.assertTrue(found.has("--new-flag"))  # kept, for doctor to report
        self.assertEqual(found.server, ["npx", "--", "--policy"])

    def test_every_proxy_option_that_takes_a_value_is_read_with_it(self):
        found = read_proxy_command(["agent-sentinel", "proxy", "--tool-names", "strict", "--elicitation-host",
                                    "auth.example.com", "--approve-with", "dialog", "--env-file", "s.env", "--",
                                    "server"])
        self.assertEqual(found.value("--tool-names"), "strict")
        self.assertEqual(found.value("--elicitation-host"), "auth.example.com")
        self.assertEqual([name for name, _ in found.options],
                         ["--tool-names", "--elicitation-host", "--approve-with", "--env-file"])
        self.assertEqual(found.server, ["server"])

    def test_a_value_option_takes_the_next_word_even_if_it_looks_like_the_separator(self):
        found = read_proxy_command(["agent-sentinel", "proxy", "--policy", "--", "--", "server"])
        self.assertEqual(found.value("--policy"), "--")
        self.assertEqual(found.server, ["server"])

    def test_commands_that_do_not_start_the_proxy(self):
        for words in (["npx", "agent-sentinel"], ["npx", "-y", "proxy"], ["agent-sentinel", "scan"], ["x"], []):
            with self.subTest(words=words):
                self.assertIsNone(read_proxy_command(words))

    def test_the_launcher_is_looked_for_only_near_the_start(self):
        words = ["x"] * 20 + ["agent-sentinel", "proxy", "--", "y"]
        self.assertIsNone(read_proxy_command(words))
        self.assertFalse(wrapping.mentions_proxy(words))

    def test_only_the_known_launcher_shapes_start_the_proxy(self):
        for launcher in (["agent-sentinel"], [r"C:\Py\Scripts\agent-sentinel.exe"], ["agent_sentinel.cmd"],
                         ["python", "-m", "agent_sentinel"], ["/usr/bin/python3.12", "-I", "-m", "agent_sentinel"],
                         ["py", "-3.12", "-X", "utf8", "-IB", "-m", "agent_sentinel"],
                         [r"C:\venv\Scripts\pythonw.exe", "-m", "agent_sentinel"],
                         ["uvx", "agent-sentinel@0.5.0"], ["uvx.exe", "agent-sentinel==0.5.0"],
                         ["uvx", "--from", "agent-sentinel==0.5.0", "agent-sentinel"],
                         ["uv", "tool", "run", "agent-sentinel"],
                         ["pipx", "run", "--spec", "agent-sentinel", "agent-sentinel"]):
            with self.subTest(launcher=launcher):
                found = read_proxy_command([*launcher, "proxy", "--policy", "p.json", "--", "server"])
                self.assertEqual(found.launcher, [*launcher, "proxy"])
                self.assertEqual(found.server, ["server"])

    def test_a_command_that_runs_something_else_before_the_proxy_does_not_start_it(self):
        for before in (["C:/Windows/System32/cmd.exe", "/c", "python", "evil.py", "&"], ["node", "evil.js"],
                       ["bash", "-c", "evil", "x"], ["python", "evil.py"], ["python", "-c", "import evil", "x"],
                       ["uvx", "--from", "evil-package"], ["npx", "-y"], ["sudo"]):
            for launcher in (["agent-sentinel"], ["agent_sentinel"]):
                words = [*before, *launcher, "proxy", "--policy", "p.json", "--", "server"]
                with self.subTest(words=words):
                    self.assertIsNone(read_proxy_command(words))
                    self.assertTrue(wrapping.mentions_proxy(words))
                    self.assertEqual(wrapping.status_of({"command": words[0], "args": words[1:]}), "broken")
        for words in (["python", "-c", "x", "-m", "agent_sentinel", "proxy", "--", "s"],
                      ["bash", "-m", "agent_sentinel", "proxy", "--", "s"],
                      ["python", "-m", "agent_sentinel.__main__", "proxy", "--", "s"]):
            with self.subTest(words=words):
                self.assertIsNone(read_proxy_command(words))

    def test_a_package_runner_must_run_agent_sentinel_at_a_version_and_nothing_else(self):
        # pip, uv and pipx read "agent-sentinel@<URL>" as "install whatever is at that URL under this name".
        for package in ("agent-sentinel@0.5.0", "agent-sentinel==0.5.0", "agent_sentinel@latest",
                        "Agent-Sentinel==1!2.0.0rc1+local", "agent-sentinel@1", "agent-sentinel@0.5.0a1",
                        "agent-sentinel==0.5.0.post1.dev2", "agent-sentinel@0.5.0RC1+abc.1"):
            for launcher in (["uvx", package], ["uvx", "--from", package, "agent-sentinel"],
                             ["pipx", "run", "--spec", package, "agent-sentinel"]):
                with self.subTest(launcher=launcher):
                    words = [*launcher, "proxy", "--policy", "p.json", "--", "server"]
                    self.assertEqual(read_proxy_command(words).launcher, [*launcher, "proxy"])
                    self.assertEqual(wrapping.status_of({"command": words[0], "args": words[1:]}), "protected")
        for package in ("agent-sentinel@git+https://evil.example/x", "agent-sentinel@file:///C:/Users/Public/evil",
                        "agent-sentinel@https://evil.example/x.whl", "agent-sentinel @ git+https://evil.example/x",
                        "agent-sentinel@ git+https://evil.example/x", "agent-sentinel[extra]==0.5.0",
                        "agent-sentinel==0.5.0; python_version>'3'", "agent-sentinel@../evil", "agent-sentinel>=0.5",
                        "agent-sentinel.exe", "agent-sentinel@", "agent-sentinel==",
                        # Not PEP 440 versions: uv reads each as a folder of that name in the client's folder.
                        "agent-sentinel@0.5.0-evil", "agent-sentinel@1x", "agent-sentinel@1.zip",
                        "agent-sentinel@0.5.0-local", "agent-sentinel==0.5.0-evil", "agent-sentinel==1x",
                        "agent-sentinel@LATEST", "agent-sentinel@" + "9" * 19, "agent-sentinel@0.5.0\n"):
            for launcher in (["uvx", package], ["uv", "tool", "run", package], ["pipx", "run", package],
                             ["uvx", "--from", package, "agent-sentinel"],
                             ["pipx", "run", "--spec", package, "agent-sentinel"]):
                words = [*launcher, "proxy", "--policy", "p.json", "--", "server"]
                with self.subTest(words=words):
                    self.assertIsNone(read_proxy_command(words))
                    self.assertTrue(wrapping.mentions_proxy(words))
                    self.assertEqual(wrapping.status_of({"command": words[0], "args": words[1:]}), "broken")

    def test_a_shortened_proxy_option_is_recognised(self):
        self.assertEqual(wrapping.shortened_option("--mon"), ["--monitor"])
        self.assertEqual(wrapping.shortened_option("--polic"), ["--policy"])
        self.assertEqual(wrapping.shortened_option("--polic=weak.json"), ["--policy"])
        self.assertEqual(wrapping.shortened_option("--p"), ["--pass-env", "--pins", "--policy"])
        for word in ("--monitor", "--policy=x", "--frobnicate", "-m", "--", "weak.json", "-"):
            with self.subTest(word=word):
                self.assertEqual(wrapping.shortened_option(word), [])


class TheProxysOwnOptions(unittest.TestCase):
    """The proxy's parser must read options exactly as wrap writes them and doctor reads them."""

    def parse(self, *words):
        from agent_sentinel import mcp_proxy
        with mock.patch("sys.stderr"):
            return mcp_proxy._argument_parser().parse_args(list(words))

    def test_a_shortened_option_is_refused_so_the_proxy_does_not_start(self):
        for words in (("--policy", "p.json", "--mon", "--", "python", "server.py"),
                      ("--policy", "good.json", "--polic", "weak.json", "--", "python", "server.py"),
                      ("--policy", "good.json", "--polic=weak.json", "--", "python", "server.py")):
            with self.subTest(words=words), self.assertRaises(SystemExit):
                self.parse(*words)

    def test_options_written_in_full_are_read(self):
        args = self.parse("--policy", "p.json", "--monitor", "--", "python", "server.py", "--mon")
        self.assertTrue(args.monitor)
        self.assertEqual(args.policy, "p.json")
        self.assertEqual(args.command, ["--", "python", "server.py", "--mon"])  # the server's own words


class StatusFromTheEntryAlone(unittest.TestCase):
    def test_what_clients_counts(self):
        good = wrapped({"command": "npx", "args": ["x"]})
        monitor = wrap_entry({"command": "npx"}, ProxySettings(SETTINGS.python, SETTINGS.policy, SETTINGS.audit,
                                                               SETTINGS.pins_folder, monitor=True), "x", "PINS")
        shortened = {"command": "agent-sentinel", "args": ["proxy", "--policy", "p.json", "--mon", "--", "s"]}
        twice = {"command": "agent-sentinel", "args": ["proxy", "--policy", "p.json", "--policy", "q.json", "--", "s"]}
        for entry, expected in ((good, "protected"), (monitor, "unprotected"), (shortened, "broken"),
                                (twice, "broken"), ({"command": "npx"}, "unprotected"),
                                ({"url": "https://x"}, "remote"), ({"args": []}, "broken")):
            with self.subTest(entry=entry):
                self.assertEqual(wrapping.status_of(entry), expected)


class EnvThatChangesWhatStarts(unittest.TestCase):
    """The client starts the launcher with the entry's "env": some variables make it run other code."""

    TAIL = ["proxy", "--policy", os.path.join(ROOT, "policy.json"), "--", "npx", "server"]
    PYTHON = os.path.join(ROOT, "python.exe")
    # (launcher, variables that change what it starts, variables that do not)
    CASES = (
        ([PYTHON, "-I", "-m", "agent_sentinel"], ["__PYVENV_LAUNCHER__", "PYTHONEXECUTABLE"],
         ["PYTHONPATH", "PYTHONHOME", "APPDATA", "HOME", "PATH", "UV_INDEX_URL", "PYTHONUNBUFFERED", "GITHUB_TOKEN"]),
        ([PYTHON, "-m", "agent_sentinel"],
         ["PYTHONPATH", "pythonpath", "PYTHONHOME", "PYTHONUSERBASE", "PYTHONPLATLIBDIR", "PYTHONPYCACHEPREFIX",
          "APPDATA", "HOME", "USERPROFILE", "__PYVENV_LAUNCHER__"],
         ["PATH", "UV_INDEX_URL", "PYTHONUNBUFFERED", "PYTHONIOENCODING", "VIRTUAL_ENV"]),
        ([PYTHON, "-E", "-s", "-m", "agent_sentinel"], ["__PYVENV_LAUNCHER__"], ["PYTHONPATH", "APPDATA"]),
        (["python", "-I", "-m", "agent_sentinel"], ["PATH", "__PYVENV_LAUNCHER__"], ["PYTHONPATH"]),
        (["py", "-3.12", "-I", "-m", "agent_sentinel"], ["VIRTUAL_ENV", "PY_PYTHON", "PYLAUNCHER_ALLOW_INSTALL", "PATH"],
         ["PYTHONPATH"]),
        (["agent-sentinel"], ["PATH", "PYTHONPATH", "PYTHONHOME", "APPDATA", "__PYVENV_LAUNCHER__"],
         ["UV_INDEX_URL", "PYTHONUNBUFFERED"]),
        ([os.path.join(ROOT, "Scripts", "agent-sentinel.exe")], ["PYTHONPATH", "APPDATA"], ["PATH", "PIP_INDEX_URL"]),
        (["uvx", "agent-sentinel==0.5.0"],
         ["UV_INDEX", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL", "UV_FIND_LINKS", "UV_CONFIG_FILE",
          "UV_PYTHON", "UV_CACHE_DIR", "UV_TOOL_DIR", "UV_SOMETHING_NEW", "XDG_CONFIG_HOME", "APPDATA", "PATH",
          "SSL_CERT_FILE", "PYTHONPATH"],
         ["UV_NO_CONFIG", "UV_OFFLINE", "PYTHONUNBUFFERED", "GITHUB_TOKEN"]),
        (["uv", "tool", "run", "--from", "agent-sentinel@0.5.0", "agent-sentinel"], ["UV_INDEX_URL", "UV_PYTHON"],
         ["UV_NO_CONFIG"]),
        (["pipx", "run", "--spec", "agent-sentinel==0.5.0", "agent-sentinel"],
         ["PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_CONFIG_FILE", "PIP_TRUSTED_HOST",
          "PIPX_HOME", "PIPX_DEFAULT_PYTHON", "LOCALAPPDATA", "PYTHONPATH"],
         ["PIP_DISABLE_PIP_VERSION_CHECK", "PYTHONUNBUFFERED"]),
    )

    def entry(self, launcher, env):
        words = [*launcher, *self.TAIL]
        return {"command": words[0], "args": words[1:], "env": env}

    def redirected(self, entry, environ):
        proxy = wrapping.proxy_command_of(entry)
        self.assertIsNotNone(proxy)
        return [name for name, _ in wrapping.env_redirects(entry, proxy, environ=environ)]

    def test_each_launcher_has_its_own_variables(self):
        for launcher, changing, harmless in self.CASES:
            for name in changing:
                with self.subTest(launcher=launcher, name=name):
                    entry = self.entry(launcher, {name: "C:/evil-folder"})
                    self.assertEqual(self.redirected(entry, {}), [name])
                    self.assertEqual(wrapping.status_of(entry), "broken")
            with self.subTest(launcher=launcher, harmless=harmless):
                entry = self.entry(launcher, {name: "C:/elsewhere" for name in harmless})
                self.assertEqual(self.redirected(entry, {}), [])
                self.assertEqual(wrapping.status_of(entry), "protected")

    def test_a_variable_set_to_its_own_value_changes_nothing(self):
        entry = self.entry([self.PYTHON, "-m", "agent_sentinel"], {"APPDATA": "C:/Users/me/AppData/Roaming"})
        self.assertEqual(self.redirected(entry, {"APPDATA": "C:/Users/me/AppData/Roaming"}), [])
        self.assertEqual(self.redirected(entry, {"APPDATA": "C:/Users/someone-else/AppData/Roaming"}), ["APPDATA"])
        with mock.patch.dict(os.environ, {"APPDATA": "C:/Users/me/AppData/Roaming"}):
            self.assertEqual(wrapping.status_of(entry), "protected")

    def test_wrap_does_not_write_an_entry_its_env_would_break(self):
        plain = ProxySettings(SETTINGS.python, SETTINGS.policy, SETTINGS.audit, SETTINGS.pins_folder, isolated=False)
        for settings, env, refused in ((SETTINGS, {"PYTHONPATH": "evil"}, False),
                                       (SETTINGS, {"__PYVENV_LAUNCHER__": "evil/Scripts/python.exe"}, True),
                                       (plain, {"PYTHONPATH": "evil"}, True),
                                       (plain, {"PYTHONUNBUFFERED": "1"}, False)):
            entry = {"command": "npx", "args": ["server"], "env": env}
            with self.subTest(isolated=settings.isolated, env=env):
                if refused:
                    with self.assertRaises(WrapError) as caught:
                        wrapped(entry, settings)
                    self.assertIn(f"its \"env\" sets {next(iter(env))}", str(caught.exception))
                else:
                    self.assertEqual(wrapping.status_of(wrapped(entry, settings)), "protected")


class NamesAndPinsFiles(unittest.TestCase):
    def test_names_keep_to_the_proxys_characters_and_are_unique(self):
        taken = set()
        self.assertEqual(wrapping.server_label("files", taken), "files")
        self.assertEqual(wrapping.server_label("Files", taken), "Files-2")  # unique ignoring case
        self.assertEqual(wrapping.server_label("my server/1", taken), "my-server-1")
        self.assertEqual(wrapping.server_label("!!!", taken), "server")
        self.assertEqual(len(wrapping.server_label("x" * 100, taken)), 64)
        self.assertEqual(wrapping.server_label("x" * 100, taken), "x" * 62 + "-2")
        self.assertEqual(wrapping.server_label("\x1b[2J", taken), "2J")

    def test_each_configuration_file_gets_its_own_pins_files(self):
        one = wrapping.pins_file(SETTINGS, "cursor", "files", os.path.join(ROOT, "a", ".cursor", "mcp.json"))
        two = wrapping.pins_file(SETTINGS, "cursor", "files", os.path.join(ROOT, "b", ".cursor", "mcp.json"))
        again = wrapping.pins_file(SETTINGS, "cursor", "files", os.path.join(ROOT, "a", ".cursor", "mcp.json"))
        self.assertNotEqual(one, two)
        self.assertEqual(one, again)
        self.assertRegex(os.path.basename(one), r"^cursor-files-[0-9a-f]{8}\.json$")
        self.assertEqual(os.path.dirname(one), SETTINGS.pins_folder)

    def test_the_installed_version_of_a_missing_program_is_none(self):
        self.assertIsNone(wrapping.installed_version(os.path.join(ROOT, "no-such-python")))


if __name__ == "__main__":
    unittest.main()
