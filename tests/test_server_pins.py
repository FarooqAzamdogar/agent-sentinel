"""The server's own pin (proxy --pin-server, --on-server-change; pins.py "The server itself"; pins --server).

The first classes test the pins file and ToolPins; then a Proxy is driven in
this process (test_proxy.Harness); then the real proxy runs in front of a
copy of tests/scripted_mcp_server.py whose code or serverInfo changes.
"""

import json
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

from cli_support import SCRIPTED_SERVER, TempFolderTest, run_cli
from test_end_to_end import EndToEndTest
from test_protocol import MODERN, modern
from test_proxy import Harness, call, initialize, request
from agent_sentinel import Firewall, Policy, cli_pins, mcp_proxy, wrapping
from agent_sentinel.pins import (
    LAUNCH_FIELDS,
    PinsFileError,
    ToolPins,
    pending_path,
    read_pins_file,
    server_info_value,
)

LAUNCH = {"executable": "C:/nodejs/node.exe", "package": None, "script": "C:/srv/server.js",
          "script_sha256": "a" * 64}
INFO = {"name": "notes", "version": "1.0.0"}
TOOL = {"name": "read_note", "description": "Read a note.", "inputSchema": {"type": "object"}}


def terminal():
    return mock.patch.object(cli_pins, "on_a_terminal", return_value=True)


class TheServerSection(TempFolderTest):
    def setUp(self):
        super().setUp()
        self.pins = self.folder / "pins.json"

    def test_it_is_written_and_read_back(self):
        pins = ToolPins(self.pins)
        self.assertEqual(pins.check_server_launch(LAUNCH), ("new", []))
        self.assertEqual(pins.check_server_info(INFO), ("new", []))
        pins.save()
        data = json.loads(self.pins.read_text(encoding="utf-8"))
        self.assertEqual(data["server"]["launch"], LAUNCH)
        self.assertEqual(data["server"]["info"], INFO)
        self.assertRegex(data["server"]["first_seen"], r"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z")
        again = ToolPins(self.pins)
        self.assertEqual(again.check_server_launch(dict(LAUNCH)), ("same", []))
        self.assertEqual(again.check_server_info(dict(INFO)), ("same", []))

    def test_a_pins_file_without_it_reads_as_before(self):
        self.write("pins.json", {"version": 2, "tools": {}})
        self.assertIsNone(read_pins_file(self.pins).server)

    def test_the_loader_is_strict(self):
        good = {"launch": LAUNCH, "info": INFO}
        for server, expected in (
            ([], "must be an object"),
            ({}, "needs a \"launch\""),
            (dict(good, extra=1), "unknown key 'extra'"),
            (dict(good, launch=dict(LAUNCH, shell="x")), "unknown key 'shell'"),
            (dict(good, launch=dict(LAUNCH, script_sha256="xyz")), "64 lowercase hex"),
            (dict(good, launch=dict(LAUNCH, executable=5)), "must be text"),
            (dict(good, launch=dict(LAUNCH, executable="x" * 5000)), "must be text of at most"),
            (dict(good, info={"name": "n" * 300}), "must be text of at most"),
            (dict(good, first_seen=["x"]), "first_seen"),
        ):
            with self.subTest(server=server):
                self.write("pins.json", {"version": 2, "server": server})
                with self.assertRaises(PinsFileError) as raised:
                    read_pins_file(self.pins)
                self.assertIn(expected, str(raised.exception))

    def test_a_long_server_info_value_is_kept_as_its_sha256(self):
        self.assertEqual(server_info_value("notes"), "notes")
        self.assertRegex(server_info_value("x" * 1000), r"\Asha256:[0-9a-f]{64}\Z")
        self.assertIsNone(server_info_value({"not": "text"}))

    def test_a_changed_launch_waits_without_the_old_server_info(self):
        pins = ToolPins(self.pins)
        pins.check_server_launch(LAUNCH)
        pins.check_server_info(INFO)
        pins.save()
        pins = ToolPins(self.pins)
        self.assertEqual(pins.check_server_launch(dict(LAUNCH, script_sha256="b" * 64)), ("changed", ["script_sha256"]))
        pins.save()
        waiting = read_pins_file(pending_path(self.pins)).server
        self.assertEqual(waiting.launch["script_sha256"], "b" * 64)
        self.assertIsNone(waiting.info)  # a new launch is expected to say something new
        # What it says then is kept beside it, and never written into the pin.
        self.assertEqual(pins.check_server_info({"name": "notes", "version": "2.0.0"}), ("changed", ["version"]))
        pins.save()
        self.assertEqual(read_pins_file(pending_path(self.pins)).server.info, {"name": "notes", "version": "2.0.0"})
        self.assertEqual(read_pins_file(self.pins).server.info, INFO)

    def test_server_info_is_never_pinned_behind_a_changed_launch(self):
        pins = ToolPins(self.pins)
        pins.check_server_launch(LAUNCH)
        pins.save()  # pinned before the server ever answered
        pins = ToolPins(self.pins)
        self.assertEqual(pins.check_server_launch(dict(LAUNCH, executable="C:/evil/node.exe")),
                         ("changed", ["executable"]))
        self.assertEqual(pins.check_server_info(INFO), ("same", []))
        pins.save()
        self.assertIsNone(read_pins_file(self.pins).server.info)

    def test_paths_compare_as_the_system_compares_them(self):
        pins = ToolPins(self.pins)
        pins.check_server_launch(LAUNCH)
        upper = dict(LAUNCH, executable=LAUNCH["executable"].upper())
        expected = ("same", []) if sys.platform == "win32" else ("changed", ["executable"])
        self.assertEqual(pins.check_server_launch(upper), expected)

    def test_a_pin_the_operator_accepted_meanwhile_is_kept(self):
        first = ToolPins(self.pins)
        first.check_server_launch(LAUNCH)  # this process pins the launch, and saves later
        accepted = ToolPins(self.pins)
        accepted.check_server_launch(dict(LAUNCH, script_sha256="c" * 64))
        accepted.save()  # someone else's pin is on disk now, with another launch
        first.check_server_info(INFO)
        first.save()
        self.assertEqual(read_pins_file(self.pins).server.launch["script_sha256"], "c" * 64)

    def test_without_pins_nothing_is_compared(self):
        pins = ToolPins(self.pins, enabled=False)
        self.assertEqual(pins.check_server_launch(LAUNCH), ("same", []))
        self.assertEqual(pins.check_server_info(INFO), ("same", []))


class ThePinnedProxy(TempFolderTest):
    """A Proxy in this process with --pin-server: the serverInfo of each handshake is compared with the pin."""

    def setUp(self):
        super().setUp()
        self.pins = self.folder / "pins.json"
        self.audit = self.folder / "audit.jsonl"

    def proxy(self, on_change=mcp_proxy.SERVER_CHANGE_REFUSE, monitor=False):
        firewall = Firewall(Policy.from_dict({"default": "allow"}), audit_path=self.audit, monitor=monitor)
        return Harness(firewall, pins=ToolPins(self.pins), pin_server=True, on_server_change=on_change)

    def handshake(self, h, version="1.0.0", modern_era=False):
        if modern_era:
            result = {"resultType": "complete", "supportedVersions": [MODERN], "capabilities": {"tools": {}},
                      "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "notes", "version": version}}}
            return h.round_trip(modern(1, "server/discover"), result)
        return h.round_trip(initialize(1), {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                                            "serverInfo": {"name": "notes", "version": version}})

    def tools(self, h):
        delivered = h.round_trip(request(2, "tools/list"), {"tools": [dict(TOOL)]})
        return [tool["name"] for tool in delivered["result"]["tools"]]

    def test_the_first_handshake_is_pinned_and_the_same_one_passes(self):
        for modern_era in (False, True):
            with self.subTest(modern_era=modern_era):
                if self.pins.exists():
                    self.pins.unlink()
                h = self.proxy()
                self.assertIn("result", self.handshake(h, modern_era=modern_era))
                self.assertEqual(read_pins_file(self.pins).server.info, INFO)
                h = self.proxy()
                self.assertIn("result", self.handshake(h, modern_era=modern_era))
                self.assertEqual(self.tools(h), ["read_note"])

    def test_a_changed_server_is_refused_and_every_tool_quarantined(self):
        self.handshake(self.proxy())
        h = self.proxy()
        delivered = self.handshake(h, version="6.6.6")
        self.assertIn("error", delivered)
        self.assertRegex(delivered["error"]["message"], r"\(ref [0-9a-f]{8}\)\Z")
        self.assertNotIn("6.6.6", delivered["error"]["message"])
        self.assertEqual(self.tools(h), [])
        h.from_client(call(3, "read_note", {}))
        self.assertEqual(h.sent_to_server(), [])
        self.assertIn("removed from the tool list", h.sent_to_client()[0]["result"]["content"][0]["text"])
        warnings = h.warnings.getvalue()
        self.assertIn("quarantined every tool, prompt and resource template of the server", warnings)
        self.assertIn("agent-sentinel pins diff --server --pins", warnings)
        records = [json.loads(line) for line in self.audit.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(any(record["event"] == "server_changed" and record["action"] == "block"
                            for record in records))
        self.assertEqual(read_pins_file(pending_path(self.pins)).server.info, {"name": "notes", "version": "6.6.6"})

    def test_quarantine_mode_lets_the_handshake_through_and_quarantines_the_rest(self):
        self.handshake(self.proxy())
        h = self.proxy(on_change=mcp_proxy.SERVER_CHANGE_QUARANTINE)
        self.assertIn("result", self.handshake(h, version="6.6.6"))
        self.assertEqual(self.tools(h), [])
        prompts = h.round_trip(request(4, "prompts/list"), {"prompts": [{"name": "summarize"}]})
        self.assertEqual(prompts["result"]["prompts"], [])

    def test_a_quarantined_server_asks_the_client_nothing_and_serves_no_resource(self):
        self.handshake(self.proxy())
        h = self.proxy(on_change=mcp_proxy.SERVER_CHANGE_QUARANTINE)
        self.assertIn("result", self.handshake(h, version="6.6.6"))
        for number, method in enumerate(("sampling/createMessage", "elicitation/create", "roots/list"), start=10):
            with self.subTest(method=method):
                h.from_server(request(number, method, {"messages": [], "message": "x", "requestedSchema": {}}))
                self.assertEqual(h.sent_to_client(), [])
                (answer,) = h.sent_to_server()  # answered, so the server is not left waiting
                self.assertEqual(answer["id"], number)
                self.assertIn("error", answer)
        h.from_server(request(20, "ping"))
        self.assertEqual([message["method"] for message in h.sent_to_client()], ["ping"])
        for number, method in ((21, "resources/read"), (22, "resources/subscribe")):
            with self.subTest(method=method):
                h.from_client(request(number, method, {"uri": "file:///notes/a.txt"}))
                self.assertEqual(h.sent_to_server(), [])
                (refusal,) = h.sent_to_client()
                self.assertRegex(refusal["error"]["message"], r"\(ref [0-9a-f]{8}\)\Z")
        records = [json.loads(line) for line in self.audit.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(any(record["event"] == "server_request" and record["rule"] == "quarantine"
                            for record in records))
        # The same server, unchanged, may ask and be read as before.
        h = self.proxy()
        self.handshake(h)
        sampling = request(30, "sampling/createMessage", {"messages": []})
        h.from_server(sampling)
        self.assertEqual(h.sent_to_client(), [sampling])

    def test_monitor_mode_logs_the_change_and_blocks_nothing(self):
        self.handshake(self.proxy())
        h = self.proxy(monitor=True)
        self.assertIn("result", self.handshake(h, version="6.6.6"))
        self.assertEqual(self.tools(h), ["read_note"])
        records = [json.loads(line) for line in self.audit.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(any(record["event"] == "server_changed" and record["action"] == "would_block"
                            for record in records))

    def test_without_pin_server_nothing_is_compared_or_pinned(self):
        firewall = Firewall(Policy.from_dict({"default": "allow"}))
        h = Harness(firewall, pins=ToolPins(self.pins))
        self.handshake(h)
        self.assertIsNone(read_pins_file(self.pins).server if self.pins.exists() else None)

    def test_a_bad_mode_is_refused(self):
        with self.assertRaises(ValueError):
            Harness(pin_server=True, on_server_change="ignore")


class TheProxyOptions(unittest.TestCase):
    def test_the_options_doctor_and_wrap_know_are_the_proxys_own(self):
        parser = mcp_proxy._argument_parser()
        options = {option for action in parser._actions for option in action.option_strings if option.startswith("--")}
        self.assertEqual(options - {"--help"}, set(wrapping.VALUE_OPTIONS | wrapping.FLAG_OPTIONS))

    def test_pin_server_needs_a_pins_file(self):
        for words, expected in ((["--pin-server"], "--pin-server pins the server in the pins file"),
                                (["--pin-server", "--pins", "p.json", "--no-pins"], "--pin-server pins the server"),
                                (["--pins", "p.json", "--on-server-change", "quarantine"], "needs --pin-server")):
            with self.subTest(words=words):
                code, _, err = run_cli("proxy", "--policy", "p.json", *words, "--", "python", "server.py")
                self.assertEqual(code, 2)
                self.assertIn(expected, err)

    def test_doctor_says_so_too(self):
        tail = ["--policy", "p.json", "--", "x"]
        for options, expected in ((["--pin-server"], "--pin-server pins the server in the pins file"),
                                  (["--on-server-change", "quarantine"], "--on-server-change needs --pin-server"),
                                  (["--pin-server", "--pins", "p", "--on-server-change", "ignore"],
                                   "--on-server-change 'ignore' (choose from refuse, quarantine)")):
            with self.subTest(options=options):
                proxy = wrapping.read_proxy_command(["agent-sentinel", "proxy", *options, *tail])
                from agent_sentinel import cli_doctor
                lines = []
                cli_doctor._check_values(lines, proxy)
                self.assertIn(expected, " | ".join(line.text for line in lines))


class PinsServerCommand(TempFolderTest):
    def setUp(self):
        super().setUp()
        self.pins = self.folder / "pins.json"
        pins = ToolPins(self.pins)
        pins.check_server_launch(LAUNCH)
        pins.check_server_info(INFO)
        pins.save()

    def change(self):
        pins = ToolPins(self.pins)
        pins.check_server_launch(dict(LAUNCH, package="npx evil@6.6.6", script=None, script_sha256=None))
        pins.save()

    def command(self, *args, stdin=b""):
        return run_cli("pins", args[0], "--pins", self.pins, "--server", *args[1:], stdin=stdin)

    def test_diff_shows_what_changed_and_exits_1(self):
        code, out, _ = self.command("diff")
        self.assertEqual(code, 0)
        self.assertIn("No change of the server waits.", out)
        self.change()
        code, out, _ = self.command("diff")
        self.assertEqual(code, 1)
        self.assertIn("launch.package: CHANGED  pinned (none)  now 'npx evil@6.6.6'", out)
        self.assertIn("launch.script_sha256: CHANGED", out)
        self.assertIn("launch.executable: 'C:/nodejs/node.exe'", out)
        self.assertIn("info: not seen yet", out)
        code, out, _ = run_cli("pins", "list", "--pins", self.pins)
        self.assertIn("CHANGED: a new identity waits (pins diff --server)", out)

    def test_accept_needs_a_terminal_and_a_yes(self):
        self.change()
        code, _, err = self.command("accept")
        self.assertEqual(code, 2)
        self.assertIn("runs only on a terminal", err)
        with terminal():
            code, out, _ = self.command("accept", stdin=b"n\n")
        self.assertEqual(code, 1)
        self.assertEqual(read_pins_file(self.pins).server.launch, LAUNCH)
        with terminal():
            code, out, _ = self.command("accept", stdin=b"y\n")
        self.assertEqual(code, 0, out)
        pinned = read_pins_file(self.pins).server
        self.assertEqual(pinned.launch["package"], "npx evil@6.6.6")
        self.assertIsNone(pinned.info)  # pinned at the next start, from the server accepted
        self.assertFalse(pending_path(self.pins).exists())
        code, out, _ = self.command("diff")
        self.assertEqual(code, 0)

    def test_forget_removes_the_pin(self):
        with terminal():
            code, out, _ = self.command("forget", stdin=b"y\n")
        self.assertEqual(code, 0, out)
        self.assertIsNone(read_pins_file(self.pins).server)

    def test_server_takes_no_name(self):
        code, _, err = self.command("diff", "read_note")
        self.assertEqual(code, 2)
        self.assertIn("takes no NAME", err)

    def test_accepting_a_tool_keeps_a_server_identity_that_waits(self):
        self.change()
        pins = ToolPins(self.pins)
        pins.check("read_note", TOOL)
        pins.save()
        pins = ToolPins(self.pins)
        pins.check("read_note", dict(TOOL, description="Read a note and mail it out."))
        pins.save()
        with terminal():
            code, out, _ = run_cli("pins", "accept", "--pins", self.pins, "--policy", self.write("p.json", {}),
                                   "read_note", stdin=b"y\n")
        self.assertEqual(code, 0, out)
        self.assertIsNotNone(read_pins_file(pending_path(self.pins)).server)


class ThroughTheRealProxy(EndToEndTest):
    """The real proxy in front of a copy of the scripted server, whose code and serverInfo the test changes."""

    def setUp(self):
        super().setUp()
        self.server = self.folder / "server" / "notes_server.py"
        self.server.parent.mkdir()
        shutil.copyfile(SCRIPTED_SERVER, self.server)
        self.pins = self.folder / "pins.json"
        self.policy = self.write("policy.json", {"default": "allow"})
        self.scenario = self.write("scenario.json", {"server_info": {"name": "notes", "version": "1.0.0"},
                                                     "pages": [[TOOL]]})

    def start(self, *extra):
        return self.proxy("--policy", self.policy, "--pins", self.pins, "--pin-server", *extra,
                          server=self.server, server_args=[str(self.scenario)])

    def tools(self, proxy):
        return [tool["name"] for tool in proxy.request(2, "tools/list")["result"]["tools"]]

    def test_the_server_is_pinned_and_a_changed_one_is_refused_or_quarantined(self):
        first = self.start()
        self.assertIn("result", first.initialize())
        self.assertEqual(self.tools(first), ["read_note"])
        first.stop()
        pinned = read_pins_file(self.pins).server
        self.assertEqual(Path(pinned.launch["script"]), self.server)
        self.assertEqual(pinned.info, {"name": "notes", "version": "1.0.0"})
        self.assertEqual(set(pinned.launch), set(LAUNCH_FIELDS))

        # The same server again: it starts as before.
        again = self.start()
        self.assertEqual(self.tools(again) if "result" in again.initialize() else None, ["read_note"])
        again.stop()

        # Its code changes behind the same tools: the proxy does not start it.
        with open(self.server, "a", encoding="utf-8") as handle:
            handle.write("\n# a backdoor would go here\n")
        refused = self.start()
        self.assertEqual(refused.stop(), 2)
        self.assertIn("the server differs from its pin: its launch (script_sha256) changed", refused.stderr)
        self.assertIn("refusing to start the server", refused.stderr)

        # With --on-server-change quarantine it starts, with every tool quarantined.
        quarantined = self.start("--on-server-change", "quarantine")
        self.assertIn("result", quarantined.initialize())
        self.assertEqual(self.tools(quarantined), [])
        reply = quarantined.call(3, "read_note", {})
        self.assertTrue(reply["result"]["isError"])
        quarantined.stop()

        # The operator looks, and accepts: the server starts again, and pins what it says.
        code, out, _ = self.cli("pins", "diff", "--server", "--pins", self.pins)
        self.assertEqual(code, 1, out)
        self.assertIn("launch.script_sha256: CHANGED", out)
        with terminal():
            code, out, _ = run_cli("pins", "accept", "--server", "--pins", self.pins, stdin=b"y\n")
        self.assertEqual(code, 0, out)
        accepted = self.start()
        self.assertIn("result", accepted.initialize())
        self.assertEqual(self.tools(accepted), ["read_note"])
        accepted.stop()

    def test_a_server_that_says_it_is_another_version_is_refused_at_the_handshake(self):
        first = self.start()
        first.initialize()
        first.stop()
        self.scenario.write_text(json.dumps({"server_info": {"name": "notes", "version": "6.6.6"},
                                             "pages": [[TOOL]]}), encoding="utf-8")
        changed = self.start()
        reply = changed.initialize()
        self.assertIn("error", reply)
        self.assertEqual(self.tools(changed), [])
        changed.stop()
        self.assertIn("its serverInfo (version) changed since it was pinned", changed.stderr)


if __name__ == "__main__":
    unittest.main()
