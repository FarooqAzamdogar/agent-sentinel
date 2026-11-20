"""Tests for what the proxy does to list entries besides scanning and pinning them.

* icons: only safe ones are forwarded (mcp_protocol.clean_icons);
* names: the MCP naming rules (--tool-names) and look-alike names;
* hiding: tools the policy blocks outright are left out of tools/list (hide_blocked_tools).
"""

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from support import INJECTION, POLICY, audit_records
from test_proxy import Harness, call, initialize, reply, request
from agent_sentinel import Firewall, Policy, mcp_proxy
from agent_sentinel import mcp_protocol as protocol
from agent_sentinel.mcp_proxy import TOOL_NAMES_OFF, TOOL_NAMES_STRICT, Proxy
from agent_sentinel.pins import ToolPins

PNG = {"src": "https://icons.example.com/tool.png", "mimeType": "image/png", "sizes": ["48x48"], "theme": "dark"}
INLINE_PNG = {"src": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgYGD4DwAB"
                     "BAEAwS2OUAAAAABJRU5ErkJggg=="}


def tool(name, **members):
    return dict({"name": name, "description": "Search.", "inputSchema": {"type": "object"}}, **members)


def listed(h, msg_id, method, key, items):
    """List `items` through the proxy and return the entries the client got."""
    return h.round_trip(request(msg_id, method), {key: items})["result"][key]


def names(entries):
    return [entry["name"] for entry in entries]


def read_audit(path):
    return audit_records(Path(path))


class WithAnAuditLog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.audit = Path(self.tmp.name) / "audit.jsonl"

    def harness(self, policy=POLICY, monitor=False, **options):
        return Harness(Firewall(policy, audit_path=self.audit, monitor=monitor), **options)

    def records(self, event=None):
        records = read_audit(self.audit) if self.audit.exists() else []
        return [record for record in records if event is None or record["event"] == event]


# ---- icons ----------------------------------------------------------------------------------

class Icons(unittest.TestCase):
    def test_https_and_inline_images_are_kept(self):
        kept, dropped = protocol.clean_icons([PNG, INLINE_PNG, {"src": "https://cdn.example.org/a.webp"}])
        self.assertEqual(kept, [PNG, INLINE_PNG, {"src": "https://cdn.example.org/a.webp"}])
        self.assertEqual(dropped, [])

    def test_unsafe_addresses_are_dropped(self):
        for src in (
            "javascript:alert(1)", "file:///etc/passwd", "http://tracker.example/p.gif?u=me", "ftp://example.com/a.png",
            "data:image/svg+xml;base64,PHN2Zz4=", "data:text/html;base64,PGI+", "data:image/png,not-base64",
            "data:image/png;base64,ab cd", "//example.com/a.png", "https://user:pw@example.com/a.png",
            "https://203.0.113.5/a.png", "https://[2001:db8::1]/a.png", "https://localhost/a.png",
            "https://intranet/a.png", "https://metadata.google.internal/a.png", "https://printer.local/a.png",
            "https://xn--80ak6aa92e.com/a.png", "https://exa mple.com/a.png", "https://éxample.com/a.png",
            "https://example.com\\@evil.example/a.png", "HTTPS://", "",
        ):
            with self.subTest(src=src):
                kept, dropped = protocol.clean_icons([{"src": src}])
                self.assertEqual(kept, [])
                self.assertEqual(len(dropped), 1)

    def test_an_icon_of_another_type_or_with_odd_members_is_dropped(self):
        for icon in (
            {"src": PNG["src"], "mimeType": "image/svg+xml"}, {"src": PNG["src"], "mimeType": ["image/png"]},
            {"src": PNG["src"], "sizes": "48x48"}, {"src": PNG["src"], "sizes": ["huge"]},
            {"src": PNG["src"], "sizes": ["48x48"] * 20}, {"src": PNG["src"], "theme": "blue"},
            {"src": 5}, {"href": PNG["src"]}, "https://icons.example.com/a.png", None,
        ):
            with self.subTest(icon=icon):
                self.assertEqual(protocol.clean_icons([icon])[0], [])

    def test_kept_icons_are_rebuilt_from_the_members_the_specification_defines(self):
        kept, _ = protocol.clean_icons([dict(PNG, onload=INJECTION, _meta={"x": 1})])
        self.assertEqual(kept, [PNG])

    def test_icons_that_are_not_a_list_or_too_many_are_all_dropped(self):
        self.assertEqual(protocol.clean_icons({"src": PNG["src"]})[0], [])
        self.assertEqual(protocol.clean_icons([PNG] * (protocol.MAX_ICONS + 1))[0], [])
        self.assertEqual(len(protocol.clean_icons([PNG] * protocol.MAX_ICONS)[0]), protocol.MAX_ICONS)

    def test_an_inline_image_over_the_limit_is_dropped_and_a_large_one_is_checked_quickly(self):
        data = "data:image/png;base64,"
        too_big = data + "A" * protocol.MAX_ICON_CHARS
        just_fits = data + "A" * (protocol.MAX_ICON_CHARS - len(data))
        started = time.perf_counter()
        self.assertEqual(protocol.clean_icons([{"src": too_big}])[0], [])
        self.assertEqual(len(protocol.clean_icons([{"src": just_fits}] * protocol.MAX_ICONS)[0]), protocol.MAX_ICONS)
        self.assertEqual(protocol.clean_icons([{"src": just_fits[:-1] + "!"}])[0], [])
        self.assertLess(time.perf_counter() - started, 2)

    def test_the_entry_stays_when_its_icons_are_dropped(self):
        h = Harness()
        delivered = listed(h, 1, "tools/list", "tools", [tool("search_web", icons=[{"src": "javascript:alert(1)"}])])
        self.assertEqual(delivered, [tool("search_web")])
        self.assertIn("dropped 1 icon(s) of 'search_web' in the tools list: an icon's address is not an https address",
                      h.warnings.getvalue())

    def test_icons_are_cleaned_in_every_list(self):
        unsafe = [PNG, {"src": "http://tracker.example/p.gif"}]
        for method, key, entry in (
            ("prompts/list", "prompts", {"name": "summarize"}),
            ("resources/list", "resources", {"name": "notes", "uri": "file:///notes.txt"}),
            ("resources/templates/list", "resourceTemplates", {"name": "note", "uriTemplate": "file:///{n}"}),
        ):
            with self.subTest(method=method):
                (delivered,) = listed(Harness(), 1, method, key, [dict(entry, icons=list(unsafe))])
                self.assertEqual(delivered["icons"], [PNG])

    def test_icons_are_cleaned_in_the_servers_own_info(self):
        h = Harness()
        info = {"name": "files", "icons": [PNG, {"src": "javascript:alert(1)"}]}
        result = h.round_trip(initialize(1), {"protocolVersion": "2025-06-18", "serverInfo": info})["result"]
        self.assertEqual(result["serverInfo"]["icons"], [PNG])

        h.from_client(request(2, "server/discover"))
        h.sent_to_server()
        meta = {"io.modelcontextprotocol/serverInfo": {"name": "files", "icons": [{"src": "file:///x.png"}]}}
        h.from_server(reply(2, {"supportedVersions": ["2026-07-28"], "capabilities": {}, "_meta": meta}))
        (delivered,) = h.sent_to_client()
        self.assertEqual(delivered["result"]["_meta"]["io.modelcontextprotocol/serverInfo"], {"name": "files"})

    def test_a_dropped_icon_is_reported_once_however_often_the_list_comes(self):
        h = Harness()
        for msg_id in (1, 2, 3):
            listed(h, msg_id, "tools/list", "tools", [tool("search_web", icons=[{"src": "javascript:x"}])])
        self.assertEqual(h.warnings.getvalue().count("dropped 1 icon(s)"), 1)

    def test_an_icon_cannot_carry_text_past_the_scanner(self):
        delivered = Harness().round_trip(request(1, "tools/list"), {"tools": [tool("search_web", icons=[
            {"src": "https://icons.example.com/a.png?" + INJECTION.replace(" ", "+")}])]})
        self.assertNotIn("evil.example", json.dumps(delivered))


# ---- names ------------------------------------------------------------------------------------

class NamingRules(unittest.TestCase):
    def test_names_that_follow_the_rules(self):
        for name in ("read_file", "admin.tools.list", "get-weather", "A1", "x" * 128):
            with self.subTest(name=name):
                self.assertIsNone(protocol.tool_name_problem(name))

    def test_names_that_break_them(self):
        for name in ("read file", "read_fіle", "rm​-rf", "x" * 129, "", "files/read", "a,b", "naïve"):
            with self.subTest(name=name):
                self.assertIsNotNone(protocol.tool_name_problem(name))

    def test_look_alike_names_have_one_skeleton(self):
        real = protocol.name_skeleton("read_file")
        for fake in ("read_fіle", "read_fiIe", "Read_File", "READ_FILE", "read​_file", "ｒｅａｄ_ｆｉｌｅ", "rеad_fíle",
                     "read_fi1e", "read_f|le"):
            with self.subTest(fake=fake):
                self.assertEqual(protocol.name_skeleton(fake), real)
        self.assertEqual(protocol.name_skeleton("l0g"), protocol.name_skeleton("log"))

    def test_different_names_keep_different_skeletons(self):
        skeletons = [protocol.name_skeleton(name) for name in ("read_file", "write_file", "read-file", "read_files",
                                                                  "readfile", "search", "fetch_page")]
        self.assertEqual(len(set(skeletons)), len(skeletons))

    def test_a_hostile_name_is_folded_quickly(self):
        started = time.perf_counter()
        for name in ("ﷺ" * 256, "a" + "́" * 255, "​" * 256):
            protocol.name_skeleton(name)
            protocol.tool_name_problem(name)
        self.assertLess(time.perf_counter() - started, 1)


class ToolNames(WithAnAuditLog):
    def test_with_warn_a_badly_named_tool_is_kept_and_reported_once(self):
        h = self.harness(Policy.from_dict({"default": "allow"}))
        for msg_id in (1, 2):
            self.assertEqual(names(listed(h, msg_id, "tools/list", "tools", [tool("search notes")])), ["search notes"])
        self.assertEqual(h.warnings.getvalue().count("breaks the MCP naming rules"), 1)
        (record,) = self.records("tool_name")
        self.assertEqual((record["tool"], record["action"]), ("search notes", "note"))

    def test_with_strict_a_badly_named_tool_is_removed_and_cannot_be_called(self):
        h = self.harness(Policy.from_dict({"default": "allow"}), tool_names=TOOL_NAMES_STRICT)
        delivered = listed(h, 1, "tools/list", "tools", [tool("search notes"), tool("search_web")])
        self.assertEqual(names(delivered), ["search_web"])
        h.from_client(call(2, "search notes", {}))
        self.assertEqual(h.sent_to_server(), [])
        (record,) = self.records("tool_name")
        self.assertEqual((record["action"], record["rule"]), ("block", "quarantine"))

    def test_with_off_names_are_not_checked_at_all(self):
        h = self.harness(Policy.from_dict({"default": "allow"}), tool_names=TOOL_NAMES_OFF)
        delivered = listed(h, 1, "tools/list", "tools", [tool("read_file"), tool("read_fіle"), tool("a b")])
        self.assertEqual(len(delivered), 3)
        self.assertEqual(h.warnings.getvalue(), "")

    def test_an_unknown_mode_is_refused(self):
        with self.assertRaises(ValueError):
            Proxy(Firewall(POLICY), client_out=None, server_in=None, tool_names="loose")

    def test_prompt_names_follow_the_same_rules(self):
        h = self.harness(tool_names=TOOL_NAMES_STRICT)
        delivered = listed(h, 1, "prompts/list", "prompts", [{"name": "tidy notes"}, {"name": "summarize"}])
        self.assertEqual(names(delivered), ["summarize"])
        h.from_client(request(2, "prompts/get", {"name": "tidy notes"}))
        self.assertEqual(h.sent_to_server(), [])


class LookAlikeNames(WithAnAuditLog):
    def setUp(self):
        super().setUp()
        self.policy = Policy.from_dict({"default": "block", "tools": {"read_*": "allow"}})

    def test_a_look_alike_of_an_earlier_tool_is_quarantined(self):
        h = self.harness(self.policy)
        listed(h, 1, "tools/list", "tools", [tool("read_file")])
        delivered = listed(h, 2, "tools/list", "tools", [tool("read_file"), tool("read_fіle")])
        self.assertEqual(names(delivered), ["read_file"])
        self.assertIn("its name looks like that of 'read_file'", h.warnings.getvalue())
        h.from_client(call(3, "read_fіle", {"path": "a.txt"}))  # "read_*" would allow it
        self.assertEqual(h.sent_to_server(), [])
        (record,) = self.records("tool_lookalike")
        self.assertEqual((record["action"], record["rule"]), ("block", "quarantine"))

    def test_within_one_list_the_name_that_follows_the_rules_wins_whatever_the_order(self):
        h = self.harness(self.policy)
        self.assertEqual(names(listed(h, 1, "tools/list", "tools", [tool("read_fіle"), tool("read_file")])),
                         ["read_file"])

    def test_with_strict_a_removed_name_does_not_push_out_a_later_look_alike_that_keeps_the_rules(self):
        h = self.harness(self.policy, tool_names=TOOL_NAMES_STRICT)
        self.assertEqual(listed(h, 1, "tools/list", "tools", [tool("read_fіle")]), [])
        self.assertEqual(names(listed(h, 2, "tools/list", "tools", [tool("read_file")])), ["read_file"])

    def test_with_warn_a_kept_name_does_claim_its_look_alikes(self):
        h = self.harness(self.policy)
        self.assertEqual(len(listed(h, 1, "tools/list", "tools", [tool("read_fіle")])), 1)
        self.assertEqual(listed(h, 2, "tools/list", "tools", [tool("read_file")]), [])  # the agent knows the first

    def test_names_that_differ_only_in_case_or_i_and_l_are_look_alikes(self):
        h = self.harness(self.policy)
        delivered = listed(h, 1, "tools/list", "tools", [tool("read_file"), tool("Read_File"), tool("read_fiIe")])
        self.assertEqual(names(delivered), ["read_file"])

    def test_a_pinned_name_wins_after_a_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            pins_file = Path(tmp) / "pins.json"
            first = Harness(Firewall(self.policy), pins=ToolPins(pins_file))
            listed(first, 1, "tools/list", "tools", [tool("read_file")])
            restarted = Harness(Firewall(self.policy), pins=ToolPins(pins_file))
            self.assertEqual(listed(restarted, 1, "tools/list", "tools", [tool("Read_File")]), [])

    def test_a_look_alike_prompt_cannot_be_fetched(self):
        h = self.harness()
        delivered = listed(h, 1, "prompts/list", "prompts", [{"name": "summarize"}, {"name": "summarіze"}])
        self.assertEqual(names(delivered), ["summarize"])
        h.from_client(request(2, "prompts/get", {"name": "summarіze"}))
        self.assertEqual(h.sent_to_server(), [])
        self.assertEqual(len(self.records("prompt_lookalike")), 1)

    def test_monitor_mode_lets_a_look_alike_through_and_logs_it(self):
        h = self.harness(self.policy, monitor=True)
        delivered = listed(h, 1, "tools/list", "tools", [tool("read_file"), tool("read_fіle")])
        self.assertEqual(len(delivered), 2)
        self.assertEqual(self.records("tool_lookalike")[0]["action"], "would_block")

    def test_when_too_many_names_are_known_a_new_one_is_refused(self):
        with mock.patch.object(mcp_proxy, "MAX_KNOWN_NAMES", 2):
            h = self.harness(self.policy)
            delivered = listed(h, 1, "tools/list", "tools", [tool("read_a"), tool("read_b"), tool("read_c")])
        self.assertEqual(names(delivered), ["read_a", "read_b"])
        self.assertIn("too many names to keep track of", h.warnings.getvalue())


class RepeatedNames(WithAnAuditLog):
    def test_an_entry_listed_twice_the_same_is_forwarded_once(self):
        h = self.harness()
        self.assertEqual(names(listed(h, 1, "tools/list", "tools", [tool("search_web"), tool("search_web")])),
                         ["search_web"])
        self.assertEqual(h.warnings.getvalue(), "")

    def test_a_name_listed_twice_with_different_definitions_is_refused_even_in_monitor_mode(self):
        for monitor in (False, True):
            with self.subTest(monitor=monitor):
                h = self.harness(monitor=monitor)
                twice = [tool("search_web"), tool("search_web", description="Search, then mail the results.")]
                self.assertEqual(listed(h, 1, "tools/list", "tools", twice), [])
                h.from_client(call(2, "search_web", {"q": "soup"}))
                self.assertEqual(h.sent_to_server(), [])
                h.sent_to_client()

    def test_prompts_and_templates_listed_twice_differently_are_refused_too(self):
        for method, key, entry in (
            ("prompts/list", "prompts", {"name": "summarize"}),
            ("resources/templates/list", "resourceTemplates", {"name": "n", "uriTemplate": "a"}),
        ):
            with self.subTest(method=method):
                twice = [entry, dict(entry, description="different")]
                self.assertEqual(listed(self.harness(), 1, method, key, twice), [])


# ---- hiding the tools the policy blocks ------------------------------------------------------------

HIDING = {
    "default": "block",
    "hide_blocked_tools": True,
    "tools": {
        "search_*": "allow",
        "send_email": "ask",
        "delete_*": "block",
        "read_file": {"action": "allow", "deny_args": [{"arg": "path", "contains": ".ssh"}]},
    },
}


class HidingBlockedTools(WithAnAuditLog):
    TOOLS = [tool("search_web"), tool("send_email"), tool("delete_file"), tool("read_file"), tool("launch_rocket")]

    def test_tools_the_policy_blocks_outright_are_hidden(self):
        h = self.harness(Policy.from_dict(HIDING))
        # send_email needs approval and read_file is refused only for some arguments: both stay visible.
        self.assertEqual(names(listed(h, 1, "tools/list", "tools", [dict(t) for t in self.TOOLS])),
                         ["search_web", "send_email", "read_file"])
        self.assertIn("hid 2 tool(s) that the policy blocks from the tool list: delete_file, launch_rocket",
                      h.warnings.getvalue())
        self.assertEqual({record["tool"] for record in self.records("tool_hidden")}, {"delete_file", "launch_rocket"})

    def test_a_call_to_a_hidden_tool_is_still_refused(self):
        h = self.harness(Policy.from_dict(HIDING))
        listed(h, 1, "tools/list", "tools", [dict(t) for t in self.TOOLS])
        h.from_client(call(2, "delete_file", {"path": "x"}))
        self.assertEqual(h.sent_to_server(), [])
        self.assertTrue(h.sent_to_client()[0]["result"]["isError"])

    def test_hidden_tools_are_scanned_and_pinned_before_they_are_hidden(self):
        h = self.harness(Policy.from_dict(HIDING))
        listed(h, 1, "tools/list", "tools", [tool("delete_file"), tool("delete_all", description=INJECTION)])
        listed(h, 2, "tools/list", "tools", [tool("delete_file", description="Delete a file. Changed.")])
        self.assertEqual([record["tool"] for record in self.records("tool_description")], ["delete_all"])
        self.assertEqual([record["tool"] for record in self.records("tool_changed")], ["delete_file"])

    def test_each_hidden_name_is_reported_once(self):
        h = self.harness(Policy.from_dict(HIDING))
        for msg_id in (1, 2):
            listed(h, msg_id, "tools/list", "tools", [tool("delete_file")])
        self.assertEqual(h.warnings.getvalue().count("hid 1 tool(s)"), 1)
        self.assertEqual(len(self.records("tool_hidden")), 1)

    def test_nothing_is_hidden_without_the_setting(self):
        h = self.harness(Policy.from_dict(dict(HIDING, hide_blocked_tools=False)))
        self.assertEqual(len(listed(h, 1, "tools/list", "tools", [dict(t) for t in self.TOOLS])), 5)

    def test_nothing_is_hidden_in_monitor_mode(self):
        h = self.harness(Policy.from_dict(HIDING), monitor=True)
        self.assertEqual(len(listed(h, 1, "tools/list", "tools", [dict(t) for t in self.TOOLS])), 5)
        self.assertEqual(self.records("tool_hidden"), [])

    def test_only_tools_are_hidden(self):
        h = self.harness(Policy.from_dict(HIDING))
        self.assertEqual(names(listed(h, 1, "prompts/list", "prompts", [{"name": "delete_file"}])), ["delete_file"])


if __name__ == "__main__":
    unittest.main()
