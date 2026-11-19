"""The corpus in tests/attack_corpus: real harmless tool metadata, and published attacks.

benign_tool_metadata.json holds tool, parameter, prompt and resource
descriptions and server instructions copied from popular public MCP servers,
each with the repository, commit and line it came from. None of them may be
high in any way the proxy reads them: a high finding in a tool description
removes the tool for the life of the proxy.

tool_poisoning.json holds the published attacks, written in our own words
with the same moves, and what the firewall must find in each. Entries whose
expectation is "nothing found" are known misses, kept so the coverage stays
honest.
"""

import json
import unittest
from pathlib import Path

import support  # noqa: F401  (sets up the import path)
from agent_sentinel import Firewall, Policy
from agent_sentinel.detector import max_severity

CORPUS = Path(__file__).resolve().parent / "attack_corpus"
BENIGN = json.loads((CORPUS / "benign_tool_metadata.json").read_text(encoding="utf-8"))
ATTACKS = json.loads((CORPUS / "tool_poisoning.json").read_text(encoding="utf-8"))

# Tool names a policy might give for OTHER servers, passed as foreign tools while
# the harmless descriptions are read. Plain words ("search") and snake_case names
# ("read_file") both appear in the descriptions as ordinary words or as the
# server's own tools, and must not make anything high.
FOREIGN = ["send_email", "read_file", "create_issue", "delete_file", "search", "fetch", "list", "get", "query"]


def firewall():
    return Firewall(Policy.from_dict({"default": "allow"}))


def readings(entry):
    """Every way the proxy can read one harmless text: (label, content, event)."""
    text = entry["text"]
    as_parameter = {
        "name": entry["tool"] or "tool",
        "description": "Does one thing.",
        "inputSchema": {"type": "object", "properties": {"value": {"type": "string", "description": text}}},
    }
    return [
        ("tool description", {"name": entry["tool"] or "tool", "description": text}, "tool_description"),
        ("parameter description", as_parameter, "tool_description"),
        ("server instructions", text, "server_instructions"),
        ("list entry", {"name": "entry", "description": text}, "list_item"),
        ("tool result", text, "result"),
    ]


class TheBenignSet(unittest.TestCase):
    def test_it_holds_at_least_fifty_real_tool_descriptions_from_many_servers(self):
        tools = [entry for entry in BENIGN["texts"] if entry["kind"] == "tool"]
        self.assertGreaterEqual(len(tools), 50)
        repositories = {source["repository"] for source in BENIGN["sources"].values()}
        for wanted in ("modelcontextprotocol/servers", "github/github-mcp-server", "microsoft/playwright",
                       "upstash/context7"):
            self.assertIn(f"https://github.com/{wanted}", repositories)

    def test_every_text_names_the_file_and_commit_it_was_copied_from(self):
        for number, source in BENIGN["sources"].items():
            with self.subTest(source=number):
                self.assertRegex(source["commit"], r"\A[0-9a-f]{40}\Z")
                self.assertEqual(
                    source["url"], f"{source['repository']}/blob/{source['commit']}/{source['path']}"
                )
        for entry in BENIGN["texts"]:
            self.assertIn(entry["source"], BENIGN["sources"])
            self.assertIsInstance(entry["line"], int)
            self.assertTrue(entry["text"].strip())

    def test_no_harmless_text_is_high_however_the_proxy_reads_it(self):
        guard = firewall()
        for entry in BENIGN["texts"]:
            for label, content, event in readings(entry):
                decision = guard.scan_result("t", content, event=event, foreign_tools=FOREIGN)
                worst = max_severity(decision.findings)
                if worst == "high":
                    source = BENIGN["sources"][entry["source"]]["url"]
                    self.fail(f"{label} from {source}#L{entry['line']} is high: {decision.findings}")

    def test_warnings_on_harmless_texts_stay_rare(self):
        # Preference and ordering wording is medium or low by design (real servers
        # write "Always call this tool when ..."), but it must stay the exception.
        guard = firewall()
        warned = []
        for entry in BENIGN["texts"]:
            decision = guard.scan_result("t", {"name": "t", "description": entry["text"]}, event="tool_description")
            if max_severity(decision.findings) == "medium":
                warned.append(entry["text"][:60])
        self.assertLessEqual(len(warned), len(BENIGN["texts"]) // 100, warned)

    def test_tool_results_with_these_texts_have_no_findings_at_all(self):
        guard = firewall()
        for entry in BENIGN["texts"]:
            self.assertEqual(guard.scan_result("t", entry["text"]).findings, [], entry["text"][:80])


class PublishedAttacks(unittest.TestCase):
    def test_each_attack_gets_the_findings_it_should(self):
        guard = firewall()
        for case in ATTACKS["cases"]:
            with self.subTest(case=case["id"]):
                decision = guard.scan_result(
                    "t", case["content"], event=case["event"], foreign_tools=case.get("foreign_tools", ())
                )
                found = {finding.rule for finding in decision.findings}
                self.assertEqual(max_severity(decision.findings), case["expect"]["worst"], decision.findings)
                self.assertLessEqual(set(case["expect"]["rules"]), found)

    def test_each_high_attack_is_blocked_and_the_rest_are_let_through(self):
        guard = firewall()
        for case in ATTACKS["cases"]:
            with self.subTest(case=case["id"]):
                decision = guard.scan_result(
                    "t", case["content"], event=case["event"], foreign_tools=case.get("foreign_tools", ())
                )
                self.assertEqual(decision.allowed, case["expect"]["worst"] != "high")

    def test_every_attack_names_its_source(self):
        for case in ATTACKS["cases"]:
            with self.subTest(case=case["id"]):
                self.assertTrue(case["source"].startswith("https://"))
                self.assertTrue(case["about"])
        ids = [case["id"] for case in ATTACKS["cases"]]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
