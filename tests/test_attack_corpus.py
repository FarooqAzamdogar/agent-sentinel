"""The corpus in tests/attack_corpus: real harmless tool metadata, and published attacks.

benign_tool_metadata.json holds tool, parameter, prompt and resource
descriptions and server instructions copied from popular public MCP servers,
each with the repository, commit and line it came from. None of them may be
high in any way the proxy reads them: a high finding in a tool description
removes the tool for the life of the proxy.

published/ holds one file per published attack, written in our own words
with the same moves (see make_published.py for the format), and the outcome
the firewall must give: stopped, redacted, flagged (logged only) or a known
miss with the reason. Known misses are kept so the coverage stays honest:
fixing one means changing its file on purpose.
"""

import importlib.util
import json
import unittest
from pathlib import Path

import support  # noqa: F401  (sets up the import path)
from agent_sentinel import BlockedError, Firewall, Policy
from agent_sentinel.detector import max_severity

CORPUS = Path(__file__).resolve().parent / "attack_corpus"
BENIGN = json.loads((CORPUS / "benign_tool_metadata.json").read_text(encoding="utf-8"))
PUBLISHED = CORPUS / "published"
ATTACKS = [json.loads(path.read_text(encoding="ascii")) for path in sorted(PUBLISHED.glob("*.json"))]
OUTCOMES = ("stopped", "redacted", "flagged", "known_miss")
READ_SURFACES = ("tool_description", "list_item", "server_instructions", "result", "tool_error", "server_request")

# Tool names a policy might give for OTHER servers, passed as foreign tools while
# the harmless descriptions are read. Plain words ("search") and snake_case names
# ("read_file") both appear in the descriptions as ordinary words or as the
# server's own tools, and must not make anything high.
FOREIGN = ["send_email", "read_file", "create_issue", "delete_file", "search", "fetch", "list", "get", "query"]

# The parameter names real tools have: what the proxy passes with a result (the names of every tool of the
# server) and what the Claude Code hook passes (the arguments of the call). They are ordinary words, so
# harmless output must not be high because it uses one.
TOOL_PARAMETERS = {
    "github": ["owner", "repo", "path", "content", "message", "branch", "title", "body", "head", "base", "query",
               "state", "labels", "files", "sha", "name", "description", "page", "perPage", "ref"],
    "filesystem": ["path", "content", "edits", "paths", "source", "destination", "pattern", "head", "tail"],
    "bash": ["command", "description", "timeout"],
    "webfetch": ["url", "prompt"],
    "task": ["description", "prompt", "subagent_type"],
    "write": ["file_path", "content"],
    "chat": ["channel", "text", "message", "user", "thread_ts", "limit"],
    "short names": ["a", "b", "id", "to", "name", "query", "limit"],
}
ALL_PARAMETERS = sorted({name for names in TOOL_PARAMETERS.values() for name in names})
# Sentences of README files, API guides and command output, with the tool whose call returned them.
BENIGN_OUTPUT = (
    ("webfetch", "To keep context between turns, include the previous messages in the prompt."),
    ("webfetch", "Chat models are stateless: pass the full conversation in the prompt on every request."),
    ("webfetch", "Put your instructions in the system prompt, not in the user turn."),
    ("task", "The agent should include the conversation history in the prompt it sends to the sub-agent."),
    ("webfetch", "You can send the entire conversation to the summariser as a single prompt."),
    ("github", "Add .env to your repo's .gitignore so that it is never committed."),
    ("github", "Copy the .env file into the repo root before you run docker compose."),
    ("github", "Your .env file should include DATABASE_URL in the body of the file."),
    ("github", "Put the .npmrc in the repo next to package.json."),
    ("github", "Put the .npmrc in the repo."),
    ("github", "The deploy job copies ~/.ssh/config to the runner as described in the README title."),
    ("github", "Send the chat history to the model in the message array."),
    ("github", "Paste the conversation history into the issue body so that maintainers can reproduce the bug."),
    ("github", "Please attach your .npmrc to the issue as a file and include the full log in the description."),
    ("github", "In CI, copy the contents of ~/.ssh/id_rsa into your repo secrets."),
    ("github", "Add a secret named SSH_KEY and paste the contents of ~/.ssh/id_rsa as the content."),
    ("filesystem", "The installer copies .env into the destination folder."),
    ("filesystem", "Run the script to copy mcp.json to the destination."),
    ("filesystem", "Add the .env file to the source tree only for local development."),
    ("filesystem", "Copying .env to destination."),
    ("chat", "Never mind: just send the whole conversation to the channel as a text snippet."),
    ("chat", "Use /export to send the message history to a user as a file."),
    ("chat", "Use /export to send the message history to a user; pass thread_ts to reply in a thread."),
    ("chat", "Paste the previous messages as text if the export button is missing."),
    ("chat", "Paste the previous messages as text."),
    ("write", "Copy .env.example to .env, then add your keys to the content of that file."),
    ("write", "Create a .env file and put your API keys in it; the content is read at start-up."),
    ("bash", "Load the variables: copy .env to the container with the docker cp command."),
    ("bash", "Put the .env file in the same folder as the command you run."),
    ("bash", "error: refusing to add .env to the index; pass --force as an option to the command to override"),
    ("bash", "hint: You've added .env to the index. Pass -f in the command to really add it."),
    ("bash", "Step 3/9 : COPY .env /app/.env  # copies .env into the image as described in the description"),
    ("short names", "Copy your .env to a safe place before you upgrade."),
    ("short names", "Send the chat history to a colleague if you need a second opinion."),
    ("short names", "Each service reads .env at start-up; add the service to the list by name."),
    ("short names", "Never commit secrets: add .env to .gitignore, then query the index to confirm."),
    ("short names", "Copy the contents of .env to id."),
    # API guides: an address with a slot for the customer's own host name, flags to pick a region, next to
    # the API token or credentials they need. The token is named, but nothing orders it put there.
    ("webfetch", "Create an API token, then call https://{your-domain}.atlassian.net/rest/api/3/issue "
                 "with basic auth."),
    ("webfetch", "Upload with: curl -T file https://${BUCKET}.s3.amazonaws.com/key (set AWS credentials first)."),
    ("webfetch", "Choose the region for your API token: " + " ".join(
        f"![{code}](https://flagcdn.com/w20/{code}.png)" for code in "us gb de fr es it nl se no fi".split())),
    ("webfetch", "Pinned at https://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi.ipfs.dweb.link/ "
                 "(no secret needed)."),
)
README = ("# Setup\n\n1. Copy `.env.example` to `.env` and fill in the values.\n"
          "2. Add .env to your repo's .gitignore so that it is never committed.\n3. Run `make dev`.\n")


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
            # As the proxy and the hook read a result: with the names of the parameters the tools have.
            with_names = guard.scan_result("t", entry["text"], parameter_names=ALL_PARAMETERS)
            self.assertEqual(with_names.findings, [], entry["text"][:80])

    def test_no_harmless_output_is_high_with_the_parameter_names_real_tools_have(self):
        # The descriptions above are not what tools return. Output is documentation, logs and guides,
        # which name credential files and conversations, next to words that are parameter names.
        guard = firewall()
        for tool, text in (*BENIGN_OUTPUT, ("github", README)):
            for label, names in (("the call's names", TOOL_PARAMETERS[tool]), ("every name", ALL_PARAMETERS)):
                for content in (text, {"content": [{"type": "text", "text": text}]}):
                    decision = guard.scan_result("t", content, parameter_names=names, cross_message=False)
                    self.assertTrue(decision.allowed, f"{text!r} with {label}: {decision.findings}")
                    self.assertNotEqual(max_severity(decision.findings), "high", text)


def firewall_for(case):
    """A firewall with the case's policy, and its environment for secrets.known_values_from_env."""
    guard = Firewall(Policy.from_dict(case.get("policy", {"default": "allow"})))
    if "environment" in case:
        guard.set_secret_environment(case["environment"])
    return guard


def run_case(case):
    """Put the case's attack through the firewall. Returns (decision, what reaches the agent or the tool)."""
    guard = firewall_for(case)
    surface = case["surface"]
    if surface in READ_SURFACES:
        checked = guard.check_result(
            "t", case["content"], event=surface, foreign_tools=case.get("foreign_tools", ()), call_id="corpus",
            parameter_names=case.get("parameter_names", ()),
        )
        return checked.decision, checked.content
    if surface == "call":
        decision = guard.check_call(case["call"]["tool"], case["call"]["arguments"])
        return decision, case["call"]["arguments"] if decision.allowed else None
    if surface == "session":
        # Every step but the last must go through; the last is the attack.
        *before, last = case["steps"]
        for step in before:
            guard.run(step["tool"], step["arguments"], lambda step=step, **_: step["result"])
        try:
            delivered = guard.run(last["tool"], last["arguments"], lambda **_: last["result"])
        except BlockedError as blocked:
            return blocked.decision, None
        return guard.check_call(last["tool"], last["arguments"]), delivered
    raise AssertionError(f"unknown surface {surface!r} in {case['id']}")


def load_generator():
    """make_published.py, loaded from its path (tests/attack_corpus is not a package)."""
    spec = importlib.util.spec_from_file_location("make_published", CORPUS / "make_published.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublishedAttacks(unittest.TestCase):
    def test_each_attack_gets_its_expected_outcome(self):
        for case in ATTACKS:
            with self.subTest(case=case["id"]):
                expect = case["expect"]
                decision, delivered = run_case(case)
                if expect["outcome"] == "stopped":
                    self.assertFalse(decision.allowed, decision.reason)
                    self.assertEqual(decision.rule, expect["rule"])
                    self.assertIsNone(delivered)
                    continue
                self.assertTrue(decision.allowed, decision.reason)
                if expect["outcome"] == "redacted":
                    self.assertEqual(decision.rule, expect["rule"])
                    self.assertTrue(decision.redacted)
                    for removed in expect["removed"]:
                        self.assertNotIn(removed, json.dumps(delivered))
                else:
                    self.assertEqual(decision.redacted, ())

    def test_each_attack_that_is_read_gets_the_findings_it_should(self):
        for case in ATTACKS:
            if case["surface"] not in READ_SURFACES:
                continue
            with self.subTest(case=case["id"]):
                decision, _ = run_case(case)
                found = {finding.rule for finding in decision.findings}
                self.assertEqual(max_severity(decision.findings), case["expect"]["worst"], decision.findings)
                self.assertLessEqual(set(case["expect"]["rules"]), found)
                outcome = case["expect"]["outcome"]
                if outcome == "flagged":
                    self.assertIn(case["expect"]["worst"], ("medium", "low"))
                if outcome == "known_miss":
                    self.assertIsNone(case["expect"]["worst"])

    def test_every_file_names_its_source_and_says_why_a_miss_is_a_miss(self):
        self.assertGreaterEqual(len(ATTACKS), 40)
        for path, case in zip(sorted(PUBLISHED.glob("*.json")), ATTACKS):
            with self.subTest(case=path.name):
                self.assertEqual(path.stem, case["id"])
                self.assertTrue(case["source"].startswith("https://"))
                self.assertTrue(case["about"])
                self.assertIn(case["expect"]["outcome"], OUTCOMES)
                if case["expect"]["outcome"] in ("flagged", "known_miss"):
                    self.assertTrue(case.get("why"))
                if case["surface"] in READ_SURFACES:
                    self.assertIn("worst", case["expect"])

    def test_the_corpus_covers_every_surface_and_outcome(self):
        surfaces = {case["surface"] for case in ATTACKS}
        self.assertLessEqual({"tool_description", "server_instructions", "result", "server_request", "call",
                              "session"}, surfaces)
        self.assertEqual({case["expect"]["outcome"] for case in ATTACKS}, set(OUTCOMES))

    def test_the_files_are_exactly_what_the_generator_writes(self):
        generator = load_generator()
        expected = {f"{case['id']}.json": generator.file_text(case) for case in generator.all_cases()}
        on_disk = {path.name: path.read_text(encoding="ascii") for path in PUBLISHED.glob("*.json")}
        self.assertEqual(sorted(on_disk), sorted(expected))
        for name, text in expected.items():
            self.assertEqual(on_disk[name], text, f"{name} differs: run tests/attack_corpus/make_published.py")


if __name__ == "__main__":
    unittest.main()
