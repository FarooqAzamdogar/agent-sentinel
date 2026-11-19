"""The MCP protocol coverage table (mcp_protocol.COVERAGE) stays in step with the proxy's code.

The table is written by hand for the documentation. These tests make sure
that every method the proxy's code treats in a way of its own has a row:
the names it keeps in constants, and every method name written in its source.
"""

import ast
import re
import unittest
from pathlib import Path

import support  # noqa: F401  (puts the project folder on sys.path)
from agent_sentinel import elicitation, mcp_protocol, mcp_proxy
from agent_sentinel.mcp_protocol import COVERAGE, HANDLINGS
from agent_sentinel.policy import PROMPTS_GET

PACKAGE = Path(mcp_proxy.__file__).parent
# The modules whose code decides what happens to a message.
PROXY_MODULES = ("mcp_proxy.py", "mcp_protocol.py", "elicitation.py", "approvers.py")
# The first part of an MCP method name; anything else with a "/" (a MIME type such as image/png) is not a method.
MCP_NAMESPACES = ("tools", "resources", "prompts", "completion", "logging", "sampling", "elicitation", "roots",
                  "notifications", "tasks", "server", "subscriptions")
METHOD = re.compile(r"(?:%s)/[A-Za-z_/*]+" % "|".join(MCP_NAMESPACES))


def rows():
    return {row.message for row in COVERAGE}


def methods_named_in_the_source():
    """Every string constant in the proxy's modules that is an MCP method name."""
    found = set()
    for name in PROXY_MODULES:
        tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and METHOD.fullmatch(node.value):
                found.add(node.value)
    return found


class TheCoverageTable(unittest.TestCase):
    def test_every_method_the_proxy_keeps_in_a_constant_has_a_row(self):
        constants = {
            *mcp_proxy._LIST_ITEMS_KEY, *mcp_proxy._RESOURCE_METHODS, PROMPTS_GET, mcp_proxy.COMPLETION_COMPLETE,
            mcp_protocol.INITIALIZE, mcp_protocol.SERVER_DISCOVER, mcp_protocol.SUBSCRIPTIONS_LISTEN,
            mcp_protocol.TASKS_METHOD_PREFIX + "*", *mcp_protocol.INPUT_METHODS, *mcp_protocol.INPUT_REQUEST_METHODS,
            *mcp_protocol.CAPABILITY_METHODS.values(), elicitation.ELICITATION_CREATE, "notifications/cancelled",
        }
        self.assertEqual(sorted(constants - rows()), [])

    def test_every_method_named_in_the_proxys_source_has_a_row(self):
        named = methods_named_in_the_source()
        self.assertIn("tools/call", named)  # the search works
        # "tasks/" is how the proxy matches every tasks method; the table writes it "tasks/*".
        named = {"tasks/*" if name == mcp_protocol.TASKS_METHOD_PREFIX else name for name in named}
        self.assertEqual(sorted(named - rows()), [])

    def test_each_row_is_complete(self):
        for row in COVERAGE:
            with self.subTest(message=row.message):
                self.assertIn(row.sender, ("client", "server", "proxy"))
                self.assertTrue(row.handling)
                self.assertTrue(set(row.handling) <= set(HANDLINGS), row.handling)
                self.assertTrue(row.revisions)
                self.assertGreater(len(row.detail), 20)

    def test_no_message_has_two_rows_from_one_side(self):
        keys = [(row.message, row.sender) for row in COVERAGE]
        self.assertEqual(len(keys), len(set(keys)))

    def test_both_eras_are_covered(self):
        revisions = {row.revisions for row in COVERAGE}
        self.assertIn(mcp_protocol.LEGACY_ONLY, revisions)
        self.assertIn(mcp_protocol.MODERN_ONLY, revisions)
        self.assertIn(mcp_protocol.ALL_REVISIONS, revisions)

    def test_what_is_always_refused_says_so(self):
        refused = {row.message for row in COVERAGE if mcp_protocol.REFUSED in row.handling}
        self.assertTrue({"tasks/*", "JSON-RPC batch"} <= refused)


if __name__ == "__main__":
    unittest.main()
