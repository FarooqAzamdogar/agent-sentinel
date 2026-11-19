"""The framework recipes in examples/, run against small stand-ins for the frameworks.

The stand-ins do only what the recipes rely on, as the frameworks document
it. They cannot notice when a framework changes, which is why the recipes are
labelled best effort.
"""

import ast
import asyncio
import dataclasses
import importlib.util
import inspect
import json
import sys
import types
import typing
from pathlib import Path
from unittest import mock

from cli_support import TempFolderTest
from support import INJECTION, ROOT
from agent_sentinel import Firewall, Policy

EXAMPLES = ROOT / "examples"
EVENTS = Path(__file__).resolve().parent / "claude_code_events"


def load_example(file_name, stand_ins):
    """Import an example with stand-in modules in place of the framework it imports."""
    with mock.patch.dict(sys.modules, stand_ins):
        spec = importlib.util.spec_from_file_location(f"recipe_{Path(file_name).stem}", EXAMPLES / file_name)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


# ---- a stand-in for the Claude Agent SDK (claude_agent_sdk) ---------------------------------------

@dataclasses.dataclass
class HookMatcher:
    matcher: typing.Optional[str] = None
    hooks: list = dataclasses.field(default_factory=list)
    timeout: typing.Optional[float] = None
    on_failure: typing.Optional[str] = None


class ClaudeAgentOptions:
    def __init__(self, hooks=None, **options):
        self.hooks = hooks
        self.options = options


def claude_agent_sdk_stand_in():
    module = types.ModuleType("claude_agent_sdk")
    module.HookMatcher = HookMatcher
    module.ClaudeAgentOptions = ClaudeAgentOptions
    module.ClaudeSDKClient = object
    return {"claude_agent_sdk": module}


class ClaudeAgentSdkRecipe(TempFolderTest):
    def setUp(self):
        super().setUp()
        self.recipe = load_example("claude_agent_sdk_hooks.py", claude_agent_sdk_stand_in())
        policy = self.write("policy.json", {"default": "block", "tools": {"Bash": "allow", "mcp__github__*": "allow"}})
        self.options = self.recipe.sentinel_options(str(policy), str(self.folder / "audit.jsonl"),
                                                    permission_mode="default")

    def callback(self, event_name):
        (matcher,) = self.options.hooks[event_name]
        (callback,) = matcher.hooks
        return callback

    def event(self, name, **changes):
        return {**json.loads((EVENTS / name).read_text(encoding="utf-8")), **changes}

    def test_every_tool_event_gets_a_matcher_that_blocks_when_its_callback_fails(self):
        self.assertEqual(set(self.options.hooks), {"PreToolUse", "PostToolUse", "PostToolUseFailure"})
        for matchers in self.options.hooks.values():
            (matcher,) = matchers
            self.assertEqual((matcher.matcher, matcher.on_failure), (None, "block"))
            self.assertTrue(inspect.iscoroutinefunction(matcher.hooks[0]))
        self.assertEqual(self.options.options, {"permission_mode": "default"})

    def test_the_callbacks_answer_as_the_sdk_documents(self):
        pre = self.callback("PreToolUse")
        self.assertEqual(asyncio.run(pre(self.event("pre_tool_use_bash.json"), "toolu_01ABC123", {"signal": None})),
                         {})
        denied = asyncio.run(pre(self.event("pre_tool_use_mcp.json"), "toolu_01MAIL", {"signal": None}))
        self.assertEqual(denied["hookSpecificOutput"]["permissionDecision"], "deny")
        post = self.callback("PostToolUse")
        withheld = asyncio.run(post(self.event("post_tool_use_mcp.json"), "toolu_01ISSUE", {"signal": None}))
        self.assertNotIn(INJECTION, json.dumps(withheld))
        self.assertEqual(withheld["decision"], "block")


# ---- a stand-in for LangChain's @tool (langchain_core.tools.tool) -----------------------------------

class StructuredTool:
    """What @tool builds: a name, a description and an argument schema read from the function."""

    def __init__(self, function):
        self.name = function.__name__
        self.description = inspect.getdoc(function)
        self.arguments = list(inspect.signature(function).parameters)
        self.hints = typing.get_type_hints(function)
        self.function = function

    def invoke(self, arguments):
        return self.function(**arguments)

    async def ainvoke(self, arguments):
        return await self.function(**arguments)


def langchain_stand_in():
    package = types.ModuleType("langchain_core")
    tools = types.ModuleType("langchain_core.tools")
    tools.tool = StructuredTool
    package.tools = tools
    return {"langchain_core": package, "langchain_core.tools": tools}


# The rule from the recipe's docstring, as a person would copy it into a policy.
NOTES_POLICY = {
    "default": "block",
    "tools": {
        "read_note": {"action": "allow", "allow_args": [
            {"arg": "name", "pattern": "[A-Za-z0-9_-]+\\.txt"},
            {"arg": "max_chars", "pattern": "[0-9]{1,5}"}]},
        "search_notes": "allow",
    },
}


class LangChainRecipe(TempFolderTest):
    def setUp(self):
        super().setUp()
        recipe = load_example("langchain_guarded_tools.py", langchain_stand_in())
        self.notes = self.folder / "notes"
        self.notes.mkdir()
        (self.notes / "todo.txt").write_text("buy milk", encoding="utf-8")
        (self.notes / "trap.txt").write_text(INJECTION, encoding="utf-8")
        (self.folder / "secret.txt").write_text("the secret", encoding="utf-8")
        self.firewall = Firewall(Policy.from_dict(NOTES_POLICY))
        self.read_note, self.search_notes = recipe.make_tools(self.firewall, self.notes)

    def test_langchain_reads_the_original_name_description_and_arguments(self):
        self.assertEqual((self.read_note.name, self.search_notes.name), ("read_note", "search_notes"))
        self.assertEqual(self.read_note.description, "Read one note from the notes folder and return its text.")
        self.assertEqual(self.read_note.arguments, ["name", "max_chars"])
        self.assertEqual(self.read_note.hints, {"name": str, "max_chars": int, "return": str})

    def test_allowed_calls_run(self):
        self.assertEqual(self.read_note.invoke({"name": "todo.txt"}), "buy milk")
        self.assertEqual(asyncio.run(self.search_notes.ainvoke({"query": "milk"})), "todo.txt")

    def test_a_refused_call_or_an_injected_note_gives_the_model_a_short_text(self):
        refused = self.read_note.invoke({"name": "../secret.txt"})
        self.assertRegex(refused, r"^argument 'name' has a value the policy does not allow \(ref [0-9a-f]{8}\)$")
        withheld = self.read_note.invoke({"name": "trap.txt"})
        self.assertRegex(withheld, r"^possible prompt injection; the content was withheld \(ref [0-9a-f]{8}\)$")

    def test_the_recipes_policy_rule_is_the_one_its_docstring_shows(self):
        docstring = ast.get_docstring(ast.parse((EXAMPLES / "langchain_guarded_tools.py").read_text(encoding="utf-8")))
        start = docstring.index('"read_note": {')
        end = docstring.index("]}", start) + 2
        written = json.loads("{" + docstring[start:end] + "}")
        self.assertEqual(written["read_note"], NOTES_POLICY["tools"]["read_note"])
