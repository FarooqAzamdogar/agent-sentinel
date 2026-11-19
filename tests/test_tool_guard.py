"""The guard() decorator (agent_sentinel/tool_guard.py)."""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import typing

from cli_support import TempFolderTest
from support import INJECTION, REF_SUFFIX
from agent_sentinel import BlockedError, Firewall, Policy
from agent_sentinel.tool_guard import guard

POLICY = {
    "default": "block",
    "tools": {
        "read_file": {"action": "allow", "allow_args": [
            {"arg": "path", "pattern": r"notes/[a-z]+\.txt"},
            {"arg": "limit", "pattern": "[0-9]{1,3}"},
        ]},
        "fetch": "allow",
        "files.read": "allow",
        "search": "allow",
    },
}


class Note:
    """A type used in an annotation, to check that type hints still resolve after guarding."""


class GuardTest(TempFolderTest):
    def setUp(self):
        super().setUp()
        self.audit = self.folder / "audit.jsonl"
        self.firewall = Firewall(Policy.from_dict(POLICY), self.audit)
        self.ran = []

    def records(self):
        return [json.loads(line) for line in self.audit.read_text(encoding="utf-8").splitlines()]

    def read_file_tool(self, **options):
        @guard(self.firewall, **options)
        def read_file(path: str, limit: int = 10) -> Note:
            """Read the start of a note."""
            self.ran.append((path, limit))
            return f"{limit} lines of {path}"

        return read_file


class KeepingWhatFrameworksRead(GuardTest):
    def test_the_name_docstring_signature_and_type_hints_are_kept(self):
        def read_file(path: str, limit: int = 10) -> Note:
            """Read the start of a note."""

        guarded = self.read_file_tool()
        self.assertEqual(guarded.__name__, "read_file")
        self.assertEqual(inspect.getdoc(guarded), "Read the start of a note.")
        self.assertEqual(inspect.signature(guarded), inspect.signature(read_file))
        # With `from __future__ import annotations` the hints are strings; they resolve in the original's module.
        self.assertEqual(typing.get_type_hints(guarded), {"path": str, "limit": int, "return": Note})

    def test_an_async_tool_stays_an_async_function(self):
        @guard(self.firewall)
        async def fetch(url: str) -> str:
            return "page"

        self.assertTrue(inspect.iscoroutinefunction(fetch))
        self.assertEqual(asyncio.run(fetch("https://example.com")), "page")


class CheckingEveryCall(GuardTest):
    def test_the_policy_sees_every_argument_by_name_with_its_default(self):
        read_file = self.read_file_tool()
        self.assertEqual(read_file("notes/todo.txt"), "10 lines of notes/todo.txt")
        self.assertEqual(read_file(limit=3, path="notes/todo.txt"), "3 lines of notes/todo.txt")
        self.assertEqual([record["args"] for record in self.records() if record["event"] == "call"],
                         [{"path": "notes/todo.txt", "limit": 10}, {"path": "notes/todo.txt", "limit": 3}])

    def test_a_blocked_call_raises_and_the_function_never_runs(self):
        read_file = self.read_file_tool()
        for args in (("../secret.txt",), ("notes/todo.txt", 5000)):
            with self.subTest(args=args), self.assertRaises(BlockedError) as caught:
                read_file(*args)
            self.assertRegex(str(caught.exception), REF_SUFFIX)
        self.assertEqual(self.ran, [])

    def test_with_on_block_return_the_model_gets_the_public_text(self):
        read_file = self.read_file_tool(on_block="return")
        text = read_file("../secret.txt")
        self.assertRegex(text, r"^argument 'path' has a value the policy does not permit \(ref [0-9a-f]{8}\)$")
        self.assertEqual(self.ran, [])

    def test_an_allowed_call_returns_the_result_itself_never_a_text_about_the_policy(self):
        self.assertEqual(self.read_file_tool(on_block="return")("notes/a.txt", 1), "1 lines of notes/a.txt")

    def test_what_the_tool_returns_is_scanned(self):
        @guard(self.firewall)
        def search(query: str) -> str:
            return INJECTION

        with self.assertRaises(BlockedError) as caught:
            search("x")
        self.assertIn("possible prompt injection", str(caught.exception))
        self.assertEqual(caught.exception.decision.rule, "injection")
        returned = guard(self.firewall, on_block="return")(search.__wrapped__)("x")
        self.assertRegex(returned, r"^possible prompt injection; the content was withheld \(ref [0-9a-f]{8}\)$")

    def test_the_text_of_an_error_the_tool_raises_is_scanned(self):
        @guard(self.firewall)
        def search(query: str) -> str:
            raise RuntimeError(INJECTION)

        with self.assertRaises(BlockedError):
            search("x")

    def test_an_async_tool_is_checked_the_same_way(self):
        @guard(self.firewall, on_block="return")
        async def fetch(url: str) -> str:
            return INJECTION

        self.assertIn("possible prompt injection", asyncio.run(fetch("https://example.com")))

        @guard(self.firewall)
        async def not_allowed(url: str) -> str:
            self.ran.append(url)
            return "page"

        with self.assertRaises(BlockedError):
            asyncio.run(not_allowed("https://example.com"))
        self.assertEqual(self.ran, [])

    def test_a_call_that_does_not_fit_the_signature_fails_as_usual_and_is_not_logged(self):
        read_file = self.read_file_tool()
        with self.assertRaises(TypeError):
            read_file()
        with self.assertRaises(TypeError):
            read_file("notes/a.txt", nonsense=1)
        self.assertFalse(self.audit.exists())

    def test_the_tool_can_be_given_another_name(self):
        @guard(self.firewall, name="files.read")
        def read(path: str) -> str:
            return "ok"

        self.assertEqual(read("x"), "ok")
        self.assertEqual(self.records()[0]["tool"], "files.read")

    def test_a_bound_method_is_guarded_without_its_self(self):
        class Notes:
            def search(self, query: str) -> str:
                return f"found {query}"

        search = guard(self.firewall)(Notes().search)
        self.assertEqual(search("x"), "found x")
        self.assertEqual(self.records()[0]["args"], {"query": "x"})


class RefusingWhatCannotBeChecked(GuardTest):
    def test_functions_that_do_not_name_every_argument_are_refused(self):
        def star_args(*paths):
            pass

        def star_kwargs(path, **options):
            pass

        def positional_only(path, /):
            pass

        for function, message in ((star_args, r"\*paths"), (star_kwargs, r"\*\*options"),
                                  (positional_only, "positional-only")):
            with self.subTest(function=function.__name__), self.assertRaisesRegex(TypeError, message):
                guard(self.firewall)(function)

    def test_generators_are_refused(self):
        def lines(path: str):
            yield "a"

        async def pages(url: str):
            yield "a"

        for function in (lines, pages):
            with self.subTest(function=function.__name__), self.assertRaisesRegex(TypeError, "generator"):
                guard(self.firewall)(function)

    def test_a_tool_without_a_name_needs_one(self):
        with self.assertRaisesRegex(TypeError, "name="):
            guard(self.firewall)(lambda path: path)
        with self.assertRaisesRegex(TypeError, "name="):
            guard(self.firewall)(functools.partial(lambda path, limit: path, limit=1))
        self.assertEqual(guard(self.firewall, name="search")(lambda query: "ok")(query="x"), "ok")

    def test_wrong_options_are_refused_when_the_decorator_is_made(self):
        with self.assertRaises(TypeError):
            guard(Policy.from_dict(POLICY))
        with self.assertRaises(ValueError):
            guard(self.firewall, on_block="ignore")
        for name in ("", "  ", 5):
            with self.subTest(name=name), self.assertRaises(ValueError):
                guard(self.firewall, name=name)
        with self.assertRaises(TypeError):
            guard(self.firewall)("not a function")
