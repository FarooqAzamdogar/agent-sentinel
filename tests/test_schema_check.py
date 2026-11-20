"""Tests for schema_check.py (the validator, remote references, the store) and the policy's schema_checks."""

import time
import unittest

import support  # noqa: F401  (puts the project folder on sys.path)
from agent_sentinel import Policy, PolicyError, fix_hints, templates
from agent_sentinel import schema_check
from agent_sentinel.policy import SchemaChecks
from agent_sentinel.schema_check import SchemaStore, remote_refs, validate

SECRET = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0" + "P1o2N3m4L5k6J7i8"


class TheValidator(unittest.TestCase):
    SCHEMA = {
        "type": "object",
        "properties": {
            "path": {"type": "string", "minLength": 1, "maxLength": 20},
            "count": {"type": "integer", "minimum": 1, "maximum": 10},
            "mode": {"enum": ["read", "write"]},
            "ratio": {"type": "number", "exclusiveMinimum": 0, "exclusiveMaximum": 1},
            "tags": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 3},
            "flag": {"const": True},
            "nested": {"type": "object", "properties": {"x": {"type": ["integer", "null"]}},
                       "additionalProperties": False},
        },
        "required": ["path"],
        "additionalProperties": False,
    }

    def test_arguments_that_match_have_no_problems(self):
        good = {"path": "a.txt", "count": 3, "mode": "read", "ratio": 0.5, "tags": ["x"], "flag": True,
                "nested": {"x": None}}
        self.assertEqual(validate(good, self.SCHEMA), [])
        self.assertEqual(validate({"path": "a", "count": 3.0}, self.SCHEMA), [])  # 3.0 is an integer in JSON Schema

    def test_each_keyword_is_checked(self):
        for arguments, expected in (
            ({}, "missing the required property 'path'"),
            ({"path": ""}, "fewer than 1 characters"),
            ({"path": "x" * 21}, "more than 20 characters"),
            ({"path": 5}, "is an integer, not string"),
            ({"path": "a", "count": 0}, "below the minimum (1)"),
            ({"path": "a", "count": 11}, "above the maximum (10)"),
            ({"path": "a", "count": 2.5}, "is a number, not integer"),
            ({"path": "a", "count": True}, "is true or false, not integer"),
            ({"path": "a", "mode": "delete"}, "not one of the 2 value(s)"),
            ({"path": "a", "ratio": 0}, "not above 0 (exclusiveMinimum)"),
            ({"path": "a", "ratio": 1}, "not below 1 (exclusiveMaximum)"),
            ({"path": "a", "tags": []}, "fewer than 1 items"),
            ({"path": "a", "tags": ["a", "b", "c", "d"]}, "more than 3 items"),
            ({"path": "a", "tags": ["a", 2]}, "tags[1] is an integer, not string"),
            ({"path": "a", "flag": 1}, "not the value the schema requires"),
            ({"path": "a", "nested": {"x": "no"}}, "nested.x is text, not integer or null"),
            ({"path": "a", "nested": {"y": 1}}, "nested has a property the schema does not allow: 'y'"),
            ({"path": "a", "extra": 1}, "has a property the schema does not allow: 'extra'"),
        ):
            with self.subTest(arguments=arguments):
                problems = validate(arguments, self.SCHEMA, root="the arguments")
                self.assertTrue(problems)
                self.assertIn(expected, " ".join(problems))
                self.assertTrue(all(problem.startswith("the arguments") for problem in problems))

    def test_problems_never_hold_the_value(self):
        problems = validate({"path": SECRET, "count": SECRET, "mode": SECRET, "extra": SECRET}, self.SCHEMA)
        self.assertTrue(problems)
        self.assertNotIn(SECRET, " ".join(problems))

    def test_json_equality_tells_true_from_one(self):
        self.assertTrue(validate(1, {"enum": [True]}))
        self.assertTrue(validate(True, {"const": 1}))
        self.assertEqual(validate(1, {"const": 1.0}), [])
        self.assertEqual(validate({"a": [1, {"b": None}]}, {"const": {"a": [1, {"b": None}]}}), [])
        self.assertTrue(validate({"a": [1, {"b": None}]}, {"const": {"a": [1, {"b": False}]}}))

    def test_draft_04_exclusive_bounds_are_read(self):
        schema = {"minimum": 0, "exclusiveMinimum": True, "maximum": 5, "exclusiveMaximum": False}
        self.assertTrue(validate(0, schema))
        self.assertEqual(validate(5, schema), [])

    def test_boolean_schemas_and_additional_properties_as_a_schema(self):
        self.assertTrue(validate(1, False))
        self.assertEqual(validate(1, True), [])
        schema = {"type": "object", "properties": {"a": {}}, "additionalProperties": {"type": "integer"}}
        self.assertEqual(validate({"a": "x", "b": 2}, schema), [])
        self.assertIn("b is text, not integer", " ".join(validate({"b": "no"}, schema)))

    def test_unknown_keywords_and_malformed_values_are_ignored(self):
        schema = {"type": "object", "properties": {"a": {"$ref": "#/$defs/x", "format": "email",
                                                         "pattern": "(a+)+$", "minimum": "5", "type": "any"}},
                  "$defs": {"x": {"type": "integer"}}, "if": {}, "then": False}
        self.assertEqual(validate({"a": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"}, schema), [])

    def test_pattern_properties_are_never_run_so_additional_properties_are_not_checked(self):
        schema = {"type": "object", "patternProperties": {"^(a+)+$": {}}, "additionalProperties": False}
        self.assertEqual(validate({"anything": 1}, schema), [])

    def test_a_part_nested_too_deeply_to_check_is_a_problem(self):
        schema = value = None
        for _ in range(20):
            schema = {"type": "object", "properties": {"a": schema if schema is not None else {"type": "integer"}}}
            value = {"a": value if value is not None else "no"}
        problems = validate(value, schema)
        self.assertTrue(any("too deep to check" in problem for problem in problems), problems)
        # Deep nesting the schema says nothing about is not a problem.
        self.assertEqual(validate(value, {"type": "object"}), [])

    def test_hostile_input_stays_fast_and_too_much_work_is_a_problem(self):
        cases = (
            ([0] * 1_000_000, {"type": "array", "items": {"type": "integer"}}),
            ({str(i): i for i in range(500_000)}, {"type": "object", "additionalProperties": {"type": "integer"}}),
            ("x", {"enum": [["y"] * 1000] * 1000}),
            ([[0] * 1000] * 1000, {"const": [[0] * 1000] * 1000}),
            ({"a": 1}, {"required": ["b"] * 1_000_000}),
        )
        for value, schema in cases:
            with self.subTest(schema=str(schema)[:60]):
                started = time.perf_counter()
                problems = validate(value, schema)
                self.assertLess(time.perf_counter() - started, 2.0)
                self.assertTrue(problems)
                self.assertLessEqual(len(problems), schema_check.MAX_PROBLEMS)
        self.assertIn("too large to check", " ".join(validate([0] * 1_000_000, cases[0][1])))


class RemoteReferences(unittest.TestCase):
    def test_references_outside_the_schema_are_found(self):
        tool = {"name": "t", "inputSchema": {
            "type": "object", "$id": "https://example.com/tool.json",
            "properties": {
                "a": {"$ref": "https://evil.example/s.json"},
                "b": {"$ref": "#/$defs/local"},
                "c": {"items": {"$dynamicRef": "other.json#node"}},
                "$ref": {"type": "string"},  # a property named $ref is not a reference
            },
            "$defs": {"local": {"type": "string"}},
        }, "outputSchema": {"$schema": "https://evil.example/meta", "default": {"$recursiveRef": "//host/x"}}}
        found = remote_refs(tool)
        self.assertEqual(len(found), 5, found)
        joined = " ".join(found)
        for expected in ('$id "https://example.com/tool.json"', '$ref "https://evil.example/s.json"',
                         '$dynamicRef "other.json#node"', '$schema "https://evil.example/meta"',
                         '$recursiveRef "//host/x"'):
            self.assertIn(expected, joined)

    def test_local_pointers_and_the_standard_meta_schemas_are_fine(self):
        for meta in ("https://json-schema.org/draft/2020-12/schema", "http://json-schema.org/draft-07/schema#",
                     "http://json-schema.org/draft-04/schema#"):
            tool = {"inputSchema": {"$schema": meta, "$id": "urn:uuid:1", "properties": {"x": {"$ref": "#/a"}}}}
            with self.subTest(meta=meta):
                self.assertEqual(remote_refs(tool), [])
        self.assertEqual(remote_refs({"inputSchema": {"$schema": "https://json-schema.org/draft/2020-12/schema/x"}})[0],
                         '$schema "https://json-schema.org/draft/2020-12/schema/x"')
        self.assertEqual(remote_refs({"inputSchema": {"$ref": "file:///etc/passwd"}}), ['$ref "file:///etc/passwd"'])
        self.assertEqual(remote_refs("not a tool"), [])

    def test_a_schema_too_large_to_look_through_is_reported_quickly(self):
        schema = {"items": [{"a": [{}] * 10} for _ in range(20_000)]}
        started = time.perf_counter()
        found = remote_refs({"inputSchema": schema})
        self.assertLess(time.perf_counter() - started, 2.0)
        self.assertEqual(len(found), 1)
        self.assertIn("too large to look through", found[0])

    def test_at_most_a_few_are_reported(self):
        tool = {"inputSchema": {"properties": {str(i): {"$ref": f"https://x.example/{i}"} for i in range(100)}}}
        self.assertEqual(len(remote_refs(tool)), schema_check.MAX_REFERENCES_REPORTED)


class TheStore(unittest.TestCase):
    def test_a_tool_is_kept_and_replaced(self):
        store = SchemaStore()
        self.assertEqual(store.lookup("t"), (None, "the tool was not in a tool list of this session"))
        store.remember("t", {"inputSchema": {"type": "object"}})
        found, why = store.lookup("t")
        self.assertEqual((found.input, found.has_output, why), ({"type": "object"}, False, ""))
        store.remember("t", {"inputSchema": {}, "outputSchema": {"type": "object"}})
        self.assertTrue(store.lookup("t")[0].has_output)

    def test_schemas_too_large_or_too_many_are_not_kept(self):
        store = SchemaStore(max_tools=2, max_chars=100)
        store.remember("big", {"inputSchema": {"description": "x" * (schema_check.MAX_TOOL_SCHEMA_CHARS + 1)}})
        self.assertIn("too large to keep", store.lookup("big")[1])
        store.remember("medium", {"inputSchema": {"description": "x" * 200}})
        self.assertIn("more schema text than can be kept", store.lookup("medium")[1])
        store.remember("third", {"inputSchema": {}})
        self.assertEqual(store.lookup("third"), (None, "the session has more tools than can be kept track of"))


class ThePolicysSchemaChecks(unittest.TestCase):
    def test_the_defaults_report_remote_references_and_check_nothing_else(self):
        policy = Policy.from_dict({})
        self.assertEqual(policy.schema_checks_for("x"),
                         SchemaChecks(arguments="off", results="off", undeclared_args="allow", remote_refs="warn"))
        self.assertFalse(policy.uses_schema_checks)

    def test_top_level_and_per_tool_settings(self):
        policy = Policy.from_dict({
            "schema_checks": {"arguments": "enforce", "results": "warn"},
            "tools": {
                "sloppy": {"action": "allow", "schema_checks": {"arguments": "warn"}},
                "files_*": {"action": "allow", "schema_checks": {"undeclared_args": "block"}},
                "*_read": {"action": "allow", "schema_checks": {"remote_refs": "quarantine", "results": "off"}},
            },
        })
        self.assertTrue(policy.uses_schema_checks)
        self.assertEqual(policy.schema_checks_for("other").arguments, "enforce")
        self.assertEqual(policy.schema_checks_for("sloppy").arguments, "warn")  # an exact rule may loosen
        both = policy.schema_checks_for("files_read")  # two wildcards: each setting from the strictest that sets it
        self.assertEqual((both.undeclared_args, both.remote_refs, both.results, both.arguments),
                         ("block", "quarantine", "off", "enforce"))

    def test_a_tool_rule_alone_turns_the_checks_on(self):
        policy = Policy.from_dict({"tools": {"t": {"action": "allow", "schema_checks": {"results": "enforce"}}}})
        self.assertTrue(policy.uses_schema_checks)

    def test_bad_settings_are_refused(self):
        for spec in ({"schema_checks": {"arguments": "block"}}, {"schema_checks": {"remote_refs": "enforce"}},
                     {"schema_checks": {"argument": "warn"}}, {"schema_checks": "enforce"},
                     {"tools": {"t": {"action": "allow", "schema_checks": {"undeclared_args": "warn"}}}}):
            with self.subTest(spec=spec), self.assertRaises(PolicyError):
                Policy.from_dict(spec)
        with self.assertRaises(PolicyError):
            SchemaChecks(arguments="Enforce")
        with self.assertRaises(PolicyError):
            Policy(schema_checks={"arguments": "warn"})

    def test_the_templates_warn_in_starter_and_enforce_in_strict(self):
        starter = Policy.from_dict(templates.template("starter")).schema_checks_for("read_file")
        strict = Policy.from_dict(templates.template("strict")).schema_checks_for("read_file")
        self.assertEqual((starter.arguments, starter.results, starter.undeclared_args, starter.remote_refs),
                         ("warn", "warn", "allow", "warn"))
        self.assertEqual((strict.arguments, strict.results, strict.undeclared_args, strict.remote_refs),
                         ("enforce", "enforce", "block", "quarantine"))

    def test_the_rule_ids_are_described_and_get_hints(self):
        policy = Policy.from_dict({})
        for rule in ("schema.arguments", "schema.result", "schema.remote_refs"):
            with self.subTest(rule=rule):
                self.assertIn("schema_checks", policy.describe_rule(rule))
                self.assertIn(fix_hints.classify(rule).kind, fix_hints.PROTECTIVE_KINDS)
                self.assertIn("schema", fix_hints.fix_hint(rule))


if __name__ == "__main__":
    unittest.main()
