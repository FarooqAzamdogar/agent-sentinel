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

    def test_the_caller_decides_how_names_are_shown_and_gets_them_whole(self):
        # PB2-1: a name may be a secret. `names` gets each name before it is shortened, so a long one that
        # holds a secret can be hidden whole; it is asked only for a problem, never for a value that passes.
        long_name = "k" * 30 + SECRET + "z" * 30
        asked = []

        def hidden(name):
            asked.append(name)
            return "[hidden]"

        self.assertEqual(validate({"path": "a"}, self.SCHEMA, names=hidden), [])
        self.assertEqual(asked, [])
        problems = validate({"path": "a", long_name: 1, "nested": {SECRET: 2}}, self.SCHEMA, root="the arguments",
                            names=hidden)
        text = " ".join(problems)
        self.assertIn("the arguments has a property the schema does not allow: '[hidden]'", text)
        self.assertIn("the arguments.[hidden] has a property the schema does not allow: '[hidden]'", text)
        self.assertNotIn("ghp_", text)
        self.assertIn(long_name, asked)  # whole, not cut at 60 characters
        self.assertIn(SECRET, asked)
        required = validate({}, self.SCHEMA, names=lambda name: name.upper())
        self.assertIn("missing the required property 'PATH'", " ".join(required))
        path = validate({"tags": ["a", 2], "path": "a"}, self.SCHEMA, root="r", names=lambda name: f"<{name}>")
        self.assertEqual(path, ["r.<tags>[1] is an integer, not string"])

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

    def test_beside_prefix_items_items_is_about_the_rest(self):
        # Review of 0.6: a 2020-12 tuple was refused, since `items` was applied to the positions that
        # prefixItems covers as well.
        rest = {"type": "array", "prefixItems": [{"type": "string"}], "items": {"type": "integer"}}
        self.assertEqual(validate(["label", 1, 2, 3], rest), [])
        self.assertEqual(validate(["label"], rest), [])
        self.assertEqual(validate([], rest), [])
        self.assertEqual(validate(["label", 1, "two"], rest), ["the value[2] is text, not integer"])
        closed = {"type": "array", "prefixItems": [{"type": "string"}, {"type": "number"}], "items": False}
        self.assertEqual(validate(["x", 1.5], closed), [])
        self.assertEqual(validate(["x"], closed), [])
        self.assertEqual(validate(["x", 1.5, "more"], closed), ["the value[2] is not allowed by the schema"])
        self.assertEqual(validate([1, "x"], closed), [])  # prefixItems itself is not checked
        nested = {"type": "object", "properties": {"point": closed}}
        self.assertEqual(validate({"point": ["x", 1.5]}, nested), [])
        # Without prefixItems, or with one that is no list, `items` is about every element, as before.
        for prefix in ({}, {"prefixItems": {"type": "string"}}, {"prefixItems": None}):
            with self.subTest(prefix=prefix):
                self.assertEqual(validate(["a", 1], {**prefix, "items": {"type": "integer"}}),
                                 ["the value[0] is text, not integer"])

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

    def test_work_that_grows_with_the_schema_is_paid_for_on_every_part_of_the_value(self):
        # Each case once cost the size of the schema for every part of the value, outside the budget.
        long_types = {"type": "array", "items": {"type": ["null"] * 25_000 + ["integer"]}}
        many_keys = {f"k{i}": 1 for i in range(25_000)}
        deep_schema, deep_value = many_keys, list(range(5_000))
        for _ in range(schema_check.MAX_DEPTH + 1):
            deep_schema = {"items": deep_schema}
        for _ in range(schema_check.MAX_DEPTH):
            deep_value = [deep_value]
        same_keys = {f"k{i}": 0 for i in range(1_000)}
        other_keys = {f"k{i}": 0 for i in range(999)}
        other_keys["k-last"] = 0  # as many keys, and only the last one differs
        key_walks = {"items": {"enum": [other_keys] * 29 + [same_keys]}}  # each item matches the last choice
        cases = (
            ("a long type list", list(range(200_000)), long_types, True),
            ("a schema with many keys past the depth cap", deep_value, deep_schema, False),
            ("objects compared key by key", [same_keys] * 5_000, key_walks, True),
        )
        for label, value, schema, problem in cases:
            with self.subTest(label):
                started = time.perf_counter()
                problems = validate(value, schema)
                self.assertLess(time.perf_counter() - started, 2.0)
                self.assertEqual(bool(problems), problem, problems)
        # A short list is read as before, and costs nothing extra.
        self.assertEqual(validate(list(range(100_000)), {"items": {"type": ["integer", "null"]}}), [])
        self.assertTrue(validate(["x"], {"items": {"type": ["integer", "integer", "null"]}}))


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

    def test_spellings_a_url_parser_reads_as_an_address_are_found(self):
        # WHATWG URL parsers (browsers, Node) add the slashes to "https:host", drop controls and spaces at the
        # ends and tabs and newlines inside, and read a backslash as a slash.
        for key, value in (("$schema", "https:evil.example/meta"), ("$schema", " https://evil.example/meta"),
                           ("$schema", "https:\\\\evil.example\\meta"), ("$schema", "file:/etc/passwd"),
                           ("$schema", "evil.example/meta"), ("$schema", "http://json-schema.org/draft-07/schema# "),
                           ("$id", "https:evil.example/a.json"), ("$id", "\thttps://evil.example/a.json"),
                           ("$id", "ht\ntps://evil.example/a.json"), ("$id", "\x00//evil.example/a.json"),
                           ("$id", "\\\\evil.example\\a.json"), ("$id", "/\\evil.example/a.json"),
                           ("$id", "file:/etc/passwd"), ("$id", "C:/schemas/a.json")):
            with self.subTest(key=key, value=value):
                found = remote_refs({"name": "t", "inputSchema": {"type": "object", key: value}})
                self.assertEqual(len(found), 1, found)
                self.assertTrue(found[0].startswith(f"{key} "))
        for value in ("urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66", "URN:example:x", "#anchor", "item.json", ""):
            with self.subTest(value=value):
                self.assertEqual(remote_refs({"inputSchema": {"$id": value}}), [])

    def test_draft_04_id_counts_only_in_a_draft_04_or_03_schema(self):
        for meta in ("http://json-schema.org/draft-04/schema#", "https://json-schema.org/draft-03/schema"):
            tool = {"inputSchema": {"$schema": meta, "id": "https://evil.example/d4.json",
                                    "properties": {"a": {"id": "https:evil.example/x"}, "id": {"type": "string"}}}}
            with self.subTest(meta=meta):
                found = remote_refs(tool)
                self.assertEqual(sorted(found), sorted(['id "https:evil.example/x"',
                                                        'id "https://evil.example/d4.json"']))
        later = {"inputSchema": {"$schema": "http://json-schema.org/draft-07/schema#",
                                 "default": {"id": "https://example.com/items/1"}}}
        self.assertEqual(remote_refs(later), [])  # "id" is only data there

    def test_a_schema_keyword_that_is_not_text_is_read_without_error(self):
        # PB2-2: "$schema": [] at the top made remote_refs raise TypeError (unhashable), which lost the whole list.
        for meta in ([], {}, ["http://json-schema.org/draft-04/schema#"], {"a": 1}, 4, None, True):
            for key in ("inputSchema", "outputSchema"):
                tool = {"inputSchema": {"type": "object"}, key: {"type": "object", "$schema": meta,
                                                                 "id": "https://evil.example/x.json"}}
                with self.subTest(meta=meta, key=key):
                    self.assertEqual(remote_refs(tool), [])  # not text: names no draft, and "id" is only data
        nested = {"inputSchema": {"$schema": [], "properties": {"a": {"$ref": "https://x.example/a"}}}}
        self.assertEqual(remote_refs(nested), ['$ref "https://x.example/a"'])

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

    def test_the_schema_may_be_in_another_member(self):
        params = {"mode": "form", "message": "Which one?",
                  "requestedSchema": {"type": "object", "properties": {"q": {"$ref": "https://evil.example/s.json"}}}}
        self.assertEqual(remote_refs(params), [])  # an elicitation has no inputSchema
        self.assertEqual(remote_refs(params, ("requestedSchema",)), ['$ref "https://evil.example/s.json"'])
        self.assertEqual(remote_refs({"requestedSchema": "https://evil.example/"}, ("requestedSchema",)), [])


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
