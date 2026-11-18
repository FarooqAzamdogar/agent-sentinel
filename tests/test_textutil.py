import dataclasses
import unittest
from collections import OrderedDict, deque
from types import MappingProxyType

import support  # noqa: F401  (sets up the import path)
from agent_sentinel.textutil import UnscannableError, printable, text_views, texts_in


@dataclasses.dataclass
class Page:
    title: str
    lines: list


class TextsIn(unittest.TestCase):
    def test_collects_nested_text_in_document_order(self):
        value = {"a": "one", "b": ["two", {"c": "three"}], "d": 4}
        self.assertEqual(texts_in(value), ["a", "one", "b", "two", "c", "three", "d"])

    def test_keys_and_scalars_are_optional(self):
        value = {"a": "one", "n": 4, "ok": True, "none": None}
        self.assertEqual(texts_in(value, keys=False), ["one"])
        self.assertEqual(texts_in(value, keys=False, scalars=True), ["one", "4", "true", "null"])

    def test_plain_values(self):
        self.assertEqual(texts_in("text"), ["text"])
        self.assertEqual(texts_in(None), [])
        self.assertEqual(texts_in(7, scalars=True), ["7"])

    def test_very_deep_nesting_does_not_overflow(self):
        value = "deep"
        for _ in range(50_000):
            value = [value]
        self.assertEqual(texts_in(value), ["deep"])

    def test_very_deep_objects_do_not_overflow_either(self):
        value = "deep"
        for _ in range(50_000):
            value = {"k": value}
        self.assertEqual(texts_in(value, keys=False), ["deep"])
        self.assertEqual(text_views(value)[0].count("k"), 50_000)

    def test_bytes_are_read_as_utf8(self):
        for value in (b"caf\xc3\xa9", bytearray(b"caf\xc3\xa9"), memoryview(b"caf\xc3\xa9")):
            with self.subTest(type=type(value).__name__):
                self.assertEqual(texts_in(value), ["café"])
        self.assertEqual(texts_in({b"key": [b"value"]}), ["key", "value"])

    def test_bytes_that_are_not_utf8_are_still_collected(self):
        self.assertEqual(texts_in(b"ok \xff\xfe"), ["ok \ufffd\ufffd"])

    def test_sets_deques_and_other_mappings_and_sequences_are_walked(self):
        self.assertEqual(texts_in(deque(["a", ["b"]])), ["a", "b"])
        self.assertEqual(texts_in(("a", ("b",))), ["a", "b"])
        self.assertEqual(texts_in(OrderedDict(a="one")), ["a", "one"])
        self.assertEqual(texts_in(MappingProxyType({"a": "one"})), ["a", "one"])
        self.assertEqual(sorted(texts_in({"a", "b"})), ["a", "b"])
        self.assertEqual(sorted(texts_in([frozenset({"a", "b"})])), ["a", "b"])

    def test_dataclass_instances_are_walked_like_objects_with_named_fields(self):
        page = Page(title="Soup", lines=["simmer", b"serve"])
        self.assertEqual(texts_in(page), ["title", "Soup", "lines", "simmer", "serve"])
        self.assertEqual(texts_in(page, keys=False), ["Soup", "simmer", "serve"])

    def test_a_dataclass_type_is_not_an_instance(self):
        with self.assertRaises(UnscannableError):
            texts_in(Page, strict=True)

    def test_a_value_that_contains_itself_is_walked_once(self):
        loop = {"text": "again and again"}
        loop["self"] = loop
        loop["list"] = [loop, "end"]
        self.assertEqual(texts_in(loop), ["text", "again and again", "self", "list", "end"])

    def test_values_that_cannot_be_walked_are_left_out_by_default(self):
        lines = (line for line in ["never read"])
        self.assertEqual(texts_in(["a", lines, object(), iter(["x"])]), ["a"])
        self.assertEqual(next(lines), "never read")  # the generator was not used up

    def test_scalars_mode_still_writes_unknown_values_with_str(self):
        self.assertEqual(texts_in([1.5, complex(1, 2)], scalars=True), ["1.5", '"(1+2j)"'])

    def test_strict_refuses_a_value_that_cannot_be_walked_and_names_its_type(self):
        unreadable = {
            "generator": (line for line in ["x"]),
            "list_iterator": iter(["x"]),
            "dict_values": {"a": "x"}.values(),
            "object": object(),
            "complex": complex(1, 2),
        }
        for type_name, value in unreadable.items():
            with self.subTest(type=type_name):
                with self.assertRaises(UnscannableError) as raised:
                    texts_in({"result": ["fine", value]}, strict=True)
                self.assertEqual(str(raised.exception), f"a value of type {type_name} cannot be scanned")

    def test_strict_does_not_read_from_a_generator_before_refusing_it(self):
        lines = (line for line in ["never read"])
        with self.assertRaises(UnscannableError):
            texts_in(lines, strict=True)
        self.assertEqual(next(lines), "never read")

    def test_strict_accepts_everything_json_can_hold(self):
        value = {"a": ["text", 1, 2.5, True, None, {"b": []}]}
        self.assertEqual(texts_in(value, strict=True), ["a", "text", "b"])
        self.assertEqual(texts_in(None, strict=True), [])

    def test_unscannable_error_is_a_type_error(self):
        self.assertTrue(issubclass(UnscannableError, TypeError))


class TextViews(unittest.TestCase):
    def test_a_plain_string_is_its_own_single_view(self):
        self.assertEqual(text_views("Lentil soup"), ["Lentil soup"])

    def test_first_view_is_every_key_and_string_joined_by_newlines(self):
        value = {"a": "one", "b": ["two", {"c": "three"}], "d": 4}
        self.assertEqual(text_views(value)[0], "\n".join(texts_in(value)))

    def test_strings_split_over_list_items_are_joined_into_one_view(self):
        value = {"content": [{"type": "text", "text": "Do not"}, {"type": "text", "text": "tell the user"}]}
        self.assertEqual(
            text_views(value),
            ["content\ntype\ntext\ntext\nDo not\ntype\ntext\ntext\ntell the user", "text text", "Do not tell the user"],
        )

    def test_strings_under_different_keys_are_not_joined(self):
        value = {"title": "Do not", "body": "tell the user"}
        self.assertEqual(text_views(value), ["title\nDo not\nbody\ntell the user"])

    def test_items_of_a_plain_list_are_joined(self):
        self.assertEqual(text_views(["Never", "reveal this"]), ["Never\nreveal this", "Never reveal this"])

    def test_rows_of_a_nested_list_share_one_view(self):
        self.assertEqual(text_views({"rows": [["a", "b"], ["c"]]}), ["rows\na\nb\nc", "a b c"])

    def test_bytes_take_part_like_strings(self):
        self.assertEqual(text_views([b"Do not", "tell the user"])[-1], "Do not tell the user")

    def test_blank_and_duplicate_views_are_left_out(self):
        self.assertEqual(text_views(None), [])
        self.assertEqual(text_views({}), [])
        self.assertEqual(text_views(["", " "]), [])
        self.assertEqual(text_views(["", "only"]), ["\nonly", " only"])
        self.assertEqual(text_views({"a": ["x", "x"], "b": ["x", "x"]}), ["a\nx\nx\nb\nx\nx", "x x"])

    def test_strict_is_passed_on_to_the_walk(self):
        self.assertEqual(text_views(["a", object()]), ["a"])
        with self.assertRaises(UnscannableError):
            text_views(["a", object()], strict=True)


class Printable(unittest.TestCase):
    def test_ordinary_text_is_unchanged(self):
        self.assertEqual(printable("Lentil soup, اردو, 你好"), "Lentil soup, اردو, 你好")

    def test_control_and_invisible_characters_are_escaped(self):
        self.assertEqual(printable("a\x1b[31mb\nc​d"), "a\\x1b[31mb\\nc\\u200bd")

    def test_characters_that_draw_nothing_are_escaped_even_if_python_calls_them_printable(self):
        self.assertEqual(printable("read\ufe0f_file"), "read\\ufe0f_file")
        self.assertEqual(printable("read\U000e0100_file"), "read\\U000e0100_file")
        self.assertEqual(printable("a\u034fb\u115fc\u3164d\u2800e"), "a\\u034fb\\u115fc\\u3164d\\u2800e")

    def test_accents_written_as_combining_marks_are_unchanged(self):
        decomposed = "cafe\u0301, Vie\u0323\u0302t, ع\u064eر\u064eب\u0650ي"
        self.assertEqual(printable(decomposed), decomposed)

    def test_a_long_stack_of_combining_marks_is_escaped_after_the_second(self):
        self.assertEqual(printable("x" + "\u0301" * 5 + "y"), "x\u0301\u0301" + "\\u0301" * 3 + "y")

    def test_long_text_is_cut(self):
        self.assertEqual(printable("x" * 500, limit=10), "x" * 10 + "...")

    def test_non_text_is_converted(self):
        self.assertEqual(printable(None), "None")


if __name__ == "__main__":
    unittest.main()
