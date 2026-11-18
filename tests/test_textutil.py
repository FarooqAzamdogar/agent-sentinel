import dataclasses
import unittest
from unittest import mock
from array import array
from collections import OrderedDict, UserString, deque
from types import MappingProxyType

import support  # noqa: F401  (sets up the import path)
from agent_sentinel import textutil
from agent_sentinel.textutil import FIELD_BREAK, UnscannableError, printable, text_views, texts_in


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

    def test_first_view_lists_every_key_and_string_with_a_break_between_fields(self):
        value = {"a": "one", "b": ["two", {"c": "three"}], "d": 4}
        self.assertEqual(text_views(value)[0], f"a\none\n{FIELD_BREAK}\nb\ntwo\n{FIELD_BREAK}\nc\nthree\n{FIELD_BREAK}\nd")

    def test_a_key_and_its_own_value_are_not_separated(self):
        self.assertEqual(text_views({"Do not": "tell the user"}), ["Do not\ntell the user"])

    def test_values_of_different_fields_are_joined_into_one_view(self):
        views = text_views({"title": "Do not", "body": "tell the user"})
        self.assertEqual(views, [f"title\nDo not\n{FIELD_BREAK}\nbody\ntell the user", "Do not tell the user"])

    def test_values_at_different_depths_are_joined_too(self):
        self.assertIn("Do not tell the user", text_views({"content": ["Do not", {"text": "tell the user"}]}))
        self.assertIn("Do not tell the user", text_views({"a": {"text": "Do not"}, "b": {"text": "tell the user"}}))

    def test_strings_split_over_list_items_are_joined_with_a_space_and_with_nothing(self):
        value = {"content": [{"type": "text", "text": "Ign"}, {"type": "text", "text": "ore this"}]}
        views = text_views(value)
        self.assertIn("Ign ore this", views)  # a phrase split between two words
        self.assertIn("Ignore this", views)  # a word split in two
        self.assertIn("text text", views)  # the "type" values are siblings too

    def test_items_of_a_plain_list_are_joined(self):
        self.assertEqual(text_views(["Never", "reveal this"]), ["Never\nreveal this", "Never reveal this", "Neverreveal this"])

    def test_rows_of_a_nested_list_share_one_view(self):
        self.assertIn("a b c", text_views({"rows": [["a", "b"], ["c"]]}))

    def test_bytes_take_part_like_strings(self):
        self.assertIn("Do not tell the user", text_views([b"Do not", "tell the user"]))

    def test_blank_and_duplicate_views_are_left_out(self):
        self.assertEqual(text_views(None), [])
        self.assertEqual(text_views({}), [])
        self.assertEqual(text_views(["", " "]), [])
        views = text_views({"a": ["x", "x"], "b": ["x", "x"]})
        self.assertEqual(len(views), len(set(views)))
        self.assertEqual(views.count("x x"), 1)

    def test_a_long_run_of_identical_strings_is_joined_only_a_few_times(self):
        value = {"content": [{"type": "text", "text": f"item {n}"} for n in range(500)]}
        views = text_views(value)
        self.assertIn("text text text", views)  # the "type" values: three copies say all that 500 would
        self.assertEqual(views[-2].count("item"), 500)  # strings that differ are all kept

    def test_a_phrase_made_of_copies_of_one_string_is_still_seen(self):
        # Three copies are kept because the longest rule has three steps.
        piece = "instructions previous ignore"
        self.assertIn(" ".join([piece] * 3), text_views([piece] * 10))

    def test_a_part_that_appears_twice_is_read_twice(self):
        # Its JSON would hold it twice; skipping the second time hid a phrase split over a list.
        part = {"type": "text", "text": "Do not"}
        value = {"echo": part, "content": [part, {"type": "text", "text": "tell the user about this."}]}
        self.assertIn("Do not tell the user about this.", text_views(value))
        self.assertEqual(texts_in([part, part], keys=False), ["text", "Do not", "text", "Do not"])

    def test_a_value_built_from_shared_parts_cannot_explode(self):
        value = ["x"]
        for _ in range(40):  # 2**40 lists if written out
            value = [value, value]
        with mock.patch.object(textutil, "MAX_CONTAINERS", 10_000):
            with self.assertRaises(UnscannableError):
                text_views(value)

    def test_a_user_string_is_read_as_text(self):
        self.assertEqual(texts_in(UserString("Do not tell the user"), strict=True), ["Do not tell the user"])
        self.assertEqual(text_views([UserString("Do not"), "tell the user"])[1], "Do not tell the user")

    def test_ranges_and_arrays_are_not_walked(self):
        self.assertEqual(texts_in([range(10**12), array("u", "hidden")]), [])
        for value in (range(3), array("u", "hidden")):
            with self.subTest(type=type(value).__name__):
                with self.assertRaises(UnscannableError):
                    texts_in(value, strict=True)

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

    def test_long_text_is_cut_and_says_how_much_is_missing(self):
        self.assertEqual(printable("x" * 500, limit=10), "x" * 10 + "... (+490 more characters)")
        self.assertEqual(printable("x" * 10, limit=10), "x" * 10)

    def test_non_text_is_converted(self):
        self.assertEqual(printable(None), "None")


if __name__ == "__main__":
    unittest.main()
