import unittest

import support  # noqa: F401  (sets up the import path)
from agent_sentinel.textutil import printable, texts_in


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


class Printable(unittest.TestCase):
    def test_ordinary_text_is_unchanged(self):
        self.assertEqual(printable("Lentil soup, اردو, 你好"), "Lentil soup, اردو, 你好")

    def test_control_and_invisible_characters_are_escaped(self):
        self.assertEqual(printable("a\x1b[31mb\nc​d"), "a\\x1b[31mb\\nc\\u200bd")

    def test_long_text_is_cut(self):
        self.assertEqual(printable("x" * 500, limit=10), "x" * 10 + "...")

    def test_non_text_is_converted(self):
        self.assertEqual(printable(None), "None")


if __name__ == "__main__":
    unittest.main()
