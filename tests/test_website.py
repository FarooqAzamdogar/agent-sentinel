"""The website in docs/ stays in step with the package and keeps to its own Content-Security-Policy.

The pages are read with html.parser, and nothing is fetched. The version the site gives is
the package's, every link and every file a page names exists, nothing comes from another
origin, and the pages and site.js keep to the policy, which allows no inline code and
enforces Trusted Types. Without docs/ the whole module is skipped.
"""

import functools
import json
import re
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
sys.path.insert(0, str(ROOT))  # as support.py does: this module also runs as tests.test_website

from agent_sentinel import __version__  # noqa: E402

HOME, NOT_FOUND = "index.html", "404.html"
PAGES = (HOME, NOT_FOUND)
# GitHub Pages serves the site under this path, and the 404 page for a missing URL at any
# depth, so the 404 page names every file and every link by its full path.
SITE_PATH = "/agent-sentinel/"
# A <link> with one of these rels makes the browser fetch its href, or contact its origin.
LOADING_RELS = {"stylesheet", "preload", "modulepreload", "prefetch", "preconnect", "dns-prefetch",
                "icon", "apple-touch-icon", "mask-icon", "manifest"}
# Attributes that hold the ids of other elements of the same page.
ID_LISTS = ("aria-labelledby", "aria-describedby", "aria-controls", "aria-owns", "for", "data-tab")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
CSP = "content-security-policy"
# What Trusted Types and the policy refuse: HTML written from a string, and code run from one.
UNSAFE_IN_SCRIPT = {
    "innerHTML": re.compile(r"innerHTML"),
    "outerHTML": re.compile(r"outerHTML"),
    "insertAdjacentHTML": re.compile(r"insertAdjacentHTML"),
    "document.write": re.compile(r"\bdocument\s*\.\s*write"),
    "eval(": re.compile(r"\beval\s*\("),
    "new Function": re.compile(r"\bnew\s+Function\b"),
}
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


def setUpModule():
    if not DOCS.is_dir():
        raise unittest.SkipTest("docs/ is not in this copy of the project")


class Element:
    """One element of a page: its tag, its attributes, and what it holds (elements and text)."""

    def __init__(self, tag, attrs, parent=None):
        self.tag = tag
        self.attrs = dict(attrs)
        self.parent = parent
        self.children = []

    def attr(self, name):
        """The attribute's value; "" when it is absent or has no value."""
        return self.attrs.get(name) or ""

    def classes(self):
        return self.attr("class").split()

    def walk(self):
        """This element and every element inside it, in document order."""
        yield self
        for child in self.children:
            if isinstance(child, Element):
                yield from child.walk()

    def text(self):
        return "".join(child if isinstance(child, str) else child.text() for child in self.children)


class TreeBuilder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.document = Element("#document", [])
        self.current = self.document

    def handle_starttag(self, tag, attrs):
        element = Element(tag, attrs, self.current)
        self.current.children.append(element)
        if tag not in VOID:
            self.current = element

    def handle_startendtag(self, tag, attrs):
        self.current.children.append(Element(tag, attrs, self.current))

    def handle_endtag(self, tag):
        element = self.current
        while element is not self.document and element.tag != tag:
            element = element.parent
        if element is not self.document:
            self.current = element.parent

    def handle_data(self, data):
        self.current.children.append(data)


@functools.lru_cache(maxsize=None)
def page(name):
    """Every element of a page, in document order."""
    builder = TreeBuilder()
    builder.feed((DOCS / name).read_text(encoding="utf-8"))
    builder.close()
    return tuple(builder.document.walk())[1:]


@functools.lru_cache(maxsize=None)
def ids(name):
    return frozenset(element.attr("id") for element in page(name) if element.attr("id"))


def links(name, start):
    return [element.attr("href") for element in page(name)
            if element.tag == "a" and element.attr("href").startswith(start)]


def json_ld_blocks(name):
    return [element.text() for element in page(name)
            if element.tag == "script" and element.attr("type").lower() == "application/ld+json"]


def parsed_json_ld(name):
    """The JSON-LD blocks of a page that parse; test_every_json_ld_block_parses reports the others."""
    parsed = []
    for block in json_ld_blocks(name):
        try:
            parsed.append(json.loads(block))
        except ValueError:
            pass
    return parsed


def nodes_of_type(data, wanted):
    """Every object in parsed JSON-LD whose @type is, or includes, the wanted type."""
    if isinstance(data, dict):
        kind = data.get("@type")
        if kind == wanted or (isinstance(kind, list) and wanted in kind):
            yield data
        for value in data.values():
            yield from nodes_of_type(value, wanted)
    elif isinstance(data, list):
        for value in data:
            yield from nodes_of_type(value, wanted)


def loaded_addresses(name):
    """(tag, address) for everything the page makes the browser fetch."""
    for element in page(name):
        if element.tag == "link" and LOADING_RELS & set(element.attr("rel").lower().split()):
            yield element.tag, element.attr("href")
        for attribute in ("src", "poster"):
            if element.attr(attribute):
                yield element.tag, element.attr(attribute)
        if element.tag == "object" and element.attr("data"):
            yield element.tag, element.attr("data")


def from_another_origin(address):
    return bool(SCHEME.match(address.strip())) or "//" in address


def policies(name):
    """The page's Content-Security-Policy meta elements."""
    return [element for element in page(name) if element.attr("http-equiv").lower() == CSP]


def policy(name):
    """The page's first Content-Security-Policy meta element, or None."""
    return (policies(name) or [None])[0]


def without_comments(source):
    """JavaScript source without its comments; strings are kept. A rough scanner, enough for site.js."""
    out, i, quote = [], 0, None
    while i < len(source):
        char = source[i]
        if quote:
            step = 2 if char == "\\" else 1
            out.append(source[i:i + step])
            i += step
            if char == quote:
                quote = None
        elif char in "'\"`":
            quote = char
            out.append(char)
            i += 1
        elif source.startswith("//", i):
            end = source.find("\n", i)
            i = len(source) if end == -1 else end
        elif source.startswith("/*", i):
            end = source.find("*/", i + 2)
            i = len(source) if end == -1 else end + 2
            out.append(" ")
        else:
            out.append(char)
            i += 1
    return "".join(out)


class TheVersionTheSiteGives(unittest.TestCase):
    def test_every_json_ld_block_parses(self):
        self.assertTrue(json_ld_blocks(HOME))
        for name in PAGES:
            for number, block in enumerate(json_ld_blocks(name), 1):
                with self.subTest(page=name, block=number):
                    try:
                        json.loads(block)
                    except ValueError as error:
                        self.fail("not JSON: %s" % error)

    def test_the_software_version_is_the_package_version(self):
        applications = [node for data in parsed_json_ld(HOME) for node in nodes_of_type(data, "SoftwareApplication")]
        self.assertEqual(len(applications), 1, "one SoftwareApplication in the JSON-LD")
        self.assertEqual(applications[0].get("softwareVersion"), __version__)

    def test_the_hero_shows_the_package_version(self):
        eyebrow = next((element for element in page(HOME) if "hero__eyebrow" in element.classes()), None)
        self.assertIsNotNone(eyebrow, "the hero's eyebrow is missing")
        pill = next((element for element in eyebrow.walk() if "pill" in element.classes()), None)
        self.assertIsNotNone(pill, "the version pill is missing")
        self.assertEqual(pill.text().split()[:1], ["v" + __version__])


class WhatThePagesPointAt(unittest.TestCase):
    def test_every_link_within_the_home_page_names_an_id_on_it(self):
        found = links(HOME, "#")
        self.assertIn("#quick-start", found)  # the search works
        self.assertEqual([link for link in found if link[1:] not in ids(HOME)], [])

    def test_every_link_from_the_404_page_into_the_home_page_names_an_id_on_it(self):
        sections = [link for link in links(NOT_FOUND, SITE_PATH) if "#" in link]
        self.assertTrue(sections)
        for link in sections:
            with self.subTest(link=link):
                address, _, fragment = link.partition("#")
                self.assertIn(address, (SITE_PATH, SITE_PATH + HOME))
                self.assertIn(fragment, ids(HOME))
        # Its own in-page links, such as the skip link, name ids on the 404 page.
        self.assertEqual([link for link in links(NOT_FOUND, "#") if link[1:] not in ids(NOT_FOUND)], [])

    def test_every_id_an_attribute_names_is_on_its_page(self):
        for name in PAGES:
            missing = []
            for element in page(name):
                named = [word for attribute in ID_LISTS for word in element.attr(attribute).split()]
                if element.tag == "use":
                    named.append(re.sub("^#", "", element.attr("href") or element.attr("xlink:href")))
                missing += [(element.tag, word) for word in named if word not in ids(name)]
            with self.subTest(page=name):
                self.assertEqual(missing, [])

    def test_every_file_a_page_loads_is_in_docs(self):
        for name in PAGES:
            for _, address in loaded_addresses(name):
                if from_another_origin(address):
                    continue  # that is test_nothing_is_loaded_from_another_origin
                with self.subTest(page=name, address=address):
                    path = re.split("[?#]", address)[0]
                    if name == NOT_FOUND:
                        self.assertTrue(path.startswith(SITE_PATH), "the 404 page names files by their full path")
                    if path.startswith(SITE_PATH):
                        path = path[len(SITE_PATH):]
                    self.assertFalse(path.startswith("/"), "outside the site")
                    file = (DOCS / path).resolve()
                    self.assertTrue(file.is_relative_to(DOCS.resolve()), "outside docs/")
                    self.assertTrue(file.is_file(), "no such file in docs/")

    def test_nothing_is_loaded_from_another_origin(self):
        for name in PAGES:
            addresses = [address for _, address in loaded_addresses(name)]
            with self.subTest(page=name):
                self.assertTrue(addresses)  # the search works
                self.assertEqual([address for address in addresses if from_another_origin(address)], [])


class TheContentSecurityPolicy(unittest.TestCase):
    def test_the_policy_comes_right_after_the_charset(self):
        for name in PAGES:
            with self.subTest(page=name):
                head = next(element for element in page(name) if element.tag == "head")
                first, second = [child for child in head.children if isinstance(child, Element)][:2]
                self.assertEqual((first.tag, first.attr("charset").lower()), ("meta", "utf-8"))
                self.assertIs(second, policy(name))
                self.assertEqual(len(policies(name)), 1)

    def test_the_policy_enforces_trusted_types_and_allows_no_inline_code(self):
        for name in PAGES:
            with self.subTest(page=name):
                self.assertIsNotNone(policy(name))
                content = policy(name).attr("content")
                self.assertIn("require-trusted-types-for 'script'", content)
                self.assertNotIn("'unsafe-inline'", content)
                self.assertNotIn("'unsafe-eval'", content)

    def test_the_only_script_written_into_a_page_is_json_ld(self):
        for name in PAGES:
            inline = [element.attr("type") for element in page(name)
                      if element.tag == "script" and "src" not in element.attrs
                      and element.attr("type").lower() != "application/ld+json"]
            with self.subTest(page=name):
                self.assertEqual(inline, [])

    def test_no_style_is_written_into_a_page(self):
        for name in PAGES:
            styled = [element.tag for element in page(name) if "style" in element.attrs or element.tag == "style"]
            with self.subTest(page=name):
                self.assertEqual(styled, [])

    def test_no_element_has_an_event_handler_or_a_javascript_address(self):
        for name in PAGES:
            found = [(element.tag, attribute) for element in page(name) for attribute, value in element.attrs.items()
                     if attribute.startswith("on")
                     or re.sub(r"[\t\n\r]", "", value or "").strip().lower().startswith("javascript:")]
            with self.subTest(page=name):
                self.assertEqual(found, [])

    def test_the_script_writes_no_html_and_runs_no_strings(self):
        code = without_comments((DOCS / "site.js").read_text(encoding="utf-8"))
        self.assertIn("textContent", code)  # the comments went, the code stayed
        self.assertEqual([name for name, pattern in UNSAFE_IN_SCRIPT.items() if pattern.search(code)], [])


if __name__ == "__main__":
    unittest.main()
