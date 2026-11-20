"""Tool arguments and results checked against the JSON Schemas a server declared (the policy's schema_checks).

The proxy reads each tool's inputSchema and outputSchema in the server's
tools/list reply, after the tool has been scanned and compared with its pin.
Three things here work on them, all bounded and all pure:

* `remote_refs` finds the references in a tool's schemas that point outside
  the schema: a $ref, $dynamicRef or $recursiveRef that is not a local
  "#..." pointer, and a network $id or $schema (other than the standard JSON
  Schema meta-schemas). The proxy never follows one, but a client that does
  would read text nobody scanned (MCP 2026-07-28 says implementations MUST
  NOT dereference network references). The policy decides whether such a
  tool is only reported or quarantined (schema_checks.remote_refs).
* `validate` is a small JSON Schema validator for the keywords listed below,
  used for a call's arguments (against the inputSchema) and a result's
  structuredContent (against the outputSchema).
* `SchemaStore` keeps the checked schemas of the tools listed in this
  session, so that a call is checked against the schema that was scanned and
  pinned, never against one the server sends later.

The validator knows these keywords only: type, properties, required,
additionalProperties (true, false or a schema), enum, const, minimum,
maximum, exclusiveMinimum, exclusiveMaximum (a number, or draft-04's true or
false), minLength, maxLength, items (one schema), minItems and maxItems.
Every other keyword is ignored, $ref included: a part of a schema that only
refers elsewhere accepts anything. Nothing the server wrote is ever run as a
regular expression (pattern, patternProperties, format are ignored), so a
hostile pattern cannot make a check slow; when a schema has
patternProperties, its additionalProperties is not checked either, since the
patterns decide which properties are additional.

The work is bounded: at most MAX_DEPTH levels of nesting are checked (a
deeper part that the schema constrains is a problem: it cannot be checked),
and at most MAX_STEPS checks are made in all (beyond that the value is a
problem: too large to check). Work that grows with the schema rather than
the value (a long "type" list, comparing objects key by key) is paid for
from the same budget each time, so that a server's schema cannot make every
part of a large value slow. Problems are described without the values they
are about, since a value may be a secret; the names on their path are made
printable.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass
from typing import Any

from .textutil import printable

MAX_DEPTH = 16  # levels of nesting below the value checked against the top of the schema
MAX_STEPS = 200_000  # parts of a value checked, and enum or const entries compared, in one validation
MAX_PROBLEMS = 5  # problems reported for one value; the first ones found
MAX_REFERENCE_NODES = 100_000  # objects and arrays looked through for remote references in one tool
MAX_REFERENCES_REPORTED = 5

# What a server may declare per tool before its schemas are not kept (they are not checked then).
MAX_TOOL_SCHEMA_CHARS = 256 * 1024  # inputSchema and outputSchema of one tool, as JSON
MAX_STORED_SCHEMA_CHARS = 16 * 1024 * 1024  # all tools together
MAX_STORED_TOOLS = 10_000

_REFERENCE_KEYS = ("$ref", "$dynamicRef", "$recursiveRef")
# The meta-schemas of the JSON Schema drafts, as $schema names them. Naming one is ordinary, and no
# client needs to fetch it to read the schema.
_META_SCHEMA_PATHS = ("/schema", "/draft-03/schema", "/draft-04/schema", "/draft-06/schema", "/draft-07/schema",
                      "/draft/2019-09/schema", "/draft/2020-12/schema")
STANDARD_META_SCHEMAS = frozenset(
    f"{scheme}://json-schema.org{path}{end}"
    for scheme in ("http", "https") for path in _META_SCHEMA_PATHS for end in ("", "#")
)
# The drafts that set a schema's base URI with "id" (no $): 03 and 04.
_ID_DRAFT_META_SCHEMAS = frozenset(
    name for name in STANDARD_META_SCHEMAS if "/draft-03/" in name or "/draft-04/" in name
)
# A URI with a scheme ("https:", "file:", "https:evil.example" too, which URL parsers read as https://).
_URI_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
# URL parsers (WHATWG) drop C0 controls and spaces from both ends, and tabs and newlines from anywhere.
_URL_ENDS = "".join(chr(code) for code in range(0x21))
_URL_DROPPED = re.compile(r"[\t\n\r]")

# The keywords the validator acts on: a part of a schema that has none of them accepts anything.
KEYWORDS = frozenset((
    "type", "properties", "required", "additionalProperties", "enum", "const", "minimum", "maximum",
    "exclusiveMinimum", "exclusiveMaximum", "minLength", "maxLength", "items", "minItems", "maxItems",
))


# ---- references that point outside the schema -----------------------------------------------------

def remote_refs(tool: Any) -> list[str]:
    """The references in a tool's inputSchema and outputSchema that point outside the schema, described.

    Each is described as the keyword and its value, shortened and printable:
    '$ref "https://example.com/s.json"'. At most MAX_REFERENCES_REPORTED are
    returned. Every object in the schemas is looked at, wherever it is (a
    client that resolves references may resolve them anywhere, even inside
    "default" or "examples"); keys whose value is not text are property names
    or are malformed, and are not references. A schema with more than
    MAX_REFERENCE_NODES objects and arrays is itself reported: it cannot be
    looked through. Empty when nothing points outside.

    What counts: a $ref, $dynamicRef or $recursiveRef that is not a local
    "#..." pointer; a $schema other than the standard meta-schemas (a client
    that does not know the meta-schema a schema names may fetch it); and an
    $id that is a network address (see _is_address). In a schema whose
    $schema names draft-03 or draft-04, "id" counts as $id does.
    """
    if not isinstance(tool, dict):
        return []
    found: list[str] = []
    stack: list[tuple[Any, bool]] = []
    for key in ("inputSchema", "outputSchema"):
        schema = tool.get(key)
        if isinstance(schema, (dict, list)):
            old_ids = isinstance(schema, dict) and schema.get("$schema") in _ID_DRAFT_META_SCHEMAS
            stack.append((schema, old_ids))
    nodes = 0
    while stack and len(found) < MAX_REFERENCES_REPORTED:
        item, old_ids = stack.pop()
        nodes += 1
        if nodes > MAX_REFERENCE_NODES:
            found.append(f"a schema with more than {MAX_REFERENCE_NODES} parts, too large to look through")
            break
        if isinstance(item, list):
            stack.extend((child, old_ids) for child in item if isinstance(child, (dict, list)))
            continue
        for key, value in item.items():
            if isinstance(value, str):
                problem = _outside_reference(key, value, old_ids)
                if problem is not None and len(found) < MAX_REFERENCES_REPORTED:
                    found.append(problem)
            elif isinstance(value, (dict, list)):
                stack.append((value, old_ids))
    return found


def _outside_reference(key: Any, value: str, old_ids: bool = False) -> str | None:
    """The description of `key: value` if it is a reference to somewhere outside the schema, else None.

    old_ids: the schema is draft-03 or draft-04, where "id" sets the base URI.
    """
    if key in _REFERENCE_KEYS:
        outside = not value.startswith("#")
    elif key == "$id" or (old_ids and key == "id"):
        outside = _is_address(value)
    elif key == "$schema":
        outside = value not in STANDARD_META_SCHEMAS
    else:
        return None
    return f'{key} "{printable(value, limit=80)}"' if outside else None


def _is_address(value: str) -> bool:
    """Whether a URI may be fetched: it has a scheme, or is a network-path reference ("//host/...").

    It is read as a WHATWG URL parser reads it, so that a spelling a browser or
    Node accepts cannot hide one: controls and spaces at the ends and tabs and
    newlines anywhere are dropped, "https:host/x" counts (a parser adds the
    slashes), and a backslash counts as a slash ("\\\\host\\x"). A "urn:" name
    is not an address: no resolver fetches it.
    """
    address = _URL_DROPPED.sub("", value.strip(_URL_ENDS))
    if address[:1] in ("/", "\\") and address[1:2] in ("/", "\\"):
        return True
    scheme = _URI_SCHEME.match(address)
    return scheme is not None and scheme.group().lower() != "urn:"


# ---- the validator -------------------------------------------------------------------------------------

class _TooLarge(Exception):
    """The step budget ran out."""


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_integer(value: Any) -> bool:
    # JSON Schema counts 1.0 as an integer: it is the number, not the spelling, that matters.
    return (isinstance(value, int) and not isinstance(value, bool)) or (isinstance(value, float) and value.is_integer())


_TYPE_CHECKS = {
    "object": lambda value: isinstance(value, dict),
    "array": lambda value: isinstance(value, list),
    "string": lambda value: isinstance(value, str),
    "number": _is_number,
    "integer": _is_integer,
    "boolean": lambda value: isinstance(value, bool),
    "null": lambda value: value is None,
}


def _kind_of(value: Any) -> str:
    """What a value is, in words, for a problem: never the value itself."""
    if isinstance(value, bool):
        return "true or false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return "an integer"
    if isinstance(value, float):
        return "a number"
    if isinstance(value, str):
        return "text"
    if isinstance(value, list):
        return "an array"
    if isinstance(value, dict):
        return "an object"
    return "of an unknown kind"


def _where(root: str, path: tuple[Any, ...]) -> str:
    parts = [root]
    for step in path:
        parts.append(f"[{step}]" if isinstance(step, int) else f".{printable(step, limit=40)}")
    return "".join(parts)


def _shown_number(value: Any) -> str:
    return printable(json.dumps(value), limit=40)


def _count(value: Any) -> int | None:
    """A minLength, maxItems ... value: a whole number of 0 or more; None for anything else (then it is ignored)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return value if isinstance(value, int) and value >= 0 else None


def validate(value: Any, schema: Any, root: str = "the value", *, max_depth: int = MAX_DEPTH,
             max_steps: int = MAX_STEPS) -> list[str]:
    """The problems of `value` against `schema` (see the module docstring for what is checked); empty when none.

    root: how the top of the value is named in the problems ("the arguments",
          "structuredContent"): "the arguments.count is above the maximum (10)".
    At most MAX_PROBLEMS problems are returned. A value too large or too
    deeply nested to check is a problem too: what cannot be checked does not pass.
    """
    problems: list[str] = []
    budget = [max_steps]
    stack: list[tuple[Any, Any, tuple[Any, ...]]] = [(value, schema, ())]
    try:
        while stack and len(problems) < MAX_PROBLEMS:
            item, part, path = stack.pop()
            budget[0] -= 1
            if budget[0] < 0:
                raise _TooLarge
            stack.extend(_check_one(item, part, path, root, problems, budget, max_depth))
    except _TooLarge:
        problems.append(f"{root} is too large to check against the schema (more than {max_steps} checks)")
    return problems[:MAX_PROBLEMS]


def _check_one(value: Any, schema: Any, path: tuple[Any, ...], root: str, problems: list[str], budget: list[int],
               max_depth: int) -> list[tuple[Any, Any, tuple[Any, ...]]]:
    """Check one value against one part of the schema; return the (value, schema, path) of its parts to check next."""
    if schema is False:
        problems.append(f"{_where(root, path)} is not allowed by the schema")
        return []
    if not isinstance(schema, dict):
        return []  # true, or not a schema at all: anything is accepted
    if len(path) > max_depth:
        # One lookup per keyword, never a walk over the schema's keys: a schema may have very many.
        if any(keyword in schema for keyword in KEYWORDS):
            problems.append(f"{_where(root, path)} is nested more than {max_depth} levels deep, too deep to check")
        return []
    problem = _type_problem(value, schema, budget) or _value_problem(value, schema, budget)
    if problem is None:
        if _is_number(value):
            problem = _number_problem(value, schema)
        elif isinstance(value, str):
            problem = _length_problem(len(value), schema, "minLength", "maxLength", "characters")
        elif isinstance(value, list):
            problem = _length_problem(len(value), schema, "minItems", "maxItems", "items")
    if problem is not None:
        problems.append(f"{_where(root, path)} {problem}")
        return []
    if isinstance(value, dict):
        return _object_parts(value, schema, path, root, problems, budget)
    if isinstance(value, list):
        items = schema.get("items")
        if isinstance(items, (dict, bool)) and value:
            if len(value) > budget[0]:
                raise _TooLarge
            return [(child, items, (*path, index)) for index, child in enumerate(value)]
    return []


def _spend(budget: list[int], steps: int) -> None:
    """Take steps from the budget of a validation; _TooLarge when it runs out."""
    budget[0] -= steps
    if budget[0] < 0:
        raise _TooLarge


def _type_problem(value: Any, schema: dict[str, Any], budget: list[int]) -> str | None:
    wanted = schema.get("type")
    names = [wanted] if isinstance(wanted, str) else wanted if isinstance(wanted, list) else None
    if names is not None and len(names) > len(_TYPE_CHECKS):
        # The names must be unique, so a longer list repeats some or names unknown ones. Reading it is
        # paid for from the budget, each time, so that a long list cannot make every part of a value slow.
        _spend(budget, len(names))
    if not names or not all(isinstance(name, str) and name in _TYPE_CHECKS for name in names):
        return None  # no type, or one the validator does not know: not checked
    if any(_TYPE_CHECKS[name](value) for name in names):
        return None
    return f"is {_kind_of(value)}, not {' or '.join(printable(name, limit=20) for name in names[:8])}"


def _value_problem(value: Any, schema: dict[str, Any], budget: list[int]) -> str | None:
    """enum and const."""
    allowed = schema.get("enum")
    if isinstance(allowed, list) and not any(_json_equal(value, choice, budget) for choice in allowed):
        return f"is not one of the {len(allowed)} value(s) the schema allows"
    if "const" in schema and not _json_equal(value, schema["const"], budget):
        return "is not the value the schema requires"
    return None


def _number_problem(value: Any, schema: dict[str, Any]) -> str | None:
    """minimum, maximum, exclusiveMinimum and exclusiveMaximum (also draft-04's true or false forms)."""
    for bound, exclusive, below in (("minimum", "exclusiveMinimum", True), ("maximum", "exclusiveMaximum", False)):
        limit = schema.get(bound)
        strict = schema.get(exclusive)
        if _is_number(limit):
            if isinstance(strict, bool) and strict:  # draft-04: the bound itself is excluded
                if (value <= limit) if below else (value >= limit):
                    return f"is not {'above' if below else 'below'} {_shown_number(limit)} ({exclusive})"
            elif (value < limit) if below else (value > limit):
                return f"is {'below the minimum' if below else 'above the maximum'} ({_shown_number(limit)})"
        if _is_number(strict) and ((value <= strict) if below else (value >= strict)):
            return f"is not {'above' if below else 'below'} {_shown_number(strict)} ({exclusive})"
    return None


def _length_problem(length: int, schema: dict[str, Any], low: str, high: str, unit: str) -> str | None:
    least, most = _count(schema.get(low)), _count(schema.get(high))
    if least is not None and length < least:
        return f"has fewer than {least} {unit} ({low})"
    if most is not None and length > most:
        return f"has more than {most} {unit} ({high})"
    return None


def _object_parts(value: dict[Any, Any], schema: dict[str, Any], path: tuple[Any, ...], root: str,
                  problems: list[str], budget: list[int]) -> list[tuple[Any, Any, tuple[Any, ...]]]:
    """required, properties and additionalProperties of an object; return its members to check next."""
    required = schema.get("required")
    if isinstance(required, list):
        budget[0] -= len(required)
        if budget[0] < 0:
            raise _TooLarge
        for name in required:
            if isinstance(name, str) and name not in value and len(problems) < MAX_PROBLEMS:
                problems.append(f"{_where(root, path)} is missing the required property '{printable(name, limit=60)}'")
    properties = schema.get("properties")
    properties = properties if isinstance(properties, dict) else {}
    # The patterns decide which properties are additional, and the validator does not run them.
    extra = None if "patternProperties" in schema else schema.get("additionalProperties")
    if len(value) > budget[0]:
        raise _TooLarge
    parts = []
    for name, member in value.items():
        if name in properties:
            parts.append((member, properties[name], (*path, name)))
        elif extra is False:
            if len(problems) < MAX_PROBLEMS:
                problems.append(f"{_where(root, path)} has a property the schema does not allow: "
                                f"'{printable(name, limit=60)}'")
        elif isinstance(extra, dict):
            parts.append((member, extra, (*path, name)))
    return parts


def _json_equal(one: Any, other: Any, budget: list[int]) -> bool:
    """Whether two JSON values are equal as JSON Schema compares them: true is not 1, but 1 is 1.0."""
    stack = [(one, other)]
    while stack:
        first, second = stack.pop()
        budget[0] -= 1
        if budget[0] < 0:
            raise _TooLarge
        if isinstance(first, bool) or isinstance(second, bool):
            if not (isinstance(first, bool) and isinstance(second, bool) and first == second):
                return False
        elif _is_number(first) and _is_number(second):
            if first != second:
                return False
        elif isinstance(first, str) and isinstance(second, str):
            if first != second:
                return False
        elif first is None and second is None:
            continue
        elif isinstance(first, list) and isinstance(second, list):
            if len(first) != len(second):
                return False
            stack.extend(zip(first, second))
        elif isinstance(first, dict) and isinstance(second, dict):
            if len(first) != len(second):
                return False
            _spend(budget, len(first))  # comparing the keys walks them
            if first.keys() != second.keys():
                return False
            stack.extend((first[key], second[key]) for key in first)
        else:
            return False
    return True


# ---- the schemas of this session's tools ----------------------------------------------------------------

@dataclass(frozen=True)
class ToolSchemas:
    """The schemas of one tool, as it was listed, checked and pinned."""

    input: Any  # the inputSchema (None when the tool has none, which accepts any arguments)
    output: Any  # the outputSchema, or None when the tool declares none
    has_output: bool  # whether the tool declares an outputSchema


class SchemaStore:
    """The checked schemas of the tools listed in this session, by tool name. Thread-safe and bounded.

    A tool listed again replaces its schemas. Schemas larger than
    MAX_TOOL_SCHEMA_CHARS, or that would take the store past
    MAX_STORED_SCHEMA_CHARS or MAX_STORED_TOOLS, are not kept: the tool is
    remembered as one whose schemas cannot be checked, and `lookup` says why.
    """

    def __init__(self, max_tools: int = MAX_STORED_TOOLS, max_chars: int = MAX_STORED_SCHEMA_CHARS) -> None:
        self._lock = threading.Lock()
        self._tools: dict[str, tuple[ToolSchemas | None, int, str]] = {}  # name -> (schemas or None, size, why)
        self._chars = 0
        self._max_tools = max_tools
        self._max_chars = max_chars
        self._overflowed = False

    def remember(self, name: str, tool: dict[str, Any]) -> None:
        """Keep the schemas of a tool that passed the checks of a tools/list reply."""
        schemas = ToolSchemas(tool.get("inputSchema"), tool.get("outputSchema"), "outputSchema" in tool)
        try:
            size = len(json.dumps([schemas.input, schemas.output]))
        except (TypeError, ValueError, RecursionError):
            size = MAX_TOOL_SCHEMA_CHARS + 1
        with self._lock:
            _, old_size, _ = self._tools.pop(name, (None, 0, ""))
            self._chars -= old_size
            if len(self._tools) >= self._max_tools:
                self._overflowed = True  # this one is not remembered at all
                return
            if size > MAX_TOOL_SCHEMA_CHARS:
                entry = (None, 0, f"its schemas are larger than {MAX_TOOL_SCHEMA_CHARS} characters, too large to keep")
            elif self._chars + size > self._max_chars:
                entry = (None, 0, "the tools of this session have more schema text than can be kept")
            else:
                entry = (schemas, size, "")
                self._chars += size
            self._tools[name] = entry

    def lookup(self, name: str) -> tuple[ToolSchemas | None, str]:
        """(the tool's schemas, "") or (None, why they cannot be checked)."""
        with self._lock:
            entry = self._tools.get(name)
            overflowed = self._overflowed
        if entry is None:
            if overflowed:
                return None, "the session has more tools than can be kept track of"
            return None, "the tool was not in a tool list of this session"
        schemas, _, why = entry
        return schemas, why
