"""Permission policy: which tools an agent may call, and with what arguments.

A policy is loaded from JSON (see policy.example.json) and answers one
question, `Policy.evaluate(tool, args)`, with a `Verdict` of allow, ask or
block. Loading is strict: an unknown key or a wrong type is an error, because
a typo that is silently ignored leaves a policy weaker than its author thinks.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .detector import SEVERITY_ORDER
from .textutil import texts_in

ACTIONS = ("allow", "ask", "block")

# In deny_args, this argument name means "any argument, at any depth".
ANY_ARG = "*"


class PolicyError(ValueError):
    """The policy is malformed."""


@dataclass(frozen=True)
class ArgRule:
    arg: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class ToolRule:
    name: str  # exact tool name or a glob such as "delete_*"
    action: str
    deny_args: tuple[ArgRule, ...] = ()
    allow_args: tuple[ArgRule, ...] = ()


@dataclass(frozen=True)
class Verdict:
    action: str  # "allow", "ask" or "block"
    reason: str  # shown to the agent, so it never includes policy patterns


@dataclass
class Policy:
    default: str = "block"
    tools: list[ToolRule] = field(default_factory=list)
    # Text with a finding at or above this severity is blocked.
    # None disables blocking (findings are still logged).
    block_severity: str | None = "high"

    # ---- loading ------------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except ValueError as exc:  # bad JSON or bad UTF-8
            raise PolicyError(f"{path}: not valid JSON ({exc})") from exc
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Any) -> "Policy":
        _expect_object(data, "the policy", allowed_keys=("default", "tools", "injection"))

        default = data.get("default", "block")
        _expect_action(default, "default")

        tool_specs = data.get("tools", {})
        _expect_object(tool_specs, "tools")
        tools = [_tool_rule(name, spec) for name, spec in tool_specs.items()]

        injection = data.get("injection", {})
        _expect_object(injection, "injection", allowed_keys=("block_severity",))
        severity = injection.get("block_severity", "high")
        if severity is not None and severity not in SEVERITY_ORDER:
            raise PolicyError(f"injection.block_severity must be one of {list(SEVERITY_ORDER)} or null")

        return cls(default=default, tools=tools, block_severity=severity)

    # ---- evaluating ---------------------------------------------------------

    def evaluate(self, tool: str, args: dict[str, Any] | None) -> Verdict:
        """Decide what should happen to a call of `tool` with `args`."""
        args = args or {}
        rule = self._rule_for(tool)
        if rule is None:
            return Verdict(self.default, f"no rule for '{tool}', default is {self.default}")

        for deny in rule.deny_args:
            if _is_denied(deny, args):
                which = "an argument" if deny.arg == ANY_ARG else f"argument '{deny.arg}'"
                return Verdict("block", f"{which} has a value the policy denies")

        for allow in rule.allow_args:
            if allow.arg not in args:
                return Verdict("block", f"argument '{allow.arg}' is required by the policy but missing")
            if not _is_allowed(allow, args[allow.arg]):
                return Verdict("block", f"argument '{allow.arg}' has a value the policy does not allow")

        return Verdict(rule.action, f"rule '{rule.name}' says {rule.action}")

    def _rule_for(self, tool: str) -> ToolRule | None:
        for rule in self.tools:  # an exact name always wins over a glob
            if rule.name == tool:
                return rule
        for rule in self.tools:
            if fnmatch.fnmatchcase(tool, rule.name):
                return rule
        return None


# ---- argument matching ------------------------------------------------------

def _is_denied(rule: ArgRule, args: dict[str, Any]) -> bool:
    """True if the pattern is found anywhere in the argument's text.

    Looks inside nested lists and objects, including object keys, so a denied
    value cannot be hidden one level down.
    """
    if rule.arg == ANY_ARG:
        value: Any = args
    elif rule.arg in args:
        value = args[rule.arg]
    else:
        return False
    return any(rule.pattern.search(text) for text in texts_in(value, keys=True, scalars=True))


def _is_allowed(rule: ArgRule, value: Any) -> bool:
    """True if the pattern matches the WHOLE value.

    Whole-value matching is deliberate: with a "contains" match, the address
    list "attacker@evil.example, boss@example.com" would pass a rule meant to
    allow only example.com. For a list or object, every value inside must
    match, and an empty one is refused.
    """
    texts = texts_in(value, keys=False, scalars=True)
    return bool(texts) and all(rule.pattern.fullmatch(text) for text in texts)


# ---- validation helpers -----------------------------------------------------

def _tool_rule(name: str, spec: Any) -> ToolRule:
    where = f"tools.{name}"
    if isinstance(spec, str):  # shorthand: "tool": "allow"
        spec = {"action": spec}
    _expect_object(spec, where, allowed_keys=("action", "deny_args", "allow_args"))
    action = spec.get("action", "allow")
    _expect_action(action, f"{where}.action")
    return ToolRule(
        name=name,
        action=action,
        deny_args=_arg_rules(spec.get("deny_args", []), f"{where}.deny_args", allow_any_arg=True),
        allow_args=_arg_rules(spec.get("allow_args", []), f"{where}.allow_args", allow_any_arg=False),
    )


def _arg_rules(specs: Any, where: str, allow_any_arg: bool) -> tuple[ArgRule, ...]:
    if not isinstance(specs, list):
        raise PolicyError(f"{where} must be a list")
    rules = []
    for spec in specs:
        _expect_object(spec, f"an entry of {where}", allowed_keys=("arg", "pattern"))
        arg, pattern = spec.get("arg"), spec.get("pattern")
        if not isinstance(arg, str) or not isinstance(pattern, str):
            raise PolicyError(f"each entry of {where} needs a text 'arg' and a text 'pattern'")
        if arg == ANY_ARG and not allow_any_arg:
            raise PolicyError(f"{where}: '{ANY_ARG}' is only supported in deny_args")
        try:
            rules.append(ArgRule(arg, re.compile(pattern, re.IGNORECASE)))
        except re.error as exc:
            raise PolicyError(f"{where}: bad pattern {pattern!r} ({exc})") from exc
    return tuple(rules)


def _expect_object(value: Any, where: str, allowed_keys: tuple[str, ...] | None = None) -> None:
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be a JSON object")
    if allowed_keys is not None:
        unknown = sorted(set(value) - set(allowed_keys))
        if unknown:
            raise PolicyError(f"{where} has unknown key(s) {unknown}; allowed keys are {list(allowed_keys)}")


def _expect_action(action: Any, where: str) -> None:
    if action not in ACTIONS:
        raise PolicyError(f"{where} must be one of {list(ACTIONS)}, got {action!r}")
