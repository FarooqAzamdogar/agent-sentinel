"""Permission policy: which tools an agent may call, and with what arguments."""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .detector import SEVERITY_ORDER

ACTIONS = ("allow", "ask", "block")


class PolicyError(ValueError):
    """The policy file is malformed."""


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
    reason: str


@dataclass
class Policy:
    default: str = "block"
    tools: list[ToolRule] = field(default_factory=list)
    # Tool results with a finding at or above this severity are blocked.
    # None disables blocking (findings are still logged).
    block_severity: str | None = "high"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        default = data.get("default", "block")
        _check_action(default, "default")
        tools = []
        for name, spec in (data.get("tools") or {}).items():
            if isinstance(spec, str):
                spec = {"action": spec}
            action = spec.get("action", "allow")
            _check_action(action, f"tools.{name}.action")
            tools.append(
                ToolRule(
                    name=name,
                    action=action,
                    deny_args=_arg_rules(spec.get("deny_args"), name),
                    allow_args=_arg_rules(spec.get("allow_args"), name),
                )
            )
        severity = (data.get("injection") or {}).get("block_severity", "high")
        if severity is not None and severity not in SEVERITY_ORDER:
            raise PolicyError(f"injection.block_severity must be one of {list(SEVERITY_ORDER)} or null")
        return cls(default=default, tools=tools, block_severity=severity)

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise PolicyError(f"{path}: not valid JSON ({exc})") from exc
        return cls.from_dict(data)

    def _rule_for(self, tool: str) -> ToolRule | None:
        for rule in self.tools:  # an exact name always wins over a glob
            if rule.name == tool:
                return rule
        for rule in self.tools:
            if fnmatch.fnmatchcase(tool, rule.name):
                return rule
        return None

    def evaluate(self, tool: str, args: dict[str, Any] | None) -> Verdict:
        args = args or {}
        rule = self._rule_for(tool)
        if rule is None:
            return Verdict(self.default, f"no rule for tool '{tool}', default is {self.default}")

        for deny in rule.deny_args:
            if deny.arg in args and deny.pattern.search(_as_text(args[deny.arg])):
                return Verdict("block", f"argument '{deny.arg}' matches denied pattern /{deny.pattern.pattern}/")

        for allow in rule.allow_args:
            if allow.arg not in args:
                return Verdict("block", f"argument '{allow.arg}' is required by the policy but missing")
            if not allow.pattern.search(_as_text(args[allow.arg])):
                return Verdict("block", f"argument '{allow.arg}' does not match allowed pattern /{allow.pattern.pattern}/")

        return Verdict(rule.action, f"rule '{rule.name}' says {rule.action}")


def _check_action(action: Any, where: str) -> None:
    if action not in ACTIONS:
        raise PolicyError(f"{where} must be one of {list(ACTIONS)}, got {action!r}")


def _arg_rules(specs: Any, tool: str) -> tuple[ArgRule, ...]:
    rules = []
    for spec in specs or []:
        try:
            rules.append(ArgRule(spec["arg"], re.compile(spec["pattern"], re.IGNORECASE)))
        except (KeyError, TypeError) as exc:
            raise PolicyError(f"tools.{tool}: each argument rule needs 'arg' and 'pattern'") from exc
        except re.error as exc:
            raise PolicyError(f"tools.{tool}: bad pattern {spec['pattern']!r} ({exc})") from exc
    return tuple(rules)


def _as_text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
