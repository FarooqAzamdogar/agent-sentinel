"""Permission policy: which tools an agent may call, and with what arguments.

A policy is loaded from JSON (see policy.example.json) and answers one main
question, `Policy.evaluate(tool, args)`, with a `Verdict` of allow, ask or
block. It also holds the settings the firewall and the proxy read: limits on
calls per minute, what to do with secrets in arguments, and which requests
the server may send to the client.

Loading is strict: an unknown key, a repeated key or a wrong type is an error,
because a slip that is silently ignored leaves a policy weaker than its author
thinks. The error says where the mistake is and, when it can tell, what was
meant (see policy_errors.py). How an argument's value is judged is in
matchers.py.

A verdict carries two texts. `reason` is the full detail, for the audit log
and the human approver. `public` is what the agent may be told. It never says
which rule, wildcard or default produced a refusal, because a hijacked model
would use that to map the policy.

A verdict also names the rule that decided it, in `rule`, and for a rule
about one argument the argument it matched, in `matched_arg`. Both are for
the audit log and the operator only. A rule is named by where it is written
in the policy file:

    default                              the "default" action
    tools.send_email                     the action of that tool rule (a wildcard keeps its "*": tools.delete_*)
    deny_args[0]                         the first policy-wide deny rule
    tools.read_file.deny_args[1]         a tool rule's deny rule
    tools.send_email.allow_args[0]       a tool rule's allow rule
    tools.send_email.other_args          an argument no allow rule names
    tools.send_email.max_calls_per_minute, limits.max_calls_per_minute   rate limits
    server_requests.sampling/createMessage

Checks that are not written in the policy have the fixed names below (RULE_*).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence, TypeVar

from . import matchers
from .detector import SEVERITY_ORDER
from .matchers import Matcher, PathMatcher, PatternMatcher, decoded_spellings
from .policy_errors import (
    PolicyError,
    choice_message,
    json_error_message,
    listed,
    quoted,
    type_name,
    unicode_error_message,
    unknown_keys_message,
)
from .textutil import printable, texts_in

ACTIONS = ("allow", "ask", "block")

# In deny_args, this argument name means "any argument, at any depth".
ANY_ARG = "*"

# The one sentence an agent gets for a refusal that comes from a rule's action,
# from the default, or from an "ask". One constant for all three, so the agent
# cannot tell them apart and learns no rule name, wildcard or default.
NOT_PERMITTED = "this call is not permitted by the policy"

# The one text for anything that is let through, whichever rule, default or
# approval allowed it. Nothing shows it to the agent today; a program that
# does must not be able to leak a rule name ("rule 'search_*' says allow").
PERMITTED = "allowed"

# ---- names of checks that are not rules in the policy file ---------------------
RULE_DEFAULT = "default"
RULE_SECRETS = "secrets"  # the arguments hold what looks like a key or token
RULE_INJECTION = "injection"  # the detector found text at or above the blocking severity
RULE_UNSCANNABLE = "unscannable"  # content of a type that cannot be read
RULE_MALFORMED = "malformed"  # a call or message whose shape cannot be checked
RULE_QUARANTINE = "quarantine"  # a tool removed from the tool list, or one that cannot be vouched for yet
RULE_CALLER = "caller"  # Firewall.block() called by the program that uses the firewall

# An argument name is chosen by the agent; `matched_arg` keeps at most this much of it.
MAX_MATCHED_ARG_CHARS = 200

# Higher is stricter. When several wildcard rules match, the strictest verdict wins.
_STRICTNESS = {"allow": 0, "ask": 1, "block": 2}


def limit_rule(bucket: str) -> str:
    """The rule id for a bucket name from `Policy.call_limits` ("*" or "rule:<name>")."""
    if bucket.startswith("rule:"):
        return f"tools.{bucket[len('rule:'):]}.max_calls_per_minute"
    return "limits.max_calls_per_minute"


# ---- names with wildcards -----------------------------------------------------

def _glob_matches(pieces: tuple[str, ...], text: str) -> bool:
    """True if `text` is the pieces in order, with anything (or nothing) where each "*" stood.

    `pieces` is a rule name split at its stars. Only "*" is special, so "["
    and "?" in a name mean themselves, and case matters.

    Plain string search instead of a regular expression, on purpose: the text
    is a name chosen by the model, and "*_a_*_b_*" translated to ".*_a_.*_b_.*"
    takes quadratic time on a long hostile name. Taking the leftmost place for
    each piece never has to back up.
    """
    if len(pieces) == 1:
        return text == pieces[0]
    first, last = pieces[0], pieces[-1]
    if len(text) < len(first) + len(last) or not text.startswith(first) or not text.endswith(last):
        return False
    position, end = len(first), len(text) - len(last)
    for piece in pieces[1:-1]:
        found = text.find(piece, position, end)
        if found < 0:
            return False
        position = found + len(piece)
    return True


@dataclass(frozen=True)
class _NamedRule:
    """What tool rules and server-request rules share: a name that may hold "*", and an action."""

    name: str  # exact name, or a wildcard such as "delete_*"
    action: str
    _pieces: tuple[str, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        # Split once, at load time, so that checking a call does no parsing.
        object.__setattr__(self, "_pieces", tuple(self.name.split("*")))

    @property
    def is_glob(self) -> bool:
        return len(self._pieces) > 1

    def matches(self, name: str) -> bool:
        return _glob_matches(self._pieces, name)


_Rule = TypeVar("_Rule", bound=_NamedRule)


def _deciding_rules(rules: Sequence[_Rule], name: str) -> list[_Rule]:
    """The rules that decide for `name`: the exact one if there is one, otherwise every wildcard that fits.

    An exact name wins outright. That is the documented way to make an
    exception to a wildcard, for example "delete_draft" next to "delete_*".
    """
    for rule in rules:
        if not rule.is_glob and rule.name == name:
            return [rule]
    return [rule for rule in rules if rule.is_glob and rule.matches(name)]


# ---- the parts of a policy ----------------------------------------------------

@dataclass(frozen=True)
class ArgRule:
    """One entry of deny_args or allow_args: an argument name and the matcher that judges its value."""

    arg: str
    matcher: Matcher
    # allow_args only: the argument may be left out, but a value that is given must be acceptable.
    optional: bool = False

    def __post_init__(self) -> None:
        # Code written before matchers existed passed a compiled pattern here.
        if isinstance(self.matcher, re.Pattern):
            object.__setattr__(self, "matcher", PatternMatcher(self.matcher))

    def describe(self) -> str:
        """What this entry checks, for the operator."""
        which = "every argument" if self.arg == ANY_ARG else f"argument {quoted(self.arg)}"
        return f"{which}: {self.matcher.describe()}" + (", or left out" if self.optional else "")


@dataclass(frozen=True)
class ToolRule(_NamedRule):
    deny_args: tuple[ArgRule, ...] = ()
    allow_args: tuple[ArgRule, ...] = ()
    # "block" closes the argument list: a top-level argument that no allow_args entry names blocks the call.
    other_args: str = "allow"
    # Calls per minute for this rule. A wildcard rule has one count for all the tools it matches.
    max_calls_per_minute: int | None = None


@dataclass(frozen=True)
class ServerRequestRule(_NamedRule):
    """Whether the server may send the client a request with this method, such as "sampling/createMessage"."""


@dataclass(frozen=True)
class Verdict:
    action: str  # "allow", "ask" or "block"
    reason: str  # full detail, for the audit log and the human approver; never includes a pattern
    public: str  # what the agent may be told
    rule: str | None = None  # operator only: the rule that decided (see the module docstring)
    matched_arg: str | None = None  # operator only: the argument an argument rule matched


def _rule_verdict(action: str, reason: str, rule: str) -> Verdict:
    """A verdict that comes from a rule's action or from the default.

    Anything but allow gets the same public sentence, so a blocked rule, a
    blocked default and a call waiting for approval look alike to the agent.
    An allow gets the neutral PERMITTED, never the reason, which names the rule.
    """
    return Verdict(action, reason, PERMITTED if action == "allow" else NOT_PERMITTED, rule)


def _argument_block(reason: str, rule: str, matched_arg: str) -> Verdict:
    """A block caused by one argument.

    The agent is told which argument, because a well-behaved agent can fix the
    call with that. It is never told the pattern or which list held the rule.
    """
    return Verdict("block", reason, reason, rule, matched_arg)


def _bounded_name(name: Any) -> str:
    """An argument name to keep in `matched_arg`: as written, but not unboundedly long."""
    text = name if isinstance(name, str) else str(name)
    return text if len(text) <= MAX_MATCHED_ARG_CHARS else text[:MAX_MATCHED_ARG_CHARS] + "..."


@dataclass
class Policy:
    default: str = "block"
    tools: list[ToolRule] = field(default_factory=list)
    # Text with a finding at or above this severity is blocked.
    # None disables blocking (findings are still logged).
    block_severity: str | None = "high"
    # Deny rules for every call, whatever the tool. No tool rule can switch them off.
    deny_args: tuple[ArgRule, ...] = ()
    # "block" refuses a call whose arguments hold what looks like a credential; "allow" lets it through.
    secrets_in_arguments: str = "block"
    # Calls per minute for all tools together. None means no limit.
    max_calls_per_minute: int | None = None
    server_requests: tuple[ServerRequestRule, ...] = ()

    def __post_init__(self) -> None:
        # A policy can also be built in code, without the loader. An action such
        # as "deny" or "Block" must not get through to mean "anything goes".
        _expect_choice(self.default, "default", ACTIONS)
        for rule in self.tools:
            _expect_choice(rule.action, f"tools.{rule.name}.action", ACTIONS)
        for request in self.server_requests:
            _expect_choice(request.action, f"server_requests.{request.name}", ("allow", "block"))
        _expect_choice(self.secrets_in_arguments, "secrets.in_arguments", ("block", "allow"))
        _expect_severity(self.block_severity)

    # ---- loading ------------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        """Load a policy from a JSON file.

        Read as "utf-8-sig" because some Windows editors put a byte order mark
        at the start of the UTF-8 files they save. A file in another encoding
        (UTF-16, for example) is reported as not UTF-8. Every error starts with
        the file's name; a JSON syntax error also shows the line and a caret.

        A file that cannot be read raises OSError, as open() does;
        `policy_errors.file_error_message` words it for a person.
        """
        label = str(path)
        try:
            text = Path(path).read_text(encoding="utf-8-sig")
        except UnicodeDecodeError as exc:
            raise PolicyError(unicode_error_message(label, exc)) from exc
        try:
            data = json.loads(text, object_pairs_hook=_no_duplicate_keys)
        except PolicyError as exc:  # a repeated key: say so, instead of "not valid JSON"
            raise PolicyError(f"{label}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise PolicyError(json_error_message(label, exc)) from exc
        except (ValueError, RecursionError) as exc:  # absurd nesting, or a number Python cannot hold
            raise PolicyError(f"{label}: not valid JSON ({exc})") from exc
        try:
            return cls.from_dict(data)
        except PolicyError as exc:
            raise PolicyError(f"{label}: {exc}") from exc

    @classmethod
    def from_dict(cls, data: Any) -> "Policy":
        _expect_object(
            data, "the policy",
            allowed_keys=("default", "deny_args", "tools", "server_requests", "injection", "secrets", "limits"),
        )

        default = data.get("default", "block")
        _expect_choice(default, "default", ACTIONS)

        tool_specs = data.get("tools", {})
        _expect_object(tool_specs, "tools")
        tools = [_tool_rule(name, spec) for name, spec in tool_specs.items()]

        injection = data.get("injection", {})
        _expect_object(injection, "injection", allowed_keys=("block_severity",))
        severity = injection.get("block_severity", "high")
        _expect_severity(severity)

        secrets = data.get("secrets", {})
        _expect_object(secrets, "secrets", allowed_keys=("in_arguments",))
        in_arguments = secrets.get("in_arguments", "block")
        _expect_choice(in_arguments, "secrets.in_arguments", ("block", "allow"))

        limits = data.get("limits", {})
        _expect_object(limits, "limits", allowed_keys=("max_calls_per_minute",))

        return cls(
            default=default,
            tools=tools,
            block_severity=severity,
            deny_args=_arg_rules(data.get("deny_args", []), "deny_args", deny=True),
            secrets_in_arguments=in_arguments,
            max_calls_per_minute=_calls_per_minute(limits, "limits"),
            server_requests=_server_request_rules(data.get("server_requests", {})),
        )

    # ---- evaluating ---------------------------------------------------------

    def evaluate(self, tool: str, args: dict[str, Any] | None) -> Verdict:
        """Decide what should happen to a call of `tool` with `args`.

        In order: the policy-wide deny_args, which hold for every call; then
        the rule with exactly this name; otherwise every wildcard rule that
        matches, each checked in full, and the strictest result wins. With no
        rule at all, the default.
        """
        if args is None:
            args = {}
        if not isinstance(tool, str) or not isinstance(args, dict):
            # Nothing below can check such a call, and what cannot be checked is not let through.
            reason = "the tool name is not text or the arguments are not an object"
            return Verdict("block", reason, NOT_PERMITTED, RULE_MALFORMED)

        denied = _denied_argument(self.deny_args, args, "deny_args")
        if denied is not None:
            return denied

        rules = _deciding_rules(self.tools, tool)
        if not rules:
            reason = f"no rule for '{printable(tool, limit=80)}', default is {self.default}"
            return _rule_verdict(self.default, reason, RULE_DEFAULT)

        # Strictest wins, so a block holds whatever else matches and the order of
        # the rules in the file does not matter. max() returns the first of equals,
        # which keeps file order between verdicts that are equally strict.
        verdicts = [_apply_rule(rule, args) for rule in rules]
        return max(verdicts, key=lambda verdict: _STRICTNESS[verdict.action])

    def server_request_verdict(self, method: str) -> Verdict:
        """Decide whether the server may send the client a request or notification with this method.

        An exact method name beats a wildcard; among matching wildcards a
        block wins. With no matching rule the request is allowed, as it was
        before this section existed, and the verdict names no rule. A policy
        closes that with "*": "block".
        """
        if not isinstance(method, str):
            return Verdict("block", "the method name is not text", NOT_PERMITTED, RULE_MALFORMED)
        rules = _deciding_rules(self.server_requests, method)
        for rule in rules:
            if rule.action == "block":
                reason = f"server_requests rule '{rule.name}' says block"
                return Verdict("block", reason, NOT_PERMITTED, f"server_requests.{rule.name}")
        if rules:
            reason = f"server_requests rule '{rules[0].name}' says allow"
            return Verdict("allow", reason, PERMITTED, f"server_requests.{rules[0].name}")
        return Verdict("allow", "no server_requests rule matches, so it is allowed", PERMITTED)

    def server_request_action(self, method: str) -> str:
        """Return "allow" or "block" for a request the server sends to the client (see server_request_verdict)."""
        return self.server_request_verdict(method).action

    def call_limits(self, tool: str) -> list[tuple[str, int]]:
        """Return the (bucket name, calls per minute) limits that apply to a call of `tool`.

        "*" is the limit for all tools together. "rule:<name>" is the limit of
        one rule. Every rule that matches counts, an exact name and wildcards
        alike: a limit on "delete_*" still covers a tool that also has a rule
        of its own, because a limit that an exception could lift would not be
        much of a limit. `limit_rule` turns a bucket name into a rule id.
        """
        limits: list[tuple[str, int]] = []
        if self.max_calls_per_minute is not None:
            limits.append(("*", self.max_calls_per_minute))
        if isinstance(tool, str):
            limits.extend(
                (f"rule:{rule.name}", rule.max_calls_per_minute)
                for rule in self.tools
                if rule.max_calls_per_minute is not None and rule.matches(tool)
            )
        return limits

    # ---- advice for the author ------------------------------------------------

    def warnings(self) -> list[str]:
        """Things that are valid but probably not what the author meant. Printed by `validate`."""
        found: list[str] = []
        if self.default == "allow":
            found.append('default is "allow", so every tool without a rule can be called; "block" is the safe default')
        found.extend(_empty_match_warnings("deny_args", self.deny_args, ()))
        for rule in self.tools:
            found.extend(_empty_match_warnings(f"tools.{rule.name}", rule.deny_args, rule.allow_args))
        found.extend(_overridden_glob_warnings(self.tools))
        found.extend(_missing_root_warnings(self))
        return found

    def describe_rule(self, rule_id: str) -> str | None:
        """What the rule with this id checks, for the operator; None if this policy has no such rule.

        For `explain` and similar tools that start from an audit record. Never
        show the result to the agent: it names patterns and rules.
        """
        fixed = {
            RULE_DEFAULT: f'the default: "{self.default}" for every tool without a rule',
            RULE_SECRETS: "the secret guard: the arguments hold what looks like a key or token (secrets.in_arguments)",
            RULE_INJECTION: f"the injection detector: a finding at or above '{self.block_severity}' "
                            "(injection.block_severity)",
            RULE_UNSCANNABLE: "content of a type that cannot be read is refused",
            RULE_MALFORMED: "a call or message whose shape cannot be checked is refused",
            RULE_QUARANTINE: "the tool was removed from the tool list (its description was flagged, it changed "
                             "after it was first seen, or its list could not be checked)",
            RULE_CALLER: "the program that uses the firewall blocked it (Firewall.block)",
        }
        if rule_id in fixed:
            return fixed[rule_id]
        if rule_id == "limits.max_calls_per_minute" and self.max_calls_per_minute is not None:
            return f"at most {self.max_calls_per_minute} call(s) per minute for all tools together"
        indexed = re.fullmatch(r"deny_args\[([0-9]+)\]", rule_id)
        if indexed:
            entry = _entry(self.deny_args, indexed.group(1))
            return None if entry is None else f"policy-wide deny rule, {entry.describe()}"
        if rule_id.startswith("server_requests."):
            name = rule_id[len("server_requests."):]
            for request in self.server_requests:
                if request.name == name:
                    return f"server request rule '{name}': {request.action}"
            return None
        for rule in self.tools:
            found = _describe_tool_rule_part(rule, rule_id)
            if found is not None:
                return found
        return None


# ---- applying a rule ----------------------------------------------------------

def _apply_rule(rule: ToolRule, args: dict[str, Any]) -> Verdict:
    """Check a call against one rule: its deny_args, its allow_args, its other_args, then its action."""
    where = f"tools.{rule.name}"
    denied = _denied_argument(rule.deny_args, args, f"{where}.deny_args")
    if denied is not None:
        return denied

    for index, allow in enumerate(rule.allow_args):
        rule_id = f"{where}.allow_args[{index}]"
        if allow.arg not in args:
            if allow.optional:
                continue
            return _argument_block(f"argument '{allow.arg}' is required by the policy but missing", rule_id, allow.arg)
        if not _is_allowed(allow, args[allow.arg]):
            return _argument_block(f"argument '{allow.arg}' has a value the policy does not allow", rule_id, allow.arg)

    if rule.other_args == "block":
        # Top level only. An allowed argument cannot carry more arguments inside
        # it, because _is_allowed refuses objects.
        named = {allow.arg for allow in rule.allow_args}
        for name in args:
            if name not in named:
                # The name is chosen by the agent: shorten and escape it before repeating it.
                reason = f"argument '{printable(name, limit=60)}' is not accepted by the policy"
                return _argument_block(reason, f"{where}.other_args", _bounded_name(name))

    return _rule_verdict(rule.action, f"rule '{rule.name}' says {rule.action}", where)


def _denied_argument(rules: tuple[ArgRule, ...], args: dict[str, Any], where: str) -> Verdict | None:
    """Return a block for the first deny rule that matches, or None.

    The wording is the same for policy-wide and per-rule deny lists, so the
    agent cannot tell which list refused it; `rule` tells the operator.
    """
    for index, rule in enumerate(rules):
        matched = _denied_in(rule, args)
        if matched is not None:
            which = "an argument" if rule.arg == ANY_ARG else f"argument '{rule.arg}'"
            return _argument_block(f"{which} has a value the policy denies", f"{where}[{index}]", matched)
    return None


def _denied_in(rule: ArgRule, args: dict[str, Any]) -> str | None:
    """The name of the argument in which the deny rule matches, or None.

    Looks inside nested lists and objects, including object keys, so a denied
    value cannot be hidden one level down. For "*", the name of an argument
    is itself one of the texts checked.
    """
    if rule.arg == ANY_ARG:
        for name, value in args.items():
            if _found_in_any(rule.matcher, texts_in({name: value}, keys=True, scalars=True)):
                return _bounded_name(name)
        return None
    if rule.arg not in args:
        return None
    # An empty list or object holds no text, but the argument is there: check
    # it as empty text, so that a pattern meant to forbid the argument still does.
    texts = texts_in(args[rule.arg], keys=True, scalars=True) or [""]
    return rule.arg if _found_in_any(rule.matcher, texts) else None


def _found_in_any(matcher: Matcher, texts: list[str]) -> bool:
    """True if the matcher finds a match in any text, as written or after percent-decoding.

    Extra spellings can only add blocks. A text still encoded after the last
    round of decoding counts as a match: it could not be checked.
    """
    for text in texts:
        for spelling in decoded_spellings(text):
            if spelling is None or matcher.found_in(spelling):
                return True
    return False


def _is_allowed(rule: ArgRule, value: Any) -> bool:
    """True if the matcher accepts the WHOLE value.

    Whole-value matching is deliberate: with a "contains" match, the address
    list "attacker@evil.example, boss@example.com" would pass a rule meant to
    allow only example.com.

    Accepted shapes are text, a number, true or false, or a flat list of those
    in which every entry is acceptable. Numbers and booleans are matched as
    JSON writes them ("5", "1.5", "true"), so a pattern of "true" pins a flag;
    a typed matcher (path, url, email) accepts text only. Everything else is
    refused: an empty list, a nested list, null, and any object, because a
    matcher cannot vouch for an object's keys and a tool may read data from them.
    """
    entries = value if isinstance(value, (list, tuple)) else [value]
    if not entries:
        return False
    for entry in entries:
        text = _scalar_text(entry)
        if text is None or (rule.matcher.text_only and not isinstance(entry, str)):
            return False
        if not rule.matcher.accepts(text):
            return False
    return True


def _scalar_text(value: Any) -> str | None:
    """The text an allow matcher is given, or None for a value that is not a plain scalar."""
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):
        return json.dumps(value)
    return None


# ---- describing rules -----------------------------------------------------------

def _entry(entries: tuple[ArgRule, ...], index: str) -> ArgRule | None:
    position = int(index)
    return entries[position] if position < len(entries) else None


def _describe_tool_rule_part(rule: ToolRule, rule_id: str) -> str | None:
    """Describe `rule_id` if it names this tool rule or one of its parts."""
    prefix = f"tools.{rule.name}"
    if rule_id == prefix:
        return f"tool rule '{rule.name}': {rule.action}"
    if not rule_id.startswith(prefix + "."):
        return None
    part = rule_id[len(prefix) + 1:]
    if part == "other_args" and rule.other_args == "block":
        named = ", ".join(quoted(allow.arg) for allow in rule.allow_args) or "none"
        return f"tool rule '{rule.name}' accepts only the arguments its allow_args name ({named})"
    if part == "max_calls_per_minute" and rule.max_calls_per_minute is not None:
        return f"tool rule '{rule.name}': at most {rule.max_calls_per_minute} call(s) per minute"
    indexed = re.fullmatch(r"(deny_args|allow_args)\[([0-9]+)\]", part)
    if indexed:
        entries = rule.deny_args if indexed.group(1) == "deny_args" else rule.allow_args
        entry = _entry(entries, indexed.group(2))
        if entry is not None:
            kind = "deny" if indexed.group(1) == "deny_args" else "allow"
            return f"tool rule '{rule.name}', {kind} rule for {entry.describe()}"
    return None


# ---- warnings -----------------------------------------------------------------

def _empty_match_warnings(where: str, deny_args: tuple[ArgRule, ...], allow_args: tuple[ArgRule, ...]) -> list[str]:
    """Warn about patterns that match the empty string.

    A warning and not an error: an empty deny pattern is a legitimate way to
    forbid an argument outright. A deny pattern that matches only the empty
    string ("^$") forbids empty values and is not reported. Optional allow
    entries are skipped, because "any text, or left out" is how a closed
    argument list names a free-text argument, and an empty value there says
    no more than leaving it out. Only patterns can do this; the other
    matchers refuse empty settings when the policy is loaded.
    """
    found = []
    for deny in deny_args:
        if not isinstance(deny.matcher, PatternMatcher):
            continue
        if deny.matcher.pattern.search("") and deny.matcher.pattern.search("x"):
            scope = "every call" if deny.arg == ANY_ARG else "every call that has the argument"
            found.append(
                f"{where}: the deny pattern for argument '{deny.arg}' matches the empty string, "
                f"so it probably blocks {scope}"
            )
    for allow in allow_args:
        if isinstance(allow.matcher, PatternMatcher) and not allow.optional and allow.matcher.pattern.fullmatch(""):
            found.append(
                f"{where}: the allow pattern for argument '{allow.arg}' matches the empty string, "
                "so an empty value is accepted"
            )
    return found


def _overridden_glob_warnings(tools: list[ToolRule]) -> list[str]:
    """Warn about a wildcard rule whose action can never win because a rule of only "*" is stricter.

    The strictest matching wildcard wins, so {"*": "ask", "search_*": "allow"}
    asks for every search tool. Overlap between two partial wildcards is not
    reported: it depends on which tool names exist.
    """
    globs = [rule for rule in tools if rule.is_glob]
    found = []
    for catch_all in globs:
        if catch_all.name.strip("*"):
            continue
        if catch_all.action == "allow":
            found.append(
                f"tools.{catch_all.name}: allows every tool that has no rule of its own, "
                'which is the same as "default": "allow"'
            )
        for rule in globs:
            if _STRICTNESS[rule.action] < _STRICTNESS[catch_all.action]:
                found.append(
                    f"tools.{rule.name}: says {rule.action}, but rule '{catch_all.name}' matches the same tools and "
                    f"says {catch_all.action}, and the strictest wildcard wins; use \"default\" for the fallback"
                )
    return found


def _missing_root_warnings(policy: Policy) -> list[str]:
    """Warn about a path root that is not a folder on this machine: probably a typo, or the wrong machine."""
    lists = [("deny_args", policy.deny_args)]
    for rule in policy.tools:
        lists += [(f"tools.{rule.name}.deny_args", rule.deny_args), (f"tools.{rule.name}.allow_args", rule.allow_args)]
    found = []
    for where, entries in lists:
        for index, entry in enumerate(entries):
            if isinstance(entry.matcher, PathMatcher):
                found.extend(
                    f"{where}[{index}]: the root '{root}' is not a folder on this machine"
                    for root in entry.matcher.roots if not os.path.isdir(root)
                )
    return found


# ---- validation helpers -------------------------------------------------------

def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build one JSON object, refusing a key that appears twice.

    json.loads keeps the last of two equal keys without a word, so a second
    "run_shell": "allow" further down a long file would replace the block
    above it.
    """
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"duplicate key {key!r}: a key may appear only once in an object")
        result[key] = value
    return result


def _tool_rule(name: Any, spec: Any) -> ToolRule:
    _expect_name(name, "tool name")
    where = f"tools.{name}"
    if isinstance(spec, str):  # shorthand: "tool": "allow"
        _expect_choice(spec, where, ACTIONS)
        spec = {"action": spec}
    elif not isinstance(spec, dict):
        raise PolicyError(f"{where} must be an action ({listed(ACTIONS)}) or an object, got {type_name(spec)}")
    _expect_object(
        spec, where, allowed_keys=("action", "deny_args", "allow_args", "other_args", "max_calls_per_minute")
    )
    if "action" not in spec:
        # No default on purpose: a rule left without an action while editing must not come to mean allow.
        raise PolicyError(f"{where} needs an 'action', one of {list(ACTIONS)}")
    _expect_choice(spec["action"], f"{where}.action", ACTIONS)
    other_args = spec.get("other_args", "allow")
    _expect_choice(other_args, f"{where}.other_args", ("allow", "block"))
    return ToolRule(
        name=name,
        action=spec["action"],
        deny_args=_arg_rules(spec.get("deny_args", []), f"{where}.deny_args", deny=True),
        allow_args=_arg_rules(spec.get("allow_args", []), f"{where}.allow_args", deny=False),
        other_args=other_args,
        max_calls_per_minute=_calls_per_minute(spec, where),
    )


def _arg_rules(specs: Any, where: str, deny: bool) -> tuple[ArgRule, ...]:
    """Read a deny_args (deny=True) or allow_args (deny=False) list. Each entry is named where[index]."""
    if not isinstance(specs, list):
        raise PolicyError(f"{where} must be a list ([ ... ]), got {type_name(specs)}")
    rules = []
    for index, spec in enumerate(specs):
        entry = f"{where}[{index}]"
        _expect_object(spec, entry, allowed_keys=matchers.ENTRY_KEYS)
        arg = spec.get("arg")
        if not isinstance(arg, str):
            got = "" if arg is None else f", got {type_name(arg)}"
            raise PolicyError(f"{entry} needs an 'arg': the name of the argument, as text{got}")
        _expect_name(arg, f"{entry}: argument name")
        if arg == ANY_ARG and not deny:
            raise PolicyError(f"{entry}: '{ANY_ARG}' is only supported in deny_args")
        if "*" in arg and arg != ANY_ARG:
            # Tool names take wildcards; argument names do not. "file_*" would
            # load and then match only an argument literally called "file_*".
            raise PolicyError(
                f"{entry}: argument name {arg!r} holds a '*'. Argument names are exact; "
                f"use '{ANY_ARG}' alone to mean every argument"
            )
        # "optional" makes sense on the allow side only. Accepting it on the
        # deny side would be a key that is silently ignored.
        if deny and "optional" in spec:
            raise PolicyError(f"{entry}: 'optional' is only used in allow_args")
        optional = spec.get("optional", False)
        if not isinstance(optional, bool):
            raise PolicyError(f"{entry}: 'optional' must be true or false, got {quoted(optional)}")
        rules.append(ArgRule(arg, matchers.build(spec, entry, deny=deny, any_arg=arg == ANY_ARG), optional))
    return tuple(rules)


def _server_request_rules(specs: Any) -> tuple[ServerRequestRule, ...]:
    _expect_object(specs, "server_requests")
    rules = []
    for name, action in specs.items():
        _expect_name(name, "server_requests: method name")
        # No "ask": the proxy has nobody to ask on the server's behalf.
        _expect_choice(action, f"server_requests.{name}", ("allow", "block"))
        rules.append(ServerRequestRule(name, action))
    return tuple(rules)


def _calls_per_minute(spec: dict[str, Any], where: str) -> int | None:
    """Read an optional max_calls_per_minute. None means the key is absent, so there is no limit."""
    if "max_calls_per_minute" not in spec:
        return None
    value = spec["max_calls_per_minute"]
    # bool is a subclass of int in Python, and `true` is not a number of calls.
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise PolicyError(f"{where}.max_calls_per_minute must be a whole number of 1 or more, got {quoted(value)}")
    return value


def _expect_object(value: Any, where: str, allowed_keys: tuple[str, ...] | None = None) -> None:
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be a JSON object ({{ ... }}), got {type_name(value)}")
    if allowed_keys is not None:
        unknown = [str(key) for key in value if key not in allowed_keys]
        if unknown:
            raise PolicyError(unknown_keys_message(where, unknown, allowed_keys))


def _expect_choice(value: Any, where: str, choices: tuple[str, ...]) -> None:
    if not isinstance(value, str) or value not in choices:
        raise PolicyError(choice_message(where, value, choices))


def _expect_severity(severity: Any) -> None:
    # The type check comes first: a list or object here cannot be looked up in a dict.
    if severity is not None and (not isinstance(severity, str) or severity not in SEVERITY_ORDER):
        message = choice_message("injection.block_severity", severity, tuple(SEVERITY_ORDER))
        raise PolicyError(f"{message}. null turns blocking off")


def _expect_name(name: Any, what: str) -> None:
    """Refuse a tool, method or argument name that is empty or has spaces around it: almost certainly a typo."""
    if not isinstance(name, str) or not name or name != name.strip():
        raise PolicyError(f"{what} {name!r} must be text that is not empty and has no spaces around it")
