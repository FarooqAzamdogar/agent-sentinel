"""Permission policy: which tools an agent may call, and with what arguments.

A policy is loaded from JSON (see policy.example.json) and answers one main
question, `Policy.evaluate(tool, args)`, with a `Verdict` of allow, ask or
block. It also holds the settings the firewall and the proxy read: limits on
calls per minute, what to do with secrets in arguments, and which requests
the server may send to the client.

Loading is strict: an unknown key, a repeated key or a wrong type is an error,
because a slip that is silently ignored leaves a policy weaker than its author
thinks.

A verdict carries two texts. `reason` is the full detail, for the audit log
and the human approver. `public` is what the agent may be told. It never says
which rule, wildcard or default produced a refusal, because a hijacked model
would use that to map the policy.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence, TypeVar
from urllib.parse import unquote

from .detector import SEVERITY_ORDER
from .textutil import texts_in

ACTIONS = ("allow", "ask", "block")

# In deny_args, this argument name means "any argument, at any depth".
ANY_ARG = "*"

# The one sentence an agent gets for a refusal that comes from a rule's action,
# from the default, or from an "ask". One constant for all three, so the agent
# cannot tell them apart and learns no rule name, wildcard or default.
NOT_PERMITTED = "this call is not permitted by the policy"

# Higher is stricter. When several wildcard rules match, the strictest verdict wins.
_STRICTNESS = {"allow": 0, "ask": 1, "block": 2}

# A server decodes a percent-encoded value once. Three rounds leave room for
# values that were encoded again on the way; a value that needs more is refused.
_DECODE_ROUNDS = 3

# What unquote() would change. Looking for it first keeps text with no escapes
# in it ("100% done", or megabytes of bare "%") away from unquote, which is slow there.
_PERCENT_ESCAPE = re.compile("%[0-9A-Fa-f]{2}")


class PolicyError(ValueError):
    """The policy is malformed."""


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
    arg: str
    pattern: re.Pattern[str]
    # allow_args only: the argument may be left out, but a value that is given must match.
    optional: bool = False


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


def _rule_verdict(action: str, reason: str) -> Verdict:
    """A verdict that comes from a rule's action or from the default.

    Anything but allow gets the same public sentence, so a blocked rule, a
    blocked default and a call waiting for approval look alike to the agent.
    """
    return Verdict(action, reason, reason if action == "allow" else NOT_PERMITTED)


def _argument_block(reason: str) -> Verdict:
    """A block caused by one argument.

    The agent is told which argument, because a well-behaved agent can fix the
    call with that. It is never told the pattern.
    """
    return Verdict("block", reason, reason)


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

    # ---- loading ------------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        """Load a policy from a JSON file.

        Read as "utf-8-sig" because Notepad and Windows PowerShell 5 put a
        byte order mark at the start of the files they save.
        """
        try:
            text = Path(path).read_text(encoding="utf-8-sig")
            data = json.loads(text, object_pairs_hook=_no_duplicate_keys)
        except PolicyError as exc:  # a repeated key: say so, instead of "not valid JSON"
            raise PolicyError(f"{path}: {exc}") from exc
        except (ValueError, RecursionError) as exc:  # bad JSON, bad UTF-8 or absurd nesting
            raise PolicyError(f"{path}: not valid JSON ({exc})") from exc
        return cls.from_dict(data)

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
        # The type check comes first: a list or object here cannot be looked up in a dict.
        if severity is not None and (not isinstance(severity, str) or severity not in SEVERITY_ORDER):
            raise PolicyError(f"injection.block_severity must be one of {list(SEVERITY_ORDER)} or null")

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
            return Verdict("block", "the tool name is not text or the arguments are not an object", NOT_PERMITTED)

        denied = _denied_argument(self.deny_args, args)
        if denied is not None:
            return denied

        rules = _deciding_rules(self.tools, tool)
        if not rules:
            return _rule_verdict(self.default, f"no rule for '{tool}', default is {self.default}")

        # Strictest wins, so a block holds whatever else matches and the order of
        # the rules in the file does not matter. max() returns the first of equals,
        # which keeps file order between verdicts that are equally strict.
        verdicts = [_apply_rule(rule, args) for rule in rules]
        return max(verdicts, key=lambda verdict: _STRICTNESS[verdict.action])

    def server_request_action(self, method: str) -> str:
        """Return "allow" or "block" for a request the server sends to the client.

        An exact method name beats a wildcard; among matching wildcards a
        block wins. With no matching rule the request is allowed, as it was
        before this section existed. A policy closes that with "*": "block".
        """
        if not isinstance(method, str):
            return "block"
        actions = [rule.action for rule in _deciding_rules(self.server_requests, method)]
        return "block" if "block" in actions else "allow"

    def call_limits(self, tool: str) -> list[tuple[str, int]]:
        """Return the (bucket name, calls per minute) limits that apply to a call of `tool`.

        "*" is the limit for all tools together. "rule:<name>" is the limit of
        one rule. Every rule that matches counts, an exact name and wildcards
        alike: a limit on "delete_*" still covers a tool that also has a rule
        of its own, because a limit that an exception could lift would not be
        much of a limit.
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
        return found


# ---- applying a rule ----------------------------------------------------------

def _apply_rule(rule: ToolRule, args: dict[str, Any]) -> Verdict:
    """Check a call against one rule: its deny_args, its allow_args, its other_args, then its action."""
    denied = _denied_argument(rule.deny_args, args)
    if denied is not None:
        return denied

    for allow in rule.allow_args:
        if allow.arg not in args:
            if allow.optional:
                continue
            return _argument_block(f"argument '{allow.arg}' is required by the policy but missing")
        if not _is_allowed(allow, args[allow.arg]):
            return _argument_block(f"argument '{allow.arg}' has a value the policy does not allow")

    if rule.other_args == "block":
        # Top level only. An allowed argument cannot carry more arguments inside
        # it, because _is_allowed refuses objects.
        named = {allow.arg for allow in rule.allow_args}
        for name in args:
            if name not in named:
                return _argument_block(f"argument '{name}' is not accepted by the policy")

    return _rule_verdict(rule.action, f"rule '{rule.name}' says {rule.action}")


def _denied_argument(rules: tuple[ArgRule, ...], args: dict[str, Any]) -> Verdict | None:
    """Return a block for the first deny rule that matches, or None.

    The wording is the same for policy-wide and per-rule deny lists, so the
    agent cannot tell which list refused it.
    """
    for rule in rules:
        if _is_denied(rule, args):
            which = "an argument" if rule.arg == ANY_ARG else f"argument '{rule.arg}'"
            return _argument_block(f"{which} has a value the policy denies")
    return None


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
    return any(_found_in_any_spelling(rule.pattern, text) for text in texts_in(value, keys=True, scalars=True))


def _found_in_any_spelling(pattern: re.Pattern[str], text: str) -> bool:
    """True if the pattern is found in the text as written or after percent-decoding.

    "file:///home/me/%2Essh/id_rsa" names the same file as the plain spelling
    to anything that treats the value as a URI, so a deny rule has to see both.
    Extra spellings can only add blocks, and only for values that decode to
    something the author already denied.

    The number of rounds is fixed, so a value that was encoded a thousand
    times over cannot buy a thousand rounds of work. A value that still holds
    an escape after the last round is treated as denied: nothing ordinary is
    encoded that many times.

    Compatibility folding (NFKC) is left out on purpose: file systems do not
    apply it, and it is slow on long runs of combining marks.
    """
    if pattern.search(text):
        return True
    for _ in range(_DECODE_ROUNDS):
        if not _PERCENT_ESCAPE.search(text):
            return False
        text = unquote(text, errors="replace")
        if pattern.search(text):
            return True
    return _PERCENT_ESCAPE.search(text) is not None


def _is_allowed(rule: ArgRule, value: Any) -> bool:
    """True if the pattern matches the WHOLE value.

    Whole-value matching is deliberate: with a "contains" match, the address
    list "attacker@evil.example, boss@example.com" would pass a rule meant to
    allow only example.com.

    Accepted shapes are text, a number, true or false, or a flat list of those
    in which every entry matches. Numbers and booleans are matched as JSON
    writes them ("5", "1.5", "true"), so a pattern of "true" pins a flag.
    Everything else is refused: an empty list, a nested list, null, and any
    object, because a pattern cannot vouch for an object's keys and a tool may
    read data from them.
    """
    entries = value if isinstance(value, (list, tuple)) else [value]
    if not entries:
        return False
    for entry in entries:
        text = _scalar_text(entry)
        if text is None or not rule.pattern.fullmatch(text):
            return False
    return True


def _scalar_text(value: Any) -> str | None:
    """The text an allow pattern is matched against, or None for a value that is not a plain scalar."""
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):
        return json.dumps(value)
    return None


# ---- warnings -----------------------------------------------------------------

def _empty_match_warnings(where: str, deny_args: tuple[ArgRule, ...], allow_args: tuple[ArgRule, ...]) -> list[str]:
    """Warn about patterns that match the empty string.

    A warning and not an error: an empty deny pattern is a legitimate way to
    forbid an argument outright. Optional allow entries are skipped, because
    "any text, or left out" is how a closed argument list names a free-text
    argument, and an empty value there says no more than leaving it out.
    """
    found = []
    for deny in deny_args:
        if deny.pattern.search(""):
            scope = "every call" if deny.arg == ANY_ARG else "every call that has the argument"
            found.append(
                f"{where}: the deny pattern for argument '{deny.arg}' matches the empty string, "
                f"so it probably blocks {scope}"
            )
    for allow in allow_args:
        if not allow.optional and allow.pattern.fullmatch(""):
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
        for rule in globs:
            if _STRICTNESS[rule.action] < _STRICTNESS[catch_all.action]:
                found.append(
                    f"tools.{rule.name}: says {rule.action}, but rule '{catch_all.name}' matches the same tools and "
                    f"says {catch_all.action}, and the strictest wildcard wins; use \"default\" for the fallback"
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
        spec = {"action": spec}
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
    """Read a deny_args (deny=True) or allow_args (deny=False) list."""
    if not isinstance(specs, list):
        raise PolicyError(f"{where} must be a list")
    # "optional" and "*" each make sense on one side only. Accepting them on the
    # other would be a key that is silently ignored.
    allowed_keys = ("arg", "pattern") if deny else ("arg", "pattern", "optional")
    rules = []
    for spec in specs:
        _expect_object(spec, f"an entry of {where}", allowed_keys=allowed_keys)
        arg, pattern, optional = spec.get("arg"), spec.get("pattern"), spec.get("optional", False)
        if not isinstance(arg, str) or not isinstance(pattern, str):
            raise PolicyError(f"each entry of {where} needs a text 'arg' and a text 'pattern'")
        _expect_name(arg, f"{where}: argument name")
        if arg == ANY_ARG and not deny:
            raise PolicyError(f"{where}: '{ANY_ARG}' is only supported in deny_args")
        if not isinstance(optional, bool):
            raise PolicyError(f"{where}: 'optional' must be true or false, got {optional!r}")
        try:
            # Patterns are not stripped or checked for edge spaces: "rm -rf " is a legitimate pattern.
            rules.append(ArgRule(arg, re.compile(pattern, re.IGNORECASE), optional))
        except re.error as exc:
            raise PolicyError(f"{where}: bad pattern {pattern!r} ({exc})") from exc
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
        raise PolicyError(f"{where}.max_calls_per_minute must be a whole number of 1 or more, got {value!r}")
    return value


def _expect_object(value: Any, where: str, allowed_keys: tuple[str, ...] | None = None) -> None:
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be a JSON object")
    if allowed_keys is not None:
        unknown = sorted(str(key) for key in value if key not in allowed_keys)
        if unknown:
            raise PolicyError(f"{where} has unknown key(s) {unknown}; allowed keys are {list(allowed_keys)}")


def _expect_choice(value: Any, where: str, choices: tuple[str, ...]) -> None:
    if not isinstance(value, str) or value not in choices:
        raise PolicyError(f"{where} must be one of {list(choices)}, got {value!r}")


def _expect_name(name: Any, what: str) -> None:
    """Refuse a tool, method or argument name that can never match: empty, or with spaces around it."""
    if not isinstance(name, str) or not name or name != name.strip():
        raise PolicyError(f"{what} {name!r} must be text that is not empty and has no spaces around it")
