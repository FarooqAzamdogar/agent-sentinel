"""Permission policy: which tools an agent may call, and with what arguments.

A policy is loaded from JSON (see policy.example.json) and answers one main
question, `Policy.evaluate(tool, args)`, with a `Verdict` of allow, ask or
block. It also holds the settings the firewall and the proxy read: limits on
calls per minute, the secret guard's settings, flow rules (which look at what
the agent has read earlier in the session, see session.py), which requests
the server may send to the client and which the client may send to the
server, and whether tools the policy blocks are hidden from the tool list.

Loading is strict: an unknown key, a repeated key or a wrong type is an error,
because a slip that is silently ignored leaves a policy weaker than its author
thinks. The error says where the mistake is and, when it can tell, what was
meant (see policy_errors.py). How an argument's value is judged is in
matchers.py.

A verdict carries two texts. `reason` is the full detail, for the audit log
and the human approver. `public` is what the agent may be told. It never says
which rule, wildcard or default produced a refusal, because a hijacked model
would use that to map the policy. It names a refused argument only for a tool
the agent may call (so that it can fix the call), and in the same words
whichever list refused the value.

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
    tools.Bash.command.network           a tool rule's command section, by class (or "unreadable")
    tools.send_email.max_calls_per_minute, limits.max_calls_per_minute   rate limits
    server_requests.sampling/createMessage
    client_requests.completion/complete
    flows[0]                             the first flow rule
    secrets.patterns[0]                  the first custom secret format

Checks that are not written in the policy have the fixed names below (RULE_*).
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence, TypeVar

from . import commands, jsonutil, matchers
from .commands import CommandRule
from .detector import SEVERITY_ORDER
from .matchers import Matcher, PathMatcher, PatternMatcher, decoded_spellings
from .policy_errors import (
    PolicyError,
    choice_message,
    did_you_mean,
    json_error_message,
    listed,
    quoted,
    type_name,
    unicode_error_message,
    unknown_keys_message,
)
from .session import BUILTIN_LABELS, PRIVATE, SINK, UNTRUSTED, SessionMarks, is_label
from .textutil import printable, texts_in

ACTIONS = ("allow", "ask", "block")

# In deny_args, this argument name means "any argument, at any depth".
ANY_ARG = "*"

# The one sentence an agent gets for a refusal that comes from a rule's action,
# from the default, or from an "ask". One constant for all three, so the agent
# cannot tell them apart and learns no rule name, wildcard or default.
NOT_PERMITTED = "this call is not permitted by the policy"

# What the agent is told about an argument whose value a deny_args or an
# allow_args entry refuses: the same words for both, and for a policy-wide
# entry as for a tool's own, so the agent cannot tell which list refused it.
VALUE_NOT_PERMITTED = "argument '{}' has a value the policy does not permit"

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
RULE_SESSION = "session"  # a result withheld because the session's marks could not be recorded (see session.py)
RULE_HOOK_FAILED = "hook_failed"  # the Claude Code hook could not finish its checks (claude_hooks.py)
# Fixed ids for the parts of the secret guard, for code that wants to say which part refused
# (RULE_SECRETS stays the id for the guard as a whole). A custom format is "secrets.patterns[<i>]".
RULE_SECRETS_IN_RESULTS = "secrets.in_results"
RULE_SECRETS_CANARIES = "secrets.canaries"
RULE_SECRETS_KNOWN_VALUES = "secrets.known_values_from_env"

# An argument name is chosen by the agent; `matched_arg` keeps at most this much of it.
MAX_MATCHED_ARG_CHARS = 200

# ---- client methods -------------------------------------------------------------

# Client methods that the "tools" rules decide, as calls: "tools/call" by the tool's
# name, the two resource methods as tool "resources/read" with the argument "uri".
# The "client_requests" section cannot name them, and its wildcards do not cover them.
POLICY_CHECKED_METHODS = ("tools/call", "resources/read", "resources/subscribe")

# prompts/get is checked like a tool call of this name, once the policy opts in
# (see Policy.checks_prompts).
PROMPTS_GET = "prompts/get"

# ---- secret settings ----------------------------------------------------------------

# secrets.in_results: leave results as they are, replace the secrets in them, or withhold them.
SECRETS_IN_RESULTS = ("off", "redact", "block")

# The characters a custom secret format's body may use. A fixed set, compiled
# by the loader, so that no operator-written regular expression ever runs on
# the agent's text.
SECRET_CHARSETS = {
    "alnum": "A-Za-z0-9",
    "upper_alnum": "A-Z0-9",
    "alnum_dash": "A-Za-z0-9_-",
    "hex": "0-9a-fA-F",
    "base64": "A-Za-z0-9+/",
    "base64url": "A-Za-z0-9_-",  # the same characters as alnum_dash, under the name people know
}
# What a custom format's literal prefix may contain: no space, quote or backslash.
_SECRET_PREFIX = re.compile(r"[A-Za-z0-9_.:/+=@~-]{3,64}")
_SECRET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.()-]{0,59}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
MIN_SECRET_BODY = 8
MAX_SECRET_BODY = 1024
MAX_SECRET_PATTERNS = 50
MIN_CANARY_CHARS = 8
MAX_CANARY_CHARS = 200
MAX_CANARIES = 100
MAX_KNOWN_VALUE_NAMES = 100

# Higher is stricter. When several wildcard rules match, the strictest verdict wins.
_STRICTNESS = {"allow": 0, "ask": 1, "block": 2}

# The keys a policy file may have, at the top and in "secrets".
_TOP_LEVEL_KEYS = (
    "default", "deny_args", "tools", "server_requests", "client_requests", "injection", "secrets", "limits",
    "flows", "classify_by_annotations", "hide_blocked_tools", "require_labels",
)
# The keys of a tool rule, and of its "command" section.
_TOOL_RULE_KEYS = ("action", "deny_args", "allow_args", "other_args", "max_calls_per_minute", "labels", "command")
_COMMAND_KEYS = ("arg", "shell", "deny_classes", "ask_classes", "allow_programs", "labels_by_class", "unreadable")
MAX_ALLOW_PROGRAMS = 100

# Tool names that suggest a tool sends something out (a request, a search query, a post): such a
# tool should be labelled "sink" once flow rules exist (a warning, see _sink_label_warnings).
_SENDS_OUT_NAME = re.compile(r"fetch|http|request|search|browse|webhook|post|upload", re.IGNORECASE)
# The most tool names a warning lists.
_NAMES_LISTED = 5
_SECRETS_KEYS = (
    "in_arguments", "in_results", "known_values_from_env", "known_values_ignore_case", "canaries", "patterns",
)


def limit_rule(bucket: str) -> str:
    """The rule id for a bucket name from `Policy.call_limits` ("*" or "rule:<name>")."""
    if bucket.startswith("rule:"):
        return f"tools.{bucket[len('rule:'):]}.max_calls_per_minute"
    return "limits.max_calls_per_minute"


# ---- names with wildcards -----------------------------------------------------

def glob_matches(pattern: str, text: str) -> bool:
    """True if `text` matches `pattern`, in which only "*" is special (anything, or nothing). Case matters.

    The rule for tool names in a policy, for code that matches a name once
    (auditlog's --tool filter). A rule splits its name once instead and calls
    _glob_matches with the pieces.
    """
    return _glob_matches(tuple(pattern.split("*")), text)


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
    """One entry of deny_args or allow_args: an argument name and the matcher that judges its value.

    A named entry of deny_args checks every top-level argument whose name is
    the same ignoring case ("Command" for "command"), because some servers
    read argument names that way.
    """

    arg: str
    matcher: Matcher
    # allow_args only: the argument may be left out, but a value that is given must be acceptable.
    optional: bool = False
    # deny_args only: "block" (the default) refuses a call the entry matches; "ask" sends it to a person.
    action: str = "block"

    def __post_init__(self) -> None:
        # Code written before matchers existed passed a compiled pattern here.
        if isinstance(self.matcher, re.Pattern):
            object.__setattr__(self, "matcher", PatternMatcher(self.matcher))

    def describe(self) -> str:
        """What this entry checks, for the operator."""
        which = "every argument" if self.arg == ANY_ARG else f"argument {quoted(self.arg)}"
        asks = ", sent to a person for approval" if self.action == "ask" else ""
        return f"{which}: {self.matcher.describe()}" + (", or left out" if self.optional else "") + asks


@dataclass(frozen=True)
class ToolRule(_NamedRule):
    deny_args: tuple[ArgRule, ...] = ()
    allow_args: tuple[ArgRule, ...] = ()
    # "block" closes the argument list: a top-level argument that no allow_args entry names blocks the call.
    other_args: str = "allow"
    # Calls per minute for this rule. A wildcard rule has one count for all the tools it matches.
    max_calls_per_minute: int | None = None
    # Flow labels of the tools this rule matches, such as ("untrusted",) or ("private", "sink").
    labels: tuple[str, ...] = ()
    # The "command" section: how the classes of a shell command argument are treated (commands.py).
    command: CommandRule | None = None
    # True when the policy file has "labels" for this rule, even an empty list: "labels": [] says the
    # tool has no flow label on purpose (see Policy.require_labels and the warnings).
    labels_given: bool = False

    @property
    def labelled(self) -> bool:
        """True if the rule has labels, or says it has none on purpose."""
        return self.labels_given or bool(self.labels)


@dataclass(frozen=True)
class ServerRequestRule(_NamedRule):
    """Whether the server may send the client a request with this method, such as "sampling/createMessage"."""


@dataclass(frozen=True)
class ClientRequestRule(_NamedRule):
    """Whether the client may send the server a request or notification with this method ("completion/complete")."""


@dataclass(frozen=True)
class FlowRule:
    """One entry of "flows": once the session has every mark in `after`, a call to a tool labelled `then` gets `action`.

    {"after": ["untrusted", "private"], "then": "sink", "action": "block"}
    reads: after the agent has read untrusted content and private data, it
    may not call a tool that sends data out.
    """

    after: tuple[str, ...]  # marks that must all be set; never "sink"
    then: str = SINK  # the label of the tool being called
    action: str = "block"  # "ask" or "block"

    def __post_init__(self) -> None:
        if isinstance(self.after, list):  # a list written in code; a text stays as it is and is refused
            object.__setattr__(self, "after", tuple(self.after))

    def describe(self) -> str:
        """What this rule does, for the operator."""
        does = "refused" if self.action == "block" else "sent to a human for approval"
        read = " and ".join(f"'{label}'" for label in self.after)
        return f"after {read} content reached the agent, a call to a tool labelled '{self.then}' is {does}"


@dataclass(frozen=True)
class SecretPattern:
    """A custom secret format: a literal prefix, then `min_len` to `max_len` characters of one charset.

    {"name": "Internal token", "prefix": "itk_", "charset": "alnum", "min_len": 32, "max_len": 32}

    `regex` is the compiled form, prefix + "[chars]{min_len,max_len}". It is
    built here from fixed parts, never from an operator's regular expression,
    so it runs in linear time. It has no guard at either end: a longer run of
    the charset still matches its first `max_len` characters.
    """

    name: str  # shown in reasons and redaction markers ("[redacted Internal token]"); never the secret
    prefix: str
    charset: str  # a key of SECRET_CHARSETS
    min_len: int  # length of the body after the prefix
    max_len: int
    regex: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        _check_secret_pattern(self, "secrets.patterns entry")
        body = f"[{SECRET_CHARSETS[self.charset]}]{{{self.min_len},{self.max_len}}}"
        object.__setattr__(self, "regex", re.compile(re.escape(self.prefix) + body))

    def describe(self) -> str:
        length = str(self.min_len) if self.min_len == self.max_len else f"{self.min_len} to {self.max_len}"
        return f"'{self.name}': '{self.prefix}' followed by {length} characters of {self.charset}"


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
    call with that. It is never told the pattern or which list held the rule,
    and for a tool it may never call it is told nothing about the arguments
    (see Policy._verdict_without_flows).
    """
    return Verdict("block", reason, reason, rule, matched_arg)


def _bounded_name(name: Any) -> str:
    """An argument name to keep in `matched_arg`: as written, but not unboundedly long."""
    text = name if isinstance(name, str) else str(name)
    return text if len(text) <= MAX_MATCHED_ARG_CHARS else text[:MAX_MATCHED_ARG_CHARS] + "..."


@dataclass
class Policy:
    """A loaded policy. Build one with `Policy.from_file` or `Policy.from_dict`.

    The fields mirror the JSON keys. Those added in 0.5, for the code that acts on them:

    secrets_in_results               "off" (the default: results are left as they are), "redact" or "block":
                                     what to do with a recognisable secret in a tool's RESULT.
    secrets_known_values_from_env    names of environment variables whose VALUES must never leave in a
                                     call; the policy holds the names only, never a value.
    secrets_canaries                 strings the user planted in private files; a call carrying one is
                                     refused. Never print them: an agent that learns one can strip it.
    secrets_patterns                 custom secret formats (SecretPattern), with a compiled `regex` each.
    client_requests                  None when the section is absent; otherwise its rules (may be empty).
                                     See client_request_verdict and checks_prompts.
    flows                            flow rules (FlowRule); see flow_verdict and session.py.
    classify_by_annotations          whether MCP tool annotations may add flow labels (default true).
    hide_blocked_tools               whether the proxy hides tools that tool_level_action says "block"
                                     from tools/list (default false). Hiding is not enforcement:
                                     a call to a hidden tool is still checked and refused.

    Added in 0.6:

    secrets_known_values_ignore_case names from secrets_known_values_from_env whose values are also
                                     matched with case ignored (a value of hex digits and "-" always is).
    require_labels                   true: every rule that allows or asks must say its flow labels
                                     ("labels", an empty list when it has none on purpose), or the
                                     policy does not load (default false: a warning when flows exist).
    """

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
    # ---- added in 0.5; kept after the older fields so that positional construction still works
    secrets_in_results: str = "off"
    secrets_known_values_from_env: tuple[str, ...] = ()
    secrets_canaries: tuple[str, ...] = ()
    secrets_patterns: tuple[SecretPattern, ...] = ()
    client_requests: tuple[ClientRequestRule, ...] | None = None
    flows: tuple[FlowRule, ...] = ()
    classify_by_annotations: bool = True
    hide_blocked_tools: bool = False
    # ---- added in 0.6
    secrets_known_values_ignore_case: tuple[str, ...] = ()
    require_labels: bool = False

    def __post_init__(self) -> None:
        # A policy can also be built in code, without the loader. An action such
        # as "deny" or "Block" must not get through to mean "anything goes".
        _expect_choice(self.default, "default", ACTIONS)
        for rule in self.tools:
            where = f"tools.{rule.name}"
            _expect_choice(rule.action, f"{where}.action", ACTIONS)
            # Only exactly "block" closes the argument list: "Block" or "deny" would quietly leave it open.
            _expect_choice(rule.other_args, f"{where}.other_args", ("allow", "block"))
            if rule.max_calls_per_minute is not None:  # None: no limit
                _expect_calls_per_minute(rule.max_calls_per_minute, where)
            _check_code_arg_rules(rule.deny_args, f"{where}.deny_args", deny=True)
            _check_code_arg_rules(rule.allow_args, f"{where}.allow_args", deny=False)
            for label in rule.labels:
                _expect_label(label, f"{where}.labels")
        _check_code_arg_rules(self.deny_args, "deny_args", deny=True)
        if self.max_calls_per_minute is not None:
            _expect_calls_per_minute(self.max_calls_per_minute, "limits")
        for request in self.server_requests:
            _expect_choice(request.action, f"server_requests.{request.name}", ("allow", "block"))
        for request in self.client_requests or ():
            _expect_choice(request.action, f"client_requests.{request.name}", ("allow", "block"))
        for index, flow in enumerate(self.flows):
            _check_flow(flow, f"flows[{index}]")
        _expect_choice(self.secrets_in_arguments, "secrets.in_arguments", ("block", "allow"))
        _expect_choice(self.secrets_in_results, "secrets.in_results", SECRETS_IN_RESULTS)
        # The same checks as the loader. Without them, a text written where a
        # tuple belongs (secrets_canaries="my-canary-1") would be read one
        # character at a time by the code that acts on these settings.
        self.secrets_known_values_from_env = _env_names(_as_list(self.secrets_known_values_from_env))
        self.secrets_known_values_ignore_case = _ignore_case_names(
            _as_list(self.secrets_known_values_ignore_case), self.secrets_known_values_from_env
        )
        self.secrets_canaries = _canaries(_as_list(self.secrets_canaries))
        self.secrets_patterns = _code_secret_patterns(self.secrets_patterns)
        _expect_severity(self.block_severity)
        for name, value in (("classify_by_annotations", self.classify_by_annotations),
                            ("hide_blocked_tools", self.hide_blocked_tools),
                            ("require_labels", self.require_labels)):
            _expect_bool(value, name)
        for rule in self.tools:
            if rule.command is not None and not isinstance(rule.command, CommandRule):
                raise PolicyError(f"tools.{rule.name}.command must be a CommandRule")
            if self.require_labels and rule.action != "block" and not _labels_said(self.tools, rule):
                raise PolicyError(
                    f'tools.{rule.name}: "require_labels" is true, so a rule that allows or asks must say its flow '
                    'labels: add "labels" (["untrusted"], ["private"], ["sink"] ..., or [] for none)'
                )

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
            data = jsonutil.loads(text)  # json.loads keeps the last of two equal keys without a word
        except jsonutil.RepeatedKeyError as exc:  # say so, instead of "not valid JSON"
            raise PolicyError(f"{label}: duplicate key {exc.key!r}: a key may appear only once in an object") from exc
        except json.JSONDecodeError as exc:
            raise PolicyError(json_error_message(label, exc)) from exc
        except (ValueError, RecursionError) as exc:  # absurd nesting, a huge number, NaN or Infinity
            raise PolicyError(f"{label}: not valid JSON ({exc})") from exc
        try:
            return cls.from_dict(data)
        except PolicyError as exc:
            raise PolicyError(f"{label}: {exc}") from exc

    @classmethod
    def from_dict(cls, data: Any) -> "Policy":
        _expect_object(data, "the policy", allowed_keys=_TOP_LEVEL_KEYS)

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
        _expect_object(secrets, "secrets", allowed_keys=_SECRETS_KEYS)
        in_arguments = secrets.get("in_arguments", "block")
        _expect_choice(in_arguments, "secrets.in_arguments", ("block", "allow"))
        in_results = secrets.get("in_results", "off")
        _expect_in_results(in_results)

        limits = data.get("limits", {})
        _expect_object(limits, "limits", allowed_keys=("max_calls_per_minute",))

        classify = data.get("classify_by_annotations", True)
        _expect_bool(classify, "classify_by_annotations")
        hide = data.get("hide_blocked_tools", False)
        _expect_bool(hide, "hide_blocked_tools")
        require_labels = data.get("require_labels", False)
        _expect_bool(require_labels, "require_labels")

        client_requests = None
        if "client_requests" in data:
            client_requests = _client_request_rules(data["client_requests"])

        return cls(
            default=default,
            tools=tools,
            block_severity=severity,
            deny_args=_arg_rules(data.get("deny_args", []), "deny_args", deny=True),
            secrets_in_arguments=in_arguments,
            max_calls_per_minute=_calls_per_minute(limits, "limits"),
            server_requests=_server_request_rules(data.get("server_requests", {})),
            secrets_in_results=in_results,
            secrets_known_values_from_env=_env_names(secrets.get("known_values_from_env", [])),
            secrets_canaries=_canaries(secrets.get("canaries", [])),
            secrets_patterns=_secret_patterns(secrets.get("patterns", [])),
            client_requests=client_requests,
            flows=_flow_rules(data.get("flows", [])),
            classify_by_annotations=classify,
            hide_blocked_tools=hide,
            secrets_known_values_ignore_case=secrets.get("known_values_ignore_case", []),
            require_labels=require_labels,
        )

    # ---- evaluating ---------------------------------------------------------

    def evaluate(
        self,
        tool: str,
        args: dict[str, Any] | None,
        marks: SessionMarks | Iterable[str] | None = None,
        extra_labels: Iterable[str] = (),
    ) -> Verdict:
        """Decide what should happen to a call of `tool` with `args`.

        In order: a call whose argument names differ only in case is refused;
        then the policy-wide deny_args, which hold for every call; then the
        deny_args and command sections of every wildcard rule that matches
        (an exact rule does not lift them); then the rule with exactly this
        name, or otherwise every wildcard rule that matches, each checked in
        full, and the strictest result wins. With no rule at all, the default.
        A deny_args entry with "action": "ask" makes the call ask, unless
        something refuses it.

        marks:        what the session has read (a SessionMarks, or plain labels
                      such as {"untrusted"} to ask "what if"). When given, the
                      flow rules are applied too, and the stricter of the two
                      verdicts wins (see flow_verdict). None leaves flows out.
        extra_labels: labels the tool has besides those the policy gives it
                      (the firewall passes the ones its MCP annotations imply).
                      The labels its command sections give this call
                      (labels_by_class) are added here.
        """
        verdict = self._verdict_without_flows(tool, args)
        if marks is None or verdict.action == "block":
            return verdict
        flow = self.flow_verdict(tool, marks, frozenset(extra_labels) | self.command_labels(tool, args))
        # A flow that is at least as strict wins a tie: its reason says more (what was read, and where from).
        if flow is not None and _STRICTNESS[flow.action] >= _STRICTNESS[verdict.action]:
            return flow
        return verdict

    def _verdict_without_flows(self, tool: str, args: dict[str, Any] | None) -> Verdict:
        """The verdict of the deny rules, tool rules and default, without flows."""
        if args is None:
            args = {}
        if not isinstance(tool, str) or not isinstance(args, dict):
            # Nothing below can check such a call, and what cannot be checked is not let through.
            reason = "the tool name is not text or the arguments are not an object"
            return Verdict("block", reason, NOT_PERMITTED, RULE_MALFORMED)

        verdict = self._argument_and_rule_verdict(tool, args)
        if verdict.public != NOT_PERMITTED and self.tool_level_action(tool) == "block":
            # The agent can never call this tool, so naming the argument would help no honest agent fix its
            # call; it would only let one probe the argument rules (the policy-wide deny_args too, through a
            # name that is no tool). The operator still gets the rule that matched.
            verdict = dataclasses.replace(verdict, public=NOT_PERMITTED)
        return verdict

    def _argument_and_rule_verdict(self, tool: str, args: dict[str, Any]) -> Verdict:
        """The policy-wide deny_args first; then the tool rules that decide for `tool`, or the default."""
        clash = _case_clash(args)
        if clash is not None:
            return clash
        asks: list[Verdict] = []
        denied = _denied_argument(self.deny_args, args, "deny_args", asks)
        if denied is not None:
            return denied

        rules = _deciding_rules(self.tools, tool)
        for rule in self.tools:
            if rule.is_glob and rule.matches(tool) and not any(rule is chosen for chosen in rules):
                # An exact rule decides for this tool, but a wildcard's restrictions still hold, as its
                # labels and rate limit do: deny rules only ever add blocks.
                denied = _restrictions(rule, args, asks)
                if denied is not None:
                    return denied
        if not rules:
            reason = f"no rule for '{printable(tool, limit=80)}', default is {self.default}"
            return max([*asks, _rule_verdict(self.default, reason, RULE_DEFAULT)], key=_strictness)

        # Strictest wins, so a block holds whatever else matches and the order of
        # the rules in the file does not matter. max() returns the first of equals,
        # which keeps file order between verdicts that are equally strict, and puts
        # an "ask" of an argument rule (which says why) before a rule's own "ask".
        verdicts = [*asks, *(_apply_rule(rule, args) for rule in rules)]
        return max(verdicts, key=_strictness)

    def server_request_verdict(self, method: str) -> Verdict:
        """Decide whether the server may send the client a request or notification with this method.

        An exact method name beats a wildcard; among matching wildcards a
        block wins. With no matching rule the request is allowed, as it was
        before this section existed, and the verdict names no rule. A policy
        closes that with "*": "block".
        """
        return _method_verdict(self.server_requests, method, "server_requests")

    def server_request_action(self, method: str) -> str:
        """Return "allow" or "block" for a request the server sends to the client (see server_request_verdict)."""
        return self.server_request_verdict(method).action

    def client_request_verdict(self, method: str) -> Verdict:
        """Decide whether the client may send the server a request or notification with this method.

        The "client_requests" section, which mirrors "server_requests": an
        exact method name beats a wildcard, and among matching wildcards a
        block wins; the verdict's rule is "client_requests.<name as written>".
        A method no rule matches is allowed with rule None, which is also the
        answer for every method when the section is absent (the behaviour
        before 0.5). A method that is not text is blocked as malformed.

        The methods in POLICY_CHECKED_METHODS (tools/call, resources/read,
        resources/subscribe) are always allowed here: the "tools" rules decide
        them, call by call. For prompts/get see `checks_prompts`.

        The proxy answers a blocked request with a JSON-RPC error (the C44
        proposal suggests code -32601, "method not found") that names no rule.
        """
        if not isinstance(method, str):
            return Verdict("block", "the method name is not text", NOT_PERMITTED, RULE_MALFORMED)
        if method in POLICY_CHECKED_METHODS:
            return Verdict("allow", f"{method} is decided by the tools rules, not client_requests", PERMITTED)
        return _method_verdict(self.client_requests or (), method, "client_requests")

    def client_request_action(self, method: str) -> str:
        """Return "allow" or "block" for a request the client sends to the server (see client_request_verdict)."""
        return self.client_request_verdict(method).action

    @property
    def checks_prompts(self) -> bool:
        """Whether prompts/get must be checked like a tool call named "prompts/get".

        True when the policy opts in: it has a "client_requests" section (even
        an empty one), or a "tools" rule named exactly "prompts/get". A
        wildcard such as "*" does not opt in, so a policy written before 0.5
        keeps forwarding prompts/get as it did. Once opted in, prompts/get is
        judged like any call: deny_args, the secret guard, the tools rules
        (wildcards included), the default, rate limits and flows.

        The proxy checks it after client_request_verdict, as
        `firewall.check_call("prompts/get", {"name": <prompt name>, "arguments": <its arguments, or {}>})`,
        so a policy can allow prompts by name ({"arg": "name", "one_of": [...]})
        and deny values in any argument ("arg": "*").
        """
        return self.client_requests is not None or any(rule.name == PROMPTS_GET for rule in self.tools)

    def tool_level_action(self, tool: str) -> str:
        """The action for `tool` before any argument is looked at: "allow", "ask" or "block".

        The action of the rule with exactly this name; otherwise the strictest
        action among the wildcard rules that match; otherwise the default. For
        hiding tools that the policy blocks outright (hide_blocked_tools): a
        tool for which this is "block" can never be called, whatever its
        arguments. The reverse does not hold: deny rules, allow rules, flows,
        rate limits and the secret guard can still refuse a call to a tool for
        which this is "allow". A name that is not text gets "block".
        """
        if not isinstance(tool, str):
            return "block"
        rules = _deciding_rules(self.tools, tool)
        if not rules:
            return self.default
        return max((rule.action for rule in rules), key=lambda action: _STRICTNESS[action])

    def may_ask(self) -> bool:
        """True if some call can be sent to a person: the default or a rule says "ask", a deny_args entry
        has "action": "ask", a command section asks (ask_classes, or "unreadable": "ask" when it judges
        any class), or a flow rule asks. For the notes of `hook install` and `wrap`."""
        if self.default == "ask" or any(entry.action == "ask" for entry in self.deny_args):
            return True
        for rule in self.tools:
            if rule.action == "ask" or any(entry.action == "ask" for entry in rule.deny_args):
                return True
            section = rule.command
            if section is not None and (section.ask_classes or section.judges and section.unreadable == "ask"):
                return True
        return any(flow.action == "ask" for flow in self.flows)

    def tool_labels(self, tool: str) -> frozenset[str]:
        """The flow labels the policy gives `tool`: those of EVERY rule that matches it.

        Unlike actions, labels add up: an exact rule does not drop the labels of
        a wildcard that also matches, just as it does not lift a wildcard's
        rate limit. A label only ever adds a restriction, so an exception
        written for some other reason must not quietly remove one.
        """
        if not isinstance(tool, str):
            return frozenset()
        return frozenset(label for rule in self.tools if rule.labels and rule.matches(tool) for label in rule.labels)

    def command_labels(self, tool: str, args: Any) -> frozenset[str]:
        """The flow labels one call gets from the labels_by_class of the command sections that match `tool`.

        Like tool labels, they add up over every rule that matches. A command
        that cannot be read gets every label its sections could give.
        """
        if not isinstance(tool, str) or args is None:
            return frozenset()
        return frozenset(label for rule in self.tools
                         if rule.command is not None and rule.command.labels_by_class and rule.matches(tool)
                         for label in rule.command.labels(args))

    def call_labels(self, tool: str, args: Any) -> frozenset[str]:
        """Every flow label the policy gives this call: the tool's labels and its command's (for explain, check)."""
        return self.tool_labels(tool) | self.command_labels(tool, args)

    def flow_verdict(
        self, tool: str, marks: SessionMarks | Iterable[str], extra_labels: Iterable[str] = ()
    ) -> Verdict | None:
        """The verdict of the flow rules for a call of `tool` in a session with these marks, or None.

        A flow rule applies when the tool has the rule's `then` label (from the
        policy, or in `extra_labels`) and the session has every mark in its
        `after`. Of the rules that apply, the strictest wins, and the first in
        the file among equals; its id is "flows[<index>]". None when no rule
        applies. The agent is told NOT_PERMITTED, as for any rule; the reason,
        for the audit log, says what was read and which tool delivered it.
        """
        if not self.flows or not isinstance(tool, str):
            return None
        if not isinstance(marks, SessionMarks):
            marks = SessionMarks.of(marks)
        labels = self.tool_labels(tool) | frozenset(extra_labels)
        chosen: tuple[int, FlowRule] | None = None
        for index, flow in enumerate(self.flows):
            if flow.then in labels and marks.has_all(flow.after):
                if chosen is None or _STRICTNESS[flow.action] > _STRICTNESS[chosen[1].action]:
                    chosen = (index, flow)
        if chosen is None:
            return None
        index, flow = chosen
        return Verdict(flow.action, _flow_reason(index, flow, tool, marks), NOT_PERMITTED, f"flows[{index}]")

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
        found.extend(_shadowed_glob_warnings(self.tools))
        found.extend(_missing_root_warnings(self))
        found.extend(_flow_warnings(self))
        found.extend(_label_warnings(self))
        found.extend(_rule_of_two_warnings(self))
        found.extend(_client_request_warnings(self))
        found.extend(known_value_warnings(self))
        return found

    def describe_rule(self, rule_id: str) -> str | None:
        """What the rule with this id checks, for the operator; None if this policy has no such rule.

        For `explain` and similar tools that start from an audit record. Never
        show the result to the agent: it names patterns and rules. An audit log
        is a plain file anyone with access can edit, so a `rule` read from it
        may be anything: what is not text, or not an id this policy has, gives None.
        """
        if not isinstance(rule_id, str):
            return None
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
            RULE_SESSION: "the session state of the flow rules could not be recorded, so the result was withheld",
            RULE_HOOK_FAILED: "the Claude Code hook could not finish its checks (a policy that does not load, or "
                              "session state that cannot be used), so it refused",
        }
        if rule_id in fixed:
            return fixed[rule_id]
        secret_part = self._describe_secret_rule(rule_id)
        if secret_part is not None:
            return secret_part
        if rule_id == "limits.max_calls_per_minute" and self.max_calls_per_minute is not None:
            return f"at most {self.max_calls_per_minute} call(s) per minute for all tools together"
        indexed = re.fullmatch(rf"deny_args{_INDEX}", rule_id)
        if indexed:
            entry = _entry(self.deny_args, indexed.group(1))
            return None if entry is None else f"policy-wide deny rule, {entry.describe()}"
        indexed = re.fullmatch(rf"flows{_INDEX}", rule_id)
        if indexed:
            flow = _entry(self.flows, indexed.group(1))
            return None if flow is None else f"flow rule: {flow.describe()}"
        for section, requests, who in (
            ("server_requests", self.server_requests, "server"),
            ("client_requests", self.client_requests or (), "client"),
        ):
            if rule_id.startswith(section + "."):
                name = rule_id[len(section) + 1:]
                for request in requests:
                    if request.name == name:
                        return f"{who} request rule '{name}': {request.action}"
                return None
        for rule in self.tools:
            found = _describe_tool_rule_part(rule, rule_id)
            if found is not None:
                return found
        return None

    def _describe_secret_rule(self, rule_id: str) -> str | None:
        """describe_rule for the parts of the secret guard. Never names a canary or a value."""
        if rule_id == RULE_SECRETS_IN_RESULTS:
            return f"the secret guard on tool results: {self.secrets_in_results} (secrets.in_results)"
        if rule_id == RULE_SECRETS_CANARIES and self.secrets_canaries:
            return f"one of the {len(self.secrets_canaries)} canary string(s) in secrets.canaries"
        if rule_id == RULE_SECRETS_KNOWN_VALUES and self.secrets_known_values_from_env:
            names = ", ".join(self.secrets_known_values_from_env)
            return f"the value of one of these environment variables: {names} (secrets.known_values_from_env)"
        indexed = re.fullmatch(rf"secrets\.patterns{_INDEX}", rule_id)
        if indexed:
            pattern = _entry(self.secrets_patterns, indexed.group(1))
            return None if pattern is None else f"custom secret format {pattern.describe()}"
        return None


# ---- applying a rule ----------------------------------------------------------

def _method_verdict(rules: Sequence[_NamedRule], method: Any, section: str) -> Verdict:
    """The verdict of a server_requests or client_requests section for one method.

    An exact name beats a wildcard; among matching wildcards a block wins.
    No matching rule: allowed, and the verdict names no rule.
    """
    if not isinstance(method, str):
        return Verdict("block", "the method name is not text", NOT_PERMITTED, RULE_MALFORMED)
    matching = _deciding_rules(rules, method)
    for rule in matching:
        if rule.action == "block":
            return Verdict("block", f"{section} rule '{rule.name}' says block", NOT_PERMITTED, f"{section}.{rule.name}")
    if matching:
        name = matching[0].name
        return Verdict("allow", f"{section} rule '{name}' says allow", PERMITTED, f"{section}.{name}")
    return Verdict("allow", f"no {section} rule matches, so it is allowed", PERMITTED)


def _flow_reason(index: int, flow: FlowRule, tool: str, marks: SessionMarks) -> str:
    """The audit reason of a flow verdict: what the session read, where from, and what the tool is.

    Tool names in it are chosen by the agent or the server, so they are shortened and escaped.
    """
    if marks.everything:
        seen = f"the session state cannot be trusted ({marks.why}), so every mark counts as set"
    else:
        parts = []
        for label in flow.after:
            cause = marks.marks.get(label)
            source = f" from '{printable(cause.tool, limit=80)}'" if cause is not None and cause.tool else ""
            when = f" at {cause.time}" if cause is not None and cause.time else ""
            parts.append(f"'{label}' content{source}{when}")
        seen = "the agent has read " + " and ".join(parts)
    outcome = "is refused" if flow.action == "block" else "needs approval"
    return (
        f"flow rule flows[{index}]: {seen}, and '{printable(tool, limit=80)}' is labelled "
        f"'{flow.then}', so the call {outcome}"
    )


def _strictness(verdict: Verdict) -> int:
    return _STRICTNESS[verdict.action]


def _apply_rule(rule: ToolRule, args: dict[str, Any]) -> Verdict:
    """Check a call against one rule: its deny_args and command section, its allow_args, its other_args, then
    its action."""
    where = f"tools.{rule.name}"
    asks: list[Verdict] = []
    denied = _restrictions(rule, args, asks)
    if denied is not None:
        return denied

    allow_names = {allow.arg for allow in rule.allow_args}
    if allow_names:
        # A server that reads names ignoring case (Go's encoding/json does) would take "Path" for "path":
        # a name that is an allow_args name in another case is not accepted, even with other_args "allow".
        folded = {allow.arg.casefold(): index for index, allow in reversed(list(enumerate(rule.allow_args)))}
        for name in args:
            if isinstance(name, str) and name not in allow_names and name.casefold() in folded:
                reason = f"argument '{printable(name, limit=60)}' is not accepted by the policy"
                return _argument_block(reason, f"{where}.allow_args[{folded[name.casefold()]}]", _bounded_name(name))

    for index, allow in enumerate(rule.allow_args):
        rule_id = f"{where}.allow_args[{index}]"
        if allow.arg not in args:
            if allow.optional:
                continue
            return _argument_block(f"argument '{allow.arg}' is required by the policy but missing", rule_id, allow.arg)
        if not _is_allowed(allow, args[allow.arg]):
            return _argument_block(VALUE_NOT_PERMITTED.format(allow.arg), rule_id, allow.arg)

    if rule.other_args == "block":
        # Top level only. An allowed argument cannot carry more arguments inside
        # it, because _is_allowed refuses objects.
        for name in args:
            if name not in allow_names:
                # The name is chosen by the agent: shorten and escape it before repeating it.
                reason = f"argument '{printable(name, limit=60)}' is not accepted by the policy"
                return _argument_block(reason, f"{where}.other_args", _bounded_name(name))

    action = _rule_verdict(rule.action, f"rule '{rule.name}' says {rule.action}", where)
    return max([*asks, action], key=_strictness)


def _restrictions(rule: ToolRule, args: dict[str, Any], asks: list[Verdict]) -> Verdict | None:
    """A rule's checks that only ever add restrictions: its deny_args and its command section.

    Returns a block, or None; an "ask" is added to `asks`.
    """
    where = f"tools.{rule.name}"
    denied = _denied_argument(rule.deny_args, args, f"{where}.deny_args", asks)
    if denied is not None:
        return denied
    command = _command_verdict(rule, args, where)
    if command is not None:
        if command.action == "block":
            return command
        asks.append(command)
    return None


def _command_verdict(rule: ToolRule, args: dict[str, Any], where: str) -> Verdict | None:
    """The verdict of a rule's command section: a block or an ask, or None when it lets the command through."""
    section = rule.command
    if section is None or not section.judges:
        return None
    reading = section.reading(args)
    rule_id = f"{where}.command"
    if reading.unreadable is not None:
        does = "sent to a person for approval" if section.unreadable == "ask" else "refused"
        reason = f"the command cannot be read with certainty ({reading.unreadable}), so it is {does}"
        return _command_result(section, section.unreadable, reason, f"{rule_id}.{commands.UNREADABLE}")
    found = section.found(reading)
    for action, listed_classes in (("block", section.deny_classes), ("ask", section.ask_classes)):
        for kind in commands.CLASSES:
            if kind in found and kind in listed_classes:
                does = "refused" if action == "block" else "sent to a person for approval"
                reason = (f"the command {found[kind].evidence}: class '{kind}' ({commands.CLASS_TEXT[kind]}), "
                          f"so it is {does}")
                return _command_result(section, action, reason, f"{rule_id}.{kind}")
    return None


def _command_result(section: CommandRule, action: str, reason: str, rule_id: str) -> Verdict:
    if action == "block":
        # Worded like any refused value, so the agent cannot tell a command rule from a deny rule.
        return Verdict("block", reason, VALUE_NOT_PERMITTED.format(section.arg), rule_id, section.arg)
    return Verdict("ask", reason, NOT_PERMITTED, rule_id, section.arg)


def _case_clash(args: dict[str, Any]) -> Verdict | None:
    """A block when two top-level argument names differ only in case ("to" and "To"), or None.

    A server that matches names ignoring case would read one of them in place
    of the other, and which one is up to the server.
    """
    seen: dict[str, str] = {}
    for name in args:
        if not isinstance(name, str):
            continue
        first = seen.setdefault(name.casefold(), name)
        if first != name:
            reason = (f"the argument names '{printable(first, limit=60)}' and '{printable(name, limit=60)}' differ "
                      "only in case")
            return Verdict("block", reason, NOT_PERMITTED, RULE_MALFORMED, _bounded_name(name))
    return None


def _denied_argument(
    rules: tuple[ArgRule, ...], args: dict[str, Any], where: str, asks: list[Verdict] | None = None
) -> Verdict | None:
    """Return a block for the first deny rule that matches, or None.

    The wording is VALUE_NOT_PERMITTED, as for an allow list, and names the
    argument also for a "*" entry, so the agent cannot tell which list
    refused it; `rule` tells the operator. An entry with "action": "ask" that
    matches adds an "ask" to `asks` (the first one only) and the checks go on;
    without `asks` it refuses like any other entry.
    """
    folded = _folded_names(args) if any(rule.arg != ANY_ARG for rule in rules) else {}
    asked = False
    for index, rule in enumerate(rules):
        if rule.action == "ask" and asks is not None and asked:
            continue  # one ask from this list says enough
        matched = _denied_in(rule, args, folded)
        if matched is None:
            continue
        # For "*" the name is the agent's: shorten and escape it before repeating it.
        shown = printable(matched, limit=60) if rule.arg == ANY_ARG else rule.arg
        if rule.action == "ask" and asks is not None:
            reason = f"argument '{shown}' has a value the policy sends to a person for approval"
            asks.append(Verdict("ask", reason, NOT_PERMITTED, f"{where}[{index}]", matched))
            asked = True
            continue
        return _argument_block(VALUE_NOT_PERMITTED.format(shown), f"{where}[{index}]", matched)
    return None


def _folded_names(args: dict[str, Any]) -> dict[str, list[Any]]:
    """The argument names by their casefolded spelling (a name that is not text keeps its own spelling)."""
    folded: dict[str, list[Any]] = {}
    for name in args:
        folded.setdefault(name.casefold() if isinstance(name, str) else name, []).append(name)
    return folded


def _denied_in(rule: ArgRule, args: dict[str, Any], folded: dict[str, list[Any]] | None = None) -> str | None:
    """The name of the argument in which the deny rule matches, or None.

    Looks inside nested lists and objects, including object keys, so a denied
    value cannot be hidden one level down. For "*", the name of an argument
    is itself one of the texts checked. A named entry checks every top-level
    argument whose name is the same ignoring case (str.casefold).
    """
    if rule.arg == ANY_ARG:
        for name, value in args.items():
            if _found_in_any(rule.matcher, texts_in({name: value}, keys=True, scalars=True)):
                return _bounded_name(name)
        return None
    if folded is None:
        folded = _folded_names(args)
    for name in folded.get(rule.arg.casefold(), ()):
        # An empty list or object holds no text, but the argument is there: check
        # it as empty text, so that a pattern meant to forbid the argument still does.
        texts = texts_in(args[name], keys=True, scalars=True) or [""]
        if _found_in_any(rule.matcher, texts):
            return rule.arg if name == rule.arg else _bounded_name(name)
    return None


def _found_in_any(matcher: Matcher, texts: list[str]) -> bool:
    """True if the matcher finds a match in any text, as written or after percent-decoding.

    Extra spellings can only add blocks. A text still encoded after the last
    round of decoding counts as a match: it could not be checked. A matcher
    that reads escapes itself (Matcher.deny_checks_decoded) sees the text as written only.
    """
    for text in texts:
        spellings = decoded_spellings(text) if matcher.deny_checks_decoded else (text,)
        for spelling in spellings:
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

# A position as rule ids write it: "[0]", "[12]". No leading zeros, so each entry
# has one id; at most nine digits, so a hostile id cannot make int() do much work
# (or fail: Python refuses to read a number of more than 4300 digits).
# A position in a rule id, "[3]": no leading zeros, at most nine digits. Shared with fix_hints.
RULE_INDEX = r"\[(0|[1-9][0-9]{0,8})\]"
_INDEX = RULE_INDEX


def _entry(entries: tuple[Any, ...], index: str) -> Any:
    """The entry at a position written in a rule id ("deny_args[2]"), or None if there is no such entry."""
    position = int(index)
    return entries[position] if position < len(entries) else None


def _describe_tool_rule_part(rule: ToolRule, rule_id: str) -> str | None:
    """Describe `rule_id` if it names this tool rule or one of its parts."""
    prefix = f"tools.{rule.name}"
    if rule_id == prefix:
        labels = f" (flow labels: {', '.join(rule.labels)})" if rule.labels else ""
        return f"tool rule '{rule.name}': {rule.action}{labels}"
    if not rule_id.startswith(prefix + "."):
        return None
    part = rule_id[len(prefix) + 1:]
    if part == "other_args" and rule.other_args == "block":
        named = ", ".join(quoted(allow.arg) for allow in rule.allow_args) or "none"
        return f"tool rule '{rule.name}' accepts only the arguments its allow_args name ({named})"
    if part == "max_calls_per_minute" and rule.max_calls_per_minute is not None:
        return f"tool rule '{rule.name}': at most {rule.max_calls_per_minute} call(s) per minute"
    section = rule.command
    if section is not None and part.startswith("command."):
        kind = part[len("command."):]
        if kind == commands.UNREADABLE and section.judges:
            does = "sent to a person for approval" if section.unreadable == "ask" else "refused"
            return (f"tool rule '{rule.name}': a {section.shell} command that cannot be read with certainty "
                    f"(an unclosed quote, a heredoc, a program chosen at run time ...) is {does}")
        for action, listed_classes in (("refused", section.deny_classes), ("sent to a person for approval",
                                                                             section.ask_classes)):
            if kind in listed_classes:
                return (f"tool rule '{rule.name}': a {section.shell} command in the class '{kind}' "
                        f"({commands.CLASS_TEXT[kind]}) is {action}")
    indexed = re.fullmatch(rf"(deny_args|allow_args){_INDEX}", part)
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


def _shadowed_glob_warnings(tools: list[ToolRule]) -> list[str]:
    """Warn when an exact rule replaces the allow_args (or the closed list) of a wildcard rule that matches it.

    The exact rule decides the action and the allowed arguments; the
    wildcard's deny_args, command section, labels and rate limit still apply.
    """
    found = []
    for rule in tools:
        if rule.is_glob:
            continue
        for glob in tools:
            if glob.is_glob and glob.matches(rule.name) and (glob.allow_args or glob.other_args == "block"):
                found.append(
                    f"tools.{rule.name}: this exact rule replaces the allow_args of the wildcard rule '{glob.name}', "
                    f"so they do not apply to '{rule.name}' (its deny_args, labels and rate limit still do); "
                    "copy the allow_args you need into the exact rule"
                )
    return found


def _missing_root_warnings(policy: Policy) -> list[str]:
    """Warn about a path root that is not a folder on this machine: probably a typo, or the wrong machine.

    A deny root is reported only when the folder that would hold it is missing
    too: a deny rule for a folder that does not exist yet (~/.codex on a
    machine without Codex) protects it once it does.
    """
    lists = [("deny_args", policy.deny_args, True)]
    for rule in policy.tools:
        lists += [(f"tools.{rule.name}.deny_args", rule.deny_args, True),
                  (f"tools.{rule.name}.allow_args", rule.allow_args, False)]
    found = []
    for where, entries, deny in lists:
        for index, entry in enumerate(entries):
            if isinstance(entry.matcher, PathMatcher):
                found.extend(
                    f"{where}[{index}]: the root '{root}' is not a folder on this machine"
                    for root in entry.matcher.roots
                    if not os.path.isdir(os.path.dirname(root) if deny else root)
                )
    return found


def _labels_said(tools: Sequence[ToolRule], rule: ToolRule) -> bool:
    """True if the rule says its flow labels (maybe none), or, for an exact rule, a matching wildcard does."""
    if rule.labelled:
        return True
    return not rule.is_glob and any(other.is_glob and other.labelled and other.matches(rule.name) for other in tools)


def _possible_labels(policy: Policy, rule: ToolRule) -> frozenset[str]:
    """The labels a call to the tools of this rule can have: its own (with a matching wildcard's), and its
    command section's labels_by_class."""
    labels = set(rule.labels if rule.is_glob else policy.tool_labels(rule.name))
    if rule.command is not None:
        labels.update(label for _, given in rule.command.labels_by_class for label in given)
    return frozenset(labels)


def _some_names(names: list[str]) -> str:
    shown = ", ".join(printable(name, limit=60) for name in names[:_NAMES_LISTED])
    return shown + (f" and {len(names) - _NAMES_LISTED} more" if len(names) > _NAMES_LISTED else "")


def _label_warnings(policy: Policy) -> list[str]:
    """Warn about tools the flow rules cannot see: allowed with no labels, or likely to send data out unlabelled.

    Only when flow rules exist. A tool also labelled "private" is not asked to
    be a sink: it is a source of private data, and a block flow would lock it.
    """
    if not policy.flows:
        return []
    found = []
    for rule in policy.tools:
        if rule.action == "block":
            continue
        if not _labels_said(policy.tools, rule):
            found.append(
                f"tools.{rule.name}: it is allowed but has no flow labels, so the flow rules cannot see what it "
                'reads or sends; add "labels" (["untrusted"], ["private"], ["sink"] ..., or [] if it has none)'
            )
            continue
        labels = _possible_labels(policy, rule)
        if SINK in labels or PRIVATE in labels:
            continue
        if UNTRUSTED in labels:
            found.append(
                f"tools.{rule.name}: it is labelled 'untrusted' but not 'sink'. A tool that fetches content sends "
                "something too (a URL, a query), which can carry private data out; add 'sink'"
            )
        elif _SENDS_OUT_NAME.search(rule.name):
            found.append(
                f"tools.{rule.name}: its name says it fetches, searches or posts, but it is not labelled 'sink', so "
                "a flow rule does not stop it from carrying data out; add 'sink' if it sends anything"
            )
    return found


def _rule_of_two_warnings(policy: Policy) -> list[str]:
    """Warn when one session can reach untrusted content, private data and a sink, and no flow rule covers it.

    The agents' "Rule of Two": an agent should not have all three at once. A
    tool counts when a rule allows it or asks for it; with
    classify_by_annotations, MCP annotations can make any server tool
    untrusted and a sink. A flow covers the combination when its "after" holds
    only 'untrusted' and 'private' and its "then" is 'sink'.
    """
    reachable = {UNTRUSTED: [], PRIVATE: [], SINK: []}
    for rule in policy.tools:
        if rule.action == "block":
            continue
        labels = _possible_labels(policy, rule)
        for label, names in reachable.items():
            if label in labels:
                names.append(rule.name)
    if not reachable[PRIVATE]:
        return []
    if policy.classify_by_annotations:
        for label in (UNTRUSTED, SINK):
            reachable[label].append("any server tool its MCP annotations mark")
    if not reachable[UNTRUSTED] or not reachable[SINK]:
        return []
    if any(flow.then == SINK and set(flow.after) <= {UNTRUSTED, PRIVATE} for flow in policy.flows):
        return []
    return [
        f"one session can reach untrusted content ({_some_names(reachable[UNTRUSTED])}), private data "
        f"({_some_names(reachable[PRIVATE])}) and a tool that sends data out ({_some_names(reachable[SINK])}), and "
        'no flow rule blocks or asks for that: add {"after": ["untrusted", "private"], "then": "sink", '
        '"action": "block"} to "flows"'
    ]


def _flow_warnings(policy: Policy) -> list[str]:
    """Warn about flow rules that can never apply, labels nothing uses, and tools a flow will lock after one use."""
    if not policy.flows:
        return []
    given = {label for rule in policy.tools for label in _possible_labels(policy, rule)}
    from_annotations = {UNTRUSTED, SINK} if policy.classify_by_annotations else set()
    used = {label for flow in policy.flows for label in (*flow.after, flow.then)}
    found = []
    for index, flow in enumerate(policy.flows):
        for label in dict.fromkeys((*flow.after, flow.then)):
            if label in given or label in from_annotations:
                continue
            hint = did_you_mean(label, sorted(given))
            found.append(
                f"flows[{index}]: no tool rule has the label '{label}', so this flow never applies"
                + (f"; did you mean '{hint}'?" if hint else "")
            )
    for rule in policy.tools:
        for label in rule.labels:
            # A built-in label is never a typo, and it describes the tool for the Rule of Two check
            # even when no flow names it.
            if label not in used and label not in BUILTIN_LABELS:
                hint = did_you_mean(label, sorted(used))
                found.append(
                    f"tools.{rule.name}.labels: no flow rule uses the label '{label}'"
                    + (f"; did you mean '{hint}'?" if hint else "")
                )
        for index, flow in enumerate(policy.flows):
            if flow.action == "block" and flow.then in rule.labels and set(flow.after) <= set(rule.labels):
                labels = ", ".join(f"'{label}'" for label in (*flow.after, flow.then))
                found.append(
                    f"tools.{rule.name}: it has the labels {labels}, so once one of its results reaches the agent, "
                    f"flows[{index}] refuses every later call to it"
                )
    return found


def _client_request_warnings(policy: Policy) -> list[str]:
    """Warn about client_requests settings that would break the connection or refuse every prompt."""
    found = []
    if policy.client_requests is not None:
        for method in ("initialize", "notifications/initialized"):
            if policy.client_request_action(method) == "block":
                found.append(f"client_requests blocks '{method}', so no client can connect")
    prompts_reach_the_policy = (
        policy.checks_prompts and policy.client_request_action(PROMPTS_GET) == "allow"
    )
    if prompts_reach_the_policy and not _deciding_rules(policy.tools, PROMPTS_GET) and policy.default != "allow":
        found.append(
            "prompts/get is checked like a tool call because the policy has a client_requests section, but no "
            f'tools rule matches it, so the default "{policy.default}" applies to every prompt; '
            'add a rule for "prompts/get" to tools'
        )
    return found


def known_value_warnings(policy: Policy) -> list[str]:
    """Warn about secrets.known_values_from_env names that are not set where `validate` runs.

    Part of Policy.warnings. The proxy, which knows the environment its server
    gets, prints the firewall's own warnings instead (Firewall.secret_warnings).
    """
    return [
        f"secrets.known_values_from_env: '{name}' is not set in this environment "
        "(it is read where the firewall runs, so this may be expected)"
        for name in policy.secrets_known_values_from_env
        if name not in os.environ
    ]


# ---- validation helpers -------------------------------------------------------

def _tool_rule(name: Any, spec: Any) -> ToolRule:
    _expect_name(name, "tool name")
    where = f"tools.{name}"
    if isinstance(spec, str):  # shorthand: "tool": "allow"
        _expect_choice(spec, where, ACTIONS)
        spec = {"action": spec}
    elif not isinstance(spec, dict):
        raise PolicyError(f"{where} must be an action ({listed(ACTIONS)}) or an object, got {type_name(spec)}")
    _expect_object(spec, where, allowed_keys=_TOOL_RULE_KEYS)
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
        labels=_labels(spec.get("labels", []), f"{where}.labels", allow_sink=True),
        command=_command_rule(spec["command"], f"{where}.command") if "command" in spec else None,
        labels_given="labels" in spec,
    )


def _command_rule(spec: Any, where: str) -> CommandRule:
    """Read a tool rule's "command" section (see commands.CommandRule)."""
    _expect_object(spec, where, allowed_keys=_COMMAND_KEYS)
    arg = spec.get("arg", "command")
    if not isinstance(arg, str) or arg == ANY_ARG:
        raise PolicyError(f"{where}.arg must be the name of the argument that holds the command, got {quoted(arg)}")
    _expect_name(arg, f"{where}.arg")
    shell = matchers.command_shell(spec.get("shell", "bash"), f"{where}.shell")
    deny = matchers.command_classes(spec.get("deny_classes", []), f"{where}.deny_classes", allow_empty=True)
    ask = matchers.command_classes(spec.get("ask_classes", []), f"{where}.ask_classes", allow_empty=True)
    both = sorted(deny & ask)
    if both:
        raise PolicyError(f"{where}: the class {quoted(both[0])} is in both deny_classes and ask_classes; "
                          "keep it in one")
    unreadable = spec.get("unreadable", "ask")
    _expect_choice(unreadable, f"{where}.unreadable", ("ask", "block"))
    return CommandRule(
        arg=arg,
        shell=shell,
        deny_classes=tuple(kind for kind in commands.CLASSES if kind in deny),
        ask_classes=tuple(kind for kind in commands.CLASSES if kind in ask),
        allow_programs=_allow_programs(spec.get("allow_programs", []), f"{where}.allow_programs"),
        labels_by_class=_labels_by_class(spec.get("labels_by_class", {}), f"{where}.labels_by_class"),
        unreadable=unreadable,
    )


def _allow_programs(specs: Any, where: str) -> tuple[tuple[str, ...], ...]:
    if not isinstance(specs, list):
        raise PolicyError(f"{where} must be a list of programs such as [\"git push\", \"curl\"], got "
                          f"{type_name(specs)}")
    if len(specs) > MAX_ALLOW_PROGRAMS:
        raise PolicyError(f"{where} can name at most {MAX_ALLOW_PROGRAMS} programs")
    entries = []
    for index, spec in enumerate(specs):
        entry = commands.allow_program_entry(spec) if isinstance(spec, str) else None
        if entry is None:
            raise PolicyError(
                f"{where}[{index}] must be a program name, maybe with its first words (\"git push\"): at most 8 "
                f"words, without quotes, '$' or shell operators, got {quoted(spec)}"
            )
        entries.append(entry)
    return tuple(entries)


def _labels_by_class(specs: Any, where: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    _expect_object(specs, where)
    pairs = []
    for kind, labels in specs.items():
        matchers.command_classes([kind], f"{where}: key")
        pairs.append((kind, _labels(labels, f"{where}.{kind}", allow_sink=True)))
    return tuple(pairs)


def _labels(specs: Any, where: str, allow_sink: bool) -> tuple[str, ...]:
    """Read a list of flow labels: tool rule "labels" (allow_sink=True) or a flow's "after" (False)."""
    if not isinstance(specs, list):
        raise PolicyError(f"{where} must be a list of labels ([ ... ]), got {type_name(specs)}")
    labels: list[str] = []
    for index, label in enumerate(specs):
        _expect_label(label, f"{where}[{index}]")
        if label == SINK and not allow_sink:
            raise PolicyError(
                f"{where}[{index}]: 'sink' describes what a tool does, not content it returns, so it is never "
                "a mark; put it in 'then'"
            )
        if label in labels:
            raise PolicyError(f"{where}[{index}]: the label '{label}' is listed twice")
        labels.append(label)
    return tuple(labels)


def _expect_label(label: Any, where: str) -> None:
    if is_label(label):
        return
    message = (
        f"{where} must be a label: a lowercase letter, then lowercase letters, digits, '_' or '-', at most 40 "
        f"characters (built in: {', '.join(BUILTIN_LABELS)}), got {quoted(label)}"
    )
    hint = did_you_mean(label, BUILTIN_LABELS)
    raise PolicyError(message + (f"; did you mean '{hint}'?" if hint else ""))


def _flow_rules(specs: Any) -> tuple[FlowRule, ...]:
    if not isinstance(specs, list):
        raise PolicyError(f"flows must be a list ([ ... ]), got {type_name(specs)}")
    flows = []
    for index, spec in enumerate(specs):
        where = f"flows[{index}]"
        _expect_object(spec, where, allowed_keys=("after", "then", "action"))
        if "after" not in spec or "action" not in spec:
            # No default action, as for tool rules; and a flow with nothing in "after" would be a plain block.
            raise PolicyError(f"{where} needs 'after' (a list of labels) and 'action' ('ask' or 'block')")
        after = _labels(spec["after"], f"{where}.after", allow_sink=False)
        if not after:
            raise PolicyError(f"{where}.after must name at least one label")
        then = spec.get("then", SINK)
        _expect_label(then, f"{where}.then")
        action = spec["action"]
        if action == "allow":
            raise PolicyError(f"{where}.action must be 'ask' or 'block': a flow rule can only add a restriction")
        _expect_choice(action, f"{where}.action", ("ask", "block"))
        flows.append(FlowRule(after, then, action))
    return tuple(flows)


def _check_flow(flow: FlowRule, where: str) -> None:
    """Validate a FlowRule built in code (the loader checks the same, with more specific messages)."""
    if not flow.after or not isinstance(flow.after, tuple):
        raise PolicyError(f"{where}.after must be a non-empty tuple of labels")
    for label in flow.after:
        _expect_label(label, f"{where}.after")
        if label == SINK:
            raise PolicyError(f"{where}.after: 'sink' is never a mark")
    _expect_label(flow.then, f"{where}.then")
    _expect_choice(flow.action, f"{where}.action", ("ask", "block"))


def _client_request_rules(specs: Any) -> tuple[ClientRequestRule, ...]:
    _expect_object(specs, "client_requests")
    rules = []
    for name, action in specs.items():
        _expect_name(name, "client_requests: method name")
        if name in POLICY_CHECKED_METHODS:
            raise PolicyError(
                f"client_requests.{name}: {name} is decided by the tools rules (as a call), so it cannot be listed "
                "here; write the rule in tools"
            )
        # No "ask": these are protocol messages, not actions a human weighs one by one.
        _expect_choice(action, f"client_requests.{name}", ("allow", "block"))
        rules.append(ClientRequestRule(name, action))
    return tuple(rules)


def _expect_in_results(value: Any) -> None:
    if value == "allow":  # the word the first proposal used; say what it is called here
        raise PolicyError("secrets.in_results must be 'off', 'redact' or 'block', got 'allow'; 'off' leaves results "
                          "as they are")
    _expect_choice(value, "secrets.in_results", SECRETS_IN_RESULTS)


def _env_names(specs: Any) -> tuple[str, ...]:
    where = "secrets.known_values_from_env"
    if not isinstance(specs, list):
        raise PolicyError(f"{where} must be a list of environment variable names ([ ... ]), got {type_name(specs)}")
    if len(specs) > MAX_KNOWN_VALUE_NAMES:
        raise PolicyError(f"{where} can name at most {MAX_KNOWN_VALUE_NAMES} variables")
    names: list[str] = []
    for index, name in enumerate(specs):
        if not isinstance(name, str) or not _ENV_NAME.fullmatch(name):
            raise PolicyError(
                f"{where}[{index}] must be the NAME of an environment variable (letters, digits and '_', not "
                f"starting with a digit), got {quoted(name)}. Never write the value itself in a policy"
            )
        if name in names:
            raise PolicyError(f"{where}[{index}]: '{name}' is listed twice")
        names.append(name)
    return tuple(names)


def _ignore_case_names(specs: Any, known: tuple[str, ...]) -> tuple[str, ...]:
    """Read secrets.known_values_ignore_case: names that secrets.known_values_from_env lists, each once."""
    where = "secrets.known_values_ignore_case"
    if not isinstance(specs, list):
        raise PolicyError(f"{where} must be a list of environment variable names ([ ... ]), got {type_name(specs)}")
    names: list[str] = []
    for index, name in enumerate(specs):
        if not isinstance(name, str) or name not in known:
            raise PolicyError(
                f"{where}[{index}] must be one of the names in secrets.known_values_from_env, got {quoted(name)}"
            )
        if name in names:
            raise PolicyError(f"{where}[{index}]: '{name}' is listed twice")
        names.append(name)
    return tuple(names)


def _canaries(specs: Any) -> tuple[str, ...]:
    """Read secrets.canaries. Error messages never repeat a canary: an agent that learns one can strip it."""
    where = "secrets.canaries"
    if not isinstance(specs, list):
        raise PolicyError(f"{where} must be a list of texts ([ ... ]), got {type_name(specs)}")
    if len(specs) > MAX_CANARIES:
        raise PolicyError(f"{where} can hold at most {MAX_CANARIES} canaries")
    canaries: list[str] = []
    for index, canary in enumerate(specs):
        if not isinstance(canary, str):
            raise PolicyError(f"{where}[{index}] must be text, got {type_name(canary)}")
        if not MIN_CANARY_CHARS <= len(canary) <= MAX_CANARY_CHARS:
            raise PolicyError(
                f"{where}[{index}] must be {MIN_CANARY_CHARS} to {MAX_CANARY_CHARS} characters long, "
                f"got {len(canary)}: a short canary would match ordinary text"
            )
        if not canary.isprintable() or canary != canary.strip():
            raise PolicyError(f"{where}[{index}] must be printable text with no spaces at either end")
        if canary.casefold() in (known.casefold() for known in canaries):
            raise PolicyError(f"{where}[{index}] is the same as an earlier canary (canaries are matched ignoring case)")
        canaries.append(canary)
    return tuple(canaries)


def _secret_patterns(specs: Any) -> tuple[SecretPattern, ...]:
    where = "secrets.patterns"
    if not isinstance(specs, list):
        raise PolicyError(f"{where} must be a list ([ ... ]), got {type_name(specs)}")
    if len(specs) > MAX_SECRET_PATTERNS:
        raise PolicyError(f"{where} can hold at most {MAX_SECRET_PATTERNS} formats")
    patterns = []
    keys = ("name", "prefix", "charset", "min_len", "max_len")
    for index, spec in enumerate(specs):
        entry = f"{where}[{index}]"
        _expect_object(spec, entry, allowed_keys=keys)
        missing = [key for key in keys if key not in spec]
        if missing:
            raise PolicyError(
                f"{entry} needs {listed(missing)}: a secret format is a name, a literal prefix, a charset "
                f"({', '.join(SECRET_CHARSETS)}) and the body's min_len and max_len"
            )
        _check_secret_pattern(spec, entry)
        patterns.append(SecretPattern(spec["name"], spec["prefix"], spec["charset"], spec["min_len"], spec["max_len"]))
    return tuple(patterns)


def _as_list(value: Any) -> Any:
    """A tuple given in code, as the list the loader's checks expect; anything else unchanged, for them to refuse."""
    return list(value) if isinstance(value, tuple) else value


def _code_secret_patterns(value: Any) -> tuple[SecretPattern, ...]:
    """Check secrets_patterns given in code: a list or tuple of SecretPattern (each checked itself when made)."""
    where = "secrets.patterns"
    if not isinstance(value, (list, tuple)):
        raise PolicyError(f"{where} must be a tuple of SecretPattern, got {type_name(value)}")
    for index, entry in enumerate(value):
        if not isinstance(entry, SecretPattern):
            raise PolicyError(f"{where}[{index}] must be a SecretPattern, got {type_name(entry)}")
    if len(value) > MAX_SECRET_PATTERNS:
        raise PolicyError(f"{where} can hold at most {MAX_SECRET_PATTERNS} formats")
    return tuple(value)


def _check_secret_pattern(spec: Any, where: str) -> None:
    """Validate one custom secret format, given as the policy's object or as a SecretPattern."""
    get = spec.get if isinstance(spec, dict) else lambda key: getattr(spec, key)
    name, prefix, charset = get("name"), get("prefix"), get("charset")
    if not isinstance(name, str) or not _SECRET_NAME.fullmatch(name) or name != name.strip():
        raise PolicyError(
            f"{where}.name must be 1 to 60 letters, digits, spaces or '_.()-', starting with a letter or digit, "
            f"got {quoted(name)}"
        )
    if not isinstance(prefix, str) or not _SECRET_PREFIX.fullmatch(prefix):
        raise PolicyError(
            f"{where}.prefix must be 3 to 64 characters of letters, digits and '_.:/+=@~-' (no spaces or quotes), "
            f"got {quoted(prefix)}: a secret format must start with literal text that ordinary words do not"
        )
    _expect_choice(charset, f"{where}.charset", tuple(SECRET_CHARSETS))
    lengths = []
    for key in ("min_len", "max_len"):
        value = get(key)
        if isinstance(value, bool) or not isinstance(value, int) or not MIN_SECRET_BODY <= value <= MAX_SECRET_BODY:
            raise PolicyError(
                f"{where}.{key} must be a whole number from {MIN_SECRET_BODY} to {MAX_SECRET_BODY}, got {quoted(value)}"
            )
        lengths.append(value)
    if lengths[0] > lengths[1]:
        raise PolicyError(f"{where}: min_len ({lengths[0]}) is larger than max_len ({lengths[1]})")


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
        if not deny and "action" in spec:
            raise PolicyError(f"{entry}: 'action' is only used in deny_args (\"ask\" sends a matching call to a "
                              "person instead of refusing it)")
        action = spec.get("action", "block")
        _expect_choice(action, f"{entry}.action", ("block", "ask"))
        rules.append(ArgRule(arg, matchers.build(spec, entry, deny=deny, any_arg=arg == ANY_ARG), optional, action))
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
    _expect_calls_per_minute(value, where)
    return value


def _expect_calls_per_minute(value: Any, where: str) -> None:
    """Refuse a max_calls_per_minute that is not a whole number of 1 or more."""
    # bool is a subclass of int in Python, and `true` is not a number of calls.
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise PolicyError(f"{where}.max_calls_per_minute must be a whole number of 1 or more, got {quoted(value)}")


def _check_code_arg_rules(rules: Sequence[ArgRule], where: str, deny: bool) -> None:
    """The checks `_arg_rules` makes of "optional", for argument rules built in code (Policy.__post_init__).

    A truthy text such as "no" must not make a required argument optional,
    and a deny entry is never optional.
    """
    for index, rule in enumerate(rules):
        if not isinstance(rule.optional, bool):
            raise PolicyError(f"{where}[{index}]: 'optional' must be true or false, got {quoted(rule.optional)}")
        if deny and rule.optional:
            raise PolicyError(f"{where}[{index}]: 'optional' is only used in allow_args")
        # A typo such as "Ask" or "allow" must not quietly turn a deny entry into something else.
        _expect_choice(rule.action, f"{where}[{index}].action", ("block", "ask") if deny else ("block",))


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


def _expect_bool(value: Any, where: str) -> None:
    if not isinstance(value, bool):
        raise PolicyError(f"{where} must be true or false (without quotes), got {quoted(value)}")


def _expect_severity(severity: Any) -> None:
    # The type check comes first: a list or object here cannot be looked up in a dict.
    if severity is not None and (not isinstance(severity, str) or severity not in SEVERITY_ORDER):
        message = choice_message("injection.block_severity", severity, tuple(SEVERITY_ORDER))
        raise PolicyError(f"{message}. null turns blocking off")


def _expect_name(name: Any, what: str) -> None:
    """Refuse a tool, method or argument name that is empty or has spaces around it: almost certainly a typo."""
    if not isinstance(name, str) or not name or name != name.strip():
        raise PolicyError(f"{what} {name!r} must be text that is not empty and has no spaces around it")
