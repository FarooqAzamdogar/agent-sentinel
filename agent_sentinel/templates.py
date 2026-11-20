"""Policy templates for `agent-sentinel init --template NAME`, and the parts every drafted policy shares.

The templates are Python constants (not data files), so they are installed
with the package without any packaging configuration, and a test loads each
one with the strict loader. `template(name)` returns a fresh copy.

Every template:

  * blocks by default, and hides the tools it blocks outright from the
    agent's tool list (hide_blocked_tools);
  * denies arguments that name credential files (the preset of
    policy.example.json) or agent-sentinel's own folder, where the policy,
    the audit log and the pins live;
  * refuses arguments that hold a recognisable secret, and keeps the server
    from using the client's model (sampling/createMessage).

The tool names are those of the reference MCP servers (filesystem, git,
fetch, memory). Other servers name their tools differently: `agent-sentinel
inspect -- <server command>` lists a server's names, and `agent-sentinel init
-- <server command>` drafts a policy from them.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

# What may come right before a credential file's name: the start of the text,
# a path separator or a drive's ":", but also a space or a character a shell or
# a command line puts there. So "cat .env", "curl -d @.env", "--env-file=.env"
# and "Get-Content .env" match, as well as "~/.ssh/id_rsa".
_NAME_START = r"(^|[\s\\/:@='\"`<>|;&(,{])"

# The credential preset of policy.example.json (a test keeps the two the same).
CREDENTIAL_PATTERN = (
    _NAME_START + r"\.(ssh|aws|azure|docker|gnupg|kube|env|netrc|npmrc|pypirc|pgpass|git-credentials)\b"
    r"|id_(rsa|dsa|ecdsa|ed25519)"
    r"|" + _NAME_START + r"(ssh|aws|azure|docker|gnupg|kube|env|netrc|npmrc|pypirc|pgpass|git-cr|id_ed2)~[0-9]"
    r"|" + _NAME_START + r"(\.config|config~[0-9]+)[\\/](gh|gcloud|github-copilot)\b"
    r"|(^|[\\/])proc[\\/][^\\/]+[\\/]environ\b"
    r"|claude_desktop_config\.json"
    r"|" + _NAME_START + r"\.claude\.json\b"
    r"|" + _NAME_START + r"\.(cursor|vscode)[\\/]mcp\.json\b"
    r"|[\\/]code[\\/]user[\\/]mcp\.json\b"
)

# Deny rules for every call. The second and third keep an agent away from
# agent-sentinel's own folder (home.py): an agent that could rewrite the policy
# or the pins could switch the protection off. "AGENT-~1" is the Windows short
# name the folder can also be reached by.
BASELINE_DENY_ARGS: tuple[dict[str, Any], ...] = (
    {"arg": "*", "pattern": CREDENTIAL_PATTERN},
    {"arg": "*", "contains": ".agent-sentinel"},
    {"arg": "*", "pattern": r"(^|[\\/:])agent-~[0-9]"},
)

# A value that starts with "-" can be read as an option by a program the tool
# starts (git's "--output=...", for example). Used on tools that run commands.
NO_OPTIONS: dict[str, Any] = {"arg": "*", "no_options": True}

# The server may not ask the client's model to write text for it. Everything else it may ask.
SERVER_REQUESTS: dict[str, str] = {"sampling/createMessage": "block", "*": "allow"}

# The strict template refuses every request from the server ("*" below), but lets
# through the notifications that only report something and the harmless ping.
# Refusing those would fill the audit log and stderr with a line for each progress
# report. They are still scanned like everything else the server sends.
STRICT_SERVER_REQUESTS: dict[str, str] = {
    "notifications/message": "allow",
    "notifications/progress": "allow",
    "notifications/cancelled": "allow",
    "notifications/tools/list_changed": "allow",
    "notifications/prompts/list_changed": "allow",
    "notifications/resources/list_changed": "allow",
    "notifications/resources/updated": "allow",
    "ping": "allow",
    "*": "block",
}

# Read-only tools of the reference servers, by what they read.
FILE_READ_TOOLS = (
    "read_text_file", "read_file", "read_multiple_files", "read_media_file", "list_directory",
    "list_directory_with_sizes", "directory_tree", "search_files", "get_file_info", "list_allowed_directories",
)
GIT_READ_TOOLS = ("git_status", "git_diff_unstaged", "git_diff_staged", "git_diff", "git_log", "git_show", "git_branch")
MEMORY_READ_TOOLS = ("read_graph", "search_nodes", "open_nodes")
FILE_WRITE_TOOLS = ("write_file", "edit_file", "create_directory", "move_file")

# Tools whose arguments name paths, and the arguments that do (reference filesystem and git servers).
_PATH_ARGUMENTS: dict[str, tuple[str, ...]] = {
    "read_text_file": ("path",), "read_file": ("path",), "read_multiple_files": ("paths",),
    "read_media_file": ("path",), "list_directory": ("path",), "list_directory_with_sizes": ("path",),
    "directory_tree": ("path",), "search_files": ("path",), "get_file_info": ("path",),
    "write_file": ("path",), "edit_file": ("path",), "create_directory": ("path",),
    "move_file": ("source", "destination"),
    **{name: ("repo_path",) for name in GIT_READ_TOOLS},
}
# The folder the strict template lets the agent read, unless `init --root` names others.
# A placeholder: `init` says to change it.
STRICT_ROOT = "~/projects"

# Hosts a fetch tool must never reach: this machine, names of the local network, and
# the cloud metadata services, which hand out credentials. A deny rule of type url also
# refuses any URL it cannot read with certainty (user names in it, backslashes, odd
# spellings of an address such as http://2130706433/).
_LOCAL_HOSTS = ["localhost", ".localhost", ".local", ".internal", ".home.arpa", "metadata.goog"]
# The rest of the local network: a URL whose host is an IP address ("http://10.0.0.5/",
# "http://[::1]/") or a name without a dot ("http://router/"). A type url rule lists
# hosts one by one, so this one is a pattern. It refuses public IP addresses too:
# web pages are fetched by name.
LOCAL_NETWORK_URL = r"^\s*[a-z][a-z0-9+.-]*:/*(\[|[0-9.]+([:/?#]|$)|[^./?#:@]+([:/?#]|$))"


@dataclass(frozen=True)
class Template:
    """One template: what it is for, the policy itself, and what to do after writing it."""

    name: str
    summary: str
    policy: dict[str, Any]
    next_steps: tuple[str, ...]


def _rules(names: tuple[str, ...], rule: Any) -> dict[str, Any]:
    return {name: copy.deepcopy(rule) for name in names}


def _baseline() -> dict[str, Any]:
    """The parts every template and every drafted policy starts from, in the order they are written."""
    return {
        "default": "block",
        "hide_blocked_tools": True,
        "deny_args": [dict(entry) for entry in BASELINE_DENY_ARGS],
        "tools": {},
        "server_requests": dict(SERVER_REQUESTS),
        "injection": {"block_severity": "high"},
        "secrets": {"in_arguments": "block"},
        "limits": {"max_calls_per_minute": 120},
    }


def baseline_policy() -> dict[str, Any]:
    """A fresh copy of the baseline, for `init -- <server command>` to add the server's tools to."""
    return _baseline()


def _starter() -> dict[str, Any]:
    policy = _baseline()
    tools = policy["tools"]
    tools.update(_rules(FILE_READ_TOOLS, {"action": "allow", "labels": ["private"]}))
    tools.update(_rules(GIT_READ_TOOLS, {"action": "allow", "labels": ["private"], "deny_args": [NO_OPTIONS]}))
    tools.update(_rules(MEMORY_READ_TOOLS, {"action": "allow", "labels": ["private"]}))
    tools["fetch"] = {
        "action": "allow",
        "labels": ["untrusted", "sink"],
        "deny_args": [
            {"arg": "url", "type": "url", "hosts": list(_LOCAL_HOSTS)},
            {"arg": "url", "pattern": LOCAL_NETWORK_URL},
        ],
    }
    tools.update(_rules(FILE_WRITE_TOOLS, {"action": "ask", "labels": ["sink"]}))
    tools["delete_*"] = "block"
    tools["run_*"] = "block"
    policy["secrets"]["in_results"] = "redact"
    # The "lethal trifecta": once the agent has read both web content (which can
    # carry instructions) and private files, it may no longer use a tool that
    # sends data out.
    policy["flows"] = [{"after": ["untrusted", "private"], "then": "sink", "action": "block"}]
    return policy


def _strict(roots: tuple[str, ...] = (STRICT_ROOT,)) -> dict[str, Any]:
    policy = _baseline()
    tools = policy["tools"]
    # Every path the agent names, to read, to write or to run git in, must be inside a root.
    for name, arguments in _PATH_ARGUMENTS.items():
        tools[name] = {
            "action": "ask" if name in FILE_WRITE_TOOLS else "allow",
            "allow_args": [{"arg": argument, "type": "path", "roots": list(roots)} for argument in arguments],
        }
        if name in GIT_READ_TOOLS:
            tools[name]["deny_args"] = [dict(NO_OPTIONS)]
        if name in FILE_WRITE_TOOLS:
            tools[name]["labels"] = ["sink"]
    tools["list_allowed_directories"] = "allow"
    # Prompts are checked like tool calls once client_requests exists; none is allowed.
    tools["prompts/get"] = "block"
    policy["server_requests"] = dict(STRICT_SERVER_REQUESTS)
    policy["client_requests"] = {"completion/complete": "block", "*": "allow"}
    policy["injection"]["block_severity"] = "medium"
    policy["secrets"]["in_results"] = "block"
    policy["limits"]["max_calls_per_minute"] = 60
    # One mark is enough: after any untrusted content, nothing may be sent out.
    policy["flows"] = [{"after": ["untrusted"], "then": "sink", "action": "block"}]
    return policy


def _readonly() -> dict[str, Any]:
    policy = _baseline()
    tools = policy["tools"]
    tools.update(_rules(FILE_READ_TOOLS, "allow"))
    tools.update(_rules(GIT_READ_TOOLS, {"action": "allow", "deny_args": [NO_OPTIONS]}))
    tools.update(_rules(MEMORY_READ_TOOLS, "allow"))
    policy["secrets"]["in_results"] = "redact"
    return policy


def _monitor() -> dict[str, Any]:
    # No tool rules on purpose: in monitor mode every call is logged with the
    # rule that would have blocked it, and `suggest` turns the calls that only
    # the default blocked into exact rules.
    return _baseline()


_NEXT_COMMON = (
    "Check the tool names against your servers: agent-sentinel inspect --policy {policy} -- <server command>",
    "Validate it: agent-sentinel validate {policy}",
)

TEMPLATES: dict[str, Template] = {
    template.name: template
    for template in (
        Template(
            "starter",
            "Reads files, git history and web pages (never the local network); asks before writing (refused unless "
            "the proxy has an approver); once web content and private files have both been read, nothing more may "
            "be sent out.",
            _starter(),
            (*_NEXT_COMMON, "Protect a client: agent-sentinel wrap --client claude-desktop --policy {policy}"),
        ),
        Template(
            "strict",
            "Reads files, runs git and (after asking) writes only inside the folders given with --root; refuses "
            "every request from the server, checks prompts like tool calls, withholds results that hold a secret, "
            "and blocks medium injection findings.",
            _strict(),
            (*_NEXT_COMMON, "Protect a client: agent-sentinel wrap --client claude-desktop --policy {policy}"),
        ),
        Template(
            "readonly",
            "Reads files, git history and the memory graph; every other tool, including web fetches and all "
            "writes, is blocked and hidden from the agent.",
            _readonly(),
            (*_NEXT_COMMON, "Protect a client: agent-sentinel wrap --client claude-desktop --policy {policy}"),
        ),
        Template(
            "monitor",
            "For learning what your agent does: no tool is allowed yet. Run the proxy with --monitor (it logs what "
            "it would block and blocks nothing), use your agent, then let `suggest` draft the rules.",
            _monitor(),
            (
                "Wrap a client in monitor mode: "
                "agent-sentinel wrap --client claude-desktop --policy {policy} --monitor",
                "After using the agent a while: agent-sentinel suggest {audit} --policy {policy}",
                "Then unwrap and wrap again without --monitor: monitor mode protects nothing.",
            ),
        ),
    )
}


def template(name: str, roots: tuple[str, ...] = ()) -> dict[str, Any]:
    """A fresh copy of the named template's policy. KeyError for an unknown name.

    `roots` (strict only) replaces the placeholder folder in every "roots".
    The loader checks them when the policy is loaded, like any root.
    """
    if roots:
        if name != "strict":
            raise ValueError("only the strict template has folders to set")
        return _strict(roots)
    return copy.deepcopy(TEMPLATES[name].policy)
