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
-- <server command>` drafts a policy from them. The claude-code templates are
for the Claude Code hooks, with Claude Code's own tool names (Read, Bash ...).

Templates whose tools write files keep them away from agents' configuration
(write_protection): the starter templates ask, the strict ones refuse.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

# What may come right before a credential file's name: the start of the text,
# a path separator or a drive's ":", but also a space or a character a shell or
# a command line puts there. So "cat .env", "curl -d @.env", "--env-file=.env"
# and "Get-Content .env" match, as well as "~/.ssh/id_rsa". The typographic
# quotes ‘ to „ are there because PowerShell reads them as quotes
# (Get-Content ‘.env’).
_NAME_START = r"(^|[\s\\/:@='\"`<>|;&(,{\u2018-\u201e])"
# The quotes a setting's name may stand in: ' and ", and the typographic ones PowerShell also reads as quotes.
_QUOTE = r"[\"'\u2018-\u201e]"

# What may come right after a credential file's name when the name ends there:
# the end of the value, white space, or a character that closes an argument.
# A path separator is not here, and neither is "." or "-", because a name that
# goes on is a different name.
_NAME_END = r"(?=$|[\s'\"`<>|;&,)}\]\u2018-\u201e])"
# A name that only looks like a credential file: the example committed beside
# it (".env.example", ".npmrc.sample"), which holds placeholders, not secrets.
# Writing and naming one is ordinary work, so EVERY name below is left out when
# one of the four endings is where the name ends. ".env.example" and
# "cat .npmrc.sample" pass; ".env.example.bak", ".env.sample-prod" and anything
# under a folder named ".env.example" are refused, as ".env" itself is. The
# detector leaves the same four endings out of its own names the same way
# (_CREDENTIAL_FILE in detector.py); a test holds the two together.
_EXAMPLE_FILE = r"(?!\.(example|sample|template|dist)" + _NAME_END + r")"

# The credential preset of policy.example.json (a test keeps the two the same).
# Every alternative ends with _EXAMPLE_FILE, so no name is refused in its
# committed-example spelling.
CREDENTIAL_PATTERN = (
    _NAME_START + r"\.(ssh|aws|azure|docker|gnupg|kube|env|netrc|npmrc|pypirc|pgpass|git-credentials)\b"
    + _EXAMPLE_FILE
    + r"|id_(rsa|dsa|ecdsa|ed25519)" + _EXAMPLE_FILE
    + r"|" + _NAME_START + r"(ssh|aws|azure|docker|gnupg|kube|env|netrc|npmrc|pypirc|pgpass|git-cr|id_ed2)~[0-9]"
    + _EXAMPLE_FILE
    + r"|" + _NAME_START + r"(\.config|config~[0-9]+)[\\/](gh|gcloud|github-copilot)\b" + _EXAMPLE_FILE
    + r"|(^|[\\/])proc[\\/][^\\/]+[\\/]environ\b" + _EXAMPLE_FILE
    + r"|claude_desktop_config\.json" + _EXAMPLE_FILE
    + r"|" + _NAME_START + r"\.claude\.json\b" + _EXAMPLE_FILE
    + r"|" + _NAME_START + r"\.(cursor|vscode)[\\/]mcp\.json\b" + _EXAMPLE_FILE
    + r"|[\\/]code[\\/]user[\\/]mcp\.json\b" + _EXAMPLE_FILE
)

# Deny rules for every call. The second and third keep an agent away from
# agent-sentinel's own folder (home.py): an agent that could rewrite the policy
# or the pins could switch the protection off. "AGENT-~1" is the Windows short
# name the folder can also be reached by.
AGENT_SENTINEL_HOME_PATTERN = r"(^|[\\/:])agent-~[0-9]"
BASELINE_DENY_ARGS: tuple[dict[str, Any], ...] = (
    {"arg": "*", "pattern": CREDENTIAL_PATTERN},
    {"arg": "*", "contains": ".agent-sentinel"},
    {"arg": "*", "pattern": AGENT_SENTINEL_HOME_PATTERN},
)

# Files that tell an agent what to do, or let it run code when it or a shell
# starts: its settings and hooks, the MCP servers it starts, its instruction and
# memory files, git hooks, and shell start-up files. An agent that may write one
# can switch agent-sentinel off for the next session or plant instructions.
# Used ONLY on the arguments of tools that write (never "arg": "*"): reading
# CLAUDE.md, or a commit message that names it, must stay possible. The Windows
# short names of these files are refused by the path entries that go with it
# (HOME_CONFIG_ROOTS), which refuse every short name.
AGENT_CONFIG_PATTERN = (
    r"(^|[\\/:])\.claude[\\/](settings(\.local)?\.json|hooks|agents|skills|commands|rules)\b"
    r"|(^|[\\/:])\.mcp\.json\b"
    r"|(^|[\\/:])(CLAUDE(\.local)?|AGENTS|MEMORY|GEMINI)\.md\b"
    r"|(^|[\\/:])\.github[\\/]copilot-instructions\.md\b"
    r"|(^|[\\/:])\.vscode[\\/](settings|tasks)\.json\b"
    r"|(^|[\\/:])\.cursor[\\/](rules|cli\.json|hooks\.json)\b"
    r"|(^|[\\/:])\.cursorrules\b"
    r"|(^|[\\/:])\.(gemini|windsurf)([\\/]|$)"
    r"|(^|[\\/:])mcp_config\.json\b"
    r"|(^|[\\/:])\.codex[\\/]config\.toml\b"
    r"|(^|[\\/:])\.git[\\/](hooks|config)\b"
    r"|(^|[\\/:])\.(bashrc|bash_profile|bash_login|zshrc|zshenv|zprofile|profile)\b"
    r"|(^|[\\/:])([\w.]+_)?profile\.ps1\b"
)
# A path spelled in a roundabout way: a "." or ".." part after a name, or two
# separators in a row after a name ("app/.claude/./settings.json",
# "app/.claude//settings.json", "app/.claude/x/../settings.json"). Every system
# opens the plain path, but a text pattern such as AGENT_CONFIG_PATTERN does not
# see it there, so the write tools are not given such a path at all. A leading
# "./" or "../" is plain and still allowed; so is a trailing separator.
ROUNDABOUT_PATH_PATTERN = (
    r"[^\\/:][\\/]{2,}"
    r"|(^|[\\/:])(?!\.\.?[\\/])[^\\/:]+[\\/]+\.\.?([\\/]|$)"
)
# The folders in the home folder that hold agents' own settings, and agent-sentinel's.
# A "type": "path" entry with these roots also refuses every Windows short name
# ("CLAUDE~1") and every value it cannot read with certainty.
HOME_CONFIG_ROOTS = ("~/.claude", "~/.cursor", "~/.codeium", "~/.gemini", "~/.codex", "~/.agent-sentinel")
# Folders of keys that no tool of an agent needs: a "type": "path" deny for the
# arguments that name a file, beside the text pattern, because it refuses
# short names ("SSH~1\\ID_ED2~1") and spellings such as %USERPROFILE%.
SECRET_ROOTS = ("~/.ssh", "~/.aws", "~/.agent-sentinel")
# Text that sets what decides where an agent sends its requests, which code
# Node loads, or whether the agent asks before it acts.
#   * NAME= / "NAME": / NAME: anywhere (code, settings, a shell): a *_BASE_URL in
#     upper case (as environment variables are written; "api_base_url = ..." in
#     ordinary code is left alone), and Anthropic's own *_BASE_URL and
#     NODE_OPTIONS in any case, because Windows and Node on Windows read
#     environment variable names without case;
#   * Windows' own ways of setting a variable, where case never matters: setx,
#     $env:NAME = ..., PowerShell's env: drive (Set-Item env:NAME) and
#     [Environment]::SetEnvironmentVariable('NAME', ...);
#   * a name with a plain letter, digit, "_" or "." written as an escape that
#     the program reading the file decodes (JSON's, and YAML's and TOML's,
#     _ or \U0000005f), right before ":" or "=": "chat.tools.autoApprove":
#     and NODE_OPTIONS=. Ordinary files have no reason to escape those.
#     The name is read once, from its start, as one run of letters, digits,
#     "_", "." and backslashes (so other escapes in it, such as \x5f, count
#     too): a match tried at every escape of a long run of escapes cost
#     seconds per megabyte. A lookahead finds the escape in the run, then the
#     run is passed over in one step.
_ANY_CASE_SETTING = r"\w*_base_url|node_options"
_ESCAPED_PLAIN = r"\\(u00|U000000)(2e|3[0-9]|4[1-9a-f]|5[0-9af]|6[1-9a-f]|7[0-9a])"
_ESCAPED_NAME = r"(?<![\w.\\])(?=[\w.\\]*?" + _ESCAPED_PLAIN + r")[\w.\\]*"
CONTROL_SETTING_PATTERN = (
    r"(?<![\w.-])((?-i:[A-Z][A-Z0-9_]*_BASE_URL)|anthropic\w*_base_url|node_options"
    r"|chat\.tools\.(global\.)?autoApprove|enableAllProjectMcpServers|disableAllHooks)"
    + _QUOTE + r"?\s*[:=]"
    r"|\bsetx(\.exe)?\s+(/m\s+)?" + _QUOTE + r"?(" + _ANY_CASE_SETTING + r")\b"
    r"|\$\{?env:(" + _ANY_CASE_SETTING + r")\}?\s*\+?="
    r"|(?<![\w$:{])env:[\\/]?(" + _ANY_CASE_SETTING + r")\b"
    r"|SetEnvironmentVariable\s*\(\s*" + _QUOTE + r"?(" + _ANY_CASE_SETTING + r")\b"
    r"|" + _ESCAPED_NAME + _QUOTE + r"?\s*[:=]"
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

# Claude Code's own tools (hook mode), and the arguments that name the file they read or write.
CLAUDE_CODE_READ_TOOLS: dict[str, str] = {"Read": "file_path", "Grep": "path", "Glob": "path"}
# The tools that search a folder, and the argument that holds the file pattern of the search (Grep's
# "pattern" is the text looked for, a regular expression; its file pattern is "glob").
CLAUDE_CODE_SEARCH_TOOLS: dict[str, str] = {"Grep": "glob", "Glob": "pattern"}
CLAUDE_CODE_WRITE_TOOLS: dict[str, str] = {
    "Edit": "file_path", "Write": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path",
}
# Tools that neither read nor send anything the flow rules care about ("labels": [] says so): subagents,
# the to-do and task lists, plan mode, questions to the user, and stopping a background task.
CLAUDE_CODE_PLAIN_TOOLS = (
    "Agent", "Task", "TodoWrite", "AskUserQuestion", "ExitPlanMode", "SubagentHandback", "EnterPlanMode",
    "TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "TaskStop", "KillShell",
)
# Tools that bring text this machine holds into the conversation, as Read does: a skill's instructions,
# what a background command has printed (TaskOutput; BashOutput in older versions of Claude Code), and
# the definition of a tool that Claude Code has not loaded yet (ToolSearch, which sends nothing out).
CLAUDE_CODE_LOCAL_TEXT_TOOLS = ("Skill", "TaskOutput", "BashOutput", "ToolSearch")
# The command classes each template refuses or asks about (commands.py).
COMMAND_CLASSES_ASKED = ["network", "install", "config_write", "obfuscation"]
COMMAND_CLASSES_STRICT = ["network", "install", "secret_read", "config_write", "obfuscation", "encoded_host"]
# What a command adds to the flow labels of a Bash or PowerShell call (which is "private" whatever it
# runs: a shell reads local files as Read and Grep do). One that talks to another machine can carry data
# out, and what it prints is content from there, as a fetched page is.
COMMAND_LABELS = {"network": ["untrusted", "sink"], "install": ["untrusted", "sink"], "secret_read": ["private"]}
# A file pattern with a hidden file or folder spelled through a wildcard, a class or a brace list
# (".ss*/*", "**/.e*", "[.]ssh/*", "{.aws,x}/cred*"): it can name a credential folder that the text
# patterns do not see. Used on the file pattern of the search tools only.
HIDDEN_GLOB_PATTERN = r"(^|[\\/{,])(\.[^\\/]*[*?\[{]|\[[^\]\\/]*\.)"
# The strict hook template keeps the parts of a fetched URL that can carry data short.
STRICT_URL_LIMITS = {"max_label_length": 30, "max_path_segment_chars": 80, "max_query_chars": 128}

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


def write_protection(arguments: tuple[str, ...], action: str) -> list[dict[str, Any]]:
    """deny_args for a tool that writes files ("ask" or "block" for what they match).

    Its path arguments may not name an agent's configuration, instruction or
    hook file (AGENT_CONFIG_PATTERN), nor anything in the home folders of
    agents' settings (HOME_CONFIG_ROOTS: a path entry, which also refuses
    Windows short names and values it cannot read), nor be spelled in a
    roundabout way that the text pattern would not see through
    (ROUNDABOUT_PATH_PATTERN: "a/./b", "a//b", "a/x/../b"). No argument may set
    what decides where the agent's requests go or whether it asks first
    (CONTROL_SETTING_PATTERN). Never for "arg": "*" on every tool: reading
    CLAUDE.md must stay possible.
    """
    entries: list[dict[str, Any]] = []
    for argument in arguments:
        entries.append({"arg": argument, "pattern": AGENT_CONFIG_PATTERN})
        entries.append({"arg": argument, "type": "path", "roots": list(HOME_CONFIG_ROOTS)})
        entries.append({"arg": argument, "pattern": ROUNDABOUT_PATH_PATTERN})
    entries.append({"arg": "*", "pattern": CONTROL_SETTING_PATTERN})
    if action == "ask":
        for entry in entries:
            entry["action"] = "ask"
    return entries


def _fetch_denies(limits: dict[str, int] | None = None) -> list[dict[str, Any]]:
    """A fetch tool's url argument: never this machine, the local network or a cloud metadata service."""
    return [
        {"arg": "url", "type": "url", "hosts": list(_LOCAL_HOSTS), **(limits or {})},
        {"arg": "url", "pattern": LOCAL_NETWORK_URL},
    ]


def _starter() -> dict[str, Any]:
    policy = _baseline()
    tools = policy["tools"]
    tools.update(_rules(FILE_READ_TOOLS, {"action": "allow", "labels": ["private"]}))
    tools.update(_rules(GIT_READ_TOOLS, {"action": "allow", "labels": ["private"], "deny_args": [NO_OPTIONS]}))
    tools.update(_rules(MEMORY_READ_TOOLS, {"action": "allow", "labels": ["private"]}))
    tools["fetch"] = {"action": "allow", "labels": ["untrusted", "sink"], "deny_args": _fetch_denies()}
    for name in FILE_WRITE_TOOLS:
        tools[name] = {"action": "ask", "labels": ["sink"], "deny_args": write_protection(_PATH_ARGUMENTS[name], "ask")}
    tools["delete_*"] = "block"
    tools["run_*"] = "block"
    policy["secrets"]["in_results"] = "redact"
    # A result that reads like instructions to the agent (a medium finding) reaches it with a notice to
    # treat it as data. mark_at stays off: ordinary documentation pages are often written as orders.
    policy["injection"]["warn_severity"] = "medium"
    # The "lethal trifecta": once the agent has read both web content (which can
    # carry instructions) and private files, it may no longer use a tool that
    # sends data out.
    policy["flows"] = [{"after": ["untrusted", "private"], "then": "sink", "action": "block"}]
    # The proxy reports calls and results that do not match the server's schemas, and schemas that
    # refer outside themselves, without refusing anything for it.
    policy["schema_checks"] = {"arguments": "warn", "results": "warn", "remote_refs": "warn"}
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
            # Even inside a root: a project's .claude/settings.json, .mcp.json or CLAUDE.md is refused.
            tools[name]["deny_args"] = write_protection(arguments, "block")
        else:
            tools[name]["labels"] = ["private"]
    tools["list_allowed_directories"] = {"action": "allow", "labels": ["private"]}
    # Prompts are checked like tool calls once client_requests exists; none is allowed.
    tools["prompts/get"] = "block"
    policy["server_requests"] = dict(STRICT_SERVER_REQUESTS)
    policy["client_requests"] = {"completion/complete": "block", "*": "allow"}
    policy["injection"]["block_severity"] = "medium"
    # Content with a medium finding is withheld here; were it let through (monitor mode, a lower
    # block_severity), it would get the notice and count as untrusted for the flow rule below.
    policy["injection"]["warn_severity"] = "medium"
    policy["injection"]["mark_at"] = "medium"
    policy["secrets"]["in_results"] = "block"
    policy["limits"]["max_calls_per_minute"] = 60
    # One mark is enough: after any untrusted content, nothing may be sent out.
    policy["flows"] = [{"after": ["untrusted"], "then": "sink", "action": "block"}]
    # The proxy refuses calls and results that do not match the server's schemas and arguments the
    # schema does not declare, and quarantines a tool whose schema refers outside itself.
    policy["schema_checks"] = {"arguments": "enforce", "results": "enforce", "undeclared_args": "block",
                               "remote_refs": "quarantine"}
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


def _claude_code(strict: bool) -> dict[str, Any]:
    """A policy for the Claude Code hooks (`hook install claude-code`), with Claude Code's own tool names.

    "allow" lets Claude Code's own permission rules decide; "ask" shows its
    prompt (and refuses in a mode that shows none, such as bypassPermissions).
    """
    policy = _baseline()
    tools = policy["tools"]
    action = "block" if strict else "ask"
    for name, argument in CLAUDE_CODE_READ_TOOLS.items():
        tools[name] = {"action": "allow", "labels": ["private"],
                       "deny_args": [{"arg": argument, "type": "path", "roots": list(SECRET_ROOTS)}]}
    for name, argument in CLAUDE_CODE_SEARCH_TOOLS.items():
        # A search reaches everything below its folder: it may not start in a credential folder, nor in a
        # folder above one (the home folder), and its file pattern may not spell a hidden name with wildcards.
        tools[name]["deny_args"][0]["or_above"] = True
        tools[name]["deny_args"].append({"arg": argument, "pattern": HIDDEN_GLOB_PATTERN})
    for name, argument in CLAUDE_CODE_WRITE_TOOLS.items():
        tools[name] = {
            "action": "allow",
            "labels": [],
            "deny_args": [{"arg": argument, "type": "path", "roots": list(SECRET_ROOTS)},
                          *write_protection((argument,), action)],
        }
    for name, shell in (("Bash", "bash"), ("PowerShell", "powershell")):
        setting = {"arg": "command", "pattern": CONTROL_SETTING_PATTERN}
        if not strict:
            setting["action"] = "ask"
        command: dict[str, Any] = {"shell": shell}
        if strict:
            command["deny_classes"] = list(COMMAND_CLASSES_STRICT)
        else:
            command["ask_classes"] = list(COMMAND_CLASSES_ASKED)
        command["labels_by_class"] = copy.deepcopy(COMMAND_LABELS)
        tools[name] = {"action": "allow", "labels": ["private"], "deny_args": [setting], "command": command}
    tools["WebFetch"] = {"action": "allow", "labels": ["untrusted", "sink"],
                         "deny_args": _fetch_denies(STRICT_URL_LIMITS if strict else None)}
    # A search query, a resource URI and a server name all leave the machine.
    for name in ("WebSearch", "ReadMcpResourceTool", "ListMcpResourcesTool"):
        tools[name] = {"action": "allow", "labels": ["untrusted", "sink"]}
    tools["Monitor"] = {"action": "ask", "labels": ["untrusted", "sink"]}
    tools.update(_rules(CLAUDE_CODE_PLAIN_TOOLS, {"action": "allow", "labels": []}))
    tools.update(_rules(CLAUDE_CODE_LOCAL_TEXT_TOOLS, {"action": "allow", "labels": ["private"]}))
    tools["mcp__*"] = {"action": "ask", "labels": ["untrusted", "sink"]}
    # As in the proxy templates: output that reads like instructions to the agent (a medium finding)
    # reaches Claude with a notice to treat it as data (PostToolUse additionalContext). In the strict
    # template such output is withheld, so the notice shows only where it is let through (monitor mode).
    policy["injection"]["warn_severity"] = "medium"
    if strict:
        policy["injection"]["block_severity"] = "medium"
        policy["secrets"]["in_results"] = "block"
        policy["limits"]["max_calls_per_minute"] = 60
        # After untrusted content, a person approves each call that sends something out; after untrusted
        # content and private data, nothing is sent. (A block after untrusted alone would make WebFetch
        # refuse itself after its first page.)
        policy["flows"] = [
            {"after": ["untrusted"], "then": "sink", "action": "ask"},
            {"after": ["untrusted", "private"], "then": "sink", "action": "block"},
        ]
    else:
        policy["secrets"]["in_results"] = "redact"
        policy["flows"] = [{"after": ["untrusted", "private"], "then": "sink", "action": "block"}]
    return policy


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
        Template(
            "claude-code",
            "For the Claude Code hooks: Claude Code's own tools, with credential folders kept out of reach, writes "
            "to agent settings and instruction files asked about, Bash and PowerShell commands that reach the "
            "network, install packages, write agent settings or hide what they run asked about, and nothing sent "
            "out once web content and private files have both been read.",
            _claude_code(strict=False),
            (
                "Validate it: agent-sentinel validate {policy}",
                "Install the hooks: agent-sentinel hook install claude-code --policy {policy}",
            ),
        ),
        Template(
            "claude-code-strict",
            "Like claude-code, but refuses the writes to agent settings and instruction files and the commands "
            "it asks about there, and any command that names a credential file or a host that looks like it "
            "carries data (a command it cannot read, Monitor and MCP tools are still asked about); keeps WebFetch "
            "URLs short, asks before anything is sent out after untrusted content, and blocks medium injection "
            "findings.",
            _claude_code(strict=True),
            (
                "Validate it: agent-sentinel validate {policy}",
                "Install the hooks: agent-sentinel hook install claude-code --policy {policy}",
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
