"""agent-sentinel: a permission and prompt-injection firewall for AI agent tool calls.

Module map:

  The core: what a program that runs tools uses
    detector.py       finds prompt injection in text            (no dependencies)
    leaks.py          recognises secrets in calls, results and logs  (uses textutil)
    policy.py         decides allow / ask / block for a call    (uses detector for severities)
    matchers.py       the ways a policy judges one argument's value (pattern, one_of, path, url, ...)
    policy_errors.py  error messages that help fix a policy file
    session.py        what the agent has read this session, for flow rules (memory or file store)
    session_limits.py session limits, approval memory, and what an approval question shows
    tail_scan.py      reads the end of the last delivered result with the start of the next (DET-5)
    filelock.py       operating-system file locks (audit log, session files)
    firewall.py       combines the three and writes the audit log   (the public core)
    tool_guard.py     guard(): the firewall around a tool function
    textutil.py       helpers shared by the above
    jsonutil.py       strict JSON reading (no repeated keys, NaN or Infinity), for every file and event

  The MCP proxy
    mcp_proxy.py      puts the firewall in front of an MCP server
    mcp_protocol.py   what the proxy knows about MCP message shapes and protocol revisions
    pins.py           what the proxy remembers of tools, prompts, templates and instructions (pins file v2)
    elicitation.py    what an elicitation may ask the user
    server_env.py     the environment the server is started with
    approvers.py      how the proxy asks a person to approve a call (dialog, command, elicitation)
    proxy_report.py   what the proxy tells the operator on stderr

  Claude Code and the Claude Agent SDK
    claude_hooks.py   the answers to Claude Code's hook events; claude_sdk_hooks() for the Agent SDK
    hook_state.py     rate-limit counts per session, in a file (hook mode)

  The command line
    __main__.py       the `agent-sentinel` command line: the parser, then one module per command
    cli_<command>.py  each command (cli_check.py, cli_wrap.py, cli_pins.py, ...)
    cli_common.py     what the commands share: exit codes, reading input, printing
    auditlog.py       reading audit logs (report, explain, suggest)
    fix_hints.py      how to allow a call that a rule blocked (explain, report)
    home.py           the agent-sentinel home folder (~/.agent-sentinel)
    templates.py      the policies of `init --template`
    server_probe.py   start a server and list its tools through the proxy (inspect, init --)
    clients.py        the MCP clients and where their configurations are
    config_file.py    reading and editing a client's configuration file safely
    wrapping.py       putting the proxy in front of one server entry, and taking it out
    demo_server.py    the deliberately poisoned server of `agent-sentinel demo`
"""

# Set before the imports below, so that a module can read it while the package is being imported.
__version__ = "0.5.0"

from .claude_hooks import claude_sdk_hooks  # noqa: E402
from .detector import Finding, scan  # noqa: E402
from .firewall import BlockedError, CheckedResult, Decision, Firewall  # noqa: E402
from .policy import Policy, PolicyError  # noqa: E402
from .session import FileSessionStore, MemorySessionStore, SessionStateError  # noqa: E402
from .textutil import printable  # noqa: E402
from .tool_guard import guard  # noqa: E402

__all__ = [
    "BlockedError", "CheckedResult", "Decision", "FileSessionStore", "Finding", "Firewall", "MemorySessionStore",
    "Policy", "PolicyError", "SessionStateError", "claude_sdk_hooks", "guard", "printable", "scan",
]
