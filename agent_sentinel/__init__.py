"""agent-sentinel: a permission and prompt-injection firewall for AI agent tool calls.

Module map:

  The core: what a program that runs tools uses
    detector.py       finds prompt injection in text            (no dependencies)
    leaks.py          recognises secrets in calls, results and logs  (uses textutil)
    policy.py         decides allow / ask / block for a call    (uses detector for severities)
    matchers.py       the ways a policy judges one argument's value (pattern, one_of, path, url, ...)
    policy_errors.py  error messages that help fix a policy file
    session.py        what the agent has read this session, for flow rules (memory or file store)
    filelock.py       operating-system file locks (audit log, session files)
    audit_chain.py    the audit log's hash chain: writing, rotation, checking (audit verify)
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
    containment.py    keeping the server's processes in check (--contain: job object, process group; --sandbox)
    schema_check.py   tool arguments and results against the server's schemas; references outside a schema
    approvers.py      how the proxy asks a person to approve a call (dialog, command, elicitation)
    proxy_report.py   what the proxy tells the operator on stderr
    client_run.py     which run of the MCP client a proxy belongs to (proxy --session-group)
    uri_template.py   whether a URI may come from a quarantined resource template (RFC 6570)

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
    launch.py         what a server's launch command runs, and what is risky about it (doctor, wrap, pins)
    advisories.py     known-bad MCP packages and popular names, as dated data (goes stale between releases)
    control_plane.py  whether the agent can reach agent-sentinel's own files (doctor)
    doctor_baseline.py  doctor --save-baseline / --baseline: what was added or changed since
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
