"""agent-sentinel: a permission and prompt-injection firewall for AI agent tool calls.

Module map:

    detector.py   finds prompt injection in text            (no dependencies)
    leaks.py      recognises secrets in calls, results and logs  (uses textutil)
    policy.py     decides allow / ask / block for a call    (uses detector for severities)
    matchers.py   the ways a policy judges one argument's value (pattern, one_of, path, url, ...)
    policy_errors.py  error messages that help fix a policy file
    session.py    what the agent has read this session, for flow rules (memory or file store)
    filelock.py   operating-system file locks (audit log, session files)
    firewall.py   combines the three and writes the audit log   (the public core)
    mcp_proxy.py  puts the firewall in front of an MCP server
    __main__.py   the `agent-sentinel` command line
    textutil.py   helpers shared by the above
"""

from .detector import Finding, scan
from .firewall import BlockedError, CheckedResult, Decision, Firewall
from .policy import Policy, PolicyError
from .session import FileSessionStore, MemorySessionStore, SessionStateError
from .textutil import printable

__all__ = [
    "BlockedError", "CheckedResult", "Decision", "FileSessionStore", "Finding", "Firewall", "MemorySessionStore",
    "Policy", "PolicyError", "SessionStateError", "printable", "scan",
]
__version__ = "0.4.1"
