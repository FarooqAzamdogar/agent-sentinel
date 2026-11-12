"""agent-sentinel: a permission and prompt-injection firewall for AI agent tool calls.

Module map:

    detector.py   finds prompt injection in text            (no dependencies)
    policy.py     decides allow / ask / block for a call    (uses detector for severities)
    firewall.py   combines both and writes the audit log    (the public core)
    mcp_proxy.py  puts the firewall in front of an MCP server
    __main__.py   the `agent-sentinel` command line
    textutil.py   helpers shared by the above
"""

from .detector import Finding, scan
from .firewall import BlockedError, Decision, Firewall
from .policy import Policy, PolicyError

__all__ = ["BlockedError", "Decision", "Finding", "Firewall", "Policy", "PolicyError", "scan"]
__version__ = "0.3.0"
