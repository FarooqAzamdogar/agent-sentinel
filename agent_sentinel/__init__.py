"""agent-sentinel: a permission and prompt-injection firewall for AI agent tool calls.

Module map:

    detector.py   finds prompt injection in text            (no dependencies)
    leaks.py      recognises secrets in outgoing text       (no dependencies)
    policy.py     decides allow / ask / block for a call    (uses detector for severities)
    matchers.py   the ways a policy judges one argument's value (pattern, one_of, path, url, ...)
    policy_errors.py  error messages that help fix a policy file
    firewall.py   combines the three and writes the audit log   (the public core)
    mcp_proxy.py  puts the firewall in front of an MCP server
    __main__.py   the `agent-sentinel` command line
    textutil.py   helpers shared by the above
"""

from .detector import Finding, scan
from .firewall import BlockedError, Decision, Firewall
from .policy import Policy, PolicyError
from .textutil import printable

__all__ = ["BlockedError", "Decision", "Finding", "Firewall", "Policy", "PolicyError", "printable", "scan"]
__version__ = "0.4.1"
