"""agent-sentinel: a permission and prompt-injection firewall for AI agent tool calls."""

from .detector import Finding, scan
from .firewall import BlockedError, Decision, Firewall
from .policy import Policy, PolicyError

__all__ = ["BlockedError", "Decision", "Finding", "Firewall", "Policy", "PolicyError", "scan"]
__version__ = "0.2.0"
