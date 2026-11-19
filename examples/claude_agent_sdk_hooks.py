"""Recipe: agent-sentinel in an application built on the Claude Agent SDK for Python.

    pip install claude-agent-sdk          (agent-sentinel itself needs nothing else)
    python examples/claude_agent_sdk_hooks.py policy.json "List the files in this folder"

Every tool call the agent makes is checked against the policy before it runs
(PreToolUse), and what tools return is scanned for prompt injection before
the model reads it (PostToolUse, PostToolUseFailure). The callbacks come from
`agent_sentinel.claude_hooks.claude_sdk_hooks` and give the same answers as
`agent-sentinel hook claude-code` does for Claude Code itself.

Tool names are the SDK's: "Read", "Bash", "WebFetch", and
"mcp__<server>__<tool>" for MCP tools, so the policy has rules for those.

BEST EFFORT. This recipe follows the SDK's documentation
(https://code.claude.com/docs/en/agent-sdk/hooks) and is tested against a
stand-in for the SDK, not against the SDK itself, whose API changes often.
`on_failure="block"` needs Python Agent SDK 0.2.177 or later: with it, a
callback that fails blocks the call instead of letting it through.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, HookMatcher

from agent_sentinel import Firewall, Policy
from agent_sentinel.claude_hooks import claude_sdk_hooks


def sentinel_hooks(firewall: Firewall) -> dict[str, list[Any]]:
    """The `hooks` option: one matcher per event, for every tool, blocking when a callback fails."""
    return {
        event: [HookMatcher(hooks=[callback], on_failure="block")]
        for event, callback in claude_sdk_hooks(firewall).items()
    }


def sentinel_options(policy_path: str, audit_path: str | None = None, **options: Any) -> ClaudeAgentOptions:
    """ClaudeAgentOptions with the firewall's hooks. One Firewall is one session: make new options per client."""
    firewall = Firewall(Policy.from_file(policy_path), audit_path)
    return ClaudeAgentOptions(hooks=sentinel_hooks(firewall), **options)


async def main(policy_path: str, prompt: str) -> None:
    options = sentinel_options(policy_path, audit_path="audit.jsonl")
    async with ClaudeSDKClient(options=options) as client:
        await client.query(prompt)
        async for message in client.receive_response():
            print(message)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python examples/claude_agent_sdk_hooks.py POLICY PROMPT")
    asyncio.run(main(sys.argv[1], sys.argv[2]))
