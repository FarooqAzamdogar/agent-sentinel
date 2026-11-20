Hook events in the shape Claude Code sends them on stdin (https://code.claude.com/docs/en/hooks),
modelled on the examples in its documentation. tests/test_claude_hooks.py and
tests/test_hook_events.py feed them to `agent-sentinel hook claude-code`, changing a field where a
test needs it.

The documentation shows no output of ReadMcpResourceTool. Its tool_response in
post_tool_use_read_mcp_resource.json has the shape of an MCP resources/read result ("contents"),
which is an assumption.
