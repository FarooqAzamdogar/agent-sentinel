Hook events in the shape Claude Code sends them on stdin (https://code.claude.com/docs/en/hooks),
modelled on the examples in its documentation. tests/test_claude_hooks.py feeds them to
`agent-sentinel hook claude-code`, changing a field where a test needs it.
