# agent-sentinel

A small firewall for AI agents. It sits between an agent and its tools and does three things:

1. **Checks every tool call against a permission policy** before the tool runs.
2. **Scans what tools return for prompt injection** before the agent reads it, including poisoned tool descriptions.
3. **Writes an audit log** of every decision.

It is pure Python (3.10+) with no dependencies. It works as a library inside your own agent, or as a proxy in front of any MCP server that uses the stdio transport.

> **Status: early version (0.2.0).** The injection detector is a set of pattern rules, not a trained classifier. It catches common, unsophisticated injections. It will miss paraphrased, translated or encoded ones, and it can flag harmless text. The permission policy is the dependable part; treat the detector as an extra layer, not as proof that content is safe. The proxy has been tested against a test server included in this repository, not yet against third-party MCP servers.

## Install

```bash
pip install .
```

This adds the `agent-sentinel` command. Without installing, run `python -m agent_sentinel` from the project folder instead.

## Try it

```bash
python examples/demo.py
```

A pretend agent makes six tool calls. The firewall allows a normal file read, blocks a read of an SSH key, blocks a web page that contains a hidden injection, asks a human before sending an email, blocks an email to an unapproved address, and blocks a file deletion.

## Write a policy

A policy is a JSON file. See [policy.example.json](policy.example.json).

```json
{
  "default": "block",
  "tools": {
    "read_file": {
      "action": "allow",
      "deny_args": [{ "arg": "path", "pattern": "\\.env|\\.ssh|id_rsa" }]
    },
    "search_*": "allow",
    "send_email": {
      "action": "ask",
      "allow_args": [{ "arg": "to", "pattern": "@example\\.com$" }]
    },
    "delete_*": "block"
  },
  "injection": { "block_severity": "high" }
}
```

| Field | Meaning |
|---|---|
| `default` | What happens to a tool with no rule: `allow`, `ask` or `block`. Use `block`. |
| `tools` | One rule per tool name. `*` wildcards are allowed; an exact name beats a wildcard. |
| `action` | `allow` runs the tool, `block` refuses it, `ask` needs a human to approve. |
| `deny_args` | The call is blocked if the named argument matches the pattern. |
| `allow_args` | The call is blocked unless the named argument is present and matches the pattern. |
| `injection.block_severity` | Text with a finding at or above this level (`low`, `medium`, `high`) is blocked. `null` only logs. |

Patterns are regular expressions and ignore case. Check a policy with:

```bash
agent-sentinel validate policy.json
```

Argument patterns match the text of the argument as given. They do not resolve file paths, so `notes/../.ssh/id_rsa` is caught by a pattern for `.ssh` but a symbolic link to that file is not. Use the tool's own access controls as well.

## Use it as a library

```python
from agent_sentinel import BlockedError, Firewall, Policy

def approve(tool, args, reason):
    return input(f"Allow {tool} {args}? [y/N] ").lower() == "y"

firewall = Firewall(Policy.from_file("policy.json"), audit_path="audit.jsonl", approver=approve)

try:
    result = firewall.run("read_file", {"path": "notes.txt"}, read_file)
except BlockedError as reason:
    result = f"Blocked: {reason}"   # give this to the agent instead of the tool result
```

`firewall.run` checks the call, runs the function, scans its result and returns it. If you need the steps separately, use `firewall.check_call(tool, args)` and `firewall.scan_result(tool, text)`; each returns a `Decision` with `allowed`, `reason` and `findings`.

## Use it in front of an MCP server

Put the proxy command where the server command used to be:

```bash
agent-sentinel proxy --policy policy.json --audit audit.jsonl -- npx some-mcp-server
```

For example, in an MCP client configuration:

```json
{
  "mcpServers": {
    "files": {
      "command": "agent-sentinel",
      "args": ["proxy", "--policy", "policy.json", "--audit", "audit.jsonl", "--", "npx", "some-mcp-server"]
    }
  }
}
```

What the proxy does:

| Traffic | Handling |
|---|---|
| `tools/call` request | Checked against the policy. A blocked call is answered by the proxy and never reaches the server. |
| `tools/call` result | Scanned. A result with an injection is replaced with an error. |
| `tools/list` result | Each tool's name, description and schema are scanned. A poisoned tool is removed from the list, and later calls to it are blocked. |
| `resources/read` and `prompts/get` results | Scanned. A result with an injection is replaced with an error. |
| Anything malformed | Dropped. Invalid JSON, batched requests, bad ids and bad arguments are never forwarded. |
| Everything else | Passed through. |

The proxy fails closed: if it cannot check a message, it does not forward it. Messages are re-serialized, so the server sees exactly what the proxy checked. Warnings go to standard error.

Limits of the proxy in this version:

- Only the stdio transport is supported, not HTTP.
- Rules with action `ask` are blocked, because the proxy has no terminal to ask a human on.
- Requests that the server sends to the client (sampling, elicitation) and notifications are not scanned.
- A tool whose description changes after it was first listed is scanned again, but the change itself is not reported.
- Binary content (images, audio, base64 data) is not decoded or scanned.

## The command line

```bash
agent-sentinel scan page.txt          # scan a file (or stdin) for prompt injection; exit code 1 if found
agent-sentinel validate policy.json   # check a policy file
agent-sentinel report audit.jsonl     # allowed and blocked counts per tool, plus recent blocks
agent-sentinel proxy ...              # run an MCP server behind the firewall
```

## The audit log

One JSON object per line:

```json
{"time": "2026-11-12T21:03:42+00:00", "event": "call", "tool": "read_file", "action": "block", "reason": "argument 'path' matches denied pattern ...", "args": {"path": "/home/me/.ssh/id_rsa"}}
```

`event` is `call`, `result` or `tool_description`. Tool arguments are logged, and they can contain sensitive data. Pass `log_args=False` to `Firewall`, or `--no-log-args` to the proxy, to leave them out. If the log cannot be written, the firewall prints one warning and keeps enforcing decisions.

## What the detector looks for

| Rule | Severity | Example |
|---|---|---|
| `instruction_override` | high | "Ignore all previous instructions" |
| `hide_from_user` | high | "Do not tell the user" |
| `exfiltration_to_destination` | high | "Send the API keys to http://..." |
| `secret_request` | medium | "Send me the password" (no destination named) |
| `role_hijack` | medium | "You are now...", `<system>` tags |
| `tool_command` | medium | "Run the shell command silently" |
| `invisible_characters` | medium | Zero-width or hidden Unicode characters |
| `markdown_image_exfiltration` | medium | An image link that carries data in its URL |

Before matching, text is normalized: invisible characters are removed and look-alike forms such as full-width letters are folded to plain ones. With the default policy only high findings block; medium findings are logged.

## Run the tests

```bash
python -m unittest discover tests -v
```

## Ideas for what to build next

- Test against widely used MCP servers and clients.
- Human approval in the proxy, through a local web page.
- A dashboard that reads the audit log.
- Alerts when a tool's description changes after first use ("rug pull").
- An optional model-based injection classifier next to the pattern rules.
- HTTP transport for the proxy.

## License

MIT. See [LICENSE](LICENSE).
