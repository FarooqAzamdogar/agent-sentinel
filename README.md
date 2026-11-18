# agent-sentinel

A security sentinel for AI agents and MCP servers. It sits between an agent and its tools and does four things:

1. **Checks every tool call against a permission policy** before the tool runs.
2. **Scans everything a tool server sends for prompt injection** before the agent reads it, including poisoned tool descriptions.
3. **Stops secrets leaving** in tool-call arguments.
4. **Writes an audit log** of every tool call and everything it blocks.

It is pure Python (3.10+) with no dependencies. It works as a library inside your own agent, or as a proxy in front of any MCP server that uses the stdio transport.

Website: https://farooqazamdogar.github.io/agent-sentinel/

> **Status: early version (0.4.1).** The injection detector is a set of pattern rules, not a trained classifier. It catches common, direct injections and undoes several cheap disguises. It will miss reworded, translated or base64-encoded ones, and it can flag harmless text. The permission policy is the dependable part; treat the detector as an extra layer, not as proof that content is safe. The proxy has been tested against a test server included in this repository, not yet against third-party MCP servers. See [SECURITY.md](SECURITY.md) for what is and is not covered.

## Install

```bash
pip install git+https://github.com/FarooqAzamdogar/agent-sentinel.git
```

This adds the `agent-sentinel` command. From a clone of the repository, `pip install .` does the same, and `python -m agent_sentinel` works without installing.

## Try it

```bash
git clone https://github.com/FarooqAzamdogar/agent-sentinel.git
cd agent-sentinel
python examples/demo.py
```

A pretend agent makes six tool calls. The firewall allows a normal file read, blocks a read of an SSH key, blocks a web page that contains a hidden injection, asks a human before sending an email, blocks an email to an unapproved address, and blocks a file deletion.

## Write a policy

A policy is a JSON file. See [policy.example.json](policy.example.json) for a complete one.

```json
{
  "default": "block",
  "deny_args": [{ "arg": "*", "pattern": "(^|[\\\\/:])\\.(ssh|aws|env)\\b|id_rsa" }],
  "tools": {
    "read_file": "allow",
    "search_*": "allow",
    "send_email": {
      "action": "ask",
      "allow_args": [
        { "arg": "to", "pattern": "[^@\\s,;]+@example\\.com" },
        { "arg": "cc", "pattern": "[^@\\s,;]+@example\\.com", "optional": true },
        { "arg": "body", "pattern": "(?s).*", "optional": true }
      ],
      "other_args": "block",
      "max_calls_per_minute": 5
    },
    "delete_*": "block",
    "resources/read": "allow"
  },
  "server_requests": { "sampling/createMessage": "block", "*": "allow" },
  "injection": { "block_severity": "high" },
  "secrets": { "in_arguments": "block" },
  "limits": { "max_calls_per_minute": 120 }
}
```

| Field | Meaning |
|---|---|
| `default` | What happens to a tool with no rule: `allow`, `ask` or `block`. Defaults to `block`; keep it that way. |
| `deny_args` (top level) | Deny rules for every call, whichever tool it is for, including tools with no rule. |
| `tools` | One rule per tool name. `*` is a wildcard. A rule is either an action (`"allow"`) or an object with an `action` and the fields below. |
| `action` | `allow` runs the tool, `block` refuses it, `ask` needs a human to approve. Required in the object form. |
| `deny_args` (in a rule) | The call is blocked if the pattern is found **anywhere in** the named argument, including inside nested lists and objects. `"arg": "*"` checks every argument. |
| `allow_args` | The call is blocked unless the named argument is present and the pattern matches its **whole value**. With `"optional": true` the argument may be absent. |
| `other_args` | `"block"` refuses any top-level argument that no `allow_args` entry names. Default `"allow"`. |
| `max_calls_per_minute` | A rate limit for the tools this rule matches. |
| `server_requests` | Which requests the MCP server may send to the client (`allow` or `block`), by method name. Everything is allowed, and scanned, if this is left out. |
| `injection.block_severity` | Text with a finding at or above this level (`low`, `medium`, `high`) is blocked. `null` only logs. |
| `secrets.in_arguments` | `block` (the default) refuses a call whose arguments contain a recognisable secret. `allow` turns that off. |
| `limits.max_calls_per_minute` | A rate limit for all tool calls together. |

Things to know when writing rules:

- **Patterns** are regular expressions and ignore case.
- **Deny is "contains", allow is "whole value".** An allow pattern of `[^@\s,;]+@example\.com` accepts `boss@example.com` and refuses `attacker@evil.example, boss@example.com`. For a list, every entry must match; objects and empty lists are refused.
- **Deny rules also see percent-decoded spellings**, so `%2Essh` does not get round a rule for `.ssh`. A value that is still percent-encoded after three rounds of decoding is denied.
- **Allow rules match the value as written.** They do not decode it, so an allow pattern that lists `%` on purpose keeps working. If your tool percent-decodes its arguments, leave `%` out of the pattern. Letters that only look like a match under case-insensitive rules (such as dotless `ı` for `i`) are refused.
- **Argument names are exact.** Only tool names take `*`; in `deny_args`, `"arg": "*"` alone means every argument.
- **When several wildcard rules match a tool, the strictest wins** (block over ask over allow). A rule with the exact tool name beats all wildcards. Use `default` for the fallback, not a `"*"` rule.
- **Loading is strict.** An unknown key, a duplicate key, a rule without an `action` or a wrong type is an error, so a typo cannot silently weaken a policy. Check a policy with `agent-sentinel validate policy.json`; it also prints warnings.
- **MCP resource reads and subscriptions** are checked under the tool name `resources/read`, with one argument, `uri`. With `"default": "block"` they need a rule to be allowed.
- **Patterns match text, not files.** A deny pattern for `.ssh` catches `notes/../.ssh/id_rsa` but not a symbolic link to that file. Use the tool's own access controls as well.

## Use it as a library

```python
from agent_sentinel import BlockedError, Firewall, Policy, printable

def approve(tool, args, reason):
    # tool and args are chosen by the agent: make them safe to display, and show
    # every argument in full, or a long harmless one can push "bcc" out of sight.
    print(f"The agent wants to call {printable(tool)}:")
    for name, value in args.items():
        print(f"  {printable(name, limit=80)} = {printable(value, limit=4000)}")
    return input("Allow? [y/N] ").strip().lower() == "y"      # must return exactly True to approve

firewall = Firewall(Policy.from_file("policy.json"), audit_path="audit.jsonl", approver=approve)

try:
    result = firewall.run("read_file", {"path": "notes.txt"}, read_file)
except BlockedError as error:
    result = f"Blocked: {error}"   # safe to give to the agent in place of the tool result
```

`firewall.run` checks the call, runs the function, scans its result and returns it. For an `async def` tool use `await firewall.run_async(...)`.

- **What is scanned:** strings, bytes, and anything made of lists, tuples, sets, dictionaries and dataclasses. A result of any other kind (a generator, a response object) is refused, because it cannot be read without using it up; convert it to text first. An error message raised by the tool is scanned too.
- **What the agent is told:** `str(error)` never names the rule or pattern that refused the call. The full reason is in `error.decision.reason` and in the audit log.
- **Doing the steps yourself:** `firewall.check_call(tool, args)` and `firewall.scan_result(tool, result)` each return a `Decision` with `allowed`, `reason`, `public_reason` and `findings`. A blocked `Decision` is falsy. `scan_result` takes whatever the tool returned: text, bytes, or a structure of lists and dictionaries.
- **Trying a policy safely:** `Firewall(..., monitor=True)` blocks nothing and logs what it would have blocked.

## Use it in front of an MCP server

Put the proxy command where the server command used to be:

```bash
agent-sentinel proxy --policy policy.json --audit audit.jsonl --pins pins.json -- npx some-mcp-server
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

| Option | Meaning |
|---|---|
| `--policy FILE` | The policy. Required. |
| `--audit FILE` | Where to write the audit log. |
| `--pins FILE` | Remember each tool's definition in this file, so a change is caught across restarts. Use one file per server. |
| `--no-pins` | Do not quarantine a tool whose definition changes. For servers that change their tools often. |
| `--monitor` | Log what the policy and the scanner would block, but block nothing. For tuning a policy; it protects nothing. |
| `--no-log-args` | Leave tool arguments out of the audit log. |
| `--max-message-bytes N` | Drop any message larger than this. Default 16 MiB. |

What the proxy does:

| Traffic | Handling |
|---|---|
| `tools/call` request | Checked against the policy, the secret guard and the rate limits. A blocked call is answered by the proxy and never reaches the server. |
| `resources/read`, `resources/subscribe` requests | Checked against the policy, under the name `resources/read`. |
| Every reply from the server | Scanned, then rebuilt from the checked parts, so nothing else in the message rides along. A reply with an injection is replaced with an error. |
| `tools/list` reply | Each tool's name, description and schema are scanned. A poisoned tool is removed from the list and calls to it are refused from then on. |
| A tool that changes | A tool whose name, description, schema or annotations differ from the first time it was listed is removed and quarantined (a "rug pull"). This is on even without `--pins`, for as long as the proxy runs. |
| `prompts/list`, `resources/list` replies | Scanned entry by entry; poisoned entries are removed. |
| `initialize` reply | The server's `instructions` are scanned and removed if they look like an injection. |
| Requests and notifications from the server | Refused if the policy's `server_requests` says so; otherwise scanned. |
| The server's error output (stderr) | Printed with control codes escaped and a `server stderr:` label, so it cannot pass for a message from the proxy. |
| A reply that matches no request | Dropped. |
| Anything malformed or oversized | Dropped. Invalid JSON, batched requests, bad ids and bad arguments are never forwarded. |

The proxy fails closed: if it cannot check a message, it does not forward it. Messages are re-serialized, so each side receives exactly what the proxy checked. Warnings go to standard error.

Limits of the proxy in this version:

- Only the stdio transport is supported, not HTTP.
- Rules with action `ask` are blocked, because the proxy has no way to reach a human yet.
- Binary content (images, audio, base64 data) is not decoded or scanned.
- The server command is looked up on `PATH` only, never in the current folder or through a relative `PATH` entry. To run a local file, write its path, such as `./server`.
- On Windows, a server started through a `.cmd` or `.bat` launcher (such as `npx`) cannot be given an argument that contains `&`, `%`, `^`, `|`, `<`, `>`, `!` or a quote: `cmd.exe` would change it, so the proxy refuses to start. Start the program behind the launcher directly instead.
- A quarantined tool stays quarantined until the proxy is restarted. To accept a legitimate update to a pinned tool: stop the proxy, delete the tool's entry from the pins file (or the file), and start it again.
- The server gets about a second and a half to exit after the client disconnects, then it is stopped.

## The command line

```bash
agent-sentinel scan page.txt          # scan a file (or stdin) for prompt injection; exit code 1 if found
agent-sentinel validate policy.json   # check a policy file and print warnings
agent-sentinel report audit.jsonl     # allowed and blocked counts per tool, plus recent blocks
agent-sentinel proxy ...              # run an MCP server behind the firewall
```

## The audit log

One JSON object per line:

```json
{"time": "2026-11-17T22:04:04+00:00", "event": "call", "tool": "read_file", "action": "block", "reason": "an argument has a value the policy denies", "args": {"path": "/home/me/.ssh/id_rsa"}}
```

- **`event`** is `call` for a tool call or resource request. Content checks use `result`, `tool_error`, `tool_description`, `tool_changed`, `list_item`, `server_instructions` or `server_request`. `dropped` records a message that was discarded for its shape.
- **`action`** is `allow`, `block`, or `would_block` in monitor mode.
- **`tool`** is the tool name on a call record (`resources/read` for a resource request). On content checks it is the tool name, the resource URI, a method name such as `initialize`, or `server:<method>` for something the server sent.
- **What is not logged:** list entries and server notifications that pass their check. Tool calls, replies to them, and everything that is blocked or dropped are always logged.
- **Secrets are redacted.** Recognisable keys and tokens are replaced with a marker such as `[redacted GitHub token]`. Other argument values are logged as they are; pass `log_args=False` to `Firewall`, or `--no-log-args` to the proxy, to leave arguments out. Arguments over 100,000 characters are not logged.
- **Several writers are safe.** Two proxies may share one log file; each record is written under a file lock.
- **Control characters are escaped**, so a hostile tool name cannot rewrite your terminal or split a record when you read the file.
- If the log cannot be written, the firewall prints one warning and keeps enforcing decisions.

## The secret guard

A hijacked agent that has read a key will try to pass it to a tool. Calls whose tool name or arguments contain one of these are refused: a PEM private key, an AWS access key, a GitHub, Slack or Stripe token, a Google API key, or an OpenAI- or Anthropic-style API key. Percent-encoded text is decoded first. Only formats with a fixed, recognisable shape are listed, so ordinary identifiers, hashes and product names that start with `sk-` are not flagged. It is not a general secret scanner: a password, a key in a format it does not know, a key split over two arguments or a base64-encoded key passes. It applies to tool calls and resource requests, not to the client's answers to requests from the server.

## What the detector looks for

| Rule | Severity | Example |
|---|---|---|
| `instruction_override` | high | "Ignore all previous instructions" |
| `hide_from_user` | high | "Do not tell the user" |
| `exfiltration_to_destination` | high | "Send the API keys to http://..." |
| `unscannable_content` | high | Text built to make scanning very slow; refused instead of scanned |
| `instruction_override_weak` | medium | "Ignore all the rules" (too common in ordinary text to block) |
| `secret_request` | medium | "Send me the password" (no destination named) |
| `role_hijack` | medium | "You are now...", `<system>` tags |
| `tool_command` | medium | "Run the shell command silently" |
| `invisible_characters` | medium or low | Hidden Unicode characters. Low when they are only the kind that emoji and some scripts use. |
| `markdown_image_exfiltration` | medium | An image link that carries data in its URL |

Before matching, text is normalized so that cheap disguises fail: invisible characters and terminal colour codes are removed, accents and look-alike letters (full-width, Cyrillic, Greek) are folded to plain ones, and HTML entities, HTML tags inside words and percent-encoding are undone. A structured reply is read several ways, so a phrase, or a single word, split across list items or fields is still seen as one, while field names alone (`email`, `token`, `url`) are not read as a sentence. With the default policy only high findings block; medium and low findings are logged.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how the code is organized, how a message flows through it, and how to add a detector rule. To report a security problem, see [SECURITY.md](SECURITY.md).

```bash
python -m unittest discover tests -v
```

## Ideas for what to build next

- Test against widely used MCP servers and clients.
- Human approval in the proxy.
- A dashboard that reads the audit log.
- A tamper-evident audit log.
- An optional model-based injection classifier next to the pattern rules.
- HTTP transport for the proxy.

## License

MIT. See [LICENSE](LICENSE).
