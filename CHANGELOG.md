# Changelog

All notable changes to agent-sentinel. The newest version is first.

## 0.5.0 (2026-11-20)

The biggest release so far: commands that set up real MCP clients, Claude Code hooks, flow rules, human approval in the proxy, typed argument rules, a much wider secret guard, and support for the MCP 2026-07-28 protocol.

### New commands

- `init`: write a first policy from a template (`--template starter|strict|readonly|monitor`, `--root DIR` for strict), or draft one from a real server's tool list (`init -- <server command>`, asking about each tool on a terminal, or `--trust-annotations`). Never overwrites a file.
- `inspect`: start a server, list its tools through the real proxy, and show what would reach the agent and what a policy would do with each tool. Calls no tool.
- `clients`: list the MCP client configurations on this machine and in this folder, and how many servers are protected.
- `wrap` and `unwrap`: put the proxy in front of every server of Claude Desktop (also the Microsoft Store app), Claude Code (`.mcp.json`), Cursor, VS Code and Windsurf, or take it out again. Shows a diff; `--apply` writes it after a backup, changing only the wrapped entries. Prints a ready entry for Codex, Cline, Antigravity, Claude Code's user scope and any other client.
- `doctor`: a read-only check that every server is protected and would start, that policies load, and that logs and pins can be written.
- `hook claude-code` and `hook install claude-code`: enforce the policy inside Claude Code through its hooks.
- `pins list|show|diff|accept|forget`: look at what a proxy has pinned, see what changed in a definition it removed, and accept or forget it (on a terminal only).
- `check`: try one call against a policy and see which rule decides, what the agent would be told, and how to allow it (`--marks`, `--show-rules`, `--result`, `--proxy`).
- `test`: run a policy's test cases from a JSON file, for CI.
- `explain`: say why calls were blocked, by the reference the agent was shown (`--ref 7f3a9c21`) or the last few, with a hint for each.
- `suggest`: draft exact-name rules from a monitor-mode log, as a diff. Never loosens a block that has a reason.
- `demo`: the library and the proxy at work, in a temporary folder.
- `report` gained filters (`--tool`, `--server`, `--action`, `--event`, `--since`, `--until`), `--by server`, `--show-args`, the top reasons for blocks with how to fix each, `--format json` and `--follow`.
- `scan` takes several files, `--policy` or `--fail-on` for the threshold, `--as description|instructions` for the stricter rules, and `--format json`.
- `validate` prints flow rules, labels, secret settings and hidden tools, and its errors name the file, line and column, show a caret, and suggest the word you probably meant.
- A home folder for one user's files: `~/.agent-sentinel` (`%USERPROFILE%\.agent-sentinel` on Windows), or `AGENT_SENTINEL_HOME`.

### Proxy and protocol

- MCP 2026-07-28: `server/discover`, `resultType`, `input_required` results (each request inside must pass `server_requests`), `subscriptions/listen`, and retried requests with `inputResponses`. Known revisions: 2024-11-05 to 2025-11-25 and 2026-07-28. An unknown version is downgraded, answered with -32022, or refused.
- Human approval: `--approve-with dialog|elicitation|command:PROGRAM` and `--approval-timeout`. "Ask" calls are held, asked about one at a time, and forwarded only after a yes.
- A report for the operator on stderr: a startup summary, one line per block with its rule and reference, `--quiet` and `--verbose`, and a line budget so a flood cannot fill the log.
- `--name NAME` labels the proxy's lines and audit records.
- The server's environment: `--clean-env`, `--pass-env NAME`, `--env-file FILE`, and a warning about variables whose names look like secrets.
- Pins version 2: prompts, resource templates and the server's instructions are pinned too, and tools also by their icons and `execution`. A changed definition is kept in `<pins>.pending` for `pins diff`.
- Icons are cleaned: only public https addresses and PNG, JPEG or WebP data are kept.
- Tool and prompt names: `--tool-names strict|warn|off` for MCP's naming rules; names that look like another tool's name (`read_fіle` with a Cyrillic letter) and names listed twice with different definitions are removed.
- `hide_blocked_tools`: tools the policy blocks outright are left out of the tool list.
- Elicitation checks: a URL must be a public https address (`--elicitation-host` for a list), and a form may not ask for a password, key or card number.
- `client_requests` gates the client's other requests; `prompts/get` can be checked like a tool call; `completion/complete` passes the secret guard.
- What the proxy forwards is cleaned of terminal escape codes, control characters, Unicode tag characters and bidi controls.
- The client's answers to server requests are rebuilt and pass the secret guard.
- Capabilities are minimised: the server's copy of the client's capabilities loses sampling, elicitation and roots when `server_requests` blocks them.
- Tasks are refused everywhere.
- The protocol coverage table (`mcp_protocol.COVERAGE`, in the README) says what happens to every MCP message.

### Detection and secrets

- A stricter detection profile for tool descriptions, list entries and server instructions: `parameter_smuggling`, `tool_shadowing`, `sensitive_file_read`, `conversation_parameter`, `authority_tag`, `hidden_comment`, `preference_manipulation`, `command_rewrite`, `terminal_escape`, `foreign_tool_reference`, `call_ordering`, and a wider `hide_from_user`.
- `ascii_smuggling`: text hidden in Unicode tag characters is read and blocked.
- Reference-style Markdown images that carry data are caught like inline ones.
- Base64 and hex runs are decoded once (within limits) and read by the detector and the secret guard.
- The secret guard knows many more formats: GitLab, Slack webhooks, Google OAuth, Stripe restricted keys, OpenAI project keys, OpenRouter, Groq, xAI, Perplexity, Hugging Face, npm, PyPI, SendGrid, DigitalOcean, Shopify, Databricks, Docker Hub, Vault, Postman, Linear, age, Azure storage keys, and JWTs (redacted only).
- Secrets split over two arguments are found.
- `secrets.known_values_from_env`, `secrets.canaries` and `secrets.patterns` (your own formats).
- `secrets.in_results`: `redact` replaces secrets in what tools return; `block` withholds such a result. New `Firewall.check_result`.
- A corpus of 650 real tool descriptions (none may be high) and 43 published attacks, with the misses and why.

### Policy

- Typed argument matchers: `contains`, `one_of`, `starts_with`, `ends_with`, `no_options`, and `"type": "path"` (roots), `"type": "url"` (hosts, schemes) and `"type": "email"` (domains).
- Flow rules: `labels` on tool rules, a `flows` section, and `classify_by_annotations` (MCP annotations add labels).
- Rule ids and references: every block names the rule that decided (in the log and for the operator), and the agent's text ends with `(ref xxxxxxxx)`.
- Friendlier errors: did-you-mean, synonyms (`deny` for `block`), the line and column of a JSON mistake, and the doubled-backslash hint.
- New keys: `hide_blocked_tools`, `client_requests`, `flows`, `classify_by_annotations`, `labels`, and `secrets.in_results`, `known_values_from_env`, `canaries`, `patterns`.

### Integrations

- Claude Code hooks: PreToolUse, PostToolUse, PostToolUseFailure and SessionStart, with flow marks and rate limits kept per session in files, Claude Code's own prompt for "ask", and fail-closed answers.
- `guard()`: a decorator that puts the firewall around a tool function.
- `claude_sdk_hooks()`: callbacks for apps built on the Claude Agent SDK for Python.
- Recipes: `examples/claude_agent_sdk_hooks.py` and `examples/langchain_guarded_tools.py`.
- Audit records gain `server`, `session`, `call_id`, `rule`, `matched_arg`, `ref`, `approval` and `redacted`; new actions `ask` and `note`; new events such as `approval`, `prompt_changed`, `instructions_changed` and `tool_hidden`.

### Behaviour changes that may need action

- **The agent's refusal text changed.** Every refusal ends with `(ref xxxxxxxx)`. A refused argument reads `argument 'path' has a value the policy does not permit`, and a call to a tool the agent can never call reads `this call is not permitted by the policy`. If your code or tests compare these texts, update them.
- **`policy.example.json` changed.** It now hides blocked tools, has labels and a flow rule, checks e-mail addresses with `"type": "email"`, redacts secrets in results, and has a canary and a custom format. A policy copied from it behaves differently.
- **`initialize` must name a protocol version.** One without `params.protocolVersion` is refused; an unknown version is replaced with 2025-11-25.
- **`prompts/get`** with no valid name is refused, and a prompt removed from the list cannot be fetched. Prompts and templates without a name are removed from their lists.
- **Pins files are upgraded to version 2** the first time each tool is listed. 0.4 files are still read. Prompts, templates and instructions are pinned from now on. The quarantine message now points to `pins diff`.
- **Proxy options must be written in full.** `--mon` or `--polic` now stop the proxy. `doctor` reports such an entry as broken.
- **Names the client could not ask for are removed**: a tool, prompt, template or resource whose name or URI holds control, escape, tag or bidi characters.
- **`--max-message-bytes`** must be a whole number of at most 1 GiB.
- **stderr is rate-limited**: the proxy prints at most 20 lines in 10 seconds, and relays at most 60 lines a minute of the server's stderr.
- **Library:** `Decision` has new fields (`rule`, `matched_arg`, `ref`, `call_id`, `pending`, `redacted`, `approval`, `would_block`), added at the end. The public text of an allowed decision is `"allowed"`. A `Policy` built in code is validated like a file. `Policy.from_file` refuses NaN, Infinity and huge numbers. `ToolPins.save()` raises `OSError` instead of hiding it.
- **`examples/demo.py`** writes its audit log to a temporary folder.

### Fixes

- Zero-width characters used in place of spaces no longer hide a phrase from the detector.
- An attacker-written U+241E character can no longer split a sentence.
- Percent-decoding no longer slows down on hostile input: a megabyte of crafted text took 5 to 14 seconds.
- The audit log is always valid JSON: NaN and Infinity in arguments are replaced by a note.
- A secret split over several arguments is no longer written to the log in pieces.
- The Windows file lock no longer fails when many processes write the audit log at once.
- Every refusal the proxy makes is audited and carries a reference, including "too many requests are waiting" and internal errors.
- Server instructions that are not text are removed.
- The "cannot write audit log" line names the server and is safe to print.

## 0.4.1 (2026-11-18)

Fixes from a line-by-line review of 0.4.0.

- Secrets: values are redacted before the audit record is written; the guard reads percent-decoded text and the tool name, finds tokens glued to other text, and runs before the policy so its answer reveals nothing.
- Detector: one scan budget for all views of a value; more disguises are undone (control characters and blank fillers between words, abbreviations, zero-padded references, long tags, escaped slashes); field names are not read as a sentence.
- Policy: case look-alike letters no longer pass an allow pattern; a wildcard in an argument name is an error; a catch-all allow rule is warned about.
- Firewall: `scan_result` reads any value a tool returns; errors raised by tools are scanned with their causes; the audit log is written under a file lock.
- Proxy: list replies are scanned as a whole after filtering; pins cover only what the model reads, and `--no-pins` switches them off; one short shutdown deadline; the server command is not taken from a relative PATH entry, and a batch launcher is not given arguments `cmd.exe` would change.
- A new website design.

## 0.4.0 (2026-11-18)

Fixes from a multi-angle security review, and new defences.

- New: the secret guard (calls carrying a private key or API token are blocked, and secrets are redacted from the audit log), tool pinning (a tool whose definition changes is quarantined), policy-wide deny rules, optional and closed argument lists, rate limits, `server_requests`, monitor mode, `run_async`, and the project website.
- Proxy: replies are rebuilt from their checked result or error; malformed list replies are refused; client replies must answer a request the server made; oversized messages are dropped; the server's stderr is escaped and labelled.
- Policy: the strictest wildcard rule wins; duplicate keys and rules without an action are errors; deny rules see percent-decoded spellings.
- Firewall: only an exact `True` from the approver approves; results that cannot be read are refused; tool errors are scanned; the agent is no longer told which rule refused a call.

## 0.3.0 (2026-11-13)

Hardening after a security review, and a structure for contributors.

- The scanner no longer stalls on hostile input.
- The proxy scans every server message: instructions, server requests, notifications and all replies; unmatched replies are dropped.
- Resource reads are checked by the policy as `resources/read`.
- `allow_args` match the whole value; `deny_args` look inside nested values and take `"arg": "*"`.
- Policy loading is strict, untrusted text is made safe before printing, and block reasons no longer reveal policy patterns.
- CONTRIBUTING.md and SECURITY.md.

## 0.2.0 (2026-11-13)

The first version: a permission policy for tool calls, a prompt-injection scanner for tool results and descriptions, and an audit log. It works as a Python library or as a proxy in front of a stdio MCP server.
