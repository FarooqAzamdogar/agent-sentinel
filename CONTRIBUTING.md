# Contributing to agent-sentinel

Thanks for helping. This page explains how the code is organized, how a message flows through it, how to add the most common things, and the rules a change must keep.

## Set up

There is nothing to install. You need Python 3.10 or newer. The package uses only the standard library.

```bash
python -m unittest discover tests -v     # run all tests (about eight minutes)
python -m agent_sentinel demo            # see the library and the proxy at work
```

The code must run on Python 3.10: no `except*`, `ExceptionGroup`, `add_note`, `tomllib` or typing features newer than 3.10. CI runs the tests on Linux and Windows with Python 3.10 to 3.13. Its test and build jobs are given 45 minutes each, so that a slow hosted runner is not cancelled with every test passing.

Run the tests with `AGENT_SENTINEL_HOME` unset, or set to a folder named `.agent-sentinel` (see "The tests").

## The files

All code is in `agent_sentinel/`. The module map at the top of `agent_sentinel/__init__.py` lists the same modules; a test checks that it names every one.

### The core: what a program that runs tools uses

| File | What it does | Depends on |
|---|---|---|
| `detector.py` | Finds prompt injection in text. Two profiles: `result` and `metadata` (tool descriptions, list entries, instructions). Pure functions, no state. Also says which views of a text it matches in (`VIEW_KINDS`), for the tail scan. | textutil |
| `leaks.py` | Recognises secrets (built-in formats, custom formats, known values, canaries) in calls, results and logs, and redacts them. | textutil |
| `policy.py` | Loads a policy and answers allow / ask / block for a call, including command sections and flow rules. Holds the rule ids. | commands, detector, matchers, policy_errors, session, jsonutil, textutil |
| `matchers.py` | The ways a policy judges one argument's value: pattern, contains, one_of, starts_with, ends_with, no_options, and the path, url, email and command types. | commands, policy_errors, textutil |
| `commands.py` | Reads a Bash or PowerShell command line and sorts what it does into classes (`network`, `install`, `secret_read`, `config_write`, `obfuscation`, `encoded_host`), or says it is unreadable. | templates, textutil |
| `policy_errors.py` | Error messages that help fix a policy file (did-you-mean, line and caret, the doubled-backslash hint). Home of `PolicyError`. | textutil |
| `session.py` | What the agent has read this session (flow marks), the end of the last delivered result and the session's counts: a memory store, a locked file store (hook mode) and the store that the proxies of a session group share. | filelock, jsonutil |
| `session_limits.py` | Session budgets (`max_calls_per_session`, `max_distinct` ...), approval memory, and where a call sends data, for the approval question. | matchers, policy, session, textutil |
| `tail_scan.py` | Reads the end of the last delivered result together with the start of the next, so that an injection split over two results is seen. | detector, session, textutil |
| `filelock.py` | Operating-system file locks, replacing a file in one step, and making an owner-only folder. | nothing |
| `audit_chain.py` | The audit log's hash chain: appending a record, signing it with a key, rotating the log, and checking a log (`audit verify`). | auditlog, filelock, jsonutil, textutil |
| `firewall.py` | Combines policy, secret guard, rate limits, session budgets, approval memory, flow marks and detector, and writes the audit log. The public core: `Firewall`, `Decision`, `BlockedError`. | audit_chain, detector, leaks, policy, session, session_limits, tail_scan, textutil |
| `tool_guard.py` | `guard()`: the firewall around a tool function. | firewall |
| `textutil.py` | Collecting text from nested data (`texts_in`, `text_views`), the JSON copy of a call's arguments (`normalised_arguments`), `printable`, the forwarding cleaner, the base64/hex decoder, hidden text in invisible characters. | nothing |
| `jsonutil.py` | Strict JSON reading (no repeated keys, NaN or Infinity), used by every reader of a file or event. | policy_errors, textutil |

### The MCP proxy

| File | What it does | Depends on |
|---|---|---|
| `mcp_proxy.py` | Puts the firewall between an MCP client and server: parses, checks, rebuilds and forwards each message; the `proxy` command's options and its order at startup. | firewall, the modules below, and launch and home |
| `mcp_protocol.py` | What the proxy knows about MCP message shapes and protocol revisions; the protocol coverage table (`COVERAGE`). Pure functions. | matchers, textutil |
| `pins.py` | What the proxy remembers of tools, prompts, templates and instructions, and of the server itself (`--pin-server`): the pins file (version 2) and its `.pending` file. | filelock, jsonutil, textutil |
| `elicitation.py` | What an elicitation may ask the user (URLs, form fields). Pure functions. Also used by the Claude Code hook. | matchers, mcp_protocol, textutil |
| `server_env.py` | The environment the server is started with (`--clean-env`, `--pass-env`, `--env-file`), and which names look secret. | nothing |
| `containment.py` | Keeping the server's processes in check: `--contain` (a job object on Windows, a process group elsewhere), the limits, and the words for the `bwrap` and `sandbox-exec` sandboxes. | home |
| `schema_check.py` | A bounded JSON Schema validator for a call's arguments and a result's `structuredContent`; references that lead outside a schema; the store of checked schemas. | textutil |
| `approvers.py` | How the proxy asks a person to approve a call: dialog, command, elicitation; what the person is shown. | textutil |
| `proxy_report.py` | What the proxy tells the operator on stderr: the startup summary, one line per block, the line budget. | firewall, home, leaks, policy, textutil |
| `client_run.py` | Which run of the MCP client a proxy belongs to (the client's process and when it started), for `--session-group`. One reader per operating system. | nothing |
| `uri_template.py` | Whether a URI may come from a quarantined resource template (a bounded, broad RFC 6570 match). | policy, textutil |

### Claude Code and the Claude Agent SDK

| File | What it does | Depends on |
|---|---|---|
| `claude_hooks.py` | The answers to Claude Code's hook events (tool calls and results, elicitations, settings changes, the start of a session); `claude_sdk_hooks()` for the Agent SDK. | audit_chain, auditlog, elicitation, firewall, hook_state, home, jsonutil, mcp_protocol, policy, policy_errors, session, textutil |
| `hook_state.py` | Rate-limit counts per session, the snapshot of Claude Code's settings, and the policy file a session began with, each in a file (every hook run is a new process). Also the owner-only state folder and the pruning of old sessions' files. | filelock, firewall, jsonutil, session |

### The command line

| File | What it does |
|---|---|
| `__main__.py` | The `agent-sentinel` command: builds the parser and hands each command to its module. `proxy` goes straight to `mcp_proxy.main`. |
| `cli_<command>.py` | One module per command: `cli_init`, `cli_inspect`, `cli_clients`, `cli_wrap`, `cli_unwrap`, `cli_doctor`, `cli_hook`, `cli_pins`, `cli_check`, `cli_test`, `cli_validate`, `cli_scan`, `cli_report`, `cli_explain`, `cli_suggest`, `cli_audit`, `cli_demo`. |
| `cli_common.py` | What the commands share: exit codes, loading a policy, reading input, strict JSON, printing a command line. |
| `shortened_options.py` | The shortened options that 0.5.0 read as one option and a newer option made ambiguous (`hook claude-code --au`, `wrap --con`, `check --s`): the table and the function that registers them on a parser. |
| `auditlog.py` | Reading audit logs with bounded lines; times and filters; which records describe the log and the session and not a call (`META_EVENTS`). |
| `fix_hints.py` | How to allow a call that a rule blocked, one hint per kind of rule (explain, report, check), and which kinds `suggest` never loosens. |
| `home.py` | The agent-sentinel home folder (`~/.agent-sentinel`, or `AGENT_SENTINEL_HOME`). |
| `templates.py` | The policies of `init --template`, the baseline every drafted policy starts from, and the patterns for credential files, agent configuration and control settings. |
| `server_probe.py` | Start a server, list its tools through a real `Proxy`, stop it (inspect, init --). |
| `clients.py` | The MCP clients and where their configurations are; snippets for the others. |
| `config_file.py` | Reading a client's configuration strictly, and changing entries in it without disturbing the rest (backup, atomic write). |
| `wrapping.py` | One server entry: its kind, wrapping and unwrapping it, reading a wrapped command line. Lists every option of the proxy (`VALUE_OPTIONS`, `FLAG_OPTIONS`). |
| `launch.py` | What a server's launch command runs, behind wrappers too: its packages, what is risky about it (doctor, clients, wrap, inspect), and what a server pin records. |
| `advisories.py` | Known-bad MCP packages and well-known package names. Data only, with a date. |
| `control_plane.py` | Whether the agent or a server can reach agent-sentinel's own files (doctor's "Control plane" section; the warnings of wrap and hook install). |
| `doctor_baseline.py` | `doctor --save-baseline` and `--baseline`: what was added, changed or removed since. |
| `demo_server.py` | The deliberately poisoned server of `agent-sentinel demo`. |

Other folders: `examples/` (the library demo, the fake MCP server the tests use, and the Claude Agent SDK and LangChain recipes), `docs/` (the website, served by GitHub Pages: plain HTML, CSS and a little JavaScript, no build step), `.github/workflows/` (tests, and the release to PyPI on a version tag).

## The tests

Tests are in `tests/`, one file (or a few) per module. From the project folder, run all of them with `python -m unittest discover tests -v`, or one file with `python -m unittest discover tests -p test_policy.py`. (`python -m unittest tests.test_policy` does not work: the test modules import their helpers by name, from the `tests` folder.)

| Area | Test files |
|---|---|
| Detector and text | `test_detector.py`, `test_textutil.py`, `test_hidden_text.py` (decoders, invisible text, words broken up), `test_result_rules.py` (poisoned output, links and hosts, terminal escapes), `test_attack_corpus.py` (with `attack_corpus/`) |
| Secrets | `test_leaks.py`, `test_secret_guard.py` |
| Policy | `test_policy.py`, `test_policy_errors.py`, `test_policy_sections.py`, `test_policy_hardening.py` (argument names, paths with variables, write protection, label warnings, the templates for Claude Code), `test_matchers.py`, `test_commands.py` (the command reader), `test_rule_ids.py`, `test_flows.py` |
| Firewall | `test_firewall.py`, `test_call_arguments.py` (the JSON copy of the arguments), `test_results.py`, `test_approval.py`, `test_audit_identity.py`, `test_audit_chain.py` (the chain, rotation, keys, `audit verify`), `test_session.py`, `test_session_limits.py` (flow exceptions, session budgets, approval memory, `check --history`), `test_warnings_and_tail.py` (the notice, content marks, `server_labels`, the tail scan), `test_jsonutil.py`, `test_tool_guard.py` |
| Proxy | `test_proxy.py`, `test_proxy_hardening.py`, `test_proxy_lists.py`, `test_proxy_pins.py`, `test_proxy_client_requests.py`, `test_proxy_launch.py`, `test_proxy_approvals.py`, `test_proxy_report.py`, `test_approvers.py`, `test_proxy_gaps.py` (unseen tools, sampling, template quarantine, pages of a list, the call timeout), `test_proxy_schemas.py`, `test_schema_check.py`, `test_containment.py`, `test_session_groups.py`, `test_server_pins.py` |
| MCP protocol | `test_protocol.py`, `test_protocol_elicitation.py`, `test_protocol_coverage.py` |
| Claude Code | `test_claude_hooks.py` and `test_hook_events.py` (with events in the shape Claude Code sends them, in `claude_code_events/`), `test_hook_state.py`, `test_cli_hook.py`, `test_recipes.py` |
| Commands | `test_cli.py`, `test_cli_commands.py`, `test_cli_cases.py`, and `test_cli_<command>.py` for each command (`audit verify` is tested in `test_audit_chain.py`); `test_auditlog.py`, `test_fix_hints.py`, `test_home.py`, `test_clients.py`, `test_config_file.py`, `test_wrapping.py`, `test_launch.py` (the launch check, advisories, what a server pin holds), `test_doctor_checks.py` (doctor's launch lines, control plane, permissions, baseline), `test_shortened_options.py` (every shortening 0.5.0 took, against today's parsers) |
| Several parts together | `test_json_arguments_meet_the_rules.py`, `test_checks_meet_the_session.py`, `test_hook_session_features.py`, `test_server_pin_and_flows.py`, `test_startup_audit_and_sandbox.py`, `test_shared_marks_and_one_trail.py` |
| Everything together | `test_integration.py`, `test_second_review.py` (one test for each gap found in the 0.4.0 review), `test_end_to_end.py` (real processes, as a user runs them: the library, every command, the Claude Code hook, and the proxy in both protocol eras), and the end-to-end modules of single areas: `test_core_end_to_end.py`, `test_detection_end_to_end.py`, `test_audit_end_to_end.py` |

Shared helpers: `tests/support.py` (the example policy, a typical injection, and `audit_records(path)`, which reads an audit log without the records about the log and the session), `tests/cli_support.py` (an in-process command runner, temporary folders, and `IsolatedHomeTest`), `tests/scripted_mcp_server.py` (a server driven by a scenario, for `inspect` and `init`), `tests/e2e_mcp_server.py` (a server whose tools make it send requests, notifications and any reply, for the end-to-end tests).

- **Test names are sentences** that say the behaviour: `test_a_blocked_call_gets_a_reference`.
- **Test the failure paths**, the error messages, and at least one hostile input for every new parser.
- **Never touch real client settings.** A test (or a manual try) of `wrap`, `unwrap`, `init`, `doctor`, `clients` or `hook install` must use `IsolatedHomeTest`, or set `HOME`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `XDG_CONFIG_HOME` and `AGENT_SENTINEL_HOME` to a temporary folder. The Claude Code hook reads `~/.claude/settings.json` when a session starts, so a test that feeds it a SessionStart event needs an isolated home too.
- **`AGENT_SENTINEL_HOME` must be unset, or name a folder called `.agent-sentinel`,** when you run the tests. Not every test isolates the home folder, and the templates protect agent-sentinel's own files by that folder name: with a home folder of another name, the tests that check this fail.
- **Read an audit log with `support.audit_records`.** Every new log starts with a `chain_start` record, and the proxy adds `session_start`, `protocol` and `session_end`. A test that takes the first line for the first call, or counts lines, breaks on them.
- **List the tools before you call one** in a proxy test with flow rules. A tool that no checked `tools/list` has shown counts as untrusted and a sink, and the flow rule refuses the call instead of what you meant to test.
- **Timing tests and a busy machine.** About thirty test modules check that hostile input stays fast, with `assertLess(seconds, limit)`. On an idle machine no check uses more than about 40% of its limit. A second test run on the same machine at the same time makes the scans three to four times slower, and then the 5-second checks with an idle time above about 1.2 seconds can fail: the hostile-input classes of `test_hidden_text.py`, `test_result_rules.py`, `test_detector.py` and `test_proxy_gaps.py`. Run the suite alone before you read such a failure as a regression, and do not raise a limit to make a loaded run pass.
- **Tests for another system skip themselves.** The tests of POSIX file modes, the Linux sandbox and the Windows job object run only where they can. On Windows 20 tests are skipped; they run in CI. Nothing runs on macOS, so the code for it (the `sandbox-exec` profile, the `ps` reader of `client_run.py`) is tested as text or with a stand-in: say so in SECURITY.md when you add to it.
- **Tests that use pydantic** must skip when it is not installed. The package itself never imports it.
- **The attack corpus.** `tests/attack_corpus/benign_tool_metadata.json` holds 650 real tool descriptions: none may be high, read as metadata and as tool output with the parameter names of real tools. `tests/attack_corpus/published/` holds one file per published attack (87 of them), written by `make_published.py` (run it after editing; a test checks the files are what it writes).

## How a tool call flows (library use)

```
firewall.run(tool, args, fn)
  │
  ├─ check_call
  │    ├─ the JSON copy of the arguments: everything below reads it; what cannot be made JSON is refused
  │    ├─ secret guard: do the tool name or arguments (numbers too) hold a key, a known value or a canary?
  │    ├─ policy.evaluate ──► allow / ask / block       (deny_args, the tool rule, its command section,
  │    │                                                 its argument entries)
  │    ├─ flow rules: does the session hold every 'after' mark of a flow that applies to this tool, or
  │    │              to what its command does? Does the call fail the flow's unless_args?
  │    ├─ approval memory: did a person refuse this very call a short while ago?
  │    ├─ rate limits, then the session budgets
  │    └─ ask ──► approver(tool, args, reason), which must return exactly True
  │              (with defer_ask=True: a pending Decision, finished later by finish_approval)
  │
  ├─ fn(**args)                 the tool gets its own objects, not the copy;
  │                             an error it raises is scanned before it is re-raised
  │
  ├─ check_result ──► secrets.in_results: redact or block
  │               └─► detector.scan_views(text_views(result)) ──► findings
  │                   tail_scan.read_with_tail: the end of the last delivered result + the start of this one
  │                   a finding at or above injection.block_severity ──► BlockedError
  │                   a finding at or above injection.warn_severity  ──► Decision.notice
  │
  └─ mark_delivered ──► the session gains the tool's labels, the labels its command gives the call, and
                        injection.mark for flagged content; the end of the result is kept for the next one
                        (last step, only if returned)
```

Every decision writes one line to the audit log, through `Firewall._write_record`, which links it into the hash chain (`audit_chain.append_chained`). A `Decision` has two texts: `reason` for the log and the operator, and `public_reason` for the agent. A block also has a `rule` id and a `ref`, and `public_reason` ends with `(ref xxxxxxxx)`.

## How a message flows (MCP proxy)

```
client ──► handle_client_line ──► _inspect_client_message ──► _Outcome ──► server
client ◄── handle_server_line ◄── _inspect_server_message ◄── _Outcome ◄── server
```

- `handle_*_line` parses one line and sends whatever the `_Outcome` says.
- `_inspect_*` methods make the decision and return an `_Outcome`. They never write to a stream, which is what makes them easy to test.
- `mcp_protocol.COVERAGE` describes what happens to every MCP message, and `tests/test_protocol_coverage.py` fails when the proxy's code names a method that has no row there. The README shows the same table, copied by hand: change both.

Client side, in order:

1. Refuse batches, non-objects and invalid ids.
2. A message with no method must be the answer to a request the server made; otherwise it is dropped. The answer to one of the proxy's own approval questions is taken first and never forwarded. Other answers are rebuilt and pass the secret guard.
3. Check the protocol revision: `initialize` (version, capabilities minimised for the server's copy), a version in `_meta` (unknown: -32022), `inputResponses` of a retried request (shape, then the secret guard). `tasks/*` are refused.
4. `completion/complete` passes the secret guard; then `client_requests` may refuse the method. A server that `--pin-server` quarantined is sent only the handshake, `ping`, the list requests and `logging/setLevel`.
5. `tools/call`: validate the shape, wait for any tool list still being checked, refuse reserved names, quarantined tools and every tool of a quarantined server, check the arguments against the tool's schema when `schema_checks` says so, then `firewall.check_call`. `resources/read` and `resources/subscribe` are refused when a quarantined template may produce the URI, then checked as tool `resources/read` with argument `uri`; `subscriptions/listen` checks each URI the same way; `prompts/get` is refused if quarantined, and checked like a call when the policy opts in.
6. An "ask" with `--approve-with` is held and asked about in a worker thread; when approved, quarantine is checked again and the request is forwarded.
7. Anything else with an id is remembered in `_pending`, so its reply can be matched, and forwarded. With `limits.call_timeout_seconds`, a call is remembered with its deadline.

Server side, in order:

1. A message with a `method` must be a well-formed request or notification. In a 2026-07-28 session a request is refused. `server_requests` may refuse it; a sampling request is refused when it asks for context or when a block flow to a sink applies; an elicitation is checked for what it asks; then all of it is scanned, with the parameter names of the server's tools.
2. Otherwise it is a reply. If it matches nothing in `_pending`, or answers a call that timed out, drop it. It must have exactly one of `result` and `error`, and a `resultType` the proxy knows. The entries of an `input_required` result pass `server_requests` and the elicitation checks.
3. Lists are filtered entry by entry: icons cleaned, names checked (naming rules, look-alikes, repeats), each entry scanned with the metadata rules (tools with the policy's other tool names, for shadowing), pinned against the pins file, tools checked for references that lead outside their schemas, then blocked tools hidden. The schemas and parameter names of the tools that pass are remembered. A page that continues a list is also scanned with the end of the page before, and a `nextCursor` must be a string. `initialize` and `server/discover` have the server's name and version compared with the server pin, their `serverInfo` cleaned, their instructions checked and pinned, and their capabilities and versions cut down.
4. A `tools/call` result is checked against the tool's output schema when `schema_checks` says so. Then the reply goes through `Firewall.check_result` (scan, the tail scan, and `secrets.in_results`), is cleaned of escape codes, control, tag and bidi characters (`textutil.clean_value_for_forwarding`), and checked again if cleaning changed it. A notice (`injection.warn_severity`) is added after all checks.
5. The request's flow marks are set, with those of `server_labels` and `injection.mark_at`, in the session group's file when there is one. Then a new message is built from the checked `result` or `error`. The server's own envelope is never forwarded.

At startup, `mcp_proxy.main` keeps this order: read the options, the policy, the pins file and the server's environment; name the session group without joining it; build the firewall (the audit key is read here); print the startup lines; write `session_start`; compare the launch with the server pin; set up the containment; join the session group; start the server. A proxy that refuses to start its server therefore never writes into the group's file, and every exit after `session_start` writes a `session_end` that says why.

## Rules a change must keep

These are the security properties of the project. A pull request that breaks one needs a very good reason.

1. **Fail closed.** If a message cannot be parsed, matched or checked, it is dropped or answered with an error. It is never forwarded "just in case". An exception inside a check counts as a failed check. Session state that cannot be read counts as every mark set. Monitor mode lifts policy and scanner blocks only, never these.
2. **Everything from the server is scanned.** Do not add a path that forwards server text to the client without passing through `scan_result` or `check_result`, and scan `text_views(...)`, not a hand-made join.
3. **Forward only what was checked.** The proxy re-serializes messages and rebuilds replies. Never forward the raw bytes that came in, a server's envelope, or the original of something that was changed (forward `checked.content`).
4. **Untrusted text is never printed raw.** Anything from a server, an agent, a log or a config that reaches a terminal goes through `printable`; the audit log escapes control characters. A command line shown to the user goes through `shown_command` (it redacts secrets).
5. **Bounded work on hostile input.** Text is attacker-controlled, in both directions. Cap counts, sizes and decoding rounds. Read the note at the top of `detector.py` before adding a pattern, and add a case to the hostile-input tests.
6. **Do not tell the agent how the policy works.** What goes to the agent is `public_reason`: it may name an argument, never a rule, a pattern or the default. Rule ids, patterns and argument rules go only to the audit log, stderr and operator commands. Tell a refused server nothing at all.
7. **No dependencies.** The package uses only the standard library, which keeps the supply chain of a security tool small. Operating-system calls go through `ctypes`, guarded per platform.
8. **Strict configuration.** Every key of a policy, a case file, a pins, session or baseline file and a client configuration is validated. An unknown key, a repeated key or a wrong type is an error with a clear message. A new key needs validation, tests for wrong values, and a line in the README's policy reference.
9. **One writer for the audit log.** Every record goes through the `Firewall` (`_audit`, `note`, `provenance`, `refuse`, `block`), so that it is linked into the chain and signed. Never append to the log from anywhere else.
10. **Say what a feature does not do.** Every limit of a new defence goes into SECURITY.md, and code that could not be run on the system it is written for is listed there under "What has not been run on a real system".
11. **Readable code.** Small functions, plain-English docstrings, comments that say why, names that say what things are.

Some lists must stay in step, and a test fails when they do not: the module map in `agent_sentinel/__init__.py` names every module; `wrapping.VALUE_OPTIONS` and `FLAG_OPTIONS` together are exactly the options of the proxy's parser; `mcp_protocol.COVERAGE` has a row for every method the proxy's code names; the hook policy in the README is the `claude-code` template; the credential pattern in `policy.example.json` is `templates.CREDENTIAL_PATTERN`; `templates.CREDENTIAL_PATTERN` and `detector._CREDENTIAL_FILE` name the same files, but for the differences written out in the test; every `policy.RULE_*` id is named in `README.md`; `agent-sentinel validate` names every setting of a policy that decides something; and every shortened option 0.5.0 read as one option still reads as that option (`shortened_options.KEPT`).

## How to add a detector rule

1. Add a `_rule(...)` entry in `detector.py`: to `_RULES`, to `_METADATA_RULES` if it only makes sense in what a server says about its tools, or to `_RESULT_RULES` if it only makes sense in what a tool returns. A rule is a first pattern followed by `(max_gap, pattern)` steps. Write patterns in lowercase and follow the conventions in the note at the top of the file; they are what keeps matching fast.
2. Choose the severity carefully. `high` blocks content by default, so a high rule must be narrow. In tool descriptions a false high quarantines a tool for the life of the proxy. A medium rule is not free either: the strict templates block medium findings, and the others put a notice in front of the result.
3. In `tests/test_detector.py` (or `test_result_rules.py` for a result rule), add a test that it fires, a harmless sentence that must not be high, and a repetitive input to the hostile-input tests.
4. Run `tests/test_attack_corpus.py`: every text of `benign_tool_metadata.json` must stay below high. If the rule catches a published attack, add it to `make_published.py` and run that script.
5. Add the rule to the detector table in the README.

If you add a new view of the text for the rules to match in (as the view that joins broken-up words is), add its kind to `detector.VIEW_KINDS` too. The tail scan keeps the end of a result in each kind of view, and `tests/test_warnings_and_tail.py` fails until the two agree.

## How to add a matcher

A matcher is one way of judging an argument's value (`"pattern"`, `"one_of"`, `"type": "path"` ...).

1. In `matchers.py`, write a `Matcher` subclass with its `key`, `found_in(text)` (deny_args: is this text a match?), `accepts(text)` (allow_args: is this the whole of an acceptable value?) and `describe()` (what it checks, for the operator). Set `text_only` if numbers must not pass in allow_args, and `deny_checks_decoded = False` only if the matcher reads escapes itself.
2. Add its key to `MATCHER_KEYS` (or a new type to `TYPES`, `_TYPE_REQUIRED` and `_TYPE_OPTIONAL`), and build it in `build()` or `_typed()`. Validate its value strictly, with a message that says what to write instead. If it makes no sense on one side (like `contains` in allow_args), refuse it there with an explanation.
3. When it cannot read a value with certainty, it must answer "found" in deny_args and "not accepted" in allow_args. It works on text only: no file system, no network.
4. In `tests/test_matchers.py`, test both sides, the configuration errors, and hostile values (long, nested, encoded, look-alike letters).
5. Add a row to the matcher table in the README.

## How to teach the command reader a program

`commands.py` reads a command line into simple commands and then looks at each one's program and words.

1. Find the list the program belongs to: a wrapper that runs another command (`_WRAPPERS`, with the options of it that take a value), a program that talks to another machine (`_NETWORK_PROGRAMS`), a writer, an installer, a program that changes folder (`_CD_PROGRAMS`). The module's docstring says what each class means.
2. If the reader cannot be sure what a form of the command runs, make it unreadable (`Unreadable`), not "nothing found". The policy then asks or refuses.
3. A word the shell may expand to a hidden protected file counts as that file ("Names the shell expands" in the module's docstring). If the program you add writes, reads or changes folder, say which of its words are paths, so that check applies to them.
4. In `tests/test_commands.py`, add the command with the class it must get, a look-alike that must stay clean, and a hostile input with a time limit. Add an everyday use of the program to `ORDINARY_BASH` or `ORDINARY_POWERSHELL`: the `claude-code` template must deny none of those commands, and `claude-code-strict` must refuse exactly what `claude-code` asks about, apart from an unreadable command, Monitor and MCP tools.
5. Add what the reader still does not follow to "The command reader" in SECURITY.md.

## How to add a policy key

1. Add it to the key list of its section in `policy.py` (`_TOP_LEVEL_KEYS`, `_TOOL_RULE_KEYS`, `_LIMITS_KEYS`, `_INJECTION_KEYS`, `_HOOK_KEYS` ...), validate its value there with a message that says what to write, and add a field with a default at the end of `Policy` or `ToolRule`, so that code that builds them by position keeps working.
2. A policy built in code must be validated like a file (`__post_init__`).
3. Print it in `cli_validate.py`: every setting that decides something must be named there, and `tests/test_policy_sections.py` holds that rule. Say the value that is worth saying — for a setting whose default is the strict value, that is the value which turns a check off. Add a warning to `Policy.warnings()` for a value that loads but is probably a mistake.
4. Decide what each template gets (`templates.py`). Every template must still load without a warning.
5. Test wrong values and unknown keys in `tests/test_policy_sections.py`, and add the key to the README's policy reference.

## How to add a rule id

Every refusal names the rule that decided, and operators look it up with `explain`.

1. A rule that is written in the policy gets the id of where it is written (`tools.NAME.deny_args[0]`, `limits.max_distinct[0]`). A fixed check gets a constant in `policy.py` (`RULE_*`), or in its own module when the check belongs to nothing a policy writes, as `elicitation.py` holds `elicitation.url` and `elicitation.form`.
2. Describe it in `Policy.describe_rule`. A check that no policy writes has nothing to describe there, and `describe_rule` leaves it alone.
3. Give it a kind and a hint in `fix_hints.py`. If the block protects against an attack and does not just show a gap in the policy, add the kind to `PROTECTIVE_KINDS`, so that `suggest` never offers to loosen it.
4. Name it in the README, in the `rule` field of the audit log's table. A rule id reaches the operator, and one that no document names leaves the reader of a log with nothing to look up. `tests/test_rule_ids.py` reads every module for a rule-id constant and fails when the README names none.
5. Add it to `tests/test_rule_ids.py` and `tests/test_fix_hints.py`.

## How to add a proxy option

1. Add it to the parser in `mcp_proxy.py`, with a parser function for its value that says what to write instead.
2. Add it to `wrapping.VALUE_OPTIONS` or `FLAG_OPTIONS`, so that `doctor` and `unwrap` know it, and its value check to `_VALUE_CHECKS` in `cli_doctor.py`, so that `doctor` marks an entry the proxy would refuse to start as broken.
3. Say what it does in the startup summary (`proxy_report.Startup`).
4. Keep the order at startup (above): nothing may start the server before the checks that can still refuse it.
5. Add it to the proxy options table in the README.

The proxy takes no shortened option, so nothing more is needed for it. An option added to any **other** command can make a shortening that 0.5.0 read as one option ambiguous, and then a script or a hand-written hook entry stops working (a Claude Code hook that exits with an error blocks every tool call). `tests/test_shortened_options.py` tries every shortening 0.5.0 took against today's parsers; when it fails, add the shortening and the option it meant to `shortened_options.KEPT`. Never widen the table beyond that: a shortening that was already ambiguous in 0.5.0 must stay ambiguous. `hook claude-code` builds a second parser of its own (`cli_hook.event_parser`, the one Claude Code's events go through); the same test holds the two parsers' option words equal, so an option added to either is tried on both.

## How to add an audit event

1. Write it through the `Firewall`: `block` or `refuse` for a refusal (it gets the policy hash and a reference), `note` for something that was let through and is worth recording, `provenance` for a record about the session itself.
2. A record that describes the log or the session and not a call belongs in `auditlog.META_EVENTS`, which `report`'s counts and `support.audit_records` leave out. Everything else is counted.
3. Under `--audit-required`, a decision that leaves no record is refused, and a note that cannot be written is dropped. Decide which of the two the new record is.
4. Add the event to the audit log section of the README.

## How to add a command

1. Create `agent_sentinel/cli_<name>.py` with `HELP` (one line), `add_arguments(parser)` and `run(args) -> int`. Optional: `DESCRIPTION`, `EPILOG` (examples and exit codes), `USAGE`, and `TAKES_SERVER_COMMAND = True` for a command that takes `-- <server command>`. `cli_common.py` describes these parts.
2. Register it in `_COMMANDS` in `__main__.py` (the order is the order of `--help`) and in the list at the top of that file, and add it to the module map in `__init__.py`.
3. Use the shared pieces: the exit codes (0 ok, 1 blocked or found, 2 an error in the input, 3 ask), `load_policy`, `read_input`, `strict_json`. Print anything you did not write yourself through `printable`.
4. A command that writes files never overwrites one (open with `"x"`), prints the full path of what it wrote, and changes a client's file only with `--apply`, after a backup (`config_file`). A new folder is made with `filelock.make_private_folder`, and a file that holds a policy or a key is created with mode 0600.
5. Add `tests/test_cli_<name>.py`. `tests/test_cli_commands.py` already checks that the command has a help page and refuses stray words.
6. Add the command to the commands table in the README, and name every option it takes there or in the details below the table. An option that no document names cannot be found by the person who needs it.

## How to add a secret format

Add an entry to `_FORMATS` in `leaks.py`. It must start with a literal prefix, have explicit length bounds, list its `needles` (literal text every match contains, so texts without them are skipped), and must not be able to match a double quote. Add a positive example, a negative example (a placeholder or a look-alike) and a hostile input to `tests/test_leaks.py`, and add the service to the list in the README.

## How to update the advisories

`agent_sentinel/advisories.py` is data: the packages `doctor` fails or warns about, and the names a typosquat imitates. It is a snapshot. `doctor` never looks anything up online, so the list is only as fresh as the release.

1. Add an `Advisory` to `MALICIOUS` (a version that is itself malware: give `first_bad`, every later version counts too) or to `VULNERABLE` (a published vulnerability: give `fixed`, the first version with the fix). Name the package as its registry spells it, give the CVE numbers or a short name of the incident, one sentence for the operator, and an `https://` source. Add only what a source you can cite confirms.
2. To report typosquats of a well-known package, add its name to `POPULAR`. No two names in it may be one edit apart; a test checks this. A legitimate package that is one edit from a popular name goes into `LOOKALIKES_OK`.
3. **Set `LAST_UPDATED` to the day you checked the list**, also when you only went through it and changed nothing. The date tells users how stale the list may be.
4. Run `python -m unittest discover tests -p test_launch.py` and `-p test_doctor_checks.py`.
5. Add a line to CHANGELOG.md. Go through the list before every release.

## Style

- Every function that is not obvious has a docstring that says what it is for, and comments explain why, not what.
- Type hints on every function signature.
- Lines up to 120 characters.
- Tests are named for the behaviour they check, for example `test_call_blocked_by_policy_never_reaches_the_server`.

## Pull requests

- One change per pull request, with tests.
- All tests pass on your machine, on Python 3.10 and on a newer version. CI runs them on Linux and Windows.
- If you change behaviour that users see, update the README and add a line to CHANGELOG.md. If the change makes something stricter, add it to "Changes that may need action" there.
- If you add or change a defence, update SECURITY.md: what it guarantees, and what it does not do.
- For a security problem, do not open a public issue. Follow [SECURITY.md](SECURITY.md).
