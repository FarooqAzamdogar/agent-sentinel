# Contributing to agent-sentinel

Thanks for helping. This page explains how the code is organized, how a message flows through it, and the rules a change must keep.

## Set up

There is nothing to install. You need Python 3.10 or newer.

```bash
python -m unittest discover tests -v     # run all tests
python examples/demo.py                  # see the firewall make six decisions
```

## The files

| File | What it does | Depends on |
|---|---|---|
| `agent_sentinel/detector.py` | Finds prompt injection in text. Pure functions, no state. | nothing |
| `agent_sentinel/policy.py` | Loads a policy and answers allow / ask / block for a call. | detector (severity names) |
| `agent_sentinel/firewall.py` | Combines policy and detector, and writes the audit log. The public core. | detector, policy |
| `agent_sentinel/mcp_proxy.py` | Puts the firewall between an MCP client and server. | firewall |
| `agent_sentinel/__main__.py` | The `agent-sentinel` command line. | everything |
| `agent_sentinel/textutil.py` | `texts_in` (collect text from nested data) and `printable` (make text terminal-safe). | nothing |

Each module has its own test file in `tests/`: `test_detector.py`, `test_policy.py`, `test_firewall.py`, `test_textutil.py`, `test_proxy.py` (for `mcp_proxy.py`) and `test_cli.py` (for `__main__.py`). `tests/support.py` holds the shared setup.

## How a tool call flows (library use)

```
firewall.run(tool, args, fn)
  │
  ├─ check_call ──► policy.evaluate ──► allow / ask / block
  │                   ask ──► approver(tool, args, reason)
  │                   block ──► BlockedError (fn never runs)
  │
  ├─ fn(**args)
  │
  └─ scan_result ──► detector.scan ──► findings
                      a finding at or above policy.block_severity ──► BlockedError
```

Every `check_call` and `scan_result` writes one line to the audit log.

## How a message flows (MCP proxy)

```
client ──► handle_client_line ──► _inspect_client_message ──► _Outcome ──► server
client ◄── handle_server_line ◄── _inspect_server_message ◄── _Outcome ◄── server
```

- `handle_*_line` parses one line and sends whatever the `_Outcome` says.
- `_inspect_*` methods make the decision and return an `_Outcome`. They never write to a stream, which is what makes them easy to test.

Client side, in order:

1. Refuse batches, non-objects and invalid ids.
2. `tools/call`: validate the shape, wait for any tool list still being checked, refuse quarantined tools, then ask the policy.
3. `resources/read`: ask the policy, as tool `resources/read` with argument `uri`.
4. Anything else with an id is remembered in `_pending`, so its reply can be matched, and forwarded.

Server side, in order:

1. A message with a `method` is a request or notification from the server: scan it all.
2. Otherwise it is a reply. If it matches nothing in `_pending`, drop it.
3. Scan the reply. Lists are filtered entry by entry; `initialize` has its `instructions` checked; everything else is scanned whole.

## Rules a change must keep

These are the security properties of the project. A pull request that breaks one needs a very good reason.

1. **Fail closed.** If a message cannot be parsed, matched or checked, it is dropped or answered with an error. It is never forwarded "just in case". An exception inside a check counts as a failed check.
2. **Everything from the server is scanned.** Do not add a path that forwards server text to the client without passing through `scan_result`.
3. **Forward what was checked.** The proxy re-serializes messages. Never forward the raw bytes that came in.
4. **Untrusted text is never printed raw.** Anything that reaches a terminal goes through `printable`.
5. **The scanner must stay fast on hostile input.** Text is attacker-controlled. Read the note at the top of `detector.py` before adding a pattern, and add a case to `HostileInputIsScannedQuickly` in `tests/test_detector.py`.
6. **Do not tell the agent how the policy works.** Reasons returned to the agent say that a value was denied, not which pattern denied it.
7. **No dependencies.** The package uses only the standard library, which keeps the supply chain of a security tool small.

## How to add a detector rule

1. Add a `_rule(...)` entry to `_RULES` in `detector.py`. A rule is a first pattern followed by `(max_gap, pattern)` steps.
2. Choose the severity carefully. `high` blocks content by default, so a high rule must be narrow.
3. In `tests/test_detector.py`, add a test that it fires, a harmless sentence to `test_harmless_sentences_are_not_high_severity`, and a repetitive input to `HostileInputIsScannedQuickly`.
4. Add the rule to the table in the README.

## Style

- Every function that is not obvious has a docstring that says what it is for, and comments explain why, not what.
- Type hints on every function signature.
- Lines up to 120 characters.
- Tests are named for the behavior they check, for example `test_call_blocked_by_policy_never_reaches_the_server`.

## Pull requests

- One change per pull request, with tests.
- All tests pass on your machine. CI runs them on Linux and Windows.
- If you change behavior that users see, update the README.
- For a security problem, do not open a public issue. Follow [SECURITY.md](SECURITY.md).
