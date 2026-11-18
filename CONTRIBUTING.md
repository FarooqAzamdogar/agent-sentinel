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
| `agent_sentinel/detector.py` | Finds prompt injection in text. Pure functions, no state. | textutil |
| `agent_sentinel/leaks.py` | Recognises secrets (keys, tokens) in outgoing text and redacts them. | nothing |
| `agent_sentinel/policy.py` | Loads a policy and answers allow / ask / block for a call. | detector (severity names), textutil |
| `agent_sentinel/firewall.py` | Combines policy, secret guard, rate limits and detector, and writes the audit log. The public core. | the three above |
| `agent_sentinel/mcp_proxy.py` | Puts the firewall between an MCP client and server. | firewall |
| `agent_sentinel/__main__.py` | The `agent-sentinel` command line. | everything |
| `agent_sentinel/textutil.py` | `texts_in` and `text_views` (collect text from nested data) and `printable` (make text terminal-safe). | nothing |
| `docs/` | The project website, served by GitHub Pages. Plain HTML, CSS and a little JavaScript; no build step. | nothing |

Each module has its own test file in `tests/`: `test_detector.py`, `test_leaks.py`, `test_policy.py`, `test_firewall.py`, `test_textutil.py`, `test_proxy.py` and `test_proxy_hardening.py` (for `mcp_proxy.py`) and `test_cli.py` (for `__main__.py`). `tests/support.py` holds the shared setup.

## How a tool call flows (library use)

```
firewall.run(tool, args, fn)
  │
  ├─ check_call
  │    ├─ policy.evaluate ──► allow / ask / block      (block stops here)
  │    ├─ secret guard: do the arguments hold a key or token?
  │    ├─ rate limits
  │    └─ ask ──► approver(tool, args, reason), which must return exactly True
  │
  ├─ fn(**args)                 an error it raises is scanned before it is re-raised
  │
  └─ scan_result ──► detector.scan_views(text_views(result)) ──► findings
                      a finding at or above policy.block_severity ──► BlockedError
```

Every decision writes one line to the audit log. A `Decision` has two texts: `reason` for the log and the operator, and `public_reason` for the agent.

## How a message flows (MCP proxy)

```
client ──► handle_client_line ──► _inspect_client_message ──► _Outcome ──► server
client ◄── handle_server_line ◄── _inspect_server_message ◄── _Outcome ◄── server
```

- `handle_*_line` parses one line and sends whatever the `_Outcome` says.
- `_inspect_*` methods make the decision and return an `_Outcome`. They never write to a stream, which is what makes them easy to test.

Client side, in order:

1. Refuse batches, non-objects and invalid ids.
2. A message with no method must be the answer to a request the server made; otherwise it is dropped.
3. `tools/call`: validate the shape, wait for any tool list still being checked, refuse quarantined tools, then ask the firewall.
4. `resources/read` and `resources/subscribe`: ask the firewall, as tool `resources/read` with argument `uri`.
5. Anything else with an id is remembered in `_pending`, so its reply can be matched, and forwarded.

Server side, in order:

1. A message with a `method` must be a well-formed request or notification. The policy's `server_requests` may refuse it; otherwise all of it is scanned.
2. Otherwise it is a reply. If it matches nothing in `_pending`, drop it. It must have exactly one of `result` and `error`.
3. Check the reply. Lists are filtered entry by entry, and tools are compared with their pinned definition; `initialize` has its `instructions` checked; everything else is scanned whole.
4. Build a new message from the checked `result` or `error`. The server's own envelope is never forwarded.

## Rules a change must keep

These are the security properties of the project. A pull request that breaks one needs a very good reason.

1. **Fail closed.** If a message cannot be parsed, matched or checked, it is dropped or answered with an error. It is never forwarded "just in case". An exception inside a check counts as a failed check. Monitor mode lifts policy and scanner blocks only, never these.
2. **Everything from the server is scanned.** Do not add a path that forwards server text to the client without passing through `scan_result`, and scan `text_views(...)`, not a hand-made join.
3. **Forward what was checked.** The proxy re-serializes messages and rebuilds replies. Never forward the raw bytes that came in, or a server's envelope.
4. **Untrusted text is never printed raw.** Anything that reaches a terminal goes through `printable`; the audit log escapes control characters.
5. **Stay fast on hostile input.** Text is attacker-controlled, in both directions. Read the note at the top of `detector.py` before adding a pattern, and add a case to the hostile-input tests. Anything that grows with what a peer sends needs a bound.
6. **Do not tell the agent how the policy works.** What goes to the agent is `public_reason`: it may name an argument, never a rule, a pattern or the default. Tell a refused server nothing at all.
7. **No dependencies.** The package uses only the standard library, which keeps the supply chain of a security tool small.
8. **Strict configuration.** A policy key the loader does not know is an error. A new key needs validation, a test for a wrong type, and a line in the README table.

## How to add a detector rule

1. Add a `_rule(...)` entry to `_RULES` in `detector.py`. A rule is a first pattern followed by `(max_gap, pattern)` steps. Write patterns in lowercase and follow the conventions in the note at the top of that file; they are what keeps matching fast.
2. Choose the severity carefully. `high` blocks content by default, so a high rule must be narrow.
3. In `tests/test_detector.py`, add a test that it fires, a harmless sentence that must not be high, and a repetitive input to the hostile-input tests.
4. Add the rule to the table in the README.

## How to add a secret format

Add a pattern to `leaks.py`. It must start with a literal prefix, have explicit length bounds, and must not be able to match a double quote. Add a positive and a negative example to `tests/test_leaks.py`.

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
