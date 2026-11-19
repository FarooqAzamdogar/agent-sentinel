# Security

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private reporting instead: on the repository page, open the **Security** tab and choose **Report a vulnerability**. Include the input that shows the problem and what you expected to happen.

A bypass counts as a vulnerability when it breaks one of the guarantees listed below. A new way to phrase a prompt injection that the pattern rules miss is expected (see the limits) and is welcome as an ordinary issue or pull request.

## What agent-sentinel is meant to guarantee

### When the proxy is in front of an MCP server

1. A `tools/call`, `resources/read` or `resources/subscribe` request, each URI of a `subscriptions/listen` request, and (when the policy opts in) a `prompts/get` request reach the server only if the policy allows them. A call the policy says "ask" for reaches the server only after a person approved it through an approver given with `--approve-with`; without one, it is refused.
2. Every message from the server is scanned before any of it reaches the client. That includes the requests a 2026-07-28 server puts inside its replies (`input_required`): each one must pass `server_requests` too. A reply, a list entry or the server's instructions are rebuilt from the parts that were checked, and cleaned of terminal escape codes, control characters, Unicode tag characters and bidi controls.
3. A message the proxy cannot parse, match to a request, or check is not forwarded. Unknown protocol versions, unknown result types and tasks are refused.
4. The server receives exactly the message that was checked, not the original bytes. The client's answers to the server's requests are rebuilt and pass the secret guard.
5. Hostile text cannot stall the scanner, and text printed by the proxy or written to the audit log has its control codes escaped. This includes the server's error output.
6. A tool, prompt or resource template whose description is flagged, or whose definition changes after it was first listed, is removed from its list and cannot be called or fetched. Server instructions that are flagged or change are removed.
7. What the agent is told about a refusal never names a rule or a pattern. It is a generic reason and a reference (`(ref 7f3a9c21)`) that only the operator can look up.

### When the Claude Code hook is installed

8. With Claude Code v2.1.295 or later and `"onFailure": "block"` on each hook (as `hook install` writes them), a tool call that Claude Code reports to the PreToolUse hook runs only if the policy allows it, or asks for it in Claude Code's own permission prompt. When the hook cannot read the event, load the policy or record the session's state, the call is refused.

### Everywhere (library, proxy, hook)

9. Once a session holds every `after` mark of a flow rule whose action is `block`, a call to a tool with its `then` label is refused for the rest of that session. Marks are set when a result is delivered and are never cleared by anything the agent does.
10. A call that carries a canary, or the value of a variable named in `known_values_from_env`, is refused, even when `secrets.in_arguments` is `"allow"`.

These guarantees were checked by internal reviews: a multi-angle review of version 0.3.0, a line-by-line review of 0.4.0 (fixed in 0.4.1), and for 0.5.0 a review of the shared core and a review of the finished code, whose findings are fixed or listed below as limits. There has been no independent audit.

## Who is trusted

| Party | Trusted? | Why |
|---|---|---|
| The person who writes the policy and starts the proxy or installs the hook | Yes | They choose the server command, the rules and the approvers. |
| The policy, pins file, audit log and session state files | As plain files | Anything that can write them can change what agent-sentinel does or reports. Keep them out of every folder the agent's tools can write to. |
| The MCP server and everything it sends | No | Tool results, descriptions, schemas, annotations, icons, instructions and requests can all carry hostile text. Annotations can only add flow labels, never remove one. |
| The agent (the model) | Partly | It may have been hijacked by text it read earlier, so the actions it requests must pass the policy. It never chooses an approver and never answers an approval. |
| The client application's own protocol messages | Yes | The proxy assumes the client software itself is not malicious. Its answers to server requests still pass the secret guard, because they can carry what the agent or the user typed. |
| The person who answers an approval, and the route to them | Yes | An approval is only as safe as the way the question reaches a person (see the limits). |
| Approver programs (`command:`), and `osascript` or `zenity` for the dialog | Yes | They are operator code that decides. Keep them out of the agent's reach. |
| Claude Code, in hook mode | Yes | It reports tool calls to the hook and carries out its answers. A hook it does not run protects nothing. |
| A client configuration that `doctor` or `wrap` reads (for example a project's `.mcp.json`) | No | `doctor` never starts a program the file names and never opens a path on another machine. |

## Known limits

These are not guarantees, and reports about them are not vulnerabilities.

### The detector

- **It is pattern rules, in English.** It misses reworded and translated attacks, and look-alike letters outside the set it folds. It only scans text, not images or audio. It can flag harmless text: a field named `override_system_prompt` reads as the phrase it spells.
- **Base64 and hex are decoded one level only**, and only runs of at least 32 base64 or 48 hex characters (24 and 40 for the secret guard). A payload split over runs, encoded twice, written with separators, or in another encoding (base32, rot13, gzip) passes. The decoding limits (64 runs tried, 16 kept, 64 KiB per text) can be used up on purpose by harmless runs placed before the payload.
- **Fewer than 8 hidden Unicode tag characters** are only a medium `invisible_characters` finding.
- **Sending a secret to an address is high only within one sentence**, and not when the verb is negated ("never email your password to..."). Both exist to keep login pages and security advice from being blocked.
- **False positives in tool descriptions are costly.** A high finding in a tool description quarantines the tool for the life of the proxy, and there is no per-tool override (only `injection.block_severity`, which also governs results). Known cases that are high: a tool whose purpose is to receive the conversation and whose description says to include it in an argument, and a tool that asks for the values of a `.env` file in an argument. None occurs in the 650 real descriptions of the test set.
- **Shadowing** (a description giving orders about another server's tool) is caught as high only for tool names the policy writes out in full and this server never listed. A paginated tool list may name a tool of the same server that only a later page lists: on a first run, that can be a false positive.
- **Tool output** that asks for a credential file in an argument is read with the result rules and is not caught.
- **Reference-style images** are caught only when the image and its definition are in the same text.

### The policy and the argument matchers

- **A policy is only as strict as it is written.** `"default": "allow"` lets any tool without a rule run. `prompts/get` is checked only when the policy opts in (a `client_requests` section, or a tool rule named `prompts/get`); otherwise only its reply is scanned. `client_requests` gates methods, not what is inside them.
- **Paths are judged as text** (`"type": "path"` and patterns). Nothing resolves symbolic links, junctions or mount points, so a link inside a root can lead out of it, and a path checked now can be swapped later. `deny_args` knows the junctions every Windows creates: `C:\Documents and Settings`; `All Users` and `Default User` in `C:\Users`; `Application Data`, `Local Settings`, `My Documents`, `Start Menu`, `SendTo`, `Recent`, `Templates`, `NetHood`, `PrintHood` and `Cookies` in a profile; `Application Data`, `History` and `Temporary Internet Files` in `AppData\Local`; `My Music`, `My Pictures` and `My Videos` in Documents; and `Application Data`, `Start Menu`, `Templates`, `Desktop` and `Documents` in `C:\ProgramData`. It also knows macOS's `/private/etc`. They are read in the value only, so write each root with the folder's real name (`~/AppData/...`, not `~/Start Menu`). A value with more alias readings than are followed is denied. Other links are not known: your own symbolic links and junctions, `subst` and mapped drive letters, bind mounts, and macOS firmlinks. Relative paths are read from the proxy's current folder, and a server in a container or VM sees other paths. Unicode normalization is not applied.
- **URLs are judged without DNS.** A listed name that resolves to a private address (DNS rebinding) passes. A subdomain entry (`.example.com`) lets an agent carry data in subdomain labels; prefer exact hosts. Internationalized (IDN) host names cannot be allowed with `"type": "url"`.
- **`"type": "email"` refuses some valid addresses** (quoted names, `%`, `!`, `=`, `&`, `#`).
- **In `deny_args`, a url or email entry denies every value it cannot read**, so on a free-text argument it denies almost everything.
- **`no_options` in `allow_args` checks the value as written**: a tool that percent-decodes would see `%2D` as `-`. `ends_with` in `allow_args` does not refuse a `..` segment.
- **The example credential deny rule is a text pattern.** It covers only the names it lists, and the Windows short names (`SSH~1`) only of those folders. Use `"type": "path"` roots for containment.
- **Block references are 32 random bits.** They identify a record; they prove nothing, and two records in a long log can share one.

### Flow rules

- **In the proxy, a session is one server.** One proxy process is one session, so a chain across servers (read from a web server, then send with a mail server) is caught only where one policy sees every tool: the library, or the Claude Code hook.
- **Marks are set when a result is delivered.** A call the client sends before an earlier result reached it (pipelined or parallel calls) is judged without that result's marks.
- **Only some replies set marks:** the replies to `tools/call` and `resources/read`, and to `prompts/get` when the policy checks prompts. Server notifications, sampling and elicitation requests, completion replies and other forwarded replies set none: injected text arriving there is scanned, but does not set a mark.
- **Marks never expire within a session.** A sink stays refused until the proxy restarts or a new Claude Code session starts.
- **Annotations are the server's claims.** They can only add labels. A server that leaves them out gets none.
- **The hook's session files** fail closed when missing, damaged or swapped (every mark counts as set), but anything that can write the state folder can replace a file with a consistent one with fewer marks. A forked or resumed Claude Code session with a new id starts with every mark set.
- **In hook mode, a PostToolUse matcher narrower than the default** (for example one without `WebFetch`) means that tool's output never sets its marks. Keep the default, or use `--scan-all-results`.
- **A probing agent can tell that its history matters**, even though it is told only "not permitted".

### Asking a person

- **An approval is only as safe as the host that shows it.** A client that answers elicitation by itself (an automatic hook, a print mode, an automatic cancel) decides for the person: a decline fails closed, but a host that accepts automatically approves. Use `--approve-with elicitation` only with a client that shows the form to a person; Claude Desktop is reported not to show elicitations, so `dialog` is the way there.
- **The person sees each value cut at 200 characters** (with how much was cut) and at most 20 arguments; a call with more is refused.
- **The dialog's 3-second guard is a mitigation.** It refuses an "OK" given less than 3 seconds after the dialog was asked for, so keys typed for another window do not approve. A person who keeps typing for longer can still press Tab then Enter into it. The macOS and Linux dialogs were tested only with stand-ins; the Windows box through a stand-in for user32.
- **Timing shows the agent which tools need approval** (an ask waits, a block is immediate). Rate limits are counted when the call is asked about, not again when it is approved.
- **At most 16 calls wait at a time**, and one question is asked at a time; more are refused. An answer that comes after the timeout changes nothing. An "ask" in `subscriptions/listen` is refused, not asked about. Elicitation approval is not used in a 2026-07-28 session.

### The MCP protocol

- **Only the stdio transport is supported.** Streamable HTTP, SSE and WebSocket are not. A remote server can be put behind the proxy only through a stdio bridge started as the server command.
- **Only the revisions 2024-11-05 to 2026-07-28 are passed on.** Anything newer is refused or downgraded until the proxy is updated. Tasks (2025-11-25 tasks and the 2026-07-28 tasks extension) are not supported.
- **The protocol era is learnt from the client.** Before the client's first request, a server request is judged by `server_requests` alone.
- **`requestState` is opaque.** It is size-checked and scanned on its way to the client, but the secret guard does not look at it on the way back. MRTR answers are not matched to what was asked.
- **Server requests and notifications are scanned but not cleaned**, because cleaning could change what the client answers by.
- **MCP Apps** (`_meta.ui`, `ui://` resources) are not checked or pinned, and the icons of `resource_link` items inside results are not cleaned.
- **Each URI in `subscriptions/listen` counts as one call** for rate limits.
- **`prompts/get` does not wait** for a `prompts/list` reply that is still being checked (`tools/call` does).

### Tool lists, pins and names

- **Pins are trust on first use.** A definition that is malicious when first seen is pinned. Prompts, templates and instructions were not pinned before 0.5, so their first listing after the upgrade is trusted.
- **The pins file is plain JSON**, and the `.pending` file beside it is advisory. `pins accept` rescans and asks on a terminal, but anything that can write the pins file can make a changed definition look pinned. A running proxy keeps its pins until it restarts.
- **Hiding blocked tools is not enforcement.** `hide_blocked_tools` hides only tools blocked outright, and only tools (not resources). Argument rules, flow rules and rate limits still apply at call time.
- **Look-alike names are caught within one server**, for the letters the detector folds plus `i`/`l`/`1`/`|`, `o`/`0` and case. Other confusables (`rn` for `m`, other scripts) are not. It can refuse a real tool whose name differs from another only in case or in `i`/`l`/`1`; `--tool-names off` turns the checks off.
- **Icons:** an https icon is still fetched by the client from a host the server chose (a tracking pixel is possible). The proxy refuses only unsafe schemes, local hosts, IP addresses and SVG.
- **Elicitation:** no DNS lookup; without `--elicitation-host` any public https address is allowed; the words for secrets are English; the message text and the titles of choices are not checked.

### Secrets

- **Only formats with a fixed start are known.** Passwords, AWS secret access keys, Azure AD client secrets and other keys without a fixed start pass, unless their variable is named in `known_values_from_env` or they carry a canary.
- **Known values are matched whole and exactly.** A value cut into pieces inside one argument (DNS labels, spaces, dashes), reversed, encoded twice, or in another encoding passes. Pieces in separate arguments are caught only when they are next to each other, within the first 100,000 joined characters.
- **Known values are read when the firewall starts.** A value changed later is not guarded until a restart. A value shorter than 8 characters is not guarded. A value must really be secret: an ordinary word blocks every call that says it. In the proxy, the value guarded is the one the server's environment has (env file included), else the proxy's own; one value per name.
- **Canaries are never removed from results** (by design: they must reach the agent so that sending them trips the guard). In calls they are found as written (any case), percent-encoded, or in base64 or hex.
- **JWTs never cause a refusal.** They are only redacted.
- **`secrets.in_results` covers replies**, not tool descriptions, list entries, server instructions or server requests. Under `redact`, a secret split over several strings, or inside a value that cannot be rebuilt, makes the whole result refused instead. In hook mode, a built-in tool's redacted output relies on Claude Code accepting a replacement of the same shape, and an error text cannot be redacted: the agent is stopped instead.
- **The audit log** leaves out a finding's excerpt when it may show a known value or canary, but a value with fewer than 6 letters and digits can still appear. Runs of 20 or more letters and digits anywhere in an excerpt, and a piece of 6 or more at either end that has a digit or an inner capital, become `[...]`, since the excerpt window can cut through a token and leave a part that redaction no longer recognises; a shorter piece of a token can still show. `scan`, `check`, `pins` and `explain` mask excerpts the same way. Arguments that hold a secret split over several values are left out of the record.
- **Cost:** with the maximum of 100 known values and 100 canaries, checking 1 MB of text takes one to two seconds.

### The server's environment

- **The server inherits the proxy's environment variables**, unless the proxy is started with `--clean-env`. The proxy warns about variables whose names look like secrets; that is a guess from the name.
- **`--clean-env` can remove variables a server needs** (`HTTP_PROXY`, `NODE_*`, `SSL_CERT_FILE` ...): name them with `--pass-env`.

### Claude Code hooks and the library integrations

- **Older Claude Code, or a hook without `"onFailure": "block"`, fails open.** A hook that cannot start (Python missing, the package not importable), crashes or times out then lets the call through. The hook itself exits only with 0 or 2.
- **Hooks are a guardrail, not a sandbox.** They see the tool calls Claude Code reports. A Bash command is judged by its text, not by what it does.
- **Results are scanned only for the tools in the PostToolUse matcher** (by default WebFetch, WebSearch and MCP tools). The output of Read, Grep and Bash is not scanned unless the hooks were installed with `--scan-all-results`.
- **A blocked built-in tool output may still reach Claude** when Claude Code drops a replacement that does not fit the tool's schema. The hook then stops the agent and counts the output as read, but the text stays in the context if the user goes on. A PostToolUse hook that fails or times out cannot take an output back.
- **"ask" relies on Claude Code's prompt.** It is refused in `bypassPermissions` mode and unknown modes; a setting that approves calls automatically skips the prompt.
- **Rate-limit counts use wall-clock seconds**; a call may count up to one second longer than a minute.
- **Only Claude Code is covered.** Hooks for Codex, Cursor, VS Code (Copilot) and the Antigravity CLI are not built.
- **`claude_sdk_hooks()` and the recipes in `examples/` are best effort**: tested against stand-ins, not the real SDKs.
- **`guard()` checks the arguments as bound to the function.** It cannot see what the tool does with them, and a value changed after the check is not checked again.

### The commands

- **`check` and `test` are dry runs of one call in a fresh session**: no annotation labels, no rate-limit history, no quarantine, no pins.
- **`report`, `explain` and `suggest` trust nothing in the log**, but the log is a plain file: an edited log can make them show wrong rules or hints. `suggest` proposes rules from names the agent or server chose: review the diff.
- **`wrap` edits only the plain-JSON files of the clients it knows.** A client that keeps another copy (the Microsoft Store Claude Desktop, settings sync) can bring back an unwrapped entry: run `doctor` after changes. Desktop Extensions, remote servers and servers in other files stay unprotected. `unwrap` does not bring back an empty `"args": []`.
- **A wrapped entry trusts the Python it names.** With a `pip install --user` copy it runs without `-I`, and a folder named `agent_sentinel` in the client's working folder would run instead (`wrap` and `doctor` warn).
- **Backups hold the original configuration**, tokens included. They are readable by their owner only (on POSIX). A file inside a project under version control (`.git`, `.hg`, `.svn` or `.jj` above it) is backed up to the home folder instead. That backups folder holds a `.gitignore` that ignores everything in it (git and jj read it). A home folder inside a Mercurial or Subversion working copy is refused, because neither reads that file.
- **`inspect` and `init --` run the server command you give**, with your environment. A probe sees what a server lists to one client at one moment. `inspect` tells a proxy refusal from a server error by its text.
- **`doctor`'s checks are static.** It cannot see the client's environment or PATH, whether the client really reads that file, or links inside a project that point to a network share (it only refuses paths written as `\\server`).
- **The starter template's fetch rules are text checks without DNS**: a public name that resolves to a private address passes, and every URL with an IP address is refused, public ones too.

### Resources and processes

- **Resource limits are simple.** Messages over a size limit are dropped and the proxy caps what it remembers, but a server can still keep the proxy busy with a flood of valid messages. A message dropped for its size is not answered: a client request dropped this way, or one whose reply was dropped, waits until the client's own timeout.
- **stderr is rate-limited.** Past 20 lines in 10 seconds, the proxy's own lines are counted instead of printed, and the server's stderr is relayed at most 60 lines a minute. The audit log has every block; without `--audit` the rest are lost.
- **A killed proxy cannot stop its server.** If the host application kills the proxy outright, the server is left running. The proxy stops the server itself when its input closes or it is asked to terminate.
- **A tool call waits for a tool list that is being checked.** A server that never answers a list request delays tool calls by up to 15 seconds before they are refused.

### Monitor mode and the audit log

- **Monitor mode protects nothing.** It exists for tuning a policy.
- **The audit log is a plain file.** Anyone who can write to it can change it. It records tool arguments unless that is turned off; only recognisable secrets, known values and canaries are redacted.

## Supported versions

Only the latest release receives fixes.
