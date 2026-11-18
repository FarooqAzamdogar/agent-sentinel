# Security

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private reporting instead: on the repository page, open the **Security** tab and choose **Report a vulnerability**. Include the input that shows the problem and what you expected to happen.

A bypass counts as a vulnerability when it breaks one of the guarantees listed below. A new way to phrase a prompt injection that the pattern rules miss is expected (see the limits) and is welcome as an ordinary issue or pull request.

## What agent-sentinel is meant to guarantee

When the proxy is in front of an MCP server:

1. A `tools/call`, `resources/read` or `resources/subscribe` request reaches the server only if the policy allows it.
2. Every message from the server is scanned before any of it reaches the client, and a reply is rebuilt from the parts that were scanned.
3. A message the proxy cannot parse, match to a request, or check is not forwarded.
4. The server receives exactly the message that was checked, not the original bytes.
5. Hostile text cannot stall the scanner, and text printed by the proxy or written to the audit log has its control codes escaped. This includes the server's error output.
6. A tool whose description is flagged, or whose definition changes after it was first listed, is removed from the tool list and cannot be called.

These were last checked by an internal multi-angle review of version 0.3.0, whose findings were fixed in 0.4.0. There has been no independent audit.

## Who is trusted

| Party | Trusted? | Why |
|---|---|---|
| The person who writes the policy and starts the proxy | Yes | They choose the server command and the rules. |
| The MCP server and everything it returns | No | Tool results, tool descriptions and server instructions can all carry injected text. |
| The agent (the model) | Partly | It may have been hijacked by text it read earlier, so the actions it requests must pass the policy. |
| The client application's own protocol messages | Yes | The proxy assumes the client software itself is not malicious. |

## Known limits

These are not guarantees, and reports about them are not vulnerabilities:

- **The detector is pattern rules.** It misses reworded and translated attacks, base64 or hex encoded text, and look-alike letters outside the small set it folds. It only scans text, not images or audio. It can flag harmless text.
- **Policy patterns match text.** Deny rules undo percent-encoding, but nothing resolves paths, follows symbolic links or decodes other encodings. A deny rule is one layer; the tool should enforce its own access controls.
- **A policy is only as strict as it is written.** `"default": "allow"` lets any tool without a rule run. Methods other than tool calls and resource requests (for example `prompts/get`) are forwarded without a policy check; their replies are scanned.
- **The secret guard knows a fixed list of formats.** Passwords and keys in other formats pass.
- **`ask` rules are blocked in the proxy**, because there is no way to reach a human yet.
- **Monitor mode protects nothing.** It exists for tuning a policy.
- **The audit log is a plain file.** Anyone who can write to it can change it. It records tool arguments unless that is turned off; only recognisable secrets are redacted.
- **Resource limits are simple.** Messages over a size limit are dropped and the proxy caps what it remembers, but a server can still keep the proxy busy with a flood of valid messages.
- **A tool call waits for a tool list that is being checked.** A server that never answers a list request delays tool calls by up to 15 seconds before they are refused.
- **The server inherits the proxy's environment variables.** Do not start the proxy with secrets in its environment that the server should not see.
- **Only the stdio transport is supported.**

## Supported versions

Only the latest release receives fixes.
