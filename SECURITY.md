# Security

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private reporting instead: on the repository page, open the **Security** tab and choose **Report a vulnerability**. Include the input that shows the problem and what you expected to happen.

A bypass counts as a vulnerability when it breaks one of the guarantees listed below. A new way to phrase a prompt injection that the pattern rules miss is expected (see the limits) and is welcome as an ordinary issue or pull request.

## What agent-sentinel is meant to guarantee

When the proxy is in front of an MCP server:

1. A `tools/call` or `resources/read` request reaches the server only if the policy allows it.
2. Every message from the server is scanned before any of it reaches the client.
3. A message the proxy cannot parse, match to a request, or check is not forwarded.
4. The server receives exactly the message that was checked, not the original bytes.
5. Hostile text cannot stall the scanner or inject control codes into the terminal or audit log.

## Who is trusted

| Party | Trusted? | Why |
|---|---|---|
| The person who writes the policy and starts the proxy | Yes | They choose the server command and the rules. |
| The MCP server and everything it returns | No | Tool results, tool descriptions and server instructions can all carry injected text. |
| The agent (the model) | Partly | It may have been hijacked by text it read earlier, so the actions it requests must pass the policy. |
| The client application's own protocol messages | Yes | The proxy assumes the client software itself is not malicious. |

## Known limits

These are not guarantees, and reports about them are not vulnerabilities:

- **The detector is pattern rules.** It misses paraphrased, translated, encoded (base64, HTML entities, URL encoding) and look-alike-letter (for example Cyrillic) variants. It only scans text, not images or audio.
- **Policy patterns match text.** They do not resolve paths, follow symbolic links or decode encodings. A deny rule is one layer; the tool should enforce its own access controls.
- **A policy is only as strict as it is written.** `"default": "allow"` lets any tool without a rule run.
- **`ask` rules are blocked in the proxy**, because there is no way to reach a human yet.
- **The audit log is a plain file.** Anyone who can write to it can change it. It records tool arguments unless that is turned off.
- **The proxy has no resource limits.** A server can send very large messages; they are scanned in roughly linear time but held in memory.
- **Only the stdio transport is supported.**

## Supported versions

Only the latest release receives fixes.
