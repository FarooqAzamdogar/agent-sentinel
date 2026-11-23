"""Known-bad MCP server packages, and the popular names a typosquat imitates. Data only.

THIS LIST GOES STALE BETWEEN RELEASES. It is a snapshot, taken on
LAST_UPDATED, of a few well-sourced advisories, and it is updated with each
release of agent-sentinel. A package missing from it is not thereby safe:
doctor never looks anything up on the network. Check the advisories of the
packages you run (npm audit, pip-audit, the GitHub advisory database).

How doctor, clients, wrap and inspect use it (launch.py does the matching):

    MALICIOUS    a package version that is itself malware. doctor fails ([fail]).
                 A run that does not pin an exact version may fetch one of them,
                 so it fails too.
    VULNERABLE   a package version with a published vulnerability, fixed in
                 `fixed`. doctor warns about a pinned version below it, and about
                 a range that allows only versions below it ("<0.1.16"). A run
                 without a pinned version fetches the newest one, which has the fix.
                 `fixed` is the release the sources name; a version from an older
                 release line that got a fix of its own is below it and is warned
                 about all the same, which the entry's summary then says.
    POPULAR      the names of well-known MCP server packages. A package whose name
                 is one edit (a letter added, left out, changed, or two letters
                 swapped) from one of them is reported as a possible typosquat:
                 a warning only, since forks and look-alike names are legitimate
                 too. An exact match never warns, nor does a name in LOOKALIKES_OK.

Versions are compared as dotted numbers (1.0.16, 2025.7.1); a pre-release
(1.0.16-beta.1, 2025.12.18rc1) comes before its release.
"""

from __future__ import annotations

from typing import NamedTuple

LAST_UPDATED = "2026-11-20"

NPM = "npm"
PYPI = "pypi"


class Advisory(NamedTuple):
    ecosystem: str  # NPM or PYPI
    name: str  # as the registry spells it (npm: lowercase, with its @scope; PyPI: normalised, see launch.py)
    first_bad: str | None  # MALICIOUS: the first malicious version (every later one counts too)
    fixed: str | None  # VULNERABLE: the first version with the fix
    ids: str  # CVE numbers or a short name of the incident
    summary: str  # one sentence for the operator
    source: str  # where it was reported


MALICIOUS: tuple[Advisory, ...] = (
    Advisory(NPM, "postmark-mcp", "1.0.16", None, "postmark-mcp backdoor (September 2025)",
             "an unofficial copy of Postmark's server whose version 1.0.16 and later secretly sent a copy (BCC) of "
             "every email to the attacker", "https://www.koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft"),
)

VULNERABLE: tuple[Advisory, ...] = (
    Advisory(NPM, "mcp-remote", None, "0.1.16", "CVE-2025-6514",
             "OS command injection through the authorization endpoint a malicious remote server names",
             "https://thehackernews.com/2025/07/critical-mcp-remote-vulnerability.html"),
    Advisory(NPM, "@modelcontextprotocol/inspector", None, "0.14.1", "CVE-2025-49596",
             "remote code execution through the Inspector's unauthenticated local proxy",
             "https://feedly.com/cve/CVE-2025-49596"),
    Advisory(NPM, "@modelcontextprotocol/server-filesystem", None, "2025.7.1", "CVE-2025-53109, CVE-2025-53110",
             "escapes from the allowed folders (a path prefix match, and symbolic links); the sources name "
             "2025.7.1 as the release with the fix, so an older release line that has a fix of its own is "
             "warned about too (check the advisory for it)",
             "https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/"),
    Advisory(PYPI, "mcp-server-git", None, "2026.1.14",
             "CVE-2026-27735, CVE-2025-68143, CVE-2025-68144, CVE-2025-68145",
             "path traversal and argument injection in the git tools (the three 2025 CVEs were fixed by "
             "2025.12.18, CVE-2026-27735 in 2026.1.14)",
             "https://thehackernews.com/2026/01/three-flaws-in-anthropic-mcp-git-server.html"),
)

# Well-known MCP server packages (and the tools people run beside them), by registry.
POPULAR: dict[str, tuple[str, ...]] = {
    NPM: (
        "@modelcontextprotocol/server-filesystem",
        "@modelcontextprotocol/server-memory",
        "@modelcontextprotocol/server-everything",
        "@modelcontextprotocol/server-sequential-thinking",
        "@modelcontextprotocol/server-github",
        "@modelcontextprotocol/server-puppeteer",
        "@modelcontextprotocol/server-brave-search",
        "@modelcontextprotocol/server-slack",
        "@modelcontextprotocol/server-postgres",
        "@modelcontextprotocol/inspector",
        "mcp-remote",
        "@playwright/mcp",
        "@upstash/context7-mcp",
        "@notionhq/notion-mcp-server",
        "firecrawl-mcp",
        "@supabase/mcp-server-supabase",
        "chrome-devtools-mcp",
        "@browsermcp/mcp",
        "@stripe/mcp",
    ),
    PYPI: (
        "mcp-server-git",
        "mcp-server-fetch",
        "mcp-server-time",
        "mcp-server-sqlite",
        "fastmcp",
    ),
}

# Legitimate packages that happen to be one edit from a POPULAR name: never reported as typosquats.
LOOKALIKES_OK: dict[str, frozenset[str]] = {
    NPM: frozenset(),
    PYPI: frozenset(),
}

# Names shorter than this are not compared: too many real packages are one edit apart.
MIN_TYPOSQUAT_CHARS = 6
