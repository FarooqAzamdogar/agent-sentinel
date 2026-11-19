"""`agent-sentinel clients`: list the MCP client configurations found on this machine and in this folder.

Read-only. For each configuration file that exists: the client, the path,
and how many of its servers are protected (wrapped), not protected, remote
(which the proxy cannot protect) or broken. For Claude Desktop, the Desktop
Extensions beside it, which cannot be wrapped, and a warning when there are
two configuration files and it is not clear which one the app reads.
"""

from __future__ import annotations

import argparse
from collections import Counter
from typing import Any

from . import clients
from .cli_common import EXIT_OK, shown_path
from .clients import CLIENTS, Location
from .config_file import ConfigError, read_config
from .textutil import printable
from .wrapping import status_of

HELP = "list the MCP client configurations on this machine and in this folder, and how many servers are protected"
DESCRIPTION = (
    "List the MCP client configurations agent-sentinel knows about, on this machine and in the current folder "
    "(the project), with how many of their servers are protected. Nothing is changed."
)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    pass


def server_counts(servers: Any) -> Counter:
    """How many entries are protected, unprotected (monitor mode included), remote and broken (wrapping.status_of)."""
    return Counter(status_of(entry) for entry in (servers.values() if isinstance(servers, dict) else ()))


def describe_counts(counts: Counter) -> str:
    total = sum(counts.values())
    parts = [f"{counts[kind]} {words}" for kind, words in (
        ("protected", "protected"), ("unprotected", "NOT protected"), ("remote", "remote (cannot be protected)"),
        ("broken", "broken"),
    ) if counts[kind]]
    return f"{total} server(s)" + (": " + ", ".join(parts) if parts else "")


def run(args: argparse.Namespace) -> int:
    locations = clients.all_locations()
    found = [location for location in locations if location.path.is_file()]
    missing = [location for location in locations if not location.path.is_file()]
    if found:
        print("MCP client configurations found:")
        for location in found:
            _print_location(location)
    else:
        print("No MCP client configuration was found.")
    desktops = [location for location in found if location.client == "claude-desktop"]
    if len(desktops) > 1:
        print("\nWarning: Claude Desktop has more than one configuration file. The Microsoft Store app reads the copy "
              "under Packages; Settings > Developer > Edit Config opens the one under AppData. wrap asks you to choose "
              "with --config.")
    if missing:
        print("\nAlso looked for (not found):")
        for location in missing:
            print(f"  {_title(location):24} {shown_path(location.path)}")
    print("\nTo protect a client's servers (it shows the change first):")
    print("  agent-sentinel wrap --client NAME --policy POLICY")
    print("Other clients (Claude Code user scope, Codex, Cline, Antigravity, ...): print an entry to paste with")
    print("  agent-sentinel wrap --client codex --policy POLICY --name NAME -- <server command>")
    return EXIT_OK


def _title(location: Location) -> str:
    scope = " (project)" if location.scope == "project" else ""
    return f"{location.client}{scope}"


def _print_location(location: Location) -> None:
    print(f"  {_title(location):24} {shown_path(location.path)}")
    if location.note:
        print(f"  {'':24} {location.note}")
    try:
        config = read_config(location.path)
    except ConfigError as exc:
        print(f"  {'':24} cannot be read: {printable(str(exc).splitlines()[0], limit=200)}")
        return
    key = CLIENTS[location.client].servers_key
    servers = config.document.get(key, {})
    if not isinstance(servers, dict):
        print(f"  {'':24} \"{key}\" is not an object")
        return
    print(f"  {'':24} {describe_counts(server_counts(servers))}")
    if location.client == "claude-desktop":
        extensions = clients.desktop_extensions(location.path)
        if extensions:
            print(f"  {'':24} {len(extensions)} Desktop Extension(s), which cannot be wrapped: "
                  + ", ".join(printable(name, limit=40) for name in extensions[:10])
                  + (" ..." if len(extensions) > 10 else ""))
