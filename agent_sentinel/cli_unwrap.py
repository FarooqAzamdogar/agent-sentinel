"""`agent-sentinel unwrap`: take the proxy out of the servers of an MCP client's configuration again.

    agent-sentinel unwrap --client claude-desktop            show what would change
    agent-sentinel unwrap --client claude-desktop --apply    change it (after a backup)

Each wrapped entry gets back the command written after the proxy's "--"
(wrapping.unwrap_entry); every other key stays as it is. Like wrap, it shows
a diff by default and writes only with --apply, after a timestamped backup.
The policy, the audit log and the pins files are left where they are.
"""

from __future__ import annotations

import argparse

from .cli_common import EXIT_OK, shown_command, shown_path
from .cli_wrap import (
    Step,
    add_config_arguments,
    apply_changes,
    open_config,
    print_diffs,
    print_plan,
    selected,
    servers_of,
)
from .clients import CLIENTS
from .config_file import ConfigFile
from .wrapping import WrapError, proxy_command_of, unwrap_entry

HELP = "take the proxy out of a client's configuration again (shows a diff; writes with --apply)"
DESCRIPTION = (
    "Give each wrapped server in an MCP client's configuration back its own command (the one after the proxy's "
    "'--'). Prints what would change; --apply writes it, after a backup."
)
EPILOG = """\
examples:
  agent-sentinel unwrap --client claude-desktop
  agent-sentinel unwrap --client cursor --project --apply
"""


def add_arguments(parser: argparse.ArgumentParser) -> None:
    editable = tuple(name for name, info in CLIENTS.items() if info.editable)
    parser.add_argument("--client", required=True, choices=editable, help="the MCP client")
    add_config_arguments(parser)
    parser.add_argument("--server", action="append", default=[], metavar="NAME",
                        help="unwrap only this server (repeat for more; default: every wrapped one)")
    parser.add_argument("--apply", action="store_true",
                        help="write the change (after a backup); without it, only show it")


def run(args: argparse.Namespace) -> int:
    config = open_config(args.client, args.config, args.project)
    servers = servers_of(config, args.client)
    names = selected(servers, args.server)
    plan = [_unwrap_step(name, entry, explicit=bool(args.server)) for name, entry in servers.items() if name in names]
    plan = [step for step in plan if step is not None]
    print(f"{CLIENTS[args.client].label} configuration: {shown_path(config.path)}")
    changes = {step.name: step.new for step in plan if step.new is not None}
    if not plan:
        print("\nNo server in it is wrapped. Nothing to unwrap.")
        return EXIT_OK
    print_plan(plan)
    if not changes:
        print("\nNothing to unwrap.")
        return EXIT_OK
    print_diffs(plan, "unwrapped")
    if not args.apply:
        print("\nNothing was changed. To make this change, run the same command with --apply.")
        return EXIT_OK
    return _apply(config, args.client, changes)


def _unwrap_step(name: str, entry: object, explicit: bool) -> Step | None:
    """What unwrap does with one entry. An entry that is not wrapped is listed only when it was named."""
    if proxy_command_of(entry) is None:
        return Step(name, entry, None, "skipped: not wrapped") if explicit else None
    try:
        new = unwrap_entry(entry)  # type: ignore[arg-type]  (proxy_command_of returned a value, so it is a dict)
    except WrapError as exc:
        return Step(name, entry, None, f"skipped: {exc}")
    command = shown_command([new["command"], *new.get("args", [])], limit=120)
    return Step(name, entry, new, f"will start {command} directly again: NOT protected")


def _apply(config: ConfigFile, client: str, changes: dict) -> int:
    backup = apply_changes(config, client, changes)
    print(f"\nBackup of the original: {shown_path(backup)}")
    print(f"Wrote {shown_path(config.path)}: {len(changes)} server(s) unwrapped; they are not protected any more.")
    print(f"Next: {CLIENTS[client].restart}")
    return EXIT_OK
