"""Command line for agent-sentinel.

    agent-sentinel proxy --policy policy.json -- <mcp server command...>
    agent-sentinel init --template starter              write a first policy (or: init -- <server command>)
    agent-sentinel inspect -- <server command>          list a server's tools and what the proxy would do
    agent-sentinel clients                              list the MCP client configurations on this machine
    agent-sentinel wrap --client NAME --policy POLICY   put the proxy in front of a client's servers
    agent-sentinel unwrap --client NAME                 take it out again
    agent-sentinel doctor                               check that every server is protected
    agent-sentinel hook install claude-code --policy P  enforce the policy inside Claude Code (its hooks)
    agent-sentinel pins diff --pins FILE                see what changed in a definition the proxy removed
    agent-sentinel check POLICY TOOL [name=value ...]   try one call against a policy
    agent-sentinel test POLICY CASES.json               run a policy's test cases (for CI)
    agent-sentinel validate POLICY                      check that a policy file is well formed
    agent-sentinel scan [FILE ...]                      scan text (or stdin) for prompt injection
    agent-sentinel report AUDIT_LOG                     summarize an audit log
    agent-sentinel explain AUDIT_LOG [--ref REF]        say why calls were blocked, and how to allow them
    agent-sentinel suggest AUDIT_LOG --policy POLICY    draft rules from a monitor-mode log
    agent-sentinel audit verify AUDIT_LOG               check the audit log's hash chain (and MACs)
    agent-sentinel demo                                 see the firewall and the proxy at work

This module only builds the argument parser and hands each command to the
module that does its work, agent_sentinel/cli_<command>.py (see cli_common.py
for what such a module provides). The proxy parses its own arguments, in
mcp_proxy.py. A command module that sets TAKES_SERVER_COMMAND gets what
follows the first "--" as `args.server_command`, word for word.

Everything printed may contain untrusted text (file contents, tool names
from an audit log), so the command modules pass it through `printable` first.
"""

from __future__ import annotations

import argparse
import importlib
import sys
from typing import Any

from . import __version__
from .cli_common import EXIT_ERROR, CommandError, print_error
from .textutil import printable

# The commands, in the order --help lists them: each is run by the module agent_sentinel/cli_<name>.py.
_COMMAND_NAMES = (
    "init", "inspect", "clients", "wrap", "unwrap", "doctor", "hook", "pins", "check", "test", "validate", "scan",
    "report", "explain", "suggest", "audit", "demo",
)


def _commands() -> tuple[tuple[str, Any], ...]:
    """Each command's name and the module that runs it.

    The modules are loaded here, not when this one is: Claude Code starts
    `hook claude-code` anew for every event, and that command needs none of
    the others (see main).
    """
    return tuple((name, importlib.import_module(f".cli_{name}", __package__)) for name in _COMMAND_NAMES)


def __getattr__(name: str) -> Any:
    """_COMMANDS, the commands with their modules as 0.5 had them, for code that lists them (tests do)."""
    if name == "_COMMANDS":
        return _commands()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# Exit code for a command stopped with Ctrl+C, as shells report it.
_EXIT_INTERRUPTED = 130


def _make_output_safe() -> None:
    """Never crash on a character the console cannot show (common on Windows)."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")


def _build_parser() -> tuple[argparse.ArgumentParser, dict[str, argparse.ArgumentParser]]:
    """The parser, and the parser of each command (for error messages that show the command's usage)."""
    parser = argparse.ArgumentParser(prog="agent-sentinel", description="A firewall for AI agent tool calls.")
    parser.add_argument("--version", action="version", version=f"agent-sentinel {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    commands.add_parser("proxy", help="run an MCP server behind the firewall (see: proxy --help)")
    command_parsers = {}
    for name, module in _commands():
        command = commands.add_parser(
            name,
            help=module.HELP,
            usage=getattr(module, "USAGE", None),
            description=getattr(module, "DESCRIPTION", None) or module.HELP,
            epilog=getattr(module, "EPILOG", None),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        module.add_arguments(command)
        command.set_defaults(func=module.run, module=module)
        command_parsers[name] = command
    return parser, command_parsers


def _split_server_command(argv: list[str]) -> tuple[list[str], list[str] | None]:
    """Split "COMMAND [options] -- server words..." at the first "--", for the commands that start a server.

    argparse treats "--" differently from one Python version to the next, and
    the server's own words (its options, a second "--") must reach it exactly
    as written. None when there is no "--" or the command takes no server command.
    """
    takes = {name for name, module in _commands() if getattr(module, "TAKES_SERVER_COMMAND", False)}
    if argv[:1] and argv[0] in takes and "--" in argv:
        at = argv.index("--")
        return argv[:at], argv[at + 1:]
    return argv, None


def main(argv: list[str] | None = None) -> int:
    _make_output_safe()
    argv = sys.argv[1:] if argv is None else argv
    if argv[:2] == ["hook", "claude-code"]:
        # What Claude Code runs for every event: answered without loading the other commands.
        from . import cli_hook

        return cli_hook.run_event(argv[2:])
    if argv[:1] == ["proxy"]:  # the proxy parses its own arguments, including the '--' part
        from . import mcp_proxy

        mcp_proxy.exit_process(mcp_proxy.main(argv[1:]))  # does not return: see exit_process for why

    parser, command_parsers = _build_parser()
    argv, server_command = _split_server_command(argv)
    # parse_known_args, so that `check` can take name=value arguments after its options as
    # well as before them (argparse alone would refuse "check p.json tool --proxy a=1").
    args, extras = parser.parse_known_args(argv)
    if not hasattr(args, "func"):  # "proxy" reached here because something came before it, such as "--"
        parser.error("write 'proxy' first: agent-sentinel proxy --policy FILE -- COMMAND")
    if getattr(args.module, "TAKES_SERVER_COMMAND", False):
        args.server_command = server_command
    take_extras = getattr(args.module, "take_extra_arguments", None)
    if extras and (take_extras is None or not take_extras(args, extras)):
        command_parsers[args.command].error(f"unrecognized arguments: {printable(' '.join(extras), limit=200)}")
    try:
        return args.func(args)
    except CommandError as exc:
        print_error(str(exc))
        return EXIT_ERROR
    except OSError as exc:
        print_error(f"{exc.strerror or type(exc).__name__}: {exc.filename}" if exc.filename else str(exc))
        return EXIT_ERROR
    except KeyboardInterrupt:
        return _EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
