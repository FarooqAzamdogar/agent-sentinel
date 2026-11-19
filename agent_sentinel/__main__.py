"""Command line for agent-sentinel.

    agent-sentinel proxy --policy policy.json -- <mcp server command...>
    agent-sentinel check POLICY TOOL [name=value ...]   try one call against a policy
    agent-sentinel test POLICY CASES.json               run a policy's test cases (for CI)
    agent-sentinel validate POLICY                      check that a policy file is well formed
    agent-sentinel scan [FILE ...]                      scan text (or stdin) for prompt injection
    agent-sentinel report AUDIT_LOG                     summarize an audit log
    agent-sentinel explain AUDIT_LOG [--ref REF]        say why calls were blocked, and how to allow them
    agent-sentinel suggest AUDIT_LOG --policy POLICY    draft rules from a monitor-mode log
    agent-sentinel demo                                 see the firewall and the proxy at work

This module only builds the argument parser and hands each command to the
module that does its work, agent_sentinel/cli_<command>.py (see cli_common.py
for what such a module provides). The proxy parses its own arguments, in
mcp_proxy.py.

Everything printed may contain untrusted text (file contents, tool names
from an audit log), so the command modules pass it through `printable` first.
"""

from __future__ import annotations

import argparse
import sys

from . import (
    __version__,
    cli_check,
    cli_demo,
    cli_explain,
    cli_report,
    cli_scan,
    cli_suggest,
    cli_test,
    cli_validate,
    mcp_proxy,
)
from .cli_common import EXIT_ERROR, CommandError, print_error
from .textutil import printable

# The commands, in the order --help lists them: name and the module that runs it.
_COMMANDS = (
    ("check", cli_check),
    ("test", cli_test),
    ("validate", cli_validate),
    ("scan", cli_scan),
    ("report", cli_report),
    ("explain", cli_explain),
    ("suggest", cli_suggest),
    ("demo", cli_demo),
)

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
    for name, module in _COMMANDS:
        command = commands.add_parser(
            name,
            help=module.HELP,
            description=getattr(module, "DESCRIPTION", None) or module.HELP,
            epilog=getattr(module, "EPILOG", None),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        module.add_arguments(command)
        command.set_defaults(func=module.run, module=module)
        command_parsers[name] = command
    return parser, command_parsers


def main(argv: list[str] | None = None) -> int:
    _make_output_safe()
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["proxy"]:  # the proxy parses its own arguments, including the '--' part
        mcp_proxy.exit_process(mcp_proxy.main(argv[1:]))  # does not return: see exit_process for why

    parser, command_parsers = _build_parser()
    # parse_known_args, so that `check` can take name=value arguments after its options as
    # well as before them (argparse alone would refuse "check p.json tool --proxy a=1").
    args, extras = parser.parse_known_args(argv)
    if not hasattr(args, "func"):  # "proxy" reached here because something came before it, such as "--"
        parser.error("write 'proxy' first: agent-sentinel proxy --policy FILE -- COMMAND")
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
