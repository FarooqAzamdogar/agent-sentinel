"""The shortened options that 0.5.0 took and a newer option would make ambiguous: kept, with their meaning.

The commands' parsers take a shortened option when it can only mean one
option ("--con" for --config). Each option added since can turn such a
shortening into an error: with wrap's --contain, "--con" could mean two
options. A script or a hook entry written for 0.5.0 would then stop
working, and a Claude Code hook that exits with an error blocks every tool
call. So every shortening that 0.5.0 read as one option, and that an option
added later made ambiguous, is listed here and still means what it meant.

    KEPT    command (as typed after agent-sentinel) -> {shortened option: the option it stands for}
    keep    register them on a command's parser (and on the parsers of its own subcommands)

Nothing here widens what a parser takes: a shortening that was ambiguous in
0.5.0 still is, and the proxy takes no shortened option at all (it never
did: mcp_proxy.py). When an option is added to a command, a shortening it
would break goes into KEPT (tests/test_shortened_options.py checks every
shortening 0.5.0 took).
"""

from __future__ import annotations

import argparse
from typing import Any, Callable

KEPT: dict[str, dict[str, str]] = {
    # check's --server, added in 0.6, made "--s" ambiguous with --show-rules, which 0.5.0 already had.
    "check": {"--h": "--help", "--s": "--show-rules"},
    "hook claude-code": {"--a": "--audit", "--au": "--audit", "--aud": "--audit", "--audi": "--audit"},
    "hook install": {
        "--au": "--audit", "--aud": "--audit", "--audi": "--audit",
        "--sc": "--scan-all-results", "--sca": "--scan-all-results", "--scan": "--scan-all-results",
        "--scan-": "--scan-all-results",
    },
    "wrap": {
        "--co": "--config", "--con": "--config",
        "--n": "--name",
        "--s": "--server", "--se": "--server",
    },
}


def keep(name: str, parser: argparse.ArgumentParser) -> None:
    """Make the parser of the command `name` take the shortened options KEPT lists for it, and for its own
    subcommands ("hook install").

    argparse looks a word up among a parser's option strings before it tries
    it as a shortening, so each kept shortening is registered as one more
    string of the option it stands for. It is not added to the option's own
    list, which is what --help prints, and an ambiguous shortening is still
    reported with the options' own names only (_without_kept).
    """
    kept = KEPT.get(name, {})
    for short, full in kept.items():
        action = parser._option_string_actions.get(full)
        if action is not None:
            parser._option_string_actions.setdefault(short, action)
    if kept:
        find = parser._get_option_tuples
        parser._get_option_tuples = _without_kept(find, frozenset(kept))  # type: ignore[method-assign]
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for sub_name, sub_parser in action.choices.items():
                keep(f"{name} {sub_name}", sub_parser)


def _without_kept(find: Callable[[str], list[Any]], kept: frozenset[str]) -> Callable[[str], list[Any]]:
    """A parser's search for the options a shortening may stand for, without the kept shortenings among them.

    Each kept shortening begins the name of the option it stands for, so
    that option is found too: what a word means does not change, and "--c"
    is reported as "could match --client, --config, --contain", not with
    "--co" and "--con" as well. (Each match is a tuple whose second item is
    the option string, in every Python version this runs on.)
    """
    def option_tuples(option_string: str) -> list[Any]:
        return [found for found in find(option_string) if found[1] not in kept]

    return option_tuples
