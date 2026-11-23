"""`agent-sentinel init`: write a first policy, from a template or from a server's real tool list.

    agent-sentinel init --template starter
    agent-sentinel init --template strict --root C:/work/app --out C:/policies/app.json
    agent-sentinel init -- npx -y @modelcontextprotocol/server-filesystem C:/work
    agent-sentinel init --trust-annotations -- python my_server.py

With --template, the policy is one of the templates in templates.py.

With a server command, the server is started and its tools listed through
the proxy (server_probe.py; no tool is called). The draft blocks by default
and names every tool exactly, each "allow" or "block":

  * on a terminal, you are asked about each tool (y/N), and shown what the
    server claims about it ("server says read-only (unverified)");
  * without a terminal, every tool is blocked, and the notes file says which
    ones the server calls read-only, as candidates to allow by hand;
  * --trust-annotations allows the tools the server calls read-only without
    asking. Annotations are the server's claims, so this is a choice to
    believe the server;
  * a tool the proxy removed (a poisoned description) is always blocked;
  * a name that is not plain (letters, digits, "_", "." and "-") is never
    written: in a policy "*" is a wildcard, and the default blocks it anyway.

The reasons for each choice go to a notes file beside the policy, because the
policy loader refuses keys it does not know.

The policy goes to <home>/policy.json (see home.py) unless --out names
another file. An existing file is never overwritten. Every path written is
printed in full.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
import textwrap
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from . import home, server_probe, templates
from .cli_common import EXIT_OK, CommandError, full_path, shown_command, shown_path
from .cli_inspect import timeout_seconds
from .policy import Policy, PolicyError
from .server_probe import ListedTool, ProbeResult
from .textutil import printable

HELP = "write a first policy: from a template (--template NAME), or from a server's tools (-- <server command>)"
DESCRIPTION = (
    "Write a first policy, either from a template or from the tools a real server lists. The policy goes to "
    "the agent-sentinel home folder (policy.json) unless --out names another file; an existing file is never "
    "overwritten."
)
_NAME_WIDTH = max(len(name) for name in templates.TEMPLATES) + 2
EPILOG = """\
templates:
""" + "".join(
    textwrap.fill(template.summary, width=100, initial_indent=f"  {name:{_NAME_WIDTH}}",
                  subsequent_indent=" " * (_NAME_WIDTH + 2)) + "\n"
    for name, template in templates.TEMPLATES.items()
) + """
examples:
  agent-sentinel init --template starter
  agent-sentinel init --template strict --root C:/work/app --out C:/policies/app.json
  agent-sentinel init -- npx -y @modelcontextprotocol/server-filesystem C:/work
"""
USAGE = """agent-sentinel init --template NAME [--out FILE] [--root DIR ...]
       agent-sentinel init [--out FILE] [--trust-annotations] [--timeout SECONDS] -- SERVER_COMMAND ..."""
TAKES_SERVER_COMMAND = True

# A tool name that may be written as a rule: exactly the name, never a wildcard.
PLAIN_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")

# Asks a person about one tool; True means allow.
Asker = Callable[[ListedTool], bool]


@dataclass
class Choice:
    """What the draft does with one tool, and why (the why goes to the notes file)."""

    tool: ListedTool
    action: str | None  # "allow", "block", or None when no rule is written
    why: str


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--template", choices=tuple(templates.TEMPLATES), help="write this template")
    parser.add_argument("--out", metavar="FILE",
                        help="where to write the policy (default: policy.json in the agent-sentinel home folder)")
    parser.add_argument("--root", action="append", default=[], metavar="DIR",
                        help="strict template: a folder the agent may use (repeat for more)")
    parser.add_argument("--trust-annotations", action="store_true",
                        help="with a server: allow, without asking, the tools the server says are read-only")
    parser.add_argument("--timeout", type=timeout_seconds, default=server_probe.DEFAULT_TIMEOUT_SECONDS,
                        metavar="SECONDS", help="with a server: give up if it has not answered by then")


def run(args: argparse.Namespace) -> int:
    command = args.server_command
    if (args.template is None) == (not command):
        raise CommandError(
            "give either --template NAME or a server command after '--', for example:\n"
            "  agent-sentinel init --template starter\n"
            "  agent-sentinel init -- npx -y @modelcontextprotocol/server-filesystem /path/to/folder"
        )
    if args.root and args.template != "strict":
        raise CommandError("--root sets the folders of the strict template; use it with --template strict")
    if args.trust_annotations and not command:
        raise CommandError("--trust-annotations is for a policy drafted from a server (init -- <server command>)")
    target = _target(args.out, notes=bool(command))
    if args.template is not None:
        return _from_template(args.template, _roots(args.root), target)
    return _from_server(command, target, args.trust_annotations, args.timeout)


# ---- where to write ----------------------------------------------------------------------------

@dataclass
class _Target:
    policy: Path
    notes: Path | None
    in_home: Path | None  # the home folder, when the policy goes there (it is created if missing)


def _target(out: str | None, notes: bool) -> _Target:
    """Where the policy (and the notes) go. Checked before anything else happens, so nothing is overwritten."""
    if out is None:
        folder = home.home_folder()
        policy, in_home = home.policy_file(folder), folder
    elif out == "-":
        raise CommandError("init writes files; give --out a file name")
    else:
        policy, in_home = Path(full_path(out)), None
        if not policy.parent.is_dir():
            raise CommandError(f"the folder {policy.parent} does not exist; create it first, or choose another --out")
    notes_path = _notes_path(policy) if notes else None
    for path in (policy, notes_path):
        if path is not None and os.path.lexists(path):
            raise CommandError(
                f"{path} already exists, and init never overwrites a file. Give --out a new file name"
                + ("" if out is not None else ", or move the existing file away")
            )
    return _Target(policy, notes_path, in_home)


def _notes_path(policy: Path) -> Path:
    """policy.json -> policy.notes.txt, beside it."""
    stem = policy.stem if policy.suffix.lower() == ".json" else policy.name
    return policy.with_name(f"{stem}.notes.txt")


def _write_new(path: Path, text: str) -> None:
    """Write a new file, readable by its owner only (0600 on POSIX): a policy may list canaries."""
    # O_EXCL: a file that appeared meanwhile is not replaced.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        with os.fdopen(os.open(path, flags, home.PRIVATE_FILE_MODE), "w", encoding="utf-8") as handle:
            handle.write(text)
    except FileExistsError as exc:
        raise CommandError(f"{path} already exists, and init never overwrites a file") from exc
    except OSError as exc:
        raise CommandError(f"cannot write {path}: {exc.strerror or exc}") from exc


def _prepare(target: _Target) -> None:
    """Create the home folder and its pins folder when the policy goes there, and say so."""
    if target.in_home is not None:
        for folder in home.make_folders(target.in_home):
            print(f"Created the folder {shown_path(folder)}")


def _layout(policy: dict[str, Any]) -> str:
    return json.dumps(policy, indent=2, ensure_ascii=False) + "\n"


def _checked(policy: dict[str, Any], what: str) -> Policy:
    """Load the draft with the strict loader before writing it: what init writes must pass `validate`."""
    try:
        return Policy.from_dict(copy.deepcopy(policy))
    except PolicyError as exc:
        raise CommandError(f"{what}: {exc}; nothing was written") from exc


# ---- --template ----------------------------------------------------------------------------------

def _roots(roots: list[str]) -> tuple[str, ...]:
    """--root folders as the policy will hold them: full paths ("~/..." is kept: the loader expands it)."""
    return tuple(root if root.startswith("~") else os.path.abspath(root) for root in roots)


def _from_template(name: str, roots: tuple[str, ...], target: _Target) -> int:
    policy = templates.template(name, roots)
    loaded = _checked(policy, "--root" if roots else f"the {name} template")
    _prepare(target)
    _write_new(target.policy, _layout(policy))
    print(f"Wrote the '{name}' template to {shown_path(target.policy)}")
    print(f"  {templates.TEMPLATES[name].summary}")
    for warning in _grouped(loaded.warnings()):
        print(f"  Warning: {printable(warning)}")
    steps = list(templates.TEMPLATES[name].next_steps)
    if name == "strict" and not roots:
        steps.insert(0, f"Change the folder {templates.STRICT_ROOT} in each \"roots\" to the folders the agent may "
                        "use (or write the policy again with --root).")
    _print_steps(steps, target.policy)
    return EXIT_OK


def _grouped(warnings: list[str]) -> list[str]:
    """Warnings that say the same after "where: " said once, with how many places in the policy they concern."""
    by_text: dict[str, list[str]] = {}
    for warning in warnings:
        where, _, text = warning.partition(": ")
        by_text.setdefault(text or where, []).append(where)
    return [text if len(places) == 1 else f"{text} (in {len(places)} places)" for text, places in by_text.items()]


def _print_steps(steps: list[str], policy: Path) -> None:
    try:
        audit = shown_path(home.audit_file(home.home_folder()))
    except home.HomeError:
        audit = "AUDIT_LOG"
    print("Next:")
    for number, step in enumerate(steps, start=1):
        print(f"  {number}. {step.format(policy=shown_path(policy), audit=audit)}")


# ---- -- <server command> --------------------------------------------------------------------------

def _from_server(command: list[str], target: _Target, trust_annotations: bool, timeout: float) -> int:
    result = server_probe.probe(command, None, timeout)
    if result.list_error and not result.tools:
        raise CommandError(f"{result.list_error}; nothing was written")
    asker = terminal_asker()
    if asker is not None and any(_needs_asking(tool, trust_annotations) for tool in result.tools):
        print(f"{printable(result.server_name or 'The server', limit=80)} lists {len(result.tools)} tool(s). "
              "For each, say whether the agent may call it (Enter means no).")
    choices = decide(result.tools, trust_annotations, asker)
    policy = draft(choices)
    _checked(policy, "the drafted policy")
    _prepare(target)
    _write_new(target.policy, _layout(policy))
    assert target.notes is not None
    _write_new(target.notes, notes_text(result, choices, target.policy, trust_annotations, asked=asker is not None))
    _print_summary(result, choices, target, asked=asker is not None)
    return EXIT_OK


def terminal_asker() -> Asker | None:
    """A y/N question per tool when a person is at the terminal; None otherwise (then nothing is allowed)."""
    try:
        interactive = sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        interactive = False
    if not interactive:
        return None

    def ask(tool: ListedTool) -> bool:
        print(f"\n{printable(tool.name, limit=100)}")
        if tool.description:
            print(f"  description (from the server): {printable(tool.description, limit=300)}")
        says = tool.says()
        print(f"  server says: {', '.join(says)} (unverified)" if says else "  server says nothing about what it does")
        try:
            answer = input("  Allow the agent to call it? [y/N] ")
        except EOFError:
            return False
        return answer.strip().lower() in ("y", "yes")

    return ask


def _needs_asking(tool: ListedTool, trust_annotations: bool) -> bool:
    return (tool.reaches_agent and PLAIN_NAME.fullmatch(tool.name) is not None
            and not (trust_annotations and tool.claims_read_only))


def decide(tools: list[ListedTool], trust_annotations: bool, asker: Asker | None) -> list[Choice]:
    """Choose allow or block for each tool (see the module docstring for the rules)."""
    choices = []
    for tool in tools:
        if PLAIN_NAME.fullmatch(tool.name) is None:
            choices.append(Choice(tool, None, (
                "not written: the name has characters other than letters, digits, '_', '.' and '-' (or is longer "
                "than 128); a rule for it could act as a wildcard. The default blocks it"
            )))
        elif not tool.reaches_agent:
            reason = printable(tool.removed_because or "removed by the proxy", limit=200)
            choices.append(Choice(tool, "block", f"removed by the proxy ({reason}); never allow it unread"))
        elif trust_annotations and tool.claims_read_only:
            choices.append(Choice(tool, "allow", "the server says it is read-only, and --trust-annotations was given"))
        elif asker is not None:
            allowed = asker(tool)
            choices.append(Choice(tool, "allow" if allowed else "block",
                                  "you allowed it" if allowed else "you did not allow it"))
        else:
            why = "no terminal to ask on, so it is blocked"
            if tool.claims_read_only:
                why += "; the server says it is read-only (unverified): a candidate to allow"
            choices.append(Choice(tool, "block", why))
    return choices


def draft(choices: list[Choice]) -> dict[str, Any]:
    """The policy: the baseline, plus one exact rule per tool with a plain name."""
    policy = templates.baseline_policy()
    for choice in choices:
        if choice.action is not None:
            policy["tools"][choice.tool.name] = choice.action
    return policy


# ---- the notes file and the summary -----------------------------------------------------------------

def notes_text(result: ProbeResult, choices: list[Choice], policy_path: Path, trust_annotations: bool,
               asked: bool) -> str:
    """The notes file. Every server text in it is made printable: the file may be shown on a terminal."""
    server = printable(result.server_name or "(no name)", limit=80)
    if result.server_version:
        server += f" {printable(result.server_version, limit=40)}"
    how = "asked on the terminal" if asked else "no terminal: every tool blocked"
    if trust_annotations:
        how += "; --trust-annotations: tools the server calls read-only allowed"
    lines = [
        f"Notes for {policy_path}",
        f"Drafted by agent-sentinel init on {datetime.now().strftime('%Y-%m-%d %H:%M')} from the tools of:",
        f"  {shown_command(result.command)}",
        f"Server: {server}, MCP {printable(result.protocol_version or '(no version)', limit=40)} ({how})",
        "",
        "agent-sentinel does not read this file: the policy loader refuses keys it does not know,",
        "so the reason for each rule is kept here.",
        "",
        f"Tools ({len(choices)}):",
    ]
    width = min(40, max([len(printable(choice.tool.name, limit=40)) for choice in choices] or [4]))
    for choice in choices:
        says = choice.tool.says()
        claim = f" Server says: {', '.join(says)} (unverified)." if says else ""
        lines.append(f"  {printable(choice.tool.name, limit=40):{width}}  {choice.action or '(none)':7} "
                     f"{choice.why}.{claim}")
    if result.malformed_entries:
        lines.append(f"  ({result.malformed_entries} entry(ies) of the list were not a tool with a usable name)")
    if result.truncated:
        lines.append(f"  (only the first {len(result.tools)} tools were looked at)")
    lines += [
        "",
        "MCP annotations (readOnlyHint, destructiveHint, ...) are what the server says about its own",
        "tools. Nothing checks them: a server can call a tool read-only that deletes files.",
        "",
        "To allow a tool, change its \"block\" to \"allow\" in the policy. Then:",
        f"  agent-sentinel validate {shown_path(policy_path)}",
        f"  agent-sentinel inspect --policy {shown_path(policy_path)} -- {shown_command(result.command)}",
        "",
    ]
    return "\n".join(lines)


def _print_summary(result: ProbeResult, choices: list[Choice], target: _Target, asked: bool) -> None:
    allowed = [choice for choice in choices if choice.action == "allow"]
    blocked = [choice for choice in choices if choice.action == "block"]
    removed = [choice for choice in choices if not choice.tool.reaches_agent]
    print(f"\nWrote a draft policy to {shown_path(target.policy)}")
    print(f"  {len(allowed)} tool(s) allowed, {len(blocked)} blocked"
          + (f" ({len(removed)} removed by the proxy for what their description says)" if removed else "")
          + "; every other tool is blocked by the default.")
    candidates = [choice for choice in blocked if choice.tool.claims_read_only and choice.tool.reaches_agent]
    if not asked:
        print("  There was no terminal to ask on, so no tool was allowed"
              + (" except those --trust-annotations allows" if allowed else "") + "."
              + (f" The server calls {len(candidates)} blocked tool(s) read-only (unverified); the notes list them "
                 "as candidates." if candidates else ""))
    print(f"Wrote the reasons to {shown_path(target.notes)}")
    command = shown_command(result.command)
    print("Next:")
    print(f"  1. Read both files, and allow what the agent needs: agent-sentinel validate {shown_path(target.policy)}")
    print(f"  2. See the result: agent-sentinel inspect --policy {shown_path(target.policy)} -- {command}")
    print(f"  3. Protect a client: agent-sentinel wrap --client claude-desktop --policy {shown_path(target.policy)}")
