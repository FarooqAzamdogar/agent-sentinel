"""`agent-sentinel pins`: look at a proxy's pins file, and accept or forget a pinned definition.

    agent-sentinel pins list   --pins FILE
    agent-sentinel pins show   --pins FILE [--kind KIND] [NAME]
    agent-sentinel pins diff   --pins FILE [--kind KIND] [--policy POLICY] [NAME ...]
    agent-sentinel pins accept --pins FILE [--kind KIND] [--policy POLICY] [--force] [NAME ...]
    agent-sentinel pins forget --pins FILE [--kind KIND] [NAME ...]
    agent-sentinel pins diff|accept|forget --pins FILE --server

KIND is tool (the default), prompt, template or instructions (which takes no NAME).

--server is about the server itself, pinned by proxy --pin-server (pins.py,
"The server itself"): how it is launched and the name and version it
reports. diff shows what differs, accept makes what the proxy last saw the
pin, forget removes the pin (the proxy pins the server again at its next start).

The proxy pins each tool, prompt, resource template and the server's
instructions the first time it sees them (pins.py). When a pinned
definition changes, the proxy removes that entry for as long as it runs, and
keeps the new definition beside the pins file, in "<pins file>.pending".

    list    every pin: when it was first seen, its fingerprint, and whether a change waits
    show    one pinned definition, as the server sent it
    diff    what changed: the pinned definition beside the new one, line by line, and what
            the scanner finds in the new one. Exit code 1 when a change waits, else 0
    accept  make the new definition the pinned one, after showing the change and asking
    forget  remove a pin, so that the proxy pins the next definition it sees

accept and forget are for the operator only: they ask for a yes on a
terminal and refuse to run without one, so neither an agent nor a script can
accept a change. accept scans the new definition again (the pending file is
a plain file, which anything that can write there could have edited) and
refuses one in which the scanner finds what the policy blocks
(injection.block_severity; "high" without --policy) unless --force is given.
Both copy the pins file to a backup first, write it atomically, and refuse
if the file changed while the person was deciding. A running proxy keeps
the pins it started with: restart it afterwards.

Everything the server wrote (names, definitions) is printed through
`printable`, and definitions as JSON with every character outside ASCII
escaped, so a look-alike letter or a hidden character shows as \\uXXXX.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .cli_common import EXIT_ERROR, EXIT_FAIL, EXIT_OK, CommandError, load_policy, shell_line, shown_path
from .firewall import Firewall
from .pins import (
    INFO_FIELDS,
    INSTRUCTIONS,
    KIND_WORDS,
    LAUNCH_FIELDS,
    PINNED_LISTS,
    Pin,
    PinsFile,
    PinsFileError,
    ServerPin,
    fingerprint,
    now,
    pending_path,
    read_pins_file,
    server_changes,
    write_pins_file,
)
from .policy import Policy
from .textutil import printable

HELP = "look at a proxy's pins, and accept or forget a pinned definition (pins list, show, diff, accept, forget)"
DESCRIPTION = (
    "Look at the definitions a proxy has pinned (--pins FILE), see what changed in one it removed, and, on a "
    "terminal, accept the new definition or forget the pin."
)
EPILOG = """\
examples:
  agent-sentinel pins list --pins ~/.agent-sentinel/pins/claude-desktop-github.json
  agent-sentinel pins diff --pins PINS                      every change that waits
  agent-sentinel pins accept --pins PINS create_issue       on a terminal: look, then answer y
  agent-sentinel pins accept --pins PINS --kind instructions
  agent-sentinel pins forget --pins PINS --kind prompt summarize
  agent-sentinel pins diff --pins PINS --server                how the server changed (proxy --pin-server)

After accept or forget, restart the proxy (restart the MCP client): a running proxy keeps its pins.
"""

ACTIONS = ("list", "show", "diff", "accept", "forget")
# --kind words, and the section of the pins file each one names.
SECTIONS = {word: section for section, word in KIND_WORDS.items()}
# The longest definition (in lines of indented JSON) compared line by line; longer ones are
# compared member by member only, so that a hostile definition cannot make the comparison slow.
MAX_DIFF_LINES = 2_000
# What a finding's excerpt is cut to when it is printed.
MAX_EXCERPT_CHARS = 160


def add_arguments(parser: argparse.ArgumentParser) -> None:
    actions = parser.add_subparsers(dest="pins_action", required=True, metavar="{" + ",".join(ACTIONS) + "}")
    helps = {
        "list": "every pin, and the changes that wait",
        "show": "one pinned definition",
        "diff": "what changed in a definition the proxy removed (exit code 1 when a change waits)",
        "accept": "on a terminal: make the new definition the pinned one",
        "forget": "on a terminal: remove a pin, so the next definition seen is pinned",
    }
    for action in ACTIONS:
        sub = actions.add_parser(action, help=helps[action], description=helps[action].capitalize() + ".")
        sub.add_argument("--pins", required=True, metavar="FILE", help="the pins file (proxy --pins)")
        if action == "list":
            continue
        sub.add_argument("--kind", choices=tuple(SECTIONS), default=None,
                         help="what NAME is: tool (the default), prompt, template, or instructions (no NAME)")
        if action in ("diff", "accept"):
            sub.add_argument("--policy", metavar="POLICY",
                             help="judge the new definition by this policy's injection.block_severity, and its tool "
                                  "names for shadowing (default: block at high)")
        if action == "accept":
            sub.add_argument("--force", action="store_true",
                             help="accept a definition even if the scanner finds what the policy would block")
        if action in ("diff", "accept", "forget"):
            sub.add_argument("--server", action="store_true",
                             help="the server itself (pinned by proxy --pin-server): how it is launched and what it "
                                  "says it is; takes no NAME")
        many = "*" if action in ("diff", "accept", "forget") else "?"
        sub.add_argument("names", nargs=many, metavar="NAME", help="the name of the tool, prompt or template")


def run(args: argparse.Namespace) -> int:
    path = Path(args.pins)
    if args.pins_action == "list":
        return _list(path)
    if getattr(args, "server", False):
        return _server_command(path, args)
    targets = _targets(args)
    if args.pins_action == "show":
        return _show(path, targets)
    if args.pins_action == "diff":
        return _diff(path, targets, _judge(args, path))
    if not on_a_terminal():
        raise CommandError(
            f"pins {args.pins_action} asks a person for a yes, so it runs only on a terminal "
            "(an agent or a script cannot change pins)"
        )
    if args.pins_action == "accept":
        return _accept(path, targets, _judge(args, path), args.force)
    return _forget(path, targets)


def on_a_terminal() -> bool:
    """Whether a person can be asked: stdin and stdout are both a terminal."""
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


# ---- what the command line names ----------------------------------------------------------------

@dataclass(frozen=True)
class Target:
    """One entry of a pins file: its section (PINNED_LISTS or INSTRUCTIONS), and its name (None for instructions)."""

    section: str
    name: str | None

    def __str__(self) -> str:
        if self.section == INSTRUCTIONS:
            return "the server's instructions"
        return f"{KIND_WORDS[self.section]} '{printable(self.name, limit=100)}'"


def _targets(args: argparse.Namespace) -> list[Target] | None:
    """The entries the command line names; None for "every entry" (diff without names)."""
    names = args.names if isinstance(args.names, list) else ([args.names] if args.names else [])
    section = SECTIONS[args.kind] if args.kind else None
    if section == INSTRUCTIONS:
        if names:
            raise CommandError("--kind instructions takes no NAME: a server has one set of instructions")
        return [Target(INSTRUCTIONS, None)]
    if not names:
        if args.pins_action == "diff":
            return None if section is None else [Target(section, None)]  # every change of that kind
        raise CommandError(f"pins {args.pins_action} needs the NAME of a tool, prompt or template "
                           "(or --kind instructions)")
    return [Target(section or "tools", name) for name in dict.fromkeys(names)]


# ---- reading the files --------------------------------------------------------------------------

def _read_pins(path: Path) -> tuple[PinsFile, bytes]:
    """The pins file, and its bytes as read (to see later whether it changed meanwhile)."""
    try:
        data = path.read_bytes()
        return read_pins_file(path), data
    except FileNotFoundError:
        raise CommandError(f"there is no pins file at {os.path.abspath(path)}") from None
    except PinsFileError as exc:
        raise CommandError(f"cannot use the pins file: {exc}") from None
    except OSError as exc:
        raise CommandError(f"cannot read the pins file {path}: {exc.strerror or type(exc).__name__}") from None


def _read_pending(path: Path) -> PinsFile:
    """The changes that wait beside a pins file (none if there is no pending file)."""
    waiting = pending_path(path)
    try:
        return read_pins_file(waiting)
    except FileNotFoundError:
        return PinsFile()
    except PinsFileError as exc:
        raise CommandError(f"cannot use the file of changes that wait: {exc}") from None
    except OSError as exc:
        raise CommandError(f"cannot read {waiting}: {exc.strerror or type(exc).__name__}") from None


def _pin_of(pins: PinsFile, target: Target) -> Pin | None:
    if target.section == INSTRUCTIONS:
        return pins.instructions
    return pins.lists[target.section].get(target.name or "")


def _entries(pins: PinsFile) -> list[tuple[Target, Pin]]:
    """Every pin of a file, section by section, in the order they were pinned."""
    entries = [(Target(section, name), pin) for section in PINNED_LISTS for name, pin in pins.lists[section].items()]
    if pins.instructions is not None:
        entries.append((Target(INSTRUCTIONS, None), pins.instructions))
    return entries


def _waiting(pins: PinsFile, pending: PinsFile, targets: list[Target] | None) -> list[tuple[Target, Pin]]:
    """The changes that wait and are not yet the pinned definition, of the entries named (None: all)."""
    found = []
    for target, new in _entries(pending):
        if targets is not None and not any(
            wanted.section == target.section and wanted.name in (None, target.name) for wanted in targets
        ):
            continue
        old = _pin_of(pins, target)
        if old is not None and old.sha256 == new.sha256:
            continue  # accepted already
        found.append((target, new))
    return found


# ---- list and show --------------------------------------------------------------------------------

def _list(path: Path) -> int:
    pins, _ = _read_pins(path)
    pending = _read_pending(path)
    waiting = {(target.section, target.name) for target, _ in _waiting(pins, pending, None)}
    print(f"Pins file: {shown_path(os.path.abspath(path))} (version {pins.version} on disk)")
    for section in PINNED_LISTS:
        entries = pins.lists[section]
        print(f"\n{KIND_WORDS[section]}s ({len(entries)})")
        for name, pin in entries.items():
            print(f"  {_pin_line(name, pin, (section, name) in waiting)}")
        for target, _ in _waiting(pins, pending, [Target(section, None)]):
            if target.name not in entries:
                print(f"  {printable(target.name, limit=100)}  not pinned; a definition waits (pins diff)")
    if pins.instructions is not None:
        print(f"\ninstructions\n  {_pin_line(None, pins.instructions, (INSTRUCTIONS, None) in waiting)}")
    else:
        print("\ninstructions: none pinned")
    server_waits = _server_waiting(pins, pending) is not None
    if pins.server is not None or server_waits:
        _print_server_summary(pins.server, server_waits)
    if waiting:
        print(f"\n{len(waiting)} change(s) wait: {shell_line(['agent-sentinel', 'pins', 'diff', '--pins', str(path)])}")
    if server_waits:
        command = shell_line(["agent-sentinel", "pins", "diff", "--server", "--pins", str(path)])
        print(f"\nThe server changed: {command}")
    return EXIT_OK


def _pin_line(name: str | None, pin: Pin, changed: bool) -> str:
    parts = [] if name is None else [printable(name, limit=100)]
    if pin.sha256_v1 is not None:
        parts.append(f"pinned by agent-sentinel 0.4 (sha256 {pin.sha256_v1[:12]}); its definition is not known")
    else:
        parts.append(f"first seen {printable(pin.first_seen or '?', limit=40)}, sha256 {(pin.sha256 or '?')[:12]}")
        if pin.definition is None:
            parts.append("(too large to keep: fingerprint only)")
    if changed:
        parts.append("CHANGED: a new definition waits (pins diff)")
    return "  ".join(parts)


def _show(path: Path, targets: list[Target] | None) -> int:
    pins, _ = _read_pins(path)
    assert targets is not None
    target = targets[0]
    pin = _pin_of(pins, target)
    if pin is None:
        raise CommandError(f"{target} is not pinned in {path}")
    print(f"{target}: {_pin_line(None, pin, False)}")
    if pin.definition is None:
        print("The definition is not stored, only its fingerprint.")
        return EXIT_OK
    print("Definition, as the server sent it (characters outside ASCII written as \\uXXXX):")
    for line in definition_lines(pin.definition):
        print(f"  {printable(line, limit=100_000)}")
    return EXIT_OK


def definition_lines(definition: dict[str, Any]) -> list[str]:
    """A definition as indented JSON lines, keys sorted, every character outside ASCII escaped."""
    return json.dumps(definition, indent=2, sort_keys=True, ensure_ascii=True).splitlines()


# ---- diff --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class _Judge:
    """How a new definition is judged: the policy's threshold, and the tool names of other servers."""

    firewall: Firewall
    foreign_tools: frozenset[str]

    @property
    def threshold(self) -> str | None:
        return self.firewall.policy.block_severity


def _judge(args: argparse.Namespace, path: Path) -> _Judge:
    policy = Policy()
    if getattr(args, "policy", None):
        loaded = load_policy(args.policy)
        if loaded is None:
            raise CommandError("the policy cannot be loaded (see above)")
        policy = loaded
    firewall = Firewall(policy)  # no audit log: nothing here is a decision about traffic
    try:
        own = set(read_pins_file(path).lists["tools"])
    except (OSError, ValueError):
        own = set()
    return _Judge(firewall, firewall.foreign_tool_names(own))


def _diff(path: Path, targets: list[Target] | None, judge: _Judge) -> int:
    pins, _ = _read_pins(path)
    waiting = _waiting(pins, _read_pending(path), targets)
    if targets is not None and any(target.name is not None for target in targets):
        missing = [target for target in targets if not any(found == target for found, _ in waiting)]
        for target in missing:
            print(f"{target}: no change waits")
    if not waiting:
        if targets is None:
            print("No change waits: every definition the proxy saw matches its pin.")
        return EXIT_OK
    for number, (target, new) in enumerate(waiting):
        if number:
            print()
        _print_change(target, _pin_of(pins, target), new, judge)
    print(f"\n{len(waiting)} change(s) wait. To accept one, on a terminal: agent-sentinel pins accept --pins "
          f"{shown_path(path)} [--kind KIND] NAME")
    return EXIT_FAIL


def _print_change(target: Target, old: Pin | None, new: Pin, judge: _Judge) -> None:
    """Print one change: the pinned definition beside the new one, then what the scanner finds in the new one."""
    seen = printable(new.first_seen or "?", limit=40)
    print(f"{target}: changed (the new definition was seen {seen})")
    if new.definition is None:
        print("  The new definition was too large to keep, so it cannot be shown or accepted. To pin it, forget the")
        print("  old pin (pins forget) and restart the proxy: the next definition it sees is pinned as it is.")
        return
    if old is None:
        print("  It is not pinned now: the proxy pins the next definition it sees. The new one:")
        _print_lines("+", definition_lines(new.definition))
    elif old.definition is None:
        why = "it was pinned by agent-sentinel 0.4" if old.sha256_v1 is not None else "it was too large to keep"
        print(f"  The pinned definition is not stored ({why}). The new one:")
        _print_lines("+", definition_lines(new.definition))
    else:
        _print_comparison(old.definition, new.definition)
    _print_findings(target, new.definition, judge)


def _print_comparison(old: dict[str, Any], new: dict[str, Any]) -> None:
    changed = sorted(key for key in set(old) | set(new) if old.get(key, _MISSING) != new.get(key, _MISSING))
    print(f"  Changed: {', '.join(printable(key, limit=60) for key in changed)}")
    before, after = definition_lines(old), definition_lines(new)
    if len(before) > MAX_DIFF_LINES or len(after) > MAX_DIFF_LINES:
        print(f"  (too long to compare line by line: {len(before)} and {len(after)} lines; use pins show)")
        return
    for line in list(difflib.unified_diff(before, after, "pinned", "new", lineterm="", n=2)):
        print(f"  {printable(line, limit=100_000)}")


_MISSING = object()


def _print_lines(mark: str, lines: list[str]) -> None:
    for line in lines[:MAX_DIFF_LINES]:
        print(f"  {mark}{printable(line, limit=100_000)}")
    if len(lines) > MAX_DIFF_LINES:
        print(f"  ... {len(lines) - MAX_DIFF_LINES} more line(s): use pins show after accepting, or the pending file")


def _findings(target: Target, definition: dict[str, Any], judge: _Judge) -> tuple[list[Any], bool]:
    """What the scanner finds in a definition, read as the proxy reads it, and whether it reaches the threshold."""
    if target.section == INSTRUCTIONS:
        decision = judge.firewall.scan_result("instructions", definition.get(INSTRUCTIONS, ""),
                                              event="server_instructions", log_clean=False)
    else:
        event = "tool_description" if target.section == "tools" else "list_item"
        foreign = judge.foreign_tools if target.section == "tools" else frozenset()
        decision = judge.firewall.scan_result(target.name or "?", definition, event=event, log_clean=False,
                                              foreign_tools=foreign)
    return decision.findings, not decision.allowed


def _print_findings(target: Target, definition: dict[str, Any], judge: _Judge) -> None:
    findings, blocks = _findings(target, definition, judge)
    if not findings:
        print("  Scanner: nothing found in the new definition.")
        return
    threshold = judge.threshold or "nothing (block_severity is null)"
    print(f"  Scanner, on the new definition (the policy blocks from {threshold}):")
    for finding in findings:
        excerpt = printable(judge.firewall.shown_excerpt(finding.excerpt), limit=MAX_EXCERPT_CHARS)
        print(f"    {finding.severity:6}  {printable(finding.rule, limit=60)}: {excerpt}")
    if blocks:
        print("  The proxy would remove it for these findings even if it were accepted.")


# ---- accept and forget ------------------------------------------------------------------------

def _accept(path: Path, targets: list[Target] | None, judge: _Judge, force: bool) -> int:
    assert targets is not None
    pins, original = _read_pins(path)
    pending = _read_pending(path)
    waiting = dict(_waiting(pins, pending, targets))
    for target in targets:
        if target not in waiting:
            raise CommandError(f"no new definition of {target} waits in {pending_path(path)}. The proxy keeps one "
                               "there when a pinned definition changes (it needs --pins)")
    accepted = []
    for target in targets:
        new = waiting[target]
        _print_change(target, _pin_of(pins, target), new, judge)
        if new.definition is None:
            continue
        _, blocks = _findings(target, new.definition, judge)
        if blocks and not force:
            print(f"  Not accepted: the scanner finds what the policy blocks. Read it closely; to accept it anyway, "
                  "add --force (the proxy would still remove it, unless the policy's block_severity allows it).")
            continue
        if not _yes(f"Accept this as the pinned definition of {target}?"):
            print("  Not accepted.")
            continue
        accepted.append((target, Pin(sha256=fingerprint(new.definition), first_seen=now(), definition=new.definition)))
    if not accepted:
        return EXIT_FAIL
    for target, pin in accepted:
        _set_pin(pins, target, pin)
        _set_pin(pending, target, None)
    backup = _write(path, pins, original)
    _write_pending(path, pending)
    for target, _ in accepted:
        print(f"Accepted {target}.")
    _print_after(path, backup)
    return EXIT_OK if len(accepted) == len(targets) else EXIT_FAIL


def _forget(path: Path, targets: list[Target] | None) -> int:
    assert targets is not None
    pins, original = _read_pins(path)
    pending = _read_pending(path)
    for target in targets:
        if _pin_of(pins, target) is None:
            raise CommandError(f"{target} is not pinned in {path}")
    forgotten = []
    for target in targets:
        question = (f"Forget the pin of {target}? The next definition the proxy sees is pinned as it is, "
                    "compared with nothing.")
        if _yes(question):
            forgotten.append(target)
        else:
            print("  Kept.")
    if not forgotten:
        return EXIT_FAIL
    for target in forgotten:
        _set_pin(pins, target, None)
        _set_pin(pending, target, None)
    backup = _write(path, pins, original)
    _write_pending(path, pending)
    for target in forgotten:
        print(f"Forgot {target}.")
    _print_after(path, backup)
    return EXIT_OK if len(forgotten) == len(targets) else EXIT_FAIL


def _yes(question: str) -> bool:
    try:
        answer = input(f"{question} [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def _set_pin(pins: PinsFile, target: Target, pin: Pin | None) -> None:
    if target.section == INSTRUCTIONS:
        pins.instructions = pin
    elif pin is None:
        pins.lists[target.section].pop(target.name or "", None)
    else:
        pins.lists[target.section][target.name or ""] = pin


def _write(path: Path, pins: PinsFile, original: bytes) -> Path:
    """Back up the pins file, then write it atomically; refuse if it changed since it was read. Returns the backup."""
    try:
        if path.read_bytes() != original:
            raise CommandError("the pins file changed while you were deciding (a proxy pinned something new); "
                               "nothing was written. Run the command again")
        backup = _backup(path, original)
        write_pins_file(path, pins)
    except OSError as exc:
        raise CommandError(f"cannot write the pins file {path}: {exc.strerror or type(exc).__name__}") from None
    return backup


def _backup(path: Path, data: bytes) -> Path:
    """Copy the pins file's bytes to <file>.<time>.bak, never over an existing file."""
    stamp = now().replace(":", "").replace("-", "")
    for number in range(100):
        backup = path.with_name(f"{path.name}.{stamp}{f'-{number}' if number else ''}.bak")
        try:
            with open(backup, "xb") as handle:
                handle.write(data)
            return backup
        except FileExistsError:
            continue
    raise CommandError(f"cannot find a free name for a backup of {path}")


def _write_pending(path: Path, pending: PinsFile) -> None:
    """Write what still waits, or remove the pending file when nothing does."""
    waiting = pending_path(path)
    try:
        if _entries(pending) or pending.server is not None:
            write_pins_file(waiting, pending)
        elif waiting.exists():
            waiting.unlink()
    except OSError as exc:
        print(f"agent-sentinel: could not update {printable(str(waiting), limit=300)}: "
              f"{exc.strerror or type(exc).__name__}", file=sys.stderr)


# ---- the server itself (--server) ----------------------------------------------------------------

def _server_command(path: Path, args: argparse.Namespace) -> int:
    """pins diff|accept|forget --server: the server's own pin (proxy --pin-server)."""
    if args.names or args.kind:
        raise CommandError("--server is about the server itself: it takes no NAME and no --kind")
    if args.pins_action == "diff":
        return _diff_server(path)
    if not on_a_terminal():
        raise CommandError(f"pins {args.pins_action} asks a person for a yes, so it runs only on a terminal "
                           "(an agent or a script cannot change pins)")
    if args.pins_action == "accept":
        return _accept_server(path)
    return _forget_server(path)


def _server_waiting(pins: PinsFile, pending: PinsFile) -> ServerPin | None:
    """The server identity that waits in the pending file and is not the pin already; None when none does."""
    new = pending.server
    if new is None:
        return None
    old = pins.server
    if old is not None and not server_changes(old.launch, new.launch) and (
            new.info is None or (old.info is not None and not server_changes(old.info, new.info))):
        return None  # accepted already
    return new


def _shown_value(value: str | None) -> str:
    return "(none)" if value is None else repr(printable(value, limit=1000))


def _print_server_summary(pin: ServerPin | None, changed: bool) -> None:
    print("\nserver (proxy --pin-server)")
    if pin is None:
        print("  not pinned; a new identity waits (pins diff --server)")
        return
    launch = pin.launch.get("package") or pin.launch.get("script") or pin.launch.get("executable")
    says = (f", reports {_shown_value(pin.info.get('name'))} {_shown_value(pin.info.get('version'))}"
            if pin.info is not None else ", has not answered a handshake yet")
    print(f"  first seen {printable(pin.first_seen or '?', limit=40)}: launched as {_shown_value(launch)}{says}"
          + ("  CHANGED: a new identity waits (pins diff --server)" if changed else ""))


def _print_server_change(old: ServerPin | None, new: ServerPin) -> None:
    """The pinned identity beside the one seen, field by field (names and values printable)."""
    print(f"the server: changed (seen {printable(new.first_seen or '?', limit=40)})")
    for section, fields, pinned, seen in (("launch", LAUNCH_FIELDS, old.launch if old else None, new.launch),
                                          ("info", INFO_FIELDS, old.info if old else None, new.info)):
        if seen is None:
            print(f"  {section}: not seen yet (the proxy pins it at the next start once this is accepted)")
            continue
        changed = set(server_changes(pinned, seen)) if pinned is not None else set(fields)
        for name in fields:
            after = _shown_value(seen.get(name))
            if name in changed:
                before = _shown_value(pinned.get(name)) if pinned is not None else "(not pinned)"
                print(f"  {section}.{name}: CHANGED  pinned {before}  now {after}")
            else:
                print(f"  {section}.{name}: {after}")


def _diff_server(path: Path) -> int:
    pins, _ = _read_pins(path)
    new = _server_waiting(pins, _read_pending(path))
    if new is None:
        print("No change of the server waits." + ("" if pins.server is not None else
                                                  " (The server is not pinned: the proxy pins it with --pin-server.)"))
        return EXIT_OK
    _print_server_change(pins.server, new)
    print(f"\nTo accept it, on a terminal: agent-sentinel pins accept --server --pins {shown_path(path)}")
    return EXIT_FAIL


def _accept_server(path: Path) -> int:
    pins, original = _read_pins(path)
    pending = _read_pending(path)
    new = _server_waiting(pins, pending)
    if new is None:
        raise CommandError(f"no new identity of the server waits in {pending_path(path)}. The proxy keeps one there "
                           "when a server pinned with --pin-server changes")
    _print_server_change(pins.server, new)
    if not _yes("Accept this as the pinned server?"):
        print("  Not accepted.")
        return EXIT_FAIL
    pins.server = ServerPin(launch=dict(new.launch), info=dict(new.info) if new.info is not None else None,
                            first_seen=now())
    pending.server = None
    backup = _write(path, pins, original)
    _write_pending(path, pending)
    print("Accepted the server as it is now.")
    _print_after(path, backup)
    return EXIT_OK


def _forget_server(path: Path) -> int:
    pins, original = _read_pins(path)
    pending = _read_pending(path)
    if pins.server is None:
        raise CommandError(f"the server is not pinned in {path}")
    if not _yes("Forget the server's pin? The proxy pins the server as it finds it at its next start."):
        print("  Kept.")
        return EXIT_FAIL
    pins.server = None
    pending.server = None
    backup = _write(path, pins, original)
    _write_pending(path, pending)
    print("Forgot the server's pin.")
    _print_after(path, backup)
    return EXIT_OK


def _print_after(path: Path, backup: Path) -> None:
    print(f"Pins file: {shown_path(os.path.abspath(path))} (the old one is in {shown_path(backup)})")
    print("Next: restart the proxy (restart the MCP client). A running proxy keeps the pins it started with, and "
          "an entry it removed stays removed until it restarts.")
