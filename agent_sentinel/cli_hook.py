"""`agent-sentinel hook`: enforce the policy inside Claude Code, through its hooks.

    agent-sentinel hook claude-code --policy FILE [--audit FILE] [--state-dir DIR] [--no-log-args]
        What Claude Code runs. Reads one hook event as JSON on stdin and prints
        the answer (see claude_hooks.py). Exits 0, or 2 to block; never anything else.

    agent-sentinel hook install claude-code --policy FILE [--settings FILE] [--audit FILE] [--state-dir DIR]
                                            [--scan-all-results | --scan-subagent-reports] [--no-log-args] [--apply]
        Prints the hooks to add to a Claude Code settings file. With --settings,
        shows the change to that file; with --apply as well, makes it, after a
        backup (config_file.py: the rest of the file is kept byte for byte).
        The hooks: SessionStart, PreToolUse, PostToolUse and PostToolUseFailure
        (the tool calls), Elicitation and ElicitationResult (what an MCP server
        asks the user, and the answer), and ConfigChange (settings files and
        skills changed during a session).

Both also take the audit options of the proxy: --audit-key-file FILE (sign
every record), --audit-required (block a call whose record cannot be
written) and --audit-max-bytes BYTES (rotate the log); install writes them
into the hook entries.

The hooks run this Python with absolute paths for the policy, the audit log
and the state folder, in exec form (no shell), with "onFailure": "block" so
that a hook that cannot start, crashes or times out blocks the call. That
field needs Claude Code v2.1.295 or later; older versions let the call through.

Other clients with hooks (Codex, Cursor, VS Code Copilot, the Antigravity
CLI) use other formats, and several of them let a call through when a hook
fails. Supporting them is later work.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

from . import __version__, audit_chain, claude_hooks, home
from .claude_hooks import HookAnswer, HookSettings
from .cli_common import EXIT_ERROR, EXIT_OK, INSTALL_COMMAND, CommandError, full_path, load_policy, shown_path
from .firewall import new_ref
from .leaks import redact_value
from .policy import Policy
from .textutil import printable

# Claude Code starts `hook claude-code` anew for every event, so this module loads at its top only what
# answering an event needs. What only `hook install` uses (the client configurations, the settings file
# editor, the checks of this Python) is imported inside the functions that use it.
if TYPE_CHECKING:
    from .config_file import ConfigFile
    from .wrapping import PythonCheck

HELP = "enforce the policy inside Claude Code through its hooks (hook claude-code, hook install claude-code)"
DESCRIPTION = (
    "Enforce the policy inside Claude Code, through its hooks: tool calls and what they return, what MCP servers "
    "ask the user (elicitation), and changes to its settings. 'hook install claude-code' prints the settings to "
    "add (and with --settings FILE --apply, adds them); 'hook claude-code' is what Claude Code runs for each event."
)
EPILOG = """\
examples:
  agent-sentinel hook install claude-code --policy C:/Users/me/.agent-sentinel/policy.json
      print the hooks to add
  agent-sentinel hook install claude-code --policy ~/.agent-sentinel/policy.json --settings ~/.claude/settings.json
      show the change to that settings file; add --apply to make it (after a backup)

Codex, Cursor, VS Code (Copilot) and the Antigravity CLI are not supported yet.
"""

# How long Claude Code waits for one hook run, in seconds. A timeout blocks the call ("onFailure": "block").
HOOK_TIMEOUT_SECONDS = 60
# What the PostToolUse hooks scan by default: what comes from the web and from MCP servers, MCP resources
# included (see claude_hooks.RESULTS_MATCHER). The PreToolUse hook sets the flow marks of the other tools itself.
RESULTS_MATCHER = claude_hooks.RESULTS_MATCHER
# With --scan-subagent-reports: the default, and the tools that hand Claude a subagent's report.
SUBAGENT_RESULTS_MATCHER = "|".join((RESULTS_MATCHER, *claude_hooks.SUBAGENT_REPORT_TOOLS))
# ConfigChange: every source Claude Code reports. Letters, "_" and "|" only, so an exact list, not a pattern.
CONFIG_MATCHER = "|".join(claude_hooks.CONFIG_SOURCES)
ALL = "*"
# Claude Code's own tools that the hook templates have a rule for. A policy written for MCP servers blocks
# them all when its default is "block", including the ones Claude uses to ask the user something or to
# leave plan mode, to read MCP resources, to look up a tool it has not loaded yet (ToolSearch), to run a
# skill, or to hand back a subagent's report in auto mode. `hook install` warns about those it blocks.
BUILT_IN_TOOLS = (
    "Read", "Glob", "Grep", "Edit", "Write", "NotebookEdit", "Bash", "WebFetch", "WebSearch", "Agent",
    "AskUserQuestion", "ExitPlanMode", "SubagentHandback", "ReadMcpResourceTool", "ListMcpResourcesTool", "Monitor",
    "MultiEdit", "PowerShell", "Task", "TodoWrite", "EnterPlanMode", "ToolSearch", "Skill", "TaskCreate",
    "TaskUpdate", "TaskList", "TaskGet", "TaskOutput", "TaskStop", "BashOutput", "KillShell",
)
# More of Claude Code's own tools, which the hook templates leave without a rule (so they are refused there):
# what they do depends on how they are used. `hook install` names the ones a policy has no rule for.
OTHER_BUILT_IN_TOOLS = (
    "EnterWorktree", "ExitWorktree", "LSP", "CronCreate", "CronDelete", "CronList", "SendMessage", "ListAgents",
)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="hook_command", required=True, metavar="{claude-code,install}")
    run_parser = commands.add_parser(
        "claude-code", help="answer one Claude Code hook event (what Claude Code runs; the event comes on stdin)",
        description="Answer one Claude Code hook event, read as JSON on stdin. Exits 0, or 2 to block.",
    )
    _add_paths(run_parser)
    install = commands.add_parser(
        "install", help="print the Claude Code hooks to add; with --settings FILE --apply, add them",
        description=(
            "Print the hooks that run agent-sentinel inside Claude Code. With --settings FILE, show the change to "
            "that settings file; with --apply too, make it, after a backup."
        ),
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    install.add_argument("client", choices=("claude-code",), help="the client (only claude-code for now)")
    _add_paths(install)
    install.add_argument("--settings", metavar="FILE",
                         help="the Claude Code settings file to change, e.g. ~/.claude/settings.json "
                              "(without it, the hooks are only printed)")
    results = install.add_mutually_exclusive_group()
    results.add_argument("--scan-all-results", action="store_true",
                         help="scan what every tool returns, not only WebFetch, WebSearch, MCP tools and MCP "
                              "resources")
    results.add_argument("--scan-subagent-reports", action="store_true",
                         help="also scan a subagent's report (Agent, SubagentHandback). A flagged report stops the "
                              "whole agent, so this is off by default")
    install.add_argument("--apply", action="store_true", help="write the change (after a backup); needs --settings")


def _add_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy", required=True, metavar="FILE", help="the policy")
    parser.add_argument("--audit", metavar="FILE",
                        help="the audit log (hook claude-code: none if left out; install: audit.jsonl in the "
                             "agent-sentinel home folder)")
    parser.add_argument("--state-dir", metavar="DIR",
                        help="the folder for each session's flow marks, rate-limit counts, session limits, the end "
                             "of the last output (tail scan) and the settings snapshot (default: hook-state in the "
                             "agent-sentinel home folder). Keep it out of the agent's reach")
    parser.add_argument("--no-log-args", action="store_true", help="leave tool inputs out of the audit log")
    parser.add_argument("--audit-key-file", metavar="FILE",
                        help="sign every audit record (HMAC-SHA256) with the key in FILE; on POSIX the file must be "
                             "owner-only. Keep it where the agent's tools cannot read it")
    parser.add_argument("--audit-required", action="store_true",
                        help="block every call whose audit record cannot be written")
    parser.add_argument("--audit-max-bytes", type=_audit_max_bytes, metavar="BYTES",
                        help="past about this size, move the audit log to FILE.1 (then FILE.2, ...) and start it "
                             "again, its chain continuing; nothing is deleted "
                             f"({audit_chain.MIN_MAX_BYTES} to {audit_chain.MAX_MAX_BYTES})")


def _audit_max_bytes(text: str) -> int:
    try:
        return audit_chain.parse_max_bytes(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def run(args: argparse.Namespace) -> int:
    if args.hook_command == "claude-code":
        return run_claude_code(args)
    return install_claude_code(args)


def run_event(argv: list[str]) -> int:
    """`hook claude-code` with these words after it, without the other commands being loaded.

    __main__ comes here first for the command Claude Code runs for every
    event. The options are those of add_arguments; a word that is not one of
    them ends the process with exit code 2 (argparse), which blocks.
    """
    parser = argparse.ArgumentParser(
        prog="agent-sentinel hook claude-code",
        description="Answer one Claude Code hook event, read as JSON on stdin. Exits 0, or 2 to block.",
    )
    _add_paths(parser)
    return run_claude_code(parser.parse_args(argv))


# ---- hook claude-code ------------------------------------------------------------------------------

def run_claude_code(args: argparse.Namespace) -> int:
    """Answer one event. Never raises, and exits only with 0 or 2: any other code would let the call through.

    Everything printed while the event is checked is held back: on exit 2,
    Claude Code shows stderr to Claude, which must read only the answer's
    generic text. On exit 0 the held-back lines go to stderr, where Claude
    Code keeps them for the user's debugging and Claude never sees them.
    """
    stdout, stderr = sys.stdout, sys.stderr
    held = io.StringIO()
    try:
        with contextlib.redirect_stdout(held), contextlib.redirect_stderr(held):
            answer, line = _answer(args)
    except BaseException:  # even Ctrl+C must not end with an exit code that lets the call through
        answer = claude_hooks.failed_answer(None, new_ref())
        line = _line(answer)
    try:
        _send(answer, line, held.getvalue(), stdout, stderr)
    except BaseException:  # the answer could not be written (a closed pipe): nothing was said, so block
        return claude_hooks.EXIT_BLOCK
    return answer.exit_code


def _answer(args: argparse.Namespace) -> tuple[HookAnswer, str | None]:
    """The answer to the event on stdin, and the line that goes to stdout for it (None: nothing)."""
    data = sys.stdin.buffer.read(claude_hooks.MAX_EVENT_BYTES + 1)
    try:
        settings = _hook_settings(args)
    except Exception as exc:  # e.g. the home folder for the default state folder cannot be worked out
        audit = Path(os.path.abspath(args.audit)) if args.audit else None
        answer = claude_hooks.refusal_without_settings(data, audit, f"the hook could not start: {exc}")
        return answer, _line(answer)
    answer = claude_hooks.answer_event(data, settings)
    try:
        return answer, _line(answer)
    except (RecursionError, ValueError, TypeError) as exc:
        # A replaced output sits a few levels deeper in the answer than it did in the event: one nested as
        # deeply as the reader accepts may be more than the writer can write. The original cannot then be
        # replaced, so the event is refused like any other that could not be checked.
        answer = claude_hooks.refusal_without_settings(
            data, settings.audit, f"the answer could not be written: {type(exc).__name__}", settings)
        return answer, _line(answer)


def _line(answer: HookAnswer) -> str | None:
    """One line of ASCII JSON and nothing else: Claude Code reads stdout as the answer only then."""
    return None if answer.output is None else json.dumps(answer.output, ensure_ascii=True)


def _hook_settings(args: argparse.Namespace) -> HookSettings:
    if not args.audit and (args.audit_key_file or args.audit_required or args.audit_max_bytes is not None):
        raise ValueError("--audit-key-file, --audit-required and --audit-max-bytes need --audit FILE")
    state_dir = args.state_dir or str(home.hook_state_folder(home.home_folder()))
    return HookSettings(
        policy=Path(os.path.abspath(args.policy)),
        audit=Path(os.path.abspath(args.audit)) if args.audit else None,
        state_dir=Path(os.path.abspath(state_dir)),
        log_args=not args.no_log_args,
        audit_key_file=Path(full_path(args.audit_key_file)) if args.audit_key_file else None,
        audit_required=bool(args.audit_required),
        audit_max_bytes=args.audit_max_bytes,
    )


def _send(answer: HookAnswer, line: str | None, held: str, stdout: TextIO, stderr: TextIO) -> None:
    if line is not None:
        stdout.write(line + "\n")
        stdout.flush()
    text = answer.message if answer.exit_code != claude_hooks.EXIT_OK else held + answer.message
    for line in text.splitlines():
        if line.strip():
            stderr.write(printable(line, limit=2000) + "\n")
    stderr.flush()


# ---- hook install claude-code ----------------------------------------------------------------------

def install_claude_code(args: argparse.Namespace) -> int:
    if args.apply and args.settings is None:
        raise CommandError("--apply needs --settings FILE: agent-sentinel changes only a settings file it is given")
    policy_path = full_path(args.policy)
    policy = load_policy(policy_path)
    if policy is None:
        return EXIT_ERROR
    folder = None if (args.audit and args.state_dir) else home.home_folder()
    audit = full_path(args.audit) if args.audit else str(home.audit_file(folder))
    state = full_path(args.state_dir) if args.state_dir else str(home.hook_state_folder(folder))
    for what, path in (("policy", policy_path), ("audit log", audit), ("state folder", state)):
        if "${" in path:
            raise CommandError(f"the {what} path {printable(path, limit=200)} contains '${{', which Claude Code would "
                               "read as a placeholder; use a folder without it")
    key_file = full_path(args.audit_key_file) if args.audit_key_file else None
    if key_file is not None:
        if "${" in key_file:
            raise CommandError(f"the audit key file path {printable(key_file, limit=200)} contains '${{', which Claude "
                               "Code would read as a placeholder; use a folder without it")
        try:
            audit_chain.read_key_file(key_file)  # the same checks the hook makes, so a bad key is found now
        except audit_chain.AuditKeyError as exc:
            raise CommandError(f"cannot use --audit-key-file {printable(key_file, limit=200)}: {exc}") from exc
    python = this_python()
    handler = hook_handler(os.path.abspath(sys.executable), python.isolated, policy_path, audit, state,
                           log_args=not args.no_log_args,
                           audit_options=audit_options(key_file, args.audit_required, args.audit_max_bytes))
    hooks = hook_groups(handler, scan_all_results=args.scan_all_results,
                        scan_subagent_reports=args.scan_subagent_reports)
    _print_header(policy_path, policy, audit, state, args)
    if args.settings is None:
        _print_snippet(hooks, policy_path)
        _warn_about_python(handler["command"], python)
        return EXIT_OK
    files = {"policy": policy_path, "audit log": audit, "state folder": state}
    if key_file is not None:
        files["audit key file"] = key_file
    return _change_settings(Path(full_path(args.settings)), handler, args, python, files, policy)


def this_python() -> PythonCheck:
    """Whether this Python can start agent-sentinel from another folder, and how (cli_wrap.this_python)."""
    from .cli_wrap import this_python as check

    return check()


def audit_options(key_file: str | None, required: bool, max_bytes: int | None) -> list[str]:
    """The audit options of `hook claude-code`, as words for the hook entry (none when not used)."""
    words = ["--audit-key-file", key_file] if key_file else []
    if required:
        words.append("--audit-required")
    if max_bytes is not None:
        words += ["--audit-max-bytes", str(max_bytes)]
    return words


def hook_handler(python: str, isolated: bool, policy: str, audit: str, state: str, log_args: bool = True,
                 audit_options: list[str] | None = None) -> dict[str, Any]:
    """The hook entry that runs `agent-sentinel hook claude-code`: exec form, absolute paths, blocking on failure."""
    from .wrapping import ISOLATED_MODULE, PLAIN_MODULE

    words = [*(ISOLATED_MODULE if isolated else PLAIN_MODULE), "hook", "claude-code",
             "--policy", policy, "--audit", audit, "--state-dir", state]
    if not log_args:
        words.append("--no-log-args")
    words += audit_options or []
    return {"type": "command", "command": python, "args": words, "timeout": HOOK_TIMEOUT_SECONDS,
            "onFailure": "block"}


def hook_groups(handler: dict[str, Any], scan_all_results: bool = False, scan_subagent_reports: bool = False
                ) -> dict[str, list[dict[str, Any]]]:
    """The "hooks" section with only agent-sentinel's entries: event -> matcher groups.

    The tool events, SessionStart, both elicitation events (every MCP server)
    and ConfigChange (every source Claude Code reports). The PostToolUse
    hooks run for RESULTS_MATCHER; for every tool with scan_all_results; and
    for subagent reports too with scan_subagent_reports.
    """
    if scan_all_results:
        results = ALL
    elif scan_subagent_reports:
        results = SUBAGENT_RESULTS_MATCHER
    else:
        results = RESULTS_MATCHER
    matchers = {
        claude_hooks.SESSION_START: ALL,
        claude_hooks.PRE_TOOL_USE: ALL,
        claude_hooks.POST_TOOL_USE: results,
        claude_hooks.POST_TOOL_USE_FAILURE: results,
        claude_hooks.ELICITATION: ALL,
        claude_hooks.ELICITATION_RESULT: ALL,
        claude_hooks.CONFIG_CHANGE: CONFIG_MATCHER,
    }
    return {event: [{"matcher": matcher, "hooks": [handler]}] for event, matcher in matchers.items()}


def merged_hooks(existing: Any, ours: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """A settings file's "hooks" with agent-sentinel's entries replaced by `ours`; every other hook kept as it is.

    An entry is agent-sentinel's when it runs `agent_sentinel hook claude-code`
    (is_our_handler). So installing twice gives the same file, and installing
    with another policy replaces the old entries.
    """
    if existing is None:
        existing = {}
    if not isinstance(existing, dict):
        raise CommandError('"hooks" in the settings file is not an object ({ ... }); fix it by hand first')
    merged: dict[str, Any] = {}
    for event, groups in existing.items():
        if event in ours:
            if not isinstance(groups, list):
                raise CommandError(f'"hooks.{printable(event, limit=40)}" in the settings file is not a list; '
                                   "fix it by hand first")
            groups = [group for group in (_without_ours(group) for group in groups) if group is not None]
        merged[event] = groups
    for event, groups in ours.items():
        merged[event] = [*merged.get(event, []), *groups]
    return merged


def _without_ours(group: Any) -> Any:
    """A matcher group without agent-sentinel's handlers; None when nothing else was in it."""
    if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
        return group  # not a shape this command wrote: left for its owner
    kept = [handler for handler in group["hooks"] if not is_our_handler(handler)]
    if len(kept) == len(group["hooks"]):
        return group
    return {**group, "hooks": kept} if kept else None


def is_our_handler(handler: Any) -> bool:
    """Whether a hook entry runs `agent-sentinel hook claude-code` (as install writes it, or by hand)."""
    if not isinstance(handler, dict) or not isinstance(handler.get("command"), str):
        return False
    from .wrapping import PACKAGE, SCRIPT

    args = handler.get("args")
    words = [handler["command"], *args] if isinstance(args, list) else handler["command"].split()
    # The last part of each word, whichever slash it uses: "C:\py\Scripts\agent-sentinel.exe" -> "agent-sentinel.exe".
    names = [re.split(r"[\\/]", word)[-1].lower() for word in words if isinstance(word, str)]
    for index in range(len(names) - 1):
        if names[index] == "hook" and names[index + 1] == "claude-code":
            # The same names as a wrapped proxy entry (wrapping.SCRIPT, PACKAGE): the script, the module, or a
            # package with its version, as uvx and pipx run it ("agent-sentinel@0.5.0", "agent-sentinel==0.5.0").
            return any(SCRIPT.fullmatch(name) or PACKAGE.fullmatch(name) or name.split(".")[0] == "agent_sentinel"
                       for name in names[:index])
    return False


def _print_header(policy_path: str, policy: Policy, audit: str, state: str, args: argparse.Namespace) -> None:
    if args.scan_all_results:
        scanned = "every tool returns."
    else:
        scanned = ("web and MCP tools return (WebFetch, WebSearch, mcp__*, MCP resources"
                   + (" and subagent reports)." if args.scan_subagent_reports else ")."))
    print("Claude Code hooks: agent-sentinel checks every tool call before it runs, and what " + scanned)
    print("                   It also checks what MCP servers ask the user (elicitation) and the answer, and "
          "records changes to Claude Code's settings during a session.")
    warnings = policy.warnings()
    note = f"; {len(warnings)} warning(s): agent-sentinel validate {shown_path(policy_path)}" if warnings else ""
    rules = f"default {policy.default}, {len(policy.tools)} tool rule(s){note}"
    print(f"Policy:        {shown_path(policy_path)} ({rules})")
    print("               In hook mode tools have Claude Code's names: Read, Bash, WebFetch, mcp__<server>__<tool>.")
    blocked = [tool for tool in BUILT_IN_TOOLS if policy.tool_level_action(tool) == "block"]
    if blocked:
        print(f"  Warning: the policy blocks Claude Code's own tools {', '.join(blocked)} (it has no rule that "
              'allows them). Add rules for the ones the agent should use, such as "Read": "allow" or "Bash": "ask".')
    others = [tool for tool in OTHER_BUILT_IN_TOOLS if policy.tool_level_action(tool) == "block"]
    if others:
        print(f"  Note: the policy also refuses {', '.join(others)}, tools of Claude Code that the hook templates "
              "leave without a rule. Add a rule for one the agent should use.")
    if policy.may_ask():
        auto = ("every 'ask' in auto mode (hook.treat_auto_as_non_prompting)" if policy.hook.treat_auto_as_non_prompting
                else "an 'ask' for SubagentHandback in auto mode, which runs without a prompt")
        print("               Its 'ask' rules show Claude Code's own permission prompt; in bypassPermissions mode "
              f"they are refused, and so is {auto}. The hook never sees the answer, so approval memory "
              "(approvals) does not apply.")
    if policy.warn_severity is not None:
        print(f"               Output with a finding at or above {policy.warn_severity} (injection.warn_severity) "
              "reaches Claude with a notice to treat it as data.")
    if policy.server_labels:
        print("  Note: the policy's server_labels apply in the proxy only; in hook mode give the labels to the "
              'mcp__<server>__* tool rules instead, such as "mcp__web__*": {"action": "allow", "labels": '
              '["untrusted"]}.')
    if policy.tool_level_action("Monitor") != "block":
        note = "  Note: the policy lets the agent use Monitor, whose streamed events no hook can scan."
        if not {"untrusted", "sink"} <= set(policy.tool_labels("Monitor")):
            note += ' Label it "untrusted" and "sink" for the flow rules, or block it.'
        print(note)
    if policy.hook.config_changes == "block":
        print("Settings:      a change to Claude Code's settings or skills during a session is refused "
              "(hook.config_changes); the file stays changed, and the next session reads it.")
    if policy.hook.policy_changes == "block":
        print("               If the policy file changes during a session, that session's calls are refused until "
              "a new session starts (hook.policy_changes).")
    else:
        print("               A change to the policy file during a session is only recorded, and applies at once "
              '(hook.policy_changes is "audit").')
    print(f"Audit log:     {shown_path(audit)}")
    print(f"Session state: {shown_path(state)} (flow marks, rate-limit counts, session limits, the end of the last "
          "output for the tail scan, and the settings snapshot; keep it out of the agent's reach)")
    print('Needs Claude Code v2.1.295 or later: with "onFailure": "block", a hook that cannot start or times out '
          "blocks the call. Older versions let the call through.")


def _print_snippet(hooks: dict[str, Any], policy_path: str) -> None:
    user = home.user_folder()
    user_settings = str(user / ".claude" / "settings.json") if user is not None else "~/.claude/settings.json"
    print('\nAdd this to one Claude Code settings file, merged with any "hooks" it already has:')
    for line in json.dumps({"hooks": hooks}, indent=2).splitlines():
        print(printable(line, limit=5000))
    print("\nWhich file:")
    print(f"  {shown_path(user_settings):40}  for you, in every project")
    print(f"  {'.claude/settings.json':40}  for one project, shared with everyone who works on it")
    print(f"  {'.claude/settings.local.json':40}  for one project, just you")
    print("Or let agent-sentinel merge it into one (it shows the change first; --apply writes it, after a backup):")
    print(f"  agent-sentinel hook install claude-code --policy {shown_path(policy_path)} "
          f"--settings {shown_path(user_settings)}")


def _change_settings(path: Path, handler: dict[str, Any], args: argparse.Namespace, python: PythonCheck,
                     files: dict[str, str], policy: Policy | None = None) -> int:
    import difflib

    from . import control_plane
    from .clients import is_app_state
    from .config_file import create_config, read_config, with_top_level_value, write_config

    if is_app_state(path):
        raise CommandError(f"{path} is Claude Code's own state file, which agent-sentinel never edits; hooks belong "
                           "in a settings file such as ~/.claude/settings.json")
    config: ConfigFile | None = None
    if path.exists() or path.is_symlink():
        config = read_config(path, for_writing=True)
        old = config.document.get("hooks")
    elif not path.parent.is_dir():
        raise CommandError(f"the folder {path.parent} does not exist; create it first, or give another --settings")
    else:
        old = None
    new = merged_hooks(old, hook_groups(handler, scan_all_results=args.scan_all_results,
                                        scan_subagent_reports=args.scan_subagent_reports))
    print(f"\nSettings file: {shown_path(path)}" + ("" if config is not None else " (does not exist yet; it would be "
                                                                              "created)"))
    _warn_about_project(path, files)
    exposed = control_plane.writable_warning(policy, path, "this settings file") if policy is not None else None
    if exposed:
        print(f"Warning: {exposed}")
    if new == old:
        print("The hooks are already in it, exactly as shown. Nothing to change.")
        return EXIT_OK
    _warn_about_python(handler["command"], python)
    print('\nThe change (only "hooks" changes; the rest of the file is kept as it is):')
    shown_old = json.dumps(redact_value(old if old is not None else {}), indent=2, ensure_ascii=False)
    shown_new = json.dumps(redact_value(new), indent=2, ensure_ascii=False)
    for line in difflib.unified_diff(shown_old.splitlines(), shown_new.splitlines(), fromfile="hooks (now)",
                                     tofile="hooks (with agent-sentinel)", lineterm="", n=2):
        print(printable(line, limit=1000))
    if not args.apply:
        print("\nNothing was changed. To make this change, run the same command with --apply.")
        return EXIT_OK
    for folder in _make_folders(files["audit log"], files["state folder"]):
        print(f"Created the folder {shown_path(folder)}")
    if config is None:
        create_config(path, json.dumps({"hooks": new}, indent=2) + "\n")
        print(f"\nCreated {shown_path(path)}.")
    else:
        backup = write_config(config, with_top_level_value(config, "hooks", new))
        print(f"\nBackup of the original: {shown_path(backup)}")
        print(f"Wrote {shown_path(path)}.")
    print("Next: start a new Claude Code session (run /hooks in it to see the hooks), then try a call the policy "
          "blocks.")
    print("To undo: copy the backup back, or delete the entries that run 'agent_sentinel hook claude-code'.")
    return EXIT_OK


def _warn_about_project(settings: Path, files: dict[str, str]) -> None:
    """For a project's settings file (<project>/.claude/...): say so if the policy or the state is in that project."""
    if settings.parent.name.lower() != ".claude":
        return
    from .clients import inside_folder

    project = settings.parent.parent
    user = home.user_folder()
    if user is not None and inside_folder(project, user) and inside_folder(user, project):
        return  # ~/.claude/settings.json: the user's own settings, not a project's
    exposed = [what for what, path in files.items() if inside_folder(path, project)]
    if exposed:
        print(f"Warning: the {', the '.join(exposed)} would be inside the project folder, where the agent's own tools "
              "may be able to change them (and so switch the protection off). Keep them in the agent-sentinel home "
              "folder.")


def _make_folders(audit: str, state: str) -> list[Path]:
    """Create the audit log's folder and the state folder (owner-only) if they are missing; return those created."""
    created = []
    for folder in (Path(audit).parent, Path(state)):
        if not folder.is_dir():
            try:
                home.make_private_folder(folder)
            except OSError as exc:
                raise CommandError(f"cannot create the folder {folder}: {exc.strerror or exc}; nothing was changed"
                                   ) from exc
            created.append(folder)
    return created


def _warn_about_python(python: str, check: PythonCheck) -> None:
    """Say so if the hooks could not start agent-sentinel the safe way, or at all."""
    shown = printable(python, limit=200)
    if check.version is None:
        print(f"\nWarning: {shown} cannot import agent_sentinel when started from another folder, so the hooks would "
              'fail, and with "onFailure": "block" Claude Code would block every tool call. Install the package for '
              f"that Python first ({INSTALL_COMMAND}, run with that Python; see Install in the README).")
        return
    if not check.isolated:
        print(f"\nWarning: {shown} finds agent_sentinel only in your own site-packages (pip install --user), which "
              "Python's isolated mode (-I) leaves out. So the hooks start it without -I, and a folder named "
              "agent_sentinel in the project Claude Code works in would run instead. Install the package for all "
              "users or in a virtual environment, then install the hooks again.")
    if check.version != __version__:
        print(f"\nWarning: {shown} has agent-sentinel {printable(check.version, limit=20)} installed, not "
              f"{__version__} (this command); the hooks need {__version__}.")
