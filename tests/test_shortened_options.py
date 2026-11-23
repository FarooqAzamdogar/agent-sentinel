"""The shortened options 0.5.0 took still mean what they meant (agent_sentinel/shortened_options.py).

The commands' parsers take "--con" for --config while no other option
begins so. An option added later (wrap --contain) would turn that into an
error. Every option name of 0.5.0 is listed here, so that each shortening
it took as one option is tried against today's parsers: it must read
exactly as the option written in full.
"""

import contextlib
import io
import unittest
import unittest.mock

import support  # noqa: F401  (puts the project folder on sys.path)
from agent_sentinel import cli_hook, shortened_options
from agent_sentinel.__main__ import _build_parser

# The "--" options of each command in 0.5.0 (the proxy takes no shortened option, then and now).
OPTIONS_0_5_0 = {
    "init": ("--help", "--out", "--root", "--template", "--timeout", "--trust-annotations"),
    "inspect": ("--format", "--help", "--policy", "--timeout"),
    "clients": ("--help",),
    "wrap": ("--apply", "--audit", "--client", "--config", "--help", "--monitor", "--name", "--pins-dir", "--policy",
             "--project", "--server"),
    "unwrap": ("--apply", "--client", "--config", "--help", "--project", "--server"),
    "doctor": ("--config", "--format", "--help"),
    "hook claude-code": ("--audit", "--help", "--no-log-args", "--policy", "--state-dir"),
    "hook install": ("--apply", "--audit", "--help", "--no-log-args", "--policy", "--scan-all-results", "--settings",
                     "--state-dir"),
    "hook": ("--help",),
    "pins list": ("--help", "--pins"),
    "pins show": ("--help", "--kind", "--pins"),
    "pins diff": ("--help", "--kind", "--pins", "--policy"),
    "pins accept": ("--force", "--help", "--kind", "--pins", "--policy"),
    "pins forget": ("--help", "--kind", "--pins"),
    "pins": ("--help",),
    "check": ("--args", "--help", "--marks", "--proxy", "--result", "--show-rules"),
    "test": ("--help", "--quiet"),
    "validate": ("--help",),
    "scan": ("--as", "--fail-on", "--format", "--help", "--policy"),
    "report": ("--action", "--by", "--event", "--follow", "--format", "--help", "--last", "--server", "--show-args",
               "--since", "--tool", "--until"),
    "explain": ("--help", "--last", "--policy", "--ref"),
    "suggest": ("--as", "--help", "--no-limits", "--out", "--policy", "--server"),
    "demo": ("--help", "--keep"),
}


def shortenings(options):
    """(shortened, the one option it meant) for every shortening 0.5.0 read as one option: "--con" -> --config."""
    for option in options:
        for end in range(3, len(option)):
            shortened = option[:end]
            if [other for other in options if other.startswith(shortened)] == [option]:
                yield shortened, option


class ShortenedOptions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser, _ = _build_parser()

    def command_parser(self, command):
        parser = self.parser
        for word in command.split():
            (subcommands,) = [action for action in parser._actions if hasattr(action, "choices")
                              and isinstance(action.choices, dict)]
            parser = subcommands.choices[word]
        return parser

    def outcome(self, argv):
        """What parsing gives: the values read, or the exit code and what was printed (an error, the help)."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                values, extras = self.parser.parse_known_args(argv)
            except SystemExit as exc:
                return "exit", exc.code, out.getvalue(), err.getvalue()
        return "read", vars(values), extras

    def test_every_shortening_0_5_0_took_reads_as_the_option_in_full(self):
        tried = 0
        for command, options in OPTIONS_0_5_0.items():
            parser = self.command_parser(command)
            for shortened, option in shortenings(options):
                with self.subTest(command=command, shortened=shortened):
                    action = parser._option_string_actions[option]
                    value = [] if action.nargs == 0 else ["x"]
                    words = command.split()
                    short, full = self.outcome([*words, shortened, *value]), self.outcome([*words, option, *value])
                    self.assertNotIn("ambiguous option", str(short))
                    self.assertEqual(short, full)
                    short = self.outcome([*words, *(f"{shortened}=x",) * bool(value)])
                    self.assertEqual(short, self.outcome([*words, *(f"{option}=x",) * bool(value)]))
                    tried += 1
        self.assertGreater(tried, 400)

    def test_what_is_kept_is_what_0_5_0_meant_and_no_more(self):
        for command, kept in shortened_options.KEPT.items():
            meant = dict(shortenings(OPTIONS_0_5_0[command]))
            for shortened, option in kept.items():
                with self.subTest(command=command, shortened=shortened):
                    self.assertEqual(meant.get(shortened), option)  # never a shortening 0.5.0 refused or read otherwise
        # one that was ambiguous in 0.5.0 still is, and one of a new option alone is read as that option
        self.assertIn("ambiguous option: --c", self.outcome(["wrap", "--c", "x"])[3])
        self.assertIn("ambiguous option: --a", self.outcome(["hook", "install", "claude-code", "--a", "x"])[3])
        # and such an error names the options themselves, never the shortenings kept for them
        self.assertIn("ambiguous option: --c could match --client, --config, --contain\n",
                      self.outcome(["wrap", "--c", "x"])[3])
        error = self.outcome(["hook", "install", "claude-code", "--s", "x"])[3]
        self.assertIn("ambiguous option: --s could match ", error)
        for shortened in shortened_options.KEPT["hook install"]:
            self.assertNotRegex(error, r"(?<![\w-])" + shortened + r"(?![\w-])")
        self.assertEqual(self.outcome(["wrap", "--client", "cursor", "--policy", "p", "--cont"])[1]["contain"], True)

    def test_the_kept_shortenings_are_not_listed_in_the_help(self):
        for command in ("wrap", "check", "hook install", "hook claude-code"):
            with self.subTest(command=command):
                text = self.command_parser(command).format_help()
                for shortened in shortened_options.KEPT[command]:
                    self.assertNotRegex(text, r"(?<![\w-])" + shortened + r"(?![\w-])")

    def test_a_hook_entry_written_with_a_shortened_audit_still_runs(self):
        # A hand-written 0.5.0 hook entry: an error here would block every tool call of the session.
        kind, values, extras = self.outcome(["hook", "claude-code", "--policy", "p.json", "--aud", "a.jsonl"])
        self.assertEqual((kind, values["audit"], extras), ("read", "a.jsonl", []))
        kind, values, _ = self.outcome(["hook", "install", "claude-code", "--policy", "p.json", "--scan"])
        self.assertEqual((kind, values["scan_all_results"]), ("read", True))
        kind, values, _ = self.outcome(["wrap", "--client", "cursor", "--policy", "p", "--con", "c.json", "--se", "a",
                                        "--n", "b"])
        self.assertEqual((values["config"], values["server"], values["name"]), ("c.json", ["a"], "b"))

    def test_the_hook_event_path_takes_the_kept_shortenings_too(self):
        """`hook claude-code` builds its own parser (cli_hook.run_event), which must keep them as well.

        __main__ answers that command without building the parser of every
        command, so a shortening registered only there would be lost on the
        one path where an argparse error blocks every tool call.
        """
        for shortened, option in shortened_options.KEPT["hook claude-code"].items():
            with self.subTest(shortened=shortened):
                self.assertEqual(self.read_by_run_event([shortened, "a.jsonl"]),
                                 self.read_by_run_event([option, "a.jsonl"]))
        # and nothing is widened: a shortening 0.5.0 never read as one option is still an error
        with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
            self.read_by_run_event(["--audit-", "a.jsonl"])
        self.assertIn("ambiguous option: --audit-", err.getvalue())

    def read_by_run_event(self, words):
        """What cli_hook.run_event reads from these words, without answering the event."""
        read = {}

        def instead(args):
            read.update(vars(args))
            return 0

        with unittest.mock.patch.object(cli_hook, "run_claude_code", instead):
            cli_hook.run_event(["--policy", "p.json", *words])
        return read


if __name__ == "__main__":
    unittest.main()
