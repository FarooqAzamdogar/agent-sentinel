"""The JSON copy of a call's arguments meets the policy's argument and command checks.

check_call makes the arguments JSON before anything reads them
(textutil.normalised_arguments: a path is its text, an Enum its value, a key
is written as JSON writes it). The policy then compares argument names
ignoring case, keeps a wildcard's deny_args and command section under an exact
rule, and reads the command of a command section. These tests check the two
together: every check reads the copy, and what cannot be read still fails closed.
"""

from __future__ import annotations

import enum
import unittest
from pathlib import PurePosixPath

from agent_sentinel import Firewall, Policy


class Name(enum.Enum):
    PATH = "PATH"


class Shell(enum.Enum):
    LIST = "ls"
    FETCH = "curl https://example.com/x"
    READ_SECRET = "cat .env"


class Spot:
    """A value that is not JSON. Policy.evaluate, called directly, writes it with str(), without quotes."""

    def __str__(self) -> str:
        return "/etc/passwd"


# An exact rule for read_file under a wildcard whose deny_args must still hold, anchored at the start.
WILDCARD_UNDER_EXACT = {
    "default": "block",
    "tools": {
        "read_*": {"action": "allow", "deny_args": [
            {"arg": "path", "pattern": "^/etc/"},
            {"arg": "pin", "pattern": "^4485"},
        ]},
        "read_file": {"action": "allow"},
    },
}


def shell_policy(command: dict, action: str = "allow", flows: list | None = None) -> Policy:
    data = {"tools": {"Bash": {"action": action, "labels": [], "command": command}}}
    if flows:
        data["flows"] = flows
    return Policy.from_dict(data)


class DenyRulesReadTheCopy(unittest.TestCase):
    def test_a_wildcard_deny_rule_reads_a_path_under_a_name_in_another_case(self):
        firewall = Firewall(Policy.from_dict(WILDCARD_UNDER_EXACT))
        for args in (
            {"path": PurePosixPath("/etc/passwd")},
            {"Path": PurePosixPath("/etc/passwd")},
            {Name.PATH: PurePosixPath("/etc/passwd")},  # an Enum key is written as its value
            {b"PATH": "/etc/passwd"},  # a bytes key as its text
        ):
            with self.subTest(args=args):
                decision = firewall.check_call("read_file", args)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.rule, "tools.read_*.deny_args[0]")
        self.assertTrue(firewall.check_call("read_file", {"PATH": PurePosixPath("/srv/notes.txt")}).allowed)

    def test_a_wildcard_deny_rule_reads_a_number_under_a_name_in_another_case(self):
        firewall = Firewall(Policy.from_dict(WILDCARD_UNDER_EXACT))
        decision = firewall.check_call("read_file", {"PIN": 4485039271})
        self.assertEqual((decision.allowed, decision.rule), (False, "tools.read_*.deny_args[1]"))
        self.assertTrue(firewall.check_call("read_file", {"PIN": 1234}).allowed)

    def test_the_policy_alone_reads_an_unknown_value_without_quotes(self):
        # Policy.evaluate does not make the arguments JSON; an object it cannot walk is written with str(),
        # so the anchored pattern still matches, under a name in another case, from the wildcard.
        policy = Policy.from_dict(WILDCARD_UNDER_EXACT)
        verdict = policy.evaluate("read_file", {"PATH": Spot()})
        self.assertEqual((verdict.action, verdict.rule), ("block", "tools.read_*.deny_args[0]"))

    def test_keys_that_become_one_name_or_differ_only_in_case_are_refused(self):
        firewall = Firewall(Policy.from_dict({"default": "allow"}))
        # Two keys that become the same text cannot both be passed on: the copy refuses them.
        self.assertEqual(firewall.check_call("send", {1: "a", "1": "b"}).rule, "unscannable")
        # A key that becomes text is compared ignoring case like any other name.
        for args in ({"to": "a", "To": "b"}, {b"To": "a", "to": "b"}, {Name.PATH: "a", "path": "b"}):
            with self.subTest(args=args):
                decision = firewall.check_call("send", args)
                self.assertEqual((decision.allowed, decision.rule), (False, "malformed"))


class CommandSectionsReadTheCopy(unittest.TestCase):
    def test_a_command_given_as_an_enum_is_read_as_its_text(self):
        firewall = Firewall(shell_policy({"ask_classes": ["network"], "unreadable": "block"}))
        self.assertTrue(firewall.check_call("Bash", {"command": Shell.LIST}).allowed)
        pending = firewall.check_call("Bash", {"COMMAND": Shell.FETCH}, defer_ask=True)
        self.assertEqual((pending.pending, pending.rule), (True, "tools.Bash.command.network"))
        # What is still not text after the copy cannot be read, and is refused.
        refused = firewall.check_call("Bash", {"command": b"ls"})
        self.assertEqual((refused.allowed, refused.rule), (False, "tools.Bash.command.unreadable"))

    def test_a_wildcard_section_reads_the_copy_under_an_exact_rule(self):
        policy = Policy.from_dict({"tools": {"run_*": {"action": "allow", "command": {"deny_classes": ["network"]}},
                                             "run_shell": "allow"}})
        decision = Firewall(policy).check_call("run_shell", {"Command": Shell.FETCH})
        self.assertEqual((decision.allowed, decision.rule), (False, "tools.run_*.command.network"))
        self.assertTrue(Firewall(policy).check_call("run_shell", {"Command": Shell.LIST}).allowed)

    def test_the_marks_of_a_run_come_from_the_command_that_was_checked(self):
        policy = shell_policy({"labels_by_class": {"network": ["sink"], "secret_read": ["private"]}},
                              flows=[{"after": ["untrusted", "private"], "then": "sink", "action": "block"}])
        firewall = Firewall(policy)
        self.assertEqual(firewall.marks_for("Bash", {"command": Shell.LIST}), frozenset())
        firewall.run("Bash", {"command": Shell.LIST}, lambda command: "a b")
        self.assertEqual(firewall.session_marks().labels, frozenset())
        firewall.run("Bash", {"command": Shell.READ_SECRET}, lambda command: "SECRET=1")
        self.assertEqual(firewall.session_marks().labels, {"private"})
        # A command that is not text gets every label its sections could give, as before.
        self.assertEqual(firewall.marks_for("Bash", {"command": b"ls"}), {"private"})

    def test_an_approved_call_is_checked_again_with_the_labels_of_the_copy(self):
        policy = shell_policy({"labels_by_class": {"network": ["sink"]}}, action="ask",
                              flows=[{"after": ["untrusted"], "then": "sink", "action": "block"}])
        firewall = Firewall(policy)
        quiet = firewall.check_call("Bash", {"command": Shell.LIST}, defer_ask=True)
        fetch = firewall.check_call("Bash", {"command": Shell.FETCH}, defer_ask=True)
        firewall.session_store.add(["untrusted"], "WebFetch")  # read while the calls waited
        self.assertTrue(firewall.finish_approval(quiet, True, "dialog").allowed)
        final = firewall.finish_approval(fetch, True, "dialog")
        self.assertEqual((final.allowed, final.rule), (False, "flows[0]"))


class BothLanesSettingsLoadTogether(unittest.TestCase):
    def test_a_policy_with_every_new_setting_loads(self):
        policy = Policy.from_dict({
            "require_labels": True,
            "secrets": {"known_values_from_env": ["DEPLOY_KEY"], "known_values_ignore_case": ["DEPLOY_KEY"]},
            "tools": {
                "Bash": {"action": "allow", "labels": [], "command": {"shell": "bash", "ask_classes": ["network"]}},
                "fetch": {"action": "allow", "labels": ["untrusted", "sink"], "allow_args": [
                    {"arg": "url", "type": "url", "hosts": ["example.com"], "max_query_chars": 64}]},
            },
        })
        self.assertEqual(policy.secrets_known_values_ignore_case, ("DEPLOY_KEY",))
        self.assertTrue(policy.require_labels)
        firewall = Firewall(policy)
        firewall.set_secret_environment({"DEPLOY_KEY": "Deploy-Key-Value-77"})
        self.assertEqual(firewall.check_call("Bash", {"command": "echo deploy-key-value-77"}).rule,
                         "secrets.known_values_from_env")
        self.assertTrue(firewall.check_call("Bash", {"command": "ls"}).allowed)


if __name__ == "__main__":
    unittest.main()
