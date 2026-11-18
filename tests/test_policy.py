import json
import tempfile
import time
import unittest
from pathlib import Path

from support import POLICY
from agent_sentinel import Policy, PolicyError
from agent_sentinel.policy import NOT_PERMITTED

ADDRESS = r"[^@\s,;]+@example\.com"


def action(tool, args):
    return POLICY.evaluate(tool, args).action


def rules(tools, **more):
    """A policy with these tool rules; `more` are other top-level keys."""
    return Policy.from_dict({"tools": tools, **more})


def load_text(text, encoding="utf-8"):
    """Load a policy from a file with exactly this text, as `validate` and the proxy do."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "policy.json"
        path.write_bytes(text.encode(encoding))
        return Policy.from_file(path)


class ToolRules(unittest.TestCase):
    def test_allowed_tool(self):
        self.assertEqual(action("read_file", {"path": "notes.txt"}), "allow")

    def test_glob_rules(self):
        self.assertEqual(action("delete_everything", {}), "block")
        self.assertEqual(action("search_web", {"q": "soup"}), "allow")

    def test_unknown_tool_uses_the_default(self):
        self.assertEqual(action("launch_rocket", {}), "block")

    def test_exact_name_beats_glob(self):
        policy = Policy.from_dict({"tools": {"delete_*": "block", "delete_draft": "allow"}})
        self.assertEqual(policy.evaluate("delete_draft", {}).action, "allow")

    def test_default_is_block_when_omitted(self):
        self.assertEqual(Policy.from_dict({}).evaluate("anything", {}).action, "block")

    def test_missing_arguments_are_treated_as_no_arguments(self):
        self.assertEqual(POLICY.evaluate("read_file", None).action, "allow")

    def test_call_that_cannot_be_checked_is_blocked(self):
        policy = rules({"*": "allow"}, default="allow")
        self.assertEqual(policy.evaluate("read_file", [".ssh/id_rsa"]).action, "block")
        self.assertEqual(policy.evaluate(["read_file"], {}).action, "block")


class OverlappingGlobs(unittest.TestCase):
    def test_block_glob_beats_allow_glob_listed_first(self):
        policy = rules({"*_file": "allow", "delete_*": "block"})
        self.assertEqual(policy.evaluate("delete_file", {}).action, "block")
        self.assertEqual(policy.evaluate("read_file", {}).action, "allow")

    def test_block_glob_beats_allow_glob_listed_second(self):
        policy = rules({"delete_*": "block", "*_file": "allow"})
        self.assertEqual(policy.evaluate("delete_file", {}).action, "block")
        self.assertEqual(policy.evaluate("read_file", {}).action, "allow")

    def test_ask_glob_beats_allow_glob_in_both_file_orders(self):
        for tools in ({"*_file": "allow", "write_*": "ask"}, {"write_*": "ask", "*_file": "allow"}):
            with self.subTest(order=list(tools)):
                self.assertEqual(rules(tools).evaluate("write_file", {}).action, "ask")

    def test_block_glob_beats_ask_glob(self):
        policy = rules({"*_file": "ask", "delete_*": "block"})
        self.assertEqual(policy.evaluate("delete_file", {}).action, "block")

    def test_deny_args_of_every_matching_glob_are_checked(self):
        guarded = {"action": "allow", "deny_args": [{"arg": "path", "pattern": "private"}]}
        for tools in ({"*_file": "allow", "read_*": guarded}, {"read_*": guarded, "*_file": "allow"}):
            with self.subTest(order=list(tools)):
                policy = rules(tools)
                self.assertEqual(policy.evaluate("read_file", {"path": "private/a.txt"}).action, "block")
                self.assertEqual(policy.evaluate("read_file", {"path": "public/a.txt"}).action, "allow")

    def test_allow_args_of_every_matching_glob_are_checked(self):
        policy = rules({
            "send_*": "allow",
            "*_email": {"action": "allow", "allow_args": [{"arg": "to", "pattern": ADDRESS}]},
        })
        self.assertEqual(policy.evaluate("send_email", {"to": "a@example.com"}).action, "allow")
        self.assertEqual(policy.evaluate("send_email", {"to": "a@evil.example"}).action, "block")
        self.assertEqual(policy.evaluate("send_email", {}).action, "block")

    def test_equally_strict_globs_keep_file_order(self):
        self.assertIn("'*_file'", rules({"*_file": "block", "delete_*": "block"}).evaluate("delete_file", {}).reason)
        self.assertIn("'delete_*'", rules({"delete_*": "block", "*_file": "block"}).evaluate("delete_file", {}).reason)

    def test_exact_name_beats_a_stricter_glob_and_ignores_its_arguments(self):
        policy = rules({
            "delete_*": {"action": "block", "deny_args": [{"arg": "*", "pattern": "draft"}]},
            "delete_draft": "allow",
        })
        self.assertEqual(policy.evaluate("delete_draft", {"name": "draft 1"}).action, "allow")


class GlobSyntax(unittest.TestCase):
    def test_square_bracket_in_a_tool_name_is_literal(self):
        policy = rules({"get_report[1]": "allow", "list[*]": "allow"})
        self.assertEqual(policy.evaluate("get_report[1]", {}).action, "allow")
        self.assertEqual(policy.evaluate("get_report1", {}).action, "block")
        self.assertEqual(policy.evaluate("list[all]", {}).action, "allow")
        self.assertEqual(policy.evaluate("lista", {}).action, "block")

    def test_question_mark_in_a_tool_name_is_literal(self):
        policy = rules({"is_ready?": "allow", "can_*?": "allow"})
        self.assertEqual(policy.evaluate("is_ready?", {}).action, "allow")
        self.assertEqual(policy.evaluate("is_readyX", {}).action, "block")
        self.assertEqual(policy.evaluate("can_write?", {}).action, "allow")
        self.assertEqual(policy.evaluate("can_write!", {}).action, "block")

    def test_star_matches_at_the_start_in_the_middle_and_at_the_end(self):
        policy = rules({"*_file": "allow", "db_*_ro": "allow", "search_*": "allow", "a*b*c": "allow"})
        for tool in ("read_file", "_file", "db_users_ro", "db__ro", "search_", "search_web", "abc", "a1b2c", "abcbc"):
            with self.subTest(tool=tool):
                self.assertEqual(policy.evaluate(tool, {}).action, "allow")
        for tool in ("file", "read_files", "db_ro", "db_users_rw", "search", "ac", "acb", "xabc", "abcx"):
            with self.subTest(tool=tool):
                self.assertEqual(policy.evaluate(tool, {}).action, "block")

    def test_star_also_matches_line_breaks_and_slashes(self):
        policy = rules({"delete_*": "block"}, default="allow")
        self.assertEqual(policy.evaluate("delete_a\nb", {}).action, "block")
        self.assertEqual(policy.evaluate("delete_a/b", {}).action, "block")

    def test_tool_names_are_case_sensitive(self):
        policy = rules({"read_file": "allow", "search_*": "allow"})
        self.assertEqual(policy.evaluate("Read_File", {}).action, "block")
        self.assertEqual(policy.evaluate("SEARCH_web", {}).action, "block")

    def test_long_hostile_tool_name_is_matched_quickly(self):
        # A regular expression made from this rule (".*_a_.*_b_.*") needs quadratic time here.
        policy = rules({"*_a_*_b_*": "allow", "*_a_*_a_*_c": "allow"})
        name = "_a_" * 200_000
        started = time.perf_counter()
        self.assertEqual(policy.evaluate(name, {}).action, "block")
        self.assertLess(time.perf_counter() - started, 2)


class DenyArgs(unittest.TestCase):
    def test_denied_value(self):
        self.assertEqual(action("read_file", {"path": "C:/Users/me/.ssh/id_rsa"}), "block")

    def test_any_arg_rule_sees_other_and_nested_arguments(self):
        # The example policy uses "arg": "*", so the value cannot hide elsewhere.
        self.assertEqual(action("read_file", {"path": "a.txt", "paths": ["/home/me/.ssh/id_rsa"]}), "block")
        self.assertEqual(action("read_file", {"path": "a.txt", "options": {"extra": {".env": 1}}}), "block")

    def test_named_arg_rule_sees_nested_values(self):
        policy = rules({"read": {"action": "allow", "deny_args": [{"arg": "path", "pattern": "secret"}]}})
        self.assertEqual(policy.evaluate("read", {"path": ["ok.txt", "my-secret.txt"]}).action, "block")
        self.assertEqual(policy.evaluate("read", {"path": "ok.txt", "note": "secret"}).action, "allow")

    def test_reason_does_not_reveal_the_pattern(self):
        verdict = POLICY.evaluate("read_file", {"path": ".ssh/id_rsa"})
        self.assertNotIn("id_rsa", verdict.reason)
        self.assertNotIn("id_rsa", verdict.public)

    def test_resource_read_of_a_denied_uri_is_blocked(self):
        self.assertEqual(action("resources/read", {"uri": "file:///notes.txt"}), "allow")
        self.assertEqual(action("resources/read", {"uri": "file:///home/me/.ssh/id_rsa"}), "block")


class PolicyWideDeny(unittest.TestCase):
    DENY = [{"arg": "*", "pattern": r"\.ssh"}]

    def test_it_blocks_a_tool_that_has_no_rule(self):
        verdict = Policy.from_dict({"deny_args": self.DENY}).evaluate("anything", {"path": "/home/me/.ssh/config"})
        self.assertEqual((verdict.action, verdict.reason), ("block", "an argument has a value the policy denies"))

    def test_it_holds_when_the_default_is_allow(self):
        policy = Policy.from_dict({"default": "allow", "deny_args": self.DENY})
        self.assertEqual(policy.evaluate("anything", {"path": "/home/me/.ssh/config"}).action, "block")
        self.assertEqual(policy.evaluate("anything", {"path": "notes.txt"}).action, "allow")

    def test_no_tool_rule_can_exempt_a_tool_from_it(self):
        policy = rules({"read_file": "allow", "read_*": "allow"}, deny_args=self.DENY)
        self.assertEqual(policy.evaluate("read_file", {"path": "~/.ssh/id_rsa"}).action, "block")
        self.assertEqual(policy.evaluate("read_dir", {"path": "~/.ssh"}).action, "block")

    def test_it_can_name_one_argument(self):
        policy = Policy.from_dict({"default": "allow", "deny_args": [{"arg": "path", "pattern": "private"}]})
        verdict = policy.evaluate("anything", {"path": "private/a.txt"})
        self.assertEqual((verdict.action, verdict.reason), ("block", "argument 'path' has a value the policy denies"))
        self.assertEqual(policy.evaluate("anything", {"note": "private"}).action, "allow")

    def test_example_policy_denies_secret_paths_for_every_allowed_tool(self):
        for tool, args in [
            ("fetch_page", {"url": "file:///home/me/.ssh/id_rsa"}),
            ("fetch_page", {"url": "file:///app/.env"}),
            ("search_files", {"root": "/home/me/.ssh", "pattern": "PRIVATE KEY"}),
            ("search_grep", {"path": "C:\\Users\\me\\.aws\\credentials"}),
            ("search_notes", {"q": "x", "include": ["/app/.env.production"]}),
            ("read_file", {"path": "keys/id_ed25519"}),
        ]:
            with self.subTest(tool=tool, args=args):
                self.assertEqual(action(tool, args), "block")

    def test_example_policy_leaves_ordinary_searches_and_pages_alone(self):
        for tool, args in [
            ("search_web", {"q": "secret santa gift ideas"}),
            ("search_web", {"q": "how to rotate AWS credentials safely"}),
            ("search_web", {"q": "how do I read process.env in node"}),
            ("fetch_page", {"url": "https://docs.aws.amazon.com/s3/"}),
            ("read_file", {"path": "docs/environment.md"}),
        ]:
            with self.subTest(tool=tool, args=args):
                self.assertEqual(action(tool, args), "allow")


class PercentEncodedDenyValues(unittest.TestCase):
    def test_percent_encoded_value_is_denied(self):
        for uri in [
            "file:///home/me/%2Essh/id%5Frsa",
            "file:///home/me/.%73sh/config",
            "file:///home/me/%2e%65nv",
            "file:///home/me%2F.aws/credentials",
        ]:
            with self.subTest(uri=uri):
                self.assertEqual(action("resources/read", {"uri": uri}), "block")
                self.assertEqual(action("read_file", {"path": "a.txt", "more": [uri]}), "block")

    def test_double_and_triple_encoded_value_is_denied(self):
        self.assertEqual(action("resources/read", {"uri": "file:///home/me/%252Essh/config"}), "block")
        self.assertEqual(action("resources/read", {"uri": "file:///home/me/%25252Essh/config"}), "block")

    def test_value_that_is_still_encoded_after_three_rounds_is_denied(self):
        policy = Policy.from_dict({"default": "allow", "deny_args": [{"arg": "*", "pattern": "never-in-the-value"}]})
        self.assertEqual(policy.evaluate("fetch", {"url": "x%2525252541"}).action, "block")
        self.assertEqual(policy.evaluate("fetch", {"url": "%" + "25" * 100_000 + "41"}).action, "block")
        # Three rounds are enough for these, and nothing denied comes out.
        self.assertEqual(policy.evaluate("fetch", {"url": "x%252541"}).action, "allow")
        self.assertEqual(policy.evaluate("fetch", {"url": "%25" * 100_000 + "41"}).action, "allow")

    def test_ordinary_percent_signs_are_not_denied(self):
        for uri in [
            "file:///notes%20for%20monday.txt",
            "file:///notes/100%25%20done.txt",
            "https://example.com/search?q=a%20b&r=%2F",
            "100% done, 50%off",
            "%ff%fe%zz",
        ]:
            with self.subTest(uri=uri):
                self.assertEqual(action("resources/read", {"uri": uri}), "allow")

    def test_large_percent_heavy_value_is_checked_quickly(self):
        started = time.perf_counter()
        for text in ("%" * 300_000, "%zz" * 100_000, "%25" * 100_000, "%" + "25" * 150_000):
            POLICY.evaluate("search_web", {"q": text})
        self.assertLess(time.perf_counter() - started, 5)

    def test_named_deny_argument_is_decoded_too(self):
        policy = rules({"read": {"action": "allow", "deny_args": [{"arg": "path", "pattern": "private/"}]}})
        self.assertEqual(policy.evaluate("read", {"path": "private%2Fa.txt"}).action, "block")
        self.assertEqual(policy.evaluate("read", {"path": "public%2Fa.txt"}).action, "allow")

    def test_allow_patterns_match_the_value_as_written(self):
        # Decoding is for deny rules only: it may add blocks, never permissions.
        self.assertEqual(action("send_email", {"to": "a%40example.com"}), "block")
        policy = rules({"read": {"action": "allow", "allow_args": [{"arg": "path", "pattern": r"docs/[\w%]+\.txt"}]}})
        self.assertEqual(policy.evaluate("read", {"path": "docs/my%20notes.txt"}).action, "allow")


class AllowArgs(unittest.TestCase):
    def test_matching_value_passes_to_the_rule_action(self):
        self.assertEqual(action("send_email", {"to": "a@example.com"}), "ask")

    def test_other_value_or_missing_argument_is_blocked(self):
        self.assertEqual(action("send_email", {"to": "a@evil.example"}), "block")
        self.assertEqual(action("send_email", {}), "block")

    def test_the_whole_value_must_match(self):
        # Each of these contains an allowed address but is not only that address.
        for to in [
            "x@evil.example, a@example.com",
            "x@evil.example\na@example.com",
            "a@example.com\n",
            "a@example.com.evil.example",
        ]:
            with self.subTest(to=to):
                self.assertEqual(action("send_email", {"to": to}), "block")

    def test_every_value_in_a_list_must_match(self):
        self.assertEqual(action("send_email", {"to": ["a@example.com", "b@example.com"]}), "ask")
        self.assertEqual(action("send_email", {"to": ["a@example.com", "x@evil.example"]}), "block")
        self.assertEqual(action("send_email", {"to": []}), "block")

    def test_object_value_is_not_allowed_even_when_its_values_match(self):
        for to in [
            {"attacker@evil.example": "boss@example.com"},
            {"email": "boss@example.com"},
            ["boss@example.com", {"cc:attacker@evil.example": "b@example.com"}],
            ["boss@example.com", {}],
            {},
        ]:
            with self.subTest(to=to):
                self.assertEqual(action("send_email", {"to": to}), "block")

    def test_nested_list_is_not_allowed(self):
        self.assertEqual(action("send_email", {"to": [["a@example.com"]]}), "block")
        self.assertEqual(action("send_email", {"to": ["a@example.com", ["b@example.com"]]}), "block")
        self.assertEqual(action("send_email", {"to": ["a@example.com", []]}), "block")

    def test_null_is_not_allowed(self):
        self.assertEqual(action("send_email", {"to": None}), "block")
        self.assertEqual(action("send_email", {"to": ["a@example.com", None]}), "block")
        policy = rules({"run": {"action": "allow", "allow_args": [{"arg": "mode", "pattern": "[a-z]+"}]}})
        self.assertEqual(policy.evaluate("run", {"mode": None}).action, "block")

    def test_boolean_is_matched_as_its_json_spelling(self):
        policy = rules({"deploy": {"action": "allow", "allow_args": [{"arg": "dry_run", "pattern": "true"}]}})
        self.assertEqual(policy.evaluate("deploy", {"dry_run": True}).action, "allow")
        self.assertEqual(policy.evaluate("deploy", {"dry_run": False}).action, "block")
        self.assertEqual(policy.evaluate("deploy", {"dry_run": 1}).action, "block")
        self.assertEqual(policy.evaluate("deploy", {}).action, "block")

    def test_number_is_matched_as_its_json_spelling(self):
        policy = rules({"resize": {"action": "allow", "allow_args": [{"arg": "count", "pattern": r"[1-5]|2\.5"}]}})
        self.assertEqual(policy.evaluate("resize", {"count": 3}).action, "allow")
        self.assertEqual(policy.evaluate("resize", {"count": 2.5}).action, "allow")
        self.assertEqual(policy.evaluate("resize", {"count": [1, 2, 3]}).action, "allow")
        self.assertEqual(policy.evaluate("resize", {"count": 7}).action, "block")
        self.assertEqual(policy.evaluate("resize", {"count": 33}).action, "block")


class OptionalAllowArgs(unittest.TestCase):
    def test_optional_argument_may_be_absent(self):
        self.assertEqual(action("send_email", {"to": "a@example.com"}), "ask")

    def test_optional_argument_with_a_bad_value_is_blocked(self):
        for name in ("cc", "bcc"):
            with self.subTest(arg=name):
                verdict = POLICY.evaluate("send_email", {"to": "a@example.com", name: "attacker@evil.example"})
                self.assertEqual(verdict.action, "block")
                self.assertEqual(verdict.reason, f"argument '{name}' has a value the policy does not allow")

    def test_optional_argument_with_a_good_value_passes(self):
        args = {"to": "a@example.com", "cc": ["b@example.com", "c@example.com"], "bcc": "d@example.com"}
        self.assertEqual(action("send_email", args), "ask")

    def test_optional_argument_given_as_null_or_empty_list_is_blocked(self):
        self.assertEqual(action("send_email", {"to": "a@example.com", "cc": None}), "block")
        self.assertEqual(action("send_email", {"to": "a@example.com", "cc": []}), "block")

    def test_required_argument_stays_required_next_to_optional_ones(self):
        verdict = POLICY.evaluate("send_email", {"cc": "b@example.com"})
        self.assertEqual(verdict.action, "block")
        self.assertEqual(verdict.reason, "argument 'to' is required by the policy but missing")


class OtherArgs(unittest.TestCase):
    def test_bcc_to_an_unapproved_address_is_blocked(self):
        self.assertEqual(action("send_email", {"to": "boss@example.com", "bcc": "attacker@evil.example"}), "block")

    def test_unnamed_argument_is_blocked_when_other_args_is_block(self):
        for extra in ("reply_to", "recipients", "headers", "Bcc"):
            with self.subTest(arg=extra):
                verdict = POLICY.evaluate("send_email", {"to": "boss@example.com", extra: "boss@example.com"})
                self.assertEqual(verdict.action, "block")
                self.assertEqual(verdict.reason, f"argument '{extra}' is not accepted by the policy")

    def test_ordinary_mail_with_a_multi_line_body_passes(self):
        args = {"to": "boss@example.com", "subject": "Monday", "body": "Hi,\n\nsee you at 10.\n"}
        self.assertEqual(action("send_email", args), "ask")
        self.assertEqual(action("send_email", {"to": "boss@example.com", "subject": "", "body": ""}), "ask")

    def test_unnamed_argument_passes_when_other_args_is_left_out(self):
        policy = rules({"send": {"action": "allow", "allow_args": [{"arg": "to", "pattern": ADDRESS}]}})
        self.assertEqual(policy.evaluate("send", {"to": "a@example.com", "bcc": "x@evil.example"}).action, "allow")

    def test_closed_rule_without_allow_args_accepts_no_arguments(self):
        policy = rules({"ping": {"action": "allow", "other_args": "block"}})
        self.assertEqual(policy.evaluate("ping", {}).action, "allow")
        self.assertEqual(policy.evaluate("ping", {"host": "example.com"}).action, "block")

    def test_other_args_must_be_allow_or_block(self):
        for value in ("ask", "deny", True, None):
            with self.subTest(value=value), self.assertRaises(PolicyError):
                rules({"x": {"action": "allow", "other_args": value}})


class WhatTheAgentIsTold(unittest.TestCase):
    def test_rule_block_default_block_and_ask_look_the_same(self):
        rule_block = POLICY.evaluate("delete_file", {})
        default_block = POLICY.evaluate("launch_rocket", {})
        ask = POLICY.evaluate("send_email", {"to": "a@example.com"})
        self.assertEqual((rule_block.action, default_block.action, ask.action), ("block", "block", "ask"))
        self.assertEqual(rule_block.public, NOT_PERMITTED)
        self.assertEqual(default_block.public, NOT_PERMITTED)
        self.assertEqual(ask.public, NOT_PERMITTED)

    def test_blocked_call_does_not_reveal_the_glob_or_the_default(self):
        for tool in ("delete_file", "run_shell", "launch_rocket"):
            with self.subTest(tool=tool):
                public = POLICY.evaluate(tool, {}).public
                self.assertNotIn("delete_*", public)
                self.assertNotIn("default", public)
                self.assertNotIn(tool, public)

    def test_ask_default_looks_like_a_block(self):
        verdict = Policy.from_dict({"default": "ask"}).evaluate("anything", {})
        self.assertEqual((verdict.action, verdict.public), ("ask", NOT_PERMITTED))

    def test_reason_keeps_the_detail_for_the_audit_log(self):
        self.assertEqual(POLICY.evaluate("delete_file", {}).reason, "rule 'delete_*' says block")
        self.assertEqual(POLICY.evaluate("launch_rocket", {}).reason, "no rule for 'launch_rocket', default is block")
        self.assertEqual(POLICY.evaluate("send_email", {"to": "a@example.com"}).reason, "rule 'send_email' says ask")

    def test_argument_blocks_name_only_the_argument(self):
        policy = rules({
            "read": {"action": "allow", "deny_args": [{"arg": "path", "pattern": "private"}]},
            "grep": {"action": "allow", "deny_args": [{"arg": "*", "pattern": "private"}]},
            "send": {"action": "allow", "allow_args": [{"arg": "to", "pattern": ADDRESS}], "other_args": "block"},
        })
        for tool, args, text in [
            ("grep", {"q": "private"}, "an argument has a value the policy denies"),
            ("read", {"path": "private"}, "argument 'path' has a value the policy denies"),
            ("send", {}, "argument 'to' is required by the policy but missing"),
            ("send", {"to": "x@evil.example"}, "argument 'to' has a value the policy does not allow"),
            ("send", {"to": "a@example.com", "bcc": "b@example.com"}, "argument 'bcc' is not accepted by the policy"),
        ]:
            with self.subTest(tool=tool, args=args):
                verdict = policy.evaluate(tool, args)
                self.assertEqual((verdict.action, verdict.reason, verdict.public), ("block", text, text))

    def test_policy_wide_and_rule_deny_lists_give_the_same_text(self):
        deny = [{"arg": "*", "pattern": "private"}]
        wide = Policy.from_dict({"default": "allow", "deny_args": deny}).evaluate("read", {"path": "private"})
        own = rules({"read": {"action": "allow", "deny_args": deny}}).evaluate("read", {"path": "private"})
        self.assertEqual(wide, own)

    def test_allowed_call_has_the_same_public_text_and_reason(self):
        for verdict in (POLICY.evaluate("read_file", {"path": "a.txt"}), POLICY.evaluate("search_web", {"q": "soup"})):
            self.assertEqual(verdict.action, "allow")
            self.assertEqual(verdict.public, verdict.reason)


class ServerRequests(unittest.TestCase):
    def test_everything_is_allowed_when_the_section_is_absent(self):
        self.assertEqual(Policy.from_dict({}).server_request_action("sampling/createMessage"), "allow")

    def test_named_method_is_blocked(self):
        policy = Policy.from_dict({"server_requests": {"sampling/createMessage": "block"}})
        self.assertEqual(policy.server_request_action("sampling/createMessage"), "block")

    def test_method_that_matches_nothing_is_allowed(self):
        policy = Policy.from_dict({"server_requests": {"sampling/createMessage": "block"}})
        self.assertEqual(policy.server_request_action("roots/list"), "allow")
        self.assertEqual(policy.server_request_action("sampling/createmessage"), "allow")  # names are case-sensitive

    def test_exact_method_beats_glob(self):
        closed = Policy.from_dict({"server_requests": {"*": "block", "roots/list": "allow"}})
        self.assertEqual(closed.server_request_action("roots/list"), "allow")
        self.assertEqual(closed.server_request_action("elicitation/create"), "block")
        self.assertEqual(POLICY.server_request_action("sampling/createMessage"), "block")
        self.assertEqual(POLICY.server_request_action("roots/list"), "allow")

    def test_block_glob_beats_allow_glob_in_both_file_orders(self):
        for section in ({"*": "allow", "sampling/*": "block"}, {"sampling/*": "block", "*": "allow"}):
            with self.subTest(order=list(section)):
                policy = Policy.from_dict({"server_requests": section})
                self.assertEqual(policy.server_request_action("sampling/createMessage"), "block")
                self.assertEqual(policy.server_request_action("roots/list"), "allow")

    def test_method_that_is_not_text_is_blocked(self):
        self.assertEqual(POLICY.server_request_action(None), "block")
        self.assertEqual(POLICY.server_request_action(["roots/list"]), "block")

    def test_section_must_map_method_names_to_allow_or_block(self):
        for section in ([], {"sampling/createMessage": "ask"}, {"x": {"action": "block"}}, {"": "block"},
                        {" roots/list": "block"}, {"roots/list ": "block"}):
            with self.subTest(section=section), self.assertRaises(PolicyError):
                Policy.from_dict({"server_requests": section})


class CallLimits(unittest.TestCase):
    def test_no_limits_by_default(self):
        self.assertEqual(rules({"read_file": "allow"}).call_limits("read_file"), [])
        self.assertIsNone(Policy.from_dict({}).max_calls_per_minute)

    def test_limit_for_all_tools_applies_to_every_tool(self):
        policy = rules({"read_file": "allow"}, limits={"max_calls_per_minute": 120})
        self.assertEqual(policy.max_calls_per_minute, 120)
        self.assertEqual(policy.call_limits("read_file"), [("*", 120)])
        self.assertEqual(policy.call_limits("tool_without_a_rule"), [("*", 120)])

    def test_rule_limit_applies_to_the_tools_the_rule_matches(self):
        policy = rules({"send_email": {"action": "allow", "max_calls_per_minute": 5}, "read_file": "allow"})
        self.assertEqual(policy.call_limits("send_email"), [("rule:send_email", 5)])
        self.assertEqual(policy.call_limits("read_file"), [])

    def test_exact_and_glob_rule_limits_both_apply(self):
        policy = rules(
            {
                "search_*": {"action": "allow", "max_calls_per_minute": 30},
                "search_web": {"action": "allow", "max_calls_per_minute": 10},
                "*_web": {"action": "allow", "max_calls_per_minute": 20},
                "*": "allow",
            },
            limits={"max_calls_per_minute": 100},
        )
        self.assertEqual(
            policy.call_limits("search_web"),
            [("*", 100), ("rule:search_*", 30), ("rule:search_web", 10), ("rule:*_web", 20)],
        )
        self.assertEqual(policy.call_limits("search_files"), [("*", 100), ("rule:search_*", 30)])

    def test_example_policy_limits(self):
        self.assertEqual(POLICY.call_limits("send_email"), [("*", 120), ("rule:send_email", 5)])
        self.assertEqual(POLICY.call_limits("read_file"), [("*", 120)])

    def test_limit_must_be_a_whole_number_of_one_or_more(self):
        for value in (0, -1, 1.5, 5.0, "5", True, None, [5]):
            with self.subTest(value=value):
                with self.assertRaises(PolicyError):
                    Policy.from_dict({"limits": {"max_calls_per_minute": value}})
                with self.assertRaises(PolicyError):
                    rules({"x": {"action": "allow", "max_calls_per_minute": value}})
        self.assertEqual(Policy.from_dict({"limits": {"max_calls_per_minute": 1}}).max_calls_per_minute, 1)


class Warnings(unittest.TestCase):
    def test_example_policy_has_no_warnings(self):
        self.assertEqual(POLICY.warnings(), [])

    def test_default_allow_is_warned_about(self):
        warnings = Policy.from_dict({"default": "allow"}).warnings()
        self.assertEqual(len(warnings), 1)
        self.assertIn('default is "allow"', warnings[0])
        self.assertEqual(Policy.from_dict({"default": "ask"}).warnings(), [])

    def test_deny_pattern_that_matches_the_empty_string_names_the_rule_and_argument(self):
        policy = rules({"send_email": {"action": "allow", "deny_args": [{"arg": "cc", "pattern": ""}]}})
        warnings = policy.warnings()
        self.assertEqual(len(warnings), 1)
        self.assertIn("tools.send_email", warnings[0])
        self.assertIn("'cc'", warnings[0])
        self.assertIn("empty string", warnings[0])

    def test_policy_wide_deny_pattern_that_matches_the_empty_string_is_warned_about(self):
        warnings = Policy.from_dict({"deny_args": [{"arg": "*", "pattern": "x*"}]}).warnings()
        self.assertEqual(len(warnings), 1)
        self.assertTrue(warnings[0].startswith("deny_args:"))
        self.assertIn("every call", warnings[0])

    def test_required_allow_pattern_that_matches_the_empty_string_names_the_rule_and_argument(self):
        policy = rules({"send_*": {"action": "allow", "allow_args": [{"arg": "to", "pattern": f"({ADDRESS})?"}]}})
        warnings = policy.warnings()
        self.assertEqual(len(warnings), 1)
        self.assertIn("tools.send_*", warnings[0])
        self.assertIn("'to'", warnings[0])
        self.assertIn("empty string", warnings[0])

    def test_optional_free_text_argument_is_not_warned_about(self):
        entry = {"arg": "body", "pattern": "(?s).*", "optional": True}
        self.assertEqual(rules({"send": {"action": "allow", "allow_args": [entry]}}).warnings(), [])

    def test_patterns_that_need_some_text_are_not_warned_about(self):
        policy = rules({"read": {
            "action": "allow",
            "deny_args": [{"arg": "path", "pattern": r"\.ssh"}],
            "allow_args": [{"arg": "path", "pattern": ".+"}],
        }})
        self.assertEqual(policy.warnings(), [])

    def test_allow_glob_under_a_stricter_catch_all_glob_is_warned_about(self):
        warnings = rules({"*": "ask", "search_*": "allow", "delete_*": "block", "read_file": "allow"}).warnings()
        self.assertEqual(len(warnings), 1)
        self.assertIn("tools.search_*", warnings[0])
        self.assertEqual(rules({"*": "block", "delete_*": "block"}).warnings(), [])

    def test_a_catch_all_allow_rule_is_warned_about_like_default_allow(self):
        for name in ("*", "**"):
            with self.subTest(rule=name):
                warnings = rules({name: "allow", "delete_*": "block"}).warnings()
                self.assertEqual(len(warnings), 1)
                self.assertIn('"default": "allow"', warnings[0])

    def test_a_deny_pattern_that_only_forbids_empty_values_is_not_warned_about(self):
        policy = rules({"search": {"action": "allow", "deny_args": [{"arg": "q", "pattern": r"^\s*$"}]}})
        self.assertEqual(policy.warnings(), [])
        self.assertEqual(policy.evaluate("search", {"q": "hello"}).action, "allow")


class FindingsOfTheSecondReview(unittest.TestCase):
    """Each test here closes a gap found when version 0.4.0 was reviewed."""

    def test_case_lookalike_letters_do_not_pass_an_allow_pattern(self):
        # Python's case-insensitive matching treats dotless i (U+0131) as "i",
        # so "acme-ınc.com" (a different, registrable domain) used to pass.
        policy = rules({"mail": {"action": "allow", "allow_args": [{"arg": "to", "pattern": r"[^@\s,;]+@acme-inc\.com"}]}})
        self.assertEqual(policy.evaluate("mail", {"to": "bob@acme-inc.com"}).action, "allow")
        self.assertEqual(policy.evaluate("mail", {"to": "BOB@ACME-INC.COM"}).action, "allow")
        self.assertEqual(policy.evaluate("mail", {"to": "ılker@acme-inc.com"}).action, "allow")  # in the free part
        for lookalike in ("bob@acme-ınc.com", "bob@acme-İnc.com", "bob@acme-inc.Kom"):
            with self.subTest(to=lookalike):
                self.assertEqual(policy.evaluate("mail", {"to": lookalike}).action, "block")

    def test_a_windows_drive_relative_path_does_not_get_round_the_example_deny_rule(self):
        for path in ("C:.ssh\\id_ecdsa", "C:.aws/credentials", "c:.env"):
            with self.subTest(path=path):
                self.assertEqual(POLICY.evaluate("read_file", {"path": path}).action, "block")
        self.assertEqual(POLICY.evaluate("resources/read", {"uri": "file:C:.aws/credentials"}).action, "block")
        self.assertEqual(POLICY.evaluate("search_web", {"q": "how do I read process.env in node"}).action, "allow")

    def test_an_empty_list_or_object_does_not_get_round_a_deny_rule_that_forbids_an_argument(self):
        policy = rules({"wipe": {"action": "allow", "deny_args": [{"arg": "force", "pattern": ""}]}})
        self.assertEqual(policy.evaluate("wipe", {"target": "x"}).action, "allow")
        for value in (True, "yes", [], {}, [[], {}]):
            with self.subTest(force=value):
                self.assertEqual(policy.evaluate("wipe", {"force": value}).action, "block")

    def test_a_wildcard_in_an_argument_name_is_an_error(self):
        for arg in ("file_*", "*path", "a*b"):
            with self.subTest(arg=arg):
                with self.assertRaises(PolicyError):
                    Policy.from_dict({"deny_args": [{"arg": arg, "pattern": "x"}]})
        Policy.from_dict({"deny_args": [{"arg": "*", "pattern": "x"}]})  # "*" alone is still fine

    def test_a_policy_built_in_code_is_validated_too(self):
        for bad in ({"default": "deny"}, {"default": "Block"}, {"secrets_in_arguments": "yes"}, {"block_severity": "max"}):
            with self.subTest(arguments=bad):
                with self.assertRaises(PolicyError):
                    Policy(**bad)

    def test_an_argument_name_is_shortened_and_escaped_before_it_is_repeated(self):
        policy = rules({"mail": {"action": "allow", "allow_args": [{"arg": "to", "pattern": ".+"}], "other_args": "block"}})
        verdict = policy.evaluate("mail", {"to": "a@example.com", "x\x1b[2J" + "y" * 5000: 1})
        self.assertEqual(verdict.action, "block")
        self.assertNotIn("\x1b", verdict.public)
        self.assertLess(len(verdict.public), 200)

    def test_a_tool_name_is_shortened_and_escaped_in_the_reason(self):
        verdict = Policy.from_dict({}).evaluate("t\x1b[2J" + "x" * 5000, {})
        self.assertNotIn("\x1b", verdict.reason)
        self.assertLess(len(verdict.reason), 300)


class Loading(unittest.TestCase):
    def assert_rejected(self, data):
        with self.assertRaises(PolicyError):
            Policy.from_dict(data)

    def test_wrong_values_are_rejected(self):
        self.assert_rejected({"default": "maybe"})
        self.assert_rejected({"tools": {"x": {"action": "permit"}}})
        self.assert_rejected({"tools": {"x": {"action": "allow", "deny_args": [{"arg": "a", "pattern": "("}]}}})
        self.assert_rejected({"deny_args": [{"arg": "a", "pattern": "("}]})
        self.assert_rejected({"injection": {"block_severity": "extreme"}})
        self.assert_rejected({"secrets": {"in_arguments": "ask"}})

    def test_wrong_shapes_are_rejected(self):
        self.assert_rejected([])
        self.assert_rejected({"tools": []})
        self.assert_rejected({"tools": {"x": 5}})
        self.assert_rejected({"tools": {"x": {"action": "allow", "deny_args": "path"}}})
        self.assert_rejected({"tools": {"x": {"action": "allow", "deny_args": [{"arg": "a"}]}}})
        self.assert_rejected({"tools": {"x": {"action": ["allow"]}}})
        self.assert_rejected({"deny_args": {"arg": "*", "pattern": "a"}})
        self.assert_rejected({"default": ["block"]})
        self.assert_rejected({"secrets": "block"})
        self.assert_rejected({"limits": 120})

    def test_typos_are_rejected_instead_of_ignored(self):
        self.assert_rejected({"defualt": "block"})
        self.assert_rejected({"tools": {"x": {"action": "allow", "deny_arg": [{"arg": "a", "pattern": "b"}]}}})
        self.assert_rejected({"tools": {"x": {"action": "allow", "deny_args": [{"arg": "a", "patern": "b"}]}}})
        self.assert_rejected({"tools": {"x": {"action": "allow", "other_arg": "block"}}})
        self.assert_rejected({"injection": {"block_severty": "high"}})
        self.assert_rejected({"secrets": {"in_argument": "block"}})
        self.assert_rejected({"limits": {"max_calls_per_minut": 5}})
        self.assert_rejected({"server_request": {}})

    def test_any_arg_is_only_for_deny_rules(self):
        self.assert_rejected({"tools": {"x": {"action": "allow", "allow_args": [{"arg": "*", "pattern": "a"}]}}})

    def test_optional_is_only_for_allow_rules_and_must_be_true_or_false(self):
        entry = {"arg": "a", "pattern": "b", "optional": True}
        self.assert_rejected({"tools": {"x": {"action": "allow", "deny_args": [entry]}}})
        self.assert_rejected({"deny_args": [entry]})
        for value in ("true", 1, None):
            with self.subTest(optional=value):
                bad_entry = {**entry, "optional": value}
                self.assert_rejected({"tools": {"x": {"action": "allow", "allow_args": [bad_entry]}}})
        self.assertTrue(rules({"x": {"action": "allow", "allow_args": [entry]}}).tools[0].allow_args[0].optional)

    def test_rule_object_without_an_action_is_rejected(self):
        for spec in ({}, {"deny_args": []}, {"allow_args": [{"arg": "to", "pattern": "a"}]}, {"other_args": "block"}):
            with self.subTest(spec=spec):
                with self.assertRaises(PolicyError) as caught:
                    rules({"run_shell": spec})
                self.assertIn("tools.run_shell needs an 'action'", str(caught.exception))

    def test_wrong_typed_block_severity_is_a_policy_error(self):
        for severity in (["high"], {"level": "high"}, 2, True):
            with self.subTest(severity=severity):
                self.assert_rejected({"injection": {"block_severity": severity}})
        self.assertIsNone(Policy.from_dict({"injection": {"block_severity": None}}).block_severity)

    def test_empty_or_padded_tool_name_is_rejected(self):
        for name in ("", " ", " run_shell", "run_shell ", "run_shell\n", "\trun_*"):
            with self.subTest(name=name):
                self.assert_rejected({"tools": {name: "block"}})

    def test_empty_or_padded_argument_name_is_rejected(self):
        for name in ("", " path", "path ", "path\n"):
            with self.subTest(name=name):
                entry = [{"arg": name, "pattern": "a"}]
                self.assert_rejected({"deny_args": entry})
                self.assert_rejected({"tools": {"x": {"action": "allow", "deny_args": entry}}})
                self.assert_rejected({"tools": {"x": {"action": "allow", "allow_args": entry}}})

    def test_pattern_with_spaces_at_its_edges_is_accepted(self):
        policy = rules({"run": {"action": "allow", "deny_args": [{"arg": "cmd", "pattern": "rm -rf "}]}})
        self.assertEqual(policy.evaluate("run", {"cmd": "rm -rf /"}).action, "block")
        self.assertEqual(policy.evaluate("run", {"cmd": "rm -rf"}).action, "allow")

    def test_new_sections_have_safe_defaults(self):
        policy = Policy.from_dict({})
        self.assertEqual(policy.deny_args, ())
        self.assertEqual(policy.secrets_in_arguments, "block")
        self.assertIsNone(policy.max_calls_per_minute)
        self.assertEqual(Policy.from_dict({"secrets": {"in_arguments": "allow"}}).secrets_in_arguments, "allow")

    def test_example_policy_sets_every_section(self):
        self.assertEqual(len(POLICY.deny_args), 1)
        self.assertEqual(POLICY.secrets_in_arguments, "block")
        self.assertEqual(POLICY.max_calls_per_minute, 120)
        self.assertEqual(POLICY.block_severity, "high")
        send_email = next(rule for rule in POLICY.tools if rule.name == "send_email")
        self.assertEqual((send_email.other_args, send_email.max_calls_per_minute), ("block", 5))


class LoadingFromAFile(unittest.TestCase):
    def assert_duplicate_key(self, text, key):
        with self.assertRaises(PolicyError) as caught:
            load_text(text)
        message = str(caught.exception)
        self.assertIn(f"duplicate key '{key}'", message)
        self.assertNotIn("not valid JSON", message)

    def test_file_that_is_not_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_bytes(b"\xff\xfe not json")
            with self.assertRaises(PolicyError):
                Policy.from_file(path)

    def test_broken_json_is_reported_as_not_valid_json(self):
        with self.assertRaises(PolicyError) as caught:
            load_text('{"default": "block",}')
        self.assertIn("not valid JSON", str(caught.exception))

    def test_file_with_a_utf8_byte_order_mark_loads(self):
        policy = load_text('{"default": "ask", "tools": {"read_file": "allow"}}', encoding="utf-8-sig")
        self.assertEqual(policy.default, "ask")
        self.assertEqual(policy.evaluate("read_file", {}).action, "allow")

    def test_duplicate_tool_name_is_rejected(self):
        text = '{"tools": {"run_shell": "block", "read_file": "allow", "run_shell": "allow"}}'
        self.assert_duplicate_key(text, "run_shell")

    def test_duplicate_deny_args_in_a_rule_is_rejected(self):
        text = """{"tools": {"read_file": {
            "action": "allow",
            "deny_args": [{"arg": "*", "pattern": "id_rsa"}],
            "deny_args": []
        }}}"""
        self.assert_duplicate_key(text, "deny_args")

    def test_duplicate_top_level_default_is_rejected(self):
        self.assert_duplicate_key('{"default": "block", "tools": {}, "default": "allow"}', "default")

    def test_duplicate_key_inside_an_argument_entry_is_rejected(self):
        text = '{"deny_args": [{"arg": "*", "pattern": "id_rsa", "pattern": "nothing"}]}'
        self.assert_duplicate_key(text, "pattern")

    def test_same_key_in_different_objects_is_fine(self):
        text = json.dumps({"tools": {
            "a": {"action": "allow", "deny_args": [{"arg": "x", "pattern": "1"}, {"arg": "x", "pattern": "2"}]},
            "b": {"action": "allow", "max_calls_per_minute": 5},
        }, "limits": {"max_calls_per_minute": 5}})
        self.assertEqual(len(load_text(text).tools), 2)


if __name__ == "__main__":
    unittest.main()
