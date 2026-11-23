"""Tests for the policy keys added in 0.5 besides flows: client_requests,
hide_blocked_tools and the secret guard's new settings.

The behaviour behind most of them lives in the proxy and the secret guard;
these tests cover loading, strict validation, the Policy API the rest of
the code reads, warnings, and how `validate` shows them.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import POLICY, ROOT
from agent_sentinel import Policy, PolicyError
from agent_sentinel.policy import NOT_PERMITTED, PERMITTED, SecretPattern


def load_error(data):
    """The message of the error that loading `data` must raise."""
    try:
        Policy.from_dict(data)
    except PolicyError as exc:
        return str(exc)
    raise AssertionError("the policy loaded, but an error was expected")


# ---- client_requests ------------------------------------------------------------------

class ClientRequests(unittest.TestCase):
    def test_without_the_section_every_method_is_allowed_as_before(self):
        verdict = POLICY.client_request_verdict("completion/complete")
        self.assertEqual((verdict.action, verdict.rule), ("allow", None))
        self.assertIsNone(POLICY.client_requests)
        self.assertFalse(POLICY.checks_prompts)

    def test_an_exact_method_beats_a_wildcard_and_a_block_among_wildcards_wins(self):
        policy = Policy.from_dict({"client_requests": {
            "*": "allow", "completion/*": "block", "completion/complete": "allow", "logging/*": "block",
        }})
        allowed = policy.client_request_verdict("completion/complete")
        blocked = policy.client_request_verdict("logging/setLevel")
        self.assertEqual((allowed.action, allowed.rule), ("allow", "client_requests.completion/complete"))
        self.assertEqual((blocked.action, blocked.rule), ("block", "client_requests.logging/*"))
        self.assertEqual(blocked.public, NOT_PERMITTED)
        self.assertEqual(policy.client_request_verdict("ping").rule, "client_requests.*")

    def test_a_method_no_rule_matches_is_allowed_and_names_no_rule(self):
        policy = Policy.from_dict({"client_requests": {"completion/complete": "block"}})
        verdict = policy.client_request_verdict("ping")
        self.assertEqual((verdict.action, verdict.rule, verdict.public), ("allow", None, PERMITTED))

    def test_calls_are_left_to_the_tools_rules(self):
        policy = Policy.from_dict({"client_requests": {"*": "block"}})
        for method in ("tools/call", "resources/read", "resources/subscribe"):
            with self.subTest(method=method):
                self.assertEqual(policy.client_request_verdict(method).action, "allow")
        self.assertIn("decided by the tools rules", load_error({"client_requests": {"tools/call": "block"}}))

    def test_a_method_that_is_not_text_is_blocked_as_malformed(self):
        verdict = POLICY.client_request_verdict(None)
        self.assertEqual((verdict.action, verdict.rule), ("block", "malformed"))

    def test_the_action_is_a_word_as_for_server_requests(self):
        # Comparing a Verdict with "block" is always False, so a name that suggests a word must return one.
        policy = Policy.from_dict({"client_requests": {"completion/complete": "block"},
                                   "server_requests": {"sampling/createMessage": "block"}})
        self.assertEqual(policy.client_request_action("completion/complete"), "block")
        self.assertEqual(policy.client_request_action("ping"), "allow")
        self.assertEqual(policy.server_request_action("sampling/createMessage"), "block")

    def test_mistakes_are_errors(self):
        cases = {
            "client_requests must be a JSON object": {"client_requests": ["ping"]},
            "did you mean 'block'?": {"client_requests": {"ping": "deny"}},
            "must be 'allow' or 'block', got 'ask'": {"client_requests": {"ping": "ask"}},
            "must be text that is not empty": {"client_requests": {" ping": "block"}},
        }
        for expected, data in cases.items():
            with self.subTest(expected=expected):
                self.assertIn(expected, load_error(data))

    def test_prompts_are_checked_only_when_the_policy_opts_in(self):
        self.assertFalse(Policy.from_dict({"tools": {"*": "allow"}}).checks_prompts)  # a wildcard does not opt in
        self.assertTrue(Policy.from_dict({"tools": {"prompts/get": "allow"}}).checks_prompts)
        self.assertTrue(Policy.from_dict({"client_requests": {}}).checks_prompts)

    def test_a_prompt_rule_judges_prompts_like_a_tool(self):
        policy = Policy.from_dict({"tools": {"prompts/get": {
            "action": "allow", "allow_args": [{"arg": "name", "one_of": ["summarise"]}],
        }}})
        self.assertEqual(policy.evaluate("prompts/get", {"name": "summarise", "arguments": {}}).action, "allow")
        self.assertEqual(policy.evaluate("prompts/get", {"name": "exfiltrate", "arguments": {}}).action, "block")

    def test_describe_rule_explains_a_client_request_rule(self):
        policy = Policy.from_dict({"client_requests": {"completion/complete": "block"}})
        self.assertEqual(policy.describe_rule("client_requests.completion/complete"),
                         "client request rule 'completion/complete': block")
        self.assertIsNone(policy.describe_rule("client_requests.ping"))


class ClientRequestWarnings(unittest.TestCase):
    def test_opting_in_without_a_prompt_rule_warns_that_the_default_refuses_prompts(self):
        warnings = Policy.from_dict({"client_requests": {"completion/complete": "block"}}).warnings()
        self.assertTrue(any(w.startswith("prompts/get is checked like a tool call") for w in warnings))

    def test_no_warning_when_prompts_have_a_rule_or_are_blocked_or_the_default_allows(self):
        for data in (
            {"client_requests": {}, "tools": {"prompts/get": "allow"}},
            {"client_requests": {"prompts/get": "block"}},
            {"client_requests": {}, "tools": {"prompts/*": "ask"}},
        ):
            with self.subTest(data=data):
                self.assertEqual(Policy.from_dict(data).warnings(), [])

    def test_blocking_the_handshake_is_reported(self):
        warnings = Policy.from_dict({"client_requests": {"*": "block"}}).warnings()
        self.assertIn("client_requests blocks 'initialize', so no client can connect", warnings)


# ---- hide_blocked_tools ----------------------------------------------------------------

class HideBlockedTools(unittest.TestCase):
    def test_it_is_off_unless_the_policy_turns_it_on(self):
        self.assertFalse(Policy.from_dict({}).hide_blocked_tools)
        self.assertTrue(Policy.from_dict({"hide_blocked_tools": True}).hide_blocked_tools)
        self.assertTrue(POLICY.hide_blocked_tools)  # the example turns it on, as the review asked

    def test_it_must_be_true_or_false(self):
        for value in ("true", 1, None, ["yes"]):
            with self.subTest(value=value):
                self.assertIn("hide_blocked_tools must be true or false", load_error({"hide_blocked_tools": value}))

    def test_the_tool_level_action_ignores_arguments(self):
        self.assertEqual(POLICY.tool_level_action("run_shell"), "block")
        self.assertEqual(POLICY.tool_level_action("delete_file"), "block")  # a wildcard
        self.assertEqual(POLICY.tool_level_action("send_email"), "ask")  # ask stays visible
        self.assertEqual(POLICY.tool_level_action("read_file"), "allow")
        self.assertEqual(POLICY.tool_level_action("launch_rocket"), "block")  # the default
        self.assertEqual(POLICY.tool_level_action(None), "block")

    def test_an_exact_rule_beats_wildcards_and_the_strictest_wildcard_wins(self):
        policy = Policy.from_dict({"tools": {"*_file": "allow", "delete_*": "block", "delete_draft": "allow"}})
        self.assertEqual(policy.tool_level_action("delete_file"), "block")
        self.assertEqual(policy.tool_level_action("delete_draft"), "allow")


# ---- secrets ------------------------------------------------------------------------------

class SecretSettings(unittest.TestCase):
    PATTERN = {"name": "Internal token", "prefix": "itk_", "charset": "alnum", "min_len": 32, "max_len": 32}

    def test_the_defaults_keep_today_s_behaviour(self):
        policy = Policy.from_dict({})
        self.assertEqual(policy.secrets_in_arguments, "block")
        self.assertEqual(policy.secrets_in_results, "off")
        self.assertEqual(
            (policy.secrets_known_values_from_env, policy.secrets_canaries, policy.secrets_patterns), ((), (), ())
        )

    def test_every_setting_loads(self):
        policy = Policy.from_dict({"secrets": {
            "in_arguments": "block", "in_results": "redact",
            "known_values_from_env": ["GITHUB_TOKEN", "DB_PASSWORD"],
            "canaries": ["sentinel-canary-3f9c1e"],
            "patterns": [self.PATTERN],
        }})
        self.assertEqual(policy.secrets_in_results, "redact")
        self.assertEqual(policy.secrets_known_values_from_env, ("GITHUB_TOKEN", "DB_PASSWORD"))
        self.assertEqual(policy.secrets_canaries, ("sentinel-canary-3f9c1e",))
        self.assertEqual(policy.secrets_patterns[0].name, "Internal token")

    def test_a_custom_format_is_compiled_from_fixed_parts(self):
        pattern = SecretPattern("Internal token", "itk.", "hex", 8, 12)
        self.assertEqual(pattern.regex.pattern, r"itk\.[0-9a-fA-F]{8,12}")
        self.assertTrue(pattern.regex.search("key=itk.deadbeef42"))
        self.assertIsNone(pattern.regex.search("key=itkXdeadbeef42"))  # the prefix is literal
        self.assertIsNone(pattern.regex.search("itk.deadbee"))  # too short

    def test_every_charset_compiles(self):
        for charset in ("alnum", "upper_alnum", "alnum_dash", "hex", "base64", "base64url"):
            with self.subTest(charset=charset):
                SecretPattern("x", "pre_", charset, 8, 8)

    def test_mistakes_in_in_results_are_errors(self):
        self.assertIn("'off' leaves results as they are", load_error({"secrets": {"in_results": "allow"}}))
        self.assertIn("did you mean 'redact'?", load_error({"secrets": {"in_results": "redacted"}}))
        self.assertIn("did you mean 'block'?", load_error({"secrets": {"in_results": "deny"}}))

    def test_mistakes_in_known_values_are_errors(self):
        cases = {
            "must be a list": "GITHUB_TOKEN",
            "Never write the value itself": ["ghp_abc def"],
            "listed twice": ["A", "A"],
            "got 5": [5],
        }
        for expected, value in cases.items():
            with self.subTest(expected=expected):
                self.assertIn(expected, load_error({"secrets": {"known_values_from_env": value}}))

    def test_mistakes_in_canaries_are_errors_that_never_repeat_the_canary(self):
        cases = {
            "8 to 200 characters long": ["zq7x"],
            "printable text with no spaces at either end": [" padded-canary "],
            "the same as an earlier canary": ["Canary-1234", "canary-1234"],
            "must be text": [12345678],
            "must be a list": "canary-string",
        }
        for expected, value in cases.items():
            with self.subTest(expected=expected):
                message = load_error({"secrets": {"canaries": value}})
                self.assertIn(expected, message)
                if isinstance(value, list) and isinstance(value[-1], str):
                    self.assertNotIn(value[-1].strip(), message)

    def test_mistakes_in_custom_formats_are_errors(self):
        cases = {
            "needs 'min_len' or 'max_len'": {k: v for k, v in self.PATTERN.items() if k not in ("min_len", "max_len")},
            "did you mean 'prefix'?": {**self.PATTERN, "prefx": "x"},
            "prefix must be 3 to 64 characters": {**self.PATTERN, "prefix": "a"},
            "no spaces or quotes": {**self.PATTERN, "prefix": 'it"k'},
            "did you mean 'alnum'?": {**self.PATTERN, "charset": "alnm"},
            "min_len must be a whole number from 8": {**self.PATTERN, "min_len": 4},
            "max_len must be a whole number": {**self.PATTERN, "max_len": 100_000},
            "is larger than max_len": {**self.PATTERN, "min_len": 40},
            "min_len must be a whole number from 8 to 1024, got true": {**self.PATTERN, "min_len": True},
            "name must be 1 to 60": {**self.PATTERN, "name": "[redacted]"},
        }
        for expected, spec in cases.items():
            with self.subTest(expected=expected):
                self.assertIn(expected, load_error({"secrets": {"patterns": [spec]}}))

    def test_a_regular_expression_is_not_accepted_as_a_prefix(self):
        # Operators sometimes reach for a regex; it must not compile into one.
        self.assertIn("prefix must be", load_error({"secrets": {"patterns": [{**self.PATTERN, "prefix": "(a+)+$"}]}}))

    def test_hostile_sizes_are_bounded(self):
        many = [dict(self.PATTERN, name=f"t{i}") for i in range(51)]
        self.assertIn("at most 50 formats", load_error({"secrets": {"patterns": many}}))
        canaries = [f"canary-{i:04}" for i in range(101)]
        self.assertIn("at most 100 canaries", load_error({"secrets": {"canaries": canaries}}))
        self.assertIn("8 to 200 characters", load_error({"secrets": {"canaries": ["c" * 1_000_000]}}))

    def test_a_policy_built_in_code_has_its_secret_settings_checked(self):
        # A text where a tuple belongs would otherwise be read one character at a time.
        for field, value, expected in [
            ("secrets_canaries", "sentinel-canary-3f9c1e", "must be a list"),
            ("secrets_canaries", ("short",), "8 to 200 characters"),
            ("secrets_known_values_from_env", "GITHUB_TOKEN", "must be a list"),
            ("secrets_known_values_from_env", ("not a name",), "NAME of an environment variable"),
            ("secrets_patterns", SecretPattern("x", "pre_", "hex", 8, 8), "must be a tuple of SecretPattern"),
            ("secrets_patterns", (self.PATTERN,), "secrets.patterns[0] must be a SecretPattern"),
        ]:
            with self.subTest(field=field, value=value):
                with self.assertRaises(PolicyError) as caught:
                    Policy(**{field: value})
                self.assertIn(expected, str(caught.exception))
        policy = Policy(secrets_canaries=["sentinel-canary-3f9c1e"], secrets_known_values_from_env=("DB_PASSWORD",),
                        secrets_patterns=[SecretPattern("x", "pre_", "hex", 8, 8)])
        self.assertEqual(policy.secrets_canaries, ("sentinel-canary-3f9c1e",))  # lists become tuples
        self.assertIsInstance(policy.secrets_patterns, tuple)

    def test_unknown_secret_keys_are_errors(self):
        self.assertIn("did you mean 'canaries'?", load_error({"secrets": {"canary": []}}))

    def test_describe_rule_names_the_parts_without_a_value(self):
        policy = Policy.from_dict({"secrets": {
            "in_results": "block", "known_values_from_env": ["DB_PASSWORD"], "canaries": ["sentinel-canary-3f9c1e"],
            "patterns": [self.PATTERN],
        }})
        self.assertIn("block", policy.describe_rule("secrets.in_results"))
        self.assertIn("DB_PASSWORD", policy.describe_rule("secrets.known_values_from_env"))
        canaries = policy.describe_rule("secrets.canaries")
        self.assertIn("1 canary", canaries)
        self.assertNotIn("sentinel-canary", canaries)
        self.assertIn("'itk_' followed by 32 characters of alnum", policy.describe_rule("secrets.patterns[0]"))
        self.assertIsNone(policy.describe_rule("secrets.patterns[1]"))
        self.assertIn("withheld", policy.describe_rule("session"))

    def test_a_variable_that_is_not_set_here_gets_a_warning(self):
        policy = Policy.from_dict({"secrets": {"known_values_from_env": ["A2_SET_VAR", "A2_UNSET_VAR"]}})
        with mock.patch.dict(os.environ, {"A2_SET_VAR": "value"}):
            os.environ.pop("A2_UNSET_VAR", None)
            warnings = policy.warnings()
        self.assertEqual(len(warnings), 1)
        self.assertIn("'A2_UNSET_VAR' is not set in this environment", warnings[0])


# ---- hook (0.6) ------------------------------------------------------------------------------

class HookSection(unittest.TestCase):
    def test_it_is_optional_and_its_defaults_change_nothing(self):
        policy = Policy.from_dict({})
        self.assertEqual((policy.hook.config_changes, policy.hook.treat_auto_as_non_prompting), ("audit", False))
        self.assertEqual(Policy.from_dict({"hook": {}}).hook, policy.hook)
        self.assertEqual(POLICY.hook, policy.hook)

    def test_both_settings_load(self):
        policy = Policy.from_dict({"hook": {"config_changes": "block", "treat_auto_as_non_prompting": True}})
        self.assertEqual((policy.hook.config_changes, policy.hook.treat_auto_as_non_prompting), ("block", True))
        self.assertIn('hook.config_changes is "block"', policy.describe_rule("hook.config_changes"))

    def test_mistakes_are_errors(self):
        for data, expected in (
            ({"hook": []}, "hook must be a JSON object"),
            ({"hook": {"config_change": "block"}}, "did you mean 'config_changes'?"),
            ({"hook": {"config_changes": "deny"}}, "hook.config_changes must be 'audit' or 'block'"),
            ({"hook": {"config_changes": None}}, "hook.config_changes must be"),
            ({"hook": {"treat_auto_as_non_prompting": "yes"}},
             "hook.treat_auto_as_non_prompting must be true or false"),
            ({"hooks": {}}, "did you mean 'hook'?"),
        ):
            with self.subTest(data=data):
                self.assertIn(expected, load_error(data))

    def test_a_policy_built_in_code_is_checked_too(self):
        from agent_sentinel.policy import HookOptions

        with self.assertRaises(PolicyError):
            HookOptions(config_changes="Block")
        with self.assertRaises(PolicyError):
            Policy(hook={"config_changes": "block"})


# ---- unknown top-level keys still fail ----------------------------------------------------

class TopLevelKeys(unittest.TestCase):
    def test_a_misspelt_new_key_is_an_error_with_a_suggestion(self):
        self.assertIn("did you mean 'hide_blocked_tools'?", load_error({"hide_blocked_tool": True}))
        self.assertIn("did you mean 'client_requests'?", load_error({"client_request": {}}))
        self.assertIn("did you mean 'flows'?", load_error({"flow": []}))


# ---- validate shows the new settings ----------------------------------------------------

class ValidateShowsTheNewSettings(unittest.TestCase):
    def validate(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(text, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "agent_sentinel", "validate", str(path)],
                capture_output=True, cwd=ROOT, timeout=60,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.decode("utf-8", errors="replace")

    def test_flows_labels_client_requests_secrets_and_hiding_are_listed(self):
        output = self.validate("""{
          "tools": {"fetch_page": {"action": "allow", "labels": ["untrusted"]},
                    "send_email": {"action": "allow", "labels": ["sink"]}, "run_shell": "block"},
          "flows": [{"after": ["untrusted"], "action": "block"}],
          "client_requests": {"completion/complete": "block"},
          "secrets": {"in_results": "redact", "canaries": ["sentinel-canary-3f9c1e"],
                      "patterns": [{"name": "Internal token", "prefix": "itk_", "charset": "alnum",
                                    "min_len": 32, "max_len": 32}]},
          "hide_blocked_tools": true
        }""")
        for expected in (
            "labels untrusted", "flows[0]  after 'untrusted' content reached the agent",
            "Client requests: completion/complete block.", "prompts/get is checked like a tool call",
            "Secrets in tool results: redact.", "Custom secret formats: Internal token.", "Canaries: 1.",
            "Hidden from the tool list (blocked outright): run_shell, every tool without a rule.",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, output)
        self.assertNotIn("sentinel-canary", output)  # a canary is never printed

    def test_an_older_policy_prints_nothing_new(self):
        output = self.validate('{"tools": {"read_file": "allow"}}')
        for absent in ("Flow rules", "Client requests", "Hidden", "Canaries", "prompts/get", "Claude Code hook"):
            self.assertNotIn(absent, output)

    def test_the_hook_settings_are_listed(self):
        output = self.validate('{"hook": {"config_changes": "block", "treat_auto_as_non_prompting": true}}')
        self.assertIn("Claude Code hook: changes to Claude Code's settings during a session are refused; an 'ask' "
                      "in auto mode is refused.", output)

    def test_every_security_setting_is_listed(self):
        # Approval memory switched off, require_labels, a command section's classes, deny entries that ask,
        # schema_checks, server_requests and classify_by_annotations false were not in the summary at all.
        output = self.validate("""{
          "default": "block", "classify_by_annotations": false, "require_labels": true,
          "deny_args": [{"arg": "p", "type": "path", "roots": ["~/.ssh"], "action": "ask"}],
          "tools": {"a": {"action": "allow", "labels": ["sink"], "schema_checks": {"arguments": "enforce"},
                          "deny_args": [{"arg": "x", "contains": "y", "action": "ask"}, {"arg": "z", "contains": "w"}],
                          "command": {"deny_classes": ["obfuscation"], "ask_classes": ["network"],
                                      "unreadable": "block"}}},
          "server_requests": {"sampling/createMessage": "block"},
          "secrets": {"known_values_from_env": ["DB_PASSWORD"], "known_values_ignore_case": ["DB_PASSWORD"]},
          "approvals": {"refusal_window_seconds": 0},
          "schema_checks": {"arguments": "warn", "remote_refs": "quarantine"}
        }""")
        for expected in (
            "Policy-wide deny rules: 1 (1 of them ask).", "2 deny rule(s) (1 of them ask)",
            "schema checks: arguments enforce",
            "tools.a.command  bash command in argument 'command': refuses obfuscation; asks for network; an "
            "unreadable command: block",
            "Server requests: sampling/createMessage block.",
            "MCP tool annotations add no flow labels (classify_by_annotations is false).",
            "Every rule that allows or asks must say its flow labels (require_labels).",
            "Approval memory: off (approvals.refusal_window_seconds is 0).",
            "Schema checks (the proxy), unless a tool rule says otherwise: arguments warn, remote_refs quarantine.",
            "(matched ignoring case: DB_PASSWORD)",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, output)
        paused = self.validate('{"approvals": {"refusal_window_seconds": 60, "max_refusals_per_tool": 0}}')
        self.assertIn("refused without asking for 60 seconds; the asks of a tool are never paused", paused)
        self.assertNotIn("Approval memory", self.validate('{"approvals": {"refusal_window_seconds": 600}}'))


if __name__ == "__main__":
    unittest.main()
