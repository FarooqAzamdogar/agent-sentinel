"""Tests for the elicitation checks (elicitation.py) and how the proxy applies them.

An elicitation asks the person at the client for something: to open an
address (URL mode), or to fill in a form. The first classes test the checks
themselves; the last ones drive a Proxy, for legacy elicitation/create
requests, 2026-07-28 input_required results and URLElicitationRequiredError
replies.
"""

import json
import tempfile
import time
import unittest
from pathlib import Path

from support import POLICY, audit_records
from test_proxy import Harness, call, request
from test_protocol import input_required, modern_call
from agent_sentinel import Firewall, Policy, PolicyError
from agent_sentinel import elicitation
from agent_sentinel.elicitation import allowed_hosts, review_request, review_url_required_error
from agent_sentinel.mcp_protocol import ShapeError

OPEN_POLICY = Policy.from_dict({"default": "allow"})  # server_requests allows every method


def form(**fields):
    return {"mode": "form", "message": "Please fill in", "requestedSchema": {"type": "object", "properties": fields}}


def text_field(**members):
    return dict({"type": "string"}, **members)


def url_mode(url):
    return {"mode": "url", "message": "Please sign in", "url": url, "elicitationId": "e1"}


def url_required_error(*urls):
    return {"code": -32042, "message": "Sign-in needed",
            "data": {"elicitations": [dict(url_mode(url), elicitationId=f"e{n}") for n, url in enumerate(urls)]}}


def read_audit(path):
    return audit_records(Path(path))


# ---- forms ----------------------------------------------------------------------------------

class Forms(unittest.TestCase):
    def test_a_field_that_asks_for_a_secret_is_refused(self):
        for name, members in (
            ("password", {}), ("user_password", {}), ("newPassword", {}), ("passwords", {}), ("PASSPHRASE", {}),
            ("API_KEY", {}), ("apiKey", {}), ("apikey", {}), ("api-key", {}), ("value", {"title": "Secret key"}),
            ("private_key", {}), ("cardNumber", {}), ("card", {"description": "Your credit card number"}),
            ("cvv", {}), ("ssn", {}), ("one_time_code", {}), ("code", {"title": "One-time code"}),
            ("pаssword", {}), ("ｐａｓｓｗｏｒｄ", {}), ("field", {"description": "Enter your GitHub pass phrase."}),
        ):
            with self.subTest(name=name, members=members):
                review = review_request(form(**{name: text_field(**members)}), None)
                self.assertEqual(review.rule, elicitation.RULE_FORM)
                self.assertIn("asks for a secret", review.refusal)

    def test_ordinary_fields_are_let_through(self):
        for name in ("max_tokens", "keyboard", "username", "email", "confirm", "passage", "compass", "spin",
                     "cardinality", "apiVersion", "keynote", "passport_country"):
            with self.subTest(name=name):
                review = review_request(form(**{name: text_field()}), None)
                self.assertIsNone(review.refusal)
                self.assertEqual(review.unclear, ())

    def test_words_that_only_sometimes_mean_a_secret_are_reported_and_let_through(self):
        # The reviewers' examples: pin_message and token_count are ordinary fields, so these are never refused.
        for name in ("pin", "token", "otp", "2fa", "iban", "sort_key", "secret", "credentials", "accessToken",
                     "pin_message", "token_count"):
            with self.subTest(name=name):
                review = review_request(form(**{name: text_field()}), None)
                self.assertIsNone(review.refusal)
                self.assertEqual(len(review.unclear), 1)

    def test_the_flat_fields_the_specification_defines_are_accepted(self):
        review = review_request(form(
            name=text_field(title="Your name", minLength=1), when=text_field(format="date-time"),
            count={"type": "integer", "minimum": 1}, ok={"type": "boolean", "default": True},
            colour={"type": "string", "enum": ["red", "blue"]},
            tags={"type": "array", "items": {"type": "string", "enum": ["a", "b"]}},
            size={"type": "array", "items": {"anyOf": [{"const": "s", "title": "Small"}]}},
        ), None)
        self.assertEqual(review, elicitation.Review())

    def test_a_form_of_an_odd_shape_is_malformed(self):
        cases = {
            "params that are not an object": "x",
            "an unknown mode": {"mode": "voice", "requestedSchema": {}},
            "no requestedSchema": {"mode": "form", "message": "hi"},
            "a schema that is not an object type": {"requestedSchema": {"type": "array"}},
            "properties that are a list": {"requestedSchema": {"type": "object", "properties": []}},
            "a field that is text": form(name="string"),
            "a field of an unknown type": form(name={"type": "file"}),
            "a nested object": form(address={"type": "object", "properties": {"street": text_field()}}),
            "properties inside a field": form(name=text_field(properties={})),
            "an unknown string format": form(site=text_field(format="hostname")),
            "a list of objects": form(rows={"type": "array", "items": {"type": "object"}}),
            "a title that is not text": form(name=text_field(title=["password"])),
            "too many fields": form(**{f"f{n}": text_field() for n in range(elicitation.MAX_FORM_FIELDS + 1)}),
        }
        for what, params in cases.items():
            with self.subTest(what):
                with self.assertRaises(ShapeError):
                    review_request(params, None)

    def test_a_form_without_a_mode_is_a_form(self):
        params = {"message": "hi", "requestedSchema": {"type": "object", "properties": {"password": text_field()}}}
        self.assertIsNotNone(review_request(params, None).refusal)

    def test_a_field_with_an_overlong_label_is_malformed_rather_than_read_in_part(self):
        hidden = "x" * elicitation.MAX_FIELD_TEXT_CHARS + " Enter your password."
        for params in (form(field=text_field(description=hidden)), form(**{"f" * 300: text_field()})):
            with self.assertRaises(ShapeError):
                review_request(params, None)

    def test_a_hostile_form_is_checked_quickly(self):
        limit = elicitation.MAX_FIELD_TEXT_CHARS
        fields = {
            f"f{n}": text_field(title=text[:limit], description=text[:limit])
            for n, text in enumerate(("a" + "̖́" * limit, "api " * limit, "aA" * limit, "ﬁ" * limit))
        }
        started = time.perf_counter()
        for _ in range(16):  # as many such fields as a form may have
            review_request(form(**fields), None)
        self.assertLess(time.perf_counter() - started, 3)

    def test_a_label_that_grows_too_much_when_normalised_is_refused_quickly(self):
        # U+FDFA becomes 18 characters under NFKC: a form full of it used to take seconds to read.
        label = "ﷺ" * elicitation.MAX_FIELD_TEXT_CHARS
        started = time.perf_counter()
        for _ in range(elicitation.MAX_FORM_FIELDS):
            with self.assertRaises(ShapeError):
                review_request(form(f=text_field(title=label, description=label)), None)
        self.assertLess(time.perf_counter() - started, 3)
        # A little growth is ordinary: a ligature, a circled digit, a squared word.
        self.assertIsNone(review_request(form(f=text_field(title="㍿ ﬁle ①")), None).refusal)


# ---- addresses --------------------------------------------------------------------------------

class Addresses(unittest.TestCase):
    def test_without_a_host_list_any_public_https_address_is_allowed(self):
        for url in ("https://github.com/login/device", "https://auth.example.com/cb?state=a%20b",
                    "https://EXAMPLE.com."):
            with self.subTest(url=url):
                self.assertIsNone(review_request(url_mode(url), None).refusal)

    def test_an_address_that_is_not_a_public_https_one_is_refused(self):
        for url in (
            "http://login.example.com/", "javascript:alert(1)", "file:///etc/passwd", "https://user@login.example.com/",
            "https://10.0.0.1/", "https://[::1]/", "https://localhost:8080/", "https://wiki.corp/",
            "https://xn--pple-43d.com/", "https://аpple.com/", "https://login.example.com\\@evil.example/",
            "https://exa mple.com/", "https://2852039166/", "",
        ):
            with self.subTest(url=url):
                review = review_request(url_mode(url), None)
                self.assertEqual(review.rule, elicitation.RULE_URL)
                self.assertIsNotNone(review.refusal)

    def test_with_a_host_list_only_listed_hosts_are_allowed(self):
        hosts = allowed_hosts(["auth.example.com", "*.login.example.org"])
        for url, allowed in (
            ("https://auth.example.com/x", True), ("https://eu.login.example.org/x", True),
            ("https://login.example.org/x", False), ("https://evil.example/x", False),
            ("http://auth.example.com/x", False), ("https://auth.example.com.evil.example/x", False),
        ):
            with self.subTest(url=url):
                self.assertEqual(review_request(url_mode(url), hosts).refusal is None, allowed)

    def test_an_address_longer_than_the_limit_is_refused(self):
        url = "https://auth.example.com/?" + "a" * elicitation.MAX_URL_CHARS
        self.assertIn("longer than", review_request(url_mode(url), None).refusal)

    def test_a_url_mode_request_without_a_text_url_is_malformed(self):
        for params in ({"mode": "url"}, {"mode": "url", "url": ["https://a.example.com"]}):
            with self.subTest(params=params):
                with self.assertRaises(ShapeError):
                    review_request(params, None)

    def test_the_refusal_shows_the_address_safely(self):
        review = review_request(url_mode("http://evil.example/\x1b[2J"), None)
        self.assertNotIn("\x1b", review.refusal)

    def test_a_host_list_entry_that_cannot_be_used_is_refused_clearly(self):
        for entry in ("https://auth.example.com/", "localhost", "10.0.0.1", "*", "xn--pple-43d.com"):
            with self.subTest(entry=entry):
                with self.assertRaises(PolicyError) as caught:
                    allowed_hosts([entry])
                self.assertIn("--elicitation-host", str(caught.exception))
        self.assertIsNone(allowed_hosts([]))

    def test_a_url_required_error_is_checked_like_a_url_mode_elicitation(self):
        self.assertIsNone(review_url_required_error(url_required_error("https://a.example.com/"), None).refusal)
        review = review_url_required_error(url_required_error("https://a.example.com/", "http://b.example.com/"), None)
        self.assertEqual(review.rule, elicitation.RULE_URL)

    def test_other_errors_are_not_url_required_errors(self):
        for error in ({"code": -32000, "message": "x", "data": {"elicitations": "?"}}, "text", None, {"code": True}):
            with self.subTest(error=error):
                self.assertEqual(review_url_required_error(error, None), elicitation.Review())

    def test_a_malformed_url_required_error_is_refused(self):
        for data in (None, {}, {"elicitations": "https://a.example.com"}, {"elicitations": [{"url": 5}]},
                     {"elicitations": ["https://a.example.com"]},
                     {"elicitations": [url_mode("https://a.example.com")] * (elicitation.MAX_URL_ELICITATIONS + 1)}):
            with self.subTest(data=data):
                with self.assertRaises(ShapeError):
                    review_url_required_error({"code": -32042, "message": "m", "data": data}, None)


# ---- in the proxy ---------------------------------------------------------------------------------

class ElicitationInTheProxy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.audit = Path(self.tmp.name) / "audit.jsonl"

    def harness(self, policy=OPEN_POLICY, monitor=False, **options):
        return Harness(Firewall(policy, audit_path=self.audit, monitor=monitor), **options)

    def records(self):
        return read_audit(self.audit) if self.audit.exists() else []

    def server_asks(self, h, params, msg_id=70):
        """The server sends elicitation/create; return (what the client got, what the server got)."""
        h.from_server(request(msg_id, "elicitation/create", params))
        return h.sent_to_client(), h.sent_to_server()

    def test_a_form_asking_for_a_password_is_refused_and_the_server_told_nothing(self):
        h = self.harness()
        to_client, to_server = self.server_asks(h, form(github_token=text_field(title="Personal access token"),
                                                        password=text_field()))
        self.assertEqual(to_client, [])
        self.assertEqual(to_server[0]["error"]["message"], "Blocked by agent-sentinel: request refused")
        (record,) = self.records()
        self.assertEqual((record["event"], record["rule"], record["tool"]),
                         ("server_request", "elicitation.form", "server:elicitation/create"))

    def test_a_url_to_an_unlisted_host_is_refused(self):
        h = self.harness(elicitation_hosts=["auth.example.com"])
        to_client, to_server = self.server_asks(h, url_mode("https://login.evil-example.test/oauth"))
        self.assertEqual(to_client, [])
        self.assertIn("error", to_server[0])
        self.assertIn("not on the --elicitation-host list", h.warnings.getvalue())

    def test_a_url_to_a_listed_host_reaches_the_client(self):
        h = self.harness(elicitation_hosts=["auth.example.com"])
        to_client, to_server = self.server_asks(h, url_mode("https://auth.example.com/oauth"))
        self.assertEqual(len(to_client), 1)
        self.assertEqual(to_server, [])

    def test_an_unclear_field_is_reported_and_reaches_the_client(self):
        h = self.harness()
        to_client, _ = self.server_asks(h, form(pin=text_field(title="Your PIN")))
        self.assertEqual(len(to_client), 1)
        self.assertIn("the elicitation asks for the field 'pin', which may be a secret", h.warnings.getvalue())
        self.assertEqual([record["action"] for record in self.records()], ["note"])

    def test_monitor_mode_lets_a_refused_form_through_but_not_a_malformed_one(self):
        h = self.harness(monitor=True)
        to_client, _ = self.server_asks(h, form(password=text_field()))
        self.assertEqual(len(to_client), 1)
        to_client, to_server = self.server_asks(h, form(address={"type": "object"}), msg_id=71)
        self.assertEqual(to_client, [])
        self.assertIn("error", to_server[0])
        self.assertEqual([record["action"] for record in self.records()], ["would_block", "block"])

    def test_when_the_policy_blocks_elicitation_the_policy_decides_first(self):
        policy = Policy.from_dict({"default": "allow", "server_requests": {"elicitation/create": "block"}})
        h = self.harness(policy)
        self.server_asks(h, form(name=text_field()))
        self.assertEqual(self.records()[0]["rule"], "server_requests.elicitation/create")

    def test_an_input_required_elicitation_asking_for_a_password_refuses_the_reply(self):
        h = self.harness()
        h.from_client(modern_call(1, "search", {}))
        h.sent_to_server()
        ask = {"method": "elicitation/create", "params": form(password=text_field())}
        h.from_server({"jsonrpc": "2.0", "id": 1, "result": input_required({"login": ask})})
        (refusal,) = h.sent_to_client()
        self.assertTrue(refusal["result"]["isError"])
        self.assertIn("the server asked for input that is not permitted", refusal["result"]["content"][0]["text"])
        self.assertEqual(self.records()[-1]["rule"], "elicitation.form")

    def test_an_input_required_url_elicitation_is_checked_too(self):
        h = self.harness()
        h.from_client(modern_call(1, "search", {}))
        h.sent_to_server()
        ask = {"method": "elicitation/create", "params": url_mode("https://login.evil-example.test/")}
        h.from_server({"jsonrpc": "2.0", "id": 1, "result": input_required({"login": ask})})
        self.assertEqual(len(h.sent_to_client()), 1)  # a public https address, and no host list: allowed
        h.from_client(modern_call(2, "search", {}))
        h.sent_to_server()
        ask = {"method": "elicitation/create", "params": url_mode("http://login.evil-example.test/")}
        h.from_server({"jsonrpc": "2.0", "id": 2, "result": input_required({"login": ask})})
        self.assertTrue(h.sent_to_client()[0]["result"]["isError"])

    def test_a_url_required_error_to_an_unsafe_address_is_refused(self):
        h = self.harness()
        h.from_client(call(1, "search", {}))
        h.sent_to_server()
        h.from_server({"jsonrpc": "2.0", "id": 1, "error": url_required_error("http://login.evil-example.test/")})
        (refusal,) = h.sent_to_client()
        self.assertTrue(refusal["result"]["isError"])
        self.assertNotIn("evil-example", json.dumps(refusal))
        self.assertEqual(self.records()[-1]["rule"], "elicitation.url")

    def test_a_url_required_error_to_a_safe_address_is_delivered(self):
        h = self.harness()
        h.from_client(request(1, "resources/read", {"uri": "file:///notes.txt"}))
        h.sent_to_server()
        error = url_required_error("https://auth.example.com/start")
        h.from_server({"jsonrpc": "2.0", "id": 1, "error": error})
        self.assertEqual(h.sent_to_client(), [{"jsonrpc": "2.0", "id": 1, "error": error}])

    def test_a_malformed_url_required_error_is_refused(self):
        h = self.harness()
        h.from_client(call(1, "search", {}))
        h.sent_to_server()
        h.from_server({"jsonrpc": "2.0", "id": 1, "error": {"code": -32042, "message": "m", "data": "?"}})
        (refusal,) = h.sent_to_client()
        self.assertIn("malformed reply", refusal["error"]["message"])

    def test_with_the_example_policy_a_clean_elicitation_still_reaches_the_client(self):
        h = Harness(Firewall(POLICY))
        to_client, _ = self.server_asks(h, form(folder=text_field(title="Which folder?")))
        self.assertEqual(len(to_client), 1)


if __name__ == "__main__":
    unittest.main()
