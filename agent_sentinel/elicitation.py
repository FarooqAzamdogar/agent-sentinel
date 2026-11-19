"""Checks on what a server asks the user for through elicitation.

An elicitation (elicitation/create, or an entry of an input_required result
in MCP 2026-07-28) is shown to the person at the client, not to the model.
The injection scanner still reads it, but what makes an elicitation hostile is
what it asks the person to do, so two things are checked here:

* URL mode (2025-11-25 and later): the client shows the user an address to
  open, for a sign-in or a payment. It must be a plain https address of a
  public web site (mcp_protocol.public_https_problem), at most MAX_URL_CHARS
  long, and, when the operator listed hosts (proxy --elicitation-host), on one
  of them. The same goes for the addresses in a URLElicitationRequiredError
  (-32042), which a server sends as the error reply to a request.
* Form mode: the specification says a server MUST NOT ask for passwords or
  other secrets in a form. A field whose name, title or description holds one
  of a few phrases that always mean a secret (SECRET_PHRASES) is refused.
  Words that only sometimes mean one (UNCLEAR_WORDS: "pin", "token", "key",
  ...) are reported to the operator, not refused: pin_message and token_count
  are ordinary fields.
  The form itself must have the flat shape the specification defines.

The functions are pure: they return a Review, or raise ShapeError for a
request whose shape cannot be checked, and the proxy acts on it.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Sequence

from .matchers import Matcher, build
from .mcp_protocol import ShapeError, fold_lookalikes, public_https_problem
from .textutil import printable

ELICITATION_CREATE = "elicitation/create"
URL_ELICITATION_REQUIRED = -32042  # the error code of a URLElicitationRequiredError

MAX_URL_CHARS = 2048
MAX_FORM_FIELDS = 64
# A form field's name, title and description are short labels. Longer ones are
# refused rather than read in part, so a phrase cannot hide past what is read.
MAX_FIELD_NAME_CHARS = 256
MAX_FIELD_TEXT_CHARS = 4096
MAX_URL_ELICITATIONS = 32  # addresses in one URLElicitationRequiredError
FORM_MODES = ("form", "url")
# What a form field may be (2025-11-25): text, a number, a yes/no, or a choice of several texts.
FIELD_TYPES = ("string", "number", "integer", "boolean", "array")
STRING_FORMATS = ("email", "uri", "date", "date-time")

# The audit log's rule ids for these checks (they are not rules written in the policy).
RULE_URL = "elicitation.url"
RULE_FORM = "elicitation.form"

# Phrases that always mean a secret, matched as whole words once a field's
# text is reduced to lowercase words ("apiKey" and "API_KEY" read "api key").
# A phrase of two words also matches written as one ("apikey", "passphrase").
SECRET_PHRASES = (
    "password", "pass phrase", "api key", "secret key", "private key", "card number", "cvv", "cvc", "ssn",
    "one time code",
)
# Words that mean a secret only sometimes. Reported, never refused.
UNCLEAR_WORDS = ("pin", "token", "secret", "otp", "2fa", "passcode", "credential", "credentials", "iban", "key")

# Each phrase also matches in the plural.
_SECRET_PHRASE = re.compile(
    r"\b(?:" + "|".join(phrase.replace(" ", " ?") for phrase in SECRET_PHRASES) + r")s?\b"
)
_UNCLEAR_WORD = re.compile(r"\b(?:" + "|".join(UNCLEAR_WORDS) + r")\b")
# A lowercase letter or digit followed by a capital starts a new word: "apiKey" is "api Key".
_CAMEL_CASE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NOT_A_WORD = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class Review:
    """What the checks found in one elicitation.

    refusal: why it must be refused, for the audit log and the operator; None to let it through.
    rule:    the audit rule id of a refusal (RULE_URL or RULE_FORM).
    unclear: fields whose words only sometimes mean a secret, described for the operator.
    """

    refusal: str | None = None
    rule: str = ""
    unclear: tuple[str, ...] = ()


def allowed_hosts(entries: Sequence[str]) -> Matcher | None:
    """The hosts a URL-mode elicitation may send the user to, from proxy --elicitation-host; None for no list.

    Entries are written as in a policy's "type": "url" matcher: "example.com"
    is that host only, "*.example.com" its subdomains. Raises PolicyError for
    an entry that cannot be used (a URL instead of a host, localhost, ...).
    """
    if not entries:
        return None
    return build({"type": "url", "hosts": list(entries)}, "--elicitation-host", deny=False, any_arg=False)


def review_request(params: Any, hosts: Matcher | None) -> Review:
    """Check the params of an elicitation request (elicitation/create, or an input_required entry).

    A request without a mode is a form, as before 2025-11-25.
    """
    if not isinstance(params, dict):
        raise ShapeError("an elicitation's params must be an object")
    mode = params.get("mode", "form")
    if mode not in FORM_MODES:
        raise ShapeError(f"unknown elicitation mode '{printable(mode, limit=40)}'")
    if mode == "url":
        url = params.get("url")
        if not isinstance(url, str):
            raise ShapeError("a URL-mode elicitation must have a text url")
        refusal = url_refusal(url, hosts)
        return Review(refusal, RULE_URL) if refusal else Review()
    return _review_form(params.get("requestedSchema"))


def review_url_required_error(error: Any, hosts: Matcher | None) -> Review:
    """Check the addresses in an error reply; only a URLElicitationRequiredError (-32042) has any.

    Its data must hold a list of at most MAX_URL_ELICITATIONS elicitations,
    each with a text url; one address that may not be opened refuses the reply.
    """
    if not isinstance(error, dict) or error.get("code") != URL_ELICITATION_REQUIRED:
        return Review()
    data = error.get("data")
    elicitations = data.get("elicitations") if isinstance(data, dict) else None
    if not isinstance(elicitations, list):
        raise ShapeError("a URLElicitationRequiredError must list its elicitations in data.elicitations")
    if len(elicitations) > MAX_URL_ELICITATIONS:
        raise ShapeError(f"{len(elicitations)} elicitations; at most {MAX_URL_ELICITATIONS} are accepted")
    for entry in elicitations:
        url = entry.get("url") if isinstance(entry, dict) else None
        if not isinstance(url, str):
            raise ShapeError("each elicitation in a URLElicitationRequiredError must have a text url")
        refusal = url_refusal(url, hosts)
        if refusal:
            return Review(refusal, RULE_URL)
    return Review()


def url_refusal(url: str, hosts: Matcher | None) -> str | None:
    """Why the user may not be sent to `url`, or None.

    With a host list, the URL must be https and its host listed (the url
    matcher also refuses user names, local names and private addresses).
    Without one, it must be a public https address.
    """
    shown = printable(url, limit=200)
    if len(url) > MAX_URL_CHARS:
        return f"the elicitation's address is longer than {MAX_URL_CHARS} characters"
    if hosts is not None:
        if hosts.accepts(url):
            return None
        return f"the elicitation sends the user to an address not on the --elicitation-host list: {shown}"
    problem = public_https_problem(url)
    return None if problem is None else f"the elicitation's address {problem}: {shown}"


def _review_form(schema: Any) -> Review:
    """Check a form's requestedSchema: its shape, then what each field asks for."""
    if not isinstance(schema, dict):
        raise ShapeError("a form elicitation must have a requestedSchema object")
    if schema.get("type", "object") != "object":
        raise ShapeError("a form's requestedSchema must be of type object")
    fields = schema.get("properties", {})
    if not isinstance(fields, dict):
        raise ShapeError("a form's properties must be an object")
    if len(fields) > MAX_FORM_FIELDS:
        raise ShapeError(f"the form has {len(fields)} fields; at most {MAX_FORM_FIELDS} are accepted")
    unclear: list[str] = []
    for name, field in fields.items():
        texts = _field_texts(name, field)
        words = [_as_words(text) for text in texts]
        if any(_SECRET_PHRASE.search(text) for text in words):
            reason = f"the form asks for a secret in the field '{printable(name, limit=80)}'"
            return Review(reason, RULE_FORM)
        if any(_UNCLEAR_WORD.search(text) for text in words):
            unclear.append(f"the field '{printable(name, limit=80)}'")
    return Review(unclear=tuple(unclear))


def _field_texts(name: str, field: Any) -> list[str]:
    """The texts that say what a form field is for: its name, title and description. Checks its shape first.

    A field is flat, as the specification requires: text (with an optional
    format from STRING_FORMATS), a number, a yes/no, or a list of choices.
    Its name, title and description are bounded (MAX_FIELD_NAME_CHARS, MAX_FIELD_TEXT_CHARS).
    """
    if len(name) > MAX_FIELD_NAME_CHARS:
        raise ShapeError(f"a form field's name is longer than {MAX_FIELD_NAME_CHARS} characters")
    if not isinstance(field, dict):
        raise ShapeError(f"the form field '{printable(name, limit=80)}' is not an object")
    kind = field.get("type")
    if kind not in FIELD_TYPES:
        raise ShapeError(f"the form field '{printable(name, limit=80)}' has a type a form cannot have")
    if "properties" in field or (kind == "string" and "format" in field and field["format"] not in STRING_FORMATS):
        raise ShapeError(f"the form field '{printable(name, limit=80)}' is not a plain field")
    if kind == "array":
        items = field.get("items")
        if not isinstance(items, dict) or "properties" in items or items.get("type", "string") != "string":
            raise ShapeError(f"the form field '{printable(name, limit=80)}' is not a list of choices")
    texts = [name]
    for key in ("title", "description"):
        if key in field:
            if not isinstance(field[key], str) or len(field[key]) > MAX_FIELD_TEXT_CHARS:
                raise ShapeError(f"the {key} of the form field '{printable(name, limit=80)}' is not text "
                                 f"of at most {MAX_FIELD_TEXT_CHARS} characters")
            texts.append(field[key])
    return texts


def _as_words(text: str) -> str:
    """Text as lowercase words separated by single spaces: "API_Key", "apiKey" and "api-key" all read "api key".

    Full-width letters and look-alike letters of other alphabets are folded
    first, so that "pаssword" with a Cyrillic а still reads "password".
    """
    text = unicodedata.normalize("NFKC", text)
    text = _CAMEL_CASE.sub(" ", text)
    return " ".join(_NOT_A_WORD.sub(" ", fold_lookalikes(text)).split())
