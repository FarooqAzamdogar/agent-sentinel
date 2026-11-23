"""Recognise secrets that should not leave in a tool call, reach the agent in a result, or sit in a log.

The injection detector looks at text coming IN from tools. This module looks
at secrets: a hijacked agent that has read a private key or an API token will
try to pass it to a tool (an HTTP request, an e-mail, a search query), and a
tool can hand a key to the agent in the first place (`cat .env`).

What counts as a secret:

  * Built-in formats with a fixed, recognisable shape (`_FORMATS`), so that a
    match is very likely a real credential. This is not a general "high
    entropy string" detector: those flag ordinary identifiers and hashes.
  * Custom formats the operator declares (policy `secrets.patterns`): a
    literal prefix, then a run of one character set (`CustomFormat`).
  * Exact values: the values of named environment variables (policy
    `secrets.known_values_from_env`), and canaries, strings the user planted
    in private files (policy `secrets.canaries`).

The module-level functions (`find_secrets`, `redact`, `redact_value`) know
the built-in formats only. A `SecretGuard` knows everything one policy names;
the firewall builds one.

Three uses, with different needs:

  * Blocking (`SecretGuard.find`) decides whether a call or result is refused.
    A false alarm blocks honest work, so it wants evidence: a key header must
    be followed by key material, and the vaguest token shapes must look
    random. A JWT never blocks: public ones (sample tokens, ID tokens) are
    common, so JWTs are only redacted.
  * Redacting a log (`redact`, `redact_value`) removes more, because a false
    alarm costs nothing there: a key header alone, every canary, every value.
  * Redacting a result for the agent (`SecretGuard.redact_result`) removes
    what blocking would find, plus JWTs, and keeps the rest of the content as
    it was. It never removes a canary: a canary must stay with the private
    text it marks, so that it trips the guard if that text is sent out.
    Markers for formats and values that the operator declared say only
    "[redacted secret]", so the agent learns nothing about the policy.

Every use reads through simple disguises: percent-encoding (up to three
rounds), and base64 or hex, one level deep and within fixed limits (see
`_MAX_ENCODED_RUNS`): a hijacked agent can wrap a key in either to get it
past a pattern. Base64 or hex that decodes to binary data, a token behind a
few NUL bytes or inside a file, is read as Latin-1, up to
textutil.MAX_BINARY_BYTES of it. A known value or canary is also looked for
in its own base64 and hex spellings, wherever it sits inside a longer
encoded text (and in blocks of base64 wrapped over lines, joined up), and in
a folded spelling of each text (NFKC, without format characters: full-width
letters and zero-width spaces do not hide it).
Canaries, and known values made only of hex digits and "-" (or named in
secrets.known_values_ignore_case), are matched with case ignored. Numbers
are read as JSON writes them, and a known value or canary of digits only is
found inside one (`find_in_numbers`). A key encoded twice, split up (except
over the arguments of one call, see the firewall), or placed after enough
other encoded runs to use up the limits still passes.

Adding a built-in format: anchor it on a literal prefix and give it explicit
length bounds, and make sure it cannot match a double quote. Do not use "\\b":
an underscore, or the "n" of a written-out "\\n", counts as a word character
and would hide a token that follows it. A prefix that occurs nowhere else
needs no guard in front; a common or short one takes `_NOT_AFTER`. List the
literal text every match contains as its `needles`: a text without them is
never searched with the pattern. Add a positive and a negative example to
tests/test_leaks.py, and a long repetitive input of the new prefix to its
hostile-input tests.
"""

from __future__ import annotations

import base64
import itertools
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from typing import Any, Callable, NamedTuple

from .textutil import (
    MAX_CONTAINERS,
    EncodedRuns,
    UnscannableError,
    folded_text,
    number_text,
    percent_decoded,
    texts_in,
)

_NOT_AFTER = r"(?<![A-Za-z0-9])"  # the token does not continue a longer word
_NOT_BEFORE = r"(?![A-Za-z0-9])"
_NOT_BEFORE_URLSAFE = r"(?![A-Za-z0-9_-])"


def _looks_random(token: str) -> bool:
    """True for text with a digit and a capital letter in it, as generated keys have."""
    return any(ch.isdigit() for ch in token) and any(ch.isupper() for ch in token)


def _varied(token: str) -> bool:
    """True for text that mixes at least two of capitals, small letters and digits.

    Generated tokens almost always do. A placeholder ("glpat-xxxxxxxxxxxxxxxxxxxx")
    or a long identifier in one case does not.
    """
    kinds = (any(ch.isupper() for ch in token), any(ch.islower() for ch in token), any(ch.isdigit() for ch in token))
    return sum(kinds) >= 2


def _mixed_case(token: str) -> bool:
    """True for text with both capitals and small letters (Hugging Face tokens are letters only)."""
    return any(ch.isupper() for ch in token) and any(ch.islower() for ch in token)


def _varied_last_part(url: str) -> bool:
    """For a webhook URL: its secret, the part after the last "/", must look generated (not "XXXX...")."""
    return _varied(url.rpartition("/")[2])


class _Format(NamedTuple):
    kind: str  # shown in logs, reasons and markers; it never contains the secret
    # Literal text that every match contains. A text without any of it is not
    # searched with `pattern` at all: looking for a literal is many times faster
    # than running a pattern that starts with a guard.
    needles: tuple[str, ...]
    pattern: re.Pattern[str]
    accept: Callable[[str], bool] | None = None  # an extra test of the whole match
    blocks: bool = True  # False: only ever redacted, never a reason to refuse

    def may_be_in(self, text: str) -> bool:
        return any(needle in text for needle in self.needles)


# The built-in formats. A prefix that occurs nowhere else ("ghp_", "xoxb-") is
# matched wherever it stands, even glued to other text. Where the body has a
# fixed length, a guard after it keeps a longer run of letters from matching.
# Sources for the shapes: each provider's documentation (GitLab's "Token
# prefixes" table, for one), and the public gitleaks rules
# (github.com/gitleaks/gitleaks, config/gitleaks.toml).
_FORMATS: tuple[_Format, ...] = (
    # Not the key that AWS prints in its own documentation.
    _Format(
        "AWS access key", ("AKIA", "ASIA"),
        re.compile(_NOT_AFTER + r"(?:AKIA|ASIA)(?![0-9A-Z]{9}EXAMPLE)[0-9A-Z]{16}" + _NOT_BEFORE),
    ),
    # Classic tokens (personal, OAuth, user-to-server, server-to-server, refresh) and fine-grained ones.
    _Format(
        "GitHub token", ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
        re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255}"),
    ),
    # Personal, project and group tokens (glpat-), deploy, runner, CI job, trigger, feed, incoming mail,
    # Kubernetes agent, OAuth application secret, SCIM, feature-flag and workspace tokens, and the old
    # runner registration token (GR1348941). The newer "routable" tokens end in a dot and a version and
    # checksum ("glpat-<27 or more>.01xxxxxxx"); that part is matched too, so it is replaced with the rest.
    _Format(
        "GitLab token",
        (
            "glpat-", "gldt-", "glrt", "glcbt-", "glptt-", "glft-", "glimt-", "glagent-", "gloas-", "glsoat-",
            "glffct-", "glwt-", "GR1348941",
        ),
        re.compile(
            _NOT_AFTER + r"(?:gl(?:pat|dt|rtr|rt|cbt|ptt|ft|imt|agent|oas|soat|ffct|wt)-|GR1348941)"
            r"[A-Za-z0-9_-]{20,300}(?:\.[0-9a-z]{2,9}){0,2}" + _NOT_BEFORE
        ),
        _varied,
    ),
    # Bot, user, app-level, refresh and configuration tokens ("xoxe.xoxp-1-..." holds "xoxp-").
    _Format(
        "Slack token", ("xox", "xapp-"),
        re.compile(r"xox[abeprs]-[A-Za-z0-9-]{10,255}|xapp-\d-[A-Za-z0-9-]{10,255}"),
    ),
    _Format(
        "Slack webhook URL", ("hooks.slack.com/",),
        re.compile(r"(?:https?://)?hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9_/+-]{40,200}"),
        _varied_last_part,
    ),
    _Format("Google API key", ("AIza",), re.compile(_NOT_AFTER + r"AIza[0-9A-Za-z_-]{35}" + _NOT_BEFORE_URLSAFE)),
    _Format("Google OAuth token", ("ya29.",), re.compile(_NOT_AFTER + r"ya29\.[A-Za-z0-9_-]{20,2048}"), _varied),
    _Format(
        "Google OAuth client secret", ("GOCSPX-",), re.compile(r"GOCSPX-[A-Za-z0-9_-]{28}" + _NOT_BEFORE_URLSAFE)
    ),
    # Secret and restricted keys; "test" mode keys are left alone (Stripe's own docs publish some).
    _Format("Stripe live key", ("k_live_", "k_prod_"), re.compile(r"[sr]k_(?:live|prod)_[A-Za-z0-9]{20,255}")),
    # API, admin and OAuth keys: sk-ant-api03-, sk-ant-admin01-, sk-ant-oat01-, ...
    _Format("Anthropic API key", ("sk-ant-",), re.compile(r"sk-ant-[A-Za-z0-9_-]{20,255}")),
    # Project, service-account and admin keys. Must look random: "sk-proj-" also starts CSS class names.
    _Format(
        "OpenAI API key", ("sk-proj-", "sk-svcacct-", "sk-admin-"),
        re.compile(_NOT_AFTER + r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,255}"), _looks_random,
    ),
    _Format("OpenRouter API key", ("sk-or-v1-",), re.compile(r"sk-or-v1-[0-9a-f]{64}" + _NOT_BEFORE)),
    # "sk-" alone also starts product slugs and CSS classes ("sk-hynix-platinum-..."),
    # so this vaguer form must stand on its own and look random. Older OpenAI keys
    # and those of several other providers have this shape.
    _Format(
        "API key", ("sk-",),
        re.compile(_NOT_AFTER + r"sk-(?!ant-|proj-|svcacct-|admin-|or-v1-)[A-Za-z0-9_-]{32,255}"), _looks_random,
    ),
    _Format("Groq API key", ("gsk_",), re.compile(_NOT_AFTER + r"gsk_[A-Za-z0-9]{48,64}" + _NOT_BEFORE), _varied),
    _Format("xAI API key", ("xai-",), re.compile(_NOT_AFTER + r"xai-[A-Za-z0-9]{40,128}" + _NOT_BEFORE), _varied),
    _Format(
        "Perplexity API key", ("pplx-",), re.compile(_NOT_AFTER + r"pplx-[A-Za-z0-9]{48}" + _NOT_BEFORE), _varied
    ),
    _Format(
        "Hugging Face token", ("hf_", "api_org_"),
        re.compile(_NOT_AFTER + r"(?:hf_|api_org_)[A-Za-z0-9]{34}" + _NOT_BEFORE), _mixed_case,
    ),
    _Format("npm token", ("npm_",), re.compile(_NOT_AFTER + r"npm_[A-Za-z0-9]{36}" + _NOT_BEFORE), _varied),
    # Upload tokens are macaroons whose fixed start encodes "pypi.org" (or "test.pypi.org").
    _Format(
        "PyPI token", ("pypi-Ag",),
        re.compile(r"pypi-(?:AgEIcHlwaS5vcmc|AgENdGVzdC5weXBpLm9yZw)[A-Za-z0-9_-]{50,1000}"),
    ),
    _Format(
        "SendGrid API key", ("SG.",),
        re.compile(_NOT_AFTER + r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}" + _NOT_BEFORE_URLSAFE),
    ),
    _Format("DigitalOcean token", ("_v1_",), re.compile(_NOT_AFTER + r"do[opr]_v1_[0-9a-f]{64}" + _NOT_BEFORE)),
    _Format(
        "Shopify token", ("shpat_", "shpca_", "shppa_", "shpss_"),
        re.compile(r"shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}" + _NOT_BEFORE),
    ),
    _Format("Databricks token", ("dapi",), re.compile(_NOT_AFTER + r"dapi[0-9a-f]{32}(?:-\d)?" + _NOT_BEFORE)),
    # Personal and organisation access tokens.
    _Format(
        "Docker Hub token", ("dckr_",),
        re.compile(r"dckr_(?:pat|oat)_[A-Za-z0-9_-]{27,64}" + _NOT_BEFORE_URLSAFE), _varied,
    ),
    _Format(
        "HashiCorp Vault token", ("hvs.", "hvb."),
        re.compile(_NOT_AFTER + r"hv[sb]\.[A-Za-z0-9_-]{90,300}"), _varied,
    ),
    _Format("Postman API key", ("PMAK-",), re.compile(r"PMAK-[0-9a-fA-F]{24}-[0-9a-fA-F]{34}" + _NOT_BEFORE)),
    _Format("Linear API key", ("lin_api_",), re.compile(r"lin_api_[A-Za-z0-9]{40}" + _NOT_BEFORE), _varied),
    _Format(
        "age secret key", ("AGE-SECRET-KEY-1",), re.compile(r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}")
    ),
    # In a connection string. The storage key is 64 bytes, a shared access key 32, both in base64.
    _Format("Azure storage key", ("AccountKey=",), re.compile(r"AccountKey=[A-Za-z0-9+/]{86}==")),
    _Format(
        "Azure shared access key", ("AccessKey=",),
        re.compile(_NOT_AFTER + r"(?:Shared)?AccessKey=[A-Za-z0-9+/]{43}="),
    ),
    # header.payload.signature, each base64url; header and payload are JSON objects, so they start "eyJ".
    # Only where a run of base64url characters begins: that keeps a hostile "eyJeyJeyJ..." from being
    # tried at every third position. Redacted, never a reason to refuse (see the module docstring).
    _Format(
        "JWT", ("eyJ",),
        re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,2048}\.eyJ[A-Za-z0-9_-]{5,8192}\.[A-Za-z0-9_-]{0,2048}"),
        blocks=False,
    ),
)

_PRIVATE_KEY = "private key"
_PEM_BEGIN = re.compile(r"-----BEGIN (?:[A-Z0-9]{1,20} ){0,4}PRIVATE KEY(?: BLOCK)?-----")
_PEM_END = "-----END"
_PEM_MAX_BODY = 100_000  # longer than a large PGP key block; bounds the search for the END line
# What follows a real key header: base64. Text that merely mentions the header does not have it.
_KEY_MATERIAL = re.compile(r"[A-Za-z0-9+/]{24}")
_KEY_MATERIAL_REACH = 300

_DECODE_ROUNDS = 3
_PERCENT_ESCAPE = re.compile("%[0-9A-Fa-f]{2}")
# A run of URL-like text: escapes and characters that are not spaces, quotes,
# angle or square brackets (a marker is in square brackets). Each character is
# read once: a run ends where neither an escape nor such a character follows.
_URL_RUN = re.compile(r"(?:%[0-9A-Fa-f]{2}|[^\s\"'<>%\[\]])+")
# Percent-encoded runs whose decoded text is checked, per text redacted.
_MAX_PERCENT_RUNS = 256

# Base64 and hex runs decoded per text checked or redacted: at most this many
# runs, and this many decoded bytes in all (see textutil.EncodedRuns).
_MAX_ENCODED_RUNS = 64
_MAX_DECODED_BYTES = 64 * 1024
# Shorter than the detector's minimum lengths, because one key is short: an
# AWS access key is 28 characters of base64 and 40 of hex.
_MIN_BASE64_CHARS = 24
_MIN_HEX_CHARS = 40
# A text without a run this long of base64 (or hex) characters has nothing to
# decode: checked before a decoder is made for each of many small strings.
_MAY_BE_ENCODED = re.compile(f"[A-Za-z0-9+/_-]{{{min(_MIN_BASE64_CHARS, _MIN_HEX_CHARS)}}}")
# Two or more lines that hold nothing but base64 characters: base64 wrapped
# over lines, as the base64 tool writes it (every 76 characters) or as anyone
# can (every 5). Each such block is also read with its line breaks taken out,
# so that a value or token wrapped before its 24th character is seen whole.
# At most _MAX_WRAPPED_BLOCKS blocks, and the first _MAX_UNWRAPPED_CHARS
# characters of each (as much as a call's arguments are read joined).
_WRAPPED_BLOCK = re.compile(
    r"^[A-Za-z0-9+/_-]{1,1000}(?:\r?\n[A-Za-z0-9+/_-]{1,1000}){1,100000}={0,2}\r?$", re.MULTILINE
)
_MAX_WRAPPED_BLOCKS = 64
_MAX_UNWRAPPED_CHARS = 100_000
# A known value made only of hex digits and "-" (a hex key, a UUID): matched
# with case ignored, since upper-casing it loses nothing for whoever receives it.
_HEX_VALUE = re.compile(r"[0-9A-Fa-f-]+")

# The characters a number's JSON text can hold ("-12.5e+30", "NaN", "-Infinity").
_NUMBER_TEXT_CHARS = frozenset("0123456789+-.eE" + "NaNInfinity")

# Exact values (canaries, values of environment variables) shorter than this are
# not looked for: they would match ordinary text. A canary is checked for this
# length when the policy is loaded; an environment variable is checked when read.
MIN_VALUE_CHARS = 8
# Longer values are not looked for (an environment variable can hold a whole file).
MAX_VALUE_CHARS = 64 * 1024
# No secret of any kind is shorter than this, so a shorter text needs no redacting:
# the shortest are exact values (MIN_VALUE_CHARS); every format is longer.
_SHORTEST_SECRET = MIN_VALUE_CHARS

# Where a secret came from (Found.source).
BUILT_IN = "built-in format"
CUSTOM = "custom format"
KNOWN_VALUE = "known value"
CANARY = "canary"


class CannotRedact(ValueError):
    """A result holds a secret in a part that cannot be rebuilt without it."""


@dataclass(frozen=True)
class Found:
    """One kind of secret found in a text. Never holds the secret itself.

    kind:   for reasons and the log: "GitHub token", a custom format's name,
            "value of DB_PASSWORD", "canary".
    source: BUILT_IN, CUSTOM, KNOWN_VALUE or CANARY.
    index:  for CUSTOM, the format's position in the list the guard was given
            (the policy's `secrets.patterns[<index>]`).
    blocks: False for a kind that is only ever redacted (a JWT).
    """

    kind: str
    source: str
    index: int = 0
    blocks: bool = True


# --------------------------------------------------------------------------
# Custom formats
# --------------------------------------------------------------------------


class CustomFormat:
    """An operator's secret format: a literal prefix, then min_len to max_len characters of one set.

    It finds what the regular expression ``re.escape(prefix) + "[chars]{min_len,max_len}"``
    finds (policy.SecretPattern.regex, with no guard at either end, so a token
    glued to other text is still found), but by hand and in linear time. The
    regular expression can take seconds on a hostile megabyte when the prefix
    repeats itself in the body's characters ("aaa" before "a" * 1023): it
    tries the body again at every copy of the prefix.

    name:       shown in reasons and in the log's markers; never shown to the agent.
    body_chars: the characters of the body, as written in a regex class ("A-Za-z0-9").
    """

    def __init__(self, name: str, prefix: str, body_chars: str, min_len: int, max_len: int) -> None:
        if not prefix or not 0 < min_len <= max_len:
            raise ValueError("a custom format needs a prefix and 0 < min_len <= max_len")
        self.name = name
        self.prefix = prefix
        self.min_len = min_len
        self.max_len = max_len
        self._body_run = re.compile(f"[{body_chars}]*")

    def spans(self, text: str) -> Iterator[tuple[int, int]]:
        """(start, end) of each match, left to right and not overlapping, as re.finditer would give them.

        Linear: each copy of the prefix is found once, and each run of body
        characters is measured once, however many copies of the prefix it holds.
        """
        run_start = run_end = -1  # the last run of body characters measured: text[run_start:run_end]
        position = 0
        while True:
            start = text.find(self.prefix, position)
            if start < 0:
                return
            body = start + len(self.prefix)
            if not run_start <= body <= run_end:
                # Everything from `body` to the end of this run is a body character,
                # so a later copy of the prefix whose body starts inside it ends there too.
                run_start, run_end = body, self._body_run.match(text, body).end()
            length = run_end - body
            if length >= self.min_len:
                end = body + min(length, self.max_len)
                yield start, end
                position = end
            else:
                # A later copy of the prefix whose body starts in this run has an
                # even shorter body: the next match can only start past the run.
                position = max(start + 1, run_end - len(self.prefix) + 1)

    def found_in(self, text: str) -> bool:
        return next(self.spans(text), None) is not None

    def replaced(self, text: str, marker: Callable[[], str]) -> str:
        """`text` with each match replaced by what `marker()` returns."""
        pieces: list[str] = []
        position = 0
        for start, end in self.spans(text):
            pieces += [text[position:start], marker()]
            position = end
        if not pieces:
            return text
        pieces.append(text[position:])
        return "".join(pieces)


# --------------------------------------------------------------------------
# Exact values and their encoded spellings
# --------------------------------------------------------------------------


def known_values_from_environment(
    names: Iterable[str], environ: Mapping[str, str]
) -> tuple[dict[str, str], list[str]]:
    """Read the values of the named environment variables, for SecretGuard(known_values=...).

    Returns (name -> value, warnings). A variable that is not set, or whose
    value (without surrounding spaces) is shorter than MIN_VALUE_CHARS or
    longer than MAX_VALUE_CHARS, is left out with a warning. Warnings name the
    variable only, never its value.
    """
    values: dict[str, str] = {}
    warnings: list[str] = []
    for name in names:
        value = environ.get(name)
        if value is None:
            warnings.append(f"{name} is not set, so its value is not guarded")
            continue
        value = value.strip()
        if len(value) < MIN_VALUE_CHARS:
            warnings.append(
                f"the value of {name} is shorter than {MIN_VALUE_CHARS} characters, so it is not guarded "
                "(it would match ordinary text)"
            )
        elif len(value) > MAX_VALUE_CHARS:
            warnings.append(f"the value of {name} is longer than {MAX_VALUE_CHARS} characters, so it is not guarded")
        else:
            values[name] = value
    return values, warnings


_BASE64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=")
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")
_TO_STANDARD_BASE64 = str.maketrans("-_", "+/")


def _base64_cores(data: bytes) -> list[str]:
    """The part of the base64 of `data` that is the same wherever `data` sits in a longer text.

    Base64 turns 3 bytes into 4 characters, so the characters it writes for
    `data` depend on how many bytes came before it (0, 1 or 2 more than a
    multiple of 3). For each of the three, this keeps the characters made of
    `data`'s bits alone, leaving out the one or two at each edge that mix in
    a neighbour's bits. One of the three is in the base64 of any text that
    holds `data`. Standard alphabet; the caller also reads "-" and "_" as "+"
    and "/".
    """
    cores = []
    for offset in range(3):
        encoded = base64.b64encode(bytes(offset) + data).decode("ascii")
        first = -(-8 * offset // 6)  # the first character whose bits all belong to `data`
        end = 8 * (offset + len(data)) // 6  # one past the last such character
        cores.append(encoded[first:end])
    return cores


def _form_regex(form: str) -> str:
    """A regular expression for one base64 core that reads both alphabets."""
    return "".join("[+-]" if ch == "+" else "[/_]" if ch == "/" else ch for ch in form)


class _Spelling:
    """One spelling of a text, with the copies the value search needs, each made once and only when needed."""

    def __init__(self, text: str) -> None:
        self.text = text
        self._lower: str | None = None
        self._standard_base64: str | None = None

    @property
    def lower(self) -> str:
        if self._lower is None:
            self._lower = self.text.lower()
        return self._lower

    @property
    def standard_base64(self) -> str:
        """The text with the URL-safe base64 characters ("-", "_") read as the standard ones ("+", "/")."""
        if self._standard_base64 is None:
            self._standard_base64 = self.text.translate(_TO_STANDARD_BASE64)
        return self._standard_base64


class _Value:
    """An exact value to look for, written out and in base64 and hex, ready to search and replace."""

    def __init__(self, text: str, kind: str, source: str, ignore_case: bool) -> None:
        self.kind = kind
        self.source = source
        self.ignore_case = ignore_case
        # A canary is matched ignoring case. Its encoded spellings depend on
        # case, so they are made for the canary as written, in small letters
        # and in capitals.
        variants = list(dict.fromkeys((text, text.lower(), text.upper()) if ignore_case else (text,)))
        self.plain = text.lower() if ignore_case else text
        self.base64_forms = tuple(dict.fromkeys(core for v in variants for core in _base64_cores(v.encode())))
        self.hex_forms = tuple(dict.fromkeys(v.encode().hex() for v in variants))
        self.plain_regex = re.compile(re.escape(text), re.IGNORECASE if ignore_case else 0)
        self.base64_regex = re.compile("|".join(_form_regex(form) for form in self.base64_forms))
        self.hex_regex = re.compile("|".join(self.hex_forms), re.IGNORECASE)

    def found_in(self, spelling: _Spelling) -> bool:
        if self.plain in (spelling.lower if self.ignore_case else spelling.text):
            return True
        if any(form in spelling.standard_base64 for form in self.base64_forms):
            return True
        return any(form in spelling.lower for form in self.hex_forms)


# --------------------------------------------------------------------------
# The guard
# --------------------------------------------------------------------------


class SecretGuard:
    """The secrets one policy asks for: the built-in formats, plus custom formats, known values and canaries.

    custom_formats: CustomFormat entries, in the policy's order (Found.index).
    known_values:   environment variable name -> value (see known_values_from_environment).
    canaries:       strings planted in private files; matched ignoring case.
    ignore_case:    names of known values that are matched ignoring case as
                    well (secrets.known_values_ignore_case). A value made only
                    of hex digits and "-" always is.

    Values shorter than MIN_VALUE_CHARS or longer than MAX_VALUE_CHARS are
    left out. Thread-safe: nothing in it changes after it is built, except a
    cache of folded values that is replaced in one step.
    """

    def __init__(
        self,
        custom_formats: Sequence[CustomFormat] = (),
        known_values: Mapping[str, str] | None = None,
        canaries: Sequence[str] = (),
        ignore_case: Iterable[str] = (),
    ) -> None:
        self._custom = tuple(custom_formats)
        caseless = frozenset(ignore_case)
        values = [
            _Value(value, f"value of {name}", KNOWN_VALUE,
                   ignore_case=name in caseless or _HEX_VALUE.fullmatch(value) is not None)
            for name, value in (known_values or {}).items()
            if MIN_VALUE_CHARS <= len(value) <= MAX_VALUE_CHARS
        ]
        values += [
            _Value(canary, "canary", CANARY, ignore_case=True)
            for canary in canaries
            if MIN_VALUE_CHARS <= len(canary) <= MAX_VALUE_CHARS
        ]
        self._values = tuple(values)
        # The values a number can carry: those of ASCII digits only (a PIN, an account number).
        self._digit_values = tuple(value for value in values if value.plain.isascii() and value.plain.isdigit())
        # The custom formats a number can carry: those whose prefix could stand in a number's JSON text.
        self._number_formats = tuple(custom for custom in self._custom if _NUMBER_TEXT_CHARS.issuperset(custom.prefix))
        # The values in the form `shows_a_value` compares them in: (the fold function, the folded values).
        self._folded: tuple[Callable[[str], str], tuple[str, ...]] | None = None

    @property
    def has_values(self) -> bool:
        """True when the guard has known values or canaries to look for."""
        return bool(self._values)

    @property
    def reads_numbers(self) -> bool:
        """True when a number can carry something the guard looks for, so that numbers are worth reading.

        A known value or canary of digits only, or a custom format whose prefix
        could stand in a number's JSON text ("4111"). No built-in format can:
        each has letters in it.
        """
        return bool(self._digit_values or self._number_formats)

    # ---- finding ---------------------------------------------------------------

    def find(
        self, text: str, *, formats: bool = True, canaries: bool = True, redaction_only: bool = False
    ) -> list[Found]:
        """What would make a call or a result with `text` in it refused: each kind of secret once.

        formats:        look for the built-in and custom formats (the policy's
                        secrets.in_arguments "allow" turns this off for calls).
        canaries:       look for canaries (not wanted in results; see the module docstring).
        redaction_only: also report the kinds that are only ever redacted (JWTs),
                        with Found.blocks False: to learn whether a result
                        needs redacting at all.

        Percent-decoded spellings are read too: in a URL the character before a
        token is often "%20" or "%3D", which would otherwise glue it to a word.
        So are base64 and hex runs, decoded once (see the module docstring).
        """
        found: list[Found] = []
        spellings = [(spelling, True) for spelling in _spellings(text)]
        if self._values:
            spellings += [(block, False) for block in _unwrapped_blocks(text)]
        for spelling, any_kind in spellings:
            for item in self._found_in(
                spelling, formats=formats and any_kind, canaries=canaries, redaction_only=redaction_only
            ):
                if item not in found:
                    found.append(item)
        return found

    def find_in_texts(
        self, texts: Iterable[str], *, formats: bool = True, canaries: bool = True, redaction_only: bool = False
    ) -> list[Found]:
        """`find` over several texts: each kind of secret once."""
        found: list[Found] = []
        for text in texts:
            for item in self.find(text, formats=formats, canaries=canaries, redaction_only=redaction_only):
                if item not in found:
                    found.append(item)
        return found

    def find_in_numbers(self, numbers: Iterable[str], *, formats: bool = True, canaries: bool = True) -> list[Found]:
        """What would make a call refused in its numbers, each written as JSON (textutil.numbers_in).

        A known value or canary counts only if it is made of digits alone (and,
        like every value, has at least MIN_VALUE_CHARS of them): it is then
        found inside a number's digits, as "4485039271" is inside 4485039271
        or 4485039271.5. A custom format whose prefix is digits is found too.
        No other value can be spelled by a number, so none is looked for.
        """
        joined = "\n".join(numbers)  # a line break is in no value or format: nothing matches across two numbers
        if not joined:
            return []
        found = self._found_in(joined, formats=formats, canaries=canaries, redaction_only=False, values=False)
        found += [
            Found(value.kind, value.source)
            for value in self._digit_values
            if (canaries or value.source != CANARY) and value.plain in joined
        ]
        return list(dict.fromkeys(found))

    def _number_kind(self, number: str) -> tuple[str, str] | None:
        """(kind, source) of the known value, canary or custom format a number's JSON text carries, or None."""
        for value in self._digit_values:
            if value.plain in number:
                return value.kind, value.source
        for custom in self._number_formats:
            if custom.found_in(number):
                return custom.name, CUSTOM
        return None

    def shows_a_value(self, text: str, fold: Callable[[str], str], shortest_part: int = 6) -> bool:
        """Whether `text` shows a known value or canary in another spelling, or a part of one cut off at either end.

        For a detector excerpt (firewall): it is cut from a matching view,
        which may spell a value differently from the text as it arrived
        ("_" read as a space, accents dropped, decoded), so the log's exact
        redaction would miss it; and the cut may go through a value. `fold`
        turns the text and every value into the form they are compared in
        (detector.folded_for_comparison). A value with fewer than
        `shortest_part` characters in that form, and a part of a value
        shorter than that, are not counted.
        """
        shown = fold(text)
        if not shown:
            return False
        for value in self._folded_values(fold):
            if len(value) < shortest_part:
                continue
            if value in shown:
                return True
            for size in range(shortest_part, min(len(value), len(shown) + 1)):
                if shown.startswith(value[-size:]) or shown.endswith(value[:size]):
                    return True
        return False

    def _folded_values(self, fold: Callable[[str], str]) -> tuple[str, ...]:
        cached = self._folded
        if cached is None or cached[0] is not fold:
            cached = (fold, tuple(fold(value.plain) for value in self._values))
            self._folded = cached  # one assignment: another thread sees the old pair or the new one
        return cached[1]

    def _found_in(
        self, text: str, *, formats: bool, canaries: bool, redaction_only: bool, values: bool = True
    ) -> list[Found]:
        found: list[Found] = []
        if formats:
            if _holds_a_private_key(text):
                found.append(Found(_PRIVATE_KEY, BUILT_IN))
            found += [
                Found(item.kind, BUILT_IN, blocks=item.blocks)
                for item in _formats_that_may_be_in(text)
                if (item.blocks or redaction_only) and _format_found(item, text)
            ]
            found += [Found(custom.name, CUSTOM, index) for index, custom in enumerate(self._custom)
                      if custom.found_in(text)]
        if self._values and values:
            spellings = [_Spelling(text)]
            folded = folded_text(text)  # full-width letters, zero-width spaces between them
            if folded != text:
                spellings.append(_Spelling(folded))
            found += [
                Found(value.kind, value.source)
                for value in self._values
                if (canaries or value.source != CANARY) and any(value.found_in(spelling) for spelling in spellings)
            ]
        return found

    # ---- redacting ---------------------------------------------------------------

    def redact(self, text: str) -> str:
        """`text` for a log: every secret replaced with a marker such as ``[redacted GitHub token]``.

        A base64, hex or percent-encoded run that holds a secret is replaced
        whole, with a marker such as ``[redacted GitHub token (base64)]``.
        """
        return _Redaction(self, for_agent=False).text(text)

    def redact_value(self, value: Any) -> Any:
        """A copy of a JSON-like value for a log, with the secrets in its strings and keys replaced.

        Applied to the values themselves, before they are written as JSON. Working
        on the JSON text instead would be wrong twice over: an escape such as
        "\\n" puts a letter in front of a token and hides it from the patterns, and
        a replacement that eats part of an escape leaves a line that is not JSON.
        A number (an int or a float, never true or false) whose JSON text carries
        a known value or canary of digits, or a custom format, becomes the marker
        text. Values of other types are kept as they are (the log writes them
        through `redact(str(value))`). Iterative, because the value can be nested deeply.
        """
        # Collecting the texts first costs a walk; it pays only when there are values to rule out.
        within = texts_in(value, keys=True) if self._values else None
        redaction = _Redaction(self, for_agent=False, within=within)
        numbers = self.reads_numbers
        holder: list[Any] = [None]
        stack: list[tuple[Any, Any, Any]] = [(value, holder, 0)]
        while stack:
            item, parent, key = stack.pop()
            if isinstance(item, str):
                parent[key] = redaction.text(item)
            elif numbers and type(item) in (int, float):
                carried = self._number_kind(number_text(item))
                parent[key] = item if carried is None else redaction._marker(*carried)
            elif isinstance(item, dict):
                copy: dict[Any, Any] = {}
                parent[key] = copy
                for name, child in item.items():
                    name = redaction.text(name) if isinstance(name, str) else name
                    copy[name] = None  # holds the place, so that the order of keys is kept
                    stack.append((child, copy, name))
            elif isinstance(item, (list, tuple)):
                items: list[Any] = [None] * len(item)
                parent[key] = items
                stack.extend((child, items, index) for index, child in enumerate(item))
            else:
                parent[key] = item
        return holder[0]

    def redact_result(self, value: Any) -> tuple[Any, tuple[str, ...]]:
        """A tool result with its secrets replaced, for the agent; and the kinds that were replaced.

        Replaces what `find` would refuse (canaries excepted), and JWTs. A
        format or value the operator declared becomes "[redacted secret]";
        a built-in format keeps its name ("[redacted GitHub token]").

        When nothing is replaced, `value` itself is returned (not a copy).
        Otherwise a copy, in which text, dict, list and tuple values (exactly
        those types) are rebuilt and None, booleans and numbers are kept. A
        part of any other type is kept as it is if no text in it holds a secret.

        Raises CannotRedact, rather than return something that still holds a
        secret, when a secret sits where the copy cannot be rebuilt: in a part
        of another type (bytes, a set, a dataclass, a subclass of str or dict,
        ...), or in a value that contains itself; or when two keys of one
        object become the same once redacted. Raises UnscannableError for a
        value that cannot be read at all or has more than MAX_CONTAINERS parts.

        Every string is read, which takes time on a large value: a caller can
        first ask `find(..., canaries=False, redaction_only=True)` over the
        value's text views whether anything needs replacing. Redaction works
        string by string, so a secret split over several strings is still
        there afterwards: check the copy with `find` before passing it on.
        """
        if type(value) is str:
            redaction = _Redaction(self, for_agent=True)
            redacted = redaction.text(value)
            return (redacted, redaction.kinds()) if redaction.replaced else (value, ())
        wanted = any(item.source != CANARY for item in self._values)  # canaries stay in results
        within = texts_in(value, keys=True, strict=True) if wanted else None
        redaction = _Redaction(self, for_agent=True, within=within)
        copy = _rebuilt(value, redaction)
        return (copy, redaction.kinds()) if redaction.replaced else (value, ())


def _rebuilt(value: Any, redaction: _Redaction) -> Any:
    """A copy of `value` with every exact str, dict, list and tuple rebuilt through `redaction`.

    A part of another type is kept as it is, after checking that redaction
    would not change any text in it (CannotRedact otherwise). Iterative,
    because the value can be nested deeply.
    """
    holder: list[Any] = [None]
    stack: list[tuple[Any, Any, Any]] = [(value, holder, 0)]
    inside: set[int] = set()  # the containers being copied right now, by id()
    opened = 0
    while stack:
        item, parent, key = stack.pop()
        if parent is _LEAVE:
            # Everything inside one container has been copied: a tuple can now be made.
            container_id, items, tuple_parent, tuple_key = item
            inside.discard(container_id)
            if tuple_parent is not None:
                tuple_parent[tuple_key] = tuple(items)
            continue
        kind = type(item)
        if kind is str:
            parent[key] = redaction.text(item)
        elif item is None or kind in (bool, int, float):
            parent[key] = item
        elif kind in (dict, list, tuple):
            if id(item) in inside:
                raise CannotRedact("the result contains itself, so a copy without its secrets cannot be made")
            opened += 1
            if opened > MAX_CONTAINERS:
                raise UnscannableError("the value has too many nested parts to redact")
            inside.add(id(item))
            if kind is dict:
                copy = _rebuilt_dict(item, redaction)
                parent[key] = copy
                stack.append(((id(item), None, None, None), _LEAVE, None))
                # Pushed in reverse, so that the values are copied in order.
                stack.extend((child, copy, name) for name, child in reversed(list(zip(copy, item.values()))))
            else:
                items: list[Any] = [None] * len(item)
                parent[key] = items
                tuple_parent = parent if kind is tuple else None
                stack.append(((id(item), items, tuple_parent, key), _LEAVE, None))
                stack.extend((child, items, index) for index, child in reversed(list(enumerate(item))))
        else:
            _check_kept(item, redaction.guard)
            parent[key] = item
    return holder[0]


_LEAVE = object()  # on _rebuilt's stack: the point where everything inside a container has been copied


def _rebuilt_dict(item: dict[Any, Any], redaction: _Redaction) -> dict[Any, Any]:
    """A dict with the same keys, redacted and in the same order, each holding None until its value is copied."""
    copy: dict[Any, Any] = {}
    for name in item:
        if type(name) is str:
            new_name = redaction.text(name)
        else:
            if not (name is None or type(name) in (bool, int, float)):
                _check_kept(name, redaction.guard)  # a tuple or a str subclass used as a key
            new_name = name
        if new_name in copy:
            raise CannotRedact("two keys of one object are the same once their secrets are replaced")
        copy[new_name] = None
    return copy


def _check_kept(item: Any, guard: SecretGuard) -> None:
    """Refuse to keep a part that cannot be rebuilt if redaction would change any text in it.

    The text is collected the way the scanner collects it (texts_in, strict),
    so whatever the detector will read in this part is what is checked here.
    """
    texts = texts_in(item, keys=True, strict=True)
    probe = _Redaction(guard, for_agent=True, within=texts)
    for text in texts:
        probe.text(text)
        if probe.replaced:
            raise CannotRedact(f"a value of type {type(item).__name__} holds a secret and cannot be rebuilt without it")


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------


class _Redaction:
    """Replaces secrets in texts, for one audience, and remembers which kinds it replaced.

    for_agent=False (a log): every format, every value and canary, and any
    private-key header. for_agent=True (a result): what would block, plus
    JWTs; no canaries; a key header only when key material follows it; and
    "[redacted secret]" for what the operator declared.

    within: every text that will be given to `text`, when the caller knows
    them in advance (the strings and keys of one value). Exact values that
    occur in none of them, in any spelling `find` reads, are then not looked
    for string by string: with many values and many small strings, that
    search would cost a pass per value over every string.
    """

    def __init__(
        self, guard: SecretGuard, for_agent: bool, within: Iterable[str] | None = None,
        values: Sequence[_Value] | None = None,
    ) -> None:
        self.guard = guard
        self.for_agent = for_agent
        self._kinds: list[str] = []
        if values is None:
            values = [value for value in guard._values if not (for_agent and value.source == CANARY)]
            if within is not None and values:
                values = _values_present(values, within)
        self._values = values  # the exact values looked for (passed on to probes)

    @property
    def replaced(self) -> bool:
        return bool(self._kinds)

    def kinds(self) -> tuple[str, ...]:
        """The kinds replaced so far, each once, in the order first met."""
        return tuple(dict.fromkeys(self._kinds))

    def text(self, text: str) -> str:
        """`text` with its secrets replaced; the kinds replaced are added to `kinds()`."""
        if len(text) < _SHORTEST_SECRET:
            return text
        text = self._plain(text)
        if _MAY_BE_ENCODED.search(text):
            text = self._encoded_runs(text)
        if "%" in text:
            text = self._percent_runs(text)
        return text

    def _marker(self, kind: str, source: str, encoding: str = "") -> str:
        self._kinds.append(kind)
        if self.for_agent and source in (CUSTOM, KNOWN_VALUE):
            kind = "secret"  # the operator's names are not for the agent
        return f"[redacted {kind}{f' ({encoding})' if encoding else ''}]"

    def _plain(self, text: str) -> str:
        """Replace the secrets written out in `text`, and the base64 and hex spellings of exact values."""
        text = self._private_keys(text)
        for item in _formats_that_may_be_in(text):
            if item.pattern.search(text) is None:
                continue
            text = item.pattern.sub(
                lambda match, item=item: self._marker(item.kind, BUILT_IN)
                if item.accept is None or item.accept(match.group()) else match.group(),
                text,
            )
        for custom in self.guard._custom:
            text = custom.replaced(text, partial(self._marker, custom.name, CUSTOM))
        if self._values:
            # One spelling for all the values: making its copies costs a pass over the text.
            spelling = _Spelling(text)
            for value in self._values:
                if value.found_in(spelling):
                    text = self._value(value, text)
                    spelling = _Spelling(text)
        return text

    def _private_keys(self, text: str) -> str:
        if "-----BEGIN" not in text:
            return text
        before = text
        text = _redact_private_keys(text, needs_material=self.for_agent)
        if text != before:
            self._marker(_PRIVATE_KEY, BUILT_IN)
        return text

    def _value(self, value: _Value, text: str) -> str:
        """Replace `value` in `text`: written out, and each base64 or hex run that spells it, whole."""
        text = value.plain_regex.sub(lambda match: self._marker(value.kind, value.source), text)
        for regex, alphabet, encoding in (
            (value.base64_regex, _BASE64_CHARS, "base64"),
            (value.hex_regex, _HEX_CHARS, "hex"),
        ):
            marker = partial(self._marker, value.kind, value.source, encoding)
            text = _replace_encoded_runs(text, regex, alphabet, marker)
        return text

    def _probe(self, text: str) -> tuple[str, str] | None:
        """(kind, source) of the first secret written out in `text`, or None. Nothing is recorded."""
        probe = _Redaction(self.guard, self.for_agent, values=self._values)
        probe._plain(text)
        if not probe._kinds:
            return None
        kind = probe._kinds[0]
        return kind, _source_of(kind, self.guard)

    def _encoded_runs(self, text: str) -> str:
        """Replace each base64 or hex run in `text` whose decoded text holds a secret. One level only."""
        for run in _decoder().decoded(text):
            found = self._probe(run.text)
            if found is not None:
                text = text.replace(run.run, self._marker(*found, run.kind))
        return text

    def _percent_runs(self, text: str) -> str:
        """Replace each percent-encoded run whose decoded text holds a secret, such as a key written "%67%68%70%5F...".

        A secret that was written out is already gone; this finds one whose own
        characters were encoded. At most _MAX_PERCENT_RUNS runs are decoded.
        The whole text is decoded and read first, so that text with escapes
        but no secret (most URLs) costs one pass, not one per run.
        """
        if self._probe(_percent_decoded(text)) is None:
            return text
        examined = 0
        pieces: list[str] = []
        position = 0
        for match in _URL_RUN.finditer(text):
            run = match.group()
            if "%" not in run:
                continue
            decoded = _percent_decoded(run)
            if len(decoded) < _SHORTEST_SECRET:
                continue
            examined += 1
            if examined > _MAX_PERCENT_RUNS:
                break
            found = self._probe(decoded)
            if found is not None:
                pieces += [text[position : match.start()], self._marker(*found, "percent-encoded")]
                position = match.end()
        pieces.append(text[position:])
        return "".join(pieces)


def _source_of(kind: str, guard: SecretGuard) -> str:
    """Which source a kind found by a probe came from, so that the marker hides the operator's names."""
    if any(kind == custom.name for custom in guard._custom):
        return CUSTOM
    for value in guard._values:
        if kind == value.kind:
            return value.source
    return BUILT_IN


def _replace_encoded_runs(
    text: str, regex: re.Pattern[str], alphabet: frozenset[str], marker: Callable[[], str]
) -> str:
    """Replace the whole base64 or hex run around each match of `regex` with a marker.

    The match is the part of the run that spells the value; the characters
    around it carry the rest of the encoded text (and the value's edge bits),
    so the run goes as a whole.
    """
    pieces: list[str] = []
    position = 0
    for match in regex.finditer(text):
        if match.start() < position:
            continue  # inside a run that was already replaced
        start, end = match.start(), match.end()
        while start > position and text[start - 1] in alphabet:
            start -= 1
        while end < len(text) and text[end] in alphabet:
            end += 1
        pieces += [text[position:start], marker()]
        position = end
    if not pieces:
        return text
    pieces.append(text[position:])
    return "".join(pieces)


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


# Any literal that some built-in format's matches contain: one search for it rules out every format.
_NEEDLES = sorted({needle for item in _FORMATS for needle in item.needles}, key=len, reverse=True)
_ANY_NEEDLE = re.compile("|".join(re.escape(needle) for needle in _NEEDLES))


def _formats_that_may_be_in(text: str) -> list[_Format]:
    """The built-in formats whose literal text occurs in `text`: the only ones worth searching for."""
    if _ANY_NEEDLE.search(text) is None:
        return []
    return [item for item in _FORMATS if item.may_be_in(text)]


def _format_found(item: _Format, text: str) -> bool:
    if item.accept is None:
        return item.pattern.search(text) is not None
    return any(item.accept(match.group()) for match in item.pattern.finditer(text))


def _values_present(values: Sequence[_Value], texts: Iterable[str]) -> list[_Value]:
    """The values that occur somewhere in `texts`, read in every spelling `find` reads.

    A value that a string holds, written out or in base64 or hex, is a piece
    of all the strings joined; one that is percent-encoded is a piece of the
    joined text decoded. Blocks of wrapped base64 are also read joined up,
    and the joined text in its folded spelling.
    """
    joined = "\n".join(texts)
    spellings = _spellings(joined) + _unwrapped_blocks(joined)
    folded = folded_text(joined)
    if folded != joined:
        spellings.append(folded)
    present: set[int] = set()
    for text in spellings:
        spelling = _Spelling(text)
        present.update(id(value) for value in values if id(value) not in present and value.found_in(spelling))
        if len(present) == len(values):
            break
    return [value for value in values if id(value) in present]


def _percent_decoded(text: str) -> str:
    """`text` with its percent-encoding undone, up to _DECODE_ROUNDS times."""
    for _ in range(_DECODE_ROUNDS):
        if not _PERCENT_ESCAPE.search(text):
            break
        text = percent_decoded(text)
    return text


def _spellings(text: str) -> list[str]:
    """`text`, its percent-decoded spellings, and the text of its base64 and hex runs (see the module docstring);
    binary runs as Latin-1."""
    spellings = [text]
    for _ in range(_DECODE_ROUNDS):
        if not _PERCENT_ESCAPE.search(spellings[-1]):
            break
        spellings.append(percent_decoded(spellings[-1]))
    decoder = _decoder()
    for spelling in list(spellings):
        spellings.extend(run.text for run in decoder.decoded(spelling))
    return spellings


def _unwrapped_blocks(text: str) -> list[str]:
    """Each block of wrapped base64 in `text` that is long enough to hold a secret, with its line breaks taken out.

    For exact values only: their base64 spellings are found anywhere in a
    block once it is joined up. Not for the formats, which would read the
    arguments of a call glued to their names.
    """
    if "\n" not in text:
        return []
    blocks = []
    for match in itertools.islice(_WRAPPED_BLOCK.finditer(text), _MAX_WRAPPED_BLOCKS):
        joined = match.group()[: 2 * _MAX_UNWRAPPED_CHARS].replace("\r", "").replace("\n", "")[:_MAX_UNWRAPPED_CHARS]
        if len(joined) >= _MIN_BASE64_CHARS:
            blocks.append(joined)
    return blocks


def _decoder() -> EncodedRuns:
    """A decoder of base64 and hex runs with the limits of one text; binary runs come back as Latin-1."""
    return EncodedRuns(
        max_attempts=_MAX_ENCODED_RUNS, max_kept=_MAX_ENCODED_RUNS, max_bytes=_MAX_DECODED_BYTES,
        min_base64_chars=_MIN_BASE64_CHARS, min_hex_chars=_MIN_HEX_CHARS, binary=True,
    )


def _holds_a_private_key(text: str) -> bool:
    for begin in _PEM_BEGIN.finditer(text):
        if _KEY_MATERIAL.search(text, begin.end(), begin.end() + _KEY_MATERIAL_REACH):
            return True
    return False


def _redact_private_keys(text: str, needs_material: bool = False) -> str:
    """Replace each PEM private key, from its BEGIN line to its END line.

    Done by hand instead of with one regular expression: a pattern with an
    open-ended body is slow on text that repeats the BEGIN line many times.
    If no END line is in reach (a key that was cut off, or a very long block)
    everything in reach is removed: better to lose some text than to keep
    key material. needs_material: leave a header that no key material follows
    (text that only mentions it), as the blocking check does.
    """
    pieces: list[str] = []
    pos = 0
    for begin in _PEM_BEGIN.finditer(text):
        if begin.start() < pos:
            continue  # inside a key that was already replaced
        if needs_material and not _KEY_MATERIAL.search(text, begin.end(), begin.end() + _KEY_MATERIAL_REACH):
            continue
        limit = min(len(text), begin.end() + _PEM_MAX_BODY)
        end = text.find(_PEM_END, begin.end(), limit)
        stop = limit
        if end != -1:
            closing = text.find("-----", end + len(_PEM_END), min(limit, end + 80))
            stop = closing + 5 if closing != -1 else end + len(_PEM_END)
        pieces += [text[pos : begin.start()], f"[redacted {_PRIVATE_KEY}]"]
        pos = stop
    pieces.append(text[pos:])
    return "".join(pieces)


# --------------------------------------------------------------------------
# The built-in formats alone
# --------------------------------------------------------------------------

_BUILT_IN_ONLY = SecretGuard()


def find_secrets(text: str) -> list[str]:
    """The kinds of built-in secret format that would block a call carrying `text`, each kind once."""
    return [found.kind for found in _BUILT_IN_ONLY.find(text)]


def redact(text: str) -> str:
    """`text` for a log, with every built-in secret format replaced (see SecretGuard.redact)."""
    return _BUILT_IN_ONLY.redact(text)


def redact_value(value: Any) -> Any:
    """A copy of a JSON-like value for a log, with the built-in formats replaced (see SecretGuard.redact_value)."""
    return _BUILT_IN_ONLY.redact_value(value)
