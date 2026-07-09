"""RFC 9421 signature-base construction for the Web Bot Auth profile.

Implements exactly the profile needed by Airlock Passport — not general
RFC 9421. Wire format per:

- draft-meunier-webbotauth-httpsig-protocol-00 (June 2026; successor of
  draft-meunier-web-bot-auth-architecture-05): covered components
  ``@authority`` + ``signature-agent``, parameters ``created``, ``expires``,
  ``keyid`` (base64url RFC 7638 JWK SHA-256 thumbprint), ``alg="ed25519"``,
  optional ``nonce``, ``tag="web-bot-auth"``.
- draft-meunier-webbotauth-httpsig-directory-00 (successor of
  draft-meunier-http-message-signatures-directory-05): well-known key
  directory path and media type constants.
- RFC 8941 structured fields — only the subset the profile needs
  (dictionaries, inner lists, strings, tokens, integers, byte sequences,
  booleans), with canonical re-serialization for base reconstruction.

Signers emit the *legacy string* form of ``Signature-Agent``
(``Signature-Agent: "https://directory.example"``) because deployed
verifiers (Cloudflare's Web Bot Auth implementation, mid-2026) reject the
newer Dictionary form. The verifier side accepts both forms.

All functions in this module are pure; parse errors raise ``ValueError``
(callers such as :class:`airlock.passport.verifier.PassportVerifier`
convert them into failure results).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from airlock.schemas.passport import SignatureParams

WEB_BOT_AUTH_TAG = "web-bot-auth"
WELL_KNOWN_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"

_DEFAULT_PORTS = {"http": 80, "https": 443}

# Printable ASCII allowed inside an sf-string (RFC 8941 section 3.3.3).
_SF_STRING_MIN = 0x20
_SF_STRING_MAX = 0x7E

_TOKEN_FIRST = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ*")
_TOKEN_CHARS = _TOKEN_FIRST | set("0123456789:/!#$%&'^_`|~+-.")
_KEY_FIRST = set("abcdefghijklmnopqrstuvwxyz*")
_KEY_CHARS = _KEY_FIRST | set("0123456789_-.")
_B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


# ---------------------------------------------------------------------------
# Structured-field values (typed, order-preserving)
# ---------------------------------------------------------------------------


class SfValue(BaseModel):
    """A parsed RFC 8941 bare item, preserving its wire type.

    The wire type matters: ``ed25519`` (token) and ``"ed25519"`` (string)
    serialize differently, and base reconstruction must be byte-faithful.
    """

    model_config = {"frozen": True}

    kind: Literal["integer", "string", "token", "bytes", "boolean"]
    integer: int | None = None
    text: str | None = None
    data: bytes | None = None
    flag: bool | None = None

    @classmethod
    def of_int(cls, value: int) -> SfValue:
        return cls(kind="integer", integer=value)

    @classmethod
    def of_string(cls, value: str) -> SfValue:
        return cls(kind="string", text=value)

    @classmethod
    def of_token(cls, value: str) -> SfValue:
        return cls(kind="token", text=value)

    @classmethod
    def of_bytes(cls, value: bytes) -> SfValue:
        return cls(kind="bytes", data=value)

    @classmethod
    def of_bool(cls, value: bool) -> SfValue:
        return cls(kind="boolean", flag=value)

    def as_int(self) -> int:
        if self.kind != "integer" or self.integer is None:
            raise ValueError(f"expected integer value, got {self.kind}")
        return self.integer

    def as_string(self) -> str:
        if self.kind != "string" or self.text is None:
            raise ValueError(f"expected string value, got {self.kind}")
        return self.text

    def serialize(self) -> str:
        if self.kind == "integer" and self.integer is not None:
            return str(self.integer)
        if self.kind == "string" and self.text is not None:
            return serialize_sf_string(self.text)
        if self.kind == "token" and self.text is not None:
            return _serialize_token(self.text)
        if self.kind == "bytes" and self.data is not None:
            import base64

            return ":" + base64.b64encode(self.data).decode("ascii") + ":"
        if self.kind == "boolean" and self.flag is not None:
            return "?1" if self.flag else "?0"
        raise ValueError(f"cannot serialize malformed SfValue of kind {self.kind}")


class SfParam(BaseModel):
    """A single ``;key=value`` structured-field parameter."""

    model_config = {"frozen": True}

    key: str
    value: SfValue


class ParsedComponent(BaseModel):
    """One covered component from a Signature-Input inner list.

    ``name`` is the component identifier (e.g. ``@authority`` or
    ``signature-agent``); ``params`` are its component parameters
    (the profile only supports ``key`` for dictionary-form headers).
    """

    model_config = {"frozen": True}

    name: str
    params: list[SfParam] = Field(default_factory=list)

    def param(self, key: str) -> SfValue | None:
        for p in self.params:
            if p.key == key:
                return p.value
        return None

    def serialize(self) -> str:
        return serialize_sf_string(self.name) + _serialize_params(self.params)


class SignatureInputMember(BaseModel):
    """One labelled signature from a ``Signature-Input`` header."""

    model_config = {"frozen": True}

    label: str
    components: list[ParsedComponent]
    params: list[SfParam]

    def param(self, key: str) -> SfValue | None:
        for p in self.params:
            if p.key == key:
                return p.value
        return None


class SignatureAgentMember(BaseModel):
    """One member of a dictionary-form ``Signature-Agent`` header."""

    model_config = {"frozen": True}

    label: str
    url: str
    params: list[SfParam] = Field(default_factory=list)

    def serialize_value(self) -> str:
        """Canonical serialization of the member value (with parameters)."""
        return serialize_sf_string(self.url) + _serialize_params(self.params)


class SignatureAgentValue(BaseModel):
    """A parsed ``Signature-Agent`` header (legacy string or dictionary)."""

    model_config = {"frozen": True}

    form: Literal["string", "dictionary"]
    url: str | None = None
    members: list[SignatureAgentMember] = Field(default_factory=list)

    def member(self, label: str) -> SignatureAgentMember | None:
        for m in self.members:
            if m.label == label:
                return m
        return None


# ---------------------------------------------------------------------------
# Serialization (RFC 8941 section 4.1 subset)
# ---------------------------------------------------------------------------


def serialize_sf_string(value: str) -> str:
    """Serialize a python string as an RFC 8941 sf-string (quoted)."""
    out = ['"']
    for ch in value:
        code = ord(ch)
        if code < _SF_STRING_MIN or code > _SF_STRING_MAX:
            raise ValueError(f"character {code:#x} not allowed in an sf-string")
        if ch in ('"', "\\"):
            out.append("\\")
        out.append(ch)
    out.append('"')
    return "".join(out)


def _serialize_token(value: str) -> str:
    if not value or value[0] not in _TOKEN_FIRST:
        raise ValueError(f"invalid sf-token: {value!r}")
    if any(ch not in _TOKEN_CHARS for ch in value):
        raise ValueError(f"invalid sf-token: {value!r}")
    return value


def _serialize_params(params: Sequence[SfParam]) -> str:
    parts: list[str] = []
    for p in params:
        if p.value.kind == "boolean" and p.value.flag is True:
            parts.append(f";{p.key}")
        else:
            parts.append(f";{p.key}={p.value.serialize()}")
    return "".join(parts)


def serialize_signature_params(
    covered: Sequence[ParsedComponent], params: SignatureParams
) -> str:
    """Serialize the ``@signature-params`` value for signing.

    Parameter order follows the draft's Ed25519 example (C.2.1):
    ``created``, ``keyid``, ``alg``, ``expires``, ``nonce``, ``tag``.
    """
    sf_params: list[SfParam] = [SfParam(key="created", value=SfValue.of_int(params.created))]
    sf_params.append(SfParam(key="keyid", value=SfValue.of_string(params.keyid)))
    if params.alg is not None:
        sf_params.append(SfParam(key="alg", value=SfValue.of_string(params.alg)))
    sf_params.append(SfParam(key="expires", value=SfValue.of_int(params.expires)))
    if params.nonce is not None:
        sf_params.append(SfParam(key="nonce", value=SfValue.of_string(params.nonce)))
    sf_params.append(SfParam(key="tag", value=SfValue.of_string(params.tag)))
    member = SignatureInputMember(label="sig", components=list(covered), params=sf_params)
    return serialize_signature_input_value(member)


def serialize_signature_input_value(member: SignatureInputMember) -> str:
    """Canonical serialization of one Signature-Input member value."""
    inner = "(" + " ".join(c.serialize() for c in member.components) + ")"
    return inner + _serialize_params(member.params)


def build_signature_base(
    component_lines: Sequence[tuple[str, str]], signature_params: str
) -> str:
    """Assemble the RFC 9421 signature base.

    ``component_lines`` are ``(serialized_identifier, canonical_value)``
    pairs, e.g. ``('"@authority"', 'example.com')``. The final line is
    always ``"@signature-params"``.
    """
    lines = [f"{identifier}: {value}" for identifier, value in component_lines]
    lines.append(f'"@signature-params": {signature_params}')
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Canonicalization (RFC 9421 sections 2.1-2.2 subset)
# ---------------------------------------------------------------------------


def canonicalize_authority(url: str) -> str:
    """Canonicalize the ``@authority`` derived component of a target URI.

    Lowercases the host and omits the port when it is the scheme default
    (RFC 9421 section 2.2.3).
    """
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        raise ValueError(f"URL has no host: {url!r}")
    host = host.lower()
    if ":" in host:  # IPv6 literal — urlsplit strips the brackets
        host = f"[{host}]"
    port = parts.port
    if port is None or port == _DEFAULT_PORTS.get(parts.scheme.lower()):
        return host
    return f"{host}:{port}"


def canonicalize_target_uri(url: str) -> str:
    """Canonicalize ``@target-uri`` — the absolute URI minus any fragment."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"@target-uri requires an absolute URL: {url!r}")
    return parts._replace(fragment="").geturl()


def canonicalize_field_value(raw: str) -> str:
    """Canonicalize an HTTP field value (strip leading/trailing whitespace)."""
    return raw.strip(" \t")


# ---------------------------------------------------------------------------
# Parsing (RFC 8941 section 4.2 subset)
# ---------------------------------------------------------------------------


class _Parser:
    """Minimal RFC 8941 parser for the structures the profile uses."""

    def __init__(self, text: str) -> None:
        self._s = text
        self._i = 0

    # -- low-level helpers ------------------------------------------------

    def _eof(self) -> bool:
        return self._i >= len(self._s)

    def _peek(self) -> str:
        return "" if self._eof() else self._s[self._i]

    def _take(self) -> str:
        ch = self._s[self._i]
        self._i += 1
        return ch

    def _skip_ows(self) -> None:
        while not self._eof() and self._s[self._i] in " \t":
            self._i += 1

    def _skip_sp(self) -> None:
        while not self._eof() and self._s[self._i] == " ":
            self._i += 1

    def _fail(self, message: str) -> ValueError:
        return ValueError(f"{message} at offset {self._i} in {self._s!r}")

    # -- grammar productions ----------------------------------------------

    def parse_key(self) -> str:
        if self._eof() or self._peek() not in _KEY_FIRST:
            raise self._fail("expected a parameter/dictionary key")
        start = self._i
        while not self._eof() and self._peek() in _KEY_CHARS:
            self._i += 1
        return self._s[start : self._i]

    def parse_bare_item(self) -> SfValue:
        ch = self._peek()
        if ch == '"':
            return SfValue.of_string(self._parse_string())
        if ch == ":":
            return SfValue.of_bytes(self._parse_byte_sequence())
        if ch == "?":
            return SfValue.of_bool(self._parse_boolean())
        if ch == "-" or ch.isdigit():
            return SfValue.of_int(self._parse_integer())
        if ch in _TOKEN_FIRST:
            return SfValue.of_token(self._parse_token())
        raise self._fail(f"unsupported bare item starting with {ch!r}")

    def _parse_string(self) -> str:
        self._take()  # opening quote
        out: list[str] = []
        while True:
            if self._eof():
                raise self._fail("unterminated sf-string")
            ch = self._take()
            if ch == "\\":
                if self._eof():
                    raise self._fail("dangling escape in sf-string")
                nxt = self._take()
                if nxt not in ('"', "\\"):
                    raise self._fail(f"invalid escape \\{nxt} in sf-string")
                out.append(nxt)
            elif ch == '"':
                return "".join(out)
            else:
                code = ord(ch)
                if code < _SF_STRING_MIN or code > _SF_STRING_MAX:
                    raise self._fail("non-printable character in sf-string")
                out.append(ch)

    def _parse_byte_sequence(self) -> bytes:
        import base64

        self._take()  # opening colon
        start = self._i
        while not self._eof() and self._peek() != ":":
            if self._peek() not in _B64_CHARS:
                raise self._fail("invalid character in byte sequence")
            self._i += 1
        if self._eof():
            raise self._fail("unterminated byte sequence")
        encoded = self._s[start : self._i]
        self._take()  # closing colon
        try:
            return base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise self._fail(f"invalid base64 in byte sequence: {exc}") from exc

    def _parse_boolean(self) -> bool:
        self._take()  # question mark
        ch = self._take() if not self._eof() else ""
        if ch == "1":
            return True
        if ch == "0":
            return False
        raise self._fail("invalid boolean")

    def _parse_integer(self) -> int:
        start = self._i
        if self._peek() == "-":
            self._i += 1
        digits = 0
        while not self._eof() and self._peek().isdigit():
            self._i += 1
            digits += 1
        if digits == 0 or digits > 15:
            raise self._fail("invalid integer")
        if self._peek() == ".":
            raise self._fail("decimals are not used by this profile")
        return int(self._s[start : self._i])

    def _parse_token(self) -> str:
        start = self._i
        self._i += 1
        while not self._eof() and self._peek() in _TOKEN_CHARS:
            self._i += 1
        return self._s[start : self._i]

    def parse_parameters(self) -> list[SfParam]:
        params: list[SfParam] = []
        while self._peek() == ";":
            self._take()
            self._skip_sp()
            key = self.parse_key()
            value = SfValue.of_bool(True)
            if self._peek() == "=":
                self._take()
                value = self.parse_bare_item()
            params = [p for p in params if p.key != key]
            params.append(SfParam(key=key, value=value))
        return params

    def parse_inner_list(self) -> tuple[list[tuple[SfValue, list[SfParam]]], list[SfParam]]:
        if self._peek() != "(":
            raise self._fail("expected an inner list")
        self._take()
        items: list[tuple[SfValue, list[SfParam]]] = []
        while True:
            self._skip_sp()
            if self._eof():
                raise self._fail("unterminated inner list")
            if self._peek() == ")":
                self._take()
                return items, self.parse_parameters()
            value = self.parse_bare_item()
            params = self.parse_parameters()
            items.append((value, params))
            if self._peek() not in (" ", ")"):
                raise self._fail("expected space or ')' after inner list item")

    def parse_dictionary(
        self,
    ) -> list[tuple[str, SfValue | list[tuple[SfValue, list[SfParam]]], list[SfParam]]]:
        """Parse a dictionary; members are (key, item-or-inner-list, params)."""
        members: list[
            tuple[str, SfValue | list[tuple[SfValue, list[SfParam]]], list[SfParam]]
        ] = []
        self._skip_ows()
        if self._eof():
            return members
        while True:
            key = self.parse_key()
            value: SfValue | list[tuple[SfValue, list[SfParam]]]
            if self._peek() == "=":
                self._take()
                if self._peek() == "(":
                    value, params = self.parse_inner_list()
                else:
                    value = self.parse_bare_item()
                    params = self.parse_parameters()
            else:
                value = SfValue.of_bool(True)
                params = self.parse_parameters()
            members = [m for m in members if m[0] != key]
            members.append((key, value, params))
            self._skip_ows()
            if self._eof():
                return members
            if self._take() != ",":
                raise self._fail("expected ',' between dictionary members")
            self._skip_ows()
            if self._eof():
                raise self._fail("trailing comma in dictionary")

    def expect_eof(self) -> None:
        self._skip_ows()
        if not self._eof():
            raise self._fail("unexpected trailing data")


def parse_signature_input(header_value: str) -> list[SignatureInputMember]:
    """Parse a ``Signature-Input`` header into labelled members."""
    parser = _Parser(header_value)
    members = parser.parse_dictionary()
    parser.expect_eof()
    result: list[SignatureInputMember] = []
    for label, value, params in members:
        if not isinstance(value, list):
            raise ValueError(f"Signature-Input member {label!r} is not an inner list")
        components: list[ParsedComponent] = []
        for item_value, item_params in value:
            if item_value.kind != "string" or item_value.text is None:
                raise ValueError(
                    f"covered component in {label!r} must be an sf-string"
                )
            components.append(ParsedComponent(name=item_value.text, params=item_params))
        result.append(SignatureInputMember(label=label, components=components, params=params))
    return result


def parse_signature_header(header_value: str) -> dict[str, bytes]:
    """Parse a ``Signature`` header into ``label -> signature bytes``."""
    parser = _Parser(header_value)
    members = parser.parse_dictionary()
    parser.expect_eof()
    result: dict[str, bytes] = {}
    for label, value, _params in members:
        if not isinstance(value, SfValue) or value.kind != "bytes" or value.data is None:
            raise ValueError(f"Signature member {label!r} is not a byte sequence")
        result[label] = value.data
    return result


def parse_signature_agent(header_value: str) -> SignatureAgentValue:
    """Parse a ``Signature-Agent`` header.

    Accepts both the legacy string form (``"https://directory.example"``,
    what Cloudflare verifies today) and the Dictionary form from
    draft-meunier-webbotauth-httpsig-protocol-00
    (``sig1="https://directory.example";type=jwks_uri``).
    """
    stripped = canonicalize_field_value(header_value)
    if stripped.startswith('"'):
        parser = _Parser(stripped)
        value = parser.parse_bare_item()
        parser.expect_eof()
        if value.kind != "string" or value.text is None:
            raise ValueError("Signature-Agent string form must be an sf-string")
        return SignatureAgentValue(form="string", url=value.text)

    parser = _Parser(stripped)
    members = parser.parse_dictionary()
    parser.expect_eof()
    agent_members: list[SignatureAgentMember] = []
    for label, value, params in members:
        if not isinstance(value, SfValue) or value.kind != "string" or value.text is None:
            raise ValueError(f"Signature-Agent member {label!r} must be an sf-string")
        agent_members.append(SignatureAgentMember(label=label, url=value.text, params=params))
    if not agent_members:
        raise ValueError("Signature-Agent header has no members")
    return SignatureAgentValue(form="dictionary", members=agent_members)


# ---------------------------------------------------------------------------
# Verifier-side base reconstruction
# ---------------------------------------------------------------------------

_SUPPORTED_DERIVED = {"@authority", "@target-uri", "@method", "@path", "@scheme"}


def resolve_component_value(
    component: ParsedComponent,
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
) -> str:
    """Resolve one covered component to its canonical value.

    ``headers`` must be a lowercase-keyed mapping of the request headers.
    Raises ``ValueError`` for components outside the profile.
    """
    name = component.name
    if name.startswith("@"):
        if component.params:
            raise ValueError(f"derived component {name!r} must not have parameters")
        if name not in _SUPPORTED_DERIVED:
            raise ValueError(f"unsupported derived component {name!r}")
        parts = urlsplit(url)
        if name == "@authority":
            return canonicalize_authority(url)
        if name == "@target-uri":
            return canonicalize_target_uri(url)
        if name == "@method":
            return method.upper()
        if name == "@path":
            return parts.path or "/"
        return parts.scheme.lower()  # @scheme

    if name != name.lower():
        raise ValueError(f"covered field name {name!r} must be lowercase")

    raw = headers.get(name)
    if raw is None:
        raise ValueError(f"covered field {name!r} is not present in the request")

    key_param = component.param("key")
    unknown = [p.key for p in component.params if p.key != "key"]
    if unknown:
        raise ValueError(f"unsupported component parameters {unknown} on {name!r}")

    if key_param is None:
        return canonicalize_field_value(raw)

    # Dictionary-member component (RFC 9421 section 2.1.2) — the profile
    # supports it only for the dictionary form of Signature-Agent.
    if key_param.kind != "string" or key_param.text is None:
        raise ValueError(f"'key' parameter on {name!r} must be an sf-string")
    if name != "signature-agent":
        raise ValueError(f"'key' parameter is only supported on signature-agent, not {name!r}")
    agent = parse_signature_agent(raw)
    if agent.form != "dictionary":
        raise ValueError("signature-agent;key=... covers a dictionary-form header only")
    member = agent.member(key_param.text)
    if member is None:
        raise ValueError(f"Signature-Agent has no member {key_param.text!r}")
    return member.serialize_value()


def reconstruct_signature_base(
    member: SignatureInputMember,
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
) -> str:
    """Rebuild the signature base for a received Signature-Input member.

    The ``@signature-params`` line is the canonical re-serialization of the
    parsed member (RFC 9421 section 2.3), which byte-matches any signer that
    emitted canonical structured fields.
    """
    seen: set[str] = set()
    lines: list[tuple[str, str]] = []
    for component in member.components:
        identifier = component.serialize()
        if identifier in seen:
            raise ValueError(f"duplicate covered component {identifier}")
        seen.add(identifier)
        value = resolve_component_value(component, method=method, url=url, headers=headers)
        lines.append((identifier, value))
    return build_signature_base(lines, serialize_signature_input_value(member))
