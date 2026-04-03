"""Security tests for SSRF protection, prompt injection mitigation, and input validation."""

from __future__ import annotations

from airlock.gateway.url_validator import validate_callback_url
from airlock.semantic.challenge import _sanitize_answer

# ---------------------------------------------------------------------------
# SSRF: URL validator
# ---------------------------------------------------------------------------


class TestCallbackUrlValidator:
    def test_rejects_none(self):
        assert validate_callback_url(None) is None

    def test_rejects_empty(self):
        assert validate_callback_url("") is None

    def test_rejects_localhost(self):
        assert validate_callback_url("http://localhost:8080/callback") is None

    def test_rejects_127(self):
        assert validate_callback_url("http://127.0.0.1:9000/hook") is None

    def test_rejects_private_10(self):
        assert validate_callback_url("http://10.0.0.5/callback") is None

    def test_rejects_private_172(self):
        assert validate_callback_url("http://172.16.0.1/callback") is None

    def test_rejects_private_192(self):
        assert validate_callback_url("http://192.168.1.1/callback") is None

    def test_rejects_metadata_endpoint(self):
        assert validate_callback_url("http://169.254.169.254/latest/meta-data/") is None

    def test_rejects_ftp_scheme(self):
        assert validate_callback_url("ftp://example.com/file") is None

    def test_allows_external_https(self):
        assert (
            validate_callback_url("https://api.example.com/callback")
            == "https://api.example.com/callback"
        )

    def test_allows_external_http(self):
        assert validate_callback_url("http://webhook.site/abc123") == "http://webhook.site/abc123"

    def test_allows_domain_name(self):
        assert (
            validate_callback_url("https://agents.example.com/hook")
            == "https://agents.example.com/hook"
        )


# ---------------------------------------------------------------------------
# Prompt injection: answer sanitization
# ---------------------------------------------------------------------------


class TestAnswerSanitization:
    def test_strips_control_characters(self):
        dirty = "Hello\x00World\x07Test\x1f"
        clean = _sanitize_answer(dirty)
        assert "\x00" not in clean
        assert "\x07" not in clean
        assert "\x1f" not in clean
        assert "HelloWorldTest" == clean

    def test_preserves_normal_text(self):
        text = "A nonce prevents replay attacks by ensuring each message is unique."
        assert _sanitize_answer(text) == text

    def test_limits_length(self):
        long_answer = "A" * 5000
        result = _sanitize_answer(long_answer)
        assert len(result) == 2000

    def test_preserves_unicode(self):
        text = "Unicode test: \u00e9\u00e8\u00ea"
        assert _sanitize_answer(text) == text

    def test_empty_answer(self):
        assert _sanitize_answer("") == ""


# ---------------------------------------------------------------------------
# DID validation
# ---------------------------------------------------------------------------


class TestDidValidation:
    def test_valid_did(self):
        from airlock.gateway.handlers import _is_valid_did

        valid = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        assert _is_valid_did(valid) is True

    def test_rejects_non_did(self):
        from airlock.gateway.handlers import _is_valid_did

        assert _is_valid_did("not-a-did") is False

    def test_rejects_empty(self):
        from airlock.gateway.handlers import _is_valid_did

        assert _is_valid_did("") is False

    def test_rejects_wrong_method(self):
        from airlock.gateway.handlers import _is_valid_did

        assert _is_valid_did("did:web:example.com") is False

    def test_rejects_missing_multibase(self):
        from airlock.gateway.handlers import _is_valid_did

        assert _is_valid_did("did:key:abc") is False
