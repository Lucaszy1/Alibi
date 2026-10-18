"""The report sanitizer must redact secrets, and it must do so BEFORE truncation so a credential
can never be half-exposed by the length cut, while attack indicators survive."""

from alibi.redact import MASK
from alibi.report import _san


def test_san_redacts_secret_keeps_host():
    out = _san("token: SEKRET123 http://evil.example/x", 200)
    assert MASK in out
    assert "evil.example" in out
    assert "SEKRET123" not in out


def test_san_redacts_before_truncation():
    out = _san("password=SUPERSECRETVALUE1234567890", 20)
    assert "SUPERSECRET" not in out
