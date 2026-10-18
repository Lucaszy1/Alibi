"""The decoding pass reveals payloads hidden behind common encodings, and leaves plain text alone."""

import base64

from alibi.decode import reveal


def test_base64_url_is_revealed():
    blob = base64.b64encode(b"http://evil.example/stage2").decode()
    assert "evil.example" in reveal(f"echo {blob} | base64 -d | sh")


def test_powershell_enc_is_revealed():
    blob = base64.b64encode("whoami /priv".encode("utf-16-le")).decode()
    assert "whoami" in reveal(f"powershell -enc {blob}")


def test_hex_escapes_are_revealed():
    assert "evil" in reveal(r"payload \x65\x76\x69\x6c here")


def test_percent_encoding_is_revealed():
    assert "http://" in reveal("fetch %68%74%74%70%3a%2f%2fx")


def test_plain_text_is_unchanged():
    s = "curl http://plain.example/readme and run pytest"
    assert reveal(s) == s
