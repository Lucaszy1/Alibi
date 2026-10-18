"""M-decode: extended layers. gzip-in-base64, base32, and ROT13 each recover a hidden indicator,
while the gated transforms leave ordinary text untouched (no provenance noise). Brute-force XOR was
intentionally not added (a 256-key sweep over attacker-controlled blobs is a DoS vector)."""

import base64
import codecs
import gzip

from alibi.decode import reveal


def test_gzip_in_base64():
    blob = base64.b64encode(gzip.compress(b"iex http://gz.example.dev/p")).decode()
    assert "gz.example.dev" in reveal(f"run {blob}")


def test_base32():
    tok = base64.b32encode(b"visit http://b32host.io/x").decode()
    assert "b32host.io" in reveal(f"data {tok}")


def test_rot13():
    enc = codecs.encode("fetch http://rot.example.io/page", "rot_13")
    assert "rot.example.io" in reveal(f"note {enc}")


def test_plain_text_unchanged():
    t = "just a normal sentence with several words here"
    assert reveal(t) == t


def test_existing_base64_url_still_revealed():
    tok = base64.b64encode(b"download http://plain.example.com/setup").decode()
    assert "plain.example.com" in reveal(f"x {tok}")
