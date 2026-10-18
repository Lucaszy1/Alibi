"""Item 16: widened host TLD allowlist. Common ccTLDs and abused gTLDs now extract as bare hosts,
while word-like TLDs were deliberately not added, so ordinary dotted phrases stay non-hosts."""

from alibi.judge import extract_targets


def _hosts(t):
    return {x.value for x in extract_targets(t) if x.kind.value == "host"}


def test_new_cctlds_and_gtlds_extract():
    h = _hosts("beacon to evil.jp and bad.icu and c2.cyou and drop.cfd")
    assert {"evil.jp", "bad.icu", "c2.cyou", "drop.cfd"} <= h


def test_wordlike_tlds_not_added():
    h = _hosts("see refer.to and built.in and as.it today")
    assert "refer.to" not in h and "built.in" not in h and "as.it" not in h


def test_file_ext_gtld_still_filtered():
    assert "setup.sh" not in _hosts("curl http://1.2.3.4/x -o setup.sh")
