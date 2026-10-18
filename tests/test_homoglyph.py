"""Homoglyph and bidi evasion: a look-alike host built from Cyrillic/Greek letters canonicalizes to
its Latin form, and bidi-control characters are stripped, so neither hides a target from matching."""

from alibi.judge import _norm_text


def test_cyrillic_homoglyph_host_folds_to_latin():
    # 'o' and 'e' here are Cyrillic (U+043E, U+0435)
    assert _norm_text("g\u043eogl\u0435.com") == "google.com"


def test_mixed_cyrillic_host_folds():
    # paypal with Cyrillic 'a' (U+0430)
    assert _norm_text("p\u0430yp\u0430l.com") == "paypal.com"


def test_greek_homoglyph_folds():
    assert _norm_text("\u03bf\u03bf.com") == "oo.com"


def test_bidi_control_stripped():
    assert _norm_text("\u202eevil.com\u202c") == "evil.com"


def test_greek_upsilon_folds():
    assert _norm_text("y\u03c5m.com") == "yum.com"


def test_greek_uppercase_zeta_folds():
    assert _norm_text("\u0396ebra.com") == "zebra.com"


def test_armenian_homoglyph_folds():
    # Armenian o (U+0585) and n (U+0578)
    assert _norm_text("\u0585\u0578.com") == "on.com"


def test_extended_latin_alpha_folds():
    # Latin small alpha (U+0251), distinct from ASCII 'a' under NFKC
    assert _norm_text("\u0251pple.com") == "apple.com"
