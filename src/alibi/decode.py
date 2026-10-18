"""Decoding pass: reveal payloads hidden behind base64, PowerShell -enc (UTF-16LE), hex, \\xNN
escapes, percent-encoding, gzip-in-base64, base32, and ROT13, so downstream tiers judge the real
content, not the disguise.

Pure and self-contained. reveal(text) returns the text with any decoded payloads appended. It only
adds plausibly-decoded printable strings, and the noisier transforms (base32, ROT13) are gated to
contribute only when they reveal a real indicator, so ordinary text passes through unchanged."""

from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import re
import urllib.parse
import zlib

_ENC_FLAG = re.compile(r"-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})", re.I)
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_B32 = re.compile(r"\b[A-Z2-7]{16,}={0,6}")
_XHEX = re.compile(r"(?:\\x[0-9a-fA-F]{2}){3,}")
_HEX = re.compile(r"\b((?:[0-9a-fA-F]{2}){8,})\b")
_PCT = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")
_INDICATORS = re.compile(
    r"https?://|(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|app|ai|sh|co|ru|cn|xyz|top)\b|"
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b|invoke-webrequest|downloadstring|\biex\b|\bcurl\b|\bwget\b|"
    r"powershell|cmd\.exe|-enc|certutil|bitsadmin",
    re.I,
)


def _printable(b: bytes) -> str | None:
    s = None
    for enc in ("utf-8", "utf-16-le"):
        try:
            s = b.decode(enc)
            break
        except (UnicodeDecodeError, LookupError):
            continue
    if not s:
        return None
    ok = sum(1 for c in s if c.isprintable() or c.isspace())
    return s if ok / len(s) > 0.8 else None


def _meaningful(s: str) -> bool:
    """A decoded string worth surfacing from a noisy transform: it names a real indicator."""
    return bool(_INDICATORS.search(s))


def _from_bytes(raw: bytes) -> list[str]:
    """Decoded forms of a decoded blob: its printable text and, when it is gzip, the inner payload."""
    out: list[str] = []
    s = _printable(raw)
    if s and s.strip():
        out.append(s)
    if raw[:2] == b"\x1f\x8b":
        try:
            g = _printable(gzip.decompress(raw))
        except (OSError, EOFError, zlib.error):
            g = None
        if g and g.strip():
            out.append(g)
    return out


def _resolve_inline(text: str) -> str:
    """Reassemble a host/command split by quote-concatenation or same-command shell variables."""
    out = text.replace('""', "").replace("''", "")
    variables = {}
    for m in re.finditer(r"(?:^|[;&|(\s])(\w+)=(\S+)", out):
        val = m.group(2).rstrip(";&|)")
        if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
            val = val[1:-1]
        variables[m.group(1)] = val
    if variables:
        out = re.sub(r"\$\{(\w+)\}|\$(\w+)|%(\w+)%",
                     lambda m: variables.get(m.group(1) or m.group(2) or m.group(3), m.group(0)), out)
    return out


def reveal(text: str) -> str:
    found: list[str] = []

    for m in _ENC_FLAG.finditer(text):
        tok = m.group(1)
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4))
        except (binascii.Error, ValueError):
            continue
        s = raw.decode("utf-16-le", "ignore").strip("\x00")
        if s:
            found.append(s)
        if raw[:2] == b"\x1f\x8b":
            try:
                g = _printable(gzip.decompress(raw))
            except (OSError, EOFError, zlib.error):
                g = None
            if g and g.strip():
                found.append(g)

    for m in _B64.finditer(text):
        tok = m.group(0)
        if len(set(tok)) < 6:
            continue
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4))
        except (binascii.Error, ValueError):
            continue
        found.extend(_from_bytes(raw))

    for m in _B32.finditer(text):
        t = m.group(0).rstrip("=")
        try:
            raw = base64.b32decode(t + "=" * (-len(t) % 8))
        except (binascii.Error, ValueError):
            continue
        cand = _printable(raw)
        if cand and cand.strip() and _meaningful(cand):
            found.append(cand)

    for m in _XHEX.finditer(text):
        try:
            raw = bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", m.group(0)))
        except ValueError:
            continue
        found.extend(_from_bytes(raw))

    for m in _HEX.finditer(text):
        try:
            raw = binascii.unhexlify(m.group(1))
        except (binascii.Error, ValueError):
            continue
        found.extend(_from_bytes(raw))

    if _PCT.search(text):
        dec = urllib.parse.unquote(text)
        if dec != text:
            found.append(dec)

    rot = codecs.encode(text, "rot_13")
    if rot != text and _meaningful(rot):
        found.append(rot)

    resolved = _resolve_inline(text)
    if resolved != text:
        found.append(resolved)
    return text + " " + " ".join(found) if found else text
