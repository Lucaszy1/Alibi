"""Decoding pass: reveal payloads hidden behind base64, PowerShell -enc (UTF-16LE), hex, \\xNN
escapes, and percent-encoding, so downstream tiers judge the real content, not the disguise.

Pure and self-contained. reveal(text) returns the text with any decoded payloads appended; it only
adds plausibly-decoded printable strings, so ordinary text passes through unchanged."""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse

_ENC_FLAG = re.compile(r"-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})", re.I)
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_XHEX = re.compile(r"(?:\\x[0-9a-fA-F]{2}){3,}")
_HEX = re.compile(r"\b((?:[0-9a-fA-F]{2}){8,})\b")
_PCT = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")


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

    for m in _B64.finditer(text):
        tok = m.group(0)
        if len(set(tok)) < 6:
            continue
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4))
        except (binascii.Error, ValueError):
            continue
        s = _printable(raw)
        if s and s.strip():
            found.append(s)

    for m in _XHEX.finditer(text):
        try:
            raw = bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", m.group(0)))
        except ValueError:
            continue
        s = _printable(raw)
        if s:
            found.append(s)

    for m in _HEX.finditer(text):
        try:
            raw = binascii.unhexlify(m.group(1))
        except (binascii.Error, ValueError):
            continue
        s = _printable(raw)
        if s and s.strip():
            found.append(s)

    for m in _PCT.finditer(text):
        s = urllib.parse.unquote(m.group(0))
        if s and s != m.group(0):
            found.append(s)

    return text + " " + " ".join(found) if found else text
