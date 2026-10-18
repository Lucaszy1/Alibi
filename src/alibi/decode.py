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

    for m in _B64.finditer(text):
        tok = m.group(0)
        if len(set(tok)) < 6:
            continue
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4))
        except (binascii.Error, ValueError):
            continue
        s = _printable(raw)  # type: ignore[assignment]
        if s and s.strip():
            found.append(s)

    for m in _XHEX.finditer(text):
        try:
            raw = bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", m.group(0)))
        except ValueError:
            continue
        s = _printable(raw)  # type: ignore[assignment]
        if s:
            found.append(s)

    for m in _HEX.finditer(text):
        try:
            raw = binascii.unhexlify(m.group(1))
        except (binascii.Error, ValueError):
            continue
        s = _printable(raw)  # type: ignore[assignment]
        if s and s.strip():
            found.append(s)

    if _PCT.search(text):
        dec = urllib.parse.unquote(text)
        if dec != text:
            found.append(dec)

    resolved = _resolve_inline(text)
    if resolved != text:
        found.append(resolved)
    return text + " " + " ".join(found) if found else text
