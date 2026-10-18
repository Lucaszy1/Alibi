"""Decoding pass: reveal payloads hidden behind base64, PowerShell -enc (UTF-16LE), hex, \\xNN
escapes, percent-encoding, gzip-in-base64, base32, ROT13, and nested multi-layer combinations of
these, so downstream tiers judge the real
content, not the disguise.

Pure, self-contained, and bounded so hostile input cannot make it slow: every scan is linear, the
number and size of decoded tokens are capped, gunzip output is size-limited, and the whole-text
ROT13 transform is skipped on large inputs. reveal(text) returns the text with any decoded payloads
appended; the noisier transforms (base32, ROT13) are gated to contribute only on a real indicator."""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import urllib.parse
import zlib

_ENC_FLAG = re.compile(r"-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})", re.I)
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_B32 = re.compile(r"\b[A-Z2-7]{16,}={0,6}")
_XHEX = re.compile(r"(?:\\x[0-9a-fA-F]{2}){3,}")
_HEX = re.compile(r"\b((?:[0-9a-fA-F]{2}){8,})\b")
_PCT = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")
# Deliberately linear: no nested quantifiers (those invite catastrophic backtracking / ReDoS).
_INDICATORS = re.compile(
    r"https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b|invoke-webrequest|downloadstring|\biex\b|"
    r"\bcurl\b|\bwget\b|powershell|cmd\.exe|-enc|certutil|bitsadmin",
    re.I,
)

_MAX_TOKEN = 8192      # do not try to decode a single blob larger than this
_MAX_MATCHES = 64      # cap how many blobs per scheme we decode
_ROT13_LIMIT = 20000   # skip the whole-text ROT13 transform above this size
_GUNZIP_LIMIT = 65536  # cap gunzip output so a compression bomb cannot blow memory


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


def _gunzip(raw: bytes) -> bytes | None:
    """Decompress a gzip blob, but never more than _GUNZIP_LIMIT bytes (bomb-safe)."""
    try:
        return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(raw, _GUNZIP_LIMIT)
    except (zlib.error, OSError, EOFError):
        return None


def _from_bytes(raw: bytes) -> list[str]:
    """Decoded forms of a decoded blob: its printable text and, when it is gzip, the inner payload."""
    out: list[str] = []
    s = _printable(raw)
    if s and s.strip():
        out.append(s)
    if raw[:2] == b"\x1f\x8b":
        g = _gunzip(raw)
        gs = _printable(g) if g else None
        if gs and gs.strip():
            out.append(gs)
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


def _decode_once(text: str) -> list[str]:
    found: list[str] = []

    for m in list(_ENC_FLAG.finditer(text))[:_MAX_MATCHES]:
        tok = m.group(1)
        if len(tok) > _MAX_TOKEN:
            continue
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4))
        except (binascii.Error, ValueError):
            continue
        s = raw.decode("utf-16-le", "ignore").strip("\x00")
        if s:
            found.append(s)
        if raw[:2] == b"\x1f\x8b":
            g = _gunzip(raw)
            gs = _printable(g) if g else None
            if gs and gs.strip():
                found.append(gs)

    for m in list(_B64.finditer(text))[:_MAX_MATCHES]:
        tok = m.group(0)
        if len(tok) > _MAX_TOKEN or len(set(tok)) < 6:
            continue
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4))
        except (binascii.Error, ValueError):
            continue
        found.extend(_from_bytes(raw))

    for m in list(_B32.finditer(text))[:_MAX_MATCHES]:
        tok = m.group(0)
        if len(tok) > _MAX_TOKEN:
            continue
        t = tok.rstrip("=")
        try:
            raw = base64.b32decode(t + "=" * (-len(t) % 8))
        except (binascii.Error, ValueError):
            continue
        cand = _printable(raw)
        if cand and cand.strip() and _meaningful(cand):
            found.append(cand)

    for m in list(_XHEX.finditer(text))[:_MAX_MATCHES]:
        if len(m.group(0)) > _MAX_TOKEN:
            continue
        try:
            raw = bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", m.group(0)))
        except ValueError:
            continue
        found.extend(_from_bytes(raw))

    for m in list(_HEX.finditer(text))[:_MAX_MATCHES]:
        if len(m.group(1)) > _MAX_TOKEN:
            continue
        try:
            raw = binascii.unhexlify(m.group(1))
        except (binascii.Error, ValueError):
            continue
        found.extend(_from_bytes(raw))

    if _PCT.search(text):
        dec = urllib.parse.unquote(text)
        if dec != text:
            found.append(dec)

    if len(text) <= _ROT13_LIMIT:
        rot = codecs.encode(text, "rot_13")
        if rot != text and _meaningful(rot):
            found.append(rot)

    resolved = _resolve_inline(text)
    if resolved != text:
        found.append(resolved)
    return found


_MAX_DEPTH = 3     # how many nested layers to peel (base64-of-base64-of-...)
_MAX_TOTAL = 256   # global cap on decoded strings per reveal, so nesting cannot blow up


def _collect(text: str, depth: int, seen: set) -> list[str]:
    out: list[str] = []
    for f in _decode_once(text):
        if f and f != text and f not in seen:
            seen.add(f)
            out.append(f)
            if depth < _MAX_DEPTH and len(seen) < _MAX_TOTAL:
                out.extend(_collect(f, depth + 1, seen))
    return out


def reveal(text: str) -> str:
    """Reveal decoded payloads, recursing through nested encodings up to a bounded depth and total."""
    found = _collect(text, 1, {text})
    return text + " " + " ".join(found) if found else text
