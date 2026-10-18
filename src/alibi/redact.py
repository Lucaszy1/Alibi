"""Secret redaction for Alibi's shared outputs.

Incident reports are handed to other people, so credential-like values are masked before they leave
the tool. The redactor deliberately preserves attack indicators (hostnames, URLs, process and command
structure) because those are the evidence an analyst needs; it masks only secret VALUES and known
fixed-shape tokens, never the command that moved them and never generic high-entropy strings (which
would eat base64 payloads that are themselves evidence)."""

from __future__ import annotations

import re

MASK = "***REDACTED***"

# key=value / key: value where the key names a credential. The value runs until whitespace or a shell
# metacharacter, so a redaction never swallows the rest of a pipeline.
_KEYED = re.compile(
    r"(?i)\b(pass(?:word|wd)?|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"client[_-]?secret|session[_-]?id|private[_-]?key)(\s*[:=]\s*)(['\"]?)([^\s'\"`;|&]+)"
)
# scheme://user:pass@host
_URL_CRED = re.compile(r"(?i)([a-z][a-z0-9+.\-]*://[^:/?#\s]+:)([^@/?#\s]+)(@)")
# Authorization: Bearer|Basic|Token <value>
_AUTH_HEADER = re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer|basic|token)\s+)([A-Za-z0-9._\-=+/]{8,})")
# bare "Bearer <token>" not preceded by the header word
_BEARER = re.compile(r"(?i)(\bbearer\s+)([A-Za-z0-9._\-=+/]{8,})")
_AWS_AKID = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_GH_PAT = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
_SLACK = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----", re.DOTALL
)


def redact(text: str) -> str:
    """Mask credential-like values while leaving attack indicators intact."""
    if not text:
        return text
    text = _PRIVATE_KEY.sub(MASK, text)
    text = _URL_CRED.sub(lambda m: m.group(1) + MASK + m.group(3), text)
    text = _AUTH_HEADER.sub(lambda m: m.group(1) + MASK, text)
    text = _KEYED.sub(lambda m: m.group(1) + m.group(2) + m.group(3) + MASK, text)
    text = _BEARER.sub(lambda m: m.group(1) + MASK, text)
    text = _AWS_AKID.sub(MASK, text)
    text = _GH_PAT.sub(MASK, text)
    text = _SLACK.sub(MASK, text)
    return text
