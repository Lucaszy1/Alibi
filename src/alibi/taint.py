"""Taint tracking: follow untrusted data from the tool result that introduced it to the argument
of a later, dangerous tool call, across intervening calls.

Provenance (judge.trace_provenance) asks whether a distinctive target in the action also appears in
untrusted content: one hop, target-shaped. Taint tracking generalises it. It tracks arbitrary
distinctive tokens (URLs, hosts, IPs, paths, and base64 / opaque blobs) entering through an
UNTRUSTED result, propagates them through later calls (a write carrying a tainted token makes the
written file itself tainted), and reports whether the target call's input is taint-derived, with the
flow path as evidence. Pure and self-contained: it imports nothing from judge, so judge can depend
on it with no import cycle."""

from __future__ import annotations

import re
from dataclasses import dataclass

from alibi.transcript import ToolCall, ToolResult
from alibi.transcript import SourceKind

_URL = re.compile(r"https?://[^\s'\"<>|`)]+", re.I)
_IP = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_HOST = re.compile(
    r"(?<![\w.@-])(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|app|ai|sh|co|me|info|biz|xyz|top|site|online|"
    r"ru|cn|su|tk|cc|ws|us|uk|de|fr|eu|gov|edu|cloud|link|zip|onion)(?![\w-])",
    re.I,
)
_PATHISH = re.compile(r"(?:[A-Za-z]:\\|/|\./|~/|\.\\)[\w./\\-]{2,}")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

_WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
_STRENGTH = {"url": 0.9, "host": 0.9, "ip": 0.9, "path": 0.85, "b64": 0.75}


@dataclass(frozen=True)
class TaintStep:
    call: ToolCall
    token: str
    wrote: str | None  # a file path this call produced that is now tainted


@dataclass(frozen=True)
class TaintResult:
    tainted: bool
    token: str | None = None
    kind: str | None = None
    source: ToolResult | None = None
    path: tuple = ()        # intervening carriers, oldest first
    via_file: bool = False  # taint reached the call through a dropped file
    strength: float = 0.0


def _text(call: ToolCall) -> str:
    return " ".join(str(v) for v in call.tool_input.values())


def _written_path(call: ToolCall):
    if call.tool_name in _WRITE_TOOLS:
        fp = call.tool_input.get("file_path") or call.tool_input.get("path")
        return str(fp) if fp else None
    return None


def _tokens(text: str):
    out = []
    for rx, kind in ((_URL, "url"), (_IP, "ip"), (_HOST, "host"), (_PATHISH, "path")):
        for m in rx.finditer(text):
            out.append((m.group(0), kind))
    for m in _B64.finditer(text):
        tok = m.group(0)
        if len(tok) >= 16 and not tok.isdigit() and len(set(tok)) >= 6:
            out.append((tok, "b64"))
    return out


def trace_taint(events, target_call: ToolCall) -> TaintResult:
    """Whether target_call's input derives from untrusted content seen earlier in the session."""
    tainted: dict = {}        # token.lower() -> (orig, source, kind)
    tainted_paths: dict = {}  # path.lower() -> (orig, source, kind, step)
    steps: list = []

    for e in events:
        if e is target_call:
            break
        if isinstance(e, ToolResult) and e.source_kind is SourceKind.UNTRUSTED:
            for tok, kind in _tokens(e.content):
                tainted.setdefault(tok.lower(), (tok, e, kind))
        elif isinstance(e, ToolCall):
            low = _text(e).lower()
            carried = next(((o, s, k) for key, (o, s, k) in tainted.items() if key in low), None)
            via_path = next((tp for tp in tainted_paths if tp in low), None)
            if carried or via_path:
                if carried:
                    token, source, kind = carried
                else:
                    orig, source, kind, _ = tainted_paths[via_path]
                    token = orig
                wrote = _written_path(e)
                steps.append(TaintStep(e, token, wrote))
                if wrote:
                    tainted_paths[wrote.lower()] = (wrote, source, kind, steps[-1])

    low = _text(target_call).lower()
    direct = next(((o, s, k) for key, (o, s, k) in tainted.items() if key in low), None)
    if direct:
        o, s, k = direct
        return TaintResult(True, o, k, s, tuple(steps), False, _STRENGTH.get(k, 0.7))
    via = next((tp for tp in tainted_paths if tp in low), None)
    if via:
        orig, source, kind, _ = tainted_paths[via]
        return TaintResult(True, orig, "path", source, tuple(steps), True, 0.8)
    return TaintResult(False)
