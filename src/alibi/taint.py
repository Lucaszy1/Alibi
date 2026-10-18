"""Taint tracking: follow untrusted data from the tool result that introduced it to the argument
of a later, dangerous tool call, across intervening calls.

Provenance (judge.trace_provenance) asks whether a distinctive target in the action also appears in
untrusted content: one hop, target-shaped. Taint tracking generalises it. It tracks arbitrary
distinctive tokens (URLs, hosts, IPs, paths, and base64 / opaque blobs) entering through an
UNTRUSTED result, propagates them through later calls (a write carrying a tainted token makes the
written file itself tainted), and reports whether the target call's input is taint-derived, with the
flow path as evidence. Pure and self-contained: it imports nothing from judge, so judge can depend
on it with no import cycle.

TaintIndex does the propagation in one pass over the session and snapshots the state before each
call, so any call's taint resolves in roughly the cost of that one call rather than re-walking (and
re-decoding) the whole session per call. trace_taint keeps the one-shot signature for direct callers."""

from __future__ import annotations

import re
from dataclasses import dataclass

from alibi.decode import reveal
from alibi.transcript import SourceKind, ToolCall, ToolResult

_URL = re.compile(r"https?://[^\s'\"<>|`)]+", re.I)
_IP = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_HOST = re.compile(
    r"(?<![\w.@-])(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|app|ai|sh|co|me|info|biz|xyz|top|site|online|"
    r"ru|cn|su|tk|cc|ws|us|uk|de|fr|eu|gov|edu|cloud|link|zip|onion|nl|jp|kr|br|au|ca|ch|se|pl|cz|pt|gr|sg|hk|tw|za|mx|ar|cl|nz|ie|kz|ua|vn|ph|my|th|ng|ke|icu|cfd|sbs|cyou|bond|quest|pw|best)(?![\w-])",
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


_ASSIGN = re.compile(r"(?:^|[;&|(\s])(?:export\s+|set\s+)?(\w+)=(\S+)")
_VARUSE = re.compile(r"\$\{(\w+)\}|\$(\w+)|%(\w+)%")


def _collect_env(text, env):
    for m in _ASSIGN.finditer(text):
        val = m.group(2).rstrip(";&|)")
        if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
            val = val[1:-1]
        env[m.group(1)] = val


def _apply_env(text, env):
    if not env:
        return text
    return _VARUSE.sub(lambda m: env.get(m.group(1) or m.group(2) or m.group(3), m.group(0)), text)


class TaintIndex:
    """One pass over a session's events, snapshotting the taint state (tokens, tainted files, env,
    carrier steps) just before each tool call. Built once; trace(call) then resolves that call's
    taint from its snapshot in O(tokens in the call), not O(events)."""

    def __init__(self, events) -> None:
        self._snap: dict[int, tuple] = {}
        tainted: dict = {}
        tainted_paths: dict = {}
        steps: list = []
        env: dict = {}
        for e in events:
            if isinstance(e, ToolCall):
                self._snap[id(e)] = (dict(tainted), dict(tainted_paths), dict(env), tuple(steps))
                _collect_env(_text(e), env)
                low = reveal(_apply_env(_text(e), env)).lower()
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
            elif isinstance(e, ToolResult) and e.source_kind is SourceKind.UNTRUSTED:
                for tok, kind in _tokens(reveal(e.content)):
                    tainted.setdefault(tok.lower(), (tok, e, kind))

    def trace(self, target_call: ToolCall) -> TaintResult:
        """Whether target_call's input derives from untrusted content seen earlier in the session."""
        tainted, tainted_paths, env, steps = self._snap.get(id(target_call), ({}, {}, {}, ()))
        low = reveal(_apply_env(_text(target_call), env)).lower()
        direct = next(((o, s, k) for key, (o, s, k) in tainted.items() if key in low), None)
        if direct:
            o, s, k = direct
            return TaintResult(True, o, k, s, tuple(steps), False, _STRENGTH.get(k, 0.7))
        via = next((tp for tp in tainted_paths if tp in low), None)
        if via:
            orig, source, kind, _ = tainted_paths[via]
            return TaintResult(True, orig, "path", source, tuple(steps), True, 0.8)
        return TaintResult(False)


def trace_taint(events, target_call: ToolCall) -> TaintResult:
    """One-shot taint trace for a single call (builds a throwaway index). The judge uses a cached
    TaintIndex per session instead, so it does not rebuild per call."""
    return TaintIndex(events).trace(target_call)
