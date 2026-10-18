"""Durable run history: append a compact JSON record of each adjudication run so results persist
across invocations (the judge itself is stateless). This is a readable audit trail of what each run
found, not a full verdict round-trip."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from alibi.verdict import Disposition, VerdictKind


def _short(text, n=200):
    t = " ".join((text or "").split())
    return t if len(t) <= n else t[: n - 1] + "\u2026"


def _label(v):
    if v.disposition is Disposition.VERDICT and v.verdict is not None:
        return v.verdict.value
    return v.disposition.value


def _flagged(v):
    return v.disposition is Disposition.VERDICT and v.verdict in (VerdictKind.HIJACKED, VerdictKind.UNJUSTIFIED)


def _cmd(v):
    call = v.tool_call
    if call is not None:
        inp = call.tool_input
        return str(inp.get("command") or inp.get("file_path") or inp.get("url") or "") or None
    return v.alert.command_line


def record_run(path, verdicts, source=None) -> dict:
    """Append one JSON-line record summarizing this run to path, and return it."""
    counts: dict[str, int] = {}
    for v in verdicts:
        counts[_label(v)] = counts.get(_label(v), 0) + 1
    rec = {
        "run_at": datetime.now(UTC).isoformat(),
        "source": source,
        "total": len(verdicts),
        "counts": counts,
        "flagged": [
            {"timestamp": v.alert.timestamp.isoformat(), "label": _label(v),
             "confidence": round(v.confidence, 3), "reason": _short(v.reason),
             "command": _cmd(v), "techniques": list(v.techniques)}
            for v in verdicts if _flagged(v)
        ],
    }
    with Path(path).open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    return rec


def load_runs(path) -> list:
    """Read all recorded runs (oldest first); an absent file means no history."""
    p = Path(path)
    if not p.is_file():
        return []
    out: list[dict] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out
