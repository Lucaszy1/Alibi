"""The ``alibi`` command: run the whole pipeline over a Hayabusa results CSV and a transcript.

    alibi scan <hayabusa-results.csv> [transcript.jsonl] [--json] [--all]
               [--min-confidence X] [--window-seconds N] [--color auto|always|never]

By default only what needs a human is listed: HIJACKED, UNJUSTIFIED, UNKNOWN, and harness
activity with ELEVATED concern. ``--all`` adds JUSTIFIED, low-concern harness, and stand-aside.

Exit codes, so a CI run or pipeline can gate on the result:
    0  nothing HIJACKED or UNJUSTIFIED
    1  at least one HIJACKED or UNJUSTIFIED verdict at or above --min-confidence
    2  usage error, missing file, or input that could not be parsed
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import timezone
from pathlib import Path
from typing import Any, Iterable, TextIO

from alibi.alerts import load_alerts
from alibi.judge import Judge
from alibi.link import DEFAULT_WINDOW_SECONDS
from alibi.transcript import ToolCall, load_transcript
from alibi.verdict import Concern, Disposition, Verdict, VerdictKind

SUMMARY_ORDER = ("HIJACKED", "UNJUSTIFIED", "UNKNOWN", "HARNESS", "JUSTIFIED", "STAND_ASIDE")
# Lower sorts first in the listing.
_RANK = {"HIJACKED": 0, "UNJUSTIFIED": 1, "UNKNOWN": 2, "HARNESS/ELEVATED": 3, "JUSTIFIED": 4,
         "HARNESS/LOW": 5, "STAND_ASIDE": 6}
_COLORS = {"HIJACKED": "1;31", "UNJUSTIFIED": "31", "UNKNOWN": "33", "HARNESS/ELEVATED": "35",
           "JUSTIFIED": "32", "HARNESS/LOW": "2", "STAND_ASIDE": "2"}


def default_projects_dir() -> Path:
    return Path.home() / ".claude" / "projects"


def find_latest_transcript(projects_dir: Path | None = None) -> Path | None:
    """The most recently modified session transcript (top-level ``<project>/<session>.jsonl``)."""
    base = projects_dir or default_projects_dir()
    candidates = [p for p in base.glob("*/*.jsonl") if p.is_file()]
    return max(candidates, key=lambda p: p.stat().st_mtime) if candidates else None


def needs_attention(v: Verdict) -> bool:
    if v.disposition is Disposition.VERDICT:
        return v.verdict is not VerdictKind.JUSTIFIED
    return v.disposition is Disposition.HARNESS and v.concern is Concern.ELEVATED


def _summary_key(v: Verdict) -> str:
    return v.verdict.value if v.disposition is Disposition.VERDICT else v.disposition.value


def _call_text(call: ToolCall | None) -> str | None:
    if call is None:
        return None
    inp = call.tool_input
    return str(inp.get("command") or inp.get("file_path") or inp.get("notebook_path") or inp.get("url") or "") or None


def verdict_to_json(v: Verdict) -> dict[str, Any]:
    a, call = v.alert, v.tool_call
    return {
        "timestamp": a.timestamp.isoformat(),
        "disposition": v.disposition.value,
        "verdict": v.verdict.value if v.verdict else None,
        "concern": v.concern.value if v.concern else None,
        "label": v.label,
        "confidence": v.confidence,
        "reason": v.reason,
        "tier": v.tier.name,
        "rule_title": a.rule_title,
        "rule_id": a.rule_id,
        "level": a.level,
        "computer": a.computer,
        "channel": a.channel,
        "event_id": a.event_id,
        "record_id": a.record_id,
        "techniques": list(v.techniques),
        "tactics": list(a.mitre_tactics),
        "process": {
            "image": a.process_image, "pid": a.pid, "command_line": a.command_line,
            "parent_image": a.parent_image, "parent_pid": a.parent_pid,
        },
        "link": {"origin": v.link.origin.value, "reason": v.link.match_reason, "confidence": v.link.confidence},
        "tool_call": None if call is None else {
            "tool_use_id": call.tool_use_id, "tool_name": call.tool_name,
            "timestamp": call.timestamp.isoformat(), "command": _call_text(call),
        },
        "command": _call_text(call),
        "evidence": [
            {"source": e.source.value, "text": e.text,
             "timestamp": e.timestamp.isoformat() if e.timestamp else None,
             "tool_use_id": e.tool_use_id, "tool_name": e.tool_name}
            for e in v.evidence
        ],
    }


# ---------------------------------------------------------------------------------------------
# Human output


class _Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.enabled and code else text


def _use_color(mode: str, stream: TextIO) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _shorten(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _key_evidence(v: Verdict):
    from alibi.verdict import EvidenceSource

    for source in (EvidenceSource.UNTRUSTED_RESULT, EvidenceSource.USER_PROMPT, EvidenceSource.POLICY, EvidenceSource.LINK):
        for e in v.evidence:
            if e.source is source:
                return e
    return None


def _group(verdicts: Iterable[Verdict]) -> list[list[Verdict]]:
    """Alerts from the same tool call with the same outcome read as one finding."""
    groups: dict[tuple, list[Verdict]] = {}
    for v in verdicts:
        call = v.tool_call
        key = (v.label, v.reason, call.tool_use_id if call else f"alert:{id(v)}")
        groups.setdefault(key, []).append(v)
    return list(groups.values())


def render_human(verdicts: list[Verdict], shown: list[Verdict], out: TextIO, style: _Style,
                 source: str, hidden_low_conf: int) -> None:
    counts = Counter(_summary_key(v) for v in verdicts)
    elevated = sum(1 for v in verdicts if v.concern is Concern.ELEVATED)
    parts = []
    for key in SUMMARY_ORDER:
        n = counts.get(key, 0)
        label = f"{key} {n}"
        if key == "HARNESS" and elevated:
            label += f" ({elevated} elevated)"
        color = _COLORS.get("HARNESS/ELEVATED" if key == "HARNESS" and elevated else key, "")
        parts.append(style(label, color) if n else label)
    print(f"alibi: {len(verdicts)} alerts  |  " + "  ".join(parts), file=out)
    print(style(f"transcript: {source}", "2"), file=out)

    if not shown:
        print("\nNothing needs attention." if not hidden_low_conf else "", file=out)
    groups = sorted(_group(shown), key=lambda g: (_RANK.get(g[0].label, 9), -g[0].confidence, g[0].alert.timestamp))
    for g in groups:
        v = g[0]
        ts = v.alert.timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        head = style(f"{v.label:<11}", _COLORS.get(v.label, "")) + f" {v.confidence:.2f}  {ts}  tier {v.tier.value} ({v.tier.name.lower()})"
        print(f"\n{head}", file=out)
        rules = Counter(x.alert.rule_title for x in g)
        techniques = sorted({t for x in g for t in x.techniques})
        rule_line = ", ".join(f"{r} x{n}" if n > 1 else r for r, n in rules.items())
        print(f"  alert:    {rule_line}" + (f"  [{', '.join(techniques)}]" if techniques else "")
              + (f"  ({len(g)} alerts)" if len(g) > 1 else ""), file=out)
        print(f"  why:      {v.reason}", file=out)
        cmd = _call_text(v.tool_call)
        if cmd:
            print(f"  action:   {v.tool_call.tool_name}: {_shorten(cmd, 160)}", file=out)
        elif v.alert.command_line:
            print(f"  process:  {_shorten(v.alert.command_line, 160)}", file=out)
        e = _key_evidence(v)
        if e:
            where = e.source.value.lower().replace("_", " ")
            if e.tool_name:
                where += f" ({e.tool_name})"
            print(f"  evidence: {style(where, '2')}: {_shorten(e.text, 240)}", file=out)
    if hidden_low_conf:
        print(style(f"\n{hidden_low_conf} more below --min-confidence not shown.", "2"), file=out)


# ---------------------------------------------------------------------------------------------
# Entry point


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alibi", description="Judge endpoint alerts against an AI agent session.",
        epilog="exit codes: 0 clean, 1 HIJACKED or UNJUSTIFIED found, 2 error",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser(
        "scan", help="judge every alert in a Hayabusa results CSV",
        epilog="exit codes: 0 clean, 1 HIJACKED or UNJUSTIFIED at or above --min-confidence, 2 error",
    )
    scan.add_argument("results", type=Path, help="Hayabusa results CSV")
    scan.add_argument("transcript", type=Path, nargs="?",
                      help="session transcript (.jsonl); default: the most recent under ~/.claude/projects")
    scan.add_argument("--json", action="store_true", help="one JSON object per verdict (JSON Lines)")
    scan.add_argument("--all", action="store_true", help="include JUSTIFIED, low-concern harness, and stand-aside")
    scan.add_argument("--min-confidence", type=float, default=0.0, metavar="X",
                      help="only list verdicts with confidence >= X (summary still counts all)")
    scan.add_argument("--window-seconds", type=float, default=DEFAULT_WINDOW_SECONDS, metavar="N",
                      help=f"attribution window for calls with no result or run in background (default {DEFAULT_WINDOW_SECONDS:g})")
    scan.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    scan.add_argument("--model", nargs="?", const="llama3.1:8b", default=None, metavar="NAME",
                      help="adjudicate UNKNOWN verdicts with a local Ollama model (default llama3.1:8b)")
    scan.add_argument("--ollama-host", default="http://127.0.0.1:11434", metavar="URL",
                      help="Ollama host for --model (default http://127.0.0.1:11434)")
    scan.add_argument("--max-model-calls", type=int, default=50, metavar="N",
                      help="cap model adjudications per scan (default 50)")
    return parser


def main(argv: list[str] | None = None, out: TextIO | None = None, err: TextIO | None = None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    for stream in (out, err):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")  # a cp1252 console must not crash on "…"
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.results.is_file():
        print(f"alibi: results file not found: {args.results}", file=err)
        return 2
    transcript = args.transcript or find_latest_transcript()
    if transcript is None:
        print(f"alibi: no transcript given and none found under {default_projects_dir()}", file=err)
        return 2
    if not transcript.is_file():
        print(f"alibi: transcript not found: {transcript}", file=err)
        return 2

    try:
        alerts = load_alerts(args.results)
        events = load_transcript(transcript)
    except Exception as exc:  # a crash would exit 1, which reads as "findings" to a CI gate
        print(f"alibi: could not read input: {type(exc).__name__}: {exc}", file=err)
        return 2
    calls = [e for e in events if isinstance(e, ToolCall)]
    if alerts and calls and (calls[-1].timestamp < alerts[0].timestamp or calls[0].timestamp > alerts[-1].timestamp):
        print(f"alibi: warning: {transcript.name} does not overlap the alerts in time; nothing can link.", file=err)

    model_tier = None
    if args.model:
        from alibi.model_tier import CachingModelTier, OllamaBackend
        model_tier = CachingModelTier(OllamaBackend(model=args.model, host=args.ollama_host),
                                      max_calls=args.max_model_calls)
    verdicts = Judge(events, model_tier=model_tier, window_seconds=args.window_seconds).judge_all(alerts)
    selected = verdicts if args.all else [v for v in verdicts if needs_attention(v)]
    shown = [v for v in selected if v.confidence >= args.min_confidence]
    shown.sort(key=lambda v: (_RANK.get(v.label, 9), -v.confidence, v.alert.timestamp))

    if args.json:
        for v in shown:
            out.write(json.dumps(verdict_to_json(v)) + "\n")
    else:
        render_human(verdicts, shown, out, _Style(_use_color(args.color, out)), str(transcript), len(selected) - len(shown))

    failing = (VerdictKind.HIJACKED, VerdictKind.UNJUSTIFIED)
    return 1 if any(v.verdict in failing and v.confidence >= args.min_confidence for v in verdicts) else 0


if __name__ == "__main__":
    sys.exit(main())
