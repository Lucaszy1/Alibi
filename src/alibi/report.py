"""Incident reporting: turn verdicts into a readable Markdown report, one section per correlated
incident, with the injected snippet, the action, a provenance graph (Mermaid), the techniques, and
the proposed reversals. Pure; builds on incidents.correlate and remediate.plan_remediations."""

from __future__ import annotations

from alibi.incidents import correlate
from alibi.remediate import plan_remediations
from alibi.verdict import EvidenceSource
from alibi.redact import redact

_FENCE = chr(96) * 3


def _san(text, n=60):
    t = " ".join(redact(text or "").split()).replace('"', "'")
    return (t[: n - 1] + "\u2026") if len(t) > n else t


def _ev(v, source):
    for e in v.evidence:
        if getattr(e, "source", None) is source:
            return getattr(e, "text", "") or ""
    return ""


def _action(v):
    return _ev(v, EvidenceSource.TOOL_CALL) or (v.alert.command_line or v.alert.rule_title)


def build_report(verdicts, window_seconds: float = 120.0) -> str:
    incs = correlate(verdicts, window_seconds)
    out = ["# Alibi incident report", ""]
    if not incs:
        out.append("No incidents: nothing flagged.")
        return "\n".join(out) + "\n"
    out.append(f"{len(incs)} incident(s).")
    out.append("")
    for n, inc in enumerate(incs, 1):
        out.append(f"## Incident {n} - {inc.computer}")
        out.append("")
        out.append(f"- {redact(inc.summary)}")
        out.append(f"- Window: {inc.start:%Y-%m-%d %H:%M:%SZ} to {inc.end:%H:%M:%SZ}")
        out.append("")
        out.append("### Timeline")
        for i, v in enumerate(inc.verdicts, 1):
            out.append(f"{i}. {v.alert.timestamp:%H:%M:%SZ}  {v.label} ({v.confidence:.2f}) - {_san(v.reason, 160)}")
            out.append(f"    - action: {_san(_action(v), 120)}")
            unt = _ev(v, EvidenceSource.UNTRUSTED_RESULT)
            if unt:
                out.append(f"    - untrusted source: {_san(unt, 120)}")
        out.append("")
        out.append("### Provenance")
        out.append(_FENCE + "mermaid")
        out.append("flowchart LR")
        for i, v in enumerate(inc.verdicts, 1):
            out.append(f'  A{i}["{_san(_action(v), 40)}"]')
            unt = _ev(v, EvidenceSource.UNTRUSTED_RESULT)
            if unt:
                out.append(f'  U{i}["untrusted: {_san(unt, 40)}"] --> A{i}')
        out.append(_FENCE)
        out.append("")
        out.append("### Proposed remediation")
        rems = plan_remediations(inc.verdicts)
        if not rems:
            out.append("- none (manual review)")
        for r in rems:
            out.append(f"- {r.action}: {_san(r.description, 140)}{'' if r.manual else ' (automatic)'}")
        out.append("")
    return "\n".join(out) + "\n"
