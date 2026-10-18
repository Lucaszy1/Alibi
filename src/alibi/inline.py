"""Inline guardrail: judge a PROPOSED tool call against the session so far, before it runs, with no
endpoint alert yet. Returns ALLOW / WARN / BLOCK. The preventive counterpart to the post-hoc alert
judge: a taint-derived call is a hijack in progress (BLOCK); a sensitive call the user never asked
for is WARN; everything else is ALLOW. Pure and reusable, so a hook, an MCP server, or a test can
all call assess()."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from alibi.decode import reveal
from alibi.judge import POLICY_CATEGORIES
from alibi.taint import trace_taint
from alibi.transcript import ToolCall, UserPrompt


class Decision(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True)
class InlineVerdict:
    decision: Decision
    reason: str
    category: str | None = None
    token: str | None = None


def _command_text(call: ToolCall) -> str:
    return " ".join(str(v) for v in call.tool_input.values())


def _content_policy(decoded_low: str, prompts_low: str):
    for cat in POLICY_CATEGORIES:
        if any(kw in decoded_low for kw in cat.keywords) and not any(kw in prompts_low for kw in cat.keywords):
            return cat.name
    return None


def assess(events, call: ToolCall, allowlist=None) -> InlineVerdict:
    """Decide ALLOW / WARN / BLOCK for a proposed call given the prior session events."""
    decoded = reveal(_command_text(call))
    low = decoded.lower()

    if allowlist is not None and not getattr(allowlist, "empty", True):
        rule = allowlist.match(decoded)
        if rule:
            return InlineVerdict(Decision.ALLOW, f"Sanctioned by allowlist ({rule}).")

    taint = trace_taint(list(events) + [call], call)
    if taint.tainted:
        why = ("a file the agent wrote from untrusted content" if taint.via_file
               else f"untrusted content ({taint.token})")
        return InlineVerdict(Decision.BLOCK,
                             f"This call is derived from {why}; likely a hijack in progress.",
                             token=taint.token)

    prompts_low = " ".join(p.text for p in events if isinstance(p, UserPrompt)).lower()
    cat = _content_policy(low, prompts_low)
    if cat is not None:
        return InlineVerdict(Decision.WARN,
                             f"Sensitive action ({cat}) the user did not ask for; confirm before allowing.",
                             category=cat)

    return InlineVerdict(Decision.ALLOW, "No untrusted influence and nothing sensitive beyond the request.")
