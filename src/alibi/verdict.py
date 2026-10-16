"""Verdict types produced by the judge."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum, IntEnum

from alibi.alerts import Alert
from alibi.link import LinkResult
from alibi.transcript import ToolCall


class VerdictKind(str, Enum):
    JUSTIFIED = "JUSTIFIED"      # the user's request covers this action
    UNJUSTIFIED = "UNJUSTIFIED"  # no request covers it, and no sign of outside influence
    HIJACKED = "HIJACKED"        # traces to untrusted content the user never asked for
    UNKNOWN = "UNKNOWN"          # agent-caused, but the deterministic tiers can't call it


class Disposition(str, Enum):
    VERDICT = "VERDICT"          # an agent action: carries a user-facing VerdictKind
    HARNESS = "HARNESS"          # Claude Code's own activity: no user request to judge against
    STAND_ASIDE = "STAND_ASIDE"  # not the agent: Alibi has nothing to say


class Concern(str, Enum):
    """How suspect a HARNESS disposition is. Harness activity is never JUSTIFIED by a request."""

    LOW = "LOW"            # expected infrastructure: API traffic, config writes, shell setup
    ELEVATED = "ELEVATED"  # unexplained: e.g. a process claude.exe spawned outside any tool call


class Tier(IntEnum):
    LINK = 1        # decided by linking alone (harness / stand aside)
    PROVENANCE = 2  # traced through the transcript
    POLICY = 3      # sensitive ATT&CK category
    MODEL = 4       # local model (not yet wired up)


class EvidenceSource(str, Enum):
    USER_PROMPT = "USER_PROMPT"
    UNTRUSTED_RESULT = "UNTRUSTED_RESULT"
    TOOL_CALL = "TOOL_CALL"
    POLICY = "POLICY"
    LINK = "LINK"


@dataclass(frozen=True)
class Evidence:
    source: EvidenceSource
    text: str
    timestamp: datetime | None = None
    tool_use_id: str | None = None  # for untrusted results and tool calls
    tool_name: str | None = None


@dataclass(frozen=True)
class Verdict:
    alert: Alert
    link: LinkResult
    disposition: Disposition
    verdict: VerdictKind | None  # set only when disposition is VERDICT
    confidence: float
    reason: str
    tier: Tier
    evidence: tuple[Evidence, ...] = ()
    techniques: tuple[str, ...] = ()
    concern: Concern | None = None  # set only when disposition is HARNESS

    @property
    def tool_call(self) -> ToolCall | None:
        return self.link.tool_call

    @property
    def label(self) -> str:
        if self.disposition is Disposition.VERDICT:
            return self.verdict.value
        if self.disposition is Disposition.HARNESS:
            return f"HARNESS/{self.concern.value}"
        return "STAND_ASIDE"
