"""Attack-chain correlation: group the separate flagged verdicts from one intrusion into a single
incident. A hijack unfolds as a burst of actions on one host (poisoned read, credential access,
exfiltration); reported separately they read as noise, grouped they tell the story.

Pure and self-contained: flagged verdicts on the same host within a window chain into one incident;
different hosts or a gap larger than the window start a new one."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from alibi.verdict import Disposition, VerdictKind

_FLAGGED = (VerdictKind.HIJACKED, VerdictKind.UNJUSTIFIED)
DEFAULT_WINDOW_SECONDS = 120.0


@dataclass(frozen=True)
class Incident:
    verdicts: tuple

    @property
    def computer(self):
        return self.verdicts[0].alert.computer

    @property
    def start(self):
        return self.verdicts[0].alert.timestamp

    @property
    def end(self):
        return self.verdicts[-1].alert.timestamp

    @property
    def span_seconds(self) -> float:
        return (self.end - self.start).total_seconds()

    @property
    def hijacked(self) -> bool:
        return any(v.verdict is VerdictKind.HIJACKED for v in self.verdicts)

    @property
    def techniques(self) -> tuple:
        out = []
        for v in self.verdicts:
            for t in v.techniques:
                if t not in out:
                    out.append(t)
        return tuple(out)

    @property
    def summary(self) -> str:
        kind = "hijack chain" if self.hijacked else "unrequested-action cluster"
        techs = ", ".join(self.techniques) or "none"
        return (f"{len(self.verdicts)} flagged actions on {self.computer} over "
                f"{self.span_seconds:.0f}s ({kind}); techniques: {techs}")


def correlate(verdicts, window_seconds: float = DEFAULT_WINDOW_SECONDS) -> list:
    """Chain flagged verdicts on the same host within window_seconds into incidents, time-ordered."""
    flagged = sorted(
        (v for v in verdicts if v.disposition is Disposition.VERDICT and v.verdict in _FLAGGED),
        key=lambda v: v.alert.timestamp,
    )
    incidents: list = []
    current: list = []
    for v in flagged:
        if (current and v.alert.computer == current[-1].alert.computer
                and (v.alert.timestamp - current[-1].alert.timestamp) <= timedelta(seconds=window_seconds)):
            current.append(v)
        else:
            if current:
                incidents.append(Incident(tuple(current)))
            current = [v]
    if current:
        incidents.append(Incident(tuple(current)))
    return incidents
