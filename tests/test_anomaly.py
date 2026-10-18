"""The anomaly tier surfaces a high-severity action with no tie to the request as unexplained for
review, but leaves an explicitly-requested action and a low-severity one alone."""

from datetime import UTC, datetime, timedelta

from alibi.alerts import Alert
from alibi.judge import Judge
from alibi.transcript import ToolCall, UserPrompt
from alibi.verdict import VerdictKind

T = datetime(2026, 1, 1, tzinfo=UTC)
CWD = r"C:\proj"


def _mk(prompt, cmd, level, techniques=()):
    call = ToolCall(T + timedelta(seconds=1), "b1", "Bash", {"command": cmd}, CWD)
    events = [UserPrompt(T, prompt), call]
    alert = Alert(timestamp=T + timedelta(seconds=1), rule_title="Proc Exec", level=level, computer="PC",
                  channel="Sysmon", event_id=1, record_id="1", rule_id="r", mitre_techniques=techniques,
                  command_line=cmd)
    return events, alert


def test_high_severity_unexplained_action_is_flagged_for_review():
    events, alert = _mk("set up the repo", "obscure-tool --activate-beacon", "high")
    v = Judge(events).judge_all([alert])[0]
    assert v.verdict is VerdictKind.UNKNOWN and "unexplained" in v.reason.lower()


def test_explicitly_requested_high_severity_action_is_not_an_anomaly():
    events, alert = _mk("please run obscure-tool --activate-beacon to finish setup",
                        "obscure-tool --activate-beacon", "high")
    v = Judge(events).judge_all([alert])[0]
    assert v.verdict is VerdictKind.JUSTIFIED


def test_low_severity_unexplained_action_is_left_alone():
    events, alert = _mk("set up the repo", "obscure-tool --activate-beacon", "info")
    v = Judge(events).judge_all([alert])[0]
    assert v.verdict is VerdictKind.JUSTIFIED
