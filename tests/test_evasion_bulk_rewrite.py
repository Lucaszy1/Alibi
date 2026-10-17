"""Refactor vs ransomware: a burst of file rewrites the user never licensed is flagged UNJUSTIFIED,
but the same burst stays clean when the request asks for a bulk operation."""

from datetime import datetime, timedelta, timezone

from alibi.alerts import Alert
from alibi.judge import Judge
from alibi.transcript import SourceKind, ToolCall, ToolResult, UserPrompt
from alibi.verdict import VerdictKind

T = datetime(2026, 1, 1, tzinfo=timezone.utc)
CWD = r"C:\victim-repo"
CLAUDE = r"C:\Users\user\AppData\Local\Programs\claude\claude.exe"


def _burst(prompt, n=14):
    events = [UserPrompt(T, prompt)]
    alerts = []
    for i in range(n):
        path = CWD + rf"\src\mod_{i}.py"
        ts = T + timedelta(seconds=1 + i)
        events.append(ToolCall(ts, f"w{i}", "Write", {"file_path": path, "content": "x = 1\n"}, CWD))
        events.append(ToolResult(ts + timedelta(milliseconds=200), f"w{i}", "File created.", SourceKind.TRUSTED))
        alerts.append(Alert(timestamp=ts + timedelta(milliseconds=100),
                            rule_title="File Created (Sysmon Alert)", level="med", computer="PC",
                            channel="Sysmon", event_id=11, record_id=str(i), rule_id="r",
                            process_image=CLAUDE, fields={"TargetFilename": path}))
    return Judge(events).judge_all(alerts)


def test_unrequested_mass_rewrite_is_flagged():
    verdicts = _burst("summarize the README for me")
    assert len([v for v in verdicts if v.verdict is VerdictKind.UNJUSTIFIED]) >= 10


def test_requested_bulk_refactor_stays_clean():
    verdicts = _burst("refactor and reformat every file in the src module")
    assert all(v.verdict is not VerdictKind.UNJUSTIFIED for v in verdicts)


def test_small_number_of_writes_is_not_a_burst():
    verdicts = _burst("summarize the README for me", n=4)
    assert all(v.verdict is not VerdictKind.UNJUSTIFIED for v in verdicts)
