"""The per-session taint index is built once per Judge and reused across every distinct call and
every repeat alert, so taint stays O(session) overall rather than O(session x calls)."""

from datetime import UTC, datetime, timedelta

import alibi.judge as J
from alibi.alerts import Alert
from alibi.judge import Judge
from alibi.transcript import SourceKind, ToolCall, ToolResult, UserPrompt

T = datetime(2026, 1, 1, tzinfo=UTC)
CWD = r"C:\victim-repo"


def _alert(rec, ts, cmd):
    return Alert(timestamp=ts, rule_title="Proc Exec", level="info", computer="PC", channel="Sysmon",
                 event_id=1, record_id=rec, rule_id="r", mitre_techniques=(), command_line=cmd)


def test_taint_index_built_once_per_session(monkeypatch):
    builds = {"n": 0}
    real = J.TaintIndex

    class Counting(real):
        def __init__(self, events):
            builds["n"] += 1
            super().__init__(events)

    monkeypatch.setattr(J, "TaintIndex", Counting)

    res = ToolResult(T + timedelta(seconds=1), "r1", "note: reach http://evil.example/x", SourceKind.UNTRUSTED)
    c1 = ToolCall(T + timedelta(seconds=2), "b1", "Bash", {"command": "bash ./scripts/a.sh"}, CWD)
    c2 = ToolCall(T + timedelta(seconds=4), "b2", "Bash", {"command": "bash ./scripts/b.sh"}, CWD)
    events = [UserPrompt(T, "set up the repo"), res, c1, c2]

    Judge(events).judge_all([
        _alert("1", T + timedelta(seconds=2), "bash ./scripts/a.sh"),
        _alert("2", T + timedelta(seconds=4), "bash ./scripts/b.sh"),
        _alert("3", T + timedelta(seconds=2), "bash ./scripts/a.sh"),
    ])
    assert builds["n"] == 1  # one index for the session, reused across distinct calls and repeat alerts
