"""The 'remediate' CLI path: dry run lists proposals and touches nothing; --apply runs a reversal
only after a y/N confirm. subprocess.run and input are stubbed, so no real command executes."""

import builtins
import io
import subprocess

from alibi.alerts import Alert
from alibi.cli import _remediate
from alibi.link import LinkResult
from alibi.transcript import ToolCall
from alibi.verdict import Disposition, Tier, Verdict, VerdictKind

from datetime import datetime, timezone

TS = datetime(2026, 1, 1, tzinfo=timezone.utc)


class _Args:
    def __init__(self, apply):
        self.apply = apply


def _sched_verdict():
    cmd = 'schtasks /create /tn WinHealthCheck /sc once /tr "cmd /c cmdkey /list"'
    call = ToolCall(TS, "t1", "Bash", {"command": cmd}, r"C:\proj")
    link = LinkResult(call, "linked", 0.9)
    alert = Alert(timestamp=TS, rule_title="rule", level="high", computer="PC", channel="Sysmon",
                  event_id=1, record_id="1", rule_id="r", mitre_techniques=(), command_line=cmd)
    return Verdict(alert, link, Disposition.VERDICT, VerdictKind.HIJACKED, 0.85,
                   "payload of a scheduled task", Tier.POLICY, (), ())


def test_dry_run_lists_and_runs_nothing(monkeypatch):
    ran = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: ran.append(a[0]))
    out, err = io.StringIO(), io.StringIO()
    code = _remediate([_sched_verdict()], _Args(False), out, err)
    assert "delete_scheduled_task" in out.getvalue() and "Dry run" in out.getvalue()
    assert ran == [] and code == 1


def test_apply_runs_after_yes(monkeypatch):
    ran = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: ran.append(a[0]))
    monkeypatch.setattr(builtins, "input", lambda *a, **k: "y")
    out, err = io.StringIO(), io.StringIO()
    code = _remediate([_sched_verdict()], _Args(True), out, err)
    assert ran and "schtasks /delete" in ran[0]
    assert "applied" in out.getvalue() and code == 1


def test_apply_declined_runs_nothing(monkeypatch):
    ran = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: ran.append(a[0]))
    monkeypatch.setattr(builtins, "input", lambda *a, **k: "n")
    out, err = io.StringIO(), io.StringIO()
    _remediate([_sched_verdict()], _Args(True), out, err)
    assert ran == [] and "declined" in out.getvalue()


def test_nothing_flagged_is_clean(monkeypatch):
    out, err = io.StringIO(), io.StringIO()
    code = _remediate([], _Args(True), out, err)
    assert code == 0 and "nothing flagged" in err.getvalue()
