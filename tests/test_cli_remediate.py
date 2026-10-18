"""The 'remediate' CLI path: dry run lists proposals and touches nothing; --apply runs a reversal
only after a y/N confirm. subprocess.run and input are stubbed, so no real command executes."""

import builtins
import io
import json
import subprocess
from datetime import UTC, datetime

from alibi.alerts import Alert
from alibi.cli import _remediate
from alibi.link import LinkResult
from alibi.transcript import ToolCall
from alibi.verdict import Disposition, Tier, Verdict, VerdictKind

TS = datetime(2026, 1, 1, tzinfo=UTC)


class _Args:
    def __init__(self, apply, json=False):
        self.apply = apply
        self.json = json


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
    assert ran and "schtasks" in ran[0] and "/delete" in ran[0]  # argv form, shell-free
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


def test_json_dry_run_emits_proposal_objects():
    out, err = io.StringIO(), io.StringIO()
    code = _remediate([_sched_verdict()], _Args(False, json=True), out, err)
    rows = [json.loads(l) for l in out.getvalue().splitlines() if l.strip()]
    assert code == 1 and rows and rows[0]["action"] == "delete_scheduled_task"
    assert rows[0]["manual"] is False and "Dry run" not in out.getvalue()


def test_json_apply_includes_status(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(builtins, "input", lambda *a, **k: "y")
    out, err = io.StringIO(), io.StringIO()
    _remediate([_sched_verdict()], _Args(True, json=True), out, err)
    rows = [json.loads(l) for l in out.getvalue().splitlines() if l.strip()]
    assert rows and rows[0]["status"] == "applied"
