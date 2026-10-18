"""M13b: Windows persistence reversals. Run-key, sc service, and startup-folder drops get safe
automatic reversals (targets validated, unsafe names withheld to manual); WMI subscriptions are
manual by design because no single safe command removes the filter, consumer, and binding together."""

from datetime import UTC, datetime

from alibi.alerts import Alert
from alibi.link import LinkResult
from alibi.remediate import plan_remediations
from alibi.transcript import ToolCall
from alibi.verdict import Disposition, Tier, Verdict, VerdictKind

TS = datetime(2026, 1, 1, tzinfo=UTC)


def _v(cmd, reason="persistence the user never asked for"):
    call = ToolCall(TS, "t1", "Bash", {"command": cmd}, r"C:\proj")
    link = LinkResult(call, "linked", 0.9)
    alert = Alert(timestamp=TS, rule_title="rule", level="high", computer="PC", channel="Sysmon",
                  event_id=1, record_id="1", rule_id="r", mitre_techniques=(), command_line=cmd)
    return Verdict(alert, link, Disposition.VERDICT, VerdictKind.HIJACKED, 0.85, reason, Tier.POLICY, (), ())


def test_run_key_reversal():
    cmd = r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "C:\x\p.exe" /f'
    r = plan_remediations([_v(cmd)])[0]
    assert r.action == "delete_run_key" and r.automatic
    assert r.command == r'reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Updater" /f'


def test_runonce_key_reversal():
    cmd = r'reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Boot /d evil.exe /f'
    r = plan_remediations([_v(cmd)])[0]
    assert r.action == "delete_run_key" and "RunOnce" in r.command and r.automatic


def test_service_create_reversal():
    cmd = 'sc create EvilSvc binPath= "C:\\x\\p.exe" start= auto'
    r = plan_remediations([_v(cmd)])[0]
    assert r.action == "delete_service" and "sc delete EvilSvc" in r.command and r.automatic


def test_new_service_powershell_reversal():
    cmd = 'New-Service -Name Persist -BinaryPathName C:\\x\\p.exe -StartupType Automatic'
    r = plan_remediations([_v(cmd)])[0]
    assert r.action == "delete_service" and "Persist" in r.command


def test_startup_folder_drop_quarantined():
    cmd = r'copy payload.exe "C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\upd.exe"'
    r = plan_remediations([_v(cmd)])[0]
    assert r.action == "quarantine_file" and r.target.endswith("upd.exe") and r.reversible


def test_wmi_persistence_is_manual():
    cmd = 'wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name="f", Query="SELECT *"'
    r = plan_remediations([_v(cmd)])[0]
    assert r.action == "review_wmi" and r.manual


def test_run_key_withheld_for_unsafe_value_name():
    cmd = r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Pwn;calc /d x /f'
    r = plan_remediations([_v(cmd)])[0]
    assert r.action == "manual_review" and r.command is None


def test_service_withheld_for_unsafe_name():
    cmd = 'sc create Evil$(calc) binPath= x'
    r = plan_remediations([_v(cmd)])[0]
    assert r.action == "manual_review" and r.command is None
