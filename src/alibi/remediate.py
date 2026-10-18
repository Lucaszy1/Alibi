"""Proposed reversals for flagged verdicts, gated behind human approval.

Alibi never acts on its own. plan_remediations turns HIJACKED / UNJUSTIFIED verdicts into
concrete, described reversals; apply_remediations runs one only if an approver says yes AND a
real executor is supplied. With no executor an approved item is a dry run, so planning and review
are always side-effect free."""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace

from alibi.verdict import Disposition, Verdict, VerdictKind

_FLAGGED = (VerdictKind.HIJACKED, VerdictKind.UNJUSTIFIED)
_CRED_EXFIL = {"T1555", "T1003", "T1552", "T1558", "T1539", "T1041", "T1048", "T1567", "T1020"}
_SCHTASK_NAME_RE = re.compile(r"/tn\s+\"?([^\"/]+?)\"?(?:\s|$)", re.I)


@dataclass(frozen=True)
class Remediation:
    verdict: Verdict
    action: str                 # delete_scheduled_task | quarantine_file | restore_files | rotate_credential | manual_review
    description: str
    command: str | None = None  # concrete reversal, or None when only a human can do it
    target: str | None = None
    reversible: bool = False     # whether the reversal itself can be undone (quarantine, git restore)
    manual: bool = True          # True => Alibi cannot do it automatically
    argv: tuple | None = None    # shell-free argument vector from validated parts; None => needs a shell

    @property
    def automatic(self) -> bool:
        return not self.manual and self.command is not None

    @property
    def needs_shell(self) -> bool:
        return self.argv is None and self.command is not None


_CRED_CMD_RE = re.compile(r"(cmdkey|vaultcmd|secretsdump|mimikatz|lsass|/\.aws/credentials|/\.ssh/id_|\.netrc|security find-generic-password)", re.I)
_EXFIL_CMD_RE = re.compile(r"\b(curl|wget|invoke-webrequest|iwr|ncat|scp)\b", re.I)


_SYSTEMD_UNIT_RE = re.compile(r"([\w@.\-]+\.service)\b", re.I)
_SYSTEMD_ENABLE_RE = re.compile(r"systemctl\s+(?:--[\w=]+\s+)*(?:enable|start|unmask)\s+(?:--[\w=]+\s+)*([\w@.\-]+)", re.I)
_PLIST_RE = re.compile(r"([^\s\"']+\.plist)", re.I)


def _systemd_unit(cmd):
    m = _SYSTEMD_UNIT_RE.search(cmd) or _SYSTEMD_ENABLE_RE.search(cmd)
    return m.group(1) if m else None


def _plist_path(cmd):
    m = _PLIST_RE.search(cmd)
    return m.group(1) if m else None


def _default_os() -> str:
    return "windows" if sys.platform.startswith("win") else "posix"


def _command(v: Verdict) -> str:
    call = v.tool_call
    if call is not None:
        c = call.tool_input.get("command") or call.tool_input.get("content") or ""
        if c:
            return str(c)
    return v.alert.command_line or ""


def _bases(v: Verdict) -> set:
    return {t.split(".")[0].upper() for t in v.techniques}


def _file_target(v: Verdict):
    for key in ("TargetFilename", "Path", "TgtFile"):
        val = v.alert.fields.get(key)
        if val and val.strip() not in ("", "-"):
            return val.strip()
    call = v.tool_call
    if call is not None and call.tool_input.get("file_path"):
        return str(call.tool_input["file_path"])
    return None


def _schtask_name(cmd: str):
    m = _SCHTASK_NAME_RE.search(cmd)
    return m.group(1).strip() if m else None


_REG_RUN_RE = re.compile(r"reg(?:\.exe)?\s+add\s+\"?(HK[^\"\s]+)\"?.*?/v\s+\"?([^\"/]+?)\"?(?:\s+/|\s*$)", re.I | re.S)
_SC_CREATE_RE = re.compile(r"\bsc(?:\.exe)?\s+create\s+\"?([^\"\s]+)\"?", re.I)
_NEWSVC_RE = re.compile(r"New-Service\b.*?-Name\s+\"?([^\"\s]+)\"?", re.I | re.S)
_STARTUP_RE = re.compile(r"([A-Za-z]:\\[^\"\r\n|&]*?\\Startup\\[^\"\r\n|&]+)", re.I)
_WMI_RE = re.compile(r"(CommandLineEventConsumer|ActiveScriptEventConsumer|__EventFilter|__FilterToConsumerBinding|Register-WmiEvent|Set-WmiInstance)", re.I)
_SAFE_KEY_RE = re.compile(r"^HK[A-Za-z0-9_\\]+$", re.I)


def _win_persistence(v, cmd):
    low = cmd.lower()
    m = _REG_RUN_RE.search(cmd)
    if m and "\\run" in m.group(1).lower():
        key, name = m.group(1), m.group(2).strip()
        if _SAFE_KEY_RE.match(key):
            return Remediation(v, "delete_run_key",
                               f"Delete the Run-key autostart entry '{name}' the agent added under {key}.",
                               command=f'reg delete "{key}" /v "{name}" /f', target=name, manual=False,
                               argv=("reg", "delete", key, "/v", name, "/f"))
        return Remediation(v, "manual_review",
                           "Run-key persistence detected but the registry path looks unsafe to auto-edit; remove it manually.",
                           manual=True)
    m = _SC_CREATE_RE.search(cmd) or _NEWSVC_RE.search(cmd)
    if m and ("sc create" in low or "sc.exe create" in low or "new-service" in low):
        name = m.group(1).strip()
        return Remediation(v, "delete_service",
                           f"Stop and delete the Windows service '{name}' the agent created.",
                           command=f"sc stop {name} & sc delete {name}", target=name, manual=False)
    m = _STARTUP_RE.search(cmd)
    if m:
        path = m.group(1).strip().strip('"')
        stamp = v.alert.timestamp.strftime("%Y%m%d%H%M%S")
        dest = f"{path}.{stamp}.alibi-quarantine"
        return Remediation(v, "quarantine_file",
                           f"Quarantine the autostart file dropped in the Startup folder ({path}).",
                           command=f'move "{path}" "{dest}"', target=path,
                           reversible=True, manual=False, argv=("move", path, dest))
    if _WMI_RE.search(cmd):
        return Remediation(v, "review_wmi",
                           "WMI event-subscription persistence detected. Removing it safely means deleting the "
                           "__EventFilter, the consumer, and their binding; Alibi will not auto-edit WMI. "
                           "Inspect 'Get-WmiObject -Namespace root/subscription' and remove them manually.",
                           manual=True)
    return None


def _propose(v: Verdict, os_name: str) -> Remediation:
    cmd = _command(v)
    reason = v.reason.lower()
    bases = _bases(v)

    if "scheduled task" in reason or "T1053" in bases or "schtasks" in cmd.lower():
        name = _schtask_name(cmd)
        if name:
            return Remediation(v, "delete_scheduled_task",
                               f"Delete the scheduled task '{name}' the agent created.",
                               command=f'schtasks /delete /tn "{name}" /f', target=name, manual=False,
                               argv=("schtasks", "/delete", "/tn", name, "/f"))

    win = _win_persistence(v, cmd)
    if win is not None:
        return win

    low = cmd.lower()
    plist = _plist_path(cmd)
    if "launchctl" in low and plist:
        return Remediation(v, "unload_launch_agent",
                           f"Unload and remove the launch agent the agent installed ({plist}).",
                           command=f'launchctl unload "{plist}"', target=plist, manual=False,
                           argv=("launchctl", "unload", plist))
    unit = _systemd_unit(cmd)
    if unit:
        return Remediation(v, "disable_service",
                           f"Disable and stop the systemd service the agent installed ({unit}).",
                           command=f"systemctl disable --now {unit}", target=unit, manual=False,
                           argv=("systemctl", "disable", "--now", unit))
    if "crontab" in low or "/etc/cron" in low:
        return Remediation(v, "review_cron",
                           "Review the crontab (crontab -l) or /etc/cron.* and remove the entry the agent added; "
                           "Alibi will not edit your crontab automatically.", manual=True)

    path = _file_target(v)
    if path and (v.alert.event_id == 11 or "wrote" in reason or "file" in v.alert.rule_title.lower()
                 or (v.tool_call and v.tool_call.tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"))):
        stamp = v.alert.timestamp.strftime("%Y%m%d%H%M%S")
        dest = f"{path}.{stamp}.alibi-quarantine"
        mv = "move" if os_name == "windows" else "mv"
        return Remediation(v, "quarantine_file",
                           f"Quarantine the file the agent wrote ({path}) by moving it aside.",
                           command=f'{mv} "{path}" "{dest}"', target=path,
                           reversible=True, manual=False, argv=(mv, path, dest))

    if "files rewritten" in reason:
        return Remediation(v, "restore_files",
                           "Restore the rewritten files from version control (git restore) or a backup. "
                           "This discards the agent's edits and cannot be undone by Alibi.",
                           command="git restore .", reversible=False, manual=False,
                           argv=("git", "restore", "."))

    is_cred = bool(_CRED_CMD_RE.search(cmd))
    is_exfil = ("targets host" in reason or "exfiltrat" in reason
                or (bool(_EXFIL_CMD_RE.search(cmd)) and ("http" in cmd.lower() or "--data" in cmd.lower())))
    if (bases & _CRED_EXFIL) or is_cred or is_exfil:
        return Remediation(v, "rotate_credential",
                           "Rotate or revoke any credential the agent could have read or sent. Alibi cannot do this for you.",
                           manual=True)

    return Remediation(v, "manual_review", "No safe automatic reversal; review this action manually.", manual=True)


_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9 _.\-:()\\/~]+$")
_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9.\-]+$")
_SAFE_SVC_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
_SAFE_RUNVAL_RE = re.compile(r"^[A-Za-z0-9 _.\-]+$")
_SAFE_UNIT_RE = re.compile(r"^[A-Za-z0-9@._\-]+$")
_SAFE_TASK_RE = re.compile(r"^[A-Za-z0-9 _.\-\\/]+$")


_URL_HOST_RE = re.compile(r"https?://([^/\s\"']+)", re.I)
_REASON_HOST_RE = re.compile(r"targets host:([^\s]+)", re.I)


def _host(cmd, reason):
    m = _URL_HOST_RE.search(cmd) or _REASON_HOST_RE.search(reason)
    return m.group(1).strip().strip(".,;") if m else None


def _norm_target(raw):
    raw = (raw or "").strip().strip(".,;")
    if raw.startswith("["):
        return raw[1:raw.index("]")] if "]" in raw else raw[1:]
    if raw.count(":") == 1:
        return raw.split(":", 1)[0]
    return raw


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_ipv6(host):
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


def _extra(v, os_name):
    cmd = _command(v)
    reason = v.reason.lower()
    is_exfil = ("targets host" in reason or "exfiltrat" in reason
                or (bool(_EXFIL_CMD_RE.search(cmd)) and ("http" in cmd.lower() or "--data" in cmd.lower())))
    raw = _host(cmd, reason) if is_exfil else None
    if not raw:
        return []
    host = _norm_target(raw)
    if _is_ip(host):
        if os_name == "windows":
            blk = f'netsh advfirewall firewall add rule name="Alibi block {host}" dir=out action=block remoteip={host}'
            argv = ("netsh", "advfirewall", "firewall", "add", "rule",
                    f"name=Alibi block {host}", "dir=out", "action=block", f"remoteip={host}")
        else:
            tool = "ip6tables" if _is_ipv6(host) else "iptables"
            blk = f"sudo {tool} -A OUTPUT -d {host} -j DROP"
            argv = ("sudo", tool, "-A", "OUTPUT", "-d", host, "-j", "DROP")
        return [Remediation(v, "block_ip",
                            f"Block the exfiltration IP {host} outbound with a firewall rule.",
                            command=blk, target=host, reversible=True, manual=False, argv=argv)]
    if os_name == "windows":
        blk = rf"echo 0.0.0.0 {host} >> %SystemRoot%\System32\drivers\etc\hosts"
    else:
        blk = f'echo "0.0.0.0 {host}" | sudo tee -a /etc/hosts'
    return [Remediation(v, "block_host",
                        f"Block the exfiltration host {host} by routing it to 0.0.0.0 in the hosts file.",
                        command=blk, target=host, reversible=True, manual=False)]


def _target_is_safe(rem) -> bool:
    if rem.command and ("\n" in rem.command or "\r" in rem.command):
        return False
    t = rem.target or ""
    if rem.action in ("quarantine_file", "unload_launch_agent"):
        return bool(_SAFE_PATH_RE.match(t))
    if rem.action == "delete_scheduled_task":
        return bool(_SAFE_TASK_RE.match(t))
    if rem.action == "disable_service":
        return bool(_SAFE_UNIT_RE.match(t))
    if rem.action == "block_host":
        return bool(_SAFE_HOST_RE.match(t))
    if rem.action == "block_ip":
        return _is_ip(t)
    if rem.action == "delete_service":
        return bool(_SAFE_SVC_RE.match(t))
    if rem.action == "delete_run_key":
        return bool(_SAFE_RUNVAL_RE.match(t))
    return True


def _harden(rem):
    """Fail safe: never auto-run a reversal Alibi cannot vouch for.

    An attacker controls file paths, hosts, service units and task names inside the session, so an
    interpolated command could be a code-execution path under --apply (unsafe characters), and a
    name extracted from a quoted multi-word argument may be truncated to the wrong target. Either
    case is downgraded to a manual review with no command."""
    if not rem.automatic:
        return rem
    cmd = _command(rem.verdict)
    for quoted in re.findall(r'"([^"]*\s[^"]*)"', cmd):
        if rem.target and rem.target in quoted and rem.target != quoted:
            return replace(rem, action="manual_review", command=None, argv=None, reversible=False, manual=True,
                           description="Generated reversal withheld: the target name was truncated from a "
                                       "quoted multi-word argument and may hit the wrong target. Handle it manually.")
    if not _target_is_safe(rem):
        return replace(rem, action="manual_review", command=None, argv=None, reversible=False, manual=True,
                       description="Generated reversal withheld: the target has unusual or unsafe "
                                   "characters. Inspect and handle this manually.")
    return rem


def plan_remediations(verdicts, target_os: str | None = None) -> list:
    """A proposed reversal for each HIJACKED / UNJUSTIFIED verdict, de-duplicated. Pure, no side effects.

    target_os ("windows" or "posix") picks the shell form of generated commands; it defaults to
    the platform running Alibi, since that is where --apply would execute them. Verdicts that map
    to the same reversal (one action flagged by several overlapping rules) collapse to one proposal."""
    os_name = target_os or _default_os()
    seen = set()
    out = []
    for v in verdicts:
        if v.disposition is not Disposition.VERDICT or v.verdict not in _FLAGGED:
            continue
        for rem in (_propose(v, os_name), *_extra(v, os_name)):
            rem = _harden(rem)
            key = (rem.action, rem.command, rem.target)
            if key in seen:
                continue
            seen.add(key)
            out.append(rem)
    return out


def apply_remediations(remediations, approver: Callable, executor: Callable | None = None) -> list:
    """Run each remediation ONLY if the approver says yes and an executor is supplied.

    approver is asked per item; a falsey answer leaves it untouched. With no executor an approved
    item is a dry run ("approved-dryrun") that changes nothing. Manual items are never executed.
    Nothing here runs without an explicit yes."""
    results = []
    for r in remediations:
        if not r.automatic:
            results.append((r, "manual"))
            continue
        if not approver(r):
            results.append((r, "declined"))
            continue
        if executor is None:
            results.append((r, "approved-dryrun"))
            continue
        executor(r)
        results.append((r, "applied"))
    return results


@dataclass(frozen=True)
class UndoStep:
    action: str
    description: str
    command: str | None
    manual: bool
    argv: tuple | None = None

    @property
    def needs_shell(self) -> bool:
        return self.argv is None and self.command is not None


def _inverse(rem, os_name):
    """The exact inverse of one applied, reversible containment action, or None when it should not
    be auto-undone. Deletions of persistence are never undone here: reversing them would reinstate
    the attacker's autostart."""
    if rem.action == "quarantine_file":
        paths = re.findall(r'"([^"]*)"', rem.command or "")
        if len(paths) == 2:
            mv = "move" if os_name == "windows" else "mv"
            return UndoStep("restore_quarantined_file",
                            f"Move the quarantined file back to {paths[0]}.",
                            f'{mv} "{paths[1]}" "{paths[0]}"', False,
                            argv=(mv, paths[1], paths[0]))
        return None
    if rem.action == "block_ip":
        cmd = rem.command or ""
        if cmd.startswith("netsh"):
            return UndoStep("unblock_ip",
                            f"Remove the firewall rule blocking {rem.target}.",
                            f'netsh advfirewall firewall delete rule name="Alibi block {rem.target}"',
                            False,
                            argv=("netsh", "advfirewall", "firewall", "delete", "rule",
                                  f"name=Alibi block {rem.target}"))
        tool = "ip6tables" if "ip6tables" in cmd else "iptables"
        return UndoStep("unblock_ip",
                        f"Remove the firewall DROP rule for {rem.target}.",
                        cmd.replace(" -A OUTPUT ", " -D OUTPUT ", 1), False,
                        argv=("sudo", tool, "-D", "OUTPUT", "-d", rem.target, "-j", "DROP"))
    if rem.action == "block_host":
        return UndoStep("unblock_host",
                        f"Remove the '0.0.0.0 {rem.target}' line from the hosts file by hand; "
                        "Alibi will not auto-edit the hosts file to undo a block.",
                        None, True)
    return None


def rollback_bundle(results, target_os: str | None = None) -> list:
    """Undo steps for the reversals Alibi actually applied (status 'applied'). A dry run changes
    nothing, so it yields no undo steps. Pure; builds the plan, runs nothing."""
    os_name = target_os or _default_os()
    steps = []
    for rem, status in results:
        if status != "applied":
            continue
        step = _inverse(rem, os_name)
        if step is not None:
            steps.append(step)
    return steps


def bundle_to_json(steps) -> str:
    """Serialize an undo bundle so an operator can keep it and revert in a later session."""
    return json.dumps([asdict(s) for s in steps], indent=2)


def apply_undo(steps, approver, executor=None) -> list:
    """Run undo steps under the same consent gate as apply_remediations: a manual step or one with
    no command is never executed; others run only on an explicit yes AND a real executor."""
    results = []
    for s in steps:
        if s.manual or s.command is None:
            results.append((s, "manual"))
            continue
        if not approver(s):
            results.append((s, "declined"))
            continue
        if executor is None:
            results.append((s, "approved-dryrun"))
            continue
        executor(s)
        results.append((s, "applied"))
    return results


def undo_from_json(text):
    """Reconstruct undo steps from a saved rollback bundle so `alibi undo` can revert later."""
    data = json.loads(text)
    return [UndoStep(d["action"], d["description"], d.get("command"), bool(d["manual"]),
                     tuple(d["argv"]) if d.get("argv") else None)
            for d in data]
