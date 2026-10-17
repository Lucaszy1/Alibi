"""Proposed reversals for flagged verdicts, gated behind human approval.

Alibi never acts on its own. plan_remediations turns HIJACKED / UNJUSTIFIED verdicts into
concrete, described reversals; apply_remediations runs one only if an approver says yes AND a
real executor is supplied. With no executor an approved item is a dry run, so planning and review
are always side-effect free."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import Callable

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

    @property
    def automatic(self) -> bool:
        return not self.manual and self.command is not None


_CRED_CMD_RE = re.compile(r"(cmdkey|vaultcmd|secretsdump|mimikatz|lsass|/\.aws/credentials|/\.ssh/id_|\.netrc|security find-generic-password)", re.I)
_EXFIL_CMD_RE = re.compile(r"\b(curl|wget|invoke-webrequest|iwr|ncat|scp)\b", re.I)


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


def _propose(v: Verdict, os_name: str) -> Remediation:
    cmd = _command(v)
    reason = v.reason.lower()
    bases = _bases(v)

    if "scheduled task" in reason or "T1053" in bases or "schtasks" in cmd.lower():
        name = _schtask_name(cmd)
        if name:
            return Remediation(v, "delete_scheduled_task",
                               f"Delete the scheduled task '{name}' the agent created.",
                               command=f'schtasks /delete /tn "{name}" /f', target=name, manual=False)

    path = _file_target(v)
    if path and (v.alert.event_id == 11 or "wrote" in reason or "file" in v.alert.rule_title.lower()
                 or (v.tool_call and v.tool_call.tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"))):
        stamp = v.alert.timestamp.strftime("%Y%m%d%H%M%S")
        dest = f"{path}.{stamp}.alibi-quarantine"
        mv = "move" if os_name == "windows" else "mv"
        return Remediation(v, "quarantine_file",
                           f"Quarantine the file the agent wrote ({path}) by moving it aside.",
                           command=f'{mv} "{path}" "{dest}"', target=path,
                           reversible=True, manual=False)

    if "files rewritten" in reason:
        return Remediation(v, "restore_files",
                           "Restore the rewritten files from version control (git restore) or a backup.",
                           command="git restore .", reversible=True, manual=False)

    is_cred = bool(_CRED_CMD_RE.search(cmd))
    is_exfil = ("targets host" in reason or "exfiltrat" in reason
                or (bool(_EXFIL_CMD_RE.search(cmd)) and ("http" in cmd.lower() or "--data" in cmd.lower())))
    if (bases & _CRED_EXFIL) or is_cred or is_exfil:
        return Remediation(v, "rotate_credential",
                           "Rotate or revoke any credential the agent could have read or sent. Alibi cannot do this for you.",
                           manual=True)

    return Remediation(v, "manual_review", "No safe automatic reversal; review this action manually.", manual=True)


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
        rem = _propose(v, os_name)
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
