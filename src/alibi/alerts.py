"""Parsing of endpoint-security alerts from a Hayabusa results CSV.

Hayabusa's standard output profile has these columns:

    Timestamp, RuleTitle, Level, Computer, Channel, EventID, RecordID,
    Details, ExtraFieldInfo, RuleID

``Details`` and ``ExtraFieldInfo`` pack ``Key: value`` pairs separated by `` ¦ ``. Key names
are Hayabusa's abbreviations and vary by rule, e.g. ``Proc``/``Cmdline``/``PID``/``ParentPID``
for process creation, ``SrcProc``/``SrcPID`` for process injection, ``ProcessId`` (in
ExtraFieldInfo) for logon events. Hayabusa flattens newlines in values to spaces, so a
multi-line command appears on one line.

The standard profile has no MITRE columns. The verbose profiles add ``MitreTactics`` and
``MitreTags``; when those are absent, tags are read from the rule YAML whose ``id`` matches
``RuleID`` in the Hayabusa ``rules/`` directory.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import yaml

FIELD_SEPARATOR = " ¦ "
_KEY_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]*): ?(.*)$", re.S)
_RULE_ID_RE = re.compile(r"^id:\s*['\"]?([0-9a-fA-F-]{36})", re.M)
# Some shipped rules omit the "t" (e.g. "attack.1136.001"), so it is optional here.
_TECHNIQUE_RE = re.compile(r"^attack\.t?(\d{4}(?:\.\d{3})?)$", re.I)
# ATT&CK software (S####) and group (G####) ids are neither tactics nor techniques.
_SOFTWARE_OR_GROUP_RE = re.compile(r"^attack\.[sg]\d{4}$", re.I)
_EMPTY = {"", "-", "n/a", "N/A", "<unknown process>"}

# Hayabusa's abbreviations, in order of preference. The acting process comes first; for
# injection events that is the source process, not the target.
_IMAGE_KEYS = ("Proc", "SrcProc", "Image", "CallingProcess")
_CMDLINE_KEYS = ("Cmdline", "CommandLine")
_PID_KEYS = ("PID", "SrcPID", "ProcessId")
_PGUID_KEYS = ("PGUID", "SrcPGUID", "ProcessGuid")
_PARENT_IMAGE_KEYS = ("ParentImage", "ParentProc")
_PARENT_CMDLINE_KEYS = ("ParentCmdline", "ParentCommandLine")
_PARENT_PID_KEYS = ("ParentPID", "ParentProcessId")
_PARENT_PGUID_KEYS = ("ParentPGUID", "ParentProcessGuid")
_USER_KEYS = ("User", "SrcUser", "SubjectUserName")


@dataclass(frozen=True)
class Alert:
    timestamp: datetime
    rule_title: str
    level: str
    computer: str
    channel: str
    event_id: int | None
    record_id: str
    rule_id: str
    mitre_tactics: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()
    other_tags: tuple[str, ...] = ()
    process_image: str | None = None
    command_line: str | None = None
    pid: int | None = None
    process_guid: str | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    parent_pid: int | None = None
    parent_process_guid: str | None = None
    user: str | None = None
    # Every Key: value pair from Details and ExtraFieldInfo (Details wins on collision).
    fields: dict[str, str] = field(default_factory=dict, hash=False, compare=False)


def parse_packed_fields(text: str) -> dict[str, str]:
    """Split a Details / ExtraFieldInfo cell into its ``Key: value`` pairs.

    A fragment that doesn't start with ``Key:`` is treated as a continuation of the previous
    value (a value that itself contained the separator).
    """
    out: dict[str, str] = {}
    last_key = None
    if not text or text.strip() in _EMPTY:
        return out
    for part in text.split(FIELD_SEPARATOR):
        m = _KEY_RE.match(part)
        if m:
            last_key = m.group(1)
            out[last_key] = m.group(2).strip()
        elif last_key is not None:
            out[last_key] += FIELD_SEPARATOR + part
    return out


def _first(fields: dict[str, str], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = fields.get(key)
        if value is not None and value.strip() not in _EMPTY:
            return value.strip()
    return None


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 0)  # accepts decimal and 0x-prefixed hex
    except ValueError:
        return None


def image_from_command_line(cmdline: str | None) -> str | None:
    """Best-effort executable path from a command line (quoted, or up to the first space)."""
    if not cmdline:
        return None
    cmdline = cmdline.strip()
    if cmdline.startswith('"'):
        end = cmdline.find('"', 1)
        return cmdline[1:end] if end > 1 else None
    m = re.match(r"^(.+?\.(?:exe|com|bat|cmd))(?=\s|$)", cmdline, re.I)
    return m.group(1) if m else cmdline.split(" ", 1)[0]


def _parse_timestamp(value: str) -> datetime:
    value = value.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f %z", "%Y-%m-%d %H:%M:%S %z"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    # e.g. ISO 8601 output from Hayabusa's --ISO-8601 / --UTC options.
    return datetime.fromisoformat(value)


def _split_tags(tags: list[str]) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    tactics, techniques, other = [], [], []
    for tag in tags:
        tag = str(tag).strip()
        if not tag:
            continue
        technique = _TECHNIQUE_RE.match(tag)
        if technique:
            techniques.append("T" + technique.group(1))
        elif tag.lower().startswith("attack.") and not _SOFTWARE_OR_GROUP_RE.match(tag):
            tactics.append(tag[len("attack."):].lower())
        else:
            other.append(tag)
    return tuple(tactics), tuple(techniques), tuple(other)


def _split_column_tags(value: str | None) -> list[str]:
    """Verbose-profile tag columns: abbreviated values separated by `` ¦ ``."""
    if not value or value.strip() in _EMPTY:
        return []
    return [v.strip() for v in value.split(FIELD_SEPARATOR) if v.strip() not in _EMPTY]


def load_rule_tags(rules_dir: str | Path, rule_ids: set[str]) -> dict[str, list[str]]:
    """Map rule id -> ``tags`` list for the given ids, read from Hayabusa/Sigma rule YAMLs.

    Each file's id is found with a cheap regex first; only matching files are YAML-parsed.
    """
    wanted = {r.lower() for r in rule_ids}
    out: dict[str, list[str]] = {}
    for path in Path(rules_dir).rglob("*.yml"):
        if len(out) == len(wanted):
            break
        text = path.read_text(encoding="utf-8", errors="replace")
        m = _RULE_ID_RE.search(text)
        if not m or m.group(1).lower() not in wanted:
            continue
        for doc in yaml.safe_load_all(text):
            if isinstance(doc, dict) and str(doc.get("id", "")).lower() == m.group(1).lower():
                out[m.group(1).lower()] = list(doc.get("tags") or [])
                break
    return out


def _iter_json_records(text: str):
    if text.lstrip()[:1] == "[":
        return [r for r in json.loads(text) if isinstance(r, dict)]
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def _parse_ts_any(value):
    s = str(value).strip()
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return _parse_timestamp(s)


# Field-name aliases so a neutral feed, Elastic ECS, or Splunk all map onto the same Alert. Nested
# vendor keys (process.command_line, host.name, event.code) are reached by flattening to dotted keys.
_NEUTRAL_ALIASES = {
    "timestamp": ("timestamp", "ts", "@timestamp", "_time"),
    "rule_title": ("rule", "rule_title", "rule.name", "signal.rule.name", "search_name"),
    "level": ("level", "severity", "event.severity"),
    "computer": ("computer", "host", "host.name", "hostname", "ComputerName", "winlog.computer_name"),
    "channel": ("channel", "winlog.channel", "log.file.path", "source"),
    "event_id": ("event_id", "event.code", "EventCode", "winlog.event_id"),
    "record_id": ("record_id", "id", "event.id", "RecordID"),
    "rule_id": ("rule_id", "rule.id", "signal.rule.id"),
    "command_line": ("command", "command_line", "process.command_line", "CommandLine", "process.args"),
    "process_image": ("process", "process_image", "process.executable", "process.name", "Image", "NewProcessName"),
}


def _flatten(record: dict, prefix: str = "", out: dict | None = None) -> dict:
    out = {} if out is None else out
    for k, v in record.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            _flatten(v, key + ".", out)
        elif key not in out:
            out[key] = v
    return out


def _pick(flat: dict, keys):
    for k in keys:
        v = flat.get(k)
        if v not in (None, ""):
            return v
    return None


def _vendor_techniques(record: dict, flat: dict):
    for key in ("techniques", "mitre", "mitre_techniques", "threat.technique.id"):
        v = flat.get(key)
        if v:
            return v
    threat = record.get("threat")
    if isinstance(threat, dict):
        t = threat.get("technique")
        if isinstance(t, list):
            return [str(x.get("id")) for x in t if isinstance(x, dict) and x.get("id")]
        if isinstance(t, dict) and t.get("id"):
            return t["id"]
    return ()


def _load_neutral_alerts(records) -> list:
    """Parse a neutral JSON/JSONL alert feed, including Elastic ECS and Splunk field names, so any
    SIEM or EDR that emits JSON can feed Alibi. Binary EVTX and osquery epoch feeds still need a
    format-specific adapter (see KNOWN_LIMITATIONS)."""
    alerts = []
    for r in records:
        if not isinstance(r, dict):
            continue
        flat = _flatten(r)
        ts = _pick(flat, _NEUTRAL_ALIASES["timestamp"])
        if not ts:
            continue
        techs = _vendor_techniques(r, flat)
        if isinstance(techs, str):
            techs = [t.strip() for t in techs.split(",") if t.strip()]
        techs = tuple(str(t) for t in techs) if isinstance(techs, (list, tuple)) else ()
        raw_fields = r.get("fields")
        fields = {str(k): str(v) for k, v in raw_fields.items()} if isinstance(raw_fields, dict) else {}
        eid = _pick(flat, _NEUTRAL_ALIASES["event_id"])
        cmd = _pick(flat, _NEUTRAL_ALIASES["command_line"])
        if isinstance(cmd, list):
            cmd = " ".join(str(x) for x in cmd)
        proc = _pick(flat, _NEUTRAL_ALIASES["process_image"])
        alerts.append(Alert(
            timestamp=_parse_ts_any(ts),
            rule_title=str(_pick(flat, _NEUTRAL_ALIASES["rule_title"]) or "").strip(),
            level=str(_pick(flat, _NEUTRAL_ALIASES["level"]) or "info").strip(),
            computer=str(_pick(flat, _NEUTRAL_ALIASES["computer"]) or "").strip(),
            channel=str(_pick(flat, _NEUTRAL_ALIASES["channel"]) or "").strip(),
            event_id=_to_int(str(eid)) if eid is not None else None,
            record_id=str(_pick(flat, _NEUTRAL_ALIASES["record_id"]) or "").strip(),
            rule_id=str(_pick(flat, _NEUTRAL_ALIASES["rule_id"]) or "").strip(),
            mitre_techniques=techs,
            command_line=str(cmd) if cmd else None,
            process_image=str(proc) if proc else None,
            fields=fields,
        ))
    alerts.sort(key=lambda a: a.timestamp)
    return alerts


def _build_alert(row: dict[str, str], rule_tags: dict[str, list[str]]) -> Alert:
    extra = parse_packed_fields(row.get("ExtraFieldInfo", ""))
    details = parse_packed_fields(row.get("Details", ""))
    fields = {**extra, **details}

    rule_id = (row.get("RuleID") or "").strip()
    if "MitreTactics" in row or "MitreTags" in row:
        tactics = tuple(_split_column_tags(row.get("MitreTactics")))
        techniques = tuple(_split_column_tags(row.get("MitreTags")))
        other = tuple(_split_column_tags(row.get("OtherTags")))
    else:
        tactics, techniques, other = _split_tags(rule_tags.get(rule_id.lower(), []))

    parent_cmdline = _first(fields, _PARENT_CMDLINE_KEYS)
    return Alert(
        timestamp=_parse_timestamp(row["Timestamp"]),
        rule_title=row.get("RuleTitle", "").strip(),
        level=row.get("Level", "").strip(),
        computer=row.get("Computer", "").strip(),
        channel=row.get("Channel", "").strip(),
        event_id=_to_int(row.get("EventID")),
        record_id=(row.get("RecordID") or "").strip(),
        rule_id=rule_id,
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        other_tags=other,
        process_image=_first(fields, _IMAGE_KEYS),
        command_line=_first(fields, _CMDLINE_KEYS),
        pid=_to_int(_first(fields, _PID_KEYS)),
        process_guid=_first(fields, _PGUID_KEYS),
        # ParentImage is often missing; the parent command line usually names the binary.
        parent_image=_first(fields, _PARENT_IMAGE_KEYS) or image_from_command_line(parent_cmdline),
        parent_command_line=parent_cmdline,
        parent_pid=_to_int(_first(fields, _PARENT_PID_KEYS)),
        parent_process_guid=_first(fields, _PARENT_PGUID_KEYS),
        user=_first(fields, _USER_KEYS),
        fields=fields,
    )


MAX_ALERTS_BYTES = 200 * 1024 * 1024


def load_alerts(path: str | Path, rules_dir: str | Path | None = None) -> list[Alert]:
    """Parse a Hayabusa results CSV into Alerts sorted by timestamp.

    ``rules_dir`` is used to look up MITRE tags when the CSV has no tag columns; it defaults
    to a ``rules`` directory next to the CSV, if one exists.
    """
    path = Path(path)
    if path.stat().st_size > MAX_ALERTS_BYTES:
        raise ValueError(f"alerts CSV too large: {path.stat().st_size} bytes exceeds {MAX_ALERTS_BYTES}")
    # utf-8-sig: Hayabusa may write a BOM.
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() in (".json", ".jsonl") or text.lstrip()[:1] in ("[", "{"):
        return _load_neutral_alerts(_iter_json_records(text))
    rows = list(csv.DictReader(io.StringIO(text)))

    rule_tags: dict[str, list[str]] = {}
    has_tag_columns = bool(rows) and ("MitreTactics" in rows[0] or "MitreTags" in rows[0])
    if not has_tag_columns:
        rules_dir = Path(rules_dir) if rules_dir else path.parent / "rules"
        if rules_dir.is_dir():
            rule_tags = load_rule_tags(rules_dir, {r["RuleID"].strip() for r in rows if r.get("RuleID")})

    alerts = [_build_alert(row, rule_tags) for row in rows]
    alerts.sort(key=lambda a: a.timestamp)
    return alerts
