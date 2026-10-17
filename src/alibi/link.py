"""Tier 1 of the judge: link an alert to the agent tool call that caused it.

How Claude Code's actions surface in Sysmon/Hayabusa on Windows (observed, not assumed):

- **Bash tool**: ``claude.exe`` spawns
  ``bash.exe -c "source <snapshot> ... && eval '<COMMAND>' < /dev/null && pwd -P >| ...claude-XXXX-cwd"``.
  The real command sits inside ``eval '...'``, with ``'`` escaped as ``'"'"'`` and Windows
  argv escaping (``\\"``) on top. Programs the command runs (``python -c``, pip's build
  subprocesses, ...) appear as their own processes, usually with an unalerted parent.
- **PowerShell tool**: ``cmd.exe /c "chcp 65001 & powershell -Command $env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT ..."``.
  The command travels in an environment variable and never appears on a command line, so
  only time can tie the launcher to a specific call.
- **Write/Edit tools**: ``claude.exe`` writes ``<file_path>.tmp.<pid>.<hex>`` then renames it,
  which trips file-creation / timestomping rules.
- **Harness activity** with no tool call behind it: ``claude.exe``'s own network traffic and
  ``~/.claude.json`` writes, a one-off shell-snapshot setup on the first Bash call, and a
  ``powershell -EncodedCommand`` that parses each PowerShell command for permission checks.

Hayabusa flattens newlines to spaces and doubles ``%``; both are undone before comparing.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Iterable

from alibi.alerts import Alert
from alibi.transcript import Event, ToolCall, ToolResult

DEFAULT_WINDOW_SECONDS = 60.0
# A deferred mechanism (scheduled task, service) can fire long after it is created.
DEFERRED_WINDOW = timedelta(hours=24)
# Records are written slightly before the process starts, and results slightly after it ends.
CLOCK_SKEW = timedelta(seconds=2)
MIN_CONFIDENCE = 0.5

SHELL_TOOLS = frozenset({"Bash", "PowerShell"})
FILE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})

_AGENT_IMAGE_RE = re.compile(r"(^|[\\/])claude(\.exe)?$|[\\/]@anthropic-ai[\\/]claude-code[\\/]", re.I)
_BASH_WRAPPER_RE = re.compile(
    r"&& eval '(?P<cmd>.*)'(?: < /dev/null)? && pwd -P >\| \S*claude-[0-9a-f]+-cwd\s*$", re.S
)
_TMP_WRITE_RE = re.compile(r"\.tmp\.\d+\.[0-9a-f]+$", re.I)
_TOKEN_RE = re.compile(r"[A-Za-z0-9_.\-]+")
_GENERIC_TOKENS = frozenset(
    {"true", "null", "dev", "eval", "echo", "head", "tail", "grep", "print", "import", "from",
     "exe", "bin", "usr", "users", "program", "files", "windows", "system32", "appdata", "local",
     "temp", "programs", "python312", "lib", "site-packages", "import", "return", "none"}
)


class Origin(str, Enum):
    AGENT_ACTION = "AGENT_ACTION"    # caused by a tool call
    AGENT_HARNESS = "AGENT_HARNESS"  # caused by Claude Code itself, not by what it was asked to do
    UNRELATED = "UNRELATED"          # not the agent; Alibi stands aside


@dataclass(frozen=True)
class LinkResult:
    tool_call: ToolCall | None
    match_reason: str
    confidence: float
    origin: Origin = Origin.AGENT_ACTION

    @property
    def is_agent(self) -> bool:
        return self.origin is not Origin.UNRELATED


UNRELATED = LinkResult(None, "no agent tool call matched", 0.0, Origin.UNRELATED)


# ---------------------------------------------------------------------------------------------
# Command-line normalisation


def split_windows_cmdline(cmdline: str) -> list[str]:
    """Split a command line the way CommandLineToArgvW does."""
    args: list[str] = []
    buf: list[str] = []
    in_quotes = False
    have_arg = False
    i, n = 0, len(cmdline)
    while i < n:
        c = cmdline[i]
        if c == "\\":
            j = i
            while j < n and cmdline[j] == "\\":
                j += 1
            count = j - i
            if j < n and cmdline[j] == '"':
                buf.append("\\" * (count // 2))
                if count % 2:
                    buf.append('"')
                    i = j + 1
                else:
                    i = j
            else:
                buf.append("\\" * count)
                i = j
            have_arg = True
            continue
        if c == '"':
            if in_quotes and i + 1 < n and cmdline[i + 1] == '"':
                buf.append('"')  # "" inside quotes is a literal quote
                i += 2
                continue
            in_quotes = not in_quotes
            have_arg = True
        elif c in " \t" and not in_quotes:
            if have_arg:
                args.append("".join(buf))
                buf, have_arg = [], False
        else:
            buf.append(c)
            have_arg = True
        i += 1
    if have_arg:
        args.append("".join(buf))
    return args


def normalize(text: str) -> str:
    """Collapse all whitespace runs to one space (Hayabusa flattens newlines)."""
    return " ".join(text.split())


def _undo_hayabusa(cmdline: str) -> str:
    return cmdline.replace("%%", "%")


def unwrap_bash_wrapper(cmdline: str) -> str | None:
    """The agent's command from a Claude Code ``bash.exe -c "... eval '<cmd>' ..."`` wrapper."""
    argv = split_windows_cmdline(_undo_hayabusa(cmdline))
    if len(argv) < 3 or not re.search(r"bash(\.exe)?$", argv[0], re.I):
        return None
    m = _BASH_WRAPPER_RE.search(argv[-1])
    if not m:
        return None
    return m.group("cmd").replace("'\"'\"'", "'")


def _decode_encoded_command(cmdline: str) -> str | None:
    m = re.search(r"-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{16,})", cmdline, re.I)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1)).decode("utf-16-le", errors="replace")
    except (binascii.Error, ValueError):
        return None


def _harness_kind(cmdline: str) -> str | None:
    """Name of the Claude Code harness activity this command line is, if any."""
    if "shell-snapshots" in cmdline and "SNAPSHOT_FILE=" in cmdline:
        return "shell snapshot setup"
    argv = split_windows_cmdline(cmdline)
    if len(argv) >= 2 and re.search(r"bash(\.exe)?$", argv[0], re.I):
        if argv[1:] == ["-c", "env"] or (argv[1] == "-lc" and argv[2:] == ['echo "$PATH"']):
            return "shell environment probe"
    decoded = _decode_encoded_command(cmdline)
    if decoded and _is_ps_parser(decoded):
        return "PowerShell command parser (permission check)"
    return None


def _is_ps_parser(script: str) -> bool:
    return "Language.Parser]::ParseInput" in script or (
        "function Write-Result($Json)" in script and "$EncodedCommand = [Console]::In.ReadToEnd()" in script
    )


def _strip_image(cmdline: str) -> str:
    """``"C:\\...\\python.exe" -c x`` -> ``python -c x``, to compare against what was typed."""
    cmdline = cmdline.strip()
    if cmdline.startswith('"'):
        end = cmdline.find('"', 1)
        exe, rest = (cmdline[1:end], cmdline[end + 1:]) if end > 0 else (cmdline, "")
    else:
        m = re.match(r"^(.+?\.(?:exe|com|bat|cmd))(?=\s|$)(.*)$", cmdline, re.I | re.S)
        exe, rest = (m.group(1), m.group(2)) if m else (cmdline.split(" ", 1)[0], cmdline[len(cmdline.split(" ", 1)[0]):])
    return _image_name(exe) + rest


def _image_name(image: str | None) -> str:
    if not image:
        return ""
    name = re.split(r"[\\/]", image.strip('"'))[-1].lower()
    return re.sub(r"\.(exe|com|bat|cmd)$", "", name)


def _tokens(text: str) -> set[str]:
    out = set()
    for tok in _TOKEN_RE.findall(text.lower()):
        tok = tok.strip(".-")
        if len(tok) >= 4 and tok not in _GENERIC_TOKENS and not tok.isdigit():
            out.add(tok)
    return out


def _is_agent_image(image: str | None) -> bool:
    return bool(image) and bool(_AGENT_IMAGE_RE.search(image))


def _norm_path(path: str) -> str:
    return path.replace("/", "\\").rstrip("\\").lower()


# ---------------------------------------------------------------------------------------------
# Tool-call spans


@dataclass(frozen=True)
class _Span:
    call: ToolCall
    start: datetime
    end: datetime

    def contains(self, ts: datetime) -> bool:
        return self.start <= ts <= self.end


def _spans(events: Iterable[Event], window_seconds: float) -> list[_Span]:
    """When each tool call could have been running: from the call until its result."""
    events = list(events)
    results = {e.tool_use_id: e for e in events if isinstance(e, ToolResult)}
    window = timedelta(seconds=window_seconds)
    spans = []
    for e in events:
        if not isinstance(e, ToolCall):
            continue
        result = results.get(e.tool_use_id)
        background = bool(e.tool_input.get("run_in_background"))
        if result is None or background:
            end = e.timestamp + window
        else:
            end = result.timestamp
        spans.append(_Span(e, e.timestamp - CLOCK_SKEW, end + CLOCK_SKEW))
    return spans


def _active(spans: list[_Span], ts: datetime, tools: frozenset[str]) -> list[_Span]:
    """Spans of the given tools covering ``ts``, most recently started first."""
    hits = [s for s in spans if s.call.tool_name in tools and s.contains(ts)]
    return sorted(hits, key=lambda s: s.call.timestamp, reverse=True)


# ---------------------------------------------------------------------------------------------
# Scoring


def _score_command(alert_cmd: str, image: str | None, call_cmd: str) -> tuple[float, str]:
    call_norm = normalize(call_cmd)
    if not call_norm:
        return 0.0, ""

    wrapped = unwrap_bash_wrapper(alert_cmd)
    if wrapped is not None:
        if normalize(wrapped) == call_norm:
            return 1.0, "exact command (Claude Code bash wrapper)"
        return 0.0, ""  # a wrapper for some other command

    alert_norm = normalize(_undo_hayabusa(alert_cmd))
    if alert_norm == call_norm:
        return 0.97, "exact command line"
    if len(call_norm) >= 8 and call_norm in alert_norm:
        return 0.9, "agent command contained in alert command line"
    stripped = normalize(_strip_image(alert_norm))
    if len(stripped) >= 8 and stripped in call_norm:
        return 0.9, "alert process command appears inside agent command (child process)"

    alert_tokens = _tokens(stripped)
    shared = alert_tokens & _tokens(call_norm)
    if alert_tokens and len(shared) >= 2:
        frac = len(shared) / len(alert_tokens)
        if frac >= 0.5:
            return 0.5 + 0.35 * frac, f"shares distinctive tokens: {', '.join(sorted(shared)[:5])}"

    name = _image_name(image)
    if name and re.search(rf"(^|[\s;&|(/\\]){re.escape(name)}(\.exe)?(\s|$)", call_norm, re.I):
        return 0.55, f"child process '{name}' named in agent command; matched by time"
    return 0.0, ""


_DEFERRED_CREATORS = (
    ("scheduled task",
     re.compile(r"\bschtasks(?:\.exe)?\b.*?/create\b", re.I),
     re.compile(r"/tr\s+(?P<p>.+?)(?:\s+/(?:sc|mo|tn|st|sd|ed|ru|rp|rl|it|du|et|f|k|z|v1|xml)\b|$)", re.I | re.S)),
    ("service",
     re.compile(r"\bsc(?:\.exe)?\s+create\b", re.I),
     re.compile(r"binpath=\s*(?P<p>.+?)\s*(?:\s[a-z]+=|$)", re.I | re.S)),
    ("service",
     re.compile(r"\bNew-Service\b", re.I),
     re.compile(r"-BinaryPathName\s+(?P<p>.+?)(?:\s+-\w|$)", re.I | re.S)),
    ("scheduled task",
     re.compile(r"\bRegister-ScheduledTask\b", re.I),
     re.compile(r"-(?:Execute|Argument)\s+(?P<p>.+?)(?:\s+-\w|$)", re.I | re.S)),
)


def _deferred_payload(cmd: str) -> tuple[str | None, str | None]:
    """If a command creates a deferred mechanism, return (kind, the payload it embeds)."""
    for kind, creator_re, payload_re in _DEFERRED_CREATORS:
        if creator_re.search(cmd):
            m = payload_re.search(cmd)
            if m:
                return kind, m.group("p").strip().strip("\"'")
    return None, None


def _match_deferred(alert_cmd: str, spans: list[_Span], ts: datetime) -> LinkResult | None:
    """Link an orphan process to a deferred task/service the agent created in a tool call.

    The visible agent action is the creation command; the payload it embedded (e.g. schtasks
    ``/tr``) runs later under the OS scheduler, with no agent ancestry and outside any tool-call
    window. Causation is recovered by matching the orphan command to that embedded payload.
    """
    alert_norm = normalize(_undo_hayabusa(alert_cmd))
    if len(alert_norm) < 6:
        return None
    hit = None
    for span in spans:
        if span.call.tool_name not in SHELL_TOOLS:
            continue
        _, payload = _deferred_payload(str(span.call.tool_input.get("command", "")))
        if not payload:
            continue
        if not (span.call.timestamp - CLOCK_SKEW <= ts <= span.call.timestamp + DEFERRED_WINDOW):
            continue
        if alert_norm in normalize(payload) and (hit is None or span.call.timestamp > hit.timestamp):
            hit = span.call
    if hit is None:
        return None
    return LinkResult(hit, "payload of a scheduled task/service the agent created (deferred execution)", 0.85)


def _alert_path(alert: Alert) -> str | None:
    for key in ("TargetFilename", "Path", "TgtFile"):
        value = alert.fields.get(key)
        if value and value.strip() not in ("-", "n/a"):
            return value.strip()
    return None


def _link_agent_process(alert: Alert, spans: list[_Span]) -> LinkResult:
    """Activity of claude.exe itself: a Write/Edit temp file, or harness traffic."""
    path = _alert_path(alert)
    if path:
        target = _norm_path(_TMP_WRITE_RE.sub("", path))
        for span in _active(spans, alert.timestamp, FILE_TOOLS):
            file_path = span.call.tool_input.get("file_path") or span.call.tool_input.get("notebook_path")
            if file_path and _norm_path(file_path) == target:
                return LinkResult(span.call, f"agent wrote {file_path} ({span.call.tool_name} tool)", 0.95)
    return LinkResult(None, "Claude Code's own activity (API traffic, config writes)", 0.9, Origin.AGENT_HARNESS)


def link_alert(
    alert: Alert, events: list[Event], window_seconds: float = DEFAULT_WINDOW_SECONDS
) -> LinkResult:
    """Link one alert to the tool call that caused it, from command line, path and time.

    A call is only considered while it could have been running: from its timestamp until its
    result arrives, or for ``window_seconds`` when there is no result (or it ran in the
    background). ``link_alerts`` additionally follows process lineage between alerts.
    """
    return _link_direct(alert, _spans(events, window_seconds))


def _link_direct(alert: Alert, spans: list[_Span]) -> LinkResult:
    if _is_agent_image(alert.process_image):
        return _link_agent_process(alert, spans)

    # PowerShell script-block logging (4104) records the text that actually ran: the only
    # place a PowerShell tool call's command is visible, since the launcher hides it.
    script = alert.fields.get("ScriptBlockText") or alert.fields.get("ScriptBlock")
    if script:
        active = _active(spans, alert.timestamp, frozenset({"PowerShell"}))
        if _is_ps_parser(script):
            trigger = active[0].call if active else None
            return LinkResult(trigger, "Claude Code harness: PowerShell command parser (permission check)", 0.9, Origin.AGENT_HARNESS)
        script_norm = normalize(_undo_hayabusa(script))
        for span in active:
            call_norm = normalize(str(span.call.tool_input.get("command", "")))
            if call_norm and (call_norm in script_norm or script_norm in call_norm):
                return LinkResult(span.call, "PowerShell script block matches agent command", 0.95)

    cmd = alert.command_line
    if cmd:
        harness = _harness_kind(_undo_hayabusa(cmd))
        if harness:
            active = _active(spans, alert.timestamp, SHELL_TOOLS)
            trigger = active[0].call if active else None
            return LinkResult(trigger, f"Claude Code harness: {harness}", 0.9, Origin.AGENT_HARNESS)

        if "CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT" in cmd:
            active = _active(spans, alert.timestamp, frozenset({"PowerShell"}))
            if active:
                return LinkResult(
                    active[0].call,
                    "PowerShell tool launcher (command passed via environment); matched by time",
                    0.8,
                )

        best: tuple[float, str, _Span | None] = (0.0, "", None)
        for span in _active(spans, alert.timestamp, SHELL_TOOLS):
            score, reason = _score_command(cmd, alert.process_image, str(span.call.tool_input.get("command", "")))
            if score > best[0]:  # ties go to the most recently started call
                best = (score, reason, span)
        if best[2] is not None and best[0] >= MIN_CONFIDENCE:
            return LinkResult(best[2].call, best[1], round(best[0], 3))

        deferred = _match_deferred(cmd, spans, alert.timestamp)
        if deferred is not None:
            return deferred

        if unwrap_bash_wrapper(cmd) is not None:
            return LinkResult(None, "Claude Code bash wrapper, but no matching tool call in this transcript", 0.9)

    path = _alert_path(alert)
    if path:
        target = _norm_path(path)
        for span in _active(spans, alert.timestamp, SHELL_TOOLS | FILE_TOOLS):
            text = _norm_path(str(span.call.tool_input.get("command") or span.call.tool_input.get("file_path") or ""))
            if len(target) >= 8 and target in text:
                return LinkResult(span.call, f"alert path {path} named in agent {span.call.tool_name} call", 0.8)

    if not cmd:
        name = _image_name(alert.process_image)
        for span in _active(spans, alert.timestamp, SHELL_TOOLS):
            call_norm = normalize(str(span.call.tool_input.get("command", "")))
            if name and re.search(rf"(^|[\s;&|(/\\]){re.escape(name)}(\.exe)?(\s|$)", call_norm, re.I):
                return LinkResult(span.call, f"process '{name}' named in agent command; matched by time", 0.55)

    if _is_agent_image(alert.parent_image):
        active = _active(spans, alert.timestamp, SHELL_TOOLS)
        if active:
            return LinkResult(active[0].call, "spawned directly by the agent process; matched by time", 0.7)
        return LinkResult(None, "spawned directly by the agent process, outside any tool call", 0.7, Origin.AGENT_HARNESS)

    return UNRELATED


# ---------------------------------------------------------------------------------------------
# Batch linking with process lineage


def _process_key(guid: str | None, pid: int | None) -> str | None:
    if guid:
        return f"guid:{guid.upper()}"
    if pid is not None:
        return f"pid:{pid}"
    return None


def link_alerts(
    alerts: list[Alert], events: list[Event], window_seconds: float = DEFAULT_WINDOW_SECONDS
) -> list[LinkResult]:
    """Link every alert; also inherit links through Sysmon process lineage between alerts.

    A process already linked to a tool call passes that link on to its later events (same
    process GUID) and to its children (parent GUID). PIDs stand in when GUIDs are missing, but
    only within ``window_seconds``, since PIDs are reused.
    """
    spans = _spans(events, window_seconds)
    window = timedelta(seconds=window_seconds)
    results = [_link_direct(a, spans) for a in alerts]

    order = sorted(range(len(alerts)), key=lambda i: alerts[i].timestamp)
    for _ in range(2):  # a second pass catches parents logged after their children
        known: dict[str, tuple[LinkResult, datetime]] = {}
        for i in order:
            a, r = alerts[i], results[i]
            key = _process_key(a.process_guid, a.pid)
            if r.tool_call is not None and key and not _is_agent_image(a.process_image):
                prev = known.get(key)
                if prev is None or r.confidence > prev[0].confidence:
                    known[key] = (r, a.timestamp)
        for i in order:
            a, r = alerts[i], results[i]
            for key, relation, factor in (
                (_process_key(a.process_guid, a.pid), "same process as", 0.95),
                (_process_key(a.parent_process_guid, a.parent_pid), "child of", 0.9),
            ):
                hit = known.get(key) if key else None
                if hit is None:
                    continue
                parent, seen_at = hit
                if key.startswith("pid:") and abs(a.timestamp - seen_at) > window:
                    continue
                inherited = round(parent.confidence * factor, 3)
                if inherited > r.confidence or (r.origin is Origin.UNRELATED and inherited >= MIN_CONFIDENCE):
                    r = LinkResult(
                        parent.tool_call,
                        f"{relation} a process linked by: {parent.match_reason}",
                        inherited,
                        parent.origin,
                    )
            results[i] = r
    return results
