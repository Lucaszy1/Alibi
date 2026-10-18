"""Pin source classification: only agent-side action tools are TRUSTED; every external-content vector
(Read, Bash, WebFetch/WebSearch, Glob/Grep, subagent Task, any mcp__* connector, and anything unknown)
stays UNTRUSTED by default. This is a guardrail test — it fails loudly if a future edit promotes an
injection vector into the trusted set, which would silently collapse the provenance model."""

import pytest

from alibi.transcript import SourceKind, classify_source

TRUSTED = [
    "Write", "Edit", "MultiEdit", "NotebookEdit", "TodoWrite",
    "AskUserQuestion", "EnterPlanMode", "ExitPlanMode", "ScheduleWakeup", "ToolSearch",
]

UNTRUSTED = [
    "Read", "Bash", "WebFetch", "WebSearch", "Glob", "Grep",
    "Task", "Agent", "SlashCommand",
    "mcp__github__get_issue", "mcp__slack__read_messages", "mcp__gmail__get_message",
    "SomeBrandNewToolWeHaveNeverSeen", "", "read", "WEBFETCH",
]


@pytest.mark.parametrize("name", TRUSTED)
def test_agent_action_tools_are_trusted(name):
    assert classify_source(name) is SourceKind.TRUSTED


@pytest.mark.parametrize("name", UNTRUSTED)
def test_external_and_unknown_tools_are_untrusted(name):
    assert classify_source(name) is SourceKind.UNTRUSTED
