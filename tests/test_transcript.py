"""Parse real Claude Code transcripts from the local ~/.claude/projects folder."""

from pathlib import Path

import pytest

from alibi.transcript import (
    SourceKind,
    ToolCall,
    ToolResult,
    UserPrompt,
    events_before,
    last_prompt_before,
    load_transcript,
)

PROJECTS_DIR = Path.home() / ".claude" / "projects"


def _real_transcripts() -> list[Path]:
    if not PROJECTS_DIR.is_dir():
        return []
    return sorted(PROJECTS_DIR.glob("*/*.jsonl"), key=lambda p: p.stat().st_size, reverse=True)


@pytest.fixture(scope="module")
def events():
    transcripts = _real_transcripts()
    if not transcripts:
        pytest.skip(f"no transcripts under {PROJECTS_DIR}")
    return load_transcript(transcripts[0])


def test_produces_events_of_each_kind(events):
    assert events
    assert any(isinstance(e, UserPrompt) for e in events)
    assert any(isinstance(e, ToolCall) for e in events)
    assert any(isinstance(e, ToolResult) for e in events)


def test_events_are_sorted(events):
    stamps = [e.timestamp for e in events]
    assert stamps == sorted(stamps)


def test_results_match_earlier_calls(events):
    calls = {e.tool_use_id: e for e in events if isinstance(e, ToolCall)}
    for result in (e for e in events if isinstance(e, ToolResult)):
        call = calls.get(result.tool_use_id)
        assert call is not None, result.tool_use_id
        assert call.timestamp <= result.timestamp
        assert isinstance(result.source_kind, SourceKind)


def test_prompts_are_text(events):
    for prompt in (e for e in events if isinstance(e, UserPrompt)):
        assert isinstance(prompt.text, str) and prompt.text.strip()


def test_last_prompt_before_a_tool_call(events):
    first_call = next(e for e in events if isinstance(e, ToolCall))
    prompt = last_prompt_before(events, first_call.timestamp)
    assert prompt is not None
    assert prompt.timestamp < first_call.timestamp

    preceding = events_before(events, first_call.timestamp, limit=3)
    assert 0 < len(preceding) <= 3
    assert all(e.timestamp < first_call.timestamp for e in preceding)
