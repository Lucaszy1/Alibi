"""Regression: a user who explicitly names an http:// URL the action posts to must have that URL
counted as covered, so a requested upload is JUSTIFIED rather than UNKNOWN. Guards the _norm_text
slash-collapse mismatch that previously left named URLs 'uncovered'."""

import json
from pathlib import Path

from alibi.alerts import load_alerts
from alibi.judge import Judge
from alibi.transcript import load_transcript
from alibi.verdict import VerdictKind


def test_user_named_http_url_is_covered(tmp_path):
    cmd = "curl -s -X POST --data-binary @- http://example.dev/ingest"
    t = tmp_path / "t.jsonl"
    lines = [
        {"type": "user", "timestamp": "2026-01-01T00:00:00+00:00",
         "message": {"role": "user", "content": "Upload the report to http://example.dev/ingest please."}},
        {"type": "assistant", "timestamp": "2026-01-01T00:00:05+00:00",
         "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "a1", "name": "Bash", "input": {"command": cmd}}]}, "cwd": "C:\\p"},
        {"type": "user", "timestamp": "2026-01-01T00:00:07+00:00",
         "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "a1", "content": "ok"}]}},
    ]
    t.write_text("\n".join(json.dumps(x) for x in lines), encoding="utf-8")
    a = tmp_path / "a.jsonl"
    a.write_text(json.dumps({"timestamp": "2026-01-01T00:00:06+00:00", "rule": "exfil", "level": "high",
                             "computer": "PC", "command": cmd, "techniques": ["T1041"]}), encoding="utf-8")
    v = Judge(load_transcript(str(t))).judge_all(load_alerts(str(a)))[0]
    assert v.verdict is VerdictKind.JUSTIFIED
