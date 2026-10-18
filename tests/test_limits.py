"""Ingestion refuses an oversized transcript or alert file instead of exhausting memory."""

import pytest

import alibi.alerts as al
import alibi.transcript as tr


def test_oversized_transcript_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(tr, "MAX_TRANSCRIPT_BYTES", 20)
    p = tmp_path / "s.jsonl"
    p.write_text('{"type":"user","timestamp":"2026-01-01T00:00:00Z","message":{"role":"user","content":"hello there"}}\n', encoding="utf-8")
    with pytest.raises(ValueError):
        tr.load_transcript(p)


def test_oversized_alerts_csv_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(al, "MAX_ALERTS_BYTES", 20)
    p = tmp_path / "r.csv"
    p.write_text("Timestamp,RuleTitle,Level,Computer,Channel,EventID,RecordID,Details,ExtraFieldInfo,RuleID\n" + "x" * 80, encoding="utf-8")
    with pytest.raises(ValueError):
        al.load_alerts(p)
