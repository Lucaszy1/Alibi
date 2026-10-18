"""The report builder produces a Markdown incident report with the injected snippet, a provenance
graph, and proposed reversals, and says so plainly when there is nothing to report."""

from pathlib import Path

from alibi.alerts import load_alerts
from alibi.judge import Judge
from alibi.report import build_report
from alibi.transcript import load_transcript

FIX = Path(__file__).parent / "fixtures"


def _verdicts(transcript):
    return Judge(load_transcript(FIX / transcript)).judge_all(load_alerts(FIX / "hijacked_exfil.results.csv"))


def test_report_on_hijack_fixture():
    md = build_report(_verdicts("hijacked_exfil.jsonl"))
    assert "# Alibi incident report" in md
    assert "Incident 1" in md
    assert "telemetry-collect.dev" in md
    assert "mermaid" in md
    assert ("rotate_credential" in md or "block_host" in md)


def test_report_empty_when_clean():
    md = build_report(_verdicts("defended_readonly.jsonl"))
    assert "No incidents" in md
