"""The report subcommand prints a Markdown incident report for a hijack and nothing to report for a
clean session."""

import io
from pathlib import Path

from alibi.cli import main

FIX = Path(__file__).parent / "fixtures"
RESULTS = str(FIX / "hijacked_exfil.results.csv")


def test_cli_report_on_hijack():
    out, err = io.StringIO(), io.StringIO()
    code = main(["report", RESULTS, str(FIX / "hijacked_exfil.jsonl")], out, err)
    text = out.getvalue()
    assert code == 1 and "Incident 1" in text and "telemetry-collect.dev" in text and "mermaid" in text


def test_cli_report_clean():
    out, err = io.StringIO(), io.StringIO()
    code = main(["report", RESULTS, str(FIX / "defended_readonly.jsonl")], out, err)
    assert code == 0 and "No incidents" in out.getvalue()
