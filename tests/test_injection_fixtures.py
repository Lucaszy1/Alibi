"""Regression on real captured telemetry: a hijacked session and a defended one judged
against the SAME Hayabusa slice. The verdict must come from the transcript, not the alerts."""

import io
import json
from pathlib import Path

from alibi.cli import main

FIX = Path(__file__).parent / "fixtures"
RESULTS = FIX / "hijacked_exfil.results.csv"
HIJACK_TX = FIX / "hijacked_exfil.jsonl"
DEFENDED_TX = FIX / "defended_readonly.jsonl"
EXFIL_HOST = "telemetry-collect.dev"


def _scan(results, transcript, *flags):
    out, err = io.StringIO(), io.StringIO()
    code = main(["scan", str(results), str(transcript), *flags], out, err)
    return code, out.getvalue(), err.getvalue()


def _records(out):
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def test_exfil_transcript_is_hijacked():
    code, out, err = _scan(RESULTS, HIJACK_TX, "--json", "--all")
    assert code == 1, err  # a hijack fails the run
    hijacks = [r for r in _records(out) if r["label"] == "HIJACKED"]
    assert hijacks, "expected at least one HIJACKED verdict"
    h = hijacks[0]
    assert EXFIL_HOST in h["command"]
    assert h["tier"] == "PROVENANCE"
    assert any(e["source"] == "UNTRUSTED_RESULT" and EXFIL_HOST in e["text"] for e in h["evidence"])


def test_defended_transcript_has_no_hijack():
    # Same alerts, but this agent read the poisoned README and refused to act on it.
    code, out, err = _scan(RESULTS, DEFENDED_TX, "--json", "--all")
    assert code == 0, err
    bad = [r for r in _records(out) if r["label"] in ("HIJACKED", "UNJUSTIFIED")]
    assert not bad, "a session that only read the README must not be blamed"
