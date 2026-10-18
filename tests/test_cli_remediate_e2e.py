"""End-to-end: main(["remediate", csv, transcript]) through real CSV + transcript parsing.
An unrequested file-write burst yields proposals and exit 1; the same burst asked for is clean."""

import csv
import io
import json
from datetime import UTC, datetime, timedelta

from alibi.cli import main

BASE = datetime(2026, 10, 16, 18, 0, 0, tzinfo=UTC)
CWD = r"C:\victim-repo"


def _csv_ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " +00:00"


def _burst(tmp_path, prompt, n=14):
    csv_path, tx = tmp_path / "results.csv", tmp_path / "s.jsonl"
    rows = []
    recs = [{"type": "user", "timestamp": BASE.isoformat(), "cwd": CWD,
             "message": {"role": "user", "content": prompt}, "origin": {"kind": "human"}}]
    for i in range(n):
        call_ts = BASE + timedelta(seconds=1 + i)
        path = CWD + rf"\src\mod_{i}.py"
        recs.append({"type": "assistant", "timestamp": call_ts.isoformat(), "cwd": CWD,
                     "message": {"role": "assistant", "content": [
                         {"type": "tool_use", "id": f"w{i}", "name": "Write",
                          "input": {"file_path": path, "content": "x = 1\n"}}]}})
        recs.append({"type": "user", "timestamp": (call_ts + timedelta(milliseconds=200)).isoformat(), "cwd": CWD,
                     "message": {"role": "user", "content": [
                         {"type": "tool_result", "tool_use_id": f"w{i}", "content": "File created."}]}})
        rows.append([_csv_ts(call_ts + timedelta(milliseconds=100)), "File Created (Sysmon Alert)", "med",
                     "PC", "Sysmon", "11", str(i), f"TgtFile: {path}", "-", "r"])
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID",
                    "RecordID", "Details", "ExtraFieldInfo", "RuleID"])
        w.writerows(rows)
    with open(tx, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    return csv_path, tx


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, out, err)
    return code, out.getvalue(), err.getvalue()


def test_remediate_subcommand_proposes_on_unrequested_burst(tmp_path):
    csv_path, tx = _burst(tmp_path, "summarize the README for me")
    code, out, err = _run(["remediate", str(csv_path), str(tx)])
    assert code == 1 and "Dry run" in out   # plan produced proposals, dry run listed them


def test_remediate_subcommand_clean_when_requested(tmp_path):
    csv_path, tx = _burst(tmp_path, "refactor and reformat every file in the src module")
    code, out, err = _run(["remediate", str(csv_path), str(tx)])
    assert code == 0 and "nothing flagged" in err   # requested bulk op -> nothing to remediate
