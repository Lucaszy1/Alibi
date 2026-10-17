"""The 'does not overlap in time' warning must fire only on a genuine mismatch (gap larger than
the linking window), not when a tool call precedes the alert it caused by a fraction of a second."""

import csv
import io
import json
from datetime import datetime, timedelta, timezone

from alibi.cli import main

BASE = datetime(2026, 10, 16, 18, 0, 0, tzinfo=timezone.utc)


def _csv_ts(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " +00:00"


def _write(tmp_path, call_dt, alert_dt):
    csv_path, tx = tmp_path / "r.csv", tmp_path / "s.jsonl"
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID",
                    "RecordID", "Details", "ExtraFieldInfo", "RuleID"])
        w.writerow([_csv_ts(alert_dt), "Proc Exec", "info", "PC", "Sysmon", "1", "1",
                    "Cmdline: whoami", "-", "r1"])
    recs = [
        {"type": "user", "timestamp": BASE.isoformat(), "cwd": r"C:\proj",
         "message": {"role": "user", "content": "check the environment"}},
        {"type": "assistant", "timestamp": call_dt.isoformat(), "cwd": r"C:\proj",
         "message": {"role": "assistant", "content": [
             {"type": "tool_use", "id": "b1", "name": "Bash", "input": {"command": "whoami"}}]}},
        {"type": "user", "timestamp": (call_dt + timedelta(seconds=1)).isoformat(), "cwd": r"C:\proj",
         "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "b1", "content": "PC\\user"}]}},
    ]
    with open(tx, "w", encoding="utf-8") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    return csv_path, tx


def _scan(csv_path, tx):
    out, err = io.StringIO(), io.StringIO()
    main(["scan", str(csv_path), str(tx)], out, err)
    return err.getvalue()


def test_no_warning_when_call_just_precedes_alert(tmp_path):
    # Call at BASE+5s, alert at BASE+6s: the alert follows the call it caused, well within window.
    csv_path, tx = _write(tmp_path, BASE + timedelta(seconds=5), BASE + timedelta(seconds=6))
    assert "does not overlap" not in _scan(csv_path, tx)


def test_warning_when_transcript_is_far_from_alerts(tmp_path):
    # Call two hours after the alert: genuinely unrelated, should warn.
    csv_path, tx = _write(tmp_path, BASE + timedelta(hours=2), BASE)
    assert "does not overlap" in _scan(csv_path, tx)
