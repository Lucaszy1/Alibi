"""The incidents subcommand groups the hijack fixture's flagged alerts into one chain, and reports
none for the defended twin."""

import io
import json
from pathlib import Path

from alibi.cli import main

FIX = Path(__file__).parent / "fixtures"
RESULTS = str(FIX / "hijacked_exfil.results.csv")


def test_incidents_groups_the_hijack_into_one_chain():
    out, err = io.StringIO(), io.StringIO()
    code = main(["incidents", RESULTS, str(FIX / "hijacked_exfil.jsonl"), "--json"], out, err)
    rows = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
    assert code == 1 and len(rows) == 1
    assert rows[0]["hijacked"] is True and len(rows[0]["steps"]) >= 2


def test_incidents_clean_on_defended_session():
    out, err = io.StringIO(), io.StringIO()
    code = main(["incidents", RESULTS, str(FIX / "defended_readonly.jsonl")], out, err)
    assert code == 0 and "no incidents" in err.getvalue()
