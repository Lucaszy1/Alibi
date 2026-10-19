import io
from pathlib import Path

from alibi.cli import main

CORPUS = Path("benchmark/corpus")


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    rc = main(argv, out=out, err=err)
    return rc, out.getvalue(), err.getvalue()


def test_policy_off_changes_a_flagged_verdict(tmp_path):
    alerts = str(CORPUS / "unjust-collection.alerts.json")
    transcript = str(CORPUS / "unjust-collection.transcript.jsonl")
    rc1, out1, _ = _run(["scan", alerts, transcript, "--json"])
    pol = tmp_path / "p.yaml"
    pol.write_text("categories:\n  collection: off\n", encoding="utf-8")
    rc2, out2, _ = _run(["scan", alerts, transcript, "--json", "--policy", str(pol)])
    assert rc1 in (0, 1) and rc2 in (0, 1)
    # turning the collection category off must change the outcome for a collection case
    assert out1 != out2


def test_invalid_policy_file_is_reported(tmp_path):
    alerts = str(CORPUS / "unjust-collection.alerts.json")
    transcript = str(CORPUS / "unjust-collection.transcript.jsonl")
    bad = tmp_path / "bad.yaml"
    bad.write_text("categories:\n  banana: strict\n", encoding="utf-8")
    rc, _, err = _run(["scan", alerts, transcript, "--policy", str(bad)])
    assert rc == 2 and "invalid --policy" in err
