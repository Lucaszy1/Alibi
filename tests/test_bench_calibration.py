"""Item 14: confidence calibration report. The bands cover every case, the weighted accuracy equals
the overall accuracy (consistency), and the report renders as a table. It is a measurement, not a
claim of calibration."""

from pathlib import Path

from alibi.bench import calibration, calibration_report, evaluate, load_corpus

ROOT = Path(__file__).resolve().parent.parent / "benchmark" / "corpus"


def test_calibration_covers_all_cases():
    assert sum(b["n"] for b in calibration(load_corpus(ROOT))) == 25


def test_calibration_weighted_matches_overall_accuracy():
    c = load_corpus(ROOT)
    rows = calibration(c)
    total = sum(b["n"] for b in rows)
    weighted = sum(b["accuracy"] * b["n"] for b in rows) / total
    m, _ = evaluate(c)
    assert abs(weighted - m.accuracy) < 0.02


def test_calibration_report_is_a_table():
    rep = calibration_report(load_corpus(ROOT))
    assert "confidence calibration" in rep.lower() and "mean confidence" in rep
