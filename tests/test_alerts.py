"""Parse the real Hayabusa results CSV."""

from pathlib import Path

import pytest

from alibi.alerts import Alert, load_alerts, parse_packed_fields

RESULTS_CSV = Path(r"C:\Tools\Hayabusa\results.csv")


@pytest.fixture(scope="module")
def alerts() -> list[Alert]:
    if not RESULTS_CSV.is_file():
        pytest.skip(f"{RESULTS_CSV} not found")
    return load_alerts(RESULTS_CSV)


def test_produces_alerts(alerts):
    assert alerts
    for a in alerts:
        assert a.rule_title and a.level and a.computer and a.rule_id


def test_sorted_by_timestamp(alerts):
    stamps = [a.timestamp for a in alerts]
    assert all(s.tzinfo is not None for s in stamps)
    assert stamps == sorted(stamps)


def test_command_lines_populated(alerts):
    with_cmd = [a for a in alerts if a.command_line]
    assert with_cmd
    for a in with_cmd:
        # A process-creation alert carries the full process lineage.
        assert a.process_image
        assert a.pid is not None
        assert a.parent_pid is not None
        assert a.parent_command_line
        assert a.parent_image


def test_mitre_tags_resolved_from_rules(alerts):
    assert any(a.mitre_tactics for a in alerts)
    for a in alerts:
        assert all(t.startswith("T") for t in a.mitre_techniques), a.mitre_techniques
        assert not any(t[0].isdigit() for t in a.mitre_tactics), a.mitre_tactics


def test_parse_packed_fields_keeps_separator_inside_values():
    sep = " \u00a6 "
    parsed = parse_packed_fields(f"Cmdline: echo a{sep}b{sep}PID: 42{sep}LGUID:")
    assert parsed == {"Cmdline": f"echo a{sep}b", "PID": "42", "LGUID": ""}
