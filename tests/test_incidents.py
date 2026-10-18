"""Correlation groups a same-host burst of flagged verdicts into one incident, and keeps separate
intrusions, distant-in-time flags, and clean verdicts apart."""

from datetime import UTC, datetime, timedelta

from alibi.alerts import Alert
from alibi.incidents import correlate
from alibi.link import LinkResult
from alibi.transcript import ToolCall
from alibi.verdict import Disposition, Tier, Verdict, VerdictKind

T = datetime(2026, 1, 1, tzinfo=UTC)


def _v(kind, secs, computer="PC-1", techniques=()):
    ts = T + timedelta(seconds=secs)
    call = ToolCall(ts, "t", "Bash", {"command": "x"}, r"C:\p")
    link = LinkResult(call, "linked", 0.9)
    alert = Alert(timestamp=ts, rule_title="r", level="high", computer=computer, channel="Sysmon",
                  event_id=1, record_id=str(secs), rule_id="r", mitre_techniques=techniques, command_line="x")
    return Verdict(alert, link, Disposition.VERDICT, kind, 0.8, "reason", Tier.PROVENANCE, (), techniques)


def test_burst_on_one_host_is_one_incident():
    vs = [_v(VerdictKind.HIJACKED, 0, techniques=("T1114",)),
          _v(VerdictKind.HIJACKED, 3, techniques=("T1041",)),
          _v(VerdictKind.UNJUSTIFIED, 5)]
    inc = correlate(vs)
    assert len(inc) == 1 and len(inc[0].verdicts) == 3
    assert inc[0].hijacked and "T1114" in inc[0].techniques and "T1041" in inc[0].techniques


def test_far_apart_flags_are_separate_incidents():
    assert len(correlate([_v(VerdictKind.HIJACKED, 0), _v(VerdictKind.HIJACKED, 600)])) == 2


def test_different_hosts_never_merge():
    vs = [_v(VerdictKind.HIJACKED, 0, computer="PC-1"), _v(VerdictKind.HIJACKED, 2, computer="PC-2")]
    assert len(correlate(vs)) == 2


def test_clean_verdicts_are_excluded():
    inc = correlate([_v(VerdictKind.JUSTIFIED, 0), _v(VerdictKind.HIJACKED, 1)])
    assert len(inc) == 1 and len(inc[0].verdicts) == 1 and inc[0].verdicts[0].verdict is VerdictKind.HIJACKED
