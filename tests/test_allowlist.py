"""The allowlist loads from a trusted config and matches sanctioned hosts, paths and commands."""

from alibi.allowlist import Allowlist, load_allowlist


def test_load_parses_sections_and_ignores_comments(tmp_path):
    p = tmp_path / "allow.txt"
    p.write_text("# sanctioned by the user\nhost: telemetry.internal\npath: C:\\build\ncmd: pytest\n\n", encoding="utf-8")
    a = load_allowlist(p)
    assert "telemetry.internal" in a.hosts and "c:\\build" in a.paths and "pytest" in a.commands
    assert not a.empty


def test_match_host_path_and_command():
    a = Allowlist(hosts=frozenset({"telemetry.internal"}), paths=frozenset({r"c:\build"}), commands=frozenset({"pytest"}))
    assert a.match("curl http://telemetry.internal/x").startswith("host")
    assert a.match(r"del C:\build\tmp").startswith("path")
    assert a.match("pytest -q").startswith("command")
    assert a.match("curl http://evil.example/x") is None


def test_empty_allowlist_matches_nothing():
    assert Allowlist().empty and Allowlist().match("anything") is None
