import pytest

from alibi.judge import _CATS_BY_NAME, PolicyLevel, effective_level
from alibi.policy import load_policy


def _write(tmp_path, text):
    f = tmp_path / "policy.yaml"
    f.write_text(text, encoding="utf-8")
    return f


def test_load_levels_and_allow(tmp_path):
    f = _write(tmp_path, "categories:\n  collection: off\n  persistence: escalate\n"
                         "allow:\n  hosts: [updates.vendor.com]\n  paths: ['C:/Corp/*']\n")
    pol = load_policy(f)
    assert pol.levels["collection / capture"] is None
    assert pol.levels["persistence"] is PolicyLevel.ESCALATE
    assert "updates.vendor.com" in pol.allowlist.hosts
    assert "c:/corp/*" in pol.allowlist.paths


def test_unknown_category_rejected(tmp_path):
    with pytest.raises(ValueError):
        load_policy(_write(tmp_path, "categories:\n  banana: strict\n"))


def test_unknown_level_rejected(tmp_path):
    with pytest.raises(ValueError):
        load_policy(_write(tmp_path, "categories:\n  exfiltration: maybe\n"))


def test_effective_level_applies_overrides(tmp_path):
    pol = load_policy(_write(tmp_path, "categories:\n  exfiltration: escalate\n  collection: off\n"))
    assert effective_level(pol, _CATS_BY_NAME["exfiltration"]) is PolicyLevel.ESCALATE
    assert effective_level(pol, _CATS_BY_NAME["collection / capture"]) is None
    assert effective_level(pol, _CATS_BY_NAME["persistence"]) is PolicyLevel.STRICT
    assert effective_level(None, _CATS_BY_NAME["exfiltration"]) is PolicyLevel.STRICT


def test_empty_policy(tmp_path):
    pol = load_policy(_write(tmp_path, "# nothing here\n"))
    assert pol.empty
