"""M13 CLI undo: a saved rollback bundle round-trips and `alibi undo` lists it (dry run) or reverts."""

import io

from alibi.cli import main
from alibi.remediate import UndoStep, bundle_to_json, undo_from_json


def test_undo_from_json_roundtrip():
    steps = [UndoStep("unblock_ip", "remove rule", "sudo iptables -D OUTPUT -d 1.2.3.4 -j DROP", False,
                      ("sudo", "iptables", "-D", "OUTPUT", "-d", "1.2.3.4", "-j", "DROP")),
             UndoStep("unblock_host", "manual", None, True, None)]
    back = undo_from_json(bundle_to_json(steps))
    assert len(back) == 2
    assert back[0].argv == ("sudo", "iptables", "-D", "OUTPUT", "-d", "1.2.3.4", "-j", "DROP")
    assert back[1].command is None and back[1].manual


def test_undo_cli_dry_run_lists_steps(tmp_path):
    b = tmp_path / "undo.json"
    b.write_text(bundle_to_json([UndoStep("unblock_ip", "remove rule",
                 "sudo iptables -D OUTPUT -d 1.2.3.4 -j DROP", False, None)]), encoding="utf-8")
    out, err = io.StringIO(), io.StringIO()
    rc = main(["undo", str(b)], out=out, err=err)
    assert rc == 0 and "unblock_ip" in out.getvalue() and "Dry run" in out.getvalue()


def test_undo_cli_missing_bundle_errors():
    out, err = io.StringIO(), io.StringIO()
    rc = main(["undo", "nope-xyz.json"], out=out, err=err)
    assert rc == 2
