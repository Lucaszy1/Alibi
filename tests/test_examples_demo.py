"""The cold-start demo must keep running and must keep catching the hijack."""

import io
import runpy
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_demo_runs_and_flags_the_hijack():
    buf = io.StringIO()
    with redirect_stdout(buf):
        runpy.run_path(str(ROOT / "examples" / "demo.py"), run_name="__main__")
    out = buf.getvalue()
    assert "HIJACKED" in out            # the hijacked session is caught
    assert "telemetry-collect.dev" in out
