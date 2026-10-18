"""User-sanctioned allowlist to suppress false positives. Loaded from a trusted config file the
user controls, never from the session, so an attacker cannot allowlist their own target. An
allowlisted host, path, or command downgrades a flag to JUSTIFIED with an explicit note, so work
the user has blessed stops tripping alerts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

MAX_ALLOWLIST_BYTES = 1 * 1024 * 1024


@dataclass(frozen=True)
class Allowlist:
    hosts: frozenset = frozenset()
    paths: frozenset = frozenset()
    commands: frozenset = frozenset()

    @property
    def empty(self) -> bool:
        return not (self.hosts or self.paths or self.commands)

    def match(self, text: str):
        """Return a short rule string if the action text is sanctioned, else None."""
        low = (text or "").lower()
        for h in self.hosts:
            if h in low:
                return f"host {h}"
        for p in self.paths:
            if p in low:
                return f"path {p}"
        for c in self.commands:
            if c in low:
                return f"command {c}"
        return None


def load_allowlist(path) -> Allowlist:
    path = Path(path)
    if path.stat().st_size > MAX_ALLOWLIST_BYTES:
        raise ValueError(f"allowlist too large: {path.stat().st_size} bytes exceeds {MAX_ALLOWLIST_BYTES}")
    hosts, paths, cmds = set(), set(), set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip().lower()
        if not val:
            continue
        if key in ("host", "hosts"):
            hosts.add(val)
        elif key in ("path", "paths"):
            paths.add(val)
        elif key in ("cmd", "command", "commands"):
            cmds.add(val)
    return Allowlist(frozenset(hosts), frozenset(paths), frozenset(cmds))
