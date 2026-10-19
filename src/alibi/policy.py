"""Policy configuration: a user-controlled file that tunes which action categories Alibi treats as
strict or escalate, and which it ignores, plus the allowlist. Loaded from a trusted file the user
controls (never from the session), so an attacker cannot relax policy on their own target. YAML, so
it adds no dependency Alibi does not already use."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .allowlist import Allowlist
from .judge import PolicyLevel

MAX_POLICY_BYTES = 1 * 1024 * 1024

# Friendly config keys -> Alibi's internal category names.
_KEY_TO_NAME = {
    "exfiltration": "exfiltration",
    "destruction": "data destruction / impact",
    "data_destruction": "data destruction / impact",
    "impact": "data destruction / impact",
    "persistence": "persistence",
    "credential_access": "credential access",
    "credentials": "credential access",
    "defense_evasion": "defense impairment",
    "defense_impairment": "defense impairment",
    "collection": "collection / capture",
    "capture": "collection / capture",
    "command_control": "command and control",
    "command_and_control": "command and control",
    "c2": "command and control",
    "stealth": "stealth / proxy execution",
    "proxy_execution": "stealth / proxy execution",
}
_LEVELS: dict[str, PolicyLevel | None] = {
    "strict": PolicyLevel.STRICT,
    "escalate": PolicyLevel.ESCALATE,
    "off": None,
    "ignore": None,
    "disable": None,
}


@dataclass(frozen=True)
class Policy:
    levels: dict = field(default_factory=dict)
    allowlist: Allowlist = field(default_factory=Allowlist)

    @property
    def empty(self) -> bool:
        return not self.levels and self.allowlist.empty


def _as_set(v) -> frozenset:
    if v is None:
        return frozenset()
    if isinstance(v, str):
        v = [v]
    return frozenset(str(x).strip().lower() for x in v if str(x).strip())


def load_policy(path) -> Policy:
    path = Path(path)
    size = path.stat().st_size
    if size > MAX_POLICY_BYTES:
        raise ValueError(f"policy too large: {size} bytes exceeds {MAX_POLICY_BYTES}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("policy file must be a mapping")

    levels: dict = {}
    cats = data.get("categories") or {}
    if not isinstance(cats, dict):
        raise ValueError("policy 'categories' must be a mapping")
    for key, val in cats.items():
        name = _KEY_TO_NAME.get(str(key).strip().lower().replace(" ", "_"))
        if name is None:
            raise ValueError(f"unknown policy category: {key!r}")
        if isinstance(val, bool):  # YAML parses off/no/false as booleans
            val = "off" if val is False else "on"
        lvl = str(val).strip().lower()
        if lvl not in _LEVELS:
            raise ValueError(f"unknown level {val!r} for {key!r}; use strict, escalate, or off")
        levels[name] = _LEVELS[lvl]

    allow = data.get("allow") or {}
    if not isinstance(allow, dict):
        raise ValueError("policy 'allow' must be a mapping")
    hosts = allow.get("hosts") if allow.get("hosts") is not None else allow.get("host")
    paths = allow.get("paths") if allow.get("paths") is not None else allow.get("path")
    cmds = allow.get("commands") if allow.get("commands") is not None else allow.get("command")
    allowlist = Allowlist(_as_set(hosts), _as_set(paths), _as_set(cmds))
    return Policy(levels, allowlist)
