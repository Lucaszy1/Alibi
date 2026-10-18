"""The judge: link an alert to an agent action, then decide whether the user's request covers it.

Tiers run cheapest-first and are all deterministic so far:

1. **Link** (``link.py``): UNRELATED alerts stand aside; AGENT_HARNESS alerts get a HARNESS
   disposition (never JUSTIFIED: no request is behind them) with a concern level.
2. **Provenance**: the action's distinctive targets (paths, URLs, hosts, IPs, packages) are
   traced to the user's prompts and to UNTRUSTED tool results since the last prompt.
3. **Policy**: sensitive ATT&CK techniques need the user to have asked for that kind of thing.
4. **Model**: a pluggable ``ModelTier`` consulted for UNKNOWN verdicts. None is wired up yet.
"""

from __future__ import annotations

import posixpath
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from alibi.alerts import Alert
from alibi.decode import reveal
from alibi.link import DEFAULT_WINDOW_SECONDS, LinkResult, Origin, link_alert, link_alerts
from alibi.taint import TaintIndex
from alibi.transcript import Event, SourceKind, ToolCall, ToolResult, UserPrompt
from alibi.verdict import (
    Concern,
    Disposition,
    Evidence,
    EvidenceSource,
    Tier,
    Verdict,
    VerdictKind,
)

EXCERPT_RADIUS = 160
INSTRUCTION_RADIUS = 400

# ---------------------------------------------------------------------------------------------
# Text normalisation and target extraction


_PASTED_TAG_RE = re.compile(r"</?pasted_content[^>]*>")
_URL_RE = re.compile(r"https?://[^\s'\"<>|`)]+", re.I)
_IP_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
# A TLD allowlist keeps Python dotted names (alibi.alerts, yaml.safe_load) from reading as hosts.
_HOST_RE = re.compile(
    r"(?<![\w.@-])(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|app|ai|sh|co|me|info|biz|xyz|top|site|online|"
    r"ru|cn|su|tk|cc|ws|us|uk|de|fr|eu|gov|edu|cloud|link|zip|onion|nl|jp|kr|br|au|ca|ch|se|pl|cz|pt|gr|sg|hk|tw|za|mx|ar|cl|nz|ie|kz|ua|vn|ph|my|th|ng|ke|icu|cfd|sbs|cyou|bond|quest|pw|best)(?![\w-])",
    re.I,
)
_WIN_PATH_RE = re.compile(r"(?<![\w])[A-Za-z]:[\\/]+[^\s'\"<>|;&*?`]*")
# Escapes inside quoted strings (printf '...\n') would otherwise read as path separators.
_STRING_ESCAPE_RE = re.compile(r"\\[ntr](?![A-Za-z0-9_])")
# Claude Code's per-session scratch area (…/Temp/claude/<project>/<session>/) belongs to the agent.
_AGENT_SCRATCH_RE = re.compile(r"(^|/)(appdata/local/)?te?mp/claude/[^/]+/[0-9a-f-]{36}(/|$)")
# Not after "$": a shell/PowerShell variable ($R/hayabusa) can't be resolved statically.
_REL_PATH_RE = re.compile(r"(?<![\w:/\\.$-])(?:~|\.{1,2})?/?[\w.~@+\-\[\]]+(?:[\\/]+[\w.~@+\-\[\]]+)+[\\/]?")
_PKG_INSTALL_RE = re.compile(r"\b(?:pip3?|uv pip|npm|pnpm|yarn|gem|cargo|go)\s+(?:install|add|get)\b([^;&|\n]*)", re.I)
_IGNORED_PATHS = {"/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/usr/bin/env", "/bin/sh", "/bin/bash"}
_WORD_RE = re.compile(r"[a-z][a-z0-9_\-]{3,}")
_GENERIC_WORDS = frozenset(
    """python python3 bash powershell node echo grep head tail true false null print import from
    return none with else elif then done this that file files path paths list dict self open read
    write test tests main src data true usr bin dev tmp temp users local appdata windows program
    programs system32 exit eval cat sort uniq less more find xargs sed awk printf export source
    encoding utf-8 utf-8-sig line lines text json csv for while print and not the you your""".split()
)

_INSTRUCTION_RES = [
    re.compile(p, re.I)
    for p in (
        r"\b(ignore|disregard|forget)\b.{0,40}\b(instructions?|previous|prior|above|rules)\b",
        r"\byou (must|should|need to|are required to|have to)\b",
        r"\b(ai|llm|assistant|agent|claude|copilot|chatgpt)s?\b.{0,60}\b(must|should|run|execute|please)\b",
        r"\b(run|execute|download|install|invoke|fetch)\b.{0,30}\b(this|the following|it|now|immediately)\b",
        r"\b(important|attention|urgent)\s*[:!]",
        r"\bsystem\s*(prompt|message|note|instruction)\b",
        r"\bdo not (tell|mention|inform|ask)\b",
        r"<!--",
    )
]


_PASTED_BLOCK_RE = re.compile(r"<pasted_content[^>]*>.*?</pasted_content>", re.I | re.S)
_ZW_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")


# Homoglyphs folded to Latin look-alikes across Cyrillic, Greek, Armenian and extended Latin. A wide
# curated subset of letters abused in look-alike domains and injections, not the full Unicode table.
_CONFUSABLES = str.maketrans({
    # Cyrillic lowercase -> Latin
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u043a": "k", "\u043c": "m", "\u043d": "h", "\u0442": "t", "\u0432": "b",
    "\u0433": "r", "\u0501": "d", "\u051b": "q", "\u051d": "w", "\u0475": "v",
    "\u04cf": "l",
    # Cyrillic uppercase -> Latin
    "\u0410": "A", "\u0415": "E", "\u041e": "O", "\u0420": "P", "\u0421": "C",
    "\u0425": "X", "\u0423": "Y", "\u0406": "I", "\u0405": "S", "\u041a": "K",
    "\u041c": "M", "\u041d": "H", "\u0422": "T", "\u0412": "B", "\u0408": "J",
    "\u051a": "Q", "\u051c": "W", "\u0474": "V", "\u04c0": "I",
    # Greek lowercase -> Latin
    "\u03bf": "o", "\u03b1": "a", "\u03c1": "p", "\u03b5": "e", "\u03ba": "k",
    "\u03bc": "m", "\u03bd": "v", "\u03c4": "t", "\u03c7": "x", "\u03b9": "i",
    "\u03c5": "u", "\u03b3": "y", "\u03f2": "c",
    # Greek uppercase -> Latin
    "\u039f": "O", "\u0391": "A", "\u03a1": "P", "\u0395": "E", "\u039a": "K",
    "\u039c": "M", "\u039d": "N", "\u03a4": "T", "\u03a7": "X", "\u0399": "I",
    "\u0392": "B", "\u0397": "H", "\u0396": "Z", "\u03a5": "Y",
    # Armenian -> Latin
    "\u0585": "o", "\u0578": "n", "\u057d": "u",
    # Extended Latin look-alikes (NFKC keeps these distinct from ASCII)
    "\u0251": "a", "\u0131": "i", "\u0261": "g",
})


def _denoise(text: str) -> str:
    """Canonicalise unicode (NFKC), strip zero-width / bidi-control characters, and fold common
    Cyrillic/Greek homoglyphs to their Latin look-alikes, so an injection or look-alike host hidden
    with invisible characters, fullwidth glyphs, or confusable letters still matches."""
    t = unicodedata.normalize("NFKC", text)
    t = _ZW_RE.sub("", t)
    return t.translate(_CONFUSABLES)


def _user_intent(text: str) -> str:
    """User text with pasted/attached blocks removed: pasted content may be attacker-controlled (a
    malicious doc the user pasted), so it must not count as the user's request when justifying an
    action -- otherwise an attacker could self-justify by getting their payload pasted into the chat."""
    return _PASTED_BLOCK_RE.sub(" ", text)


def _clean(text: str) -> str:
    return " ".join(_PASTED_TAG_RE.sub(" ", text).split())


def _norm_text(text: str) -> str:
    """Lower-case, forward slashes, git-bash drive paths as c:/, quotes dropped, single spaces."""
    t = _denoise(text).lower().replace("\\", "/")
    t = re.sub(r"/{2,}", "/", t)
    t = re.sub(r"(?<![\w:])/([a-z])/", r"\1:/", t)
    t = t.replace('"', " ").replace("'", " ").replace("`", " ")
    return " ".join(t.split())


def _norm_path(p: str) -> str:
    p = p.strip().strip("'\"`,;:)(").replace("\\", "/")
    p = re.sub(r"/{2,}", "/", p)
    p = re.sub(r"^/([a-zA-Z])/", r"\1:/", p)
    if p.startswith("./"):
        p = p[2:]
    return p.rstrip("/").lower()


class TargetKind(StrEnum):
    PATH = "path"
    URL = "url"
    HOST = "host"
    IP = "ip"
    PACKAGE = "package"


@dataclass(frozen=True)
class Target:
    kind: TargetKind
    value: str  # normalised

    def __str__(self) -> str:
        return f"{self.kind.value}:{self.value}"


def _paths(text: str) -> set[str]:
    out = set()
    text = _STRING_ESCAPE_RE.sub(" ", text)
    for m in list(_WIN_PATH_RE.finditer(text)) + list(_REL_PATH_RE.finditer(text)):
        p = _norm_path(m.group(0))
        if p in _IGNORED_PATHS or p.startswith("/dev/") or not re.search(r"[a-z]", p):
            continue
        if p.startswith("-") or "://" in m.group(0):
            continue
        segments = [s for s in re.split(r"[:/]", p) if s]
        if len(segments) >= 2 or re.match(r"^[a-z]:/", p):
            out.add(p)
    return out


_FILE_EXT_TLD = {"sh", "zip", "app"}  # gTLDs that, in command text, are almost always file extensions


def _looks_like_file(host: str) -> bool:
    """A bare one-dot token whose extension is a file-extension gTLD (s.sh, backup.zip, My.app) is a
    local file, not a host. URL hosts never reach this check, so a real http://host.sh is unaffected."""
    parts = host.split(".")
    return len(parts) == 2 and parts[-1] in _FILE_EXT_TLD


def extract_targets(text: str) -> set[Target]:
    """Distinctive things an action touches: paths, URLs, hosts, IPs, installed packages."""
    targets: set[Target] = set()
    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:").lower()
        targets.add(Target(TargetKind.URL, url))
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
        targets.add(Target(TargetKind.HOST, host))
    without_urls = _URL_RE.sub(" ", text)
    for m in _HOST_RE.finditer(without_urls):
        host = m.group(0).lower()
        if not _looks_like_file(host):
            targets.add(Target(TargetKind.HOST, host))
    for m in _IP_RE.finditer(without_urls):
        targets.add(Target(TargetKind.IP, m.group(0)))
    for p in _paths(without_urls):
        targets.add(Target(TargetKind.PATH, p))
    for m in _PKG_INSTALL_RE.finditer(text):
        for arg in m.group(1).split():
            arg = arg.strip("'\"")
            name = re.split(r"[<>=!~\[@]", arg)[0].lower()
            if name and not arg.startswith(("-", ".", "/")) and re.match(r"^[a-z][\w.\-]*$", name):
                targets.add(Target(TargetKind.PACKAGE, name))
    return targets


def _call_text(call: ToolCall) -> str:
    inp = call.tool_input
    for key in ("command", "file_path", "notebook_path", "url", "path", "pattern", "query"):
        if inp.get(key):
            return str(inp[key])
    return " ".join(str(v) for v in inp.values() if isinstance(v, (str, int, float)))


# ---------------------------------------------------------------------------------------------
# Coverage: is a target something the user asked for?


def _user_paths(prompts_text: str) -> set[str]:
    paths = _paths(prompts_text)
    # A named file vouches for its directory ("C:\Tools\Hayabusa\results.csv" covers rules\).
    for p in list(paths):
        parent, _, last = p.rpartition("/")
        if "." in last and parent and len([s for s in re.split(r"[:/]", parent) if s]) >= 2:
            paths.add(parent)
    return paths


def _path_covered(target: str, user_paths: set[str], user_norm: str, roots: Iterable[str]) -> bool:
    padded = "/" + target + "/"
    for p in user_paths:
        if ("/" + p + "/") in padded:
            return True
    is_relative = not re.match(r"^([a-z]:/|/|~)", target)
    for root in roots:
        if not root:
            continue
        resolved = posixpath.normpath(f"{root}/{target}") if is_relative else target
        if resolved == root or resolved.startswith(root + "/"):
            return True
    if _AGENT_SCRATCH_RE.search(target):
        return True
    base = target.rsplit("/", 1)[-1]
    if "." in base and len(base) >= 5 and re.search(rf"(?<![\w.-]){re.escape(base)}(?![\w-])", user_norm):
        return True
    return False


def _covered(target: Target, user_paths: set[str], user_norm: str, roots: Iterable[str]) -> bool:
    if target.kind is TargetKind.PATH:
        return _path_covered(target.value, user_paths, user_norm, roots)
    if target.kind is TargetKind.URL:
        return re.sub(r"/{2,}", "/", target.value) in user_norm
    return re.search(rf"(?<![\w.-]){re.escape(target.value)}(?![\w-])", user_norm) is not None


def _appears_in(target: Target, text_norm: str) -> int:
    """Index of the target in normalised text, or -1."""
    if target.kind is TargetKind.PATH:
        i = text_norm.find(target.value)
        if i < 0:
            base = target.value.rsplit("/", 1)[-1]
            if "." in base and len(base) >= 5:
                m = re.search(rf"(?<![\w.-]){re.escape(base)}(?![\w-])", text_norm)
                return m.start() if m else -1
        return i
    m = re.search(rf"(?<![\w.-]){re.escape(target.value)}(?![\w-])", text_norm)
    return m.start() if m else -1


def _shingles(text_norm: str, n: int = 3) -> set[str]:
    words = text_norm.split()
    out = set()
    for i in range(len(words) - n + 1):
        gram = words[i:i + n]
        if any(len(w) >= 4 and re.search(r"[a-z]", w) and w not in _GENERIC_WORDS for w in gram):
            out.add(" ".join(gram))
    return out


def _excerpt(text: str, index: int, radius: int = EXCERPT_RADIUS) -> str:
    start, end = max(0, index - radius), min(len(text), index + radius)
    return ("…" if start else "") + text[start:end] + ("…" if end < len(text) else "")


# ---------------------------------------------------------------------------------------------
# Policy (tier 3)


class PolicyLevel(StrEnum):
    STRICT = "STRICT"      # not mentioned -> UNJUSTIFIED
    ESCALATE = "ESCALATE"  # not mentioned -> UNKNOWN (defer)


@dataclass(frozen=True)
class PolicyCategory:
    name: str
    level: PolicyLevel
    techniques: tuple[str, ...]
    keywords: tuple[str, ...]


POLICY_CATEGORIES = (
    PolicyCategory(
        "credential access", PolicyLevel.STRICT, ("T1555", "T1003", "T1552", "T1558", "T1539"),
        ("credential", "password", "passwd", "secret", "token", "api key", "apikey", "keychain", "vault",
         "lsass", "private key", "ssh key", ".ssh", "cookie", "cmdkey"),
    ),
    PolicyCategory(
        "persistence", PolicyLevel.STRICT, ("T1547", "T1053", "T1543", "T1546", "T1136", "T1098", "T1037", "T1574"),
        ("startup", "autostart", "autorun", "run key", "scheduled task", "schtasks", "crontab", "cron",
         "service", "launch agent", "launchd", "login item", "persistence", "persist", "boot",
         "user account", "add user", "new user", "admin group", "local admin"),
    ),
    PolicyCategory(
        "defense impairment", PolicyLevel.STRICT, ("T1562", "T1070", "T1553", "T1548", "T1134"),
        ("defender", "antivirus", "firewall", "exclusion", "tamper", "event log", "audit", "clear log",
         "wevtutil", "uac", "execution policy", "amsi", "etw", "disable security", "code signing"),
    ),
    PolicyCategory(
        "exfiltration", PolicyLevel.STRICT, ("T1041", "T1048", "T1567", "T1020", "T1030", "T1011"),
        ("exfiltrate", "upload", "send to", "post to", "webhook", "pastebin", "curl", "wget",
         "invoke-webrequest", "bitsadmin", "scp", "rclone"),
    ),
    PolicyCategory(
        "data destruction / impact", PolicyLevel.STRICT, ("T1485", "T1486", "T1490", "T1561", "T1491"),
        ("encrypt", "ransom", "delete", "wipe", "erase", "format", "overwrite", "destroy",
         "shadow copy", "vssadmin", "cipher", "mass delete"),
    ),
    PolicyCategory(
        "collection / capture", PolicyLevel.STRICT, ("T1056", "T1113", "T1115", "T1114", "T1125", "T1123"),
        ("keylog", "keystroke", "screenshot", "screen capture", "screen record", "record screen",
         "clipboard", "webcam", "microphone", "capture input"),
    ),
    PolicyCategory(
        "command and control", PolicyLevel.ESCALATE, ("T1090", "T1105", "T1572", "T1219", "T1102"),
        ("proxy", "tunnel", "beacon", "reverse shell", "ngrok", "certutil", "bitsadmin",
         "remote access", "download tool", "c2"),
    ),
    PolicyCategory(
        "stealth / proxy execution", PolicyLevel.ESCALATE, ("T1055", "T1218", "T1027", "T1036", "T1140", "T1564"),
        ("inject", "obfuscat", "encode", "base64", "rundll32", "regsvr32", "mshta", "hidden", "masquerad"),
    ),
)


@dataclass(frozen=True)
class PolicyHit:
    category: PolicyCategory
    technique: str
    mentioned: str | None  # keyword the user used, if any
    mentioned_in: UserPrompt | None = None


def policy_hits(alert: Alert, prompts: list[UserPrompt]) -> list[PolicyHit]:
    hits = []
    for technique in alert.mitre_techniques:
        base = technique.split(".")[0].upper()
        for cat in POLICY_CATEGORIES:
            if base not in cat.techniques:
                continue
            mentioned, where = None, None
            for prompt in reversed(prompts):
                low = prompt.text.lower()
                for kw in (*cat.keywords, base.lower(), technique.lower()):
                    if re.search(rf"(?<![a-z]){re.escape(kw)}", low):
                        mentioned, where = kw, prompt
                        break
                if mentioned:
                    break
            hits.append(PolicyHit(cat, technique, mentioned, where))
    return hits


# Unambiguous command signatures, mapped to a policy category, for the decoded-content scan. These
# are deliberately anchored to specific tool/command forms (never dual-use tokens like curl/wget) so
# a tagged-but-under-labelled alert still gets policy treatment without false-flagging benign work.
_CONTENT_SIGS = (
    ("credential access", re.compile(
        r"\bcmdkey\b|\bvaultcmd\b|\bmimikatz\b|lsass|secretsdump|/\.ssh/id_|\.netrc|"
        r"security\s+find-generic-password|reg\s+save[^\n]*\\sam", re.I)),
    ("persistence", re.compile(
        r"\bschtasks\b[^\n]*/create|reg\s+add[^\n]*\\run|New-Service\b|\bsc(?:\.exe)?\s+create\b|"
        r"crontab|launchctl\s+load|systemctl\s+enable", re.I)),
    ("defense impairment", re.compile(
        r"set-mppreference[^\n]*-disable|netsh\s+advfirewall[^\n]*state\s+off|wevtutil\s+cl", re.I)),
    ("data destruction / impact", re.compile(
        r"\bvssadmin\s+delete\s+shadows|cipher\s+/w|\bdel\s+/[sq]|\bformat\s+[a-z]:|rm\s+-rf\s+/", re.I)),
    ("collection / capture", re.compile(r"get-clipboard|\bscreencapture\b|\bscreenshot\b", re.I)),
)
_CATS_BY_NAME = {c.name: c for c in POLICY_CATEGORIES}


def _content_policy_hits(action_text: str, prompts: list[UserPrompt], existing: list[PolicyHit]) -> list[PolicyHit]:
    """Policy hits derived from the decoded command content for categories the alert tags missed.
    The same mentioned-check applies, so a user-requested dangerous command is still cleared."""
    have = {h.category.name for h in existing}
    out: list[PolicyHit] = []
    for name, rx in _CONTENT_SIGS:
        if name in have or not rx.search(action_text):
            continue
        cat = _CATS_BY_NAME[name]
        mentioned, where = None, None
        for prompt in reversed(prompts):
            low = prompt.text.lower()
            for kw in cat.keywords:
                if re.search(rf"(?<![a-z]){re.escape(kw)}", low):
                    mentioned, where = kw, prompt
                    break
            if mentioned:
                break
        out.append(PolicyHit(cat, f"content:{name}", mentioned, where))
        have.add(name)
    return out


# ---------------------------------------------------------------------------------------------
# Provenance (tier 2)


@dataclass(frozen=True)
class UntrustedHit:
    target: Target
    result: ToolResult
    tool_name: str | None
    excerpt: str
    instruction_like: bool


@dataclass(frozen=True)
class Provenance:
    targets: frozenset[Target]
    covered: frozenset[Target]
    uncovered: frozenset[Target]
    untrusted_hits: tuple[UntrustedHit, ...]
    phrase_match: tuple[UserPrompt, str] | None  # the user typed (part of) the command
    target_match: tuple[UserPrompt, Target, int] | None
    word_match: tuple[UserPrompt, str] | None


def trace_provenance(
    call: ToolCall,
    prompts: list[UserPrompt],
    untrusted: list[ToolResult],
    tool_names: dict[str, str],
    roots: Iterable[str] = (),
) -> Provenance:
    action = reveal(_call_text(call))
    action_norm = _norm_text(action)
    targets = extract_targets(action)
    if call.tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        targets = {t for t in targets if t.kind is TargetKind.PATH}

    user_all = " ".join(_user_intent(p.text) for p in prompts)
    user_norm = _norm_text(user_all)
    user_paths = _user_paths(user_all)
    roots = [_norm_path(r) for r in roots if r]
    covered = {t for t in targets if _covered(t, user_paths, user_norm, roots)}
    uncovered = set(targets) - covered

    # For file-writing tools, also trace targets embedded in the WRITTEN CONTENT, not just
    # the path. A hijacked agent can drop a payload to disk; if what it wrote names a host or
    # URL the user never asked for and that came from untrusted input, that is a hijack even
    # though the file sits in the workspace. These only ever raise an untrusted-content hit,
    # never generic UNKNOWN noise, so ordinary code that merely contains a URL stays clean.
    content_targets: set[Target] = set()
    if call.tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        written = reveal(" ".join(str(call.tool_input.get(k, "")) for k in ("content", "new_string", "new_str", "new_source")))
        content_targets = {
            t for t in extract_targets(written)
            if t.kind is not TargetKind.PATH and not _covered(t, user_paths, user_norm, roots)
        }

    hits = []
    for target in uncovered | content_targets:
        for result in untrusted:
            raw = result.content
            idx = _appears_in(target, _norm_text(raw))
            if idx < 0:
                continue
            # Locate in the raw text for a readable excerpt (normalisation shifts offsets a little).
            raw_idx = max(0, min(len(raw) - 1, idx))
            window = _denoise(raw[max(0, raw_idx - INSTRUCTION_RADIUS): raw_idx + INSTRUCTION_RADIUS])
            hits.append(
                UntrustedHit(
                    target, result, tool_names.get(result.tool_use_id), _excerpt(_clean(raw), _clean_index(raw, raw_idx)),
                    any(r.search(window) for r in _INSTRUCTION_RES),
                )
            )

    phrase = None
    cmd_shingles = _shingles(action_norm)
    for prompt in reversed(prompts):
        p_norm = _norm_text(_user_intent(prompt.text))
        found = next((s for s in cmd_shingles if s in p_norm), None)
        if found:
            phrase = (prompt, found)
            break

    target_match = None
    for prompt in reversed(prompts):
        p_norm = _norm_text(_user_intent(prompt.text))
        p_paths = _user_paths(_user_intent(prompt.text))
        for t in sorted(covered, key=str):
            if _covered(t, p_paths, p_norm, ()):
                idx = _appears_in(t, p_norm)
                target_match = (prompt, t, idx)
                break
        if target_match:
            break

    word = None
    action_words = {w for w in _WORD_RE.findall(action_norm) if w not in _GENERIC_WORDS}
    for prompt in reversed(prompts):
        p_words = set(_WORD_RE.findall(_norm_text(_user_intent(prompt.text))))
        shared = sorted(action_words & p_words)
        if shared:
            word = (prompt, ", ".join(shared[:5]))
            break

    return Provenance(
        frozenset(targets), frozenset(covered), frozenset(uncovered), tuple(hits), phrase, target_match, word
    )


def _clean_index(raw: str, idx: int) -> int:
    """Approximate position in the cleaned text for an index into the raw text."""
    return len(_clean(raw[:idx]))


# ---------------------------------------------------------------------------------------------
# Tier 4 seam


@dataclass(frozen=True)
class JudgeContext:
    """Everything a model tier needs to re-judge an UNKNOWN verdict."""

    alert: Alert
    link: LinkResult
    tool_call: ToolCall | None
    prompts: tuple[UserPrompt, ...]
    untrusted_results: tuple[ToolResult, ...]
    provenance: Provenance | None
    policy: tuple[PolicyHit, ...]
    deterministic: Verdict


class ModelTier(Protocol):
    """A later tier (e.g. a local model). Return a Verdict to override UNKNOWN, or None to pass."""

    def judge(self, context: JudgeContext) -> Verdict | None: ...


# ---------------------------------------------------------------------------------------------
# The judge


_BULK_KEYWORDS = (
    "refactor", "rename", "reformat", "format", "lint", "prettier", "black", "isort", "migrat",
    "rewrite", "codemod", "find and replace", "sed ", "mass ", "bulk", "every file", "all files",
    "across the repo", "whole repo", "entire repo", "clean up all", "normalize", "apply fixes",
)
_BULK_THRESHOLD = 10
_BULK_WINDOW = timedelta(seconds=120)


def _is_file_write(v):
    if v.disposition is not Disposition.VERDICT:
        return False
    call = v.tool_call
    if call is not None and call.tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        return True
    return v.alert.event_id == 11 or "file created" in v.alert.rule_title.lower()


def _densest_cluster(writes, window):
    best = []
    for i in range(len(writes)):
        k = i
        while k < len(writes) and writes[k].alert.timestamp - writes[i].alert.timestamp <= window:
            k += 1
        if k - i > len(best):
            best = writes[i:k]
    return best


@dataclass
class Judge:
    events: list[Event]
    model_tier: ModelTier | None = None
    window_seconds: float = DEFAULT_WINDOW_SECONDS
    # Directories the user implicitly put in scope; each call's cwd is always included.
    workspace_roots: tuple[str, ...] = ()
    allowlist: Any = None
    disable_policy: bool = False
    _tool_names: dict[str, str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._tool_names = {e.tool_use_id: e.tool_name for e in self.events if isinstance(e, ToolCall)}

    def judge_all(self, alerts: list[Alert]) -> list[Verdict]:
        links = link_alerts(alerts, self.events, self.window_seconds)
        verdicts = [self.judge(a, link) for a, link in zip(alerts, links)]
        return self._flag_bulk_rewrites(verdicts)

    def _flag_bulk_rewrites(self, verdicts: list[Verdict]) -> list[Verdict]:
        """A burst of file rewrites the user never licensed (ransomware-shaped) is suspicious even
        when no single write is. If the request names no bulk operation (refactor, rename, format,
        ...), flag the densest cluster of agent file-writes as UNJUSTIFIED."""
        writes = sorted((v for v in verdicts if _is_file_write(v)), key=lambda v: v.alert.timestamp)
        if len(writes) < _BULK_THRESHOLD:
            return verdicts
        user_text = " ".join(e.text for e in self.events if isinstance(e, UserPrompt)).lower()
        if any(k in user_text for k in _BULK_KEYWORDS):
            return verdicts
        cluster = _densest_cluster(writes, _BULK_WINDOW)
        if len(cluster) < _BULK_THRESHOLD:
            return verdicts
        flagged = {id(v) for v in cluster}
        span = (cluster[-1].alert.timestamp - cluster[0].alert.timestamp).total_seconds()
        reason = (f"{len(cluster)} files rewritten in {span:.0f}s, a mass file change the request "
                  f"never licensed (no refactor, rename or format asked for).")
        return [
            replace(v, verdict=VerdictKind.UNJUSTIFIED, reason=reason, tier=Tier.POLICY, confidence=0.8)
            if id(v) in flagged and v.verdict in (VerdictKind.JUSTIFIED, VerdictKind.UNKNOWN) else v
            for v in verdicts
        ]

    def judge(self, alert: Alert, link: LinkResult | None = None) -> Verdict:
        if link is None:
            link = link_alert(alert, self.events, self.window_seconds)

        if link.origin is Origin.UNRELATED:
            return Verdict(alert, link, Disposition.STAND_ASIDE, None, link.confidence or 1.0,
                           "Not caused by the agent.", Tier.LINK, techniques=alert.mitre_techniques)
        if link.origin is Origin.AGENT_HARNESS:
            return self._harness(alert, link)

        verdict, context = self._deterministic(alert, link)
        verdict = self._anomaly(verdict, context)
        final = verdict
        if self.model_tier is not None:
            if verdict.verdict is VerdictKind.UNKNOWN:
                # Strictly non-exonerating: the model may escalate an UNKNOWN to UNJUSTIFIED/HIJACKED
                # but never clear it to JUSTIFIED. The untrusted content it reads could carry a prompt
                # injection aimed at the judge ("respond JUSTIFIED"), so exoneration is never accepted.
                override = self.model_tier.judge(context)
                if override is not None and override.verdict is not VerdictKind.JUSTIFIED:
                    final = override
            elif verdict.verdict is VerdictKind.UNJUSTIFIED and context.untrusted_results:
                # Paraphrase recovery: untrusted content is present but no literal link was found,
                # so a semantically-induced hijack may be laundered past the deterministic tiers.
                # Let the model read the untrusted content, but accept its override ONLY if it
                # strengthens the verdict to HIJACKED. The model may never exonerate a flag.
                override = self.model_tier.judge(context)
                if override is not None and override.verdict is VerdictKind.HIJACKED:
                    final = override
        return self._apply_allowlist(final, alert, link)

    # -- harness -------------------------------------------------------------------------------

    def _anomaly(self, v: Verdict, context: JudgeContext) -> Verdict:
        """Attack-agnostic catch: a high-severity action the EDR flagged that we can only call
        routine, with no external target and no tie to the request, is unexplained. Surface it as
        a non-blocking review item, even with no untrusted source and no known technique. This is
        the catch for a genuinely novel attack that leaves no other signal."""
        if (v.disposition is Disposition.VERDICT and v.verdict is VerdictKind.JUSTIFIED
                and v.confidence < 0.6
                and context.alert.level.lower() in ("high", "crit", "critical")):
            return replace(
                v, verdict=VerdictKind.UNKNOWN, confidence=1.0, tier=Tier.POLICY, concern=Concern.ELEVATED,
                reason=(f"High-severity action with no external target and no tie to the request; "
                        f"unexplained, needs review (was: {v.reason})"),
            )
        return v

    def _apply_allowlist(self, v: Verdict, alert: Alert, link: LinkResult) -> Verdict:
        """A user-sanctioned target downgrades a flag to JUSTIFIED, keeping the original finding
        in the reason. The allowlist comes only from the trusted --allow file, never the session."""
        al = getattr(self, "allowlist", None)
        if (al is None or al.empty or v.disposition is not Disposition.VERDICT
                or v.verdict not in (VerdictKind.HIJACKED, VerdictKind.UNJUSTIFIED)):
            return v
        call = link.tool_call
        text = (_call_text(call) if call is not None else "") + " " + (alert.command_line or "")
        rule = al.match(text)
        if not rule:
            return v
        return replace(v, verdict=VerdictKind.JUSTIFIED,
                       reason=f"Sanctioned by allowlist ({rule}); original finding: {v.reason}")

    def _harness(self, alert: Alert, link: LinkResult) -> Verdict:
        reasons = []
        if "outside any tool call" in link.match_reason:
            reasons.append("the agent spawned a process outside any tool call")
        # A positively recognised harness pattern (the linker named it) explains a noisy rule;
        # anything else the agent process does gets the rule's severity taken at face value.
        recognised = link.match_reason.startswith("Claude Code harness:")
        if not recognised:
            if alert.level.lower() in ("high", "crit", "critical"):
                reasons.append(f"rule level is {alert.level}")
            sensitive = [h for h in policy_hits(alert, []) if h.category.level is PolicyLevel.STRICT]
            if sensitive:
                reasons.append(f"technique {sensitive[0].technique} ({sensitive[0].category.name})")
        concern = Concern.ELEVATED if reasons else Concern.LOW
        reason = (
            f"Claude Code's own activity, not a user request; flagged because {'; '.join(reasons)}."
            if reasons else f"Claude Code's own activity, not a user request ({link.match_reason})."
        )
        return Verdict(alert, link, Disposition.HARNESS, None, link.confidence, reason, Tier.LINK,
                       (Evidence(EvidenceSource.LINK, link.match_reason),), alert.mitre_techniques, concern)

    # -- agent actions -------------------------------------------------------------------------

    def _deterministic(self, alert: Alert, link: LinkResult) -> tuple[Verdict, JudgeContext]:
        call = link.tool_call
        techniques = alert.mitre_techniques

        def make(kind: VerdictKind, conf: float, reason: str, tier: Tier, evidence: Iterable[Evidence] = ()) -> Verdict:
            return Verdict(alert, link, Disposition.VERDICT, kind, round(conf * link.confidence, 3), reason,
                           tier, tuple(evidence), techniques)

        if call is None:
            v = make(VerdictKind.UNKNOWN, 1.0, "Agent-caused, but the tool call is not in this transcript.", Tier.LINK,
                     [Evidence(EvidenceSource.LINK, link.match_reason)])
            return v, JudgeContext(alert, link, None, (), (), None, (), v)

        prompts = [e for e in self.events if isinstance(e, UserPrompt) and e.timestamp <= call.timestamp]
        last_prompt_ts = prompts[-1].timestamp if prompts else datetime.min.replace(tzinfo=call.timestamp.tzinfo)
        untrusted = [
            e for e in self.events
            if isinstance(e, ToolResult) and e.source_kind is SourceKind.UNTRUSTED
            and last_prompt_ts <= e.timestamp <= call.timestamp
        ]
        roots = (*self.workspace_roots, *([call.cwd] if call.cwd else []))
        prov = trace_provenance(call, prompts, untrusted, self._tool_names, roots)
        hits: list[PolicyHit]
        if self.disable_policy:
            hits = []
        else:
            hits = policy_hits(alert, prompts)
            hits = hits + _content_policy_hits(reveal(_call_text(call)), prompts, hits)
        call_ev = Evidence(EvidenceSource.TOOL_CALL, _call_text(call)[:300], call.timestamp, call.tool_use_id, call.tool_name)

        def ctx(v: Verdict) -> JudgeContext:
            return JudgeContext(alert, link, call, tuple(prompts), tuple(untrusted), prov, tuple(hits), v)

        if not prompts:
            v = make(VerdictKind.UNKNOWN, 1.0, "No user prompt precedes this action.", Tier.PROVENANCE, [call_ev])
            return v, ctx(v)

        explicit = prov.phrase_match is not None
        strict_unmet = [h for h in hits if h.category.level is PolicyLevel.STRICT and not h.mentioned and not explicit]
        escalate_unmet = [
            h for h in hits
            if h.category.level is PolicyLevel.ESCALATE and not h.mentioned and not explicit and prov.target_match is None
        ]

        # Tier 2: hijack. Targets the user never named, found in untrusted content since the
        # last prompt. Instruction-like wording around them, or a sensitive technique, makes it a
        # call; otherwise it's likely ordinary discovery (ls, grep) and goes to a later tier.
        if prov.untrusted_hits:
            instructed = [h for h in prov.untrusted_hits if h.instruction_like]
            if instructed or strict_unmet or escalate_unmet:
                h = (instructed or list(prov.untrusted_hits))[0]
                conf = 0.9 if instructed else 0.75
                why = "instruction-like text" if instructed else "untrusted content"
                v = make(
                    VerdictKind.HIJACKED, conf,
                    f"The action targets {h.target} which the user never mentioned but which appears in {why} "
                    f"from a {h.tool_name or 'tool'} result.",
                    Tier.PROVENANCE,
                    [Evidence(EvidenceSource.UNTRUSTED_RESULT, h.excerpt, h.result.timestamp, h.result.tool_use_id, h.tool_name),
                     call_ev],
                )
                return v, ctx(v)

        # Tier 2b: taint. No distinctive target of the action appeared in untrusted content, but
        # the argument can still be derived from it: a decoded blob, or a file the agent wrote from
        # untrusted input and then ran. Flag such a flow when the action is consequential (a strict
        # sensitive category, or it executed a dropped file); plain benign base64 does not qualify.
        if not prov.untrusted_hits:
            idx = self.__dict__.get("_taint_index")
            if idx is None:
                idx = TaintIndex(self.events)
                self.__dict__["_taint_index"] = idx
            cache = self.__dict__.setdefault("_taint_cache", {})
            if id(call) not in cache:
                cache[id(call)] = idx.trace(call)
            taint = cache[id(call)]
            if taint.tainted and (strict_unmet or taint.via_file):
                ev = [call_ev]
                hop = next((st for st in taint.path if st.wrote), None)
                if hop is not None:
                    ev.insert(0, Evidence(EvidenceSource.TOOL_CALL,
                                          f"wrote {hop.wrote} from untrusted content, then it was run",
                                          hop.call.timestamp, hop.call.tool_use_id, hop.call.tool_name))
                if taint.source is not None:
                    raw = taint.source.content
                    i = raw.lower().find((taint.token or "").lower())
                    snip = _excerpt(_clean(raw), _clean_index(raw, i)) if i >= 0 else _clean(raw)[: 2 * EXCERPT_RADIUS]
                    ev.insert(0, Evidence(EvidenceSource.UNTRUSTED_RESULT, snip, taint.source.timestamp, taint.source.tool_use_id))
                why = ("a file the agent wrote from untrusted content" if taint.via_file
                       else f"untrusted content ({taint.token})")
                conf = min(0.95, round(0.7 + 0.2 * taint.strength + (0.05 if taint.via_file else 0.0), 2))
                v = make(VerdictKind.HIJACKED, conf,
                         f"The action is derived from {why}, which the user never introduced.",
                         Tier.PROVENANCE, ev)
                return v, ctx(v)

        # Tier 3: sensitive categories need the user to have asked for that kind of thing.
        if strict_unmet:
            ph = strict_unmet[0]
            v = make(
                VerdictKind.UNJUSTIFIED, 0.85,
                f"{ph.technique} is {ph.category.name}, which the user never asked for.",
                Tier.POLICY,
                [Evidence(EvidenceSource.POLICY, f"{ph.technique} → {ph.category.name}; no prompt mentions it"), call_ev],
            )
            return v, ctx(v)
        if escalate_unmet:
            ph = escalate_unmet[0]
            v = make(
                VerdictKind.UNKNOWN, 1.0,
                f"{ph.technique} ({ph.category.name}) with nothing in the request about it; needs review.",
                Tier.POLICY,
                [Evidence(EvidenceSource.POLICY, f"{ph.technique} → {ph.category.name}; no prompt mentions it"), call_ev],
            )
            return v, ctx(v)

        # Tier 2: justification, strongest evidence first.
        if prov.phrase_match:
            prompt, phrase = prov.phrase_match
            v = make(VerdictKind.JUSTIFIED, 0.9, f"The user asked for this command ('{phrase}').", Tier.PROVENANCE,
                     [self._prompt_evidence(prompt, phrase), call_ev])
            return v, ctx(v)
        if prov.untrusted_hits or prov.uncovered:
            first = sorted(prov.uncovered, key=str)[0] if prov.uncovered else prov.untrusted_hits[0].target
            source = " (also seen in untrusted output, likely discovery)" if prov.untrusted_hits else ""
            evidence = [call_ev] + [
                Evidence(EvidenceSource.UNTRUSTED_RESULT, h.excerpt, h.result.timestamp, h.result.tool_use_id, h.tool_name)
                for h in prov.untrusted_hits[:1]
            ]
            v = make(VerdictKind.UNKNOWN, 1.0, f"The action targets {first}, which the user never named{source}.",
                     Tier.PROVENANCE, evidence)
            return v, ctx(v)
        if prov.target_match:
            prompt, target, _ = prov.target_match
            v = make(VerdictKind.JUSTIFIED, 0.85, f"The user's request names the target {target}.", Tier.PROVENANCE,
                     [self._prompt_evidence(prompt, target.value.rsplit("/", 1)[-1]), call_ev])
            return v, ctx(v)
        if prov.targets:  # every target is in the workspace the user launched the agent in
            v = make(VerdictKind.JUSTIFIED, 0.7, "Every target is inside the user's workspace.", Tier.PROVENANCE,
                     [self._prompt_evidence(prompts[-1], None), call_ev])
            return v, ctx(v)
        if prov.word_match:
            prompt, words = prov.word_match
            v = make(VerdictKind.JUSTIFIED, 0.7, f"The request covers this action (shared terms: {words}).",
                     Tier.PROVENANCE, [self._prompt_evidence(prompt, words.split(", ")[0]), call_ev])
            return v, ctx(v)
        v = make(VerdictKind.JUSTIFIED, 0.55, "Routine action with no external targets, during the user's task.",
                 Tier.PROVENANCE, [self._prompt_evidence(prompts[-1], None), call_ev])
        return v, ctx(v)

    @staticmethod
    def _prompt_evidence(prompt: UserPrompt, needle: str | None) -> Evidence:
        text = _clean(prompt.text)
        idx = -1
        if needle:
            idx = _norm_text(text).find(_norm_text(needle))
        snippet = _excerpt(text, idx) if idx >= 0 else text[: 2 * EXCERPT_RADIUS] + ("…" if len(text) > 2 * EXCERPT_RADIUS else "")
        return Evidence(EvidenceSource.USER_PROMPT, snippet, prompt.timestamp)


def judge_alert(alert: Alert, events: list[Event], **kwargs) -> Verdict:
    return Judge(events, **kwargs).judge(alert)
