"""MCP server: expose Alibi's inline guardrail (inline.assess) as an `assess` tool over stdio, so any
MCP-speaking agent can ask Alibi to allow / warn / block a proposed tool call before it runs. The
preventive counterpart to the shipped Claude Code PreToolUse hook.

Dependency-free: newline-delimited JSON-RPC 2.0 on stdin/stdout, no MCP SDK. handle(request) is pure
(request dict -> response dict, or None for a notification) so it can be unit-tested without stdio."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime

from alibi.inline import assess
from alibi.transcript import ToolCall, load_transcript

PROTOCOL_VERSION = "2024-11-05"
_ASSESS_SCHEMA = {
    "type": "object",
    "properties": {
        "tool_name": {"type": "string", "description": "the tool the agent proposes to call"},
        "tool_input": {"type": "object", "description": "the proposed tool arguments"},
        "cwd": {"type": "string", "description": "working directory of the call (optional)"},
        "tool_use_id": {"type": "string", "description": "id for the proposed call (optional)"},
        "transcript_path": {"type": "string", "description": "path to the session transcript so far (optional)"},
    },
    "required": ["tool_name", "tool_input"],
}
_ASSESS_DESC = ("Judge a proposed tool call against the session so far and return allow / warn / block: "
                "block means the call is derived from untrusted content (a hijack in progress), warn means "
                "it is a sensitive action the user did not ask for, allow otherwise.")


def _ok(rid, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _error(rid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def _assess_result(args: dict) -> dict:
    tool_input = args.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    events = []
    tpath = args.get("transcript_path")
    if tpath:
        try:
            events = load_transcript(str(tpath))
        except Exception:
            events = []
    call = ToolCall(datetime.now(UTC), str(args.get("tool_use_id") or "candidate"),
                    str(args.get("tool_name") or ""), tool_input, args.get("cwd"))
    v = assess(events, call)
    return {
        "content": [{"type": "text", "text": f"{v.decision.value.upper()}: {v.reason}"}],
        "structuredContent": {"decision": v.decision.value, "reason": v.reason,
                              "category": v.category, "token": v.token},
        "isError": False,
    }


def handle(request: dict) -> dict | None:
    """Handle one JSON-RPC request. Returns a response dict, or None for a notification."""
    if not isinstance(request, dict):
        return _error(None, -32600, "invalid request")
    rid = request.get("id")
    method = request.get("method")
    if isinstance(method, str) and method.startswith("notifications/"):
        return None
    if method == "initialize":
        return _ok(rid, {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}},
                         "serverInfo": {"name": "alibi", "version": "0.1.0"}})
    if method == "tools/list":
        return _ok(rid, {"tools": [{"name": "assess", "description": _ASSESS_DESC, "inputSchema": _ASSESS_SCHEMA}]})
    if method == "tools/call":
        params = request.get("params") or {}
        if params.get("name") != "assess":
            return _error(rid, -32602, f"unknown tool: {params.get('name')!r}")
        args = params.get("arguments") or {}
        try:
            return _ok(rid, _assess_result(args))
        except Exception as exc:  # never crash the server on one bad call
            return _ok(rid, {"content": [{"type": "text", "text": f"assess failed: {type(exc).__name__}: {exc}"}],
                             "isError": True})
    return _error(rid, -32601, f"method not found: {method!r}")


def serve(inp=None, outp=None) -> None:
    """Newline-delimited JSON-RPC loop over stdio until EOF."""
    inp = inp or sys.stdin
    outp = outp or sys.stdout
    for line in inp:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError:
            outp.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            outp.flush()
            continue
        response = handle(request)
        if response is not None:
            outp.write(json.dumps(response) + "\n")
            outp.flush()
