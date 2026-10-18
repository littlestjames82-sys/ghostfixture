"""GhostFixture MCP server (stdio, local only, no network).

Tools: build_fixture, check_fixture. Payloads are summaries only:
paths, counts, reasons. No file bodies are ever returned.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from . import __version__
from .build import CheckError, build_fixture, check_fixture
from .bundle import BundleError

TOOLS = [
    {
        "name": "build_fixture",
        "description": "Build a minimal repro project from a GhostSlice bundle: referenced files plus static local import closure, secret-flagged files excluded by default.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project": {"type": "string"},
                "bundle": {"type": "string"},
                "out": {"type": "string"},
                "task": {"type": "string"},
                "max_bytes": {"type": "integer"},
            },
            "required": ["project", "bundle", "out"],
        },
    },
    {
        "name": "check_fixture",
        "description": "Re-verify a fixture tree against its fixture-manifest.json.",
        "inputSchema": {
            "type": "object",
            "properties": {"fixture": {"type": "string"}},
            "required": ["fixture"],
        },
    },
]

_MAX_ITEMS = 50


def _summary(manifest: dict) -> dict:
    return {
        "totals": manifest["totals"],
        "max_bytes": manifest["max_bytes"],
        "included": [e["path"] for e in manifest["included"][:_MAX_ITEMS]],
        "excluded_flagged": manifest["excluded_flagged"][:_MAX_ITEMS],
        "upstream_disagreements": manifest.get(
            "upstream_disagreements", [])[:_MAX_ITEMS],
        "left_out": manifest["left_out"][:_MAX_ITEMS],
    }


def _call_tool(name: str, args: dict) -> dict:
    if name == "build_fixture":
        manifest = build_fixture(
            args["project"], args["bundle"], args["out"],
            task=str(args.get("task") or ""),
            max_bytes=int(args.get("max_bytes") or 0) or 2 * 1024 * 1024,
        )
        return _summary(manifest)
    if name == "check_fixture":
        return check_fixture(args["fixture"])
    raise ValueError(f"unknown tool: {name}")


def serve(stdin=None, stdout=None) -> None:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            continue
        method = req.get("method", "")
        rid = req.get("id")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05",
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": "ghostfixture", "version": __version__}}
            _send(stdout, rid, result)
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            _send(stdout, rid, {"tools": TOOLS})
        elif method == "tools/call":
            params = req.get("params") or {}
            try:
                payload = _call_tool(params.get("name", ""), params.get("arguments") or {})
                _send(stdout, rid, {"content": [{"type": "text",
                                                 "text": json.dumps(payload, indent=2)}]})
            except (BundleError, CheckError, ValueError, KeyError, OSError) as exc:
                _send(stdout, rid, {"content": [{"type": "text", "text": f"error: {exc}"}],
                                    "isError": True})
        elif rid is not None:
            _send(stdout, rid, {}, error={"code": -32601, "message": f"method not found: {method}"})


def _send(stdout, rid, result, error=None) -> None:
    msg: dict = {"jsonrpc": "2.0", "id": rid}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    stdout.write(json.dumps(msg) + "\n")
    stdout.flush()
