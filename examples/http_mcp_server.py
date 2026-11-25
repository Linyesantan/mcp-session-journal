#!/usr/bin/env python3
"""Minimal authenticated MCP HTTP server with built-in multi-session journal.

Stdlib-only example showing how to embed `mcp_journal` directly into an MCP
Streamable HTTP server.

Usage:
    MCP_TOKEN="change-me" python3 examples/http_mcp_server.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import mcp_journal

HOST = os.environ.get("MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_PORT", "8767"))
MCP_TOKEN = os.environ.get("MCP_TOKEN", "").strip()
HOME = Path.home()
MAX_RPC_BODY = 4 * 1024 * 1024

JOURNAL = mcp_journal.SessionJournal(source="http-mcp")

TOOLS = [
    {
        "name": "run",
        "description": "Execute a shell command in the local environment.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "timeout": {"type": "integer", "minimum": 1, "maximum": 300},
                "cwd": {"type": "string"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a UTF-8 text file. Paths starting with ~ are supported.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "max_bytes": {"type": "integer", "maximum": 200000}},
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "Write UTF-8 text to a file, creating parent directories.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
        },
    },
    {
        "name": "list_dir",
        "description": "List entries in a directory.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
]


def result_text(value) -> dict:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return {"content": [{"type": "text", "text": text}]}


def path_arg(value: str) -> Path:
    p = Path(value).expanduser()
    return p if p.is_absolute() else HOME / p


def run_cmd(command: str, *, cwd=None, timeout=30) -> dict:
    try:
        p = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=max(1, min(int(timeout), 300)),
        )
        return {"code": p.returncode, "output": p.stdout[-200000:]}
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        return {"code": 124, "output": str(out)[-200000:] + "\n[timeout]"}
    except Exception as e:
        return {"code": 1, "output": f"{type(e).__name__}: {e}"}


def call_tool(name: str, args: dict) -> dict:
    if name == "run":
        cmd = str(args.get("command", "")).strip()
        if not cmd:
            raise ValueError("command is required")
        cwd = path_arg(args["cwd"]) if args.get("cwd") else HOME
        return result_text(run_cmd(cmd, cwd=cwd, timeout=args.get("timeout", 30)))
    if name == "read_file":
        p = path_arg(args["path"])
        limit = max(1, min(int(args.get("max_bytes", 200000)), 200000))
        with p.open("rb") as f:
            data = f.read(limit)
        return result_text(data.decode("utf-8", errors="replace"))
    if name == "write_file":
        p = path_arg(args["path"])
        p.parent.mkdir(parents=True, exist_ok=True)
        content = str(args["content"])
        p.write_text(content, encoding="utf-8")
        os.chmod(p, 0o600)
        return result_text({"path": str(p), "bytes": len(content.encode("utf-8"))})
    if name == "list_dir":
        p = path_arg(args["path"])
        entries = [{"name": c.name, "type": "dir" if c.is_dir() else "file"} for c in sorted(p.iterdir(), key=lambda x: x.name)]
        return result_text(entries)
    raise ValueError(f"unknown tool: {name}")


def rpc(msg: dict, header_sid: str = "") -> tuple[dict | None, str]:
    if not isinstance(msg, dict):
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}, header_sid
    mid = msg.get("id")
    method = msg.get("method")
    params = msg.get("params")
    if params is None:
        params = {}
    elif not isinstance(params, dict):
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "params must be an object"}}, header_sid

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": mid,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mcp-session-journal-example", "version": "1.0.0"},
                "instructions": mcp_journal.INSTRUCTIONS,
            },
        }, JOURNAL.new_session_id()
    if method == "notifications/initialized" and mid is None:
        return None, header_sid
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}, header_sid
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": mcp_journal.augment_tools(TOOLS)}}, header_sid
    if method == "tools/call":
        if mid is None:
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "tools/call requires request id"}}, header_sid
        name = params.get("name")
        if not isinstance(name, str) or not name:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "tool name is required"}}, header_sid
        clean_args, why, session_override = mcp_journal.extract_meta_args(params.get("arguments"))
        if name in mcp_journal.JOURNAL_TOOL_NAMES:
            try:
                res = JOURNAL.handle_journal_tool(name, clean_args, header_sid=header_sid, session_override=session_override)
                return {"jsonrpc": "2.0", "id": mid, "result": result_text(res)}, header_sid
            except Exception as e:
                return {"jsonrpc": "2.0", "id": mid, "result": {"isError": True, **result_text(f"{type(e).__name__}: {e}")}}, header_sid
        try:
            locked_sid = JOURNAL.resolve_session_id(header_sid=header_sid, arg_sid=session_override)
        except ValueError as e:
            return {"jsonrpc": "2.0", "id": mid, "result": {"isError": True, **result_text(str(e))}}, header_sid
        t0 = time.monotonic()
        try:
            res = call_tool(name, clean_args)
        except Exception as e:
            res = {"isError": True, **result_text(f"{type(e).__name__}: {e}")}
        dur_ms = int((time.monotonic() - t0) * 1000)
        try:
            reminder = JOURNAL.record_event(locked_sid, name, clean_args, res, why=why, duration_ms=dur_ms)
            mcp_journal.attach_reminder(res, reminder)
        except Exception as je:
            print(f"[journal error] {type(je).__name__}: {je}", flush=True)
        return {"jsonrpc": "2.0", "id": mid, "result": res}, header_sid
    if mid is None:
        return None, header_sid
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}, header_sid


class Handler(BaseHTTPRequestHandler):
    server_version = "mcp-journal-example/1.0"

    def log_message(self, fmt, *args):
        print("%s %s" % (time.strftime("%H:%M:%S"), mcp_journal.redact_url_path(fmt % args)), flush=True)

    def authorized(self) -> bool:
        if not MCP_TOKEN:
            return True
        supplied = self.headers.get("Authorization", "")
        bearer = supplied[7:].strip() if supplied.lower().startswith("bearer ") else ""
        parts = [unquote(x) for x in self.path.split("/") if x]
        path_token = parts[1] if len(parts) >= 2 and parts[0] == "mcp" else ""
        return bearer == MCP_TOKEN or path_token == MCP_TOKEN

    def send_json(self, code: int, payload: dict, extra_headers: dict | None = None):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (extra_headers or {}).items():
            if v:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path.rstrip("/") == "/health":
            self.send_json(200, {"ok": True, "port": PORT})
            return
        self.send_json(401 if not self.authorized() else 405, {"error": "MCP uses POST"})

    def do_POST(self):
        if not self.authorized():
            self.send_json(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid Content-Length"}})
            return
        if length < 0 or length > MAX_RPC_BODY:
            self.send_json(413, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "request body too large"}})
            return
        try:
            msg = json.loads(self.rfile.read(length))
        except Exception as e:
            self.send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"parse error: {e}"}})
            return
        header_sid = (self.headers.get("Mcp-Session-Id") or "").strip()
        if header_sid:
            try:
                header_sid = mcp_journal.sanitize_session_id(header_sid)
            except ValueError:
                self.send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid Mcp-Session-Id"}})
                return
        out, resp_sid = rpc(msg, header_sid=header_sid)
        extra = {"Mcp-Session-Id": resp_sid} if resp_sid else None
        if out is None:
            self.send_response(202)
            if resp_sid:
                self.send_header("Mcp-Session-Id", resp_sid)
            self.end_headers()
        else:
            self.send_json(200, out, extra_headers=extra)


if __name__ == "__main__":
    os.umask(0o077)
    print(f"MCP server listening on http://{HOST}:{PORT}/mcp", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
