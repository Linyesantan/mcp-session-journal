#!/usr/bin/env python3
"""Transparent MCP HTTP proxy that adds multi-session black-box journaling
and incremental summaries to ANY upstream Streamable HTTP MCP server.

Usage:
    UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=8766 MCP_TOKEN="change-me" \
        python3 examples/http_mcp_proxy.py
"""
from __future__ import annotations

import http.client
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import mcp_journal

HOST = os.environ.get("MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_PORT", "8765"))
UPSTREAM_HOST = os.environ.get("UPSTREAM_HOST", "127.0.0.1")
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "8766"))
UPSTREAM_PATH = os.environ.get("UPSTREAM_PATH", "/mcp")
MCP_TOKEN = os.environ.get("MCP_TOKEN", "").strip()
UPSTREAM_TOKEN = os.environ.get("UPSTREAM_TOKEN", MCP_TOKEN).strip()

JOURNAL = mcp_journal.SessionJournal(source="mcp-proxy")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(mcp_journal.redact_url_path(fmt % args), flush=True)

    def authorized(self) -> bool:
        if not MCP_TOKEN:
            return True
        supplied = self.headers.get("Authorization", "")
        bearer = supplied[7:].strip() if supplied.lower().startswith("bearer ") else ""
        parts = [unquote(x) for x in urlsplit(self.path).path.split("/") if x]
        path_token = parts[1] if len(parts) == 2 and parts[0] == "mcp" else ""
        return bearer == MCP_TOKEN or path_token == MCP_TOKEN

    def reply(self, code: int, obj: dict, extra_headers: dict | None = None):
        raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
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
            self.reply(200, {"ok": True, "proxy": True, "upstream": f"{UPSTREAM_HOST}:{UPSTREAM_PORT}"})
        elif not self.authorized():
            self.reply(401, {"error": "unauthorized"})
        else:
            self.reply(405, {"error": "MCP uses POST"})

    def do_POST(self):
        if not self.authorized():
            self.reply(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.reply(400, {"error": "invalid Content-Length"})
            return
        if length < 0 or length > 4 * 1024 * 1024:
            self.reply(413, {"error": "request body too large"})
            return
        body = self.rfile.read(length)
        header_sid = (self.headers.get("Mcp-Session-Id") or "").strip()
        if header_sid:
            try:
                header_sid = mcp_journal.sanitize_session_id(header_sid)
            except ValueError:
                self.reply(400, {"error": "invalid Mcp-Session-Id"})
                return

        msg = None
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                msg = parsed
        except Exception:
            pass

        method = msg.get("method") if msg else None
        raw_params = msg.get("params") if msg else None
        params = raw_params if isinstance(raw_params, dict) else {}
        tool_name = None
        clean_args: dict = {}
        why = ""
        session_override = ""
        locked_sid = ""

        if method == "tools/call":
            if msg.get("id") is None:
                self.reply(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "tools/call requires request id"}})
                return
            tool_name = params.get("name")
            if not isinstance(tool_name, str) or not tool_name:
                self.reply(400, {"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32602, "message": "tool name is required"}})
                return
            clean_args, why, session_override = mcp_journal.extract_meta_args(params.get("arguments"))
            if tool_name in mcp_journal.JOURNAL_TOOL_NAMES:
                extra = {"Mcp-Session-Id": header_sid} if header_sid else None
                try:
                    res = JOURNAL.handle_journal_tool(
                        tool_name,
                        clean_args,
                        header_sid=header_sid,
                        session_override=session_override,
                    )
                    text = json.dumps(res, ensure_ascii=False, default=str)
                    self.reply(200, {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"content": [{"type": "text", "text": text}]}}, extra_headers=extra)
                except Exception as e:
                    self.reply(200, {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"isError": True, "content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}]}}, extra_headers=extra)
                return
            try:
                locked_sid = JOURNAL.resolve_session_id(header_sid=header_sid, arg_sid=session_override)
            except ValueError as e:
                self.reply(200, {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"isError": True, "content": [{"type": "text", "text": str(e)}]}})
                return
            orig_args = params.get("arguments")
            if isinstance(orig_args, dict) and (mcp_journal.META_WHY_KEY in orig_args or mcp_journal.META_SESSION_KEY in orig_args):
                fwd_msg = dict(msg)
                fwd_params = dict(params)
                fwd_params["arguments"] = clean_args
                fwd_msg["params"] = fwd_params
                body = json.dumps(fwd_msg, ensure_ascii=False).encode("utf-8")

        headers = {
            "Content-Type": self.headers.get("Content-Type", "application/json"),
            "Accept": "application/json",
        }
        if UPSTREAM_TOKEN:
            headers["Authorization"] = f"Bearer {UPSTREAM_TOKEN}"
        if header_sid:
            headers["Mcp-Session-Id"] = header_sid

        t0 = time.monotonic()
        conn = http.client.HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT, timeout=300)
        try:
            conn.request("POST", UPSTREAM_PATH, body=body, headers=headers)
            upstream = conn.getresponse()
            data = upstream.read(8 * 1024 * 1024 + 1)
            dur_ms = int((time.monotonic() - t0) * 1000)
            if len(data) > 8 * 1024 * 1024:
                self.reply(502, {"error": "upstream response too large"})
                return
            up_ct = upstream.getheader("Content-Type") or ""
            up_sid = (upstream.getheader("Mcp-Session-Id") or "").strip()

            if "json" in up_ct.lower() and data:
                try:
                    resp_obj = json.loads(data)
                except Exception:
                    resp_obj = None
                if isinstance(resp_obj, dict):
                    modified = False
                    if isinstance(resp_obj.get("result"), dict):
                        if method == "initialize":
                            existing = str(resp_obj["result"].get("instructions") or "").strip()
                            resp_obj["result"]["instructions"] = (
                                f"{existing}\n\n{mcp_journal.INSTRUCTIONS}" if existing else mcp_journal.INSTRUCTIONS
                            )
                            modified = True
                        elif method == "tools/list" and isinstance(resp_obj["result"].get("tools"), list):
                            resp_obj["result"]["tools"] = mcp_journal.augment_tools(resp_obj["result"]["tools"])
                            modified = True
                        elif method == "tools/call" and tool_name and locked_sid:
                            try:
                                reminder = JOURNAL.record_event(
                                    locked_sid, tool_name, clean_args, resp_obj["result"], why=why, duration_ms=dur_ms
                                )
                                if mcp_journal.attach_reminder(resp_obj["result"], reminder):
                                    modified = True
                            except Exception as je:
                                print(f"[journal error] {type(je).__name__}: {je}", flush=True)
                    elif method == "tools/call" and tool_name and locked_sid and "error" in resp_obj:
                        try:
                            err_res = {"isError": True, "content": [{"type": "text", "text": json.dumps(resp_obj["error"], ensure_ascii=False)}]}
                            JOURNAL.record_event(locked_sid, tool_name, clean_args, err_res, why=why, duration_ms=dur_ms)
                        except Exception as je:
                            print(f"[journal error] {type(je).__name__}: {je}", flush=True)
                    if modified:
                        data = json.dumps(resp_obj, ensure_ascii=False).encode("utf-8")

            self.send_response(upstream.status)
            if up_ct:
                self.send_header("Content-Type", up_ct)
            self.send_header("Content-Length", str(len(data)))
            if up_sid:
                self.send_header("Mcp-Session-Id", up_sid)
            cache_ctrl = upstream.getheader("Cache-Control")
            if cache_ctrl:
                self.send_header("Cache-Control", cache_ctrl)
            self.end_headers()
            self.wfile.write(data)
        except TimeoutError:
            dur_ms = int((time.monotonic() - t0) * 1000)
            if method == "tools/call" and tool_name and locked_sid:
                try:
                    JOURNAL.record_event(locked_sid, tool_name, clean_args, {"isError": True, "content": [{"type": "text", "text": "[upstream timeout]"}]}, why=why, duration_ms=dur_ms)
                except Exception:
                    pass
            self.reply(504, {"error": "upstream timeout"})
        except OSError as e:
            dur_ms = int((time.monotonic() - t0) * 1000)
            if method == "tools/call" and tool_name and locked_sid:
                try:
                    JOURNAL.record_event(locked_sid, tool_name, clean_args, {"isError": True, "content": [{"type": "text", "text": f"[upstream error] {e}"}]}, why=why, duration_ms=dur_ms)
                except Exception:
                    pass
            self.reply(502, {"error": f"upstream unavailable: {e}"})
        finally:
            conn.close()


if __name__ == "__main__":
    os.umask(0o077)
    print(f"MCP journal proxy http://{HOST}:{PORT} -> http://{UPSTREAM_HOST}:{UPSTREAM_PORT}{UPSTREAM_PATH}", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
