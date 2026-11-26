#!/usr/bin/env python3
"""Multi-session black-box journal & handoff helper for Termux MCP servers.

Stdlib-only (SQLite WAL), multi-process safe, zero external dependencies.
Provides:
  - High-entropy session ID generation
  - Automatic tool-call recording with recursive secret redaction & safe truncation
  - Single-hop client_sid -> task_id binding in SQLite transactions
  - 3 MCP tools: list_sessions, resume, task_note
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote

DEFAULT_ROOT = Path(
    os.environ.get("MCP_JOURNAL_DIR", str(Path.home() / ".local/state/mcp-sessions"))
).expanduser()
RETENTION_DAYS = int(os.environ.get("MCP_JOURNAL_RETENTION_DAYS", "14"))
MAX_EVENTS_PER_SESSION = int(os.environ.get("MCP_JOURNAL_MAX_EVENTS", "500"))
MAX_ACTIVE_SESSIONS = int(os.environ.get("MCP_JOURNAL_MAX_SESSIONS", "200"))
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
RESERVED_NAMES = {".", "..", "aliases.json", "journal.db", "journal.db-wal", "journal.db-shm"}

META_WHY_KEY = "_journal_why"
META_SESSION_KEY = "_journal_session"
JOURNAL_TOOL_NAMES = {"list_sessions", "resume", "task_note", "append_summary"}
SHELL_TOOLS = {"run", "rish", "termux_shell", "termux_api"}
MAX_SUMMARY_FILE_BYTES = 128 * 1024
# Stateless clients (one HTTP connection / initialize per tool call) get a fresh Mcp-Session-Id
# every call. Within this idle window, a new connection from the same client fingerprint
# continues the session that fingerprint last used instead of starting a one-step session.
STICKY_SECONDS = int(os.environ.get("MCP_JOURNAL_STICKY_SECONDS", "7200"))
NEW_SESSION_WORDS = {"new", "fresh", "none"}


def client_fingerprint(*parts: Any) -> str:
    raw = "|".join(str(p or "").strip().lower() for p in parts)
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:20]


# Client labels are case-insensitive (normalised to lower case) and global to one journal DB:
# every client configured with the same label shares sticky sessions.
LABEL_RE = re.compile(r"^(?!\.{1,2}$)[A-Za-z0-9._-]{1,40}$")
LOOPBACK_ADDRS = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}


class RouteError(ValueError):
    """Malformed MCP route or client label; the server should answer 400."""


def parse_mcp_route(raw_path: str, headers: Any = None, prefix: str = "mcp") -> tuple[str, str]:
    """Strictly parse `/<prefix>[/<token>[/<label>]][?client=<label>]`.

    Returns (path_token, label). No percent-encoding or empty segments are accepted in the
    path, so what authentication compares is exactly what the access log redacts.
    The label may come from the path, an `X-MCP-Client` header, or a single `client` query
    parameter; an invalid, repeated, or conflicting label raises RouteError instead of
    silently falling back to the IP/User-Agent fingerprint.
    """
    path, _, query = str(raw_path or "").partition("?")
    if "%" in path or not path.startswith("/"):
        raise RouteError("malformed path")
    segs = path[1:].split("/")
    if len(segs) > 1 and segs[-1] == "":
        segs = segs[:-1]  # tolerate one trailing slash
    if not segs or segs[0] != prefix or any(x == "" for x in segs) or len(segs) > 3:
        raise RouteError("unknown route")
    tok = segs[1] if len(segs) >= 2 else ""
    found: list[str] = []
    if len(segs) == 3:
        found.append(segs[2])
    if headers is not None:
        hv = headers.get_all("X-MCP-Client") if hasattr(headers, "get_all") else (
            [headers.get("X-MCP-Client")] if headers.get("X-MCP-Client") is not None else None)
        hv = [str(x).strip() for x in (hv or [])]
        if len(hv) > 1:
            raise RouteError("repeated X-MCP-Client header")
        found.extend(hv)
    if query:
        qv = []
        for kv in query.split("&"):
            k, _, v = kv.partition("=")
            if unquote(k) == "client":
                qv.append(unquote(v).strip())
        if len(qv) > 1:
            raise RouteError("repeated client query parameter")
        found.extend(qv)
    labels = []
    for cand in found:
        if not LABEL_RE.fullmatch(cand):
            raise RouteError("invalid client label")
        labels.append(cand.lower())
    if len(set(labels)) > 1:
        raise RouteError("conflicting client labels")
    return tok, (labels[0] if labels else "")


def request_fingerprint(label: str, headers: Any, client_addr: str) -> tuple[str, str]:
    """Fingerprint for sticky sessions: the label if given, else IP + User-Agent.

    Forwarded-IP headers are trusted only when the TCP peer is loopback (a local tunnel such
    as cloudflared); otherwise the socket address is used.
    """
    if label:
        # No "|" in this encoding, so it can never equal an ip|ua fingerprint input.
        return client_fingerprint("label\x00" + label), f"label={label}"
    ip = str(client_addr or "")
    if ip in LOOPBACK_ADDRS and headers is not None:
        fwd = (headers.get("CF-Connecting-IP") or (headers.get("X-Forwarded-For") or "").split(",")[0]).strip()
        ip = fwd or ip
    ua = (headers.get("User-Agent") if headers is not None else "") or ""
    ua = ua.strip()
    return client_fingerprint(ip, ua), f"ip={ip} ua={ua[:120]}"


def safe_log_line(command: str, path: str, code: Any) -> str:
    """Access-log line without any path/query content (tokens can hide in odd encodings)."""
    seg = str(path or "").lstrip("/").split("/", 1)[0].split("?", 1)[0]
    route = seg if seg in {"mcp", "files", "health"} else "?"
    return f"{time.strftime('%H:%M:%S')} {str(command or '')[:10]} /{route} {code}"


TRIVIAL_SQL = (
    "(steps <= 1 AND summary_count = 0 AND title = '' AND goal = '' AND next = '' AND notes = '' "
    "AND done_json IN ('', '[]') AND blockers_json IN ('', '[]'))"
)


def _is_trivial_row(r: Any) -> bool:
    return (
        int(r["steps"] or 0) <= 1
        and int(r["summary_count"] or 0) == 0
        and not (r["title"] or r["goal"] or r["next"] or r["notes"])
        and (r["done_json"] or "[]") == "[]"
        and (r["blockers_json"] or "[]") == "[]"
    )

INSTRUCTIONS = (
    "This MCP server maintains a per-session black-box journal and an incremental summary file "
    "so a new AI can seamlessly take over if your session hits a quota limit. "
    f"1) Pass the optional `{META_WHY_KEY}` argument on tool calls to note brief intent. "
    "2) IMPORTANT — Incremental summary habit: at task start and after every milestone or every ~10 tool calls, "
    "call `append_summary` to append a concise 2-4 line incremental summary (what was done, "
    "key findings/paths, and next step) to this session's dedicated markdown summary file. "
    "Use `task_note` to set/update the overall title, goal, or mark status='done'. "
    "3) If the user asks you to continue an interrupted task, call `list_sessions` first and then "
    "`resume` with that `session_id` (attach=true by default) to read the session's incremental "
    "summary file plus any recent unsummarized tool calls. "
    "4) Sessions are sticky per client: clients that reconnect for every call keep landing in the same "
    "session (idle window applies), and after `resume` all later calls from your client continue there. "
    "Call `resume` with session_id='new' to start a fresh session."
)

JOURNAL_TOOLS: list[dict[str, Any]] = [
    {
        "name": "list_sessions",
        "description": (
            "List recent MCP sessions with their title, goal, status, step count, summary count, "
            "last tool call, and whether the last step succeeded. Use this to find an interrupted task to resume."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "description": "Max sessions to return (default 15)"},
                "include_done": {"type": "boolean", "description": "Include sessions marked done (default false)"},
                "include_trivial": {"type": "boolean", "description": "Include throwaway one-step sessions with no title/summary (default false)"},
            },
        },
    },
    {
        "name": "resume",
        "description": (
            "Load a session's handoff state: its dedicated incremental summary markdown file, task note, "
            "touched files, and recent tool-call history (including any steps after the last summary). "
            "With attach=true (default on active sessions), subsequent tool calls and summaries from this "
            "client continue in that session, even across reconnects. Pass reopen=true to re-activate a done session. "
            "Pass session_id='new' to detach and start a fresh session."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Target session_id; 'new' starts a fresh session; omit to resume the most recent meaningful active session"},
                "last_n": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Number of recent tool calls to include (default 20)"},
                "attach": {"type": "boolean", "description": "Bind current MCP connection to this session (default true)"},
                "reopen": {"type": "boolean", "description": "If target session is done, reopen it to active before attaching (default false)"},
            },
        },
    },
    {
        "name": "append_summary",
        "description": (
            "Append an incremental summary entry (2-4 lines: what was done, key findings/errors, next step) "
            "to this session's dedicated markdown summary file. Call this at task start, after each milestone, "
            "or every ~10 tool calls so a new AI can instantly understand the progress if your session runs out of quota."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "Concise incremental summary of progress and findings since the last entry"},
                "next_step": {"type": "string", "description": "Optional concrete next step (also updates task_note.next)"},
                "session_id": {"type": "string", "description": "Optional session_id override"},
            },
            "required": ["summary"],
        },
    },
    {
        "name": "task_note",
        "description": (
            "Create or update the structured handoff note for the current (or specified) session: "
            "title, goal, done items, blockers, next step, notes, or mark status='done'."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Optional session_id override"},
                "title": {"type": "string", "description": "Short task title"},
                "goal": {"type": "string", "description": "Overall task goal"},
                "done": {"type": "array", "items": {"type": "string"}, "description": "Replace completed items list"},
                "add_done": {"type": "string", "description": "Append a single completed item"},
                "blockers": {"type": "array", "items": {"type": "string"}, "description": "Current blockers or open errors"},
                "next": {"type": "string", "description": "Concrete next step"},
                "notes": {"type": "string", "description": "Additional key findings or paths"},
                "status": {"type": "string", "enum": ["active", "done"], "description": "Session status"},
            },
        },
    },
]

_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|auth(orization)?|cookie|credential|private[_-]?key|sshpass)"
)

_SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s\"']+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{12,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(sshpass|password|passwd|secret|token|api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]?[^\s'\"`]+['\"]?"), r"\1=[REDACTED]"),
    (re.compile(r"\b(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"), "[REDACTED]"),
    (re.compile(r"(/(?:mcp|files)/)[A-Za-z0-9._~%-]{8,}"), r"\1[REDACTED]"),
    (re.compile(r"([?&](?:token|key|api_key|apikey|secret|password|auth)=)[^&\s]+", re.IGNORECASE), r"\1[REDACTED]"),
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def sanitize_session_id(raw: str | None) -> str:
    if not raw:
        return ""
    s = str(raw).strip()
    if not s or s in RESERVED_NAMES or not SESSION_ID_RE.fullmatch(s):
        raise ValueError(f"invalid session_id: {raw!r}")
    return s


def redact_url_path(path: str) -> str:
    # Drop everything after /mcp/ or /files/ (token, label, query); any percent-encoded or
    # query-bearing path is redacted whole, since a token could hide in its encoding.
    out = re.sub(r"(?i)\S*%[0-9a-f]{2}\S*", "[REDACTED]", path or "")
    out = re.sub(r"(?i)(/(?:mcp|files)/)\S*", r"\1[REDACTED]", out)
    return re.sub(r"\?\S*", "?[REDACTED]", out)


def redact_text(text: str) -> str:
    out = text
    for pat, repl in _SECRET_PATTERNS:
        out = pat.sub(repl, out)
    return out


def truncate_text(text: str, head: int = 500, tail: int = 1000) -> str:
    text = redact_text(text)
    head = max(0, int(head))
    tail = max(0, int(tail))
    limit = head + tail
    if limit == 0:
        return ""
    if len(text) <= limit:
        return text
    omitted = len(text) - limit
    if tail == 0:
        return f"{text[:head]}... [truncated {omitted} chars]"
    if head == 0:
        return f"[truncated {omitted} chars] ...{text[-tail:]}"
    return f"{text[:head]}\n... [truncated {omitted} chars] ...\n{text[-tail:]}"


def _redact_value(val: Any, *, depth: int = 0) -> Any:
    if depth > 4:
        return "[nested]"
    if isinstance(val, str):
        return truncate_text(val, head=300, tail=150)
    if isinstance(val, dict):
        out: dict[str, Any] = {}
        for idx, (k, v) in enumerate(val.items()):
            if idx >= 30:
                out["_truncated_keys"] = len(val) - 30
                break
            ks = str(k)
            if _SENSITIVE_KEY_RE.search(ks):
                out[ks] = "[REDACTED]"
            else:
                out[ks] = _redact_value(v, depth=depth + 1)
        return out
    if isinstance(val, list):
        items = [_redact_value(x, depth=depth + 1) for x in val[:20]]
        if len(val) > 20:
            items.append(f"... [{len(val) - 20} more items]")
        return items
    return val


def augment_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a copy of tools with namespaced optional journal args and the 3 journal tools."""
    out: list[dict[str, Any]] = []
    existing_names = set()
    for t in tools:
        if not isinstance(t, dict):
            continue
        existing_names.add(t.get("name"))
        t_copy = json.loads(json.dumps(t))
        schema = t_copy.setdefault("inputSchema", {"type": "object", "properties": {}})
        if isinstance(schema, dict) and schema.get("type") == "object":
            props = schema.setdefault("properties", {})
            if isinstance(props, dict):
                if META_WHY_KEY not in props:
                    props[META_WHY_KEY] = {
                        "type": "string",
                        "description": "Optional brief intent for the session journal (helps handoff).",
                    }
                if META_SESSION_KEY not in props:
                    props[META_SESSION_KEY] = {
                        "type": "string",
                        "description": "Optional session_id override when client does not send Mcp-Session-Id.",
                    }
        out.append(t_copy)
    for jt in JOURNAL_TOOLS:
        if jt["name"] not in existing_names:
            out.append(jt)
    return out


def extract_meta_args(args: Any) -> tuple[dict[str, Any], str, str]:
    """Split only namespaced journal args (`_journal_why`, `_journal_session`) from tool arguments."""
    if not isinstance(args, dict):
        return {}, "", ""
    clean = dict(args)
    raw_why = clean.pop(META_WHY_KEY, None)
    raw_session = clean.pop(META_SESSION_KEY, None)
    why = str(raw_why).strip()[:300] if isinstance(raw_why, str) else ""
    session_override = str(raw_session).strip() if isinstance(raw_session, str) else ""
    return clean, why, session_override


def summarize_args(tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Compact & recursively redact tool arguments for storage."""
    out: dict[str, Any] = {}
    for k, v in (args or {}).items():
        ks = str(k)
        if _SENSITIVE_KEY_RE.search(ks):
            out[ks] = "[REDACTED]"
        elif ks == "content" and isinstance(v, str):
            out["content_bytes"] = len(v.encode("utf-8", errors="replace"))
            out["content_preview"] = truncate_text(v, head=180, tail=0)
        else:
            out[ks] = _redact_value(v, depth=0)
    return out


def summarize_call_label(tool_name: str, args: dict[str, Any]) -> str:
    for key in ("command", "cmd", "path", "text", "service"):
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            line = redact_text(val.strip().splitlines()[0])
            return f"{tool_name}: {line[:120]}"
    return tool_name


def extract_touched_path(tool_name: str, args: dict[str, Any]) -> str | None:
    if any(tok in tool_name.lower() for tok in ("write", "edit", "patch", "delete", "remove", "mkdir")):
        for key in ("path", "file_path", "target", "destination"):
            val = args.get(key)
            if isinstance(val, str) and val.strip():
                return redact_text(val.strip())[:300]
    return None


def attach_reminder(result: Any, reminder: str | None) -> bool:
    """Append a non-destructive reminder text block to an MCP tool result dict. Returns True if modified."""
    if not reminder or not isinstance(result, dict):
        return False
    content = result.get("content")
    if not isinstance(content, list):
        return False
    result["content"] = list(content) + [{"type": "text", "text": reminder}]
    return True


def extract_result_info(tool_name: str, result: Any) -> tuple[bool, int | None, str]:
    """Inspect an MCP tool result dict and return (ok, exit_code, output_summary)."""
    if not isinstance(result, dict):
        return True, None, truncate_text(str(result))
    is_error = bool(result.get("isError"))
    texts: list[str] = []
    for item in result.get("content") or []:
        if isinstance(item, dict) and item.get("type") == "text":
            texts.append(str(item.get("text", "")))
    joined = "\n".join(texts).strip()
    code: int | None = None
    output = joined
    if joined.startswith("{") and joined.endswith("}"):
        try:
            parsed = json.loads(joined)
            if isinstance(parsed, dict):
                if tool_name in SHELL_TOOLS and isinstance(parsed.get("code"), int):
                    code = parsed["code"]
                    if code != 0:
                        is_error = True
                if isinstance(parsed.get("output"), str):
                    output = parsed["output"]
        except Exception:
            pass
    return (not is_error), code, truncate_text(output)


class SessionJournal:
    def __init__(self, root: Path | None = None, source: str = "mcp"):
        self.root = (root or DEFAULT_ROOT).expanduser()
        self.source = source
        self._local_lock = threading.RLock()
        self._last_prune = 0.0
        self.root.mkdir(parents=True, exist_ok=True)
        self.summaries_dir = self.root / "summaries"
        self.summaries_dir.mkdir(parents=True, exist_ok=True)
        for d in (self.root, self.summaries_dir):
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass
        self.db_path = self.root / "journal.db"
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        with self._local_lock:
            conn = self._connect()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS sessions (
                        session_id TEXT PRIMARY KEY,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        updated_ts REAL NOT NULL,
                        status TEXT NOT NULL DEFAULT 'active',
                        source TEXT NOT NULL DEFAULT '',
                        title TEXT NOT NULL DEFAULT '',
                        goal TEXT NOT NULL DEFAULT '',
                        done_json TEXT NOT NULL DEFAULT '[]',
                        blockers_json TEXT NOT NULL DEFAULT '[]',
                        next TEXT NOT NULL DEFAULT '',
                        notes TEXT NOT NULL DEFAULT '',
                        steps INTEGER NOT NULL DEFAULT 0,
                        files_json TEXT NOT NULL DEFAULT '[]',
                        last_tool TEXT NOT NULL DEFAULT '',
                        last_summary TEXT NOT NULL DEFAULT '',
                        last_ok INTEGER NOT NULL DEFAULT 1,
                        summary_count INTEGER NOT NULL DEFAULT 0,
                        last_summary_step INTEGER NOT NULL DEFAULT 0
                    );
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL,
                        seq INTEGER NOT NULL,
                        ts TEXT NOT NULL,
                        source TEXT NOT NULL,
                        tool TEXT NOT NULL,
                        why TEXT NOT NULL DEFAULT '',
                        args_json TEXT NOT NULL DEFAULT '{}',
                        ok INTEGER NOT NULL DEFAULT 1,
                        code INTEGER,
                        duration_ms INTEGER NOT NULL DEFAULT 0,
                        output TEXT NOT NULL DEFAULT ''
                    );
                    CREATE INDEX IF NOT EXISTS idx_events_session_seq ON events(session_id, seq);
                    CREATE TABLE IF NOT EXISTS bindings (
                        client_sid TEXT PRIMARY KEY,
                        target_sid TEXT NOT NULL,
                        updated_ts REAL NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS client_fps (
                        client_sid TEXT PRIMARY KEY,
                        fp TEXT NOT NULL,
                        info TEXT NOT NULL DEFAULT '',
                        updated_ts REAL NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS client_links (
                        fp TEXT PRIMARY KEY,
                        target_sid TEXT NOT NULL,
                        updated_ts REAL NOT NULL
                    );
                    """
                )
                cols = {r["name"] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()}
                if "summary_count" not in cols:
                    conn.execute("ALTER TABLE sessions ADD COLUMN summary_count INTEGER NOT NULL DEFAULT 0")
                if "last_summary_step" not in cols:
                    conn.execute("ALTER TABLE sessions ADD COLUMN last_summary_step INTEGER NOT NULL DEFAULT 0")
            finally:
                conn.close()
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass

    def new_session_id(self) -> str:
        stamp = datetime.now().strftime("%y%m%d-%H%M")
        return f"{stamp}-{secrets.token_hex(6)}"

    def _summary_path(self, sid: str) -> Path:
        return self.summaries_dir / f"{sanitize_session_id(sid)}.md"

    def _read_summary_md(self, sid: str, max_chars: int = 8000) -> str:
        p = self._summary_path(sid)
        if not p.is_file():
            return ""
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(p), flags)
            with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            return ""
        if len(text) <= max_chars:
            return text
        return f"... [earlier summary truncated, showing last {max_chars} chars] ...\n" + text[-max_chars:]

    def _delete_summary_files(self, sids: list[str]) -> None:
        for sid in sids:
            try:
                self._summary_path(sid).unlink(missing_ok=True)
            except Exception:
                pass

    def _row_to_meta(self, row: sqlite3.Row) -> dict[str, Any]:
        sid = row["session_id"]
        steps = int(row["steps"])
        last_sum_step = int(row["last_summary_step"]) if "last_summary_step" in row.keys() else 0
        sum_count = int(row["summary_count"]) if "summary_count" in row.keys() else 0
        return {
            "session_id": sid,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "status": row["status"],
            "source": row["source"],
            "title": row["title"],
            "goal": row["goal"],
            "done": json.loads(row["done_json"] or "[]"),
            "blockers": json.loads(row["blockers_json"] or "[]"),
            "next": row["next"],
            "notes": row["notes"],
            "steps": steps,
            "summary_count": sum_count,
            "steps_since_summary": max(0, steps - last_sum_step),
            "summary_file": str(self._summary_path(sid)),
            "files_touched": json.loads(row["files_json"] or "[]"),
            "last_tool": row["last_tool"],
            "last_summary": row["last_summary"],
            "last_ok": bool(row["last_ok"]),
        }

    @staticmethod
    def _rollback(conn: sqlite3.Connection) -> None:
        if conn.in_transaction:
            conn.execute("ROLLBACK")

    def register_client(self, client_sid: str, fp: str, info: str = "") -> None:
        """Remember which client fingerprint opened this Mcp-Session-Id (called on initialize)."""
        if not client_sid or not fp:
            return
        with self._local_lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO client_fps (client_sid, fp, info, updated_ts) VALUES (?, ?, ?, ?)
                    ON CONFLICT(client_sid) DO UPDATE SET fp=excluded.fp, info=excluded.info, updated_ts=excluded.updated_ts
                    """,
                    (sanitize_session_id(client_sid), fp, redact_text(info)[:300], time.time()),
                )
            finally:
                conn.close()

    def _fp_for(self, conn: sqlite3.Connection, client_sid: str, fp: str = "") -> str:
        if client_sid:
            row = conn.execute("SELECT fp FROM client_fps WHERE client_sid = ?", (client_sid,)).fetchone()
            if row and row["fp"]:
                return row["fp"]
        return fp or ""

    def _active(self, conn: sqlite3.Connection, sid: str) -> bool:
        row = conn.execute("SELECT status FROM sessions WHERE session_id = ?", (sid,)).fetchone()
        return row is not None and row["status"] != "done"

    def _touch_link(self, conn: sqlite3.Connection, fp: str, sid: str) -> None:
        """Refresh this fingerprint's sticky link for an ordinary call.

        A live link to a *different* active session (the client switched with `resume` /
        `resume new` on another connection) is left alone, so an older connection cannot
        silently switch the client back.
        """
        if not fp or not sid or sid == "default" or STICKY_SECONDS <= 0:
            return
        link = conn.execute("SELECT target_sid, updated_ts FROM client_links WHERE fp = ?", (fp,)).fetchone()
        if (
            link is not None
            and link["target_sid"] != sid
            and time.time() - float(link["updated_ts"]) <= STICKY_SECONDS
            and self._active(conn, link["target_sid"])
        ):
            return
        self._link_fp(conn, fp, sid)

    def _link_fp(self, conn: sqlite3.Connection, fp: str, target: str) -> None:
        if not fp or not target or STICKY_SECONDS <= 0:
            return
        conn.execute(
            """
            INSERT INTO client_links (fp, target_sid, updated_ts) VALUES (?, ?, ?)
            ON CONFLICT(fp) DO UPDATE SET target_sid=excluded.target_sid, updated_ts=excluded.updated_ts
            """,
            (fp, target, time.time()),
        )

    def _bind(self, conn: sqlite3.Connection, client_sid: str, target: str) -> None:
        if not client_sid:
            return
        if client_sid == target:
            conn.execute("DELETE FROM bindings WHERE client_sid = ?", (client_sid,))
            return
        conn.execute(
            """
            INSERT INTO bindings (client_sid, target_sid, updated_ts) VALUES (?, ?, ?)
            ON CONFLICT(client_sid) DO UPDATE SET target_sid=excluded.target_sid, updated_ts=excluded.updated_ts
            """,
            (client_sid, target, time.time()),
        )

    def _resolve_in_conn(self, conn: sqlite3.Connection, header_sid: str = "", arg_sid: str = "", fp: str = "") -> str:
        # Priority: explicit arg_sid > bound Mcp-Session-Id (target still active) > sticky client
        # link > raw Mcp-Session-Id (a fresh session if that one is done) > new session for a
        # headerless client with a fingerprint > "default" (legacy anonymous callers).
        if arg_sid:
            return sanitize_session_id(arg_sid)
        raw = sanitize_session_id(header_sid) if header_sid else ""
        if raw:
            row = conn.execute("SELECT target_sid FROM bindings WHERE client_sid = ?", (raw,)).fetchone()
            if row and row["target_sid"]:
                target = sanitize_session_id(row["target_sid"])
                if self._active(conn, target):
                    return target
                # Target finished or pruned: the binding no longer routes anything.
                conn.execute("DELETE FROM bindings WHERE client_sid = ?", (raw,))
        fp = self._fp_for(conn, raw, fp)
        if fp and STICKY_SECONDS > 0:
            link = conn.execute("SELECT target_sid, updated_ts FROM client_links WHERE fp = ?", (fp,)).fetchone()
            own = conn.execute("SELECT steps, status FROM sessions WHERE session_id = ?", (raw,)).fetchone() if raw else None
            # A connection may follow the client's link if it has no history of its own yet,
            # or its own session is finished.
            fresh_conn = own is None or int(own["steps"] or 0) == 0 or own["status"] == "done"
            if link and fresh_conn and link["target_sid"] != raw and time.time() - float(link["updated_ts"]) <= STICKY_SECONDS:
                target = sanitize_session_id(link["target_sid"])
                if self._active(conn, target):
                    if raw:
                        self._bind(conn, raw, target)
                    return target
        if raw:
            if conn.execute("SELECT 1 FROM sessions WHERE session_id = ? AND status = 'done'", (raw,)).fetchone():
                fresh = self.new_session_id()
                self._bind(conn, raw, fresh)
                return fresh
            return raw
        if fp and STICKY_SECONDS > 0:
            return self.new_session_id()
        return "default"

    def resolve_session_id(self, header_sid: str | None = None, arg_sid: str | None = None, fp: str = "") -> str:
        """Resolve the session a call belongs to, creating its row and refreshing the client's
        sticky link in one IMMEDIATE transaction (safe across processes sharing the DB)."""
        clean_header = sanitize_session_id(header_sid) if header_sid else ""
        with self._local_lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                sid = self._resolve_in_conn(conn, clean_header, arg_sid or "", fp)
                if sid != "default":
                    self._ensure_session_row(conn, sid, self.source)
                if clean_header:
                    conn.execute("UPDATE client_fps SET updated_ts = ? WHERE client_sid = ?", (time.time(), clean_header))
                # Explicit overrides (task_note on another session, _journal_session) must not
                # re-point this client's sticky session.
                if not arg_sid:
                    self._touch_link(conn, self._fp_for(conn, clean_header, fp), sid)
                conn.execute("COMMIT")
                return sid
            except Exception:
                self._rollback(conn)
                raise
            finally:
                conn.close()

    def _maybe_prune(self, conn: sqlite3.Connection) -> None:
        now = time.time()
        if now - self._last_prune < 3600:
            return
        self._last_prune = now
        if RETENTION_DAYS > 0:
            cutoff = now - RETENTION_DAYS * 86400
            old_ids = [
                r["session_id"]
                for r in conn.execute("SELECT session_id FROM sessions WHERE updated_ts < ?", (cutoff,)).fetchall()
            ]
            if old_ids:
                placeholders = ",".join("?" for _ in old_ids)
                conn.execute(f"DELETE FROM events WHERE session_id IN ({placeholders})", old_ids)
                conn.execute(f"DELETE FROM sessions WHERE session_id IN ({placeholders})", old_ids)
                conn.execute(f"DELETE FROM bindings WHERE target_sid IN ({placeholders})", old_ids)
                conn.execute(f"DELETE FROM client_links WHERE target_sid IN ({placeholders})", old_ids)
                self._delete_summary_files(old_ids)
            conn.execute("DELETE FROM client_fps WHERE updated_ts < ?", (cutoff,))
            conn.execute("DELETE FROM bindings WHERE updated_ts < ?", (cutoff,))
        # Keep total sessions bounded
        total = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        if total > MAX_ACTIVE_SESSIONS:
            excess = total - MAX_ACTIVE_SESSIONS
            drop_ids = [
                r["session_id"]
                for r in conn.execute(
                    "SELECT session_id FROM sessions ORDER BY updated_ts ASC LIMIT ?", (excess,)
                ).fetchall()
            ]
            if drop_ids:
                placeholders = ",".join("?" for _ in drop_ids)
                conn.execute(f"DELETE FROM events WHERE session_id IN ({placeholders})", drop_ids)
                conn.execute(f"DELETE FROM sessions WHERE session_id IN ({placeholders})", drop_ids)
                conn.execute(f"DELETE FROM bindings WHERE target_sid IN ({placeholders})", drop_ids)
                conn.execute(f"DELETE FROM client_links WHERE target_sid IN ({placeholders})", drop_ids)
                self._delete_summary_files(drop_ids)
        # Sticky links are useless once their idle window has passed or their target is gone.
        conn.execute("DELETE FROM client_links WHERE updated_ts < ?", (now - max(STICKY_SECONDS, 0),))
        conn.execute("DELETE FROM client_links WHERE target_sid NOT IN (SELECT session_id FROM sessions)")
        conn.execute("DELETE FROM bindings WHERE target_sid NOT IN (SELECT session_id FROM sessions)")

    def _ensure_session_row(self, conn: sqlite3.Connection, sid: str, source: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (sid,)).fetchone()
        if row is not None:
            return row
        now = _now_iso()
        now_ts = time.time()
        conn.execute(
            """
            INSERT INTO sessions (session_id, created_at, updated_at, updated_ts, status, source)
            VALUES (?, ?, ?, ?, 'active', ?)
            """,
            (sid, now, now, now_ts, source),
        )
        return conn.execute("SELECT * FROM sessions WHERE session_id = ?", (sid,)).fetchone()

    def record_event(
        self,
        session_id: str,
        tool_name: str,
        args: dict[str, Any],
        result: Any,
        *,
        why: str = "",
        duration_ms: int = 0,
        source: str | None = None,
    ) -> str | None:
        if tool_name in JOURNAL_TOOL_NAMES:
            return None
        sid = sanitize_session_id(session_id)
        src = source or self.source
        ok, code, output = extract_result_info(tool_name, result)
        args_json = json.dumps(summarize_args(tool_name, args), ensure_ascii=False)
        clean_why = redact_text(why)[:300] if why else ""
        label = summarize_call_label(tool_name, args)
        touched = extract_touched_path(tool_name, args)
        now = _now_iso()
        now_ts = time.time()

        with self._local_lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                self._maybe_prune(conn)
                row = self._ensure_session_row(conn, sid, src)
                seq = int(row["steps"]) + 1
                sum_count = int(row["summary_count"])
                last_sum_step = int(row["last_summary_step"])
                goal = str(row["goal"] or "")
                files = json.loads(row["files_json"] or "[]")
                if touched:
                    if touched in files:
                        files.remove(touched)
                    files.append(touched)
                    files = files[-50:]
                title = row["title"] or (clean_why[:80] if clean_why else "")

                conn.execute(
                    """
                    INSERT INTO events (session_id, seq, ts, source, tool, why, args_json, ok, code, duration_ms, output)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (sid, seq, now, src, tool_name, clean_why, args_json, 1 if ok else 0, code, int(duration_ms), output),
                )
                if seq > MAX_EVENTS_PER_SESSION and seq % 25 == 0:
                    conn.execute(
                        """
                        DELETE FROM events
                        WHERE session_id = ? AND seq <= ?
                        """,
                        (sid, seq - MAX_EVENTS_PER_SESSION),
                    )
                conn.execute(
                    """
                    UPDATE sessions
                    SET updated_at = ?, updated_ts = ?, steps = ?, files_json = ?,
                        title = ?, last_tool = ?, last_summary = ?, last_ok = ?
                    WHERE session_id = ?
                    """,
                    (now, now_ts, seq, json.dumps(files, ensure_ascii=False), title, tool_name, label, 1 if ok else 0, sid),
                )
                conn.execute("COMMIT")
                steps_since = max(0, seq - last_sum_step)
                if seq == 1 and sum_count == 0 and not goal:
                    return (
                        f"[Journal Reminder] Session `{sid}` started (step #1). "
                        "Briefly call `task_note` or `append_summary` to record your goal/progress "
                        "in this session's summary file so a new AI can resume if quota runs out."
                    )
                if steps_since > 0 and steps_since % 10 == 0:
                    return (
                        f"[Journal Reminder] {steps_since} tool calls since the last summary in session `{sid}`. "
                        "Please call `append_summary(summary, next_step)` to write a concise incremental summary."
                    )
                return None
            except Exception:
                self._rollback(conn)
                raise
            finally:
                conn.close()

    def list_sessions(self, *, limit: int = 15, include_done: bool = False, include_trivial: bool = False) -> dict[str, Any]:
        limit = max(1, min(int(limit or 15), 50))
        with self._local_lock:
            conn = self._connect()
            try:
                where = "1=1" if include_done else "status != 'done'"
                hidden = 0
                if not include_trivial:
                    hidden = conn.execute(f"SELECT COUNT(*) FROM sessions WHERE {where} AND {TRIVIAL_SQL}").fetchone()[0]
                    where += f" AND NOT {TRIVIAL_SQL}"
                rows = conn.execute(
                    f"SELECT * FROM sessions WHERE {where} ORDER BY updated_ts DESC LIMIT ?", (limit,)
                ).fetchall()
                sessions = [
                    {
                        "session_id": r["session_id"],
                        "status": r["status"],
                        "source": r["source"],
                        "title": r["title"],
                        "goal": r["goal"],
                        "next": r["next"],
                        "steps": r["steps"],
                        "summary_count": r["summary_count"],
                        "updated_at": r["updated_at"],
                        "last_summary": r["last_summary"],
                        "last_ok": bool(r["last_ok"]),
                    }
                    for r in rows
                ]
                out = {"count": len(sessions), "sessions": sessions}
                if hidden:
                    out["hidden_trivial"] = hidden
                    out["hint"] = "One-step untitled sessions are hidden; pass include_trivial=true to see them."
                return out
            finally:
                conn.close()

    def append_summary(self, session_id: str, summary: str, *, next_step: str = "") -> dict[str, Any]:
        sid = sanitize_session_id(session_id)
        text = redact_text(str(summary or "").strip())[:4000]
        if not text:
            raise ValueError("summary is required and cannot be empty")
        clean_next = redact_text(str(next_step or "").strip())[:1000]
        now = _now_iso()
        now_ts = time.time()
        sp = self._summary_path(sid)

        with self._local_lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._ensure_session_row(conn, sid, self.source)
                steps = int(row["steps"])
                new_count = int(row["summary_count"]) + 1
                is_new_file = not sp.exists()

                entry_lines = []
                if is_new_file:
                    title = row["title"] or sid
                    entry_lines.append(f"# Session Summary: {title} ({sid})\n")
                entry_lines.append(f"\n## [{new_count}] {now} (after step #{steps})\n{text}\n")
                if clean_next:
                    entry_lines.append(f"**Next:** {clean_next}\n")
                chunk = "".join(entry_lines)

                flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(str(sp), flags, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(chunk)

                # Trim summary file if it exceeds hard cap
                try:
                    if sp.stat().st_size > MAX_SUMMARY_FILE_BYTES:
                        raw = sp.read_bytes()
                        kept = b"# Session Summary (trimmed)\n...\n" + raw[-(MAX_SUMMARY_FILE_BYTES - 64):]
                        tmp = sp.with_name(f".{sp.name}.{os.getpid()}.{threading.get_ident()}.tmp")
                        fd2 = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        with os.fdopen(fd2, "wb") as f2:
                            f2.write(kept)
                        os.replace(tmp, sp)
                except OSError:
                    pass

                new_title = row["title"] or text.splitlines()[0].lstrip("#- *")[:80]
                new_next = clean_next if clean_next else row["next"]
                conn.execute(
                    """
                    UPDATE sessions
                    SET updated_at = ?, updated_ts = ?, summary_count = ?, last_summary_step = ?,
                        title = ?, next = ?
                    WHERE session_id = ?
                    """,
                    (now, now_ts, new_count, steps, new_title, new_next, sid),
                )
                conn.execute("COMMIT")
                return {
                    "ok": True,
                    "session_id": sid,
                    "summary_file": str(sp),
                    "summary_count": new_count,
                    "recorded_at_step": steps,
                }
            except Exception:
                self._rollback(conn)
                raise
            finally:
                conn.close()

    def update_task_note(self, session_id: str, args: dict[str, Any]) -> dict[str, Any]:
        sid = sanitize_session_id(session_id)
        has_update = any(
            k in args and args[k] is not None
            for k in ("title", "goal", "next", "notes", "done", "add_done", "blockers", "status")
        )
        if not has_update:
            raise ValueError("at least one field (title, goal, done, add_done, blockers, next, notes, status) is required")
        now = _now_iso()
        now_ts = time.time()
        with self._local_lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = self._ensure_session_row(conn, sid, self.source)
                meta = self._row_to_meta(row)
                for field in ("title", "goal", "next", "notes"):
                    if field in args and args[field] is not None:
                        meta[field] = redact_text(str(args[field]).strip())[:2000]
                if "done" in args and isinstance(args["done"], list):
                    meta["done"] = [redact_text(str(x).strip())[:300] for x in args["done"] if str(x).strip()][:50]
                if args.get("add_done"):
                    item = redact_text(str(args["add_done"]).strip())[:300]
                    if item and item not in meta["done"]:
                        meta["done"].append(item)
                        meta["done"] = meta["done"][-50:]
                if "blockers" in args and isinstance(args["blockers"], list):
                    meta["blockers"] = [redact_text(str(x).strip())[:300] for x in args["blockers"] if str(x).strip()][:30]
                if args.get("status") in {"active", "done"}:
                    meta["status"] = args["status"]
                conn.execute(
                    """
                    UPDATE sessions
                    SET updated_at = ?, updated_ts = ?, status = ?, title = ?, goal = ?,
                        done_json = ?, blockers_json = ?, next = ?, notes = ?
                    WHERE session_id = ?
                    """,
                    (
                        now,
                        now_ts,
                        meta["status"],
                        meta["title"],
                        meta["goal"],
                        json.dumps(meta["done"], ensure_ascii=False),
                        json.dumps(meta["blockers"], ensure_ascii=False),
                        meta["next"],
                        meta["notes"],
                        sid,
                    ),
                )
                if meta["status"] == "done":
                    # A finished task stops attracting new calls via bindings or sticky links.
                    conn.execute("DELETE FROM bindings WHERE target_sid = ?", (sid,))
                    conn.execute("DELETE FROM client_links WHERE target_sid = ?", (sid,))
                updated_row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (sid,)).fetchone()
                conn.execute("COMMIT")
                return {"ok": True, "session_id": sid, "meta": self._row_to_meta(updated_row)}
            except Exception:
                self._rollback(conn)
                raise
            finally:
                conn.close()

    def resume(
        self,
        *,
        session_id: str = "",
        client_sid: str = "",
        last_n: int = 20,
        attach: bool = True,
        reopen: bool = False,
        fp: str = "",
    ) -> dict[str, Any]:
        n = max(1, min(int(last_n or 20), 100))
        with self._local_lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                clean_client = sanitize_session_id(client_sid) if client_sid else ""
                client_fp = self._fp_for(conn, clean_client, fp)
                target_row = None
                wants_new = bool(session_id) and session_id.strip().lower() in NEW_SESSION_WORDS
                if wants_new and conn.execute(
                    "SELECT 1 FROM sessions WHERE session_id = ?", (session_id.strip(),)
                ).fetchone():
                    wants_new = False  # a legacy session literally named "new"/"fresh"/"none"
                if wants_new:
                    fresh = self.new_session_id()
                    self._ensure_session_row(conn, fresh, self.source)
                    can_bind = attach and (bool(clean_client) or (bool(client_fp) and STICKY_SECONDS > 0))
                    if can_bind:
                        if clean_client:
                            self._bind(conn, clean_client, fresh)
                        self._link_fp(conn, client_fp, fresh)
                    conn.execute("COMMIT")
                    out = {"found": True, "session_id": fresh, "attached": can_bind, "new": True}
                    if can_bind:
                        out["message"] = "Started a fresh session; later calls from this client go here."
                    else:
                        out["message"] = (
                            "Created a fresh session but could not bind this client to it; "
                            f"pass `{META_SESSION_KEY}`=\"{fresh}\" on later calls."
                        )
                    return out
                if session_id:
                    target = sanitize_session_id(session_id)
                    target_row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (target,)).fetchone()
                    if target_row is None:
                        conn.execute("ROLLBACK")
                        return {"found": False, "session_id": target, "message": f"Session not found: {target}"}
                else:
                    # Most recent meaningful active session (not a throwaway one-step session,
                    # and not the caller's own brand-new sid); fall back to any non-empty one.
                    rows = conn.execute(
                        """
                        SELECT * FROM sessions
                        WHERE status != 'done'
                          AND (steps > 0 OR summary_count > 0 OR title != '' OR goal != '' OR next != '' OR notes != ''
                               OR done_json NOT IN ('', '[]') OR blockers_json NOT IN ('', '[]'))
                        ORDER BY updated_ts DESC
                        LIMIT 300
                        """
                    ).fetchall()
                    for r in rows:
                        if r["session_id"] != clean_client and not _is_trivial_row(r):
                            target_row = r
                            break
                    if target_row is None:
                        for r in rows:
                            if r["session_id"] != clean_client:
                                target_row = r
                                break
                    if target_row is None and rows:
                        target_row = rows[0]
                    if target_row is None:
                        conn.execute("ROLLBACK")
                        return {"found": False, "message": "No non-empty active sessions found to resume."}

                target = target_row["session_id"]
                attached = False
                note = ""
                if target_row["status"] == "done" and attach:
                    if reopen:
                        conn.execute(
                            "UPDATE sessions SET status = 'active', updated_at = ?, updated_ts = ? WHERE session_id = ?",
                            (_now_iso(), time.time(), target),
                        )
                        target_row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (target,)).fetchone()
                    else:
                        attach = False
                        note = "Session is marked done; opened read-only. Pass reopen=true to re-activate and attach."

                if attach and (clean_client or (client_fp and STICKY_SECONDS > 0)):
                    if clean_client:
                        self._bind(conn, clean_client, target)
                    # Sticky across reconnects: later connections from the same client land here too.
                    self._link_fp(conn, client_fp, target)
                    # Drop the caller's own empty placeholder session, if any (never one with
                    # handoff data, a summary file, or a done status).
                    if clean_client and clean_client != target:
                        own = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (clean_client,)).fetchone()
                        if (
                            own is not None
                            and int(own["steps"] or 0) == 0
                            and own["status"] != "done"
                            and _is_trivial_row(own)
                            and not self._summary_path(clean_client).exists()
                        ):
                            conn.execute("DELETE FROM sessions WHERE session_id = ?", (clean_client,))
                    attached = True

                ev_rows = conn.execute(
                    """
                    SELECT seq, ts, source, tool, why, args_json, ok, code, duration_ms, output
                    FROM events
                    WHERE session_id = ?
                    ORDER BY seq DESC
                    LIMIT ?
                    """,
                    (target, n),
                ).fetchall()
                conn.execute("COMMIT")

                events = [
                    {
                        "seq": r["seq"],
                        "ts": r["ts"],
                        "source": r["source"],
                        "tool": r["tool"],
                        "why": r["why"],
                        "args": json.loads(r["args_json"] or "{}"),
                        "ok": bool(r["ok"]),
                        "code": r["code"],
                        "duration_ms": r["duration_ms"],
                        "output": r["output"],
                    }
                    for r in reversed(ev_rows)
                ]
                meta = self._row_to_meta(target_row)
                out: dict[str, Any] = {
                    "found": True,
                    "session_id": target,
                    "attached": attached,
                    "meta": meta,
                    "summary_file": meta["summary_file"],
                    "summary_markdown": self._read_summary_md(target),
                    "steps_since_summary": meta["steps_since_summary"],
                    "recent_events_count": len(events),
                    "recent_events": events,
                }
                if note:
                    out["note"] = note
                return out
            except Exception:
                self._rollback(conn)
                raise
            finally:
                conn.close()

    def handle_journal_tool(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        header_sid: str = "",
        session_override: str = "",
        fp: str = "",
    ) -> dict[str, Any]:
        if tool_name == "list_sessions":
            return self.list_sessions(
                limit=int(args.get("limit", 15) or 15),
                include_done=bool(args.get("include_done", False)),
                include_trivial=bool(args.get("include_trivial", False)),
            )
        if tool_name == "resume":
            sid_arg = str(args.get("session_id") or session_override or "").strip()
            return self.resume(
                session_id=sid_arg,
                client_sid=header_sid,
                last_n=int(args.get("last_n", 20) or 20),
                attach=bool(args.get("attach", True)),
                reopen=bool(args.get("reopen", False)),
                fp=fp,
            )
        if tool_name == "append_summary":
            if not str(args.get("summary") or "").strip():
                raise ValueError("summary is required and cannot be empty")
            sid_arg = str(args.get("session_id") or session_override or "").strip()
            resolved = self.resolve_session_id(header_sid=header_sid, arg_sid=sid_arg, fp=fp)
            return self.append_summary(
                resolved,
                str(args.get("summary") or ""),
                next_step=str(args.get("next_step") or ""),
            )
        if tool_name == "task_note":
            if not any(
                k in args and args[k] is not None
                for k in ("title", "goal", "next", "notes", "done", "add_done", "blockers", "status")
            ):
                raise ValueError("at least one field (title, goal, done, add_done, blockers, next, notes, status) is required")
            sid_arg = str(args.get("session_id") or session_override or "").strip()
            resolved = self.resolve_session_id(header_sid=header_sid, arg_sid=sid_arg, fp=fp)
            return self.update_task_note(resolved, args)
        raise ValueError(f"unknown journal tool: {tool_name}")
