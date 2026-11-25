#!/usr/bin/env python3
"""Multi-session black-box journal & handoff helper for MCP servers.

Stdlib-only (SQLite WAL), multi-process safe, zero external dependencies.
Provides:
  - High-entropy session ID generation
  - Automatic tool-call recording with recursive secret redaction & safe truncation
  - Single-hop client_sid -> task_id binding in SQLite transactions
  - 3 MCP tools: list_sessions, resume, task_note
"""
from __future__ import annotations

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
    "summary file plus any recent unsummarized tool calls."
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
            },
        },
    },
    {
        "name": "resume",
        "description": (
            "Load a session's handoff state: its dedicated incremental summary markdown file, task note, "
            "touched files, and recent tool-call history (including any steps after the last summary). "
            "With attach=true (default on active sessions), subsequent tool calls and summaries from this "
            "connection continue in that session. Pass reopen=true to re-activate a done session."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Target session_id; omit to resume the most recent non-empty active session"},
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
    return re.sub(r"(/(?:mcp|files)/)[^/\s?]+", r"\1[REDACTED]", path or "")


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

    def _resolve_in_conn(self, conn: sqlite3.Connection, header_sid: str = "", arg_sid: str = "") -> str:
        # Priority: explicit arg_sid > bound Mcp-Session-Id > raw Mcp-Session-Id > "default"
        if arg_sid:
            return sanitize_session_id(arg_sid)
        if header_sid:
            raw = sanitize_session_id(header_sid)
            row = conn.execute("SELECT target_sid FROM bindings WHERE client_sid = ?", (raw,)).fetchone()
            if row and row["target_sid"]:
                return sanitize_session_id(row["target_sid"])
            return raw
        return "default"

    def resolve_session_id(self, header_sid: str | None = None, arg_sid: str | None = None) -> str:
        with self._local_lock:
            conn = self._connect()
            try:
                return self._resolve_in_conn(conn, header_sid or "", arg_sid or "")
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
                self._delete_summary_files(old_ids)
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
                self._delete_summary_files(drop_ids)

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
                conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def list_sessions(self, *, limit: int = 15, include_done: bool = False) -> dict[str, Any]:
        limit = max(1, min(int(limit or 15), 50))
        with self._local_lock:
            conn = self._connect()
            try:
                if include_done:
                    rows = conn.execute(
                        "SELECT * FROM sessions ORDER BY updated_ts DESC LIMIT ?", (limit,)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM sessions WHERE status != 'done' ORDER BY updated_ts DESC LIMIT ?", (limit,)
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
                return {"count": len(sessions), "sessions": sessions}
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
                conn.execute("ROLLBACK")
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
                updated_row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (sid,)).fetchone()
                conn.execute("COMMIT")
                return {"ok": True, "session_id": sid, "meta": self._row_to_meta(updated_row)}
            except Exception:
                conn.execute("ROLLBACK")
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
    ) -> dict[str, Any]:
        n = max(1, min(int(last_n or 20), 100))
        with self._local_lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                target_row = None
                if session_id:
                    target = sanitize_session_id(session_id)
                    target_row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (target,)).fetchone()
                    if target_row is None:
                        conn.execute("ROLLBACK")
                        return {"found": False, "session_id": target, "message": f"Session not found: {target}"}
                else:
                    # Find most recent non-empty active session (excluding caller's own brand-new sid)
                    rows = conn.execute(
                        """
                        SELECT * FROM sessions
                        WHERE status != 'done'
                          AND (steps > 0 OR summary_count > 0 OR title != '' OR goal != '' OR next != '' OR notes != '')
                        ORDER BY updated_ts DESC
                        LIMIT 20
                        """
                    ).fetchall()
                    for r in rows:
                        if r["session_id"] != client_sid:
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

                if attach and client_sid:
                    clean_client = sanitize_session_id(client_sid)
                    if clean_client != target:
                        conn.execute(
                            """
                            INSERT INTO bindings (client_sid, target_sid, updated_ts)
                            VALUES (?, ?, ?)
                            ON CONFLICT(client_sid) DO UPDATE SET target_sid=excluded.target_sid, updated_ts=excluded.updated_ts
                            """,
                            (clean_client, target, time.time()),
                        )
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
                conn.execute("ROLLBACK")
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
    ) -> dict[str, Any]:
        if tool_name == "list_sessions":
            return self.list_sessions(
                limit=int(args.get("limit", 15) or 15),
                include_done=bool(args.get("include_done", False)),
            )
        if tool_name == "resume":
            sid_arg = str(args.get("session_id") or session_override or "").strip()
            return self.resume(
                session_id=sid_arg,
                client_sid=header_sid,
                last_n=int(args.get("last_n", 20) or 20),
                attach=bool(args.get("attach", True)),
                reopen=bool(args.get("reopen", False)),
            )
        if tool_name == "append_summary":
            sid_arg = str(args.get("session_id") or session_override or "").strip()
            resolved = self.resolve_session_id(header_sid=header_sid, arg_sid=sid_arg)
            return self.append_summary(
                resolved,
                str(args.get("summary") or ""),
                next_step=str(args.get("next_step") or ""),
            )
        if tool_name == "task_note":
            sid_arg = str(args.get("session_id") or session_override or "").strip()
            resolved = self.resolve_session_id(header_sid=header_sid, arg_sid=sid_arg)
            return self.update_task_note(resolved, args)
        raise ValueError(f"unknown journal tool: {tool_name}")
