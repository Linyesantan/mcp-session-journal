#!/usr/bin/env python3
"""Unit tests for mcp_journal."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import mcp_journal as m


class TestMcpJournal(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.journal = m.SessionJournal(root=self.root, source="test")

    def tearDown(self):
        self._tmp.cleanup()

    def test_truncation_and_recursive_redaction(self):
        v = "x" * 300
        prev = m.summarize_args("write_file", {"content": v})["content_preview"]
        self.assertLess(len(prev), 230)
        self.assertNotIn(v, prev)

        nested = m.summarize_args(
            "api",
            {"options": {"secret": "topsecret", "deep": {"api_key": "k123", "note": "token=abc999"}}},
        )
        self.assertEqual(nested["options"]["secret"], "[REDACTED]")
        self.assertEqual(nested["options"]["deep"]["api_key"], "[REDACTED]")
        self.assertNotIn("abc999", nested["options"]["deep"]["note"])

        redacted_url = m.redact_url_path("POST /mcp/supersecrettoken123 HTTP/1.1")
        self.assertIn("/mcp/[REDACTED]", redacted_url)
        self.assertNotIn("supersecrettoken123", redacted_url)

    def test_namespaced_meta_args_preserve_upstream_session(self):
        clean, why, s_ov = m.extract_meta_args(
            {"session": "upstream_value", "_journal_why": "check logs", "_journal_session": "s1"}
        )
        self.assertEqual(clean, {"session": "upstream_value"})
        self.assertEqual(why, "check logs")
        self.assertEqual(s_ov, "s1")

    def test_reserved_session_names_rejected(self):
        for bad in ("..", ".", "aliases.json", "journal.db", "a/b", "bad space"):
            with self.assertRaises(ValueError):
                m.sanitize_session_id(bad)

    def test_multi_session_incremental_summary_and_resume(self):
        sid_a = self.journal.new_session_id()
        sid_b = self.journal.new_session_id()
        self.assertNotEqual(sid_a, sid_b)

        # Step 1 triggers initial reminder
        rem1 = self.journal.record_event(sid_a, "run", {"command": "echo 1"}, {"content": [{"type": "text", "text": '{"code":0,"output":"1"}'}]})
        self.assertIsNotNone(rem1)
        self.assertIn("step #1", rem1)

        # Steps 2..9 silent, step 10 reminds
        reminded = []
        for i in range(2, 11):
            r = self.journal.record_event(sid_a, "run", {"command": f"echo {i}"}, {"content": [{"type": "text", "text": '{"code":0,"output":"ok"}'}]})
            if r:
                reminded.append(i)
        self.assertEqual(reminded, [10])

        # Append incremental summary
        s1 = self.journal.append_summary(sid_a, "Finished steps 1-10, checked token=leak123", next_step="Proceed to 11")
        self.assertTrue(s1["ok"])
        self.assertEqual(s1["summary_count"], 1)
        sp = Path(s1["summary_file"])
        self.assertTrue(sp.is_file())
        self.assertEqual(os.stat(sp).st_mode & 0o777, 0o600)

        # Step 11..19 silent, step 20 reminds
        reminded_after = []
        for i in range(11, 21):
            r = self.journal.record_event(sid_a, "run", {"command": f"echo {i}"}, {"content": [{"type": "text", "text": '{"code":0,"output":"ok"}'}]})
            if r:
                reminded_after.append(i)
        self.assertEqual(reminded_after, [20])

        # Resume from new client session B with attach=True
        res = self.journal.resume(session_id=sid_a, client_sid=sid_b, attach=True)
        self.assertTrue(res["found"])
        self.assertTrue(res["attached"])
        self.assertEqual(res["steps_since_summary"], 10)
        self.assertNotIn("leak123", res["summary_markdown"])
        self.assertIn("[REDACTED]", res["summary_markdown"])

        # Subsequent calls from client B resolve to sid_a
        self.assertEqual(self.journal.resolve_session_id(header_sid=sid_b), sid_a)

        # Mark done -> resume without reopen is read-only
        self.journal.update_task_note(sid_a, {"status": "done"})
        sid_c = self.journal.new_session_id()
        ro = self.journal.resume(session_id=sid_a, client_sid=sid_c, attach=True, reopen=False)
        self.assertFalse(ro["attached"])
        rw = self.journal.resume(session_id=sid_a, client_sid=sid_c, attach=True, reopen=True)
        self.assertTrue(rw["attached"])
        self.assertEqual(rw["meta"]["status"], "active")


class FakeHeaders(dict):
    def get_all(self, k):
        v = self.get(k)
        return None if v is None else (v if isinstance(v, list) else [v])


class TestStickySessions(unittest.TestCase):
    OK = {"content": [{"type": "text", "text": '{"code":0,"output":"ok"}'}]}

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.j = m.SessionJournal(root=self.root, source="test")
        self.fa = m.request_fingerprint("laba", None, "")[0]
        self.fb = m.request_fingerprint("labb", None, "")[0]

    def tearDown(self):
        self._tmp.cleanup()

    def call(self, header="", fp="", arg="", j=None):
        j = j or self.j
        sid = j.resolve_session_id(header_sid=header, arg_sid=arg, fp=fp)
        j.record_event(sid, "run", {"command": "echo"}, self.OK)
        return sid

    def test_headerless_clients_get_own_sessions(self):
        a1 = self.call(fp=self.fa)
        b1 = self.call(fp=self.fb)
        self.assertNotIn("default", (a1, b1))
        self.assertNotEqual(a1, b1)
        self.assertEqual(self.call(fp=self.fa), a1)
        self.assertEqual(self.call(fp=self.fb), b1)
        self.assertEqual(self.j.resolve_session_id(), "default")

    def test_new_connections_with_same_fp_share_session(self):
        c1, c2 = self.j.new_session_id(), self.j.new_session_id()
        self.j.register_client(c1, self.fa)
        self.j.register_client(c2, self.fa)
        # Both resolve before either records an event (parallel first calls).
        s1 = self.j.resolve_session_id(header_sid=c1, fp=self.fa)
        other = m.SessionJournal(root=self.root, source="other-process")
        s2 = other.resolve_session_id(header_sid=c2, fp=self.fa)
        self.assertEqual(s1, s2)

    def test_done_stops_bound_and_own_sessions(self):
        c1 = self.j.new_session_id()
        self.j.register_client(c1, self.fa)
        s = self.call(header=c1, fp=self.fa)
        c2 = self.j.new_session_id()
        self.j.register_client(c2, self.fa)
        self.assertEqual(self.call(header=c2, fp=self.fa), s)  # sticky + auto-bound
        self.j.update_task_note(s, {"status": "done"})
        n2 = self.call(header=c2, fp=self.fa)
        n1 = self.call(header=c1, fp=self.fa)
        self.assertNotEqual(n2, s)
        self.assertNotEqual(n1, s)
        self.assertEqual(n1, n2)  # both continue the client's new session
        self.assertEqual(self.j.list_sessions(include_done=True, include_trivial=True)["count"], 2)

    def test_resume_new_is_fresh_and_old_connection_cannot_revert(self):
        c_old = self.j.new_session_id()
        self.j.register_client(c_old, self.fa)
        old = self.call(header=c_old, fp=self.fa)
        r = self.j.resume(session_id="new", client_sid=c_old, fp=self.fa)
        self.assertTrue(r["attached"])
        self.assertNotEqual(r["session_id"], c_old)
        fresh = r["session_id"]
        self.assertEqual(self.call(header=c_old, fp=self.fa), fresh)
        # Another, older connection still bound to the previous session keeps it...
        c_other = self.j.new_session_id()
        self.j.resume(session_id=old, client_sid=c_other, fp="")
        self.assertEqual(self.call(header=c_other, fp=self.fa), old)
        # ...but cannot pull the client's sticky link back.
        self.assertEqual(self.call(fp=self.fa), fresh)

    def test_resume_to_own_sid_clears_binding(self):
        c = self.j.new_session_id()
        own = self.call(header=c)
        other = self.call(header=self.j.new_session_id())
        self.j.resume(session_id=other, client_sid=c)
        self.assertEqual(self.call(header=c), other)
        self.j.resume(session_id=own, client_sid=c)
        self.assertEqual(self.call(header=c), own)

    def test_resume_new_without_binding_reports_unattached(self):
        r = self.j.resume(session_id="new")
        self.assertFalse(r["attached"])
        self.assertIn("_journal_session", r["message"])

    def test_blocker_only_session_is_listed_and_not_deleted(self):
        sid = self.j.new_session_id()
        self.j.update_task_note(sid, {"blockers": ["waiting on user"]})
        listed = [x["session_id"] for x in self.j.list_sessions()["sessions"]]
        self.assertIn(sid, listed)
        self.assertEqual(self.j.resume(client_sid=sid)["session_id"], sid)
        target = self.call(header=self.j.new_session_id())
        self.j.update_task_note(target, {"title": "t"})
        self.j.resume(session_id=target, client_sid=sid)
        self.assertIn(sid, [x["session_id"] for x in self.j.list_sessions(include_trivial=True)["sessions"]])

    def test_trivial_filter_applies_before_limit(self):
        keep = self.call(header=self.j.new_session_id())
        self.j.update_task_note(keep, {"title": "real"})
        for _ in range(60):
            self.call(header=self.j.new_session_id())
        out = self.j.list_sessions(limit=5)
        self.assertEqual([x["session_id"] for x in out["sessions"]], [keep])
        self.assertEqual(out["hidden_trivial"], 60)

    def test_legacy_session_named_new(self):
        self.j.update_task_note("new", {"title": "legacy"})
        r = self.j.resume(session_id="new", client_sid=self.j.new_session_id())
        self.assertEqual(r["session_id"], "new")
        self.assertNotIn("new", r.get("new", "") or "")

    def test_journal_tool_validation_has_no_side_effects(self):
        with self.assertRaises(ValueError):
            self.j.handle_journal_tool("append_summary", {"summary": "  "}, fp=self.fa)
        with self.assertRaises(ValueError):
            self.j.handle_journal_tool("task_note", {}, fp=self.fa)
        self.assertEqual(self.j.list_sessions(include_trivial=True)["count"], 0)


class TestRoutes(unittest.TestCase):
    def test_parse_routes(self):
        H = FakeHeaders
        self.assertEqual(m.parse_mcp_route("/mcp/tok"), ("tok", ""))
        self.assertEqual(m.parse_mcp_route("/mcp/tok/"), ("tok", ""))
        self.assertEqual(m.parse_mcp_route("/mcp"), ("", ""))
        self.assertEqual(m.parse_mcp_route("/mcp/tok/Hark-1"), ("tok", "hark-1"))
        self.assertEqual(m.parse_mcp_route("/mcp/tok?client=a", H()), ("tok", "a"))
        self.assertEqual(m.parse_mcp_route("/mcp/tok/a", H({"X-MCP-Client": "A"})), ("tok", "a"))
        for bad, hdr in [
            ("/%6dcp/tok", None), ("/mcp/%74ok", None), ("/mcp//tok", None), ("//mcp/tok", None),
            ("/mcp/tok/a/b", None), ("/mcp/tok/..", None), ("/mcp/tok/bad!", None),
            ("/mcp/tok?client=a&client=b", None), ("/mcp/tok/a", H({"X-MCP-Client": "b"})),
            ("/mcp/tok/a?client=b", None), ("/mcp/tok", H({"X-MCP-Client": ["a", "a"]})),
            ("/mcp/tok", H({"X-MCP-Client": "no spaces"})), ("/files/tok", None),
        ]:
            with self.assertRaises(m.RouteError, msg=bad):
                m.parse_mcp_route(bad, hdr)

    def test_fingerprint_trusts_forwarded_only_from_loopback(self):
        h = FakeHeaders({"CF-Connecting-IP": "1.2.3.4", "User-Agent": "x"})
        self.assertEqual(m.request_fingerprint("", h, "127.0.0.1"), m.request_fingerprint("", FakeHeaders({"User-Agent": "x"}), "1.2.3.4"))
        self.assertNotEqual(m.request_fingerprint("", h, "5.6.7.8"), m.request_fingerprint("", h, "127.0.0.1"))
        self.assertNotEqual(m.request_fingerprint("a", h, "1.1.1.1")[0], m.request_fingerprint("", h, "1.1.1.1")[0])
        self.assertEqual(m.request_fingerprint("a", h, "1.1.1.1")[0], m.request_fingerprint("a", None, "9.9.9.9")[0])

    def test_logs_never_carry_path(self):
        line = m.safe_log_line("POST", "/%6dcp/secret?x=secret", 200)
        self.assertNotIn("secret", line)
        self.assertIn("/mcp", m.safe_log_line("POST", "/mcp/secret/lab", 200))
        self.assertNotIn("secret", m.safe_log_line("POST", "/mcp/secret/lab", 200))
        for p in ("POST /%6dcp/secret HTTP/1.1", "POST /mcp/x?client=secret HTTP/1.1", "GET /MCP/secret HTTP/1.1"):
            self.assertNotIn("secret", m.redact_url_path(p))


if __name__ == "__main__":
    unittest.main()

