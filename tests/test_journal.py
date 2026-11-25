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


if __name__ == "__main__":
    unittest.main()
