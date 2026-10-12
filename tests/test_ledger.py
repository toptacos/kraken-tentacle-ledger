#!/usr/bin/env python3
"""ledger contract tests. Offline, temp KRAKEN_HOME.

The point of this arm is that a value never reaches disk, so that gets the
most attention here: every shape of secret, and the shape a secret takes when
it is nested in something innocuous.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "ledger.jsonl"


def invoke(action, payload=None, home=None, raw=None):
    run = os.environ.copy()
    run["KRAKEN_OFFLINE"] = "1"
    run["KRAKEN_HOME"] = home or tempfile.mkdtemp()
    body = (
        raw
        if raw is not None
        else json.dumps(
            {"v": 1, "id": None, "action": action, "payload": payload or {}}
        )
    )
    proc = subprocess.run(
        ["sh", str(ROOT / "handler.sh")],
        input=body,
        text=True,
        capture_output=True,
        env=run,
        check=False,
    )
    lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("{")]
    if not lines:
        raise AssertionError(
            f"no JSON on stdout: rc={proc.returncode} err={proc.stderr[:400]}"
        )
    return json.loads(lines[-1])


class Ledger(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.path = Path(self.home) / ".kraken" / "data" / "ledger" / "ledger.jsonl"

    def call(self, action, payload=None, **kw):
        kw.setdefault("home", self.home)
        return invoke(action, payload, **kw)

    def on_disk(self):
        return self.path.read_text(encoding="utf-8") if self.path.exists() else ""

    # --- envelope -------------------------------------------------------

    def test_ping(self):
        r = self.call("ping")
        self.assertTrue(r["ok"])
        self.assertEqual(r["result"]["arm"], "ledger")
        self.assertEqual(r["result"]["protocol"], 1)

    def test_ping_on_empty_stdin(self):
        r = invoke(None, home=self.home, raw="")
        self.assertTrue(r["ok"])

    def test_malformed_stdin_is_an_envelope(self):
        for raw in ("{not json", "[]", '"a string"'):
            r = invoke(None, home=self.home, raw=raw)
            self.assertFalse(r["ok"], raw)
            self.assertIn("error", r)

    def test_unknown_action(self):
        r = self.call("nope")
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"]["code"], "unknown_action")

    def test_where(self):
        r = self.call("where")
        self.assertTrue(r["ok"])
        self.assertIn("ledger", r["result"]["dir"])

    # --- append ---------------------------------------------------------

    def test_append_writes_one_line(self):
        r = self.call("append", {"envelope": {"arm": "watch", "action": "tick"}})
        self.assertTrue(r["ok"])
        lines = [ln for ln in self.on_disk().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1)
        row = json.loads(lines[0])
        self.assertEqual(row["arm"], "watch")
        self.assertIn("ts", row)

    def test_append_is_append_only(self):
        for i in range(3):
            self.call("append", {"envelope": {"arm": "a", "n": i}})
        rows = [json.loads(ln) for ln in self.on_disk().splitlines() if ln.strip()]
        self.assertEqual(len(rows), 3)
        self.assertEqual([r["event"]["n"] for r in rows], [0, 1, 2])

    def test_append_needs_an_envelope(self):
        r = self.call("append", {})
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"]["code"], "bad_payload")

    # --- the important part: a value never lands -----------------------

    def test_a_plain_value_is_redacted(self):
        self.call("append", {"envelope": {"arm": "watch", "value": "must-be-redacted"}})
        self.assertNotIn("must-be-redacted", self.on_disk())
        self.assertIn("[redacted]", self.on_disk())

    def test_secret_key_names_are_redacted(self):
        secrets = {
            "api_key": "abc123",
            "token": "t",
            "password": "hunter2",
            "secret": "s",
            "authorization": "Bearer x",
            "cookie": "sso_token=1",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----",
            "session": "1",
            "credential": "c",
        }
        self.call("append", {"envelope": secrets})
        text = self.on_disk()
        for value in ("abc123", "hunter2", "Bearer x", "BEGIN RSA PRIVATE KEY"):
            self.assertNotIn(value, text, f"{value!r} reached the ledger")

    def test_secret_values_are_caught_even_under_an_innocuous_key(self):
        # The name says nothing, so the value pattern has to catch it.
        for value in (
            "sk-live-0123456789abcdef",
            "ghp_0123456789abcdefghijklmnop",
            "xoxb-0123456789-abcdef",
            "AKIA0123456789ABCDEF",
        ):
            with tempfile.TemporaryDirectory() as home:
                invoke("append", {"envelope": {"note": value}}, home=home)
                path = Path(home) / ".kraken" / "data" / "ledger" / "ledger.jsonl"
                self.assertNotIn(value, path.read_text())

    def test_nested_secrets_are_redacted(self):
        self.call(
            "append",
            {"envelope": {"arm": "x", "config": {"db": {"password": "hunter2"}}}},
        )
        self.assertNotIn("hunter2", self.on_disk())

    def test_secrets_inside_lists_are_redacted(self):
        self.call("append", {"envelope": {"tokens": ["sk-live-0123456789abc"]}})
        self.assertNotIn("sk-live-0123456789abc", self.on_disk())

    def test_harmless_data_survives(self):
        # Redacting everything would be just as useless as storing everything.
        self.call(
            "append", {"envelope": {"arm": "watch", "ok": True, "ms": 12, "n": 3}}
        )
        text = self.on_disk()
        self.assertIn("watch", text)
        self.assertNotIn("[redacted]", text)

    # --- list -----------------------------------------------------------

    def test_list_returns_entries(self):
        self.call("append", {"envelope": {"arm": "a"}})
        self.call("append", {"envelope": {"arm": "b"}})
        r = self.call("list")
        self.assertEqual(r["result"]["count"], 2)

    def test_list_filters_by_arm(self):
        self.call("append", {"envelope": {"arm": "a"}})
        self.call("append", {"envelope": {"arm": "b"}})
        r = self.call("list", {"arm": "b"})
        self.assertEqual(r["result"]["count"], 1)
        self.assertEqual(r["result"]["entries"][0]["arm"], "b")

    def test_list_respects_limit(self):
        for i in range(5):
            self.call("append", {"envelope": {"arm": "a", "n": i}})
        self.assertEqual(self.call("list", {"limit": 2})["result"]["count"], 2)

    def test_list_on_empty_ledger(self):
        r = self.call("list")
        self.assertTrue(r["ok"])
        self.assertEqual(r["result"]["count"], 0)

    def test_a_truncated_tail_does_not_break_the_read(self):
        self.call("append", {"envelope": {"arm": "a"}})
        with self.path.open("a") as fh:
            fh.write('{"ts": 1, "arm": "trunc')
        r = self.call("list")
        self.assertTrue(r["ok"])
        self.assertEqual(r["result"]["count"], 1)

    # --- clear ----------------------------------------------------------

    def test_clear_needs_confirmation(self):
        self.call("append", {"envelope": {"arm": "a"}})
        r = self.call("clear")
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"]["code"], "confirm_required")
        self.assertIn("a", self.on_disk(), "nothing should have been cleared")

    def test_clear_with_confirmation(self):
        self.call("append", {"envelope": {"arm": "a"}})
        r = self.call("clear", {"confirm": True})
        self.assertTrue(r["ok"])
        self.assertEqual(r["result"]["cleared"], 1)
        self.assertEqual(self.on_disk().strip(), "")

    # --- storage hygiene -------------------------------------------------

    def test_file_is_owner_only(self):
        self.call("append", {"envelope": {"arm": "a"}})
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_no_secret_from_a_previous_run_leaks_into_a_new_home(self):
        other = tempfile.mkdtemp()
        self.call("append", {"envelope": {"arm": "a"}})
        r = invoke("list", home=other)
        self.assertEqual(r["result"]["count"], 0)

    def test_honours_a_configured_data_dir(self):
        home = Path(self.home)
        (home / ".kraken").mkdir(parents=True, exist_ok=True)
        (home / ".kraken" / "config.yaml").write_text("data_dir: elsewhere\n")
        self.call("append", {"envelope": {"arm": "a"}})
        moved = home / ".kraken" / "elsewhere" / "ledger" / "ledger.jsonl"
        self.assertTrue(moved.is_file(), "ledger ignored data_dir")


if __name__ == "__main__":
    unittest.main()
