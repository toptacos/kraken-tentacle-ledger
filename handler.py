#!/usr/bin/env python3
"""kraken tentacle — ledger.

An append-only JSONL record of what ran and whether it worked. No network, no
daemon, no secrets.

The one rule that matters here: a value is never stored. The workflow this arm
exists to serve hands it a payload containing `value: "must-be-redacted-if-
-present"`, and a log is exactly where a secret goes to hide — logs get copied
into tickets, attached to bug reports, and shipped to places that were never
approved to hold a key. So `append` records the shape of the event and drops
the value.

The file is 0600 and append-only: there is no rewrite action, and `clear`
requires an explicit flag.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

#: Keys whose values are never written, at any depth.
SECRET_KEYS = re.compile(
    r"(secret|token|password|passwd|apikey|api_key|key|credential|auth|"
    r"cookie|session|private|signature|bearer)",
    re.I,
)

#: Inline value patterns, for keys we cannot identify by name.
SECRET_VALUES = (
    re.compile(r"\bsk-[A-Za-z0-9_\-]{12,}"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAKIA[0-9A-Z]{12,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)

#: Fields redacted by exact name. `value` is here because that is what the
#: cross-arm workflow hands us, and this arm's contract is that a value never
#: reaches disk. The pattern below catches everything that merely looks like a
#: credential.
SENSITIVE_EXACT = {"value", "values", "payload_value", "raw_value"}

REDACTED = "[redacted]"
MAX_FIELD = 200
MAX_BYTES = 8 * 1024 * 1024


def ok(ident: Any, result: dict[str, Any]) -> int:
    json.dump({"v": 1, "id": ident, "ok": True, "result": result}, sys.stdout)
    sys.stdout.write("\n")
    return 0


def err(ident: Any, code: str, message: str) -> int:
    """An application failure is a valid v1 response, so it exits 0.

    docs/CONTRACT.md: a non-zero exit is a transport failure, and core
    discards the body and raises. Returning 1 here turned "no project config"
    into a RuntimeError and a stack trace, and threw the reason away.
    """
    json.dump(
        {"v": 1, "id": ident, "ok": False, "error": {"code": code, "message": message}},
        sys.stdout,
    )
    sys.stdout.write("\n")
    return 0


def data_dir() -> Path:
    # Honour the configured data_dir rather than assuming "data".
    home = Path(os.environ.get("KRAKEN_HOME", Path.home()))
    name = "data"
    cfg = home / ".kraken" / "config.yaml"
    if cfg.is_file():
        try:
            import yaml

            loaded = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict) and isinstance(loaded.get("data_dir"), str):
                name = loaded["data_dir"]
        except Exception:
            pass
    path = home / ".kraken" / name / "ledger"
    path.mkdir(parents=True, exist_ok=True)
    return path


def ledger_file() -> Path:
    return data_dir() / "ledger.jsonl"


def scrub(value: Any, key: str = "", depth: int = 0) -> Any:
    """Return a record of the event with every secret-shaped value removed."""
    if depth > 6:
        return "[depth]"
    if key and (key.lower() in SENSITIVE_EXACT or SECRET_KEYS.search(key)):
        return REDACTED
    if isinstance(value, str):
        for pattern in SECRET_VALUES:
            if pattern.search(value):
                return REDACTED
        return value[:MAX_FIELD]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {k: scrub(v, str(k), depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(v, key, depth + 1) for v in list(value)[:50]]
    return str(value)[:MAX_FIELD]


def append_entry(entry: dict[str, Any]) -> None:
    path = ledger_file()
    try:
        if path.exists() and path.stat().st_size > MAX_BYTES:
            raise OSError("ledger is over its size limit; refusing to grow further")
    except OSError as exc:
        raise OSError(str(exc)) from exc
    line = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    # O_APPEND: a write cannot land in the middle of an existing entry.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (line + "\n").encode())
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def read_entries(limit: int = 0, arm: str = "", since: int = 0) -> list[dict[str, Any]]:
    path = ledger_file()
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            # A truncated tail from a hard kill should not break the read.
            continue
        if not isinstance(row, dict):
            continue
        if arm and row.get("arm") != arm:
            continue
        if since and float(row.get("ts", 0)) <= since:
            continue
        out.append(row)
    if limit and limit > 0:
        return out[-limit:]
    return out


def main() -> int:
    raw = sys.stdin.read()
    ident = None
    try:
        req = json.loads(raw) if raw.strip() else {"action": "ping", "payload": {}}
    except json.JSONDecodeError as exc:
        return err(None, "bad_json", f"stdin must be JSON: {exc}")

    # Valid JSON is not necessarily an object, and a list has no .get.
    if not isinstance(req, dict):
        return err(None, "bad_json", "request must be an object")
    ident = req.get("id")
    action = req.get("action") or "ping"
    payload = req.get("payload") or {}
    if not isinstance(payload, dict):
        return err(ident, "bad_payload", "payload must be an object")

    if action == "ping":
        path = ledger_file()
        return ok(
            ident,
            {
                "arm": "ledger",
                "protocol": 1,
                "path": str(path),
                "entries": len(read_entries()),
            },
        )

    if action == "where":
        return ok(ident, {"arm": "ledger", "dir": str(data_dir()), "scope": "home"})

    if action == "append":
        envelope = payload.get("envelope")
        if not isinstance(envelope, dict):
            return err(ident, "bad_payload", "append needs an 'envelope' object")
        cleaned = scrub(envelope)
        entry = {
            "ts": time.time(),
            "arm": str(cleaned.get("arm", "")),
            "action": str(cleaned.get("action", "")),
            "event": cleaned,
        }
        if "value" in cleaned:
            entry["value"] = REDACTED
        try:
            append_entry(entry)
        except OSError as exc:
            return err(ident, "write_failed", str(exc))
        return ok(
            ident,
            {
                "arm": "ledger",
                "appended": True,
                "redacted": "value" in cleaned or "value" in envelope,
                "entries": len(read_entries()),
            },
        )

    if action == "list":
        rows = read_entries(
            limit=int(payload.get("limit") or 0),
            arm=str(payload.get("arm") or ""),
            since=int(payload.get("since") or 0),
        )
        return ok(ident, {"arm": "ledger", "count": len(rows), "entries": rows})

    if action == "clear":
        if not payload.get("confirm"):
            return err(
                ident,
                "confirm_required",
                'clear empties the ledger; pass {"confirm": true} to allow it',
            )
        path = ledger_file()
        count = len(read_entries())
        path.write_text("", encoding="utf-8")
        return ok(ident, {"arm": "ledger", "cleared": count})

    return err(ident, "unknown_action", f"ledger does not expose {action!r}")


if __name__ == "__main__":
    raise SystemExit(main())
