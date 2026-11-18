"""Append-only change journal (``journal.jsonl``) used for audit and ``router_undo``.

Every applied plan writes a ``pending`` record - including the full *before* state and
every request - and fsyncs it BEFORE the first request is sent, then appends a result
record (``applied`` / ``partial`` / ``failed`` / ``unknown``) with the *after* state.

The journal keeps secrets unredacted (undo must be able to restore a Wi-Fi password or a
VPN key), so the directory is 0700 and the file 0600.  Override the location with
``TPLINK_JOURNAL_DIR``.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any


def default_dir() -> Path:
    env = os.environ.get("TPLINK_JOURNAL_DIR")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return Path(base) / "mcp-tplink-router"


class Journal:
    def __init__(self, directory: str | Path | None = None) -> None:
        self.dir = Path(directory) if directory else default_dir()
        self.path = self.dir / "journal.jsonl"

    def _append(self, record: dict[str, Any]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.dir, 0o700)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, (json.dumps(record, ensure_ascii=False, default=str) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def begin(self, tool: str, summary: str, requests: list[dict[str, Any]], before: dict[str, Any],
              *, risk: str, undo_of: str | None = None, router: str = "main") -> str:
        entry_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        self._append({
            "id": entry_id, "ts": time.time(), "router": router, "tool": tool, "summary": summary, "risk": risk,
            "requests": requests, "before": before, "status": "pending", "undo_of": undo_of,
        })
        return entry_id

    def wire(self, entry_id: str, step: int, path: str, op: str, fields: dict[str, str]) -> None:
        """Record the exact request (incl. index/old JSON computed at send time) before sending."""
        self._append({"id": entry_id, "wire": {"step": step + 1, "path": path, "operation": op, "fields": fields}})

    def finish(self, entry_id: str, status: str, *, after: dict[str, Any] | None = None,
               detail: Any = None, steps_applied: int | None = None) -> None:
        self._append({"id": entry_id, "ts_done": time.time(), "status": status, "after": after,
                      "detail": detail, "steps_applied": steps_applied})

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        merged: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                rid = rec.get("id")
                if not rid:
                    continue
                if rid not in merged:
                    merged[rid] = {}
                    order.append(rid)
                if "wire" in rec:
                    merged[rid].setdefault("wire", []).append(rec["wire"])
                    continue
                merged[rid].update({k: v for k, v in rec.items() if v is not None or k not in merged[rid]})
        return [merged[r] for r in order]

    def get(self, entry_id: str) -> dict[str, Any] | None:
        for e in self.entries():
            if e["id"] == entry_id:
                return e
        return None
