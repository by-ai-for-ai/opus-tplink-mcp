"""Append-only change journal (``journal.jsonl``) used for audit and ``router_undo``.

Every applied plan writes a ``pending`` record - including the full *before* state and
every request - and fsyncs it BEFORE the first request is sent, then appends a result
record (``applied`` / ``partial`` / ``failed`` / ``unknown``) with the *after* state.

Undo must be able to restore a Wi-Fi password or a VPN key, so the journal keeps the full device
state - but never as plain text.  Every section that holds device state (``requests``, ``before``,
``after``, ``wire``, ``detail``) is encrypted at rest with AES-256-GCM under a random per-install key
(``~/.config/opus-tplink-mcp/journal.key``, 0600; override with ``TPLINK_JOURNAL_KEY``).  The labels
needed to list changes (id, time, tool, summary, status) stay readable.  This protects copies of the
journal (pastes, bug reports, backups, sync, an assistant printing it); it does not protect against
someone already logged in as you, who can read the key too.  Directory 0700, file 0600.  Override the
location with ``TPLINK_JOURNAL_DIR``.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

try:  # POSIX
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]
    import msvcrt

from Crypto.Cipher import AES  # nosec B413 - pycryptodome (maintained), not the dead pyCrypto

SEALED_SECTIONS = ("requests", "before", "after", "wire", "detail")
ENC = "$enc"
UNREADABLE = "unreadable"  # set on an entry whose sealed state cannot be decrypted (key missing or changed)


def default_dir() -> Path:
    env = os.environ.get("TPLINK_JOURNAL_DIR")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return Path(base) / "mcp-tplink-router"


def default_key_path() -> Path:
    env = os.environ.get("TPLINK_JOURNAL_KEY")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "opus-tplink-mcp" / "journal.key"


def _load_key(path: Path, create: bool) -> bytes | None:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        if not create:
            return None
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".journal-key-")
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, base64.b64encode(os.urandom(32)) + b"\n")
            os.fsync(fd)
            os.close(fd)
            with contextlib.suppress(FileExistsError):  # another process won the race: use its key
                os.link(tmp, path)  # atomic: readers never see a half-written key
        finally:
            with contextlib.suppress(OSError):
                os.close(fd)
            os.unlink(tmp)
        raw = path.read_bytes()
    key = base64.b64decode(raw.strip() or b"", validate=True)
    if len(key) != 32:
        raise ValueError(f"journal key {path} is not a 32-byte key")
    return key


def _kid(key: bytes) -> str:
    return hashlib.sha256(b"journal-key-id|" + key).hexdigest()[:8]


class Journal:
    def __init__(self, directory: str | Path | None = None, key_path: str | Path | None = None) -> None:
        self.dir = Path(directory) if directory else default_dir()
        self.path = self.dir / "journal.jsonl"
        self.key_path = Path(key_path) if key_path else default_key_path()

    @contextlib.contextmanager
    def _locked(self):  # type: ignore[no-untyped-def]
        """One writer at a time across processes (two MCP clients can each run a server)."""
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.dir / ".journal.lock", os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            else:
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            yield
        finally:
            os.close(fd)  # closing releases the lock on both

    # -------------------------------------------------------------------------- encryption at rest
    def _seal(self, record: dict[str, Any]) -> dict[str, Any]:
        key = _load_key(self.key_path, create=True)
        assert key is not None
        out = dict(record)
        for sec in SEALED_SECTIONS:
            if out.get(sec) is None or (isinstance(out[sec], dict) and ENC in out[sec]):
                continue
            nonce = os.urandom(12)
            c = AES.new(key, AES.MODE_GCM, nonce=nonce)
            c.update(f"{out.get('id')}|{sec}".encode())
            ct, tag = c.encrypt_and_digest(json.dumps(out[sec], ensure_ascii=False, default=str).encode())
            out[sec] = {ENC: base64.b64encode(nonce + ct + tag).decode(), "v": 1, "kid": _kid(key)}
        return out

    def _open(self, record: dict[str, Any], key: bytes | None) -> dict[str, Any]:
        out = dict(record)
        for sec in SEALED_SECTIONS:
            v = out.get(sec)
            if not (isinstance(v, dict) and ENC in v):
                continue
            try:
                if key is None:
                    out[UNREADABLE] = "the journal key is missing"
                    raise ValueError("no key")
                if v.get("kid") and v["kid"] != _kid(key):
                    out[UNREADABLE] = "this change was saved under a different journal key"
                    raise ValueError("other key")
                blob = base64.b64decode(v[ENC])
                c = AES.new(key, AES.MODE_GCM, nonce=blob[:12])
                c.update(f"{out.get('id')}|{sec}".encode())
                out[sec] = json.loads(c.decrypt_and_verify(blob[12:-16], blob[-16:]))
            except (ValueError, KeyError):
                out[sec] = None
                out.setdefault(UNREADABLE, "the saved state failed its integrity check (edited or damaged)")
        return out

    @staticmethod
    def _has_plaintext(record: dict[str, Any]) -> bool:
        return any(record.get(sec) is not None and not (isinstance(record[sec], dict) and ENC in record[sec])
                   for sec in SEALED_SECTIONS)

    def migrate(self) -> int:
        """Encrypt any plain-text state left by older versions.  Returns how many records were sealed."""
        if not self.path.exists():
            return 0
        with self._locked():
            return self._migrate_locked()

    def _migrate_locked(self) -> int:
        lines = self.path.read_text(encoding="utf-8").splitlines()
        out, n = [], 0
        for line in lines:
            try:
                rec = json.loads(line) if line.strip() else None
            except ValueError:
                rec = None
            if isinstance(rec, dict) and self._has_plaintext(rec):
                rec, n = self._seal(rec), n + 1
                out.append(json.dumps(rec, ensure_ascii=False, default=str))
            else:
                out.append(line)
        if n:
            fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".journal-", suffix=".tmp")
            try:
                os.fchmod(fd, 0o600)
                os.write(fd, ("\n".join(out) + "\n").encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, self.path)
            dfd = os.open(self.dir, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        return n

    def _append(self, record: dict[str, Any]) -> None:
        line = (json.dumps(self._seal(record), ensure_ascii=False, default=str) + "\n").encode()
        with self._locked():  # opened after taking the lock, so a migration's rename is never written past
            os.chmod(self.dir, 0o700)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.fchmod(fd, 0o600)
                os.write(fd, line)
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
        try:
            key = _load_key(self.key_path, create=False)
        except ValueError:
            key = None
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
                rec = self._open(rec, key)
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
