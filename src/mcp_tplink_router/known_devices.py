"""This computer's private record of the devices on its network - never sent anywhere.

Holds what only the household knows: your own label for a device ("Sam's laptop"), an optional owner and note,
when it was first and last seen, and every MAC it has used (phones with private Wi-Fi addresses change them).
A device that has never been seen before is new on the network.

Stored as ONE file, ``known-devices.enc`` next to the change journal, encrypted with AES-256-GCM under a key
derived from the journal key (``journal.default_key_path()``), written atomically (temp file + rename), 0600,
one writer at a time.  Like the journal it protects copies of the file, not against someone already logged in
as you.  Nothing here is ever uploaded: the shared device-identity service only ever receives a maker prefix
and model names announced by devices (see ``device_db.py``).
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES  # nosec B413 - pycryptodome

from . import journal

try:  # POSIX
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]
    import msvcrt

FILE = "known-devices.enc"
WIPE_HINT = "run `opus-tplink-mcp devices wipe` (or delete the file)"
NEW_FOR = 24 * 3600  # a device stays "new on the network" for a day after it is first seen
OFF_WORDS = ("0", "off", "false", "no", "disabled")
OFF_NOTE = ("the private device record is switched off on this computer (TPLINK_KNOWN_DEVICES=off): nothing is "
            "saved or read. Remove that setting to turn it back on.")


def enabled() -> bool:
    """ON unless the user turned it off: TPLINK_KNOWN_DEVICES=off (or 0/false/no).  Off = nothing read or written."""
    return os.environ.get("TPLINK_KNOWN_DEVICES", "on").strip().lower() not in OFF_WORDS
MAX_TEXT = 60


def path() -> Path:
    return journal.default_dir() / FILE


def _key() -> bytes:
    base = journal._load_key(journal.default_key_path(), create=True)
    assert base is not None
    return hashlib.sha256(b"opus-tplink-mcp known-devices v1|" + base).digest()


@contextlib.contextmanager
def _locked():  # type: ignore[no-untyped-def]
    d = path().parent
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(d / ".known-devices.lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        else:
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        yield
    finally:
        os.close(fd)


def load() -> dict[str, Any]:
    """{mac: record}.  A missing file is an empty store; a file that cannot be decrypted raises ValueError."""
    return _read().get("devices", {})


def _read() -> dict[str, Any]:
    try:
        blob = path().read_bytes()
    except FileNotFoundError:
        return {}
    try:
        raw = base64.b64decode(blob.strip())
        nonce, ct, tag = raw[:12], raw[12:-16], raw[-16:]
        c = AES.new(_key(), AES.MODE_GCM, nonce=nonce)
        c.update(b"known-devices")
        data = json.loads(c.decrypt_and_verify(ct, tag))
    except (ValueError, KeyError) as exc:
        raise ValueError(f"cannot read {path()} (damaged, or saved under a different journal key). "
                         f"To start over: {WIPE_HINT}") from exc
    return data if isinstance(data, dict) else {}


def _save(devices: dict[str, Any], created: float | None = None) -> None:
    nonce = os.urandom(12)
    c = AES.new(_key(), AES.MODE_GCM, nonce=nonce)
    c.update(b"known-devices")
    body = {"v": 1, "created": created or time.time(), "devices": devices}
    ct, tag = c.encrypt_and_digest(json.dumps(body, ensure_ascii=False).encode())
    target = path()
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".known-devices-")
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, base64.b64encode(nonce + ct + tag) + b"\n")
        os.fsync(fd)
        os.close(fd)
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _text(v: Any) -> str:
    s = " ".join("".join(c if c.isprintable() else " " for c in str(v)).split())
    return s[:MAX_TEXT]


def observe(devices: list[dict[str, Any]], now: float | None = None) -> tuple[dict[str, Any], set[str]]:
    """Record the devices seen now (first/last seen, earlier MACs under the same name).

    Returns (store, macs that are new on the network): first seen within the last day, but not while the store
    itself was being started (on the very first listing every device is "first seen").  Never raises: any
    problem returns ({}, set()) - remembering devices must never break a listing or the tool.
    """
    if not enabled():
        return {}, set()
    now = time.time() if now is None else now
    try:
        with _locked():
            data = _read()
            store = data.get("devices", {})
            created = data.get("created") or now
            for d in devices:
                mac = str(d.get("mac") or "").upper()
                if not mac:
                    continue
                rec = store.setdefault(mac, {"first_seen": now})
                rec["last_seen"] = now
                if d.get("name") and rec.get("router_name") != d.get("name"):
                    rec["router_name"] = _text(d["name"])
                for m in d.get("same_name_seen_on") or []:
                    if m not in rec.setdefault("other_macs", []):
                        rec["other_macs"] = (rec["other_macs"] + [m])[-12:]
            _save(store, created)
            new = {m for m, r in store.items()
                   if now - r.get("first_seen", 0) < NEW_FOR and r.get("first_seen", 0) - created > 60}
            return store, new
    except Exception:  # noqa: BLE001 - e.g. a damaged store, a read-only disk, os.fchmod missing on old Windows
        return {}, set()


def label(mac: str, name: str | None, owner: str | None = None, note: str | None = None) -> dict[str, Any]:
    with _locked():
        data = _read()
        store = data.get("devices", {})
        rec = store.setdefault(mac.upper(), {"first_seen": time.time()})
        for k, v in (("label", name), ("owner", owner), ("note", note)):
            if v is not None:
                if str(v).strip():
                    rec[k] = _text(v)
                else:
                    rec.pop(k, None)
        _save(store, data.get("created"))
        return dict(rec)


def forget(mac: str) -> bool:
    with _locked():
        data = _read()
        store = data.get("devices", {})
        gone = store.pop(mac.upper(), None) is not None
        if gone:
            _save(store, data.get("created"))
        return gone


def wipe() -> bool:
    """Delete the whole private record - works even when it cannot be decrypted.  True if a file was removed."""
    removed = False
    for p in (path(), path().parent / ".known-devices.lock"):
        try:
            p.unlink()
            removed = removed or p.name == FILE
        except FileNotFoundError:
            pass
    return removed


def cli(argv: list[str]) -> int:
    """`opus-tplink-mcp devices [status|wipe]` - for people (no MCP tool can wipe it)."""
    cmd = argv[0] if argv else "status"
    if cmd in ("sharing", "sent"):
        from . import device_db

        return device_db.cli(argv)
    if cmd == "wipe":
        if "--yes" not in argv:
            try:
                ok = input(f"Delete {path()} (your device labels and history)? Type yes: ").strip().lower() == "yes"
            except EOFError:
                ok = False
            if not ok:
                print("Nothing deleted.")
                return 1
        print("Deleted." if wipe() else f"Nothing to delete ({path()} does not exist).")
        return 0
    if cmd == "status":
        state = "ON" if enabled() else "OFF (TPLINK_KNOWN_DEVICES)"
        try:
            n = f"{len(load())} device(s)" if path().exists() else "empty"
        except ValueError as exc:
            n = f"UNREADABLE - {exc}"
        print(f"private device record: {state}\nfile: {path()}\ncontents: {n}")
        return 0
    print("usage: opus-tplink-mcp devices [status | wipe [--yes] | sharing | sent]")
    return 2
