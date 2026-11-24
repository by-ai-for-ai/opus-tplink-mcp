"""Local event log (``events.jsonl``): what the server did that deserves a look, for the live viewer.

One JSON line per event - errors, refusals, NOT DONE, recoveries, unreachable devices, failed logins,
verified changes, Wi-Fi restarts, unknown devices, and the firmware each device reported.  It lives
next to the change journal (``TPLINK_JOURNAL_DIR``; ``TPLINK_EVENTS_FILE`` overrides), mode 0600, and
rotates at 5 MB (one old file kept).  Everything written is passed through ``safety.redact`` first:
no passwords or keys, ever.  Writing an event never raises - the log must not break a tool call.

This file never leaves the machine.  (Optional anonymous field reports are a separate, opt-in module.)
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

MAX_BYTES = 5 * 1024 * 1024
_lock = threading.Lock()

# What each event kind means - also the colour key for the viewers.
KINDS = {
    "error": "a tool call failed",
    "not_done": "a change was asked for and nothing changed",
    "unknown": "a change may or may not have reached the device",
    "refused": "the safety gate refused a change (preview / token)",
    "mismatch": "the device did not end up as requested",
    "recovered": "the tool handed back the right call after a model mistake",
    "no_such_device": "a device name that is not configured",
    "not_supported": "a feature this tool does not support on this router's firmware",
    "unreachable": "a device did not answer",
    "login_failed": "a device refused the login",
    "changed": "a change was applied and verified",
    "restart": "a change restarted the device's Wi-Fi",
    "firmware_seen": "the first firmware seen for a device",
    "firmware_changed": "a device now reports different firmware",
    "mode_changed": "a device now runs in a different operation mode (router / AP / repeater ...)",
}


def path() -> Path:
    env = os.environ.get("TPLINK_EVENTS_FILE")
    if env:
        return Path(env).expanduser()
    from .journal import default_dir

    return default_dir() / "events.jsonl"


def emit(kind: str, router: str | None = None, **data: Any) -> None:
    """Append one event.  Never raises."""
    try:
        from .safety import redact

        rec = redact({"ts": time.time(), "kind": kind, "router": router, **data})
        line = (json.dumps(rec, ensure_ascii=False, default=str) + "\n").encode()
        p = path()
        with _lock:
            p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                if p.stat().st_size + len(line) > MAX_BYTES:
                    os.replace(p, p.with_suffix(".jsonl.1"))
            except FileNotFoundError:
                pass
            fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line)
            finally:
                os.close(fd)
    except Exception:  # noqa: BLE001 - the log must never break a tool call
        pass


def read(limit: int = 200) -> list[dict[str, Any]]:
    """The newest ``limit`` events, oldest first."""
    p = path()
    if not p.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


# ------------------------------------------------------------------------------------- tool outcomes
def from_reply(tool: str, args: dict[str, Any], out: Any, router: str | None, read_only: bool) -> None:
    """Classify one tool reply into (at most) one event.  Plain successful reads are not logged."""
    if not isinstance(out, dict):
        return
    st = str(out.get("status") or "")
    base = {"tool": tool, "action": args.get("action"), "read": read_only}
    tell = str(out.get("tell_user") or "")[:300]
    err = out.get("error")
    msg = str(out.get("message") or "")
    if st == "NOT_SUPPORTED":
        emit("not_supported", router, **base, tell_user=tell)
    elif st == "NO_SUCH_DEVICE":
        emit("no_such_device", router, **base, asked=args.get("router") or args.get("device"))
    elif err and ("did not answer" in str(out.get("hint", "")) or "timed out" in msg or "ConnectTimeout" in msg):
        emit("unreachable", router, **base, error=str(err)[:200])
    elif err and str(err).startswith("login"):
        emit("login_failed", router, **base, error=str(err)[:200])
    elif st in ("REFUSED_NOTHING_CHANGED",) or out.get("refused"):
        emit("refused", router, **base, reason=str(out.get("refused") or "")[:200])
    elif "next_call" in out and "left out arguments" in str(out.get("hint", "")):
        emit("recovered", router, **base, hint=str(out.get("hint"))[:200])
    elif st == "NOT_DONE":
        emit("not_done", router, **base, error=str(err or "")[:200], tell_user=tell)
    elif st == "UNKNOWN" or out.get("verified") == "unknown" and st not in ("applied",):
        emit("unknown", router, **base, tell_user=tell)
    elif st in ("mismatch", "no_effect", "collateral", "partial", "failed"):
        emit("mismatch", router, **base, status=st, tell_user=tell)
    elif st == "applied" and out.get("verified") in ("yes", "after_restart"):
        emit("changed", router, **base, verified=out.get("verified"), tell_user=tell,
             journal_id=out.get("journal_id"))
        if out.get("after_restart"):
            emit("restart", router, **base, after_restart=out.get("after_restart"))
    elif err:
        emit("error", router, **base, error=str(err)[:200], message=msg[:200])


# ------------------------------------------------------------------------------------- firmware watch
_SEEN: dict[str, float] = {}
FIRMWARE_EVERY = 6 * 3600.0  # seconds between firmware checks per device per process


def _state_file() -> Path:
    return path().with_name("devices-seen.json")


def firmware_due(router: str) -> bool:
    return time.time() - _SEEN.get(router, 0) >= FIRMWARE_EVERY


def note_firmware(router: str, host: str, fw: dict[str, Any] | None) -> dict[str, Any] | None:
    """Record the model / hardware / firmware a device reported.  Returns the change, if any."""
    _SEEN[router] = time.time()
    if not isinstance(fw, dict):
        return None
    now = {k: fw.get(k) for k in ("model", "hardware_version", "firmware_version", "mode") if fw.get(k)}
    if not now.get("firmware_version"):
        return None
    sf = _state_file()
    try:
        state = json.loads(sf.read_text()) if sf.exists() else {}
    except ValueError:
        state = {}
    key = f"{router}@{host}"
    prev = state.get(key)
    change = None
    if prev is None:
        emit("firmware_seen", router, **now)
    elif {k: prev.get(k) for k in now} != now:
        change = {"from": {k: prev.get(k) for k in now}, "to": now}
        fw_keys = ("model", "hardware_version", "firmware_version")
        if any(prev.get(k) != now.get(k) for k in fw_keys if k in now):
            emit("firmware_changed", router, **change)
        else:
            emit("mode_changed", router, **change)
    state[key] = {**now, "seen": time.time()}
    try:
        with _lock:
            sf.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = sf.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, json.dumps(state, indent=1).encode())
            finally:
                os.close(fd)
            os.replace(tmp, sf)
    except OSError:
        pass
    return change


def device_info(router: str, host: str) -> dict[str, Any]:
    """Model / hardware / firmware last seen for this device (empty if never read)."""
    try:
        return dict(json.loads(_state_file().read_text()).get(f"{router}@{host}") or {})
    except (OSError, ValueError):
        return {}
