"""Optional field reports: what failed (and which models/firmware this tool met), so it gets fixed.

OFF until a person turns it on.  The choice is made by a human in an interactive terminal
(``opus-tplink-mcp setup``) or the viewer window, after reading NOTICE; it is stored as a consent record
(choice, notice version, date) in the user's config dir.  ``TPLINK_REPORTING=off`` can force it off; no
environment variable, MCP tool or AI agent can turn it on.  A new NOTICE_VERSION reverts everyone to OFF
until they re-confirm.  OFF means no network traffic at all.

THE CONTRACT (tests/test_reporting.py holds it):
  * Reports are built from a separate allowlisted structure - never from the local event log, which
    holds Wi-Fi names, MACs and hostnames.
  * Fields: a code from CODES, a feature CATEGORY (not the exact form), the exception TYPE name, stack
    frames inside this package as module:function:line, tool / Python / OS-family versions, protocol,
    device kind, model tier (small/large - never the AI model's name), and the router model / hardware /
    firmware strings after validation.  Never arguments, addresses, MACs, SSIDs, names, messages, paths.
  * No install ID.  Deduplicated and capped per day on disk (AI clients restart the server constantly).
  * Every payload sent is also written to reports-sent.jsonl, and ``opus-tplink-mcp report --dry-run``
    prints what would be sent.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import sys
import threading
import time
import traceback
import urllib.request
from pathlib import Path
from typing import Any

NOTICE_VERSION = 1
DEFAULT_SERVER = "https://by-ai-for-ai.com/api/opus-tplink-mcp"
API_KEY = "AmLd-jBQtV6djsbbR9vD7rveFvITjEdk"  # ships in the open-source client; the server validates everything
DAILY_CAP = 40
_TIMEOUT = 4

NOTICE = """\
=========================================================================
  opus-tplink-mcp can send FIELD REPORTS to a small public server run by
  its maintainer, so problems get fixed and the list of supported
  routers grows by itself.  It is OFF until you choose.

  If you turn it on, it sends:
    1. Problems - when a change fails, a router refuses a request, or the
       tool crashes: an error code, a feature category (e.g. "wifi",
       "access controls"), the error type, where in this tool it happened
       (module:function:line), and the tool / Python / OS-family versions.
    2. The routers it met - model, hardware version and firmware version
       (e.g. "Archer AX3000 v1.0, 1.0.6"), the login style, and whether
       things worked.  Once per model and firmware, not per use.

  It never sends: passwords, addresses (IP or MAC), Wi-Fi names, device
  or host names, what you asked for, error messages, or file paths.
  No install ID.  Your IP address does reach the server (it is run by an
  individual); the server does not store it.  Only totals are published.

  Change your mind any time:   opus-tplink-mcp setup
  See exactly what is sent:    opus-tplink-mcp report --dry-run
========================================================================="""

CODES = {
    "no_such_callback", "http_404", "login_refused", "login_failed", "not_done", "unknown_after_apply",
    "mismatch", "no_effect", "collateral", "unreachable", "settle_timeout", "firmware_changed",
    "refused", "recovered_previewed_call", "no_such_device", "internal_error", "device_seen",
}
CATEGORIES = {  # tool -> coarse feature category (exact forms reveal what a household does)
    "wifi_set": "wifi", "wifi_extra": "wifi", "wifi_schedule": "wifi", "mesh": "wifi",
    "access_control": "access controls", "parental_control": "access controls", "ip_mac_binding": "network",
    "dhcp_reservation": "network", "dhcp_server_set": "network", "lan": "network", "routing": "network",
    "internet": "internet", "ddns": "internet", "port_forwarding": "internet", "upnp": "internet",
    "vpn_client": "vpn", "vpn_server": "vpn", "system": "system", "maintenance": "system", "admin": "system",
    "usb": "system", "clients": "devices", "device_log": "devices", "router_status": "status",
    "router_logs": "status", "router_journal": "journal", "router_undo": "journal", "extender": "extender",
    "extender_set": "extender", "router_get": "raw", "router_raw_read": "raw", "router_raw_write": "raw",
    "router_catalog": "raw",
}
_SAFE_STR = re.compile(r"^[A-Za-z0-9 ._()+/-]{1,64}$")
_lock = threading.Lock()


# ------------------------------------------------------------------------------------- consent
def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "opus-tplink-mcp"


def _consent_file() -> Path:
    return config_dir() / "reporting.json"


def consent() -> dict[str, Any]:
    try:
        return json.loads(_consent_file().read_text())
    except (OSError, ValueError):
        return {}


def is_enabled() -> bool:
    if os.environ.get("TPLINK_REPORTING", "").strip().lower() in ("off", "0", "false", "no"):
        return False
    c = consent()
    return c.get("choice") == "on" and int(c.get("notice_version") or 0) >= NOTICE_VERSION


def decided() -> bool:
    c = consent()
    return c.get("choice") in ("on", "off") and int(c.get("notice_version") or 0) >= NOTICE_VERSION


def record_choice(on: bool) -> None:
    """Called only from an interactive prompt or the viewer - never from an MCP tool."""
    d = config_dir()
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = d / ".reporting.json.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps({"choice": "on" if on else "off", "notice_version": NOTICE_VERSION,
                                 "decided_at": time.strftime("%Y-%m-%d")}).encode())
    finally:
        os.close(fd)
    os.replace(tmp, _consent_file())


def status_line() -> str:
    if os.environ.get("TPLINK_REPORTING", "").strip().lower() in ("off", "0", "false", "no"):
        return "field reports: OFF (forced by TPLINK_REPORTING=off)"
    c = consent()
    if not decided():
        return "field reports: OFF - not chosen yet (run: opus-tplink-mcp setup)"
    return f"field reports: {c['choice'].upper()} since {c.get('decided_at', '?')} (change: opus-tplink-mcp setup)"


def interactive_setup(stdin: Any = None, stdout: Any = None) -> int:
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    if not (hasattr(stdin, "isatty") and stdin.isatty()):
        print("opus-tplink-mcp setup must be run by a person in a terminal (it asks a question).", file=sys.stderr)
        return 2
    print(NOTICE, file=stdout)
    print(f"\nCurrently: {status_line()}", file=stdout)
    while True:
        print("Turn field reports ON or OFF? [on/off]: ", end="", file=stdout, flush=True)
        ans = stdin.readline().strip().lower()
        if ans in ("on", "off"):
            record_choice(ans == "on")
            print(status_line(), file=stdout)
            return 0
        if not ans:
            print("(nothing chosen - reports stay OFF)", file=stdout)
            return 1


# ------------------------------------------------------------------------------------- payloads
def _clean(v: Any) -> str | None:
    s = str(v or "").strip()
    return s if _SAFE_STR.match(s) else None


def _frames(exc: BaseException | None) -> list[str]:
    if exc is None:
        return []
    out = []
    for fr in traceback.extract_tb(exc.__traceback__):
        mod = Path(fr.filename).stem
        if "mcp_tplink_router" in fr.filename.replace("\\", "/"):
            out.append(f"mcp_tplink_router.{mod}:{fr.name}:{fr.lineno}")
    return out[-8:]


def build(code: str, *, tool: str | None = None, device: dict[str, Any] | None = None, protocol: str | None = None,
          kind: str | None = None, exc: BaseException | None = None) -> dict[str, Any] | None:
    """The ONLY way a report payload is made.  Unknown codes produce nothing."""
    if code not in CODES:
        return None
    from . import __version__
    from .safety import model_tier

    d = device or {}
    p: dict[str, Any] = {
        "code": code,
        "category": CATEGORIES.get(str(tool), "other") if tool else None,
        "exc_type": type(exc).__name__ if exc else None,
        "stack": _frames(exc),
        "tool_version": __version__,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "os": {"Linux": "Linux", "Windows": "Windows", "Darwin": "Darwin"}.get(platform.system(), "Other"),
        "protocol": protocol if protocol in ("plain", "encrypted", "extender", "encrypted-v2") else None,
        "kind": kind if kind in ("router", "extender") else None,
        "tier": model_tier(),
        "model": _clean(d.get("model")),
        "hardware": _clean(d.get("hardware_version")),
        "firmware": _clean(d.get("firmware_version")),
        "day": time.strftime("%Y-%m-%d", time.gmtime()),
    }
    return {k: v for k, v in p.items() if v not in (None, [], "")}


# ------------------------------------------------------------------------------------- sending
def _state_path() -> Path:
    from . import events

    return events.path().with_name("reports-state.json")


def _sent_log() -> Path:
    from . import events

    return events.path().with_name("reports-sent.jsonl")


def submit(payload: dict[str, Any] | None) -> bool:
    """Queue one report.  Returns True if it was (or would be) sent.  Never raises, never blocks."""
    if not payload or not is_enabled():
        return False
    try:
        key = hashlib.sha256(json.dumps({k: v for k, v in payload.items() if k != "day"}, sort_keys=True)
                             .encode()).hexdigest()[:16]
        today = time.strftime("%Y-%m-%d", time.gmtime())
        with _lock:
            sp = _state_path()
            try:
                st = json.loads(sp.read_text())
            except (OSError, ValueError):
                st = {}
            if st.get("day") != today:
                st = {"day": today, "count": 0, "keys": [], "seen_devices": st.get("seen_devices", [])}
            if key in st["keys"] or st["count"] >= DAILY_CAP:
                return False
            if payload.get("code") == "device_seen":
                dk = "|".join(str(payload.get(k)) for k in ("model", "hardware", "firmware", "tool_version"))
                if dk in st["seen_devices"]:
                    return False
                st["seen_devices"] = (st["seen_devices"] + [dk])[-500:]
            st["keys"].append(key)
            st["count"] += 1
            sp.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            sp.write_text(json.dumps(st))
            os.chmod(sp, 0o600)
            fd = os.open(_sent_log(), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, (json.dumps(payload) + "\n").encode())
            finally:
                os.close(fd)
        threading.Thread(target=_post, args=(payload,), daemon=True).start()
        return True
    except Exception:  # noqa: BLE001 - reporting must never affect the tool
        return False


def _post(payload: dict[str, Any]) -> None:
    url = os.environ.get("TPLINK_REPORT_URL", DEFAULT_SERVER).rstrip("/") + "/report"
    if not url.startswith("https://"):
        return
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                     headers={"content-type": "application/json", "x-otm-key": API_KEY,
                                              "user-agent": "opus-tplink-mcp"})
        urllib.request.urlopen(req, timeout=_TIMEOUT).read(256)  # nosec B310 - https only, fixed host
    except Exception:  # noqa: BLE001,S110 - fire and forget
        pass


# ------------------------------------------------------------------------------------- tool outcomes
_STATUS_CODES = {"NOT_DONE": "not_done", "UNKNOWN": "unknown_after_apply", "mismatch": "mismatch",
                 "no_effect": "no_effect", "collateral": "collateral", "NO_SUCH_DEVICE": "no_such_device",
                 "REFUSED_NOTHING_CHANGED": "refused"}


def from_reply(tool: str, out: Any, device: dict[str, Any] | None, protocol: str | None, kind: str | None) -> None:
    """Map a tool reply to at most one report code.  Only structural facts - nothing from the reply text."""
    if not is_enabled() or not isinstance(out, dict):
        return
    st = str(out.get("status") or "")
    err = str(out.get("error") or "")
    code = _STATUS_CODES.get(st)
    if not code and err:
        code = ("no_such_callback" if "no such callback" in err else "http_404" if "404" in err
                else "login_failed" if err.startswith("login") else "unreachable" if "network" in err
                else None)
    if not code and "left out arguments" in str(out.get("hint", "")):
        code = "recovered_previewed_call"
    if code:
        submit(build(code, tool=tool, device=device, protocol=protocol, kind=kind))


def dry_run_main(_argv: list[str] | None = None) -> int:
    from . import events

    print(status_line())
    sf = events.path().with_name("devices-seen.json")
    try:
        seen = json.loads(sf.read_text())
    except (OSError, ValueError):
        seen = {}
    print("\nExample payloads this install WOULD send (nothing is sent by this command):")
    for v in list(seen.values())[:3]:
        print(json.dumps(build("device_seen", device=v), indent=1))
    print(json.dumps(build("not_done", tool="wifi_set", device=next(iter(seen.values()), None)), indent=1))
    log = _sent_log()
    n = len(log.read_text().splitlines()) if log.exists() else 0
    print(f"\nReports actually sent so far: {n} (each one is recorded in {log})")
    return 0
