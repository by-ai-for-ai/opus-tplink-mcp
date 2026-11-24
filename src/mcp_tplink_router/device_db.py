"""Shared known-device identities: receive the community table, and (only if a person chose it) contribute.

Three choices, set only by a person in a terminal (`opus-tplink-mcp devices sharing`), never by an MCP tool:

  * off      (default) nothing is downloaded or sent.
  * receive  the public table (maker prefix -> model names devices announced, seen on >= 3 networks) is
             downloaded about once a week and matched LOCALLY - no per-device question ever leaves the computer.
  * share    receive, and also send one identity per device that announced its model over mDNS:
             {oui: first 6 hex digits of a NON-private MAC (the maker's prefix), model: what the device
             announced, kind: the router's type guess}.  Never a full MAC, IP, hostname, a name you or the
             router gave it, or anything from the private device record.  One device per request, each at most
             once a month; every payload sent is logged in known-devices-sent.jsonl.

`TPLINK_DEVICE_SHARING=off` forces off (it cannot turn anything on).  Downloads and sends run in a background
thread with short timeouts and never raise: the tool works the same with the service down.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

from . import events, makers
from .reporting import API_KEY, config_dir

# The shared device names have their own host, NOT behind a CDN: TLS ends on the maintainer's server, which keeps
# no access log and no IPs (an IP over the rate limit is logged for up to a day so it can be banned).
KD_SERVER = "https://kd.by-ai-for-ai.com"

CHOICES = ("off", "receive", "share")
REFRESH = 7 * 86400
RESEND = 30 * 86400
_TIMEOUT = 5
MODEL_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()+/,&-]{1,47}$")
NOTICE = """\
=========================================================================
  Shared device names (optional).  Helps name the devices on your network
  whose own name is a placeholder ("network device", "localhost").

  off      nothing is downloaded or sent (default)
  receive  use the public table (shipped with the tool, refreshed about
           weekly) on this computer; nothing about your network is sent
  share    receive, and also send, for each device that announced its
           model over mDNS: the maker prefix (first half of its MAC,
           never a private one), that model name, and the router's type
           guess.  NEVER a full MAC, an IP address, a hostname, a name
           you or the router gave it, or your private device record.
           One device per request; the server cannot join them up.

  The server (kd.by-ai-for-ai.com, not behind a CDN) sees your IP while
  it answers and does not keep it; an IP that floods it is logged for up
  to a day to ban it.  Every payload sent is logged on this computer.
  Change any time:
  opus-tplink-mcp devices sharing
=========================================================================
"""


def _choice_file() -> Path:
    return config_dir() / "device-sharing.json"


def choice() -> str:
    if os.environ.get("TPLINK_DEVICE_SHARING", "").strip().lower() in ("off", "0", "false", "no"):
        return "off"
    try:
        c = json.loads(_choice_file().read_text()).get("choice")
    except (OSError, ValueError, AttributeError):
        return "off"
    return c if c in CHOICES else "off"


def record_choice(c: str) -> None:
    """Called only from the interactive prompt - never from an MCP tool."""
    if c not in CHOICES:
        raise ValueError(c)
    d = config_dir()
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = d / ".device-sharing.json.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps({"choice": c, "decided_at": time.strftime("%Y-%m-%d")}).encode())
    finally:
        os.close(fd)
    os.replace(tmp, _choice_file())


def interactive(stdin: Any = None, stdout: Any = None) -> int:
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    if not (hasattr(stdin, "isatty") and stdin.isatty()):
        print("this must be run by a person in a terminal (it asks a question).", file=sys.stderr)
        return 2
    print(NOTICE, file=stdout)
    print(f"Currently: {choice()}", file=stdout)
    print("Choose off / receive / share: ", end="", file=stdout, flush=True)
    ans = stdin.readline().strip().lower()
    if ans in CHOICES:
        record_choice(ans)
        print(f"Shared device names: {ans}", file=stdout)
        return 0
    print("(nothing chosen - unchanged)", file=stdout)
    return 1


# ------------------------------------------------------------------------------------------- payload
def build(device: dict[str, Any]) -> dict[str, str] | None:
    """The ONLY thing ever sent for a device: maker prefix, announced model, router type.  None = send nothing."""
    raw = str(((device.get("announces") or {}).get("details") or {}).get("model") or "")
    model = " ".join(raw.split())
    if any(not c.isprintable() for c in raw) or not MODEL_OK.match(model):
        return None
    mac = "".join(c for c in str(device.get("mac") or "").upper() if c in "0123456789ABCDEF")
    oui = "" if len(mac) != 12 or makers.is_private(mac) or makers.virtual(mac) else mac[:6]
    kind = str(device.get("type") or "").removesuffix(" (the router's guess)")
    return {"oui": oui, "model": model, "kind": kind}


def _state_dir() -> Path:
    return events.path().parent


def _sent_log() -> Path:
    return _state_dir() / "known-devices-sent.jsonl"


def _sent_recently() -> dict[str, float]:
    out: dict[str, float] = {}
    try:
        for line in _sent_log().read_text().splitlines():
            r = json.loads(line)
            out[r["key"]] = max(out.get(r["key"], 0.0), float(r["at"]))
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return out


def _server() -> str | None:
    url = os.environ.get("TPLINK_KD_URL", KD_SERVER).rstrip("/")
    return url if url.startswith("https://") else None


def _send_all(payloads: list[dict[str, str]]) -> None:
    base = _server()
    if not base:
        return
    recent, now = _sent_recently(), time.time()
    for p in payloads:
        key = hashlib.sha256(f"{p['oui']}|{p['model']}".encode()).hexdigest()[:16]
        if now - recent.get(key, 0) < RESEND:
            continue
        try:
            req = urllib.request.Request(base + "/known-devices", data=json.dumps(p).encode(), method="POST",
                                         headers={"content-type": "application/json", "x-otm-key": API_KEY,
                                                  "user-agent": "opus-tplink-mcp"})
            urllib.request.urlopen(req, timeout=_TIMEOUT).read(256)  # nosec B310 - https only, fixed host
        except Exception:  # noqa: BLE001,S112 - best effort
            continue
        try:
            _sent_log().parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(_sent_log(), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            os.write(fd, (json.dumps({"at": now, "key": key, "sent": p}) + "\n").encode())
            os.close(fd)
        except OSError:
            pass
        recent[key] = now


def contribute(devices: list[dict[str, Any]]) -> int:
    """Queue identities for the devices that announced a model (share only).  Returns how many were queued."""
    if choice() != "share":
        return 0
    payloads = [p for p in (build(d) for d in devices) if p]
    if payloads:
        threading.Thread(target=_send_all, args=(payloads,), daemon=True).start()
    return len(payloads)


# ------------------------------------------------------------------------------------------- receive
def _cache() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "opus-tplink-mcp" / "known-devices.json"


def _download() -> None:
    base = _server()
    if not base:
        return
    try:
        req = urllib.request.Request(base + "/known-devices.json", headers={"user-agent": "opus-tplink-mcp"})
        raw = urllib.request.urlopen(req, timeout=_TIMEOUT).read(5_000_000)  # nosec B310 - https only
        data = json.loads(raw)
        if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
            return
        p = _cache()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_bytes(raw)
        os.replace(tmp, p)
    except Exception:  # noqa: BLE001,S110 - best effort
        pass


_refreshing = threading.Lock()


def _bundled() -> list[Any]:
    """The table shipped with this release (scripts/build_known_devices.py): no network request needed."""
    from importlib import resources

    try:
        data = json.loads(resources.files(__package__).joinpath("data/known-devices.json").read_text())
        return data.get("entries") or [] if isinstance(data, dict) else []
    except (OSError, ValueError, AttributeError):
        return []


def table() -> dict[str, list[dict[str, Any]]]:
    """{oui: [{model, kind, networks}]} from the cached public table (refreshed in the background weekly)."""
    if choice() == "off":
        return {}
    p = _cache()
    try:
        age = time.time() - p.stat().st_mtime
    except OSError:
        age = REFRESH + 1
    if age > REFRESH and _refreshing.acquire(blocking=False):
        def run() -> None:
            try:
                _download()
            finally:
                _refreshing.release()
        threading.Thread(target=run, daemon=True).start()
    try:
        entries = json.loads(p.read_text()).get("entries") or []
    except (OSError, ValueError, AttributeError):
        entries = _bundled()
    out: dict[str, list[dict[str, Any]]] = {}
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, dict):
            continue
        raw = str(e.get("model") or "")
        model = " ".join(raw.split())
        if any(not c.isprintable() for c in raw) or not MODEL_OK.match(model):  # device-announced text: re-check
            continue
        oui = str(e.get("oui") or "").upper()
        try:
            nets = int(e.get("networks") or 0)
        except (TypeError, ValueError):
            continue
        out.setdefault(oui, []).append({"model": model, "kind": str(e.get("kind") or "")[:24], "networks": nets})
    return out


def seen_as(mac: str, tab: dict[str, list[dict[str, Any]]]) -> str | None:
    """'seen as X (N networks), Y (M networks)' for a non-private MAC's maker prefix, or None."""
    hexed = "".join(c for c in str(mac).upper() if c in "0123456789ABCDEF")
    if len(hexed) < 6 or makers.is_private(hexed):
        return None
    hits = sorted(tab.get(hexed[:6], []), key=lambda e: -e["networks"])[:3]
    if not hits:
        return None
    return ("other networks saw devices with this maker prefix announce: "
            + "; ".join(f"{h['model']} ({h['networks']} networks)" for h in hits)
            + " - shared device-announced text, a likely match, not a certainty")


def cli(argv: list[str]) -> int:
    if argv and argv[0] == "sent":
        try:
            print(_sent_log().read_text() or "(nothing sent)")
        except OSError:
            print("(nothing sent)")
        return 0
    return interactive()
