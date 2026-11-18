"""Everything the router knows about ONE device, and a local per-MAC history of it.

The router itself only keeps today's parental-control counts, a rolling system log and the
current client list.  ``report`` gathers all of it for one MAC in one place; ``record``
appends what is NEW since the last record to ``<state dir>/device-logs/<MAC>.jsonl`` so a
history survives beyond what the router keeps (run it from a timer for continuous logging);
``history`` reads that file back.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .. import forms
from ..transport import RouterError
from . import Ctx, UsageError, find_mac, pick

PACTRL = "avira_parental_control?form=avira_pactrl"


def log_dir() -> Path:
    base = os.environ.get("TPLINK_DEVICE_LOG_DIR") or os.path.join(
        os.environ.get("TPLINK_JOURNAL_DIR") or os.path.expanduser("~/.local/state/mcp-tplink-router"),
        "device-logs")
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _mac_patterns(mac: str) -> list[str]:
    raw = mac.replace("-", "").lower()
    pairs = [raw[i:i + 2] for i in range(0, 12, 2)]
    return [":".join(pairs), "-".join(pairs), raw]


def _try(fn: Any, *a: Any) -> Any:
    try:
        return fn(*a)
    except RouterError as exc:
        return {"error": exc.code}


def _rows(data: Any) -> list[dict[str, Any]]:
    return data if isinstance(data, list) else []


def gather(ctx: Ctx, mac: str) -> dict[str, Any]:
    """One snapshot of everything about ``mac``."""
    t = ctx.t
    online = next((c for c in _try(ctx.clients) or [] if isinstance(c, dict) and c.get("mac") == mac), None)
    leases = _rows(_try(ctx.rows, "dhcps?form=client"))
    lease = next((r for r in leases if forms.key_equal("mac", r.get("macaddr"), mac)), None)
    reservation = pick(_rows(_try(ctx.rows, "dhcps?form=reservation")), mac=mac)
    ips = {x for x in ((online or {}).get("ip"), (lease or {}).get("ipaddr"),
                       *(r.get("ip") for r in reservation)) if x}
    # router system log lines that mention the MAC (any notation) or one of its IPs
    pats = _mac_patterns(mac)
    ip_res = [re.compile(rf"(?<![\d.]){re.escape(ip)}(?![\d.])") for ip in ips]
    logs = []
    for r in _rows(_try(forms.load_table, t, "syslog?form=log")):
        text = str(r.get("content", ""))
        low = text.lower()
        if any(p in low for p in pats) or any(rx.search(text) for rx in ip_res):
            logs.append({"time": r.get("time"), "type": r.get("type"), "level": r.get("level"), "content": text})
    # parental-control profile (sites are per PROFILE, not per device)
    devs = _try(t.call, PACTRL, "getDevicesList")
    dev = next((d for d in ((devs or {}).get("clientList") or [] if isinstance(devs, dict) else [])
                if forms.key_equal("mac", d.get("mac"), mac)), None)
    profile: dict[str, Any] | None = None
    owner = str((dev or {}).get("ownerId", -1))
    if dev and owner not in ("-1", "", "None"):
        profile = {"owner_id": owner,
                   "sites_today": _try(t.call, PACTRL, "getTodayVisitSites", {"ownerId": owner}),
                   "blocked_attempts": _try(t.call, PACTRL, "getBlockHistory", {"ownerId": owner})}
    mode = _try(ctx.read, "access_control?form=mode")
    ac_on = _try(ctx.read, "access_control?form=enable")
    blocked = bool(pick(_rows(_try(ctx.rows, "access_control?form=black_list")), mac=mac))
    allowed = bool(pick(_rows(_try(ctx.rows, "access_control?form=white_list")), mac=mac))
    prio = pick(_rows(_try(ctx.rows, "smart_network?form=device_priority")), mac=mac)
    return {
        "mac": mac,
        "time": datetime.now().isoformat(timespec="seconds"),
        "online": online is not None,
        "connection": online,
        "name": (online or {}).get("name") or (lease or {}).get("name") or (dev or {}).get("name"),
        "dhcp_lease": lease,
        "reservation": reservation[0] if reservation else None,
        "random_mac": bool(int(mac[:2], 16) & 0x02),
        "access_control": {"enabled": (ac_on or {}).get("enable") if isinstance(ac_on, dict) else None,
                           "mode": (mode or {}).get("access_mode") if isinstance(mode, dict) else None,
                           "on_block_list": blocked, "on_allow_list": allowed},
        "vpn_client_routed": bool(pick(_rows(_try(ctx.rows, "vpn?form=vpn_user_list")), mac=mac, access="on")),
        "on_iot_network": bool(pick(_rows(_try(ctx.rows, "iot_security?form=isolated_list")), mac=mac)),
        "traffic": ({k: prio[0].get(k) for k in ("downloadSpeed", "uploadSpeed", "trafficUsage", "enablePriority")}
                    if prio else None),
        "parental_profile": profile,
        "router_log": logs,
    }


def _last_state(path: Path) -> dict[str, Any]:
    state: dict[str, Any] = {"online": None, "logs": set(), "sites": {}, "blocks": set(), "day": ""}
    if not path.exists():
        return state
    for line in path.read_text().splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        kind = e.get("event")
        if kind in ("online", "offline"):
            state["online"] = kind == "online"
        elif kind == "router_log":
            state["logs"].add(f'{e.get("time")}|{e.get("content")}')
        elif kind == "site":
            if e.get("day") != state["day"]:
                state["day"], state["sites"] = e.get("day"), {}
            state["sites"][e.get("url")] = e.get("visits_today", 0)
        elif kind == "blocked":
            state["blocks"].add(json.dumps(e.get("entry"), sort_keys=True))
    return state


def _site_list(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    return _rows(data)


def record(snap: dict[str, Any], path: Path) -> list[dict[str, Any]]:
    """Append only what changed since the last record; returns the new events."""
    prev = _last_state(path)
    now, day = snap["time"], snap["time"][:10]
    events: list[dict[str, Any]] = []
    if prev["online"] is None or prev["online"] != snap["online"]:
        events.append({"event": "online" if snap["online"] else "offline", "connection": snap["connection"],
                       "name": snap["name"]})
    for line in snap["router_log"]:
        if f'{line["time"]}|{line["content"]}' not in prev["logs"]:
            events.append({"event": "router_log", **line})
    prof = snap.get("parental_profile") or {}
    seen = prev["sites"] if prev["day"] == day else {}
    for s in _site_list(prof.get("sites_today")):
        url = s.get("url") or s.get("site") or s.get("domain")
        cnt = int(s.get("count") or s.get("visitCount") or 0)
        if url and cnt > int(seen.get(url, 0)):
            events.append({"event": "site", "day": day, "url": url, "visits_today": cnt,
                           "new_visits": cnt - int(seen.get(url, 0)), "minutes_today": s.get("spendTime")})
    for b in _site_list(prof.get("blocked_attempts")):
        if json.dumps(b, sort_keys=True) not in prev["blocks"]:
            events.append({"event": "blocked", "entry": b})
    if events:
        with open(path, "a") as fh:
            for e in events:
                fh.write(json.dumps({"ts": now, **e}, default=str) + "\n")
        os.chmod(path, 0o600)
    return events


def device_log(ctx: Ctx) -> Any:
    action = ctx.arg("action", "report")
    if action == "list":
        return {"dir": str(log_dir()), "devices": sorted(p.stem for p in log_dir().glob("*.jsonl"))}
    mac = find_mac(ctx.need("mac"))
    path = log_dir() / f"{ctx.router}-{mac}.jsonl"
    if action == "report":
        return gather(ctx, mac)
    if action == "record":
        events = record(gather(ctx, mac), path)
        return {"log": str(path), "new_events": len(events), "events": events}
    if action == "history":
        if not path.exists():
            return {"log": str(path), "events": [], "note": "nothing recorded yet: action=record"}
        lines = path.read_text().splitlines()
        limit = max(1, min(int(ctx.arg("limit", 200)), 5000))
        kind = ctx.arg("event")
        events = [json.loads(x) for x in lines if x.strip()]
        if kind:
            events = [e for e in events if e.get("event") == kind]
        return {"log": str(path), "total": len(events), "events": events[-limit:]}
    raise UsageError(f"unknown action {action!r}")
