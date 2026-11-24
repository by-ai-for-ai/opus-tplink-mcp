"""Per-client controls: rename a device, speed limits, game accelerator status, and the
IoT network (moving smart-home devices onto their own isolated network)."""

from __future__ import annotations

import re
from typing import Any

from .. import forms
from . import Ctx, UsageError, find_mac, pick, safe_read, settings_change

SPEED = "smart_network?form=client_speed_limit"
IOT_LIST = "iot_security?form=isolated_list"


def _client(ctx: Ctx, mac: str) -> dict[str, Any] | None:
    return next((c for c in ctx.clients() if c["mac"] == mac), None)


def _current_name(ctx: Ctx, mac: str) -> str:
    """A device's name from the router's FULL device list (wired + offline included), falling back to
    the live client list and the DHCP leases."""
    devs = safe_read(ctx, "avira_parental_control?form=avira_pactrl", "getDevicesList")
    for d in (devs or {}).get("clientList") or [] if isinstance(devs, dict) else []:
        if forms.key_equal("mac", d.get("mac"), mac) and d.get("name"):
            return str(d["name"])
    c = _client(ctx, mac)
    if c and c.get("name"):
        return str(c["name"])
    for r in ctx.rows("dhcps?form=client"):
        if forms.key_equal("mac", r.get("macaddr"), mac) and r.get("name"):
            return str(r["name"])
    return ""


_MAC = re.compile(r"[0-9A-Fa-f]{2}([-:]?[0-9A-Fa-f]{2}){5}")


def _human(n: Any) -> str:
    try:
        v = float(n)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            return f"{v:.0f} {unit}" if unit == "B" else f"{v:.1f} {unit}"
        v /= 1024
    return "?"


def _traffic(ctx: Ctx) -> Any:
    """Per-device usage from the router's own traffic statistics (Archer AX3000 / AXE5400 class firmware)."""
    from ..capabilities import describe_device

    st = ctx.read("traffic?form=status")
    source = describe_device(ctx.router, ctx.host)
    if str(st.get("enable")) != "on":
        return {"enabled": False, "tell_user": f"Traffic statistics are OFF on {source}, so there is no usage data. "
                                               "Turning them on is a change (it will be previewed)."}
    rows = ctx.t.call("traffic?form=lists", "load") or []
    rows = rows if isinstance(rows, list) else []
    names: dict[str, Any] = {}
    try:
        names = {str(c.get("mac", "")).upper(): c.get("name") for c in ctx.clients()}
    except Exception:  # noqa: BLE001 - newer firmware: client list may not parse; fall back to DHCP leases
        names = {}
    try:  # live (Archer AXE5400 fw 1.5.6): the client list carried no names; the DHCP leases do
        for r in ctx.rows("dhcps?form=client"):
            mac = str(r.get("macaddr") or r.get("mac") or "").upper().replace(":", "-")
            if mac and not names.get(mac) and r.get("name") not in (None, "", "--"):
                names[mac] = r.get("name")
    except Exception:  # noqa: BLE001
        pass
    own_ips = {str(ctx.host).split("//")[-1].split(":")[0].split("/")[0]}
    want = str(ctx.arg("client") or "").strip()  # NOT "device": that is the alias for router
    picked = []
    for r in rows:
        mac = str(r.get("mac", "")).upper().replace(":", "-")
        name = names.get(mac) or ""
        if want and not (forms.key_equal("mac", mac, want) if _MAC.fullmatch(want) else
                         want == r.get("ip") or want.lower() in name.lower()):
            continue
        private = len(mac) >= 2 and int(mac[:2], 16) & 2 == 2 if all(c in "0123456789ABCDEF" for c in mac[:2]) else False
        if r.get("ip") in own_ips:
            name = "this router (its own traffic)"
        picked.append({"name": name or "(no name)", "mac": mac, "ip": r.get("ip"),
                       "total": _human(r.get("total_byte")), "total_bytes": r.get("total_byte"),
                       "upload_now": _human(r.get("retx_byte")) + "/s", "download_now": _human(r.get("rerx_byte")) + "/s",
                       **({"private_mac": True} if private else {})})
    if want and not picked:
        return {"found": False, "tell_user": f"No device matching {want!r} in the traffic statistics of {source}. "
                                             "It may be on another router's network, offline, or named differently."}
    if want and len(picked) > 1 and not any(want == p["ip"] or (_MAC.fullmatch(want) and forms.key_equal("mac", p["mac"], want))
                                            for p in picked):
        return {"ambiguous": True, "candidates": [{k: p[k] for k in ("name", "mac", "ip")} for p in picked],
                "tell_user": f"{len(picked)} devices match {want!r}; ask the user which one (by name, IP or MAC)."}
    out: dict[str, Any] = {"devices": picked}
    period = ctx.arg("history")
    if period and len(picked) == 1:
        if period not in ("minute", "hour", "day"):
            raise UsageError("history is one of minute, hour, day")
        h = ctx.t.call("traffic?form=data", "seg_get", {"ip": picked[0]["ip"], "seg_type": period})
        data = (h or {}).get("data") if isinstance(h, dict) else None
        out["history"] = {"period": period, "points": [{"up": _human(d.get("ups")), "down": _human(d.get("downs"))}
                                                       for d in (data or [])],
                          "note": "kept by IP address: if this IP was used by another device earlier, its traffic is "
                                  "included"}
    out["source"] = (f"From the traffic statistics of {source}, counted since they were last reset or the router "
                     "restarted. Covers only devices on this router's own network. 'now' values are the router's "
                     "current upload/download rates.")
    return out


def clients(ctx: Ctx) -> Any:
    action = ctx.arg("action", "list")
    if action == "list":
        return {"clients": ctx.clients()}
    if action == "traffic":
        return _traffic(ctx)
    if action == "rename":
        mac = find_mac(ctx.need("mac"))
        name = str(ctx.need("name"))
        if len(name) > 64:
            raise UsageError("names are at most 64 characters")
        old = _current_name(ctx, mac)
        plan = ctx.plan("clients", f"rename {mac} to {name!r}")
        if not old:
            plan.warnings.append("the current name could not be read, so router_undo cannot restore it")
        plan.add(forms.plan_custom("traffic?form=dev_name", "write", {"mac": mac, "alias": name}, label="rename",
                                   inverse={"op": "write", "fields": {"mac": mac, "alias": old}} if old else None))
        return plan
    if action == "speed":
        return {"limits_max": safe_read(ctx, SPEED, "read_max"),
                "devices": safe_read(ctx, "smart_network?form=device_priority")}
    if action == "speed_limit":
        # download_kbps / upload_kbps: 0 = no limit.  enable=false removes the limit.  The router stores
        # enableLimit verbatim and uses on/off (seen live in smart_network?form=device_priority).
        mac = find_mac(ctx.need("mac"))
        enable = bool(ctx.arg("enable", True))
        down, up = int(ctx.arg("download_kbps", 0)), int(ctx.arg("upload_kbps", 0))
        if down < 0 or up < 0:
            raise UsageError("limits are kbps >= 0 (0 = unlimited)")
        rows = [r for r in safe_read(ctx, "smart_network?form=device_priority") or [] if isinstance(r, dict)
                and forms.key_equal("mac", r.get("mac"), mac)]
        fields = {"mac": mac, "enableLimit": "on" if enable else "off",
                  "downloadLimit": str(down), "uploadLimit": str(up)}
        old = rows[0] if rows else {}
        inverse = {"op": "write", "fields": {
            "mac": mac, "enableLimit": str(old.get("enableLimit") or "off"),
            "downloadLimit": str(old.get("downloadLimit", 0)), "uploadLimit": str(old.get("uploadLimit", 0))}}
        plan = ctx.plan("clients", f"speed limit for {mac}: down {down or 'unlimited'} / up {up or 'unlimited'} kbps")
        plan.add(forms.plan_custom(SPEED, "write", fields, label="speed limit", inverse=inverse))
        if not rows:
            plan.warnings.append("this device is not in the router's per-device table (smart_network "
                                 "device_priority), so the limit may not apply; see action=speed")
        return plan
    if action == "game_accelerator":
        return {"devices": safe_read(ctx, "smart_network?form=game_accelerator", "loadDevice"),
                "speed": safe_read(ctx, "smart_network?form=game_accelerator", "loadSpeed")}
    # -------------------------------------------------------------------- IoT network
    if action == "iot_status":
        return {"iot_network": safe_read(ctx, "iot_security?form=enable"),
                "on_iot": safe_read(ctx, IOT_LIST),
                "candidates_main": safe_read(ctx, "iot_security?form=isolated_devices_main"),
                "candidates_iot": safe_read(ctx, "iot_security?form=isolated_devices_iot")}
    if action in ("iot_enable", "iot_disable"):
        return settings_change(ctx, "clients", "iot_security?form=enable", {"enable": action == "iot_enable"},
                               "IoT network")
    if action in ("iot_add", "iot_remove"):
        macs = [find_mac(m) for m in (ctx.args.get("macs") or [ctx.need("mac")])]
        rows = ctx.rows(IOT_LIST)
        plan = ctx.plan("clients", f"{'move' if action == 'iot_add' else 'return'} {', '.join(macs)} "
                        f"{'to' if action == 'iot_add' else 'from'} the IoT network", IOT_LIST)
        if action == "iot_add":
            new = [m for m in macs if not pick(rows, mac=m)]
            if not new:
                return {"status": "no_change", "note": "already on the IoT network"}
            plan.add(forms.plan_custom(IOT_LIST, "write", {"mac": forms.jdump(new), "totalNum": str(len(new))},
                                       label="iot add"))
        else:
            for m in macs:
                if not pick(rows, mac=m):
                    raise UsageError(f"{m} is not on the IoT network")
                plan.add(forms.plan_custom(IOT_LIST, "remove", {"mac": m}, label="iot remove",
                                           inverse={"op": "write", "fields": {"mac": forms.jdump([m]),
                                                                              "totalNum": "1"}}))
        if ctx.own_macs() & set(macs):
            plan.critical_reasons.append("THIS machine would move networks")
        plan.warnings.append("moved devices reconnect to the IoT Wi-Fi; wired devices are unaffected")
        return plan
    raise UsageError(f"unknown action {action!r}")
