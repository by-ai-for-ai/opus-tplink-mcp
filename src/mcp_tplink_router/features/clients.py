"""Per-client controls: rename a device, speed limits, game accelerator status, and the
IoT network (moving smart-home devices onto their own isolated network)."""

from __future__ import annotations

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


def clients(ctx: Ctx) -> Any:
    action = ctx.arg("action", "list")
    if action == "list":
        return {"clients": ctx.clients()}
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
