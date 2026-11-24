"""System odds and ends: LEDs, eco mode, time, reboot, firmware, QoS, device priority,
DDNS and the basic firewall switches."""

from __future__ import annotations

from typing import Any

from .. import forms
from ..safety import Plan
from ..transport import RouterError
from . import OFF, ON, Ctx, UsageError, boolish, find_mac

SIMPLE_FORMS = {
    # action: (path, friendly description)
    "led": ("ledgeneral?form=setting", "LEDs"),
    "led_night": ("ledpm?form=setting", "LED night mode"),
    "eco": ("eco_mode?form=settings", "eco mode"),
    "time": ("time?form=settings", "time / NTP"),
    "auto_upgrade": ("firmware?form=auto_upgrade", "automatic firmware updates"),
    "qos": ("smart_network?form=qos", "QoS"),
    "firewall": ("security_settings?form=new_enable", "firewall / ping replies"),
    "dst": ("time?form=dst", "daylight saving time"),
    "hour24": ("time?form=hour24", "24-hour clock"),
}
PRIORITY = "smart_network?form=device_priority"


def _safe(ctx: Ctx, path: str) -> Any:
    try:
        return ctx.read(path)
    except RouterError as exc:
        return {"error": exc.code}


def system(ctx: Ctx) -> Plan | dict[str, Any]:
    action = ctx.arg("action", "info")
    if action == "info":
        out = {name: _safe(ctx, path) for name, (path, _) in SIMPLE_FORMS.items()}
        out["firmware"] = _safe(ctx, "firmware?form=upgrade")
        out["mode"] = _safe(ctx, "system?form=sysmode")
        out["ddns_provider"] = _safe(ctx, "ddns?form=provider")
        return out
    if action == "firmware_check":
        # The UI's "check for updates" button; changes nothing.
        return {"result": ctx.t.call("firmware?form=upgrade", "fwup_check"),
                "current": _safe(ctx, "firmware?form=upgrade")}
    if action == "ddns":
        return {"provider": _safe(ctx, "ddns?form=provider"), "tplink": _safe_rows(ctx, "ddns?form=tplink"),
                "noip": _safe(ctx, "ddns?form=noip"), "dyndns": _safe(ctx, "ddns?form=dyndns")}
    if action == "device_priority":
        return {"devices": ctx.rows(PRIORITY)}
    if action == "set_device_priority":
        mac = find_mac(ctx.need("mac"))
        rows = ctx.rows(PRIORITY)
        changes: dict[str, Any] = {}
        if ctx.args.get("enable") is not None:
            changes["enablePriority"] = bool(ctx.args["enable"])
        if ctx.args.get("time_period") is not None:
            changes["timePeriod"] = str(ctx.args["time_period"])
        if not changes:
            raise UsageError("pass enable and/or time_period")
        plan = ctx.plan("system", f"device priority for {mac}", PRIORITY)
        plan.add(forms.plan_update(PRIORITY, rows, mac, changes))
        return plan
    if action == "reboot":
        plan = Plan(tool="system", summary="reboot the router (2-3 minutes without network)")
        plan.add(forms.plan_custom("system?form=reboot", "reboot"))
        plan.critical_reasons.append("every device loses network for a few minutes; not undoable")
        return plan
    if action == "time_sync":
        plan = Plan(tool="system", summary="resync the router clock from NTP")
        plan.add(forms.plan_custom("time?form=settings", "refresh"))
        return plan
    if action in SIMPLE_FORMS:
        path, what = SIMPLE_FORMS[action]
        settings = ctx.obj("settings")
        if ctx.args.get("enable") is not None:
            key = {"dst": "dst_enable", "hour24": "hour24_enable"}.get(action, "enable")
            settings.setdefault(key, ctx.args["enable"])
        if action == "eco" and settings.get("power_mode") not in (None, "strong", "medium", "weak"):
            raise UsageError("eco power_mode must be strong | medium | weak")
        if not settings:
            return {action: ctx.read(path)}
        cur = ctx.read(path)
        changes = {k: boolish(cur.get(k), v)
                   for k, v in settings.items()}
        plan = ctx.plan("system", f"change {what}", path)
        plan.add(forms.plan_write(path, cur, changes, label=what))
        if action == "firewall" and changes.get("enable") == OFF:
            plan.critical_reasons.append("turns the SPI firewall off")
        if action == "firewall" and changes.get("wan_ping") == ON:
            plan.warnings.append("the router will answer pings from the internet")
        if action in ("time", "dst", "hour24"):
            plan.warnings.append("time write format is inferred (not from the UI JS); verify after applying")
        return plan
    raise UsageError(f"unknown action {action!r}")


def _safe_rows(ctx: Ctx, path: str) -> Any:
    try:
        return ctx.rows(path)
    except RouterError as exc:
        return {"error": exc.code}
