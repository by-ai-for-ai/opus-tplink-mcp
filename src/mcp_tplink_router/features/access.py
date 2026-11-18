"""Access control (block/allow lists) and HomeShield/Avira parental controls (local ops)."""

from __future__ import annotations

from typing import Any

from .. import forms
from ..safety import Plan
from . import OFF, ON, Ctx, UsageError, find_mac, is_on

AC_ENABLE = "access_control?form=enable"
AC_MODE = "access_control?form=mode"
LISTS = {"black": "access_control?form=black_list", "white": "access_control?form=white_list"}
CANDIDATES = {"black": "access_control?form=black_devices", "white": "access_control?form=white_devices"}


def _own(ctx: Ctx) -> set[str]:
    """This machine's MAC(s): local detection + rows the router itself marks host=HOST."""
    macs = set(ctx.own_macs())
    for path in CANDIDATES.values():
        try:
            for r in ctx.rows(path):
                if str(r.get("host", "")).upper() == "HOST" and r.get("mac"):
                    macs.add(forms.normalize_mac(r["mac"]))
        except Exception:  # noqa: BLE001 - best effort
            pass
    host_mac = ctx.read(AC_ENABLE).get("host_mac")
    if host_mac:
        try:
            macs.add(forms.normalize_mac(host_mac))
        except ValueError:
            pass
    return macs


def _device_row(ctx: Ctx, mac: str, name: str | None) -> dict[str, Any]:
    """The row shape the UI inserts: {name, deviceType, mac, ipaddr, host, conn_type, key}."""
    client = next((c for c in ctx.clients() if c["mac"] == mac), None)
    return {"name": name or (client or {}).get("name") or mac, "deviceType": "other", "mac": mac,
            "ipaddr": (client or {}).get("ip") or "", "host": "NOT HOST",
            "conn_type": (client or {}).get("connection") or "", "key": ""}


def access_control(ctx: Ctx) -> Plan | dict[str, Any]:
    action = ctx.arg("action", "status")
    enable = ctx.read(AC_ENABLE)
    mode = str(ctx.read(AC_MODE).get("access_mode", "black"))
    if action == "status":
        return {"enabled": is_on(enable.get("enable")), "mode": mode,
                "blocklist": ctx.rows(LISTS["black"]), "allowlist": ctx.rows(LISTS["white"]),
                "note": "black mode blocks the listed devices; white mode blocks EVERYTHING not listed"}
    if action == "candidates":
        return {k: ctx.rows(p) for k, p in CANDIDATES.items()}
    own = _own(ctx)
    allow = ctx.rows(LISTS["white"])
    allowed_me = any(forms.normalize_mac(r["mac"]) in own for r in allow if r.get("mac"))
    if action in ("enable", "disable"):
        plan = ctx.plan("access_control", f"{action} access control ({mode} mode)", AC_ENABLE)
        plan.add(forms.plan_write(AC_ENABLE, enable, {"enable": ON if action == "enable" else OFF}))
        if action == "enable" and mode == "white":
            plan.critical_reasons.append("white mode: every device NOT on the allowlist loses access"
                                         + ("" if allowed_me else " - including THIS machine"))
        return plan
    if action == "set_mode":
        new = str(ctx.need("mode")).lower()
        if new not in ("black", "white"):
            raise UsageError("mode must be black or white")
        plan = ctx.plan("access_control", f"switch access control to {new} mode", AC_MODE)
        plan.add(forms.plan_write(AC_MODE, ctx.read(AC_MODE), {"access_mode": new}))
        if new == "white" and mode != "white":
            plan.critical_reasons.append("switching to allowlist (white) mode: devices not listed lose access"
                                         + ("" if allowed_me else "; THIS machine is not on the allowlist"))
        return plan
    lst = {"block": "black", "unblock": "black", "allow": "white", "disallow": "white"}.get(action)
    if lst is None:
        raise UsageError(f"unknown action {action!r}")
    path = LISTS[lst]
    rows = ctx.rows(path)
    mac = find_mac(ctx.need("mac"))
    if action in ("block", "allow"):
        plan = ctx.plan("access_control", f"{action} {mac}", path)
        if forms.find_rows(rows, "mac", mac):
            plan.errors.append(f"{mac} is already on the {lst} list")
            return plan
        plan.add(forms.plan_insert(path, _device_row(ctx, mac, ctx.arg("name")), label=mac))
        if action == "block" and mac in own:
            plan.critical_reasons.append(f"{mac} is THIS machine: blocking it cuts the server off the router")
        if action == "block" and not is_on(enable.get("enable")):
            plan.warnings.append("access control is currently OFF; the blocklist takes effect once enabled")
        if action == "block" and mode == "white":
            plan.warnings.append("the router is in white (allowlist) mode; the blocklist is not in effect")
        return plan
    plan = ctx.plan("access_control", f"{action} {mac}", path)
    plan.add(forms.plan_remove(path, rows, mac, label=mac))
    if action == "disallow" and len(rows) == 1:
        plan.critical_reasons.append("removes the LAST allowlisted device: with white mode on, nothing can connect")
    if action == "disallow" and mac in own and mode == "white":
        plan.critical_reasons.append("removes THIS machine from the allowlist while white mode is in force")
    return plan


# ------------------------------------------------------------------------ parental
PACTRL = "avira_parental_control?form=avira_pactrl"


def _owner(ctx: Ctx) -> str:
    return str(ctx.need("owner_id"))


def _sites(ctx: Ctx) -> list[str]:
    sites = ctx.arg("sites")
    if not isinstance(sites, list) or not all(isinstance(s, str) for s in sites):
        raise UsageError("sites must be a list of domain strings")
    return [s.strip() for s in sites if s.strip()]


def parental_control(ctx: Ctx) -> Plan | dict[str, Any]:
    action = ctx.arg("action", "owners")
    call = ctx.t.call
    if action == "owners":
        return {"data": call(PACTRL, "getOwnerTotalData")}
    if action == "devices":
        return {"data": call(PACTRL, "getDevicesList")}
    if action == "block_history":
        return {"data": call(PACTRL, "getBlockHistory", {"ownerId": _owner(ctx)})}
    if action == "today_sites":
        return {"data": call(PACTRL, "getTodayVisitSites", {"ownerId": _owner(ctx)})}
    if action == "filter_get":
        return {"data": call(PACTRL, "getFilterWebsiteInfo", {"ownerId": _owner(ctx)})}
    if action == "allowed_sites_get":
        return {"data": call(PACTRL, "getFreeWebsite", {"ownerId": _owner(ctx)})}
    if action == "internet_block":
        owner = _owner(ctx)
        blocked = bool(ctx.need("blocked"))
        owners = (call(PACTRL, "getOwnerTotalData") or {}).get("ownerList") or []
        cur = next((o for o in owners if str(o.get("ownerId")) == owner), None)
        if cur is None:
            raise UsageError(f"no parental-control owner with id {owner!r} (see action=owners)")
        before = cur.get("internetBlocked")
        plan = Plan(tool="parental_control", summary=f"{'pause' if blocked else 'resume'} internet for owner {owner}")
        plan.before[PACTRL] = {"owner": cur}
        if isinstance(before, bool) and before == blocked:
            return plan
        inverse = ({"op": "internetBlock", "fields": {"ownerId": owner, "internetBlocked": before}}
                   if isinstance(before, bool) else None)
        plan.add(forms.plan_custom(PACTRL, "internetBlock", {"ownerId": owner, "internetBlocked": blocked},
                                   inverse=inverse, label=str(cur.get("name") or owner)))
        return plan
    if action in ("filter_set", "allowed_sites_set"):
        owner = _owner(ctx)
        sites = _sites(ctx)
        get_op, set_op, fld = (("getFilterWebsiteInfo", "setFilterWebsiteInfo", "filterWebsiteList")
                               if action == "filter_set" else
                               ("getFreeWebsite", "setFreeWebsite", "filterFreeWebsiteList"))
        cur = call(PACTRL, get_op, {"ownerId": owner}) or {}
        old = next((v for k, v in cur.items() if isinstance(v, list)), None) if isinstance(cur, dict) else None
        plan = Plan(tool="parental_control", summary=f"set {'blocked' if action == 'filter_set' else 'always-allowed'} "
                                                      f"websites for owner {owner}")
        plan.before[PACTRL] = {"current": cur}
        if old is not None and sorted(map(str, old)) == sorted(sites):
            return plan
        inverse = {"op": set_op, "fields": {"ownerId": owner, fld: old}} if isinstance(old, list) else None
        plan.add(forms.plan_custom(PACTRL, set_op, {"ownerId": owner, fld: sites}, inverse=inverse))
        if inverse is None:
            plan.warnings.append("could not read the current list in a known format: this change is not undoable")
        return plan
    if action == "remove_owner":
        owner = _owner(ctx)
        plan = Plan(tool="parental_control", summary=f"delete parental-control profile {owner}")
        plan.add(forms.plan_custom(PACTRL, "delOwnerInList", {"ownerList": [owner]}))
        plan.critical_reasons.append("deletes a parental-control profile (its filters and time limits)")
        return plan
    if action == "add_owner":
        fields = ctx.obj("owner")
        if not fields:
            raise UsageError("owner={...} with the profile fields is required (see the web UI's add-profile form)")
        plan = Plan(tool="parental_control", summary="add a parental-control profile")
        plan.add(forms.plan_custom(PACTRL, "addOwnerInList", fields))
        return plan
    raise UsageError(f"unknown action {action!r}")
