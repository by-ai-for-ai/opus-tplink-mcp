"""DHCP server settings, reservations and leases (the owner's top priority).

Kiosk tablets need stable reservations.  The single most common way a reservation
"doesn't work" is a phone/tablet using a randomised (locally administered) MAC; every
add/update warns about it.
"""

from __future__ import annotations

from typing import Any

from .. import forms
from ..netcalc import is_locally_administered, normalize_mac
from ..safety import Plan
from ..validate import validate_dhcp_setting, validate_reservation
from . import OFF, Ctx, UsageError, find_mac, is_on, onoff

SETTING = "dhcps?form=setting"
RESV = "dhcps?form=reservation"
NAME_NOTE = ("the router labels reservations with the device's own hostname; custom names are not stored "
             "(it keeps \"\" for devices it has never seen)")
LEASES = "dhcps?form=client"

_ARG_TO_FIELD = {"enable": "enable", "start": "ipaddr_start", "end": "ipaddr_end",
                 "lease_minutes": "leasetime", "gateway": "gateway", "dns1": "pri_dns", "dns2": "snd_dns"}


def dhcp_server_set(ctx: Ctx) -> Plan | dict[str, Any]:
    cur = ctx.read(SETTING)
    if ctx.arg("action") == "get":
        return {"setting": cur, "lan": {"ip": str(ctx.lan().ip), "subnet": str(ctx.lan().network)},
                "leases": len(ctx.rows(LEASES)), "reservations": len(ctx.rows(RESV))}
    changes: dict[str, Any] = {}
    for arg, fld in _ARG_TO_FIELD.items():
        v = ctx.args.get(arg)
        if v is None:
            continue
        changes[fld] = onoff(v) if arg == "enable" else str(v)
    if not changes:
        raise UsageError("nothing to change: pass enable/start/end/lease_minutes/gateway/dns1/dns2 "
                         "(or action=get)")
    lan = ctx.lan()
    new = {**cur, **changes}
    plan = ctx.plan("dhcp_server_set", "change DHCP server settings", SETTING)
    errors, warnings = validate_dhcp_setting(new, lan, ctx.rows(RESV), ctx.rows(LEASES), old=cur)
    plan.errors += errors
    plan.warnings += warnings
    if changes.get("enable") == OFF and is_on(cur.get("enable")):
        plan.critical_reasons.append("disables the DHCP server: devices stop getting addresses as leases expire")
    gw = new.get("gateway")
    if gw and str(gw) != str(lan.ip) and "gateway" in changes:
        plan.critical_reasons.append(f"gateway {gw} is not the router's LAN IP {lan.ip}")
    plan.add(forms.plan_write(SETTING, cur, changes, label="DHCP server"))
    return plan


def _annotated_reservations(ctx: Ctx) -> list[dict[str, Any]]:
    leases = {}
    for x in ctx.rows(LEASES):
        try:
            leases[normalize_mac(x.get("macaddr", ""))] = x
        except ValueError:
            pass
    online = {c["mac"]: c for c in ctx.clients()}
    out = []
    for r in ctx.rows(RESV):
        e = dict(r)
        try:
            mac = normalize_mac(r.get("mac", ""))
        except ValueError:
            out.append(e)
            continue
        lease = leases.get(mac)
        e["current_lease_ip"] = lease.get("ipaddr") if lease else None
        e["online"] = mac in online
        e["working"] = bool(lease and lease.get("ipaddr") == r.get("ip")) or (online.get(mac, {}).get("ip") == r.get("ip"))
        if is_locally_administered(mac):
            e["warning"] = "randomised/private MAC - set the device to 'use device MAC' or this won't stick"
        out.append(e)
    return out


def _context(ctx: Ctx) -> tuple[Any, list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    return ctx.lan(), ctx.rows(RESV), ctx.rows(LEASES), ctx.clients()


def dhcp_reservation(ctx: Ctx) -> Plan | dict[str, Any]:
    action = ctx.arg("action", "list")
    if action == "list":
        return {"reservations": _annotated_reservations(ctx), "leases": ctx.rows(LEASES)}
    if action == "leases":
        return {"leases": ctx.rows(LEASES)}
    lan, existing, leases, clients = _context(ctx)
    if action in ("add", "reserve_current"):
        if action == "reserve_current":
            mac, ip = _current_lease(ctx, leases, clients)
            ip = ctx.arg("ip") or ip
        else:
            mac, ip = find_mac(ctx.need("mac")), str(ctx.need("ip"))
        name = str(ctx.arg("name", "") or "")
        row = {"mac": mac, "ip": ip, "comment": name, "enable": onoff(ctx.arg("enable", True))}
        plan = ctx.plan("dhcp_reservation", f"reserve {ip} for {mac}" + (f" ({name})" if name else ""), RESV)
        errors, warnings = validate_reservation(row, lan, existing, leases, clients)
        plan.errors += errors
        plan.warnings += warnings
        if name:
            plan.warnings.append(NAME_NOTE)
        if not errors:
            plan.add(forms.plan_insert(RESV, row, label=f"{mac} -> {ip}"))
            plan.warnings.append("the device picks up the reserved IP at its next DHCP renewal "
                                 "(reconnect it or toggle its Wi-Fi to apply now)")
        return plan
    mac = find_mac(ctx.need("mac"))
    if action == "update":
        rows = [r for r in existing if forms.key_equal("mac", r.get("mac"), mac)]
        if not rows:
            raise UsageError(f"no reservation for {mac}; use action=add")
        changes: dict[str, Any] = {}
        if ctx.args.get("ip") is not None:
            changes["ip"] = str(ctx.args["ip"])
        if ctx.args.get("name") is not None:
            changes["comment"] = str(ctx.args["name"])
        if ctx.args.get("enable") is not None:
            changes["enable"] = onoff(ctx.args["enable"])
        if not changes:
            raise UsageError("nothing to change: pass ip, name or enable")
        if set(changes) == {"comment"}:
            raise UsageError(NAME_NOTE)
        new = {**rows[0], **changes}
        plan = ctx.plan("dhcp_reservation", f"update reservation for {mac}", RESV)
        errors, warnings = validate_reservation(new, lan, existing, leases, clients, replacing_mac=mac)
        if "comment" in changes:
            warnings.append(NAME_NOTE)
        plan.errors += errors
        plan.warnings += warnings
        if not errors:
            plan.add(forms.plan_update(RESV, existing, mac, changes, label=str(mac)))
        return plan
    if action == "remove":
        plan = ctx.plan("dhcp_reservation", f"remove reservation for {mac}", RESV)
        plan.add(forms.plan_remove(RESV, existing, mac, label=str(mac)))
        return plan
    raise UsageError(f"unknown action {action!r}")


def _current_lease(ctx: Ctx, leases: list[dict[str, Any]], clients: list[dict[str, Any]]) -> tuple[str, str]:
    """Find the client named by mac / ip / name and return (MAC, its current IP)."""
    mac_arg, ip_arg, name_arg = ctx.arg("mac"), ctx.arg("current_ip"), ctx.arg("client")
    if not (mac_arg or ip_arg or name_arg):
        raise UsageError("reserve_current needs mac, current_ip or client (a hostname)")
    pool = [{"mac": x.get("macaddr"), "ip": x.get("ipaddr"), "name": x.get("name")} for x in leases]
    pool += [{"mac": c["mac"], "ip": c.get("ip"), "name": c.get("name")} for c in clients]
    hits = []
    for p in pool:
        try:
            pm = normalize_mac(p.get("mac") or "")
        except ValueError:
            continue
        if mac_arg and pm != find_mac(mac_arg):
            continue
        if ip_arg and str(p.get("ip")) != str(ip_arg):
            continue
        if name_arg and str(name_arg).lower() not in str(p.get("name") or "").lower():
            continue
        if p.get("ip"):
            hits.append((pm, str(p["ip"])))
    uniq = sorted(set(hits))
    if not uniq:
        raise UsageError("no current lease/connected client matches")
    if len({m for m, _ in uniq}) > 1:
        raise UsageError(f"ambiguous: {len({m for m, _ in uniq})} clients match {uniq}; pass the mac")
    return uniq[0]
