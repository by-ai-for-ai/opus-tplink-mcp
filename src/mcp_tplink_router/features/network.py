"""IP-MAC binding, UPnP, mesh and static routing."""

from __future__ import annotations

from typing import Any

from .. import forms
from ..catalog import CRITICAL
from ..netcalc import is_ipv4, normalize_mac, parse_ipv4
from ..safety import Plan
from . import OFF, ON, Ctx, UsageError, find_mac, is_on, onoff

# ------------------------------------------------------------------------ IP-MAC binding
IMB = "imb?form=setting"
BINDS = "imb?form=bind_list"
ARP = "imb?form=arp_list"


def _check_bind(ctx: Ctx, plan: Plan, mac: str, ip: str) -> None:
    lan = ctx.lan()
    if not is_ipv4(ip) or not lan.is_host(parse_ipv4(ip)) or parse_ipv4(ip) == lan.ip:
        plan.errors.append(f"{ip!r} is not a usable host address in {lan.network}")
    own_ip = (ctx.identity() or {}).get("ip")
    if mac in ctx.own_macs() and own_ip and ip != own_ip:
        plan.critical_reasons.append(f"binds THIS machine's MAC {mac} to {ip}, not its current {own_ip}: "
                                     "with binding enforced it could lose access to the router")
    for res in ctx.rows("dhcps?form=reservation"):
        if res.get("ip") == ip and not forms.key_equal("mac", res.get("mac"), mac):
            plan.errors.append(f"{ip} is DHCP-reserved for {res.get('mac')}: the router refuses the binding "
                               "('DHCP reservation duplication'); move the reservation first "
                               "(dhcp_reservation remove + add)")


def ip_mac_binding(ctx: Ctx) -> Plan | dict[str, Any]:
    action = ctx.arg("action", "status")
    if action in ("status", "list"):
        return {"setting": ctx.read(IMB), "bindings": ctx.rows(BINDS), "arp": ctx.rows(ARP)}
    if action in ("enable", "disable"):
        plan = ctx.plan("ip_mac_binding", f"{action} IP-MAC binding", IMB)
        plan.add(forms.plan_write(IMB, ctx.read(IMB), {"enable": ON if action == "enable" else OFF}))
        if action == "enable":
            plan.warnings.append("devices whose IP does not match their binding will be blocked")
        return plan
    rows = ctx.rows(BINDS)
    if action in ("add", "bind_current"):
        if action == "bind_current":
            key = ctx.arg("mac") or ctx.arg("ip")
            if not key:
                raise UsageError("bind_current needs mac or ip (of an entry in the ARP list)")
            hits = [r for r in ctx.rows(ARP)
                    if (ctx.arg("mac") and forms.key_equal("mac", r.get("mac"), ctx.arg("mac")))
                    or (ctx.arg("ip") and r.get("ipaddr") == ctx.arg("ip"))]
            if len(hits) != 1:
                raise UsageError(f"{len(hits)} ARP entries match; pass the exact mac")
            mac, ip = normalize_mac(hits[0]["mac"]), str(hits[0]["ipaddr"])
            name = ctx.arg("name") or hits[0].get("name") or ""
        else:
            mac, ip, name = find_mac(ctx.need("mac")), str(ctx.need("ip")), ctx.arg("name", "")
        row = {"mac": mac, "ipaddr": ip, "name": str(name), "description": str(ctx.arg("description", "")),
               "enable": onoff(ctx.arg("enable", True))}
        plan = ctx.plan("ip_mac_binding", f"bind {mac} to {ip}", BINDS)
        if forms.find_rows(rows, "mac", mac):
            plan.errors.append(f"{mac} is already bound; use action=update")
        if any(r.get("ipaddr") == ip for r in rows):
            plan.errors.append(f"{ip} is already bound to another MAC")
        _check_bind(ctx, plan, mac, ip)
        if not plan.errors:
            plan.add(forms.plan_insert(BINDS, row, label=f"{mac} = {ip}"))
        return plan
    mac = find_mac(ctx.need("mac"))
    if action == "remove":
        plan = ctx.plan("ip_mac_binding", f"remove binding for {mac}", BINDS)
        plan.add(forms.plan_remove(BINDS, rows, mac))
        return plan
    if action == "update":
        # The UI has no update op for this table: remove + insert (both journaled, both undoable).
        hits = [r for r in rows if forms.key_equal("mac", r.get("mac"), mac)]
        if not hits:
            raise UsageError(f"no binding for {mac}; use action=add")
        old = hits[0]
        new = dict(old)
        for arg, fld in (("ip", "ipaddr"), ("name", "name"), ("description", "description")):
            if ctx.args.get(arg) is not None:
                new[fld] = str(ctx.args[arg])
        if ctx.args.get("enable") is not None:
            new["enable"] = onoff(ctx.args["enable"])
        plan = ctx.plan("ip_mac_binding", f"update binding for {mac} (remove + re-add)", BINDS)
        if forms.same_row(new, old):
            return plan
        if new["ipaddr"] != old.get("ipaddr") and any(r.get("ipaddr") == new["ipaddr"] for r in rows):
            plan.errors.append(f"{new['ipaddr']} is already bound to another MAC")
        _check_bind(ctx, plan, mac, str(new["ipaddr"]))
        if not plan.errors:
            plan.add(forms.plan_remove(BINDS, rows, mac, label="old binding"))
            plan.add(forms.plan_insert(BINDS, {k: v for k, v in new.items() if not k.startswith(".")},
                                       label="new binding"))
        return plan
    raise UsageError(f"unknown action {action!r}")


# --------------------------------------------------------------------------------- UPnP
UPNP = "upnp?form=enable"
UPNP_MAP = "upnp?form=service"


def upnp(ctx: Ctx) -> Plan | dict[str, Any]:
    action = ctx.arg("action", "status")
    if action in ("status", "list"):
        return {"enabled": is_on(ctx.read(UPNP).get("enable")), "mappings": ctx.rows(UPNP_MAP),
                "note": "mappings are created by devices; the router UI offers no per-mapping delete"}
    if action in ("enable", "disable"):
        plan = ctx.plan("upnp", f"{action} UPnP", UPNP)
        plan.add(forms.plan_write(UPNP, ctx.read(UPNP), {"enable": ON if action == "enable" else OFF}))
        if action == "disable" and ctx.rows(UPNP_MAP):
            plan.warnings.append(f"{len(ctx.rows(UPNP_MAP))} active mapping(s) will be dropped "
                                 "(game consoles / apps may lose inbound connectivity)")
        return plan
    raise UsageError(f"unknown action {action!r}")


# --------------------------------------------------------------------------------- mesh
MESH = "easymesh?form=easymesh_enable"
MESH_MANAGE = "easymesh_network?form=available_mesh_device_manage"
MESH_SEARCH = "easymesh?form=search_slave"


def mesh(ctx: Ctx) -> Plan | dict[str, Any]:
    action = ctx.arg("action", "status")

    def safe(path: str) -> Any:
        try:
            return ctx.read(path)
        except Exception as exc:  # noqa: BLE001
            return {"error": str(exc)}

    if action == "status":
        return {"setting": ctx.read(MESH), "devices": safe("easymesh_network?form=get_mesh_device_list_all"),
                "topology": safe("easymesh_network?form=get_mesh_topo")}
    if action == "devices":
        return {"devices": safe("easymesh_network?form=get_mesh_device_list_all")}
    if action == "clients":
        return {"clients": safe("easymesh_network?form=mesh_sclient_list_all")}
    if action == "topology":
        return {"topology": safe("easymesh_network?form=get_mesh_topo")}
    if action == "search_status":
        return {"search": ctx.t.call(MESH_SEARCH, "check")}
    if action in ("enable", "disable"):
        plan = ctx.plan("mesh", f"{action} EasyMesh", MESH)
        plan.add(forms.plan_write(MESH, ctx.read(MESH), {"enable": ON if action == "enable" else OFF}))
        devices = safe("easymesh_network?form=get_mesh_device_list_all")
        if action == "disable" and devices and not (isinstance(devices, dict) and "error" in devices):
            plan.critical_reasons.append("satellites are attached; disabling mesh disconnects them and their clients")
        return plan
    if action in ("search_start", "search_stop"):
        plan = Plan(tool="mesh", summary=f"{action.replace('_', ' ')} for new mesh satellites")
        if action == "search_start":
            plan.critical_reasons.append(
                "UNVERIFIED and implicated in a router lock-up (search + WPS together needed a factory reset on "
                "a BE9300); take a backup first and do not start WPS while the search runs")
        plan.add(forms.plan_custom(MESH_SEARCH, "start" if action == "search_start" else "stop",
                                   inverse={"op": "stop", "fields": {}} if action == "search_start" else None))
        return plan
    if action == "pair" and not ctx.args.get("i_understand_this_locked_up_a_router"):
        raise UsageError(
            "mesh pair is DISABLED: in live testing on an Archer BE9300 (fw 1.2.4), starting the mesh satellite "
            "search and a WPS session in the same admin login locked the router up so badly that a reboot did "
            "not recover it (factory reset + config restore needed). Pair satellites from the web UI / Tether "
            "app or the physical WPS button instead.")
    if action == "pair":
        # The easy way to add a satellite: open the mesh search AND press WPS on the main router.
        # Then press the satellite's WPS/pair button within ~2 minutes; watch search_status/devices.
        if not is_on(ctx.read(MESH).get("enable")):
            raise UsageError("EasyMesh is off on this router: mesh action=enable first, then pair")
        wps = safe("wireless?form=syspara_wps")
        if isinstance(wps, dict) and str(wps.get("wps", "on")).lower() == "off":
            raise UsageError("WPS is off: wifi_extra action=wps_settings enable=true first")
        plan = Plan(tool="mesh", summary="pair a new mesh satellite (mesh search + WPS push button)")
        plan.add(forms.plan_custom(MESH_SEARCH, "start", label="mesh search",
                                   inverse={"op": "stop", "fields": {}}))
        from .wifi_extra import wps_poll

        wps_step = forms.plan_custom("wireless?form=wps_connect", "", {"option": "connect"}, label="wps push")
        wps_step.poll = wps_poll("pbc", int(ctx.arg("wait", 125)))
        plan.add(wps_step)
        plan.warnings.append("press the satellite's WPS / pair button within 2 minutes: this call stays "
                             "connected until it pairs or the window closes, then shows mesh action=devices. "
                             "Any WPS device can join meanwhile.")
        return plan
    if action == "device_detail":
        mac = find_mac(ctx.need("mac"))
        return {"device": ctx.t.call("easymesh_network?form=mesh_sclient_detail", "read", {"mac": mac})}
    if action == "set_device":
        # Name / place a mesh unit: settings={name, location, led (satellite), preferred_wifi_uplink_ap
        # (satellite), traffic_separation / backhaul_steering (main router)}
        mac = find_mac(ctx.need("mac"))
        path = "easymesh_network?form=mesh_sclient_detail"
        cur = ctx.t.call(path, "read", {"mac": mac}) or {}
        settings = ctx.obj("settings")
        if not settings:
            raise UsageError("pass settings={name, location, ...}")
        allowed = forms.endpoint(path).write_fields or ()
        bad = [k for k in settings if k not in allowed]
        if bad:
            raise UsageError(f"unknown mesh device setting(s) {bad}; allowed {list(allowed)}")
        base = {k: cur.get(k) for k in ("name", "location") if cur.get(k) is not None}
        fields = {"mac": mac, **base, **{k: (ON if v is True else OFF if v is False else v)
                                         for k, v in settings.items()}}
        plan = Plan(tool="mesh", summary=f"update mesh device {cur.get('name') or mac}")
        old = {"mac": mac, **{k: cur.get(k) for k in fields if k != "mac" and cur.get(k) is not None}}
        plan.add(forms.plan_custom(path, "write", fields, label="mesh device",
                                   inverse={"op": "write", "fields": old}))
        return plan
    if action == "rebalance":
        plan = Plan(tool="mesh", summary="let mesh clients re-pick the best unit")
        plan.add(forms.plan_custom("easymesh_network?form=change_satellite", "write",
                                   {"change_satellite": "true"}, label="rebalance"))
        return plan
    if action == "bind_client":
        # Pin a client to one mesh unit (bind=true) or release it (bind=false).
        agent, client = find_mac(ctx.need("mac")), find_mac(ctx.need("client_mac"))
        bind = bool(ctx.arg("bind", True))
        plan = Plan(tool="mesh", summary=f"{'pin' if bind else 'unpin'} client {client} to unit {agent}")
        plan.add(forms.plan_custom(MESH_MANAGE, "bind_to_current_ap",
                                   {"agent_mac": agent, "client_mac": client, "bind": "true" if bind else "false"},
                                   inverse={"op": "bind_to_current_ap",
                                            "fields": {"agent_mac": agent, "client_mac": client,
                                                       "bind": "false" if bind else "true"}}))
        return plan
    if action == "ap_avoidance":
        return {"ap_avoidance": safe("easymesh_network?form=ap_avoidance_enable_status")}
    if action in ("reboot_satellite", "unlink", "link", "add_onboarding"):
        mac = find_mac(ctx.need("mac"))
        op = {"reboot_satellite": "reboot"}.get(action, action)
        plan = Plan(tool="mesh", summary=f"{op} mesh device {mac}")
        inverse = {"unlink": {"op": "link", "fields": {"mac": mac}},
                   "link": {"op": "unlink", "fields": {"mac": mac}}}.get(op)
        plan.add(forms.plan_custom(MESH_MANAGE, op, {"mac": mac}, inverse=inverse))
        return plan
    raise UsageError(f"unknown action {action!r}")


# ------------------------------------------------------------------------------ routing
ROUTES = "network?form=routes_static"
SYSROUTES = "network?form=routes_system"


ROUTE_INTERFACES = ("LAN", "WAN")  # the UI's dropdown values; lowercase is rejected ('invalid args')


def _interface(v: Any) -> str:
    s = str(v or "LAN").strip().upper()
    if s in ("LAN/WLAN", "WLAN"):
        s = "LAN"
    if s not in ROUTE_INTERFACES:
        raise UsageError(f"interface must be one of {ROUTE_INTERFACES}")
    return s


def _route_errors(ctx: Ctx, row: dict[str, Any]) -> list[str]:
    errs = []
    for f in ("target", "netmask", "gateway"):
        if not is_ipv4(row.get(f)):
            errs.append(f"{f} {row.get(f)!r} is not an IPv4 address")
    if not errs:
        lan = ctx.lan()
        tgt = parse_ipv4(row["target"])
        if tgt in lan.network:
            errs.append(f"target {tgt} is inside the LAN {lan.network}; a static route there breaks local traffic")
        if str(row.get("interface", "")).upper() == "LAN" and parse_ipv4(row["gateway"]) not in lan.network:
            errs.append(f"gateway {row['gateway']} is not on the LAN {lan.network}")
    if not row.get("name"):
        errs.append("name is required")
    return errs


def routing(ctx: Ctx) -> Plan | dict[str, Any]:
    action = ctx.arg("action", "list")
    if action == "list":
        return {"static_routes": ctx.rows(ROUTES)}
    if action == "system":
        return {"routing_table": ctx.rows(SYSROUTES)}
    rows = ctx.rows(ROUTES)
    if action == "add":
        r = ctx.obj("route")
        row = {"name": str(r.get("name", "")), "target": str(r.get("target", "")),
               "netmask": str(r.get("netmask", "")), "gateway": str(r.get("gateway", "")),
               "interface": _interface(r.get("interface")), "enable": onoff(r.get("enable", True))}
        plan = ctx.plan("routing", f"add static route {row['name']}", ROUTES)
        plan.errors += _route_errors(ctx, row)
        if forms.find_rows(rows, "name", row["name"]):
            plan.errors.append(f"a route named {row['name']!r} exists; names must be unique here")
        if not plan.errors:
            plan.add(forms.plan_insert(ROUTES, row, label=row["name"]))
        return plan
    name = str(ctx.need("name"))
    if action == "remove":
        plan = ctx.plan("routing", f"remove static route {name}", ROUTES)
        plan.add(forms.plan_remove(ROUTES, rows, name))
        return plan
    if action == "update":
        r = ctx.obj("route")
        changes = {k: (onoff(v) if k == "enable" else _interface(v) if k == "interface" else str(v))
                   for k, v in r.items() if k in ("target", "netmask", "gateway", "interface", "enable")}
        if "name" in r and r["name"] != name:
            raise UsageError("renaming is not supported; remove and add")
        hits = [x for x in rows if x.get("name") == name]
        if not hits:
            raise UsageError(f"no route named {name!r}")
        plan = ctx.plan("routing", f"update static route {name}", ROUTES)
        plan.errors += _route_errors(ctx, {**hits[0], **changes})
        if not plan.errors:
            plan.add(forms.plan_update(ROUTES, rows, name, changes, label=name))
        return plan
    raise UsageError(f"unknown action {action!r}")


__all__ = ["ip_mac_binding", "upnp", "mesh", "routing", "CRITICAL"]
