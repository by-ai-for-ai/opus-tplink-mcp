"""MCP tool definitions and dispatch (login per call, retry rules, dry-run/apply)."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from typing import Any

from . import catalog
from .features import Ctx, UsageError
from .forms import Conflict
from .journal import Journal
from .safety import Plan, finalize, redact
from .transport import E_LOGIN, RouterError, session

logger = logging.getLogger(__name__)

ONE_SESSION_HINT = ("The router allows ONE admin login at a time: if its web page or the Tether app is "
                    "logged in, log that out and try again.")

WRITE_PROPS: dict[str, Any] = {
    "apply": {"type": "boolean", "default": False,
              "description": "false (default) = dry run: show the plan, diff, warnings and risk, send nothing. "
                             "true = send it."},
    "confirm_token": {"type": "string",
                      "description": "Required with apply=true for CRITICAL changes: the token from the dry run "
                                     "(valid 5 minutes, bound to the exact plan and current router state)."},
    "reveal": {"type": "boolean", "default": False, "description": "Show secrets (passwords/keys) unmasked."},
}
REVEAL_PROP = {"reveal": WRITE_PROPS["reveal"]}
ROUTER_PROP = {"router": {"type": "string", "default": "main",
                          "description": "Which router (see router_status 'routers'); default main."}}


@dataclass
class ToolDef:
    name: str
    description: str
    handler: Callable[[Ctx], Any]
    properties: dict[str, Any] = field(default_factory=dict)
    required: list[str] = field(default_factory=list)
    read_only: bool = False
    kinds: tuple[str, ...] = ("router",)  # device kinds this tool supports

    def schema(self) -> dict[str, Any]:
        props = dict(self.properties)
        props.update(REVEAL_PROP if self.read_only else WRITE_PROPS)
        props.update(ROUTER_PROP)
        return {"type": "object", "properties": props, "required": self.required, "additionalProperties": False}


TOOLS: dict[str, ToolDef] = {}


def register(tool: ToolDef) -> None:
    TOOLS[tool.name] = tool


@dataclass
class Runtime:
    """Everything a tool call needs from the outside world for ONE router (injected in tests)."""

    factory: Callable[[], Any]
    journal: Journal
    host: str = ""
    identity: Callable[[], dict[str, Any]] = field(default=lambda: {"ip": None, "macs": []})
    retry_delay: float = 2.0
    name: str = "main"
    protocol: str = "plain"
    kind: str = "router"

    @property
    def profile(self) -> str:
        return "main" if self.name == "main" else "secondary"

    def reopen(self) -> AbstractContextManager[Any]:
        return session(self.factory)


@dataclass
class Registry:
    """All configured routers by name (``main`` is the household router)."""

    routers: dict[str, Runtime]

    def get(self, name: str) -> Runtime:
        if name not in self.routers:
            raise UsageError(f"unknown router {name!r}; configured: {sorted(self.routers)}")
        return self.routers[name]

    def describe(self) -> list[dict[str, str]]:
        return [{"name": n, "host": r.host, "protocol": r.protocol, "kind": r.kind} for n, r in self.routers.items()]


NO_CALLBACK_HINT = ("router {r!r} does not have this form/operation - its firmware differs from the BE9300 "
                    "this server was built against. Try router_raw_read, or router_catalog for what to look for.")


def run_tool(name: str, args: dict[str, Any] | None, reg: Registry | Runtime) -> dict[str, Any]:
    """Run one tool call inside its own login/logout on the selected router.

    Retries once only for login failures and for ambiguous errors while PLANNING/READING
    (nothing has been written yet).  Applying never retries: an ambiguous write is
    re-read and reported by :func:`safety.apply_plan` instead of being resent.
    """
    if isinstance(reg, Runtime):
        reg = Registry({reg.name: reg})
    tool = TOOLS.get(name)
    if tool is None:
        return {"error": f"unknown tool {name!r}"}
    args = dict(args or {})
    unknown = set(args) - set(tool.schema()["properties"])
    if unknown:
        return {"error": f"unknown argument(s) {sorted(unknown)} for {name}"}
    router = str(args.pop("router", "") or "")
    try:
        if name == "router_undo" and args.get("id"):
            # undo always targets the router the change was made on
            any_rt = next(iter(reg.routers.values()))
            entry = any_rt.journal.get(str(args["id"]))
            entry_router = (entry or {}).get("router") or "main"
            if router and router != entry_router:
                return {"error": f"journal entry {args['id']} was made on router {entry_router!r}, not {router!r}"}
            router = entry_router
        rt = reg.get(router or "main")
    except UsageError as exc:
        return {"error": str(exc)}
    if rt.kind not in tool.kinds:
        usable = sorted(n for n, t in TOOLS.items() if rt.kind in t.kinds)
        return {"error": f"{name} is not supported on {rt.name!r} ({rt.kind})", "tools_for_this_device": usable}
    last: RouterError | None = None
    for attempt in (1, 2):
        try:
            with session(rt.factory) as t:
                ctx = Ctx(t, args, rt.journal, rt.host, rt.identity, router=rt.name, routers=reg.describe(),
                          kind=rt.kind)
                result = tool.handler(ctx)
                if isinstance(result, Plan):
                    if tool.read_only:  # pragma: no cover - programming error
                        raise RuntimeError(f"{name} is read-only but produced a plan")
                    result.router = rt.name
                    for step in result.steps:  # risk tiers are per router
                        step.risk = catalog.risk_of(step.url_path, step.op, rt.profile)
                    try:
                        return finalize(t, result, args, rt.journal, rt.reopen)
                    except Exception as exc:  # noqa: BLE001 - never retry once applying started
                        logger.exception("apply failed")
                        return {"error": f"apply failed: {type(exc).__name__}: {redact(str(exc))}",
                                "note": "not retried; check router_journal and re-read before trying again"}
                return redact(result, bool(args.get("reveal")))
        except (UsageError, ValueError, TypeError) as exc:
            return {"error": str(exc)}
        except Conflict as exc:
            return {"error": f"conflict: {exc}"}
        except RouterError as exc:
            last = exc
            if attempt == 1 and (exc.code == E_LOGIN or exc.ambiguous) and not getattr(exc, "no_retry", False):
                logger.warning("%s attempt 1 failed (%s); retrying with a fresh login", name, exc.code)
                time.sleep(rt.retry_delay)
                continue
            break
    assert last is not None
    out: dict[str, Any] = {"error": last.code, "message": redact(last.message), "router": rt.name}
    unreachable = any(s in last.message for s in ("timed out", "ConnectTimeout", "Max retries exceeded",
                                                   "Connection refused", "No route to host"))
    if unreachable:
        out["hint"] = (f"{rt.name} did not answer at its configured address: it may be restarting, or its address "
                       "changed (e.g. after an operation mode switch); check the host setting for this device.")
    elif last.code == E_LOGIN or last.ambiguous:
        out["hint"] = ONE_SESSION_HINT
    elif last.code == "no such callback":
        out["hint"] = NO_CALLBACK_HINT.format(r=rt.name)
    return out


def _action(values: list[str], default: str | None = None, desc: str = "") -> dict[str, Any]:
    d: dict[str, Any] = {"type": "string", "enum": values}
    if default:
        d["default"] = default
    if desc:
        d["description"] = desc
    return d


# =============================================================================== tools
def _register_all() -> None:
    from .features import core, dhcp

    register(ToolDef(
        "router_status",
        "Router overview: WAN/LAN addresses, internet state, Wi-Fi bands, client counts, CPU/memory, "
        "firmware, VPN-client switch. On an extender: model, mode, uplink, mesh role. Read-only.",
        core.router_status, read_only=True, kinds=("router", "extender")))
    register(ToolDef(
        "router_get",
        "Read one section of the router config by friendly name (e.g. dhcp, dhcp_reservations, dhcp_leases, "
        "clients, wifi, vpn_client_profiles, static_routes, access_control, upnp_mappings, firewall, time) or "
        "any form path from router_catalog. Call with no section to list sections. Secrets masked unless reveal.",
        core.router_get, {"section": {"type": "string"}}, read_only=True))
    register(ToolDef(
        "router_catalog",
        "List every router form (219+), what each operation does to risk (read/normal/critical/forbidden) and "
        "whether its format is verified live or only copied from the web UI. filter narrows by text; path "
        "describes one form (fields, key, secrets).",
        core.router_catalog, {"filter": {"type": "string"}, "path": {"type": "string"}}, read_only=True))
    register(ToolDef(
        "router_raw_read",
        "Send a read-only operation to any catalogued form, e.g. path='iptv?form=setting', operation='read', "
        "or custom read ops like operation='getBlockHistory' with fields. Refuses write-type operations.",
        core.router_raw_read,
        {"path": {"type": "string"}, "operation": {"type": "string", "default": "read"},
         "fields": {"type": "object", "description": "extra request fields (strings; objects are JSON-encoded)"}},
        required=["path"], read_only=True, kinds=("router", "extender")))
    register(ToolDef(
        "router_logs",
        "Read the router's system log (newest first when timestamps parse). Filters: level (minimum severity, "
        "e.g. WARNING), type (e.g. DHCPD, WAN), contains (text), since ('2026-11-17 08:00:00'), limit. "
        "Never changes the router's own log filter.",
        core.router_logs,
        {"level": {"type": "string"}, "type": {"type": "string"}, "contains": {"type": "string"},
         "since": {"type": "string"}, "limit": {"type": "integer", "default": 100}}, read_only=True))
    register(ToolDef(
        "router_journal",
        "This server's change journal: action=list (recent changes, with ids) or action=show id=... (full "
        "before/after and requests). Use the id with router_undo.",
        core.router_journal,
        {"action": _action(["list", "show"], "list"), "id": {"type": "string"},
         "limit": {"type": "integer", "default": 20}}, read_only=True, kinds=("router", "extender")))
    register(ToolDef(
        "router_undo",
        "Reverse a journaled change (writes restore old values, inserts are removed, removes re-added, updates "
        "swapped back). Refuses if the router changed since, unless force=true. Reboots/firmware/actions are "
        "not undoable. Dry run first like every write.",
        core.router_undo, {"id": {"type": "string"}, "force": {"type": "boolean", "default": False}},
        required=["id"], kinds=("router", "extender")))
    register(ToolDef(
        "router_raw_write",
        "Escape hatch: send ANY operation + fields to a catalogued form. Risk comes from the catalog (unknown "
        "ops are CRITICAL, so need a confirm_token). FORBIDDEN ops (factory reset, config restore, firmware "
        "upload, quick setup, cloud bind) also need TPLINK_ALLOW_FORBIDDEN=1. Prefer the specific tools.",
        core.router_raw_write,
        {"path": {"type": "string"}, "operation": {"type": "string"},
         "fields": {"type": "object", "description": "request fields (strings; objects are JSON-encoded)"}},
        required=["path", "operation"]))
    register(ToolDef(
        "dhcp_server_set",
        "DHCP server: action=get shows settings; otherwise change enable / start / end (pool) / lease_minutes "
        "(1-2880) / gateway / dns1 / dns2. Validated against the LAN subnet, the router's own IP, active leases "
        "and reservations. Disabling DHCP or a gateway other than the router is CRITICAL.",
        dhcp.dhcp_server_set,
        {"action": _action(["get", "set"], "set"), "enable": {"type": "boolean"}, "start": {"type": "string"},
         "end": {"type": "string"}, "lease_minutes": {"type": "integer"}, "gateway": {"type": "string"},
         "dns1": {"type": "string"}, "dns2": {"type": "string"}}))
    register(ToolDef(
        "dhcp_reservation",
        "DHCP address reservations (stable IPs, e.g. for kiosk tablets). action=list (with lease status and "
        "random-MAC warnings) | leases | add (mac, ip, name) | update (mac + ip/name/enable) | remove (mac) | "
        "reserve_current (pin a client's CURRENT address; identify it by mac, current_ip or client hostname). "
        "MACs in any format. Warns when a MAC is randomised/private - that device must use its real MAC.",
        dhcp.dhcp_reservation,
        {"action": _action(["list", "leases", "add", "update", "remove", "reserve_current"], "list"),
         "mac": {"type": "string"}, "ip": {"type": "string"}, "name": {"type": "string"},
         "enable": {"type": "boolean"}, "current_ip": {"type": "string"}, "client": {"type": "string"}}))

    _register_priority()


def _register_priority() -> None:
    from .features import network, vpn

    register(ToolDef(
        "ip_mac_binding",
        "IP-MAC binding (ARP binding): action=status|list (setting, bindings, live ARP table) | enable | disable | "
        "add (mac, ip, name, description) | update (mac + ip/name/description/enable; done as remove+re-add) | "
        "remove (mac) | bind_current (bind an ARP entry as-is, by mac or ip). Binding THIS machine to a "
        "different IP is CRITICAL.",
        network.ip_mac_binding,
        {"action": _action(["status", "list", "enable", "disable", "add", "update", "remove", "bind_current"],
                           "status"),
         "mac": {"type": "string"}, "ip": {"type": "string"}, "name": {"type": "string"},
         "description": {"type": "string"}, "enable": {"type": "boolean"}}))
    register(ToolDef(
        "upnp",
        "UPnP: action=status|list (switch + current port mappings devices opened) | enable | disable. "
        "The router offers no per-mapping delete.",
        network.upnp, {"action": _action(["status", "list", "enable", "disable"], "status")}))
    register(ToolDef(
        "mesh",
        "EasyMesh: action=status|devices|clients|topology|search_status|ap_avoidance|device_detail (mac) (read) | "
        "pair (DISABLED: locked up a BE9300 in testing; use the web UI / Tether / WPS button) | enable | disable (CRITICAL if satellites are attached) | "
        "search_start | search_stop | link | unlink (CRITICAL) | reboot_satellite (CRITICAL) | add_onboarding "
        "(mac) | set_device (mac, settings={name, location, led, preferred_wifi_uplink_ap, traffic_separation, "
        "backhaul_steering}) | rebalance (clients re-pick the best unit) | bind_client (mac=unit, client_mac, "
        "bind=true|false: pin a client to a unit). Satellite firmware: maintenance action=firmware_check / "
        "satellite_firmware_update.",
        network.mesh,
        {"action": _action(["status", "devices", "clients", "topology", "search_status", "ap_avoidance",
                            "device_detail", "pair", "enable", "disable", "search_start", "search_stop", "link",
                            "unlink", "reboot_satellite", "add_onboarding", "set_device", "rebalance",
                            "bind_client"], "status"),
         "mac": {"type": "string"}, "client_mac": {"type": "string"}, "bind": {"type": "boolean"},
         "wait": {"type": "integer", "description": "pair: seconds to keep WPS open (default 125)"},
         "i_understand_this_locked_up_a_router": {"type": "boolean",
                                                  "description": "pair is disabled unless this is true"},
         "settings": {"type": "object"}}))
    register(ToolDef(
        "vpn_server",
        "The router's VPN SERVERS (people dialling in). kind=openvpn|pptp|l2tp|wireguard; action=get | set "
        "(settings={...}) | enable | disable (CRITICAL) | accounts | accounts_add (account={...}) | "
        "accounts_update (key, account={...}) | accounts_remove (key) | connected | disconnect (key). "
        "Secrets masked unless reveal.",
        vpn.vpn_server,
        {"kind": _action(list(vpn.SERVER_CONFIG)),
         "action": _action(["get", "set", "enable", "disable", "accounts", "accounts_add", "accounts_update",
                            "accounts_remove", "connected", "disconnect"], "get"),
         "settings": {"type": "object"}, "account": {"type": "object"}, "key": {"type": "string"}},
        required=["kind"]))
    register(ToolDef(
        "vpn_client",
        "The router's VPN CLIENT (router dials out). Configure a VPN, then choose which devices use it - this is "
        "how e.g. a child's device can be sent through a filtering VPN. Profiles: action=profiles | add_profile "
        "(profile={key,...}; added disabled) | set_active_profile (key; the ENABLED profile is the one in use) | "
        "update_profile / remove_profile (key). Devices (they use WHICHEVER profile is active; there is no "
        "per-device profile): devices | candidates | add_device (mac, name?, client_type?) | set_device (mac, "
        "use_vpn=true|false) | remove_device (mac). Also status | connection_status (key) | enable | disable. "
        "Everything that changes profiles or devices is CRITICAL.",
        vpn.vpn_client,
        {"action": _action(["status", "profiles", "devices", "candidates", "connection_status", "enable",
                            "disable", "add_profile", "set_active_profile", "update_profile", "remove_profile",
                            "add_device", "set_device", "remove_device"], "status"),
         "profile": {"type": "object"}, "key": {"type": "string"}, "mac": {"type": "string"},
         "name": {"type": "string"}, "client_type": {"type": "string"}, "use_vpn": {"type": "boolean"}}))
    register(ToolDef(
        "routing",
        "Static routes: action=list | system (the live routing table) | add (route={name, target, netmask, "
        "gateway, interface LAN|WAN, enable}) | update (name, route={...}) | remove (name).",
        network.routing,
        {"action": _action(["list", "system", "add", "update", "remove"], "list"),
         "name": {"type": "string"}, "route": {"type": "object"}}))

    _register_phase6()


def _register_phase6() -> None:
    from .features import access, nat, wifi

    register(ToolDef(
        "access_control",
        "Access control (who may use the network). action=status | candidates | enable | disable | "
        "set_mode (mode=black|white) | block / unblock (mac[, name]) | allow / disallow (mac). Black mode "
        "blocks listed devices; white mode blocks everything NOT listed. Switching to white mode, enabling it, "
        "or blocking THIS machine is CRITICAL.",
        access.access_control,
        {"action": _action(["status", "candidates", "enable", "disable", "set_mode", "block", "unblock", "allow",
                            "disallow"], "status"),
         "mode": _action(["black", "white"]), "mac": {"type": "string"}, "name": {"type": "string"}}))
    register(ToolDef(
        "parental_control",
        "HomeShield parental controls (local, per profile/'owner', e.g. a child). action=owners | devices | "
        "block_history (owner_id) | today_sites (owner_id) | filter_get / allowed_sites_get (owner_id) | "
        "internet_block (owner_id, blocked=true pauses the internet, false resumes) | filter_set / "
        "allowed_sites_set (owner_id, sites=[domains]) | add_owner (owner={...}) | remove_owner (owner_id).",
        access.parental_control,
        {"action": _action(["owners", "devices", "block_history", "today_sites", "filter_get", "allowed_sites_get",
                            "internet_block", "filter_set", "allowed_sites_set", "add_owner", "remove_owner"],
                           "owners"),
         "owner_id": {"type": "string"}, "blocked": {"type": "boolean"},
         "sites": {"type": "array", "items": {"type": "string"}}, "owner": {"type": "object"}}))
    register(ToolDef(
        "wifi_set",
        "Wi-Fi: action=get (band=2g|5g|6g|guest|guest_access|all) | set (band, settings={ssid|name, "
        "password, hidden, enable, channel, txpower, htmode, encryption, ...}; guest also takes guest_band="
        "2g|5g|2g5g|6g|all; guest_access takes {access, isolate}) | smart_connect (enable). Turning a radio "
        "off is CRITICAL. This server's machine is wired, so it is not cut off.",
        wifi.wifi_set,
        {"action": _action(["get", "set", "smart_connect"], "get"),
         "band": _action(["2g", "5g", "6g", "guest", "guest_access", "all"]),
         "guest_band": {"type": "string"}, "settings": {"type": "object"}, "enable": {"type": "boolean"}}))
    register(ToolDef(
        "wifi_schedule",
        "Wi-Fi off-schedule (e.g. no Wi-Fi 23:00-07:00 on school nights). action=get | enable | disable | "
        "add (rule={start 'HH:MM', end, days [sun..sat], bands [2g,5g,6g], enable}) | update (key, rule) | "
        "remove (key).",
        wifi.wifi_schedule,
        {"action": _action(["get", "enable", "disable", "add", "update", "remove"], "get"),
         "key": {"type": "string"}, "rule": {"type": "object"}}))
    register(ToolDef(
        "port_forwarding",
        "Port forwarding. kind=vs (virtual servers, default) | pt (port triggering) | dmz. action=list | add "
        "(rule={name, external_port, internal_port, ip, protocol ALL|TCP|UDP, enable}) | update (name, rule) | "
        "remove (name); for dmz: list | enable (ip) | disable. Overlapping external ports are refused.",
        nat.port_forwarding,
        {"kind": _action(["vs", "pt", "dmz"], "vs"),
         "action": _action(["list", "add", "update", "remove", "enable", "disable"], "list"),
         "name": {"type": "string"}, "rule": {"type": "object"}, "ip": {"type": "string"}}))

    _register_phase7()


def _register_phase7() -> None:
    from .features import system

    register(ToolDef(
        "system",
        "System settings. action=info (all of the below) | firmware_check (ask TP-Link for updates; changes "
        "nothing) | ddns (read) | device_priority (list) | set_device_priority (mac, enable, time_period) | "
        "led / led_night / eco / time / dst / hour24 / auto_upgrade / qos / firewall (no settings = read; settings={...} or "
        "enable=bool = change) | time_sync | reboot (CRITICAL, not undoable).",
        system.system,
        {"action": _action(["info", "firmware_check", "ddns", "device_priority", "set_device_priority", "led",
                            "led_night", "eco", "time", "dst", "hour24", "auto_upgrade", "qos", "firewall",
                            "time_sync", "reboot"], "info"),
         "settings": {"type": "object"}, "enable": {"type": "boolean"}, "mac": {"type": "string"},
         "time_period": {"type": "string"}}))


def _register_phase8() -> None:
    from .features import (
        admin,
        clients,
        ddns,
        device_log,
        internet,
        lan,
        maintenance,
        usb,
        wifi_extra,
    )

    settings = {"type": "object", "description": "fields to change (see the matching router_catalog form)"}
    enable = {"type": "boolean"}
    register(ToolDef(
        "internet",
        "Internet (WAN). action=status (connection, IPv4/IPv6, WAN port, dual-NAT, speed, DNS privacy) | protocols "
        "| get (family=4|6, proto?) | set (family, proto=dynamic|staticip|pppoe|l2tp|pptp|dslite|v6plus|ocn for "
        "IPv4; dynamic|static|pppoe|pass|tunnel for IPv6, settings={...}) CRITICAL | renew | release (family) | "
        "ipv6_enable | ipv6_disable | autodetect | dns_privacy (settings={dns_privacy: none|doh|dot, dns_mode: "
        "default|strict, server_list: [...]}) | dns_privacy_servers (kind=doh|dot) | dns_privacy_test (settings) | "
        "mac_clone (settings={mac_clone_type, mac_custom}) | flow_control (settings={rx_enable, tx_enable}).",
        internet.internet,
        {"action": _action(["status", "protocols", "get", "set", "renew", "release", "ipv6_enable", "ipv6_disable",
                            "autodetect", "dns_privacy", "dns_privacy_servers", "dns_privacy_test", "mac_clone",
                            "flow_control"], "status"),
         "family": _action(["4", "6"]), "proto": {"type": "string"}, "kind": _action(["doh", "dot"]),
         "settings": settings}))
    register(ToolDef(
        "lan",
        "LAN side. action=status (all below + port status) | lan_ipv4 (router LAN IP/mask: CRITICAL) | lan_ipv6 | "
        "port_speed (settings={speed}) | link_aggregation (LACP: enable_agg, hashmode, lacpmode, port_settings) | "
        "flow_control (rx_enable, tx_enable) | iptv (IPTV/VLAN: enable, mode, internet/iptv/ipphone VLAN ids, "
        "IGMP, port_settings) | udp_proxy | nat (NAT and hardware NAT boost) | alg (settings={ftp, tftp, h323, rtsp, "
        "sip, pptp, l2tp, ipsec: true/false}). Firewall / ping replies: system action=firewall. No settings = read.",
        lan.lan,
        {"action": _action(["status", *lan.GROUPS], "status"), "settings": settings, "enable": enable}))
    register(ToolDef(
        "maintenance",
        "Maintenance. action=info | backup (download the config to the backup folder) | backups (list) | restore "
        "(file = a backup name or path; CRITICAL, reboots) | firmware_check (router + mesh satellites, online) | "
        "firmware_update_online (CRITICAL, reboots) | firmware_status | firmware_upload (file = image path; "
        "CRITICAL) | satellite_firmware_update (mac) | ping / traceroute (target, count, size, max_hops, timeout) | "
        "operation_mode (mode=router|ap|repeater|client|multissid; none = read; CRITICAL; keep_access) | reboot_schedule "
        "(settings). Factory reset is deliberately only reachable via router_raw_write (forbidden tier).",
        maintenance.maintenance,
        {"action": _action(["info", "backup", "backups", "restore", "firmware_check", "firmware_update_online",
                            "firmware_status", "firmware_upload", "satellite_firmware_update", "ping", "traceroute",
                            "operation_mode", "reboot_schedule"], "info"),
         "file": {"type": "string"}, "mac": {"type": "string"}, "target": {"type": "string"},
         "count": {"type": "integer"}, "size": {"type": "integer"}, "max_hops": {"type": "integer"},
         "timeout": {"type": "integer"}, "mode": _action(list(maintenance.MODES)), "settings": settings,
         "keep_access": {"type": "boolean", "default": False, "description": "operation_mode to router: turn remote "
                         "management on first so this server can reach the device on its WAN side (exposes the "
                         "admin page there - the internet if the WAN is your ISP)"}}))
    register(ToolDef(
        "admin",
        "Router administration. action=status | change_password (old_password_file, new_password_file; "
        "CRITICAL) | remote (remote management: enable, http_port, https_port, managers) | https | local_mode "
        "(everyone vs listed devices) | local_add / local_remove (mac, name) | recovery (password-recovery "
        "e-mail) | superadmin | permissions (what the local user may see/edit). No settings = read.",
        admin.admin,
        {"action": _action(["status", "change_password", "local_add", "local_remove", *admin.GROUPS], "status"),
         "old_password_file": {"type": "string"}, "new_password_file": {"type": "string"},
         "mac": {"type": "string"}, "name": {"type": "string"}, "settings": settings, "enable": enable}))
    register(ToolDef(
        "wifi_extra",
        "Wi-Fi extras. WPS pairing: action=wps_push (press the router's WPS button; the call stays connected and "
        "returns the outcome: success + the device's MAC, or timeout) | wps_client_pin (pin = the device's PIN) "
        "| wait (seconds, default 125) | wps_cancel | wps_status (a session the web page/button started) | "
        "wps_settings (enable) | "
        "wps_pin_enable / wps_pin_disable / wps_pin_generate / wps_pin_default. Also mlo (Wi-Fi 7 multi-link "
        "network) | ofdma | ofdma_mimo | twt | fast_roaming | advanced (beacon, DTIM, RTS, airtime fairness, "
        "zero-wait DFS...) | guest_bandwidth | guest_time | afc | afc_refresh | status. To add a mesh satellite "
        "use mesh action=pair. Main SSIDs/passwords/channels: wifi_set.",
        wifi_extra.wifi_extra,
        {"action": _action(["status", "wps_push", "wps_client_pin", "wps_cancel", "wps_status",
                            "wps_pin_generate", "wps_pin_default", "wps_pin_enable", "wps_pin_disable",
                            "afc_refresh", *wifi_extra.GROUPS], "status"),
         "pin": {"type": "string"}, "pin_mode": {"type": "boolean"},
         "wait": {"type": "integer", "description": "seconds to keep WPS open (10-300, default 125)"},
         "settings": settings, "enable": enable}))
    register(ToolDef(
        "clients",
        "Connected devices. action=list | rename (mac, name: the name shown everywhere) | speed (limits/speeds) | "
        "speed_limit (mac, download_kbps, upload_kbps, enable) | game_accelerator | iot_status | iot_enable | "
        "iot_disable | iot_add / iot_remove (mac or macs: move smart-home devices to the isolated IoT network).",
        clients.clients,
        {"action": _action(["list", "rename", "speed", "speed_limit", "game_accelerator", "iot_status",
                            "iot_enable", "iot_disable", "iot_add", "iot_remove"], "list"),
         "mac": {"type": "string"}, "macs": {"type": "array", "items": {"type": "string"}},
         "name": {"type": "string"}, "download_kbps": {"type": "integer"}, "upload_kbps": {"type": "integer"},
         "enable": enable}))
    register(ToolDef(
        "usb",
        "USB. action=status (disks, sharing, accounts, media server, Time Machine, modem) | scan | partitions "
        "(serial) | partition (serial, uuid, enable: share/hide one partition) | eject (serial) | browse "
        "(uuid, path) | service (protocol=samba|ftp|ftpex|sftp|sftpex, enable/settings={port}) | sharing_auth | "
        "media_server | server_name | time_machine | modem (USB 4G backup internet; CRITICAL) | modem_isps.",
        usb.usb,
        {"action": _action(["status", "scan", "partitions", "partition", "eject", "browse", "service", "server_name",
                            "modem_isps", *usb.GROUPS], "status"),
         "serial": {"type": "string"}, "uuid": {"type": "string"}, "path": {"type": "string"},
         "name": {"type": "string"},
         "protocol": {"type": "string"}, "settings": settings, "enable": enable}))
    register(ToolDef(
        "device_log",
        "Everything the router knows about ONE device, plus a local per-MAC history. action=report (mac: online "
        "state, IP, DHCP lease/reservation, every router-log line mentioning its MAC or IP, its parental-control "
        "profile's sites today and blocked attempts, access-control / VPN / IoT status, traffic) | record (mac: "
        "append only what is NEW to <state>/device-logs/<router>-<MAC>.jsonl; run it on a timer for a "
        "continuous log beyond what the router keeps) | history (mac, event?, limit) | list. Read-only on the "
        "router.",
        device_log.device_log,
        {"action": _action(["report", "record", "history", "list"], "report"), "mac": {"type": "string"},
         "event": _action(["online", "offline", "router_log", "site", "blocked"]),
         "limit": {"type": "integer"}}, read_only=True))
    register(ToolDef(
        "ddns",
        "Dynamic DNS. action=status | refresh (provider) | tplink: add / remove / bind / unbind (domain) | "
        "noip / dyndns: login (username, domain, password_file[, wan_bind]) | logout.",
        ddns.ddns,
        {"action": _action(["status", "refresh", "add", "remove", "bind", "unbind", "login", "logout"], "status"),
         "provider": _action(["tplink", "noip", "dyndns"]), "domain": {"type": "string"},
         "username": {"type": "string"}, "password_file": {"type": "string"}, "wan_bind": {"type": "string"}}))


def _register_extender() -> None:
    from .features import extender

    register(ToolDef(
        "extender",
        "TP-Link range extender (RE series). action=status (model, mode, uplink signal, mesh role) | uplink "
        "(the network it connects to) | extended (networks it broadcasts) | guest | mesh | network | clients | "
        "wifi_advanced | system (mode, time, LEDs, eco, power schedule) | logs. Secrets masked unless reveal.",
        extender.extender,
        {"action": _action(["status", *[k for k in extender.SECTIONS if k != "status"]], "status")},
        read_only=True, kinds=("extender",)))
    register(ToolDef(
        "extender_set",
        "Change a range extender: action=led (enable) | led_night (enable, time_start, time_end) | "
        "power_schedule (enable) | reboot. (Extended networks / high-speed mode: read them with extender; "
        "writing them is not verified yet - use router_raw_write if needed.) No settings = show current values. Dry run "
        "first; critical changes need the confirm_token. Journaled and undoable (except reboot).",
        extender.extender_set,
        {"action": _action(["led", "led_night", "power_schedule", "reboot"]),
         "enable": {"type": "boolean"}, "settings": {"type": "object"}},
        required=["action"], kinds=("extender",)))


_register_all()
_register_phase8()
_register_extender()
