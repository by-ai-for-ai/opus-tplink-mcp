"""LAN side: router LAN address, LAN IPv6, port speed, link aggregation, flow control,
IPTV/VLAN and the UDP proxy, NAT / hardware NAT boost and the ALGs."""

from __future__ import annotations

from typing import Any

from . import Ctx, UsageError, safe_read, settings_change

GROUPS: dict[str, tuple[str, str, str | None]] = {
    # action: (path, description, critical reason or None)
    "lan_ipv4": ("network?form=lan_ipv4", "LAN IP / subnet",
                 "changing the router's LAN address or mask disconnects EVERY device until they renew"),
    "lan_ipv6": ("network?form=lan_ipv6", "LAN IPv6", None),
    "port_speed": ("network?form=port_speed_current", "Ethernet port speed",
                   "a wrong speed/duplex can drop the link on that port"),
    "link_aggregation": ("network?form=lan_agg", "link aggregation (LACP)",
                         "aggregating ports the switch/NAS isn't set up for breaks those links"),
    "flow_control": ("network?form=lan_fc", "LAN flow control", None),
    "iptv": ("iptv?form=setting", "IPTV / VLAN",
             "VLAN tagging on the WAN must match the ISP or the internet stops"),
    "udp_proxy": ("iptv?form=udp_proxy_setting", "IPTV UDP proxy", None),
    "nat": ("nat?form=setting", "NAT / hardware NAT boost", None),
    "alg": ("nat?form=alg", "ALG (FTP, TFTP, H.323, RTSP, SIP, PPTP/L2TP/IPsec passthrough)", None),
}


def lan(ctx: Ctx) -> Any:
    action = ctx.arg("action", "status")
    if action == "status":
        out = {name: safe_read(ctx, path) for name, (path, _, _) in GROUPS.items()}
        out["port_speed_supported"] = safe_read(ctx, "network?form=port_speed_supported")
        out["ports"] = safe_read(ctx, "status?form=router")
        return out
    if action in GROUPS:
        path, what, crit = GROUPS[action]
        settings = ctx.obj("settings")
        if ctx.args.get("enable") is not None:
            key = {"nat": "enable", "iptv": "enable", "udp_proxy": "udp_proxy_enable",
                   "link_aggregation": "enable_agg"}.get(action)
            if not key:
                raise UsageError(f"{action} has no single on/off; pass settings")
            settings.setdefault(key, ctx.args["enable"] if action != "link_aggregation"
                                else ("1" if ctx.args["enable"] else "0"))
        if action == "port_speed" and settings.get("speed") is not None:
            sup = safe_read(ctx, "network?form=port_speed_supported")
            allowed = sup.get("supported") if isinstance(sup, dict) else None
            if allowed and settings["speed"] not in allowed:
                raise UsageError(f"speed must be one of {allowed}")
        if action == "alg" and any(settings.get(k) in (False, "off") for k in ("pptp", "l2tp", "ipsec")):
            settings_warn = "VPN passthrough off: VPN clients on the LAN (work laptops) may stop connecting"
        else:
            settings_warn = None
        if action == "iptv" and settings:
            wait = safe_read(ctx, "iptv?form=setting")
            secs = wait.get("wait_time", 40) if isinstance(wait, dict) else 40
            settings_warn = (settings_warn + "; " if settings_warn else "") + \
                f"saving IPTV restarts the router's network for about {secs} s (seen live)"
        if action == "nat" and settings.get("enable") in (False, "off"):
            crit = "turning NAT off stops internet for every LAN device"
        return settings_change(ctx, "lan", path, settings, what, critical=crit if settings else None,
                               warn=settings_warn)
    raise UsageError(f"unknown action {action!r}")
