"""Internet (WAN) side: connection type for IPv4 and IPv6, DNS privacy (DoH/DoT), MAC clone,
WAN flow control, and live status (speed, dual-NAT, port link)."""

from __future__ import annotations

from typing import Any

from .. import forms
from . import Ctx, UsageError, safe_read, settings_change

WAN_CUT = "changes how the router reaches the internet: if the settings are wrong the WHOLE network goes offline"


# The router's conntype values (wan_ipv4_protos / wan_ipv6_protos) -> the settings form suffix.
CONNTYPE_FORM = {
    "4": {"dhcp": "dynamic", "static": "staticip", "pppoe": "pppoe", "l2tp": "l2tp", "pptp": "pptp",
          "dslite": "dslite", "v6plus": "v6plus", "ocn": "ocn"},
    "6": {"dhcp6c": "dynamic", "staticv6": "static", "pppoev6": "pppoe", "passthrough": "pass", "6to4": "tunnel"},
}


def _resolve(family: str, proto: str) -> tuple[str, str]:
    """Accept the router's conntype (dhcp, staticv6...) or the form name (dynamic, static...).
    Returns (conntype to write, settings form path)."""
    table = CONNTYPE_FORM[family]
    if proto in table:
        return proto, f"network?form=wan_ipv{family}_{table[proto]}"
    by_form = {v: k for k, v in table.items()}
    if proto in by_form:
        return by_form[proto], f"network?form=wan_ipv{family}_{proto}"
    raise UsageError(f"unknown IPv{family} connection type {proto!r}; one of {sorted(table)} "
                     f"(or {sorted(by_form)})")


def _current_proto(ctx: Ctx, family: str) -> str:
    st = ctx.read(f"network?form=wan_ipv{family}_status")
    return str(st.get("conntype") or "")


def internet(ctx: Ctx) -> Any:
    action = ctx.arg("action", "status")
    if action == "status":
        out = {
            "ipv4": safe_read(ctx, "network?form=status_ipv4"),
            "wan": safe_read(ctx, "network?form=wan_ipv4_status"),
            "ipv6": safe_read(ctx, "network?form=wan_ipv6_status"),
            "port": safe_read(ctx, "network?form=wan_port_status"),
            "dual_nat": safe_read(ctx, "status?form=wan_dual_nat_state"),
            "speed": safe_read(ctx, "status?form=wan_speed"),
            "dns_privacy": safe_read(ctx, "network?form=wan_dohdot"),
        }
        return out
    if action == "protocols":
        return {"ipv4": safe_read(ctx, "network?form=wan_ipv4_protos"),
                "ipv6": safe_read(ctx, "network?form=wan_ipv6_protos")}
    if action == "get":
        fam = str(ctx.arg("family", "4"))
        proto = ctx.arg("proto") or _current_proto(ctx, fam)
        if not proto or proto == "none":
            return {"proto": "none", "note": f"IPv{fam} has no connection type set"}
        conntype, path = _resolve(fam, proto)
        return {"proto": conntype, "settings": ctx.read(path)}
    if action == "set":
        # Change the connection type and/or its settings, e.g. proto=pppoe settings={username, password}.
        fam = str(ctx.arg("family", "4"))
        proto = ctx.arg("proto") or _current_proto(ctx, fam)
        conntype, path = _resolve(fam, proto)
        cur = ctx.read(path)
        changes = dict(ctx.obj("settings"))
        changes["conntype"] = conntype
        plan = ctx.plan("internet", f"IPv{fam} internet: {proto}", path)
        plan.add(forms.plan_write(path, cur, changes, label=f"wan ipv{fam} {proto}"))
        if not plan.steps:
            return {"status": "no_change", "settings": cur}
        plan.critical_reasons.append(WAN_CUT)
        plan.warnings.append("have another way online (e.g. phone tethering) before applying")
        return plan
    if action in ("renew", "release"):
        fam = str(ctx.arg("family", "4"))
        path = _resolve(fam, "dynamic")[1]
        plan = ctx.plan("internet", f"{action} the IPv{fam} DHCP lease from the ISP")
        plan.add(forms.plan_custom(path, action, label=action))
        plan.critical_reasons.append("the internet drops while the lease is renewed/released")
        return plan
    if action in ("ipv6_enable", "ipv6_disable"):
        return settings_change(ctx, "internet", "network?form=wan_ipv6_status",
                               {"enable": action == "ipv6_enable"}, "IPv6",
                               critical="IPv6 internet for every device")
    if action == "autodetect":
        return {"result": safe_read(ctx, "network?form=wan_autodetect", "read")}
    if action == "dns_privacy":
        # settings={dns_privacy: none|doh|dot, dns_mode: default|strict, server_list: [...]}
        return settings_change(ctx, "internet", "network?form=wan_dohdot", ctx.obj("settings"), "DNS privacy",
                               warn="strict mode = no fallback: if the chosen servers fail, name lookups fail")
    if action == "dns_privacy_servers":
        kind = ctx.need("kind")
        return {"servers": ctx.t.call("network?form=wan_dohdot", "get_list", {"dns_privacy": kind})}
    if action == "dns_privacy_test":
        fields = {k: forms.to_field(v) if not isinstance(v, (list, dict)) else forms.jdump(v)
                  for k, v in ctx.obj("settings").items()}
        return {"result": ctx.t.call("network?form=wan_dohdot", "detect", fields)}
    if action == "mac_clone":
        return settings_change(ctx, "internet", "network?form=mac_clone_advanced", ctx.obj("settings"),
                               "WAN MAC clone", critical=WAN_CUT,
                               warn="saving reconnects the internet: the ISP may assign a NEW public IP (breaks "
                                    "allowlists that name the old one)")
    if action == "flow_control":
        return settings_change(ctx, "internet", "network?form=wan_fc", ctx.obj("settings"), "WAN flow control")
    raise UsageError(f"unknown action {action!r}")
