"""VPN server (OpenVPN / PPTP / L2TP-IPsec / WireGuard) and VPN client.

A VPN *client* profile often carries a policy (e.g. a content filter for a child's device):
editing, disabling or removing it - or any of its device assignments - is CRITICAL on the main
router, because breaking it fails silently (the device just stops going through the VPN).
Devices listed in ``TPLINK_PROTECTED_MACS`` are called out by name in those warnings.
"""

from __future__ import annotations

from typing import Any

from .. import forms
from ..safety import Plan
from . import OFF, ON, Ctx, UsageError, find_mac, is_on, onoff

SERVER_CONFIG = {
    "openvpn": ("openvpn?form=config", "enabled"),
    "pptp": ("pptpd?form=config", "enabled"),
    "l2tp": ("l2tpoveripsec?form=config", "enabled"),
    "wireguard": ("wireguard?form=config", "enable"),
}
SERVER_ACCOUNTS = {
    "pptp": "pptpd?form=accounts",
    "l2tp": "l2tpoveripsec?form=accounts",
    "wireguard": "wireguard?form=account",
}
VPNCONN = "vpnconn?form=config"


def _kind(ctx: Ctx) -> str:
    kind = ctx.need("kind")
    if kind not in SERVER_CONFIG:
        raise UsageError(f"kind must be one of {sorted(SERVER_CONFIG)}")
    return str(kind)


def _enable_value(current: Any, on: bool) -> Any:
    """Keep the form's own type: some forms use 'on'/'off', WireGuard uses booleans."""
    if isinstance(current, bool):
        return on
    return ON if on else OFF


def vpn_server(ctx: Ctx) -> Plan | dict[str, Any]:
    kind = _kind(ctx)
    action = ctx.arg("action", "get")
    cfg_path, enable_field = SERVER_CONFIG[kind]
    acc_path = SERVER_ACCOUNTS.get(kind)
    if action == "get":
        out: dict[str, Any] = {"kind": kind, "config": ctx.read(cfg_path)}
        if acc_path:
            out["accounts"] = ctx.rows(acc_path)
        return out
    if action == "connected":
        return {"kind": kind, "connections": ctx.t.call(VPNCONN, "list", {"vpntype": kind})}
    cur = ctx.read(cfg_path)
    if action in ("enable", "disable"):
        on = action == "enable"
        plan = ctx.plan("vpn_server", f"{action} the {kind} VPN server", cfg_path)
        plan.add(forms.plan_write(cfg_path, cur, {enable_field: _enable_value(cur.get(enable_field), on)}))
        plan.critical_reasons.append(f"VPN {action}: remote users {'gain' if on else 'lose'} access")
        if on and kind == "pptp":
            plan.warnings.append("PPTP is cryptographically broken; prefer WireGuard or OpenVPN")
        return plan
    if action == "set":
        changes = ctx.obj("settings")
        if enable_field in changes:
            raise UsageError("use action=enable/disable to switch the server on or off")
        plan = ctx.plan("vpn_server", f"change {kind} VPN server settings", cfg_path)
        plan.add(forms.plan_write(cfg_path, cur, changes))
        if is_on(cur.get(enable_field)) or cur.get(enable_field) is True:
            plan.warnings.append("the server is running: existing remote clients may need new config files")
        return plan
    if action == "disconnect":
        key = str(ctx.need("key"))
        conns = ctx.t.call(VPNCONN, "list", {"vpntype": kind}) or []
        idx = [i for i, c in enumerate(conns if isinstance(conns, list) else []) if str(c.get("key")) == key]
        if not idx:
            raise UsageError(f"no connected {kind} client with key {key!r} (see action=connected)")
        plan = Plan(tool="vpn_server", summary=f"disconnect {kind} client {key}")
        plan.add(forms.plan_custom(VPNCONN, "disconnect", {"vpntype": kind, "key": key, "index": str(idx[0])}))
        return plan
    if not acc_path:
        raise UsageError(f"{kind} has no account list" + (" (OpenVPN uses certificates)" if kind == "openvpn" else ""))
    ep = forms.endpoint(acc_path)
    key_field = ep.key_field or "username"
    rows = ctx.rows(acc_path)
    if action == "accounts":
        return {"kind": kind, "accounts": rows}
    if action == "accounts_add":
        row = ctx.obj("account")
        if not row.get(key_field):
            raise UsageError(f"account.{key_field} is required")
        plan = ctx.plan("vpn_server", f"add {kind} VPN account {row[key_field]}", acc_path)
        if forms.find_rows(rows, key_field, row[key_field]):
            plan.errors.append(f"{kind} account {row[key_field]!r} already exists")
        else:
            plan.add(forms.plan_insert(acc_path, row, label=str(row[key_field])))
        plan.secret_fields = ep.secret_fields
        return plan
    key = ctx.need("key")
    if action == "accounts_update":
        plan = ctx.plan("vpn_server", f"update {kind} VPN account {key}", acc_path)
        plan.add(forms.plan_update(acc_path, rows, key, ctx.obj("account")))
        plan.secret_fields = ep.secret_fields
        return plan
    if action == "accounts_remove":
        plan = ctx.plan("vpn_server", f"remove {kind} VPN account {key}", acc_path)
        plan.add(forms.plan_remove(acc_path, rows, key))
        plan.secret_fields = ep.secret_fields
        return plan
    raise UsageError(f"unknown action {action!r}")


# ----------------------------------------------------------------------------- client
# The VPN Client page on this firmware is (a) a list of profiles (vpn?form=server) where the
# ENABLED profile is the one in use, and (b) a list of devices (vpn?form=vpn_user_list) that go
# through whichever profile is active, each with access on/off.  There is NO per-device profile
# assignment (server_key/server_des in those rows are ignored leftovers).
VPN_ENABLE = "vpn?form=enable"
PROFILES = "vpn?form=server"
DEVICES = "vpn?form=vpn_user_list"
CANDIDATES = "vpn?form=vpn_user_devices"
FILTER_NOTE = ("devices routed through the VPN client may depend on it (e.g. a content filter): breaking it "
               "fails silently (they just stop going through the VPN)")


def protected_macs() -> set[str]:
    """MACs from TPLINK_PROTECTED_MACS (comma/space separated) whose VPN routing must not break silently."""
    import os
    import re

    out = set()
    for m in re.split(r"[,\s]+", os.environ.get("TPLINK_PROTECTED_MACS", "")):
        if m:
            try:
                out.add(find_mac(m))
            except UsageError:
                pass
    return out


def _device_note(mac: str) -> str:
    return (f"{mac} is a PROTECTED device (TPLINK_PROTECTED_MACS) - " if mac in protected_macs() else "") + FILTER_NOTE


def vpn_client(ctx: Ctx) -> Plan | dict[str, Any]:
    action = ctx.arg("action", "status")
    if action == "status":
        profiles = ctx.rows(PROFILES)
        return {"enabled": is_on(ctx.read(VPN_ENABLE).get("enable")),
                "active_profile": [p.get("key") for p in profiles if is_on(p.get("enable"))],
                "profiles": profiles, "devices": ctx.rows(DEVICES),
                "note": "devices with access=on go through whichever profile is active"}
    if action == "profiles":
        return {"profiles": ctx.rows(PROFILES)}
    if action == "devices":
        return {"devices": ctx.rows(DEVICES), "note": "access=on: the device uses the active VPN profile"}
    if action == "candidates":
        return {"candidates": ctx.rows(CANDIDATES)}
    if action == "connection_status":
        return {"status": ctx.t.call(PROFILES, "connected_status", {"key": str(ctx.need("key"))})}
    if action in ("enable", "disable"):
        plan = ctx.plan("vpn_client", f"{action} the VPN client", VPN_ENABLE)
        plan.add(forms.plan_write(VPN_ENABLE, ctx.read(VPN_ENABLE), {"enable": ON if action == "enable" else OFF}))
        if action == "disable":
            plan.warnings.append(FILTER_NOTE)
        return plan
    profiles = ctx.rows(PROFILES)
    secret = forms.endpoint(PROFILES).secret_fields
    if action == "set_active_profile":
        key = str(ctx.need("key"))
        if not [p for p in profiles if str(p.get("key")) == key]:
            raise UsageError(f"no VPN client profile with key {key!r} (see action=profiles)")
        plan = ctx.plan("vpn_client", f"make VPN profile {key} the active one", PROFILES)
        plan.secret_fields = secret
        if ctx.is_main:
            plan.critical_reasons.append("changes which VPN every listed device uses; " + FILTER_NOTE)
        others = [p for p in profiles if str(p.get("key")) != key and is_on(p.get("enable"))]
        for p in others:  # switch the others off first so two profiles are never on at once
            plan.add(forms.plan_update(PROFILES, profiles, p.get("key"), {"enable": OFF}, label=f"disable {p.get('key')}"))
        plan.add(forms.plan_update(PROFILES, profiles, key, {"enable": ON}, label=f"enable {key}"))
        return plan
    if action == "add_profile":
        prof = ctx.obj("profile")
        if not prof.get("key"):
            raise UsageError("profile.key (a short unique id) is required")
        plan = ctx.plan("vpn_client", f"add VPN client profile {prof['key']}", PROFILES)
        plan.secret_fields = secret
        if forms.find_rows(profiles, "key", prof["key"]):
            plan.errors.append(f"profile {prof['key']!r} exists; use update_profile")
        else:
            prof.setdefault("enable", OFF)  # adding never changes the active profile
            plan.add(forms.plan_insert(PROFILES, prof, label=str(prof["key"])))
        return plan
    if action in ("update_profile", "remove_profile"):
        key = ctx.need("key")
        plan = ctx.plan("vpn_client", f"{action.split('_')[0]} VPN client profile {key}", PROFILES)
        plan.secret_fields = secret
        if ctx.is_main:
            plan.critical_reasons.append(FILTER_NOTE)
        if action == "update_profile":
            changes = ctx.obj("profile")
            if "enable" in changes:
                raise UsageError("use action=set_active_profile to choose the active profile")
            plan.add(forms.plan_update(PROFILES, profiles, key, changes))
        else:
            target = [p for p in profiles if str(p.get("key")) == str(key)]
            if target and is_on(target[0].get("enable")) and ctx.rows(DEVICES):
                plan.warnings.append(f"this is the ACTIVE profile; {len(ctx.rows(DEVICES))} listed device(s) use it")
            plan.add(forms.plan_remove(PROFILES, profiles, key))
        return plan
    devices = ctx.rows(DEVICES)
    mac = find_mac(ctx.need("mac"))
    if action == "add_device":
        cand = [c for c in ctx.rows(CANDIDATES) if forms.key_equal("mac", c.get("mac"), mac)]
        c0 = cand[0] if cand else {}
        # The UI's insert mapper (Ta): {key, name, mac, client_type, online}
        row = {"key": mac, "name": str(ctx.arg("name") or c0.get("name") or mac), "mac": mac,
               "client_type": str(ctx.arg("client_type") or c0.get("client_type") or "other"),
               "online": 1 if c0.get("online") in (1, "1", True) else 0}
        plan = ctx.plan("vpn_client", f"send {mac} through the active VPN profile", DEVICES)
        if ctx.is_main:
            plan.critical_reasons.append(_device_note(mac))
        if forms.find_rows(devices, "mac", mac):
            plan.errors.append(f"{mac} is already in the VPN device list; use set_device")
        else:
            plan.add(forms.plan_insert(DEVICES, row, label=mac))
        if mac in ctx.own_macs():
            plan.critical_reasons.append("routes THIS machine through the VPN (the server's own traffic changes path)")
        if not cand:
            plan.warnings.append(f"{mac} is not in the router's candidate list (action=candidates); it may refuse it")
        return plan
    if action == "set_device":
        use_vpn = ctx.args.get("use_vpn")
        if use_vpn is None:
            raise UsageError("set_device needs use_vpn=true|false")
        plan = ctx.plan("vpn_client", f"{'route' if use_vpn else 'stop routing'} {mac} through the VPN", DEVICES)
        if ctx.is_main:
            plan.critical_reasons.append(_device_note(mac))
        plan.add(forms.plan_update(DEVICES, devices, mac, {"access": onoff(use_vpn)}))
        return plan
    if action == "remove_device":
        plan = ctx.plan("vpn_client", f"remove {mac} from the VPN device list", DEVICES)
        if ctx.is_main:
            plan.critical_reasons.append(_device_note(mac))
        plan.add(forms.plan_remove(DEVICES, devices, mac))
        return plan
    raise UsageError(f"unknown action {action!r}")
