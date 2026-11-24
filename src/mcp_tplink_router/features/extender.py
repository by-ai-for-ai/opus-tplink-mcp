"""Range extenders (RE series): status, uplink, mesh role, extended networks and system settings.

Forms below were recorded from each family's own web UI (repeater mode) and read live:
X-series (RE2700X / RE1750X / RE1500X, protocol ``extender``) and the hardened generation
(RE3200BE fw 1.5, protocol ``encrypted-v2``).  Which forms a unit has depends on model and mode;
a missing one is reported as unavailable, not as an error.
"""

from __future__ import annotations

from typing import Any

from ..transport import RouterError
from . import Ctx, UsageError

# path -> (read operation, short description, secret fields)
EXTENDER_FORMS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "firmware?form=upgrade": ("read", "model, hardware and firmware version", ()),
    "system?form=sysmode": ("read", "operation mode (repeater / ap / ...)", ()),
    "status?form=rootAP": ("read", "uplink (root AP): SSID, signal, rates per band", ()),
    "status?form=repeater": ("read", "repeater link state per band and wired ports", ()),
    "status?form=repeater_status": ("read", "repeater link state (hardened UI)", ()),
    "status?form=device": ("read", "connected client counters", ()),
    "status?form=guest": ("read", "guest network state", ()),
    "status?form=wifi": ("read", "Wi-Fi state", ()),
    "status?form=ap_status": ("read", "live state of each broadcast band (hardened UI)", ("password", "psk_key", "wpa_key")),
    "status?form=mlo": ("read", "live MLO network state (Wi-Fi 7)", ("password", "psk_key", "wpa_key", "mlo_password")),
    "easy_mesh?form=mesh_info": ("read", "EasyMesh membership and sync state", ()),
    "one_mesh?form=mesh_info": ("read", "OneMesh membership and synced SSIDs", ()),
    "connect?form=settings": ("read", "the network this extender connects to (uplink)", ("password", "psk_key")),
    "extend?form=settings": ("read", "the networks this extender broadcasts", ("password", "psk_key")),
    "extend?form=guest_allow_modify": ("read", "whether the guest network may be changed", ()),
    "high_speed?form=settings": ("read", "high-speed mode (dedicated backhaul band)", ()),
    "quick_setup?form=region": ("read", "region", ()),
    "wireless?form=region": ("read", "Wi-Fi region", ()),
    "wireless?form=wireless_2g": ("read", "2.4 GHz extended network", ("psk_key", "wpa_key", "wep_key")),
    "wireless?form=wireless_5g": ("read", "5 GHz extended network", ("psk_key", "wpa_key", "wep_key")),
    "wireless?form=wps_global": ("read", "WPS", ()),
    "wireless?form=guest": ("read", "guest network", ("psk_key",)),
    "wireless_advanced?form=settings": ("read", "advanced Wi-Fi settings", ()),
    "network?form=lan_ipv4": ("read", "LAN address settings", ()),
    "network?form=status_ipv4": ("read", "current LAN address", ()),
    "dhcps?form=setting": ("read", "DHCP server", ()),
    "dhcps?form=client": ("load", "DHCP clients", ()),
    "dhcps?form=reservation": ("load", "DHCP reservations", ()),
    "access_control?form=enable": ("read", "access control switch", ()),
    "access_control?form=virtualmac_list": ("load", "virtual MAC list", ()),
    "power?form=settings": ("read", "power schedule switch", ()),
    "power?form=power_schedule": ("load", "power schedule entries", ()),
    "time?form=settings": ("read", "time settings", ()),
    "time?form=dst": ("read", "daylight saving time", ()),
    "ledgeneral?form=setting": ("read", "LED switch", ()),
    "ledpm?form=setting": ("read", "LED night mode", ()),
    "eco_mode?form=settings": ("read", "eco mode", ()),
    "firmware?form=auto_upgrade": ("read", "automatic firmware updates", ()),
    "firmware?form=config": ("read", "backup / restore page state", ()),
    "administration?form=account": ("read", "admin account", ("password",)),
    "administration?form=https": ("read", "HTTPS admin page", ()),
    "syslog?form=log": ("load", "system log", ()),
    "syslog?form=types": ("read", "system log types", ()),
}


def is_extender_form(path: str) -> bool:
    return path in EXTENDER_FORMS


def _try(ctx: Ctx, path: str) -> Any:
    op = EXTENDER_FORMS[path][0]
    try:
        return ctx.t.call(path, op)
    except RouterError as exc:
        return {"unavailable": exc.code}


def _strip(d: Any, secrets: tuple[str, ...] = ()) -> Any:
    if not isinstance(d, dict):
        return d
    return {k: ("<secret>" if (k in secrets or any(s in k.lower() for s in ("psk", "password", "pwd", "key")))
                and v else v) for k, v in d.items()}


def extender_status(ctx: Ctx) -> dict[str, Any]:
    fw = _try(ctx, "firmware?form=upgrade")
    mode = _try(ctx, "system?form=sysmode")
    root = _try(ctx, "status?form=rootAP")
    mesh = _try(ctx, "easy_mesh?form=mesh_info")
    one = _try(ctx, "one_mesh?form=mesh_info")
    lan = _try(ctx, "network?form=status_ipv4")
    uplink: dict[str, Any] = {}
    if isinstance(root, dict) and "unavailable" not in root:
        for band, suffix in (("2g", "24g"), ("5g", "5g"), ("6g", "6g")):
            if f"ap_ssid_{suffix}" in root or f"ap_mac_{suffix}" in root or f"ap_rssi_{suffix}" in root:
                uplink[band] = {k: root.get(f"ap_{k}_{suffix}") for k in ("ssid", "mac", "rssi", "signal", "channel")}
        uplink["connected"] = root.get("status") in (1, "1")
    return {
        "router": ctx.router, "kind": "extender", "routers": ctx.routers,
        "model": (fw or {}).get("model"), "firmware": (fw or {}).get("firmware_version"),
        "hardware": (fw or {}).get("hardware_version"), "mode": (mode or {}).get("mode"),
        "uplink": uplink or root,
        "mesh": {"easymesh": (mesh or {}).get("mesh_enable"), "synced": (mesh or {}).get("sync_status") in ("1", 1),
                 "onemesh": (one or {}).get("mesh_enable"), "synced_ssids": [(one or {}).get("ssid_2g"),
                                                                            (one or {}).get("ssid_5g")]},
        "lan": _strip(lan),
        "note": "an EasyMesh/OneMesh agent takes its Wi-Fi settings from the main router; local Wi-Fi changes "
                "may be overwritten by the next mesh sync" if (mesh or {}).get("sync_status") in ("1", 1) else None,
    }


SECTIONS = {
    "status": None,
    "uplink": ["connect?form=settings", "status?form=rootAP", "status?form=repeater", "status?form=repeater_status"],
    "extended": ["extend?form=settings", "wireless?form=wireless_2g", "wireless?form=wireless_5g"],
    "guest": ["wireless?form=guest", "status?form=guest", "extend?form=guest_allow_modify"],
    "mesh": ["easy_mesh?form=mesh_info", "one_mesh?form=mesh_info"],
    "network": ["network?form=lan_ipv4", "network?form=status_ipv4", "dhcps?form=setting"],
    "clients": ["dhcps?form=client", "status?form=device"],
    "wifi_advanced": ["wireless_advanced?form=settings", "high_speed?form=settings", "wireless?form=wps_global"],
    "system": ["system?form=sysmode", "time?form=settings", "time?form=dst", "ledgeneral?form=setting",
               "ledpm?form=setting", "eco_mode?form=settings", "power?form=settings", "firmware?form=auto_upgrade"],
    "logs": ["syslog?form=log"],
}


def extender(ctx: Ctx) -> Any:
    action = ctx.arg("action", "status")
    if action == "status":
        return extender_status(ctx)
    if action not in SECTIONS:
        raise UsageError(f"unknown action {action!r}; one of {list(SECTIONS)}")
    reveal = bool(ctx.arg("reveal"))
    out: dict[str, Any] = {"router": ctx.router, "section": action}
    for path in SECTIONS[action]:
        data = _try(ctx, path)
        if isinstance(data, dict) and data.get("unavailable"):
            continue
        out[path] = data if reveal else _strip(data, EXTENDER_FORMS[path][2])
    return out


# ------------------------------------------------------------------------------------------- writes
from .. import forms  # noqa: E402
from ..safety import SETTLE_PROBES, Plan  # noqa: E402
from . import settings_change  # noqa: E402

_SIMPLE = {
    # action: (path, what, critical reason or None)
    "led": ("ledgeneral?form=setting", "LEDs", None),
    "led_night": ("ledpm?form=setting", "LED night mode", None),
    "power_schedule": ("power?form=settings", "power schedule", None),
    # high_speed / extended writes are deliberately absent: neither was captured from the web UI nor run live
    # (high-speed mode is also ignored by the firmware while the extender is in an EasyMesh network).
}


MLO_PATH = "extend?form=settings"
MLO_BANDS = {"2g": "band2", "5g": "band5", "6g": "band6"}


REPEATER_STATUS = "status?form=repeater_status"


def mlo_settle_probe(fields: dict[str, Any]) -> Any:
    """After a write that touches the MLO network the extender restarts its Wi-Fi: what to check once it is back."""
    if not any(k.startswith("mlo_") for k in fields):
        return None
    want = fields.get("mlo_enable")

    def probe(t2: Any) -> dict[str, Any]:
        st = t2.call(REPEATER_STATUS, "read")
        st = st if isinstance(st, dict) else {}
        links = {name: st.get(f"repeater_conn_{k}") for name, k in (("2.4 GHz", "24g"), ("5 GHz", "5g"))
                 if st.get(f"repeater_enable_{k}") == "enable"}
        out: dict[str, Any] = {"mlo": st.get("mlo_enable"), "links_to_router": links}
        if want and st.get("mlo_enable") and st.get("mlo_enable") != want:
            out["mismatch"] = f"the MLO network is {st.get('mlo_enable')}, not {want}"
        down = [n for n, v in links.items() if v != "connected"]
        if down:
            out["waiting"] = f"its {' and '.join(down)} link to your router is still reconnecting"
        return out

    return probe


SETTLE_PROBES[MLO_PATH] = mlo_settle_probe  # undo / raw writes of this form wait for the restart too


def _extender_mlo(ctx: Ctx) -> Any:
    """MLO network on an extender that has one (e.g. RE3200BE): on/off and which bands it joins."""
    cur = ctx.read(MLO_PATH)
    support = cur.get("mlo_band_support")
    if not support:
        raise UsageError("this extender has no MLO network (only Wi-Fi 7 models such as the RE3200BE have one)")
    support = [support] if isinstance(support, str) else list(support)
    enable = ctx.arg("enable")
    bands = ctx.arg("bands")
    settings = ctx.args.get("settings") if isinstance(ctx.args.get("settings"), dict) else {}
    # Bench (Nemotron 4B): put enable inside settings, as the LED actions allow, and got a read
    if enable is None and "enable" in settings:
        enable = settings["enable"]
    if bands is None and "bands" in settings:
        bands = settings["bands"]
    if enable is None and bands is None:
        on = cur.get("mlo_enable") == "on"
        return {"current": {"enable": cur.get("mlo_enable"), "ssid": cur.get("mlo_ssid"),
                            "bands": [b for b, k in MLO_BANDS.items() if cur.get(f"mlo_{k}") == "on"],
                            "supported_bands": [b for b, k in MLO_BANDS.items() if k in support]},
                # Bench (Gemma E4B): asked to turn MLO off, it kept calling action=mlo without enable - a read
                "note": f"This only READ the MLO network (it is {'on' if on else 'off'}). To turn it "
                        f"{'off' if on else 'on'}, call extender_set with action=mlo and enable={'false' if on else 'true'}."}
    changes: dict[str, Any] = {}
    if enable is not None:
        changes["mlo_enable"] = "on" if (enable is True or str(enable).lower() in ("on", "true", "1")) else "off"
    if bands is not None:
        bands = [bands] if isinstance(bands, str) else list(bands)
        bad = [b for b in bands if b not in MLO_BANDS or MLO_BANDS[b] not in support]
        if bad:
            raise UsageError(f"unsupported MLO band(s) {bad}; this extender supports "
                             f"{[b for b, k in MLO_BANDS.items() if k in support]}")
        if len(bands) < 2:
            raise UsageError("an MLO network needs at least two bands, e.g. bands=[\"2g\", \"5g\"]")
        for b, k in MLO_BANDS.items():
            if k in support:
                changes[f"mlo_{k}"] = "on" if b in bands else "off"
    plan = ctx.plan("extender_set", "change the extender's MLO network", MLO_PATH)
    plan.add(forms.plan_write(MLO_PATH, cur, changes, label="MLO network"))
    plan.critical_reasons.append("Wi-Fi 7 devices on the MLO network reconnect; a mesh agent may get these values "
                                 "overwritten by the next mesh sync")
    plan.warnings.append("this restarts the extender's Wi-Fi: ALL its networks and its link to your router drop "
                         "briefly (seen: under a minute), the 5 GHz link to the router can take a few minutes to "
                         "return, and without a reserved address the extender may come back at a new IP address. "
                         "The tool waits for it and reports what came back.")
    plan.settle_probe = mlo_settle_probe(changes)
    if not plan.steps:
        return {"status": "no_change", "tell_user": "NOTHING WAS CHANGED: the MLO network already has these values.",
                "current": {k: cur.get(k) for k in ("mlo_enable", "mlo_band2", "mlo_band5", "mlo_band6")}}
    return plan


def extender_set(ctx: Ctx) -> Any:
    action = ctx.need("action")
    if action == "mlo":
        return _extender_mlo(ctx)
    if action == "reboot":
        plan = Plan(tool="extender_set", summary=f"reboot extender {ctx.router} (about 1-2 minutes offline)")
        plan.add(forms.plan_custom("system?form=reboot", "reboot"))
        plan.critical_reasons.append("the extender and its clients go offline for a minute or two; not undoable")
        return plan
    if action not in _SIMPLE:
        raise UsageError(f"unknown action {action!r}; one of {['reboot', *_SIMPLE]}")
    path, what, critical = _SIMPLE[action]
    settings = ctx.obj("settings")
    if "enable" in ctx.args and ctx.args["enable"] is not None:
        settings.setdefault("enable", "on" if ctx.args["enable"] else "off")
    allowed = forms.endpoint(path).write_fields or ()
    bad = [k for k in settings if allowed and k not in allowed]
    if bad:
        raise UsageError(f"{action} accepts {list(allowed)}; got {bad}")
    out = settings_change(ctx, "extender_set", path, settings, what, critical=critical)
    if action == "led_night" and isinstance(out, dict) and "current" in out and not settings:
        # Bench: asked to "turn on night mode", models stopped to ask the user for times.  The extender keeps
        # its times; say so with the exact call.
        cur = out["current"]
        times = " - ".join(str(cur.get(k)) for k in ("time_start", "time_end") if cur.get(k))
        out["note"] = (f"To turn night mode on or off, enable alone is enough: the saved times{' (' + times + ')' if times else ''} "
                       "are used. Only pass time_start/time_end if the user asked for different times.")
    return out
