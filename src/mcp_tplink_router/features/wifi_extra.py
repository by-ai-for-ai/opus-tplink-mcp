"""Wi-Fi extras: WPS (push button / PIN pairing), Wi-Fi 7 MLO network, OFDMA / MU-MIMO, TWT,
fast-roaming SSID, advanced radio settings, guest bandwidth / time limits, AFC (6 GHz)."""

from __future__ import annotations

from typing import Any

from .. import forms
from . import Ctx, UsageError, safe_read, settings_change

GROUPS: dict[str, tuple[str, str, str | None]] = {
    "wps_settings": ("wireless?form=syspara_wps", "WPS", None),
    "mlo": ("wireless?form=mlo_host", "MLO (Wi-Fi 7 multi-link) network",
            None),
    "ofdma": ("wireless?form=ofdma", "OFDMA", None),
    "ofdma_mimo": ("wireless?form=ofdma_mimo", "OFDMA + MU-MIMO", None),
    "twt": ("wireless?form=twt", "Target Wake Time", None),
    "fast_roaming": ("ffs?form=config", "fast-roaming SSID", None),
    "advanced": ("wireless?form=wireless_addition_setting", "advanced radio settings", None),
    "guest_bandwidth": ("wireless?form=guestnetwork_bandwidth_ctrl", "guest bandwidth limit", None),
    "guest_time": ("wireless?form=guestnetwork_effectivetime_ctrl", "guest network time limit", None),
    "afc": ("afc?form=settings", "AFC (standard-power 6 GHz)", None),
}
OFDMA_MIMO = ("all", "ofdma_only", "disabled")
ENABLE_KEY = {"wps_settings": "wps", "mlo": "enable", "ofdma": "enable", "twt": "enable", "fast_roaming": "enable",
              "afc": "enable"}
WPS = "wireless?form=wps_connect"


def wps_poll(mode: str, wait: int) -> dict[str, Any]:
    """Poll spec for a WPS session: option=pbc / option=pin report ok (connecting) | success | failed |
    error | overlap | timeout | na."""
    if not 10 <= wait <= 300:
        raise UsageError("wait must be 10-300 seconds")
    return {"op": "", "fields": {"option": mode}, "key": "wps_status", "while": ["ok"], "success": ["success"],
            "every": 3, "max": wait}


def wifi_extra(ctx: Ctx) -> Any:
    action = ctx.arg("action", "status")
    if action == "status":
        out = {name: safe_read(ctx, path) for name, (path, _, _) in GROUPS.items()}
        out["wps_label_state"] = safe_read(ctx, "wireless?form=wps_pin")
        out["wps_session"] = safe_read(ctx, WPS)
        return out
    if action in GROUPS:
        path, what, crit = GROUPS[action]
        settings = ctx.obj("settings")
        if action == "ofdma_mimo" and settings.get("setting") not in (None, *OFDMA_MIMO):
            raise UsageError(f"ofdma_mimo setting must be one of {list(OFDMA_MIMO)}")
        if action == "ofdma" and (settings or ctx.args.get("enable") is not None):
            mimo = safe_read(ctx, "wireless?form=ofdma_mimo")
            if isinstance(mimo, dict) and "setting" in mimo:
                raise UsageError("this router controls OFDMA through ofdma_mimo (all | ofdma_only | disabled)")
        if ctx.args.get("enable") is not None:
            if action not in ENABLE_KEY:
                raise UsageError(f"{action} has no single on/off; pass settings")
            settings.setdefault(ENABLE_KEY[action], ctx.args["enable"])
        if action == "mlo" and settings:
            return _mlo(ctx, settings)
        return settings_change(ctx, "wifi_extra", path, settings, what, critical=crit)
    # ------------------------------------------------------------------ WPS pairing
    if action in ("wps_push", "wps_client_pin", "wps_cancel"):
        # The web UI: option=connect starts push-button pairing; connect + wps_pin pairs a device by ITS
        # PIN; cancel stops.  (option=pbc / option=pin only POLL the status: see wps_status.)
        fields: dict[str, Any] = {"option": "cancel" if action == "wps_cancel" else "connect"}
        if action == "wps_client_pin":
            pin = str(ctx.need("pin")).replace("-", "").replace(" ", "")
            if not (pin.isdigit() and len(pin) in (4, 8)):
                raise UsageError("the device's WPS PIN is 4 or 8 digits")
            fields["wps_pin"] = pin
        if action != "wps_cancel":
            st = safe_read(ctx, "wireless?form=syspara_wps")
            if isinstance(st, dict) and str(st.get("wps", "on")).lower() == "off":
                raise UsageError("WPS is off: wifi_extra action=wps_settings enable=true first")
        what = {"wps_push": "start WPS push-button pairing (like pressing the WPS button; LEDs blink)",
                "wps_client_pin": "pair the device whose WPS PIN was given",
                "wps_cancel": "stop WPS pairing"}[action]
        plan = ctx.plan("wifi_extra", what)
        step = forms.plan_custom(WPS, "", fields, label="wps")
        if action != "wps_cancel":
            # The router ends WPS when the admin session logs out, so this call STAYS logged in and
            # polls (like the web page) until a device pairs, it fails, or the window closes.
            step.poll = wps_poll("pin" if action == "wps_client_pin" else "pbc", int(ctx.arg("wait", 125)))
            plan.warnings.append(f"this call stays connected for up to {int(ctx.arg('wait', 125))} s while "
                                 "WPS is open; ANY device that starts WPS meanwhile can join the main Wi-Fi")
        else:
            plan.warnings.append("a WPS session started by this server already ends when its call returns")
        plan.add(step)
        return plan
    if action == "wps_status":
        # Poll like the UI: option=pbc (push-button session) or option=pin (PIN session).
        # Only meaningful for a session another login (the web page / the WPS button) started.
        mode = "pin" if ctx.arg("pin_mode") else "pbc"
        res = ctx.t.call(WPS, "", {"option": mode}, timeout=60.0)
        return {"status": (res or {}).get("wps_status"), "mac": (res or {}).get("mac"),
                "session": safe_read(ctx, WPS), "settings": safe_read(ctx, "wireless?form=syspara_wps")}
    if action in ("wps_pin_generate", "wps_pin_default", "wps_pin_enable", "wps_pin_disable"):
        path = "wireless?form=wps_pin"
        if action in ("wps_pin_enable", "wps_pin_disable"):
            return settings_change(ctx, "wifi_extra", path, {"wps_label": action == "wps_pin_enable"},
                                   "router WPS PIN")
        plan = ctx.plan("wifi_extra", "new random router WPS PIN" if action == "wps_pin_generate"
                        else "restore the factory router WPS PIN")
        plan.add(forms.plan_custom(path, "write", {"option": "generate" if action == "wps_pin_generate"
                                                   else "default"}, label="wps pin"))
        return plan
    if action == "afc_refresh":
        plan = ctx.plan("wifi_extra", "refresh the AFC (6 GHz standard power) grant")
        plan.add(forms.plan_custom("afc?form=settings", "refresh", label="afc"))
        return plan
    raise UsageError(f"unknown action {action!r}")



MLO_FIELDS = ("enable", "ssid", "hidden", "encryption", "psk_key", "psk_version", "selected_bands")


def _mlo(ctx: Ctx, settings: dict[str, Any]) -> Any:
    """MLO writes exactly like the web UI: off = {enable: off}; on/changes = the 7 UI fields.

    A malformed MLO write once made the firmware drop an internal per-band field (WPS then failed until
    a config restore), so this never sends anything the UI doesn't.
    """
    path = "wireless?form=mlo_host"
    cur = ctx.read(path)
    bad = [k for k in settings if k not in MLO_FIELDS]
    if bad:
        raise UsageError(f"MLO accepts only {list(MLO_FIELDS)}; got {bad}")
    full = {k: cur.get(k) for k in MLO_FIELDS if cur.get(k) is not None}
    want = {**full, **{k: (("on" if v else "off") if isinstance(v, bool) else v) for k, v in settings.items()}}
    if want.get("enable") == "on":
        if not want.get("selected_bands"):
            raise UsageError("MLO needs selected_bands (e.g. ['5g', '6g'])")
        if len(want["selected_bands"]) < 2:
            raise UsageError("MLO needs at least two selected_bands")
    if all(forms.cmp_value(want.get(k)) == forms.cmp_value(full.get(k)) for k in want):
        return {"status": "no_change", "current": cur}
    restore = full if full.get("enable") == "on" else {"enable": "off"}
    send = {"enable": "off"} if want.get("enable") == "off" else want
    plan = ctx.plan("wifi_extra", "MLO network: " + ", ".join(f"{k}={'<secret>' if k == 'psk_key' else v}"
                                                             for k, v in settings.items()), path)
    plan.secret_fields = ("psk_key",)
    plan.add(forms.plan_custom(path, "write", send, label="MLO", inverse={"op": "write", "fields": restore}))
    if (ctx.device_config().get("mloNetwork") or {}).get("reboot"):
        # the web UI: "The router will reboot after saving your new MLO settings" (live: Archer BE3600)
        plan.reboots = "the router reboots after an MLO change: about 2-3 minutes without network"
        plan.critical_reasons.append(plan.reboots)
    else:
        plan.critical_reasons.append("MLO changes rebuild the Wi-Fi interfaces; MLO clients drop for ~30 s")
    return plan
