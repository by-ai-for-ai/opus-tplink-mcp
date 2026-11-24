"""Wi-Fi bands, guest network, smart connect and the Wi-Fi schedule.

Main bands follow the UI: read with ``read_spf`` on ``wireless?form=wireless_<band>`` and
write with ``write_spf`` to the multi-form URL using ``wireless_<band>_<field>`` keys.  The
machine running this server is wired, so Wi-Fi changes cannot cut it off - but they do
disconnect every wireless client.
"""

from __future__ import annotations

from typing import Any

from .. import catalog, forms
from ..safety import Plan
from . import OFF, ON, Ctx, UsageError, is_on, onoff

FRIENDLY = {"password": "psk_key", "name": "ssid"}
BOOLISH = {"enable", "hidden", "mu_mimo", "psc", "disabled_all", "redirect"}


def _band_path(band: str) -> str:
    if band in catalog.WIFI_BANDS:
        return f"wireless?form=wireless_{band}"
    raise UsageError(f"band must be one of {list(catalog.WIFI_BANDS)}, guest or guest_access")


def _normalise(settings: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in settings.items():
        k = FRIENDLY.get(k, k)
        out[k] = onoff(v) if k in BOOLISH else (v if isinstance(v, str) else str(v))
    return out


def wifi_set(ctx: Ctx) -> Plan | dict[str, Any]:
    action = ctx.arg("action", "get")
    band = str(ctx.arg("band", "")) or None
    if action == "get":
        if band in (None, "all"):
            from .core import wifi_view

            return wifi_view(ctx)
        if band == "guest":
            return {"guest": ctx.read(catalog.GUEST_PATH), "access": ctx.read("wireless?form=guest")}
        if band == "guest_access":
            return {"access": ctx.read("wireless?form=guest")}
        return {band: ctx.read(_band_path(band))}
    if action == "smart_connect":
        path = "wireless?form=smart_connect"
        plan = ctx.plan("wifi_set", "change smart connect (one SSID across bands)", path)
        plan.add(forms.plan_write(path, ctx.read(path), {"smart_enable": onoff(ctx.need("enable"))}))
        plan.warnings.append("wireless clients reconnect when smart connect changes")
        return plan
    if action != "set":
        raise UsageError(f"unknown action {action!r}")
    if not band:
        raise UsageError("band is required")
    settings = _normalise(ctx.obj("settings"))
    if ctx.args.get("enable") is not None and band not in ("guest_access",):
        # enable at the top level of action=set means the band on/off (a small model sent exactly this, got
        # "settings required" with an ssid/password example, and filled in ssid/password "dummy").
        settings.setdefault("enable", onoff(ctx.args["enable"]))
    if any("led" in str(k).lower() for k in settings):
        raise UsageError("LEDs are not a Wi-Fi setting: use the tool system action=led (enable=true/false)")
    if not settings:
        raise UsageError("say what to change: enable=false (or settings={\"enable\": \"off\"}) turns the band off; "
                         "settings={\"ssid\": ...} or {\"password\": ...} change ONLY when the user asked for that - "
                         "never fill in a name or password yourself")
    if band == "guest_access":
        path = "wireless?form=guest"
        plan = ctx.plan("wifi_set", "change guest network access/isolation", path)
        plan.add(forms.plan_write(path, ctx.read(path), settings))
        return plan
    if band == "guest":
        sub = str(ctx.arg("guest_band", "all"))
        bands = catalog.GUEST_BANDS if sub == "all" else (sub,)
        if any(b not in catalog.GUEST_BANDS for b in bands):
            raise UsageError(f"guest_band must be one of {list(catalog.GUEST_BANDS)} or all")
        cur = ctx.read(catalog.GUEST_PATH)
        unknown = [k for k in settings if k not in catalog.GUEST_FIELDS
                   and not any(f"guest_{b}_{k}" in cur for b in bands)]
        if unknown:  # never drop a setting silently: the model then reports a change that never happened
            raise UsageError(f"guest Wi-Fi has no setting(s) {unknown}; valid: {sorted(catalog.GUEST_FIELDS)}"
                             + _elsewhere(unknown))
        changes = {f"guest_{b}_{k}": v for b in bands for k, v in settings.items()
                   if f"guest_{b}_{k}" in cur or k in catalog.GUEST_FIELDS}
        plan = ctx.plan("wifi_set", f"change guest Wi-Fi ({sub})", catalog.GUEST_PATH)
        plan.secret_fields = forms.endpoint(catalog.GUEST_PATH).secret_fields
        _check_psk(plan, settings)
        plan.add(forms.plan_write(catalog.GUEST_PATH, cur, changes, label="guest Wi-Fi"))
        return plan
    path = _band_path(band)
    cur = ctx.read(path)
    if "enable" in settings:
        settings["disabled_all"] = OFF if settings["enable"] == ON else ON  # the UI keeps these paired
    smart = is_on(ctx.read("wireless?form=smart_connect").get("smart_enable"))
    plan = ctx.plan("wifi_set", f"change {band} Wi-Fi", path)
    plan.secret_fields = forms.endpoint(path).secret_fields
    _check_psk(plan, settings)
    if settings.get("enable") == OFF and is_on(cur.get("enable")):
        plan.critical_reasons.append(f"turns the {band} radio OFF: every device on it disconnects")
    if {"ssid", "psk_key", "encryption"} & set(settings):
        plan.warnings.append("every device on this band must reconnect (new name/password/security)")
    if smart and band != "2g":
        plan.warnings.append("smart connect is ON: the router may apply 2.4 GHz settings to all bands")
    plan.add(forms.plan_write(path, cur, settings, label=f"{band} Wi-Fi"))
    return plan


def _elsewhere(keys: list[str]) -> str:
    from .hints import guess_tool

    tool = next((guess_tool(k) for k in keys if guess_tool(k) and not guess_tool(k).startswith("wifi_set")), None)
    return f". For that, use the tool: {tool}" if tool else ""


def _check_psk(plan: Plan, settings: dict[str, Any]) -> None:
    psk = settings.get("psk_key")
    if psk is not None and not 8 <= len(str(psk)) <= 63:
        plan.errors.append("Wi-Fi password must be 8-63 characters")


# --------------------------------------------------------------------------- schedule
SCHED = "wireless_schedule_v2?form=settings"
DAYS = ("sun", "mon", "tue", "wed", "thu", "fri", "sat")


def _schedule_row(r: dict[str, Any], base: dict[str, Any] | None = None) -> dict[str, Any]:
    row = dict(base or {"key": "", "enable": True, "repeat_days": ",".join(DAYS), "time_start": "23:00",
                        "time_end": "07:00", "band_list": ",".join(catalog.WIFI_BANDS), "next_time": "off"})
    if "days" in r:
        days = r["days"] if isinstance(r["days"], list) else str(r["days"]).split(",")
        days = [d.strip().lower()[:3] for d in days if d.strip()]
        bad = [d for d in days if d not in DAYS]
        if bad or not days:
            raise UsageError(f"days must be from {DAYS}")
        row["repeat_days"] = ",".join(d for d in DAYS if d in days)
    for src, dst in (("start", "time_start"), ("end", "time_end")):
        if src in r:
            v = str(r[src])
            hh, _, mm = v.partition(":")
            if not (hh.isdigit() and mm.isdigit() and int(hh) < 24 and int(mm) < 60):
                raise UsageError(f"{src} must be HH:MM (24h)")
            row[dst] = f"{int(hh):02d}:{int(mm):02d}"
    if "bands" in r:
        bands = r["bands"] if isinstance(r["bands"], list) else str(r["bands"]).split(",")
        if any(b not in catalog.WIFI_BANDS for b in bands):
            raise UsageError(f"bands must be from {catalog.WIFI_BANDS}")
        row["band_list"] = ",".join(bands)
    if "enable" in r:
        row["enable"] = bool(r["enable"])
    return row


def wifi_schedule(ctx: Ctx) -> Plan | dict[str, Any]:
    action = ctx.arg("action", "get")
    st = ctx.read(SCHED)
    if action == "get":
        return {"enabled": st.get("enable"), "max_rules": st.get("max_rules"), "rules": ctx.rows(SCHED),
                "meaning": "each rule is a period when Wi-Fi is OFF (time_start -> time_end on repeat_days)"}
    if action in ("enable", "disable"):
        plan = ctx.plan("wifi_schedule", f"{action} the Wi-Fi off-schedule", SCHED)
        plan.add(forms.plan_write(SCHED, st, {"enable": action == "enable"}))
        return plan
    rows = ctx.rows(SCHED)
    if action == "add":
        row = _schedule_row(ctx.obj("rule"))
        plan = ctx.plan("wifi_schedule", f"Wi-Fi off {row['time_start']}-{row['time_end']} on {row['repeat_days']}", SCHED)
        if st.get("max_rules") and len(rows) >= int(st["max_rules"]):
            plan.errors.append(f"the router allows at most {st['max_rules']} schedule rules")
        else:
            plan.add(forms.plan_insert(SCHED, row))
        return plan
    key = ctx.need("key")
    if action == "update":
        hits = [r for r in rows if str(r.get("key")) == str(key)]
        if not hits:
            raise UsageError(f"no schedule rule with key {key!r}")
        new = _schedule_row(ctx.obj("rule"), base=hits[0])
        plan = ctx.plan("wifi_schedule", f"update schedule rule {key}", SCHED)
        plan.add(forms.plan_update(SCHED, rows, key, {k: v for k, v in new.items() if k != "key"}))
        return plan
    if action == "remove":
        plan = ctx.plan("wifi_schedule", f"remove schedule rule {key}", SCHED)
        plan.add(forms.plan_remove(SCHED, rows, key))
        return plan
    raise UsageError(f"unknown action {action!r}")
