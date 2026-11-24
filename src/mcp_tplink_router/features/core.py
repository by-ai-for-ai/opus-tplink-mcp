"""Read-only overview tools, raw access, logs, journal and undo."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from .. import catalog, forms
from ..catalog import is_read_op
from ..netcalc import is_locally_administered, normalize_mac
from ..safety import Plan, plan_undo, redact
from ..transport import RouterError
from . import Ctx, UsageError, is_on
from .hints import dedicated_tool, guess_tool, use_instead

# ------------------------------------------------------------------------------ status
_STATUS_KEYS = (
    "wan_ipv4_ipaddr", "wan_ipv4_gateway", "wan_ipv4_conntype", "wan_ipv4_uptime", "wan_ipv4_pridns",
    "wan_ipv4_snddns", "wan_ipv6_enable", "wan_ipv6_ip6addr", "lan_ipv4_ipaddr", "lan_ipv4_netmask",
    "lan_ipv4_dhcp_enable", "lan_macaddr", "cpu_usage", "mem_usage",
)


def _try(fn: Any, *a: Any) -> Any:
    try:
        return fn(*a)
    except RouterError as exc:
        return {"error": exc.code}


def router_status(ctx: Ctx) -> dict[str, Any]:
    if ctx.arg("capabilities"):
        from ..capabilities import summary

        return summary(ctx.router, ctx.host)
    if ctx.kind == "extender":
        from .extender import extender_status

        return extender_status(ctx)
    try:
        st = ctx.read("status?form=all")
    except RouterError as exc:
        st = {"status_all": f"unavailable on this firmware ({exc.code})"}
    out: dict[str, Any] = {"router": ctx.router, "routers": ctx.routers}
    out.update({k: st.get(k) for k in _STATUS_KEYS if k in st})
    wifi = {}
    for b in catalog.WIFI_BANDS:
        if f"wireless_{b}_enable" in st:
            wifi[b] = {"enabled": is_on(st.get(f"wireless_{b}_enable")), "ssid": st.get(f"wireless_{b}_ssid"),
                       "channel": st.get(f"wireless_{b}_current_channel") or st.get(f"wireless_{b}_channel")}
    out["wifi"] = wifi
    if "guest_access" in st:
        out["guest_wifi_access"] = st.get("guest_access")
    clients = ctx.clients()
    if "status_all" in st:
        out["note"] = st["status_all"]
    out["clients"] = {"total": len(clients), "wired": sum(c["connection"] == "wired" for c in clients),
                      "wireless": sum(c["connection"] != "wired" for c in clients)}
    out["internet"] = _try(ctx.read, "status?form=internet")
    from ..safety import model_tier

    out["model_tier"] = model_tier()
    keys = ("model", "firmware_version", "hardware_version")
    fw = _try(ctx.read, "firmware?form=upgrade")
    if "error" not in fw and not any(fw.get(k) for k in keys):
        fw = _try(ctx.read, "firmware?form=upgrade")  # the router sometimes answers empty while busy: ask once more
    if "error" in fw:
        out["firmware"] = {"unavailable": f"could not read the firmware details ({fw['error']}); ask again"}
    elif not any(fw.get(k) for k in keys):
        # Never pass on nulls as if they were the answer (a model reported "firmware: not specified").
        out["firmware"] = {"unavailable": "the router returned no firmware details this time; ask again"}
    else:
        out["firmware"] = {k: fw.get(k) for k in keys}
    out["mode"] = _try(ctx.read, "system?form=sysmode").get("mode")
    out["vpn_client_enabled"] = _try(ctx.read, "vpn?form=enable").get("enable")
    return out


# --------------------------------------------------------------------------- clients
def clients_view(ctx: Ctx) -> dict[str, Any]:
    """Connected clients merged with DHCP leases and reservations."""
    leases = {}
    for x in ctx.rows("dhcps?form=client"):
        try:
            leases[normalize_mac(x.get("macaddr", ""))] = x
        except ValueError:
            pass
    resv = {}
    for r in ctx.rows("dhcps?form=reservation"):
        try:
            resv[normalize_mac(r.get("mac", ""))] = r
        except ValueError:
            pass
    own = ctx.own_macs()
    seen: dict[str, dict[str, Any]] = {}
    for c in ctx.clients():
        seen[c["mac"]] = {**c, "online": True}
    for mac, x in leases.items():
        seen.setdefault(mac, {"mac": mac, "ip": x.get("ipaddr"), "name": x.get("name"), "online": False})
    out = []
    def _ip_key(kv: tuple[str, dict[str, Any]]) -> tuple[int, ...]:
        parts = str(kv[1].get("ip") or "").split(".")
        return tuple(int(p) for p in parts if p.isdigit()) or (0,)

    for mac, c in sorted(seen.items(), key=_ip_key):
        lease, r = leases.get(mac), resv.get(mac)
        entry = dict(c)
        entry["lease"] = {"ip": lease.get("ipaddr"), "remaining": lease.get("leasetime")} if lease else None
        entry["reservation"] = {"ip": r.get("ip"), "comment": r.get("comment"), "enabled": is_on(r.get("enable"))} if r else None
        entry["random_mac"] = is_locally_administered(mac)
        if mac in own:
            entry["this_machine"] = True
        out.append(entry)
    return {"count": len(out), "clients": out}


def wifi_view(ctx: Ctx) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for b in catalog.WIFI_BANDS:
        out[b] = _try(ctx.read, f"wireless?form=wireless_{b}")
    out["guest"] = _try(ctx.read, catalog.GUEST_PATH)
    out["guest_access"] = _try(ctx.read, "wireless?form=guest")
    out["smart_connect"] = _try(ctx.read, "wireless?form=smart_connect")
    return out


SYNTHETIC = {"clients": clients_view, "wifi": wifi_view}


def router_get(ctx: Ctx) -> dict[str, Any]:
    section = ctx.arg("section")
    if not section:
        return {"sections": sorted([*catalog.SECTIONS, *SYNTHETIC]),
                "hint": "pass section=<name>, or any form path from router_catalog (e.g. 'iptv?form=setting')"}
    if section in SYNTHETIC:
        data = SYNTHETIC[section](ctx)
        return {"section": section, "data": data}
    path = catalog.SECTIONS.get(section, section)
    ep = catalog.get(path)
    if ep is None:
        raise UsageError(f"unknown section {section!r}; call router_get without arguments for the list")
    if not ep.read_op:
        raise UsageError(f"{path} is not readable with a plain read ({ep.note}); try router_raw_read")
    data = forms.read_state(ctx.t, path)
    return {"section": section, "path": path, "data": redact(data, bool(ctx.arg("reveal")), ep.secret_fields)}


def router_catalog(ctx: Ctx) -> dict[str, Any]:
    path = ctx.arg("path")
    if path:
        return catalog.describe(path)
    flt = str(ctx.arg("filter", "")).lower()
    rows = []
    for p in catalog.all_paths():
        d = catalog.describe(p)
        if flt and flt not in p.lower() and flt not in str(d.get("section") or "").lower():
            continue
        ops = d.get("ops") or {}
        row = {"path": p, "section": d.get("section"),
               "ops": {op: f"{v['risk']}/{v['verified']}" for op, v in ops.items()}}  # type: ignore[union-attr]
        tool = dedicated_tool(p, ctx.kind)
        if tool:
            row["use_tool"] = tool
        rows.append(row)
    return {"router": ctx.router, "routers": ctx.routers, "count": len(rows),
            "risk_profile": "main" if ctx.is_main else "secondary (VPN-client protection rules off; access-control "
            "mode/enable and parental internet pause are critical)", "legend": "op: risk/verified (live = tested on this router, ui = from the web UI's JS)",
            "forms": rows}


def _fields_arg(ctx: Ctx) -> dict[str, str]:
    raw = ctx.obj("fields")
    out = {}
    for k, v in raw.items():
        if isinstance(v, (dict, list)):
            out[k] = forms.jdump(v)
        else:
            out[k] = forms.to_field(v)
    return out


def router_raw_read(ctx: Ctx) -> dict[str, Any]:
    path = str(ctx.need("path")).lstrip("/").removeprefix("admin/")
    op = str(ctx.arg("operation", "read"))
    if ctx.kind == "extender":
        from .extender import EXTENDER_FORMS

        if path not in EXTENDER_FORMS:
            raise UsageError(f"{path!r} is not a catalogued extender form; known: {sorted(EXTENDER_FORMS)}")
        if op != EXTENDER_FORMS[path][0]:
            raise UsageError(f"{path} is read with operation={EXTENDER_FORMS[path][0]!r}")
        data = ctx.t.call(path, op, _fields_arg(ctx))
        return {"path": path, "operation": op,
                "data": redact(data, bool(ctx.arg("reveal")), EXTENDER_FORMS[path][2])}
    for single in catalog.split_forms(path):
        if catalog.get(single) is None:
            guess = guess_tool(single)
            raise UsageError(f"{single!r} is not a form the router UI uses"
                             + (f"; for this, use the tool: {guess}" if guess else " (see router_catalog)"))
    if catalog.is_forbidden_path(path):
        raise UsageError(f"{path} is in the forbidden tier (debug/cloud/firmware-upload/quick-setup); not readable here")
    if not is_read_op(op) or catalog.risk_of(path, op) != catalog.READ:
        raise UsageError(f"operation {op!r} on {path} is not read-only; use router_raw_write")
    data = ctx.t.call(path, op, _fields_arg(ctx))
    ep = catalog.get(path)
    return {"path": path, "operation": op, **use_instead(path, ctx.kind),
            "data": redact(data, bool(ctx.arg("reveal")), ep.secret_fields if ep else ())}


# ---------------------------------------------------------------------------------- logs
_LEVELS = ["EMERG", "ALERT", "CRIT", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"]
_LEVEL_ALIASES = {"ERR": "ERROR", "WARN": "WARNING", "CRITICAL": "CRIT", "EMERGENCY": "EMERG"}
_TIME_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                 "%b %d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d")


def _parse_time(s: Any) -> datetime | None:
    s = str(s or "").strip()
    for fmt in _TIME_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def _level_rank(level: Any) -> int | None:
    lv = str(level or "").upper()
    lv = _LEVEL_ALIASES.get(lv, lv)
    return _LEVELS.index(lv) if lv in _LEVELS else None


def router_logs(ctx: Ctx) -> dict[str, Any]:
    # NOTE: the web UI writes syslog?form=filter before loading; we never write - load all, filter here.
    rows = forms.load_table(ctx.t, "syslog?form=log")
    level = ctx.arg("level")
    typ = ctx.arg("type")
    contains = str(ctx.arg("contains", "")).lower()
    since = _parse_time(ctx.arg("since")) if ctx.arg("since") else None
    if ctx.arg("since") and since is None:
        raise UsageError("since must look like '2026-11-17 08:00:00'")
    limit = max(1, min(int(ctx.arg("limit", 100)), 2000))
    want_rank = _level_rank(level) if level else None
    out = []
    for r in rows:
        if level:
            rank = _level_rank(r.get("level"))
            if want_rank is not None and rank is not None:
                if rank > want_rank:
                    continue
            elif str(r.get("level", "")).lower() != str(level).lower():
                continue
        if typ and str(r.get("type", "")).lower() != str(typ).lower():
            continue
        if contains and contains not in str(r.get("content", "")).lower():
            continue
        if since:
            ts = _parse_time(r.get("time"))
            if ts is not None and ts < since:
                continue
        out.append(r)
    stamped = [(_parse_time(r.get("time")), i, r) for i, r in enumerate(out)]
    if stamped and all(s[0] for s in stamped):
        stamped.sort(key=lambda s: (s[0], -s[1]), reverse=True)
        out = [s[2] for s in stamped]
    types = sorted({str(r.get("type")) for r in rows if r.get("type")})
    levels = sorted({str(r.get("level")) for r in rows if r.get("level")})
    return {"total": len(rows), "matched": len(out), "returned": min(len(out), limit),
            "order": "newest first" if stamped and all(s[0] for s in stamped) else "router order",
            "available_types": types, "available_levels": levels,
            "level_filter": "at least this severe" if want_rank is not None else "exact", "logs": out[:limit]}


# ------------------------------------------------------------------------------ journal
def router_journal(ctx: Ctx) -> dict[str, Any]:
    action = ctx.arg("action", "list")
    reveal = bool(ctx.arg("reveal"))
    if action == "show":
        e = ctx.journal.get(str(ctx.need("id")))
        if e is None:
            raise UsageError("no journal entry with that id")
        return redact(e, reveal)
    limit = int(ctx.arg("limit", 20))
    rows = [{"id": e["id"], "router": e.get("router", "main"), "tool": e.get("tool"), "summary": e.get("summary"), "status": e.get("status"),
             "risk": e.get("risk"), "undo_of": e.get("undo_of"),
             "undoable": not e.get("unreadable") and all(r.get("undoable", True) for r in e.get("requests") or [])}
            for e in ctx.journal.entries()]
    return {"journal": str(ctx.journal.path), "entries": list(reversed(rows))[:limit]}


def router_undo(ctx: Ctx) -> Plan:
    from ..safety import model_tier

    jid = ctx.arg("id")
    if not jid:
        if model_tier() != "small":
            raise UsageError("id is required: find it with router_journal action=list")
        # small tier: no id = the most recent change on this router (still previewed before anything is sent).
        # Local-model bench: models could not find the journal id ("I could not find an action to undo").
        undone = {e.get("undo_of") for e in ctx.journal.entries() if e.get("undo_of")}
        # Only the last 10 minutes (the same window as recent_changes): an old change, maybe from another
        # conversation, is never picked implicitly - it needs its id.
        import time as _time

        cands = [e for e in ctx.journal.entries()
                 if e.get("router", "main") == ctx.router and e.get("status") in ("applied", "partial", "mismatch",
                                                                                     "collateral")
                 and e.get("tool") != "router_undo" and e.get("id") not in undone
                 and _time.time() - float(e.get("ts") or 0) <= 600]
        if not cands:
            raise UsageError("nothing recent to undo: no change in the last 10 minutes. For an older change, pass its "
                             "id (router_journal action=list)")
        jid = cands[-1]["id"]
    e = ctx.journal.get(str(jid))
    if e is None:
        raise UsageError("no journal entry with that id (see router_journal)")
    return plan_undo(e, ctx.t, force=bool(ctx.arg("force")))


# ---------------------------------------------------------------------------- raw write
def router_raw_write(ctx: Ctx) -> Plan:
    path = str(ctx.need("path")).lstrip("/").removeprefix("admin/")
    op = str(ctx.need("operation"))
    for single in catalog.split_forms(path):
        if catalog.get(single) is None:
            guess = guess_tool(single)
            raise UsageError(f"{single!r} is not a form the router UI uses"
                             + (f"; for this, use the tool: {guess}" if guess else " (see router_catalog)"))
    fields = _fields_arg(ctx)
    risk = catalog.risk_of(path, op)
    plan = Plan(tool="router_raw_write", summary=f"raw {op} on {path}")
    better = dedicated_tool(path, ctx.kind)
    if better:
        plan.warnings.append(f"USE THE DEDICATED TOOL INSTEAD: {better} (checked fields, verified, undoable). "
                             "router_raw_write sends unchecked fields.")
    ep = catalog.get(path)
    inverse = None
    if op in ("write", "write_spf") and ep and ep.read_op and ep.kind == "form" and not ep.field_prefix:
        try:
            cur = forms.read_form(ctx.t, path)
            plan.before[path] = cur
            if all(k in cur and not isinstance(cur[k], (dict, list)) for k in fields):
                inverse = {"op": op, "fields": {k: forms.to_field(cur[k]) for k in fields}}
                plan.warnings.append("undoable: the previous values of these fields were captured")
        except RouterError:
            pass
    if inverse is None:
        plan.warnings.append("raw request: router_undo cannot reverse this one")
    plan.add(forms.plan_custom(path, op, fields, inverse=inverse, risk=risk, label="raw request"))
    if ep:
        plan.secret_fields = ep.secret_fields
    if risk == catalog.FORBIDDEN and os.environ.get("TPLINK_ALLOW_FORBIDDEN") != "1":
        plan.warnings.append("FORBIDDEN tier: will be refused unless TPLINK_ALLOW_FORBIDDEN=1 is set for the server")
    return plan
