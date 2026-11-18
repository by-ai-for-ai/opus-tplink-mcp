"""Port forwarding (virtual servers), port triggering and DMZ."""

from __future__ import annotations

from typing import Any

from .. import forms
from ..netcalc import is_ipv4, parse_ipv4
from ..safety import Plan
from . import OFF, ON, Ctx, UsageError, onoff

VS = "nat?form=vs"
PT = "nat?form=pt"
DMZ = "nat?form=dmz"
PROTOCOLS = ("ALL", "TCP", "UDP")  # values from the web UI's protocol dropdown


def _ports(v: Any, what: str) -> str:
    s = str(v).strip()
    parts = s.split("-")
    if not 1 <= len(parts) <= 2 or not all(p.isdigit() and 1 <= int(p) <= 65535 for p in parts):
        raise UsageError(f"{what} must be a port 1-65535 or a range like 8000-8010")
    if len(parts) == 2 and int(parts[0]) > int(parts[1]):
        raise UsageError(f"{what} range is backwards")
    return s


def _lan_host(ctx: Ctx, ip: Any) -> str:
    lan = ctx.lan()
    if not is_ipv4(ip) or not lan.is_host(parse_ipv4(ip)) or parse_ipv4(ip) == lan.ip:
        raise UsageError(f"{ip!r} is not a device address in {lan.network}")
    return str(ip)


def _vs_row(ctx: Ctx, r: dict[str, Any], base: dict[str, Any] | None = None) -> dict[str, Any]:
    row = dict(base or {"enable": ON, "protocol": "ALL"})
    if "name" in r:
        row["name"] = str(r["name"])
    if "external_port" in r:
        row["external_port"] = _ports(r["external_port"], "external_port")
    if "internal_port" in r:
        row["internal_port"] = _ports(r["internal_port"], "internal_port")
    elif "external_port" in r and not base:
        row["internal_port"] = row["external_port"]
    if "ip" in r or "ipaddr" in r:
        row["ipaddr"] = _lan_host(ctx, r.get("ip", r.get("ipaddr")))
    if "protocol" in r:
        p = str(r["protocol"]).upper().replace("TCP/UDP", "ALL").replace("BOTH", "ALL")
        if p not in PROTOCOLS:
            raise UsageError(f"protocol must be one of {PROTOCOLS}")
        row["protocol"] = p
    if "enable" in r:
        row["enable"] = onoff(r["enable"])
    for f in ("name", "external_port", "internal_port", "ipaddr"):
        if not row.get(f):
            raise UsageError(f"rule.{f} is required")
    return row


def _overlaps(a: str, b: str) -> bool:
    def rng(s: str) -> tuple[int, int]:
        p = [int(x) for x in s.split("-")]
        return p[0], p[-1]

    (a1, a2), (b1, b2) = rng(a), rng(b)
    return a1 <= b2 and b1 <= a2


def port_forwarding(ctx: Ctx) -> Plan | dict[str, Any]:
    kind = ctx.arg("kind", "vs")
    action = ctx.arg("action", "list")
    if kind == "dmz":
        cur = ctx.read(DMZ)
        if action == "list":
            return {"dmz": cur}
        if action not in ("enable", "disable"):
            raise UsageError("DMZ actions: list, enable (ip), disable")
        changes: dict[str, Any] = {"enable": ON if action == "enable" else OFF}
        if action == "enable":
            changes["ipaddr"] = _lan_host(ctx, ctx.need("ip"))
        plan = ctx.plan("port_forwarding", f"{action} DMZ", DMZ)
        plan.add(forms.plan_write(DMZ, cur, changes))
        if action == "enable":
            plan.warnings.append(f"DMZ exposes EVERY port of {changes['ipaddr']} to the internet")
        return plan
    path = {"vs": VS, "pt": PT}.get(kind)
    if path is None:
        raise UsageError("kind must be vs (port forwarding), pt (port triggering) or dmz")
    rows = ctx.rows(path)
    if action == "list":
        return {"kind": kind, "rules": rows}
    if action == "add":
        rule = ctx.obj("rule")
        row = _vs_row(ctx, rule) if kind == "vs" else {**rule, "enable": onoff(rule.get("enable", True))}
        plan = ctx.plan("port_forwarding", f"add {kind} rule {row.get('name')}", path)
        if forms.find_rows(rows, "name", row.get("name")):
            plan.errors.append(f"a rule named {row.get('name')!r} exists")
        if kind == "vs":
            for r in rows:
                same_proto = "ALL" in (r.get("protocol"), row["protocol"]) or r.get("protocol") == row["protocol"]
                if r.get("external_port") and same_proto and _overlaps(str(r["external_port"]), row["external_port"]):
                    plan.errors.append(f"external port {row['external_port']} overlaps rule {r.get('name')!r}")
        if not plan.errors:
            plan.add(forms.plan_insert(path, row, label=str(row.get("name"))))
        return plan
    name = str(ctx.need("name"))
    if action == "remove":
        plan = ctx.plan("port_forwarding", f"remove {kind} rule {name}", path)
        plan.add(forms.plan_remove(path, rows, name))
        return plan
    if action == "update":
        hits = [r for r in rows if r.get("name") == name]
        if not hits:
            raise UsageError(f"no {kind} rule named {name!r}")
        rule = ctx.obj("rule")
        new = _vs_row(ctx, rule, base=hits[0]) if kind == "vs" else {**hits[0], **rule}
        plan = ctx.plan("port_forwarding", f"update {kind} rule {name}", path)
        plan.add(forms.plan_update(path, rows, name, {k: v for k, v in new.items() if k != "name"}))
        return plan
    raise UsageError(f"unknown action {action!r}")
