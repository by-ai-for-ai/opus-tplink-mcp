"""Feature handlers.  Each handler takes a :class:`Ctx` and returns a dict (read) or a
:class:`~mcp_tplink_router.safety.Plan` (write; the dispatcher dry-runs or applies it)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .. import forms
from ..journal import Journal
from ..netcalc import Lan, lan_from_lan_ipv4, normalize_mac
from ..safety import Plan

ON, OFF = "on", "off"


class UsageError(ValueError):
    """Bad tool arguments (reported to the caller, never retried)."""


def onoff(value: Any) -> str:
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("on", "true", "1", "yes", "enable", "enabled"):
            return ON
        if v in ("off", "false", "0", "no", "disable", "disabled"):
            return OFF
        raise UsageError(f"expected on/off, got {value!r}")
    return ON if value else OFF


def is_on(value: Any) -> bool:
    return str(value).lower() in ("on", "true", "1", "yes")


@dataclass
class Ctx:
    t: Any
    args: dict[str, Any]
    journal: Journal
    host: str = ""
    identity: Callable[[], dict[str, Any]] = field(default=lambda: {"ip": None, "macs": []})
    router: str = "main"
    routers: list[dict[str, str]] = field(default_factory=list)
    kind: str = "router"
    _cache: dict[str, Any] = field(default_factory=dict)

    # -- arguments ---------------------------------------------------------------------
    def arg(self, name: str, default: Any = None) -> Any:
        v = self.args.get(name, default)
        return default if v is None else v

    def need(self, name: str) -> Any:
        v = self.args.get(name)
        if v is None or v == "":
            raise UsageError(f"'{name}' is required for action={self.args.get('action')!r}")
        return v

    def obj(self, name: str) -> dict[str, Any]:
        v = self.args.get(name) or {}
        if not isinstance(v, dict):
            raise UsageError(f"'{name}' must be an object")
        return dict(v)

    # -- cached reads ------------------------------------------------------------------
    def device_config(self) -> dict[str, Any]:
        """The router's capability flags where the transport can read them (encrypted firmware), else {}."""
        if "device_config" not in self._cache:
            fn = getattr(self.t, "device_config", None)
            self._cache["device_config"] = (fn() if callable(fn) else None) or {}
        return self._cache["device_config"]  # type: ignore[no-any-return]

    def read(self, path: str) -> dict[str, Any]:
        key = "r:" + path
        if key not in self._cache:
            self._cache[key] = forms.read_form(self.t, path)
        return self._cache[key]  # type: ignore[no-any-return]

    def rows(self, path: str) -> list[dict[str, Any]]:
        key = "t:" + path
        if key not in self._cache:
            self._cache[key] = forms.load_table(self.t, path)
        return self._cache[key]  # type: ignore[no-any-return]

    def lan(self) -> Lan:
        return lan_from_lan_ipv4(self.read("network?form=lan_ipv4"))

    def clients(self) -> list[dict[str, Any]]:
        """Connected clients: [{mac, ip, name, connection}] from status?form=all."""
        from ..transport import RouterError

        try:
            st = self.read("status?form=all")
        except RouterError:
            st = self.read("status?form=client_status")  # older firmware (BE4800)
        out = []
        lists = ("access_devices_wired", "access_devices_wireless_host", "access_devices_wireless_guest")
        for src, conn in zip(lists, ("wired", "wireless", "guest")):
            for d in st.get(src) or []:
                try:
                    mac = normalize_mac(d.get("macaddr", ""))
                except ValueError:
                    continue
                out.append({"mac": mac, "ip": d.get("ipaddr"), "name": d.get("hostname"),
                            "connection": d.get("wire_type") or conn})
        if not any(k in st for k in lists):
            out = self._clients_from_device_list()
        return out

    def _clients_from_device_list(self) -> list[dict[str, Any]]:
        """Encrypted-protocol firmware (BE4800, BE3600) has no client lists in status?form=all; the web
        UI's connected-clients view reads smart_network?form=game_accelerator operation=loadDevice."""
        rows = safe_read(self, "smart_network?form=game_accelerator", "loadDevice")
        out = []
        for d in rows if isinstance(rows, list) else []:
            if not isinstance(d, dict):
                continue
            try:
                mac = normalize_mac(d.get("mac", ""))
            except ValueError:
                continue
            tag = str(d.get("deviceTag") or "").lower()
            conn = ("guest" if d.get("isGuest") or "guest" in tag else "wired" if "wire" in tag
                    else "iot" if tag.startswith("iot") else "wireless")
            ip = d.get("ip")
            out.append({"mac": mac, "ip": None if ip in ("", "0.0.0.0") else ip, "name": d.get("deviceName"),  # nosec B104 - "no address" placeholder, not a bind
                        "connection": conn, "band": d.get("deviceTag")})
        return out

    @property
    def is_main(self) -> bool:
        return self.router == "main"

    def own_macs(self) -> set[str]:
        """MAC(s) of the machine running this server, as seen by the router."""
        if "own" not in self._cache:
            ident = self.identity() or {}
            macs = set()
            for m in ident.get("macs") or []:
                try:
                    macs.add(normalize_mac(m))
                except ValueError:
                    pass
            ip = ident.get("ip")
            if ip:
                try:
                    macs.update(c["mac"] for c in self.clients() if c.get("ip") == ip)
                except Exception:  # noqa: BLE001 - best effort
                    pass
            self._cache["own"] = macs
        return self._cache["own"]  # type: ignore[no-any-return]

    def plan(self, tool: str, summary: str, *paths: str) -> Plan:
        """New plan whose ``before`` snapshot covers ``paths``."""
        p = Plan(tool=tool, summary=summary)
        for path in paths:
            p.before[path] = self.state(path)
        return p

    def state(self, path: str) -> Any:
        ep = forms.endpoint(path)
        if ep.kind == "table" or (ep.list_key and ep.table_ops):
            return self.rows(path)
        return self.read(path)


def find_mac(value: str) -> str:
    try:
        return normalize_mac(value)
    except ValueError as exc:
        raise UsageError(str(exc)) from exc


def pick(rows: list[dict[str, Any]], **match: Any) -> list[dict[str, Any]]:
    return [r for r in rows if all(forms.key_equal(k, r.get(k), v) for k, v in match.items())]


_TRUE_WORDS = ("true", "on", "yes", "enable", "enabled", "1")
_FALSE_WORDS = ("false", "off", "no", "disable", "disabled", "0")


def boolish(cur: Any, value: Any) -> Any:
    """Convert a caller's bool to the form's own vocabulary (on/off strings or real bools).

    Also "true"/"false" sent as TEXT for an on/off field (small models do this; the router stored "off"
    for "false" and the re-read was then misreported as a mismatch).
    """
    on_off_field = isinstance(cur, bool) or (isinstance(cur, str) and cur.lower() in _TRUE_WORDS + _FALSE_WORDS)
    if isinstance(value, str) and on_off_field and value.strip().lower() in ("true", "false", "yes", "no",
                                                                               "enable", "disable",
                                                                               "enabled", "disabled"):
        value = value.strip().lower() in _TRUE_WORDS
    if isinstance(value, bool):
        if isinstance(cur, bool):
            return value
        if isinstance(cur, str) and cur.lower() in ("yes", "no"):
            return "yes" if value else "no"
        if isinstance(cur, str) and cur in ("0", "1"):
            return "1" if value else "0"
        return ON if value else OFF
    return value


def settings_change(ctx: Ctx, tool: str, path: str, settings: dict[str, Any], what: str,
                    *, critical: str | None = None, warn: str | None = None) -> Plan | dict[str, Any]:
    """Read-modify-write one settings form.  No settings = return the current values."""
    cur = ctx.read(path)
    if not settings:
        return {"current": cur}
    lists = forms.endpoint(path).list_fields
    changes = {}
    for k, v in settings.items():
        v = boolish(cur.get(k), v)
        if isinstance(v, (list, dict)) and k not in lists:
            v = forms.jdump(v)
        if k in lists and not isinstance(v, list):
            raise UsageError(f"{k} must be a list")
        changes[k] = v
    plan = ctx.plan(tool, f"change {what}", path)
    plan.add(forms.plan_write(path, cur, changes, label=what))
    if critical:
        plan.critical_reasons.append(critical)
    if warn:
        plan.warnings.append(warn)
    if not plan.steps:
        return {"status": "no_change", "verified": "no",
                "tell_user": "NOTHING WAS CHANGED: the device already has these values.", "current": cur}
    return plan


def safe_read(ctx: Ctx, path: str, op: str | None = None, fields: dict[str, Any] | None = None) -> Any:
    """Read for an overview: a missing form becomes {"error": ...} instead of failing the call."""
    from ..transport import RouterError

    try:
        if op is None and not fields:
            return ctx.state(path)
        return ctx.t.call(path, op or "read", {k: forms.to_field(v) for k, v in (fields or {}).items()})
    except RouterError as exc:
        return {"error": exc.code}
