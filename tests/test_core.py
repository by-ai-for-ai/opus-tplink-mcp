"""Catalog consistency, redaction, raw tools, logs, journal, forbidden gating."""

from __future__ import annotations

import json
import os
import stat

import pytest

from mcp_tplink_router import catalog
from mcp_tplink_router.safety import is_secret_field, redact

from .fake_router import SHAPES, WIFI_PSK


# ------------------------------------------------------------------ catalog
def _shape_keys(path: str) -> set[str] | None:
    entry = SHAPES.get(path)
    if not entry or not entry.get("op"):
        return None
    shape = entry["shape"]
    if isinstance(shape, list):
        return set(shape[0]) if shape and isinstance(shape[0], dict) else None
    return set(shape) or None if isinstance(shape, dict) else None


def test_catalog_fields_exist_in_live_shapes() -> None:
    """Cheap typo catcher: every key_field / write_field must exist in that form's live shape."""
    for ep in catalog.CURATED.values():
        keys = _shape_keys(ep.path)
        if keys is None:
            continue
        if ep.list_key:
            assert ep.list_key in keys, ep.path
            continue
        if ep.key_field and ep.kind == "table":
            assert ep.key_field in keys, (ep.path, ep.key_field)
        for f in ep.write_fields or ():
            assert f in keys, (ep.path, f)


def test_catalog_read_ops_match_probe() -> None:
    for ep in catalog.CURATED.values():
        entry = SHAPES.get(ep.path)
        if entry and entry.get("op") and ep.kind == "form":
            assert ep.read_op == entry["op"], ep.path


def test_risk_tiers() -> None:
    assert catalog.risk_of("firmware?form=config", "factory") == "forbidden"
    assert catalog.risk_of("firmware?form=config", "check") == "read"
    assert catalog.risk_of("quick_setup?form=quick_setup", "write") == "forbidden"
    assert catalog.risk_of("cloud_account?form=cloud_unbind", "write") == "forbidden"
    assert catalog.risk_of("network?form=wan_ipv4_dynamic", "write") == "critical"
    assert catalog.risk_of("network?form=lan_ipv4", "write") == "critical"
    assert catalog.risk_of("system?form=reboot", "reboot") == "critical"
    assert catalog.risk_of("wireguard?form=config", "renew") == "critical"
    assert catalog.risk_of("syslog?form=log", "remove") == "critical"
    assert catalog.risk_of("dhcps?form=reservation", "insert") == "normal"
    assert catalog.risk_of("iptv?form=setting", "read") == "read"
    assert catalog.risk_of("accessibility?form=accessibility_state", "write") == "critical"  # unknown write format -> look first
    assert len(catalog.all_paths()) >= 219


def test_catalog_tool(call) -> None:  # type: ignore[no-untyped-def]
    out = call("router_catalog", filter="dhcps")
    assert {f["path"] for f in out["forms"]} == {"dhcps?form=setting", "dhcps?form=reservation", "dhcps?form=client"}
    one = call("router_catalog", path="dhcps?form=reservation")
    assert one["ops"]["insert"] == {"risk": "normal", "verified": "live"} and one["key_field"] == "mac"


# ---------------------------------------------------------------- redaction
@pytest.mark.parametrize("name", ["psk_key", "wpa_key", "wep_key3", "password", "portal_password", "private_key",
                                  "preshared_key", "old_pwd", "wps_pin", "token", "guest_2g_psk_key", "secret",
                                  "wireless_5g_wpa_key", "wep_key1", "guest_6g_portal_password", "new_pwd"])
def test_secret_names(name: str) -> None:
    assert is_secret_field(name)


@pytest.mark.parametrize("name", ["key", "public_key", "server_key", "wan_ping", "lan_ping", "pri_dns", "mapping",
                                  "modem_pinlock", "keepalive", "kill_switch", "ssid", "mac", "psk_cipher",
                                  "psk_version", "wireless_2g_psk_cipher", "guest_5g_psk_version", "passwd_cycle",
                                  "wpa_cipher", "wpa_version", "wep_select", "wep_format1", "wep_type2", "wep_mode",
                                  "password_type"])
def test_not_secret_names(name: str) -> None:
    assert not is_secret_field(name)


def test_redact_scrubs_values_inside_strings() -> None:
    obj = {"psk_key": "hunter2-long", "old": json.dumps({"private_key": "PRIV-1234"}), "msg": "bad PRIV-1234 x"}
    out = redact(obj)
    assert out["psk_key"] == "<redacted>"
    assert "PRIV-1234" not in json.dumps(out)
    assert redact(obj, reveal=True) == obj


def test_status_and_get_never_leak_wifi_password(call) -> None:  # type: ignore[no-untyped-def]
    for out in (call("router_status"), call("router_get", section="status"), call("router_get", section="wifi"),
                call("router_raw_read", path="wireless?form=wireless_2g", operation="read_spf")):
        assert WIFI_PSK not in json.dumps(out)
    assert WIFI_PSK in json.dumps(call("router_get", section="wifi_2g", reveal=True))


# ---------------------------------------------------------------- get / raw read
def test_router_get_sections(call) -> None:  # type: ignore[no-untyped-def]
    assert "dhcp_reservations" in call("router_get")["sections"]
    assert call("router_get", section="dhcp")["data"]["ipaddr_start"] == "192.168.0.100"
    clients = call("router_get", section="clients")["data"]["clients"]
    me = [c for c in clients if c.get("this_machine")]
    assert me and me[0]["ip"] == "192.168.0.160"
    phone = [c for c in clients if c["name"] == "kid-phone"][0]
    assert phone["random_mac"] is True and phone["reservation"] is None
    assert call("router_get", section="iptv?form=setting")["path"] == "iptv?form=setting"
    assert "unknown section" in call("router_get", section="nope")["error"]


def test_raw_read_refuses_writes(call, fake) -> None:  # type: ignore[no-untyped-def]
    assert "not read-only" in call("router_raw_read", path="dhcps?form=setting", operation="write")["error"]
    assert "not a form" in call("router_raw_read", path="evil?form=x")["error"]
    out = call("router_raw_read", path="avira_parental_control?form=avira_pactrl", operation="getBlockHistory",
               fields={"ownerId": "1"})
    assert out["data"]["history"]
    assert fake.writes() == []


# ---------------------------------------------------------------------- logs
def test_logs_filters(call, fake) -> None:  # type: ignore[no-untyped-def]
    out = call("router_logs")
    assert out["total"] == 3 and out["order"] == "newest first"
    assert out["logs"][0]["time"] == "2026-11-17 08:05:00"
    assert [r["type"] for r in call("router_logs", level="WARNING")["logs"]] == ["WAN", "SYSTEM"]
    assert call("router_logs", type="dhcpd")["matched"] == 1
    assert call("router_logs", contains="00:00:5e:00:53")["matched"] == 1
    assert call("router_logs", since="2026-11-17 08:00:00")["matched"] == 2
    assert call("router_logs", limit=1)["returned"] == 1
    assert fake.writes() == []  # never touches syslog?form=filter


# ------------------------------------------------------------- journal / raw write
def test_journal_permissions_and_listing(apply, call, rt) -> None:  # type: ignore[no-untyped-def]
    done = apply("upnp", action="disable")
    mode = stat.S_IMODE(os.stat(rt.journal.path).st_mode)
    assert mode == 0o600 and stat.S_IMODE(os.stat(rt.journal.dir).st_mode) == 0o700
    listed = call("router_journal")
    assert listed["entries"][0]["id"] == done["journal_id"]
    shown = call("router_journal", action="show", id=done["journal_id"])
    assert shown["status"] == "applied" and shown["before"]["upnp?form=enable"]["enable"] == "on"


def test_journal_keeps_secrets_but_show_redacts(apply, call, rt) -> None:  # type: ignore[no-untyped-def]
    done = apply("wifi_set", action="set", band="2g", settings={"password": "brand-new-pass-1"})
    raw = rt.journal.path.read_text()
    assert "brand-new-pass-1" in raw and WIFI_PSK in raw
    shown = call("router_journal", action="show", id=done["journal_id"])
    assert "brand-new-pass-1" not in json.dumps(shown) and WIFI_PSK not in json.dumps(shown)


def test_raw_write_undoable_when_old_values_known(apply, fake) -> None:  # type: ignore[no-untyped-def]
    done = apply("router_raw_write", path="ledgeneral?form=setting", operation="write", fields={"enable": "off"})
    assert done["status"] == "applied" and fake.state["ledgeneral?form=setting"]["enable"] == "off"
    apply("router_undo", id=done["journal_id"])
    assert fake.state["ledgeneral?form=setting"]["enable"] == "on"


def test_raw_write_unknown_op_is_critical(call) -> None:  # type: ignore[no-untyped-def]
    out = call("router_raw_write", path="iptv?form=setting", operation="frobnicate", fields={})
    assert out["risk"] == "critical" and out["confirm_token"]


def test_forbidden_needs_env(call, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    dry = call("router_raw_write", path="firmware?form=config", operation="factory", fields={"all": "false"})
    assert dry["risk"] == "forbidden"
    out = call("router_raw_write", path="firmware?form=config", operation="factory", fields={"all": "false"},
               apply=True, confirm_token=dry["confirm_token"])
    assert out["applied"] is False and "TPLINK_ALLOW_FORBIDDEN" in out["refused"]
    assert fake.writes() == []
    monkeypatch.setenv("TPLINK_ALLOW_FORBIDDEN", "1")
    out = call("router_raw_write", path="firmware?form=config", operation="factory", fields={"all": "false"},
               apply=True)
    assert out["applied"] is False and "confirm_token" in out["refused"]


def test_reboot_not_undoable(apply, call) -> None:  # type: ignore[no-untyped-def]
    done = apply("router_raw_write", path="system?form=reboot", operation="reboot", fields={})
    out = call("router_undo", id=done["journal_id"])
    assert any("cannot be undone" in e for e in out["errors"])


def test_tool_annotations() -> None:
    from mcp_tplink_router.server import tool_definitions

    defs = {t.name: t for t in tool_definitions()}
    assert defs["router_status"].annotations.readOnlyHint is True
    assert defs["dhcp_reservation"].annotations.destructiveHint is True
    assert len(defs) <= 34  # compact tool list; extenders add a read-only + a write tool


def test_raw_read_refuses_forbidden_forms(call, fake) -> None:  # type: ignore[no-untyped-def]
    for path, op in (("debug?form=cmd", "read"), ("cloud_account?form=get_token", "read"),
                     ("quick_setup?form=quick_setup", "read"), ("firmware?form=config", "factory")):
        out = call("router_raw_read", path=path, operation=op)
        assert "error" in out, (path, out)
    assert fake.calls == []


def test_unreachable_device_gets_an_address_hint_not_the_one_session_hint() -> None:
    from mcp_tplink_router.journal import Journal
    from mcp_tplink_router.tools import Runtime, run_tool
    from mcp_tplink_router.transport import RouterError

    def down() -> None:
        raise RouterError("login_failed", "HTTPSConnectionPool(host='192.0.2.9', port=443): Max retries exceeded "
                                          "(Caused by ConnectTimeoutError(... 'Connection to 192.0.2.9 timed out.'))")
    out = run_tool("router_status", {}, Runtime(factory=down, journal=Journal(), retry_delay=0))
    assert out["error"] == "login_failed" and "did not answer" in out["hint"] and "ONE admin" not in out["hint"]
