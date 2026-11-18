"""DHCP server, reservations, leases - plus the safety machinery they exercise."""

from __future__ import annotations

import json

from mcp_tplink_router.netcalc import lan_from
from mcp_tplink_router.validate import validate_dhcp_setting, validate_reservation

from .fake_router import DESKTOP_MAC, PHONE_MAC, TABLET_MAC

RESV = "dhcps?form=reservation"
LAN = lan_from("192.168.0.1", "255.255.255.0")


# ---------------------------------------------------------------- pure validation
def _setting(**kw):  # type: ignore[no-untyped-def]
    base = {"enable": "on", "ipaddr_start": "192.168.0.100", "ipaddr_end": "192.168.0.199", "leasetime": "120",
            "gateway": "192.168.0.1"}
    base.update(kw)
    return base


def test_dhcp_setting_errors() -> None:
    cases = {
        "not an IPv4": _setting(ipaddr_start="300.1.1.1"),
        "after pool end": _setting(ipaddr_start="192.168.0.200"),
        "outside the LAN": _setting(ipaddr_end="192.168.1.10"),
        "network or broadcast": _setting(ipaddr_end="192.168.0.255"),
        "router's own LAN IP": _setting(ipaddr_start="192.168.0.1"),
        "outside 1..2880": _setting(leasetime="3000"),
    }
    for needle, s in cases.items():
        errors, _ = validate_dhcp_setting(s, LAN, [], [])
        assert any(needle in e for e in errors), (needle, errors)


def test_dhcp_pool_smaller_than_leases() -> None:
    leases = [{"macaddr": f"00-11-22-33-44-{i:02X}", "ipaddr": f"192.168.0.{100 + i}"} for i in range(5)]
    errors, _ = validate_dhcp_setting(_setting(ipaddr_end="192.168.0.102"), LAN, [], leases)
    assert any("currently hold leases" in e for e in errors)


def test_dhcp_warnings_reservation_outside_and_shrink() -> None:
    errors, warnings = validate_dhcp_setting(
        _setting(ipaddr_end="192.168.0.150"), LAN, [{"mac": TABLET_MAC, "ip": "192.168.0.170"}], [],
        old=_setting())
    assert not errors
    assert any("outside the new pool" in w for w in warnings)
    assert any("shrinks" in w for w in warnings)


def test_reservation_validation() -> None:
    existing = [{"mac": TABLET_MAC, "ip": "192.168.0.157"}]
    leases = [{"macaddr": PHONE_MAC, "ipaddr": "192.168.0.123"}]
    e, w = validate_reservation({"mac": "01:00:5e:00:00:01", "ip": "192.168.0.50"}, LAN, existing, leases, [])
    assert any("multicast" in x for x in e)
    e, w = validate_reservation({"mac": "00:00:00:00:00:00", "ip": "192.168.0.50"}, LAN, existing, leases, [])
    assert e
    e, w = validate_reservation({"mac": "aabb.ccdd.eeff", "ip": "192.168.0.157"}, LAN, existing, leases, [])
    assert any("already reserved" in x for x in e)
    e, w = validate_reservation({"mac": TABLET_MAC.lower(), "ip": "192.168.0.158"}, LAN, existing, leases, [])
    assert any("use action=update" in x for x in e)
    e, w = validate_reservation({"mac": "AABBCCDDEEFF", "ip": "192.168.0.1"}, LAN, existing, leases, [])
    assert any("own LAN IP" in x for x in e)
    e, w = validate_reservation({"mac": "AA-BB-CC-DD-EE-FF", "ip": "192.168.0.123"}, LAN, existing, leases, [])
    assert not e and any("currently leased" in x for x in w) and any("never been seen" in x for x in w)
    e, w = validate_reservation({"mac": PHONE_MAC, "ip": "192.168.0.123"}, LAN, existing, leases, [])
    assert not e and any("use device MAC" in x for x in w)


# ---------------------------------------------------------------- tools
def test_list_reservations_annotated(call) -> None:  # type: ignore[no-untyped-def]
    out = call("dhcp_reservation", action="list")
    r = out["reservations"][0]
    assert r["mac"] == TABLET_MAC and r["working"] is True and r["online"] is True


def test_add_dry_run_sends_nothing(call, fake) -> None:  # type: ignore[no-untyped-def]
    out = call("dhcp_reservation", action="add", mac="02:00:00:00:00:01", ip="192.168.0.250", name="sentinel")
    assert out["dry_run"] is True and out["risk"] == "normal" and "confirm_token" not in out
    assert any("use device MAC" in w for w in out["warnings"])  # 02- is locally administered
    assert out["diff"][0]["add_row"] == {"mac": "02-00-00-00-00-01", "ip": "192.168.0.250",
                                         "comment": "sentinel", "enable": "on"}
    assert fake.writes() == []


def test_add_apply_wire_format_and_journal(call, fake, rt) -> None:  # type: ignore[no-untyped-def]
    out = call("dhcp_reservation", action="add", mac="02:00:00:00:00:01", ip="192.168.0.250", apply=True)
    assert out["status"] == "applied" and out["verify"][0]["applied"] is True
    (path, op, fields), = fake.writes()
    assert (path, op) == (RESV, "insert")
    assert json.loads(fields["new"]) == {"mac": "02-00-00-00-00-01", "ip": "192.168.0.250", "comment": "", "enable": "on"}
    assert fields["index"] == "0"
    entry = rt.journal.get(out["journal_id"])
    assert entry["status"] == "applied" and entry["before"][RESV][0]["mac"] == TABLET_MAC
    assert len(entry["after"][RESV]) == 2


def test_add_rejects_conflicting_ip(call, fake) -> None:  # type: ignore[no-untyped-def]
    out = call("dhcp_reservation", action="add", mac="AA-BB-CC-DD-EE-01", ip="192.168.0.157", apply=True)
    assert out["applied"] is False and out["errors"] and fake.writes() == []


def test_remove_uses_fresh_index_and_verifies(call, fake) -> None:  # type: ignore[no-untyped-def]
    fake.state[RESV].insert(0, {"mac": "AA-BB-CC-DD-EE-01", "ip": "192.168.0.200", "comment": "x",
                                "hostname": "", "enable": "on"})
    out = call("dhcp_reservation", action="remove", mac=TABLET_MAC.lower().replace("-", ":"), apply=True)
    assert out["status"] == "applied"
    (path, op, fields), = fake.writes()
    assert op == "remove" and fields["index"] == "1"
    assert [r["mac"] for r in fake.state[RESV]] == ["AA-BB-CC-DD-EE-01"]


def test_update_sends_old_and_new(call, fake) -> None:  # type: ignore[no-untyped-def]
    out = call("dhcp_reservation", action="update", mac=TABLET_MAC, ip="192.168.0.158", apply=True)
    assert out["status"] == "applied"
    (_, op, fields), = fake.writes()
    assert op == "update"
    assert json.loads(fields["old"])["ip"] == "192.168.0.157"
    assert json.loads(fields["new"])["ip"] == "192.168.0.158"
    assert fake.state[RESV][0]["ip"] == "192.168.0.158"


def test_reserve_current_by_hostname(call, fake) -> None:  # type: ignore[no-untyped-def]
    out = call("dhcp_reservation", action="reserve_current", client="desktop", name="desk", apply=True)
    assert out["status"] == "applied"
    assert {"mac": DESKTOP_MAC, "ip": "192.168.0.160"}.items() <= fake.state[RESV][-1].items()


def test_conflict_if_row_changed_between_plan_and_send(call, fake) -> None:  # type: ignore[no-untyped-def]
    loads = {"n": 0}

    def hook(path, op, fields):  # type: ignore[no-untyped-def]
        if path == RESV and op == "load":
            loads["n"] += 1
            if loads["n"] == 2:  # the pre-send re-load: the owner edited the row meanwhile
                fake.state[RESV][0]["comment"] = "edited elsewhere"

    fake.on_call = hook
    out = call("dhcp_reservation", action="remove", mac=TABLET_MAC, apply=True)
    assert out["status"] == "failed" and "changed since" in out["error"]
    assert not [w for w in fake.writes() if w[1] == "remove"]


def _fail_on(fake, op, *, after_apply):  # type: ignore[no-untyped-def]
    armed = {"done": False}

    def hook(path, o, fields):  # type: ignore[no-untyped-def]
        if o == op and not armed["done"]:
            armed["done"] = True
            fake.fail_next("timeout", after_apply=after_apply)

    fake.on_call = hook


def test_ambiguous_write_applied_is_reread_not_resent(call, fake, rt) -> None:  # type: ignore[no-untyped-def]
    _fail_on(fake, "insert", after_apply=True)
    out = call("dhcp_reservation", action="add", mac="AA-BB-CC-DD-EE-01", ip="192.168.0.201", apply=True)
    assert out["status"] == "applied", out
    assert len([c for c in fake.calls if c[1] == "insert"]) == 1, "an ambiguous write must never be resent"
    assert fake.logins == 2  # re-logged in to re-read
    assert rt.journal.get(out["journal_id"])["status"] == "applied"


def test_ambiguous_write_not_applied_reports_failed(call, fake, rt) -> None:  # type: ignore[no-untyped-def]
    _fail_on(fake, "insert", after_apply=False)
    out = call("dhcp_reservation", action="add", mac="AA-BB-CC-DD-EE-01", ip="192.168.0.201", apply=True)
    assert out["status"] == "failed" and out["steps_applied"] == 0
    assert len([c for c in fake.calls if c[1] == "insert"]) == 1
    assert rt.journal.get(out["journal_id"])["status"] == "failed"


def test_dhcp_server_set_validation_and_critical(call, fake) -> None:  # type: ignore[no-untyped-def]
    bad = call("dhcp_server_set", start="192.168.0.1", end="192.168.0.50")
    assert bad["errors"]
    ok = call("dhcp_server_set", lease_minutes=240)
    assert ok["risk"] == "normal" and ok["diff"][0]["changes"] == {"leasetime": {"from": "120", "to": "240"}}
    off = call("dhcp_server_set", enable=False)
    assert off["risk"] == "critical" and off["confirm_token"]
    refused = call("dhcp_server_set", enable=False, apply=True)
    assert refused["applied"] is False and "CRITICAL" in refused["refused"]
    assert fake.writes() == []
    done = call("dhcp_server_set", enable=False, apply=True, confirm_token=off["confirm_token"])
    assert done["status"] == "applied"
    (_, op, fields), = fake.writes()
    assert op == "write" and fields["enable"] == "off"
    assert set(fields) == {"enable", "ipaddr_start", "ipaddr_end", "leasetime", "gateway", "pri_dns", "snd_dns"}


def test_confirm_token_bound_to_state(call, fake) -> None:  # type: ignore[no-untyped-def]
    dry = call("dhcp_server_set", enable=False)
    fake.state["dhcps?form=setting"]["ipaddr_end"] = "192.168.0.240"  # someone changed it meanwhile
    out = call("dhcp_server_set", enable=False, apply=True, confirm_token=dry["confirm_token"])
    assert out["applied"] is False and "does not match" in out["refused"]


def test_no_change_is_reported(call, fake) -> None:  # type: ignore[no-untyped-def]
    out = call("dhcp_server_set", lease_minutes=120, apply=True)
    assert out["no_change"] is True and fake.writes() == []


def test_undo_roundtrip(apply, call, fake) -> None:  # type: ignore[no-untyped-def]
    added = apply("dhcp_reservation", action="add", mac="AA-BB-CC-DD-EE-01", ip="192.168.0.201")
    assert len(fake.state[RESV]) == 2
    undo = apply("router_undo", id=added["journal_id"])
    assert undo["status"] == "applied" and len(fake.state[RESV]) == 1
    removed = apply("dhcp_reservation", action="remove", mac=TABLET_MAC)
    assert fake.state[RESV] == []
    apply("router_undo", id=removed["journal_id"])
    assert fake.state[RESV][0]["mac"] == TABLET_MAC
    changed = apply("dhcp_server_set", lease_minutes=600)
    apply("router_undo", id=changed["journal_id"])
    assert fake.state["dhcps?form=setting"]["leasetime"] == "120"


def test_undo_refuses_after_drift(apply, call, fake) -> None:  # type: ignore[no-untyped-def]
    changed = apply("dhcp_server_set", lease_minutes=600)
    fake.state["dhcps?form=setting"]["leasetime"] = "700"
    out = call("router_undo", id=changed["journal_id"])
    assert out["errors"] and "force" in out["errors"][0]
    forced = call("router_undo", id=changed["journal_id"], force=True)
    assert forced["dry_run"]


def test_wrong_row_removed_is_flagged_and_undo_restores_it(call, apply, fake, rt) -> None:  # type: ignore[no-untyped-def]
    """If the router ever interpreted 'index' differently, the kiosk tablet's row must not vanish silently."""
    apply("dhcp_reservation", action="add", mac="02-00-00-00-00-01", ip="192.168.0.250")
    fake.index_offset = -1  # the router removes the row BEFORE the one we asked for (the tablet)
    out = call("dhcp_reservation", action="remove", mac="02-00-00-00-00-01", apply=True)
    fake.index_offset = 0
    assert out["status"] == "collateral", out
    assert out["collateral"]["missing"][0]["mac"] == TABLET_MAC
    entry = rt.journal.get(out["journal_id"])
    assert entry["status"] == "collateral" and entry["wire"][0]["fields"]["index"] == "1"
    undo = apply("router_undo", id=out["journal_id"])
    assert undo["status"] == "applied"
    assert sorted(r["mac"] for r in fake.state[RESV]) == sorted(["02-00-00-00-00-01", TABLET_MAC])


def test_wire_record_has_send_time_fields(apply, rt) -> None:  # type: ignore[no-untyped-def]
    done = apply("dhcp_reservation", action="update", mac=TABLET_MAC, ip="192.168.0.158")
    wire = rt.journal.get(done["journal_id"])["wire"]
    assert wire[0]["operation"] == "update" and json.loads(wire[0]["fields"]["old"])["comment"] == "kiosk-tablet"


def test_reservation_name_note(call) -> None:  # type: ignore[no-untyped-def]
    out = call("dhcp_reservation", action="add", mac="AA-BB-CC-DD-EE-01", ip="192.168.0.201", name="kiosk")
    assert any("custom names are not stored" in w for w in out["warnings"])
    assert "custom names are not stored" in call("dhcp_reservation", action="update", mac=TABLET_MAC,
                                                 name="x")["error"]


def test_router_ignoring_a_write_reports_no_effect(call, fake, rt) -> None:  # type: ignore[no-untyped-def]
    fake.ignore_changes.add("dhcps?form=setting")
    out = call("dhcp_server_set", lease_minutes=240, apply=True)
    assert out["status"] == "no_effect" and "NO EFFECT" in out["warning"]
    assert rt.journal.get(out["journal_id"])["status"] == "no_effect"


def test_router_ignoring_an_update_reports_no_effect(call, fake) -> None:  # type: ignore[no-untyped-def]
    fake.ignore_changes.add(RESV)
    out = call("dhcp_reservation", action="update", mac=TABLET_MAC, ip="192.168.0.158", apply=True)
    assert out["status"] == "no_effect"
