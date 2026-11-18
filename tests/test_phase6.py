"""Access control, parental control, Wi-Fi (+guest), Wi-Fi schedule, port forwarding."""

from __future__ import annotations

import json

from .fake_router import DESKTOP_MAC, PHONE_MAC, WIFI_PSK

BLACK = "access_control?form=black_list"


# ------------------------------------------------------------------ access control
def test_block_phone_wire_row(apply, fake) -> None:  # type: ignore[no-untyped-def]
    out = apply("access_control", action="block", mac=PHONE_MAC)
    assert out["status"] == "applied" and any("currently OFF" in w for w in out["warnings"])
    _, op, fields = fake.writes()[-1]
    assert op == "insert"
    assert json.loads(fields["new"]) == {"name": "kid-phone", "deviceType": "other", "mac": PHONE_MAC,
                                         "ipaddr": "192.168.0.123", "host": "NOT HOST", "conn_type": "2.4G", "key": ""}
    apply("access_control", action="unblock", mac=PHONE_MAC)
    assert fake.state[BLACK] == []


def test_block_own_machine_is_critical(call) -> None:  # type: ignore[no-untyped-def]
    out = call("access_control", action="block", mac=DESKTOP_MAC)
    assert out["risk"] == "critical" and "THIS machine" in out["critical_because"][0]


def test_host_marked_row_counts_as_own(call, fake) -> None:  # type: ignore[no-untyped-def]
    fake.state["access_control?form=black_devices"] = [{"mac": "AA-AA-AA-AA-AA-01", "host": "HOST", "name": "x",
                                                        "ipaddr": "", "type": "", "access_time": 0, "conn_type": "",
                                                        "guest": "", "raw_conn_type": ""}]
    assert call("access_control", action="block", mac="AA-AA-AA-AA-AA-01")["risk"] == "critical"


def test_white_mode_is_critical(call, apply, fake) -> None:  # type: ignore[no-untyped-def]
    out = call("access_control", action="set_mode", mode="white")
    assert out["risk"] == "critical" and "not on the allowlist" in out["critical_because"][0]
    apply("access_control", action="allow", mac=DESKTOP_MAC)
    out = call("access_control", action="set_mode", mode="white")
    assert out["risk"] == "critical" and "not on the allowlist" not in out["critical_because"][0]
    assert call("access_control", action="enable")["risk"] == "normal"  # black mode
    apply("access_control", action="set_mode", mode="white")
    assert call("access_control", action="enable")["risk"] == "critical"
    _, _, fields = [w for w in fake.writes() if w[0] == "access_control?form=mode"][-1]
    assert fields == {"access_mode": "white"}


# ------------------------------------------------------------------ parental
def test_parental_reads(call) -> None:  # type: ignore[no-untyped-def]
    owners = call("parental_control")["data"]
    assert owners["ownerList"][0]["name"] == "Child" and owners["totalOwnerMax"] == 16
    assert call("parental_control", action="today_sites", owner_id="1")["data"]["sites"]


def test_parental_internet_block_and_undo(apply, call, fake) -> None:  # type: ignore[no-untyped-def]
    done = apply("parental_control", action="internet_block", owner_id="1", blocked=True)
    assert done["status"] == "applied" and fake.avira["owners"][0]["internetBlocked"] is True
    assert fake.writes()[-1][2] == {"ownerId": "1", "internetBlocked": "true"}
    assert call("parental_control", action="internet_block", owner_id="1", blocked=True)["no_change"]
    apply("router_undo", id=done["journal_id"])
    assert fake.avira["owners"][0]["internetBlocked"] is False


def test_parental_filter_set_json_list(apply, fake) -> None:  # type: ignore[no-untyped-def]
    done = apply("parental_control", action="filter_set", owner_id="1", sites=["tiktok.com", "example-games.com"])
    assert json.loads(fake.writes()[-1][2]["filterWebsiteList"]) == ["tiktok.com", "example-games.com"]
    apply("router_undo", id=done["journal_id"])
    assert fake.avira["owners"][0]["filterWebsiteList"] == ["example-games.com"]


# ------------------------------------------------------------------ Wi-Fi
def test_wifi_set_password_uses_write_spf_multiform(apply, fake) -> None:  # type: ignore[no-untyped-def]
    out = apply("wifi_set", action="set", band="5g", settings={"password": "new-pass-5g!"})
    assert out["status"] == "applied" and "new-pass-5g!" not in json.dumps(out)
    path, op, fields = fake.writes()[-1]
    assert path == "wireless?form=wireless_2g&form=wireless_5g&form=wireless_6g" and op == "write_spf"
    assert fields["wireless_5g_psk_key"] == "new-pass-5g!"
    assert all(k.startswith("wireless_5g_") for k in fields)
    assert "wireless_5g_wpa_key" not in fields  # empty values are dropped like the UI does
    assert "wireless_5g_current_channel" not in fields  # not in the UI's writable list
    assert fake.state["wireless?form=wireless_5g"]["psk_key"] == "new-pass-5g!"


def test_wifi_disable_is_critical_and_pairs_disabled_all(call, apply, fake) -> None:  # type: ignore[no-untyped-def]
    assert call("wifi_set", action="set", band="6g", settings={"enable": False})["risk"] == "critical"
    apply("wifi_set", action="set", band="6g", settings={"enable": False})
    assert fake.state["wireless?form=wireless_6g"]["enable"] == "off"
    assert fake.state["wireless?form=wireless_6g"]["disabled_all"] == "on"


def test_wifi_short_password_rejected(call) -> None:  # type: ignore[no-untyped-def]
    out = call("wifi_set", action="set", band="2g", settings={"password": "short"})
    assert any("8-63" in e for e in out["errors"])


def test_guest_wifi(apply, call, fake) -> None:  # type: ignore[no-untyped-def]
    got = call("wifi_set", action="get", band="guest")
    assert got["guest"]["guest_2g_psk_key"] == "<redacted>"
    apply("wifi_set", action="set", band="guest", settings={"enable": True, "ssid": "Visitors"})
    path, op, fields = fake.writes()[-1]
    assert path.startswith("wireless?form=guest_2g&") and op == "write"
    assert fields["guest_2g5g_ssid"] == "Visitors" and fields["guest_6g_enable"] == "on"
    assert fake.state["wireless?form=guest_2g5g"]["ssid"] == "Visitors"
    apply("wifi_set", action="set", band="guest_access", settings={"access": "on"})
    assert fake.state["wireless?form=guest"]["access"] == "on"


def test_journal_keeps_wifi_secret_for_undo(apply, rt, fake) -> None:  # type: ignore[no-untyped-def]
    done = apply("wifi_set", action="set", band="2g", settings={"password": "brand-new-pass-1"})
    assert WIFI_PSK in rt.journal.path.read_text()
    apply("router_undo", id=done["journal_id"])
    assert fake.state["wireless?form=wireless_2g"]["psk_key"] == WIFI_PSK


# ------------------------------------------------------------------ schedule
def test_wifi_schedule(apply, call, fake) -> None:  # type: ignore[no-untyped-def]
    apply("wifi_schedule", action="add", rule={"start": "22:30", "end": "6:45", "days": ["mon", "sun", "tue"]})
    rules = fake.state["wireless_schedule_v2?form=settings"]["list"]
    assert rules == [{"key": "", "enable": True, "repeat_days": "sun,mon,tue", "time_start": "22:30",
                      "time_end": "06:45", "band_list": "2g,5g,6g", "next_time": "off"}]
    rules[0]["key"] = "r1"  # the router assigns keys
    apply("wifi_schedule", action="update", key="r1", rule={"end": "07:00"})
    assert rules[0]["time_end"] == "07:00"
    apply("wifi_schedule", action="enable")
    assert fake.writes()[-1][2] == {"enable": "true"}
    apply("wifi_schedule", action="remove", key="r1")
    assert fake.state["wireless_schedule_v2?form=settings"]["list"] == []
    assert "HH:MM" in call("wifi_schedule", action="add", rule={"start": "25:00"})["error"]


# ------------------------------------------------------------------ port forwarding
def test_port_forwarding_crud(apply, call, fake) -> None:  # type: ignore[no-untyped-def]
    apply("port_forwarding", action="add", rule={"name": "nas", "external_port": 8443, "ip": "192.168.0.149",
                                                 "internal_port": 443, "protocol": "tcp"})
    assert fake.state["nat?form=vs"][0] == {"enable": "on", "protocol": "TCP", "name": "nas",
                                            "external_port": "8443", "internal_port": "443", "ipaddr": "192.168.0.149"}
    clash = call("port_forwarding", action="add", rule={"name": "x", "external_port": "8440-8450",
                                                         "ip": "192.168.0.150"})
    assert any("overlaps" in e for e in clash["errors"])
    apply("port_forwarding", action="update", name="nas", rule={"internal_port": "8443"})
    assert fake.state["nat?form=vs"][0]["internal_port"] == "8443"
    apply("port_forwarding", action="remove", name="nas")
    assert fake.state["nat?form=vs"] == []
    assert "not a device address" in call("port_forwarding", action="add",
                                          rule={"name": "y", "external_port": 1, "ip": "192.168.0.1"})["error"]


def test_dmz(apply, fake) -> None:  # type: ignore[no-untyped-def]
    out = apply("port_forwarding", kind="dmz", action="enable", ip="192.168.0.149")
    assert any("EVERY port" in w for w in out["warnings"])
    assert fake.state["nat?form=dmz"] == {"enable": "on", "ipaddr": "192.168.0.149"}


# ------------------------------------------------------------------ phase 7: system
def test_system_info_and_led(call, apply, fake) -> None:  # type: ignore[no-untyped-def]
    info = call("system")
    assert info["firmware"]["model"] == "Archer BE9300" and "led" in info
    assert call("system", action="led")["led"]["enable"] == "on"
    done = apply("system", action="led", enable=False)
    assert fake.state["ledgeneral?form=setting"]["enable"] == "off"
    assert fake.writes()[-1] == ("ledgeneral?form=setting", "write", {"enable": "off"})
    apply("router_undo", id=done["journal_id"])
    assert fake.state["ledgeneral?form=setting"]["enable"] == "on"


def test_system_reboot_critical(call, apply, fake) -> None:  # type: ignore[no-untyped-def]
    dry = call("system", action="reboot")
    assert dry["risk"] == "critical" and dry["requests"][0]["undoable"] is False
    assert call("system", action="reboot", apply=True)["applied"] is False
    apply("system", action="reboot")
    assert fake.writes()[-1] == ("system?form=reboot", "reboot", {})


def test_system_firmware_check_is_read(call, fake) -> None:  # type: ignore[no-untyped-def]
    assert call("system", action="firmware_check")["result"] == {"latest": True}
    assert fake.writes() == []


def test_device_priority(apply, fake) -> None:  # type: ignore[no-untyped-def]
    apply("system", action="set_device_priority", mac=PHONE_MAC, enable=True, time_period="1h")
    row = fake.state["smart_network?form=device_priority"][0]
    assert row["enablePriority"] is True and row["timePeriod"] == "1h"


def test_firewall_off_is_critical(call) -> None:  # type: ignore[no-untyped-def]
    assert call("system", action="firewall", settings={"enable": False})["risk"] == "critical"
    assert call("system", action="firewall", settings={"wan_ping": True})["risk"] == "normal"
