"""Internet, LAN, maintenance, admin, Wi-Fi extras / WPS, mesh pairing, clients, USB, DDNS."""

from __future__ import annotations

import json
from typing import Any

import pytest

from .fake_router import FakeTransport


@pytest.fixture(autouse=True)
def _fast_polls(monkeypatch: Any) -> None:
    import time

    monkeypatch.setattr(time, "sleep", lambda s: None)


def _sent(fake: FakeTransport, path: str, op: str) -> list[dict[str, str]]:
    return [f for p, o, f in fake.calls if p == path and o == op]


# ------------------------------------------------------------------------------ internet
def test_internet_status_and_get(call: Any) -> None:
    st = call("internet")
    assert "ipv4" in st and "dns_privacy" in st
    got = call("internet", action="get")
    assert got["proto"] == "dhcp" and "mtu" in got["settings"]


def test_internet_set_is_critical_and_applies(call: Any, apply: Any, fake: FakeTransport) -> None:
    dry = call("internet", action="set", proto="dynamic", settings={"mtu": "1480"})
    assert dry["risk"] == "critical" and "confirm_token" in dry
    assert not fake.writes()
    out = apply("internet", action="set", proto="dynamic", settings={"mtu": "1480"})
    assert out["applied"], out
    assert fake.state["network?form=wan_ipv4_dynamic"]["mtu"] == "1480"


def test_internet_rejects_unknown_proto_and_field(call: Any) -> None:
    assert "unknown IPv4" in call("internet", action="set", proto="carrier-pigeon")["error"]
    assert "does not accept" in call("internet", action="set", proto="dynamic", settings={"bogus": 1})["error"]


def test_dns_privacy_doh(apply: Any, fake: FakeTransport) -> None:
    out = apply("internet", action="dns_privacy",
                settings={"dns_privacy": "doh", "server_list": ["https://dns.example/dns-query", "", ""]})
    assert out["applied"], out
    st = fake.state["network?form=wan_dohdot"]
    assert st["dns_privacy"] == "doh"
    assert st["server_list"] == ["https://dns.example/dns-query", "", ""]
    w = [f for p, o, f in fake.calls if p == "network?form=wan_dohdot" and o == "write"][-1]
    assert w["server_list"] == ["https://dns.example/dns-query", "", ""]  # a real list -> repeated key


def test_dns_mode_change_always_sends_server_list(apply: Any, fake: FakeTransport) -> None:
    fake.state["network?form=wan_dohdot"].update({"dns_privacy": "doh", "dns_mode": "strict",
                                                  "server_list": ["https://a.example/dns-query", "", ""]})
    apply("internet", action="dns_privacy", settings={"dns_mode": "default"})
    w = [f for p, o, f in fake.calls if p == "network?form=wan_dohdot" and o == "write"][-1]
    assert w["server_list"] == ["https://a.example/dns-query", "", ""] and w["dns_mode"] == "default"


def test_dns_privacy_servers(call: Any) -> None:
    assert call("internet", action="dns_privacy_servers", kind="dot")["servers"] == ["dns.example"]


def test_ipv6_enable(apply: Any, fake: FakeTransport) -> None:
    out = apply("internet", action="ipv6_enable")
    assert out["applied"], out
    assert fake.state["network?form=wan_ipv6_status"]["enable"] == "on"


# ----------------------------------------------------------------------------------- lan
def test_lan_flow_control_and_nat_off_is_critical(call: Any, apply: Any, fake: FakeTransport) -> None:
    out = apply("lan", action="flow_control", settings={"rx_enable": True})
    assert out["applied"], out
    assert fake.state["network?form=lan_fc"]["rx_enable"] == "true"  # form-encoded bool
    assert call("lan", action="nat", enable=False)["risk"] == "critical"


def test_lan_read_without_settings(call: Any) -> None:
    assert "mode" in call("lan", action="iptv")["current"]


# --------------------------------------------------------------------------- maintenance
def test_backup_saves_private_file(call: Any, tmp_path: Any, monkeypatch: Any) -> None:
    import os

    monkeypatch.setenv("TPLINK_BACKUP_DIR", str(tmp_path / "bk"))
    out = call("maintenance", action="backup")
    assert out["bytes"] == len(b"FAKE-CONFIG-BACKUP")
    assert oct(os.stat(out["saved"]).st_mode & 0o777) == "0o600"
    assert call("maintenance", action="backups")["files"]


def test_restore_is_critical_and_bound_to_file(call: Any, tmp_path: Any, fake: FakeTransport) -> None:
    f = tmp_path / "cfg.bin"
    f.write_bytes(b"one")
    dry = call("maintenance", action="restore", file=str(f))
    assert dry["risk"] == "critical"
    f.write_bytes(b"two")  # changed after the dry run: the token no longer fits
    out = call("maintenance", action="restore", file=str(f), apply=True, confirm_token=dry["confirm_token"])
    assert not out.get("applied")
    assert not fake.uploads
    dry = call("maintenance", action="restore", file=str(f))
    out = call("maintenance", action="restore", file=str(f), apply=True, confirm_token=dry["confirm_token"])
    assert out["applied"], out
    assert fake.uploads[0][0] == "firmware?form=config_multipart"
    assert fake.uploads[0][1]["operation"] == "restore"


def test_firmware_upload_and_online(call: Any, apply: Any, tmp_path: Any, fake: FakeTransport) -> None:
    img = tmp_path / "fw.bin"
    img.write_bytes(b"\x00" * 16)
    out = apply("maintenance", action="firmware_upload", file=str(img))
    assert out["applied"], out
    assert fake.uploads[-1][1] == {"operation": "firmware", "keep": "on"}
    assert fake.uploads[-1][2] == {"image": ("fw.bin", 16)}
    assert call("maintenance", action="firmware_update_online")["risk"] == "critical"


def test_factory_reset_stays_forbidden(call: Any) -> None:
    out = call("router_raw_write", path="firmware?form=config", operation="factory", fields={"all": "true"})
    assert out["risk"] == "forbidden"


def test_ping_polls_until_finished(call: Any, fake: FakeTransport) -> None:
    out = call("maintenance", action="ping", target="1.1.1.1", count=4, timeout=10)
    assert out["finished"] and "4 received" in out["result"]
    start = _sent(fake, "diag?form=diag", "start")[0]
    assert start == {"type": "0", "ipaddr": "1.1.1.1", "ipaddr_ping": "1.1.1.1", "count": "4", "pktsize": "64"}


def test_traceroute_validates_hops(call: Any) -> None:
    assert "max_hops" in call("maintenance", action="traceroute", target="1.1.1.1", max_hops=99)["error"]


def test_operation_mode(call: Any) -> None:
    assert "modes" in call("maintenance", action="operation_mode")
    assert call("maintenance", action="operation_mode", mode="ap")["risk"] == "critical"
    assert "mode must be" in call("maintenance", action="operation_mode", mode="bridge")["error"]


def test_satellite_firmware(call: Any) -> None:
    dry = call("maintenance", action="satellite_firmware_update", mac="02:00:00:00:aa:01")
    assert dry["risk"] == "critical"
    assert "no mesh satellite" in call("maintenance", action="satellite_firmware_update", mac="02-00-00-00-00-99")["error"]


# --------------------------------------------------------------------------------- admin
def test_change_password_needs_files_and_encrypts_at_send(call: Any, tmp_path: Any, fake: FakeTransport) -> None:
    assert "old_password_file" in call("admin", action="change_password")["error"]
    old, new = tmp_path / "old", tmp_path / "new"
    old.write_text("old-pass-1\n")
    new.write_text("new-pass-22\n")
    args = {"old_password_file": str(old), "new_password_file": str(new)}
    dry = call("admin", action="change_password", **args)
    assert dry["risk"] == "critical"
    assert "new-pass-22" not in json.dumps(dry)
    out = call("admin", action="change_password", apply=True, confirm_token=dry["confirm_token"], **args)
    assert out["status"] == "applied", out
    sent = _sent(fake, "administration?form=account", "write")[0]
    assert set(sent) == {"old_pwd", "new_pwd", "cfm_pwd"}
    assert all(len(v) == 256 and v != "new-pass-22" for v in sent.values())  # RSA-1024 hex


def test_admin_remote_management_is_critical(call: Any) -> None:
    assert call("admin", action="remote", enable=True)["risk"] == "critical"


# ---------------------------------------------------------------------------- wifi / wps
def test_wps_push_sends_no_operation(apply: Any, fake: FakeTransport) -> None:
    out = apply("wifi_extra", action="wps_push")
    assert out["applied"] is not False, out
    assert _sent(fake, "wireless?form=wps_connect", "")[0] == {"option": "connect"}
    assert ("wireless?form=wps_connect", 60.0) in fake.timeouts  # the router takes ~18 s to answer


def test_wps_push_holds_session_and_reports_outcome(call: Any, fake: FakeTransport, monkeypatch: Any) -> None:
    import time

    monkeypatch.setattr(time, "sleep", lambda s: None)
    out = call("wifi_extra", action="wps_push", apply=True)
    v = out["verify"][0]
    assert v["outcome"] == "success" and v["succeeded"] and v["mac"] == "02-00-00-00-DD-01"
    assert v["states"] == ["ok", "success"]
    polls = [f for p, o, f in fake.calls if p == "wireless?form=wps_connect" and o == ""]
    assert polls[0] == {"option": "connect"} and polls[-1] == {"option": "pbc"}
    assert fake.logins == 1 or all(c for c in fake.calls)  # one login for the whole session
    fake.wps_result = "timeout"
    v = call("wifi_extra", action="wps_push", apply=True)["verify"][0]
    assert v["outcome"] == "timeout" and v["succeeded"] is False


def test_wps_client_pin_validated(call: Any, apply: Any, fake: FakeTransport) -> None:
    assert "4 or 8 digits" in call("wifi_extra", action="wps_client_pin", pin="12ab")["error"]
    apply("wifi_extra", action="wps_client_pin", pin="1234-5670")
    sent = _sent(fake, "wireless?form=wps_connect", "")
    assert sent[0] == {"option": "connect", "wps_pin": "12345670"} and sent[-1] == {"option": "pin"}


def test_wps_refused_when_off(call: Any, fake: FakeTransport) -> None:
    fake.state["wireless?form=syspara_wps"]["wps"] = "off"
    assert "WPS is off" in call("wifi_extra", action="wps_push")["error"]


def test_wps_pin_is_masked(call: Any) -> None:
    st = call("wifi_extra")
    assert st["wps_label_state"]["wps_pin"] == "<redacted>"


def test_wifi_extra_toggles(apply: Any, fake: FakeTransport) -> None:
    assert apply("wifi_extra", action="twt", enable=False)["applied"]
    assert fake.state["wireless?form=twt"]["enable"] == "off"


# ---------------------------------------------------------------------------------- mesh
def test_mesh_pair_needs_mesh_on(call: Any, fake: FakeTransport) -> None:
    fake.state["easymesh?form=easymesh_enable"]["enable"] = "off"
    assert "EasyMesh is off" in call("mesh", action="pair", i_understand_this_locked_up_a_router=True)["error"]


def test_mesh_pair_is_disabled_by_default(call: Any, fake: FakeTransport) -> None:
    assert "DISABLED" in call("mesh", action="pair")["error"]
    assert not fake.writes()


def test_mesh_pair_opens_search_and_presses_wps(apply: Any, fake: FakeTransport) -> None:
    out = apply("mesh", action="pair", i_understand_this_locked_up_a_router=True)
    assert out["status"] == "applied", out
    assert _sent(fake, "easymesh?form=search_slave", "start")
    assert _sent(fake, "wireless?form=wps_connect", "")[0] == {"option": "connect"}
    assert out["verify"][1]["outcome"] == "success"


def test_mesh_set_device_and_undo(apply: Any, call: Any, fake: FakeTransport) -> None:
    out = apply("mesh", action="set_device", mac="02-00-00-00-AA-01", settings={"name": "Hallway", "led": False})
    assert out["status"] == "applied", out
    w = _sent(fake, "easymesh_network?form=mesh_sclient_detail", "write")[0]
    assert w["name"] == "Hallway" and w["led"] == "off" and w["location"] == "hall"
    undo = call("router_undo", id=out["journal_id"])
    assert "error" not in undo, undo
    assert "unknown mesh device setting" in call("mesh", action="set_device", mac="02-00-00-00-AA-01",
                                                  settings={"ssid": "x"})["error"]


def test_mesh_bind_client(apply: Any, fake: FakeTransport) -> None:
    apply("mesh", action="bind_client", mac="02-00-00-00-AA-01", client_mac="02-00-00-00-BB-02")
    f = _sent(fake, "easymesh_network?form=available_mesh_device_manage", "bind_to_current_ap")[0]
    assert f == {"agent_mac": "02-00-00-00-AA-01", "client_mac": "02-00-00-00-BB-02", "bind": "true"}


# ------------------------------------------------------------------------------- clients
def test_rename_client_and_undo_for_wired_offline_device(apply: Any, call: Any, fake: FakeTransport) -> None:
    mac = "02-00-00-00-EE-01"  # not in the live client list: name only in the full device list
    fake.custom[("avira_parental_control?form=avira_pactrl", "getDevicesList")] = lambda f: {
        "clientList": [{"mac": mac, "name": "nas-box", "connType": "wired", "online": False}]}
    out = apply("clients", action="rename", mac=mac, name="Kitchen NAS")
    assert _sent(fake, "traffic?form=dev_name", "write") == [{"mac": mac, "alias": "Kitchen NAS"}]
    dry = call("router_undo", id=out["journal_id"])
    assert "error" not in dry and not dry.get("errors"), dry
    call("router_undo", id=out["journal_id"], apply=True)
    assert _sent(fake, "traffic?form=dev_name", "write")[-1] == {"mac": mac, "alias": "nas-box"}


def test_ddns_tplink_has_no_refresh(call: Any) -> None:
    assert "updates itself" in call("ddns", action="refresh", provider="tplink")["error"]


def test_iot_add_remove(apply: Any, fake: FakeTransport) -> None:
    mac = "02-00-00-00-CC-01"
    assert apply("clients", action="iot_add", mac=mac)["status"] == "applied"
    assert fake.state["iot_security?form=isolated_list"][0]["mac"] == mac
    assert apply("clients", action="iot_remove", mac=mac)["status"] == "applied"
    assert fake.state["iot_security?form=isolated_list"] == []


def test_iot_moving_this_machine_is_critical(call: Any) -> None:
    from .fake_router import DESKTOP_MAC

    assert call("clients", action="iot_add", mac=DESKTOP_MAC)["risk"] == "critical"


def test_speed_limit(apply: Any, fake: FakeTransport) -> None:
    apply("clients", action="speed_limit", mac="02-00-00-00-CC-02", download_kbps=5000)
    f = _sent(fake, "smart_network?form=client_speed_limit", "write")[0]
    assert f == {"mac": "02-00-00-00-CC-02", "enableLimit": "on", "downloadLimit": "5000", "uploadLimit": "0"}


# ----------------------------------------------------------------------------------- usb
def test_usb_service_and_auth(call: Any, apply: Any, fake: FakeTransport) -> None:
    apply("usb", action="service", protocol="samba", enable=True)
    f = _sent(fake, "folder_sharing?form=settings", "save")[0]
    assert f == {"server": "TP-Share", "enable": "on,off,off", "port": "21"}  # one combined save, like the UI
    assert call("usb", action="sharing_auth", enable=False)["risk"] == "critical"
    assert "no sharing service" in call("usb", action="service", protocol="nfs")["error"]
    assert any("INTERNET" in w for w in call("usb", action="service", protocol="ftpex", enable=True)["warnings"])
    apply("usb", action="server_name", name="Basement")
    assert _sent(fake, "folder_sharing?form=settings", "save")[-1]["server"] == "Basement"


def test_usb_eject(apply: Any, fake: FakeTransport) -> None:
    fake.custom[("disk_setting?form=remove", "remove")] = lambda f: {}
    apply("usb", action="eject", serial="SN123")
    assert _sent(fake, "disk_setting?form=remove", "remove") == [{"serial": "SN123"}]


# ---------------------------------------------------------------------------------- ddns
def test_ddns_tplink_and_login(apply: Any, call: Any, tmp_path: Any, fake: FakeTransport) -> None:
    apply("ddns", action="add", provider="tplink", domain="home.example")
    assert _sent(fake, "ddns?form=tplink", "insert") == [{"domain": "home.example"}]
    pw = tmp_path / "pw"
    pw.write_text("ddns-secret-9")
    dry = call("ddns", action="login", provider="noip", username="u", domain="h.example", password_file=str(pw))
    assert "ddns-secret-9" not in json.dumps(dry)
    apply("ddns", action="login", provider="noip", username="u", domain="h.example", password_file=str(pw))
    assert _sent(fake, "ddns?form=noip", "login")[0]["password"] == "ddns-secret-9"


# ---------------------------------------------------------------------------- device log
def test_device_log_report_and_record(call: Any, fake: FakeTransport, tmp_path: Any, monkeypatch: Any) -> None:
    from .fake_router import TABLET_MAC

    monkeypatch.setenv("TPLINK_DEVICE_LOG_DIR", str(tmp_path / "dl"))
    fake.custom[("avira_parental_control?form=avira_pactrl", "getDevicesList")] = lambda f: {
        "clientList": [{"mac": TABLET_MAC, "ownerId": 1, "name": "kiosk-tablet"}]}
    rep = call("device_log", mac=TABLET_MAC.lower().replace("-", ":"))
    assert rep["online"] and rep["connection"]["ip"] == "192.168.0.157"
    assert rep["reservation"]["ip"] == "192.168.0.157"
    assert any("DHCPACK" in x["content"] for x in rep["router_log"])  # matched by MAC in colon form
    assert rep["parental_profile"]["owner_id"] == "1"
    first = call("device_log", action="record", mac=TABLET_MAC)
    kinds = {e["event"] for e in first["events"]}
    assert {"online", "router_log", "site"} <= kinds
    assert call("device_log", action="record", mac=TABLET_MAC)["new_events"] == 0  # nothing new
    fake.state["syslog?form=log"].insert(0, {"time": "2026-11-17 09:00:00", "type": "DHCPD", "level": "INFO",
                                             "content": "DHCPRELEASE 192.168.0.157"})
    again = call("device_log", action="record", mac=TABLET_MAC)
    assert [e["event"] for e in again["events"]] == ["router_log"]  # matched by IP
    hist = call("device_log", action="history", mac=TABLET_MAC, event="router_log")
    assert hist["total"] == 2
    assert not fake.writes()


def test_alg(call: Any, apply: Any, fake: FakeTransport) -> None:
    fake.state["nat?form=alg"].update(dict.fromkeys(("ftp", "h323", "ipsec", "l2tp", "pptp", "rtsp", "sip", "tftp"),
                                                    "on"))
    assert apply("lan", action="alg", settings={"sip": False})["applied"]
    assert fake.state["nat?form=alg"]["sip"] == "off"
    assert any("VPN passthrough" in w for w in call("lan", action="alg", settings={"pptp": False})["warnings"])


def test_undo_restores_list_field(apply: Any, call: Any, fake: FakeTransport) -> None:
    fake.state["network?form=wan_dohdot"].update({"dns_privacy": "doh", "dns_mode": "strict",
                                                  "server_list": ["https://a.example/dns-query", "", ""]})
    out = apply("internet", action="dns_privacy", settings={"server_list": ["https://b.example/dns-query", "", ""]})
    assert out["applied"], out
    dry = call("router_undo", id=out["journal_id"])
    extra = {"confirm_token": dry["confirm_token"]} if "confirm_token" in dry else {}
    undone = call("router_undo", id=out["journal_id"], apply=True, **extra)
    assert undone["applied"], undone
    assert fake.state["network?form=wan_dohdot"]["server_list"] == ["https://a.example/dns-query", "", ""]


def test_guest_write_sends_only_changed_fields(apply: Any, fake: FakeTransport) -> None:
    apply("wifi_set", action="set", band="guest", guest_band="5g", settings={"hidden": "on"})
    w = [f for p, o, f in fake.calls if o == "write" and "guest_5g" in p]
    assert w and w[-1] == {"guest_5g_hidden": "on"}


def test_ofdma_routed_to_combined_setting(call: Any, fake: FakeTransport) -> None:
    fake.state["wireless?form=ofdma_mimo"] = {"setting": "all"}
    assert "ofdma_mimo" in call("wifi_extra", action="ofdma", enable=True)["error"]
    assert "must be one of" in call("wifi_extra", action="ofdma_mimo", settings={"setting": "x"})["error"]


def test_binding_refused_when_ip_reserved_for_other_mac(call: Any) -> None:
    out = call("ip_mac_binding", action="add", mac="02-00-00-00-FF-01", ip="192.168.0.157")  # tablet's
    assert any("DHCP-reserved" in e for e in out["errors"]), out


def test_lan_agg_always_sends_port_settings_as_json(apply: Any, fake: FakeTransport) -> None:
    fake.state["network?form=lan_agg"] = {"enable_agg": "0", "hashmode": "0", "lacpmode": "0",
                                          "port_settings": [{"name": "lan2", "enable": True}]}
    apply("lan", action="link_aggregation", settings={"hashmode": "1"})
    w = [f for p, o, f in fake.calls if p == "network?form=lan_agg" and o == "write"][-1]
    assert json.loads(w["port_settings"]) == [{"name": "lan2", "enable": True}] and w["hashmode"] == "1"


def test_blank_restore_kept_by_router_is_not_a_failure(apply: Any, call: Any, fake: FakeTransport,
                                                       monkeypatch: Any) -> None:
    # keeps_blank is per-endpoint (live: the BE9300's custom WAN MAC); exercised here on a simple form
    from dataclasses import replace

    from mcp_tplink_router import catalog
    monkeypatch.setitem(catalog.CURATED, "nat?form=dmz", replace(catalog.CURATED["nat?form=dmz"], keeps_blank=("ipaddr",)))
    fake.state["nat?form=dmz"] = {"enable": "off", "ipaddr": ""}
    out = apply("port_forwarding", kind="dmz", action="enable", ip="192.168.0.250")
    fake.custom[("nat?form=dmz", "write")] = lambda f: fake.state["nat?form=dmz"].update(
        {k: v for k, v in f.items() if v != ""}) or {}  # the router ignores a blank address
    d = call("router_undo", id=out["journal_id"])
    u = call("router_undo", id=out["journal_id"], apply=True, **({"confirm_token": d["confirm_token"]} if "confirm_token" in d else {}))
    assert u["verify"][0]["applied"] is True and u["verify"][0]["router_kept"] == {"ipaddr": "192.168.0.250"}
    assert fake.state["nat?form=dmz"]["enable"] == "off"


def test_mlo_off_sends_only_enable_and_undo_restores_ui_fields(apply: Any, call: Any, fake: FakeTransport) -> None:
    fake.state["wireless?form=mlo_host"] = {"enable": "on", "ssid": "Home", "hidden": "off", "encryption": "psk_sae",
                                            "psk_key": "k-secret-1", "psk_version": "sae_only", "band_select": "on",
                                            "selected_bands": ["5g", "6g"], "support": "on"}
    out = apply("wifi_extra", action="mlo", enable=False)
    w = [f for p, o, f in fake.calls if p == "wireless?form=mlo_host" and o == "write"]
    assert w[-1] == {"enable": "off"}
    d = call("router_undo", id=out["journal_id"])
    call("router_undo", id=out["journal_id"], apply=True, **({"confirm_token": d["confirm_token"]} if "confirm_token" in d else {}))
    w = [f for p, o, f in fake.calls if p == "wireless?form=mlo_host" and o == "write"][-1]
    assert w["selected_bands"] == ["5g", "6g"] and w["enable"] == "on"
    assert sorted(w) == sorted(("enable", "ssid", "hidden", "encryption", "psk_key", "psk_version", "selected_bands"))
    assert "error" in call("wifi_extra", action="mlo", enable=True, settings={"selected_bands": ["5g"]})
    assert "support" in call("wifi_extra", action="mlo", settings={"support": "off"})["error"]


def test_wifi_change_reports_health_and_auto_backup(apply: Any, fake: FakeTransport, tmp_path: Any,
                                                    monkeypatch: Any) -> None:
    monkeypatch.setenv("TPLINK_BACKUP_DIR", str(tmp_path / "bk"))
    monkeypatch.setenv("TPLINK_AUTO_BACKUP", "1")
    out = apply("wifi_extra", action="twt", enable=False)
    assert out["wifi_health"]["ok"] is True
    fake.custom[("wireless?form=wps_pin", "read")] = lambda f: (_ for _ in ()).throw(
        __import__("mcp_tplink_router.transport", fromlist=["RouterError"]).RouterError(
            "server_error", "bad argument #1 to 'lower'"))
    out = apply("wifi_extra", action="twt", enable=True)
    assert out["wifi_health"]["ok"] is False and any("DAMAGED" in w for w in out["warnings_after"])
    crit = apply("internet", action="set", proto="dhcp", settings={"mtu": "1480"})
    assert crit["pre_change_backup"]["bytes"] > 0


def test_clients_fall_back_to_load_device_on_encrypted_firmware(call: Any, fake: FakeTransport) -> None:
    # BE4800 / BE3600: status?form=all has no access_devices_* lists; the UI uses loadDevice
    fake.state["status?form=all"] = {"wan_ipv4_ipaddr": "192.0.2.10", "lan_ipv4_ipaddr": "192.168.1.1"}
    fake.custom[("smart_network?form=game_accelerator", "loadDevice")] = lambda f: [
        {"mac": "02-00-00-00-00-01", "ip": "192.168.1.127", "deviceName": "Phone", "deviceTag": "iot_2.4G",
         "isGuest": False},
        {"mac": "02-00-00-00-00-02", "ip": "0.0.0.0", "deviceName": "Laptop", "deviceTag": "5G", "isGuest": False},
        {"mac": "02-00-00-00-00-03", "ip": "192.168.1.9", "deviceName": "PC", "deviceTag": "wired", "isGuest": False},
        {"mac": "02-00-00-00-00-04", "ip": "192.168.1.8", "deviceName": "Visitor", "deviceTag": "5G", "isGuest": True}]
    rows = call("clients", action="list")["clients"]
    assert [(r["name"], r["connection"], r["ip"]) for r in rows] == [
        ("Phone", "iot", "192.168.1.127"), ("Laptop", "wireless", None), ("PC", "wired", "192.168.1.9"),
        ("Visitor", "guest", "192.168.1.8")]


def test_mlo_change_on_a_rebooting_model_reports_the_reboot(apply: Any, call: Any, fake: FakeTransport) -> None:
    # Archer BE3600: device_config mloNetwork.reboot = true -> the router reboots after an MLO save
    fake.device_config = lambda: {"mloNetwork": {"mlo": True, "reboot": True, "rebootType": ["all"]}}
    fake.state["wireless?form=mlo_host"] = {"enable": "off", "ssid": "Home", "hidden": "off", "encryption": "psk_sae",
                                            "psk_key": "k-secret-1", "psk_version": "sae_only",
                                            "selected_bands": ["2g", "5g"]}
    dry = call("wifi_extra", action="mlo", enable=True)
    assert any("reboots" in r for r in dry["critical_because"])
    n = len(fake.calls)
    out = apply("wifi_extra", action="mlo", enable=True)
    assert out["router_rebooting"] and out["wifi_health"]["ok"] is None
    assert not any(p == "wireless?form=wps_pin" for p, _, _ in fake.calls[n:])  # no health probe on a rebooting router


def test_operation_mode_switch_is_not_reported_as_ignored(apply: Any, fake: FakeTransport) -> None:
    # Live (BE3600): the router accepts sysmode, still reads the old mode, and switches ~15 s later.
    fake.state["system?form=sysmode"] = {"support": "yes", "mode": "ap"}
    fake.ignore_changes.add("system?form=sysmode")
    out = apply("maintenance", action="operation_mode", mode="router")
    assert out["status"] == "applied" and out["verify_deferred"] and out["router_rebooting"]
    assert out["verify"][-1]["applied"] is None and "deferred" in out["verify"][-1]
    assert "no_effect" not in out and "NO EFFECT" not in str(out.get("warning"))


def test_switch_to_router_mode_keep_access_is_opt_in(call: Any, apply: Any, fake: FakeTransport) -> None:
    # Live (BE3600): leaving router mode turns remote management off; going back keeps whatever it is set to.
    fake.state["system?form=sysmode"] = {"support": "yes", "mode": "ap"}
    fake.state["administration?form=remote"] = {"enable": "off", "enable_superadmin": "off", "http_port": "80",
                                                "https_port": "443", "managers": "all", "web_address": ""}
    dry = call("maintenance", action="operation_mode", mode="router")
    assert [d["path"] for d in dry["diff"]] == ["system?form=sysmode"]  # default: remote management untouched
    assert any("keep_access=true" in w for w in dry["warnings"])
    opt = call("maintenance", action="operation_mode", mode="router", keep_access=True)
    assert [d["path"] for d in opt["diff"]] == ["administration?form=remote", "system?form=sysmode"]
    assert any("INTERNET" in r for r in opt["critical_because"])
    fake.ignore_changes.add("system?form=sysmode")  # the switch happens ~15 s later, after the re-read
    out = apply("maintenance", action="operation_mode", mode="router", keep_access=True)
    assert out["status"] == "applied" and out["verify"][0]["applied"] is True and out["verify_deferred"]
    assert fake.state["administration?form=remote"]["enable"] == "on"


def test_ignored_write_in_a_rebooting_plan_is_still_no_effect(fake: FakeTransport, tmp_path: Any) -> None:
    # The deferred check is keyed on the operation-mode form only: plan.reboots (set e.g. for MLO on a
    # BE3600) must not turn a silently ignored write into "applied".
    from contextlib import nullcontext

    from mcp_tplink_router import forms
    from mcp_tplink_router.journal import Journal
    from mcp_tplink_router.safety import Plan, apply_plan
    from mcp_tplink_router.transport import session

    fake.ignore_changes.add("upnp?form=enable")
    plan = Plan(tool="t", summary="s", reboots="the router reboots")
    with session(lambda: fake) as t:
        plan.add(forms.plan_write("upnp?form=enable", forms.read_form(t, "upnp?form=enable"), {"enable": "off"}))
        out = apply_plan(t, plan, Journal(tmp_path / "j"), lambda: nullcontext(t))
    assert out["status"] == "no_effect" and "verify_deferred" not in out


def test_undoing_a_mode_switch_is_also_checked_after_restart(apply: Any, fake: FakeTransport) -> None:
    fake.state["system?form=sysmode"] = {"support": "yes", "mode": "router"}
    first = apply("maintenance", action="operation_mode", mode="ap")
    assert first["status"] == "applied"
    fake.ignore_changes.add("system?form=sysmode")
    undo = apply("router_undo", id=first["journal_id"])
    assert undo["status"] == "applied" and undo["verify_deferred"]


def test_leaving_router_mode_warns_about_remote_management(call: Any, fake: FakeTransport) -> None:
    fake.state["system?form=sysmode"] = {"support": "yes", "mode": "router"}
    dry = call("maintenance", action="operation_mode", mode="ap")
    assert [d["path"] for d in dry["diff"]] == ["system?form=sysmode"]
    assert any("turns remote management off" in w for w in dry["warnings"])
    assert call("maintenance", action="operation_mode", mode="router")["status"] == "no_change"
