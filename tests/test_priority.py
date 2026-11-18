"""IP-MAC binding, UPnP, mesh, VPN server, VPN client, routing."""

from __future__ import annotations

import json

from .fake_router import DESKTOP_MAC, LAPTOP_MAC, PHONE_MAC, TABLET_MAC, VPN_PRIVATE

BINDS = "imb?form=bind_list"


# ------------------------------------------------------------------ IP-MAC binding
def test_imb_status(call) -> None:  # type: ignore[no-untyped-def]
    out = call("ip_mac_binding")
    assert out["setting"] == {"enable": "off"} and len(out["arp"]) == 2


def test_imb_enable_and_add(apply, fake) -> None:  # type: ignore[no-untyped-def]
    assert apply("ip_mac_binding", action="enable")["status"] == "applied"
    assert fake.state["imb?form=setting"]["enable"] == "on"
    out = apply("ip_mac_binding", action="add", mac="00:00:5e:00:53:16", ip="192.168.0.157", name="tablet")
    assert out["status"] == "applied"
    assert fake.state[BINDS][0] == {"mac": TABLET_MAC, "ipaddr": "192.168.0.157", "name": "tablet",
                                    "description": "", "enable": "on"}


def test_imb_bind_current_and_update_is_remove_insert(apply, fake) -> None:  # type: ignore[no-untyped-def]
    apply("ip_mac_binding", action="bind_current", ip="192.168.0.157")
    out = apply("ip_mac_binding", action="update", mac=TABLET_MAC, ip="192.168.0.158")
    assert [d["action"] for d in out["diff"]] == ["remove", "insert"]
    assert fake.state[BINDS][0]["ipaddr"] == "192.168.0.158"


def test_imb_binding_own_mac_elsewhere_is_critical(call) -> None:  # type: ignore[no-untyped-def]
    out = call("ip_mac_binding", action="add", mac=DESKTOP_MAC, ip="192.168.0.170")
    assert out["risk"] == "critical" and "THIS machine" in out["critical_because"][0]
    same = call("ip_mac_binding", action="add", mac=DESKTOP_MAC, ip="192.168.0.160")
    assert same["risk"] == "normal"


# ------------------------------------------------------------------------- UPnP
def test_upnp(call, apply, fake) -> None:  # type: ignore[no-untyped-def]
    st = call("upnp")
    assert st["enabled"] is True and st["mappings"][0]["name"] == "game"
    out = apply("upnp", action="disable")
    assert any("mapping" in w for w in out["warnings"]) and fake.state["upnp?form=enable"]["enable"] == "off"


# ------------------------------------------------------------------------- mesh
def test_mesh_actions(call, apply, fake) -> None:  # type: ignore[no-untyped-def]
    assert call("mesh")["setting"]["enable"] == "on"
    assert call("mesh", action="disable")["risk"] == "normal"  # no satellites in the fake
    fake.state["easymesh_network?form=get_mesh_device_list_all"] = {"list": [{"mac": "AA-00-00-00-00-09"}]}
    assert call("mesh", action="disable")["risk"] == "critical"
    out = call("mesh", action="reboot_satellite", mac="aa:00:00:00:00:09")
    assert out["risk"] == "critical"
    done = apply("mesh", action="reboot_satellite", mac="aa:00:00:00:00:09")
    assert done["status"] == "applied"
    assert fake.writes()[-1] == ("easymesh_network?form=available_mesh_device_manage", "reboot",
                                 {"mac": "AA-00-00-00-00-09"})


# ------------------------------------------------------------------- VPN server
def test_vpn_server_get_redacts(call) -> None:  # type: ignore[no-untyped-def]
    out = call("vpn_server", kind="wireguard")
    assert out["config"]["private_key"] == "<redacted>" and out["config"]["public_key"] == "WG-SERVER-PUB="
    shown = call("vpn_server", kind="wireguard", reveal=True)
    assert shown["config"]["private_key"] == "WG-SERVER-PRIV="


def test_vpn_server_enable_is_critical_and_keeps_bool_type(call, apply, fake) -> None:  # type: ignore[no-untyped-def]
    dry = call("vpn_server", kind="wireguard", action="enable")
    assert dry["risk"] == "critical" and dry["confirm_token"]
    apply("vpn_server", kind="wireguard", action="enable")
    path, op, fields = fake.writes()[-1]
    assert (path, op) == ("wireguard?form=config", "write") and fields["enable"] == "true"
    assert "private_key" not in fields  # read-only key material is never written back


def test_vpn_server_set_and_accounts(apply, call, fake) -> None:  # type: ignore[no-untyped-def]
    apply("vpn_server", kind="wireguard", action="set", settings={"listen_port": "51830"})
    assert fake.state["wireguard?form=config"]["listen_port"] == "51830"
    bad = call("vpn_server", kind="wireguard", action="set", settings={"private_key": "x"})
    assert "does not accept" in bad["error"]
    apply("vpn_server", kind="pptp", action="accounts_add", account={"username": "bob", "password": "pw-secret-1"})
    assert fake.state["pptpd?form=accounts"][0]["username"] == "bob"
    shown = call("vpn_server", kind="pptp", action="accounts")
    assert shown["accounts"][0]["password"] == "<redacted>"
    apply("vpn_server", kind="pptp", action="accounts_remove", key="bob")
    assert fake.state["pptpd?form=accounts"] == []


def test_vpn_server_connected_and_disconnect(call, apply, fake) -> None:  # type: ignore[no-untyped-def]
    conns = call("vpn_server", kind="wireguard", action="connected")["connections"]
    assert conns[0]["key"] == "c1"
    apply("vpn_server", kind="wireguard", action="disconnect", key="c1")
    assert fake.writes()[-1] == ("vpnconn?form=config", "disconnect", {"vpntype": "wireguard", "key": "c1", "index": "0"})


# ------------------------------------------------------------------- VPN client
def test_vpn_client_status_redacts_profile_keys(call) -> None:  # type: ignore[no-untyped-def]
    out = call("vpn_client")
    prof = out["profiles"][0]
    assert prof["private_key"] == "<redacted>" and prof["preshared_key"] == "<redacted>"
    assert prof["public_key"] == "PUBKEY-public=" and prof["key"] == "wg_filter"
    assert VPN_PRIVATE not in json.dumps(out)


def test_vpn_client_changes_are_critical(call) -> None:  # type: ignore[no-untyped-def]
    for args in ({"action": "update_profile", "key": "wg_filter", "profile": {"kill_switch": "off"}},
                 {"action": "remove_profile", "key": "wg_filter"},
                 {"action": "add_device", "mac": PHONE_MAC},
                 {"action": "set_device", "mac": LAPTOP_MAC, "use_vpn": False},
                 {"action": "remove_device", "mac": LAPTOP_MAC},
                 {"action": "disable"}):
        out = call("vpn_client", **args)
        assert out.get("risk") == "critical", (args, out)
        assert VPN_PRIVATE not in json.dumps(out)


def test_vpn_client_remove_active_profile_warns(call) -> None:  # type: ignore[no-untyped-def]
    out = call("vpn_client", action="remove_profile", key="wg_filter")
    assert any("ACTIVE profile" in w for w in out["warnings"])


def test_vpn_client_add_device_uses_ui_insert_fields(apply, fake) -> None:  # type: ignore[no-untyped-def]
    out = apply("vpn_client", action="add_device", mac=PHONE_MAC)
    assert out["status"] == "applied"
    path, op, fields = fake.writes()[-1]
    assert (path, op) == ("vpn?form=vpn_user_list", "insert") and "new" not in fields
    assert json.loads(fields["list"]) == [{"key": PHONE_MAC, "name": "kid-phone", "mac": PHONE_MAC,
                                           "client_type": "phone", "online": 1}]


def test_vpn_client_set_device_sends_only_ui_fields(apply, fake) -> None:  # type: ignore[no-untyped-def]
    out = apply("vpn_client", action="set_device", mac=LAPTOP_MAC, use_vpn=False)
    assert out["status"] == "applied"
    _, op, fields = fake.writes()[-1]
    assert op == "update" and fields["key"] == LAPTOP_MAC
    assert json.loads(fields["new"]) == {"name": "Filtered laptop", "mac": LAPTOP_MAC, "access": "off",
                                         "client_type": "laptop"}
    assert json.loads(fields["old"])["access"] == "on" and "server_key" not in fields["old"]


def test_vpn_client_remove_device(apply, fake) -> None:  # type: ignore[no-untyped-def]
    apply("vpn_client", action="remove_device", mac=LAPTOP_MAC)
    assert fake.state["vpn?form=vpn_user_list"] == []


def test_vpn_client_set_active_profile(apply, call, fake) -> None:  # type: ignore[no-untyped-def]
    fake.state["vpn?form=server"][0]["enable"] = "on"
    fake.state["vpn?form=server"].append({**fake.state["vpn?form=server"][0], "key": "wg_home", "enable": "off",
                                          ".name": "wg_home", "des": "Home"})
    assert call("vpn_client", action="set_active_profile", key="wg_home")["risk"] == "critical"
    out = apply("vpn_client", action="set_active_profile", key="wg_home")
    assert out["status"] == "applied", out
    assert [p["enable"] for p in fake.state["vpn?form=server"]] == ["off", "on"]


def test_vpn_client_ignored_update_is_no_effect(call, fake) -> None:  # type: ignore[no-untyped-def]
    fake.ignore_changes.add("vpn?form=vpn_user_list")
    dry = call("vpn_client", action="set_device", mac=LAPTOP_MAC, use_vpn=False)
    out = call("vpn_client", action="set_device", mac=LAPTOP_MAC, use_vpn=False, apply=True,
               confirm_token=dry["confirm_token"])
    assert out["status"] == "no_effect"


def test_vpn_client_update_profile_undo_restores_secret(apply, fake) -> None:  # type: ignore[no-untyped-def]
    done = apply("vpn_client", action="update_profile", key="wg_filter", profile={"kill_switch": "off"})
    assert fake.state["vpn?form=server"][0]["kill_switch"] == "off"
    path, op, fields = fake.writes()[-1]
    assert json.loads(fields["old"])["private_key"] == VPN_PRIVATE  # the router needs the exact old row
    assert VPN_PRIVATE not in json.dumps(done)  # ...but results never show it
    apply("router_undo", id=done["journal_id"])
    assert fake.state["vpn?form=server"][0]["kill_switch"] == "on"
    assert fake.state["vpn?form=server"][0]["private_key"] == VPN_PRIVATE


# ---------------------------------------------------------------------- routing
def test_routing_add_update_remove(apply, call, fake) -> None:  # type: ignore[no-untyped-def]
    route = {"name": "lab", "target": "10.20.0.0", "netmask": "255.255.0.0", "gateway": "192.168.0.50",
             "interface": "lan"}
    apply("routing", action="add", route=route)
    assert fake.state["network?form=routes_static"][0]["target"] == "10.20.0.0"
    assert fake.state["network?form=routes_static"][0]["interface"] == "LAN"
    assert "interface must be" in call("routing", action="add", route={**route, "name": "x", "interface": "dmz"})["error"]
    apply("routing", action="update", name="lab", route={"gateway": "192.168.0.51"})
    assert fake.state["network?form=routes_static"][0]["gateway"] == "192.168.0.51"
    apply("routing", action="remove", name="lab")
    assert fake.state["network?form=routes_static"] == []
    bad = call("routing", action="add", route={**route, "target": "192.168.0.0"})
    assert any("inside the LAN" in e for e in bad["errors"])
    assert call("routing", action="system")["routing_table"][0]["gateway"] == "203.0.113.1"


def test_tablet_untouched_by_other_tools(apply, fake) -> None:  # type: ignore[no-untyped-def]
    apply("upnp", action="disable")
    assert fake.state["dhcps?form=reservation"][0]["mac"] == TABLET_MAC


def test_live_counters_do_not_break_tokens_or_conflict_checks(call, fake) -> None:  # type: ignore[no-untyped-def]
    dry = call("vpn_client", action="update_profile", key="wg_filter", profile={"kill_switch": "off"})
    prof = fake.state["vpn?form=server"][0]
    prof["download_speed"], prof["upload_speed"], prof["status"] = 12345, 678, "connecting"
    out = call("vpn_client", action="update_profile", key="wg_filter", profile={"kill_switch": "off"},
               apply=True, confirm_token=dry["confirm_token"])
    assert out["status"] == "applied", out
    _, op, fields = fake.writes()[-1]
    assert json.loads(fields["old"])["download_speed"] == 12345  # old = the router's row right now
    assert fake.state["vpn?form=server"][0]["kill_switch"] == "off"
