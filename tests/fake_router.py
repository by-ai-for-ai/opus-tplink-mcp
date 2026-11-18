"""An in-memory BE9300 for tests.  NEVER talks to a network.

Forms and tables are seeded from ``fixtures/shapes.json`` (live field *shapes*, no values)
with concrete fake values, then overridden for the endpoints the tests care about.  It
implements the UI's ops (read/load/write/insert/update/remove/read_spf/write_spf,
multi-form paths, custom ops) with router-like errors, records every call, and can be told
to fail the next call (optionally AFTER applying it, to simulate a lost reply).
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mcp_tplink_router.transport import E_LOGIN, E_TIMEOUT, RouterError, check_fields

SHAPES = json.loads((Path(__file__).parent / "fixtures" / "shapes.json").read_text())

ROUTER_LAN = "192.168.0.1"
DESKTOP_MAC = "00-00-5E-00-53-01"  # "this machine" (wired, .160)
TABLET_MAC = "00-00-5E-00-53-16"
PHONE_MAC = "3A-11-22-33-44-55"  # locally administered (randomised)
LAPTOP_MAC = "5C-AA-BB-CC-DD-01"  # child's filtered laptop (VPN-assigned)
WIFI_PSK = "wifi-secret-123"
VPN_PRIVATE = "PRIVKEY-abc123secret="
# A throwaway 1024-bit RSA modulus (hex) for the admin-password test; not a real key.
RSA_N = format((1 << 1023) + 0x1D3B, "x")


def _fill(shape: Any) -> Any:
    if isinstance(shape, dict):
        return {k: _fill(v) for k, v in shape.items()}
    if isinstance(shape, list):
        if shape and isinstance(shape[0], dict):
            return []  # tables start empty unless overridden
        return [_fill(v) for v in shape]
    if shape == "<str>":
        return ""
    if shape == "int":
        return 0
    if shape == "float":
        return 0.0
    if shape == "bool":
        return False
    return shape


def _wifi(band: str, ssid: str) -> dict[str, Any]:
    d = {"enable": "on", "disabled": "off", "disabled_all": "off", "ssid": ssid, "hidden": "off",
         "encryption": "psk", "psk_key": WIFI_PSK, "psk_version": "auto", "psk_cipher": "aes",
         "wpa_key": "", "channel": "auto", "htmode": "auto", "hwmode": "be", "txpower": "high",
         "mu_mimo": "on", "server": "", "port": "", "current_channel": "6"}
    for i in range(1, 5):
        d[f"wep_key{i}"] = ""
    if band == "6g":
        d["psc"] = "on"
    return d


def _guest(band: str) -> dict[str, Any]:
    return {"enable": "off", "ssid": f"Home-Guest-{band}", "hidden": "off", "encryption": "psk",
            "psk_key": "guest-secret-1", "psk_version": "auto", "psk_cipher": "aes", "portal_password": "",
            "authentication_type": "", "authentication_timeout": "", "redirect": "off", "redirect_url": "",
            "passwd_cycle": "", "disabled": "off"}


def default_state() -> dict[str, Any]:
    state: dict[str, Any] = {}
    for path, entry in SHAPES.items():
        if entry.get("op"):
            shape = entry["shape"]
            # an empty table loads as {} on the real router; model it as an empty row list
            state[path] = [] if entry["op"] == "load" and shape == {} else _fill(shape)
    state.update({
        "network?form=lan_ipv4": {"ipaddr": ROUTER_LAN, "mask_type": "255.255.255.0", "custom_value": "",
                                  "lan_type": "static", "macaddr": "AA-BB-CC-00-00-01", "pri_dns": "", "snd_dns": ""},
        "dhcps?form=setting": {"enable": "on", "leasetime": "120", "pri_dns": "", "snd_dns": "",
                               "gateway": ROUTER_LAN, "ipaddr_start": "192.168.0.100",
                               "ipaddr_end": "192.168.0.249", "domain": ""},
        "dhcps?form=reservation": [
            {"mac": TABLET_MAC, "ip": "192.168.0.157", "comment": "kiosk-tablet", "hostname": "kiosk-tablet", "enable": "on"},
        ],
        "dhcps?form=client": [
            {"macaddr": TABLET_MAC, "ipaddr": "192.168.0.157", "name": "kiosk-tablet", "leasetime": "01:30:00"},
            {"macaddr": DESKTOP_MAC, "ipaddr": "192.168.0.160", "name": "desktop", "leasetime": "01:10:00"},
            {"macaddr": PHONE_MAC, "ipaddr": "192.168.0.123", "name": "kid-phone", "leasetime": "00:50:00"},
        ],
        "imb?form=setting": {"enable": "off"},
        "imb?form=bind_list": [],
        "imb?form=arp_list": [{"enable": "off", "ipaddr": "192.168.0.160", "mac": DESKTOP_MAC, "name": "desktop"},
                              {"enable": "off", "ipaddr": "192.168.0.157", "mac": TABLET_MAC, "name": "kiosk-tablet"}],
        "upnp?form=enable": {"enable": "on"},
        "upnp?form=service": [{"external_port": "5000", "internal_port": "5000", "ipaddr": "192.168.0.123",
                               "leasetime": "3600", "name": "game", "protocol": "UDP"}],
        "easymesh?form=easymesh_enable": {"enable": "on", "time": 0},
        "vpn?form=enable": {"enable": "on"},
        "vpn?form=server": [{
            ".anonymous": False, ".name": "wg_filter", ".type": "server", "key": "wg_filter", "type": "wireguard",
            "des": "Content filter", "enable": "on", "status": "connected", "address": "10.8.0.2/32",
            "allowed_ips": "0.0.0.0/0", "endpoint_address": "198.51.100.5", "endpoint_port": "51821",
            "private_key": VPN_PRIVATE, "preshared_key": "PSK-xyz789secret=", "public_key": "PUBKEY-public=",
            "kill_switch": "on", "mtu": "1420", "persistent_keepalive": "25", "manual": True, "nat": True,
            "download_speed": 0, "upload_speed": 0, "ruleindex": "0", "server": "", "vendor": "manual"}],
        "vpn?form=vpn_user_list": [{"access": "on", "client_type": "laptop", "mac": LAPTOP_MAC,
                                    "name": "Filtered laptop", "server_des": "Content filter", "server_key": "wg_filter"}],
        "vpn?form=vpn_user_devices": [{"client_type": "phone", "device_id": "d1", "mac": PHONE_MAC,
                                       "name": "kid-phone", "online": 1, "owner_id": "", "prio": "off",
                                       "prio_time": "", "time_period": ""}],
        "wireguard?form=config": {"access": "home", "address": "10.5.5.1/24", "dns": True, "enable": False,
                                  "listen_port": "51820", "persistent_keepalive": "25",
                                  "private_key": "WG-SERVER-PRIV=", "public_key": "WG-SERVER-PUB="},
        "wireguard?form=account": [],
        "network?form=routes_static": [],
        "network?form=routes_system": [{"dest": "0.0.0.0", "gateway": "203.0.113.1", "interface": "wan", "mask": "0.0.0.0"}],
        "access_control?form=enable": {"enable": "off", "host_mac": DESKTOP_MAC},
        "access_control?form=mode": {"access_mode": "black"},
        "access_control?form=black_list": [],
        "access_control?form=white_list": [],
        "nat?form=vs": [],
        "nat?form=pt": [],
        "nat?form=dmz": {"enable": "off", "ipaddr": ""},
        "smart_network?form=device_priority": [
            {"deviceName": "kid-phone", "deviceTag": "", "deviceType": "phone", "downloadSpeed": 0,
             "enableLimit": "off", "enablePriority": False, "index": 0, "key": "k1", "mac": PHONE_MAC,
             "remainTime": 0, "timePeriod": "always", "trafficUsage": 0, "uploadSpeed": 0}],
        "syslog?form=log": [
            {"time": "2026-11-17 08:00:01", "type": "DHCPD", "level": "INFO", "content": "DHCPACK 192.168.0.157 to 00:00:5e:00:53:16"},
            {"time": "2026-11-17 08:05:00", "type": "WAN", "level": "WARNING", "content": "PPP link flap"},
            {"time": "2026-11-17 07:59:00", "type": "SYSTEM", "level": "ERROR", "content": "watchdog fired"},
        ],
        "syslog?form=types": [{"name": "ALL"}, {"name": "DHCPD"}, {"name": "WAN"}],
        "wireless?form=wireless_2g": _wifi("2g", "Home"),
        "wireless?form=wireless_5g": _wifi("5g", "Home"),
        "wireless?form=wireless_6g": _wifi("6g", "Home-6E"),
        "wireless?form=guest": {"access": "off", "isolate": "on"},
        "wireless?form=smart_connect": {"smart_enable": "off"},
        "wireless_schedule_v2?form=settings": {"enable": False, "list": [], "max_rules": 10},
        "firmware?form=upgrade": {"firmware_version": "1.1.0 Build 20250101", "hardware_version": "Archer BE9300 v1",
                                  "is_default": False, "model": "Archer BE9300", "totaltime": 0,
                                  "upgraded": False, "upgradetime": 0},
    })
    state.update({
        "wireless?form=syspara_wps": {"wps": "on", "wait_time": "120"},
        "wireless?form=wps_connect": {"wps_timeout": 120, "available": True, "disabled": "off"},
        "wireless?form=wps_pin": {"wps_label": "on", "wps_pin": "12345670", "lock_2g": "unlock"},
        "afc?form=settings": {"enable": "off"},
        "reboot?form=set": {"enable": "off", "cycle": "week", "time": "03:00", "day": "Mon"},
        "iot_security?form=isolated_list": [],
        "folder_sharing?form=settings": [
            {"edit": False, "enable": "off", "key": 1, "link": "", "port": "---", "protocol": "samba"},
            {"edit": False, "enable": "off", "key": 2, "link": "", "port": 21, "protocol": "ftp"},
            {"edit": True, "enable": "off", "key": 3, "link": "", "port": "21", "protocol": "ftpex"}],
        "folder_sharing?form=server": {"server": "TP-Share"},
        "ddns?form=tplink": [],
        "administration?form=account": {"old_acc": "admin", "new_acc": "admin",
                                        "old_pwd": [RSA_N, "010001"], "new_pwd": [RSA_N, "010001"],
                                        "cfm_pwd": [RSA_N, "010001"]},
    })
    state["network?form=wan_ipv4_status"].update({"conntype": "dhcp"})
    state["network?form=wan_ipv4_dynamic"].update({"conntype": "dhcp", "mtu": "1500", "hostname": "router"})
    state["network?form=wan_dohdot"].update({"dns_privacy": "none", "dns_mode": "default", "server_list": []})
    for b in ("2g", "5g", "2g5g", "6g"):
        state[f"wireless?form=guest_{b}"] = _guest(b)
    st = state["status?form=all"]
    st.update({"lan_ipv4_ipaddr": ROUTER_LAN, "lan_ipv4_netmask": "255.255.255.0", "wan_ipv4_ipaddr": "203.0.113.7",
               "wan_ipv4_gateway": "203.0.113.1", "wireless_2g_enable": "on", "wireless_2g_ssid": "Home",
               "wireless_2g_psk_key": WIFI_PSK, "wireless_5g_enable": "on", "wireless_6g_enable": "on",
               "access_devices_wired": [{"hostname": "desktop", "ipaddr": "192.168.0.160", "macaddr": DESKTOP_MAC,
                                         "wire_type": "wired"}],
               "access_devices_wireless_host": [
                   {"hostname": "kiosk-tablet", "ipaddr": "192.168.0.157", "macaddr": TABLET_MAC, "wire_type": "5G"},
                   {"hostname": "kid-phone", "ipaddr": "192.168.0.123", "macaddr": PHONE_MAC, "wire_type": "2.4G"}]})
    return state


TABLE_LIST_KEY = {"wireless_schedule_v2?form=settings": "list"}


class FakeTransport:
    """Implements the Transport protocol plus login/logout, in memory."""

    def __init__(self, state: dict[str, Any] | None = None) -> None:
        self.state = state if state is not None else default_state()
        self.calls: list[tuple[str, str, dict[str, str]]] = []
        self.logged_in = False
        self.logins = 0
        self.fail_logins = 0
        self._fail: list[tuple[str, bool, bool]] = []
        self.custom: dict[tuple[str, str], Callable[[dict[str, str]], Any]] = {}
        # Called before every call; may mutate state or arm fail_next() for THIS call.
        self.on_call: Callable[[str, str, dict[str, str]], None] | None = None
        # Simulate a router that reads "index" differently (e.g. off by one) for remove/update.
        self.index_offset = 0
        # Paths whose write/update the router "accepts" (success) but silently ignores.
        self.ignore_changes: set[str] = set()
        self.avira = {"owners": [{"ownerId": "1", "name": "Child", "internetBlocked": False,
                                  "filterWebsiteList": ["example-games.com"], "freeWebsiteList": []}]}
        self._install_custom()

    # ------------------------------------------------------------------ test controls
    def fail_next(self, code: str = E_TIMEOUT, *, after_apply: bool = False, ambiguous: bool | None = None) -> None:
        amb = code in ("timeout", "network", "server_error") if ambiguous is None else ambiguous
        self._fail.append((code, after_apply, amb))

    def writes(self) -> list[tuple[str, str, dict[str, str]]]:
        from mcp_tplink_router.catalog import is_read_op

        return [c for c in self.calls if not is_read_op(c[1])]

    # ---------------------------------------------------------------------- session
    def login(self) -> None:
        self.logins += 1
        if self.fail_logins > 0:
            self.fail_logins -= 1
            raise RouterError(E_LOGIN, "login failed")
        self.logged_in = True

    def logout(self) -> None:
        self.logged_in = False

    # ------------------------------------------------------------------------- calls
    def call(self, path: str, op: str, fields: dict[str, str] | None = None, *,
             timeout: float | None = None) -> Any:
        fields = check_fields(fields)
        if timeout is not None:
            self.timeouts.append((path, timeout))
        assert self.logged_in, "call outside a session"
        self.calls.append((path, op, dict(fields)))
        if self.on_call:
            self.on_call(path, op, fields)
        if self._fail:
            code, after_apply, amb = self._fail.pop(0)
            if after_apply:
                self._dispatch(path, op, fields)
            raise RouterError(code, "injected failure", ambiguous=amb)
        return copy.deepcopy(self._dispatch(path, op, fields))

    def _forms(self, path: str) -> list[str]:
        if "?" not in path:
            return [path]
        module, query = path.split("?", 1)
        return [f"{module}?{p}" for p in query.split("&") if p.startswith("form=")]

    def _get(self, path: str) -> Any:
        if path not in self.state:
            raise RouterError("no such callback")
        return self.state[path]

    def _rows(self, path: str) -> list[dict[str, Any]]:
        data = self._get(path)
        lk = TABLE_LIST_KEY.get(path)
        if lk:
            data = data.setdefault(lk, [])
        if not isinstance(data, list):
            raise RouterError("invalid operation")
        return data

    def _dispatch(self, path: str, op: str, fields: dict[str, str]) -> Any:
        if (path, op) in self.custom:
            return self.custom[(path, op)](fields)
        forms_ = self._forms(path)
        if op in ("read", "load", "read_spf"):
            if len(forms_) == 1:
                return self._get(forms_[0])
            out = {}
            for f in forms_:
                name = f.split("form=", 1)[1]
                for k, v in self._get(f).items():
                    out[f"{name}_{k}"] = v
            return out
        if op in ("write", "write_spf", "update") and path in self.ignore_changes:
            return {}
        if op in ("write", "write_spf"):
            if len(forms_) == 1 and not any(k.startswith(forms_[0].split("form=", 1)[1] + "_") for k in fields):
                target = self._get(forms_[0])
                if isinstance(target, list):
                    raise RouterError("invalid operation")
                target.update(fields)
                return {}
            names = {f.split("form=", 1)[1]: f for f in forms_}
            for k, v in fields.items():
                owners = [n for n in names if k.startswith(n + "_")]
                if not owners:
                    raise RouterError("invalid field")
                n = max(owners, key=len)  # wireless_5g_2_x belongs to wireless_5g_2
                self._get(names[n])[k[len(n) + 1:]] = v
            return {}
        if op == "insert":
            rows = self._rows(path)
            if "list" in fields:
                rows.extend(json.loads(fields["list"]))
            else:
                rows.append(json.loads(fields["new"]))
            return {}
        if op == "remove":
            rows = self._rows(path)
            idx = int(fields.get("index", "-1")) + self.index_offset
            if not 0 <= idx < len(rows):
                raise RouterError("invalid index")
            rows.pop(idx)
            return {}
        if op == "update":
            rows = self._rows(path)
            old, new = json.loads(fields["old"]), json.loads(fields["new"])
            for i, r in enumerate(rows):
                if r == old:
                    rows[i] = new
                    return {}
            for i, r in enumerate(rows):  # projected old/new (UI sends only some fields): merge
                if all(r.get(k) == v for k, v in old.items()):
                    rows[i] = {**r, **new}
                    return {}
            raise RouterError("entry not found")
        self._get(path)
        raise RouterError("unsupported operation")

    def _wps(self, f: dict[str, str]) -> Any:
        opt = f.get("option")
        if opt == "connect":
            self.wps_polls = 0
            return {"wps_status": "ok"}
        if opt in ("pbc", "pin"):
            self.wps_polls += 1
            if self.wps_polls < 2:
                return {"wps_status": "ok"}
            return {"wps_status": self.wps_result, "mac": "02-00-00-00-DD-01"}
        return {"wps_status": "cancel"}

    # --------------------------------------------------------------------- files
    def upload(self, path: str, fields: dict[str, str], files: dict[str, tuple[str, bytes]],
               *, timeout: float = 720.0) -> Any:
        assert self.logged_in, "call outside a session"
        self.uploads.append((path, dict(fields), {k: (n, len(d)) for k, (n, d) in files.items()}))
        self.calls.append((path, fields.get("operation", ""), dict(fields)))
        return {}

    def download(self, path: str, fields: dict[str, str]) -> tuple[bytes, str]:
        assert self.logged_in, "call outside a session"
        self.calls.append((path, fields.get("operation", ""), dict(fields)))
        return b"FAKE-CONFIG-BACKUP", "config.bin"

    # ------------------------------------------------------------------- custom ops
    def _install_custom(self) -> None:
        self.uploads: list[tuple[str, dict[str, str], dict[str, tuple[str, int]]]] = []
        self.timeouts: list[tuple[str, float]] = []
        self.wps_polls = 0
        self.wps_result = "success"
        self.diag_polls = 0

        def diag_start(_: dict[str, str]) -> Any:
            self.diag_polls = 0
            return {"finish": "0", "result": "PING ..."}

        def diag_continue(_: dict[str, str]) -> Any:
            self.diag_polls += 1
            return {"finish": "1" if self.diag_polls >= 2 else "0", "result": "4 packets transmitted, 4 received"}

        def iot_write(f: dict[str, str]) -> Any:
            for m in json.loads(f["mac"]):
                self.state["iot_security?form=isolated_list"].append({"mac": m, "name": m})
            return {}

        def iot_remove(f: dict[str, str]) -> Any:
            rows = self.state["iot_security?form=isolated_list"]
            rows[:] = [r for r in rows if r["mac"] != f["mac"]]
            return {}

        self.custom.update({
            ("diag?form=diag", "start"): diag_start,
            ("diag?form=diag", "continue"): diag_continue,
            ("diag?form=diag", "stop"): lambda f: {"finish": "1", "result": "4 packets transmitted, 4 received"},
            ("wireless?form=wps_connect", ""): self._wps,
            ("wireless?form=wps_pin", "write"): lambda f: (self.state["wireless?form=wps_pin"].update(
                {k: v for k, v in f.items() if k != "option"}) or {}),
            ("network?form=wan_dohdot", "get_list"): lambda f: ["dns.example"],
            ("network?form=wan_dohdot", "detect"): lambda f: {"status": "connected"},
            ("network?form=wan_ipv4_dynamic", "renew"): lambda f: {},
            ("cloud_account?form=check_upgrade", "read"): lambda f: {"update_number": "0"},
            ("cloud_account?form=cloud_upgrade", "read"): lambda f: {"version": "same"},
            ("cloud_account?form=cloud_upgrade", "upgrade"): lambda f: {},
            ("firmware?form=slave_cmd", "slave_get_info"): lambda f: [
                {"name": "Hall", "mac": "02-00-00-00-AA-01", "ip": "192.168.0.2", "is_latest": True}],
            ("firmware?form=slave_cmd", "slave_upgrade_firmware"): lambda f: {},
            ("traffic?form=dev_name", "write"): lambda f: {},
            ("smart_network?form=client_speed_limit", "write"): lambda f: {},
            ("iot_security?form=isolated_list", "write"): iot_write,
            ("iot_security?form=isolated_list", "remove"): iot_remove,
            ("disk_setting?form=scan", "scan"): lambda f: {"list": [], "number": 0},
            ("folder_sharing?form=settings", "save"): lambda f: {},
            ("ddns?form=tplink", "insert"): lambda f: {},
            ("ddns?form=noip", "login"): lambda f: {},
            ("easymesh_network?form=mesh_sclient_detail", "read"): lambda f: {"mac": f["mac"], "name": "Hall",
                                                                             "location": "hall", "led": "on"},
            ("easymesh_network?form=mesh_sclient_detail", "write"): lambda f: {},
            ("easymesh_network?form=change_satellite", "write"): lambda f: {},
            ("easymesh_network?form=available_mesh_device_manage", "bind_to_current_ap"): lambda f: {},
            ("easymesh?form=search_slave", "stop"): lambda f: {},
            ("administration?form=account", "write"): lambda f: {},
        })
        av = "avira_parental_control?form=avira_pactrl"

        def owner(fields: dict[str, str]) -> dict[str, Any]:
            for o in self.avira["owners"]:
                if o["ownerId"] == fields.get("ownerId"):
                    return o
            raise RouterError("owner not found")

        def total(_: dict[str, str]) -> Any:
            return {"availableOwnerMax": 15, "clientPerOwnerMax": 32, "filterFreeWebsiteMax": 64,
                    "filterWebsiteMax": 64, "ownerList": copy.deepcopy(self.avira["owners"]), "state": "on",
                    "totalOwnerMax": 16}

        def block(fields: dict[str, str]) -> Any:
            owner(fields)["internetBlocked"] = fields["internetBlocked"] == "true"
            return {}

        def set_filter(fields: dict[str, str]) -> Any:
            owner(fields)["filterWebsiteList"] = json.loads(fields["filterWebsiteList"])
            return {}

        def get_filter(fields: dict[str, str]) -> Any:
            return {"filterWebsiteList": owner(fields)["filterWebsiteList"]}

        self.custom.update({
            (av, "getOwnerTotalData"): total,
            (av, "internetBlock"): block,
            (av, "setFilterWebsiteInfo"): set_filter,
            (av, "getFilterWebsiteInfo"): get_filter,
            (av, "getBlockHistory"): lambda f: {"history": [{"site": "blocked.example", "time": "08:00"}]},
            (av, "getTodayVisitSites"): lambda f: {"sites": [{"site": "school.example", "count": 4}]},
            (av, "getDevicesList"): lambda f: {"devices": []},
            ("vpnconn?form=config", "list"): lambda f: [{"key": "c1", "name": "phone", "ip": "10.5.5.2",
                                                          "vpntype": f.get("vpntype")}],
            ("vpnconn?form=config", "disconnect"): lambda f: {},
            ("system?form=reboot", "reboot"): lambda f: {},
            ("firmware?form=upgrade", "fwup_check"): lambda f: {"latest": True},
            ("easymesh?form=search_slave", "start"): lambda f: {},
            ("easymesh_network?form=available_mesh_device_manage", "reboot"): lambda f: {},
        })


# ----------------------------------------------------------------- encrypted (BE4800)
UPSTAIRS_PASSWORD = "kid-test-pw-not-real"
KID_LAPTOP = "AA-BB-CC-11-22-33"


def be4800_state() -> dict[str, Any]:
    """An older-firmware router: no status?form=all, clients under status?form=client_status."""
    st = default_state()
    st.pop("status?form=all")
    st["status?form=client_status"] = {
        "access_devices_wired": [],
        "access_devices_wireless_host": [{"hostname": "kid-laptop", "ipaddr": "192.168.1.50",
                                          "macaddr": KID_LAPTOP, "wire_type": "5G"}]}
    st["access_control?form=white_list"] = [{".anonymous": True, ".name": "cfg01", ".type": "white_list",
                                             "deviceType": "laptop", "host": "NOT HOST", "mac": KID_LAPTOP,
                                             "name": "kid-laptop"}]
    st["access_control?form=mode"] = {"access_mode": "white"}
    st["access_control?form=enable"] = {"enable": "on", "host_mac": ""}
    return st


class FakeEncryptedClient:
    """Mimics tplinkrouterc6u.TplinkRouter: authorize(), request(path, urlencoded, ignore_errors), logout()."""

    def __init__(self, fake: FakeTransport, password: str) -> None:
        self.fake = fake
        self.password = password
        self.bodies: list[tuple[str, str]] = []

    def authorize(self) -> None:
        if self.password != UPSTAIRS_PASSWORD:
            raise Exception("TplinkRouter - login failed")
        self.fake.login()

    def logout(self) -> None:
        self.fake.logout()

    def request(self, path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False) -> Any:
        from urllib.parse import parse_qsl

        self.bodies.append((path, data))
        assert path.startswith("admin/")
        fields = dict(parse_qsl(data, keep_blank_values=True))
        op = fields.pop("operation")
        try:
            return self.fake.call(path[len("admin/"):], op, fields)
        except RouterError as exc:
            if exc.ambiguous:
                raise type("ReadTimeout", (Exception,), {})("timed out") from exc
            if ignore_errors:
                return {"success": False, "errorcode": exc.code}
            raise


def fake_encrypted_transport(fake: FakeTransport, password_getter: Callable[[], str]) -> Any:
    from mcp_tplink_router.transport import EncryptedRouterTransport

    clients: list[FakeEncryptedClient] = []

    def factory(host: str, password: str, timeout: int) -> FakeEncryptedClient:
        c = FakeEncryptedClient(fake, password)
        clients.append(c)
        return c

    t = EncryptedRouterTransport("https://192.0.2.47", password_getter, client_factory=factory)
    t.clients = clients  # type: ignore[attr-defined]
    return t
