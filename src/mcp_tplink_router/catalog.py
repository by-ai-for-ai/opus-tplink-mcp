"""What the router exposes, how to talk to each form, and how dangerous each operation is.

Sources: ``_endpoints.PROBED`` (every form in the web UI + whether a live read worked) and
the UI's own JavaScript store (which op each page sends and which fields it writes).
``verified`` records where each op's format comes from:

* ``live``  - exercised against the owner's router (reads from the shape probe, and the
  DHCP-reservation insert);
* ``ui``    - copied from the web UI's JS but not yet exercised by this server;
* ``none``  - inferred; treat with suspicion.

Risk tiers (see :mod:`safety`): ``read`` < ``normal`` < ``critical`` < ``forbidden``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ._endpoints import PROBED

READ, NORMAL, CRITICAL, FORBIDDEN = "read", "normal", "critical", "forbidden"
RISK_ORDER = {READ: 0, NORMAL: 1, CRITICAL: 2, FORBIDDEN: 3}

READ_OPS = frozenset(
    {
        "read", "load", "read_spf", "list", "wg_status", "connected_status", "read_max",
        "check", "fwup_check", "loadDevice", "loadSpeed", "file_check", "get_default", "check_collision",
        "cloud_check", "read_match",
    }
)


def is_read_op(op: str) -> bool:
    return op in READ_OPS or op.startswith("get") or op.startswith("read")


def max_risk(*risks: str) -> str:
    return max(risks, key=lambda r: RISK_ORDER[r]) if risks else READ


@dataclass(frozen=True)
class Endpoint:
    path: str
    kind: str = "form"  # form | table | action
    section: str = ""
    read_op: str | None = None  # how to read it (read / load / read_spf); None = not readable
    list_key: str | None = None  # table rows live under this key of a form read
    write_op: str = "write"
    write_path: str | None = None  # URL to write to when it differs (multi-form writes)
    field_prefix: str = ""  # write field names are prefix + name (wireless_2g_ssid...)
    skip_empty: bool = False  # the UI drops empty-string fields from this form's writes
    volatile: tuple[str, ...] = ()  # live counters/status in rows: ignored when comparing rows
    row_fields: tuple[str, ...] | None = None  # update new/old JSON carry only these fields (UI mapper)
    verify_ignore: tuple[str, ...] = ()  # fields the router overrides itself (not checked after a write)
    write_fields: tuple[str, ...] | None = None  # fields a form write sends (UI allowlist)
    partial_write: bool = False  # the UI sends ONLY the changed fields (full-form writes are refused)
    timeout: float | None = None  # per-request timeout when the router answers slowly (e.g. WPS ~18 s)
    list_fields: tuple[str, ...] = ()  # list-valued fields sent as a repeated key (always sent with writes)
    json_fields: tuple[str, ...] = ()  # nested fields ALWAYS sent, JSON-encoded (the router 500s without them)
    keeps_blank: tuple[str, ...] = ()  # fields the router keeps when sent blank (a blank restore is not a failure)
    table_ops: frozenset[str] = frozenset()
    key_field: str | None = None  # logical identity of a table row
    secret_fields: tuple[str, ...] = ()
    op_risk: dict[str, str] = field(default_factory=dict)
    verified: dict[str, str] = field(default_factory=dict)
    note: str = ""

    def risk(self, op: str) -> str:
        return risk_of(self.path, op)


def _ep(path: str, **kw: object) -> Endpoint:
    probed = PROBED.get(path.split("&", 1)[0])
    if "read_op" not in kw and probed and probed[0]:
        kw["read_op"] = probed[0]
    ver = dict(kw.pop("verified", {}) or {})  # type: ignore[arg-type]
    if probed and probed[0] and kw.get("read_op") == probed[0]:
        ver.setdefault(str(probed[0]), "live")
    kw["verified"] = ver
    for k in ("table_ops",):
        if k in kw:
            kw[k] = frozenset(kw[k])  # type: ignore[arg-type]
    return Endpoint(path=path, **kw)  # type: ignore[arg-type]


WIFI_BANDS = ("2g", "5g", "6g")
WIFI_WRITE_PATH = "wireless?" + "&".join(f"form=wireless_{b}" for b in WIFI_BANDS)
GUEST_BANDS = ("2g", "5g", "2g5g", "6g")
GUEST_PATH = "wireless?" + "&".join(f"form=guest_{b}" for b in GUEST_BANDS)
# The UI's writable-field list for a main Wi-Fi band (model "V" in the wireless page JS).
WIFI_FIELDS = (
    "disabled_all", "enable", "hidden", "mu_mimo", "psc", "ssid", "encryption", "psk_key",
    "psk_version", "server", "port", "wpa_key", "hwmode", "htmode", "channel", "txpower",
    "channel_mode", "auto_channel_unii_4",
)
GUEST_FIELDS = (
    "enable", "ssid", "hidden", "encryption", "psk_key", "psk_version", "psk_cipher",
    "authentication_type", "authentication_timeout", "portal_password", "redirect",
    "redirect_url", "passwd_cycle",
)

_CURATED: list[Endpoint] = [
    # ---- status / clients -------------------------------------------------------------
    _ep("status?form=all", section="status"),
    _ep("status?form=internet", section="internet"),
    _ep("status?form=router", section="ports"),
    _ep("status?form=client_status", section="client_status", read_op="read", verified={"read": "live"},
        note="Connected clients on older firmware (BE4800); status?form=all where available."),
    _ep("firmware?form=upgrade", section="firmware",
        op_risk={"fwup_check": READ, "write": CRITICAL}, verified={"fwup_check": "ui"}),
    _ep("system?form=sysmode", section="sysmode", write_fields=("mode",),
        op_risk={"write": CRITICAL}, verified={"write": "ui"}),
    # ---- LAN / DHCP -------------------------------------------------------------------
    _ep("network?form=lan_ipv4", section="lan", op_risk={"write": CRITICAL},
        write_fields=("lan_type", "ipaddr", "mask_type", "custom_value", "pri_dns", "snd_dns"),
        verified={"write": "none"}, note="LAN IP/mask: changing it cuts every client off until they renew."),
    _ep("dhcps?form=setting", section="dhcp",
        write_fields=("enable", "ipaddr_start", "ipaddr_end", "leasetime", "gateway", "pri_dns", "snd_dns"),
        verified={"write": "ui"}, note="leasetime is in minutes (1-2880)."),
    _ep("dhcps?form=reservation", kind="table", section="dhcp_reservations", read_op="load",
        table_ops=("insert", "update", "remove"), key_field="mac", verify_ignore=("comment", "hostname"),
        verified={"insert": "live", "update": "live", "remove": "live"},
        note="Rows have no router key: remove/update select by load-order index (+ old row JSON)."),
    _ep("dhcps?form=client", kind="table", section="dhcp_leases", read_op="load"),
    # ---- IP-MAC binding ---------------------------------------------------------------
    _ep("imb?form=setting", section="ip_mac_binding", write_fields=("enable",), verified={"write": "ui"}),
    _ep("imb?form=bind_list", kind="table", section="ip_mac_bindings", read_op="load",
        table_ops=("insert", "remove"), key_field="mac", verify_ignore=("name",),
        verified={"insert": "live", "remove": "live"},
        note="No update op in the UI: edits are remove + insert. The router drops custom names, and refuses "
             "a binding whose IP has a DHCP reservation for ANOTHER MAC ('DHCP reservation duplication')."),
    _ep("imb?form=arp_list", kind="table", section="arp", read_op="load", key_field="mac",
        op_risk={"bind": NORMAL, "remove": NORMAL}, verified={"bind": "ui"}),
    _ep("imb?form=client_list", section="imb_clients"),
    # ---- UPnP -------------------------------------------------------------------------
    _ep("upnp?form=enable", section="upnp", write_fields=("enable",), verified={"write": "ui"}),
    _ep("upnp?form=service", kind="table", section="upnp_mappings", read_op="load",
        verified={"load": "ui"}, note="Read-only in the UI (no delete op)."),
    # ---- mesh -------------------------------------------------------------------------
    _ep("easymesh?form=easymesh_enable", section="mesh", write_fields=("enable",), verified={"write": "ui"}),
    _ep("easymesh_network?form=get_mesh_device_list_all", section="mesh_devices"),
    _ep("easymesh_network?form=get_mesh_topo", section="mesh_topology"),
    _ep("easymesh_network?form=mesh_sclient_list_all", section="mesh_clients"),
    _ep("easymesh_network?form=ap_avoidance_enable_status", section="mesh_ap_avoidance"),
    _ep("easymesh_network?form=available_mesh_device_manage", kind="action",
        op_risk={"reboot": CRITICAL, "unlink": CRITICAL, "link": NORMAL, "add_onboarding": NORMAL,
                 "bind_to_current_ap": NORMAL},
        verified=dict.fromkeys(("reboot", "unlink", "link", "add_onboarding", "bind_to_current_ap"), "ui")),
    _ep("easymesh?form=search_slave", kind="action",
        op_risk={"start": NORMAL, "stop": NORMAL}, verified={"start": "ui", "stop": "ui", "check": "ui"}),
    # ---- VPN --------------------------------------------------------------------------
    _ep("vpn?form=enable", section="vpn_client", write_fields=("enable",),
        op_risk={"write": CRITICAL}, verified={"write": "ui"}),
    _ep("vpn?form=server", kind="table", section="vpn_client_profiles", read_op="load",
        table_ops=("insert", "update", "remove"), key_field="key",
        secret_fields=("private_key", "preshared_key", "password"),
        volatile=("status", "download_speed", "upload_speed"),
        op_risk={"update": CRITICAL, "remove": CRITICAL, "connected_status": READ},
        verified={"insert": "ui", "update": "ui", "remove": "ui", "connected_status": "ui"},
        note="Despite the name these are the VPN CLIENT profiles (the router dials out)."),
    _ep("vpn?form=vpn_user_list", kind="table", section="vpn_client_devices", read_op="load",
        table_ops=("insert", "update", "remove"), key_field="mac",
        row_fields=("name", "mac", "access", "client_type"),
        op_risk={"insert": CRITICAL, "update": CRITICAL, "remove": CRITICAL},
        verified={"insert": "ui", "update": "ui", "remove": "ui"},
        note=("Devices routed through the VPN client: access on = through the VPN. No per-profile "
              "assignment on this firmware (server_key/server_des are ignored leftovers). insert is "
              "{list: JSON([{key, name, mac, client_type, online}])}; update key=<mac>, new/old = "
              "{name, mac, access, client_type}.")),
    _ep("vpn?form=vpn_user_devices", kind="table", section="vpn_client_candidates", read_op="read",
        volatile=("online",)),
    _ep("vpn?form=ovpn", kind="action", secret_fields=("password",),
        op_risk={"read": READ, "write": CRITICAL}, verified={"read": "ui"}),
    _ep("openvpn?form=config", section="openvpn_server",
        write_fields=("access", "enabled", "interface_type", "mask", "port", "proto", "serverip"),
        verified={"write": "ui"}),
    _ep("openvpn?form=openvpn_cert", kind="action", op_risk={"generate": CRITICAL}, verified={"generate": "ui"}),
    _ep("pptpd?form=config", section="pptp_server",
        write_fields=("enabled", "netbios_pass", "remoteip", "samba_access", "unencrypted_access"),
        verified={"write": "ui"}),
    _ep("pptpd?form=accounts", kind="table", section="pptp_accounts", read_op="load",
        table_ops=("insert", "update", "remove"), key_field="username", secret_fields=("password",),
        verified={"insert": "ui", "update": "ui", "remove": "ui"}),
    _ep("l2tpoveripsec?form=config", section="l2tp_server",
        write_fields=("access", "enabled", "encrypt", "maxconn", "netbios_pass", "netmask", "remoteip",
                      "samba_access", "serverip", "subnet"),
        secret_fields=("psk", "ipsec_psk"), verified={"write": "ui"}),
    _ep("l2tpoveripsec?form=accounts", kind="table", section="l2tp_accounts", read_op="load",
        table_ops=("insert", "update", "remove"), key_field="username", secret_fields=("password",),
        verified={"insert": "ui", "update": "ui", "remove": "ui"}),
    _ep("wireguard?form=config", section="wireguard_server",
        write_fields=("access", "address", "dns", "enable", "listen_port", "persistent_keepalive"),
        secret_fields=("private_key",),
        op_risk={"renew": CRITICAL, "wg_status": READ}, verified={"write": "ui", "renew": "ui"},
        note="Live: listen_port changes are ignored while the server is disabled (no_effect)."),
    _ep("wireguard?form=account", kind="table", section="wireguard_accounts", read_op="load",
        table_ops=("insert", "update", "remove"), key_field="name",
        secret_fields=("private_key", "preshared_key"),
        op_risk={"renew": CRITICAL, "export": READ, "get_default": READ, "check_collision": READ},
        verified={"insert": "ui", "update": "ui", "remove": "ui", "load": "ui", "get_default": "live"},
        note="Live: insert with name/description/client_address/allowed_server is refused ('invalid "
             "description'); the web UI's exact add-account fields are not known yet."),
    _ep("vpnconn?form=config", kind="action", op_risk={"list": READ, "disconnect": NORMAL},
        verified={"list": "ui", "disconnect": "ui"},
        note="operation=list|disconnect with vpntype=openvpn|pptp|l2tp|wireguard (+key,index)."),
    # ---- routing ----------------------------------------------------------------------
    _ep("network?form=routes_static", kind="table", section="static_routes", read_op="load",
        table_ops=("insert", "update", "remove"), key_field="name",
        verified={"insert": "ui", "update": "ui", "remove": "ui"}),
    _ep("network?form=routes_system", kind="table", section="system_routes", read_op="load"),
    # ---- access control ---------------------------------------------------------------
    _ep("access_control?form=enable", section="access_control", write_fields=("enable",),
        verified={"write": "ui"}),
    _ep("access_control?form=mode", section="access_control_mode", write_fields=("access_mode",),
        verified={"write": "ui"}, note="access_mode black|white; switching to white is critical."),
    _ep("access_control?form=black_list", kind="table", section="blocklist", read_op="load",
        table_ops=("insert", "remove"), key_field="mac", verified={"insert": "ui", "remove": "ui"}),
    _ep("access_control?form=white_list", kind="table", section="allowlist", read_op="load",
        table_ops=("insert", "remove"), key_field="mac", verified={"insert": "ui", "remove": "ui"}),
    _ep("access_control?form=black_devices", kind="table", section="blocklist_candidates", read_op="load",
        op_risk={"block": NORMAL}, verified={"block": "ui"}),
    _ep("access_control?form=white_devices", kind="table", section="allowlist_candidates", read_op="load",
        op_risk={"access": NORMAL}, verified={"access": "ui"}),
    # ---- parental control (local Avira/HomeShield) ------------------------------------
    _ep("avira_parental_control?form=avira_pactrl", kind="action", section="",
        op_risk=dict.fromkeys(("addOwnerInList", "delOwnerInList", "internetBlock", "setFreeWebsite", "setFilterWebsiteInfo"), NORMAL),
        verified=dict.fromkeys(("getOwnerTotalData", "addOwnerInList", "delOwnerInList", "internetBlock", "getDevicesList", "getTodayVisitSites", "getBlockHistory", "getFreeWebsite", "setFreeWebsite", "getFilterWebsiteInfo", "setFilterWebsiteInfo"), "ui") | {"getOwnerTotalData": "live"}),
    # ---- Wi-Fi ------------------------------------------------------------------------
    *[
        _ep(f"wireless?form=wireless_{b}", section=f"wifi_{b}", read_op="read_spf", write_op="write_spf",
            write_path=WIFI_WRITE_PATH, field_prefix=f"wireless_{b}_", write_fields=WIFI_FIELDS, skip_empty=True,
            secret_fields=("psk_key", "wpa_key", "wep_key1", "wep_key2", "wep_key3", "wep_key4"),
            verified={"read_spf": "ui", "write_spf": "ui"})
        for b in WIFI_BANDS
    ],
    _ep(GUEST_PATH, section="guest_wifi", read_op="read",
        write_fields=tuple(f"guest_{b}_{f}" for b in GUEST_BANDS for f in GUEST_FIELDS),
        secret_fields=tuple(f"guest_{b}_{f}" for b in GUEST_BANDS for f in ("psk_key", "portal_password")),
        verified={"read": "ui", "write": "ui"}, partial_write=True,
        note="Multi-form: keys are guest_<band>_<field>. Only changed fields are sent (like the UI): a full "
             "write with blank passwd_cycle fields is refused."),
    _ep("wireless?form=guest", section="guest_access", read_op="read", write_fields=("access", "isolate"),
        verified={"read": "ui", "write": "ui"}),
    _ep("wireless?form=smart_connect", section="smart_connect", write_fields=("smart_enable",),
        verified={"write": "ui"}),
    _ep("wireless?form=mlo_host", section="mlo_wifi", secret_fields=("psk_key",)),
    _ep("wireless?form=region", section="wifi_region", write_fields=("country",),
        op_risk={"write": CRITICAL}, verified={"write": "ui"}),
    _ep("wireless_schedule_v2?form=settings", section="wifi_schedule", list_key="list",
        write_fields=("enable", "next_time"), table_ops=("insert", "update", "remove"), key_field="key",
        op_risk={"inforce": NORMAL, "skip": NORMAL},
        verified={"write": "ui", "insert": "ui", "update": "ui", "remove": "ui"},
        note="Rows {key, enable, repeat_days, time_start, time_end, band_list, next_time} = Wi-Fi OFF periods."),
    # ---- port forwarding --------------------------------------------------------------
    _ep("nat?form=vs", kind="table", section="port_forwarding", read_op="load",
        table_ops=("insert", "update", "remove"), key_field="name",
        verified={"insert": "ui", "update": "ui", "remove": "ui", "load": "ui"}),
    _ep("nat?form=pt", kind="table", section="port_triggering", read_op="load",
        table_ops=("insert", "update", "remove"), key_field="name",
        verified={"insert": "ui", "update": "ui", "remove": "ui", "load": "ui"}),
    _ep("nat?form=dmz", section="dmz", write_fields=("enable", "ipaddr"), keeps_blank=("ipaddr",),
        verified={"write": "ui"}, note="The router keeps the last DMZ address when it is cleared (harmless while off)."),
    _ep("nat?form=alg", section="alg",
        write_fields=("ftp", "h323", "ipsec", "l2tp", "pptp", "rtsp", "sip", "tftp"), verified={"write": "ui"}),
    # ---- QoS / system -----------------------------------------------------------------
    _ep("smart_network?form=qos", section="qos",
        write_fields=("enable", "up_band", "down_band", "up_unit", "down_unit", "high", "middle", "low"),
        verified={"write": "ui"}),
    _ep("smart_network?form=device_priority", kind="table", section="device_priority", read_op="load",
        table_ops=("update",), key_field="mac", verified={"update": "ui"},
        volatile=("downloadSpeed", "uploadSpeed", "trafficUsage", "remainTime")),
    _ep("ledgeneral?form=setting", section="led", write_fields=("enable",), verified={"write": "ui"}),
    _ep("ledpm?form=setting", section="led_night_mode", write_fields=("enable", "time_start", "time_end"),
        verified={"write": "ui"}),
    _ep("eco_mode?form=settings", section="eco_mode", write_fields=("power_mode", "time_start", "time_end"),
        verified={"write": "ui"}, note="power_mode strong | medium | weak"),
    _ep("time?form=settings", section="time",
        write_fields=("timezone", "ntp_svr1", "ntp_svr2", "type"), verified={"write": "none"},
        op_risk={"refresh": NORMAL, "gmt": NORMAL}),
    _ep("firmware?form=auto_upgrade", section="auto_upgrade", write_fields=("enable", "time"),
        op_risk={"write": NORMAL}, verified={"write": "ui"}),
    _ep("system?form=reboot", kind="action", op_risk={"reboot": CRITICAL, "write": CRITICAL},
        verified={"reboot": "ui"}),
    _ep("syslog?form=log", kind="table", section="", read_op="load", op_risk={"remove": CRITICAL},
        verified={"load": "ui", "remove": "ui"}, note="remove clears the whole system log (not undoable)."),
    _ep("syslog?form=types", kind="table", read_op="load", verified={"load": "ui"}),
    _ep("syslog?form=filter", read_op="read", verified={"read": "ui"},
        note="The UI writes the filter before loading; this server never does (filters client-side)."),
    _ep("ddns?form=noip", section="ddns_noip", secret_fields=("password",),
        op_risk={"login": NORMAL, "logout": NORMAL, "refresh": NORMAL}),
    _ep("ddns?form=dyndns", section="ddns_dyndns", secret_fields=("password",),
        op_risk={"login": NORMAL, "logout": NORMAL, "refresh": NORMAL}),
    _ep("ddns?form=tplink", kind="table", section="ddns_tplink", read_op="load",
        op_risk={"insert": NORMAL, "remove": NORMAL, "bind": NORMAL, "unbind": NORMAL},
        verified={"insert": "ui", "remove": "ui", "bind": "ui", "unbind": "ui"},
        note="No refresh op (live: 'no such callback'); TP-Link DDNS updates itself."),
    _ep("ddns?form=provider", section="ddns"),
    _ep("security_settings?form=new_enable", section="firewall", write_fields=("enable", "lan_ping", "wan_ping"),
        verified={"write": "ui"}),
    _ep("iot_security?form=enable", section="iot_network"),
    _ep("administration?form=account", section="", secret_fields=("old_pwd", "new_pwd", "cfm_pwd"),
        op_risk={"write": CRITICAL}),
    _ep("administration?form=remote", section="remote_management", op_risk={"write": CRITICAL}),
    _ep("administration?form=https", section="https_management", op_risk={"write": CRITICAL}),
    _ep("administration?form=local", kind="table", section="local_management",
        op_risk={"write": CRITICAL, "insert": CRITICAL, "remove": CRITICAL, "update": CRITICAL}),
]


# Status/derived fields a settings form reports but never takes back.
_WAN_STATUS = ("conn_status", "link_status", "nonaddress_support", "pppshare", "dyn_ip", "dyn_netmask",
               "dyn_pridns", "dyn_snddns", "dyn_gateway", "dyn_server", "inet_ip", "inet_pridns", "inet_snddns",
               "ipaddr_dyn", "is_support_dynamic_mode")
_WAN4 = {
    "dynamic": ("hostname", "mtu", "dns_mode", "manual_pridns", "manual_snddns", "unicast", "mac_clone_type"),
    "staticip": ("ipaddr", "netmask", "gateway", "pri_dns", "snd_dns", "mtu"),
    "pppoe": ("username", "password", "server", "access", "conn_mode", "demand_idle", "manual_idle", "interval",
              "time_start", "time_end", "dns_mode", "ip_mode", "specific_ip", "static_ip", "static_netmask",
              "static_pridns", "static_snddns", "mtu", "snd_conn"),
    "l2tp": ("username", "password", "conn_mode", "demand_idle", "manual_idle", "mtu", "snd_conn", "static_ip",
             "static_netmask", "static_gateway", "static_pridns", "static_snddns", "static_server"),
    "pptp": ("username", "password", "conn_mode", "demand_idle", "manual_idle", "mtu", "snd_conn", "static_ip",
             "static_netmask", "static_gateway", "static_pridns", "static_snddns", "static_server"),
    "dslite": ("AFTR_name", "dynamic_mode"),
    "v6plus": (),
    "ocn": (),
}
_WAN6 = {
    "dynamic": ("ip_config", "ip_mode", "dns_mode", "static_pridns", "static_snddns", "prefix"),
    "static": ("ip6addr", "ip6gw", "pri_dns", "snd_dns", "mtu"),
    "pppoe": ("username", "password", "ip_config", "ip_mode", "specific_ip", "dns_mode", "static_pridns",
              "static_snddns"),
    "pass": ("type",),
    "tunnel": ("tunnel_addr", "ipaddr", "netmask", "gateway", "dns_mode", "pri_dns", "snd_dns"),
}
WAN4_PROTOS, WAN6_PROTOS = tuple(_WAN4), tuple(_WAN6)
_UNVERIFIED_WRITE = {"write": "none"}

_EXTRA: list[Endpoint] = [
    # ---- internet (WAN) ---------------------------------------------------------------
    *[_ep(f"network?form=wan_ipv4_{p}", section=f"wan_ipv4_{p}", write_fields=("conntype", *f),
          secret_fields=("password",), verify_ignore=_WAN_STATUS,
          op_risk={"write": CRITICAL, "renew": CRITICAL, "release": CRITICAL, "connect": CRITICAL,
                   "disconnect": CRITICAL},
          verified={"write": "ui", **({"renew": "ui", "release": "ui"} if p == "dynamic" else {})})
      for p, f in _WAN4.items()],
    *[_ep(f"network?form=wan_ipv6_{p}", section=f"wan_ipv6_{p}", write_fields=("conntype", *f),
          secret_fields=("password",), verify_ignore=_WAN_STATUS,
          op_risk={"write": CRITICAL, "renew": CRITICAL, "release": CRITICAL},
          verified={"write": "ui", **({"renew": "ui", "release": "ui"} if p == "dynamic" else {})})
      for p, f in _WAN6.items()],
    _ep("network?form=wan_ipv4_status", section="wan", write_fields=("conntype", "autodetect"),
        op_risk={"write": CRITICAL}, verified=_UNVERIFIED_WRITE),
    _ep("network?form=wan_ipv6_status", section="wan_ipv6", write_fields=("enable", "conntype"),
        op_risk={"write": CRITICAL}, verified={"write": "ui"}),
    _ep("network?form=wan_ipv4_protos", section="wan_protocols", read_op="read"),
    _ep("network?form=wan_ipv6_protos", section="wan_ipv6_protocols", read_op="read"),
    _ep("network?form=wan_autodetect", kind="action", op_risk={"read": READ}, verified={"read": "ui"}),
    _ep("network?form=wan_dohdot", section="dns_privacy", write_fields=("dns_privacy", "dns_mode", "server_list"),
        list_fields=("server_list",), op_risk={"write": NORMAL, "get_list": READ, "detect": READ},
        verified={"write": "live", "get_list": "live", "detect": "ui"},
        note="dns_privacy none|doh|dot; dns_mode default|strict; server_list = list of servers, sent as a "
             "repeated server_list= field and REQUIRED with every doh/dot write ('no server found' otherwise). "
             "JSON wipes the list; server_list[] is refused (both seen live)."),
    _ep("network?form=mac_clone_advanced", section="mac_clone",
        write_fields=("mac_clone_type", "mac_custom", "mac_computer"), op_risk={"write": CRITICAL},
        keeps_blank=("mac_custom",), verified={"write": "live"},
        note="The router keeps the last mac_custom even when it is sent blank (harmless unless type=custom). "
             "Saving reconnects the WAN, and Fios may hand out a NEW public IP (seen live)."),
    _ep("network?form=wan_fc", section="wan_flow_control", write_fields=("rx_enable", "tx_enable"),
        op_risk={"write": NORMAL}, verified={"write": "ui"}),
    # ---- LAN / ports / IPTV -----------------------------------------------------------
    _ep("network?form=lan_ipv6", section="lan_ipv6",
        write_fields=("assign_type", "address", "dhcp_prefix", "rdnss_prefix", "release_time", "slaac_prefix"),
        verify_ignore=("address",), op_risk={"write": NORMAL}, verified={"write": "live"},
        note="address is recomputed by the router on every save (shows ::/0 while WAN IPv6 is off)."),
    _ep("network?form=lan_fc", section="lan_flow_control", write_fields=("rx_enable", "tx_enable"),
        op_risk={"write": NORMAL}, verified={"write": "ui"}),
    _ep("network?form=lan_agg", section="link_aggregation",
        write_fields=("enable_agg", "hashmode", "lacpmode", "port_settings"), json_fields=("port_settings",),
        op_risk={"write": CRITICAL}, verified={"write": "live"},
        note="port_settings is always sent as a JSON string (live: HTTP 500 without it)."),
    _ep("network?form=port_speed_current", section="port_speed", write_fields=("speed",),
        op_risk={"write": CRITICAL}, verified={"write": "live"},
        note="The internet (WAN) port; speed one of port_speed_supported (auto / 2500F / 1000F / 100F)."),
    _ep("network?form=port_speed_supported", section="port_speed_supported"),
    _ep("iptv?form=setting", section="iptv",
        write_fields=("enable", "mode", "igmp_enable", "igmp_snooping_enable", "igmp_version", "internet_tag",
                      "internet_vid", "internet_vprio", "iptv_enable", "iptv_tag", "iptv_vid", "iptv_vprio",
                      "ipphone_enable", "ipphone_tag", "ipphone_vid", "ipphone_vprio", "mciptv_enable",
                      "mciptv_vid", "mciptv_vprio", "mcwifi_enable", "port_settings", "wait_time"),
        json_fields=("port_settings",), op_risk={"write": CRITICAL}, verified={"write": "live"},
        note="Saving restarts the network for wait_time s. VLAN IDs per service; port_settings JSON maps LAN ports to services and is always sent "
             "(live: HTTP 500 without it)."),
    _ep("iptv?form=udp_proxy_setting", section="udp_proxy", write_fields=("udp_proxy_enable", "udp_proxy"),
        op_risk={"write": NORMAL}, verified=_UNVERIFIED_WRITE),
    _ep("nat?form=setting", section="nat", write_fields=("enable", "boost_enable"),
        op_risk={"write": CRITICAL}, verified=_UNVERIFIED_WRITE,
        note="enable=NAT itself (off breaks internet for LAN clients); boost_enable=hardware NAT boost."),
    # ---- wireless extras --------------------------------------------------------------
    _ep("wireless?form=syspara_wps", section="wps", read_op="read", write_fields=("wps",),
        op_risk={"write": NORMAL}, verified={"read": "live", "write": "ui"},
        note="wait_time is read-only: how long the UI should wait after toggling WPS."),
    _ep("wireless?form=wps_connect", kind="action", read_op="read", timeout=60.0,
        op_risk={"read": READ, "": NORMAL}, verified={"read": "live", "": "live"},
        note="Sent with NO operation: option=connect starts push-button pairing (connect + wps_pin = pair by "
             "the device's PIN) | cancel stops | pbc / pin POLL the push-button / PIN session status "
             "(the router takes ~18 s to answer)."),
    _ep("wireless?form=wps_pin", section="wps_pin", read_op="read", write_fields=("wps_label",),
        secret_fields=("wps_pin",), op_risk={"write": NORMAL}, verified={"read": "ui", "write": "ui"},
        note="write option=generate|default (new / factory PIN) or wps_label=on|off (router PIN on/off)."),
    _ep("wireless?form=ofdma", section="ofdma", write_fields=("enable",), verified={"write": "live"},
        note="IGNORED on routers with the combined OFDMA/MU-MIMO setting (BE9300): use ofdma_mimo."),
    _ep("wireless?form=ofdma_mimo", section="ofdma_mimo", write_fields=("setting",), verified={"write": "ui"},
        note="setting = all (OFDMA+MU-MIMO) | ofdma_only | disabled"),
    _ep("wireless?form=twt", section="twt", write_fields=("enable",), verified={"write": "ui"}),
    _ep("ffs?form=config", section="fast_roaming_ssid", write_fields=("enable",), verified={"write": "ui"}),
    _ep("wireless?form=mlo_host", section="mlo_wifi",
        write_fields=("enable", "ssid", "hidden", "encryption", "psk_key", "psk_version", "band_select",
                      "selected_bands"),
        secret_fields=("psk_key",), list_fields=("selected_bands",), verified={"write": "live"},
        note="Wi-Fi 7 multi-link (MLO) network. selected_bands must be sent with every write (repeated field): "
             "a write without it switched the MLO network OFF (seen live)."),
    _ep("wireless?form=wireless_addition_setting", section="wifi_advanced",
        write_fields=("airtime_fairness", "beacon_int", "dtim_period", "frag", "rts", "shortgi", "wmm",
                      "wpa_group_rekey", "zerowait_dfs", "usb_interference_reduction", "isolate"),
        secret_fields=("psk_key", "wep_key1", "wep_key2", "wep_key3", "wep_key4"), verified=_UNVERIFIED_WRITE),
    _ep("wireless?form=guestnetwork_bandwidth_ctrl", section="guest_bandwidth", read_op="read",
        write_fields=tuple(f"{a}_{b}" for a, bands in (("enable", ("2g", "5g1", "6g")), ("up_band", ("2g", "5g1", "6g")),
                                                       ("down_band", ("2g", "5g1", "6g"))) for b in bands),
        verified=_UNVERIFIED_WRITE),
    _ep("wireless?form=guestnetwork_effectivetime_ctrl", section="guest_time", read_op="read",
        write_fields=("effective_time", "type"),
        verified=_UNVERIFIED_WRITE),
    _ep("afc?form=settings", section="afc", read_op="read", write_fields=("enable",),
        op_risk={"refresh": NORMAL, "update_channel_list": READ}, verified={"read": "ui", "write": "ui"}),
    # ---- mesh extras ------------------------------------------------------------------
    _ep("easymesh_network?form=mesh_sclient_detail", section="", read_op=None,
        write_fields=("mac", "name", "location", "led", "preferred_wifi_uplink_ap", "traffic_separation",
                      "backhaul_steering"),
        op_risk={"read": READ, "write": NORMAL}, verified={"read": "ui", "write": "ui"},
        note="read needs mac=<device>; write names/locates a mesh unit (main: traffic_separation, "
             "backhaul_steering; satellites: led, preferred_wifi_uplink_ap)."),
    _ep("easymesh_network?form=change_satellite", kind="action", op_risk={"write": NORMAL},
        verified={"write": "ui"}, note="write change_satellite=true: let clients re-pick the best unit."),
    _ep("firmware?form=slave_cmd", kind="action",
        op_risk={"slave_get_info": READ, "slave_get_upgrade_info": READ, "slave_upgrade_firmware": CRITICAL},
        verified={"slave_get_info": "ui", "slave_get_upgrade_info": "ui", "slave_upgrade_firmware": "ui"}),
    # ---- clients / smart network ------------------------------------------------------
    _ep("traffic?form=dev_name", kind="action", op_risk={"write": NORMAL}, verified={"write": "ui"},
        note="write mac + alias renames a client everywhere in the UI."),
    _ep("smart_network?form=client_speed_limit", kind="action", read_op=None,
        write_fields=("mac", "enableLimit", "downloadLimit", "uploadLimit"),
        op_risk={"read_max": READ, "write": NORMAL},
        verified={"read_max": "live", "write": "live"},
        note="Takes effect in device_priority (enableLimit on/off, stored verbatim)."),
    _ep("smart_network?form=game_accelerator", kind="action", read_op=None,
        op_risk={"loadDevice": READ, "loadSpeed": READ}, verified={"loadDevice": "ui", "loadSpeed": "ui"}),
    _ep("iot_security?form=enable", section="iot_network", write_fields=("enable",), op_risk={"write": NORMAL},
        verified={"write": "ui"}),
    _ep("iot_security?form=isolated_list", kind="table", section="iot_isolated", read_op="load",
        op_risk={"write": NORMAL, "remove": NORMAL}, verified={"write": "ui", "remove": "ui"},
        note="write mac=<JSON list>, totalNum; remove mac=<one mac>."),
    _ep("iot_security?form=isolated_devices_main", kind="table", section="iot_candidates_main", read_op="load"),
    _ep("iot_security?form=isolated_devices_iot", section="iot_candidates_iot", read_op="load"),
    # ---- USB --------------------------------------------------------------------------
    _ep("disk_setting?form=metadata", section="usb_disks", op_risk={"scan": READ}, verified={"scan": "ui"}),
    _ep("disk_setting?form=scan", kind="action", op_risk={"scan": READ}, verified={"scan": "ui"}),
    _ep("disk_setting?form=remove", kind="action", op_risk={"remove": NORMAL}, verified={"remove": "ui"},
        note="remove serial=<disk>: safely eject. Live: accepted, but the partitions kept reading as mounted "
             "until the drive was unplugged."),
    _ep("folder_sharing?form=auth", section="usb_sharing_auth", write_fields=("authentication",),
        verified={"write": "ui"}),
    _ep("folder_sharing?form=media", section="usb_media_server", write_fields=("media_sharing",),
        verified={"write": "ui"}),
    _ep("folder_sharing?form=server", section="usb_server_name",
        note="Read-only here: the name is saved with folder_sharing settings (write is ignored, live)."),
    _ep("folder_sharing?form=settings", kind="table", section="usb_sharing_services", read_op="load",
        op_risk={"save": NORMAL}, verified={"save": "ui"},
        note="save is ONE combined request: server=<name>, enable='on,off,off' (samba,ftp,ftpex) "
             "[+ port (ftpex), sftpenable, sftpexenable, sftpport]. Per-service saves are refused (live)."),
    _ep("folder_sharing?form=mode", section="usb_sharing_mode", write_fields=("folder",), verified={"write": "ui"},
        note="folder = JSON: share everything vs selected folders."),
    _ep("folder_sharing?form=partial", kind="table", section="usb_shared_folders", read_op="load",
        table_ops=("update",), key_field="key", verified={"update": "ui"}),
    _ep("folder_sharing?form=tree", kind="action", op_risk={"load": READ}, verified={"load": "ui"}),
    _ep("time_machine?form=settings", section="time_machine", write_fields=("enable", "limitsize", "mntdir"),
        verified={"write": "ui"}),
    _ep("time_machine?form=contents", section="time_machine_contents"),
    _ep("usbmodem?form=modemset", section="usb_modem",
        write_fields=("apn", "authentype", "connectmode", "dial_num", "manualdns", "maxidletime", "mtu",
                      "password", "pincode", "primarydns", "seconddns", "setisp", "username", "ispindex",
                      "locindex"),
        secret_fields=("password", "pincode"), op_risk={"write": CRITICAL}, verified=_UNVERIFIED_WRITE),
    _ep("usbmodem?form=isplist", section="usb_modem_isps"),
    # ---- maintenance ------------------------------------------------------------------
    _ep("firmware?form=config", section="backup_restore",
        op_risk={"check": READ, "factory": FORBIDDEN, "restore": FORBIDDEN}, verified={"check": "ui"}),
    _ep("firmware?form=config_multipart", kind="action",
        op_risk={"backup": READ, "restore": CRITICAL}, verified={"backup": "live", "restore": "ui"},
        note="multipart: backup returns the config file; restore uploads one (router reboots)."),
    _ep("firmware?form=save_upgrade", kind="action", op_risk={"firmware": CRITICAL}, verified={"firmware": "ui"},
        note="multipart: operation=firmware, keep=on, image=<file> (router reboots)."),
    _ep("cloud_account?form=check_upgrade", kind="action", read_op="read", verified={"read": "live"}),
    _ep("cloud_account?form=cloud_upgrade", kind="action", read_op="read",
        op_risk={"upgrade": CRITICAL}, verified={"read": "ui", "upgrade": "ui"}),
    _ep("cloud_account?form=detect_upgrade_status", kind="action", read_op="read", verified={"read": "ui"}),
    _ep("cloud_account?form=check_internet", kind="action", read_op="read", verified={"read": "ui"}),
    _ep("diag?form=diag", kind="action", op_risk={"start": READ, "continue": READ, "stop": READ},
        verified={"start": "live", "continue": "live", "stop": "live"},
        note="type 0=ping (ipaddr_ping, count, pktsize) | 1=traceroute (ipaddr_trace, ttl); poll continue."),
    _ep("system?form=sysmode", section="sysmode", write_fields=("mode",), op_risk={"write": CRITICAL},
        verified={"write": "ui"}, note="router | ap | repeater | client | multissid"),
    _ep("reboot?form=set", section="reboot_schedule", read_op="read",
        write_fields=("enable", "cycle", "time", "day"), op_risk={"write": NORMAL}, verified=_UNVERIFIED_WRITE,
        note="Schedules a future reboot; writing the schedule does not reboot now."),
    _ep("time?form=dst", section="dst",
        write_fields=("dst_enable", "start_month", "start_week", "start_day", "start_hour", "end_month",
                      "end_week", "end_day", "end_hour"), verified=_UNVERIFIED_WRITE),
    _ep("time?form=hour24", section="hour24", write_fields=("hour24_enable",), verified=_UNVERIFIED_WRITE),
    # ---- administration ---------------------------------------------------------------
    _ep("administration?form=account", section="", read_op="read",
        write_fields=("old_pwd", "new_pwd", "cfm_pwd"),
        secret_fields=("old_pwd", "new_pwd", "cfm_pwd"), op_risk={"write": CRITICAL}, verified={"write": "live"},
        note="Passwords are RSA-encrypted with the [n, e] pair the read returns for each field."),
    _ep("administration?form=remote", section="remote_management",
        write_fields=("enable", "enable_superadmin", "http_port", "https_port", "managers", "web_address"),
        op_risk={"write": CRITICAL}, verified=_UNVERIFIED_WRITE),
    _ep("administration?form=https", section="https_management", write_fields=("https_enable",),
        op_risk={"write": CRITICAL}, verified=_UNVERIFIED_WRITE),
    _ep("administration?form=mode", section="local_management_mode", write_fields=("mode",),
        op_risk={"write": CRITICAL}, verified=_UNVERIFIED_WRITE,
        note="all devices may manage the router, or only the local-management list."),
    _ep("administration?form=local", kind="table", section="local_management", read_op="load",
        table_ops=("insert", "remove"), key_field="mac",
        op_risk={"insert": NORMAL, "remove": CRITICAL}, verified={"insert": "ui", "remove": "ui"}),
    _ep("administration?form=recovery", section="password_recovery", read_op="read",
        write_fields=("enable_rec", "from", "to", "smtp", "username", "password", "enable_auth"),
        secret_fields=("password",), op_risk={"write": NORMAL}, verified=_UNVERIFIED_WRITE),
    _ep("administration?form=superadminconfig", section="superadmin", write_fields=("disable",),
        op_risk={"write": CRITICAL}, verified={"write": "ui"}),
    _ep("administration?form=usersetting", section="user_permissions",
        write_fields=tuple(f"{a}_{b}" for a in ("additionalsettings", "alg", "backuprestore", "cwmp", "dmz",
                                                  "firewall", "firmware", "internetadv", "iptvadv", "ipv6",
                                                  "quicksetup", "remotemanagement", "upnp")
                           for b in ("editable", "visible")),
        op_risk={"write": CRITICAL}, verified={"write": "live"},
        note="Live: the router accepts the write but ignores it (reported as no_effect) for this login type."),
]

_CURATED = [e for e in _CURATED if e.path not in {x.path for x in _EXTRA}] + _EXTRA

# Operations exercised against a real Archer BE9300 (fw 1.2.4): change -> re-read -> undo -> re-read
# (2026-11-15..18).  Anything not listed keeps the source it came from ("ui" = the web UI's JS).
LIVE_VERIFIED: dict[str, tuple[str, ...]] = {
    "security_settings?form=new_enable": ("write",), "nat?form=alg": ("write",), "nat?form=dmz": ("write",),
    "nat?form=pt": ("insert", "remove"), "upnp?form=enable": ("write",),
    "network?form=lan_fc": ("write",), "network?form=lan_ipv6": ("write",), "network?form=lan_agg": ("write",),
    "network?form=port_speed_current": ("write",), "network?form=mac_clone_advanced": ("write",),
    "network?form=wan_dohdot": ("write", "get_list"), "network?form=wan_ipv4_dynamic": ("write", "renew"),
    "network?form=wan_ipv6_status": ("write",), "iptv?form=setting": ("write",),
    "wireless?form=twt": ("write",), "wireless?form=ofdma_mimo": ("write",), "wireless?form=syspara_wps": ("write",),
    "wireless?form=wps_pin": ("write",), "wireless?form=wps_connect": ("", "read"),
    "wireless?form=guestnetwork_bandwidth_ctrl": ("write",), "wireless?form=guest": ("write",),
    GUEST_PATH: ("write",), "wireless?form=wireless_6g": ("write_spf",),
    "easymesh?form=easymesh_enable": ("write",), "easymesh_network?form=mesh_sclient_detail": ("read", "write"),
    "easymesh_network?form=change_satellite": ("write",), "traffic?form=dev_name": ("write",),
    "smart_network?form=client_speed_limit": ("write", "read_max"), "iot_security?form=enable": ("write",),
    "folder_sharing?form=media": ("write",), "reboot?form=set": ("write",),
    "administration?form=local": ("insert", "remove"), "administration?form=remote": ("write",),
    "administration?form=account": ("write",), "imb?form=bind_list": ("insert", "remove"),
    "dhcps?form=reservation": ("insert", "update", "remove"), "firmware?form=config_multipart": ("backup", "restore"),
    "diag?form=diag": ("start", "continue", "stop"), "access_control?form=white_list": ("insert", "remove"),
    "vpn?form=vpn_user_list": ("update",),
    "pptpd?form=accounts": ("insert", "remove"), "l2tpoveripsec?form=accounts": ("insert", "remove"),
    "access_control?form=black_list": ("insert", "remove"), "network?form=routes_static": ("insert", "remove"),
    "dhcps?form=setting": ("write",), "ledgeneral?form=setting": ("write",), "ledpm?form=setting": ("write",),
    "eco_mode?form=settings": ("write",), "firmware?form=auto_upgrade": ("write",), "smart_network?form=qos": ("write",),
    "time?form=dst": ("write",), "time?form=hour24": ("write",), "smart_network?form=device_priority": ("update",),
    "wireless?form=mlo_host": ("write",), "wireless?form=wireless_addition_setting": ("write",),
    "wireless?form=guestnetwork_effectivetime_ctrl": ("write",), "administration?form=usersetting": ("write",),
    "openvpn?form=config": ("write",), "nat?form=vs": ("insert", "update", "remove"),
    "wireless?form=wireless_2g": ("write_spf",), "wireless_schedule_v2?form=settings": ("write", "insert", "remove"),
    "folder_sharing?form=settings": ("save",), "folder_sharing?form=auth": ("write",),
    "folder_sharing?form=tree": ("load",), "disk_setting?form=scan": ("scan",),
    "disk_setting?form=remove": ("remove",),
}


def _mark_live(eps: list[Endpoint]) -> list[Endpoint]:
    from dataclasses import replace

    out = []
    for ep in eps:
        ops = LIVE_VERIFIED.get(ep.path)
        out.append(replace(ep, verified={**ep.verified, **dict.fromkeys(ops, "live")}) if ops else ep)
    return out


_CURATED = _mark_live(_CURATED)
CURATED: dict[str, Endpoint] = {ep.path: ep for ep in _CURATED}

# Path-level rules applied to EVERY form (curated or not).
_FORBIDDEN_PATH = re.compile(
    r"^(quick_setup\?|debug\?|"
    r"cloud_account\?form=(cloud_unbind|user_login|get_token)|login\?form=cloud_login)"
)
_FORBIDDEN_OPS = {("firmware?form=config", "factory"), ("firmware?form=config", "restore")}
_CRITICAL_PATH = re.compile(
    r"^(network\?form=(wan_|lan_ipv4|lan_agg|mac_clone)|administration\?|system\?|login\?form=password|"
    r"locale\?form=country|wireless\?form=region|firmware\?|reboot\?|usbmodem\?|iptv\?)"
)


def is_forbidden_path(path: str) -> bool:
    """Forms that are off-limits for every operation via the read tools (debug shell, cloud bind...)."""
    return any(_FORBIDDEN_PATH.match(p) for p in split_forms(path))


def get(path: str) -> Endpoint | None:
    """Look up a form; uncatalogued-but-known forms get a bare entry."""
    if path in CURATED:
        return CURATED[path]
    if path in PROBED:
        op = PROBED[path][0]
        return Endpoint(path=path, read_op=op, kind="table" if op == "load" else "form",
                        verified={op: "live"} if op else {}, note=PROBED[path][1])
    return None


def split_forms(path: str) -> list[str]:
    """``wireless?form=a&form=b`` -> ``["wireless?form=a", "wireless?form=b"]``."""
    if "?" not in path:
        return [path]
    module, query = path.split("?", 1)
    forms = [part for part in query.split("&") if part.startswith("form=")]
    return [f"{module}?{f}" for f in forms] or [path]


def _risk_single(path: str, op: str) -> str:
    if _FORBIDDEN_PATH.match(path) and not is_read_op(op):
        return FORBIDDEN
    if (path, op) in _FORBIDDEN_OPS:
        return FORBIDDEN
    ep = CURATED.get(path)
    if ep and op in ep.op_risk:
        return ep.op_risk[op]
    if is_read_op(op):
        return READ
    if _CRITICAL_PATH.match(path):
        return CRITICAL
    if ep and (op in ep.table_ops or (op == ep.write_op and ep.write_fields is not None)):
        return NORMAL
    # Unknown write-ish op on an uncurated form: make the caller look at a dry run first.
    return CRITICAL


# Routers other than "main" (e.g. a second router reached over remote management) get these
# overrides: the VPN-client protection rules are main-only, while locking-out changes are critical.
SECONDARY_OVERRIDES: dict[tuple[str, str], str] = {
    **{("vpn?form=vpn_user_list", op): NORMAL for op in ("insert", "update", "remove")},
    **{("vpn?form=server", op): NORMAL for op in ("update", "remove")},
    ("access_control?form=mode", "write"): CRITICAL,
    ("access_control?form=enable", "write"): CRITICAL,
    ("avira_parental_control?form=avira_pactrl", "internetBlock"): CRITICAL,
}


def risk_of(path: str, op: str, profile: str = "main") -> str:
    """Risk tier of sending ``op`` to ``path`` (multi-form paths take the worst form).

    ``profile`` is "main" (the household router) or "secondary" (any other registered router).
    """
    if profile != "main":
        base = risk_of(path, op)
        if base == FORBIDDEN:
            return base
        return SECONDARY_OVERRIDES.get((path, op), base)
    if path in CURATED:
        return _risk_single(path, op)
    return max_risk(*[_risk_single(p, op) for p in split_forms(path)])


def all_paths() -> list[str]:
    return sorted(set(PROBED) | set(CURATED))


def describe(path: str) -> dict[str, object]:
    ep = get(path)
    if ep is None:
        return {"path": path, "known": False}
    ops: set[str] = set(ep.op_risk) | set(ep.table_ops) | set(ep.verified)
    if ep.read_op:
        ops.add(ep.read_op)
    if ep.write_fields is not None:
        ops.add(ep.write_op)
    return {
        "path": ep.path,
        "section": ep.section or None,
        "kind": ep.kind,
        "read_op": ep.read_op,
        "ops": {op: {"risk": risk_of(ep.path if op != ep.write_op or not ep.write_path else ep.write_path, op),
                     "verified": ep.verified.get(op, "none")} for op in sorted(ops)},
        "write_fields": list(ep.write_fields) if ep.write_fields is not None else None,
        "key_field": ep.key_field,
        "secret_fields": list(ep.secret_fields),
        "note": ep.note or (PROBED.get(path, (None, ""))[1] if path in PROBED else ""),
    }


SECTIONS: dict[str, str] = {ep.section: ep.path for ep in _CURATED if ep.section}
