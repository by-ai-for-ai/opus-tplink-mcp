"""Which dedicated tool handles a router form, so the raw/catalog tools can point there.

Found by the local-model bench: Nemotron 3 Nano 4B could not find `system action=led`, located the
form through router_catalog and tried router_raw_write on it instead.  A small model needs to be told
"use this tool" at the moment it reaches for the low-level ones.
"""

from __future__ import annotations

from typing import Any


def _table() -> dict[str, str]:
    from .system import SIMPLE_FORMS

    t = {path: f"system action={action}" for action, (path, _) in SIMPLE_FORMS.items()}
    t.update({
        "wireless?form=wireless_2g": "wifi_set action=set band=2g",
        "wireless?form=wireless_5g": "wifi_set action=set band=5g",
        "wireless?form=wireless_6g": "wifi_set action=set band=6g",
        "wireless?form=guest": "wifi_set action=set band=guest",
        "dhcps?form=setting": "dhcp_server_set",
        "dhcps?form=reservation": "dhcp_reservation",
        "imb?form=bind_list": "ip_mac_binding",
        "nat?form=vs": "port_forwarding",
        "upnp?form=enable": "upnp",
        "network?form=routes_static": "routing",
        "access_control?form=enable": "access_control",
        "administration?form=remote": "admin action=remote",
        "system?form=sysmode": "maintenance action=operation_mode",
        "wireless?form=mlo_host": "wifi_extra action=mlo",
    })
    return t


_KEYWORDS = (("led", "system action=led"), ("wireless", "wifi_set"), ("wifi", "wifi_set"), ("dhcp", "dhcp_server_set"),
             ("firewall", "system action=firewall"), ("reboot", "system action=reboot"), ("time", "system action=time"),
             ("port", "port_forwarding"), ("guest", "wifi_set band=guest"), ("route", "routing"))


def dedicated_tool(path: str, kind: str = "router") -> str | None:
    if kind == "extender":
        from .extender import _SIMPLE

        for action, (p, _, _) in _SIMPLE.items():
            if p == path:
                return f"extender_set action={action}"
        return None
    return _table().get(path)


def guess_tool(text: str) -> str | None:
    """For a path that is not a form at all: the likeliest dedicated tool by keyword."""
    low = text.lower()
    return next((tool for kw, tool in _KEYWORDS if kw in low), None)


def use_instead(path: str, kind: str = "router") -> dict[str, Any]:
    tool = dedicated_tool(path, kind)
    return {"use_instead": f"{tool} - the dedicated tool for this form (checked fields, dry run, verified, undoable)"} \
        if tool else {}
