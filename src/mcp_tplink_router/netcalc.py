"""Pure IPv4 / MAC helpers (no I/O)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

STANDARD_MASKS = ("255.255.255.0", "255.255.0.0", "255.0.0.0")


def normalize_mac(mac: str) -> str:
    """Accept ``aa:bb:cc:dd:ee:ff``, ``aa-bb-...``, ``aabb.ccdd.eeff`` or bare hex.

    Returns the router's form ``AA-BB-CC-DD-EE-FF``; raises ValueError otherwise.
    """
    raw = re.sub(r"[\s:\-.]", "", str(mac)).upper()
    if not re.fullmatch(r"[0-9A-F]{12}", raw):
        raise ValueError(f"not a MAC address: {mac!r}")
    return "-".join(raw[i : i + 2] for i in range(0, 12, 2))


def mac_octet0(mac: str) -> int:
    return int(normalize_mac(mac)[:2], 16)


def is_multicast_mac(mac: str) -> bool:
    return bool(mac_octet0(mac) & 0x01)


def is_locally_administered(mac: str) -> bool:
    return bool(mac_octet0(mac) & 0x02)


def parse_ipv4(value: Any) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(str(value).strip())
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise ValueError(f"not an IPv4 address: {value!r}") from exc


def is_ipv4(value: Any) -> bool:
    try:
        parse_ipv4(value)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class Lan:
    ip: ipaddress.IPv4Address
    network: ipaddress.IPv4Network

    @property
    def broadcast(self) -> ipaddress.IPv4Address:
        return self.network.broadcast_address

    def contains(self, ip: ipaddress.IPv4Address) -> bool:
        return ip in self.network

    def is_host(self, ip: ipaddress.IPv4Address) -> bool:
        """In the subnet and not the network/broadcast address."""
        return ip in self.network and ip not in (self.network.network_address, self.broadcast)


def lan_from(ip: str, mask: str) -> Lan:
    addr = parse_ipv4(ip)
    net = ipaddress.IPv4Network(f"{addr}/{mask}", strict=False)
    return Lan(addr, net)


def lan_from_lan_ipv4(form: dict[str, Any]) -> Lan:
    """Build a :class:`Lan` from ``network?form=lan_ipv4`` (mask_type or custom_value)."""
    mask = form.get("mask_type") or ""
    if mask not in STANDARD_MASKS:
        mask = form.get("custom_value") or mask or "255.255.255.0"
    return lan_from(str(form.get("ipaddr")), str(mask))


def ip_range(start: str, end: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
    return parse_ipv4(start), parse_ipv4(end)


def range_size(start: ipaddress.IPv4Address, end: ipaddress.IPv4Address) -> int:
    return int(end) - int(start) + 1
