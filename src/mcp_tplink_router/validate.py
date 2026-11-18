"""Pure validation of proposed changes.  Every function returns ``(errors, warnings)``."""

from __future__ import annotations

from typing import Any

from .netcalc import (
    Lan,
    is_ipv4,
    is_locally_administered,
    is_multicast_mac,
    normalize_mac,
    parse_ipv4,
    range_size,
)

Issues = tuple[list[str], list[str]]

RANDOM_MAC_WARNING = (
    "{mac} is a randomised/private (locally administered) MAC. Phones, tablets and laptops "
    "rotate these, so the reservation will silently stop matching: set the device's Wi-Fi "
    "privacy option to 'use device MAC' (Android: 'Use device MAC'; iOS: 'Private Wi-Fi "
    "Address' off; Windows: 'Random hardware addresses' off) or this won't stick."
)


def _lease_mac(lease: dict[str, Any]) -> str | None:
    mac = lease.get("macaddr") or lease.get("mac")
    try:
        return normalize_mac(mac) if mac else None
    except ValueError:
        return None


def validate_dhcp_setting(new: dict[str, Any], lan: Lan, reservations: list[dict[str, Any]],
                          leases: list[dict[str, Any]], old: dict[str, Any] | None = None) -> Issues:
    errors: list[str] = []
    warnings: list[str] = []
    start_s, end_s = new.get("ipaddr_start"), new.get("ipaddr_end")
    for name, val in (("ipaddr_start", start_s), ("ipaddr_end", end_s)):
        if not is_ipv4(val):
            errors.append(f"{name} {val!r} is not an IPv4 address")
    for name in ("gateway", "pri_dns", "snd_dns"):
        val = new.get(name)
        if val not in (None, "") and not is_ipv4(val):
            errors.append(f"{name} {val!r} is not an IPv4 address")
    lt = new.get("leasetime")
    if lt not in (None, ""):
        try:
            minutes = int(str(lt))
            if not 1 <= minutes <= 2880:
                errors.append(f"leasetime {minutes} minutes is outside 1..2880")
        except ValueError:
            errors.append(f"leasetime {lt!r} is not a whole number of minutes")
    if errors:
        return errors, warnings
    start, end = parse_ipv4(start_s), parse_ipv4(end_s)
    if int(start) > int(end):
        errors.append(f"pool start {start} is after pool end {end}")
    for name, ip in (("ipaddr_start", start), ("ipaddr_end", end)):
        if not lan.contains(ip):
            errors.append(f"{name} {ip} is outside the LAN subnet {lan.network}")
        elif not lan.is_host(ip):
            errors.append(f"{name} {ip} is the subnet's network or broadcast address")
    if not errors and int(start) <= int(lan.ip) <= int(end):
        errors.append(f"the pool {start}-{end} contains the router's own LAN IP {lan.ip}")
    gw = new.get("gateway")
    if gw and is_ipv4(gw) and parse_ipv4(gw) != lan.ip:
        warnings.append(f"gateway {gw} is not the router's LAN IP {lan.ip}: clients will route elsewhere")
    if errors:
        return errors, warnings
    size = range_size(start, end)
    active = {m for m in (_lease_mac(x) for x in leases) if m}
    if size < len(active):
        errors.append(f"the pool holds {size} addresses but {len(active)} clients currently hold leases")
    for r in reservations:
        ip = r.get("ip")
        if is_ipv4(ip) and not int(start) <= int(parse_ipv4(ip)) <= int(end):
            warnings.append(f"reservation {r.get('mac')} -> {ip} is outside the new pool "
                            "(fine on most TP-Link firmware, but check the device still gets it)")
    if old and is_ipv4(old.get("ipaddr_start")) and is_ipv4(old.get("ipaddr_end")):
        old_size = range_size(parse_ipv4(old["ipaddr_start"]), parse_ipv4(old["ipaddr_end"]))
        if size < old_size:
            warnings.append(f"the pool shrinks from {old_size} to {size} addresses")
        for x in leases:
            ip = x.get("ipaddr")
            if is_ipv4(ip) and not int(start) <= int(parse_ipv4(ip)) <= int(end):
                warnings.append(f"{x.get('name') or x.get('macaddr')} holds {ip}, outside the new pool; "
                                "it will move at renewal")
    return errors, warnings


def validate_reservation(row: dict[str, Any], lan: Lan, existing: list[dict[str, Any]],
                         leases: list[dict[str, Any]], clients: list[dict[str, Any]],
                         *, replacing_mac: str | None = None) -> Issues:
    """Check a reservation row ``{mac, ip, ...}``.

    ``replacing_mac`` is the MAC of the row being updated (so it doesn't conflict with
    itself).
    """
    errors: list[str] = []
    warnings: list[str] = []
    try:
        mac = normalize_mac(row.get("mac", ""))
    except ValueError as exc:
        return [str(exc)], warnings
    if mac in ("00-00-00-00-00-00", "FF-FF-FF-FF-FF-FF"):
        errors.append(f"{mac} is not a usable device MAC")
    elif is_multicast_mac(mac):
        errors.append(f"{mac} is a multicast MAC, not a device")
    elif is_locally_administered(mac):
        warnings.append(RANDOM_MAC_WARNING.format(mac=mac))
    ip_s = row.get("ip")
    if not is_ipv4(ip_s):
        errors.append(f"{ip_s!r} is not an IPv4 address")
        return errors, warnings
    ip = parse_ipv4(ip_s)
    if not lan.contains(ip):
        errors.append(f"{ip} is outside the LAN subnet {lan.network}")
    elif ip == lan.ip:
        errors.append(f"{ip} is the router's own LAN IP")
    elif not lan.is_host(ip):
        errors.append(f"{ip} is the subnet's network or broadcast address")
    rep = normalize_mac(replacing_mac) if replacing_mac else None
    for r in existing:
        try:
            rmac = normalize_mac(r.get("mac", ""))
        except ValueError:
            continue
        if rmac == rep:
            continue
        if rmac == mac:
            errors.append(f"{mac} already has a reservation ({r.get('ip')}); use action=update")
        elif str(r.get("ip")) == str(ip):
            errors.append(f"{ip} is already reserved for {rmac}")
    for x in leases:
        lm = _lease_mac(x)
        if lm and lm != mac and str(x.get("ipaddr")) == str(ip):
            warnings.append(f"{ip} is currently leased to {lm} ({x.get('name') or '?'}); "
                            "that device keeps it until its lease renews")
    seen = {m for m in (_lease_mac(x) for x in leases) if m}
    for c in clients:
        cm = c.get("macaddr") or c.get("mac")
        try:
            if cm:
                seen.add(normalize_mac(cm))
        except ValueError:
            pass
    if mac not in seen:
        warnings.append(f"{mac} has never been seen on this network (no lease, not connected) - typo?")
    return errors, warnings
