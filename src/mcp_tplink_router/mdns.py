"""Ask the devices on this machine's network who they are (mDNS / DNS-SD, RFC 6762 / 6763), on request.

Nothing listens in the background: `identify()` sends a few multicast queries from an ordinary (ephemeral) UDP
port and collects the answers for a few seconds.  A query whose source port is not 5353 is a "legacy unicast"
query (RFC 6762 section 6.7): responders answer that port directly, so this never competes with avahi or
Bonjour for port 5353 and needs no privileges.

What comes back is whatever the devices announce about themselves - hostnames (`Living-Room.local`), services
(`_googlecast._tcp`, `_ipp._tcp`, `_airplay._tcp`, ...) and TXT details such as a model (`md=Chromecast`,
`model=MacBookPro18,1`, `ty=Canon TS6400`).  It is device-supplied text: any device can call itself anything,
so every value is cleaned, length-capped and must be treated as data, never as instructions.

Only devices on the same network segment as this machine answer (mDNS does not cross routers).
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Any

GROUP = ("224.0.0.251", 5353)
A, PTR, TXT, AAAA, SRV = 1, 12, 16, 28, 33
# Common service types: devices that do not answer the service enumeration often answer for their own type.
SERVICE_TYPES = (
    "_services._dns-sd._udp.local", "_device-info._tcp.local", "_googlecast._tcp.local", "_airplay._tcp.local",
    "_raop._tcp.local", "_companion-link._tcp.local", "_ipp._tcp.local", "_ipps._tcp.local", "_printer._tcp.local",
    "_pdl-datastream._tcp.local", "_scanner._tcp.local", "_uscan._tcp.local", "_hap._tcp.local",
    "_homekit._tcp.local", "_matter._tcp.local", "_matterc._udp.local", "_spotify-connect._tcp.local",
    "_amzn-wplay._tcp.local", "_androidtvremote2._tcp.local", "_adb-tls-connect._tcp.local", "_smb._tcp.local",
    "_workstation._tcp.local", "_ssh._tcp.local", "_http._tcp.local", "_esphomelib._tcp.local",
    "_home-assistant._tcp.local", "_sonos._tcp.local", "_roku._tcp.local", "_nvstream._tcp.local",
    "_sleep-proxy._udp.local", "_rdlink._tcp.local", "_meshcop._udp.local", "_daap._tcp.local",
)
# TXT keys that say what a device IS (model, maker, friendly name); everything else is left out.
TXT_KEYS = {"md": "model", "model": "model", "am": "model", "ty": "model", "product": "model", "usb_mdl": "model",
            "mdl": "model", "manufacturer": "maker", "usb_mfg": "maker", "mfg": "maker", "fn": "name",
            "name": "name", "n": "name", "deviceid": "device_id", "osxvers": "os", "os": "os", "ve": "version",
            "fv": "version", "srcvers": "version", "integrator": "maker", "vendor": "maker"}
MAX_TEXT = 80


def clean(value: Any) -> str:
    """Device-supplied text -> printable, single-line, length-capped."""
    s = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    s = "".join(c if c.isprintable() else " " for c in s)
    s = " ".join(s.split())
    return s[:MAX_TEXT] + ("..." if len(s) > MAX_TEXT else "")


# ------------------------------------------------------------------------------------------- wire format
def _qname(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("utf-8")[:63]
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(questions: list[tuple[str, int]]) -> bytes:
    body = b"".join(_qname(n) + struct.pack("!HH", t, 1) for n, t in questions)
    return struct.pack("!HHHHHH", 0, 0, len(questions), 0, 0, 0) + body


def _name(buf: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels, jumped, end = [], False, off
    while True:
        if off >= len(buf) or depth > 20:
            raise ValueError("bad name")
        n = buf[off]
        if n & 0xC0 == 0xC0:  # compression pointer
            if off + 1 >= len(buf):
                raise ValueError("bad pointer")
            ptr = ((n & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            jumped, off, depth = True, ptr, depth + 1
            continue
        if n == 0:
            return ".".join(labels), (end if jumped else off + 1)
        labels.append(buf[off + 1:off + 1 + n].decode("utf-8", "replace"))
        off += 1 + n


def parse(buf: bytes) -> list[dict[str, Any]]:
    """All resource records (answers + authority + additional) in one DNS message; never raises.

    Network input from any device: a malformed message yields the records read before the damage."""
    recs: list[dict[str, Any]] = []
    try:
        _parse(buf, recs)
    except (ValueError, IndexError, struct.error, UnicodeError):
        pass
    return recs


def _parse(buf: bytes, recs: list[dict[str, Any]]) -> None:
    if len(buf) < 12:
        return
    _id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", buf[:12])
    off = 12
    for _ in range(qd):
        _q, off = _name(buf, off)
        off += 4
    for _ in range(an + ns + ar):
        rname, off = _name(buf, off)
        if off + 10 > len(buf):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", buf[off:off + 10])
        off += 10
        rdata = buf[off:off + rdlen]
        rec: dict[str, Any] = {"name": rname.lower(), "type": rtype}
        try:
            if rtype == A and rdlen == 4:
                rec["ip"] = socket.inet_ntoa(rdata)
            elif rtype == AAAA and rdlen == 16:
                rec["ip"] = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype == PTR:
                rec["target"] = _name(buf, off)[0]
            elif rtype == SRV and rdlen >= 6:
                rec["port"] = struct.unpack("!H", rdata[4:6])[0]
                rec["target"] = _name(buf, off + 6)[0].lower()
            elif rtype == TXT:
                items, i = [], 0
                while i < len(rdata):
                    n = rdata[i]
                    items.append(rdata[i + 1:i + 1 + n])
                    i += 1 + n
                rec["txt"] = items
        except (ValueError, OSError, struct.error):
            pass
        recs.append(rec)
        off += rdlen


# ------------------------------------------------------------------------------------------- discovery
def local_ip_toward(host: str) -> str | None:
    """This machine's address on the network that reaches `host` (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((host, 9))
            return str(s.getsockname()[0])
    except OSError:
        return None


def _reverse(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def collect(ips: list[str], seconds: float, iface_ip: str | None) -> list[tuple[str, list[dict[str, Any]]]]:
    """Send the queries and return (source_ip, records) for every answer received within `seconds`."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    if iface_ip:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
        sock.bind((iface_ip, 0))
    else:
        sock.bind(("", 0))
    got: list[tuple[str, list[dict[str, Any]]]] = []
    asked: set[str] = set()

    def ask(questions: list[tuple[str, int]]) -> None:
        for i in range(0, len(questions), 12):  # keep each packet well under one MTU
            try:
                sock.sendto(build_query(questions[i:i + 12]), GROUP)
            except OSError:
                pass

    ask([(t, PTR) for t in SERVICE_TYPES])
    ask([(_reverse(ip), PTR) for ip in ips])
    asked.update(SERVICE_TYPES)
    deadline, second_round = time.monotonic() + seconds, time.monotonic() + seconds / 2
    try:
        while (left := deadline - time.monotonic()) > 0:
            sock.settimeout(min(left, 0.25))
            try:
                data, (src, _port) = sock.recvfrom(9000)
                recs = parse(data)
            except TimeoutError:
                recs, src = [], ""
            except (OSError, ValueError, struct.error):
                continue
            if recs:
                got.append((src, recs))
            if time.monotonic() >= second_round:  # ask for the service types devices said they offer
                found = {str(r.get("target", "")).lower() for _s, rs in got for r in rs
                         if r["type"] == PTR and r["name"] == "_services._dns-sd._udp.local"}
                new = sorted(t for t in found if t and t not in asked)
                if new:
                    ask([(t, PTR) for t in new])
                    asked.update(new)
                second_round = deadline + 1
    finally:
        sock.close()
    return got


def summarise(answers: list[tuple[str, list[dict[str, Any]]]]) -> dict[str, dict[str, Any]]:
    """Per IP: hostnames, services and the identity hints in their TXT records."""
    recs = [r for _s, rs in answers for r in rs]
    host_ip: dict[str, str] = {r["name"]: r["ip"] for r in recs if r["type"] == A and r.get("ip")}
    for r in recs:  # reverse lookups: x.y.z.w.in-addr.arpa -> host.local
        if r["type"] == PTR and r["name"].endswith(".in-addr.arpa") and r.get("target"):
            ip = ".".join(reversed(r["name"].removesuffix(".in-addr.arpa").split(".")))
            host_ip.setdefault(str(r["target"]).lower(), ip)
    srv = {r["name"]: r for r in recs if r["type"] == SRV and r.get("target")}
    txt: dict[str, list[bytes]] = {}
    for r in recs:
        if r["type"] == TXT and r.get("txt"):
            txt.setdefault(r["name"], []).extend(r["txt"])
    src_of: dict[str, str] = {}
    for src, rs in answers:
        for r in rs:
            src_of.setdefault(r["name"], src)
    out: dict[str, dict[str, Any]] = {}

    def entry(ip: str) -> dict[str, Any]:
        return out.setdefault(ip, {"hostnames": set(), "services": set(), "instances": set(), "hints": {}})

    for host, ip in host_ip.items():
        entry(ip)["hostnames"].add(host)
    instances = {r["target"] for r in recs if r["type"] == PTR and str(r.get("target", "")).count("._") >= 1
                 and not r["name"].endswith(".in-addr.arpa") and r["name"] != "_services._dns-sd._udp.local"}
    instances |= set(srv) | {n for n in txt if "._" in n}
    for inst in instances:
        inst = str(inst).lower()
        s = srv.get(inst)
        ip = host_ip.get(s["target"]) if s else None
        ip = ip or src_of.get(inst)
        if not ip:
            continue
        e = entry(ip)
        label, _, stype = inst.partition("._")
        stype = "_" + stype.removesuffix(".local") if stype else ""
        if stype:
            e["services"].add(stype.split(".")[0] + "." + stype.split(".")[1] if stype.count(".") >= 1 else stype)
        if label and "._" in inst:
            e["instances"].add(clean(label))
        for item in txt.get(inst, []):
            key, _, val = item.partition(b"=")
            k = key.decode("ascii", "replace").lower()
            if k in TXT_KEYS and val:
                e["hints"].setdefault(TXT_KEYS[k], clean(val))
    return {ip: {"hostnames": sorted(clean(h.removesuffix(".local")) for h in e["hostnames"])[:4],
                 "services": sorted(e["services"])[:12], "announced_names": sorted(e["instances"])[:4],
                 **({"details": e["hints"]} if e["hints"] else {})}
            for ip, e in out.items() if e["hostnames"] or e["services"] or e["hints"]}


def identify(ips: list[str], router_host: str, seconds: float = 3.0) -> dict[str, dict[str, Any]]:
    seconds = max(1.0, min(float(seconds), 10.0))
    iface = local_ip_toward(router_host)
    return summarise(collect(ips, seconds, iface))
