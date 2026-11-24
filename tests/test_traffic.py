"""clients action=traffic: per-device usage with honest provenance; history; ambiguity; unsupported routers."""

from __future__ import annotations

import json
from typing import Any

import pytest

from mcp_tplink_router import events
from mcp_tplink_router.transport import RouterError

ROWS = [{"ip": "192.0.2.21", "mac": "00-00-5E-00-53-21", "rerx_byte": 2048, "retx_byte": 512, "total_byte": 5 * 1024 ** 3},
        {"ip": "192.0.2.22", "mac": "02-00-5E-00-53-22", "rerx_byte": 0, "retx_byte": 0, "total_byte": 1612434}]


@pytest.fixture(autouse=True)
def _iso(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    monkeypatch.setenv("TPLINK_EVENTS_FILE", str(tmp_path / "events.jsonl"))
    events._SEEN.clear()


@pytest.fixture
def traffic(fake, monkeypatch) -> list[tuple[str, str, Any]]:  # type: ignore[no-untyped-def]
    real, sent = fake.call, []

    def call(path: str, op: str, fields: Any = None, **k: Any) -> Any:
        sent.append((path, op, fields))
        if path == "traffic?form=status":
            return {"enable": "on"}
        if path == "traffic?form=lists":
            return ROWS
        if path == "traffic?form=data" and op == "seg_get":
            return {"data": [{"ups": 694256, "downs": 918178}], "tick": 1}
        if path == "traffic?form=data":
            raise AssertionError(f"unexpected traffic op {op}")       # never reset_all
        return real(path, op, fields, **k)

    monkeypatch.setattr(fake, "call", call)
    monkeypatch.setattr("mcp_tplink_router.features.Ctx.clients",
                        lambda self: [{"mac": "00-00-5E-00-53-21", "name": "Kids-Laptop"},
                                      {"mac": "02-00-5E-00-53-22", "name": "Kids-Phone"}])
    return sent


def test_lookup_by_name_ip_and_mac_with_provenance(call, traffic) -> None:  # type: ignore[no-untyped-def]
    out = call("clients", action="traffic", client="laptop")
    d = out["devices"][0]
    assert d["name"] == "Kids-Laptop" and d["total"] == "5.0 GB" and d["download_now"] == "2.0 KB/s"
    assert "counted since they were last reset or the router restarted" in out["source"]
    assert "only devices on this router's own network" in out["source"]
    assert call("clients", action="traffic", client="192.0.2.22")["devices"][0]["private_mac"] is True
    assert call("clients", action="traffic", client="00:00:5e:00:53:21")["devices"][0]["name"] == "Kids-Laptop"


def test_ambiguous_name_asks_instead_of_guessing(call, traffic) -> None:  # type: ignore[no-untyped-def]
    out = call("clients", action="traffic", client="kids")
    assert out["ambiguous"] is True and len(out["candidates"]) == 2 and "ask the user" in out["tell_user"]


def test_history_is_by_ip_and_says_so(call, traffic) -> None:  # type: ignore[no-untyped-def]
    out = call("clients", action="traffic", client="Kids-Laptop", history="hour")
    assert out["history"]["points"][0] == {"when": "this hour (so far)", "up": "678.0 KB", "down": "896.7 KB"}
    assert out["history"]["order"] == "newest first"
    assert "kept by IP address" in out["history"]["note"]
    assert ("traffic?form=data", "seg_get", {"ip": "192.0.2.21", "seg_type": "hour"}) in traffic
    assert not any(op == "reset_all" for _p, op, _f in traffic)


def test_router_without_a_traffic_monitor_is_not_supported(call, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    real = fake.call

    def none(path: str, op: str, fields: Any = None, **k: Any) -> Any:
        if path.startswith("traffic?form=status"):
            raise RouterError("no such callback")
        return real(path, op, fields, **k)

    monkeypatch.setattr(fake, "call", none)
    out = call("clients", action="traffic", client="x")
    assert out["status"] == "NOT_SUPPORTED" and "not supported by this tool on" in json.dumps(out)


def test_reset_all_is_critical_and_never_a_read() -> None:
    from mcp_tplink_router import catalog

    assert catalog.risk_of("traffic?form=data", "reset_all") == catalog.CRITICAL
    assert catalog.risk_of("traffic?form=data", "seg_get") == catalog.READ


def test_a_failed_traffic_read_is_not_labelled_not_done(call, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # live: an unreachable router made 'clients action=traffic' say "NOT DONE - NOTHING CHANGED" (it is a read)
    real = fake.call

    def down(path: str, op: str, fields: Any = None, **k: Any) -> Any:
        if path.startswith("traffic"):
            raise RouterError("network", "ConnectionError", ambiguous=True)
        return real(path, op, fields, **k)

    monkeypatch.setattr(fake, "call", down)
    out = call("clients", action="traffic", client="x")
    assert out.get("status") != "NOT_DONE" and "NOTHING CHANGED" not in json.dumps(out)


def test_names_fall_back_to_leases_and_own_traffic_is_labelled(call, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # live (Archer AXE5400 fw 1.5.6): the client list had no names, and the router listed its own address
    rows = [{"ip": "192.0.2.1", "mac": "00-00-5E-00-53-01", "rerx_byte": 0, "retx_byte": 0, "total_byte": 1},
            {"ip": "192.0.2.53", "mac": "00-00-5E-00-53-35", "rerx_byte": 0, "retx_byte": 0, "total_byte": 2}]
    real = fake.call

    def call_(path: str, op: str, fields: Any = None, **k: Any) -> Any:
        if path == "traffic?form=status":
            return {"enable": "on"}
        if path == "traffic?form=lists":
            return rows
        if path == "dhcps?form=client":
            return [{"macaddr": "00-00-5E-00-53-35", "name": "RE-Extender", "ipaddr": "192.0.2.53"}]
        return real(path, op, fields, **k)

    monkeypatch.setattr(fake, "call", call_)
    monkeypatch.setattr("mcp_tplink_router.features.Ctx.clients", lambda self: [])
    out = call("clients", action="traffic")
    by_ip = {d["ip"]: d["name"] for d in out["devices"]}
    assert by_ip["192.0.2.1"] == "this router (its own traffic)" and by_ip["192.0.2.53"] == "RE-Extender"


def _rows_call(fake, monkeypatch, rows, clients, seg=None):  # type: ignore[no-untyped-def]
    real = fake.call

    def call_(path: str, op: str, fields: Any = None, **k: Any) -> Any:
        if path == "traffic?form=status":
            return {"enable": "on"}
        if path == "traffic?form=lists":
            return rows
        if path == "traffic?form=data" and op == "seg_get":
            return seg
        return real(path, op, fields, **k)

    monkeypatch.setattr(fake, "call", call_)
    monkeypatch.setattr("mcp_tplink_router.features.Ctx.clients", lambda self: clients)


def _r(ip, mac, down=0, up=0, total=1000):  # type: ignore[no-untyped-def]
    return {"ip": ip, "mac": mac, "rerx_byte": down, "retx_byte": up, "total_byte": total}


def test_no_client_ranks_by_current_use_in_one_call(call, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # LM Studio (Bonsai 27B, 2026-11-23): "is one device using all the bandwidth?" took 25+ calls, one device at a time
    rows = [_r("192.0.2.10", "00-00-5E-00-53-10", down=2000, total=9 * 1024 ** 3),     # big past total, idle now
            _r("192.0.2.11", "00-00-5E-00-53-11", down=40 * 1024 ** 2, up=90_000),      # busy now
            _r("192.0.2.12", "00-00-5E-00-53-12", down=300)]
    clients = [{"mac": "00-00-5E-00-53-10", "name": "Living-Room-TV", "ip": "192.0.2.10"},
               {"mac": "00-00-5E-00-53-11", "name": "Desktop", "ip": "192.0.2.11"},
               {"mac": "00-00-5E-00-53-12", "name": "Phone", "ip": "192.0.2.12"}]
    _rows_call(fake, monkeypatch, rows, clients)
    out = call("clients", action="traffic")
    assert [d["name"] for d in out["devices"]] == ["Desktop", "Living-Room-TV", "Phone"]
    assert out["busiest_now"].startswith("Busiest right now: Desktop (192.0.2.11): 40.0 MB/s down")
    assert "Living-Room-TV" not in out["busiest_now"]
    assert "IPv4 ONLY" in out["source"]


def test_quiet_network_says_nobody_is_busy(call, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _rows_call(fake, monkeypatch, [_r("192.0.2.10", "00-00-5E-00-53-10", down=10, total=9 * 1024 ** 3)],
               [{"mac": "00-00-5E-00-53-10", "name": "TV", "ip": "192.0.2.10"}])
    out = call("clients", action="traffic")
    assert out["busiest_now"].startswith("No device is moving much traffic right now")
    assert "do not blame a device for past usage" in out["busiest_now"]


def test_old_leases_are_hidden_and_merged(call, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # live (BE9300): ~90 rows, one per IP ever seen; the same MAC under several old addresses
    rows = [_r("192.0.2.20", "00-00-5E-00-53-20", total=500), _r("192.0.2.21", "00-00-5E-00-53-20", total=9000),
            _r("192.0.2.30", "02-00-5E-00-53-30"),                        # gone: not a current client, idle
            _r("192.0.2.40", "00-00-5E-00-53-40", down=5000)]
    clients = [{"mac": "00-00-5E-00-53-20", "name": "Extender", "ip": "192.0.2.20"},
               {"mac": "00-00-5E-00-53-40", "name": "Laptop", "ip": "192.0.2.40"}]
    _rows_call(fake, monkeypatch, rows, clients)
    out = call("clients", action="traffic")
    by_name = {d["name"]: d for d in out["devices"]}
    assert set(by_name) == {"Extender", "Laptop"}
    assert by_name["Extender"]["ip"] == "192.0.2.20" and by_name["Extender"]["also_seen_at"] == ["192.0.2.21"]
    assert "1 old address(es)" in out["not_shown"]
    one = call("clients", action="traffic", client="Extender")       # one device, not 'ambiguous' over old leases
    assert len(one["devices"]) == 1 and "ambiguous" not in one


def test_history_points_are_labelled_from_the_router_clock(call, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    seg = {"hour": 1, "minute": 5, "tick": 44, "data": [{"ups": 1, "downs": 2048}, {"ups": 1, "downs": 1024},
                                                         {"ups": 0, "downs": 0}]}
    _rows_call(fake, monkeypatch, [_r("192.0.2.10", "00-00-5E-00-53-10")],
               [{"mac": "00-00-5E-00-53-10", "name": "TV", "ip": "192.0.2.10"}], seg)
    h = call("clients", action="traffic", client="TV", history="hour")["history"]
    assert [p["when"] for p in h["points"]] == ["this hour (01:00 to now)", "00:00-01:00", "23:00-00:00"]
    assert h["total_shown"]["down"] == "3.0 KB"
    seg["data"] = [{"ups": 0, "downs": 1}, {"ups": 0, "downs": 2}]
    d = call("clients", action="traffic", client="TV", history="day")["history"]
    assert [p["when"] for p in d["points"]] == ["today (so far)", "yesterday"]


def test_history_without_a_device_says_how(call, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _rows_call(fake, monkeypatch, [_r("192.0.2.10", "00-00-5E-00-53-10")],
               [{"mac": "00-00-5E-00-53-10", "name": "TV", "ip": "192.0.2.10"}])
    out = call("clients", action="traffic", history="day")
    assert "client=" in out["history_hint"] and "history" not in out


def test_list_filters_by_client_instead_of_dumping_everything(call, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # LM Studio (Bonsai 27B): seven clients searches each returned the full list; it then copied another device's MAC
    devs = [{"mac": "A4-F0-1F-00-53-16", "ip": "192.0.2.16", "name": "Sams-Phone", "connection": "5G"},
            {"mac": "00-00-5E-00-53-29", "ip": "192.0.2.29", "name": "Google", "connection": "5G"}]
    monkeypatch.setattr("mcp_tplink_router.features.Ctx.clients", lambda self: devs)
    assert [d["name"] for d in call("clients", action="list", client="sams")["clients"]] == ["Sams-Phone"]
    assert call("clients", action="list", client="A4-F0-1F-00-53")["clients"][0]["ip"] == "192.0.2.16"
    assert call("clients", action="list", client="00:00:5e:00:53:29")["clients"][0]["name"] == "Google"
    assert call("clients", action="list", client="192.0.2.16")["clients"][0]["name"] == "Sams-Phone"
    miss = call("clients", action="list", client="Samsung")
    assert miss["found"] is False and miss["clients"] == [] and "do not pick a different device" in miss["tell_user"]
    assert len(call("clients", action="list")["clients"]) == 2
    assert len(call("clients", client="Sams")["clients"]) == 1       # Bonsai left action out: list is the default


def test_list_names_the_maker_type_and_earlier_private_addresses(call, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # "what's that local device on my network with a generic name" - shapes from a live BE9300, values made up
    devs = [{"mac": "A4-F0-1F-00-53-07", "ip": "192.0.2.7", "name": "printer-0053", "connection": "2.4G"},
            {"mac": "A4-F0-1F-00-53-16", "ip": "192.0.2.16", "name": "Sams-Phone", "connection": "5G"},
            {"mac": "02-00-5E-00-53-17", "ip": "192.0.2.17", "name": "network device", "connection": "5G"},
            {"mac": "52-54-00-00-53-10", "ip": "192.0.2.10", "name": "DC01", "connection": "wired"},
            {"mac": "02-00-5E-00-53-52", "ip": "192.0.2.11", "name": "Phone-T7", "connection": "5G"}]
    known = {"clientList": [
        {"mac": "A4-F0-1F-00-53-07", "name": "printer-0053", "clientType": "Printer"},
        {"mac": "A4-F0-1F-00-53-16", "name": "Sams-Phone", "clientType": "Mobile"},
        {"mac": "02-00-5E-00-53-41", "name": "Sams-Phone", "clientType": "Mobile"},
        {"mac": "02-00-5E-00-53-42", "name": "Sams-Phone", "clientType": "Mobile"},
        {"mac": "BC-94-24-00-53-51", "name": "Phone-T7", "clientType": "Mobile"},
        {"mac": "02-00-5E-00-53-17", "name": "network device", "clientType": "Other"},
        {"mac": "02-00-5E-00-53-43", "name": "network device", "clientType": "Other"}]}
    real = fake.call

    def call_(path: str, op: str, fields: Any = None, **k: Any) -> Any:
        if path == "avira_parental_control?form=avira_pactrl" and op == "getDevicesList":
            return known
        return real(path, op, fields, **k)

    monkeypatch.setattr(fake, "call", call_)
    monkeypatch.setattr("mcp_tplink_router.features.Ctx.clients", lambda self: devs)
    out = call("clients", action="list")
    by = {d["name"]: d for d in out["clients"]}
    assert by["printer-0053"]["maker"] == "CANON INC." and by["printer-0053"]["type"].startswith("Printer")
    assert by["Sams-Phone"]["same_name_seen_on"] == ["02-00-5E-00-53-41", "02-00-5E-00-53-42"]
    priv = by["network device"]
    assert priv["private_mac"] is True and "cannot be read" in priv["maker"]
    assert "same_name_seen_on" not in priv and "type" not in priv     # placeholder names / 'Other' say nothing
    assert by["DC01"]["maker"] == "QEMU/KVM virtual machine" and "private_mac" not in by["DC01"]
    assert "2 device(s) use a private" in out["private_addresses"]
    from mcp_tplink_router import makers
    t = by["Phone-T7"]
    assert t["private_mac"] and t["maker_from_earlier_address"].startswith(makers.maker("BC-94-24-00-53-51") or "?")
    assert "maker_from_earlier_address" not in by["Sams-Phone"]   # its own address is real: maker already known


def test_mlo_clients_missing_from_the_status_lists_are_added(call, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # live BE9300 fw 1.2.4: status?form=all has no list for Wi-Fi 7 MLO clients; an MLO speaker and phone were
    # missing from every device list.  The full device list marks them online (connType wls_mlo).
    real = fake.call

    def call_(path: str, op: str, fields: Any = None, **k: Any) -> Any:
        if path == "avira_parental_control?form=avira_pactrl" and op == "getDevicesList":
            return {"clientList": [
                {"mac": "00-00-5E-00-53-61", "name": "Speaker", "online": True, "connType": "wls_mlo",
                 "clientType": "Voice Control"},
                {"mac": "00-00-5E-00-53-62", "name": "Old-Phone", "online": False, "connType": "wls_mlo"}]}
        if path == "dhcps?form=client":
            return [{"macaddr": "00-00-5E-00-53-61", "ipaddr": "192.0.2.61", "name": "Speaker"}]
        return real(path, op, fields, **k)

    monkeypatch.setattr(fake, "call", call_)
    out = call("clients", action="list")
    mlo = [d for d in out["clients"] if d["mac"] == "00-00-5E-00-53-61"]
    assert mlo and mlo[0]["ip"] == "192.0.2.61" and mlo[0]["connection"] == "Wi-Fi 7 MLO"
    assert mlo[0]["type"].startswith("Voice Control")
    assert not any(d["mac"] == "00-00-5E-00-53-62" for d in out["clients"])    # offline: not listed
