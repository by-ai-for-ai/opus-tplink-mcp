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
    assert out["history"]["points"][0] == {"up": "678.0 KB", "down": "896.7 KB"}
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
