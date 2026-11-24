"""known_devices: the private, encrypted, local-only record of devices; labels; new-device flag; opt-out."""

from __future__ import annotations

from typing import Any

import pytest

from mcp_tplink_router import known_devices

DEVS = [{"mac": "00-00-5E-00-53-01", "ip": "192.0.2.1", "name": "Laptop", "connection": "5G"},
        {"mac": "02-00-5E-00-53-02", "ip": "192.0.2.2", "name": "network device", "connection": "2.4G"}]


@pytest.fixture
def devs(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    current = [dict(d) for d in DEVS]
    monkeypatch.setattr("mcp_tplink_router.features.Ctx.clients", lambda self: current)
    return current


def test_store_is_encrypted_and_private(call, devs) -> None:  # type: ignore[no-untyped-def]
    call("clients", action="list")
    out = call("clients", action="label", client="laptop", name="Sam's laptop", owner="Sam")
    assert out["saved"] and "router was not changed" in out["tell_user"]
    blob = known_devices.path().read_bytes()
    assert b"Sam" not in blob and b"00-00-5E" not in blob and b"Laptop" not in blob       # encrypted at rest
    assert oct(known_devices.path().stat().st_mode & 0o777) == "0o600"
    d = next(x for x in call("clients", action="list")["clients"] if x["mac"] == "00-00-5E-00-53-01")
    assert d["your_label"] == "Sam's laptop" and d["your_owner"] == "Sam" and d["first_seen"]


def test_new_device_is_flagged_for_a_day_but_not_on_the_first_run(call, devs, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    clock = [1_000_000.0]
    monkeypatch.setattr(known_devices.time, "time", lambda: clock[0])
    first = call("clients", action="list")["clients"]
    assert not any(d.get("new_on_network") for d in first)            # first run: everything would be "new"
    clock[0] += 3600
    devs.append({"mac": "02-00-5E-00-53-09", "ip": "192.0.2.9", "name": "network device", "connection": "5G"})

    def new_macs() -> set[str]:
        return {d["mac"] for d in call("clients", action="list")["clients"] if d.get("new_on_network")}

    assert new_macs() == {"02-00-5E-00-53-09"}
    call("clients", action="list", client="192.0.2.1")                  # a filtered call does not use it up
    assert new_macs() == {"02-00-5E-00-53-09"}
    clock[0] += 25 * 3600
    assert new_macs() == set()                                          # a day later it is just a device


def test_forget_and_ambiguous_label(call, devs) -> None:  # type: ignore[no-untyped-def]
    call("clients", action="label", mac="00:00:5e:00:53:01", name="Desk")
    assert call("clients", action="forget", mac="00-00-5E-00-53-01")["forgotten"] is True
    devs.append({"mac": "00-00-5E-00-53-03", "ip": "192.0.2.3", "name": "Laptop-2", "connection": "5G"})
    amb = call("clients", action="label", client="laptop", name="x")
    assert "ask the user which one" in amb["tell_user"] and len(amb["candidates"]) == 2


def test_switched_off_reads_and_writes_nothing(call, devs, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("TPLINK_KNOWN_DEVICES", "off")
    out = call("clients", action="list")
    assert not known_devices.path().exists() and not any("first_seen" in d for d in out["clients"])
    lab = call("clients", action="label", client="laptop", name="x")
    assert lab["saved"] is False and "switched off" in lab["tell_user"] and not known_devices.path().exists()


def test_a_damaged_store_never_breaks_the_listing(call, devs) -> None:  # type: ignore[no-untyped-def]
    known_devices.path().parent.mkdir(parents=True, exist_ok=True)
    known_devices.path().write_bytes(b"not a valid store")
    assert len(call("clients", action="list")["clients"]) == 2
    err = call("clients", action="label", client="laptop", name="x")["error"]
    assert "cannot read" in err and "opus-tplink-mcp devices wipe" in err
    assert known_devices.wipe() is True and not known_devices.path().exists()      # works on an unreadable file
    assert call("clients", action="label", client="laptop", name="ok")["saved"] is True


def test_cli_wipe_asks_unless_yes(call, devs, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    call("clients", action="label", client="laptop", name="x")
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    assert known_devices.cli(["wipe"]) == 1 and known_devices.path().exists()
    assert known_devices.cli(["status"]) == 0 and "2 device(s)" in capsys.readouterr().out
    assert known_devices.cli(["wipe", "--yes"]) == 0 and not known_devices.path().exists()


def test_the_server_starts_with_a_broken_store(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # the store is only touched by clients calls: a damaged file must never stop the server from starting
    known_devices.path().parent.mkdir(parents=True, exist_ok=True)
    known_devices.path().write_bytes(b"garbage")
    from mcp_tplink_router.server import registry_from_env

    assert "main" in registry_from_env().routers
