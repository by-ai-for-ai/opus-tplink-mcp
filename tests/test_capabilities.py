"""Features a router lacks are refused honestly, remembered per firmware, and forgotten on a firmware change."""

from __future__ import annotations

import json
from typing import Any

import pytest

from mcp_tplink_router import capabilities, events
from mcp_tplink_router.transport import RouterError


@pytest.fixture(autouse=True)
def _iso(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    monkeypatch.setenv("TPLINK_EVENTS_FILE", str(tmp_path / "events.jsonl"))
    events._SEEN.clear()


def test_no_such_callback_becomes_not_supported_and_is_remembered(call, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    real = fake.call
    calls: list[str] = []

    def no_upnp(path: str, op: str, fields: Any = None, **k: Any) -> Any:
        if path.startswith("upnp"):  # this "model" has no UPnP forms
            calls.append(path)
            raise RouterError("no such callback")
        return real(path, op, fields, **k)

    monkeypatch.setattr(fake, "call", no_upnp)
    out = call("upnp")
    assert out["status"] == "NOT_SUPPORTED" and "not supported by this tool on" in out["tell_user"]
    assert "may still exist in the router's own web page" in out["tell_user"]          # never "the router lacks it"
    n = len(calls)
    again = call("upnp")
    assert again["status"] == "NOT_SUPPORTED" and len(calls) == n                        # refused up front
    caps = call("router_status", capabilities=True)
    assert "upnp" in caps["not_supported_here"]


def test_firmware_change_forgets_what_was_learned(call) -> None:  # type: ignore[no-untyped-def]
    call("router_status")                                                                # firmware read once
    dev = next(iter(json.loads(events.path().with_name("devices-seen.json").read_text())))
    router, host = dev.split("@")
    capabilities.mark_absent(router, host, "usb", {"action": "status"}, "no such callback")
    assert capabilities.known_absent(router, host, "usb", {"action": "status"})
    capabilities.forget_router(router, host)
    assert not capabilities.known_absent(router, host, "usb", {"action": "status"})


def test_write_shape_gate_refuses_fields_this_form_lacks(call, fake) -> None:  # type: ignore[no-untyped-def]
    form = fake.state["ledgeneral?form=setting"]
    form.pop("enable", None)                                                             # this "model" has no such field
    out = call("system", action="led", enable=False)
    assert "not supported by this tool on this router" in json.dumps(out)


def test_a_missing_band_does_not_block_the_other_bands() -> None:
    a = capabilities._feature("wifi_set", {"action": "get", "band": "6g"})
    b = capabilities._feature("wifi_set", {"action": "get", "band": "2g"})
    assert a != b and a == "wifi_set:get:band=6g"
    assert capabilities._feature("clients", {"action": "rename", "mac": "02-00-00-00-00-01", "name": "x"}) == "clients:rename"


def test_combined_read_survives_one_missing_form(call, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # live (Archer AX3000, no 6 GHz radio): the combined guest read failed because guest_6g does not exist
    real = fake.call

    def no_6g(path: str, op: str, fields: Any = None, **k: Any) -> Any:
        if "guest_6g" in path:
            raise RouterError("no such callback")
        return real(path, op, fields, **k)

    monkeypatch.setattr(fake, "call", no_6g)
    out = call("wifi_set", action="get", band="guest")
    g = out["guest"]
    assert g["_absent_forms"] == ["guest_6g"] and any(k.startswith("guest_2g_") for k in g)


def test_operation_mode_is_part_of_the_memory(call) -> None:  # type: ignore[no-untyped-def]
    # owner: switching a router to AP mode and back must not leave router features blocked
    call("router_status")
    seen = json.loads(events.path().with_name("devices-seen.json").read_text())
    key = next(iter(seen))
    router, host = key.split("@")
    capabilities.mark_absent(router, host, "port_forwarding", {}, "no such callback")      # learned in AP mode
    assert capabilities.known_absent(router, host, "port_forwarding", {})
    seen[key]["mode"] = "router" if seen[key].get("mode") != "router" else "ap"           # mode switched back
    events.path().with_name("devices-seen.json").write_text(json.dumps(seen))
    assert not capabilities.known_absent(router, host, "port_forwarding", {})


def test_mode_change_is_logged_and_firmware_change_still_detected() -> None:
    base = {"model": "X", "hardware_version": "X v1", "firmware_version": "1.0"}
    events.note_firmware("r", "192.0.2.9", {**base, "mode": "router"})
    events.note_firmware("r", "192.0.2.9", {**base, "mode": "ap"})
    events.note_firmware("r", "192.0.2.9", {**base, "firmware_version": "1.1", "mode": "ap"})
    kinds = [e["kind"] for e in events.read()]
    assert kinds.count("mode_changed") == 1 and kinds.count("firmware_changed") == 1


def test_switching_mode_through_the_tool_forgets_the_learned_list(call, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    call("router_status")
    key = next(iter(json.loads(events.path().with_name("devices-seen.json").read_text())))
    router, host = key.split("@")
    capabilities.mark_absent(router, host, "port_forwarding", {}, "no such callback")
    cur = fake.state["system?form=sysmode"]["mode"]
    target = "ap" if cur != "ap" else "router"
    dry = call("maintenance", action="operation_mode", mode=target)
    assert dry.get("next_call"), dry                                                       # the switch was previewed
    done = call(dry["next_call"]["tool"], **dry["next_call"]["arguments"])
    assert done.get("applied") or done.get("status") in ("applied", "unknown"), done
    assert not any(k.startswith(f"{router}@{host}#") for k in capabilities._load())       # everything forgotten
