"""Exact call shapes local models got wrong on the extender bench, and what the tool now answers."""

from __future__ import annotations

import json
from typing import Any

import pytest


@pytest.fixture
def small(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TPLINK_MODEL_TIER", "small")


def test_read_says_which_device_it_is_about(small, call) -> None:  # type: ignore[no-untyped-def]
    out = call("router_status")  # bench: "the extender called 'attic'" -> every model omitted the name
    assert "NOT about it" in out["about_device"] and 'router="<that name>"' in out["about_device"]
    assert list(out)[0] in ("memory", "about_device")  # near the top, not buried in details


def test_named_device_still_reaches_the_tool(small, call) -> None:  # type: ignore[no-untyped-def]
    out = call("router_status", router="attic")
    assert "NO router named 'attic'" in json.dumps(out)
    assert "about_device" not in out  # the model named a device: no default-device note


def test_device_is_an_alias_of_router(small, call) -> None:  # type: ignore[no-untyped-def]
    out = call("router_status", device="attic")
    assert "NO router named 'attic'" in json.dumps(out)
    assert "name different devices" in call("router_status", router="main", device="attic")["error"]
    assert "error" not in call("router_status", device="main")


def test_token_inside_settings_is_not_done_with_the_fixed_call(small, call) -> None:  # type: ignore[no-untyped-def]
    dry = call("wifi_set", action="set", band="2g", settings={"enable": "off"})
    tok = dry["next_call"]["arguments"]["confirm_token"]
    # Gemma 12B: confirm_token nested in settings -> bare error -> told the user "turned off"
    out = call("wifi_set", action="set", band="2g", apply=True, settings={"enable": "off", "confirm_token": tok})
    assert out["status"] == "NOT_DONE" and out["applied"] is False
    assert out["tell_user"].startswith("NOT DONE - NOTHING CHANGED")
    fixed = out["next_call"]["arguments"]
    assert fixed["confirm_token"] == tok and fixed["settings"] == {"enable": "off"} and fixed["apply"] is True
    done = call("wifi_set", **fixed)
    assert done["status"] == "applied"


def test_write_usage_errors_say_not_done(call) -> None:  # type: ignore[no-untyped-def]
    out = call("wifi_set", action="set", band="2g", settings={"no_such_field": "x"})
    assert out["status"] == "NOT_DONE" and "NOTHING CHANGED" in out["tell_user"]
    read = call("router_status", router="attic")  # a read never says NOT_DONE (unknown devices: NO_SUCH_DEVICE)
    assert read.get("status") != "NOT_DONE"


def test_night_mode_read_says_enable_alone_is_enough(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp_tplink_router.journal import Journal
    from mcp_tplink_router.tools import TOOLS, Runtime, run_tool

    class Dev:
        def login(self) -> None: ...
        def logout(self) -> None: ...
        def call(self, path: str, op: str, fields: Any = None, **k: Any) -> Any:
            assert path == "ledpm?form=setting"
            return {"enable": "off", "ledpm_support": "yes", "time_start": "22:00", "time_end": "06:00"}

    rt = Runtime(factory=Dev, journal=Journal(), name="ext", kind="extender", retry_delay=0)
    out = run_tool("extender_set", {"router": "ext", "action": "led_night"}, rt)
    # Bench: models asked the user for times instead of turning night mode on
    assert "enable alone is enough" in out["note"] and "22:00 - 06:00" in out["note"]
    assert "saved times are used" in TOOLS["extender_set"].description


def test_failed_read_on_a_write_tool_is_not_labelled_not_done(call, fake) -> None:  # type: ignore[no-untyped-def]
    out = call("wifi_set", action="get", band="9g")  # a bad read: an error, but no change was attempted
    assert "error" in out and out.get("status") != "NOT_DONE"


def test_kind_words_are_not_names(call) -> None:  # type: ignore[no-untyped-def]
    # one configured device (a router named main): "the router" means it; "attic" is still unknown
    assert "error" not in call("router_status", router="the router")
    assert "error" not in call("router_status", router="My Router")
    assert "NO router named 'the extender'" in json.dumps(call("router_status", router="the extender"))
    assert "NO router named 'attic'" in json.dumps(call("router_status", router="attic"))


def test_the_extender_means_the_only_extender() -> None:
    from mcp_tplink_router.journal import Journal
    from mcp_tplink_router.tools import Registry, Runtime

    ext = Runtime(factory=lambda: None, journal=Journal(), name="main", kind="extender", retry_delay=0)
    reg = Registry({"main": ext})
    assert reg.get("the extender") is ext and reg.get("Extender") is ext
    assert reg._generic("attic") == "attic"


def test_unknown_device_has_a_ready_answer(call) -> None:  # type: ignore[no-untyped-def]
    out = call("router_status", router="garage")
    assert out["status"] == "NO_SUCH_DEVICE" and "There is no device named 'garage'" in out["tell_user"]
    assert "main" in out["tell_user"]


def test_router_and_device_naming_the_same_device_is_not_a_conflict(call) -> None:  # type: ignore[no-untyped-def]
    assert "error" not in call("router_status", router="main", device="the router")
    assert "name different devices" in call("router_status", router="main", device="attic")["error"]


def test_apply_with_token_but_missing_action_gets_the_previewed_call(small, call, fake) -> None:  # type: ignore[no-untyped-def]
    dry = call("wifi_set", action="set", band="2g", enable=False)
    tok = dry["next_call"]["arguments"]["confirm_token"]
    out = call("wifi_set", band="2g", enable=False, apply=True, confirm_token=tok)  # Bonsai: action=set dropped
    assert out.get("applied") is False and out["next_call"] == dry["next_call"]
    done = call(out["next_call"]["tool"], **out["next_call"]["arguments"])
    assert done["status"] == "applied"


def test_placeholder_device_word_means_the_only_device(call) -> None:  # type: ignore[no-untyped-def]
    assert "error" not in call("router_status", device="device")  # Nemotron 4B
    assert "error" not in call("router_status", router="main", device="the device")
    assert "NO router named 'garage'" in json.dumps(call("router_status", device="garage"))


def test_garbled_token_timestamp_still_gets_the_previewed_call_but_cannot_apply(small, call, fake) -> None:  # type: ignore[no-untyped-def]
    dry = call("wifi_set", action="set", band="2g", enable=False)
    tok = dry["next_call"]["arguments"]["confirm_token"]
    garbled = "1" + tok.split(".")[0][2:] + "." + tok.split(".")[1]  # Gemma 12B: timestamp digits mangled
    out = call("wifi_set", band="2g", enable=False, apply=True, confirm_token=garbled)  # and action dropped
    assert out.get("applied") is False and out["next_call"] == dry["next_call"]
    bad = call("wifi_set", action="set", band="2g", enable=False, apply=True, confirm_token=garbled)
    assert bad.get("applied") is not True and fake.state["wireless?form=wireless_2g"]["enable"] == "on"


def test_preview_and_result_name_the_actual_change(small, call) -> None:  # type: ignore[no-untyped-def]
    # Nemotron 4B turned off 5 GHz when asked for 2.4 GHz and said "2.4 GHz turned off"
    dry = call("wifi_set", action="set", band="5g", enable=False)
    assert "5g" in dry["tell_user"] and "enable: on -> off" in dry["tell_user"]
    done = call(dry["next_call"]["tool"], **dry["next_call"]["arguments"])
    assert done["tell_user"].startswith("DONE AND VERIFIED: change 5g Wi-Fi (enable: on -> off")
    pw = call("wifi_set", action="set", band="2g", settings={"password": "brand-new-pass-1"})
    # the tool's own wording never contains it (next_call echoes the model's own argument so step 2 can send it)
    assert "brand-new-pass-1" not in pw["tell_user"] and "psk_key: changed" in pw["tell_user"]
