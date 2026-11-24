"""Catalog consistency, redaction, raw tools, logs, journal, forbidden gating."""

from __future__ import annotations

import json
import os
import stat

import pytest

from mcp_tplink_router import catalog
from mcp_tplink_router.safety import is_secret_field, redact

from .fake_router import SHAPES, WIFI_PSK


# ------------------------------------------------------------------ catalog
def _shape_keys(path: str) -> set[str] | None:
    entry = SHAPES.get(path)
    if not entry or not entry.get("op"):
        return None
    shape = entry["shape"]
    if isinstance(shape, list):
        return set(shape[0]) if shape and isinstance(shape[0], dict) else None
    return set(shape) or None if isinstance(shape, dict) else None


def test_catalog_fields_exist_in_live_shapes() -> None:
    """Cheap typo catcher: every key_field / write_field must exist in that form's live shape."""
    for ep in catalog.CURATED.values():
        keys = _shape_keys(ep.path)
        if keys is None:
            continue
        if ep.list_key:
            assert ep.list_key in keys, ep.path
            continue
        if ep.key_field and ep.kind == "table":
            assert ep.key_field in keys, (ep.path, ep.key_field)
        for f in ep.write_fields or ():
            assert f in keys, (ep.path, f)


def test_catalog_read_ops_match_probe() -> None:
    for ep in catalog.CURATED.values():
        entry = SHAPES.get(ep.path)
        if entry and entry.get("op") and ep.kind == "form":
            assert ep.read_op == entry["op"], ep.path


def test_risk_tiers() -> None:
    assert catalog.risk_of("firmware?form=config", "factory") == "forbidden"
    assert catalog.risk_of("firmware?form=config", "check") == "read"
    assert catalog.risk_of("quick_setup?form=quick_setup", "write") == "forbidden"
    assert catalog.risk_of("cloud_account?form=cloud_unbind", "write") == "forbidden"
    assert catalog.risk_of("network?form=wan_ipv4_dynamic", "write") == "critical"
    assert catalog.risk_of("network?form=lan_ipv4", "write") == "critical"
    assert catalog.risk_of("system?form=reboot", "reboot") == "critical"
    assert catalog.risk_of("wireguard?form=config", "renew") == "critical"
    assert catalog.risk_of("syslog?form=log", "remove") == "critical"
    assert catalog.risk_of("dhcps?form=reservation", "insert") == "normal"
    assert catalog.risk_of("iptv?form=setting", "read") == "read"
    assert catalog.risk_of("accessibility?form=accessibility_state", "write") == "critical"  # unknown write format -> look first
    assert len(catalog.all_paths()) >= 219


def test_catalog_tool(call) -> None:  # type: ignore[no-untyped-def]
    out = call("router_catalog", filter="dhcps")
    assert {f["path"] for f in out["forms"]} == {"dhcps?form=setting", "dhcps?form=reservation", "dhcps?form=client"}
    one = call("router_catalog", path="dhcps?form=reservation")
    assert one["ops"]["insert"] == {"risk": "normal", "verified": "live"} and one["key_field"] == "mac"


# ---------------------------------------------------------------- redaction
@pytest.mark.parametrize("name", ["psk_key", "wpa_key", "wep_key3", "password", "portal_password", "private_key",
                                  "preshared_key", "old_pwd", "wps_pin", "token", "guest_2g_psk_key", "secret",
                                  "wireless_5g_wpa_key", "wep_key1", "guest_6g_portal_password", "new_pwd"])
def test_secret_names(name: str) -> None:
    assert is_secret_field(name)


@pytest.mark.parametrize("name", ["key", "public_key", "server_key", "wan_ping", "lan_ping", "pri_dns", "mapping",
                                  "modem_pinlock", "keepalive", "kill_switch", "ssid", "mac", "psk_cipher",
                                  "psk_version", "wireless_2g_psk_cipher", "guest_5g_psk_version", "passwd_cycle",
                                  "wpa_cipher", "wpa_version", "wep_select", "wep_format1", "wep_type2", "wep_mode",
                                  "password_type"])
def test_not_secret_names(name: str) -> None:
    assert not is_secret_field(name)


def test_redact_scrubs_values_inside_strings() -> None:
    obj = {"psk_key": "hunter2-long", "old": json.dumps({"private_key": "PRIV-1234"}), "msg": "bad PRIV-1234 x"}
    out = redact(obj)
    assert out["psk_key"] == "<redacted>"
    assert "PRIV-1234" not in json.dumps(out)
    assert redact(obj, reveal=True) == obj


def test_status_and_get_never_leak_wifi_password(call) -> None:  # type: ignore[no-untyped-def]
    for out in (call("router_status"), call("router_get", section="status"), call("router_get", section="wifi"),
                call("router_raw_read", path="wireless?form=wireless_2g", operation="read_spf")):
        assert WIFI_PSK not in json.dumps(out)
    assert WIFI_PSK in json.dumps(call("router_get", section="wifi_2g", reveal=True))


# ---------------------------------------------------------------- get / raw read
def test_router_get_sections(call) -> None:  # type: ignore[no-untyped-def]
    assert "dhcp_reservations" in call("router_get")["sections"]
    assert call("router_get", section="dhcp")["data"]["ipaddr_start"] == "192.168.0.100"
    clients = call("router_get", section="clients")["data"]["clients"]
    me = [c for c in clients if c.get("this_machine")]
    assert me and me[0]["ip"] == "192.168.0.160"
    phone = [c for c in clients if c["name"] == "kid-phone"][0]
    assert phone["random_mac"] is True and phone["reservation"] is None
    assert call("router_get", section="iptv?form=setting")["path"] == "iptv?form=setting"
    assert "unknown section" in call("router_get", section="nope")["error"]


def test_raw_read_refuses_writes(call, fake) -> None:  # type: ignore[no-untyped-def]
    assert "not read-only" in call("router_raw_read", path="dhcps?form=setting", operation="write")["error"]
    assert "not a form" in call("router_raw_read", path="evil?form=x")["error"]
    out = call("router_raw_read", path="avira_parental_control?form=avira_pactrl", operation="getBlockHistory",
               fields={"ownerId": "1"})
    assert out["data"]["history"]
    assert fake.writes() == []


# ---------------------------------------------------------------------- logs
def test_logs_filters(call, fake) -> None:  # type: ignore[no-untyped-def]
    out = call("router_logs")
    assert out["total"] == 3 and out["order"] == "newest first"
    assert out["logs"][0]["time"] == "2026-11-17 08:05:00"
    assert [r["type"] for r in call("router_logs", level="WARNING")["logs"]] == ["WAN", "SYSTEM"]
    assert call("router_logs", type="dhcpd")["matched"] == 1
    assert call("router_logs", contains="00:00:5e:00:53")["matched"] == 1
    assert call("router_logs", since="2026-11-17 08:00:00")["matched"] == 2
    assert call("router_logs", limit=1)["returned"] == 1
    assert fake.writes() == []  # never touches syslog?form=filter


# ------------------------------------------------------------- journal / raw write
def test_journal_permissions_and_listing(apply, call, rt) -> None:  # type: ignore[no-untyped-def]
    done = apply("upnp", action="disable")
    mode = stat.S_IMODE(os.stat(rt.journal.path).st_mode)
    assert mode == 0o600 and stat.S_IMODE(os.stat(rt.journal.dir).st_mode) == 0o700
    listed = call("router_journal")
    assert listed["entries"][0]["id"] == done["journal_id"]
    shown = call("router_journal", action="show", id=done["journal_id"])
    assert shown["status"] == "applied" and shown["before"]["upnp?form=enable"]["enable"] == "on"


def test_journal_encrypts_secrets_at_rest_but_show_redacts(apply, call, rt) -> None:  # type: ignore[no-untyped-def]
    done = apply("wifi_set", action="set", band="2g", settings={"password": "brand-new-pass-1"})
    raw = rt.journal.path.read_text()
    assert "brand-new-pass-1" not in raw and WIFI_PSK not in raw  # never plain text on disk
    entry = rt.journal.get(done["journal_id"])  # ... but the journal itself can still read it for undo
    assert "brand-new-pass-1" in json.dumps(entry) and WIFI_PSK in json.dumps(entry)
    shown = call("router_journal", action="show", id=done["journal_id"])
    assert "brand-new-pass-1" not in json.dumps(shown) and WIFI_PSK not in json.dumps(shown)


def test_raw_write_undoable_when_old_values_known(apply, fake) -> None:  # type: ignore[no-untyped-def]
    done = apply("router_raw_write", path="ledgeneral?form=setting", operation="write", fields={"enable": "off"})
    assert done["status"] == "applied" and fake.state["ledgeneral?form=setting"]["enable"] == "off"
    apply("router_undo", id=done["journal_id"])
    assert fake.state["ledgeneral?form=setting"]["enable"] == "on"


def test_raw_write_unknown_op_is_critical(call) -> None:  # type: ignore[no-untyped-def]
    out = call("router_raw_write", path="iptv?form=setting", operation="frobnicate", fields={})
    assert out["risk"] == "critical" and out["confirm_token"]


def test_forbidden_needs_env(call, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    dry = call("router_raw_write", path="firmware?form=config", operation="factory", fields={"all": "false"})
    assert dry["risk"] == "forbidden"
    out = call("router_raw_write", path="firmware?form=config", operation="factory", fields={"all": "false"},
               apply=True, confirm_token=dry["confirm_token"])
    assert out["applied"] is False and "TPLINK_ALLOW_FORBIDDEN" in out["refused"]
    assert fake.writes() == []
    monkeypatch.setenv("TPLINK_ALLOW_FORBIDDEN", "1")
    out = call("router_raw_write", path="firmware?form=config", operation="factory", fields={"all": "false"},
               apply=True)
    assert out["applied"] is False and "confirm_token" in out["refused"]


def test_reboot_not_undoable(apply, call) -> None:  # type: ignore[no-untyped-def]
    done = apply("router_raw_write", path="system?form=reboot", operation="reboot", fields={})
    out = call("router_undo", id=done["journal_id"])
    assert any("cannot be undone" in e for e in out["errors"])


def test_tool_annotations() -> None:
    from mcp_tplink_router.server import tool_definitions

    defs = {t.name: t for t in tool_definitions()}
    assert defs["router_status"].annotations.readOnlyHint is True
    assert defs["dhcp_reservation"].annotations.destructiveHint is True
    assert len(defs) <= 34  # compact tool list; extenders add a read-only + a write tool


def test_raw_read_refuses_forbidden_forms(call, fake) -> None:  # type: ignore[no-untyped-def]
    for path, op in (("debug?form=cmd", "read"), ("cloud_account?form=get_token", "read"),
                     ("quick_setup?form=quick_setup", "read"), ("firmware?form=config", "factory")):
        out = call("router_raw_read", path=path, operation=op)
        assert "error" in out, (path, out)
    assert fake.calls == []


def test_unreachable_device_gets_an_address_hint_not_the_one_session_hint() -> None:
    from mcp_tplink_router.journal import Journal
    from mcp_tplink_router.tools import Runtime, run_tool
    from mcp_tplink_router.transport import RouterError

    def down() -> None:
        raise RouterError("login_failed", "HTTPSConnectionPool(host='192.0.2.9', port=443): Max retries exceeded "
                                          "(Caused by ConnectTimeoutError(... 'Connection to 192.0.2.9 timed out.'))")
    out = run_tool("router_status", {}, Runtime(factory=down, journal=Journal(), retry_delay=0))
    assert out["error"] == "login_failed" and "did not answer" in out["hint"] and "ONE admin" not in out["hint"]


def test_every_change_needs_a_dry_run_token(call, fake) -> None:  # type: ignore[no-untyped-def]
    # Local-model bench (Bonsai 27B, 1-bit): it sent apply=true without ever previewing whenever allowed.
    out = call("system", action="led", enable=False, apply=True)
    assert out["applied"] is False and "dry run first" in out["refused"] and fake.writes() == []
    assert out["dry_run"] and out["diff"] and out["confirm_token"]  # the refusal IS the dry run
    done = call("system", action="led", enable=False, apply=True, confirm_token=out["confirm_token"])
    assert done["status"] == "applied"


def test_a_change_request_that_only_reads_is_never_reported_as_success(call, fake) -> None:
    # Local-model bench: Bonsai left out action=set, wifi_set fell back to action=get, and the model told the
    # user "5 GHz has been turned off" while nothing changed.
    out = call("wifi_set", action="get", band="5g", settings={"enable": "off"}, apply=True, confirm_token="abc123")
    assert out["applied"] is False and out["changed"] is False and "NOTHING WAS CHANGED" in out["error"]
    assert "action=set" in out["hint"] and fake.writes() == []
    # Without an action the settings now mean "set": a fake token is refused, nothing is sent.
    fake_tok = call("wifi_set", band="5g", settings={"enable": "off"}, apply=True, confirm_token="abc123")
    assert fake_tok["applied"] is False and fake_tok["refused"] and fake.writes() == []
    led = call("system", action="led", apply=True)  # no enable / settings: a read
    assert led["changed"] is False


def test_settings_without_action_means_set(call, fake) -> None:
    # Local-model bench: Bonsai left out action=set on every wifi_set call and looped on reads.
    out = call("wifi_set", band="5g", settings={"enable": "off"})
    assert out["dry_run"] and out["confirm_token"] and "action=set" in out["assumed"]
    done = call("wifi_set", band="5g", settings={"enable": "off"}, apply=True, confirm_token=out["confirm_token"])
    assert done["status"] == "applied" and done["verified"] == "yes"


def test_nothing_changed_reply_carries_the_exact_next_call(call) -> None:
    out = call("wifi_set", action="get", band="5g", settings={"enable": "off"}, apply=True)
    assert "NOTHING WAS CHANGED" in out["error"]
    assert out["next_call"]["arguments"] == {"action": "set", "band": "5g", "settings": {"enable": "off"}}


def test_raw_and_catalog_tools_point_to_the_dedicated_tool(call) -> None:
    # Local-model bench: Nemotron 3 Nano 4B could not find system action=led and tried router_raw_write.
    cat = call("router_catalog", filter="led")
    assert any(r.get("use_tool") == "system action=led" for r in cat["forms"])
    raw = call("router_raw_read", path="ledgeneral?form=setting")
    assert raw["use_instead"].startswith("system action=led")
    w = call("router_raw_write", path="ledgeneral?form=setting", operation="write", fields={"enable": "off"})
    assert any("USE THE DEDICATED TOOL INSTEAD: system action=led" in x for x in w["warnings"])
    bad = call("router_raw_read", path="system?form=led")
    assert "use the tool: system action=led" in bad["error"]


def test_made_up_settings_are_rejected_not_dropped(call) -> None:
    # Local-model bench: Granite 4 H Tiny sent wifi_set band=guest settings={"led_off": true}; the tool
    # dropped the unknown key, returned no_change, and the model told the user the LEDs were off.
    out = call("wifi_set", action="set", band="guest", settings={"led_off": True})
    assert "use the tool system action=led" in out["error"]
    out = call("wifi_set", action="set", band="guest", settings={"made_up_field": 1})
    assert "no setting(s) ['made_up_field']" in out["error"]


def test_no_change_says_nothing_changed(call) -> None:
    cur = call("system", action="led")["led"]["enable"]
    out = call("system", action="led", enable=cur == "on")
    assert out["tell_user"].startswith("NOTHING WAS CHANGED") and out.get("applied") is not True


def test_true_false_sent_as_text_are_understood(call, fake) -> None:
    # Local-model bench: Nemotron sent settings={"enable": "false"}; the router stored "off" and the tool
    # misreported a mismatch.  "false"/"true" as text on an on/off field mean off/on.
    fake.state["ledgeneral?form=setting"] = {"enable": "on", "time_set": "yes", "ledst_support": "yes"}
    dry = call("system", action="led", settings={"enable": "false"})
    assert dry["diff"][0]["changes"]["enable"]["to"] == "off"
    done = call("system", action="led", settings={"enable": "false"}, apply=True, confirm_token=dry["confirm_token"])
    assert done["status"] == "applied" and done["verified"] == "yes"


def test_a_dry_run_says_it_is_not_done_yet(call) -> None:
    # Local-model bench: Gemma 4 12B ran the dry run four times, never applied, and said "LEDs turned off".
    out = call("system", action="led", enable=False)
    assert list(out)[:2] == ["status", "tell_user"] and out["status"] == "PREVIEW_ONLY"
    assert out["verified"] == "not_done_yet" and out["tell_user"].startswith("THIS IS A PREVIEW")
    refused = call("system", action="led", enable=False, apply=True)
    assert refused["status"] == "REFUSED_NOTHING_CHANGED" and refused["applied"] is False and refused["refused"]
    assert refused["tell_user"].startswith("NOT DONE - NOTHING CHANGED") and refused["next_call"]["arguments"]["apply"]
    # Step 2 exactly as handed over works.
    nxt = out["next_call"]
    assert nxt["tool"] == "system" and nxt["arguments"]["apply"] is True
    done = call(nxt["tool"], **nxt["arguments"])
    assert done["status"] == "applied" and done["verified"] == "yes"


def test_compact_tool_set_is_opt_in(call, monkeypatch) -> None:
    from mcp_tplink_router.server import tool_definitions

    assert len(tool_definitions()) == 33  # default: everything
    monkeypatch.setenv("TPLINK_TOOLSET", "core")
    names = {t.name for t in tool_definitions()}
    assert "router_raw_write" not in names and {"wifi_set", "system", "router_undo"} <= names
    out = call("router_raw_write", path="ledgeneral?form=setting", operation="write", fields={"enable": "off"})
    assert "compact tool set" in out["error"] and "system" in out["tools"]


def test_wifi_set_top_level_enable_means_band_on_off(call) -> None:
    # Local-model bench: Gemma 4 E4B (compact set) sent action=set band=5g enable=false, got "settings
    # required, e.g. ssid/password", and then filled in ssid/password "dummy".
    out = call("wifi_set", action="set", band="5g", enable=False)
    assert out["dry_run"] and out["diff"][0]["changes"]["enable"]["to"] == "off"
    err = call("wifi_set", action="set", band="5g")
    assert "enable=false" in err["error"] and "never fill in a name or password" in err["error"]


def test_every_literal_example_in_the_descriptions_works(call, fake) -> None:
    import json as _json
    import re as _re

    from mcp_tplink_router.tools import EXAMPLES

    for tool, examples in EXAMPLES.items():
        for ex in examples:
            raw = _re.match(r"(\{.*?\})(\s|$)", ex).group(1)
            if "<" in raw or "small tier only" in ex:
                continue  # placeholders are filled from another call; small-tier examples are tested there
            args = _json.loads(raw)
            if tool.startswith("extender"):
                continue  # needs an extender-kind device
            out = call(tool, **args)
            assert "error" not in out, (tool, args, out.get("error"))


def test_status_never_reports_empty_firmware_as_nulls(call, fake) -> None:
    # Bench: the BE3600 sometimes answered the firmware read with no details; router_status passed on
    # model/firmware_version/hardware_version = null and a model told the user "firmware: not specified".
    real = fake.state["firmware?form=upgrade"]
    fake.state["firmware?form=upgrade"] = {}
    out = call("router_status")
    assert "unavailable" in out["firmware"] and None not in out["firmware"].values()
    fake.state["firmware?form=upgrade"] = real
    assert "unavailable" not in call("router_status")["firmware"]


def test_every_applied_change_carries_its_undo(call) -> None:
    dry = call("system", action="led", enable=False)
    done = call("system", **dry["next_call"]["arguments"])
    assert done["undo_call"] == {"tool": "router_undo", "arguments": {"id": done["journal_id"]}}
    assert "To reverse it: router_undo id=" in done["tell_user"]


def test_preview_mode_critical_applies_normal_changes_directly(call, monkeypatch) -> None:
    monkeypatch.setenv("TPLINK_PREVIEW", "critical")
    out = call("system", action="led", enable=False)  # no apply, no token: a normal change applies at once
    assert out["status"] == "applied" and out["verified"] == "yes" and out["undo_call"]
    crit = call("wifi_set", action="set", band="2g", enable=False)  # critical: still a preview
    assert crit["status"] == "PREVIEW_ONLY"
    from mcp_tplink_router.server import tool_definitions
    assert "APPLY IN ONE CALL" in next(t for t in tool_definitions() if t.name == "system").description


def test_server_remembers_unfinished_changes(call) -> None:
    # Local-model bench: Gemma 4 12B planned "dry run, then apply" in its reasoning, lost that plan on the next
    # turn (clients do not send reasoning back) and previewed the same change five times.  The server keeps
    # the task state instead.
    first = call("system", action="led", enable=False)
    assert first["status"] == "PREVIEW_ONLY"
    again = call("system", action="led", enable=False)
    assert again["status"] == "ALREADY_PREVIEWED" and "Send next_call now" in again["tell_user"]
    # An unrelated call is NOT reminded (it could nudge a model into a change nobody asked for) ...
    assert "pending" not in call("router_status")
    # ... a call to the same tool is.
    same = call("system", action="led")
    assert same["pending"]["changes"][0]["change"] == first["summary"]
    assert "ONLY if the user's current request asked" in same["pending"]["note"]
    done = call("system", **again["next_call"]["arguments"])
    assert done["status"] == "applied" and "pending" not in done
    assert "pending" not in call("system", action="led")


def test_small_tier_repeat_confirms_short_replies_compact_tools(call, monkeypatch) -> None:
    # Local-model bench: Gemma 4 12B reasoned only on its first turn, then re-sent its own last call unchanged.
    monkeypatch.setenv("TPLINK_MODEL_TIER", "small")
    first = call("wifi_set", action="set", band="2g", enable=False)
    assert first["status"] == "PREVIEW_ONLY" and "details" in first and "same request again" in first["tell_user"]
    again = call("wifi_set", action="set", band="2g", enable=False)  # identical repeat = confirmation
    assert again["status"] == "applied" and again["verified"] == "yes" and "repeating" in again["details"]["mode"]
    from mcp_tplink_router.server import tool_definitions
    names = {t.name for t in tool_definitions()}
    assert "router_raw_write" not in names  # compact set by default in the small tier
    assert call("router_status")["model_tier"] == "small"


def test_large_tier_repeat_does_not_confirm(call) -> None:
    call("wifi_set", action="set", band="2g", enable=False)
    again = call("wifi_set", action="set", band="2g", enable=False)
    assert again["status"] == "ALREADY_PREVIEWED" and again["applied"] is False


def test_small_tier_declined_preview_is_not_revived_by_a_later_repeat(call, monkeypatch) -> None:
    # A repeat confirms only as the VERY NEXT call after its preview; after anything else (e.g. the user
    # declined and the model did other things), the same request gets a fresh preview.
    monkeypatch.setenv("TPLINK_MODEL_TIER", "small")
    first = call("wifi_set", action="set", band="2g", enable=False)
    assert first["status"] == "PREVIEW_ONLY"
    call("router_status")  # something else happened in between
    later = call("wifi_set", action="set", band="2g", enable=False)
    assert later["status"] in ("PREVIEW_ONLY", "ALREADY_PREVIEWED") and later["applied"] is False


def test_small_tier_repeat_window_expires(call, monkeypatch) -> None:
    from mcp_tplink_router import safety

    monkeypatch.setenv("TPLINK_MODEL_TIER", "small")
    call("wifi_set", action="set", band="2g", enable=False)
    for e in safety.PENDING["main"].values():
        e["at"] -= 120  # two minutes ago
    out = call("wifi_set", action="set", band="2g", enable=False)
    assert out["applied"] is False


def test_small_tier_states_recent_changes_and_undoes_the_last_without_an_id(call, fake, monkeypatch) -> None:
    monkeypatch.setenv("TPLINK_MODEL_TIER", "small")
    fake.state["ledgeneral?form=setting"] = {"enable": "on", "time_set": "yes", "ledst_support": "yes"}
    assert str(call("router_status")["recent_changes"]).startswith("none")  # the truth before any change
    call("system", action="led", enable=False)
    done = call("system", action="led", enable=False)  # repeat = confirm (small tier)
    assert done["status"] == "applied"
    rc = call("router_status")["recent_changes"]
    assert rc[-1]["id"] == done["journal_id"] and rc[-1]["status"] == "applied"
    prev = call("router_undo")  # no id: the most recent change, previewed first
    assert prev["status"] == "PREVIEW_ONLY"
    undone = call("router_undo")
    assert undone["status"] == "applied" and fake.state["ledgeneral?form=setting"]["enable"] == "on"


def test_large_tier_undo_still_needs_an_id(call) -> None:
    assert "id is required" in call("router_undo")["error"]


def test_small_tier_undo_without_id_ignores_old_changes(call, fake, rt, monkeypatch) -> None:
    monkeypatch.setenv("TPLINK_MODEL_TIER", "small")
    fake.state["ledgeneral?form=setting"] = {"enable": "on", "time_set": "yes", "ledst_support": "yes"}
    call("system", action="led", enable=False)
    assert call("system", action="led", enable=False)["status"] == "applied"
    import json as _json
    p = rt.journal.path  # age every entry by an hour: a change from another conversation
    lines = [_json.loads(x) for x in p.read_text().splitlines() if x.strip()]
    p.write_text("".join(_json.dumps({**r, "ts": r["ts"] - 3600} if "ts" in r else r) + "\n" for r in lines))
    out = call("router_undo")
    assert "nothing recent to undo" in out["error"]


def test_a_fake_confirm_token_is_reported_as_refused_not_as_a_preview(call) -> None:
    # Local-model bench: Gemma 4 12B sent confirm_token="abc123", got PREVIEW_ONLY and told the user "turned off".
    out = call("wifi_set", action="set", band="5g", enable=False, apply=True, confirm_token="abc123")
    assert out["status"] == "REFUSED_NOTHING_CHANGED" and out["applied"] is False
    assert out["tell_user"].startswith("NOT DONE - NOTHING CHANGED")


def test_small_tier_memory_tells_the_truth_first(call, monkeypatch) -> None:
    # Local-model bench: Gemma 4 12B wrote "5 GHz turned off" from its own turn-1 plan without reading the refusal.
    monkeypatch.setenv("TPLINK_MODEL_TIER", "small")
    out = call("wifi_set", action="set", band="5g", enable=False, apply=True, confirm_token="abc123",
               intent="turn off the 5 GHz Wi-Fi")
    assert list(out)[0] == "memory"
    m = out["memory"]
    assert m["you_were_asked_to"] == "turn off the 5 GHz Wi-Fi" and m["is_it_done"] == "NO"
    assert m["what_actually_happened"].startswith("NOT DONE - refused")
    # it carries over to the next call, and flips to YES only when the device confirms
    again = call("wifi_set", **out["next_call"]["arguments"])
    assert again["memory"]["is_it_done"] == "YES" and again["memory"]["you_were_asked_to"] == "turn off the 5 GHz Wi-Fi"


def test_large_tier_has_no_memory_block(call) -> None:
    out = call("wifi_set", action="set", band="5g", enable=False)
    assert "memory" not in out


def test_a_bool_for_an_on_off_field_is_sent_as_on_off_and_verifies(call, fake) -> None:  # type: ignore[no-untyped-def]
    # LM Studio (Bonsai 27B): settings={"isolate": false} went to the router as the text "False"; the router stored
    # "off", the re-read was reported as a mismatch ("NOT DONE"), and the model told the user "applied and verified".
    prev = call("wifi_set", action="set", band="guest_access", settings={"isolate": False})
    assert (prev.get("details") or prev)["diff"][0]["changes"]["isolate"] == {"from": "on", "to": "off"}
    done = call("wifi_set", **prev["next_call"]["arguments"])
    assert done["status"] == "applied" and done["verified"] == "yes"
    assert fake.state["wireless?form=guest"]["isolate"] == "off"


def test_isolation_on_the_guest_band_points_to_guest_access(call) -> None:
    out = call("wifi_set", action="set", band="guest", settings={"isolate": False})
    assert out["status"] == "NOT_DONE" and '"band": "guest_access"' in out["error"]


def test_a_read_through_a_write_tool_is_not_remembered_as_not_done(call, monkeypatch) -> None:
    # LM Studio (Bonsai 27B): after 'wifi_set action=get' every reply carried
    # "you_were_asked_to: wifi_set, what_actually_happened: NOT DONE - unknown result".
    monkeypatch.setenv("TPLINK_MODEL_TIER", "small")
    out = call("wifi_set", action="get", band="guest_access")
    assert "memory" not in out
    assert "memory" not in call("system", action="info")


def test_undo_of_an_old_entry_holding_false_text_is_not_drift(call, fake, rt) -> None:  # type: ignore[no-untyped-def]
    # LM Studio (Bonsai 27B): the journal held isolate="False" (what was sent before f02c1e4), the router "off";
    # router_undo called that drift and refused.
    from mcp_tplink_router.safety import Step

    fake.state["wireless?form=guest"]["isolate"] = "off"
    step = Step("write", "wireless?form=guest", "write", fields={"isolate": "False"}, old={"isolate": "on"})
    eid = rt.journal.begin("wifi_set", "change guest network access/isolation", [step.to_dict()],
                           {"wireless?form=guest": {"isolate": "on"}}, risk="normal")
    rt.journal.finish(eid, "mismatch")
    prev = call("router_undo", id=eid)
    assert not prev.get("errors"), prev
    done = call("router_undo", **(prev.get("next_call") or {}).get("arguments", {"id": eid, "apply": True,
                                                                                 "confirm_token": prev.get("confirm_token")}))
    assert done["status"] == "applied" and fake.state["wireless?form=guest"]["isolate"] == "on"


def test_a_refused_undo_is_remembered_as_refused(call, apply, fake, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    changed = apply("dhcp_server_set", lease_minutes=600)
    fake.state["dhcps?form=setting"]["leasetime"] = "700"
    monkeypatch.setenv("TPLINK_MODEL_TIER", "small")
    out = call("router_undo", id=changed["journal_id"])
    assert out["memory"]["what_actually_happened"].startswith("NOT DONE - refused, nothing changed")


def test_boolish_keeps_each_fields_own_words() -> None:
    from mcp_tplink_router.features import boolish

    assert boolish("on", False) == "off" and boolish("off", "False") == "off"
    assert boolish("true", "true") == "true" and boolish("true", False) == "false"
    assert boolish("yes", True) == "yes" and boolish("0", True) == "1" and boolish(True, False) is False
    # every write and undo's drift check run through this: never move a field to another vocabulary
    assert boolish("enable", "enable") == "enable" and boolish("enable", False) == "disable"
    assert boolish("disabled", True) == "enabled" and boolish("On", False) == "Off" and boolish("ON", False) == "OFF"
