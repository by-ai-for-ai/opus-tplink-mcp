"""device_db (client): consent, the exact payload, background send/receive, local matching of the shared table."""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from mcp_tplink_router import device_db

FULL = {"mac": "A4-F0-1F-00-53-07", "ip": "192.0.2.7", "name": "Sam's printer", "connection": "2.4G",
        "type": "Printer (the router's guess)", "your_label": "Office printer", "your_owner": "Sam",
        "announces": {"hostnames": ["printer-0053"], "announced_names": ["Office"], "services": ["_ipp._tcp"],
                      "details": {"model": "Canon G3070 series", "name": "Sam's printer", "device_id": "A4F01F005307"}}}


def test_default_is_off_and_env_can_only_force_off(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    assert device_db.choice() == "off"
    device_db.record_choice("share")
    assert device_db.choice() == "share"
    monkeypatch.setenv("TPLINK_DEVICE_SHARING", "off")
    assert device_db.choice() == "off"
    monkeypatch.setenv("TPLINK_DEVICE_SHARING", "share")      # not a way to turn it on
    device_db.record_choice("off")
    assert device_db.choice() == "off"


def test_payload_is_only_prefix_model_and_type() -> None:
    p = device_db.build(FULL)
    assert p == {"oui": "A4F01F", "model": "Canon G3070 series", "kind": "Printer"}
    blob = json.dumps(p)
    for leak in ("00-53-07", "005307", "192.0.2", "Sam", "Office", "printer-0053", "_ipp"):
        assert leak not in blob
    assert device_db.build({**FULL, "mac": "02-00-5E-00-53-07"})["oui"] == ""      # private MAC: no prefix
    assert device_db.build({**FULL, "mac": "52-54-00-00-53-07"})["oui"] == ""      # VM: not a maker
    assert device_db.build({"mac": "A4-F0-1F-00-53-07", "announces": {}}) is None  # nothing announced: nothing sent


def test_interactive_needs_a_person(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    assert device_db.interactive(io.StringIO("share\n"), io.StringIO()) == 2      # not a terminal: refused
    assert device_db.choice() == "off"

    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    assert device_db.interactive(Tty("receive\n"), io.StringIO()) == 0 and device_db.choice() == "receive"


def test_send_only_when_share_and_once_a_month(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(device_db, "_send_all", lambda ps: sent.extend(ps))
    monkeypatch.setattr(device_db.threading, "Thread",
                        lambda target, args, daemon: type("T", (), {"start": lambda self: target(*args)})())
    assert device_db.contribute([FULL]) == 0 and sent == []
    device_db.record_choice("receive")
    assert device_db.contribute([FULL]) == 0
    device_db.record_choice("share")
    assert device_db.contribute([FULL]) == 1 and sent == [device_db.build(FULL)]


def test_send_all_logs_and_dedupes(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    posts: list[bytes] = []

    class R:
        def read(self, n: int) -> bytes:
            return b""

    monkeypatch.setattr(device_db.urllib.request, "urlopen", lambda req, timeout: posts.append(req.data) or R())
    p = device_db.build(FULL)
    device_db._send_all([p, p])
    device_db._send_all([p])
    assert len(posts) == 1 and json.loads(posts[0]) == p
    log = device_db._sent_log().read_text().splitlines()
    assert len(log) == 1 and json.loads(log[0])["sent"] == p


def test_shared_table_is_matched_locally_and_cleaned(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    started: list[Any] = []
    monkeypatch.setattr(device_db.threading, "Thread",
                        lambda target, daemon: type("T", (), {"start": lambda self: started.append(1)})())
    device_db.record_choice("receive")
    c = device_db._cache()
    c.parent.mkdir(parents=True)
    c.write_text(json.dumps({"entries": [
        {"oui": "A4F01F", "model": "Canon G3070 series", "kind": "Printer", "networks": 7},
        {"oui": "A4F01F", "model": "Bad\nline", "networks": 99},
        {"oui": "B0B369", "model": "onn. Streaming Device", "networks": 4}]}))
    tab = device_db.table()
    assert [e["model"] for e in tab["A4F01F"]] == ["Canon G3070 series"]       # control characters dropped
    hint = device_db.seen_as("A4-F0-1F-00-53-99", tab)
    assert "Canon G3070 series (7 networks)" in hint and "not a certainty" in hint
    assert device_db.seen_as("02-00-5E-00-53-99", tab) is None and not started   # fresh cache: no download


def test_listing_shows_shared_names_for_placeholder_devices(call, monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    device_db.record_choice("receive")
    c = device_db._cache()
    c.parent.mkdir(parents=True)
    c.write_text(json.dumps({"entries": [{"oui": "B0B369", "model": "onn. Streaming Device", "networks": 4}]}))
    monkeypatch.setattr("mcp_tplink_router.features.Ctx.clients", lambda self: [
        {"mac": "B0-B3-69-00-53-52", "ip": "192.0.2.52", "name": "network device", "connection": "wired"},
        {"mac": "B0-B3-69-00-53-53", "ip": "192.0.2.53", "name": "Den-Box", "connection": "wired"}])
    by = {d["ip"]: d for d in call("clients", action="list")["clients"]}
    assert "onn. Streaming Device" in by["192.0.2.52"]["shared_names"]
    assert "shared_names" not in by["192.0.2.53"]                 # a real name needs no hint


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("TPLINK_EVENTS_FILE", str(tmp_path / "state" / "events.jsonl"))
    monkeypatch.delenv("TPLINK_DEVICE_SHARING", raising=False)


def test_bundled_table_is_used_without_any_download(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "empty-cache"))
    monkeypatch.setattr(device_db.threading, "Thread",
                        lambda target, daemon: type("T", (), {"start": lambda self: None})())
    monkeypatch.setattr(device_db, "_bundled",
                        lambda: [{"oui": "B0B369", "model": "onn. Streaming Device", "networks": 4}])
    device_db.record_choice("receive")
    assert device_db.table()["B0B369"][0]["model"] == "onn. Streaming Device"
    assert device_db._server() == "https://kd.by-ai-for-ai.com"           # its own host, not behind the CDN
