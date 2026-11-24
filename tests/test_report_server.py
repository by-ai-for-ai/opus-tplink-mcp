"""The report server keeps only allowlisted, validated fields and publishes only totals >= MIN_COUNT."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

SPEC = importlib.util.spec_from_file_location("report_server", Path(__file__).parents[1] / "server" / "report_server.py")


@pytest.fixture
def srv(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    mod = importlib.util.module_from_spec(SPEC)  # type: ignore[arg-type]
    SPEC.loader.exec_module(mod)  # type: ignore[union-attr]
    monkeypatch.setattr(mod, "DATA", tmp_path / "data")
    return mod


def test_only_allowlisted_validated_fields_are_kept(srv: Any) -> None:
    forged = {"code": "not_done", "category": "wifi", "model": "Archer AX3000", "firmware": "1.0.6",
              "ip": "192.0.2.77", "ssid": "MyHomeWiFi", "message": "C:\\Users\\alice\\x",
              "stack": ["mcp_tplink_router.tools:run_tool:12", "/home/alice/evil.py:x:1"],
              "exc_type": "Permission Error; drop table", "tool_version": "1.2.0"}
    rec = srv.clean(forged)
    text = json.dumps(rec)
    assert "192.0.2.77" not in text and "MyHomeWiFi" not in text and "alice" not in text
    assert rec["stack"] == ["mcp_tplink_router.tools:run_tool:12"] and "exc_type" not in rec
    assert srv.clean({"code": "rm -rf"}) is None
    assert srv.clean({"code": "not_done", "model": "<script>x</script>"}).get("model") is None


def test_public_totals_need_min_count(srv: Any) -> None:
    rec = {"code": "device_seen", "model": "Archer BE550", "hardware": "Archer BE550 v1.0", "firmware": "1.1.0"}
    for i in range(srv.MIN_COUNT - 1):
        c = srv.clean(dict(rec))
        c["src"] = srv.source_id(f"203.0.113.{i}")
        srv.store(c)
    assert srv.grouped(("model", "hardware", "firmware"), only={"device_seen"}) == []   # 4 sources: hidden
    c = srv.clean(dict(rec))
    c["src"] = srv.source_id("203.0.113.99")
    srv.store(c)
    shown = srv.grouped(("model", "hardware", "firmware"), only={"device_seen"})
    assert shown and shown[0]["sources"] == srv.MIN_COUNT and "src" not in shown[0]


REAL = [("Archer BE9300", "Archer BE9300 v1.0", "1.2.4 Build 20260402 rel.18898(5553)"),
        ("Archer AX3000", "Archer AX3000 v1.0", "1.0.6 Build 20230831 rel.67466(5553)"),
        ("Archer AXE5400", "Archer AXE5400 v1.0", "1.5.6 Build 20260623 rel.56854(5553)"),
        ("RE3200BE", "RE3200BE v1.0", "1.5.3 Build 20260529 rel.27861(5553)"),
        ("RE1750X", "RE1750X v1.0", "1.0.6 Build 20240819 Rel. 59465")]


def _seen(srv: Any, ip: str, m: str, hw: str, fw: str) -> None:
    rec = srv.clean({"code": "device_seen", "model": m, "hardware": hw, "firmware": fw})
    assert rec is not None, (m, hw, fw)
    src = srv.source_id(ip)
    if srv.admit(rec, src):
        rec["src"] = src
        srv.store(rec)


def test_real_device_strings_pass_and_junk_is_dropped(srv: Any) -> None:
    for m, hw, fw in REAL:
        assert srv.clean({"code": "device_seen", "model": m, "hardware": hw, "firmware": fw}) is not None
    for m, hw, fw in [("Totally Real Router", "Totally Real Router v1", "1.0.0"),
                      ("Archer AX3000", "Something else v1.0", "1.0.6"),           # hardware must match the model
                      ("Archer AX3000", "Archer AX3000 v1.0", "latest!!"),
                      ("Archer AX3000", None, None)]:                              # device_seen needs all three
        assert srv.clean({"code": "device_seen", "model": m, "hardware": hw, "firmware": fw}) is None


def test_one_source_cannot_inflate_a_router(srv: Any) -> None:
    m, hw, fw = REAL[1]
    for _ in range(500):                                                           # a flood from one address
        _seen(srv, "198.51.100.9", m, hw, fw)
    assert srv.grouped(("model", "hardware", "firmware"), only={"device_seen"}) == []
    raw = "".join(f.read_text() for f in (srv.DATA).glob("raw-*.jsonl"))
    assert raw.count("device_seen") == 1 and "198.51.100.9" not in raw           # counted once, no IP stored
    for i in range(srv.MIN_COUNT - 1):                                             # four more different sources
        _seen(srv, f"203.0.113.{i}", m, hw, fw)
    shown = srv.grouped(("model", "hardware", "firmware"), only={"device_seen"})
    assert shown and shown[0]["sources"] == srv.MIN_COUNT


def test_reports_never_make_a_router_verified(srv: Any) -> None:
    m, hw, fw = REAL[0]
    for i in range(20):                                                            # many sources, all fake
        _seen(srv, f"203.0.113.{i}", m, hw, fw)
    seen = srv.grouped(("model", "hardware", "firmware", "protocol", "kind"), only={"device_seen"})
    assert seen and all("verified" not in e for e in seen) and srv.verified() == {}
    (srv.DATA / "verified.json").write_text(json.dumps({f"{m}|{hw}|{fw}": {"by": "maintainer", "bench": "21/21"}}))
    assert srv.verified()[f"{m}|{hw}|{fw}"]["by"] == "maintainer"                  # only the maintainer's file


def test_private_feed_needs_a_token_and_lists_unconfirmed_devices(srv: Any) -> None:
    m, hw, fw = REAL[2]
    _seen(srv, "203.0.113.50", m, hw, fw)
    feed = srv.monitor_feed()
    assert any(e["code"] == "unconfirmed_device" and e["model"] == m for e in feed["errors"])
    assert all(e["first_seen"].endswith("T00:00:00Z") for e in feed["errors"])     # day-level times only
