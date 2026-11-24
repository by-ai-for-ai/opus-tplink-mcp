"""Field reports: OFF until a person chooses; built from an allowlist; never carry user data."""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from mcp_tplink_router import events, reporting

SECRETS = ("192.0.2.77", "00-00-5E-00-53-01", "MyHomeWiFi", "hunter2-secret", "kids-laptop")


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("TPLINK_EVENTS_FILE", str(tmp_path / "state" / "events.jsonl"))
    monkeypatch.delenv("TPLINK_REPORTING", raising=False)
    events._SEEN.clear()


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(reporting, "_post", lambda p: sent.append(p))
    return sent


def test_off_by_default_and_env_cannot_turn_it_on(monkeypatch: pytest.MonkeyPatch, no_network) -> None:  # type: ignore[no-untyped-def]
    assert not reporting.is_enabled() and not reporting.decided()
    monkeypatch.setenv("TPLINK_REPORTING", "on")          # e.g. an AI agent editing the .env
    assert not reporting.is_enabled()
    assert reporting.submit(reporting.build("not_done", tool="wifi_set")) is False and no_network == []


def test_only_a_person_can_choose(monkeypatch: pytest.MonkeyPatch) -> None:
    assert reporting.interactive_setup(stdin=io.StringIO("on\n")) == 2   # not a terminal: refused
    assert not reporting.is_enabled()

    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    assert reporting.interactive_setup(stdin=Tty("maybe\non\n"), stdout=io.StringIO()) == 0
    assert reporting.is_enabled() and "ON since" in reporting.status_line()
    monkeypatch.setenv("TPLINK_REPORTING", "off")
    assert not reporting.is_enabled()                     # env can always force it off
    monkeypatch.setattr(reporting, "NOTICE_VERSION", reporting.NOTICE_VERSION + 1)
    monkeypatch.delenv("TPLINK_REPORTING")
    assert not reporting.is_enabled()                     # new notice -> OFF until re-confirmed


def test_payload_never_carries_user_data(no_network) -> None:  # type: ignore[no-untyped-def]
    reporting.record_choice(True)
    device = {"model": "Archer AX3000", "hardware_version": "Archer AX3000 v1.0", "firmware_version": "1.0.6 Build 20230831",
              "wan_ip": SECRETS[0], "mac": SECRETS[1], "ssid": SECRETS[2], "password": SECRETS[3], "name": SECRETS[4]}
    try:
        raise PermissionError(f"cannot open /home/{SECRETS[4]}/x for {SECRETS[2]} {SECRETS[0]}")
    except PermissionError as exc:
        p = reporting.build("internal_error", tool="parental_control", device=device, protocol="encrypted",
                            kind="router", exc=exc)
    text = json.dumps(p)
    assert all(s not in text for s in SECRETS)
    assert p["category"] == "access controls" and "parental" not in text          # category, not the feature
    assert p["exc_type"] == "PermissionError" and p["model"] == "Archer AX3000"
    assert reporting.build("whatever_code") is None                                # unknown codes make nothing
    assert reporting.build("not_done", device={"model": "<script>alert(1)</script>"}).get("model") is None


def test_dedupe_cap_and_local_record(no_network, monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[no-untyped-def]
    reporting.record_choice(True)
    p = reporting.build("not_done", tool="wifi_set")
    assert reporting.submit(p) is True and reporting.submit(p) is False            # same report once a day
    seen = reporting.build("device_seen", device={"model": "M", "hardware_version": "M v1", "firmware_version": "1"})
    assert reporting.submit(seen) is True and reporting.submit(dict(seen, day="x")) is False
    monkeypatch.setattr(reporting, "DAILY_CAP", 2)
    assert reporting.submit(reporting.build("mismatch", tool="lan")) is False      # daily cap
    assert len(reporting._sent_log().read_text().splitlines()) == 2                # each sent one is recorded


def test_tool_calls_report_only_when_on(no_network, call) -> None:  # type: ignore[no-untyped-def]
    call("wifi_set", action="set", band="2g", settings={"no_such_field": "x"})
    assert no_network == []                                                        # OFF: nothing at all
    reporting.record_choice(True)
    call("wifi_set", action="set", band="2g", settings={"also_no_such_field": "y"})
    import time
    time.sleep(0.2)
    assert [p["code"] for p in no_network] == ["not_done"] or [p["code"] for p in no_network][-1] == "not_done"
