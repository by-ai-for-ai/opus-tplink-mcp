"""Local event log: private, secret-free, never breaks a call, and spots firmware changes."""

from __future__ import annotations

import os
import stat
from typing import Any

import pytest

from mcp_tplink_router import events


@pytest.fixture(autouse=True)
def _events_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    monkeypatch.setenv("TPLINK_EVENTS_FILE", str(tmp_path / "events.jsonl"))
    events._SEEN.clear()


def test_event_file_is_private_and_masks_secrets(tmp_path: Any) -> None:
    events.emit("error", "main", tool="wifi_set", password="hunter2-secret", psk_key="also-secret-9")
    raw = events.path().read_text()
    assert "hunter2-secret" not in raw and "also-secret-9" not in raw
    assert stat.S_IMODE(os.stat(events.path()).st_mode) == 0o600


def test_tool_replies_become_events(apply, call) -> None:  # type: ignore[no-untyped-def]
    apply("wifi_set", action="set", band="5g", enable=False)                      # a verified change
    call("router_status", router="garage")                                       # unknown device
    call("wifi_set", action="set", band="2g", settings={"no_such_field": "x"})   # NOT DONE
    kinds = [e["kind"] for e in events.read()]
    assert "changed" in kinds and "no_such_device" in kinds and "not_done" in kinds
    assert "firmware_seen" in kinds                                              # first use of the device


def test_firmware_change_is_detected() -> None:
    events.note_firmware("main", "192.0.2.1", {"model": "X", "hardware_version": "X v1", "firmware_version": "1.0"})
    events.note_firmware("main", "192.0.2.1", {"model": "X", "hardware_version": "X v1", "firmware_version": "1.0"})
    ch = events.note_firmware("main", "192.0.2.1", {"model": "X", "hardware_version": "X v1", "firmware_version": "1.1"})
    assert ch and ch["to"]["firmware_version"] == "1.1"
    assert [e["kind"] for e in events.read()].count("firmware_changed") == 1


def test_logging_never_breaks_a_call(monkeypatch: pytest.MonkeyPatch, call) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("TPLINK_EVENTS_FILE", "/proc/forbidden/events.jsonl")    # unwritable
    out = call("router_status")
    assert "error" not in out


def test_watch_prints_events_without_following(capsys: pytest.CaptureFixture[str]) -> None:
    from mcp_tplink_router.watch import main as watch_main

    events.emit("firmware_changed", "main", **{"from": {"firmware_version": "1.0"}, "to": {"firmware_version": "1.1"}})
    events.emit("changed", "re1750x", tell_user="DONE AND VERIFIED: change LEDs")
    assert watch_main(["--no-follow", "--router", "main"]) == 0
    out = capsys.readouterr().out
    assert "firmware_changed" in out and "re1750x" not in out


def test_viewer_without_pyside_explains_itself(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    import builtins

    real = builtins.__import__

    def no_qt(name: str, *a: Any, **k: Any) -> Any:
        if name.startswith("PySide6"):
            raise ImportError("no PySide6")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_qt)
    from mcp_tplink_router.viewer import main as viewer_main

    assert viewer_main([]) == 2 and "pip install" in capsys.readouterr().err
