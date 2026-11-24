"""Test fixtures.  HARD RULE: tests never touch a network or the real router."""

from __future__ import annotations

import socket
from typing import Any

import pytest

from mcp_tplink_router.journal import Journal
from mcp_tplink_router.tools import Runtime, run_tool

from .fake_router import DESKTOP_MAC, FakeTransport


class NetworkBlocked(RuntimeError):
    pass


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    def refuse(*_a: Any, **_k: Any) -> None:
        raise NetworkBlocked("tests must not open network connections")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    try:
        import requests

        monkeypatch.setattr(requests.Session, "request", refuse)
    except ImportError:  # pragma: no cover
        pass
    monkeypatch.setenv("TPLINK_JOURNAL_DIR", str(tmp_path / "journal"))
    monkeypatch.setenv("TPLINK_JOURNAL_KEY", str(tmp_path / "journal.key"))  # never the user's real key
    monkeypatch.delenv("TPLINK_ALLOW_FORBIDDEN", raising=False)
    monkeypatch.setenv("TPLINK_AUTO_BACKUP", "0")  # tests that check it turn it on
    monkeypatch.setenv("TPLINK_SETTLE_SECONDS", "0")  # no real waiting for a Wi-Fi restart in tests
    monkeypatch.setenv("TPLINK_PASSWORD", "test-password-not-real")
    monkeypatch.setenv("TPLINK_HOST", "192.0.2.1")  # TEST-NET-1, never routable


@pytest.fixture
def fake() -> FakeTransport:
    return FakeTransport()


@pytest.fixture
def rt(fake: FakeTransport, tmp_path: Any) -> Runtime:
    return Runtime(factory=lambda: fake, journal=Journal(tmp_path / "journal", tmp_path / "journal.key"), host="192.0.2.1",
                   identity=lambda: {"ip": "192.168.0.160", "macs": [DESKTOP_MAC]}, retry_delay=0)


@pytest.fixture
def call(rt: Runtime):  # type: ignore[no-untyped-def]
    def _call(_tool: str, **args: Any) -> dict[str, Any]:
        return run_tool(_tool, args, rt)

    return _call


@pytest.fixture
def apply(call):  # type: ignore[no-untyped-def]
    """Dry-run then apply (passing the confirm token when one is issued)."""

    def _apply(_tool: str, **args: Any) -> dict[str, Any]:
        dry = call(_tool, **args)
        assert "error" not in dry and not dry.get("errors"), dry
        if dry.get("no_change"):
            return dry
        extra = {"confirm_token": dry["confirm_token"]} if "confirm_token" in dry else {}
        return call(_tool, apply=True, **args, **extra)

    return _apply


def send(call, tool: str, **args: Any) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    """Apply a change the only way the server allows: dry run first, then apply with its confirm_token."""
    dry = call(tool, **args)
    return call(tool, **args, apply=True, confirm_token=dry.get("confirm_token"))


@pytest.fixture(autouse=True)
def _clear_pending() -> Any:  # type: ignore[misc]
    from mcp_tplink_router import safety

    safety.PENDING.clear()
    yield
    safety.PENDING.clear()


@pytest.fixture(autouse=True)
def _clear_seq() -> Any:  # type: ignore[misc]
    from mcp_tplink_router import safety

    safety.CALL_SEQ.clear()
    from mcp_tplink_router import tools as _tools

    _tools.TASK_MEMORY.clear()
    yield
    _tools.TASK_MEMORY.clear()
