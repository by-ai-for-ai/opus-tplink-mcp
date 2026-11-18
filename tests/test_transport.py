"""Transport: reply parsing, field checks, session handling and retry rules (no network)."""

from __future__ import annotations

from typing import Any

import pytest

from mcp_tplink_router.transport import (
    E_LOGIN,
    E_REDIRECT,
    E_SERVER,
    RouterError,
    RouterTransport,
    check_fields,
    parse_reply,
    session,
)

from .fake_router import FakeTransport


def test_parse_success_and_error() -> None:
    assert parse_reply(200, '{"success": true, "data": {"a": 1}}') == {"a": 1}
    with pytest.raises(RouterError) as e:
        parse_reply(200, '{"success": false, "errorcode": "no such callback"}')
    assert e.value.code == "no such callback" and not e.value.ambiguous


def test_parse_500_is_ambiguous_and_truncated() -> None:
    tb = "lua error\n" + "\n".join(f"line {i}" for i in range(50))
    with pytest.raises(RouterError) as e:
        parse_reply(500, tb)
    assert e.value.code == E_SERVER and e.value.ambiguous
    assert "line 40" not in e.value.message


def test_parse_redirect_refused() -> None:
    with pytest.raises(RouterError) as e:
        parse_reply(302, "")
    assert e.value.code == E_REDIRECT


def test_check_fields_rejects_non_strings() -> None:
    assert check_fields({"a": "x", "n": 3}) == {"a": "x", "n": "3"}
    for bad in (True, {"x": 1}, [1], None):
        with pytest.raises(TypeError):
            check_fields({"a": bad})
    with pytest.raises(ValueError):
        check_fields({"operation": "write"})


def test_router_transport_posts_form_body_not_query(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real transport must put fields in a form body, keep only ?form= in the URL,
    refuse redirects and never touch the network in tests (requests.post is stubbed)."""
    import requests

    seen: dict[str, Any] = {}

    class Resp:
        status_code = 200
        text = '{"success": true, "data": {"ok": 1}}'
        headers: dict[str, str] = {}

    def fake_post(url: str, **kw: Any) -> Resp:
        seen.update(url=url, **kw)
        return Resp()

    monkeypatch.setattr(requests, "post", fake_post)
    t = RouterTransport("192.0.2.1", "pw")

    class R:
        host = "http://192.0.2.1"
        _stok = "STOK"
        _sysauth = "AUTH"
        _headers_request = {"Referer": "x"}

    t._router = R()
    assert t.call("dhcps?form=reservation", "insert", {"new": '{"mac":"AA"}', "index": "0"}) == {"ok": 1}
    assert seen["url"] == "http://192.0.2.1/cgi-bin/luci/;stok=STOK/admin/dhcps?form=reservation"
    assert seen["data"] == {"operation": "insert", "new": '{"mac":"AA"}', "index": "0"}
    assert seen["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert seen["allow_redirects"] is False and seen["verify"] is False
    assert seen["cookies"] == {"sysauth": "AUTH"}


def test_router_transport_requires_login() -> None:
    with pytest.raises(RouterError) as e:
        RouterTransport("192.0.2.1", "pw").call("x?form=y", "read")
    assert e.value.code == E_LOGIN


def test_session_always_logs_out() -> None:
    fake = FakeTransport()
    with pytest.raises(RuntimeError), session(lambda: fake):
        assert fake.logged_in
        raise RuntimeError("boom")
    assert not fake.logged_in


def test_login_failure_retried_once(call, fake) -> None:  # type: ignore[no-untyped-def]
    fake.fail_logins = 1
    out = call("router_status")
    assert "error" not in out and fake.logins == 2


def test_login_failure_twice_gives_hint(call, fake) -> None:  # type: ignore[no-untyped-def]
    fake.fail_logins = 2
    out = call("router_status")
    assert out["error"] == E_LOGIN and "ONE admin login" in out["hint"]


def test_read_timeout_retried(call, fake) -> None:  # type: ignore[no-untyped-def]
    fake.fail_next("timeout")
    out = call("dhcp_reservation", action="list")
    assert "error" not in out and fake.logins == 2


def test_definite_router_error_not_retried(call, fake) -> None:  # type: ignore[no-untyped-def]
    fake.fail_next("permission denied", ambiguous=False)
    out = call("dhcp_reservation", action="list")
    assert out["error"] == "permission denied" and fake.logins == 1


def test_unknown_tool_and_argument(call) -> None:  # type: ignore[no-untyped-def]
    assert "unknown tool" in call("nope")["error"]
    assert "unknown argument" in call("router_status", bogus=1)["error"]
