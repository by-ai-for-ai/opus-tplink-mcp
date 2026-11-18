"""Wire format of the encrypted transport, exercised through the REAL tplinkrouterc6u client class.

Regression: the library's TplinkRouterJson.request re-encoded bodies as JSON via dict(parse_qsl()),
collapsing repeated keys (MLO selected_bands), dropping blanks and copying fields into the URL.
"""
from __future__ import annotations

import pytest

c6u = pytest.importorskip("tplinkrouterc6u.client.c6u")

from mcp_tplink_router.transport import EncryptedRouterTransport  # noqa: E402


class _Resp:
    text = "{}"

    def json(self):
        return {"data": "x"}


@pytest.fixture
def wire(monkeypatch):
    sent: dict = {}

    def fake_post(url, data=None, headers=None, **kw):  # noqa: ARG001
        sent.update(url=url, data=data, headers=dict(headers or {}))
        return _Resp()

    monkeypatch.setattr(c6u, "post", fake_post)
    monkeypatch.setattr(c6u.TplinkRouter, "_prepare_data", lambda self, data: {"plain": data})
    monkeypatch.setattr(c6u.TplinkRouter, "_decrypt_response",
                        lambda self, data: {"success": True, "data": {"ok": "1"}})
    client = c6u.TplinkRouter("https://192.0.2.1", "pw", verify_ssl=False)
    client._logged, client._stok, client._sysauth = True, "STOK", "AUTH"
    t = EncryptedRouterTransport("192.0.2.1", lambda: "pw")
    t._router = client
    return t, client, sent


def test_repeated_keys_and_blanks_reach_the_router_as_a_form(wire):
    t, client, sent = wire
    out = t.call("wireless?form=mlo_host", "write",
                 {"enable": "on", "ssid": "Net", "selected_bands": ["2g", "5g"], "hidden": ""})
    assert out == {"ok": "1"}
    assert sent["data"] == {"plain": "operation=write&enable=on&ssid=Net&selected_bands=2g&selected_bands=5g&hidden="}
    assert sent["headers"]["Content-Type"] == "application/x-www-form-urlencoded"


def test_no_fields_leak_into_the_url(wire):
    t, _, sent = wire
    t.call("wireless?form=mlo_host", "write", {"psk_key": "secret-value"})
    assert sent["url"] == "https://192.0.2.1/cgi-bin/luci/;stok=STOK/admin/wireless?form=mlo_host"
    assert "secret" not in sent["url"]


def test_client_header_is_restored_for_the_librarys_own_calls(wire):
    t, client, _ = wire
    before = client._headers_request.get("Content-Type")
    t.call("status?form=all", "read")
    assert client._headers_request.get("Content-Type") == before


def test_fails_closed_if_the_library_layout_changes(wire, monkeypatch):
    from mcp_tplink_router.transport import RouterError

    t, client, sent = wire
    monkeypatch.setattr(c6u, "TplinkRouterJson", type("Other", (), {}))
    with pytest.raises(RouterError, match="unsupported tplinkrouterc6u"):
        t.call("wireless?form=mlo_host", "write", {"selected_bands": ["2g", "5g"]})
    assert "data" not in sent  # nothing was sent through the JSON adapter
