"""Extender protocols against simulated devices that verify what the real ones verify."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any
from urllib.parse import parse_qs

import pytest

Crypto = pytest.importorskip("Crypto")
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5  # noqa: E402
from Crypto.PublicKey import RSA  # noqa: E402
from Crypto.Util.Padding import pad, unpad  # noqa: E402

from mcp_tplink_router import extender_transport as et  # noqa: E402
from mcp_tplink_router.transport import RouterError, session  # noqa: E402

PW = "test-pass-123"


class _Resp:
    def __init__(self, obj: Any = None, status: int = 200, text: str = "") -> None:
        self._obj, self.status_code, self.text = obj, status, text or json.dumps(obj)

    def json(self) -> Any:
        if self._obj is None:
            raise ValueError("no json")
        return self._obj


def _hex_n(key: Any) -> tuple[str, str]:
    return format(key.n, "X"), format(key.e, "X")


class FakeXSeries:
    """X-series: RSA-1024 key from login?form=login read; PKCS#1 v1.5 password; Referer required."""

    def __init__(self) -> None:
        self.key = RSA.generate(1024)
        self.logins = 0
        self.calls: list[tuple[str, dict[str, list[str]]]] = []

    def post(self, url: str, data: str = "", timeout: float = 0, **kw: Any) -> _Resp:  # noqa: ARG002
        assert self.headers.get("Referer", "").endswith("/webpages/index.html")
        path = url.split(";stok=", 1)[1]
        q = parse_qs(data, keep_blank_values=True)
        self.calls.append((path, q))
        if path.startswith("/login?form=login") and q["operation"] == ["read"]:
            return _Resp({"success": True, "data": {"username": "", "password": list(_hex_n(self.key))}})
        if path.startswith("/login?form=login") and q["operation"] == ["login"]:
            self.logins += 1
            pw = PKCS1_v1_5.new(self.key).decrypt(bytes.fromhex(q["password"][0]), None)
            if pw != PW.encode():
                return _Resp({"success": False, "errorcode": "login failed"})
            return _Resp({"success": True, "data": {"stok": "STOK1"}})
        assert path.startswith("STOK1/admin/")
        return _Resp({"success": True, "data": {"path": path.split("/admin/")[1], "fields": dict(q)}})


class FakeHardened:
    """encrypted-v2: verifies the OAEP login signature, SHA-256 hash, sequence and per-request HMAC."""

    def __init__(self) -> None:
        self.pkey, self.akey, self.seq = RSA.generate(2048), RSA.generate(2048), 1000
        self.k = self.i = ""
        self.logins = 0

    def _aes(self) -> Any:
        return AES.new(self.k.encode(), AES.MODE_CBC, self.i.encode())

    def post(self, url: str, data: str = "", timeout: float = 0, **kw: Any) -> _Resp:  # noqa: ARG002
        path = url.split(";stok=", 1)[1]
        q = parse_qs(data, keep_blank_values=True)
        if path == "/login?form=keys":
            return _Resp({"success": True, "data": {"password": list(_hex_n(self.pkey)), "mode": "repeater", "username": ""}})
        if path == "/login?form=auth":
            return _Resp({"success": True, "data": {"seq": self.seq, "key": list(_hex_n(self.akey))}})
        sign, body = q["sign"][0], q["data"][0]
        if path == "/login?form=login":
            self.logins += 1
            blocks = [sign[i:i + 512] for i in range(0, len(sign), 512)]
            raw = "".join(PKCS1_OAEP.new(self.akey).decrypt(bytes.fromhex(b)).decode() for b in blocks)
            parts = dict(p.split("=", 1) for p in raw.split("&"))
            self.k, self.i = parts["k"], parts["i"]
            if parts["h"] != hashlib.sha256(("admin" + PW).encode()).hexdigest() or int(parts["s"]) != self.seq + len(body):
                return _Resp(None, 403, "")
            plain = parse_qs(unpad(self._aes().decrypt(base64.b64decode(body)), 16).decode())
            pw = PKCS1_v1_5.new(self.pkey).decrypt(bytes.fromhex(plain["password"][0]), None)
            if pw != PW.encode():
                reply = {"success": False, "errorcode": "login failed"}
            else:
                reply = {"success": True, "data": {"stok": "S2"}}
            return _Resp({"data": base64.b64encode(self._aes().encrypt(pad(json.dumps(reply).encode(), 16))).decode()})
        expected = et.hmac_signature(self.k, self.i, hashlib.sha256(body.encode()).hexdigest(), self.seq, len(body))
        if not path.startswith("S2/admin/") or sign != expected:
            return _Resp(None, 403, "")
        plain = unpad(self._aes().decrypt(base64.b64decode(body)), 16).decode()
        reply = {"success": True, "data": {"echo": plain, "path": path.split("/admin/")[1]}}
        return _Resp({"data": base64.b64encode(self._aes().encrypt(pad(json.dumps(reply).encode(), 16))).decode()})


def _wire(monkeypatch: Any, fake: Any, cls: Any, pw: str = PW) -> Any:
    t = cls("192.0.2.5", lambda: pw)
    fake.headers = t._http.headers
    monkeypatch.setattr(t._http, "post", fake.post)
    return t


def test_hmac_signature_vector() -> None:
    raw = "h=" + "ab" * 32 + "&s=1234"
    want = "".join(hmac.new(b"k=1111222233334444&i=5555666677778888", raw[i:i + 53].encode(), hashlib.sha256).hexdigest()
                   for i in range(0, len(raw), 53))
    assert et.hmac_signature("1111222233334444", "5555666677778888", "ab" * 32, 1000, 234) == want
    assert len(want) == 128  # 2 blocks of 53 chars -> 2 HMACs


def test_x_series_login_and_form_call(monkeypatch: Any) -> None:
    fake = FakeXSeries()
    with session(lambda: _wire(monkeypatch, fake, et.ExtenderTransport)) as t:
        out = t.call("connect?form=settings", "write", {"enable_2g": "on", "list": ["a", "b"], "blank": ""})
    assert out["path"] == "connect?form=settings"
    assert out["fields"] == {"operation": ["write"], "enable_2g": ["on"], "list": ["a", "b"], "blank": [""]}
    assert fake.calls[-1][0] == "STOK1/admin/system?form=logout"


def test_x_series_wrong_password_is_refused_once_and_not_retried(monkeypatch: Any) -> None:
    fake = FakeXSeries()
    t = _wire(monkeypatch, fake, et.ExtenderTransport, pw="wrong")
    with pytest.raises(et.LoginRefused) as ei:
        t.login()
    assert ei.value.no_retry and fake.logins == 1


def test_run_tool_does_not_retry_a_refused_login(monkeypatch: Any) -> None:
    from mcp_tplink_router.journal import Journal
    from mcp_tplink_router.tools import Runtime, run_tool

    fake = FakeXSeries()
    rt = Runtime(factory=lambda: _wire(monkeypatch, fake, et.ExtenderTransport, pw="wrong"),
                 journal=Journal(), name="ext", kind="extender", retry_delay=0)
    out = run_tool("router_status", {"router": "ext"}, rt)
    assert out["error"] == "login_failed" and fake.logins == 1


def test_hardened_login_and_signed_requests(monkeypatch: Any) -> None:
    fake = FakeHardened()
    with session(lambda: _wire(monkeypatch, fake, et.HardenedTransport)) as t:
        a = t.call("firmware?form=upgrade", "read")
        b = t.call("extend?form=settings", "write", {"ssid_2g": "X Y", "enable_2g": "on"})
    assert a == {"echo": "operation=read", "path": "firmware?form=upgrade"}
    assert parse_qs(b["echo"]) == {"operation": ["write"], "ssid_2g": ["X Y"], "enable_2g": ["on"]}
    assert fake.logins == 1


def test_hardened_wrong_password_is_refused(monkeypatch: Any) -> None:
    fake = FakeHardened()
    t = _wire(monkeypatch, fake, et.HardenedTransport, pw="nope")
    with pytest.raises(et.LoginRefused):
        t.login()
    assert fake.logins == 1


def test_router_only_tools_refuse_extenders(monkeypatch: Any) -> None:
    from mcp_tplink_router.journal import Journal
    from mcp_tplink_router.tools import Runtime, run_tool

    rt = Runtime(factory=lambda: _wire(monkeypatch, FakeXSeries(), et.ExtenderTransport),
                 journal=Journal(), name="ext", kind="extender")
    out = run_tool("wifi_set", {"action": "get", "router": "ext"}, rt)
    assert "not supported" in out["error"] and "extender" in out["tools_for_this_device"]


def test_http_errors_map_to_router_errors(monkeypatch: Any) -> None:
    fake = FakeXSeries()
    t = _wire(monkeypatch, fake, et.ExtenderTransport)
    t.login()
    monkeypatch.setattr(t._http, "post", lambda *a, **k: _Resp(None, 500, "boom"))
    with pytest.raises(RouterError) as ei:
        t.call("status?form=rootAP", "read")
    assert ei.value.code == "server_error" and ei.value.ambiguous


class FakeHardenedTLS:
    """encrypted-v2 over HTTPS: the web UI does not wrap requests (TLS does): plain forms, the password RSA
    PKCS#1-encrypted with the login?form=keys key, confirm=true.  A signed/AES body gets 'no such callback'."""

    def __init__(self) -> None:
        self.pkey = RSA.generate(2048)
        self.logins = 0

    def post(self, url: str, data: str = "", timeout: float = 0, **kw: Any) -> _Resp:  # noqa: ARG002
        path = url.split(";stok=", 1)[1]
        q = parse_qs(data, keep_blank_values=True)
        if path == "/login?form=keys":
            return _Resp({"success": True, "data": {"password": list(_hex_n(self.pkey)), "mode": "repeater"}})
        if path == "/login?form=login":
            if "sign" in q or q.get("operation") != ["login"] or q.get("confirm") != ["true"]:
                return _Resp({"success": False, "errorcode": "no such callback"})
            self.logins += 1
            pw = PKCS1_v1_5.new(self.pkey).decrypt(bytes.fromhex(q["password"][0]), None)
            return _Resp({"success": True, "data": {"stok": "T1"}} if pw == PW.encode() else
                         {"success": False, "errorcode": "login failed"})
        assert path.startswith("T1/admin/") and "sign" not in q
        return _Resp({"success": True, "data": {"path": path.split("/admin/")[1], "fields": dict(q)}})


def test_hardened_over_https_uses_plain_forms(monkeypatch: Any) -> None:
    fake = FakeHardenedTLS()
    t = et.HardenedTransport("https://192.0.2.9", lambda: PW)
    monkeypatch.setattr(t._http, "post", fake.post)
    with session(lambda: t) as s:
        out = s.call("ledgeneral?form=setting", "write", {"enable": "off"})
    assert out == {"path": "ledgeneral?form=setting", "fields": {"operation": ["write"], "enable": ["off"]}}
    assert fake.logins == 1


def test_extender_sessions_accept_legacy_rsa_tls() -> None:
    from mcp_tplink_router.extender_transport import _WebSession

    w = _WebSession("https://192.0.2.9", lambda: PW)
    assert type(w._http.get_adapter("https://192.0.2.9/")).__name__ == "_Adapter"


def test_extender_mlo_action(monkeypatch: Any) -> None:
    from mcp_tplink_router.journal import Journal
    from mcp_tplink_router.tools import Runtime, run_tool

    state = {"mlo_enable": "on", "mlo_band2": "on", "mlo_band5": "on", "mlo_band6": "off", "mlo_band_support": ["band2", "band5"],
             "mlo_ssid": "Home", "mlo_encryption": "wpa3", "mlo_password": "s3cret-pass", "enable_2g": "on", "ssid_2g": "Home",
             "hide_2g": "off", "sec_follow_2g": "true", "sec_2g": "wpa3", "password_2g": "p", "mesh_enable": "on"}
    sent: list[dict] = []
    link5 = ["connected"]

    class Dev:
        def login(self) -> None: ...
        def logout(self) -> None: ...
        def call(self, path: str, op: str, fields: Any = None, **k: Any) -> Any:
            if path == "status?form=repeater_status":  # what the tool checks after the Wi-Fi restart
                return {"mlo_enable": state["mlo_enable"], "repeater_enable_24g": "enable",
                        "repeater_enable_5g": "enable", "repeater_conn_24g": "connected",
                        "repeater_conn_5g": link5[0]}
            assert path == "extend?form=settings"
            if op == "write":
                sent.append(dict(fields))
                state.update(fields)
            return dict(state)

    rt = Runtime(factory=Dev, journal=Journal(), name="ext", kind="extender", retry_delay=0)
    assert run_tool("extender_set", {"router": "ext", "action": "mlo"}, rt)["current"]["bands"] == ["2g", "5g"]
    dry = run_tool("extender_set", {"router": "ext", "action": "mlo", "enable": False}, rt)
    assert dry["status"] == "PREVIEW_ONLY" and dry["risk"] == "critical"
    assert dry["next_call"]["arguments"]["router"] == "ext"  # next_call targets the same device
    out = run_tool("extender_set", dry["next_call"]["arguments"], rt)
    assert out["verified"] == "yes" and state["mlo_enable"] == "off"
    assert "restarts the extender's Wi-Fi" in json.dumps(dry)  # the preview warns before anything is sent
    assert out["after_restart"]["back"] is True and "links connected" in out["tell_user"]
    link5[0] = "disconnected"  # the 5 GHz uplink is slow to return: said plainly, the change itself stands
    dry = run_tool("extender_set", {"router": "ext", "action": "mlo", "enable": True}, rt)
    out = run_tool("extender_set", dry["next_call"]["arguments"], rt)
    assert out["verified"] == "yes" and "5 GHz link to your router is still reconnecting" in out["tell_user"]
    link5[0] = "connected"
    undo = run_tool("router_undo", {"id": out["journal_id"]}, rt)
    undone = run_tool("router_undo", {"id": out["journal_id"], "apply": True, "confirm_token": undo["confirm_token"]}, rt)
    assert state["mlo_enable"] == "off" and undone["after_restart"]["back"] is True  # undo waits for the restart too
    assert "mlo_band_support" not in sent[-1] and sent[-1]["mlo_password"] == "s3cret-pass"  # full UI payload
    read = run_tool("extender_set", {"router": "ext", "action": "mlo"}, rt)
    assert "enable=" in read["note"] and "only READ" in read["note"]  # E4B: a bare action=mlo is a read; say how to change
    dry = run_tool("extender_set", {"router": "ext", "action": "mlo", "settings": {"enable": True}}, rt)
    assert dry["status"] == "PREVIEW_ONLY"  # Nemotron: enable inside settings is understood, not a silent read
    assert "at least two bands" in run_tool("extender_set", {"router": "ext", "action": "mlo", "bands": ["2g"]}, rt)["error"]
    assert "supports ['2g', '5g']" in run_tool("extender_set", {"router": "ext", "action": "mlo", "bands": ["2g", "6g"]}, rt)["error"]
