"""Transports for TP-Link range extenders (and other devices with these web-UI generations).

Two protocols, both taken from the devices' own web UI code and verified live:

``extender``      X-series web UI (e.g. RE2700X, RE1750X, RE1500X).  Plain form posts, like the
                  BE9300.  Login: the 1024-bit RSA key comes from ``login?form=login``
                  (``operation=read``); the password is RSA-PKCS#1 v1.5 encrypted (hex).

``encrypted-v2``  The hardened ("SG CLS L1 stage 2" certification profile) generation (e.g.
                  RE3200BE fw 1.5.x).  AES-CBC bodies like ``encrypted``, but:
                  * the signature hash is SHA-256("admin" + password), not MD5;
                  * the login signature is RSA-OAEP (SHA-1) encrypted, in 53-character blocks;
                  * every later request is signed with HMAC-SHA256 (key ``k=<key>&i=<iv>``) over
                    ``h=<SHA-256 of that request's ciphertext>&s=<seq + len>``, in 53-character
                    blocks.  Without the per-request hash the device answers HTTP 403.

The certification profile is compiled into each model's web UI, not served by the device, so the
scheme is chosen by configuration.  A login failure is never retried with other variants: the
devices count failed logins and lock the account.

Both require a ``Referer`` header on every request (the X-series answers "Bad Request" without it).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode

from .transport import (
    E_BAD_REPLY,
    E_HTTP,
    E_LOGIN,
    E_NETWORK,
    E_SERVER,
    E_TIMEOUT,
    RouterError,
    check_fields,
)

logger = logging.getLogger(__name__)

FORM = "application/x-www-form-urlencoded"
RSA_BLOCK = 53


class LoginRefused(RouterError):
    """The device refused the login.  Never retried automatically (failed logins lock the account)."""

    no_retry = True

    def __init__(self, message: str) -> None:
        super().__init__(E_LOGIN, message)


def _normalize_host(host: str) -> str:
    host = host.strip().rstrip("/")
    return host if re.match(r"^https?://", host) else "http://" + host


def _rsa_pkcs1_hex(n_hex: str, e_hex: str, text: str) -> str:
    from Crypto.Cipher import PKCS1_v1_5  # nosec B413 - pycryptodome (maintained), not pyCrypto
    from Crypto.PublicKey import RSA  # nosec B413 - pycryptodome (maintained), not pyCrypto

    key = RSA.construct((int(n_hex, 16), int(e_hex, 16)))
    return PKCS1_v1_5.new(key).encrypt(text.encode()).hex().rjust(len(n_hex), "0")


def _rsa_oaep_hex(n_hex: str, e_hex: str, text: str) -> str:
    from Crypto.Cipher import PKCS1_OAEP  # nosec B413 - pycryptodome (maintained), not pyCrypto
    from Crypto.PublicKey import RSA  # nosec B413 - pycryptodome (maintained), not pyCrypto

    key = RSA.construct((int(n_hex, 16), int(e_hex, 16)))
    return PKCS1_OAEP.new(key).encrypt(text.encode()).hex().rjust(len(n_hex), "0")


def hmac_signature(key: str, iv: str, hash_hex: str, seq: int, data_len: int) -> str:
    """The encrypted-v2 per-request signature (HMAC-SHA256 over 53-character blocks)."""
    raw = f"h={hash_hex}&s={seq + data_len}"
    mac_key = f"k={key}&i={iv}".encode()
    return "".join(hmac.new(mac_key, raw[i:i + RSA_BLOCK].encode(), hashlib.sha256).hexdigest()
                   for i in range(0, len(raw), RSA_BLOCK))


def _legacy_tls_adapter_cls() -> Any:
    import ssl

    from requests.adapters import HTTPAdapter

    class _Adapter(HTTPAdapter):
        """HTTPS to LAN extenders whose web UI offers only RSA key exchange (e.g. RE1750X: AES128-GCM-SHA256),
        which current Python/OpenSSL defaults refuse with a handshake failure.  Certificates are self-signed
        and not verified (as for the whole session)."""

        def init_poolmanager(self, *a: Any, **k: Any) -> Any:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # nosec B501 - LAN devices with self-signed certificates
            ctx.set_ciphers("DEFAULT:AES128-GCM-SHA256:AES256-GCM-SHA384:@SECLEVEL=1")
            k["ssl_context"] = ctx
            return super().init_poolmanager(*a, **k)

    return _Adapter


def _LegacyTLSAdapter() -> Any:  # noqa: N802 - reads like a class at the call site
    return _legacy_tls_adapter_cls()()


class _WebSession:
    """Shared HTTP plumbing: Referer on every request, JSON envelope parsing, one admin session."""

    def __init__(self, host: str, password_getter: Callable[[], str], *, timeout: float = 20.0) -> None:
        import requests

        self._host = _normalize_host(host)
        self._password_getter = password_getter
        self._timeout = timeout
        self._http = requests.Session()
        self._http.verify = False  # nosec B501 - devices use self-signed certificates on the LAN
        self._http.mount("https://", _LegacyTLSAdapter())
        self._http.headers.update({"Referer": f"{self._host}/webpages/index.html", "Content-Type": FORM,
                                   "Accept": "application/json, text/plain, */*"})
        self._stok = ""

    def _password(self) -> str:
        try:
            pw = self._password_getter()
        except OSError as exc:
            raise RouterError(E_LOGIN, f"cannot read the device password: {type(exc).__name__}") from exc
        if not pw:
            raise RouterError(E_LOGIN, "no password configured for this device")
        return pw

    def _post(self, path: str, body: str, *, stok: str | None = None) -> Any:
        import requests

        url = f"{self._host}/cgi-bin/luci/;stok={self._stok if stok is None else stok}/{path.lstrip('/')}"
        try:
            resp = self._http.post(url, data=body, timeout=self._timeout)
        except requests.Timeout as exc:
            raise RouterError(E_TIMEOUT, f"no reply within {self._timeout}s", ambiguous=True) from exc
        except requests.RequestException as exc:
            raise RouterError(E_NETWORK, type(exc).__name__, ambiguous=True) from exc
        if resp.status_code >= 500:
            raise RouterError(E_SERVER, f"HTTP {resp.status_code}", ambiguous=True)
        if resp.status_code >= 400:
            raise RouterError(E_HTTP, f"HTTP {resp.status_code}")
        return resp

    @staticmethod
    def _envelope(obj: Any) -> Any:
        if isinstance(obj, dict) and "success" in obj:
            if obj.get("success"):
                return obj.get("data")
            code = obj.get("errorcode")
            raise RouterError(str(code if code is not None else "unknown"), str(obj.get("msg") or code or ""))
        return obj

    def upload(self, *a: Any, **k: Any) -> Any:  # noqa: ARG002
        raise RouterError("unsupported", "file upload is not implemented for this device protocol")

    def download(self, *a: Any, **k: Any) -> Any:  # noqa: ARG002
        raise RouterError("unsupported", "file download is not implemented for this device protocol")


class ExtenderTransport(_WebSession):
    """X-series web UI (plain form posts; RSA-1024 PKCS#1 v1.5 login)."""

    def login(self) -> None:
        pw = self._password()
        try:
            key = self._json(self._post("login?form=login", "operation=read", stok=""))["password"]
            enc = _rsa_pkcs1_hex(key[0], key[1], pw)
        except RouterError:
            raise
        except Exception as exc:  # noqa: BLE001 - unexpected key format
            raise RouterError(E_BAD_REPLY, f"unexpected login key reply: {type(exc).__name__}") from exc
        try:
            data = self._json(self._post("login?form=login", f"operation=login&password={enc}&confirm=true", stok=""))
        except RouterError as exc:
            raise LoginRefused(f"the device refused the login ({exc.code}); check the password. Not retried: "
                               "these devices lock the account after repeated failures") from exc
        self._stok = str((data or {}).get("stok") or "")
        if not self._stok:
            raise LoginRefused("login reply had no session token")

    def _json(self, resp: Any) -> Any:
        try:
            obj = resp.json()
        except ValueError as exc:
            raise RouterError(E_BAD_REPLY, f"non-JSON reply: {resp.text[:120]!r}", ambiguous=True) from exc
        return self._envelope(obj)

    def logout(self) -> None:
        if not self._stok:
            return
        try:
            self._post("admin/system?form=logout", "operation=write")
        except RouterError as exc:
            logger.debug("logout failed: %r", exc)
        self._stok = ""

    def call(self, path: str, op: str, fields: dict[str, str] | None = None, *,
             timeout: float | None = None) -> Any:  # noqa: ARG002
        if not self._stok:
            raise RouterError(E_LOGIN, "not logged in")
        body = urlencode({**({"operation": op} if op else {}), **check_fields(fields)}, doseq=True)
        return self._json(self._post(f"admin/{path.lstrip('/')}", body))


class HardenedTransport(_WebSession):
    """encrypted-v2: AES bodies, SHA-256 hash, RSA-OAEP login signature, HMAC + per-request hash after."""

    def __init__(self, host: str, password_getter: Callable[[], str], *, timeout: float = 20.0) -> None:
        super().__init__(host, password_getter, timeout=timeout)
        # Over HTTPS this web UI does NOT wrap requests (its GdprService encrypts only when the page is plain
        # HTTP): plain form posts, the password RSA-encrypted with the login?form=keys key, confirm=true.
        self._tls = self._host.startswith("https://")
        self._key = "".join(secrets.choice("0123456789") for _ in range(16))
        self._iv = "".join(secrets.choice("0123456789") for _ in range(16))
        self._seq = 0
        self._hash = ""

    def _aes(self) -> Any:
        from Crypto.Cipher import AES  # nosec B413 - pycryptodome (maintained), not pyCrypto

        return AES.new(self._key.encode(), AES.MODE_CBC, self._iv.encode())

    def _encrypt(self, text: str) -> str:
        from Crypto.Util.Padding import pad  # nosec B413 - pycryptodome (maintained), not pyCrypto

        return base64.b64encode(self._aes().encrypt(pad(text.encode(), 16))).decode()

    def _decrypt(self, b64: str) -> str:
        from Crypto.Util.Padding import unpad  # nosec B413 - pycryptodome (maintained), not pyCrypto

        return unpad(self._aes().decrypt(base64.b64decode(b64)), 16).decode()

    def _plain_json(self, resp: Any) -> Any:
        try:
            return self._envelope(resp.json())
        except ValueError as exc:
            raise RouterError(E_BAD_REPLY, "non-JSON reply", ambiguous=True) from exc

    def _decrypted(self, resp: Any) -> Any:
        try:
            outer = resp.json()
            obj = json.loads(self._decrypt(outer["data"])) if isinstance(outer.get("data"), str) else outer
        except Exception as exc:  # noqa: BLE001 - undecodable reply: we cannot know if it acted
            raise RouterError(E_BAD_REPLY, f"undecodable reply: {type(exc).__name__}", ambiguous=True) from exc
        return self._envelope(obj)

    def login(self) -> None:
        pw = self._password()
        if self._tls:
            self._login_tls(pw)
            return
        try:
            pkey = self._plain_json(self._post("login?form=keys", "operation=read", stok=""))["password"]
            auth = self._plain_json(self._post("login?form=auth", "operation=read", stok=""))
            self._seq, akey = int(auth["seq"]), auth["key"]
        except RouterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise RouterError(E_BAD_REPLY, f"unexpected key reply: {type(exc).__name__}") from exc
        self._hash = hashlib.sha256(("admin" + pw).encode()).hexdigest()
        data = self._encrypt("operation=login&password=" + _rsa_pkcs1_hex(pkey[0], pkey[1], pw))
        raw = f"k={self._key}&i={self._iv}&h={self._hash}&s={self._seq + len(data)}"
        sign = "".join(_rsa_oaep_hex(akey[0], akey[1], raw[i:i + RSA_BLOCK]) for i in range(0, len(raw), RSA_BLOCK))
        try:
            reply = self._decrypted(self._post("login?form=login", urlencode({"sign": sign, "data": data}), stok=""))
        except RouterError as exc:
            raise LoginRefused(f"the device refused the login ({exc.code}). This protocol (encrypted-v2) is for the "
                               "hardened web UI generation (e.g. RE3200BE fw 1.5); check the password and the "
                               "configured protocol. Not retried: failed logins lock the account") from exc
        self._stok = str((reply or {}).get("stok") or "")
        if not self._stok:
            raise LoginRefused("login reply had no session token")

    def _login_tls(self, pw: str) -> None:
        try:
            pkey = self._plain_json(self._post("login?form=keys", "operation=read", stok=""))["password"]
            enc = _rsa_pkcs1_hex(pkey[0], pkey[1], pw)
        except RouterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise RouterError(E_BAD_REPLY, f"unexpected key reply: {type(exc).__name__}") from exc
        try:
            data = self._plain_json(self._post("login?form=login", f"operation=login&password={enc}&confirm=true",
                                               stok=""))
        except RouterError as exc:
            raise LoginRefused(f"the device refused the login ({exc.code}); check the password. Not retried: "
                               "failed logins lock the account") from exc
        self._stok = str((data or {}).get("stok") or "")
        if not self._stok:
            raise LoginRefused("login reply had no session token")

    def _send(self, path: str, plain: str) -> Any:
        data = self._encrypt(plain)
        sign = hmac_signature(self._key, self._iv, hashlib.sha256(data.encode()).hexdigest(), self._seq, len(data))
        return self._post(path, urlencode({"sign": sign, "data": data}))

    def logout(self) -> None:
        if not self._stok:
            return
        try:
            if self._tls:
                self._post("admin/system?form=logout", "operation=write")
            else:
                self._send("admin/system?form=logout", "operation=write")
        except RouterError as exc:
            logger.debug("logout failed: %r", exc)
        self._stok = ""

    def call(self, path: str, op: str, fields: dict[str, str] | None = None, *,
             timeout: float | None = None) -> Any:  # noqa: ARG002
        if not self._stok:
            raise RouterError(E_LOGIN, "not logged in")
        body = urlencode({**({"operation": op} if op else {}), **check_fields(fields)}, doseq=True)
        if self._tls:
            return self._plain_json(self._post(f"admin/{path.lstrip('/')}", body))
        return self._decrypted(self._send(f"admin/{path.lstrip('/')}", body))
