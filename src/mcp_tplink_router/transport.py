"""Talking to the router's LuCI JSON API.

The BE9300 web UI posts ``application/x-www-form-urlencoded`` bodies to
``/cgi-bin/luci/;stok=<stok>/admin/<module>?form=<form>``; the URL carries only the
``form=`` selector(s), and ``operation`` plus every field travel in the body.  Replies are
``{"success": true, "data": ...}`` or ``{"success": false, "errorcode": "..."}``; a crash in a
Lua handler comes back as HTTP 500 with a traceback.

Login is borrowed from ``tplinkrouterc6u.TplinkRouterV1_11`` (its RSA login works on this
firmware), but its ``request()`` is NOT used: it copies every field, unencoded, into the
query string and sends a JSON body, which leaks secrets into URLs, corrupts values and
crashes the ``/admin/vpn`` module.

The router allows ONE admin session.  :func:`session` logs in, yields a transport and
always logs out, so the owner's browser/Tether login is never held hostage.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, Protocol

logger = logging.getLogger(__name__)

# Error codes this module raises itself (router-side codes are passed through verbatim).
E_TIMEOUT = "timeout"
E_NETWORK = "network"
E_HTTP = "http_error"
E_SERVER = "server_error"  # HTTP 500 / Lua traceback
E_BAD_REPLY = "bad_reply"
E_LOGIN = "login_failed"
E_REDIRECT = "redirect"


class RouterError(Exception):
    """A failed router call.

    ``code`` is the router's ``errorcode`` (e.g. ``"no such callback"``) or one of the
    ``E_*`` constants above.  ``ambiguous`` is True when we cannot know whether the router
    acted on the request (timeout, dropped connection, server crash): callers must NEVER
    blindly resend a write in that case - re-read and report instead.
    """

    def __init__(self, code: str, message: str = "", *, ambiguous: bool = False) -> None:
        self.code = str(code)
        self.message = message or str(code)
        self.ambiguous = ambiguous
        super().__init__(f"{self.code}: {self.message}" if message else self.code)


class Transport(Protocol):
    """Anything that can perform one router call."""

    def call(self, path: str, op: str, fields: dict[str, str] | None = None) -> Any:
        """POST ``operation=op`` plus ``fields`` to ``/admin/<path>``; return ``data``."""
        ...


def check_fields(fields: dict[str, Any] | None) -> dict[str, Any]:
    """Validate a field dict: every value must already be a string.

    ``requests`` would silently mangle bools and dicts when form-encoding, so we refuse them;
    callers stringify deliberately (``"on"``/``"off"``, ``json.dumps``...).  Ints are converted.
    A list of strings is sent as the same key repeated (the router's form for e.g. server_list).
    """
    out: dict[str, Any] = {}
    for key, value in (fields or {}).items():
        if key == "operation":
            raise ValueError("'operation' is passed separately, not as a field")
        if isinstance(value, list) and all(isinstance(v, str) for v in value):
            out[str(key)] = list(value)  # sent as the SAME key repeated (key=a&key=b), like the web UI
            continue
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise TypeError(
                f"field {key!r} must be a string (got {type(value).__name__}); "
                "stringify it explicitly (e.g. 'on'/'off' or json.dumps)"
            )
        out[str(key)] = str(value)
    return out


_TRACEBACK_LINES = 6


def _summarise_500(text: str) -> str:
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    return " | ".join(lines[:_TRACEBACK_LINES])[:600]


def parse_reply(status: int, text: str) -> Any:
    """Turn an HTTP status + body into data or a :class:`RouterError`."""
    import json

    if 300 <= status < 400:
        raise RouterError(E_REDIRECT, f"HTTP {status} redirect (refusing to follow)")
    if status >= 500:
        raise RouterError(E_SERVER, f"HTTP {status}: {_summarise_500(text)}", ambiguous=True)
    if status >= 400:
        raise RouterError(E_HTTP, f"HTTP {status}: {text[:200]}")
    try:
        body = json.loads(text)
    except ValueError as exc:
        raise RouterError(E_BAD_REPLY, f"non-JSON reply: {text[:200]!r}", ambiguous=True) from exc
    if not isinstance(body, dict):
        raise RouterError(E_BAD_REPLY, f"unexpected reply: {text[:200]!r}")
    if body.get("success") is True:
        return body.get("data")
    code = body.get("errorcode")
    if code is None and isinstance(body.get("data"), dict):
        code = body["data"].get("errorcode")
    raise RouterError(str(code if code is not None else "unknown"), str(body.get("msg") or code or ""))


class RouterTransport:
    """Real transport: tplinkrouterc6u login, our own form-urlencoded POSTs."""

    def __init__(self, host: str, password: str, *, timeout: float = 20.0) -> None:
        host = host.strip().rstrip("/")
        if not re.match(r"^https?://", host):
            host = "http://" + host
        self._host = host
        self._password = password
        self._timeout = timeout
        self._router: Any = None

    # -- session -----------------------------------------------------------------------
    def login(self) -> None:
        try:
            from tplinkrouterc6u import TplinkRouterV1_11
        except ImportError as exc:  # pragma: no cover - dependency is required
            raise RouterError(E_LOGIN, "tplinkrouterc6u is not installed") from exc
        router = TplinkRouterV1_11(self._host, self._password, verify_ssl=False, timeout=int(self._timeout))
        try:
            router.authorize()
        except Exception as exc:  # noqa: BLE001 - library raises many types
            # Never echo the password; the library's messages don't include it, but be safe.
            msg = str(exc).replace(self._password, "<redacted>") if self._password else str(exc)
            raise RouterError(E_LOGIN, msg[:300]) from exc
        self._router = router

    def logout(self) -> None:
        router, self._router = self._router, None
        if router is None:
            return
        try:
            router.logout()
        except Exception as exc:  # noqa: BLE001
            logger.debug("logout failed: %r", exc)

    # -- calls -------------------------------------------------------------------------
    def _post(self, path: str, *, data: dict[str, str], files: dict[str, Any] | None = None,
              timeout: float | None = None) -> Any:
        import requests
        import urllib3

        if self._router is None:
            raise RouterError(E_LOGIN, "not logged in")
        r = self._router
        url = f"{r.host}/cgi-bin/luci/;stok={r._stok}/admin/{path.lstrip('/')}"
        headers = dict(r._headers_request)
        headers.pop("Content-Type", None)
        if files is None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        wait = timeout or self._timeout
        try:
            resp = requests.post(
                url,
                data=data,
                files=files,
                headers=headers,
                cookies={"sysauth": r._sysauth},
                verify=False,  # nosec B501 - home routers use a self-signed certificate on the LAN
                timeout=wait,
                allow_redirects=False,
            )
        except requests.Timeout as exc:
            raise RouterError(E_TIMEOUT, f"no reply within {wait}s", ambiguous=True) from exc
        except requests.RequestException as exc:
            raise RouterError(E_NETWORK, type(exc).__name__, ambiguous=True) from exc
        self._check_redirect(resp)
        return resp

    @staticmethod
    def _check_redirect(resp: Any) -> None:
        if 300 <= resp.status_code < 400:
            loc = resp.headers.get("Location", "")
            scheme = loc.split("://", 1)[0] if "://" in loc else "?"
            raise RouterError(
                E_REDIRECT,
                f"HTTP {resp.status_code} redirect to a {scheme}:// URL; not following it "
                "(a redirected POST loses its body). Set TPLINK_HOST to that scheme, "
                "e.g. https://192.168.0.1",
            )

    def call(self, path: str, op: str, fields: dict[str, str] | None = None, *,
             timeout: float | None = None) -> Any:
        """POST a form.  ``op=""`` sends no ``operation`` field (the UI does this for a few
        action forms, e.g. WPS push-button)."""
        body = {**({"operation": op} if op else {}), **check_fields(fields)}
        resp = self._post(path, data=body, timeout=timeout)
        return parse_reply(resp.status_code, resp.text)

    def upload(self, path: str, fields: dict[str, str], files: dict[str, tuple[str, bytes]],
               *, timeout: float = 720.0) -> Any:
        """multipart/form-data POST (config restore, firmware image).  The UI allows 12 minutes."""
        op = fields.get("operation", "")
        body = {**({"operation": op} if op else {}),
                **check_fields({k: v for k, v in fields.items() if k != "operation"})}
        resp = self._post(path, data=body,
                          files={k: (name, data, "application/octet-stream") for k, (name, data) in files.items()},
                          timeout=timeout)
        if resp.headers.get("Content-Type", "").startswith("application/json") or resp.text.lstrip().startswith("{"):
            return parse_reply(resp.status_code, resp.text)
        if resp.status_code >= 400:
            raise RouterError(E_HTTP if resp.status_code < 500 else E_SERVER, f"HTTP {resp.status_code}",
                              ambiguous=resp.status_code >= 500)
        return {}

    def download(self, path: str, fields: dict[str, str]) -> tuple[bytes, str]:
        """multipart POST whose reply is a file (config backup).  Returns (bytes, filename)."""
        op = fields.get("operation", "")
        parts = {**({"operation": op} if op else {}),
                 **check_fields({k: v for k, v in fields.items() if k != "operation"})}
        resp = self._post(path, data={}, files={k: (None, v) for k, v in parts.items()})
        ctype = resp.headers.get("Content-Type", "")
        if resp.status_code >= 400 or ctype.startswith("application/json") or ctype.startswith("text/"):
            return parse_reply(resp.status_code, resp.text), ""  # an error reply raises here
        disp = resp.headers.get("Content-Disposition", "")
        m = re.search(r'filename="?([^";]+)"?', disp)
        return resp.content, (m.group(1) if m else "")


TransportFactory = Callable[[], Any]


@contextmanager
def session(factory: TransportFactory) -> Iterator[Any]:
    """Log in, yield the transport, always log out (one admin session only)."""
    transport = factory()
    transport.login()
    try:
        yield transport
    finally:
        transport.logout()


class EncryptedRouterTransport:
    """Transport for older firmware (e.g. Archer BE4800 1.0.x) with the ENCRYPTED LuCI protocol.

    Login is ``tplinkrouterc6u.TplinkRouter(...).authorize()`` (RSA keys + sequence), and every
    request is AES-encrypted by that client and its reply decrypted.  The password is fetched
    from ``password_getter`` at login only.

    The body is sent exactly as the router's own web page sends it: a form-urlencoded string with
    ``Content-Type: application/x-www-form-urlencoded``.  The library's ``TplinkRouterJson.request``
    (written for the BE805) is deliberately skipped, because it re-encodes the body as JSON with
    ``dict(parse_qsl(...))``, which (1) collapses repeated keys to the last value (so a list such as
    MLO ``selected_bands=2g&selected_bands=5g`` arrives as just ``"5g"`` and the router silently
    refuses the change), (2) drops blank values, and (3) copies every field, secrets included,
    into the URL query string.
    """

    FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"

    def __init__(self, host: str, password_getter: Callable[[], str], *, timeout: float = 20.0,
                 client_factory: Callable[[str, str, int], Any] | None = None) -> None:
        host = host.strip().rstrip("/")
        if not re.match(r"^https?://", host):
            host = "https://" + host
        self._host = host
        self._password_getter = password_getter
        self._timeout = timeout
        self._client_factory = client_factory
        self._router: Any = None

    def _make_client(self, password: str) -> Any:
        if self._client_factory is not None:
            return self._client_factory(self._host, password, int(self._timeout))
        from tplinkrouterc6u import TplinkRouter

        return TplinkRouter(self._host, password, verify_ssl=False, timeout=int(self._timeout))

    def login(self) -> None:
        try:
            password = self._password_getter()
        except OSError as exc:
            raise RouterError(E_LOGIN, f"cannot read the router password: {type(exc).__name__}") from exc
        if not password:
            raise RouterError(E_LOGIN, "no password configured for this router")
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:  # pragma: no cover
            pass
        client = self._make_client(password)
        try:
            client.authorize()
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).replace(password, "<redacted>")
            raise RouterError(E_LOGIN, msg[:300]) from exc
        self._router = client

    def logout(self) -> None:
        router, self._router = self._router, None
        if router is None:
            return
        try:
            router.logout()
        except Exception as exc:  # noqa: BLE001
            logger.debug("logout failed: %r", exc)

    def device_config(self) -> dict[str, Any] | None:
        """The web UI's capability flags (device_config?form=config).  This form is outside /admin/ and
        answered in plain JSON, so it is fetched directly with the session cookie.  None if unavailable."""
        client = self._router
        try:
            import requests

            resp = requests.post(f"{client.host}/cgi-bin/luci/;stok={client._stok}/device_config?form=config",  # noqa: SLF001
                                 data="operation=read", cookies={"sysauth": client._sysauth},  # noqa: SLF001
                                 headers={"Content-Type": self.FORM_CONTENT_TYPE, "Referer": client.host + "/"},
                                 verify=False, timeout=self._timeout)  # nosec B501 - routers use self-signed certs
            data = resp.json().get("data")
        except Exception as exc:  # noqa: BLE001 - optional information
            logger.debug("device_config unavailable: %r", exc)
            return None
        return data if isinstance(data, dict) else None

    def _form_request(self, path: str, body: str) -> Any:
        """Send ``body`` as a form, through the client's encryption but past its JSON adapter."""
        client = self._router
        if self._client_factory is not None:  # injected client (tests / custom): use it as-is
            return client.request(path, body, ignore_errors=True)
        try:
            from tplinkrouterc6u.client.c6u import TplinkRouterJson
        except ImportError as exc:  # fail closed: never fall back to the JSON adapter
            raise RouterError(E_BAD_REPLY, "unsupported tplinkrouterc6u layout (TplinkRouterJson not found); "
                                           "install the pinned version") from exc
        if not isinstance(client, TplinkRouterJson):
            raise RouterError(E_BAD_REPLY, f"unsupported tplinkrouterc6u client {type(client).__name__}; "
                                           "install the pinned version")
        headers = client._headers_request  # noqa: SLF001 - instance dict owned by the client
        saved = headers.get("Content-Type")
        headers["Content-Type"] = self.FORM_CONTENT_TYPE
        try:
            return super(TplinkRouterJson, client).request(path, body, ignore_errors=True)
        finally:
            if saved is None:
                headers.pop("Content-Type", None)
            else:
                headers["Content-Type"] = saved

    def call(self, path: str, op: str, fields: dict[str, str] | None = None, *,
             timeout: float | None = None) -> Any:  # noqa: ARG002 - the library owns the timeout
        from urllib.parse import urlencode

        if self._router is None:
            raise RouterError(E_LOGIN, "not logged in")
        body = urlencode({**({"operation": op} if op else {}), **check_fields(fields)}, doseq=True)
        try:
            res = self._form_request(f"admin/{path.lstrip('/')}", body)
        except Exception as exc:  # noqa: BLE001 - requests errors + the library's ClientError
            name = type(exc).__name__
            if "Timeout" in name:
                raise RouterError(E_TIMEOUT, f"no reply within {self._timeout}s", ambiguous=True) from exc
            if "Connection" in name or "SSL" in name:
                raise RouterError(E_NETWORK, name, ambiguous=True) from exc
            # Undecodable / unexpected reply (e.g. a 500 traceback): we cannot know if it acted.
            raise RouterError(E_BAD_REPLY, f"{name}: {str(exc)[:300]}", ambiguous=True) from exc
        if isinstance(res, dict) and "success" in res:
            if res.get("success"):
                return res.get("data")
            code = res.get("errorcode")
            if code is None and isinstance(res.get("data"), dict):
                code = res["data"].get("errorcode")
            raise RouterError(str(code if code is not None else "unknown"), str(res.get("msg") or code or ""))
        return res

    def upload(self, path: str, fields: dict[str, str], files: dict[str, tuple[str, bytes]],  # noqa: ARG002
               *, timeout: float = 720.0) -> Any:  # noqa: ARG002
        raise RouterError("unsupported", "file upload is not implemented for the encrypted protocol; "
                                         "use the router's web page")

    def download(self, path: str, fields: dict[str, str]) -> tuple[bytes, str]:  # noqa: ARG002
        raise RouterError("unsupported", "file download is not implemented for the encrypted protocol; "
                                         "use the router's web page")
