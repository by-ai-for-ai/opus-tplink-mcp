"""Router registry configuration from the environment.

* ``main`` - ``TPLINK_HOST`` / ``TPLINK_PASSWORD`` (plain-form transport, BE-series firmware).
* extra routers - ``TPLINK_ROUTERS="upstairs,office"`` and per router (upper-case name):
  ``TPLINK_<NAME>_HOST``, ``TPLINK_<NAME>_PASSWORD_FILE`` (preferred) or
  ``TPLINK_<NAME>_PASSWORD``, ``TPLINK_<NAME>_PROTOCOL`` = ``plain`` | ``encrypted``
  (default plain), optional ``TPLINK_<NAME>_TIMEOUT``.

Passwords from files are read at login time only and never logged.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

PROTOCOLS = ("plain", "encrypted", "extender", "encrypted-v2")
KINDS = ("router", "extender")


@dataclass(frozen=True)
class RouterConfig:
    name: str
    host: str
    protocol: str = "plain"
    kind: str = "router"
    password: str | None = None
    password_file: str | None = None
    timeout: float = 20.0

    def password_getter(self) -> Callable[[], str]:
        if self.password_file:
            path = Path(self.password_file).expanduser()
            return lambda: path.read_text(encoding="utf-8").strip()
        pw = self.password or ""
        return lambda: pw

    def describe(self) -> dict[str, str]:
        return {"name": self.name, "host": self.host, "protocol": self.protocol, "kind": self.kind}


def load_routers(env: Mapping[str, str] | None = None) -> dict[str, RouterConfig]:
    env = os.environ if env is None else env
    routers = {
        "main": RouterConfig(
            name="main", host=env.get("TPLINK_HOST", "192.168.0.1"), protocol="plain",
            password=env.get("TPLINK_PASSWORD", ""), password_file=env.get("TPLINK_PASSWORD_FILE") or None,
            timeout=float(env.get("TPLINK_TIMEOUT", "20")),
        )
    }
    for raw in (env.get("TPLINK_ROUTERS") or "").split(","):
        name = raw.strip().lower()
        if not name:
            continue
        if not re.fullmatch(r"[a-z][a-z0-9_]*", name) or name == "main":
            raise ValueError(f"bad router name {raw!r} in TPLINK_ROUTERS")
        up = name.upper()
        host = env.get(f"TPLINK_{up}_HOST")
        if not host:
            raise ValueError(f"TPLINK_{up}_HOST is required for router {name!r}")
        proto = (env.get(f"TPLINK_{up}_PROTOCOL") or "plain").lower()
        if proto not in PROTOCOLS:
            raise ValueError(f"TPLINK_{up}_PROTOCOL must be one of {PROTOCOLS}")
        kind = (env.get(f"TPLINK_{up}_KIND") or ("extender" if proto == "extender" else "router")).lower()
        if kind not in KINDS:
            raise ValueError(f"TPLINK_{up}_KIND must be one of {KINDS}")
        routers[name] = RouterConfig(
            name=name, host=host, protocol=proto, kind=kind, password=env.get(f"TPLINK_{up}_PASSWORD"),
            password_file=env.get(f"TPLINK_{up}_PASSWORD_FILE") or None,
            timeout=float(env.get(f"TPLINK_{up}_TIMEOUT", env.get("TPLINK_TIMEOUT", "20"))),
        )
    return routers
