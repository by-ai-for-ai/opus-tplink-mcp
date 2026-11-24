"""What each router can do, as learned live - so the tool refuses up front instead of failing mid-plan.

Design review rules (2026-11-23):
  * The live device is the authority.  "absent" means: this router answered "no such callback" / HTTP 404 for
    the forms behind a tool action, on THIS model + hardware + firmware.  It is a statement about this tool's
    support, never about the router: refusals say "not supported by this tool on <model> <firmware>; it may
    exist in the router's own web page".
  * Keyed on the exact model / hardware / firmware AND operation mode (from the firmware watcher).  A firmware
    or mode change - seen by the watcher, or made through this tool - forgets everything learned for that
    router; entries also expire after an hour, so a transient state (a disabled feature, mesh role) cannot stick.
  * Refuse rather than hide: one MCP server serves several routers with one static tool list.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

TTL = 3600.0  # short on purpose: a wrong 'not supported' must not outlive a transient state


def _file() -> Path:
    from . import events

    return events.path().with_name("capabilities.json")


def _load() -> dict[str, Any]:
    try:
        return json.loads(_file().read_text())
    except (OSError, ValueError):
        return {}


def _save(d: dict[str, Any]) -> None:
    f = _file()
    try:
        f.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = f.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(d, indent=1).encode())
        finally:
            os.close(fd)
        os.replace(tmp, f)
    except OSError:
        pass


def _key(router: str, host: str) -> tuple[str, dict[str, Any]]:
    from . import events

    dev = events.device_info(router, host)
    # operation mode is part of the key: router-only features are absent in AP / repeater mode and come back after
    ident = "|".join(str(dev.get(k, "")) for k in ("model", "hardware_version", "firmware_version", "mode"))
    return f"{router}@{host}#{ident}", dev


_NOT_SELECTORS = {"action", "router", "device", "apply", "confirm_token", "reveal", "intent", "settings", "enable",
                  "force", "id", "name", "mac", "macs", "ip", "limit", "since", "contains"}


def _feature(tool: str, args: dict[str, Any]) -> str:
    """tool:action plus the selectors that pick WHICH form (band=6g, section=..., family=6) - so a missing
    6 GHz band never blocks the 2.4 / 5 GHz reads.  Values the user supplies (names, MACs, IPs) are not part."""
    a = args.get("action")
    sel = [f"{k}={v}" for k, v in sorted(args.items())
           if k not in _NOT_SELECTORS and isinstance(v, (str, int)) and not isinstance(v, bool) and len(str(v)) <= 24]
    return ":".join([tool] + ([str(a)] if a else []) + sel)


def describe_device(router: str, host: str) -> str:
    _, dev = _key(router, host)
    if dev.get("model"):
        return f"{dev.get('model')} (hardware {dev.get('hardware_version', '?')}, firmware {dev.get('firmware_version', '?')})"
    return f"router {router!r}"


def known_absent(router: str, host: str, tool: str, args: dict[str, Any]) -> bool:
    k, _ = _key(router, host)
    e = _load().get(k, {}).get(_feature(tool, args))
    return bool(e) and time.time() - float(e.get("at", 0)) < TTL


def mark_absent(router: str, host: str, tool: str, args: dict[str, Any], code: str) -> None:
    k, _ = _key(router, host)
    d = _load()
    d.setdefault(k, {})[_feature(tool, args)] = {"at": time.time(), "code": code}
    _save(d)


def forget_router(router: str, host: str) -> None:
    """Firmware changed: everything learned about this router is out of date."""
    d = _load()
    prefix = f"{router}@{host}#"
    for k in [k for k in d if k.startswith(prefix)]:
        del d[k]
    _save(d)


def not_supported(router: str, host: str, tool: str, args: dict[str, Any], cached: bool = False) -> dict[str, Any]:
    what = " ".join(_feature(tool, args).split(":"))
    dev = describe_device(router, host)
    return {
        "status": "NOT_SUPPORTED", "applied": False, "verified": "no",
        "tell_user": (f"NOT SUPPORTED: {what} is not supported by this tool on {dev}; nothing was changed. "
                      "The setting may still exist in the router's own web page or app."),
        "error": "not supported on this router" + (" (learned earlier for this exact firmware)" if cached else ""),
    }


def summary(router: str, host: str) -> dict[str, Any]:
    """For the capabilities query: what this tool has learned NOT to try on this router."""
    k, dev = _key(router, host)
    now = time.time()
    absent = sorted(f for f, e in _load().get(k, {}).items() if now - float(e.get("at", 0)) < TTL)
    return {"device": describe_device(router, host),
            "not_supported_here": absent,
            "note": "Learned live on this router's exact firmware. Anything not listed is either supported or not "
                    "tried yet; a firmware change resets this list."}
