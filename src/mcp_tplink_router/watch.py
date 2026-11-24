"""``opus-tplink-mcp watch`` - follow the local event log live in a terminal.

    opus-tplink-mcp watch                 # everything, newest last, then follow
    opus-tplink-mcp watch --router main   # one device
    opus-tplink-mcp watch --kind error,not_done,firmware_changed
    opus-tplink-mcp watch --no-follow -n 50
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from typing import Any

from . import events

# ANSI colours per kind - the same key as the viewer window
COLOURS = {
    "error": "31", "unreachable": "31", "login_failed": "31", "mismatch": "31", "unknown": "31",
    "not_done": "33", "not_supported": "33", "refused": "33", "recovered": "33", "no_such_device": "33",
    "firmware_changed": "1;34", "mode_changed": "1;34", "firmware_seen": "34",
    "changed": "32", "restart": "36",
}


def line(e: dict[str, Any], colour: bool = True) -> str:
    ts = datetime.fromtimestamp(float(e.get("ts") or 0)).strftime("%Y-%m-%d %H:%M:%S")
    kind = str(e.get("kind"))
    rest = {k: v for k, v in e.items() if k not in ("ts", "kind", "router") and v not in (None, "", [], {})}
    detail = rest.pop("tell_user", None) or rest.pop("error", None) or ""
    extra = " ".join(f"{k}={json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v}"
                     for k, v in rest.items())
    text = f"{ts}  {e.get('router') or '-':10} {kind:17} {detail} {extra}".rstrip()
    c = COLOURS.get(kind)
    return f"\033[{c}m{text}\033[0m" if colour and c else text


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="opus-tplink-mcp watch", description="Follow the local event log live.")
    ap.add_argument("--router", help="only this device name")
    ap.add_argument("--kind", help="comma-separated kinds (" + ", ".join(events.KINDS) + ")")
    ap.add_argument("-n", type=int, default=30, help="how many past events to show first (default 30)")
    ap.add_argument("--no-follow", action="store_true", help="print and exit")
    a = ap.parse_args(argv)
    kinds = set(a.kind.split(",")) if a.kind else None
    colour = sys.stdout.isatty()

    def wanted(e: dict[str, Any]) -> bool:
        return (not a.router or e.get("router") == a.router) and (not kinds or e.get("kind") in kinds)

    print(f"events: {events.path()}", file=sys.stderr)
    for e in events.read(a.n * 5)[-a.n:] if not (a.router or kinds) else [x for x in events.read(5000) if wanted(x)][-a.n:]:
        print(line(e, colour))
    if a.no_follow:
        return 0
    p = events.path()
    pos = p.stat().st_size if p.exists() else 0
    try:
        while True:
            time.sleep(1)
            if not p.exists():
                continue
            size = p.stat().st_size
            if size < pos:  # rotated
                pos = 0
            if size == pos:
                continue
            with open(p, encoding="utf-8", errors="replace") as fh:
                fh.seek(pos)
                chunk = fh.read()
                pos = fh.tell()
            for raw in chunk.splitlines():
                try:
                    e = json.loads(raw)
                except ValueError:
                    continue
                if wanted(e):
                    print(line(e, colour), flush=True)
    except KeyboardInterrupt:
        return 0
