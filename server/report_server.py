#!/usr/bin/env python3
"""opus-tplink-mcp field-report server - tiny, dependency-free (Python 3.10+ standard library only).

Receives the optional field reports the tool sends when its user turned them ON, and publishes ONLY
aggregates.  Privacy rules (see the client's reporting.py and NOTICE):
  * never stores IP addresses - the per-IP rate limit lives in memory only; run it behind a reverse proxy
    with access logging OFF for this location
  * copies only allowlisted fields, each validated; everything else in a request is dropped
  * public endpoints show totals per day, and only combinations reported at least MIN_COUNT times
  * raw rows are kept RAW_DAYS days, then only the aggregates remain
  * all strings are untrusted (the anti-spam key ships in the open-source client): escaped on output

Fake reports cannot make a router "supported" (the client is open source, so anyone CAN send reports):
  * reports only ever produce "seen in the field (unverified)" counts; "verified" comes solely from
    DATA_DIR/verified.json, which only the maintainer writes (from bench / live apply-verify-undo results)
  * each source counts once per model/hardware/firmware/code/category per MONTH: the stored marker is an HMAC of
    the sender's network (/24 or /48) + that report's key, under a random salt kept in memory only and replaced
    every month.  One machine reporting on many days is one source; one installation's different reports get
    different markers, so they cannot be joined; markers cannot be turned back into an IP once the month's salt
    is gone (never written to disk).  Totals are the busiest single month.  A restart starts a new salt, so a
    source may count twice in the month of a restart.  The IP itself is never stored or logged.
  * public totals need MIN_COUNT DISTINCT sources, not MIN_COUNT reports
  * model / hardware / firmware strings must look like TP-Link ones; implausible reports are dropped
  * per-source limits per minute and per day (memory only)
  * the maintainer's private /feed lists new model/firmware combinations as "unconfirmed"

Endpoints
  POST /report     x-otm-key header; body <= 4 KB JSON; 204 on accept
  GET  /stats      totals
  GET  /devices    model / hardware / firmware seen in the field (unverified) + maintainer-verified flag
  GET  /errors     error groups (code, category, model, firmware, tool version)
  GET  /feed       PRIVATE (x-monitor-token): every group, project-monitor "monitor feed v1" format
  GET  /about      what is stored and why (plain text)
  POST /known-devices   one device identity: {oui, model, kind} (see known_devices_db.py); 204
  GET  /known-devices.json  the published identity table (entries seen on >= KD_MIN_NETWORKS networks)
  GET  /healthz

Env: PORT (8790), HOST (127.0.0.1), DATA_DIR (./data), OTM_KEY (required), MIN_COUNT (5), RAW_DAYS (90),
     MONITOR_TOKENS (comma-separated; enables /feed), DAILY_PER_SOURCE (200).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

PORT = int(os.environ.get("PORT", "8790"))
HOST = os.environ.get("HOST", "127.0.0.1")
DATA = Path(os.environ.get("DATA_DIR", "./data"))
KEY = os.environ.get("OTM_KEY", "")
MIN_COUNT = int(os.environ.get("MIN_COUNT", "5"))
RAW_DAYS = int(os.environ.get("RAW_DAYS", "90"))
MAX_BODY = 4096
RATE = 30  # requests per source per minute (memory only)
DAILY_PER_SOURCE = int(os.environ.get("DAILY_PER_SOURCE", "200"))
MONITOR_TOKENS = [t.strip().encode() for t in os.environ.get("MONITOR_TOKENS", "").split(",") if len(t.strip()) >= 32]
MODEL_RE = re.compile(r"^(Archer [A-Z]{1,4}[0-9]{2,5}[A-Z]{0,3}( Pro| Plus)?|RE[0-9]{3,4}[A-Z]{0,3}|Deco [A-Z0-9]{1,8}"
                      r"( Pro)?|TL-[A-Z0-9-]{3,16}|[A-Z]{2,4}[0-9]{2,5}[A-Z]{0,3})$")
FW_RE = re.compile(r"^\d{1,2}\.\d{1,3}\.\d{1,3}( Build \d{8}( [Rr]el\. ?\d{1,6}(\(\d{1,5}\))?)?)?$")

CODES = {
    "no_such_callback", "http_404", "login_refused", "login_failed", "not_done", "unknown_after_apply",
    "mismatch", "no_effect", "collateral", "unreachable", "settle_timeout", "firmware_changed",
    "refused", "recovered_previewed_call", "no_such_device", "internal_error", "device_seen",
}
CATEGORIES = {"wifi", "access controls", "network", "internet", "vpn", "system", "devices", "status", "journal",
              "extender", "raw", "other"}
SAFE = re.compile(r"^[A-Za-z0-9 ._()+/-]{1,64}$")
FRAME = re.compile(r"^mcp_tplink_router\.[a-z_]+:[A-Za-z_][A-Za-z0-9_]*:\d{1,6}$")
FIELDS: dict[str, Any] = {
    "code": lambda v: v if v in CODES else None,
    "category": lambda v: v if v in CATEGORIES else None,
    "exc_type": lambda v: v if isinstance(v, str) and re.match(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$", v) else None,
    "stack": lambda v: [f for f in v if isinstance(f, str) and FRAME.match(f)][:8] if isinstance(v, list) else None,
    "tool_version": lambda v: v if isinstance(v, str) and re.match(r"^[0-9][0-9a-z.+-]{0,31}$", v) else None,
    "python": lambda v: v if isinstance(v, str) and re.match(r"^3\.\d{1,2}$", v) else None,
    "os": lambda v: v if v in ("Linux", "Windows", "Darwin", "Other") else None,
    "protocol": lambda v: v if v in ("plain", "encrypted", "extender", "encrypted-v2") else None,
    "kind": lambda v: v if v in ("router", "extender") else None,
    "tier": lambda v: v if v in ("small", "large") else None,
    "model": lambda v: v if isinstance(v, str) and SAFE.match(v) else None,
    "hardware": lambda v: v if isinstance(v, str) and SAFE.match(v) else None,
    "firmware": lambda v: v if isinstance(v, str) and SAFE.match(v) else None,
}

_lock = threading.Lock()
_hits: dict[str, deque[float]] = defaultdict(deque)

import sys  # noqa: E402 - the known-device table lives next to this file

sys.path.insert(0, str(Path(__file__).resolve().parent))
import known_devices_db  # noqa: E402

KD = known_devices_db.Store(DATA)


def plausible(rec: dict[str, Any]) -> bool:
    """Device strings must look like TP-Link ones (they come from the router, so a real client always passes)."""
    m, hw, fw = rec.get("model"), rec.get("hardware"), rec.get("firmware")
    if m is not None and not MODEL_RE.match(m):
        return False
    if hw is not None and (m is None or not hw.startswith(m) or not re.match(r"^ v\d{1,2}(\.\d{1,2})?$", hw[len(m):])):
        return False
    if fw is not None and not FW_RE.match(fw):
        return False
    return not (rec.get("code") == "device_seen" and not (m and hw and fw))  # device_seen needs all three


def clean(body: dict[str, Any]) -> dict[str, Any] | None:
    out = {k: f(body.get(k)) for k, f in FIELDS.items()}
    out = {k: v for k, v in out.items() if v not in (None, [], "")}
    if "code" not in out or not plausible(out):
        return None
    out["day"] = time.strftime("%Y-%m-%d", time.gmtime())  # the server's day, not the client's
    return out


_salt = {"day": "", "key": b""}
_seen_today: set[tuple[Any, ...]] = set()
_per_source: dict[str, int] = defaultdict(int)


def source_id(ip: str) -> str:
    """Pseudonymous per-DAY id: HMAC(ip) under a random salt kept in memory only and replaced every day."""
    day = time.strftime("%Y-%m-%d", time.gmtime())
    with _lock:
        if _salt["day"] != day:
            _salt.update(day=day, key=secrets.token_bytes(32))
            _seen_today.clear()
            _per_source.clear()
        return hmac.new(_salt["key"], ip.encode(), hashlib.sha256).hexdigest()[:16]


_month_salt = {"month": "", "key": b""}


def entry_marker(ip: str, rec: dict[str, Any]) -> str:
    """The marker stored with a report: HMAC(month secret, sender network + THIS report's key).

    Counted per month, so one machine reporting on many days is one source (the per-day id let one machine count
    as N sources over N days).  Built from the report's own key, so one installation's reports cannot be joined
    to each other; the secret lives in memory only and changes monthly.  Network = /24 (IPv4) or /48 (IPv6).
    """
    month = time.strftime("%Y-%m", time.gmtime())
    net = known_devices_db.network_of(ip)
    key = "|".join(str(rec.get(x) or "") for x in ("code", "model", "hardware", "firmware", "category"))
    with _lock:
        if _month_salt["month"] != month:
            _month_salt.update(month=month, key=secrets.token_bytes(32))
        return hmac.new(_month_salt["key"], f"{net}|{key}".encode(), hashlib.sha256).hexdigest()[:16]


def admit(rec: dict[str, Any], src: str) -> bool:
    """Count each source once per day per (code, model, hardware, firmware, category); cap per source per day."""
    k = (src, rec.get("code"), rec.get("model"), rec.get("hardware"), rec.get("firmware"), rec.get("category"))
    with _lock:
        if k in _seen_today or _per_source[src] >= DAILY_PER_SOURCE:
            return False
        _seen_today.add(k)
        _per_source[src] += 1
    return True


def verified() -> dict[str, Any]:
    """Maintainer-verified model/hardware/firmware (written by hand from bench / live tests) - never from reports."""
    try:
        return json.loads((DATA / "verified.json").read_text())
    except (OSError, ValueError):
        return {}


def store(rec: dict[str, Any]) -> None:
    with _lock:
        DATA.mkdir(parents=True, exist_ok=True)
        with open(DATA / f"raw-{rec['day']}.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        cutoff = time.time() - RAW_DAYS * 86400
        for f in DATA.glob("raw-*.jsonl"):
            if f.stat().st_mtime < cutoff:
                _fold_into_aggregate(f)


def _fold_into_aggregate(f: Path) -> None:
    agg_f = DATA / "aggregate.json"
    agg = json.loads(agg_f.read_text()) if agg_f.exists() else {}
    for line in f.read_text().splitlines():
        r = json.loads(line)
        k = json.dumps([r.get(x) for x in ("code", "category", "model", "hardware", "firmware", "tool_version")])
        agg[k] = agg.get(k, 0) + 1
    agg_f.write_text(json.dumps(agg))
    f.unlink()


def rows() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in sorted(DATA.glob("raw-*.jsonl")):
        out += [json.loads(x) for x in f.read_text().splitlines() if x.strip()]
    agg_f = DATA / "aggregate.json"
    if agg_f.exists():
        for k, n in json.loads(agg_f.read_text()).items():
            code, cat, model, hw, fw, tv = json.loads(k)
            out += [{"code": code, "category": cat, "model": model, "hardware": hw, "firmware": fw,
                     "tool_version": tv}] * n
    return out


def grouped(keys: tuple[str, ...], only: set[str] | None = None, exclude: set[str] | None = None,
            min_sources: int | None = None) -> list[dict]:
    """Totals per group; published only when MIN_COUNT DISTINCT sources reported it (not MIN_COUNT reports)."""
    need = MIN_COUNT if min_sources is None else min_sources
    g: dict[tuple, dict[str, Any]] = {}
    srcs: dict[tuple, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for r in rows():
        if only and r.get("code") not in only or exclude and r.get("code") in exclude:
            continue
        k = tuple(r.get(x) for x in keys)
        e = g.setdefault(k, {**dict(zip(keys, k)), "count": 0, "first_day": r.get("day", ""), "last_day": ""})
        e["count"] += 1
        e["last_day"] = max(e["last_day"], r.get("day", ""))
        e["first_day"] = min(e["first_day"] or r.get("day", ""), r.get("day", "") or e["first_day"])
        # markers are per month: a source counts once per month; the total is the busiest month, so one machine
        # reporting every month never adds up to several sources
        srcs[k][str(r.get("day", ""))[:7]].add(str(r.get("src") or r.get("day")))
    out = []
    for k, e in g.items():
        e["sources"] = max((len(v) for v in srcs[k].values()), default=0)
        if e["sources"] >= need:
            out.append(e)
    return sorted(out, key=lambda e: -e["sources"])


def monitor_feed() -> dict[str, Any]:
    """project-monitor "monitor feed v1": every group (owner view), day-level times, allowlisted fields only."""
    groups = grouped(("code", "category", "model", "hardware", "firmware", "tool_version", "exc_type"),
                     exclude={"device_seen"}, min_sources=1)
    new = grouped(("model", "hardware", "firmware"), only={"device_seen"}, min_sources=1)
    ver = verified()
    errors = []
    for e in groups:
        gid = "|".join(str(e.get(k) or "") for k in ("tool_version", "code", "exc_type", "model", "firmware", "category"))
        errors.append({"id": gid, "code": e["code"], "count": e["count"], "sources": e["sources"],
                       "first_seen": f"{e['first_day']}T00:00:00Z", "last_seen": f"{e['last_day']}T00:00:00Z",
                       "version": e.get("tool_version"), "exc_type": e.get("exc_type"),
                       "title": f"{e['code']} · {e.get('category') or '-'} · {e.get('model') or '?'} {e.get('firmware') or ''}".strip(),
                       "category": e.get("category"), "model": e.get("model"), "firmware": e.get("firmware")})
    for e in new:
        if not ver.get(f"{e['model']}|{e['hardware']}|{e['firmware']}"):
            errors.append({"id": f"unconfirmed|{e['model']}|{e['hardware']}|{e['firmware']}", "code": "unconfirmed_device",
                           "count": e["count"], "sources": e["sources"],
                           "first_seen": f"{e['first_day']}T00:00:00Z", "last_seen": f"{e['last_day']}T00:00:00Z",
                           "title": f"unconfirmed: {e['model']} {e['hardware']} fw {e['firmware']} (seen, not verified)",
                           "model": e["model"], "firmware": e["firmware"]})
    return {"errors": errors}


ABOUT = f"""opus-tplink-mcp field reports

Sent only by installs whose user turned field reports ON (they are OFF until a person chooses).
Stored: an error code, a feature category, the error type, stack frames inside the tool, tool / Python /
OS-family versions, login style, device kind, small/large mode, and the router model / hardware / firmware.
Not stored: IP addresses (not even in logs), MACs, Wi-Fi names, device or host names, requests,
error messages, paths, or any install ID.  Raw rows are kept {RAW_DAYS} days, then only totals.
Published: totals only, for combinations reported by at least {MIN_COUNT} DIFFERENT sources -
/devices, /errors, /stats.  Reports can be faked (the client is open source), so they never make a
router "supported": that comes only from the maintainer's own tests.
Each sender counts once per day per router/firmware, using an id derived from their IP with a random
secret that exists only in memory and changes daily, so it cannot be traced back or linked across days.
"""


class H(BaseHTTPRequestHandler):
    server_version = "otm-report/1"

    def log_message(self, *_a: Any) -> None:  # no access log: it would record IP addresses
        pass

    def _send(self, code: int, body: Any = None, ctype: str = "application/json") -> None:
        data = b"" if body is None else (body if isinstance(body, bytes) else
                                          (json.dumps(body, indent=1) if ctype == "application/json"
                                           else str(body)).encode())
        self.send_response(code)
        self.send_header("content-type", ctype + "; charset=utf-8")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        if data:
            self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        p = self.path.split("?")[0].rstrip("/") or "/"
        if p == "/healthz":
            return self._send(200, {"ok": True})
        if p in ("/", "/about"):
            return self._send(200, ABOUT, "text/plain")
        if p == "/stats":
            r = rows()
            return self._send(200, {"reports": len(r), "min_count": MIN_COUNT,
                                    "devices": len(grouped(("model", "hardware", "firmware"), only={"device_seen"}))})
        if p == "/devices":
            seen = grouped(("model", "hardware", "firmware", "protocol", "kind"), only={"device_seen"})
            problems = {(e["model"], e["firmware"]): e["count"] for e in
                        grouped(("model", "firmware"), exclude={"device_seen", "firmware_changed"})}
            ver = verified()
            for e in seen:
                e.pop("first_day", None)
                e["problem_reports"] = problems.get((e["model"], e["firmware"]), 0)
                v = ver.get(f"{e['model']}|{e['hardware']}|{e['firmware']}")
                e["status"] = "verified by the maintainer" if v else "seen in the field (unverified)"
                if v:
                    e["verified"] = v
            return self._send(200, {"note": "Field reports can be faked (the client is open source), so they never "
                                             "mark a router supported: 'verified' comes only from the maintainer's "
                                             "own tests.", "devices": seen})
        if p == "/known-devices.json":
            return self._send(200, KD.published())
        if p == "/feed":
            tok = (self.headers.get("x-monitor-token") or "").encode()
            if not MONITOR_TOKENS or not any(hmac.compare_digest(tok, t) for t in MONITOR_TOKENS):
                return self._send(404, {"error": "not found"})
            return self._send(200, monitor_feed())
        if p == "/errors":
            return self._send(200, grouped(("code", "category", "model", "firmware", "tool_version"),
                                           exclude={"device_seen"}))
        return self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.rstrip("/")
        if path not in ("/report", "", "/known-devices"):
            return self._send(404, {"error": "not found"})
        ip = self.headers.get("x-forwarded-for", self.client_address[0]).split(",")[0].strip()
        now = time.time()
        rk = source_id(ip)  # never keep the IP itself, even in memory structures
        with _lock:
            q = _hits[rk]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= RATE:
                return self._send(429, {"error": "slow down"})
            q.append(now)
        if not KEY or self.headers.get("x-otm-key") != KEY:
            return self._send(403, {"error": "key"})
        n = int(self.headers.get("content-length") or 0)
        if n <= 0 or n > MAX_BODY:
            return self._send(413, {"error": "size"})
        try:
            body = json.loads(self.rfile.read(n))
        except ValueError:
            return self._send(400, {"error": "json"})
        if path == "/known-devices":
            kd = known_devices_db.clean(body) if isinstance(body, dict) else None
            if kd is None:
                return self._send(400, {"error": "fields"})
            src = source_id(ip)
            with _lock:
                over = _per_source[src] >= DAILY_PER_SOURCE
                _per_source[src] += 1
            if not over:
                KD.add(kd, ip)  # counted once per network per entry per month; the IP is not kept
            return self._send(204)
        rec = clean(body) if isinstance(body, dict) else None
        if rec is None:
            return self._send(400, {"error": "fields"})
        if admit(rec, source_id(ip)):  # repeats from the same source are accepted silently but not counted
            rec["src"] = entry_marker(ip, rec)
            store(rec)
        return self._send(204)


if __name__ == "__main__":
    if not KEY:
        raise SystemExit("set OTM_KEY (the anti-spam key the client ships)")
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
