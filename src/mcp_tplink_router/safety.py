"""Plans, diffs, risk gating, confirm tokens, redaction and the journaled executor.

Every write tool builds a :class:`Plan` from fresh reads.  Without ``apply=true`` the plan
is only described (nothing is sent).  ``critical`` plans additionally need the
``confirm_token`` from a dry run: an HMAC over the exact requests (which embed the current
values being replaced), valid for 5 minutes, so a token cannot be replayed onto a router
whose state has since changed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import socket
import subprocess
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from typing import Any

from . import catalog, forms
from .catalog import CRITICAL, FORBIDDEN, NORMAL, READ, max_risk
from .forms import Conflict, Step
from .journal import Journal
from .transport import RouterError

TOKEN_TTL = 300
_TOKEN_KEY = os.urandom(32)

# The server's memory of previewed-but-not-applied changes, per router: {router: {key: entry}}.
# Local-model bench: a model planned "dry run, then apply", lost that plan between turns (clients do not send
# a model's reasoning back) and previewed the same change again and again.  The server keeps the task state
# instead, shows it on every reply, and catches a repeated preview.
PENDING: dict[str, dict[str, dict[str, Any]]] = {}
PENDING_TTL = 300.0
# Every tool call on a router bumps its sequence number; a small-tier repeat confirms only if it comes
# straight after its preview (no call in between) and within REPEAT_WINDOW seconds.
CALL_SEQ: dict[str, int] = {}
REPEAT_WINDOW = 60.0


def note_call(router: str) -> int:
    CALL_SEQ[router] = CALL_SEQ.get(router, 0) + 1
    return CALL_SEQ[router]


def _pending_key(plan: Plan) -> str:
    return hashlib.sha256(json.dumps([plan.tool, plan.summary, [s.to_dict() for s in plan.steps]],
                                     sort_keys=True, default=str).encode()).hexdigest()[:16]


def pending_for(router: str, tool: str | None = None, now: float | None = None) -> list[dict[str, Any]]:
    """Unfinished (previewed, not applied) changes on ``router`` made with ``tool``, newest first.

    Only the SAME tool's unfinished changes are shown: a reminder on an unrelated call could nudge a model
    into applying a change the current request never asked for.
    """
    now = time.time() if now is None else now
    entries = PENDING.get(router, {})
    for k in [k for k, e in entries.items() if now - e["at"] > PENDING_TTL]:
        del entries[k]
    return [{"change": e["summary"], "previews": e["count"], "next_call": e["next_call"]}
            for e in sorted(entries.values(), key=lambda e: -e["at"])
            if tool is None or e["next_call"].get("tool") == tool]

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------------- redaction
REDACTED = "<redacted>"
_SECRET_SEGMENTS = {"password", "passwd", "pwd", "secret", "token", "pin", "passphrase"}
# Descriptors of a secret, not the secret itself (psk_cipher, psk_version, passwd_cycle, ...).
_NOT_SECRET_SUFFIX = ("_cipher", "_version", "_type", "_mode", "_format", "_select", "_enable", "_exist",
                      "_cycle", "_timeout", "_length", "_support", "_status")
_SECRET_KEYED = re.compile(r"(wpa|wep|psk|sae|private|preshared)_?key\d*$", re.I)
_NOT_SECRET = {"key", "public_key", "server_key", "host_key", "pin_enable", "wps_pin_enable",
               "token_exist", "cert_exist"}


def is_secret_field(name: str, extra: tuple[str, ...] | set[str] = ()) -> bool:
    n = str(name).lower()
    if n in extra:
        return True
    if n in _NOT_SECRET or n.endswith(_NOT_SECRET_SUFFIX):
        return False
    if any(seg in _SECRET_SEGMENTS for seg in re.split(r"[_.\-]", n)):
        return True
    return bool(_SECRET_KEYED.search(n))


def _maybe_json(value: str) -> Any:
    if value[:1] in "[{":
        try:
            return json.loads(value)
        except ValueError:
            return None
    return None


def _collect(obj: Any, out: set[str], extra: set[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if is_secret_field(k, extra):
                for s in (v if isinstance(v, list) else [v]):
                    if isinstance(s, str) and len(s) >= 4:
                        out.add(s)
            else:
                _collect(v, out, extra)
    elif isinstance(obj, list):
        for v in obj:
            _collect(v, out, extra)
    elif isinstance(obj, str):
        parsed = _maybe_json(obj)
        if parsed is not None:
            _collect(parsed, out, extra)


def redact(obj: Any, reveal: bool = False, extra: tuple[str, ...] | set[str] = (),
           known: set[str] | None = None) -> Any:
    """Mask secret-named fields and scrub their values out of every other string."""
    if reveal:
        return obj
    extra_set = {e.lower() for e in extra}
    secrets: set[str] = set(known or ())
    _collect(obj, secrets, extra_set)
    ordered = sorted(secrets, key=len, reverse=True)

    def scrub(s: str) -> str:
        for sec in ordered:
            if sec in s:
                s = s.replace(sec, REDACTED)
        return s

    def walk(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: (REDACTED if is_secret_field(k, extra_set) and v not in ("", None, [], {}) else walk(v))
                    for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        if isinstance(o, str):
            return scrub(o)
        return o

    return walk(obj)


# ---------------------------------------------------------------------------- own MAC
def _local_ip_for(host: str) -> str | None:
    target = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target, 80))  # UDP connect sends nothing; it just picks a route
            return str(s.getsockname()[0])
    except OSError:
        return None


def _iface_mac_for_ip(ip: str) -> str | None:
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True,
                             timeout=5, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) > 3 and parts[3].split("/")[0] == ip:
            try:
                with open(f"/sys/class/net/{parts[1]}/address", encoding="ascii") as fh:
                    return fh.read().strip()
            except OSError:
                return None
    return None


def detect_own_identity(host: str) -> dict[str, Any]:
    """IP and MAC(s) of THIS machine on the router's LAN (best effort, never raises)."""
    ip = _local_ip_for(host)
    macs: list[str] = []
    if ip:
        mac = _iface_mac_for_ip(ip)
        if mac:
            try:
                macs.append(forms.normalize_mac(mac))
            except ValueError:
                pass
    return {"ip": ip, "macs": macs}


# ------------------------------------------------------------------------------- plans
@dataclass
class Plan:
    tool: str
    summary: str
    steps: list[Step] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    critical_reasons: list[str] = field(default_factory=list)
    before: dict[str, Any] = field(default_factory=dict)
    undo_of: str | None = None
    secret_fields: tuple[str, ...] = ()
    router: str = "main"
    reboots: str = ""  # non-empty: the router reboots by itself after this change (text says how long)
    # Set when the change restarts the device's Wi-Fi without a reboot (seen live: an MLO change on the
    # RE3200BE drops every network and its uplink for ~5-30 s, and the 5 GHz uplink can take minutes).
    # finalize() waits (bounded) until it answers again and reports what came back.
    settle_probe: Any = None

    @property
    def risk(self) -> str:
        r = max_risk(READ, *[s.risk for s in self.steps])
        if self.critical_reasons:
            r = max_risk(r, CRITICAL)
        return r if self.steps else READ

    def add(self, step: Step | None) -> None:
        if step is not None:
            self.steps.append(step)

    def digest(self) -> str:
        def norm(s: Step) -> dict[str, Any]:
            d = {k: v for k, v in s.to_dict().items() if k != "label"}
            if s.kind in ("insert", "remove", "update"):  # live counters must not invalidate a token
                d["fields"] = forms.stable(s.path, s.fields)
                d["old"] = forms.stable(s.path, s.old)
            return d

        payload = {"tool": self.tool, "router": self.router, "undo_of": self.undo_of,
                   "steps": [norm(s) for s in self.steps]}
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


# Forms the device accepts at once but applies only while restarting its network (verified live on a BE3600).
APPLIES_ON_RESTART = frozenset({"system?form=sysmode"})


def make_token(plan: Plan, now: float | None = None) -> str:
    exp = int((now if now is not None else time.time()) + TOKEN_TTL)
    mac = hmac.new(_TOKEN_KEY, f"{exp}:{plan.digest()}".encode(), hashlib.sha256).hexdigest()[:32]
    return f"{exp}.{mac}"


def check_token(token: str | None, plan: Plan, now: float | None = None) -> str | None:
    """None if valid, else why not."""
    if not token:
        return ("every change needs a dry run first: review the plan below, then repeat the same call with "
                "apply=true and its confirm_token")
    try:
        exp_s, mac = str(token).split(".", 1)
        exp = int(exp_s)
    except ValueError:
        return "malformed confirm_token"
    if (now if now is not None else time.time()) > exp:
        return "confirm_token expired (5 minutes): run the dry run again"
    want = hmac.new(_TOKEN_KEY, f"{exp}:{plan.digest()}".encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(want, mac):
        return ("confirm_token does not match this plan: the request or the router's current state "
                "changed since the dry run - run the dry run again and review it")
    return None


def _changes(old: dict[str, Any] | None, new: dict[str, Any]) -> dict[str, Any]:
    old = old or {}
    return {k: {"from": old.get(k), "to": v} for k, v in new.items()
            if forms.cmp_value(old.get(k)) != forms.cmp_value(v)}


def diff(plan: Plan) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for s in plan.steps:
        base: dict[str, Any] = {"path": s.path, "action": s.kind if s.kind != "custom" else s.op}
        if s.label:
            base["what"] = s.label
        if s.kind == "write":
            base["changes"] = _changes(s.old, s.fields)
        elif s.kind == "insert":
            base["add_row"] = s.fields
        elif s.kind == "remove":
            base["remove_row"] = s.old
        elif s.kind == "update":
            base["row"] = s.key_value()
            base["changes"] = _changes(s.old, s.fields)
        else:
            base["fields"] = s.fields
        base["risk"] = s.risk
        out.append(base)
    return out


def change_words(plan: Plan, limit: int = 3) -> str:
    """The change in plain words, e.g. "change 5g Wi-Fi (enable: on -> off)".

    Bench (Nemotron 4B): previewed and applied turning OFF 5 GHz when asked for 2.4 GHz, then told the user "2.4 GHz
    turned off" - the generic "DONE AND VERIFIED" never named the change.  Previews and results now say what it is,
    so the model relays the real change and a wrong one is visible before step 2.
    """
    parts: list[str] = []
    for st in plan.steps:
        if st.kind in ("write", "update"):
            for k, v in sorted((st.fields or {}).items(), key=lambda kv: kv[0] != "enable"):  # the switch first
                old = (st.old or {}).get(k)
                if forms_cmp(old) == forms_cmp(v):
                    continue
                if is_secret_field(k, plan.secret_fields):
                    parts.append(f"{k}: changed")
                elif not isinstance(v, (dict, list)):
                    parts.append(f"{k}: {old if old not in (None, '') else '(empty)'} -> {v}")
        elif st.kind == "insert":
            parts.append("add an entry")
        elif st.kind == "remove":
            parts.append("remove an entry")
    shown = parts[:limit] + ([f"+{len(parts) - limit} more"] if len(parts) > limit else [])
    return plan.summary + (f" ({'; '.join(shown)})" if shown else "")


def forms_cmp(v: Any) -> str:
    return str(v).strip().lower() if v is not None else ""


def describe(plan: Plan, reveal: bool = False) -> dict[str, Any]:
    return redact({
        "router": plan.router,
        "summary": plan.summary,
        "risk": plan.risk,
        "critical_because": plan.critical_reasons or None,
        "diff": diff(plan),
        "requests": [{"path": s.url_path, "operation": s.op, "kind": s.kind, "risk": s.risk,
                      "undoable": s.undoable} for s in plan.steps],
        "warnings": plan.warnings,
    }, reveal, plan.secret_fields)


# ---------------------------------------------------------------------------- execute
Reopen = Callable[[], AbstractContextManager[Any]]


def _affected_state(t: Any, plan: Plan) -> dict[str, Any]:
    state: dict[str, Any] = {}
    for s in plan.steps:
        if s.kind == "custom" or s.path in state:
            continue
        try:
            state[s.path] = forms.read_state(t, s.path)
        except (RouterError, ValueError) as exc:
            state[s.path] = {"error": str(exc)}
    return state


def apply_plan(t: Any, plan: Plan, journal: Journal, reopen: Reopen) -> dict[str, Any]:
    """Send every step, journaling before and after.  Never resends an ambiguous write."""
    entry = journal.begin(plan.tool, plan.summary, [s.to_dict() for s in plan.steps], plan.before,
                          risk=plan.risk, undo_of=plan.undo_of, router=plan.router)
    checks: list[dict[str, Any]] = []
    collateral_msg = ("ROWS OTHER THAN THE TARGET CHANGED: the router may have applied this to the wrong row. "
                      "Remaining steps were not sent. router_undo can re-add rows listed under 'missing'.")
    for i, step in enumerate(plan.steps):
        prep: forms.Prepared | None = None
        try:
            prep = forms.prepare(t, step)
            journal.wire(entry, i, step.url_path, step.op, prep.fields)  # exactly what goes on the wire
            reply = forms.send(t, prep)
        except Conflict as exc:
            status = "failed" if i == 0 else "partial"
            journal.finish(entry, status, after=_affected_state(t, plan), detail=str(exc), steps_applied=i)
            return {"status": status, "journal_id": entry, "steps_applied": i, "error": str(exc),
                    "note": "nothing was sent for the conflicting step"}
        except RouterError as exc:
            if not exc.ambiguous:
                status = "failed" if i == 0 else "partial"
                journal.finish(entry, status, after=_affected_state(t, plan),
                               detail=f"router refused step {i + 1}: {exc.code}", steps_applied=i)
                return {"status": status, "journal_id": entry, "steps_applied": i,
                        "error": f"router refused: {exc.code}", "router_message": exc.message}
            # Ambiguous: the router may or may not have acted.  Re-login, re-read, report.
            verdict: dict[str, Any] = {"applied": None}
            after: dict[str, Any] | None = None
            coll = None
            try:
                with reopen() as t2:
                    verdict = forms.verify(t2, step)
                    coll = forms.collateral(t2, prep) if prep is not None else None
                    after = _affected_state(t2, plan)
            except RouterError as exc2:
                verdict = {"applied": None, "error": f"re-check failed: {exc2.code}"}
            if coll:
                journal.finish(entry, "collateral", after=after, steps_applied=i + 1,
                               detail={"ambiguous_error": exc.code, "collateral": coll, **verdict})
                return {"status": "collateral", "journal_id": entry, "steps_applied": i + 1,
                        "collateral": coll, "error": collateral_msg}
            applied = verdict.get("applied")
            if applied is True:
                status = "applied" if i == len(plan.steps) - 1 else "partial"
                done = i + 1
            elif applied is False:
                status, done = ("failed" if i == 0 else "partial"), i
            else:
                status, done = "unknown", i
            journal.finish(entry, status, after=after, detail={"ambiguous_error": exc.code, **verdict},
                           steps_applied=done)
            return {"status": status, "journal_id": entry, "steps_applied": done,
                    "error": f"{exc.code} while sending step {i + 1}; re-read says applied={applied}",
                    "note": "the write was NOT resent; remaining steps were not sent"}
        checks.append({"step": i + 1, **forms.verify(t, step, reply)})
        if checks[-1].get("no_effect") and step.path in APPLIES_ON_RESTART:
            # The device applies this while restarting (operation mode): an immediate re-read still shows
            # the old value.  That is not "ignored"; the check has to wait until it is back.  Keyed on the
            # form, not on plan.reboots: a rebooting model must still report an ignored MLO write.
            checks[-1] = {"step": i + 1, "applied": None,
                          "deferred": "takes effect as the device restarts; re-read once it is back"}
        if checks[-1].get("no_effect"):
            after = _affected_state(t, plan)
            msg = (f"NO EFFECT: the router accepted step {i + 1} ({step.kind} {step.path}) but nothing changed - "
                   "it ignored the request (wrong field set/format for this firmware?). "
                   + ("Remaining steps were not sent." if i < len(plan.steps) - 1 else ""))
            journal.finish(entry, "no_effect", after=after, steps_applied=i, detail={"verify": checks})
            return {"status": "no_effect", "journal_id": entry, "steps_applied": i, "verify": checks,
                    "warning": msg.strip()}
        try:
            coll = forms.collateral(t, prep)
        except RouterError as exc:
            coll = None
            checks[-1]["collateral_check"] = f"could not re-read: {exc.code}"
        if coll:
            after = _affected_state(t, plan)
            journal.finish(entry, "collateral", after=after, steps_applied=i + 1,
                           detail={"verify": checks, "collateral": coll})
            return {"status": "collateral", "journal_id": entry, "steps_applied": i + 1, "verify": checks,
                    "collateral": coll, "error": collateral_msg}
    after = _affected_state(t, plan)
    unverified = [c for c in checks if c.get("applied") is False]
    status = "mismatch" if unverified else "applied"
    journal.finish(entry, status, after=after, detail={"verify": checks}, steps_applied=len(plan.steps))
    out: dict[str, Any] = {"status": status, "journal_id": entry, "steps_applied": len(plan.steps),
                           "verify": checks}
    if unverified:
        out["warning"] = "the router accepted every request but a re-read does not show all changes"
    if any(c.get("deferred") for c in checks):
        out["verify_deferred"] = True
    return out


def gate(plan: Plan, args: dict[str, Any], *, allow_forbidden: bool | None = None) -> str | None:
    """Why this plan may not be applied now (None = OK)."""
    if plan.errors:
        return "validation failed"
    risk = plan.risk
    if risk == FORBIDDEN:
        allowed = os.environ.get("TPLINK_ALLOW_FORBIDDEN") == "1" if allow_forbidden is None else allow_forbidden
        if not allowed:
            return ("FORBIDDEN operation (factory reset / config restore / firmware upload / quick setup / "
                    "cloud bind). Only router_raw_write may send it, and only with TPLINK_ALLOW_FORBIDDEN=1 "
                    "in the server environment.")
        return check_token(args.get("confirm_token"), plan)
    # Every change, not only critical ones, needs the confirm_token of a dry run: nothing is ever sent unseen.
    return check_token(args.get("confirm_token"), plan)


def finalize(t: Any, plan: Plan, args: dict[str, Any], journal: Journal, reopen: Reopen,
             *, allow_forbidden: bool | None = None) -> dict[str, Any]:
    """Dry run or apply a plan according to ``args`` (apply, confirm_token, reveal)."""
    reveal = bool(args.get("reveal"))
    desc = describe(plan, reveal)
    if plan.errors:
        return {"applied": False, "errors": plan.errors, **desc}
    if not plan.steps:
        return {"applied": False, "no_change": True, "verified": "no",
                "tell_user": "NOTHING WAS CHANGED: the device already has these values.",
                "summary": plan.summary, "warnings": plan.warnings}
    direct = preview_mode() == "critical" and plan.risk == NORMAL
    # small tier: an identical repeat of a request previewed in the last 5 minutes confirms it.  Seen on the
    # bench: a model reasoned only on its first turn, then re-sent its own last call unchanged - never the
    # next_call.  The change was still previewed first; asking for exactly the same thing again is insisting.
    prev = PENDING.get(plan.router, {}).get(_pending_key(plan))
    # Only as the VERY NEXT call after its preview, within a minute: that is a model insisting (seen: it
    # re-sends at once), not a request revived after the user declined it (that gets a fresh preview).
    repeat_ok = (model_tier() == "small" and plan.risk != FORBIDDEN and prev is not None
                 and time.time() - prev["at"] <= REPEAT_WINDOW
                 and prev.get("seq") == CALL_SEQ.get(plan.router, 0) - 1)
    if not args.get("apply") and not direct and not repeat_ok:
        return _preview(plan, args, desc)
    refusal = None if (direct or repeat_ok) else gate(plan, args, allow_forbidden=allow_forbidden)
    if refusal:
        if plan.risk != FORBIDDEN or allow_forbidden or os.environ.get("TPLINK_ALLOW_FORBIDDEN") == "1":
            # The refusal doubles as the dry run: the full plan plus a fresh token, so the next call can apply
            # exactly what was shown (one round trip for small models, and nothing is ever sent unseen).
            return _preview(plan, args, desc, refused=refusal)
        return {"applied": False, "refused": refusal, **desc}
    pre_backup = _auto_backup(t, plan)
    result = apply_plan(t, plan, journal, reopen)
    if pre_backup:
        result["pre_change_backup"] = pre_backup
    if plan.reboots and result.get("status") != "failed":
        result["router_rebooting"] = plan.reboots
        result["wifi_health"] = {"ok": None, "note": "not checked: the router is rebooting; re-check when it is back"}
    elif any(s.url_path.startswith("wireless?") for s in plan.steps) and result.get("status") != "failed":
        health = wifi_health(t)
        result["wifi_health"] = health
        if health.get("ok") is False:
            result.setdefault("warnings_after", []).append(
                "WI-FI CONFIG LOOKS DAMAGED after this change: " + str(health.get("problem")) + ". WPS and "
                "pairing will fail. Restore the pre-change backup (maintenance action=restore file=...) "
                + (f"({pre_backup.get('saved')})" if isinstance(pre_backup, dict) and pre_backup.get('saved') else
                   "or a recent backup") + ", or re-save the setting from the router's web page.")
    result.update(verdict(result, plan))
    attach_settle(plan)
    if plan.settle_probe and result.get("status") == "applied":
        _settle(result, plan, reopen)
    if result.get("status") in ("applied", "partial", "mismatch", "collateral", "no_effect", "failed"):
        PENDING.get(plan.router, {}).pop(_pending_key(plan), None)  # this change is no longer pending
    jid = result.get("journal_id")
    if jid and result.get("status") in ("applied", "partial", "mismatch", "collateral") and plan.tool != "router_undo":
        result["undo_call"] = {"tool": "router_undo", "arguments": {"id": jid}}
        result["tell_user"] = result["tell_user"] + f" To reverse it: router_undo id={jid}."
    if direct:
        result["mode"] = "applied directly (TPLINK_PREVIEW=critical: normal changes skip the preview)"
    elif repeat_ok and not args.get("confirm_token"):
        result["mode"] = "confirmed by repeating the previewed request (TPLINK_MODEL_TIER=small)"
    return redact({"applied": result["status"] in ("applied", "partial", "collateral"), **result, **desc},
                  reveal, plan.secret_fields)


def model_tier() -> str:
    """TPLINK_MODEL_TIER, chosen by the user for the model that drives this server.

    large (default): full tool set, preview then next_call with the confirm token, full replies.
    small: compact tool set, the same preview flow PLUS "an identical repeat of a just-previewed request
    confirms it", and short replies (status / tell_user / next_call first, details nested).
    Safety is the same in every tier: every change is previewed first, verified, journaled and undoable.
    """
    tier = os.environ.get("TPLINK_MODEL_TIER", "large").lower()
    return tier if tier in ("large", "small") else "large"


def preview_mode() -> str:
    """always (default): every change is previewed first.  critical: normal changes apply on the first call
    (each result carries its undo_call); critical and forbidden changes are still previewed."""
    mode = os.environ.get("TPLINK_PREVIEW", "always").lower()
    return mode if mode in ("always", "critical") else "always"


def _preview(plan: Plan, args: dict[str, Any], desc: dict[str, Any], refused: str | None = None) -> dict[str, Any]:
    out = _preview_body(plan, args, desc, refused)
    key = _pending_key(plan)
    entries = PENDING.setdefault(plan.router, {})
    prev = entries.get(key)
    count = (prev["count"] + 1) if prev and time.time() - prev["at"] <= PENDING_TTL else 1
    entries[key] = {"summary": plan.summary, "count": count, "at": time.time(), "next_call": out["next_call"],
                    "seq": CALL_SEQ.get(plan.router, 0)}
    if count > 1 and not refused:
        out["status"] = "ALREADY_PREVIEWED"
        out["tell_user"] = (f"YOU ALREADY PREVIEWED THIS EXACT CHANGE ({count} times) - nothing more to check and nothing "
                            f"has changed yet. Send next_call now to apply it (it has apply=true and a fresh "
                            f"confirm_token). Do not preview it again.")
        out = {"status": out["status"], "tell_user": out["tell_user"],
               **{k: v for k, v in out.items() if k not in ("status", "tell_user")}}
    return out


def _preview_body(plan: Plan, args: dict[str, Any], desc: dict[str, Any], refused: str | None = None) -> dict[str, Any]:
    """A dry run, spelled out as step 1 of 2 with the exact step-2 call.

    Local-model bench: models took a preview for the finished change (one ran four previews and said
    "LEDs turned off").  The status comes first, and step 2 is handed over ready to send.
    """
    token = make_token(plan)
    step2 = {k: v for k, v in args.items() if k not in ("reveal", "confirm_token", "apply")}
    if plan.router and plan.router != "main":  # run_tool consumed "router"; next_call must target the same device
        step2["router"] = plan.router
    step2.update({"apply": True, "confirm_token": token})
    out: dict[str, Any] = {
        "status": "PREVIEW_ONLY",
        "tell_user": f"THIS IS A PREVIEW of: {change_words(plan)} - NOTHING HAS CHANGED YET. Step 1 of 2 is done. "
                     f"Check this is what the user asked for. To make the change you "
                     f"MUST do step 2: call {plan.tool} again with exactly the arguments in next_call (they include "
                     f"apply=true and the confirm_token)"
                     + (" - or send the same request again as your very next call" if model_tier() == "small" else "")
                     + ". Do not tell the user it is done before step 2 succeeds.",
        "next_call": {"tool": plan.tool, "arguments": step2},
        "applied": False, "dry_run": True, "verified": "not_done_yet",
    }
    if refused:
        # An apply that was refused must never look like step 1 of a normal preview.  Local-model bench:
        # Gemma 4 12B sent a fake confirm_token, got status PREVIEW_ONLY back and told the user "turned off".
        out["status"] = "REFUSED_NOTHING_CHANGED"
        out["tell_user"] = (f"NOT DONE - NOTHING CHANGED: the device refused this request ({refused}). If the user "
                            f"still wants it, the plan is below: send next_call (it has a valid confirm_token).")
        out["refused"] = refused
    out.update(desc)
    out["confirm_token"] = token
    out["next"] = "review the plan, then send next_call (valid 5 min)"
    return out


def verdict(result: dict[str, Any], plan: Plan) -> dict[str, Any]:
    """The truth about a change, in one field a small model can pass on as-is.

    ``verified``: yes (re-read confirms) | no (it did not take effect) | unknown (sent, cannot be confirmed)
    | after_restart (applies as the device restarts; check again later).
    """
    st = result.get("status")
    checks = result.get("verify") or []
    done, total = result.get("steps_applied"), len(plan.steps)
    if st in ("failed", "no_effect"):
        why = result.get("error") or result.get("warning") or "the device did not apply it"
        return {"verified": "no", "tell_user": f"NOT DONE: {why}. Nothing changed."}
    if st == "mismatch":
        bad = {k: v for c in checks for k, v in (c.get("mismatch") or {}).items()}
        return {"verified": "no", "tell_user": "NOT DONE: the device accepted the request, but reading it back "
                f"shows different values: {json.dumps(bad, default=str)[:300]}. Tell the user it did not take effect."}
    if st == "collateral":
        return {"verified": "no", "tell_user": "PROBLEM: the change affected other entries too (see collateral); "
                "remaining steps were not sent. Use router_undo to restore them."}
    if st == "unknown":
        return {"verified": "unknown", "tell_user": "UNKNOWN: the connection dropped while sending; a re-read could "
                "not confirm it either way. Check the current values before telling the user anything."}
    if st == "partial" or (isinstance(done, int) and done < total):
        return {"verified": "no", "tell_user": f"PARTLY DONE: {done} of {total} steps took effect (see verify)."}
    if any(c.get("deferred") for c in checks) or plan.reboots:
        return {"verified": "after_restart", "tell_user": "SENT: it takes effect as the device restarts (a few "
                "minutes). Check again afterwards before telling the user it is done."}
    if checks and all(c.get("applied") is True for c in checks):
        return {"verified": "yes", "tell_user": f"DONE AND VERIFIED: {change_words(plan)}. Reading the device back "
                                                f"confirms it. Tell the user exactly this change."}
    return {"verified": "unknown", "tell_user": "SENT BUT NOT CONFIRMED: the device accepted it, but this change "
            "cannot be read back. Tell the user it was sent, not that it is confirmed."}


# form path -> builds a settle probe from the fields a step writes (None: this write does not restart the Wi-Fi).
# Registered by the feature that knows the device (features/extender.py for the RE3200BE MLO form), so plans
# built elsewhere - router_undo, router_raw_write - wait for the restart too.
SETTLE_PROBES: dict[str, Callable[[dict[str, Any]], Any]] = {}


def attach_settle(plan: Plan) -> None:
    if plan.settle_probe:
        return
    for step in plan.steps:
        make = SETTLE_PROBES.get(step.path)
        probe = make(dict(step.fields or {})) if make else None
        if probe:
            plan.settle_probe = probe
            return


def _settle(result: dict[str, Any], plan: Plan, reopen: Reopen) -> None:
    """Wait (bounded) for a device whose Wi-Fi restarts after this change, then report what came back."""
    limit = float(os.environ.get("TPLINK_SETTLE_SECONDS", "90"))
    first = min(8.0, limit)
    deadline = time.time() + limit
    time.sleep(first)
    last: dict[str, Any] | None = None
    while True:
        try:
            with reopen() as t2:
                last = plan.settle_probe(t2)
            if not last.get("waiting"):
                break
        except Exception:  # noqa: BLE001 - still restarting, or a probe bug: never changes an applied result
            logger.debug("settle probe failed", exc_info=True)
        if time.time() >= deadline:
            break
        time.sleep(min(10.0, max(0.0, deadline - time.time())))
    if last is None:
        result["after_restart"] = {"back": False}
        result.update({"verified": "after_restart",
                       "tell_user": "SENT: the device is restarting its Wi-Fi and has not answered again yet (this "
                                    "can take a minute, and without a reserved address it may come back at a new "
                                    "one). Check again before telling the user it is done."})
        return
    result["after_restart"] = {"back": True, **{k: v for k, v in last.items() if k != "waiting"}}
    if last.get("mismatch"):
        result.update({"verified": "no", "tell_user": f"NOT AS REQUESTED after the restart: {last['mismatch']}"})
    elif last.get("waiting"):
        result["tell_user"] = (str(result.get("tell_user", "")) + " The device restarted its Wi-Fi and is back, but "
                               + str(last["waiting"]) + " - this can take a few minutes.").strip()
    else:
        result["tell_user"] = (str(result.get("tell_user", "")) + " The device restarted its Wi-Fi and is back with "
                               "its links connected.").strip()


def wifi_health(t: Any, *, tries: int = 4, wait: float = 10.0) -> dict[str, Any]:
    """Cheap integrity probe after a Wi-Fi change.

    Live lesson (BE9300 fw 1.2.4): a malformed MLO write made the firmware drop an internal per-band
    field; Wi-Fi kept working but every WPS start failed and reading wireless?form=wps_pin crashed with
    an HTTP 500 ("bad argument to 'lower'").  That read is the canary.  Timeouts right after a Wi-Fi
    change are normal (the radios restart), so they are retried and never reported as damage.
    """
    last = ""
    for attempt in range(tries):
        try:
            t.call("wireless?form=wps_pin", "read")
            return {"ok": True} if attempt == 0 else {"ok": True, "note": f"answered after {attempt} retries"}
        except RouterError as exc:
            if exc.code == "no such callback":
                return {"ok": True, "note": "this firmware has no wps_pin form; not checked"}
            if exc.code == "server_error":
                return {"ok": False, "problem": f"wireless?form=wps_pin crashes ({exc.message[:120]})"}
            last = exc.code
        if attempt + 1 < tries:
            time.sleep(wait)
    return {"ok": None, "note": f"could not check: wps_pin read kept failing ({last}); re-check in a minute"}


def _auto_backup(t: Any, plan: Plan) -> dict[str, Any] | None:
    """Save a config backup before a CRITICAL change (TPLINK_AUTO_BACKUP=0 turns it off)."""
    import os

    if plan.risk not in (CRITICAL, FORBIDDEN) or os.environ.get("TPLINK_AUTO_BACKUP", "1") == "0":
        return None
    if not hasattr(t, "download"):
        return None
    try:
        from datetime import datetime
        from pathlib import Path

        data, _ = t.download("firmware?form=config_multipart", {"operation": "backup"})
        if not data:
            return {"error": "empty backup"}
        base = os.environ.get("TPLINK_BACKUP_DIR") or os.path.join(
            os.environ.get("TPLINK_JOURNAL_DIR") or os.path.expanduser("~/.local/state/mcp-tplink-router"),
            "backups")
        Path(base).mkdir(parents=True, exist_ok=True)
        out = Path(base) / f"{plan.router}-auto-{datetime.now().strftime('%Y%m%d-%H%M%S')}.bin"
        out.write_bytes(data)
        os.chmod(out, 0o600)
        return {"saved": str(out), "bytes": len(data)}
    except Exception as exc:  # noqa: BLE001 - a backup failure must never block or break the change
        return {"error": f"{type(exc).__name__}: {str(exc)[:120]}"}




__all__ = [
    "Plan", "make_token", "check_token", "diff", "describe", "apply_plan", "finalize", "gate",
    "redact", "is_secret_field", "detect_own_identity", "NORMAL", "CRITICAL", "FORBIDDEN", "READ",
]


# -------------------------------------------------------------------------------- undo
def plan_undo(entry: dict[str, Any], t: Any, *, force: bool = False) -> Plan:
    """Inverse of a journal entry, built against the router's CURRENT state."""
    from .catalog import risk_of

    plan = Plan(tool="router_undo", summary=f"undo {entry.get('id')}: {entry.get('summary', '')}",
                undo_of=entry.get("id"), router=entry.get("router") or "main")
    if entry.get("unreadable"):
        plan.errors.append(f"cannot undo automatically: {entry['unreadable']} (journal key, encrypted at rest), so "
                           "the old settings cannot be read; nothing was sent. Restore the old setting by hand, or put "
                           "the original journal.key back")
        return plan
    status = entry.get("status")
    if status not in ("applied", "partial", "unknown", "collateral", "mismatch"):
        plan.errors.append(f"entry status is {status!r}; nothing was applied to undo")
        return plan
    done = entry.get("steps_applied")
    steps = [Step.from_dict(d) for d in entry.get("requests") or []]
    if isinstance(done, int):
        steps = steps[:done]
    drift_msg = "the router no longer matches what that change left behind ({}); pass force=true to undo anyway"
    coll = (entry.get("detail") or {}).get("collateral") if isinstance(entry.get("detail"), dict) else None
    if coll:
        rows_now = forms.load_table(t, coll["path"])
        for row in coll.get("missing", []):
            if forms.find_matching(rows_now, row, coll["path"]):
                continue
            clean = {k: v for k, v in forms.stable(coll["path"], row).items() if not k.startswith(".")}
            plan.add(Step("insert", coll["path"], "insert", fields=clean, risk=risk_of(coll["path"], "insert"),
                          label="re-add a row lost as collateral"))
        if coll.get("unexpected"):
            plan.warnings.append(f"{len(coll['unexpected'])} row(s) were CHANGED as collateral and cannot be "
                                 "restored automatically: " + json.dumps(coll["unexpected"])[:500])
    for s in reversed(steps):
        what = f"step {s.kind} {s.op} on {s.path}"
        if not s.undoable:
            plan.errors.append(f"{what} cannot be undone (reboot/firmware/action-type requests are one-way)")
            continue
        try:
            if s.kind == "write":
                cur = forms.read_form(t, s.path)
                from .features import boolish

                # boolish: journals written before f02c1e4 hold "False"/"True" for on/off fields (the router stored
                # "off"/"on"), which read as drift and refused the undo (LM Studio, Bonsai 27B).
                drift = [k for k, v in s.fields.items()
                         if k in cur and forms.cmp_value(cur[k]) != forms.cmp_value(boolish(cur[k], v))]
                if drift and not force:
                    plan.errors.append(drift_msg.format(f"{s.path}: {', '.join(drift)} changed since"))
                    continue
                old = s.old or {}
                restore = {k: old.get(k) for k in s.fields}
                plan.add(Step("write", s.path, s.op, fields=restore, old={k: cur.get(k) for k in s.fields},
                              send_path=s.send_path, risk=s.risk, label=f"restore {s.path}"))
            elif s.kind == "insert":
                rows = forms.load_table(t, s.path)
                hits = forms.find_matching(rows, s.fields, s.path)
                ep = catalog.get(s.path)
                kf = ep.key_field if ep else None
                if not hits and kf and kf != "key" and s.fields.get(kf):
                    # The router may normalise fields it stores (seen live: BE4800 white_list rewrote
                    # deviceType), so fall back to the row's logical identity (e.g. its MAC).
                    hits = forms.find_rows(rows, kf, s.fields[kf])
                if len(hits) != 1:
                    plan.errors.append(f"{what}: expected exactly one matching row to remove, found {len(hits)}")
                    continue
                plan.add(Step("remove", s.path, "remove", old=rows[hits[0]], risk=risk_of(s.path, "remove"),
                              label="remove the row that change added"))
            elif s.kind == "remove":
                assert s.old is not None
                rows = forms.load_table(t, s.path)
                if forms.find_matching(rows, s.old, s.path):
                    plan.warnings.append(f"the removed row is present in {s.path} already; nothing to re-add")
                    continue
                row = {k: v for k, v in forms.stable(s.path, s.old).items() if not k.startswith(".")}
                plan.add(Step("insert", s.path, "insert", fields=row, extra=dict(s.extra),
                              risk=risk_of(s.path, "insert"), label="re-add the removed row"))
            elif s.kind == "update":
                assert s.old is not None
                ep = forms.endpoint(s.path)
                rows = forms.load_table(t, s.path)
                hits = forms.find_rows(rows, ep.key_field or "", s.fields.get(ep.key_field or ""))
                if len(hits) != 1:
                    plan.errors.append(f"{what}: row not found (or not unique) any more")
                    continue
                cur_row = rows[hits[0]]
                if not forms.find_matching([cur_row], s.fields, s.path) and not force:
                    plan.errors.append(drift_msg.format(f"row {s.key_value()!r} changed since"))
                    continue
                plan.add(Step("update", s.path, "update", fields=dict(s.old), old=cur_row, risk=s.risk,
                              label="put the row back"))
            elif s.kind == "custom" and s.inverse:
                plan.add(forms.plan_custom(s.path, s.inverse["op"], s.inverse.get("fields"),
                                           send_path=s.send_path, label="inverse request", risk=s.risk))
        except (RouterError, ValueError) as exc:
            plan.errors.append(f"{what}: {exc}")
    plan.before = _affected_state(t, plan)
    attach_settle(plan)  # undoing a change that restarts the Wi-Fi restarts it again: wait for it the same way
    return plan
