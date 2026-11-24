"""MCP tool definitions and dispatch (login per call, retry rules, dry-run/apply)."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from typing import Any

from . import catalog
from .features import Ctx, UsageError
from .forms import Conflict
from .journal import Journal
from .safety import Plan, finalize, redact
from .transport import E_LOGIN, RouterError, session

logger = logging.getLogger(__name__)

ONE_SESSION_HINT = ("The router allows ONE admin login at a time: if its web page or the Tether app is "
                    "logged in, log that out and try again.")

WRITE_PROPS: dict[str, Any] = {
    "apply": {"type": "boolean", "default": False,
              "description": "false (default) = dry run: show the plan, diff, warnings and risk, send nothing. "
                             "true = send it."},
    "confirm_token": {"type": "string",
                      "description": "Required with apply=true for CRITICAL changes: the token from the dry run "
                                     "(valid 5 minutes, bound to the exact plan and current router state)."},
    "reveal": {"type": "boolean", "default": False, "description": "Show secrets (passwords/keys) unmasked."},
    "intent": {"type": "string", "description": "Optional: the user's request in your own words. The server "
                                               "remembers it and reminds you of it, with what actually happened."},
}
REVEAL_PROP = {"reveal": WRITE_PROPS["reveal"]}
ROUTER_PROP = {"router": {"type": "string", "default": "main",
                          "description": "Which device - router OR extender - by its name; default main. If the user "
                                         "gives a device a NAME (\"the extender called X\", \"the upstairs router\"), "
                                         "pass that name here, even if you are not sure it exists: the tool will say so. "
                                         "Plain \"the extender\" / \"the router\" is not a name: leave router out. "
                                         "'device' is accepted as the same argument."},
              "device": {"type": "string", "description": "Same as router."}}


@dataclass
class ToolDef:
    name: str
    description: str
    handler: Callable[[Ctx], Any]
    properties: dict[str, Any] = field(default_factory=dict)
    required: list[str] = field(default_factory=list)
    read_only: bool = False
    kinds: tuple[str, ...] = ("router",)  # device kinds this tool supports

    def schema(self) -> dict[str, Any]:
        props = dict(self.properties)
        props.update(REVEAL_PROP if self.read_only else WRITE_PROPS)
        props.update(ROUTER_PROP)
        return {"type": "object", "properties": props, "required": self.required, "additionalProperties": False}


TOOLS: dict[str, ToolDef] = {}


def register(tool: ToolDef) -> None:
    TOOLS[tool.name] = tool


# Ready-to-copy calls appended to each everyday tool's description.  Local-model bench: models failed on the
# exact SHAPE of a call (missing action=set, enable at the wrong level, a preview taken for the change), and
# their reasoning showed they needed a correct command to copy.  Rules: only the change itself (on/off, ids
# from another call) - never a sample name or password a model could copy as a placeholder.  Every literal
# example is executed against the fake router by tests/test_core.py.
EXAMPLES: dict[str, list[str]] = {
    "router_status": ['{}'],
    "system": ['{"action": "led"}  (read the LEDs)', '{"action": "led", "enable": false}  (LEDs off)',
               '{"action": "firewall"}  (read)'],
    "wifi_set": ['{"action": "get", "band": "all"}', '{"action": "set", "band": "5g", "enable": false}  (5 GHz off)',
                 '{"action": "set", "band": "2g", "enable": true}  (2.4 GHz on)'],
    "clients": ['{"action": "list"}', '{"action": "rename", "mac": "<MAC from action=list>", "name": "<name the user gave>"}'],
    "dhcp_reservation": ['{"action": "list"}',
                         '{"action": "add", "mac": "<MAC from clients action=list>", "ip": "<address the user asked for>"}'],
    "access_control": ['{"action": "status"}', '{"action": "block", "mac": "<MAC from clients action=list>"}'],
    "parental_control": ['{"action": "owners"}',
                         '{"action": "internet_block", "owner_id": "<id from action=owners>", "blocked": true}'],
    "port_forwarding": ['{"action": "list"}'],
    "router_logs": ['{"level": "WARNING", "limit": 20}'],
    "router_journal": ['{"action": "list"}  (recent changes with their ids)'],
    "router_undo": ['{"id": "<id from router_journal action=list>"}',
                    '{}  (small tier only: undo the most recent change)'],
    "extender": ['{"action": "status"}'],
    "extender_set": ['{"action": "led", "enable": false}',
                     '{"action": "led_night", "enable": true}  (night mode on, with the times already saved)',
                     '{"action": "mlo", "enable": false}  (Wi-Fi 7 extenders: MLO network off)'],
}
TWO_CALLS = (" CHANGES TAKE TWO CALLS: (1) call without apply -> a preview (status PREVIEW_ONLY, nothing changed yet) "
             "that includes next_call; (2) send next_call exactly as given - it has apply=true and the confirm_token. "
             "Only after step 2 reports verified=yes is it done.")


ONE_CALL = (" NORMAL CHANGES APPLY IN ONE CALL: the result says verified=yes/no and includes undo_call to reverse it. "
            "CRITICAL changes still take two calls: (1) a preview (status PREVIEW_ONLY) with next_call; (2) send "
            "next_call exactly as given.")


def described(tool: ToolDef) -> str:
    from .safety import model_tier, preview_mode

    d = tool.description
    if not tool.read_only:
        d += ONE_CALL if preview_mode() == "critical" else TWO_CALLS
        if model_tier() == "small" and preview_mode() != "critical":
            d += " (Sending the same request again as your very next call also confirms a preview.)"
    ex = EXAMPLES.get(tool.name)
    if ex:
        d += " Examples: " + " | ".join(ex)
    return d


# TPLINK_TOOLSET=core: the everyday tools only, for small local models (a shorter tool list in a small
# context window, and no raw escape hatch).  Default: every tool.
CORE_TOOLS = frozenset({"router_status", "wifi_set", "system", "clients", "dhcp_reservation", "access_control",
                        "parental_control", "port_forwarding", "router_logs", "router_journal", "router_undo",
                        "extender", "extender_set"})


def offered(name: str) -> bool:
    import os

    from .safety import model_tier

    toolset = os.environ.get("TPLINK_TOOLSET") or ("core" if model_tier() == "small" else "full")
    return toolset.lower() != "core" or name in CORE_TOOLS


SHORT_KEYS = ("memory", "about_device", "status", "tell_user", "next_call", "error", "hint", "verified", "applied", "journal_id", "undo_call",
              "pending", "recent_changes", "router", "changed", "assumed", "refused")


def shorten(out: dict[str, Any]) -> dict[str, Any]:
    """small tier: what the model needs first; everything else nested under details."""
    if not isinstance(out, dict) or "details" in out:
        return out
    head = {k: out[k] for k in SHORT_KEYS if k in out}
    rest = {k: v for k, v in out.items() if k not in head}
    return {**head, "details": rest} if rest and head.get("status") else out


@dataclass
class Runtime:
    """Everything a tool call needs from the outside world for ONE router (injected in tests)."""

    factory: Callable[[], Any]
    journal: Journal
    host: str = ""
    identity: Callable[[], dict[str, Any]] = field(default=lambda: {"ip": None, "macs": []})
    retry_delay: float = 2.0
    name: str = "main"
    protocol: str = "plain"
    kind: str = "router"

    @property
    def profile(self) -> str:
        return "main" if self.name == "main" else "secondary"

    def reopen(self) -> AbstractContextManager[Any]:
        return session(self.factory)


@dataclass
class Registry:
    """All configured routers by name (``main`` is the household router)."""

    routers: dict[str, Runtime]

    def get(self, name: str) -> Runtime:
        name = self._generic(name)
        if name not in self.routers:
            raise UsageError(f"there is NO router named {name!r}. Tell the user it does not exist (configured: "
                             f"{sorted(self.routers)}); do not answer with another router's data")
        return self.routers[name]

    def describe(self) -> list[dict[str, str]]:
        return [{"name": n, "host": r.host, "protocol": r.protocol, "kind": r.kind} for n, r in self.routers.items()]

    # "the extender" / "my router" describe a KIND of device, not a name.  Bench: after the router argument began
    # asking for any name the user gives, Gemma 12B sent router="the extender" for "turn on night mode on the
    # extender".  When exactly one configured device is of that kind, the phrase means that device.
    _KIND_WORDS = {"router": "router", "wifi router": "router", "main router": "router", "extender": "extender",
                   "range extender": "extender", "repeater": "extender", "wifi extender": "extender"}

    def _generic(self, name: str) -> str:
        if name in self.routers:
            return name
        words = str(name).strip().lower().split()
        while words and words[0] in ("the", "my", "our", "this"):
            words = words[1:]
        phrase = " ".join(words)
        if phrase in ("device", "name", "default") and len(self.routers) == 1:
            # Bench (Nemotron 4B): filled device="device" as a placeholder; with one device it can only mean that one
            return next(iter(self.routers))
        kind = self._KIND_WORDS.get(phrase)
        if not kind:
            return name
        matches = [n for n, r in self.routers.items() if r.kind == kind]
        return matches[0] if len(matches) == 1 else name


NO_CALLBACK_HINT = ("router {r!r} does not have this form/operation - its firmware differs from the BE9300 "
                    "this server was built against. Try router_raw_read, or router_catalog for what to look for.")


def _actions(tool: ToolDef) -> list[str]:
    return list((tool.properties.get("action") or {}).get("enum") or [])


def _infer_action(tool: ToolDef, args: dict[str, Any]) -> str | None:
    """settings given but no action, on a tool whose default action only reads: the intent is "set".

    Seen in the local-model bench: a 1-bit model left out action=set on every call and looped on reads.
    """
    if "action" in args or "settings" not in args or "set" not in _actions(tool):
        return None
    args["action"] = "set"
    return "action=set (settings were given without an action)"


_CALL_KEYS = ("apply", "confirm_token", "router", "reveal", "intent")
READ_ACTIONS = frozenset({"get", "status", "list", "read", "show", "protocols", "leases", "owners", "candidates",
                          "speed", "iot_status", "dns_privacy_servers", "traffic", "game_accelerator", "devices",
                          "clients", "topology", "search_status", "uplink", "network", "wifi", "guest", "system",
                          "report", "history", "partitions", "scan", "check", "info", "connection_status",
                          "firmware_status", "firmware_check", "wps_status", "block_history", "today_sites",
                          "connected", "backups", "browse", "allowed_sites_get", "filter_get", "device_detail",
                          "modem_isps", "accounts", "profiles", "identify"})
_CHANGE_MARKS = ("status", "applied", "refused", "no_change", "dry_run", "confirm_token", "journal_id", "error")


def _wants_change(args: dict[str, Any]) -> bool:
    return bool(args.get("apply") or args.get("confirm_token") or args.get("settings")
                or args.get("enable") is not None or args.get("bands") is not None
                or str(args.get("action", "")) not in READ_ACTIONS)


def _error_status(name: str, args: dict[str, Any], out: Any) -> Any:
    """A write tool's error must read as NOT DONE (or NOT CONFIRMED), never as a bare message.

    Bench: Gemma 12B put the confirm_token inside settings, got a bare error back and told the user "the LEDs
    have been turned off".  Errors raised before applying mean nothing was sent; an error while applying
    means the device state is unknown.
    """
    tool = TOOLS.get(name)
    if not (tool and not tool.read_only and isinstance(out, dict) and out.get("error") and "status" not in out):
        return out
    # A failed READ through a write-capable tool (internet action=status, wifi_set action=get, ...) changed
    # nothing either, but "NOT DONE" would wrongly suggest a change was attempted.
    if not _wants_change(args):
        return out
    err = str(out["error"])
    if str(out.get("note", "")).startswith("not retried"):
        return {"status": "UNKNOWN", "applied": None, "verified": "unknown",
                "tell_user": "NOT CONFIRMED: something failed while applying, so the change may or may not have "
                             "reached the device. Re-read the current values before telling the user anything.",
                **out}
    res: dict[str, Any] = {"status": "NOT_DONE", "applied": False, "verified": "no",
                           "tell_user": f"NOT DONE - NOTHING CHANGED: {err}", **out}
    nested = {k: v for k, v in (args.get("settings") or {}).items() if k in _CALL_KEYS} \
        if isinstance(args.get("settings"), dict) else {}
    if nested:
        fixed = {k: v for k, v in args.items() if k != "settings"}
        rest = {k: v for k, v in args["settings"].items() if k not in _CALL_KEYS}
        if rest:
            fixed["settings"] = rest
        fixed.update(nested)
        res["hint"] = (f"{', '.join(sorted(nested))} must be top-level arguments, not inside settings. "
                       "Send next_call exactly.")
        res["next_call"] = {"tool": name, "arguments": fixed}
    return res


def _next_call(tool: ToolDef, args: dict[str, Any]) -> dict[str, Any] | None:
    """The exact call to make next, after a change request that only read."""
    if "set" in _actions(tool) and args.get("action") in (None, "get") and "settings" in args:
        nxt = {k: v for k, v in args.items() if k not in ("apply", "confirm_token")}
        nxt["action"] = "set"
        return {"tool": tool.name, "arguments": nxt, "then": "repeat with apply=true and the confirm_token it returns"}
    return None


# The tool's artificial memory, per router: the last change request and what ACTUALLY happened.  Local-model
# bench: a model reasoned only on its first turn, then wrote its answer from its own plan without reading the
# reply ("5 GHz turned off" after a refusal).  Small-tier replies START with this memory, in the model's voice.
TASK_MEMORY: dict[str, dict[str, Any]] = {}


def _outcome(out: dict[str, Any]) -> tuple[str, bool]:
    st = out.get("status")
    if st == "applied" and out.get("verified") == "yes":
        return "DONE and verified on the device", True
    if st == "applied":
        return "sent, but not confirmed by reading the device back", False
    if st in ("PREVIEW_ONLY", "ALREADY_PREVIEWED"):
        return "NOT DONE YET - only previewed, nothing changed", False
    if st == "REFUSED_NOTHING_CHANGED" or out.get("refused"):
        return f"NOT DONE - refused ({out.get('refused')}), nothing changed", False
    if st == "no_change" or out.get("no_change"):
        return "nothing needed changing - it already had those values", True
    if out.get("error"):
        return f"NOT DONE - error: {str(out['error'])[:120]}", False
    if out.get("errors") and not out.get("applied"):  # a plan refused before sending (e.g. router_undo drift)
        return f"NOT DONE - refused, nothing changed: {str(out['errors'][0])[:120]}", False
    return f"NOT DONE - {st or 'unknown result'}", False


def remember_task(router: str, tool: str, intent: Any, out: dict[str, Any]) -> None:
    prev = TASK_MEMORY.get(router) or {}
    task = str(intent) if intent else (out.get("summary") or prev.get("task") or tool)
    if not intent and prev.get("intent") and time.time() - prev.get("at", 0) < RECENT_WINDOW and prev.get("tool") == tool:
        task, intent = prev["task"], prev["intent"]  # same task continuing: keep the user's words
    what, done = _outcome(out)
    TASK_MEMORY[router] = {"task": task, "intent": intent, "tool": tool, "what": what, "done": done, "at": time.time()}


def task_memory(router: str) -> dict[str, Any] | None:
    m = TASK_MEMORY.get(router)
    if not m or time.time() - m["at"] > RECENT_WINDOW:
        return None
    return {"you_were_asked_to": m["task"], "what_actually_happened": m["what"],
            "is_it_done": "YES" if m["done"] else "NO",
            "rule": "Tell the user exactly what_actually_happened. Never say it is done unless is_it_done is YES."}


def run_tool(name: str, args: dict[str, Any] | None, reg: Registry | Runtime) -> dict[str, Any]:
    """Run a tool call and record anything worth a look in the local event log (``events.py``)."""
    out = _run_tool_with_memory(name, args, reg)
    try:
        from . import events

        a = dict(args or {})
        router = a.get("router") or a.get("device") or (reg.name if isinstance(reg, Runtime) else "main")
        tool = TOOLS.get(name)
        events.from_reply(name, a, out, str(router), bool(tool and tool.read_only))
        from . import reporting

        if reporting.is_enabled():
            rt = reg.get(str(router)) if isinstance(reg, Registry) else reg
            reporting.from_reply(name, out, events.device_info(rt.name, rt.host), rt.protocol, rt.kind)
    except Exception:  # noqa: BLE001 - logging / reporting never breaks a tool call
        pass
    return out


def _run_tool_with_memory(name: str, args: dict[str, Any] | None, reg: Registry | Runtime) -> dict[str, Any]:
    """Run a tool call; every reply also carries the server's memory of previewed-but-unapplied changes."""
    from .safety import model_tier, note_call

    if args and "device" in args:  # 'device' is an alias of 'router' (models say "the extender called X")
        args = dict(args)
        dev = args.pop("device")
        same = str(args.get("router")) == str(dev)
        if not same:
            regobj = reg if isinstance(reg, Registry) else Registry({reg.name: reg})
            same = regobj._generic(str(args.get("router"))) == regobj._generic(str(dev))
        if args.get("router") and dev and not same:
            return {"error": f"router={args['router']!r} and device={dev!r} name different devices; pass one name"}
        if dev and not args.get("router"):
            args["router"] = dev
    try:
        note_call(reg.get((args or {}).get("router") or "main").name if isinstance(reg, Registry) else reg.name)
    except Exception:  # noqa: BLE001 - unknown router: the tool reports it
        pass
    intent = (args or {}).get("intent")
    out = _run_tool(name, args, reg)
    small = model_tier() == "small"
    out = _error_status(name, args or {}, out)
    if isinstance(out, dict) and str(out.get("error", "")).startswith("there is NO router named"):
        # Bench: told 'garage'/'attic' does not exist, 12B and Bonsai then read the main device and answered for it.
        asked = (args or {}).get("router")
        known = list(reg.routers) if isinstance(reg, Registry) else [reg.name]
        out = {"status": "NO_SUCH_DEVICE",
               "tell_user": f"There is no device named {asked!r} - the configured devices are: {', '.join(known)}. "
                            "Tell the user exactly this; do not answer with another device's data.", **out}
    try:
        _router = reg.get((args or {}).get("router") or "main").name if isinstance(reg, Registry) else reg.name
    except Exception:  # noqa: BLE001
        _router = None
    tool = TOOLS.get(name)
    if _router and tool and not tool.read_only and isinstance(out, dict) and _wants_change(args or {}) \
            and any(k in out for k in _CHANGE_MARKS):
        # LM Studio (Bonsai 27B): 'wifi_set action=get' was remembered as "you were asked to wifi_set - NOT DONE -
        # unknown result", and every later reply carried that false NOT DONE.  Only change requests are tasks.
        remember_task(_router, name, intent, out)
    if (small and _router and tool and tool.read_only and isinstance(out, dict) and "error" not in out
            and not (args or {}).get("router") and name not in ("router_journal", "router_undo")):
        # Bench: asked about "the extender called attic", every model read the default device and reported its
        # values as attic's.  Say plainly which device this answer is about.
        out = {"about_device": f"{_router} (the default). If the user asked about a device by another name, this "
                               f"answer is NOT about it: call again with router=\"<that name>\".", **out}
    if small and _router and isinstance(out, dict):
        mem = task_memory(_router)
        if mem:
            out = {"memory": mem, **out}
    if not isinstance(out, dict) or out.get("status") in ("PREVIEW_ONLY", "ALREADY_PREVIEWED"):
        return shorten(out) if small else out
    try:
        router = (reg.get((args or {}).get("router") or "main").name if isinstance(reg, Registry) else reg.name)
    except Exception:  # noqa: BLE001 - unknown router: nothing to remind about
        return out
    from .safety import pending_for

    if small:
        rt_ = reg.get(router) if isinstance(reg, Registry) else reg
        out["recent_changes"] = recent_changes(rt_.journal, router)
    pend = pending_for(router, name)
    if pend:
        out["pending"] = {"note": "UNFINISHED with this tool: previewed but NOT applied. Apply it ONLY if the user's "
                                  "current request asked for exactly this change (send its next_call); otherwise "
                                  "ignore it - it expires in 5 minutes.", "changes": pend}
    return shorten(out) if small else out


RECENT_WINDOW = 600.0
APPLIED = ("applied", "partial", "mismatch", "collateral")


def recent_changes(journal: Journal, router: str) -> Any:
    """small tier: what this server actually changed on ``router`` in the last 10 minutes - a fact on every
    reply.  Local-model bench: models claimed changes they never made ("2.4 GHz turned back on") after
    only reading; now the truth sits in front of them."""
    now = time.time()
    out = [{"change": e.get("summary"), "status": e.get("status"), "id": e.get("id"),
            **({"undid": e["undo_of"]} if e.get("undo_of") else {})}
           for e in journal.entries()
           if e.get("router", "main") == router and now - float(e.get("ts") or 0) <= RECENT_WINDOW
           and e.get("status") in APPLIED]
    return out[-5:] if out else "none: this server made no changes on this router in the last 10 minutes"


def _run_tool(name: str, args: dict[str, Any] | None, reg: Registry | Runtime) -> dict[str, Any]:
    """Run one tool call inside its own login/logout on the selected router.

    Retries once only for login failures and for ambiguous errors while PLANNING/READING
    (nothing has been written yet).  Applying never retries: an ambiguous write is
    re-read and reported by :func:`safety.apply_plan` instead of being resent.
    """
    if isinstance(reg, Runtime):
        reg = Registry({reg.name: reg})
    tool = TOOLS.get(name)
    if tool is None:
        return {"error": f"unknown tool {name!r}"}
    if not offered(name):
        return {"error": f"{name} is not offered in this server's compact tool set (TPLINK_TOOLSET=core)",
                "tools": sorted(n for n in TOOLS if offered(n))}
    args = dict(args or {})
    unknown = set(args) - set(tool.schema()["properties"])
    if unknown:
        return {"error": f"unknown argument(s) {sorted(unknown)} for {name}"}
    assumed = _infer_action(tool, args)
    router = str(args.pop("router", "") or "")
    try:
        if name == "router_undo" and args.get("id"):
            # undo always targets the router the change was made on
            any_rt = next(iter(reg.routers.values()))
            entry = any_rt.journal.get(str(args["id"]))
            entry_router = (entry or {}).get("router") or "main"
            if router and router != entry_router:
                return {"error": f"journal entry {args['id']} was made on router {entry_router!r}, not {router!r}"}
            router = entry_router
        rt = reg.get(router or "main")
    except UsageError as exc:
        return {"error": str(exc)}
    if rt.kind not in tool.kinds:
        usable = sorted(n for n, t in TOOLS.items() if rt.kind in t.kinds)
        return {"error": f"{name} is not supported on {rt.name!r} ({rt.kind})", "tools_for_this_device": usable}
    from . import capabilities  # unconditional: also used by the error path below

    if (not tool.read_only or args.get("action")) and capabilities.known_absent(rt.name, rt.host, name, args):
        return capabilities.not_supported(rt.name, rt.host, name, args, cached=True)
    last: RouterError | None = None
    for attempt in (1, 2):
        try:
            with session(rt.factory) as t:
                _watch_firmware(t, rt)
                ctx = Ctx(t, args, rt.journal, rt.host, rt.identity, router=rt.name, routers=reg.describe(),
                          kind=rt.kind)
                result = tool.handler(ctx)
                if isinstance(result, Plan):
                    if tool.read_only:  # pragma: no cover - programming error
                        raise RuntimeError(f"{name} is read-only but produced a plan")
                    result.router = rt.name
                    for step in result.steps:  # risk tiers are per router
                        step.risk = catalog.risk_of(step.url_path, step.op, rt.profile)
                    try:
                        done = finalize(t, result, args, rt.journal, rt.reopen)
                        if assumed:
                            done["assumed"] = assumed
                        if (done.get("applied") or done.get("status") in ("applied", "unknown", "partial")) and any(
                                st.path == "system?form=sysmode" for st in result.steps):
                            # an operation-mode switch changes which features exist: forget what was learned
                            capabilities.forget_router(rt.name, rt.host)
                            from . import events

                            events._SEEN.pop(rt.name, None)  # re-read firmware + mode on the next call
                        return done
                    except Exception as exc:  # noqa: BLE001 - never retry once applying started
                        logger.exception("apply failed")
                        return {"error": f"apply failed: {type(exc).__name__}: {redact(str(exc))}",
                                "note": "not retried; check router_journal and re-read before trying again"}
                if args.get("apply") and not tool.read_only:
                    # Asked to change something but the call only read (missing action=set, no settings, no
                    # enable...).  Never let that look like success: a small model then reports "done".
                    if isinstance(result, dict) and result.get("status") == "no_change":
                        return redact({**result, "applied": False,
                                       "note": "nothing to change: the device already has these values"},
                                      bool(args.get("reveal")))
                    out = {"applied": False, "changed": False,
                           "error": "NOTHING WAS CHANGED: this call only read the current values.",
                           "hint": f"to change something, call {name} with the change itself "
                                   "(e.g. action=set plus settings={...}, or enable=true/false), first without "
                                   "apply to see the plan, then with apply=true and its confirm_token",
                           "current_values": redact(result, bool(args.get("reveal")))}
                    nxt = _next_call(tool, args)
                    if nxt and rt.name != "main":
                        nxt["arguments"]["router"] = rt.name
                    if nxt:
                        out["next_call"] = nxt
                    # Bench (Bonsai): previewed correctly, then sent apply + the token but dropped action=set.  The
                    # token names exactly one previewed change: hand back its next_call instead of a guess.
                    from .safety import pending_for
                    # Match on the signature after the dot: models garble the timestamp digits (Gemma 12B sent
                    # 1795350214.e8be... for 1795350220.e8be...).  This only hands back the right call; the token
                    # check that guards applying is unchanged, so a garbled token still cannot apply anything.
                    tok = str(args.get("confirm_token") or "")
                    sig = tok.rsplit(".", 1)[-1] if "." in tok else tok
                    prev = [pc for pc in pending_for(rt.name, name)
                            if len(sig) >= 16 and str(pc["next_call"].get("arguments", {}).get("confirm_token", "")
                                                      ).rsplit(".", 1)[-1] == sig]
                    if len(prev) == 1:
                        out["next_call"] = prev[0]["next_call"]
                        out["hint"] = ("this call left out arguments of the change you previewed "
                                       f"({prev[0]['change']}); send next_call exactly as given")
                    return out
                out = redact(result, bool(args.get("reveal")))
                if assumed and isinstance(out, dict):
                    out["assumed"] = assumed
                return out
        except (UsageError, ValueError, TypeError) as exc:
            return {"error": str(exc)}
        except Conflict as exc:
            return {"error": f"conflict: {exc}"}
        except RouterError as exc:
            last = exc
            if attempt == 1 and (exc.code == E_LOGIN or exc.ambiguous) and not getattr(exc, "no_retry", False):
                logger.warning("%s attempt 1 failed (%s); retrying with a fresh login", name, exc.code)
                time.sleep(rt.retry_delay)
                continue
            break
    assert last is not None
    out: dict[str, Any] = {"error": last.code, "message": redact(last.message), "router": rt.name}
    unreachable = any(s in last.message for s in ("timed out", "ConnectTimeout", "Max retries exceeded",
                                                   "Connection refused", "No route to host", "ConnectionError",
                                                   "Connection aborted", "RemoteDisconnected"))
    if unreachable:
        out["hint"] = (f"{rt.name} did not answer at its configured address: it may be restarting, or its address "
                       "changed (e.g. after an operation mode switch); check the host setting for this device.")
    elif last.code == E_LOGIN or last.ambiguous:
        out["hint"] = ONE_SESSION_HINT
    elif last.code == "no such callback" or "HTTP 404" in last.message:
        capabilities.mark_absent(rt.name, rt.host, name, args, last.code)
        return {**capabilities.not_supported(rt.name, rt.host, name, args), "router": rt.name,
                "hint": NO_CALLBACK_HINT.format(r=rt.name)}
    return out


def _watch_firmware(t: Any, rt: Runtime) -> None:
    """First use of a device in this process, then every few hours: record its model / hardware / firmware.
    A change is logged as firmware_changed (a cloud update changed a BE4800's login overnight)."""
    from . import events

    if not events.firmware_due(rt.name):
        return
    try:
        fw = t.call("firmware?form=upgrade", "read")
    except Exception:  # noqa: BLE001 - never let the watcher break the call it rides on
        events._SEEN[rt.name] = time.time()
        return
    if isinstance(fw, dict):
        try:  # operation mode keys the capability memory (router-only features vanish in AP mode)
            sm = t.call("system?form=sysmode", "read")
            if isinstance(sm, dict) and sm.get("mode"):
                fw = {**fw, "mode": str(sm["mode"])}
        except Exception:  # noqa: BLE001 - older firmware without the form: firmware alone
            pass
    change = events.note_firmware(rt.name, rt.host, fw if isinstance(fw, dict) else None)
    if change:
        from . import capabilities

        capabilities.forget_router(rt.name, rt.host)
    from . import reporting

    if reporting.is_enabled() and isinstance(fw, dict):
        reporting.submit(reporting.build("device_seen", device=fw, protocol=rt.protocol, kind=rt.kind))
        if change:
            reporting.submit(reporting.build("firmware_changed", device=fw, protocol=rt.protocol, kind=rt.kind))


def _action(values: list[str], default: str | None = None, desc: str = "") -> dict[str, Any]:
    d: dict[str, Any] = {"type": "string", "enum": values}
    if default:
        d["default"] = default
    if desc:
        d["description"] = desc
    return d


# =============================================================================== tools
def _register_all() -> None:
    from .features import core, dhcp

    register(ToolDef(
        "router_status",
        "Router overview: WAN/LAN addresses, internet state, Wi-Fi bands, client counts, CPU/memory, "
        "firmware, VPN-client switch. On an extender: model, mode, uplink, mesh role. Read-only. "
        "capabilities=true: which features this tool has found NOT supported on this router's firmware.",
        core.router_status, {"capabilities": {"type": "boolean"}}, read_only=True, kinds=("router", "extender")))
    register(ToolDef(
        "router_get",
        "Read one section of the router config by friendly name (e.g. dhcp, dhcp_reservations, dhcp_leases, "
        "clients, wifi, vpn_client_profiles, static_routes, access_control, upnp_mappings, firewall, time) or "
        "any form path from router_catalog. Call with no section to list sections. Secrets masked unless reveal.",
        core.router_get, {"section": {"type": "string"}}, read_only=True))
    register(ToolDef(
        "router_catalog",
        "List every router form (219+), what each operation does to risk (read/normal/critical/forbidden) and "
        "whether its format is verified live or only copied from the web UI. filter narrows by text; path "
        "describes one form (fields, key, secrets).",
        core.router_catalog, {"filter": {"type": "string"}, "path": {"type": "string"}}, read_only=True))
    register(ToolDef(
        "router_raw_read",
        "Send a read-only operation to any catalogued form, e.g. path='iptv?form=setting', operation='read', "
        "or custom read ops like operation='getBlockHistory' with fields. Refuses write-type operations.",
        core.router_raw_read,
        {"path": {"type": "string"}, "operation": {"type": "string", "default": "read"},
         "fields": {"type": "object", "description": "extra request fields (strings; objects are JSON-encoded)"}},
        required=["path"], read_only=True, kinds=("router", "extender")))
    register(ToolDef(
        "router_logs",
        "Read the router's system log (newest first when timestamps parse). Filters: level (minimum severity, "
        "e.g. WARNING), type (e.g. DHCPD, WAN), contains (text), since ('2026-11-17 08:00:00'), limit. "
        "Never changes the router's own log filter.",
        core.router_logs,
        {"level": {"type": "string"}, "type": {"type": "string"}, "contains": {"type": "string"},
         "since": {"type": "string"}, "limit": {"type": "integer", "default": 100}}, read_only=True))
    register(ToolDef(
        "router_journal",
        "This server's change journal: action=list (recent changes, with ids) or action=show id=... (full "
        "before/after and requests). Use the id with router_undo.",
        core.router_journal,
        {"action": _action(["list", "show"], "list"), "id": {"type": "string"},
         "limit": {"type": "integer", "default": 20}}, read_only=True, kinds=("router", "extender")))
    register(ToolDef(
        "router_undo",
        "Reverse a journaled change (writes restore old values, inserts are removed, removes re-added, updates "
        "swapped back). Refuses if the router changed since, unless force=true. Reboots/firmware/actions are "
        "not undoable. Dry run first like every write.",
        core.router_undo, {"id": {"type": "string"}, "force": {"type": "boolean", "default": False}},
        required=[], kinds=("router", "extender")))
    register(ToolDef(
        "router_raw_write",
        "EXPERTS ONLY - last resort. Do NOT use this because another tool refused or asked for a dry run: "
        "do that dry run and pass its confirm_token instead. Sends ANY operation + fields to a catalogued form "
        "with no field checks. Risk comes from the catalog (unknown ops are CRITICAL). FORBIDDEN ops (factory "
        "reset, config restore, firmware upload, quick setup, cloud bind) also need TPLINK_ALLOW_FORBIDDEN=1.",
        core.router_raw_write,
        {"path": {"type": "string"}, "operation": {"type": "string"},
         "fields": {"type": "object", "description": "request fields (strings; objects are JSON-encoded)"}},
        required=["path", "operation"]))
    register(ToolDef(
        "dhcp_server_set",
        "DHCP server: action=get shows settings; otherwise change enable / start / end (pool) / lease_minutes "
        "(1-2880) / gateway / dns1 / dns2. Validated against the LAN subnet, the router's own IP, active leases "
        "and reservations. Disabling DHCP or a gateway other than the router is CRITICAL.",
        dhcp.dhcp_server_set,
        {"action": _action(["get", "set"], "set"), "enable": {"type": "boolean"}, "start": {"type": "string"},
         "end": {"type": "string"}, "lease_minutes": {"type": "integer"}, "gateway": {"type": "string"},
         "dns1": {"type": "string"}, "dns2": {"type": "string"}}))
    register(ToolDef(
        "dhcp_reservation",
        "DHCP address reservations (stable IPs, e.g. for kiosk tablets). action=list (with lease status and "
        "random-MAC warnings) | leases | add (mac, ip, name) | update (mac + ip/name/enable) | remove (mac) | "
        "reserve_current (pin a client's CURRENT address; identify it by mac, current_ip or client hostname). "
        "MACs in any format. Warns when a MAC is randomised/private - that device must use its real MAC.",
        dhcp.dhcp_reservation,
        {"action": _action(["list", "leases", "add", "update", "remove", "reserve_current"], "list"),
         "mac": {"type": "string"}, "ip": {"type": "string"}, "name": {"type": "string"},
         "enable": {"type": "boolean"}, "current_ip": {"type": "string"}, "client": {"type": "string"}}))

    _register_priority()


def _register_priority() -> None:
    from .features import network, vpn

    register(ToolDef(
        "ip_mac_binding",
        "IP-MAC binding (ARP binding): action=status|list (setting, bindings, live ARP table) | enable | disable | "
        "add (mac, ip, name, description) | update (mac + ip/name/description/enable; done as remove+re-add) | "
        "remove (mac) | bind_current (bind an ARP entry as-is, by mac or ip). Binding THIS machine to a "
        "different IP is CRITICAL.",
        network.ip_mac_binding,
        {"action": _action(["status", "list", "enable", "disable", "add", "update", "remove", "bind_current"],
                           "status"),
         "mac": {"type": "string"}, "ip": {"type": "string"}, "name": {"type": "string"},
         "description": {"type": "string"}, "enable": {"type": "boolean"}}))
    register(ToolDef(
        "upnp",
        "UPnP: action=status|list (switch + current port mappings devices opened) | enable | disable. "
        "The router offers no per-mapping delete.",
        network.upnp, {"action": _action(["status", "list", "enable", "disable"], "status")}))
    register(ToolDef(
        "mesh",
        "EasyMesh: action=status|devices|clients|topology|search_status|ap_avoidance|device_detail (mac) (read) | "
        "pair (DISABLED: locked up a BE9300 in testing; use the web UI / Tether / WPS button) | enable | disable (CRITICAL if satellites are attached) | "
        "search_start | search_stop | link | unlink (CRITICAL) | reboot_satellite (CRITICAL) | add_onboarding "
        "(mac) | set_device (mac, settings={name, location, led, preferred_wifi_uplink_ap, traffic_separation, "
        "backhaul_steering}) | rebalance (clients re-pick the best unit) | bind_client (mac=unit, client_mac, "
        "bind=true|false: pin a client to a unit). Satellite firmware: maintenance action=firmware_check / "
        "satellite_firmware_update.",
        network.mesh,
        {"action": _action(["status", "devices", "clients", "topology", "search_status", "ap_avoidance",
                            "device_detail", "pair", "enable", "disable", "search_start", "search_stop", "link",
                            "unlink", "reboot_satellite", "add_onboarding", "set_device", "rebalance",
                            "bind_client"], "status"),
         "mac": {"type": "string"}, "client_mac": {"type": "string"}, "bind": {"type": "boolean"},
         "wait": {"type": "integer", "description": "pair: seconds to keep WPS open (default 125)"},
         "i_understand_this_locked_up_a_router": {"type": "boolean",
                                                  "description": "pair is disabled unless this is true"},
         "settings": {"type": "object"}}))
    register(ToolDef(
        "vpn_server",
        "The router's VPN SERVERS (people dialling in). kind=openvpn|pptp|l2tp|wireguard; action=get | set "
        "(settings={...}) | enable | disable (CRITICAL) | accounts | accounts_add (account={...}) | "
        "accounts_update (key, account={...}) | accounts_remove (key) | connected | disconnect (key). "
        "Secrets masked unless reveal.",
        vpn.vpn_server,
        {"kind": _action(list(vpn.SERVER_CONFIG)),
         "action": _action(["get", "set", "enable", "disable", "accounts", "accounts_add", "accounts_update",
                            "accounts_remove", "connected", "disconnect"], "get"),
         "settings": {"type": "object"}, "account": {"type": "object"}, "key": {"type": "string"}},
        required=["kind"]))
    register(ToolDef(
        "vpn_client",
        "The router's VPN CLIENT (router dials out). Configure a VPN, then choose which devices use it - this is "
        "how e.g. a child's device can be sent through a filtering VPN. Profiles: action=profiles | add_profile "
        "(profile={key,...}; added disabled) | set_active_profile (key; the ENABLED profile is the one in use) | "
        "update_profile / remove_profile (key). Devices (they use WHICHEVER profile is active; there is no "
        "per-device profile): devices | candidates | add_device (mac, name?, client_type?) | set_device (mac, "
        "use_vpn=true|false) | remove_device (mac). Also status | connection_status (key) | enable | disable. "
        "Everything that changes profiles or devices is CRITICAL.",
        vpn.vpn_client,
        {"action": _action(["status", "profiles", "devices", "candidates", "connection_status", "enable",
                            "disable", "add_profile", "set_active_profile", "update_profile", "remove_profile",
                            "add_device", "set_device", "remove_device"], "status"),
         "profile": {"type": "object"}, "key": {"type": "string"}, "mac": {"type": "string"},
         "name": {"type": "string"}, "client_type": {"type": "string"}, "use_vpn": {"type": "boolean"}}))
    register(ToolDef(
        "routing",
        "Static routes: action=list | system (the live routing table) | add (route={name, target, netmask, "
        "gateway, interface LAN|WAN, enable}) | update (name, route={...}) | remove (name).",
        network.routing,
        {"action": _action(["list", "system", "add", "update", "remove"], "list"),
         "name": {"type": "string"}, "route": {"type": "object"}}))

    _register_phase6()


def _register_phase6() -> None:
    from .features import access, nat, wifi

    register(ToolDef(
        "access_control",
        "Access control (who may use the network). action=status | candidates | enable | disable | "
        "set_mode (mode=black|white) | block / unblock (mac[, name]) | allow / disallow (mac). Black mode "
        "blocks listed devices; white mode blocks everything NOT listed. Switching to white mode, enabling it, "
        "or blocking THIS machine is CRITICAL.",
        access.access_control,
        {"action": _action(["status", "candidates", "enable", "disable", "set_mode", "block", "unblock", "allow",
                            "disallow"], "status"),
         "mode": _action(["black", "white"]), "mac": {"type": "string"}, "name": {"type": "string"}}))
    register(ToolDef(
        "parental_control",
        "HomeShield parental controls (local, per profile/'owner', e.g. a child). action=owners | devices | "
        "block_history (owner_id) | today_sites (owner_id) | filter_get / allowed_sites_get (owner_id) | "
        "internet_block (owner_id, blocked=true pauses the internet, false resumes) | filter_set / "
        "allowed_sites_set (owner_id, sites=[domains]) | add_owner (owner={...}) | remove_owner (owner_id).",
        access.parental_control,
        {"action": _action(["owners", "devices", "block_history", "today_sites", "filter_get", "allowed_sites_get",
                            "internet_block", "filter_set", "allowed_sites_set", "add_owner", "remove_owner"],
                           "owners"),
         "owner_id": {"type": "string"}, "blocked": {"type": "boolean"},
         "sites": {"type": "array", "items": {"type": "string"}}, "owner": {"type": "object"}}))
    register(ToolDef(
        "wifi_set",
        "Wi-Fi: action=get (band=2g|5g|6g|guest|guest_access|all) | set (band, settings={ssid|name, "
        "password, hidden, enable, channel, txpower, htmode, encryption, ...}; guest also takes guest_band="
        "2g|5g|2g5g|6g|all; guest_access takes {access, isolate}) | smart_connect (enable). Turning a radio "
        "off is CRITICAL. This server's machine is wired, so it is not cut off.",
        wifi.wifi_set,
        {"action": _action(["get", "set", "smart_connect"], "get"),
         "band": _action(["2g", "5g", "6g", "guest", "guest_access", "all"]),
         "guest_band": {"type": "string"}, "settings": {"type": "object"}, "enable": {"type": "boolean"}}))
    register(ToolDef(
        "wifi_schedule",
        "Wi-Fi off-schedule (e.g. no Wi-Fi 23:00-07:00 on school nights). action=get | enable | disable | "
        "add (rule={start 'HH:MM', end, days [sun..sat], bands [2g,5g,6g], enable}) | update (key, rule) | "
        "remove (key).",
        wifi.wifi_schedule,
        {"action": _action(["get", "enable", "disable", "add", "update", "remove"], "get"),
         "key": {"type": "string"}, "rule": {"type": "object"}}))
    register(ToolDef(
        "port_forwarding",
        "Port forwarding. kind=vs (virtual servers, default) | pt (port triggering) | dmz. action=list | add "
        "(rule={name, external_port, internal_port, ip, protocol ALL|TCP|UDP, enable}) | update (name, rule) | "
        "remove (name); for dmz: list | enable (ip) | disable. Overlapping external ports are refused.",
        nat.port_forwarding,
        {"kind": _action(["vs", "pt", "dmz"], "vs"),
         "action": _action(["list", "add", "update", "remove", "enable", "disable"], "list"),
         "name": {"type": "string"}, "rule": {"type": "object"}, "ip": {"type": "string"}}))

    _register_phase7()


def _register_phase7() -> None:
    from .features import system

    register(ToolDef(
        "system",
        "System settings. action=info (all of the below) | firmware_check (ask TP-Link for updates; changes "
        "nothing) | ddns (read) | device_priority (list) | set_device_priority (mac, enable, time_period) | "
        "led / led_night / eco / time / dst / hour24 / auto_upgrade / qos / firewall (no settings = read; settings={...} or "
        "enable=bool = change) | time_sync | reboot (CRITICAL, not undoable).",
        system.system,
        {"action": _action(["info", "firmware_check", "ddns", "device_priority", "set_device_priority", "led",
                            "led_night", "eco", "time", "dst", "hour24", "auto_upgrade", "qos", "firewall",
                            "time_sync", "reboot"], "info"),
         "settings": {"type": "object"}, "enable": {"type": "boolean"}, "mac": {"type": "string"},
         "time_period": {"type": "string"}}))


def _register_phase8() -> None:
    from .features import (
        admin,
        clients,
        ddns,
        device_log,
        internet,
        lan,
        maintenance,
        usb,
        wifi_extra,
    )

    settings = {"type": "object", "description": "fields to change (see the matching router_catalog form)"}
    enable = {"type": "boolean"}
    register(ToolDef(
        "internet",
        "Internet (WAN). action=status (connection, IPv4/IPv6, WAN port, dual-NAT, speed, DNS privacy) | protocols "
        "| get (family=4|6, proto?) | set (family, proto=dynamic|staticip|pppoe|l2tp|pptp|dslite|v6plus|ocn for "
        "IPv4; dynamic|static|pppoe|pass|tunnel for IPv6, settings={...}) CRITICAL | renew | release (family) | "
        "ipv6_enable | ipv6_disable | autodetect | dns_privacy (settings={dns_privacy: none|doh|dot, dns_mode: "
        "default|strict, server_list: [...]}) | dns_privacy_servers (kind=doh|dot) | dns_privacy_test (settings) | "
        "mac_clone (settings={mac_clone_type, mac_custom}) | flow_control (settings={rx_enable, tx_enable}).",
        internet.internet,
        {"action": _action(["status", "protocols", "get", "set", "renew", "release", "ipv6_enable", "ipv6_disable",
                            "autodetect", "dns_privacy", "dns_privacy_servers", "dns_privacy_test", "mac_clone",
                            "flow_control"], "status"),
         "family": _action(["4", "6"]), "proto": {"type": "string"}, "kind": _action(["doh", "dot"]),
         "settings": settings}))
    register(ToolDef(
        "lan",
        "LAN side. action=status (all below + port status) | lan_ipv4 (router LAN IP/mask: CRITICAL) | lan_ipv6 | "
        "port_speed (settings={speed}) | link_aggregation (LACP: enable_agg, hashmode, lacpmode, port_settings) | "
        "flow_control (rx_enable, tx_enable) | iptv (IPTV/VLAN: enable, mode, internet/iptv/ipphone VLAN ids, "
        "IGMP, port_settings) | udp_proxy | nat (NAT and hardware NAT boost) | alg (settings={ftp, tftp, h323, rtsp, "
        "sip, pptp, l2tp, ipsec: true/false}). Firewall / ping replies: system action=firewall. No settings = read.",
        lan.lan,
        {"action": _action(["status", *lan.GROUPS], "status"), "settings": settings, "enable": enable}))
    register(ToolDef(
        "maintenance",
        "Maintenance. action=info | backup (download the config to the backup folder) | backups (list) | restore "
        "(file = a backup name or path; CRITICAL, reboots) | firmware_check (router + mesh satellites, online) | "
        "firmware_update_online (CRITICAL, reboots) | firmware_status | firmware_upload (file = image path; "
        "CRITICAL) | satellite_firmware_update (mac) | ping / traceroute (target, count, size, max_hops, timeout) | "
        "operation_mode (mode=router|ap|repeater|client|multissid; none = read; CRITICAL; keep_access) | reboot_schedule "
        "(settings). Factory reset is deliberately only reachable via router_raw_write (forbidden tier).",
        maintenance.maintenance,
        {"action": _action(["info", "backup", "backups", "restore", "firmware_check", "firmware_update_online",
                            "firmware_status", "firmware_upload", "satellite_firmware_update", "ping", "traceroute",
                            "operation_mode", "reboot_schedule"], "info"),
         "file": {"type": "string"}, "mac": {"type": "string"}, "target": {"type": "string"},
         "count": {"type": "integer"}, "size": {"type": "integer"}, "max_hops": {"type": "integer"},
         "timeout": {"type": "integer"}, "mode": _action(list(maintenance.MODES)), "settings": settings,
         "keep_access": {"type": "boolean", "default": False, "description": "operation_mode to router: turn remote "
                         "management on first so this server can reach the device on its WAN side (exposes the "
                         "admin page there - the internet if the WAN is your ISP)"}}))
    register(ToolDef(
        "admin",
        "Router administration. action=status | change_password (old_password_file, new_password_file; "
        "CRITICAL) | remote (remote management: enable, http_port, https_port, managers) | https | local_mode "
        "(everyone vs listed devices) | local_add / local_remove (mac, name) | recovery (password-recovery "
        "e-mail) | superadmin | permissions (what the local user may see/edit). No settings = read.",
        admin.admin,
        {"action": _action(["status", "change_password", "local_add", "local_remove", *admin.GROUPS], "status"),
         "old_password_file": {"type": "string"}, "new_password_file": {"type": "string"},
         "mac": {"type": "string"}, "name": {"type": "string"}, "settings": settings, "enable": enable}))
    register(ToolDef(
        "wifi_extra",
        "Wi-Fi extras. WPS pairing: action=wps_push (press the router's WPS button; the call stays connected and "
        "returns the outcome: success + the device's MAC, or timeout) | wps_client_pin (pin = the device's PIN) "
        "| wait (seconds, default 125) | wps_cancel | wps_status (a session the web page/button started) | "
        "wps_settings (enable) | "
        "wps_pin_enable / wps_pin_disable / wps_pin_generate / wps_pin_default. Also mlo (Wi-Fi 7 multi-link "
        "network) | ofdma | ofdma_mimo | twt | fast_roaming | advanced (beacon, DTIM, RTS, airtime fairness, "
        "zero-wait DFS...) | guest_bandwidth | guest_time | afc | afc_refresh | status. To add a mesh satellite "
        "use mesh action=pair. Main SSIDs/passwords/channels: wifi_set.",
        wifi_extra.wifi_extra,
        {"action": _action(["status", "wps_push", "wps_client_pin", "wps_cancel", "wps_status",
                            "wps_pin_generate", "wps_pin_default", "wps_pin_enable", "wps_pin_disable",
                            "afc_refresh", *wifi_extra.GROUPS], "status"),
         "pin": {"type": "string"}, "pin_mode": {"type": "boolean"},
         "wait": {"type": "integer", "description": "seconds to keep WPS open (10-300, default 125)"},
         "settings": settings, "enable": enable}))
    register(ToolDef(
        "clients",
        "Connected devices. action=list (each device's maker and type; optional client=name, IP or MAC: only that device) | identify (also asks the devices themselves over mDNS who they are: hostname, services, model; takes ~3 s; optional client=) | label (mac or client=, name / owner / note: your own label, saved ONLY on this computer, encrypted; the router is not changed) | forget (mac or client=: delete that saved label) | rename (mac, name: the name shown everywhere) | speed (limits/speeds) | "
        "speed_limit (mac, download_kbps, upload_kbps, enable) | game_accelerator | iot_status | iot_enable | "
        "iot_disable | iot_add / iot_remove (mac or macs: move smart-home devices to the isolated IoT network) | "
        "traffic (no client: which devices are using the most bandwidth RIGHT NOW, ranked, in one call - use this "
        "for 'the network is slow'; client=name, IP or MAC: one device, optional history=minute|hour|day for how much "
        "it used; from the router's own traffic statistics; routers with a traffic monitor only).",
        clients.clients,
        {"action": _action(["list", "identify", "label", "forget", "rename", "speed", "speed_limit", "game_accelerator", "iot_status",
                            "iot_enable", "iot_disable", "iot_add", "iot_remove", "traffic"], "list"),
         "client": {"type": "string", "description": "list / traffic: one device to look up (name, IP or MAC); traffic without it ranks all devices by current use"},
         "history": {"type": "string", "enum": ["minute", "hour", "day"]},
         "mac": {"type": "string"}, "macs": {"type": "array", "items": {"type": "string"}},
         "name": {"type": "string"}, "owner": {"type": "string"}, "note": {"type": "string"},
         "download_kbps": {"type": "integer"}, "upload_kbps": {"type": "integer"},
         "enable": enable}))
    register(ToolDef(
        "usb",
        "USB. action=status (disks, sharing, accounts, media server, Time Machine, modem) | scan | partitions "
        "(serial) | partition (serial, uuid, enable: share/hide one partition) | eject (serial) | browse "
        "(uuid, path) | service (protocol=samba|ftp|ftpex|sftp|sftpex, enable/settings={port}) | sharing_auth | "
        "media_server | server_name | time_machine | modem (USB 4G backup internet; CRITICAL) | modem_isps.",
        usb.usb,
        {"action": _action(["status", "scan", "partitions", "partition", "eject", "browse", "service", "server_name",
                            "modem_isps", *usb.GROUPS], "status"),
         "serial": {"type": "string"}, "uuid": {"type": "string"}, "path": {"type": "string"},
         "name": {"type": "string"},
         "protocol": {"type": "string"}, "settings": settings, "enable": enable}))
    register(ToolDef(
        "device_log",
        "Everything the router knows about ONE device, plus a local per-MAC history. action=report (mac: online "
        "state, IP, DHCP lease/reservation, every router-log line mentioning its MAC or IP, its parental-control "
        "profile's sites today and blocked attempts, access-control / VPN / IoT status, traffic) | record (mac: "
        "append only what is NEW to <state>/device-logs/<router>-<MAC>.jsonl; run it on a timer for a "
        "continuous log beyond what the router keeps) | history (mac, event?, limit) | list. Read-only on the "
        "router.",
        device_log.device_log,
        {"action": _action(["report", "record", "history", "list"], "report"), "mac": {"type": "string"},
         "event": _action(["online", "offline", "router_log", "site", "blocked"]),
         "limit": {"type": "integer"}}, read_only=True))
    register(ToolDef(
        "ddns",
        "Dynamic DNS. action=status | refresh (provider) | tplink: add / remove / bind / unbind (domain) | "
        "noip / dyndns: login (username, domain, password_file[, wan_bind]) | logout.",
        ddns.ddns,
        {"action": _action(["status", "refresh", "add", "remove", "bind", "unbind", "login", "logout"], "status"),
         "provider": _action(["tplink", "noip", "dyndns"]), "domain": {"type": "string"},
         "username": {"type": "string"}, "password_file": {"type": "string"}, "wan_bind": {"type": "string"}}))


def _register_extender() -> None:
    from .features import extender

    register(ToolDef(
        "extender",
        "TP-Link range extender (RE series). action=status (model, mode, uplink signal, mesh role) | uplink "
        "(the network it connects to) | extended (networks it broadcasts) | guest | mesh | network | clients | "
        "wifi_advanced | system (mode, time, LEDs, eco, power schedule) | logs. Secrets masked unless reveal.",
        extender.extender,
        {"action": _action(["status", *[k for k in extender.SECTIONS if k != "status"]], "status")},
        read_only=True, kinds=("extender",)))
    register(ToolDef(
        "extender_set",
        "Change a range extender: action=led (enable) | led_night (enable; time_start/time_end only if the user "
        "gives times - otherwise the saved times are used) | "
        "power_schedule (enable) | mlo (Wi-Fi 7 models: enable, bands=[\"2g\",\"5g\"]; no args = read) | reboot. (Extended networks / high-speed mode: read them with extender; "
        "writing them is not verified yet - use router_raw_write if needed.) No settings = show current values. Dry run "
        "first; critical changes need the confirm_token. Journaled and undoable (except reboot).",
        extender.extender_set,
        {"action": _action(["led", "led_night", "power_schedule", "mlo", "reboot"]),
         "enable": {"type": "boolean"}, "settings": {"type": "object"},
         "bands": {"type": "array", "items": {"type": "string", "enum": ["2g", "5g", "6g"]}}},
        required=["action"], kinds=("extender",)))


_register_all()
_register_phase8()
_register_extender()
