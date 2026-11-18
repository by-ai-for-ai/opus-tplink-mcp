"""Dynamic DNS: TP-Link DDNS (domains you bind), No-IP and DynDNS (account login)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .. import forms
from . import Ctx, UsageError, safe_read

FORMS = {"tplink": "ddns?form=tplink", "noip": "ddns?form=noip", "dyndns": "ddns?form=dyndns"}


def ddns(ctx: Ctx) -> Any:
    action = ctx.arg("action", "status")
    if action == "status":
        return {"provider": safe_read(ctx, "ddns?form=provider"),
                **{k: safe_read(ctx, p) for k, p in FORMS.items()}}
    provider = str(ctx.need("provider"))
    if provider not in FORMS:
        raise UsageError(f"provider must be one of {list(FORMS)}")
    path = FORMS[provider]
    if action == "refresh" and provider == "tplink":
        raise UsageError("TP-Link DDNS updates itself (the router has no refresh for it); refresh is for noip/dyndns")
    if action == "refresh":
        plan = ctx.plan("ddns", f"update the {provider} DDNS record now")
        plan.add(forms.plan_custom(path, "refresh", label="ddns refresh"))
        return plan
    if provider == "tplink":
        if action not in ("add", "remove", "bind", "unbind"):
            raise UsageError("tplink actions: add | remove | bind | unbind (domain)")
        domain = str(ctx.need("domain"))
        op = {"add": "insert"}.get(action, action)
        inverse = {"insert": "remove", "remove": "insert", "bind": "unbind", "unbind": "bind"}[op]
        plan = ctx.plan("ddns", f"TP-Link DDNS {action} {domain}")
        plan.add(forms.plan_custom(path, op, {"domain": domain}, label="ddns",
                                   inverse={"op": inverse, "fields": {"domain": domain}}))
        return plan
    if action == "login":
        pw_file = ctx.args.get("password_file")
        if not pw_file:
            raise UsageError("pass password_file (a file holding the DDNS account password)")
        password = Path(os.path.expanduser(str(pw_file))).read_text().strip()
        fields = {"username": str(ctx.need("username")), "password": password, "domain": str(ctx.need("domain"))}
        if provider == "noip" and ctx.args.get("wan_bind") is not None:
            fields["wan_bind"] = str(ctx.args["wan_bind"])
        plan = ctx.plan("ddns", f"log in to {provider} DDNS for {fields['domain']}")
        plan.secret_fields = ("password",)
        plan.add(forms.plan_custom(path, "login", fields, label="ddns login"))
        return plan
    if action == "logout":
        plan = ctx.plan("ddns", f"log out of {provider} DDNS")
        plan.add(forms.plan_custom(path, "logout", label="ddns logout"))
        return plan
    raise UsageError(f"unknown action {action!r}")
