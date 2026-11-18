"""Administration: admin password, who may manage the router (local list / remote / HTTPS),
password recovery, super-admin and the per-user permission switches."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .. import forms
from ..safety import Plan
from . import Ctx, UsageError, find_mac, safe_read, settings_change

LOCKOUT = "a mistake here can lock you out of the router's admin page (and this server)"
GROUPS: dict[str, tuple[str, str, str | None]] = {
    "remote": ("administration?form=remote", "remote management",
               "exposes (or stops exposing) the admin page to the internet"),
    "https": ("administration?form=https", "HTTPS-only admin page", LOCKOUT),
    "local_mode": ("administration?form=mode", "local management mode", LOCKOUT),
    "recovery": ("administration?form=recovery", "password recovery e-mail", None),
    "superadmin": ("administration?form=superadminconfig", "super-admin account", LOCKOUT),
    "permissions": ("administration?form=usersetting", "user permissions", None),
}


def admin(ctx: Ctx) -> Any:
    action = ctx.arg("action", "status")
    if action == "status":
        out = {name: safe_read(ctx, path) for name, (path, _, _) in GROUPS.items()}
        out["local_list"] = safe_read(ctx, "administration?form=local")
        return out
    if action in GROUPS:
        path, what, crit = GROUPS[action]
        settings = ctx.obj("settings")
        if ctx.args.get("enable") is not None:
            key = {"remote": "enable", "https": "https_enable", "recovery": "enable_rec"}.get(action)
            if action == "superadmin":
                settings.setdefault("disable", not ctx.args["enable"])
            elif key:
                settings.setdefault(key, ctx.args["enable"])
            else:
                raise UsageError(f"{action} has no single on/off; pass settings")
        return settings_change(ctx, "admin", path, settings, what, critical=crit if settings else None)
    if action == "local_add":
        mac = find_mac(ctx.need("mac"))
        path = "administration?form=local"
        plan = ctx.plan("admin", f"allow {mac} to manage the router", path)
        plan.add(forms.plan_insert(path, {"enable": "on", "mac": mac, "name": ctx.arg("name", mac)}, label="local"))
        return plan
    if action == "local_remove":
        mac = find_mac(ctx.need("mac"))
        path = "administration?form=local"
        rows = ctx.rows(path)
        plan = ctx.plan("admin", f"stop {mac} managing the router", path)
        plan.add(forms.plan_remove(path, rows, mac, label="local"))
        if mac in ctx.own_macs():
            plan.critical_reasons.append("this is THIS machine: it may lose admin access")
        return plan
    if action == "change_password":
        # Passwords only from files: the plan/journal keep the paths, the values are read and
        # RSA-encrypted at send time (PKCS#1 padding is random, so it can't be pre-computed).
        files = {}
        for arg in ("old_password_file", "new_password_file"):
            f = ctx.args.get(arg)
            if not f:
                raise UsageError(f"pass {arg} (a file holding the password; never the password itself)")
            fp = os.path.abspath(os.path.expanduser(str(f)))
            if not os.path.isfile(fp):
                raise UsageError(f"no such file: {f}")
            files[arg] = fp
        if len(Path(files["new_password_file"]).read_text().strip()) < 6:
            raise UsageError("the new password must be at least 6 characters")
        plan = Plan(tool="admin", summary="change the router admin password")
        plan.add(forms.Step("rsa_write", "administration?form=account", "write",
                            fields={"_rsa": {"old_pwd": files["old_password_file"],
                                             "new_pwd": files["new_password_file"],
                                             "cfm_pwd": files["new_password_file"]}},
                            risk="critical", undoable=False, label="admin password"))
        plan.critical_reasons.append("this server logs in with the OLD password: point its password "
                                     "file/env at the new one right after, or every tool call will fail")
        return plan
    raise UsageError(f"unknown action {action!r}")
