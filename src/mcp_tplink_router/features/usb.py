"""USB: attached drives (scan, safely eject), file sharing (Samba/FTP/SFTP), the media server,
Time Machine backups and a USB 4G/LTE modem as backup internet."""

from __future__ import annotations

from typing import Any

from .. import forms
from . import Ctx, UsageError, safe_read, settings_change

GROUPS: dict[str, tuple[str, str, str | None]] = {
    "sharing_auth": ("folder_sharing?form=auth", "sharing login requirement",
                     None),
    "media_server": ("folder_sharing?form=media", "DLNA media server", None),
    "time_machine": ("time_machine?form=settings", "Time Machine", None),
    "modem": ("usbmodem?form=modemset", "USB modem (backup internet)",
              "the USB modem settings decide the backup internet connection"),
}
ENABLE_KEY = {"sharing_auth": "authentication", "media_server": "media_sharing", "time_machine": "enable"}
SERVICES = "folder_sharing?form=settings"


def usb(ctx: Ctx) -> Any:
    action = ctx.arg("action", "status")
    if action == "status":
        out = {name: safe_read(ctx, path) for name, (path, _, _) in GROUPS.items()}
        out["disks"] = safe_read(ctx, "disk_setting?form=metadata")
        out["services"] = safe_read(ctx, SERVICES)
        out["sharing_mode"] = safe_read(ctx, "folder_sharing?form=mode")
        out["sharing_accounts"] = safe_read(ctx, "folder_sharing?form=partial")
        return out
    if action == "scan":
        return {"disks": ctx.t.call("disk_setting?form=scan", "scan")}
    if action == "eject":
        serial = str(ctx.need("serial"))
        plan = ctx.plan("usb", f"safely eject USB disk {serial}")
        plan.add(forms.plan_custom("disk_setting?form=remove", "remove", {"serial": serial}, label="eject"))
        plan.warnings.append("shares and Time Machine on that disk stop until it is plugged back in")
        return plan
    if action == "partitions":
        serial = str(ctx.need("serial"))
        return {"serial": serial, "partitions": ctx.t.call(f"disk_setting?form=contents&serial={serial}", "load")}
    if action == "partition":
        # Share (enable=true) or hide (enable=false) one partition; the data on it is never touched.
        serial, uuid = str(ctx.need("serial")), str(ctx.need("uuid"))
        if ctx.args.get("enable") is None:
            raise UsageError("pass enable=true|false")
        path = f"disk_setting?form=contents&serial={serial}"
        rows = ctx.t.call(path, "load") or []
        idx = next((i for i, r in enumerate(rows) if str(r.get("uuid")) == uuid), None)
        if idx is None:
            raise UsageError(f"no partition {uuid} on disk {serial}")
        old = dict(rows[idx])
        new = {**old, "enable": "on" if ctx.args["enable"] else "off"}
        if new == old:
            return {"status": "no_change", "partition": old}
        key = str(old.get("id", idx))
        plan = ctx.plan("usb", f"{'share' if ctx.args['enable'] else 'hide'} partition {old.get('volumn')}")
        plan.add(forms.plan_custom(path, "update", {"key": key, "index": str(idx), "new": forms.jdump(new),
                                                    "old": forms.jdump(old)},
                                   label=str(old.get("volumn")), risk="normal",
                                   inverse={"op": "update", "fields": {"key": key, "index": str(idx),
                                                                       "new": forms.jdump(old),
                                                                       "old": forms.jdump(new)}}))
        return plan
    if action == "browse":
        return {"tree": ctx.t.call("folder_sharing?form=tree", "load",
                                   {"uuid": str(ctx.need("uuid")), "path": str(ctx.arg("path", "/"))})}
    if action in ("service", "server_name"):
        return _sharing_save(ctx, action)
    if action in GROUPS:
        path, what, crit = GROUPS[action]
        settings = ctx.obj("settings")
        if ctx.args.get("enable") is not None:
            if action not in ENABLE_KEY:
                raise UsageError(f"{action} has no single on/off; pass settings")
            settings.setdefault(ENABLE_KEY[action], ctx.args["enable"])
        if action == "sharing_auth" and settings.get(ENABLE_KEY[action]) in (False, "off"):
            crit = "anyone on the network can read/write the USB drive without a password"
        return settings_change(ctx, "usb", path, settings, what, critical=crit if settings else None)
    if action == "modem_isps":
        return {"isps": safe_read(ctx, "usbmodem?form=isplist")}
    raise UsageError(f"unknown action {action!r}")


def _onoff(v: Any) -> str:
    return "on" if v is True or str(v).lower() in ("on", "true", "1") else "off"


def _sharing_body(server: str, rows: list[dict[str, Any]]) -> dict[str, str]:
    """The web UI's combined save: server name + "on,off,off" for samba/ftp/ftpex (+ ftpex/sftp extras)."""
    body = {"server": server, "enable": ",".join(_onoff(r.get("enable")) for r in rows[:3])}
    by = {str(r.get("protocol")): r for r in rows}
    if by.get("ftpex", {}).get("edit"):
        body["port"] = str(by["ftpex"].get("port"))
    if "sftp" in by:
        body["sftpenable"] = _onoff(by["sftp"].get("enable"))
    if "sftpex" in by:
        body["sftpexenable"] = _onoff(by["sftpex"].get("enable"))
        if by["sftpex"].get("edit"):
            body["sftpport"] = str(by["sftpex"].get("port"))
    return body


def _sharing_save(ctx: Ctx, action: str) -> Any:
    rows = [dict(r) for r in ctx.rows(SERVICES)]
    server = str((safe_read(ctx, "folder_sharing?form=server") or {}).get("server") or "")
    old_body = _sharing_body(server, rows)
    settings = ctx.obj("settings")
    if action == "server_name":
        name = settings.get("server") or ctx.args.get("name")
        if not name:
            return {"server": server}
        server, what = str(name), f"USB sharing server name -> {name}"
    else:
        proto = str(ctx.need("protocol"))
        row = next((r for r in rows if str(r.get("protocol")) == proto), None)
        if row is None:
            raise UsageError(f"no sharing service {proto!r}; have {[r.get('protocol') for r in rows]}")
        if ctx.args.get("enable") is not None:
            settings.setdefault("enable", ctx.args["enable"])
        if not settings:
            return {"service": row}
        if "port" in settings and not row.get("edit"):
            raise UsageError(f"the {proto} port is fixed")
        row.update({k: (_onoff(v) if k == "enable" else v) for k, v in settings.items() if k in ("enable", "port")})
        what = f"USB sharing service {proto}: {settings}"
        if proto in ("ftpex", "sftpex") and row.get("enable") == "on":
            ctx.args["_warn_internet"] = True
    body = _sharing_body(server, rows)
    if body == old_body:
        return {"status": "no_change", "services": rows, "server": server}
    plan = ctx.plan("usb", what, SERVICES, "folder_sharing?form=server")
    plan.add(forms.plan_custom(SERVICES, "save", body, label="usb sharing",
                               inverse={"op": "save", "fields": old_body}))
    if ctx.args.pop("_warn_internet", False):
        plan.warnings.append("this exposes the USB drive to the INTERNET")
    return plan
