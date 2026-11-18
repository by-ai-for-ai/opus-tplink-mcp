"""Maintenance: config backup / restore, firmware (online, local image, mesh satellites),
diagnostics (ping / traceroute), operation mode and the reboot schedule."""

from __future__ import annotations

import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .. import forms
from ..safety import Plan
from . import Ctx, UsageError, find_mac, safe_read, settings_change

REBOOTS = "the router reboots: every device loses network for a few minutes; not undoable"
MODES = ("router", "ap", "repeater", "client", "multissid")


def backup_dir() -> Path:
    base = os.environ.get("TPLINK_BACKUP_DIR") or os.path.join(
        os.environ.get("TPLINK_JOURNAL_DIR") or os.path.expanduser("~/.local/state/mcp-tplink-router"), "backups")
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


def maintenance(ctx: Ctx) -> Any:
    action = ctx.arg("action", "info")
    if action == "info":
        return {
            "firmware": safe_read(ctx, "firmware?form=upgrade"),
            "online_update": safe_read(ctx, "cloud_account?form=check_upgrade"),
            "auto_update": safe_read(ctx, "firmware?form=auto_upgrade"),
            "operation_mode": safe_read(ctx, "system?form=sysmode"),
            "reboot_schedule": safe_read(ctx, "reboot?form=set"),
            "backups_saved_in": str(backup_dir()),
        }
    # ---------------------------------------------------------------- backup / restore
    if action == "backup":
        data, name = ctx.t.download("firmware?form=config_multipart", {"operation": "backup"})
        if not data:
            return {"error": "the router returned an empty backup"}
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name or "config.bin")
        out = backup_dir() / f"{ctx.router}-{stamp}-{safe}"
        out.write_bytes(data)
        os.chmod(out, 0o600)
        return {"saved": str(out), "bytes": len(data),
                "note": "the backup holds Wi-Fi and admin secrets; it is saved mode 600"}
    if action == "backups":
        return {"dir": str(backup_dir()),
                "files": sorted((p.name for p in backup_dir().iterdir() if p.is_file()), reverse=True)}
    if action == "restore":
        f = ctx.need("file")
        fp = f if os.path.isabs(os.path.expanduser(f)) else str(backup_dir() / f)
        plan = Plan(tool="maintenance", summary=f"restore the router config from {os.path.basename(fp)}")
        plan.add(forms.plan_upload("firmware?form=config_multipart", "restore", fp, "file", label="restore"))
        plan.critical_reasons.append("REPLACES every router setting with the file's; " + REBOOTS)
        plan.warnings.append("make a fresh backup first (action=backup) so this can be reversed by hand")
        return plan
    # ---------------------------------------------------------------- firmware
    if action == "firmware_check":
        return {"current": safe_read(ctx, "firmware?form=upgrade"),
                "online": safe_read(ctx, "cloud_account?form=check_upgrade"),
                "latest": safe_read(ctx, "cloud_account?form=cloud_upgrade"),
                "satellites": safe_read(ctx, "firmware?form=slave_cmd", "slave_get_info")}
    if action == "firmware_update_online":
        latest = safe_read(ctx, "cloud_account?form=cloud_upgrade")
        plan = Plan(tool="maintenance", summary="download and install the latest firmware from TP-Link")
        plan.add(forms.plan_custom("cloud_account?form=cloud_upgrade", "upgrade", label="online upgrade"))
        plan.critical_reasons.append("installs new firmware; " + REBOOTS + "; do not power off meanwhile")
        plan.warnings.append(f"offered by TP-Link: {latest}")
        return plan
    if action == "firmware_status":
        return {"download": safe_read(ctx, "cloud_account?form=detect_upgrade_status"),
                "firmware": safe_read(ctx, "firmware?form=upgrade")}
    if action == "firmware_upload":
        fp = ctx.need("file")
        plan = Plan(tool="maintenance", summary=f"install firmware image {os.path.basename(fp)} (settings kept)")
        plan.add(forms.plan_upload("firmware?form=save_upgrade", "firmware", fp, "image", {"keep": "on"},
                                   label="firmware image"))
        plan.critical_reasons.append("flashes a firmware image: a wrong model's image can brick the router; "
                                     + REBOOTS)
        return plan
    if action == "satellite_firmware_update":
        mac = find_mac(ctx.need("mac"))
        sats = safe_read(ctx, "firmware?form=slave_cmd", "slave_get_info")
        sat = next((s for s in (sats if isinstance(sats, list) else [])
                    if forms.key_equal("mac", s.get("mac"), mac)), None)
        if not sat:
            raise UsageError(f"no mesh satellite {mac} in the update list")
        plan = Plan(tool="maintenance", summary=f"update satellite {sat.get('name') or mac} firmware")
        plan.add(forms.plan_custom("firmware?form=slave_cmd", "slave_upgrade_firmware",
                                   {"ip": sat.get("ip", ""), "mac": sat.get("mac", "")}, label="satellite update"))
        plan.critical_reasons.append("the satellite reboots; devices on it lose Wi-Fi for a few minutes")
        return plan
    # ---------------------------------------------------------------- diagnostics
    if action in ("ping", "traceroute"):
        return _diag(ctx, action)
    # ---------------------------------------------------------------- operation mode
    if action == "operation_mode":
        mode = ctx.arg("mode")
        if not mode:
            return {"operation_mode": ctx.read("system?form=sysmode"), "modes": list(MODES)}
        if mode not in MODES:
            raise UsageError(f"mode must be one of {list(MODES)}")
        return settings_change(ctx, "maintenance", "system?form=sysmode", {"mode": mode}, "operation mode",
                               critical="switching operation mode rebuilds the network (DHCP, Wi-Fi, NAT); "
                                        "the router's address may change and it reboots")
    if action == "reboot_schedule":
        return settings_change(ctx, "maintenance", "reboot?form=set", ctx.obj("settings"), "reboot schedule")
    raise UsageError(f"unknown action {action!r}")


def _diag(ctx: Ctx, kind: str) -> dict[str, Any]:
    target = str(ctx.need("target"))
    path = "diag?form=diag"
    t = 0 if kind == "ping" else 1
    base = {"type": str(t), "ipaddr": target}
    if t == 0:
        count = int(ctx.arg("count", 4))
        if not 1 <= count <= 50:
            raise UsageError("count must be 1-50")
        start = {**base, "ipaddr_ping": target, "count": str(count), "pktsize": str(int(ctx.arg("size", 64)))}
    else:
        ttl = int(ctx.arg("max_hops", 20))
        if not 1 <= ttl <= 30:
            raise UsageError("max_hops must be 1-30")
        start = {**base, "ipaddr_trace": target, "ttl": str(ttl)}
    res = ctx.t.call(path, "start", start) or {}
    deadline = time.monotonic() + float(ctx.arg("timeout", 60))
    while str(res.get("finish")) != "1" and time.monotonic() < deadline:
        time.sleep(1)
        res = ctx.t.call(path, "continue", base) or {}
    finished = str(res.get("finish")) == "1"
    final = ctx.t.call(path, "stop", base) or res
    return {"target": target, "finished": finished, "result": final.get("result") or res.get("result", "")}
