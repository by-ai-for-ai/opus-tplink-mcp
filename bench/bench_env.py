"""Bench configuration: ONE test device, built from scratch so the bench can never reach another router.

Set BENCH_HOST, BENCH_PASSWORD_FILE and (optionally) BENCH_PROTOCOL.  Every other TPLINK_* variable is
removed from the environment first, and the registry is checked to hold only that one device.
"""
from __future__ import annotations

import os


def bench_env(journal_dir: str):  # type: ignore[no-untyped-def]
    host = os.environ.get("BENCH_HOST")
    pw = os.environ.get("BENCH_PASSWORD_FILE")
    if not host or not pw:
        raise SystemExit("set BENCH_HOST (a TEST router you can afford to change) and BENCH_PASSWORD_FILE")
    for k in [k for k in os.environ if k.startswith("TPLINK_")]:
        del os.environ[k]
    if os.environ.get("BENCH_KIND"):
        os.environ["TPLINK_KIND"] = os.environ["BENCH_KIND"]
    if os.environ.get("BENCH_TOOLSET"):
        os.environ["TPLINK_TOOLSET"] = os.environ["BENCH_TOOLSET"]
    if os.environ.get("BENCH_PREVIEW"):
        os.environ["TPLINK_PREVIEW"] = os.environ["BENCH_PREVIEW"]
    if os.environ.get("BENCH_TIER"):
        os.environ["TPLINK_MODEL_TIER"] = os.environ["BENCH_TIER"]
    os.environ.update({"TPLINK_HOST": host, "TPLINK_PROTOCOL": os.environ.get("BENCH_PROTOCOL", "plain"),
                       "TPLINK_PASSWORD_FILE": os.path.expanduser(pw),
                       "TPLINK_JOURNAL_DIR": journal_dir, "TPLINK_AUTO_BACKUP": "0"})
    from mcp_tplink_router.server import registry_from_env

    reg = registry_from_env()
    hosts = {n: rt.host for n, rt in reg.routers.items()}
    assert hosts == {"main": host}, hosts  # only the bench device, nothing else
    return reg
