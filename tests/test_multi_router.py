"""Second router (encrypted protocol, BE4800 profile): registry, config, risk tiers, journal routing."""

from __future__ import annotations

import json
from typing import Any

import pytest

from mcp_tplink_router.config import load_routers
from mcp_tplink_router.journal import Journal
from mcp_tplink_router.tools import Registry, Runtime, run_tool

from .fake_router import (
    DESKTOP_MAC,
    KID_LAPTOP,
    LAPTOP_MAC,
    UPSTAIRS_PASSWORD,
    FakeTransport,
    be4800_state,
    fake_encrypted_transport,
)


@pytest.fixture
def kid() -> FakeTransport:
    return FakeTransport(be4800_state())


@pytest.fixture
def pwfile(tmp_path: Any) -> Any:
    p = tmp_path / "kid.pw"
    p.write_text(UPSTAIRS_PASSWORD + "\n")
    return p


@pytest.fixture
def reg(fake, kid, pwfile, tmp_path) -> Registry:  # type: ignore[no-untyped-def]
    journal = Journal(tmp_path / "journal")
    ident = lambda: {"ip": "192.168.0.160", "macs": [DESKTOP_MAC]}  # noqa: E731
    main = Runtime(factory=lambda: fake, journal=journal, host="192.0.2.1", identity=ident, retry_delay=0)
    getter = lambda: pwfile.read_text().strip()  # noqa: E731
    enc = fake_encrypted_transport(kid, getter)
    sec = Runtime(factory=lambda: enc, journal=journal, host="https://192.0.2.47", identity=ident,
                  retry_delay=0, name="upstairs", protocol="encrypted")
    return Registry({"main": main, "upstairs": sec})


@pytest.fixture
def bcall(reg):  # type: ignore[no-untyped-def]
    def _c(_tool: str, **args: Any) -> dict[str, Any]:
        return run_tool(_tool, args, reg)

    return _c


def _apply(bcall, tool, **args):  # type: ignore[no-untyped-def]
    dry = bcall(tool, **args)
    assert "error" not in dry and not dry.get("errors"), dry
    extra = {"confirm_token": dry["confirm_token"]} if "confirm_token" in dry else {}
    return bcall(tool, apply=True, **args, **extra)


# ------------------------------------------------------------------ config
def test_load_routers(pwfile) -> None:  # type: ignore[no-untyped-def]
    env = {"TPLINK_HOST": "192.168.0.1", "TPLINK_PASSWORD": "x", "TPLINK_ROUTERS": "upstairs",
           "TPLINK_UPSTAIRS_HOST": "https://192.168.1.1", "TPLINK_UPSTAIRS_PASSWORD_FILE": str(pwfile),
           "TPLINK_UPSTAIRS_PROTOCOL": "encrypted"}
    r = load_routers(env)
    assert set(r) == {"main", "upstairs"}
    assert r["upstairs"].protocol == "encrypted" and r["upstairs"].password_getter()() == UPSTAIRS_PASSWORD
    assert "password" not in json.dumps(r["upstairs"].describe())
    with pytest.raises(ValueError):
        load_routers({**env, "TPLINK_UPSTAIRS_PROTOCOL": "magic"})
    with pytest.raises(ValueError):
        load_routers({"TPLINK_ROUTERS": "nohost"})
    assert set(load_routers({})) == {"main"}


# ------------------------------------------------------------------ transport
def test_encrypted_requests_go_through_client_request(bcall, reg, kid) -> None:  # type: ignore[no-untyped-def]
    out = bcall("dhcp_reservation", router="upstairs", action="leases")
    assert out["leases"]
    client = reg.routers["upstairs"].factory().clients[-1]  # type: ignore[attr-defined]
    assert client.bodies[0] == ("admin/dhcps?form=client", "operation=load")
    assert UPSTAIRS_PASSWORD not in json.dumps(out)
    assert not kid.logged_in


def test_encrypted_insert_body_is_urlencoded(bcall, reg, kid) -> None:  # type: ignore[no-untyped-def]
    out = _apply(bcall, "access_control", router="upstairs", action="allow", mac="AA-BB-CC-11-22-44")
    assert out["status"] == "applied"
    path, body = reg.routers["upstairs"].factory().clients[-1].bodies[-3]  # type: ignore[attr-defined]
    assert path == "admin/access_control?form=white_list" and body.startswith("operation=insert&new=%7B")


def test_bad_password_file_login_error(reg, pwfile, bcall) -> None:  # type: ignore[no-untyped-def]
    pwfile.write_text("wrong")
    out = bcall("router_status", router="upstairs")
    assert out["error"] == "login_failed" and "wrong" not in json.dumps(out)


# ------------------------------------------------------------------ registry / degrade
def test_status_lists_routers_and_degrades(bcall) -> None:  # type: ignore[no-untyped-def]
    out = bcall("router_status", router="upstairs")
    assert {r["name"] for r in out["routers"]} == {"main", "upstairs"}
    assert out["router"] == "upstairs" and out["clients"]["total"] == 1
    assert "unavailable" in out["note"]
    assert bcall("router_catalog", router="upstairs", filter="dhcps")["risk_profile"].startswith("secondary")
    assert "unknown router" in bcall("router_status", router="nope")["error"]


def test_no_such_callback_hint(bcall) -> None:  # type: ignore[no-untyped-def]
    out = bcall("router_get", router="upstairs", section="status")
    assert out["error"] == "no such callback" and "upstairs" in out["hint"]


def test_default_router_is_main(bcall, fake, kid) -> None:  # type: ignore[no-untyped-def]
    bcall("dhcp_reservation", action="list")
    assert fake.calls and not kid.calls


# ------------------------------------------------------------------ risk tiers
def test_upstairs_critical_tiers(bcall) -> None:  # type: ignore[no-untyped-def]
    assert bcall("access_control", router="upstairs", action="disable")["risk"] == "critical"
    assert bcall("access_control", router="upstairs", action="set_mode", mode="black")["risk"] == "critical"
    last = bcall("access_control", router="upstairs", action="disallow", mac=KID_LAPTOP)
    assert last["risk"] == "critical" and "LAST allowlisted" in last["critical_because"][0]
    assert bcall("parental_control", router="upstairs", action="internet_block", owner_id="1",
                 blocked=True)["risk"] == "critical"
    # main keeps its own rules
    main_pause = bcall("parental_control", action="internet_block", owner_id="1", blocked=True)
    assert main_pause.get("risk") == "normal", main_pause
    assert bcall("access_control", action="enable")["risk"] == "normal"  # main, black mode


def test_vpn_protection_rules_are_main_only(bcall) -> None:  # type: ignore[no-untyped-def]
    assert bcall("vpn_client", action="set_device", mac=LAPTOP_MAC, use_vpn=False)["risk"] == "critical"
    out = bcall("vpn_client", router="upstairs", action="set_device", mac=LAPTOP_MAC, use_vpn=False)
    assert out["risk"] == "normal" and not out.get("critical_because")


def test_token_bound_to_router(bcall) -> None:  # type: ignore[no-untyped-def]
    dry = bcall("access_control", action="set_mode", mode="white")  # critical on main too
    out = bcall("access_control", router="upstairs", action="set_mode", mode="white", apply=True,
                confirm_token=dry["confirm_token"])
    assert out.get("no_change") or out["applied"] is False


# ------------------------------------------------------------------ journal / undo
def test_journal_records_router_and_undo_targets_it(bcall, kid, fake) -> None:  # type: ignore[no-untyped-def]
    done = _apply(bcall, "access_control", router="upstairs", action="allow", mac="AA-BB-CC-11-22-44")
    entry = bcall("router_journal", action="show", id=done["journal_id"])
    assert entry["router"] == "upstairs"
    assert bcall("router_journal")["entries"][0]["router"] == "upstairs"
    assert "was made on router 'upstairs'" in bcall("router_undo", id=done["journal_id"], router="main")["error"]
    n_main = len(fake.calls)
    undo = _apply(bcall, "router_undo", id=done["journal_id"])
    assert undo["status"] == "applied" and len(kid.state["access_control?form=white_list"]) == 1
    assert len(fake.calls) == n_main  # main router untouched
