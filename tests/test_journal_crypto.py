"""The journal never stores device state (Wi-Fi passwords, VPN keys) as plain text."""

from __future__ import annotations

import json
import os
import stat
from typing import Any

from mcp_tplink_router.journal import Journal

from .fake_router import WIFI_PSK


def test_key_and_journal_are_private(apply, rt, tmp_path) -> None:  # type: ignore[no-untyped-def]
    apply("wifi_set", action="set", band="2g", settings={"password": "brand-new-pass-1"})
    for p in (rt.journal.path, rt.journal.key_path):
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    raw = rt.journal.path.read_text()
    assert '"$enc"' in raw and "psk_key" not in raw  # field names inside state are sealed too


def test_missing_key_refuses_undo_and_sends_nothing(apply, call, rt, fake) -> None:  # type: ignore[no-untyped-def]
    done = apply("wifi_set", action="set", band="2g", settings={"password": "brand-new-pass-1"})
    os.remove(rt.journal.key_path)
    before = json.dumps(fake.state)
    out = call("router_undo", id=done["journal_id"])
    assert out.get("applied") is not True and "journal key" in json.dumps(out)
    assert json.dumps(fake.state) == before
    # listing still works without the key: the labels are not encrypted
    listed = call("router_journal", action="list")
    rows = listed["entries"]
    assert rows and rows[0]["id"] == done["journal_id"]


def test_migration_encrypts_old_plaintext_journal(tmp_path: Any) -> None:
    j = Journal(tmp_path / "j", tmp_path / "k.key")
    j.dir.mkdir()
    old = {"id": "20260101-000000-abcdef", "ts": 1, "router": "main", "tool": "wifi_set", "summary": "x",
           "risk": "normal", "status": "pending", "undo_of": None,
           "requests": [{"kind": "write", "path": "wireless?form=wireless_2g", "fields": {"psk_key": WIFI_PSK}}],
           "before": {"wireless?form=wireless_2g": {"psk_key": WIFI_PSK}}}
    j.path.write_text(json.dumps(old) + "\n" + json.dumps({"id": old["id"], "status": "applied",
                                                             "after": {"x": {"psk_key": "after-secret-9"}}}) + "\n")
    os.chmod(j.path, 0o600)
    assert j.migrate() == 2
    raw = j.path.read_text()
    assert WIFI_PSK not in raw and "after-secret-9" not in raw
    e = j.get(old["id"])
    assert e["before"]["wireless?form=wireless_2g"]["psk_key"] == WIFI_PSK and e["status"] == "applied"
    assert stat.S_IMODE(os.stat(j.path).st_mode) == 0o600
    assert j.migrate() == 0  # idempotent


def test_sealed_section_is_bound_to_its_entry(tmp_path: Any) -> None:
    j = Journal(tmp_path / "j", tmp_path / "k.key")
    a = j.begin("t", "s", [], {"f": {"password": "one-secret-1"}}, risk="normal")
    b = j.begin("t", "s", [], {"f": {"password": "two-secret-2"}}, risk="normal")
    lines = [json.loads(x) for x in j.path.read_text().splitlines()]
    lines[1]["before"] = lines[0]["before"]  # splice a's ciphertext into b
    j.path.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    assert j.get(a)["before"]["f"]["password"] == "one-secret-1"
    eb = j.get(b)
    assert eb["before"] is None and "integrity" in eb.get("unreadable", "")


ODD = 'quo"te\\back ünïcødé-密码-9'


def test_secrets_never_in_tool_replies_or_raw_file(apply, call, rt) -> None:  # type: ignore[no-untyped-def]
    done = apply("wifi_set", action="set", band="2g", settings={"password": ODD})
    raw = rt.journal.path.read_bytes()
    for form in (ODD, json.dumps(ODD)[1:-1], json.dumps(ODD, ensure_ascii=False)[1:-1], WIFI_PSK):
        assert form.encode() not in raw
    replies = [call("router_journal", action="show", id=done["journal_id"]),
               call("router_journal", action="list"),
               call("router_undo", id=done["journal_id"])]  # the undo preview
    for r in replies:
        text = json.dumps(r, ensure_ascii=False)
        assert ODD not in text and WIFI_PSK not in text and json.dumps(ODD)[1:-1] not in text


def test_wrong_key_is_named(apply, call, rt) -> None:  # type: ignore[no-untyped-def]
    done = apply("wifi_set", action="set", band="2g", settings={"password": "brand-new-pass-1"})
    os.remove(rt.journal.key_path)
    rt.journal.begin("t", "s", [], {}, risk="normal")  # mints a NEW key
    out = call("router_undo", id=done["journal_id"])
    assert "different journal key" in json.dumps(out) and out.get("applied") is not True
