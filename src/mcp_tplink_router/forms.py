"""Generic form/table plumbing shared by every feature.

Forms are read-merge-written: a change is merged into the current values and the UI's
field allowlist for that form is sent (never a bare partial form, never read-only junk
like nested ``extinfo`` dicts).

Tables are changed one row at a time with the UI's own ops.  Many tables have no router
row key (the UI invents a throwaway one), so the router selects rows by load-order
``index`` plus the ``old`` row JSON.  Therefore every remove/update re-loads the table,
finds the row by its logical key, checks it still equals what the plan saw, and only then
sends - with the index computed from that fresh load.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

from . import catalog
from .catalog import NORMAL
from .netcalc import normalize_mac
from .transport import RouterError


class Conflict(Exception):
    """The router's state no longer matches what the plan was built from."""


def jdump(value: Any) -> str:
    """JSON exactly like the UI's ``JSON.stringify`` (compact)."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def to_field(value: Any) -> str:
    """Stringify a value the way the browser's form encoder would."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        raise TypeError("nested values cannot be form-encoded; JSON-encode them explicitly")
    return str(value)


def cmp_value(value: Any) -> str:
    """Comparable string form of any value (nested values as JSON)."""
    return jdump(value) if isinstance(value, (dict, list)) else to_field(value)


def endpoint(path: str) -> catalog.Endpoint:
    ep = catalog.get(path)
    if ep is None:
        raise ValueError(f"unknown router form {path!r} (see router_catalog)")
    return ep


# ---------------------------------------------------------------------------- reading
def read_form(t: Any, path: str) -> dict[str, Any]:
    ep = endpoint(path)
    data = t.call(path, ep.read_op or "read")
    return data if isinstance(data, dict) else {"value": data}


def _rows(data: Any) -> list[dict[str, Any]]:
    if data is None:
        return []
    if isinstance(data, dict):
        vals = list(data.values())
        return [v for v in vals if isinstance(v, dict)]
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []


def load_table(t: Any, path: str) -> list[dict[str, Any]]:
    ep = endpoint(path)
    data = t.call(path, ep.read_op or "load")
    if ep.list_key:
        data = (data or {}).get(ep.list_key) if isinstance(data, dict) else None
    return _rows(data)


def read_state(t: Any, path: str) -> Any:
    """Whatever a snapshot of ``path`` should hold (form dict or table rows)."""
    ep = endpoint(path)
    if ep.kind == "table" or (ep.list_key and ep.table_ops):
        return load_table(t, path)
    return read_form(t, path)


# --------------------------------------------------------------------------- matching
def key_equal(field_name: str | None, a: Any, b: Any) -> bool:
    if a is None or b is None:
        return False
    if field_name and "mac" in field_name.lower():
        try:
            return normalize_mac(str(a)) == normalize_mac(str(b))
        except ValueError:
            pass
    return str(a) == str(b)


def find_rows(rows: list[dict[str, Any]], key_field: str, value: Any) -> list[int]:
    return [i for i, r in enumerate(rows) if key_equal(key_field, r.get(key_field), value)]


def stable(path: str, row: dict[str, Any] | None) -> dict[str, Any]:
    """``row`` without the form's volatile live fields (counters, connection status) and
    without UCI ``.meta`` fields: the router renumbers ``.name`` (cfgXXXXXX) of the rows
    that remain after a remove (seen live on access_control black_list), which is not a
    real change."""
    ep = catalog.get(path)
    vol = set(ep.volatile) if ep else set()
    return {k: v for k, v in (row or {}).items() if k not in vol and not k.startswith(".")}


def find_matching(rows: list[dict[str, Any]], row: dict[str, Any], path: str | None = None) -> list[int]:
    """Rows whose fields equal ``row``'s (ignoring ``key``, UCI ``.meta`` fields - which the
    router may assign itself - and the form's volatile fields)."""
    vol = set(catalog.get(path).volatile) if path and catalog.get(path) else set()  # type: ignore[union-attr]
    want = {k: v for k, v in row.items() if k != "key" and not k.startswith(".") and k not in vol}
    hits = []
    for i, r in enumerate(rows):
        ok = True
        for k, v in want.items():
            if k not in r:
                continue
            if "mac" in k.lower():
                if not key_equal(k, r.get(k), v):
                    ok = False
                    break
            elif cmp_value(r.get(k)) != cmp_value(v):
                ok = False
                break
        if ok:
            hits.append(i)
    return hits


def same_row(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return jdump(a) == jdump(b) or json.loads(jdump(a)) == json.loads(jdump(b))


# ------------------------------------------------------------------------------ steps
@dataclass
class Step:
    """One request in a plan, with what is needed to verify and undo it."""

    kind: str  # write | insert | remove | update | custom
    path: str  # catalogue path
    op: str
    fields: dict[str, Any] = field(default_factory=dict)  # write fields / row / new row / raw fields
    old: dict[str, Any] | None = None  # previous values (write) or the row as loaded (remove/update)
    extra: dict[str, str] = field(default_factory=dict)  # extra selector params sent verbatim
    send_path: str | None = None
    risk: str = NORMAL
    undoable: bool = True
    label: str = ""
    inverse: dict[str, Any] | None = None  # custom steps: {"op":..., "fields":...} that undoes it
    # Keep the SAME login and poll after sending (WPS ends when the admin session logs out):
    # {"op", "fields", "key", "while": [values meaning "still running"], "every": s, "max": s}
    poll: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Step:
        return cls(**{k: d[k] for k in cls.__dataclass_fields__ if k in d})

    @property
    def url_path(self) -> str:
        if self.send_path:
            return self.send_path
        ep = catalog.get(self.path)
        if self.kind == "write" and ep and ep.write_path:
            return ep.write_path
        return self.path

    def key_value(self) -> Any:
        ep = endpoint(self.path)
        src = self.old if self.kind in ("remove", "update") else self.fields
        return (src or {}).get(ep.key_field) if ep.key_field else None


def plan_write(path: str, current: dict[str, Any], changes: dict[str, Any], *, label: str = "") -> Step | None:
    """A form write of ``changes`` merged over ``current`` (None when nothing changes)."""
    ep = endpoint(path)
    if ep.write_fields is None:
        raise ValueError(f"{path} has no known write format; use router_raw_write")
    unknown = [k for k in changes if k not in ep.write_fields]
    if unknown:
        raise ValueError(f"{path} does not accept field(s) {unknown}; writable: {list(ep.write_fields)}")
    changed = {k: v for k, v in changes.items() if cmp_value(current.get(k)) != cmp_value(v)}
    if not changed:
        return None
    merged = {**current, **changes}
    if ep.partial_write:
        send = {k: changed[k] for k in ep.write_fields if k in changed}
    else:
        send = {k: merged[k] for k in ep.write_fields if k in merged
                and (k in ep.list_fields or k in ep.json_fields or not isinstance(merged[k], (dict, list)))
                and not (ep.skip_empty and merged[k] in ("", None) and k not in changes)}
        for k in ep.json_fields:
            if k in send and isinstance(send[k], (dict, list)):
                send[k] = jdump(send[k])
    old = {k: current.get(k) for k in send}
    return Step("write", path, ep.write_op, fields=send, old=old,
                risk=catalog.risk_of(ep.write_path or path, ep.write_op), label=label)


def plan_insert(path: str, row: dict[str, Any], *, label: str = "", extra: dict[str, str] | None = None) -> Step:
    ep = endpoint(path)
    if "insert" not in ep.table_ops:
        raise ValueError(f"{path} does not support insert")
    return Step("insert", path, "insert", fields=dict(row), extra=dict(extra or {}),
                risk=catalog.risk_of(path, "insert"), label=label)


def _locate(rows: list[dict[str, Any]], path: str, key: Any) -> int:
    ep = endpoint(path)
    if not ep.key_field:
        raise ValueError(f"{path} has no row key")
    hits = find_rows(rows, ep.key_field, key)
    if not hits:
        raise ValueError(f"no row with {ep.key_field}={key!r} in {path}")
    if len(hits) > 1:
        raise ValueError(f"{len(hits)} rows have {ep.key_field}={key!r} in {path}; refusing to guess")
    return hits[0]


def plan_remove(path: str, rows: list[dict[str, Any]], key: Any, *, label: str = "") -> Step:
    ep = endpoint(path)
    if "remove" not in ep.table_ops:
        raise ValueError(f"{path} does not support remove")
    row = rows[_locate(rows, path, key)]
    return Step("remove", path, "remove", old=dict(row), risk=catalog.risk_of(path, "remove"), label=label)


def plan_update(path: str, rows: list[dict[str, Any]], key: Any, changes: dict[str, Any],
                *, label: str = "") -> Step | None:
    ep = endpoint(path)
    if "update" not in ep.table_ops:
        raise ValueError(f"{path} does not support update")
    row = rows[_locate(rows, path, key)]
    new = {**row, **changes}
    if same_row(stable(path, new), stable(path, row)):
        return None
    return Step("update", path, "update", fields=new, old=dict(row),
                risk=catalog.risk_of(path, "update"), label=label)


def plan_custom(path: str, op: str, fields: dict[str, Any] | None = None, *, label: str = "",
                inverse: dict[str, Any] | None = None, send_path: str | None = None,
                risk: str | None = None) -> Step:
    """A request sent verbatim; undoable only when ``inverse`` (op + fields) is known."""
    return Step("custom", path, op, fields=dict(fields or {}),
                risk=risk or catalog.risk_of(send_path or path, op),
                undoable=inverse is not None, label=label, send_path=send_path, inverse=inverse)


# ---------------------------------------------------------------------------- execute
@dataclass
class Prepared:
    """A step resolved against the router's current state, ready to send."""

    step: Step
    fields: dict[str, str]
    rows_before: list[dict[str, Any]] | None = None  # remove/update: the table at send time
    index: int | None = None


def prepare(t: Any, step: Step) -> Prepared:
    """Compute the exact fields to send.  Raises :class:`Conflict` (nothing sent)."""
    ep = catalog.get(step.path)
    if step.kind == "write":
        prefix = ep.field_prefix if ep else ""
        lists = ep.list_fields if ep else ()
        return Prepared(step, {prefix + k: ([str(x) for x in v] if k in lists and isinstance(v, list)
                                            else jdump(v) if isinstance(v, (dict, list)) else to_field(v))
                               for k, v in step.fields.items()})
    if step.kind == "insert":
        if ep is not None and ep.path == "vpn?form=vpn_user_list":
            return Prepared(step, {"list": jdump([step.fields]), **step.extra})
        return Prepared(step, {"new": jdump(step.fields), "index": "0", **step.extra})
    if step.kind in ("remove", "update"):
        assert ep is not None and ep.key_field and step.old is not None
        rows = load_table(t, step.path)
        idx = _locate(rows, step.path, step.old.get(ep.key_field))
        if not same_row(stable(step.path, rows[idx]), stable(step.path, step.old)):
            raise Conflict(f"row {ep.key_field}={step.old.get(ep.key_field)!r} changed since it was read")
        key = rows[idx].get("key", step.old.get(ep.key_field))
        if step.kind == "remove":
            fields = {"key": to_field(key), "index": str(idx), **step.extra}
        else:
            # old = the row exactly as the router has it NOW; new = that row + our (non-volatile) changes
            new = {**rows[idx], **stable(step.path, step.fields)}
            old = rows[idx]
            if ep.row_fields:  # the UI sends only these fields for this table
                new = {k: new.get(k, "") for k in ep.row_fields}
                old = {k: old.get(k, "") for k in ep.row_fields}
            fields = {"key": to_field(key), "new": jdump(new), "old": jdump(old), **step.extra}
        return Prepared(step, fields, rows_before=rows, index=idx)
    if step.kind == "upload":
        return Prepared(step, {k: to_field(v) for k, v in step.fields.items()})
    if step.kind == "rsa_write":
        return Prepared(step, {f"{k}_from_file": v for k, v in step.fields["_rsa"].items()})
    return Prepared(step, {k: to_field(v) if not isinstance(v, (dict, list)) else jdump(v)
                           for k, v in step.fields.items()})


def plan_upload(path: str, op: str, file_path: str, file_field: str, fields: dict[str, Any] | None = None,
                *, label: str = "", risk: str | None = None) -> Step:
    """A multipart upload (config restore, firmware image).  The file's SHA-256 is part of the
    plan, so a confirm token only applies to the exact file that was dry-run."""
    import hashlib
    import os

    fp = os.path.abspath(os.path.expanduser(file_path))
    if not os.path.isfile(fp):
        raise ValueError(f"no such file: {file_path}")
    with open(fp, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    body = {"operation": op, **{k: to_field(v) for k, v in (fields or {}).items()}}
    return Step("upload", path, op, fields={"_file": fp, "_file_field": file_field, "_sha256": digest,
                                             "_size": os.path.getsize(fp), **body},
                risk=risk or catalog.risk_of(path, op), undoable=False, label=label)


def send(t: Any, prep: Prepared) -> Any:
    step = prep.step
    if step.kind == "rsa_write":
        from pathlib import Path

        from tplinkrouterc6u.common.encryption import EncryptionWrapper

        keys = read_form(t, step.path)
        body = {}
        for name, fp in step.fields["_rsa"].items():
            key = keys.get(name)
            if not (isinstance(key, list) and len(key) == 2 and all(key)):
                raise Conflict(f"the router gave no encryption key for {name}")
            body[name] = EncryptionWrapper.rsa_encrypt(Path(fp).read_text().strip(), str(key[0]), str(key[1]))
        return t.call(step.url_path, step.op, body)
    if step.kind == "upload":
        import hashlib
        import os

        fp = str(step.fields["_file"])
        with open(fp, "rb") as fh:
            data = fh.read()
        if hashlib.sha256(data).hexdigest() != step.fields["_sha256"]:
            raise Conflict(f"{fp} changed since the dry run; dry-run again")
        body = {k: to_field(v) for k, v in step.fields.items() if not k.startswith("_")}
        return t.upload(step.url_path, body, {str(step.fields["_file_field"]): (os.path.basename(fp), data)})
    ep = catalog.get(step.path)
    kw = {"timeout": ep.timeout} if ep is not None and ep.timeout else {}
    reply = t.call(step.url_path, step.op, prep.fields, **kw)
    if step.poll:
        reply = _poll(t, step, reply, kw)
    return reply


def _poll(t: Any, step: Step, reply: Any, kw: dict[str, Any]) -> Any:
    import time

    p = step.poll or {}
    key, running = p.get("key"), set(p.get("while") or ())
    deadline = time.monotonic() + float(p.get("max", 130))
    history = []
    cur = reply
    while True:
        val = (cur or {}).get(key) if isinstance(cur, dict) else None
        if not history or history[-1] != val:
            history.append(val)
        if val not in running or time.monotonic() >= deadline:
            break
        time.sleep(float(p.get("every", 3)))
        cur = t.call(step.url_path, str(p.get("op", "")), {k: to_field(v) for k, v in (p.get("fields") or {}).items()},
                     **kw)
    return {"final": cur, "states": history, "timed_out_waiting": (cur or {}).get(key) in running}


def execute(t: Any, step: Step) -> Any:
    """Prepare and send one step.  Raises :class:`Conflict` (nothing sent) or ``RouterError``."""
    return send(t, prepare(t, step))


def collateral(t: Any, prep: Prepared) -> dict[str, Any] | None:
    """After a remove/update: did any row OTHER than the target vanish or change?

    Remove/update select rows by load-order index.  If the router ever read that index
    differently, the wrong row (e.g. the kiosk tablet's reservation) would be hit; this
    compares the whole table before/after so that can never pass silently.
    """
    if prep.rows_before is None or prep.index is None:
        return None
    step = prep.step
    ep = endpoint(step.path)
    after = load_table(t, step.path)
    before_others = [r for i, r in enumerate(prep.rows_before) if i != prep.index]
    target_key = (step.old or {}).get(ep.key_field or "")
    after_others = [r for r in after if not key_equal(ep.key_field, r.get(ep.key_field or ""), target_key)]

    def sig(r: dict[str, Any]) -> str:
        return jdump(dict(sorted(stable(step.path, r).items())))

    b = Counter(sig(r) for r in before_others)
    a = Counter(sig(r) for r in after_others)
    missing_sigs, extra_sigs = b - a, a - b
    if not missing_sigs and not extra_sigs:
        return None
    missing, pool = [], list(before_others)
    for sgn in missing_sigs.elements():
        row = next(r for r in pool if sig(r) == sgn)
        pool.remove(row)
        missing.append(row)
    unexpected = [json.loads(x) for x in extra_sigs.elements()]
    return {"path": step.path, "missing": missing, "unexpected": unexpected}


def _compare(cur: dict[str, Any], want: dict[str, Any], old: dict[str, Any], ignore: set[str]) -> dict[str, Any]:
    changed = [k for k, v in want.items() if k not in ignore and cmp_value(old.get(k)) != cmp_value(v)]
    bad = {k: {"want": cmp_value(want[k]), "got": cur.get(k)} for k in want
           if k in cur and k not in ignore and cmp_value(cur.get(k)) != cmp_value(want[k])}
    if not bad:
        return {"applied": True}
    out: dict[str, Any] = {"applied": False, "mismatch": bad}
    if changed and all(k in cur and cmp_value(cur.get(k)) == cmp_value(old.get(k)) for k in changed):
        out["no_effect"] = True
    return out


def verify(t: Any, step: Step, reply: Any = None) -> dict[str, Any]:
    """Re-read and check that ``step`` took effect.  Returns {applied: bool|None, ...}.

    ``no_effect: True`` means the router accepted the request but every changed field still
    holds its OLD value (it silently ignored the change).
    """
    if step.poll and isinstance(reply, dict):
        p = step.poll
        final = (reply.get("final") or {}).get(p.get("key")) if isinstance(reply.get("final"), dict) else None
        ok = set(p.get("success") or ())
        out_note = ({"note": "the window closed with no device paired (session ended when this call returned)"}
                    if reply.get("timed_out_waiting") else {})
        return {"applied": True, "outcome": final, "states": reply.get("states"),
                "succeeded": final in ok if ok else None, **out_note,
                **({k: v for k, v in reply["final"].items() if k != p.get("key")}
                   if isinstance(reply.get("final"), dict) else {})}
    ep = catalog.get(step.path)
    ignore = set(ep.verify_ignore) if ep else set()
    try:
        if step.kind == "write":
            cur = read_form(t, step.path)
            kept = {k for k in (ep.keeps_blank if ep else ()) if step.fields.get(k) in ("", None)}
            res = _compare(cur, step.fields, step.old or {}, ignore | kept)
            if kept and res.get("applied"):
                res["router_kept"] = {k: cur.get(k) for k in kept if cur.get(k) not in ("", None)}
            return res
        if step.kind == "insert":
            rows = load_table(t, step.path)
            want = {k: v for k, v in step.fields.items() if k not in ignore}
            if find_matching(rows, want, step.path):
                return {"applied": True}
            kf = ep.key_field if ep else None
            if kf and kf != "key" and want.get(kf) is not None:
                hits = find_rows(rows, kf, want[kf])
                if len(hits) == 1:  # present, but the router normalised some fields
                    got = rows[hits[0]]
                    return {"applied": True, "normalised": {k: got.get(k) for k in want
                                                            if cmp_value(got.get(k)) != cmp_value(want[k])}}
            return {"applied": False}
        if step.kind in ("remove", "update") and ep and ep.key_field:
            rows = load_table(t, step.path)
            key = step.key_value()
            hits = find_rows(rows, ep.key_field, key)
            if step.kind == "remove":
                return {"applied": not hits}
            if not hits:
                return {"applied": False}
            new = stable(step.path, step.fields)
            if ep.row_fields:
                new = {k: v for k, v in new.items() if k in ep.row_fields}
            return _compare(rows[hits[0]], new, stable(step.path, step.old), ignore | {"key"})
    except RouterError as exc:
        return {"applied": None, "error": exc.code}
    return {"applied": None, "note": "this kind of step cannot be verified by re-reading"}
