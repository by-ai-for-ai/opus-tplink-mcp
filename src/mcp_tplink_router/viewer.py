"""``opus-tplink-mcp viewer`` - a live window on the local event log (needs the ``gui`` extra: PySide6).

Layout follows the maintainer's tcl-fw tool: a header, a device picker and filters, a table of the devices
this server has talked to (model / hardware / firmware / last event), and a dark log pane that streams
events as they happen.  Read-only: the viewer never talks to a router and never changes a setting.
"""

from __future__ import annotations

import html
import json
import sys
from datetime import datetime
from typing import Any

from . import __version__, events

COLOURS = {  # same key as the terminal watcher
    "error": "#f87171", "unreachable": "#f87171", "login_failed": "#f87171", "mismatch": "#f87171",
    "unknown": "#f87171", "not_done": "#fbbf24", "refused": "#fbbf24", "recovered": "#fbbf24",
    "no_such_device": "#fbbf24", "not_supported": "#fbbf24", "firmware_changed": "#60a5fa", "mode_changed": "#60a5fa", "firmware_seen": "#93c5fd",
    "changed": "#4ade80", "restart": "#67e8f9",
}
GROUPS = {
    "Errors": {"error", "unreachable", "login_failed", "mismatch", "unknown"},
    "Refusals / not done": {"not_done", "refused", "recovered", "no_such_device", "not_supported"},
    "Firmware": {"firmware_changed", "firmware_seen", "mode_changed"},
    "Changes": {"changed", "restart"},
}


def _when(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return ""


def main(argv: list[str] | None = None) -> int:
    try:
        from PySide6.QtCore import Qt, QTimer
        from PySide6.QtGui import QFont
        from PySide6.QtWidgets import (
            QApplication,
            QCheckBox,
            QComboBox,
            QHBoxLayout,
            QHeaderView,
            QLabel,
            QMainWindow,
            QMessageBox,
            QPlainTextEdit,
            QPushButton,
            QTableWidget,
            QTableWidgetItem,
            QVBoxLayout,
            QWidget,
        )
    except ImportError:
        print("The viewer needs PySide6:  pip install 'opus-tplink-mcp[gui]'   (or use: opus-tplink-mcp watch)",
              file=sys.stderr)
        return 2

    app = QApplication.instance() or QApplication(sys.argv[:1] + (argv or []))
    win = QMainWindow()
    win.setWindowTitle(f"opus-tplink-mcp {__version__} — live events")
    win.resize(980, 720)
    root = QWidget()
    lay = QVBoxLayout(root)

    title = QLabel("<b style='font-size:15px'>opus-tplink-mcp</b>")
    sub = QLabel("Built by AI, for AI · what the server did, live · read-only, nothing here changes a router")
    sub.setStyleSheet("color:#6b8fd6")
    lay.addWidget(title)
    lay.addWidget(sub)

    bar = QHBoxLayout()
    bar.addWidget(QLabel("Device:"))
    dev = QComboBox()
    dev.addItem("All devices", "")
    dev.setMinimumWidth(220)
    bar.addWidget(dev)
    boxes: dict[str, QCheckBox] = {}
    for g in GROUPS:
        cb = QCheckBox(g)
        cb.setChecked(True)
        boxes[g] = cb
        bar.addWidget(cb)
    bar.addStretch(1)
    lay.addLayout(bar)

    table = QTableWidget(0, 6)
    table.setHorizontalHeaderLabels(["Device", "Model", "Hardware", "Firmware", "Last event", "When"])
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    table.verticalHeader().setVisible(False)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setMaximumHeight(230)
    lay.addWidget(table)

    log = QPlainTextEdit()
    log.setReadOnly(True)
    log.setFont(QFont("monospace", 9))
    log.setStyleSheet("background:#0f1419; color:#e6edf3; border-radius:6px; padding:6px")
    log.document().setMaximumBlockCount(5000)
    lay.addWidget(log, 1)

    status = QLabel()
    status.setStyleSheet("color:#8b949e")
    lay.addWidget(status)
    foot = QHBoxLayout()
    rep_lbl = QLabel()
    rep_btn = QPushButton("Field reports…")
    foot.addWidget(rep_lbl)
    foot.addStretch(1)
    foot.addWidget(rep_btn)
    lay.addLayout(foot)
    win.setCentralWidget(root)

    from . import reporting

    def show_rep() -> None:
        rep_lbl.setText(reporting.status_line())

    def ask_reporting() -> None:
        """First launch (or a new notice version): the person must choose ON or OFF to go on."""
        box = QMessageBox(win)
        box.setWindowTitle("opus-tplink-mcp - field reports")
        box.setIcon(QMessageBox.Icon.Information)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(reporting.NOTICE)
        on = box.addButton("Turn ON", QMessageBox.ButtonRole.AcceptRole)
        off = box.addButton("Keep OFF", QMessageBox.ButtonRole.RejectRole)
        box.setStyleSheet("QLabel{font-family:monospace; font-size:11px; min-width:620px;}")
        box.exec()
        if box.clickedButton() is on:
            reporting.record_choice(True)
        elif box.clickedButton() is off:
            reporting.record_choice(False)
        show_rep()  # closed without choosing: still OFF, asked again next launch

    rep_btn.clicked.connect(ask_reporting)
    show_rep()
    if not reporting.decided():
        QTimer.singleShot(0, ask_reporting)

    state: dict[str, Any] = {"pos": 0, "events": [], "devices": {}}

    def allowed(e: dict[str, Any]) -> bool:
        kinds = set().union(*(GROUPS[g] for g, cb in boxes.items() if cb.isChecked()))
        want = dev.currentData()
        return e.get("kind") in kinds and (not want or e.get("router") == want)

    def render_line(e: dict[str, Any]) -> str:
        kind = str(e.get("kind"))
        rest = {k: v for k, v in e.items() if k not in ("ts", "kind", "router") and v not in (None, "", [], {})}
        detail = rest.pop("tell_user", None) or rest.pop("error", None) or ""
        extra = " ".join(f"{k}={json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v}"
                         for k, v in rest.items())
        text = f"{_when(e.get('ts'))}  {str(e.get('router') or '-'):10} {kind:17} {detail} {extra}"
        safe = html.escape(text).replace(" ", "&nbsp;")  # keep the columns lined up (HTML collapses spaces)
        return f"<span style='color:{COLOURS.get(kind, '#e6edf3')}'>{safe}</span>"

    def refresh_devices() -> None:
        seen: dict[str, Any] = {}
        sf = events.path().with_name("devices-seen.json")
        try:
            for key, v in (json.loads(sf.read_text()) if sf.exists() else {}).items():
                seen[key.split("@")[0]] = dict(v)
        except ValueError:
            pass
        for e in state["events"]:
            r = e.get("router")
            if r:
                seen.setdefault(r, {})["last"] = e
        names = sorted(seen)
        known = {dev.itemData(i) for i in range(dev.count())}
        for n in names:
            if n not in known:
                dev.addItem(n, n)
        table.setRowCount(len(names))
        for row, n in enumerate(names):
            d = seen[n]
            last = d.get("last") or {}
            vals = [n, d.get("model", ""), d.get("hardware_version", ""), d.get("firmware_version", ""),
                    last.get("kind", ""), _when(last.get("ts"))]
            for col, v in enumerate(vals):
                item = QTableWidgetItem(str(v))
                if col == 4 and last.get("kind") in COLOURS:
                    item.setForeground(Qt.GlobalColor.darkRed if last["kind"] in GROUPS["Errors"] else
                                       Qt.GlobalColor.darkYellow if last["kind"] in GROUPS["Refusals / not done"]
                                       else Qt.GlobalColor.darkBlue if last["kind"] in GROUPS["Firmware"]
                                       else Qt.GlobalColor.darkGreen)
                table.setItem(row, col, item)

    def rebuild() -> None:
        log.clear()
        for e in state["events"]:
            if allowed(e):
                log.appendHtml(render_line(e))

    def poll() -> None:
        p = events.path()
        if not p.exists():
            status.setText(f"waiting for events in {p}")
            return
        size = p.stat().st_size
        if size < state["pos"]:
            state["pos"], state["events"] = 0, []
            log.clear()
        if size != state["pos"]:
            with open(p, encoding="utf-8", errors="replace") as fh:
                fh.seek(state["pos"])
                chunk = fh.read()
                state["pos"] = fh.tell()
            for raw in chunk.splitlines():
                try:
                    e = json.loads(raw)
                except ValueError:
                    continue
                state["events"].append(e)
                if allowed(e):
                    log.appendHtml(render_line(e))
            state["events"] = state["events"][-5000:]
            refresh_devices()
        errs = sum(1 for e in state["events"] if e.get("kind") in GROUPS["Errors"])
        status.setText(f"{len(state['events'])} events · {errs} errors · {p}")

    dev.currentIndexChanged.connect(lambda _i: rebuild())
    for cb in boxes.values():
        cb.toggled.connect(lambda _c: rebuild())
    timer = QTimer(win)
    timer.timeout.connect(poll)
    timer.start(1000)
    poll()
    win.show()
    rc = int(app.exec())
    timer.stop()  # tear Qt down in order: a timer firing into a deleted window aborts at exit
    win.hide()
    win.deleteLater()
    app.processEvents()
    return rc
