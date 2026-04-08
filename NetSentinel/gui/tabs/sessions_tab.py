"""
sessions_tab.py - Displays TCP/UDP session table with stream viewer popup.
"""

import datetime

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QDialog, QTextEdit,
    QVBoxLayout as DlgLayout, QMenu
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

from ..widgets.filter_bar import FilterBar


PROTO_COLORS = {
    "HTTP": "#1a3a5c",
    "HTTPS": "#1a3a5c",
    "DNS": "#1a3c2e",
    "FTP": "#2c1a3c",
    "Telnet": "#2c1a3c",
    "ICMP": "#3c2c1a",
}

SUSPICIOUS_COLOR = "#3c1a1a"


class SessionsTab(QWidget):
    """Displays sessions with color coding and stream popup on double-click."""

    COLUMNS = ["Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol",
               "App Protocol", "Duration (s)", "Bytes Fwd", "Bytes Rev",
               "State", "Flags", "Start Time"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._sessions = []
        self._stream_getter = None   # callable(src_ip, sport, dst_ip, dport, proto)
        self._setup_ui()

    def set_stream_getter(self, fn):
        self._stream_getter = fn

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._filter_bar = FilterBar("Filter by IP, port, protocol...")
        self._filter_bar.filter_changed.connect(self._apply_filter)

        self._table = QTableWidget(0, len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels(self.COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet(
            "QTableWidget { background: #1a1a2e; alternate-background-color: #16213e; "
            "color: #eaeaea; gridline-color: #0f3460; }"
            "QTableWidget::item:selected { background: #e94560; }"
            "QHeaderView::section { background: #0f3460; color: #eaeaea; "
            "padding: 4px; border: 1px solid #16213e; }"
        )
        self._table.cellDoubleClicked.connect(self._on_double_click)
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)

        layout.addWidget(self._filter_bar)
        layout.addWidget(self._table)

    def add_session(self, sess):
        self._sessions.append(sess)
        row = self._table.rowCount()
        self._table.insertRow(row)
        flags = ", ".join(sess.get("flags", []))
        vals = [
            sess.get("src_ip", ""), str(sess.get("src_port", "")),
            sess.get("dst_ip", ""), str(sess.get("dst_port", "")),
            sess.get("protocol", ""), sess.get("app_protocol", ""),
            f"{sess.get('duration', 0):.2f}",
            str(sess.get("bytes_fwd", 0)), str(sess.get("bytes_rev", 0)),
            sess.get("state", ""), flags,
            self._fmt_ts(sess.get("start_time", 0)),
        ]
        app_proto = sess.get("app_protocol", "")
        bg = PROTO_COLORS.get(app_proto, "")
        for col, val in enumerate(vals):
            item = QTableWidgetItem(str(val))
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if bg:
                item.setBackground(QColor(bg))
            self._table.setItem(row, col, item)

    def _apply_filter(self, text):
        text = text.lower()
        for row in range(self._table.rowCount()):
            visible = not text
            if text:
                for col in range(self._table.columnCount()):
                    item = self._table.item(row, col)
                    if item and text in item.text().lower():
                        visible = True
                        break
            self._table.setRowHidden(row, not visible)

    def _on_double_click(self, row, _col):
        src_ip = (self._table.item(row, 0) or QTableWidgetItem()).text()
        sport = int((self._table.item(row, 1) or QTableWidgetItem("0")).text() or 0)
        dst_ip = (self._table.item(row, 2) or QTableWidgetItem()).text()
        dport = int((self._table.item(row, 3) or QTableWidgetItem("0")).text() or 0)
        proto = (self._table.item(row, 4) or QTableWidgetItem()).text()

        stream = b""
        if self._stream_getter:
            stream = self._stream_getter(src_ip, sport, dst_ip, dport, proto)

        dlg = StreamViewer(src_ip, sport, dst_ip, dport, stream, self)
        dlg.exec_()

    def _on_context_menu(self, pos):
        row = self._table.rowAt(pos.y())
        if row < 0:
            return
        ip = (self._table.item(row, 0) or QTableWidgetItem()).text()
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background: #16213e; color: #eaeaea; }"
                           "QMenu::item:selected { background: #e94560; }")
        menu.addAction("Copy IP").triggered.connect(
            lambda: self._copy_to_clipboard(ip))
        menu.addAction("Filter by this host").triggered.connect(
            lambda: self._filter_bar._input.setText(ip))
        menu.addAction("Lookup on VirusTotal").triggered.connect(
            lambda: self._open_vt(ip))
        menu.addAction("Lookup on Shodan").triggered.connect(
            lambda: self._open_shodan(ip))
        menu.exec_(self._table.viewport().mapToGlobal(pos))

    def _copy_to_clipboard(self, text):
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(text)

    def _open_vt(self, ip):
        import webbrowser
        webbrowser.open(f"https://www.virustotal.com/gui/ip-address/{ip}")

    def _open_shodan(self, ip):
        import webbrowser
        webbrowser.open(f"https://www.shodan.io/host/{ip}")

    def clear(self):
        self._sessions.clear()
        self._table.setRowCount(0)

    def get_data(self):
        return list(self._sessions)

    @staticmethod
    def _fmt_ts(ts):
        try:
            return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(ts)


class StreamViewer(QDialog):
    """Popup dialog showing the raw reconstructed TCP stream."""

    def __init__(self, src_ip, sport, dst_ip, dport, stream_bytes, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Stream: {src_ip}:{sport} → {dst_ip}:{dport}")
        self.resize(700, 500)
        self.setStyleSheet("background: #1a1a2e; color: #eaeaea;")
        layout = DlgLayout(self)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setStyleSheet(
            "background: #16213e; color: #eaeaea; font-family: Monospace; font-size: 10px;"
        )
        try:
            decoded = stream_bytes.decode("utf-8", errors="replace")
        except Exception:
            decoded = repr(stream_bytes)
        text.setPlainText(decoded[:50000])  # Cap display at 50k chars
        layout.addWidget(text)
