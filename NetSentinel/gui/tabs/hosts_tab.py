"""
hosts_tab.py - Displays the host inventory table.
"""

import datetime

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QMenu, QAction
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QBrush

from ..widgets.filter_bar import FilterBar
from ..widgets.detail_panel import DetailPanel


class HostsTab(QWidget):
    """Shows all observed hosts with details panel."""

    host_selected = pyqtSignal(str)  # emits IP

    COLUMNS = ["IP Address", "MAC Address", "Hostname", "OS Guess",
               "Country", "Bytes Sent", "Bytes Recv", "First Seen", "Last Seen", "Ports"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._hosts = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        self._filter_bar = FilterBar("Filter by IP, hostname, OS...")
        self._filter_bar.filter_changed.connect(self._apply_filter)

        splitter = QSplitter(Qt.Vertical)

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
        self._table.cellClicked.connect(self._on_row_clicked)
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)

        self._detail = DetailPanel()

        splitter.addWidget(self._table)
        splitter.addWidget(self._detail)
        splitter.setSizes([400, 150])

        layout.addWidget(self._filter_bar)
        layout.addWidget(splitter)

    def add_host(self, host_dict):
        """Add or update a host row."""
        for i, h in enumerate(self._hosts):
            if h["ip"] == host_dict["ip"]:
                self._hosts[i] = host_dict
                self._refresh_row(i, host_dict)
                return
        self._hosts.append(host_dict)
        self._add_row(host_dict)

    def _add_row(self, host):
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._fill_row(row, host)

    def _refresh_row(self, logical_idx, host):
        # Find the visual row matching this host IP
        for row in range(self._table.rowCount()):
            item = self._table.item(row, 0)
            if item and item.text() == host["ip"]:
                self._fill_row(row, host)
                return

    def _fill_row(self, row, host):
        vals = [
            host.get("ip", ""),
            host.get("mac", ""),
            ", ".join(host.get("hostnames", [])) or "",
            host.get("os_guess", ""),
            host.get("country", ""),
            self._human_bytes(host.get("bytes_sent", 0)),
            self._human_bytes(host.get("bytes_recv", 0)),
            self._fmt_ts(host.get("first_seen", 0)),
            self._fmt_ts(host.get("last_seen", 0)),
            ", ".join(str(p) for p in host.get("ports", [])[:10]),
        ]
        for col, val in enumerate(vals):
            item = QTableWidgetItem(str(val))
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._table.setItem(row, col, item)

    def _apply_filter(self, text):
        text = text.lower()
        for row in range(self._table.rowCount()):
            visible = False
            if not text:
                visible = True
            else:
                for col in range(self._table.columnCount()):
                    item = self._table.item(row, col)
                    if item and text in item.text().lower():
                        visible = True
                        break
            self._table.setRowHidden(row, not visible)

    def _on_row_clicked(self, row, _col):
        item = self._table.item(row, 0)
        if not item:
            return
        ip = item.text()
        for h in self._hosts:
            if h["ip"] == ip:
                self._detail.set_title(f"Host: {ip}")
                self._detail.set_data({
                    "IP": h.get("ip", ""),
                    "MAC": h.get("mac", ""),
                    "Hostnames": h.get("hostnames", []),
                    "OS Guess": h.get("os_guess", ""),
                    "Country": h.get("country", ""),
                    "City": h.get("city", ""),
                    "ASN": h.get("asn", ""),
                    "Bytes Sent": self._human_bytes(h.get("bytes_sent", 0)),
                    "Bytes Recv": self._human_bytes(h.get("bytes_recv", 0)),
                    "First Seen": self._fmt_ts(h.get("first_seen", 0)),
                    "Last Seen": self._fmt_ts(h.get("last_seen", 0)),
                    "Open Ports": h.get("ports", []),
                })
                self.host_selected.emit(ip)
                break

    def _on_context_menu(self, pos):
        row = self._table.rowAt(pos.y())
        if row < 0:
            return
        ip_item = self._table.item(row, 0)
        if not ip_item:
            return
        ip = ip_item.text()
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
        self._hosts.clear()
        self._table.setRowCount(0)
        self._detail.clear()

    def get_data(self):
        return list(self._hosts)

    @staticmethod
    def _human_bytes(n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    @staticmethod
    def _fmt_ts(ts):
        if not ts:
            return ""
        try:
            return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(ts)
