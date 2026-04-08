"""
dns_tab.py - Displays DNS queries and responses with suspicious activity coloring.
"""

import datetime

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QMenu
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

from ..widgets.filter_bar import FilterBar


class DNSTab(QWidget):
    """Displays DNS records with color coding for suspicious activity."""

    COLUMNS = ["Timestamp", "Source IP", "Domain", "Type",
               "Answers", "NXDomain", "Tags"]

    # Colors
    COLOR_NORMAL = ""
    COLOR_SUSPICIOUS = "#3c3000"   # amber
    COLOR_MALICIOUS = "#3c1a1a"    # red

    def __init__(self, parent=None):
        super().__init__(parent)
        self._records = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._filter_bar = FilterBar("Filter by domain, IP, type...")
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
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)

        layout.addWidget(self._filter_bar)
        layout.addWidget(self._table)

    def add_record(self, record):
        self._records.append(record)
        row = self._table.rowCount()
        self._table.insertRow(row)

        tags = record.get("tags", [])
        nxdomain = record.get("nxdomain", False)
        is_malicious = "HIGH_ENTROPY_DGA" in tags
        is_suspicious = bool(tags)

        if is_malicious:
            bg = self.COLOR_MALICIOUS
        elif is_suspicious:
            bg = self.COLOR_SUSPICIOUS
        else:
            bg = self.COLOR_NORMAL

        vals = [
            self._fmt_ts(record.get("timestamp", 0)),
            record.get("src_ip", ""),
            record.get("domain", ""),
            record.get("query_type", ""),
            ", ".join(record.get("answers", [])),
            "Yes" if nxdomain else "",
            ", ".join(tags),
        ]
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

    def _on_context_menu(self, pos):
        row = self._table.rowAt(pos.y())
        if row < 0:
            return
        domain = (self._table.item(row, 2) or QTableWidgetItem()).text()
        ip = (self._table.item(row, 1) or QTableWidgetItem()).text()
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background: #16213e; color: #eaeaea; }"
                           "QMenu::item:selected { background: #e94560; }")
        menu.addAction("Copy Domain").triggered.connect(
            lambda: self._copy_to_clipboard(domain))
        menu.addAction("Filter by this host").triggered.connect(
            lambda: self._filter_bar._input.setText(ip))
        menu.addAction("Lookup on VirusTotal").triggered.connect(
            lambda: self._open_vt_domain(domain))
        menu.exec_(self._table.viewport().mapToGlobal(pos))

    def _copy_to_clipboard(self, text):
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(text)

    def _open_vt_domain(self, domain):
        import webbrowser
        webbrowser.open(f"https://www.virustotal.com/gui/domain/{domain}")

    def clear(self):
        self._records.clear()
        self._table.setRowCount(0)

    def get_data(self):
        return list(self._records)

    @staticmethod
    def _fmt_ts(ts):
        try:
            return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(ts)
