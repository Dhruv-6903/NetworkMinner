"""
credentials_tab.py - Displays harvested cleartext credentials (highlighted in red).
"""

import datetime

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QMenu
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

from ..widgets.filter_bar import FilterBar


class CredentialsTab(QWidget):
    """Displays cleartext credentials with red highlight."""

    COLUMNS = ["Protocol", "Username", "Password", "Source IP", "Destination IP", "Timestamp"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._credentials = []
        self._mask_passwords = False
        self._setup_ui()

    def set_mask_passwords(self, enabled):
        self._mask_passwords = enabled
        self._refresh_all()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._filter_bar = FilterBar("Filter by protocol, username, IP...")
        self._filter_bar.filter_changed.connect(self._apply_filter)

        self._table = QTableWidget(0, len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels(self.COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(False)
        self._table.setStyleSheet(
            "QTableWidget { background: #1a1a2e; color: #eaeaea; "
            "gridline-color: #0f3460; }"
            "QTableWidget::item:selected { background: #e94560; }"
            "QHeaderView::section { background: #0f3460; color: #eaeaea; "
            "padding: 4px; border: 1px solid #16213e; }"
        )
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._on_context_menu)

        layout.addWidget(self._filter_bar)
        layout.addWidget(self._table)

    def add_credential(self, cred):
        self._credentials.append(cred)
        self._insert_row(self._table.rowCount(), cred)

    def _insert_row(self, row, cred):
        password_display = "••••••••" if self._mask_passwords else cred.get("password", "")
        vals = [
            cred.get("protocol", ""),
            cred.get("username", ""),
            password_display,
            cred.get("src_ip", ""),
            cred.get("dst_ip", ""),
            self._fmt_ts(cred.get("timestamp", 0)),
        ]
        self._table.insertRow(row)
        for col, val in enumerate(vals):
            item = QTableWidgetItem(str(val))
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            item.setBackground(QColor("#3c1a1a"))   # red highlight
            item.setForeground(QColor("#eaeaea"))
            self._table.setItem(row, col, item)

    def _refresh_all(self):
        self._table.setRowCount(0)
        for cred in self._credentials:
            self._insert_row(self._table.rowCount(), cred)

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
        ip = (self._table.item(row, 3) or QTableWidgetItem()).text()
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background: #16213e; color: #eaeaea; }"
                           "QMenu::item:selected { background: #e94560; }")
        menu.addAction("Copy IP").triggered.connect(
            lambda: self._copy_to_clipboard(ip))
        menu.addAction("Filter by this host").triggered.connect(
            lambda: self._filter_bar._input.setText(ip))
        menu.addAction("Lookup on Shodan").triggered.connect(
            lambda: self._open_shodan(ip))
        menu.exec_(self._table.viewport().mapToGlobal(pos))

    def _copy_to_clipboard(self, text):
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(text)

    def _open_shodan(self, ip):
        import webbrowser
        webbrowser.open(f"https://www.shodan.io/host/{ip}")

    def clear(self):
        self._credentials.clear()
        self._table.setRowCount(0)

    def get_data(self):
        return list(self._credentials)

    @staticmethod
    def _fmt_ts(ts):
        try:
            return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(ts)
