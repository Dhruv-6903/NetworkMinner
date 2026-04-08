"""
alerts_tab.py - Displays alerts with severity color coding and live count badge.
"""

import datetime

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QMenu
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor

from ..widgets.filter_bar import FilterBar


SEVERITY_COLORS = {
    "CRITICAL": "#5c0000",
    "HIGH": "#5c2a00",
    "MEDIUM": "#4a3a00",
    "LOW": "#002a5c",
}


class AlertsTab(QWidget):
    """Displays alerts color-coded by severity."""

    alert_count_changed = pyqtSignal(int)

    COLUMNS = ["Timestamp", "Severity", "Rule Name", "Description", "Related IPs"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._alerts = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._filter_bar = FilterBar("Filter by severity, rule, IP...")
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

    def add_alert(self, alert):
        self._alerts.append(alert)
        row = self._table.rowCount()
        self._table.insertRow(row)
        severity = alert.get("severity", "LOW")
        bg = SEVERITY_COLORS.get(severity, "")
        vals = [
            self._fmt_ts(alert.get("timestamp", 0)),
            severity,
            alert.get("rule_name", ""),
            alert.get("description", ""),
            ", ".join(alert.get("related_ips", [])),
        ]
        for col, val in enumerate(vals):
            item = QTableWidgetItem(str(val))
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if bg:
                item.setBackground(QColor(bg))
            item.setForeground(QColor("#eaeaea"))
            self._table.setItem(row, col, item)
        self.alert_count_changed.emit(len(self._alerts))

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
        ips = (self._table.item(row, 4) or QTableWidgetItem()).text()
        ip = ips.split(",")[0].strip() if ips else ""
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background: #16213e; color: #eaeaea; }"
                           "QMenu::item:selected { background: #e94560; }")
        menu.addAction("Copy IPs").triggered.connect(
            lambda: self._copy_to_clipboard(ips))
        if ip:
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
        self._alerts.clear()
        self._table.setRowCount(0)
        self.alert_count_changed.emit(0)

    def get_data(self):
        return list(self._alerts)

    def count(self):
        return len(self._alerts)

    @staticmethod
    def _fmt_ts(ts):
        try:
            return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(ts)
