"""
files_tab.py - Displays extracted files with VT hash lookup status.
"""

import os
import subprocess
import sys
import datetime

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QMenu
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

from ..widgets.filter_bar import FilterBar


class FilesTab(QWidget):
    """Displays extracted files with VT status."""

    COLUMNS = ["Filename", "Protocol", "Source IP", "MIME Type",
               "File Size", "MD5 Hash", "VT Status"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._files = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._filter_bar = FilterBar("Filter by filename, protocol, hash...")
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

    def add_file(self, file_info):
        self._files.append(file_info)
        row = self._table.rowCount()
        self._table.insertRow(row)
        self._fill_row(row, file_info)

    def _fill_row(self, row, fi):
        vt = fi.get("vt_status", "Pending")
        size_str = self._human_bytes(fi.get("size", 0))
        vals = [
            fi.get("filename", ""),
            fi.get("protocol", ""),
            fi.get("src_ip", ""),
            fi.get("mime_type", ""),
            size_str,
            fi.get("md5", ""),
            vt,
        ]
        for col, val in enumerate(vals):
            item = QTableWidgetItem(str(val))
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            if vt not in ("Pending", "Clean", "Error", "Not found", "") and col == 6:
                item.setBackground(QColor("#3c1a1a"))
            self._table.setItem(row, col, item)

    def update_vt_status(self, md5, status):
        """Update VT status for a file by MD5."""
        for i, fi in enumerate(self._files):
            if fi.get("md5") == md5:
                fi["vt_status"] = status
                for row in range(self._table.rowCount()):
                    hash_item = self._table.item(row, 5)
                    if hash_item and hash_item.text() == md5:
                        vt_item = QTableWidgetItem(status)
                        vt_item.setFlags(vt_item.flags() & ~Qt.ItemIsEditable)
                        if status not in ("Clean", "Not found", "Pending", "Error"):
                            vt_item.setBackground(QColor("#3c1a1a"))
                        self._table.setItem(row, 6, vt_item)
                        break

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
        """Open containing folder."""
        if row < len(self._files):
            path = self._files[row].get("path", "")
            folder = os.path.dirname(path)
            if os.path.isdir(folder):
                if sys.platform == "win32":
                    os.startfile(folder)
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", folder])
                else:
                    subprocess.Popen(["xdg-open", folder])

    def _on_context_menu(self, pos):
        row = self._table.rowAt(pos.y())
        if row < 0:
            return
        md5 = (self._table.item(row, 5) or QTableWidgetItem()).text()
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background: #16213e; color: #eaeaea; }"
                           "QMenu::item:selected { background: #e94560; }")
        menu.addAction("Copy MD5").triggered.connect(
            lambda: self._copy_to_clipboard(md5))
        menu.addAction("Lookup on VirusTotal").triggered.connect(
            lambda: self._open_vt_hash(md5))
        menu.exec_(self._table.viewport().mapToGlobal(pos))

    def _copy_to_clipboard(self, text):
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(text)

    def _open_vt_hash(self, md5):
        import webbrowser
        webbrowser.open(f"https://www.virustotal.com/gui/file/{md5}")

    def clear(self):
        self._files.clear()
        self._table.setRowCount(0)

    def get_data(self):
        return list(self._files)

    @staticmethod
    def _human_bytes(n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"
