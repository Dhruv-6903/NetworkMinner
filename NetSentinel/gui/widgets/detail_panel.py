"""
detail_panel.py - Expandable detail view shown when a table row is clicked.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTextEdit, QLabel, QSizePolicy
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont


class DetailPanel(QWidget):
    """Right-side panel that shows structured detail for a selected row."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        self._title = QLabel("Detail View")
        self._title.setFont(QFont("Monospace", 10))
        self._title.setStyleSheet("color: #eaeaea; font-weight: bold;")

        self._text = QTextEdit()
        self._text.setReadOnly(True)
        self._text.setFont(QFont("Monospace", 9))
        self._text.setStyleSheet(
            "background-color: #16213e; color: #eaeaea; border: 1px solid #0f3460;"
        )
        self._text.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        layout.addWidget(self._title)
        layout.addWidget(self._text)

    def set_title(self, title):
        self._title.setText(title)

    def set_data(self, data_dict):
        """Display a dictionary of key-value pairs."""
        lines = []
        for k, v in data_dict.items():
            if isinstance(v, (list, set)):
                v = ", ".join(str(x) for x in v)
            lines.append(f"  {k:<20}: {v}")
        self._text.setPlainText("\n".join(lines))

    def set_raw_text(self, text):
        """Display raw text (e.g., TCP stream)."""
        self._text.setPlainText(text)

    def clear(self):
        self._text.clear()
        self._title.setText("Detail View")
